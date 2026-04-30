"""
Base MCP Server implementation for OpenSploit tool servers.

Provides a foundation for building MCP servers that wrap security tools.
"""

import asyncio
import datetime
import json
import logging
import os
import re
import subprocess
import sys
from abc import ABC, abstractmethod
from dataclasses import dataclass, field
from typing import Any, Callable, Dict, List, Optional

from mcp.server import Server
from mcp.server.lowlevel.server import request_ctx
from mcp.server.stdio import stdio_server
from mcp.types import (
    TextContent,
    Tool,
    CallToolResult,
)

logging.basicConfig(level=logging.INFO, format="%(asctime)s - %(name)s - %(levelname)s - %(message)s")


@dataclass
class ToolResult:
    """Result from a tool execution."""
    success: bool
    data: Dict[str, Any] = field(default_factory=dict)
    raw_output: str = ""
    error: Optional[str] = None
    error_class: Optional[str] = None  # "timeout" | "auth" | "network" | "permission" | "config" | "params" | "unknown"
    retryable: bool = False
    suggestions: List[str] = field(default_factory=list)

    def to_content(self) -> List[TextContent]:
        """Convert result to MCP TextContent.

        When suggestions is non-empty, they are appended after the error line.
        When suggestions is empty, the format is identical to the original
        (preserves backward compatibility for existing tools).
        """
        if self.success:
            # Include raw_output in successful results when present
            result_data = dict(self.data)
            if self.raw_output:
                result_data["raw_output"] = self.raw_output
            return [TextContent(type="text", text=json.dumps(result_data, indent=2))]
        else:
            parts = [f"Error: {self.error}"]
            if self.suggestions:
                parts.append("Suggestions: " + "; ".join(self.suggestions))
            if self.raw_output:
                parts.append(f"\nRaw output:\n{self.raw_output}")
            return [TextContent(type="text", text="\n".join(parts))]


@dataclass
class ToolError(Exception):
    """Error during tool execution."""
    message: str
    details: Optional[str] = None

    def __str__(self) -> str:
        if self.details:
            return f"{self.message}: {self.details}"
        return self.message


@dataclass
class MethodDefinition:
    """Definition of a tool method."""
    name: str
    description: str
    params: Dict[str, Dict[str, Any]]
    handler: Callable


class BaseMCPServer(ABC):
    """
    Base class for MCP tool servers.

    Subclass this to create MCP servers for specific security tools.

    Example:
        class NmapServer(BaseMCPServer):
            def __init__(self):
                super().__init__("nmap", "Network scanner")
                self.register_method(
                    name="port_scan",
                    description="Scan for open ports",
                    params={...},
                    handler=self.port_scan
                )

            async def port_scan(self, target: str, ports: str = "1-1000") -> ToolResult:
                ...
    """

    # Meta-parameters injected by the opensploit client that should be stripped
    # before calling the handler — UNLESS the method's registered params include them
    # (e.g., nmap and hydra have 'timeout' as a real param).
    META_PARAMS = {"timeout", "clock_offset"}

    def __init__(self, name: str, description: str, version: str = "1.0.0"):
        self.name = name
        self.description = description
        self.version = version
        self.methods: Dict[str, MethodDefinition] = {}
        self.logger = logging.getLogger(f"mcp.{name}")
        self._server: Optional[Server] = None

        # Register test-only methods when MCP_TEST_MODE is set
        if os.environ.get("MCP_TEST_MODE"):
            self.register_method(
                name="verify_clock",
                description="Return container's current time and FAKETIME status (test-only)",
                params={},
                handler=self._verify_clock,
            )

        # Auto-register the generic CLI runner. Every tool server inherits this
        # by virtue of subclassing BaseMCPServer — kind:cli tools rely on it
        # exclusively, kind:mcp tools use it as an escape hatch for ad-hoc
        # invocations the curated methods don't cover.
        self.register_method(
            name="run_cli",
            description=(
                "Execute the tool's binary with the given argv. Generic CLI "
                "runner for tools that take raw command-line arguments rather "
                "than structured method parameters. Returns stdout/stderr/exit "
                "code. Heartbeats every 30s; hard cap defaults to 24h."
            ),
            params={
                "binary": {
                    "type": "string",
                    "description": "Binary to execute (e.g. 'curl', 'sqlmap', 'impacket-secretsdump'). Must be on PATH inside the container.",
                    "required": True,
                },
                "args": {
                    "type": "array",
                    "items": {"type": "string"},
                    "description": "Argv list, already tokenized by the client. Each element is a single argv slot.",
                    "required": True,
                },
                "stdin_data": {
                    "type": "string",
                    "description": "Optional bytes/text fed to the binary's stdin (e.g. for john --stdin or hashcat).",
                    "required": False,
                },
                "env": {
                    "type": "object",
                    "description": "Optional env vars (Dict[str, str]) merged into the subprocess environment. Used by the plugin to forward agent-supplied values (KRB5CCNAME for Kerberos ccache, FAKETIME for libfaketime offset, etc.). The plugin enforces an allowlist before forwarding; here we just pipe to run_command_with_progress.",
                    "required": False,
                    "additionalProperties": {"type": "string"},
                },
                "max_runtime": {
                    "type": "integer",
                    "description": "Hard wall-clock cap in seconds. Defaults to 86400 (24h). Never resets — set generously.",
                    "required": False,
                    "default": 86400,
                },
            },
            handler=self.run_cli,
        )

    async def run_cli(
        self,
        binary: str,
        args: List[str],
        stdin_data: Optional[str] = None,
        env: Optional[Dict[str, str]] = None,
        max_runtime: int = 86400,
    ) -> "ToolResult":
        """Generic CLI runner — execute ``binary args...`` and return raw output.

        This is the keystone of the kind:cli architecture. The client supplies
        a fully-tokenized argv (no shell, no quoting surprises). We just exec
        and return the result. Target validation, scope checks, reject_flags
        all happened in the plugin before we ever got the call.

        Heartbeat-driven progress notifications keep the client's idle clock
        alive. ``max_runtime`` is the hard cap that catches genuinely wedged
        binaries.

        ``env`` is the plugin's sanctioned channel for per-call env vars
        (KRB5CCNAME for Kerberos ccache, FAKETIME for libfaketime offset,
        etc.). The plugin allowlists keys before forwarding; here we just
        merge into the subprocess env via run_command_with_progress.
        """
        if not binary or not isinstance(binary, str):
            return ToolResult(
                success=False,
                error="run_cli requires non-empty 'binary'",
                error_class="params",
            )
        if not isinstance(args, list) or not all(isinstance(a, str) for a in args):
            return ToolResult(
                success=False,
                error="run_cli requires 'args' to be a list of strings",
                error_class="params",
            )
        if env is not None and (
            not isinstance(env, dict)
            or not all(isinstance(k, str) and isinstance(v, str) for k, v in env.items())
        ):
            return ToolResult(
                success=False,
                error="run_cli 'env' must be a Dict[str, str] when supplied",
                error_class="params",
            )

        cmd = [binary, *args]

        try:
            result = await self.run_command_with_progress(
                cmd,
                timeout=max_runtime,
                stdin_data=stdin_data,
                env=env,
            )
        except ToolError as e:
            # ToolError from run_command_with_progress is the hard-cap path —
            # subprocess was killed and we need to surface it as a timeout.
            return ToolResult(
                success=False,
                error=str(e),
                error_class="timeout",
                retryable=True,
            )

        # MCP-level "success" means "the run completed and we have output for
        # the caller". A non-zero exit is information, not a transport
        # failure — let tool_runner / the LLM interpret exit codes. Only true
        # failures (param errors, hard-cap timeout) return success=False.
        return ToolResult(
            success=True,
            data={
                "exit_code": result.returncode,
                "stdout": result.stdout,
                "stderr": result.stderr,
                "binary": binary,
                "args": args,
                "completed": True,
            },
        )

    async def _verify_clock(self) -> "ToolResult":
        """Return the container's current time and FAKETIME configuration.

        Only registered when MCP_TEST_MODE=1 is set.  Returns enough detail
        to verify that libfaketime is working (or not installed).
        """
        faketime_val = os.environ.get("FAKETIME", "")
        ld_preload_val = os.environ.get("LD_PRELOAD", "")

        # Check if the libfaketime .so actually exists on disk
        libfaketime_exists = False
        if ld_preload_val:
            libfaketime_exists = os.path.isfile(ld_preload_val)
        else:
            # Search common locations
            import glob as _glob
            hits = _glob.glob("/usr/lib/**/libfaketime.so.1", recursive=True)
            libfaketime_exists = len(hits) > 0

        return ToolResult(
            success=True,
            data={
                "current_time": datetime.datetime.now().isoformat(),
                "utc_time": datetime.datetime.utcnow().isoformat(),
                "faketime": faketime_val,
                "ld_preload": ld_preload_val,
                "libfaketime_exists": libfaketime_exists,
            },
        )

    def _classify_unhandled_error(self, returncode: int, output: str) -> tuple:
        """Fallback classifier for universal CLI error patterns.

        Checks the LAST line of output for Python exception class names.
        In a Python traceback, the exception is always on the very last
        line at column 0 (e.g., ``PermissionError: [Errno 13] ...``).
        Checking only the last line avoids false positives from scan
        output that mentions error class names in the middle.

        Returns (error_class, retryable).  Defaults to ("unknown", False).
        """
        if not output:
            return ("unknown", False)

        # Get the last non-empty line — where Python puts the exception class
        lines = output.strip().splitlines()
        last_line = (lines[-1].strip()) if lines else ""

        # Python tracebacks: exception class on the last line.
        # Use 'in' to handle module-prefixed forms like asyncio.TimeoutError,
        # OSError subclasses, etc. Safe because we only check the last line.
        if "PermissionError" in last_line:
            return ("permission", False)
        if "TimeoutError" in last_line:
            return ("timeout", True)
        if "ConnectionRefusedError" in last_line:
            return ("network", True)
        if "FileNotFoundError" in last_line:
            return ("config", False)

        # "Connection refused" at start of any line (system-level, not in scan output)
        if re.search(r"^Connection refused", output, re.MULTILINE):
            return ("network", True)

        return ("unknown", False)

    def register_method(
        self,
        name: str,
        description: str,
        params: Dict[str, Dict[str, Any]],
        handler: Callable,
    ) -> None:
        """
        Register a tool method.

        Args:
            name: Method name (e.g., "port_scan")
            description: Human-readable description
            params: Parameter definitions with types and descriptions
            handler: Async function to handle the method call
        """
        self.methods[name] = MethodDefinition(
            name=name,
            description=description,
            params=params,
            handler=handler,
        )
        self.logger.info(f"Registered method: {name}")

    def _build_input_schema(self, params: Dict[str, Dict[str, Any]]) -> Dict[str, Any]:
        """Build JSON schema from parameter definitions."""
        properties = {}
        required = []

        for param_name, param_def in params.items():
            param_type = param_def.get("type", "string")

            # Handle enum type - JSON Schema uses type: "string" with enum array
            if param_type == "enum":
                prop = {
                    "type": "string",
                    "description": param_def.get("description", ""),
                }
                # Support both "values" (our convention) and "enum" keys
                if "values" in param_def:
                    prop["enum"] = param_def["values"]
                elif "enum" in param_def:
                    prop["enum"] = param_def["enum"]
            else:
                prop = {
                    "type": param_type,
                    "description": param_def.get("description", ""),
                }
                if "enum" in param_def:
                    prop["enum"] = param_def["enum"]

            if "default" in param_def:
                prop["default"] = param_def["default"]
            if "items" in param_def:
                prop["items"] = param_def["items"]

            properties[param_name] = prop

            if param_def.get("required", False):
                required.append(param_name)

        return {
            "type": "object",
            "properties": properties,
            "required": required,
        }

    async def run_command(
        self,
        cmd: List[str],
        timeout: int = 300,
        check: bool = False,
        env: Optional[Dict[str, str]] = None,
    ) -> subprocess.CompletedProcess:
        """
        Run a shell command asynchronously.

        .. deprecated::
            Use :meth:`run_command_with_progress` instead.  It sends MCP
            heartbeat notifications that prevent client-side idle timeouts
            and supports ``timeout=None`` for unlimited duration.

        Args:
            cmd: Command and arguments as list
            timeout: Timeout in seconds
            check: Raise exception on non-zero exit
            env: Optional env vars to merge with os.environ for the subprocess

        Returns:
            CompletedProcess with stdout and stderr
        """
        self.logger.info(f"Running command: {' '.join(cmd)}")

        merged_env = {**os.environ, **env} if env else None

        try:
            proc = await asyncio.create_subprocess_exec(
                *cmd,
                env=merged_env,
                stdin=asyncio.subprocess.DEVNULL,
                stdout=asyncio.subprocess.PIPE,
                stderr=asyncio.subprocess.PIPE,
            )

            stdout, stderr = await asyncio.wait_for(
                proc.communicate(),
                timeout=timeout,
            )

            result = subprocess.CompletedProcess(
                args=cmd,
                returncode=proc.returncode or 0,
                stdout=stdout.decode("utf-8", errors="replace"),
                stderr=stderr.decode("utf-8", errors="replace"),
            )

            if check and result.returncode != 0:
                raise ToolError(
                    message=f"Command failed with exit code {result.returncode}",
                    details=result.stderr,
                )

            return result

        except asyncio.TimeoutError:
            try:
                proc.kill()
                await proc.wait()
            except ProcessLookupError:
                pass
            raise ToolError(
                message=f"Command timed out after {timeout} seconds",
                details=" ".join(cmd),
            )
        except asyncio.CancelledError:
            self.logger.info("Request cancelled, killing subprocess")
            try:
                proc.kill()
                await proc.wait()
            except ProcessLookupError:
                pass
            raise

    async def _read_remaining(self, proc, timeout: float = 3.0) -> str:
        """Drain stdout+stderr from a terminated process with a timeout.

        Use after proc.terminate()/kill() + wait() to safely collect any
        remaining output without risking an indefinite hang on broken pipes.
        """
        output = ""
        for stream in [proc.stdout, proc.stderr]:
            if stream is None:
                continue
            try:
                data = await asyncio.wait_for(stream.read(), timeout=timeout)
                output += data.decode("utf-8", errors="replace")
            except (asyncio.TimeoutError, Exception):
                pass
        return output

    async def send_progress(self, message: str, progress: float = 0.0, total: float | None = None) -> None:
        """Send an MCP progress notification if a progress token exists on the current request.

        Safe to call unconditionally — silently no-ops when there is no active
        request context or no progress token was provided by the client.
        """
        try:
            ctx = request_ctx.get()
        except LookupError:
            return
        if ctx.meta is None or ctx.meta.progressToken is None:
            return
        try:
            await ctx.session.send_progress_notification(
                progress_token=ctx.meta.progressToken,
                progress=progress,
                total=total,
                message=message,
            )
        except Exception:
            self.logger.debug("Failed to send progress notification", exc_info=True)

    async def run_command_with_progress(
        self,
        cmd: List[str],
        timeout: int | None = None,
        check: bool = False,
        progress_filter: Callable[[str], str | None] | None = None,
        heartbeat_interval: float = 30.0,
        env: Optional[Dict[str, str]] = None,
        stdin_data: str | bytes | None = None,
    ) -> subprocess.CompletedProcess:
        """Run a command while streaming progress notifications from its output.

        Dual-clock contract:
          * **Hard cap** (this method) — ``timeout`` seconds wall-clock from
            start to finish. Never resets. Catches a hung subprocess that fools
            the heartbeat.
          * **Idle clock** (client-side) — driven by the heartbeat notifications
            this method emits every *heartbeat_interval* seconds. The MCP client
            resets its own idle timer on each heartbeat. Catches a dead server.

        Both work together. If the subprocess wedges but the asyncio event loop
        is healthy, heartbeats keep flowing and the client's idle clock won't
        fire — but the server-side ``timeout`` will, and we kill the subprocess.

        Args:
            cmd: Command and arguments as list.
            timeout: Hard wall-clock cap in seconds, or ``None`` for unlimited.
                For untrusted/long-running tools, set this generously (3600+);
                the heartbeat-driven idle clock is the first line of defense.
            check: Raise ``ToolError`` on non-zero exit code.
            progress_filter: ``(line) -> message | None``.  Return a short
                string to emit as a progress notification, or ``None`` to skip.
            heartbeat_interval: Seconds between automatic "Still running…"
                heartbeat notifications. Drives the client's idle clock; must be
                less than the client's idle_timeout (typically idle/2 or less).
            env: Optional env vars to merge with os.environ for the subprocess.
            stdin_data: Optional bytes/str to feed to the subprocess via stdin.
                When ``None``, stdin is closed (DEVNULL). Tools like ``john
                --stdin`` and ``hashcat`` need this.

        Returns:
            ``subprocess.CompletedProcess`` with full accumulated stdout/stderr
            (same interface as ``run_command``).
        """
        self.logger.info(f"Running (with progress): {' '.join(cmd)}")

        merged_env = {**os.environ, **env} if env else None

        # If caller provided stdin_data we open a pipe; otherwise close stdin.
        stdin_mode = (
            asyncio.subprocess.PIPE
            if stdin_data is not None
            else asyncio.subprocess.DEVNULL
        )

        proc = await asyncio.create_subprocess_exec(
            *cmd,
            env=merged_env,
            stdin=stdin_mode,
            stdout=asyncio.subprocess.PIPE,
            stderr=asyncio.subprocess.PIPE,
        )

        # Feed stdin (if any) and close so the subprocess sees EOF.
        if stdin_data is not None and proc.stdin is not None:
            payload = (
                stdin_data.encode("utf-8")
                if isinstance(stdin_data, str)
                else stdin_data
            )
            try:
                proc.stdin.write(payload)
                await proc.stdin.drain()
            finally:
                try:
                    proc.stdin.close()
                except Exception:
                    pass

        stdout_buf: list[str] = []
        stderr_buf: list[str] = []
        progress_count = 0

        async def _read_stream(stream: asyncio.StreamReader, buf: list[str]) -> None:
            """Read lines from a stream, sending progress_filter matches as status."""
            nonlocal progress_count
            while True:
                line_bytes = await stream.readline()
                if not line_bytes:
                    break
                line = line_bytes.decode("utf-8", errors="replace")
                buf.append(line)

                # progress_filter is for meaningful status messages, NOT heartbeating
                if progress_filter is not None:
                    msg = progress_filter(line)
                    if msg is not None:
                        progress_count += 1
                        await self.send_progress(msg, progress=float(progress_count))

        async def _heartbeat_loop() -> None:
            """Send heartbeats on a timer, independent of tool output."""
            nonlocal progress_count
            while True:
                await asyncio.sleep(heartbeat_interval)
                progress_count += 1
                await self.send_progress("Still running\u2026", progress=float(progress_count))

        heartbeat_task = asyncio.create_task(_heartbeat_loop())
        try:
            gather_coro = asyncio.gather(
                _read_stream(proc.stdout, stdout_buf),
                _read_stream(proc.stderr, stderr_buf),
            )
            if timeout is not None:
                await asyncio.wait_for(gather_coro, timeout=timeout)
            else:
                await gather_coro
            await proc.wait()
        except asyncio.TimeoutError:
            try:
                proc.kill()
                await proc.wait()
            except ProcessLookupError:
                pass
            raise ToolError(
                message=f"Command timed out after {timeout} seconds",
                details=" ".join(cmd),
            )
        except asyncio.CancelledError:
            self.logger.info("Request cancelled, killing subprocess")
            try:
                proc.kill()
                await proc.wait()
            except ProcessLookupError:
                pass
            raise
        finally:
            heartbeat_task.cancel()
            try:
                await heartbeat_task
            except asyncio.CancelledError:
                pass

        result = subprocess.CompletedProcess(
            args=cmd,
            returncode=proc.returncode or 0,
            stdout="".join(stdout_buf),
            stderr="".join(stderr_buf),
        )

        if check and result.returncode != 0:
            raise ToolError(
                message=f"Command failed with exit code {result.returncode}",
                details=result.stderr,
            )

        return result

    async def _handle_tool_call(self, name: str, arguments: Dict[str, Any]) -> CallToolResult:
        """Handle an incoming tool call."""
        if name not in self.methods:
            available_methods = list(self.methods.keys())
            error_msg = f"Unknown method: '{name}'\n\nAvailable methods for {self.name}:\n"
            for method_name in available_methods:
                method = self.methods[method_name]
                error_msg += f"  - {method_name}: {method.description}\n"
            error_msg += f"\nUse tool_registry_search to find the correct method name."
            return CallToolResult(
                content=[TextContent(type="text", text=error_msg)],
                isError=True,
            )

        method = self.methods[name]

        # --- Meta-parameter stripping ---
        # Strip known meta-params that the client sometimes passes inside args
        # by mistake, but ONLY if the method doesn't declare them as real params.
        arguments = dict(arguments)  # shallow copy to avoid mutating caller's dict
        for meta in self.META_PARAMS:
            if meta in arguments and meta not in method.params:
                self.logger.debug(f"Stripped meta-param '{meta}' from {name} call")
                del arguments[meta]

        # --- Unknown parameter stripping ---
        # Strip params not declared by the method to prevent **kwargs crashes.
        # LLMs sometimes pass params meant for other methods (e.g., 'scripts'
        # on service_scan when it belongs to vuln_scan). Log a warning so the
        # issue is visible, but don't crash.
        unknown = set(arguments.keys()) - set(method.params.keys())
        if unknown:
            self.logger.warning(
                f"Stripped unknown params for {name}: {unknown}. "
                f"Valid: {list(method.params.keys())}"
            )
            for key in unknown:
                del arguments[key]

        self.logger.info(f"Handling call to {name} with args: {arguments}")

        try:
            result = await method.handler(**arguments)

            if isinstance(result, ToolResult):
                # --- Fallback error classification ---
                if not result.success and result.error_class is None:
                    error_class, retryable = self._classify_unhandled_error(
                        0, result.raw_output
                    )
                    result.error_class = error_class
                    result.retryable = retryable

                return CallToolResult(
                    content=result.to_content(),
                    isError=not result.success,
                    structuredContent={
                        "success": result.success,
                        "error": result.error,
                        "error_class": result.error_class,
                        "retryable": result.retryable,
                        "suggestions": result.suggestions,
                        "data": result.data,
                    },
                )
            else:
                # Assume raw dict/string response
                return CallToolResult(
                    content=[TextContent(type="text", text=json.dumps(result, indent=2) if isinstance(result, dict) else str(result))],
                    isError=False,
                    structuredContent={
                        "success": True,
                        "error_class": None,
                        "retryable": False,
                        "suggestions": [],
                        "data": result if isinstance(result, dict) else {"raw": str(result)},
                    },
                )

        except ToolError as e:
            self.logger.error(f"Tool error in {name}: {e}")
            error_class, retryable = self._classify_unhandled_error(
                0, e.details or ""
            )
            return CallToolResult(
                content=[TextContent(type="text", text=str(e))],
                isError=True,
                structuredContent={
                    "success": False,
                    "error_class": error_class,
                    "retryable": retryable,
                    "suggestions": [],
                    "data": {},
                },
            )
        except Exception as e:
            self.logger.exception(f"Unexpected error in {name}")
            return CallToolResult(
                content=[TextContent(type="text", text=f"Internal error: {str(e)}")],
                isError=True,
                structuredContent={
                    "success": False,
                    "error_class": "unknown",
                    "retryable": False,
                    "suggestions": [],
                    "data": {},
                },
            )

    def _get_tools(self) -> List[Tool]:
        """Get list of available tools for MCP."""
        tools = []
        for method in self.methods.values():
            tools.append(Tool(
                name=method.name,
                description=method.description,
                inputSchema=self._build_input_schema(method.params),
            ))
        return tools

    async def run(self) -> None:
        """Start the MCP server."""
        self._server = Server(self.name, version=self.version)

        @self._server.list_tools()
        async def list_tools() -> List[Tool]:
            return self._get_tools()

        @self._server.call_tool()
        async def call_tool(name: str, arguments: Dict[str, Any]) -> CallToolResult:
            return await self._handle_tool_call(name, arguments)

        self.logger.info(f"Starting {self.name} MCP server v{self.version}")

        async with stdio_server() as (read_stream, write_stream):
            await self._server.run(
                read_stream,
                write_stream,
                self._server.create_initialization_options(),
            )

    @classmethod
    def main(cls) -> None:
        """Entry point for running the server."""
        server = cls()
        asyncio.run(server.run())
