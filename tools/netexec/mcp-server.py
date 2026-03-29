#!/usr/bin/env python3
"""
OpenSploit MCP Server: netexec

Multi-protocol credential validation and authenticated command execution.
Wraps NetExec (CrackMapExec successor) for SMB, WinRM, SSH, LDAP, MSSQL, RDP, WMI.
"""

import glob
import os
import re
import shutil
from typing import Any, Dict, List, Optional, Set

import yaml

from mcp_common import BaseMCPServer, ToolResult, ToolError, sanitize_output

CONFIG_DIR = "/session/config"
RECIPE_DIR = "/session/tool_recipes/netexec"

# Auth params handled by _build_base_cmd, not recipe flag mapping
NETEXEC_AUTH_PARAM_NAMES = {"target", "username", "password", "hash", "domain",
                            "local_auth", "port", "kerberos", "aes_key", "ccache_path"}


class NetExecServer(BaseMCPServer):
    """MCP server wrapping NetExec for multi-protocol credential operations."""

    # Markers in netexec output indicating success/failure/admin
    SUCCESS_MARKER = "[+]"
    FAILURE_MARKER = "[-]"
    ADMIN_MARKER = "(Pwn3d!)"

    def __init__(self):
        super().__init__(
            name="netexec",
            description="NetExec (CrackMapExec successor) for multi-protocol credential validation and execution",
            version="1.0.0",
        )

        # Recipe tracking
        self._recipe_methods: Set[str] = set()
        self._recipe_file_mtimes: Dict[str, float] = {}

        self.register_method(
            name="smb",
            description="SMB credential validation, share enumeration, and command execution",
            params={
                "target": {
                    "type": "string",
                    "required": True,
                    "description": "Target IP address or hostname",
                },
                "username": {
                    "type": "string",
                    "required": True,
                    "description": "Username for authentication",
                },
                "password": {
                    "type": "string",
                    "description": "Password for authentication",
                },
                "hash": {
                    "type": "string",
                    "description": "NTLM hash for pass-the-hash (format: LM:NT or just NT)",
                },
                "domain": {
                    "type": "string",
                    "description": "Active Directory domain name",
                },
                "local_auth": {
                    "type": "boolean",
                    "description": "Use local authentication instead of domain",
                },
                "port": {
                    "type": "integer",
                    "description": "SMB port (default 445)",
                },
                "kerberos": {
                    "type": "boolean",
                    "default": False,
                    "description": "Use Kerberos authentication via ccache file",
                },
                "aes_key": {
                    "type": "string",
                    "description": "AES key for Kerberos authentication (128 or 256 bit hex)",
                },
                "ccache_path": {
                    "type": "string",
                    "description": "Path to Kerberos ccache file (e.g., /session/credentials/auditor.ccache)",
                },
                "command": {
                    "type": "string",
                    "description": "CMD command to execute on target via -x (requires admin)",
                },
                "ps_command": {
                    "type": "string",
                    "description": "PowerShell command to execute on target via -X (requires admin)",
                },
                "exec_method": {
                    "type": "string",
                    "description": "Execution method: atexec, wmiexec, smbexec, or mmcexec",
                },
                "shares": {
                    "type": "boolean",
                    "description": "Enumerate SMB shares",
                },
                "spider": {
                    "type": "string",
                    "description": "Spider a share for files (share name)",
                },
                "sam": {
                    "type": "boolean",
                    "description": "Dump SAM hashes (requires admin)",
                },
                "lsa": {
                    "type": "boolean",
                    "description": "Dump LSA secrets (requires admin)",
                },
                "ntds": {
                    "type": "string",
                    "description": "Dump NTDS.dit hashes. Method: 'drsuapi' or 'vss' (requires domain admin)",
                },
                "users": {
                    "type": "boolean",
                    "description": "Enumerate domain users via SMB",
                },
                "groups": {
                    "type": "string",
                    "description": "Enumerate domain groups, optionally filter by group name",
                },
                "rid_brute": {
                    "type": "integer",
                    "description": "RID brute force to enumerate users (max RID value, e.g. 4000)",
                },
                "pass_pol": {
                    "type": "boolean",
                    "description": "Enumerate password policy",
                },
                "put_file": {
                    "type": "array",
                    "description": "Upload file: [local_path, remote_path]",
                },
                "get_file": {
                    "type": "array",
                    "description": "Download file: [remote_path, local_path]",
                },
                "module": {
                    "type": "string",
                    "description": "NetExec module to run (e.g. lsassy, enum_av, spider_plus)",
                },
                "module_options": {
                    "type": "string",
                    "description": "Module options as key=value string (used with -o)",
                },
            },
            handler=self.smb,
        )

        self.register_method(
            name="winrm",
            description="WinRM credential validation and command execution",
            params={
                "target": {
                    "type": "string",
                    "required": True,
                    "description": "Target IP address or hostname",
                },
                "username": {
                    "type": "string",
                    "required": True,
                    "description": "Username for authentication",
                },
                "password": {
                    "type": "string",
                    "description": "Password for authentication",
                },
                "hash": {
                    "type": "string",
                    "description": "NTLM hash for pass-the-hash",
                },
                "domain": {
                    "type": "string",
                    "description": "Active Directory domain name",
                },
                "local_auth": {
                    "type": "boolean",
                    "description": "Use local authentication instead of domain",
                },
                "port": {
                    "type": "string",
                    "description": "WinRM port(s), e.g. '5985' or '5985 5986'",
                },
                "kerberos": {
                    "type": "boolean",
                    "default": False,
                    "description": "Use Kerberos authentication via ccache file",
                },
                "aes_key": {
                    "type": "string",
                    "description": "AES key for Kerberos authentication",
                },
                "ccache_path": {
                    "type": "string",
                    "description": "Path to Kerberos ccache file",
                },
                "command": {
                    "type": "string",
                    "description": "CMD command to execute via WinRM -x",
                },
                "ps_command": {
                    "type": "string",
                    "description": "PowerShell command to execute via WinRM -X",
                },
                "sam": {
                    "type": "boolean",
                    "description": "Dump SAM hashes (requires admin)",
                },
                "lsa": {
                    "type": "boolean",
                    "description": "Dump LSA secrets (requires admin)",
                },
                "dpapi": {
                    "type": "boolean",
                    "description": "Dump DPAPI secrets (requires admin)",
                },
            },
            handler=self.winrm,
        )

        self.register_method(
            name="ldap",
            description="LDAP enumeration with credentials",
            params={
                "target": {
                    "type": "string",
                    "required": True,
                    "description": "Target DC IP address or hostname",
                },
                "username": {
                    "type": "string",
                    "required": True,
                    "description": "Domain username",
                },
                "password": {
                    "type": "string",
                    "description": "Domain password",
                },
                "hash": {
                    "type": "string",
                    "description": "NTLM hash for pass-the-hash",
                },
                "domain": {
                    "type": "string",
                    "description": "Active Directory domain name",
                },
                "port": {
                    "type": "integer",
                    "description": "LDAP port (default 389, or 636 for LDAPS)",
                },
                "kerberos": {
                    "type": "boolean",
                    "default": False,
                    "description": "Use Kerberos authentication via ccache file",
                },
                "aes_key": {
                    "type": "string",
                    "description": "AES key for Kerberos authentication",
                },
                "ccache_path": {
                    "type": "string",
                    "description": "Path to Kerberos ccache file",
                },
                "users": {
                    "type": "boolean",
                    "description": "Enumerate domain users",
                },
                "groups": {
                    "type": "boolean",
                    "description": "Enumerate domain groups",
                },
                "kerberoasting": {
                    "type": "string",
                    "description": "Perform Kerberoasting and write hashes to this output file",
                },
                "asreproast": {
                    "type": "string",
                    "description": "Perform AS-REP Roasting and write hashes to this output file",
                },
                "bloodhound": {
                    "type": "boolean",
                    "description": "Run BloodHound data collection",
                },
                "bloodhound_collection": {
                    "type": "string",
                    "description": "BloodHound collection type: Default, All, DCOnly, Group, LocalAdmin, Session, etc.",
                },
                "pass_pol": {
                    "type": "boolean",
                    "description": "Enumerate domain password policy",
                },
                "find_delegation": {
                    "type": "boolean",
                    "description": "Find delegations in the domain",
                },
                "computers": {
                    "type": "boolean",
                    "description": "Enumerate domain computers",
                },
                "dc_list": {
                    "type": "boolean",
                    "description": "List domain controllers",
                },
                "gmsa": {
                    "type": "boolean",
                    "description": "Enumerate Group Managed Service Accounts",
                },
                "admin_count": {
                    "type": "boolean",
                    "description": "Enumerate objects with adminCount=1",
                },
                "query": {
                    "type": "array",
                    "description": "Custom LDAP query: [filter, attributes] e.g. ['(sAMAccountName=*)', 'cn sAMAccountName']",
                },
            },
            handler=self.ldap,
        )

        self.register_method(
            name="mssql",
            description="MSSQL credential validation and command execution",
            params={
                "target": {
                    "type": "string",
                    "required": True,
                    "description": "Target IP address or hostname",
                },
                "username": {
                    "type": "string",
                    "required": True,
                    "description": "Username for authentication",
                },
                "password": {
                    "type": "string",
                    "description": "Password for authentication",
                },
                "hash": {
                    "type": "string",
                    "description": "NTLM hash for pass-the-hash (format: LM:NT or just NT)",
                },
                "domain": {
                    "type": "string",
                    "description": "Active Directory domain name",
                },
                "local_auth": {
                    "type": "boolean",
                    "description": "Use local authentication instead of domain",
                },
                "port": {
                    "type": "integer",
                    "description": "MSSQL port (default 1433)",
                },
                "kerberos": {
                    "type": "boolean",
                    "default": False,
                    "description": "Use Kerberos authentication via ccache file",
                },
                "aes_key": {
                    "type": "string",
                    "description": "AES key for Kerberos authentication",
                },
                "ccache_path": {
                    "type": "string",
                    "description": "Path to Kerberos ccache file",
                },
                "command": {
                    "type": "string",
                    "description": "OS command to execute via xp_cmdshell (-x)",
                },
                "ps_command": {
                    "type": "string",
                    "description": "PowerShell command to execute via -X",
                },
                "query": {
                    "type": "string",
                    "description": "SQL query to execute",
                },
                "database": {
                    "type": "string",
                    "description": "Target database name (optional, uses default if omitted)",
                },
                "put_file": {
                    "type": "array",
                    "description": "Upload file: [local_path, remote_path]",
                },
                "get_file": {
                    "type": "array",
                    "description": "Download file: [remote_path, local_path]",
                },
                "rid_brute": {
                    "type": "integer",
                    "description": "RID brute force to enumerate users (max RID value)",
                },
            },
            handler=self.mssql,
        )

        self.register_method(
            name="ssh",
            description="SSH credential validation and command execution",
            params={
                "target": {
                    "type": "string",
                    "required": True,
                    "description": "Target IP address or hostname",
                },
                "username": {
                    "type": "string",
                    "required": True,
                    "description": "Username for authentication",
                },
                "password": {
                    "type": "string",
                    "description": "Password for authentication",
                },
                "key_file": {
                    "type": "string",
                    "description": "Path to SSH private key file",
                },
                "port": {
                    "type": "integer",
                    "description": "SSH port (default 22)",
                },
                "command": {
                    "type": "string",
                    "description": "Command to execute via SSH",
                },
                "sudo_check": {
                    "type": "boolean",
                    "description": "Check if user has sudo privileges",
                },
                "put_file": {
                    "type": "array",
                    "description": "Upload file: [local_path, remote_path]",
                },
                "get_file": {
                    "type": "array",
                    "description": "Download file: [remote_path, local_path]",
                },
            },
            handler=self.ssh,
        )

        self.register_method(
            name="rdp",
            description="RDP credential validation, command execution, and screenshot capture",
            params={
                "target": {
                    "type": "string",
                    "required": True,
                    "description": "Target IP address or hostname",
                },
                "username": {
                    "type": "string",
                    "required": True,
                    "description": "Username for authentication",
                },
                "password": {
                    "type": "string",
                    "description": "Password for authentication",
                },
                "hash": {
                    "type": "string",
                    "description": "NTLM hash for pass-the-hash",
                },
                "domain": {
                    "type": "string",
                    "description": "Active Directory domain name",
                },
                "local_auth": {
                    "type": "boolean",
                    "description": "Use local authentication instead of domain",
                },
                "port": {
                    "type": "integer",
                    "description": "RDP port (default 3389)",
                },
                "command": {
                    "type": "string",
                    "description": "CMD command to execute via -x",
                },
                "ps_command": {
                    "type": "string",
                    "description": "PowerShell command to execute via -X",
                },
                "screenshot": {
                    "type": "boolean",
                    "description": "Take a screenshot of the RDP session",
                },
            },
            handler=self.rdp,
        )

        self.register_method(
            name="wmi",
            description="WMI credential validation, command execution, and WMI queries",
            params={
                "target": {
                    "type": "string",
                    "required": True,
                    "description": "Target IP address or hostname",
                },
                "username": {
                    "type": "string",
                    "required": True,
                    "description": "Username for authentication",
                },
                "password": {
                    "type": "string",
                    "description": "Password for authentication",
                },
                "hash": {
                    "type": "string",
                    "description": "NTLM hash for pass-the-hash (format: LM:NT or just NT)",
                },
                "domain": {
                    "type": "string",
                    "description": "Active Directory domain name",
                },
                "local_auth": {
                    "type": "boolean",
                    "description": "Use local authentication instead of domain",
                },
                "kerberos": {
                    "type": "boolean",
                    "default": False,
                    "description": "Use Kerberos authentication via ccache file",
                },
                "aes_key": {
                    "type": "string",
                    "description": "AES key for Kerberos authentication",
                },
                "ccache_path": {
                    "type": "string",
                    "description": "Path to Kerberos ccache file",
                },
                "command": {
                    "type": "string",
                    "description": "CMD command to execute via -x",
                },
                "ps_command": {
                    "type": "string",
                    "description": "PowerShell command to execute via -X",
                },
                "wmi_query": {
                    "type": "string",
                    "description": "WMI query to execute (e.g. 'SELECT * FROM Win32_Process')",
                },
                "exec_method": {
                    "type": "string",
                    "description": "Execution method: wmiexec or wmiexec-event",
                },
            },
            handler=self.wmi,
        )

        # Load dynamic recipes from session
        self._load_recipes()

    # ── Dynamic Recipe System ────────────────────────────────────

    def _load_recipes(self):
        """Load recipe YAML files from /session/tool_recipes/netexec/."""
        if not os.path.isdir(RECIPE_DIR):
            return
        for path in sorted(glob.glob(os.path.join(RECIPE_DIR, "*.yaml"))) + \
                     sorted(glob.glob(os.path.join(RECIPE_DIR, "*.yml"))):
            try:
                mtime = os.path.getmtime(path)
                if self._recipe_file_mtimes.get(path) == mtime:
                    continue
                with open(path) as f:
                    recipe = yaml.safe_load(f)
                if not recipe or not recipe.get("name"):
                    continue
                name = recipe["name"]
                if name in self.methods and name not in self._recipe_methods:
                    self.logger.warning(f"Recipe '{name}' conflicts with built-in method, skipping")
                    continue
                self._register_recipe(name, recipe)
                self._recipe_file_mtimes[path] = mtime
                self.logger.info(f"Loaded recipe: {name}")
            except Exception as e:
                self.logger.warning(f"Recipe load failed {path}: {e}")

    def _maybe_reload_recipes(self):
        """Check for new or modified recipe files."""
        if not os.path.isdir(RECIPE_DIR):
            return
        current_files = set(
            glob.glob(os.path.join(RECIPE_DIR, "*.yaml")) +
            glob.glob(os.path.join(RECIPE_DIR, "*.yml"))
        )
        needs_reload = current_files != set(self._recipe_file_mtimes.keys())
        if not needs_reload:
            for path in current_files:
                try:
                    if os.path.getmtime(path) != self._recipe_file_mtimes.get(path):
                        needs_reload = True
                        break
                except OSError:
                    needs_reload = True
                    break
        if needs_reload:
            for path in set(self._recipe_file_mtimes.keys()) - current_files:
                del self._recipe_file_mtimes[path]
            self._load_recipes()

    def _register_recipe(self, name: str, recipe: Dict[str, Any]):
        """Register a dynamic recipe method with netexec auth params."""
        recipe_params = recipe.get("params", {})
        auth_style = recipe.get("auth", "target")

        if auth_style != "none":
            # Include netexec auth params
            params = {
                "target": {"type": "string", "required": True, "description": "Target IP or hostname"},
                "username": {"type": "string", "required": True, "description": "Username"},
                "password": {"type": "string", "description": "Password"},
                "hash": {"type": "string", "description": "NTLM hash (LM:NT or NT)"},
                "domain": {"type": "string", "description": "AD domain name"},
                "local_auth": {"type": "boolean", "default": False, "description": "Use local auth"},
                "kerberos": {"type": "boolean", "default": False, "description": "Use Kerberos"},
                "aes_key": {"type": "string", "description": "AES key for Kerberos"},
                "ccache_path": {"type": "string", "description": "Kerberos ccache path"},
                "port": {"type": "integer", "description": "Target port"},
                "timeout": {"type": "integer", "default": 60, "description": "Timeout in seconds"},
            }
        else:
            params = {
                "timeout": {"type": "integer", "default": 60, "description": "Timeout in seconds"},
            }
        # Add recipe-specific params
        for k, v in recipe_params.items():
            if k not in NETEXEC_AUTH_PARAM_NAMES:
                params[k] = {
                    "type": v.get("type", "string"),
                    "required": v.get("required", False),
                    "description": v.get("description", ""),
                }

        def make_handler(r):
            async def handler(**kw):
                return await self._run_recipe(r, **kw)
            return handler

        self.register_method(
            name=name,
            description=recipe.get("description", f"Dynamic method: {name}"),
            params=params,
            handler=make_handler(recipe),
        )
        self._recipe_methods.add(name)

    async def _run_recipe(self, recipe: Dict[str, Any], **kwargs) -> ToolResult:
        """Execute a dynamic recipe method."""
        timeout = kwargs.pop("timeout", 60)
        auth_style = recipe.get("auth", "target")

        # Extract auth kwargs
        auth_kw = {k: kwargs.pop(k, None) for k in list(NETEXEC_AUTH_PARAM_NAMES) if k in kwargs}

        # Build command
        binary = recipe.get("binary", "netexec")
        cmd = binary.split() if " " in binary else [binary]

        # For netexec recipes, use _build_base_cmd if protocol is specified
        protocol = recipe.get("protocol")
        if auth_style != "none" and protocol and auth_kw.get("target") and auth_kw.get("username"):
            base_cmd = self._build_base_cmd(
                protocol=protocol,
                target=auth_kw["target"],
                username=auth_kw["username"],
                password=auth_kw.get("password"),
                hash=auth_kw.get("hash"),
                domain=auth_kw.get("domain"),
                local_auth=auth_kw.get("local_auth", False),
                port=auth_kw.get("port"),
                kerberos=auth_kw.get("kerberos", False),
                aes_key=auth_kw.get("aes_key"),
            )
            cmd = base_cmd
        elif auth_style == "none":
            pass  # No auth handling

        # Translate recipe params to CLI flags
        recipe_params = recipe.get("params", {})
        for param_name, value in kwargs.items():
            if value is None:
                continue
            param_def = recipe_params.get(param_name, {})
            flag = param_def.get("flag", f"--{param_name.replace('_', '-')}")
            if not flag:
                cmd.append(str(value))
            elif param_def.get("type") == "boolean":
                if value:
                    cmd.append(flag)
            else:
                cmd.extend([flag, str(value)])

        # Kerberos env
        env = self._get_auth_env(
            kerberos=auth_kw.get("kerberos", False),
            ccache_path=auth_kw.get("ccache_path"),
        )

        try:
            result = await self.run_command(cmd, timeout=timeout, env=env)
            combined = result.stdout + result.stderr
            return ToolResult(
                success=result.returncode == 0,
                data={"command": " ".join(cmd), "method": recipe["name"]},
                raw_output=sanitize_output(combined),
            )
        except ToolError as e:
            return ToolResult(success=False, data={"method": recipe["name"]}, error=str(e))

    async def _handle_tool_call(self, name, arguments):
        """Override to check for new recipes before handling calls."""
        self._maybe_reload_recipes()
        return await super()._handle_tool_call(name, arguments)

    def _get_auth_env(self, kerberos: bool = False, ccache_path: Optional[str] = None) -> Dict[str, str]:
        """Get env dict with KRB5CCNAME when using Kerberos auth."""
        if not kerberos:
            return {}
        # Ensure krb5.conf exists (may have been generated by impacket)
        shared_krb5 = os.path.join(CONFIG_DIR, "krb5.conf")
        if os.path.exists(shared_krb5) and not os.path.exists("/etc/krb5.conf"):
            shutil.copy(shared_krb5, "/etc/krb5.conf")
        if ccache_path and os.path.exists(ccache_path):
            return {"KRB5CCNAME": ccache_path}
        return {}

    def _build_base_cmd(
        self,
        protocol: str,
        target: str,
        username: str,
        password: Optional[str] = None,
        hash: Optional[str] = None,
        domain: Optional[str] = None,
        local_auth: bool = False,
        port: Optional[Any] = None,
        kerberos: bool = False,
        aes_key: Optional[str] = None,
    ) -> List[str]:
        """Build the base netexec command with authentication arguments."""
        cmd = ["netexec", protocol, target, "-u", username]

        if kerberos:
            cmd.append("-k")
            cmd.append("--use-kcache")
        elif hash:
            cmd.extend(["-H", hash])
        elif password is not None:
            cmd.extend(["-p", password])
        else:
            # Empty password - netexec requires -p even if blank
            cmd.extend(["-p", ""])

        if aes_key:
            cmd.extend(["--aesKey", aes_key])

        # --local-auth and -d are mutually exclusive in netexec
        if local_auth:
            cmd.append("--local-auth")
        elif domain:
            cmd.extend(["-d", domain])

        if port is not None:
            cmd.extend(["--port", str(port)])

        return cmd

    def _parse_output(self, stdout: str, stderr: str) -> Dict[str, Any]:
        """
        Parse netexec output to determine success, admin status, and extract data.

        NetExec output format:
          [+] = success (green)
          [-] = failure (red)
          [*] = info
          (Pwn3d!) = admin/privileged access
        """
        output = stdout + stderr
        lines = output.strip().split("\n") if output.strip() else []

        success = any(self.SUCCESS_MARKER in line for line in lines)
        admin = any(self.ADMIN_MARKER in line for line in lines)

        return {
            "success": success,
            "admin": admin,
            "output": stdout.strip(),
            "stderr": stderr.strip() if stderr.strip() else None,
        }

    async def smb(
        self,
        target: str,
        username: str,
        password: Optional[str] = None,
        hash: Optional[str] = None,
        domain: Optional[str] = None,
        local_auth: bool = False,
        port: Optional[int] = None,
        kerberos: bool = False,
        aes_key: Optional[str] = None,
        ccache_path: Optional[str] = None,
        command: Optional[str] = None,
        ps_command: Optional[str] = None,
        exec_method: Optional[str] = None,
        shares: bool = False,
        spider: Optional[str] = None,
        sam: bool = False,
        lsa: bool = False,
        ntds: Optional[str] = None,
        users: bool = False,
        groups: Optional[str] = None,
        rid_brute: Optional[int] = None,
        pass_pol: bool = False,
        put_file: Optional[List[str]] = None,
        get_file: Optional[List[str]] = None,
        module: Optional[str] = None,
        module_options: Optional[str] = None,
    ) -> ToolResult:
        """SMB credential validation, share enumeration, and command execution."""
        self.logger.info(f"NetExec SMB: {target} as {username}")

        cmd = self._build_base_cmd(
            "smb", target, username, password, hash, domain,
            local_auth=local_auth, port=port, kerberos=kerberos, aes_key=aes_key,
        )

        if command:
            cmd.extend(["-x", command])
        if ps_command:
            cmd.extend(["-X", ps_command])
        if exec_method:
            cmd.extend(["--exec-method", exec_method])
        if shares:
            cmd.append("--shares")
        if spider:
            cmd.extend(["--spider", spider])
        if sam:
            cmd.append("--sam")
        if lsa:
            cmd.append("--lsa")
        if ntds:
            cmd.extend(["--ntds", ntds])
        if users:
            cmd.append("--users")
        if groups is not None:
            if groups:
                cmd.extend(["--groups", groups])
            else:
                cmd.append("--groups")
        if rid_brute is not None:
            cmd.extend(["--rid-brute", str(rid_brute)])
        if pass_pol:
            cmd.append("--pass-pol")
        if put_file and len(put_file) == 2:
            cmd.extend(["--put-file", put_file[0], put_file[1]])
        if get_file and len(get_file) == 2:
            cmd.extend(["--get-file", get_file[0], get_file[1]])
        if module:
            cmd.extend(["-M", module])
        if module_options:
            cmd.extend(["-o", module_options])

        auth_env = self._get_auth_env(kerberos, ccache_path)
        result = await self.run_command(cmd, timeout=300, env=auth_env)
        parsed = self._parse_output(result.stdout, result.stderr)
        raw = sanitize_output(result.stdout + result.stderr)

        return ToolResult(
            success=parsed["success"],
            data=parsed,
            raw_output=raw,
            error=None if parsed["success"] else f"SMB authentication failed for {username}@{target}",
        )

    async def winrm(
        self,
        target: str,
        username: str,
        password: Optional[str] = None,
        hash: Optional[str] = None,
        domain: Optional[str] = None,
        local_auth: bool = False,
        port: Optional[str] = None,
        kerberos: bool = False,
        aes_key: Optional[str] = None,
        ccache_path: Optional[str] = None,
        command: Optional[str] = None,
        ps_command: Optional[str] = None,
        sam: bool = False,
        lsa: bool = False,
        dpapi: bool = False,
    ) -> ToolResult:
        """WinRM credential validation and command execution."""
        self.logger.info(f"NetExec WinRM: {target} as {username}")

        cmd = self._build_base_cmd(
            "winrm", target, username, password, hash, domain,
            local_auth=local_auth, port=port, kerberos=kerberos, aes_key=aes_key,
        )

        if command:
            cmd.extend(["-x", command])
        if ps_command:
            cmd.extend(["-X", ps_command])
        if sam:
            cmd.append("--sam")
        if lsa:
            cmd.append("--lsa")
        if dpapi:
            cmd.append("--dpapi")

        auth_env = self._get_auth_env(kerberos, ccache_path)
        result = await self.run_command(cmd, timeout=300, env=auth_env)
        parsed = self._parse_output(result.stdout, result.stderr)
        raw = sanitize_output(result.stdout + result.stderr)

        return ToolResult(
            success=parsed["success"],
            data=parsed,
            raw_output=raw,
            error=None if parsed["success"] else f"WinRM authentication failed for {username}@{target}",
        )

    async def ldap(
        self,
        target: str,
        username: str,
        password: Optional[str] = None,
        hash: Optional[str] = None,
        domain: Optional[str] = None,
        port: Optional[int] = None,
        kerberos: bool = False,
        aes_key: Optional[str] = None,
        ccache_path: Optional[str] = None,
        users: bool = False,
        groups: bool = False,
        kerberoasting: Optional[str] = None,
        asreproast: Optional[str] = None,
        bloodhound: bool = False,
        bloodhound_collection: Optional[str] = None,
        pass_pol: bool = False,
        find_delegation: bool = False,
        computers: bool = False,
        dc_list: bool = False,
        gmsa: bool = False,
        admin_count: bool = False,
        query: Optional[List[str]] = None,
    ) -> ToolResult:
        """LDAP enumeration with credentials."""
        self.logger.info(f"NetExec LDAP: {target} as {username}")

        cmd = self._build_base_cmd(
            "ldap", target, username, password, hash, domain,
            port=port, kerberos=kerberos, aes_key=aes_key,
        )

        if users:
            cmd.append("--users")
        if groups:
            cmd.append("--groups")
        if kerberoasting:
            cmd.extend(["--kerberoasting", kerberoasting])
        if asreproast:
            cmd.extend(["--asreproast", asreproast])
        if bloodhound:
            cmd.append("--bloodhound")
        if bloodhound_collection:
            cmd.extend(["-c", bloodhound_collection])
        if pass_pol:
            cmd.append("--pass-pol")
        if find_delegation:
            cmd.append("--find-delegation")
        if computers:
            cmd.append("--computers")
        if dc_list:
            cmd.append("--dc-list")
        if gmsa:
            cmd.append("--gmsa")
        if admin_count:
            cmd.append("--admin-count")
        if query and len(query) == 2:
            cmd.extend(["--query", query[0], query[1]])

        # BloodHound and kerberoasting can take a while
        timeout = 300 if (bloodhound or kerberoasting or asreproast) else 120
        auth_env = self._get_auth_env(kerberos, ccache_path)
        result = await self.run_command(cmd, timeout=timeout, env=auth_env)
        parsed = self._parse_output(result.stdout, result.stderr)
        raw = sanitize_output(result.stdout + result.stderr)

        return ToolResult(
            success=parsed["success"],
            data=parsed,
            raw_output=raw,
            error=None if parsed["success"] else f"LDAP authentication failed for {username}@{target}",
        )

    async def mssql(
        self,
        target: str,
        username: str,
        password: Optional[str] = None,
        hash: Optional[str] = None,
        domain: Optional[str] = None,
        local_auth: bool = False,
        port: Optional[int] = None,
        kerberos: bool = False,
        aes_key: Optional[str] = None,
        ccache_path: Optional[str] = None,
        command: Optional[str] = None,
        ps_command: Optional[str] = None,
        query: Optional[str] = None,
        database: Optional[str] = None,
        put_file: Optional[List[str]] = None,
        get_file: Optional[List[str]] = None,
        rid_brute: Optional[int] = None,
    ) -> ToolResult:
        """MSSQL credential validation and command execution."""
        self.logger.info(f"NetExec MSSQL: {target} as {username}")

        cmd = self._build_base_cmd(
            "mssql", target, username, password, hash, domain,
            local_auth=local_auth, port=port, kerberos=kerberos, aes_key=aes_key,
        )

        if command:
            cmd.extend(["-x", command])
        if ps_command:
            cmd.extend(["-X", ps_command])
        if query:
            cmd.extend(["-q", query])
        if database:
            cmd.extend(["--database", database])
        if put_file and len(put_file) == 2:
            cmd.extend(["--put-file", put_file[0], put_file[1]])
        if get_file and len(get_file) == 2:
            cmd.extend(["--get-file", get_file[0], get_file[1]])
        if rid_brute is not None:
            cmd.extend(["--rid-brute", str(rid_brute)])

        auth_env = self._get_auth_env(kerberos, ccache_path)
        result = await self.run_command(cmd, timeout=120, env=auth_env)
        parsed = self._parse_output(result.stdout, result.stderr)
        raw = sanitize_output(result.stdout + result.stderr)

        return ToolResult(
            success=parsed["success"],
            data=parsed,
            raw_output=raw,
            error=None if parsed["success"] else f"MSSQL authentication failed for {username}@{target}",
        )

    async def ssh(
        self,
        target: str,
        username: str,
        password: Optional[str] = None,
        key_file: Optional[str] = None,
        port: Optional[int] = None,
        command: Optional[str] = None,
        sudo_check: bool = False,
        put_file: Optional[List[str]] = None,
        get_file: Optional[List[str]] = None,
    ) -> ToolResult:
        """SSH credential validation and command execution."""
        self.logger.info(f"NetExec SSH: {target} as {username}")

        cmd = ["netexec", "ssh", target, "-u", username]

        if key_file:
            cmd.extend(["--key-file", key_file])
        elif password is not None:
            cmd.extend(["-p", password])
        else:
            cmd.extend(["-p", ""])

        if port is not None:
            cmd.extend(["--port", str(port)])

        if command:
            cmd.extend(["-x", command])
        if sudo_check:
            cmd.append("--sudo-check")
        if put_file and len(put_file) == 2:
            cmd.extend(["--put-file", put_file[0], put_file[1]])
        if get_file and len(get_file) == 2:
            cmd.extend(["--get-file", get_file[0], get_file[1]])

        result = await self.run_command(cmd, timeout=120)
        parsed = self._parse_output(result.stdout, result.stderr)
        raw = sanitize_output(result.stdout + result.stderr)

        return ToolResult(
            success=parsed["success"],
            data=parsed,
            raw_output=raw,
            error=None if parsed["success"] else f"SSH authentication failed for {username}@{target}",
        )

    async def rdp(
        self,
        target: str,
        username: str,
        password: Optional[str] = None,
        hash: Optional[str] = None,
        domain: Optional[str] = None,
        local_auth: bool = False,
        port: Optional[int] = None,
        command: Optional[str] = None,
        ps_command: Optional[str] = None,
        screenshot: bool = False,
    ) -> ToolResult:
        """RDP credential validation, command execution, and screenshot capture."""
        self.logger.info(f"NetExec RDP: {target} as {username}")

        cmd = self._build_base_cmd(
            "rdp", target, username, password, hash, domain,
            local_auth=local_auth, port=port,
        )

        if command:
            cmd.extend(["-x", command])
        if ps_command:
            cmd.extend(["-X", ps_command])
        if screenshot:
            cmd.append("--screenshot")

        result = await self.run_command(cmd, timeout=60)
        parsed = self._parse_output(result.stdout, result.stderr)
        raw = sanitize_output(result.stdout + result.stderr)

        return ToolResult(
            success=parsed["success"],
            data=parsed,
            raw_output=raw,
            error=None if parsed["success"] else f"RDP authentication failed for {username}@{target}",
        )

    async def wmi(
        self,
        target: str,
        username: str,
        password: Optional[str] = None,
        hash: Optional[str] = None,
        domain: Optional[str] = None,
        local_auth: bool = False,
        kerberos: bool = False,
        aes_key: Optional[str] = None,
        ccache_path: Optional[str] = None,
        command: Optional[str] = None,
        ps_command: Optional[str] = None,
        wmi_query: Optional[str] = None,
        exec_method: Optional[str] = None,
    ) -> ToolResult:
        """WMI credential validation, command execution, and WMI queries."""
        self.logger.info(f"NetExec WMI: {target} as {username}")

        cmd = self._build_base_cmd(
            "wmi", target, username, password, hash, domain,
            local_auth=local_auth, kerberos=kerberos, aes_key=aes_key,
        )

        if command:
            cmd.extend(["-x", command])
        if ps_command:
            cmd.extend(["-X", ps_command])
        if wmi_query:
            cmd.extend(["--wmi", wmi_query])
        if exec_method:
            cmd.extend(["--exec-method", exec_method])

        auth_env = self._get_auth_env(kerberos, ccache_path)
        result = await self.run_command(cmd, timeout=120, env=auth_env)
        parsed = self._parse_output(result.stdout, result.stderr)
        raw = sanitize_output(result.stdout + result.stderr)

        return ToolResult(
            success=parsed["success"],
            data=parsed,
            raw_output=raw,
            error=None if parsed["success"] else f"WMI authentication failed for {username}@{target}",
        )


if __name__ == "__main__":
    NetExecServer.main()
