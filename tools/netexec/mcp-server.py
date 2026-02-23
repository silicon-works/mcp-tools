#!/usr/bin/env python3
"""
OpenSploit MCP Server: netexec

Multi-protocol credential validation and authenticated command execution.
Wraps NetExec (CrackMapExec successor) for SMB, WinRM, SSH, LDAP, MSSQL, RDP, WMI.
"""

import re
from typing import Any, Dict, List, Optional

from mcp_common import BaseMCPServer, ToolResult, ToolError, sanitize_output


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
    ) -> List[str]:
        """Build the base netexec command with authentication arguments."""
        cmd = ["netexec", protocol, target, "-u", username]

        if hash:
            cmd.extend(["-H", hash])
        elif password is not None:
            cmd.extend(["-p", password])
        else:
            # Empty password - netexec requires -p even if blank
            cmd.extend(["-p", ""])

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
            local_auth=local_auth, port=port,
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

        result = await self.run_command(cmd, timeout=300)
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
            local_auth=local_auth, port=port,
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

        result = await self.run_command(cmd, timeout=300)
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
            port=port,
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
        result = await self.run_command(cmd, timeout=timeout)
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
            local_auth=local_auth, port=port,
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

        result = await self.run_command(cmd, timeout=120)
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
        command: Optional[str] = None,
        ps_command: Optional[str] = None,
        wmi_query: Optional[str] = None,
        exec_method: Optional[str] = None,
    ) -> ToolResult:
        """WMI credential validation, command execution, and WMI queries."""
        self.logger.info(f"NetExec WMI: {target} as {username}")

        cmd = self._build_base_cmd(
            "wmi", target, username, password, hash, domain,
            local_auth=local_auth,
        )

        if command:
            cmd.extend(["-x", command])
        if ps_command:
            cmd.extend(["-X", ps_command])
        if wmi_query:
            cmd.extend(["--wmi", wmi_query])
        if exec_method:
            cmd.extend(["--exec-method", exec_method])

        result = await self.run_command(cmd, timeout=120)
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
