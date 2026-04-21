#!/usr/bin/env python3
"""
OpenSploit MCP Server: netexec

Multi-protocol credential validation and authenticated command execution.
Wraps NetExec (CrackMapExec successor) for SMB, WinRM, SSH, LDAP, MSSQL, RDP, WMI.
"""

import glob
import os
import re
import shlex
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
                "kdc_host": {
                    "type": "string",
                    "description": "KDC hostname for Kerberos SPN resolution. Required when target is an IP (use hostname like 'dc.corp.local'). Defaults to target if omitted.",
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
                    "type": "boolean",
                    "description": "Enumerate domain groups. NOTE: filtering by group name was moved to the ldap protocol in newer netexec versions — use the ldap method with groups=true and base_dn for filtering.",
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
                "laps": {
                    "type": "boolean",
                    "description": "Retrieve LAPS passwords (requires admin or LAPS read permissions)",
                },
                "delegate": {
                    "type": "string",
                    "description": "S4U2Self delegation — impersonate this user",
                },
                "delegate_spn": {
                    "type": "string",
                    "description": "S4U2Proxy constrained delegation to this SPN",
                },
                "dpapi": {
                    "type": "boolean",
                    "description": "Dump DPAPI master keys and credentials (requires admin)",
                },
                "kerberos_keys": {
                    "type": "boolean",
                    "description": "Dump Kerberos AES/RC4 keys from the SAM/LSA (requires admin)",
                },
                "loggedon_users": {
                    "type": "boolean",
                    "description": "Enumerate currently logged-on users on the target",
                },
                "smb_sessions": {
                    "type": "boolean",
                    "description": "Enumerate active SMB sessions on the target",
                },
                "no_smbv1": {
                    "type": "boolean",
                    "description": "Disable SMBv1 fallback (SMB2/3 only)",
                },
                "timeout": {
                    "type": "integer",
                    "default": 120,
                    "description": "Maximum execution time in seconds. BloodHound/kerberoasting operations default higher.",
                },
                "extra_args": {
                    "type": "string",
                    "description": "Additional netexec flags appended to the command. Use for flags not exposed as named parameters. Split by shlex and appended safely.",
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
                "kdc_host": {
                    "type": "string",
                    "description": "KDC hostname for Kerberos SPN resolution. Required when target is an IP (use hostname like 'dc.corp.local'). Defaults to target if omitted.",
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
                "laps": {
                    "type": "boolean",
                    "description": "Retrieve LAPS passwords via WinRM",
                },
                "module": {
                    "type": "string",
                    "description": "NetExec module to run over WinRM (e.g. enum_dns, get_netconnections)",
                },
                "module_options": {
                    "type": "string",
                    "description": "Module options as key=value string (used with -o)",
                },
                "timeout": {
                    "type": "integer",
                    "default": 120,
                    "description": "Maximum execution time in seconds",
                },
                "extra_args": {
                    "type": "string",
                    "description": "Additional netexec flags appended to the command. Use for flags not exposed as named parameters. Split by shlex and appended safely.",
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
                "kdc_host": {
                    "type": "string",
                    "description": "KDC hostname for Kerberos SPN resolution. Required when target is an IP (use hostname like 'dc.corp.local'). Defaults to target if omitted.",
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
                "trusted_for_delegation": {
                    "type": "boolean",
                    "description": "Find accounts with TRUSTED_FOR_DELEGATION flag (unconstrained delegation)",
                },
                "password_not_required": {
                    "type": "boolean",
                    "description": "Find accounts with PASSWD_NOTREQD flag (often empty passwords)",
                },
                "get_sid": {
                    "type": "boolean",
                    "description": "Get the domain SID",
                },
                "active_users": {
                    "type": "boolean",
                    "description": "Enumerate only active (non-disabled) users",
                },
                "base_dn": {
                    "type": "string",
                    "description": "Custom LDAP base DN for searches (e.g. 'OU=Servers,DC=corp,DC=local')",
                },
                "kerberoast_account": {
                    "type": "string",
                    "description": "Kerberoast a specific account by sAMAccountName",
                },
                "simple_bind": {
                    "type": "boolean",
                    "description": "Use simple LDAP bind instead of NTLM (plaintext or LDAPS)",
                },
                "module": {
                    "type": "string",
                    "description": "NetExec module to run over LDAP (e.g. obsolete, maq)",
                },
                "module_options": {
                    "type": "string",
                    "description": "Module options as key=value string (used with -o)",
                },
                "timeout": {
                    "type": "integer",
                    "default": 120,
                    "description": "Maximum execution time in seconds. Raised to 300 for bloodhound/kerberoasting automatically.",
                },
                "extra_args": {
                    "type": "string",
                    "description": "Additional netexec flags appended to the command. Use for flags not exposed as named parameters. Split by shlex and appended safely.",
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
                "kdc_host": {
                    "type": "string",
                    "description": "KDC hostname for Kerberos SPN resolution. Required when target is an IP (use hostname like 'dc.corp.local'). Defaults to target if omitted.",
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
                "sam": {
                    "type": "boolean",
                    "description": "Dump SAM hashes via xp_cmdshell (requires sysadmin + xp_cmdshell enabled)",
                },
                "lsa": {
                    "type": "boolean",
                    "description": "Dump LSA secrets via xp_cmdshell (requires sysadmin + xp_cmdshell enabled)",
                },
                "module": {
                    "type": "string",
                    "description": "NetExec module to run over MSSQL",
                },
                "module_options": {
                    "type": "string",
                    "description": "Module options as key=value string (used with -o)",
                },
                "timeout": {
                    "type": "integer",
                    "default": 120,
                    "description": "Maximum execution time in seconds",
                },
                "extra_args": {
                    "type": "string",
                    "description": "Additional netexec flags appended to the command. Use for flags not exposed as named parameters. Split by shlex and appended safely.",
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
                "module": {
                    "type": "string",
                    "description": "NetExec module to run over SSH",
                },
                "module_options": {
                    "type": "string",
                    "description": "Module options as key=value string (used with -o)",
                },
                "timeout": {
                    "type": "integer",
                    "default": 120,
                    "description": "Maximum execution time in seconds",
                },
                "extra_args": {
                    "type": "string",
                    "description": "Additional netexec flags appended to the command. Use for flags not exposed as named parameters. Split by shlex and appended safely.",
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
                    "description": "Path to Kerberos ccache file",
                },
                "kdc_host": {
                    "type": "string",
                    "description": "KDC hostname for Kerberos SPN resolution. Required when target is an IP (use hostname like 'dc.corp.local'). Defaults to target if omitted.",
                },
                "nla_screenshot": {
                    "type": "boolean",
                    "description": "Take NLA-safe screenshot before authentication",
                },
                "screentime": {
                    "type": "integer",
                    "description": "Seconds to wait before taking the screenshot (default 10)",
                },
                "res": {
                    "type": "string",
                    "description": "Screen resolution for screenshot (e.g. '1024x768')",
                },
                "module": {
                    "type": "string",
                    "description": "NetExec module to run over RDP",
                },
                "module_options": {
                    "type": "string",
                    "description": "Module options as key=value string (used with -o)",
                },
                "timeout": {
                    "type": "integer",
                    "default": 120,
                    "description": "Maximum execution time in seconds",
                },
                "extra_args": {
                    "type": "string",
                    "description": "Additional netexec flags appended to the command. Use for flags not exposed as named parameters. Split by shlex and appended safely.",
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
                "kdc_host": {
                    "type": "string",
                    "description": "KDC hostname for Kerberos SPN resolution. Required when target is an IP (use hostname like 'dc.corp.local'). Defaults to target if omitted.",
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
                "module": {
                    "type": "string",
                    "description": "NetExec module to run over WMI",
                },
                "module_options": {
                    "type": "string",
                    "description": "Module options as key=value string (used with -o)",
                },
                "timeout": {
                    "type": "integer",
                    "default": 120,
                    "description": "Maximum execution time in seconds",
                },
                "extra_args": {
                    "type": "string",
                    "description": "Additional netexec flags appended to the command. Use for flags not exposed as named parameters. Split by shlex and appended safely.",
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
            result = await self.run_command_with_progress(cmd, env=env)
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
        kdc_host: Optional[str] = None,
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

        if kdc_host:
            cmd.extend(["--kdcHost", kdc_host])

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

        Distinguishes auth success from operation success: if auth [+] appears but
        later [-] lines indicate operation failure, the overall result is failure.
        """
        output = stdout + stderr
        lines = output.strip().split("\n") if output.strip() else []

        # Get the protocol status lines (lines starting with SMB/LDAP/WINRM etc.)
        # These are the actual result lines, filtering out [*] init/banner noise
        proto_lines = [l for l in lines if self.SUCCESS_MARKER in l or self.FAILURE_MARKER in l]

        has_success = any(self.SUCCESS_MARKER in l for l in proto_lines)
        has_failure = any(self.FAILURE_MARKER in l for l in proto_lines)
        admin = any(self.ADMIN_MARKER in l for l in lines)

        # Operation failure patterns that should override auth success
        # (auth [+] appeared but a subsequent operation [-] line shows real failure)
        operation_failure_patterns = [
            "NetBIOSTimeout",
            "Error enumerating",
            "Error executing",
            "Error getting",
            "Error retrieving",
            "Arg moved to",
            "[REMOVED]",
            "Connection reset",
            "Broken pipe",
            "STATUS_ACCESS_DENIED",
            "rpc_s_access_denied",
            "ERROR_DS_DRA_BAD_DN",
            "Could not retrieve",
            "Dumped 0 NTDS",
            "Dumped 0 LSA",
            "Dumped 0 SAM",
        ]
        has_operation_failure = any(
            pat in output for pat in operation_failure_patterns
        )

        # Success logic:
        # - Must have at least one [+] (auth worked)
        # - Must not have operation failure patterns or explicit [-] lines
        # - Exception: if the [-] is on the auth line itself (no later [+]), that's
        #   auth failure, not operation failure — but then has_success would be false
        success = has_success and not has_operation_failure and not has_failure

        # If we saw [+] but also operation failure, auth was fine but op failed
        # This is useful context for the ToolResult error
        auth_success = has_success

        return {
            "success": success,
            "admin": admin,
            "auth_success": auth_success,
            "output": stdout.strip(),
            "stderr": stderr.strip() if stderr.strip() else None,
        }

    def _detect_silent_admin_failure(
        self,
        parsed: Dict[str, Any],
        admin_op_requested: bool,
    ) -> Optional[ToolResult]:
        """Detect the silent no-op case where admin is required but user isn't admin.

        netexec silently drops -x / --sam / --lsa / --ntds / --dpapi when the user
        isn't admin, producing auth [+] with no error and no operation output.
        This method returns a proper failure ToolResult in that case, or None if the
        caller's normal flow should proceed.
        """
        if not admin_op_requested:
            return None
        if not parsed.get("auth_success") and not parsed.get("success"):
            return None
        # Auth succeeded but user is not admin — the admin-required op silently failed
        if parsed.get("success") and not parsed.get("admin"):
            return ToolResult(
                success=False,
                data=parsed,
                error="Admin-required operation requested but user is not a local administrator",
                error_class="auth",
                retryable=False,
                suggestions=[
                    "Operation requires local administrator privileges (SAM/LSA/NTDS/command exec need admin)",
                    "Use a different user with admin rights, or find a privilege escalation path",
                    "Run SMB auth first with minimal args to check admin status via (Pwn3d!) marker",
                ],
            )
        return None

    def _classify_netexec_error(self, output: str) -> tuple:
        """Classify netexec error output into error_class, retryable, suggestions.

        Returns (error_class, retryable, suggestions).
        """
        if not output:
            return ("unknown", False, [])

        # Check if there's an auth success in the output — used to distinguish
        # op-level errors (auth worked, op denied) from auth-level errors
        has_success = self.SUCCESS_MARKER in output

        # Clock skew (Kerberos)
        if "KRB_AP_ERR_SKEW" in output or "Clock skew" in output:
            return ("config", True, [
                "Set clock_offset parameter to match target DC time",
                "Use impacket.get_tgt with clock_offset to get a valid TGT first",
            ])

        # PyAsn1 / impacket BER decoding errors — library can't parse DC's LDAP response
        # Typically environmental: impacket version mismatch, or DC's response format is unexpected
        if "PyAsn1Error" in output or "BER length field" in output:
            return ("env", False, [
                "netexec's impacket/pyasn1 library cannot decode the DC's LDAP response",
                "Try ldapsearch with GSSAPI directly, or use impacket.get_ad_users for a different LDAP client",
                "This is a library compatibility issue, not an auth failure — do not retry with different creds",
            ])

        # LDAP search-level operationsError after successful bind
        if "searchRequest -> operationsError" in output or "operationsError: 000004DC" in output:
            return ("auth", False, [
                "LDAP bind succeeded but the search was rejected by the DC",
                "DC may require LDAP signing/channel binding. Try simple_bind=false or use ldap over LDAPS (port 636)",
                "Alternatively try impacket-ldapsearch with -no-signing/-debug to see the exact rejection reason",
            ])

        # nxc wrapper exception — usually a proto module crash
        if "Exception while calling proto_flow" in output:
            return ("env", False, [
                "netexec internal protocol module error — likely an impacket compat issue",
                "Try a different protocol (e.g., smb instead of ldap for user enum via --users)",
                "Check netexec version against the DC's OS version",
            ])

        # Feature/flag moved between protocols (netexec version upgrade)
        if "[REMOVED] Arg moved to" in output or "Arg moved to the ldap protocol" in output:
            return ("params", False, [
                "This flag has been moved to the LDAP protocol in a newer netexec version",
                "Call the ldap method instead of smb for this operation",
            ])

        # Connection errors
        if "Connection refused" in output or "Connection error" in output:
            return ("network", True, [
                "Verify the target IP is correct and the service is running",
                "Check that the required port is open with nmap",
            ])

        # NetBIOS/SMB session errors
        if "NetBIOSTimeout" in output:
            return ("network", True, [
                "NetBIOS session timed out — target may be filtering or slow",
                "Verify port 445 is open and the target is responsive",
                "Try with a longer timeout or check VPN/firewall",
            ])

        # Argparse / flag validation errors from netexec
        # Pattern: "netexec: error: argument --x: invalid choice: 'bogus'"
        # or "usage: netexec [-h] ... error: unrecognized arguments"
        if re.search(r"error: argument [^:]+: invalid choice", output) \
                or "error: unrecognized arguments" in output \
                or re.search(r"netexec[^:]*: error:", output):
            m = re.search(r"invalid choice: '([^']+)'.*?\(choose from ([^)]+)\)", output)
            if m:
                bad_val = m.group(1)
                choices = m.group(2)
                return ("params", False, [
                    f"Invalid value '{bad_val}' — valid choices are: {choices}",
                    "Fix the param value and retry",
                ])
            m2 = re.search(r"unrecognized arguments: (.+)", output)
            if m2:
                return ("params", False, [
                    f"Unrecognized flag: {m2.group(1)}",
                    "Check netexec --help for valid flags for this protocol",
                ])
            return ("params", False, [
                "netexec rejected the command-line arguments — check flag names and values",
            ])

        # Timeout patterns
        if "timed out" in output.lower() or "timeout" in output.lower():
            return ("timeout", True, [
                "Target may be slow or unreachable; retry with a longer timeout",
            ])

        # LDAP bind failure
        if "successful bind must be completed" in output:
            return ("auth", False, [
                "LDAP requires valid credentials; verify username and password",
                "The account may lack LDAP bind permissions",
            ])

        # NetExec WinRM doesn't support Kerberos — only NTLM. If target has NTLM
        # disabled, WinRM via netexec will always fail. Direct agent to evil-winrm.
        if ("nxc winrm only support NTLM" in output
                or "Invalid NTLM challenge received from server" in output):
            return ("config", False, [
                "NetExec's WinRM module does not support Kerberos authentication — only NTLM",
                "If the target has NTLM disabled, use evil-winrm instead (it supports Kerberos via KRB5CCNAME)",
                "Do not retry with different credentials — this is a protocol-support limitation",
            ])

        # NTLM disabled on target — protocol negotiation failure, not wrong creds
        if "STATUS_NOT_SUPPORTED" in output:
            return ("config", False, [
                "Target does not support NTLM authentication (NTLM may be disabled)",
                "Use Kerberos authentication instead: set kerberos=true with a valid ccache_path",
                "Get a TGT first with impacket.get_tgt, then retry with kerberos=true",
            ])

        # Account locked / disabled — distinct from wrong password
        if "STATUS_ACCOUNT_LOCKED_OUT" in output or "STATUS_ACCOUNT_DISABLED" in output:
            return ("auth", False, [
                "Account is locked or disabled — do not retry with this user",
                "Try a different user, or wait for lockout to expire if known",
            ])

        # Password expired / must change
        if "STATUS_PASSWORD_EXPIRED" in output or "STATUS_PASSWORD_MUST_CHANGE" in output:
            return ("auth", False, [
                "Password has expired and must be changed before use",
                "Use smbpasswd or another tool to change the password",
            ])

        # NTDS dump failure — user isn't domain admin or lacks DRSUAPI rights
        if "rpc_s_access_denied" in output or "ERROR_DS_DRA_BAD_DN" in output:
            return ("auth", False, [
                "NTDS dump requires domain admin rights or DCSync/DRSUAPI replication privileges",
                "Current user lacks the required replication rights on the DC",
                "Try a different user with 'Replicating Directory Changes' ACE, or escalate privileges",
            ])

        # Empty dump result — operation ran but produced nothing (usually permissions)
        if any(s in output for s in ("Dumped 0 NTDS", "Dumped 0 LSA", "Dumped 0 SAM")):
            return ("auth", False, [
                "Dump operation ran but produced zero entries — user likely lacks admin rights",
                "SAM/LSA/NTDS dumps require local administrator (SAM/LSA) or domain admin (NTDS)",
            ])

        # Auth failure — wrong password (always mentions creds)
        if "STATUS_LOGON_FAILURE" in output:
            return ("auth", False, [
                "Verify credentials are correct",
                "Check if account is locked or disabled",
            ])

        # Access denied can be either auth failure OR op failure after successful auth
        # If there's a [+] somewhere, it's op-level access denied (share permissions)
        if "STATUS_ACCESS_DENIED" in output:
            if has_success:
                return ("auth", False, [
                    "Authentication succeeded but access to the requested resource was denied",
                    "Try a different share (check with shares=true), or a user with more privileges",
                    "C$/ADMIN$ require local administrator; other shares may require specific ACEs",
                ])
            return ("auth", False, [
                "Access denied at the authentication level",
                "Verify credentials and check if the account has SMB access",
            ])

        # Kerberos realm/principal errors (check before generic [-] check)
        if "KDC_ERR_C_PRINCIPAL_UNKNOWN" in output:
            return ("auth", False, [
                "User principal not found in Kerberos realm; verify username and domain",
            ])

        if "KDC_ERR_S_PRINCIPAL_UNKNOWN" in output:
            return ("config", False, [
                "Service principal not found; verify the target hostname and domain",
            ])

        # Generic auth failure: [-] line without any [+] line
        lines = output.strip().split("\n")
        has_any_success = any(self.SUCCESS_MARKER in l for l in lines)
        has_any_failure = any(self.FAILURE_MARKER in l for l in lines)
        if has_any_failure and not has_any_success:
            return ("auth", False, [
                "Authentication failed; verify credentials, domain, and target",
            ])

        # No markers at all — netexec ran but produced no [+] or [-] host lines
        # (just [*] init messages). Typical signature of a closed port on
        # mssql/ssh/rdp where nxc silently exits without reporting connection refused.
        if not has_any_success and not has_any_failure:
            return ("network", True, [
                "Target produced no netexec host output — port may be closed or filtered",
                "Verify the required port is open with nmap (MSSQL:1433, SSH:22, RDP:3389, WinRM:5985/5986)",
                "Check network connectivity to the target",
            ])

        return ("unknown", False, [])

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
        kdc_host: Optional[str] = None,
        command: Optional[str] = None,
        ps_command: Optional[str] = None,
        exec_method: Optional[str] = None,
        shares: bool = False,
        spider: Optional[str] = None,
        sam: bool = False,
        lsa: bool = False,
        ntds: Optional[str] = None,
        users: bool = False,
        groups: bool = False,
        rid_brute: Optional[int] = None,
        pass_pol: bool = False,
        put_file: Optional[List[str]] = None,
        get_file: Optional[List[str]] = None,
        module: Optional[str] = None,
        module_options: Optional[str] = None,
        laps: bool = False,
        delegate: Optional[str] = None,
        delegate_spn: Optional[str] = None,
        dpapi: bool = False,
        kerberos_keys: bool = False,
        loggedon_users: bool = False,
        smb_sessions: bool = False,
        no_smbv1: bool = False,
        timeout: int = 120,
        extra_args: Optional[str] = None,
    ) -> ToolResult:
        """SMB credential validation, share enumeration, and command execution."""
        self.logger.info(f"NetExec SMB: {target} as {username}")

        cmd = self._build_base_cmd(
            "smb", target, username, password, hash, domain,
            local_auth=local_auth, port=port, kerberos=kerberos, aes_key=aes_key,
            kdc_host=kdc_host,
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
        if groups:
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
        if laps:
            cmd.append("--laps")
        if delegate:
            cmd.extend(["--delegate", delegate])
        if delegate_spn:
            cmd.extend(["--delegate-spn", delegate_spn])
        if dpapi:
            cmd.append("--dpapi")
        if kerberos_keys:
            # netexec requires --ntds as a parent flag when --kerberos-keys is used
            if not ntds:
                cmd.extend(["--ntds", "drsuapi"])
            cmd.append("--kerberos-keys")
        if loggedon_users:
            cmd.append("--loggedon-users")
        if smb_sessions:
            cmd.append("--smb-sessions")
        if no_smbv1:
            cmd.append("--no-smbv1")
        if extra_args:
            cmd.extend(shlex.split(extra_args))

        auth_env = self._get_auth_env(kerberos, ccache_path)

        def _smb_progress(line: str):
            """Extract meaningful progress from SMB output."""
            if "[+]" in line or "[-]" in line or "[*]" in line:
                return line.strip()[:120]
            return None

        result = await self.run_command_with_progress(
            cmd, env=auth_env, progress_filter=_smb_progress, timeout=timeout,
        )
        parsed = self._parse_output(result.stdout, result.stderr)
        raw = sanitize_output(result.stdout + result.stderr)

        # Detect silent admin-required failures (auth [+] but no op output)
        admin_op_requested = bool(command or ps_command or sam or lsa or ntds
                                   or dpapi or kerberos_keys)
        silent_fail = self._detect_silent_admin_failure(parsed, admin_op_requested)
        if silent_fail is not None:
            silent_fail.raw_output = raw
            return silent_fail

        if parsed["success"]:
            return ToolResult(success=True, data=parsed, raw_output=raw)

        err_class, retryable, suggestions = self._classify_netexec_error(raw)
        # If auth succeeded but op failed, the error message should reflect that
        if parsed.get("auth_success"):
            error_msg = f"SMB authentication succeeded but operation failed for {username}@{target}"
        else:
            error_msg = f"SMB authentication failed for {username}@{target}"
        return ToolResult(
            success=False,
            data=parsed,
            raw_output=raw,
            error=error_msg,
            error_class=err_class,
            retryable=retryable,
            suggestions=suggestions,
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
        kdc_host: Optional[str] = None,
        command: Optional[str] = None,
        ps_command: Optional[str] = None,
        sam: bool = False,
        lsa: bool = False,
        dpapi: bool = False,
        laps: bool = False,
        module: Optional[str] = None,
        module_options: Optional[str] = None,
        timeout: int = 120,
        extra_args: Optional[str] = None,
    ) -> ToolResult:
        """WinRM credential validation and command execution."""
        self.logger.info(f"NetExec WinRM: {target} as {username}")

        cmd = self._build_base_cmd(
            "winrm", target, username, password, hash, domain,
            local_auth=local_auth, port=port, kerberos=kerberos, aes_key=aes_key,
            kdc_host=kdc_host,
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
        if laps:
            cmd.append("--laps")
        if module:
            cmd.extend(["-M", module])
        if module_options:
            cmd.extend(["-o", module_options])
        if extra_args:
            cmd.extend(shlex.split(extra_args))

        auth_env = self._get_auth_env(kerberos, ccache_path)

        def _winrm_progress(line: str):
            if "[+]" in line or "[-]" in line or "[*]" in line:
                return line.strip()[:120]
            return None

        result = await self.run_command_with_progress(
            cmd, env=auth_env, progress_filter=_winrm_progress, timeout=timeout,
        )
        parsed = self._parse_output(result.stdout, result.stderr)
        raw = sanitize_output(result.stdout + result.stderr)

        # Detect silent admin-required failures (auth [+] but no op output)
        admin_op_requested = bool(command or ps_command or sam or lsa or dpapi)
        silent_fail = self._detect_silent_admin_failure(parsed, admin_op_requested)
        if silent_fail is not None:
            silent_fail.raw_output = raw
            return silent_fail

        if parsed["success"]:
            return ToolResult(success=True, data=parsed, raw_output=raw)

        err_class, retryable, suggestions = self._classify_netexec_error(raw)
        if parsed.get("auth_success"):
            error_msg = f"WinRM authentication succeeded but operation failed for {username}@{target}"
        else:
            error_msg = f"WinRM authentication failed for {username}@{target}"
        return ToolResult(
            success=False,
            data=parsed,
            raw_output=raw,
            error=error_msg,
            error_class=err_class,
            retryable=retryable,
            suggestions=suggestions,
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
        kdc_host: Optional[str] = None,
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
        trusted_for_delegation: bool = False,
        password_not_required: bool = False,
        get_sid: bool = False,
        active_users: bool = False,
        base_dn: Optional[str] = None,
        kerberoast_account: Optional[str] = None,
        simple_bind: bool = False,
        module: Optional[str] = None,
        module_options: Optional[str] = None,
        timeout: Optional[int] = None,
        extra_args: Optional[str] = None,
    ) -> ToolResult:
        """LDAP enumeration with credentials."""
        self.logger.info(f"NetExec LDAP: {target} as {username}")

        cmd = self._build_base_cmd(
            "ldap", target, username, password, hash, domain,
            port=port, kerberos=kerberos, aes_key=aes_key,
            kdc_host=kdc_host,
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
        if trusted_for_delegation:
            cmd.append("--trusted-for-delegation")
        if password_not_required:
            cmd.append("--password-not-required")
        if get_sid:
            cmd.append("--get-sid")
        if active_users:
            cmd.append("--active-users")
        if base_dn:
            cmd.extend(["--base-dn", base_dn])
        if kerberoast_account:
            cmd.extend(["--kerberoast-account", kerberoast_account])
        if simple_bind:
            cmd.append("--simple-bind")
        if module:
            cmd.extend(["-M", module])
        if module_options:
            cmd.extend(["-o", module_options])
        if extra_args:
            cmd.extend(shlex.split(extra_args))

        # BloodHound and kerberoasting can take a while — default higher if user didn't specify
        if timeout is None:
            timeout = 300 if (bloodhound or kerberoasting or asreproast) else 120
        auth_env = self._get_auth_env(kerberos, ccache_path)

        def _ldap_progress(line: str):
            if "[+]" in line or "[-]" in line or "[*]" in line:
                return line.strip()[:120]
            return None

        result = await self.run_command_with_progress(
            cmd, env=auth_env, progress_filter=_ldap_progress, timeout=timeout,
        )
        parsed = self._parse_output(result.stdout, result.stderr)
        raw = sanitize_output(result.stdout + result.stderr)

        if parsed["success"]:
            return ToolResult(success=True, data=parsed, raw_output=raw)

        err_class, retryable, suggestions = self._classify_netexec_error(raw)
        return ToolResult(
            success=False,
            data=parsed,
            raw_output=raw,
            error=f"LDAP authentication failed for {username}@{target}",
            error_class=err_class,
            retryable=retryable,
            suggestions=suggestions,
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
        kdc_host: Optional[str] = None,
        command: Optional[str] = None,
        ps_command: Optional[str] = None,
        query: Optional[str] = None,
        database: Optional[str] = None,
        put_file: Optional[List[str]] = None,
        get_file: Optional[List[str]] = None,
        rid_brute: Optional[int] = None,
        sam: bool = False,
        lsa: bool = False,
        module: Optional[str] = None,
        module_options: Optional[str] = None,
        timeout: int = 120,
        extra_args: Optional[str] = None,
    ) -> ToolResult:
        """MSSQL credential validation and command execution."""
        self.logger.info(f"NetExec MSSQL: {target} as {username}")

        cmd = self._build_base_cmd(
            "mssql", target, username, password, hash, domain,
            local_auth=local_auth, port=port, kerberos=kerberos, aes_key=aes_key,
            kdc_host=kdc_host,
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
        if sam:
            cmd.append("--sam")
        if lsa:
            cmd.append("--lsa")
        if module:
            cmd.extend(["-M", module])
        if module_options:
            cmd.extend(["-o", module_options])
        if extra_args:
            cmd.extend(shlex.split(extra_args))

        auth_env = self._get_auth_env(kerberos, ccache_path)
        result = await self.run_command_with_progress(cmd, env=auth_env, timeout=timeout)
        parsed = self._parse_output(result.stdout, result.stderr)
        raw = sanitize_output(result.stdout + result.stderr)

        # Detect silent admin-required failures (auth [+] but no op output)
        admin_op_requested = bool(command or ps_command or sam or lsa)
        silent_fail = self._detect_silent_admin_failure(parsed, admin_op_requested)
        if silent_fail is not None:
            silent_fail.raw_output = raw
            return silent_fail

        if parsed["success"]:
            return ToolResult(success=True, data=parsed, raw_output=raw)

        err_class, retryable, suggestions = self._classify_netexec_error(raw)
        if parsed.get("auth_success"):
            error_msg = f"MSSQL authentication succeeded but operation failed for {username}@{target}"
        else:
            error_msg = f"MSSQL authentication failed for {username}@{target}"
        return ToolResult(
            success=False,
            data=parsed,
            raw_output=raw,
            error=error_msg,
            error_class=err_class,
            retryable=retryable,
            suggestions=suggestions,
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
        module: Optional[str] = None,
        module_options: Optional[str] = None,
        timeout: int = 120,
        extra_args: Optional[str] = None,
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
        if module:
            cmd.extend(["-M", module])
        if module_options:
            cmd.extend(["-o", module_options])
        if extra_args:
            cmd.extend(shlex.split(extra_args))

        result = await self.run_command_with_progress(cmd, timeout=timeout)
        parsed = self._parse_output(result.stdout, result.stderr)
        raw = sanitize_output(result.stdout + result.stderr)

        if parsed["success"]:
            return ToolResult(success=True, data=parsed, raw_output=raw)

        err_class, retryable, suggestions = self._classify_netexec_error(raw)
        return ToolResult(
            success=False,
            data=parsed,
            raw_output=raw,
            error=f"SSH authentication failed for {username}@{target}",
            error_class=err_class,
            retryable=retryable,
            suggestions=suggestions,
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
        kerberos: bool = False,
        aes_key: Optional[str] = None,
        ccache_path: Optional[str] = None,
        kdc_host: Optional[str] = None,
        nla_screenshot: bool = False,
        screentime: Optional[int] = None,
        res: Optional[str] = None,
        module: Optional[str] = None,
        module_options: Optional[str] = None,
        timeout: int = 120,
        extra_args: Optional[str] = None,
    ) -> ToolResult:
        """RDP credential validation, command execution, and screenshot capture."""
        self.logger.info(f"NetExec RDP: {target} as {username}")

        cmd = self._build_base_cmd(
            "rdp", target, username, password, hash, domain,
            local_auth=local_auth, port=port, kerberos=kerberos, aes_key=aes_key,
            kdc_host=kdc_host,
        )

        if command:
            cmd.extend(["-x", command])
        if ps_command:
            cmd.extend(["-X", ps_command])
        if screenshot:
            cmd.append("--screenshot")
        if nla_screenshot:
            cmd.append("--nla-screenshot")
        if screentime is not None:
            cmd.extend(["--screentime", str(screentime)])
        if res:
            cmd.extend(["--res", res])
        if module:
            cmd.extend(["-M", module])
        if module_options:
            cmd.extend(["-o", module_options])
        if extra_args:
            cmd.extend(shlex.split(extra_args))

        auth_env = self._get_auth_env(kerberos, ccache_path)
        result = await self.run_command_with_progress(cmd, env=auth_env, timeout=timeout)
        parsed = self._parse_output(result.stdout, result.stderr)
        raw = sanitize_output(result.stdout + result.stderr)

        # Detect silent admin-required failures (auth [+] but no op output)
        admin_op_requested = bool(command or ps_command)
        silent_fail = self._detect_silent_admin_failure(parsed, admin_op_requested)
        if silent_fail is not None:
            silent_fail.raw_output = raw
            return silent_fail

        if parsed["success"]:
            return ToolResult(success=True, data=parsed, raw_output=raw)

        err_class, retryable, suggestions = self._classify_netexec_error(raw)
        if parsed.get("auth_success"):
            error_msg = f"RDP authentication succeeded but operation failed for {username}@{target}"
        else:
            error_msg = f"RDP authentication failed for {username}@{target}"
        return ToolResult(
            success=False,
            data=parsed,
            raw_output=raw,
            error=error_msg,
            error_class=err_class,
            retryable=retryable,
            suggestions=suggestions,
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
        kdc_host: Optional[str] = None,
        command: Optional[str] = None,
        ps_command: Optional[str] = None,
        wmi_query: Optional[str] = None,
        exec_method: Optional[str] = None,
        module: Optional[str] = None,
        module_options: Optional[str] = None,
        timeout: int = 120,
        extra_args: Optional[str] = None,
    ) -> ToolResult:
        """WMI credential validation, command execution, and WMI queries."""
        self.logger.info(f"NetExec WMI: {target} as {username}")

        cmd = self._build_base_cmd(
            "wmi", target, username, password, hash, domain,
            local_auth=local_auth, kerberos=kerberos, aes_key=aes_key,
            kdc_host=kdc_host,
        )

        if command:
            cmd.extend(["-x", command])
        if ps_command:
            cmd.extend(["-X", ps_command])
        if wmi_query:
            cmd.extend(["--wmi", wmi_query])
        if exec_method:
            cmd.extend(["--exec-method", exec_method])
        if module:
            cmd.extend(["-M", module])
        if module_options:
            cmd.extend(["-o", module_options])
        if extra_args:
            cmd.extend(shlex.split(extra_args))

        auth_env = self._get_auth_env(kerberos, ccache_path)
        result = await self.run_command_with_progress(cmd, env=auth_env, timeout=timeout)
        parsed = self._parse_output(result.stdout, result.stderr)
        raw = sanitize_output(result.stdout + result.stderr)

        # Detect silent admin-required failures (auth [+] but no op output)
        admin_op_requested = bool(command or ps_command)
        silent_fail = self._detect_silent_admin_failure(parsed, admin_op_requested)
        if silent_fail is not None:
            silent_fail.raw_output = raw
            return silent_fail

        if parsed["success"]:
            return ToolResult(success=True, data=parsed, raw_output=raw)

        err_class, retryable, suggestions = self._classify_netexec_error(raw)
        if parsed.get("auth_success"):
            error_msg = f"WMI authentication succeeded but operation failed for {username}@{target}"
        else:
            error_msg = f"WMI authentication failed for {username}@{target}"
        return ToolResult(
            success=False,
            data=parsed,
            raw_output=raw,
            error=error_msg,
            error_class=err_class,
            retryable=retryable,
            suggestions=suggestions,
        )


if __name__ == "__main__":
    NetExecServer.main()
