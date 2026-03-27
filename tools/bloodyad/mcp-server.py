#!/usr/bin/env python3
"""
OpenSploit MCP Server: bloodyad

Active Directory privilege escalation via LDAP using bloodyAD.
Covers ACL abuse, RBCD, shadow credentials, password resets, group manipulation,
and AD object enumeration/modification.
"""

import os
import shutil
from typing import Any, Dict, List, Optional

from mcp_common import BaseMCPServer, ToolResult, ToolError, sanitize_output

CRED_DIR = "/session/credentials"
CONFIG_DIR = "/session/config"


class BloodyADServer(BaseMCPServer):
    """MCP server wrapping bloodyAD for AD privilege escalation via LDAP."""

    def __init__(self):
        super().__init__(
            name="bloodyad",
            description="AD privesc via LDAP — ACL abuse, RBCD, shadow credentials, password resets",
            version="1.0.0",
        )

        # Stateful credential tracking
        self._active_ccache: Optional[str] = None
        self._krb5_configured: bool = False
        self._restore_state()

        # ── SET commands ──────────────────────────────────────────

        self.register_method(
            name="set_password",
            description="Force-change a user's password (requires ForceChangePassword or GenericAll on target)",
            params={
                **self._auth_params(),
                "target": {
                    "type": "string",
                    "required": True,
                    "description": "sAMAccountName, DN, GUID or SID of the target user",
                },
                "new_password": {
                    "type": "string",
                    "required": True,
                    "description": "New password for the target user",
                },
                "old_password": {
                    "type": "string",
                    "description": "Old password (required if you only have ChangePassword, not ForceChangePassword)",
                },
            },
            handler=self.set_password,
        )

        self.register_method(
            name="set_owner",
            description="Change ownership of an AD object (requires WriteOwner permission)",
            params={
                **self._auth_params(),
                "target": {
                    "type": "string",
                    "required": True,
                    "description": "sAMAccountName, DN, GUID or SID of the target object",
                },
                "owner": {
                    "type": "string",
                    "required": True,
                    "description": "sAMAccountName, DN, GUID or SID of the new owner",
                },
            },
            handler=self.set_owner,
        )

        self.register_method(
            name="set_object",
            description="Add, replace, or delete an attribute on an AD object",
            params={
                **self._auth_params(),
                "target": {
                    "type": "string",
                    "required": True,
                    "description": "sAMAccountName, DN, GUID or SID of the target object",
                },
                "attribute": {
                    "type": "string",
                    "required": True,
                    "description": "Name of the attribute to modify",
                },
                "values": {
                    "type": "array",
                    "description": "Values to set. Omit to delete the attribute. Multiple values supported.",
                },
            },
            handler=self.set_object,
        )

        # ── ADD commands ──────────────────────────────────────────

        self.register_method(
            name="add_genericall",
            description="Grant GenericAll (full control) to a principal on a target object (requires WriteDacl)",
            params={
                **self._auth_params(),
                "target": {
                    "type": "string",
                    "required": True,
                    "description": "sAMAccountName, DN, GUID or SID of the target object",
                },
                "trustee": {
                    "type": "string",
                    "required": True,
                    "description": "sAMAccountName, DN, GUID or SID of the principal to grant access to",
                },
            },
            handler=self.add_genericall,
        )

        self.register_method(
            name="add_rbcd",
            description="Add Resource-Based Constrained Delegation for a service on a target (requires Write on msDS-AllowedToActOnBehalfOfOtherIdentity)",
            params={
                **self._auth_params(),
                "target": {
                    "type": "string",
                    "required": True,
                    "description": "sAMAccountName, DN, GUID or SID of the target (the machine to impersonate users on)",
                },
                "service": {
                    "type": "string",
                    "required": True,
                    "description": "sAMAccountName, DN, GUID or SID of the service account (attacker-controlled machine account)",
                },
            },
            handler=self.add_rbcd,
        )

        self.register_method(
            name="add_shadow_credentials",
            description="Add Key Credentials to target for shadow credentials attack",
            params={
                **self._auth_params(),
                "target": {
                    "type": "string",
                    "required": True,
                    "description": "sAMAccountName, DN, GUID or SID of the target",
                },
                "cert_path": {
                    "type": "string",
                    "description": "File path for the generated Key Credentials certificate (default: current dir)",
                },
            },
            handler=self.add_shadow_credentials,
        )

        self.register_method(
            name="add_group_member",
            description="Add a member (user, group, computer) to a group",
            params={
                **self._auth_params(),
                "group": {
                    "type": "string",
                    "required": True,
                    "description": "sAMAccountName, DN, GUID or SID of the group",
                },
                "member": {
                    "type": "string",
                    "required": True,
                    "description": "sAMAccountName, DN, GUID or SID of the member to add",
                },
            },
            handler=self.add_group_member,
        )

        self.register_method(
            name="add_computer",
            description="Add a new machine account to the domain",
            params={
                **self._auth_params(),
                "hostname": {
                    "type": "string",
                    "required": True,
                    "description": "Computer name (without trailing $)",
                },
                "computer_pass": {
                    "type": "string",
                    "required": True,
                    "description": "Password for the new machine account",
                },
                "ou": {
                    "type": "string",
                    "description": "Organizational Unit for the computer (default: DefaultOU)",
                },
            },
            handler=self.add_computer,
        )

        self.register_method(
            name="add_dcsync",
            description="Grant DCSync rights (Replicating Directory Changes) to a principal on the domain",
            params={
                **self._auth_params(),
                "trustee": {
                    "type": "string",
                    "required": True,
                    "description": "sAMAccountName, DN, GUID or SID of the principal to grant DCSync to",
                },
            },
            handler=self.add_dcsync,
        )

        self.register_method(
            name="add_uac",
            description="Add UAC property flags to a user/computer object",
            params={
                **self._auth_params(),
                "target": {
                    "type": "string",
                    "required": True,
                    "description": "sAMAccountName, DN, GUID or SID of the target",
                },
                "flags": {
                    "type": "array",
                    "required": True,
                    "description": "UAC flags to add (e.g., ['DONT_REQ_PREAUTH', 'TRUSTED_TO_AUTH_FOR_DELEGATION'])",
                },
            },
            handler=self.add_uac,
        )

        self.register_method(
            name="add_dns_record",
            description="Add a DNS record to the AD-integrated DNS zone",
            params={
                **self._auth_params(),
                "name": {
                    "type": "string",
                    "required": True,
                    "description": "DNS record name (e.g., 'attacker' or 'evil.corp.local')",
                },
                "data": {
                    "type": "string",
                    "required": True,
                    "description": "DNS record data (e.g., IP address '10.10.10.5')",
                },
                "dnstype": {
                    "type": "string",
                    "default": "A",
                    "description": "DNS record type (default: A). e.g., A, AAAA, CNAME, TXT",
                },
                "zone": {
                    "type": "string",
                    "description": "DNS zone (default: domain zone)",
                },
                "ttl": {
                    "type": "integer",
                    "description": "TTL in seconds for the DNS record",
                },
            },
            handler=self.add_dns_record,
        )

        self.register_method(
            name="add_user",
            description="Create a new user account in the domain",
            params={
                **self._auth_params(),
                "sam_account_name": {
                    "type": "string",
                    "required": True,
                    "description": "sAMAccountName for the new user",
                },
                "new_password": {
                    "type": "string",
                    "required": True,
                    "description": "Password for the new user account",
                },
                "ou": {
                    "type": "string",
                    "description": "Organizational Unit DN for the user (default: Users container)",
                },
            },
            handler=self.add_user,
        )

        # ── GET commands ──────────────────────────────────────────

        self.register_method(
            name="get_object",
            description="Read LDAP attributes of an AD object",
            params={
                **self._auth_params(),
                "target": {
                    "type": "string",
                    "required": True,
                    "description": "sAMAccountName, DN, GUID or SID of the target (empty string for rootDSE)",
                },
                "attr": {
                    "type": "string",
                    "description": "Comma-separated list of attributes to retrieve (default: all)",
                },
                "resolve_sd": {
                    "type": "boolean",
                    "default": False,
                    "description": "Resolve security descriptor permissions",
                },
            },
            handler=self.get_object,
        )

        self.register_method(
            name="get_children",
            description="List child objects of an AD container/OU",
            params={
                **self._auth_params(),
                "target": {
                    "type": "string",
                    "description": "sAMAccountName, DN, GUID or SID of the parent (default: domain root)",
                },
                "otype": {
                    "type": "string",
                    "description": "Object class filter (e.g., user, computer, group, organizationalUnit). Default: all",
                },
                "direct": {
                    "type": "boolean",
                    "default": False,
                    "description": "Only fetch direct children (not recursive)",
                },
            },
            handler=self.get_children,
        )

        self.register_method(
            name="get_search",
            description="Search AD objects with LDAP filter",
            params={
                **self._auth_params(),
                "filter": {
                    "type": "string",
                    "required": True,
                    "description": "LDAP filter (e.g., '(objectClass=user)', '(&(objectClass=computer)(ms-MCS-AdmPwd=*))')",
                },
                "base": {
                    "type": "string",
                    "description": "Base DN for search (default: domain root)",
                },
                "attr": {
                    "type": "string",
                    "description": "Comma-separated attributes to retrieve (default: all)",
                },
            },
            handler=self.get_search,
        )

        self.register_method(
            name="get_writable",
            description="Find AD objects writable by the current user",
            params={
                **self._auth_params(),
                "otype": {
                    "type": "enum",
                    "values": ["ALL", "OU", "USER", "COMPUTER", "GROUP", "DOMAIN", "GPO"],
                    "default": "ALL",
                    "description": "Type of writable objects to search for",
                },
                "right": {
                    "type": "enum",
                    "values": ["ALL", "WRITE", "CHILD"],
                    "default": "ALL",
                    "description": "Type of right to search for",
                },
                "detail": {
                    "type": "boolean",
                    "default": False,
                    "description": "Show detailed attributes/types you can write/create",
                },
            },
            handler=self.get_writable,
        )

        self.register_method(
            name="get_membership",
            description="Retrieve all groups a target belongs to (recursive)",
            params={
                **self._auth_params(),
                "target": {
                    "type": "string",
                    "required": True,
                    "description": "sAMAccountName, DN, GUID or SID of the target",
                },
                "no_recurse": {
                    "type": "boolean",
                    "default": False,
                    "description": "Only show direct group memberships",
                },
            },
            handler=self.get_membership,
        )

        self.register_method(
            name="get_dnsdump",
            description="Dump all DNS records from the AD-integrated DNS zone",
            params={
                **self._auth_params(),
            },
            handler=self.get_dnsdump,
        )

        self.register_method(
            name="get_trusts",
            description="Enumerate all Active Directory trust relationships",
            params={
                **self._auth_params(),
            },
            handler=self.get_trusts,
        )

        # ── REMOVE commands ───────────────────────────────────────

        self.register_method(
            name="remove_genericall",
            description="Remove GenericAll ACE from a target",
            params={
                **self._auth_params(),
                "target": {
                    "type": "string",
                    "required": True,
                    "description": "sAMAccountName, DN, GUID or SID of the target",
                },
                "trustee": {
                    "type": "string",
                    "required": True,
                    "description": "sAMAccountName, DN, GUID or SID of the trustee to remove",
                },
            },
            handler=self.remove_genericall,
        )

        self.register_method(
            name="remove_rbcd",
            description="Remove Resource-Based Constrained Delegation from a target",
            params={
                **self._auth_params(),
                "target": {
                    "type": "string",
                    "required": True,
                    "description": "sAMAccountName, DN, GUID or SID of the target",
                },
                "service": {
                    "type": "string",
                    "required": True,
                    "description": "sAMAccountName, DN, GUID or SID of the service account to remove",
                },
            },
            handler=self.remove_rbcd,
        )

        self.register_method(
            name="remove_group_member",
            description="Remove a member from a group",
            params={
                **self._auth_params(),
                "group": {
                    "type": "string",
                    "required": True,
                    "description": "sAMAccountName, DN, GUID or SID of the group",
                },
                "member": {
                    "type": "string",
                    "required": True,
                    "description": "sAMAccountName, DN, GUID or SID of the member to remove",
                },
            },
            handler=self.remove_group_member,
        )

        self.register_method(
            name="remove_shadow_credentials",
            description="Remove shadow credentials (Key Credentials) from a target",
            params={
                **self._auth_params(),
                "target": {
                    "type": "string",
                    "required": True,
                    "description": "sAMAccountName, DN, GUID or SID of the target",
                },
                "key": {
                    "type": "string",
                    "description": "Specific key identifier to remove (default: all keys)",
                },
            },
            handler=self.remove_shadow_credentials,
        )

        self.register_method(
            name="remove_dcsync",
            description="Remove DCSync rights (Replicating Directory Changes) from a principal",
            params={
                **self._auth_params(),
                "trustee": {
                    "type": "string",
                    "required": True,
                    "description": "sAMAccountName, DN, GUID or SID of the principal to remove DCSync from",
                },
            },
            handler=self.remove_dcsync,
        )

        self.register_method(
            name="remove_uac",
            description="Remove UAC property flags from a user/computer object",
            params={
                **self._auth_params(),
                "target": {
                    "type": "string",
                    "required": True,
                    "description": "sAMAccountName, DN, GUID or SID of the target",
                },
                "flags": {
                    "type": "array",
                    "required": True,
                    "description": "UAC flags to remove (e.g., ['DONT_REQ_PREAUTH', 'TRUSTED_TO_AUTH_FOR_DELEGATION'])",
                },
            },
            handler=self.remove_uac,
        )

    # ── State Management ──────────────────────────────────────────

    def _restore_state(self):
        """Restore Kerberos state from /session/ on container start."""
        import glob as _glob
        if os.path.isdir(CRED_DIR):
            ccaches = _glob.glob(os.path.join(CRED_DIR, "*.ccache"))
            if ccaches:
                self._active_ccache = ccaches[-1]  # most recent
        shared_krb5 = os.path.join(CONFIG_DIR, "krb5.conf")
        if os.path.exists(shared_krb5):
            if not os.path.exists("/etc/krb5.conf"):
                shutil.copy(shared_krb5, "/etc/krb5.conf")
            self._krb5_configured = True
        if self._active_ccache:
            self.logger.info(f"Restored ccache from {self._active_ccache}")

    def _get_auth_env(self, kerberos: bool = False, ccache_path: Optional[str] = None) -> Dict[str, str]:
        """Get env dict with KRB5CCNAME when using Kerberos auth."""
        if not kerberos:
            return {}
        ccache = ccache_path or self._active_ccache
        if ccache and os.path.exists(ccache):
            return {"KRB5CCNAME": ccache}
        return {}

    # ── Parameter Definitions ─────────────────────────────────────

    def _auth_params(self) -> Dict[str, Dict[str, Any]]:
        """Common bloodyAD authentication parameters."""
        return {
            "host": {
                "type": "string",
                "required": True,
                "description": "Hostname or IP of the DC (e.g., 'dc01.corp.local' or '10.10.10.1')",
            },
            "domain": {
                "type": "string",
                "required": True,
                "description": "Active Directory domain name (e.g., 'corp.local')",
            },
            "username": {
                "type": "string",
                "description": "Username for NTLM authentication",
            },
            "password": {
                "type": "string",
                "description": "Password or LMHASH:NTHASH for NTLM, password or AES/RC4 key for Kerberos",
            },
            "kerberos": {
                "type": "boolean",
                "default": False,
                "description": "Enable Kerberos authentication. Uses ccache_path if provided.",
            },
            "ccache_path": {
                "type": "string",
                "description": "Path to Kerberos ccache file (e.g., /session/credentials/auditor.ccache)",
            },
            "dc_ip": {
                "type": "string",
                "description": "IP of the DC (useful if --host is a hostname that can't resolve)",
            },
            "secure": {
                "type": "boolean",
                "default": False,
                "description": "Use LDAPS (LDAP over TLS) instead of plain LDAP",
            },
        }

    # ── Auth Builder ──────────────────────────────────────────────

    def _build_auth(self, host: str, domain: str, username: Optional[str] = None,
                    password: Optional[str] = None, kerberos: bool = False,
                    ccache_path: Optional[str] = None, dc_ip: Optional[str] = None,
                    secure: bool = False) -> List[str]:
        """Build bloodyAD auth args."""
        cmd = ["bloodyAD", "--host", host, "-d", domain]

        if username:
            cmd.extend(["-u", username])
        if password and not kerberos:
            cmd.extend(["-p", password])
        if kerberos:
            ccache = ccache_path or self._active_ccache
            if ccache and os.path.exists(ccache):
                cmd.extend(["-k", f"ccache={ccache}"])
            else:
                cmd.append("-k")
            if password:
                cmd.extend(["-p", password])
        if dc_ip:
            cmd.extend(["--dc-ip", dc_ip])
        if secure:
            cmd.append("-s")

        return cmd

    # ── SET Method Handlers ───────────────────────────────────────

    async def set_password(self, host: str, domain: str, target: str, new_password: str,
                           username: Optional[str] = None, password: Optional[str] = None,
                           kerberos: bool = False, ccache_path: Optional[str] = None,
                           dc_ip: Optional[str] = None, secure: bool = False,
                           old_password: Optional[str] = None) -> ToolResult:
        """Force-change a user's password."""
        self.logger.info(f"Setting password for {target}")
        cmd = self._build_auth(host, domain, username, password, kerberos, ccache_path, dc_ip, secure)
        cmd.extend(["set", "password"])
        if old_password:
            cmd.extend(["--oldpass", old_password])
        cmd.extend([target, new_password])

        auth_env = self._get_auth_env(kerberos, ccache_path)
        try:
            result = await self.run_command(cmd, timeout=60, env=auth_env)
            combined = result.stdout + result.stderr
            success = result.returncode == 0 or "password" in combined.lower()
            return ToolResult(success=success, data={"target": target, "action": "set_password"},
                              raw_output=sanitize_output(combined))
        except ToolError as e:
            return ToolResult(success=False, error=str(e))

    async def set_owner(self, host: str, domain: str, target: str, owner: str,
                        username: Optional[str] = None, password: Optional[str] = None,
                        kerberos: bool = False, ccache_path: Optional[str] = None,
                        dc_ip: Optional[str] = None, secure: bool = False) -> ToolResult:
        """Set owner of an AD object."""
        self.logger.info(f"Setting owner of {target} to {owner}")
        cmd = self._build_auth(host, domain, username, password, kerberos, ccache_path, dc_ip, secure)
        cmd.extend(["set", "owner", target, owner])

        auth_env = self._get_auth_env(kerberos, ccache_path)
        try:
            result = await self.run_command(cmd, timeout=60, env=auth_env)
            combined = result.stdout + result.stderr
            return ToolResult(success=result.returncode == 0,
                              data={"target": target, "owner": owner, "action": "set_owner"},
                              raw_output=sanitize_output(combined))
        except ToolError as e:
            return ToolResult(success=False, error=str(e))

    async def set_object(self, host: str, domain: str, target: str, attribute: str,
                         username: Optional[str] = None, password: Optional[str] = None,
                         kerberos: bool = False, ccache_path: Optional[str] = None,
                         dc_ip: Optional[str] = None, secure: bool = False,
                         values: Optional[List[str]] = None) -> ToolResult:
        """Add/replace/delete an attribute on an AD object."""
        self.logger.info(f"Setting {attribute} on {target}")
        cmd = self._build_auth(host, domain, username, password, kerberos, ccache_path, dc_ip, secure)
        cmd.extend(["set", "object"])
        if values:
            for v in values:
                cmd.extend(["-v", v])
        cmd.extend([target, attribute])

        auth_env = self._get_auth_env(kerberos, ccache_path)
        try:
            result = await self.run_command(cmd, timeout=60, env=auth_env)
            combined = result.stdout + result.stderr
            return ToolResult(success=result.returncode == 0,
                              data={"target": target, "attribute": attribute, "action": "set_object"},
                              raw_output=sanitize_output(combined))
        except ToolError as e:
            return ToolResult(success=False, error=str(e))

    # ── ADD Method Handlers ───────────────────────────────────────

    async def add_genericall(self, host: str, domain: str, target: str, trustee: str,
                             username: Optional[str] = None, password: Optional[str] = None,
                             kerberos: bool = False, ccache_path: Optional[str] = None,
                             dc_ip: Optional[str] = None, secure: bool = False) -> ToolResult:
        """Grant GenericAll to trustee on target."""
        self.logger.info(f"Adding GenericAll: {trustee} -> {target}")
        cmd = self._build_auth(host, domain, username, password, kerberos, ccache_path, dc_ip, secure)
        cmd.extend(["add", "genericAll", target, trustee])

        auth_env = self._get_auth_env(kerberos, ccache_path)
        try:
            result = await self.run_command(cmd, timeout=60, env=auth_env)
            combined = result.stdout + result.stderr
            return ToolResult(success=result.returncode == 0,
                              data={"target": target, "trustee": trustee, "action": "add_genericall"},
                              raw_output=sanitize_output(combined))
        except ToolError as e:
            return ToolResult(success=False, error=str(e))

    async def add_rbcd(self, host: str, domain: str, target: str, service: str,
                       username: Optional[str] = None, password: Optional[str] = None,
                       kerberos: bool = False, ccache_path: Optional[str] = None,
                       dc_ip: Optional[str] = None, secure: bool = False) -> ToolResult:
        """Add RBCD delegation."""
        self.logger.info(f"Adding RBCD: {service} -> {target}")
        cmd = self._build_auth(host, domain, username, password, kerberos, ccache_path, dc_ip, secure)
        cmd.extend(["add", "rbcd", target, service])

        auth_env = self._get_auth_env(kerberos, ccache_path)
        try:
            result = await self.run_command(cmd, timeout=60, env=auth_env)
            combined = result.stdout + result.stderr
            return ToolResult(success=result.returncode == 0,
                              data={"target": target, "service": service, "action": "add_rbcd"},
                              raw_output=sanitize_output(combined))
        except ToolError as e:
            return ToolResult(success=False, error=str(e))

    async def add_shadow_credentials(self, host: str, domain: str, target: str,
                                     username: Optional[str] = None, password: Optional[str] = None,
                                     kerberos: bool = False, ccache_path: Optional[str] = None,
                                     dc_ip: Optional[str] = None, secure: bool = False,
                                     cert_path: Optional[str] = None) -> ToolResult:
        """Add shadow credentials to target."""
        self.logger.info(f"Adding shadow credentials to {target}")
        cmd = self._build_auth(host, domain, username, password, kerberos, ccache_path, dc_ip, secure)
        cmd.extend(["add", "shadowCredentials"])
        if cert_path:
            cmd.extend(["--path", cert_path])
        cmd.append(target)

        auth_env = self._get_auth_env(kerberos, ccache_path)
        try:
            result = await self.run_command(cmd, timeout=60, env=auth_env)
            combined = result.stdout + result.stderr
            return ToolResult(success=result.returncode == 0,
                              data={"target": target, "action": "add_shadow_credentials"},
                              raw_output=sanitize_output(combined))
        except ToolError as e:
            return ToolResult(success=False, error=str(e))

    async def add_group_member(self, host: str, domain: str, group: str, member: str,
                               username: Optional[str] = None, password: Optional[str] = None,
                               kerberos: bool = False, ccache_path: Optional[str] = None,
                               dc_ip: Optional[str] = None, secure: bool = False) -> ToolResult:
        """Add member to group."""
        self.logger.info(f"Adding {member} to group {group}")
        cmd = self._build_auth(host, domain, username, password, kerberos, ccache_path, dc_ip, secure)
        cmd.extend(["add", "groupMember", group, member])

        auth_env = self._get_auth_env(kerberos, ccache_path)
        try:
            result = await self.run_command(cmd, timeout=60, env=auth_env)
            combined = result.stdout + result.stderr
            return ToolResult(success=result.returncode == 0,
                              data={"group": group, "member": member, "action": "add_group_member"},
                              raw_output=sanitize_output(combined))
        except ToolError as e:
            return ToolResult(success=False, error=str(e))

    async def add_computer(self, host: str, domain: str, hostname: str, computer_pass: str,
                           username: Optional[str] = None, password: Optional[str] = None,
                           kerberos: bool = False, ccache_path: Optional[str] = None,
                           dc_ip: Optional[str] = None, secure: bool = False,
                           ou: Optional[str] = None) -> ToolResult:
        """Add a machine account."""
        self.logger.info(f"Adding computer {hostname}")
        cmd = self._build_auth(host, domain, username, password, kerberos, ccache_path, dc_ip, secure)
        cmd.extend(["add", "computer", hostname, computer_pass])
        if ou:
            cmd.extend(["--ou", ou])

        auth_env = self._get_auth_env(kerberos, ccache_path)
        try:
            result = await self.run_command(cmd, timeout=60, env=auth_env)
            combined = result.stdout + result.stderr
            return ToolResult(success=result.returncode == 0,
                              data={"hostname": hostname, "action": "add_computer"},
                              raw_output=sanitize_output(combined))
        except ToolError as e:
            return ToolResult(success=False, error=str(e))

    async def add_dcsync(self, host: str, domain: str, trustee: str,
                         username: Optional[str] = None, password: Optional[str] = None,
                         kerberos: bool = False, ccache_path: Optional[str] = None,
                         dc_ip: Optional[str] = None, secure: bool = False) -> ToolResult:
        """Grant DCSync rights to a principal."""
        self.logger.info(f"Granting DCSync to {trustee}")
        cmd = self._build_auth(host, domain, username, password, kerberos, ccache_path, dc_ip, secure)
        cmd.extend(["add", "dcsync", trustee])

        auth_env = self._get_auth_env(kerberos, ccache_path)
        try:
            result = await self.run_command(cmd, timeout=60, env=auth_env)
            combined = result.stdout + result.stderr
            return ToolResult(success=result.returncode == 0,
                              data={"trustee": trustee, "action": "add_dcsync"},
                              raw_output=sanitize_output(combined))
        except ToolError as e:
            return ToolResult(success=False, error=str(e))

    async def add_uac(self, host: str, domain: str, target: str, flags: List[str],
                      username: Optional[str] = None, password: Optional[str] = None,
                      kerberos: bool = False, ccache_path: Optional[str] = None,
                      dc_ip: Optional[str] = None, secure: bool = False) -> ToolResult:
        """Add UAC flags to a user/computer object."""
        self.logger.info(f"Adding UAC flags {flags} to {target}")
        cmd = self._build_auth(host, domain, username, password, kerberos, ccache_path, dc_ip, secure)
        cmd.extend(["add", "uac"])
        for flag in flags:
            cmd.extend(["-f", flag])
        cmd.append(target)

        auth_env = self._get_auth_env(kerberos, ccache_path)
        try:
            result = await self.run_command(cmd, timeout=60, env=auth_env)
            combined = result.stdout + result.stderr
            return ToolResult(success=result.returncode == 0,
                              data={"target": target, "flags": flags, "action": "add_uac"},
                              raw_output=sanitize_output(combined))
        except ToolError as e:
            return ToolResult(success=False, error=str(e))

    async def add_dns_record(self, host: str, domain: str, name: str, data: str,
                             username: Optional[str] = None, password: Optional[str] = None,
                             kerberos: bool = False, ccache_path: Optional[str] = None,
                             dc_ip: Optional[str] = None, secure: bool = False,
                             dnstype: str = "A", zone: Optional[str] = None,
                             ttl: Optional[int] = None) -> ToolResult:
        """Add a DNS record to the AD-integrated DNS zone."""
        self.logger.info(f"Adding DNS record: {name} -> {data}")
        cmd = self._build_auth(host, domain, username, password, kerberos, ccache_path, dc_ip, secure)
        cmd.extend(["add", "dnsRecord"])
        if dnstype != "A":
            cmd.extend(["--dnstype", dnstype])
        if zone:
            cmd.extend(["--zone", zone])
        if ttl is not None:
            cmd.extend(["--ttl", str(ttl)])
        cmd.extend([name, data])

        auth_env = self._get_auth_env(kerberos, ccache_path)
        try:
            result = await self.run_command(cmd, timeout=60, env=auth_env)
            combined = result.stdout + result.stderr
            return ToolResult(success=result.returncode == 0,
                              data={"name": name, "data": data, "dnstype": dnstype, "action": "add_dns_record"},
                              raw_output=sanitize_output(combined))
        except ToolError as e:
            return ToolResult(success=False, error=str(e))

    async def add_user(self, host: str, domain: str, sam_account_name: str, new_password: str,
                       username: Optional[str] = None, password: Optional[str] = None,
                       kerberos: bool = False, ccache_path: Optional[str] = None,
                       dc_ip: Optional[str] = None, secure: bool = False,
                       ou: Optional[str] = None) -> ToolResult:
        """Create a new user account in the domain."""
        self.logger.info(f"Adding user {sam_account_name}")
        cmd = self._build_auth(host, domain, username, password, kerberos, ccache_path, dc_ip, secure)
        cmd.extend(["add", "user"])
        if ou:
            cmd.extend(["--ou", ou])
        cmd.extend([sam_account_name, new_password])

        auth_env = self._get_auth_env(kerberos, ccache_path)
        try:
            result = await self.run_command(cmd, timeout=60, env=auth_env)
            combined = result.stdout + result.stderr
            return ToolResult(success=result.returncode == 0,
                              data={"sam_account_name": sam_account_name, "action": "add_user"},
                              raw_output=sanitize_output(combined))
        except ToolError as e:
            return ToolResult(success=False, error=str(e))

    # ── GET Method Handlers ───────────────────────────────────────

    async def get_object(self, host: str, domain: str, target: str,
                         username: Optional[str] = None, password: Optional[str] = None,
                         kerberos: bool = False, ccache_path: Optional[str] = None,
                         dc_ip: Optional[str] = None, secure: bool = False,
                         attr: Optional[str] = None, resolve_sd: bool = False) -> ToolResult:
        """Read LDAP attributes of an AD object."""
        self.logger.info(f"Getting object: {target}")
        cmd = self._build_auth(host, domain, username, password, kerberos, ccache_path, dc_ip, secure)
        cmd.extend(["get", "object"])
        if attr:
            cmd.extend(["--attr", attr])
        if resolve_sd:
            cmd.append("--resolve-sd")
        cmd.append(target)

        auth_env = self._get_auth_env(kerberos, ccache_path)
        try:
            result = await self.run_command(cmd, timeout=120, env=auth_env)
            combined = result.stdout + result.stderr
            return ToolResult(success=result.returncode == 0,
                              data={"target": target, "action": "get_object"},
                              raw_output=sanitize_output(combined))
        except ToolError as e:
            return ToolResult(success=False, error=str(e))

    async def get_children(self, host: str, domain: str,
                           username: Optional[str] = None, password: Optional[str] = None,
                           kerberos: bool = False, ccache_path: Optional[str] = None,
                           dc_ip: Optional[str] = None, secure: bool = False,
                           target: Optional[str] = None, otype: Optional[str] = None,
                           direct: bool = False) -> ToolResult:
        """List child objects of an AD container."""
        self.logger.info(f"Getting children of {target or 'domain root'}")
        cmd = self._build_auth(host, domain, username, password, kerberos, ccache_path, dc_ip, secure)
        cmd.extend(["get", "children"])
        if target:
            cmd.extend(["--target", target])
        if otype:
            cmd.extend(["--otype", otype])
        if direct:
            cmd.append("--direct")

        auth_env = self._get_auth_env(kerberos, ccache_path)
        try:
            result = await self.run_command(cmd, timeout=120, env=auth_env)
            combined = result.stdout + result.stderr
            return ToolResult(success=result.returncode == 0,
                              data={"target": target, "action": "get_children"},
                              raw_output=sanitize_output(combined))
        except ToolError as e:
            return ToolResult(success=False, error=str(e))

    async def get_search(self, host: str, domain: str, filter: str,
                         username: Optional[str] = None, password: Optional[str] = None,
                         kerberos: bool = False, ccache_path: Optional[str] = None,
                         dc_ip: Optional[str] = None, secure: bool = False,
                         base: Optional[str] = None, attr: Optional[str] = None) -> ToolResult:
        """Search AD objects with LDAP filter."""
        self.logger.info(f"LDAP search: {filter}")
        cmd = self._build_auth(host, domain, username, password, kerberos, ccache_path, dc_ip, secure)
        cmd.extend(["get", "search", "--filter", filter])
        if base:
            cmd.extend(["--base", base])
        if attr:
            cmd.extend(["--attr", attr])

        auth_env = self._get_auth_env(kerberos, ccache_path)
        try:
            result = await self.run_command(cmd, timeout=120, env=auth_env)
            combined = result.stdout + result.stderr
            return ToolResult(success=result.returncode == 0,
                              data={"filter": filter, "action": "get_search"},
                              raw_output=sanitize_output(combined))
        except ToolError as e:
            return ToolResult(success=False, error=str(e))

    async def get_writable(self, host: str, domain: str,
                           username: Optional[str] = None, password: Optional[str] = None,
                           kerberos: bool = False, ccache_path: Optional[str] = None,
                           dc_ip: Optional[str] = None, secure: bool = False,
                           otype: str = "ALL", right: str = "ALL",
                           detail: bool = False) -> ToolResult:
        """Find AD objects writable by the current user."""
        self.logger.info(f"Finding writable objects (type={otype}, right={right})")
        cmd = self._build_auth(host, domain, username, password, kerberos, ccache_path, dc_ip, secure)
        cmd.extend(["get", "writable"])
        if otype != "ALL":
            cmd.extend(["--otype", otype])
        if right != "ALL":
            cmd.extend(["--right", right])
        if detail:
            cmd.append("--detail")

        auth_env = self._get_auth_env(kerberos, ccache_path)
        try:
            result = await self.run_command(cmd, timeout=300, env=auth_env)
            combined = result.stdout + result.stderr
            return ToolResult(success=result.returncode == 0,
                              data={"otype": otype, "right": right, "action": "get_writable"},
                              raw_output=sanitize_output(combined))
        except ToolError as e:
            return ToolResult(success=False, error=str(e))

    async def get_membership(self, host: str, domain: str, target: str,
                             username: Optional[str] = None, password: Optional[str] = None,
                             kerberos: bool = False, ccache_path: Optional[str] = None,
                             dc_ip: Optional[str] = None, secure: bool = False,
                             no_recurse: bool = False) -> ToolResult:
        """Retrieve all groups a target belongs to."""
        self.logger.info(f"Getting membership for {target}")
        cmd = self._build_auth(host, domain, username, password, kerberos, ccache_path, dc_ip, secure)
        cmd.extend(["get", "membership"])
        if no_recurse:
            cmd.append("--no-recurse")
        cmd.append(target)

        auth_env = self._get_auth_env(kerberos, ccache_path)
        try:
            result = await self.run_command(cmd, timeout=120, env=auth_env)
            combined = result.stdout + result.stderr
            return ToolResult(success=result.returncode == 0,
                              data={"target": target, "action": "get_membership"},
                              raw_output=sanitize_output(combined))
        except ToolError as e:
            return ToolResult(success=False, error=str(e))

    async def get_dnsdump(self, host: str, domain: str,
                          username: Optional[str] = None, password: Optional[str] = None,
                          kerberos: bool = False, ccache_path: Optional[str] = None,
                          dc_ip: Optional[str] = None, secure: bool = False) -> ToolResult:
        """Dump all DNS records from the AD-integrated DNS zone."""
        self.logger.info("Dumping DNS records")
        cmd = self._build_auth(host, domain, username, password, kerberos, ccache_path, dc_ip, secure)
        cmd.extend(["get", "dnsDump"])

        auth_env = self._get_auth_env(kerberos, ccache_path)
        try:
            result = await self.run_command(cmd, timeout=120, env=auth_env)
            combined = result.stdout + result.stderr
            return ToolResult(success=result.returncode == 0,
                              data={"action": "get_dnsdump"},
                              raw_output=sanitize_output(combined))
        except ToolError as e:
            return ToolResult(success=False, error=str(e))

    async def get_trusts(self, host: str, domain: str,
                         username: Optional[str] = None, password: Optional[str] = None,
                         kerberos: bool = False, ccache_path: Optional[str] = None,
                         dc_ip: Optional[str] = None, secure: bool = False) -> ToolResult:
        """Enumerate all AD trust relationships."""
        self.logger.info("Enumerating AD trusts")
        cmd = self._build_auth(host, domain, username, password, kerberos, ccache_path, dc_ip, secure)
        cmd.extend(["get", "trusts"])

        auth_env = self._get_auth_env(kerberos, ccache_path)
        try:
            result = await self.run_command(cmd, timeout=120, env=auth_env)
            combined = result.stdout + result.stderr
            return ToolResult(success=result.returncode == 0,
                              data={"action": "get_trusts"},
                              raw_output=sanitize_output(combined))
        except ToolError as e:
            return ToolResult(success=False, error=str(e))

    # ── REMOVE Method Handlers ────────────────────────────────────

    async def remove_genericall(self, host: str, domain: str, target: str, trustee: str,
                                username: Optional[str] = None, password: Optional[str] = None,
                                kerberos: bool = False, ccache_path: Optional[str] = None,
                                dc_ip: Optional[str] = None, secure: bool = False) -> ToolResult:
        """Remove GenericAll ACE."""
        self.logger.info(f"Removing GenericAll: {trustee} from {target}")
        cmd = self._build_auth(host, domain, username, password, kerberos, ccache_path, dc_ip, secure)
        cmd.extend(["remove", "genericAll", target, trustee])

        auth_env = self._get_auth_env(kerberos, ccache_path)
        try:
            result = await self.run_command(cmd, timeout=60, env=auth_env)
            combined = result.stdout + result.stderr
            return ToolResult(success=result.returncode == 0,
                              data={"target": target, "trustee": trustee, "action": "remove_genericall"},
                              raw_output=sanitize_output(combined))
        except ToolError as e:
            return ToolResult(success=False, error=str(e))

    async def remove_rbcd(self, host: str, domain: str, target: str, service: str,
                          username: Optional[str] = None, password: Optional[str] = None,
                          kerberos: bool = False, ccache_path: Optional[str] = None,
                          dc_ip: Optional[str] = None, secure: bool = False) -> ToolResult:
        """Remove RBCD delegation."""
        self.logger.info(f"Removing RBCD: {service} from {target}")
        cmd = self._build_auth(host, domain, username, password, kerberos, ccache_path, dc_ip, secure)
        cmd.extend(["remove", "rbcd", target, service])

        auth_env = self._get_auth_env(kerberos, ccache_path)
        try:
            result = await self.run_command(cmd, timeout=60, env=auth_env)
            combined = result.stdout + result.stderr
            return ToolResult(success=result.returncode == 0,
                              data={"target": target, "service": service, "action": "remove_rbcd"},
                              raw_output=sanitize_output(combined))
        except ToolError as e:
            return ToolResult(success=False, error=str(e))

    async def remove_group_member(self, host: str, domain: str, group: str, member: str,
                                  username: Optional[str] = None, password: Optional[str] = None,
                                  kerberos: bool = False, ccache_path: Optional[str] = None,
                                  dc_ip: Optional[str] = None, secure: bool = False) -> ToolResult:
        """Remove member from group."""
        self.logger.info(f"Removing {member} from group {group}")
        cmd = self._build_auth(host, domain, username, password, kerberos, ccache_path, dc_ip, secure)
        cmd.extend(["remove", "groupMember", group, member])

        auth_env = self._get_auth_env(kerberos, ccache_path)
        try:
            result = await self.run_command(cmd, timeout=60, env=auth_env)
            combined = result.stdout + result.stderr
            return ToolResult(success=result.returncode == 0,
                              data={"group": group, "member": member, "action": "remove_group_member"},
                              raw_output=sanitize_output(combined))
        except ToolError as e:
            return ToolResult(success=False, error=str(e))

    async def remove_shadow_credentials(self, host: str, domain: str, target: str,
                                        username: Optional[str] = None, password: Optional[str] = None,
                                        kerberos: bool = False, ccache_path: Optional[str] = None,
                                        dc_ip: Optional[str] = None, secure: bool = False,
                                        key: Optional[str] = None) -> ToolResult:
        """Remove shadow credentials from a target."""
        self.logger.info(f"Removing shadow credentials from {target}")
        cmd = self._build_auth(host, domain, username, password, kerberos, ccache_path, dc_ip, secure)
        cmd.extend(["remove", "shadowCredentials"])
        if key:
            cmd.extend(["--key", key])
        cmd.append(target)

        auth_env = self._get_auth_env(kerberos, ccache_path)
        try:
            result = await self.run_command(cmd, timeout=60, env=auth_env)
            combined = result.stdout + result.stderr
            return ToolResult(success=result.returncode == 0,
                              data={"target": target, "action": "remove_shadow_credentials"},
                              raw_output=sanitize_output(combined))
        except ToolError as e:
            return ToolResult(success=False, error=str(e))

    async def remove_dcsync(self, host: str, domain: str, trustee: str,
                            username: Optional[str] = None, password: Optional[str] = None,
                            kerberos: bool = False, ccache_path: Optional[str] = None,
                            dc_ip: Optional[str] = None, secure: bool = False) -> ToolResult:
        """Remove DCSync rights from a principal."""
        self.logger.info(f"Removing DCSync from {trustee}")
        cmd = self._build_auth(host, domain, username, password, kerberos, ccache_path, dc_ip, secure)
        cmd.extend(["remove", "dcsync", trustee])

        auth_env = self._get_auth_env(kerberos, ccache_path)
        try:
            result = await self.run_command(cmd, timeout=60, env=auth_env)
            combined = result.stdout + result.stderr
            return ToolResult(success=result.returncode == 0,
                              data={"trustee": trustee, "action": "remove_dcsync"},
                              raw_output=sanitize_output(combined))
        except ToolError as e:
            return ToolResult(success=False, error=str(e))

    async def remove_uac(self, host: str, domain: str, target: str, flags: List[str],
                         username: Optional[str] = None, password: Optional[str] = None,
                         kerberos: bool = False, ccache_path: Optional[str] = None,
                         dc_ip: Optional[str] = None, secure: bool = False) -> ToolResult:
        """Remove UAC flags from a user/computer object."""
        self.logger.info(f"Removing UAC flags {flags} from {target}")
        cmd = self._build_auth(host, domain, username, password, kerberos, ccache_path, dc_ip, secure)
        cmd.extend(["remove", "uac"])
        for flag in flags:
            cmd.extend(["-f", flag])
        cmd.append(target)

        auth_env = self._get_auth_env(kerberos, ccache_path)
        try:
            result = await self.run_command(cmd, timeout=60, env=auth_env)
            combined = result.stdout + result.stderr
            return ToolResult(success=result.returncode == 0,
                              data={"target": target, "flags": flags, "action": "remove_uac"},
                              raw_output=sanitize_output(combined))
        except ToolError as e:
            return ToolResult(success=False, error=str(e))


if __name__ == "__main__":
    BloodyADServer.main()
