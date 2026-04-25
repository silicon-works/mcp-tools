#!/usr/bin/env python3
"""
OpenSploit MCP Server: bloodhound
Active Directory relationship mapping via bloodhound-python ingestor.

Wraps bloodhound-python (pip: bloodhound, CLI: bloodhound-python).
Collection methods: All, Default, DCOnly, Group, LocalAdmin, Session,
Trusts, ObjectProps, ACL, DCOM, RDP, PSRemote, LoggedOn, Container.
"""

import glob
import json
import os
import re
import shutil
import zipfile
from typing import Any, Dict, List, Optional, Tuple

from mcp_common.base_server import BaseMCPServer, ToolResult
from mcp_common.output_parsers import sanitize_output

CONFIG_DIR = "/session/config"

# Output directory inside the container (session mount)
OUTPUT_DIR = "/session"


class BloodhoundServer(BaseMCPServer):
    def __init__(self):
        super().__init__(
            name="bloodhound",
            description="Active Directory relationship mapping and attack path analysis",
            version="1.0.0",
        )

        self.register_method(
            name="collect",
            description="Collect AD data using bloodhound-python with configurable collection methods",
            params=self._collect_params(),
            handler=self.collect,
        )

        self.register_method(
            name="collect_stealth",
            description="Stealth AD collection using DCOnly method — LDAP queries to DC only, no host contact",
            params=self._collect_params(stealth=True),
            handler=self.collect_stealth,
        )

    # ── Parameter Helpers ──────────────────────────────────

    def _auth_params(self) -> Dict[str, Dict[str, Any]]:
        """Common AD authentication parameters (mirrors impacket pattern)."""
        return {
            "domain": {
                "type": "string",
                "required": True,
                "description": "Target AD domain (e.g., 'corp.local')",
            },
            "username": {
                "type": "string",
                "required": True,
                "description": "Username for LDAP bind (e.g., 'admin' or 'admin@corp.local')",
            },
            "password": {
                "type": "string",
                "description": "Password for authentication",
            },
            "hashes": {
                "type": "string",
                "description": "NTLM hash in LM:NT format for pass-the-hash (e.g., 'aad3b435b51404ee:31d6cfe0d16ae931b73c59d7e0c089c0')",
            },
            "kerberos": {
                "type": "boolean",
                "default": False,
                "description": "Use Kerberos authentication via ccache (set KRB5CCNAME env)",
            },
            "aes_key": {
                "type": "string",
                "description": "AES key for Kerberos auth (128 or 256 bit hex string)",
            },
            "auth_method": {
                "type": "enum",
                "values": ["auto", "ntlm", "kerberos"],
                "default": "auto",
                "description": "Force authentication method. 'auto' tries Kerberos then NTLM.",
            },
            "ccache_path": {
                "type": "string",
                "description": "Path to Kerberos ccache file (e.g., /session/credentials/auditor.ccache)",
            },
        }

    def _collect_params(self, stealth: bool = False) -> Dict[str, Dict[str, Any]]:
        """Build parameter dict for collect methods."""
        params = {
            **self._auth_params(),
            "dc_ip": {
                "type": "string",
                "required": True,
                "description": "Domain controller IP address. Used as DNS nameserver (-ns) for name resolution inside the container. The DC hostname is auto-discovered via DNS.",
            },
            "dc_host": {
                "type": "string",
                "description": "DC hostname FQDN (e.g., 'dc01.corp.local'). Optional — if omitted, bloodhound auto-discovers the DC hostname via DNS using dc_ip as nameserver. Only needed if auto-discovery fails.",
            },
        }

        if not stealth:
            params["collection"] = {
                "type": "string",
                "default": "Default",
                "description": "Collection method(s), comma-separated. Presets: 'All' (everything except LoggedOn), 'Default' (Group,LocalAdmin,Session,Trusts), 'DCOnly' (LDAP-only, no host contact). Individual: Group, LocalAdmin, Session, Trusts, ObjectProps, ACL, DCOM, RDP, PSRemote, LoggedOn, Container.",
            }

        params.update({
            "gc_host": {
                "type": "string",
                "description": "Override Global Catalog server (hostname or IP). Needed for multi-domain forest collection. If unset, bloodhound auto-selects.",
            },
            "use_ldaps": {
                "type": "boolean",
                "default": False,
                "description": "Use LDAP over TLS (port 636). Encrypts queries, may bypass some IDS.",
            },
            "ldap_channel_binding": {
                "type": "boolean",
                "default": False,
                "description": "Use LDAP Channel Binding. Forces LDAPS protocol. Required when the DC enforces EPA (Extended Protection for Authentication).",
            },
            "dns_tcp": {
                "type": "boolean",
                "default": True,
                "description": "Use TCP for DNS queries instead of UDP. Enabled by default for reliability in Docker.",
            },
            "dns_timeout": {
                "type": "integer",
                "default": 3,
                "description": "DNS query timeout in seconds (default: 3). Increase if DNS resolution inside Docker is slow.",
            },
            "workers": {
                "type": "integer",
                "default": 10,
                "description": "Number of concurrent worker threads. Reduce to 1 for stealth.",
            },
            "exclude_dcs": {
                "type": "boolean",
                "default": False,
                "description": "Skip domain controllers during computer enumeration. Avoids ATA/ATP detections.",
            },
            "zip_output": {
                "type": "boolean",
                "default": False,
                "description": "Compress output JSON files into a single ZIP archive.",
            },
            "computerfile": {
                "type": "string",
                "description": "Path to file with computer FQDNs to limit enumeration scope (one per line, in /session/).",
            },
            "timeout": {
                "type": "integer",
                "default": 300,
                "description": "Maximum execution time in seconds.",
            },
        })

        return params

    # ── Command Building ──────────────────────────────────

    def _build_cmd(
        self,
        domain: str,
        username: str,
        dc_ip: str,
        collection: str = "Default",
        password: Optional[str] = None,
        hashes: Optional[str] = None,
        kerberos: bool = False,
        aes_key: Optional[str] = None,
        auth_method: str = "auto",
        dc_host: Optional[str] = None,
        gc_host: Optional[str] = None,
        use_ldaps: bool = False,
        ldap_channel_binding: bool = False,
        dns_tcp: bool = True,
        dns_timeout: int = 3,
        workers: int = 10,
        exclude_dcs: bool = False,
        zip_output: bool = False,
        computerfile: Optional[str] = None,
    ) -> list[str]:
        """Build the bloodhound-python CLI command."""
        cmd = [
            "bloodhound-python",
            "-d", domain,
            "-u", username,
            "-c", collection,
            "-ns", dc_ip,
            "-w", str(workers),
            "-op", f"{OUTPUT_DIR}/bh",
            "-v",
        ]
        # -dc requires an FQDN (not IP). If dc_host provided, use it;
        # otherwise let bloodhound auto-discover the DC via DNS (-ns).
        if dc_host:
            cmd.extend(["-dc", dc_host])

        # Authentication
        if password:
            cmd.extend(["-p", password])
        if hashes:
            cmd.extend(["--hashes", hashes])
        if kerberos:
            cmd.append("-k")
        if aes_key:
            cmd.extend(["-aesKey", aes_key])
        if not password and not hashes and not aes_key:
            cmd.append("-no-pass")

        if auth_method != "auto":
            cmd.extend(["--auth-method", auth_method])

        # Collection options
        if gc_host:
            cmd.extend(["-gc", gc_host])
        if use_ldaps:
            cmd.append("--use-ldaps")
        if ldap_channel_binding:
            cmd.append("--ldap-channel-binding")
        if dns_tcp:
            cmd.append("--dns-tcp")
        if dns_timeout != 3:
            cmd.extend(["--dns-timeout", str(dns_timeout)])
        if exclude_dcs:
            cmd.append("--exclude-dcs")
        if zip_output:
            cmd.append("--zip")
        if computerfile:
            cmd.extend(["--computerfile", computerfile])

        return cmd

    def _find_output_files(self) -> list[str]:
        """Find bloodhound output files in /session/."""
        patterns = [
            os.path.join(OUTPUT_DIR, "bh_*.json"),
            os.path.join(OUTPUT_DIR, "bh_*.zip"),
        ]
        files = []
        for pattern in patterns:
            files.extend(sorted(glob.glob(pattern)))
        return files

    def _summarize_files(self, files: list[str]) -> list[Dict[str, Any]]:
        """Summarize each output file (type, count, size)."""
        summaries = []
        for f in files:
            info: Dict[str, Any] = {
                "path": f,
                "filename": os.path.basename(f),
                "size_bytes": os.path.getsize(f),
            }

            if f.endswith(".json"):
                try:
                    with open(f, "r") as fh:
                        data = json.load(fh)
                    meta = data.get("meta", {})
                    info["type"] = meta.get("type", "unknown")
                    info["count"] = meta.get("count", len(data.get("data", [])))
                except (json.JSONDecodeError, OSError):
                    info["type"] = "unknown"
                    info["count"] = 0
            elif f.endswith(".zip"):
                try:
                    with zipfile.ZipFile(f, "r") as zf:
                        info["type"] = "zip"
                        info["count"] = len(zf.namelist())
                        info["contents"] = zf.namelist()
                except zipfile.BadZipFile:
                    info["type"] = "zip_error"
                    info["count"] = 0

            summaries.append(info)
        return summaries

    # ── Error Classification ─────────────────────────────────

    def _classify_bloodhound_error(self, output: str) -> Tuple[str, bool, List[str]]:
        """Classify bloodhound-python errors from combined stdout+stderr.

        Returns (error_class, retryable, suggestions).
        """
        if not output:
            return ("unknown", False, [])

        # --- DNS errors (network) ---
        if "NoNameservers" in output or "All nameservers failed" in output:
            return ("network", True, [
                "Verify dc_ip is correct and reachable from this container",
                "Ensure port 53 (DNS) is open on the target DC",
                "If behind VPN, verify tun0 is up",
            ])

        if "LifetimeTimeout" in output or "DNS operation timed out" in output:
            return ("network", True, [
                "DNS query timed out — increase dns_timeout parameter",
                "Verify dc_ip is reachable (try ping or nmap first)",
                "If behind VPN, verify tun0 is up",
            ])

        # --- Kerberos clock skew ---
        if "KRB_AP_ERR_SKEW" in output or "Clock skew too great" in output:
            return ("config", True, [
                "Clock skew between container and DC is too large (>5min)",
                "Use clock_offset parameter to synchronize (e.g., clock_offset='+5h')",
                "Or sync with: ntpdate <dc_ip>",
            ])

        # --- Kerberos auth failures ---
        if "KDC_ERR_PREAUTH_FAILED" in output or "Pre-authentication information was invalid" in output:
            return ("auth", False, [
                "Kerberos pre-authentication failed — wrong password or hash",
                "Verify credentials are valid for this domain",
            ])

        if "KDC_ERR_C_PRINCIPAL_UNKNOWN" in output:
            return ("auth", False, [
                "Kerberos principal not found — username may be wrong",
                "Try format: username (not username@domain)",
            ])

        # --- LDAP auth failures ---
        if "Could not authenticate to LDAP" in output:
            return ("auth", False, [
                "LDAP bind failed — check username and password",
                "Try auth_method='ntlm' if Kerberos is failing",
                "Verify the account is not locked or disabled",
            ])

        # --- Domain configuration errors ---
        if "Could not find a domain controller" in output:
            return ("config", True, [
                "DNS at dc_ip could not locate a DC for this domain",
                "Verify the domain name is correct (try nmap LDAP scripts to confirm)",
                "Try specifying dc_host manually if DNS auto-discovery fails",
            ])

        if "Specified domain was not found in LDAP" in output:
            # Extract the suggested domain from the error message
            suggestions = [
                "The domain name does not match what LDAP reports",
                "Check the error output for the correct domain name",
            ]
            match = re.search(
                r"LDAP server reports is domain as (\S+)", output
            )
            if match:
                suggestions.append(f"Try using domain='{match.group(1)}' instead")
            return ("config", False, suggestions)

        if "Could not figure out the domain" in output:
            return ("config", False, [
                "Specify the domain manually with the domain parameter",
            ])

        # --- LDAP connection errors ---
        if "LDAPSocketOpenError" in output or "Failed to resolve LDAP server IP" in output:
            return ("network", True, [
                "Cannot connect to LDAP — verify DC is reachable on port 389 (or 636 for LDAPS)",
                "If using LDAPS, ensure use_ldaps=true",
            ])

        if "Connection to LDAP server lost" in output or "LDAPCommunicationError" in output:
            return ("network", True, [
                "LDAP connection dropped mid-collection — may be network instability",
                "Try reducing workers count to decrease connection load",
                "Partial data may have been collected — check output files",
            ])

        if "LDAPSocketReceiveError" in output or "LDAPSocketSendError" in output:
            return ("network", True, [
                "LDAP socket error — connection was interrupted",
                "Retry the collection",
            ])

        return ("unknown", False, [])

    # ── Methods ────────────────────────────────────────────

    async def _run_collection(
        self,
        method_name: str,
        domain: str,
        username: str,
        dc_ip: str,
        collection: str,
        password: Optional[str] = None,
        hashes: Optional[str] = None,
        kerberos: bool = False,
        aes_key: Optional[str] = None,
        auth_method: str = "auto",
        ccache_path: Optional[str] = None,
        dc_host: Optional[str] = None,
        gc_host: Optional[str] = None,
        use_ldaps: bool = False,
        ldap_channel_binding: bool = False,
        dns_tcp: bool = True,
        dns_timeout: int = 3,
        workers: int = 10,
        exclude_dcs: bool = False,
        zip_output: bool = False,
        computerfile: Optional[str] = None,
        timeout: int = 300,
    ) -> ToolResult:
        """Shared collection logic for both collect and collect_stealth."""
        if not password and not hashes and not kerberos and not aes_key:
            return ToolResult(
                success=False,
                error="No credentials provided. Supply password, hashes, aes_key, or kerberos=true.",
                error_class="params",
            )

        # Ensure output directory exists
        os.makedirs(OUTPUT_DIR, exist_ok=True)

        cmd = self._build_cmd(
            domain=domain, username=username, dc_ip=dc_ip,
            collection=collection, password=password, hashes=hashes,
            kerberos=kerberos, aes_key=aes_key, auth_method=auth_method,
            dc_host=dc_host, gc_host=gc_host, use_ldaps=use_ldaps,
            ldap_channel_binding=ldap_channel_binding,
            dns_tcp=dns_tcp, dns_timeout=dns_timeout, workers=workers,
            exclude_dcs=exclude_dcs, zip_output=zip_output,
            computerfile=computerfile,
        )

        # Kerberos env injection
        auth_env = {}
        if kerberos or auth_method == "kerberos":
            shared_krb5 = os.path.join(CONFIG_DIR, "krb5.conf")
            if os.path.exists(shared_krb5) and not os.path.exists("/etc/krb5.conf"):
                shutil.copy(shared_krb5, "/etc/krb5.conf")
            if ccache_path and os.path.exists(ccache_path):
                auth_env["KRB5CCNAME"] = ccache_path

        try:
            result = await self.run_command_with_progress(cmd, env=auth_env)
            combined = result.stdout + result.stderr

            files = self._find_output_files()
            file_summaries = self._summarize_files(files)

            # Extract collection types from output
            collection_types = []
            for s in file_summaries:
                t = s.get("type", "")
                if t and t not in ("unknown", "zip", "zip_error"):
                    collection_types.append(t)

            # Classify errors when no output files were generated
            error = None
            error_class = None
            retryable = False
            suggestions: List[str] = []
            if not files:
                error_class, retryable, suggestions = self._classify_bloodhound_error(combined)
                error = "No output files generated — check credentials and connectivity"

            return ToolResult(
                success=len(files) > 0,
                data={
                    "method": method_name,
                    "domain": domain,
                    "dc_ip": dc_ip,
                    "collection": collection,
                    "files": file_summaries,
                    "file_count": len(files),
                    "collection_types": collection_types,
                },
                raw_output=sanitize_output(combined),
                error=error,
                error_class=error_class,
                retryable=retryable,
                suggestions=suggestions,
            )
        except Exception as e:
            error_str = str(e)
            error_class, retryable, suggestions = self._classify_bloodhound_error(error_str)
            return ToolResult(
                success=False,
                error=error_str,
                error_class=error_class,
                retryable=retryable,
                suggestions=suggestions,
            )

    async def collect(
        self,
        domain: str,
        username: str,
        dc_ip: str,
        collection: str = "Default",
        password: Optional[str] = None,
        hashes: Optional[str] = None,
        kerberos: bool = False,
        aes_key: Optional[str] = None,
        auth_method: str = "auto",
        ccache_path: Optional[str] = None,
        dc_host: Optional[str] = None,
        gc_host: Optional[str] = None,
        use_ldaps: bool = False,
        ldap_channel_binding: bool = False,
        dns_tcp: bool = True,
        dns_timeout: int = 3,
        workers: int = 10,
        exclude_dcs: bool = False,
        zip_output: bool = False,
        computerfile: Optional[str] = None,
        timeout: int = 300,
    ) -> ToolResult:
        """Collect AD data with configurable collection methods."""
        return await self._run_collection(
            method_name="collect",
            domain=domain, username=username, dc_ip=dc_ip,
            collection=collection, password=password, hashes=hashes,
            kerberos=kerberos, aes_key=aes_key, auth_method=auth_method,
            ccache_path=ccache_path, dc_host=dc_host, gc_host=gc_host,
            use_ldaps=use_ldaps, ldap_channel_binding=ldap_channel_binding,
            dns_tcp=dns_tcp, dns_timeout=dns_timeout, workers=workers,
            exclude_dcs=exclude_dcs, zip_output=zip_output,
            computerfile=computerfile, timeout=timeout,
        )

    async def collect_stealth(
        self,
        domain: str,
        username: str,
        dc_ip: str,
        password: Optional[str] = None,
        hashes: Optional[str] = None,
        kerberos: bool = False,
        aes_key: Optional[str] = None,
        auth_method: str = "auto",
        ccache_path: Optional[str] = None,
        dc_host: Optional[str] = None,
        gc_host: Optional[str] = None,
        use_ldaps: bool = False,
        ldap_channel_binding: bool = False,
        dns_tcp: bool = True,
        dns_timeout: int = 3,
        workers: int = 10,
        exclude_dcs: bool = False,
        zip_output: bool = False,
        computerfile: Optional[str] = None,
        timeout: int = 300,
    ) -> ToolResult:
        """Stealth collection — DCOnly method, LDAP-only, no host contact."""
        return await self._run_collection(
            method_name="collect_stealth",
            domain=domain, username=username, dc_ip=dc_ip,
            collection="DCOnly", password=password, hashes=hashes,
            kerberos=kerberos, aes_key=aes_key, auth_method=auth_method,
            ccache_path=ccache_path, dc_host=dc_host, gc_host=gc_host,
            use_ldaps=use_ldaps, ldap_channel_binding=ldap_channel_binding,
            dns_tcp=dns_tcp, dns_timeout=dns_timeout, workers=workers,
            exclude_dcs=exclude_dcs, zip_output=zip_output,
            computerfile=computerfile, timeout=timeout,
        )


if __name__ == "__main__":
    BloodhoundServer.main()
