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
import zipfile
from typing import Any, Dict, Optional

from mcp_common.base_server import BaseMCPServer, ToolResult
from mcp_common.output_parsers import sanitize_output

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

    # ── Methods ────────────────────────────────────────────

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
        if not password and not hashes and not kerberos and not aes_key:
            return ToolResult(
                success=False,
                error="No credentials provided. Supply password, hashes, aes_key, or kerberos=true.",
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

        try:
            result = await self.run_command(cmd, timeout=timeout)
            combined = result.stdout + result.stderr

            files = self._find_output_files()
            file_summaries = self._summarize_files(files)

            # Extract collection types from output
            collection_types = []
            for s in file_summaries:
                t = s.get("type", "")
                if t and t not in ("unknown", "zip", "zip_error"):
                    collection_types.append(t)

            return ToolResult(
                success=len(files) > 0,
                data={
                    "method": "collect",
                    "domain": domain,
                    "dc_ip": dc_ip,
                    "collection": collection,
                    "files": file_summaries,
                    "file_count": len(files),
                    "collection_types": collection_types,
                },
                raw_output=sanitize_output(combined),
                error="No output files generated — check credentials and connectivity" if not files else None,
            )
        except Exception as e:
            return ToolResult(success=False, error=str(e))

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
        if not password and not hashes and not kerberos and not aes_key:
            return ToolResult(
                success=False,
                error="No credentials provided. Supply password, hashes, aes_key, or kerberos=true.",
            )

        os.makedirs(OUTPUT_DIR, exist_ok=True)

        cmd = self._build_cmd(
            domain=domain, username=username, dc_ip=dc_ip,
            collection="DCOnly",
            password=password, hashes=hashes,
            kerberos=kerberos, aes_key=aes_key, auth_method=auth_method,
            dc_host=dc_host, gc_host=gc_host, use_ldaps=use_ldaps,
            ldap_channel_binding=ldap_channel_binding,
            dns_tcp=dns_tcp, dns_timeout=dns_timeout, workers=workers,
            exclude_dcs=exclude_dcs, zip_output=zip_output,
            computerfile=computerfile,
        )

        try:
            result = await self.run_command(cmd, timeout=timeout)
            combined = result.stdout + result.stderr

            files = self._find_output_files()
            file_summaries = self._summarize_files(files)

            collection_types = []
            for s in file_summaries:
                t = s.get("type", "")
                if t and t not in ("unknown", "zip", "zip_error"):
                    collection_types.append(t)

            return ToolResult(
                success=len(files) > 0,
                data={
                    "method": "collect_stealth",
                    "domain": domain,
                    "dc_ip": dc_ip,
                    "collection": "DCOnly",
                    "files": file_summaries,
                    "file_count": len(files),
                    "collection_types": collection_types,
                },
                raw_output=sanitize_output(combined),
                error="No output files generated — check credentials and connectivity" if not files else None,
            )
        except Exception as e:
            return ToolResult(success=False, error=str(e))


if __name__ == "__main__":
    BloodhoundServer.main()
