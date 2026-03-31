#!/usr/bin/env python3
"""
OpenSploit MCP Server: snmp

SNMP enumeration via snmpwalk/snmpbulkwalk/snmpget (net-snmp) and
community string brute-force via onesixtyone.
"""

import asyncio
import re
import tempfile
import os
from typing import Any, Dict, List, Optional

from mcp_common import BaseMCPServer, ToolResult, ToolError, sanitize_output


# Common OID subtrees for targeted walks
COMMON_OIDS = {
    "system": "1.3.6.1.2.1.1",
    "interfaces": "1.3.6.1.2.1.2",
    "ip_addresses": "1.3.6.1.2.1.4.20",
    "routes": "1.3.6.1.2.1.4.21",
    "tcp_connections": "1.3.6.1.2.1.6.13",
    "udp_listeners": "1.3.6.1.2.1.7.5",
    "processes": "1.3.6.1.2.1.25.4",
    "installed_software": "1.3.6.1.2.1.25.6.3",
    "storage": "1.3.6.1.2.1.25.2",
    "users": "1.3.6.1.4.1.77.1.2.25",
}


class SnmpServer(BaseMCPServer):
    """MCP server wrapping net-snmp tools and onesixtyone for SNMP enumeration."""

    def __init__(self):
        super().__init__(
            name="snmp",
            description="SNMP enumeration via snmpwalk/snmpbulkwalk/snmpget and community string brute-force via onesixtyone",
            version="1.0.0",
        )

        self.register_method(
            name="walk",
            description="Perform an SNMP walk to enumerate an OID subtree",
            params={
                "target": {
                    "type": "string",
                    "required": True,
                    "description": "Target hostname or IP address",
                },
                "community": {
                    "type": "string",
                    "default": "public",
                    "description": "SNMP community string (v1/v2c) — default 'public'",
                },
                "version": {
                    "type": "string",
                    "enum": ["1", "2c", "3"],
                    "default": "2c",
                    "description": "SNMP version (1, 2c, or 3)",
                },
                "oid": {
                    "type": "string",
                    "description": "OID subtree to walk (e.g., '1.3.6.1.2.1.1' for system info). Omit for full walk.",
                },
                "oid_name": {
                    "type": "string",
                    "enum": list(COMMON_OIDS.keys()),
                    "description": "Named OID shortcut: system, interfaces, ip_addresses, routes, processes, installed_software, storage, users",
                },
                "port": {
                    "type": "integer",
                    "default": 161,
                    "description": "SNMP port (default 161)",
                },
                "timeout": {
                    "type": "integer",
                    "default": 30,
                    "description": "Timeout in seconds per request",
                },
                "retries": {
                    "type": "integer",
                    "default": 1,
                    "description": "Number of retries per request",
                },
                # SNMPv3 params
                "username": {
                    "type": "string",
                    "description": "SNMPv3 security name (username)",
                },
                "auth_protocol": {
                    "type": "string",
                    "enum": ["MD5", "SHA", "SHA-256", "SHA-512"],
                    "description": "SNMPv3 authentication protocol",
                },
                "auth_passphrase": {
                    "type": "string",
                    "description": "SNMPv3 authentication passphrase",
                },
                "priv_protocol": {
                    "type": "string",
                    "enum": ["DES", "AES", "AES-192", "AES-256"],
                    "description": "SNMPv3 privacy (encryption) protocol",
                },
                "priv_passphrase": {
                    "type": "string",
                    "description": "SNMPv3 privacy passphrase",
                },
                "security_level": {
                    "type": "string",
                    "enum": ["noAuthNoPriv", "authNoPriv", "authPriv"],
                    "description": "SNMPv3 security level",
                },
            },
            handler=self.walk,
        )

        self.register_method(
            name="get",
            description="Get a specific SNMP OID value",
            params={
                "target": {
                    "type": "string",
                    "required": True,
                    "description": "Target hostname or IP address",
                },
                "oid": {
                    "type": "string",
                    "required": True,
                    "description": "OID to query (e.g., '1.3.6.1.2.1.1.1.0' for sysDescr)",
                },
                "community": {
                    "type": "string",
                    "default": "public",
                    "description": "SNMP community string",
                },
                "version": {
                    "type": "string",
                    "enum": ["1", "2c", "3"],
                    "default": "2c",
                    "description": "SNMP version",
                },
                "port": {
                    "type": "integer",
                    "default": 161,
                    "description": "SNMP port",
                },
                "timeout": {
                    "type": "integer",
                    "default": 10,
                    "description": "Timeout in seconds",
                },
            },
            handler=self.get,
        )

        self.register_method(
            name="bulk_walk",
            description="High-performance SNMP bulk walk (v2c/v3 only, faster than walk for large trees)",
            params={
                "target": {
                    "type": "string",
                    "required": True,
                    "description": "Target hostname or IP address",
                },
                "community": {
                    "type": "string",
                    "default": "public",
                    "description": "SNMP community string",
                },
                "oid": {
                    "type": "string",
                    "description": "OID subtree to walk. Omit for full walk.",
                },
                "oid_name": {
                    "type": "string",
                    "enum": list(COMMON_OIDS.keys()),
                    "description": "Named OID shortcut",
                },
                "port": {
                    "type": "integer",
                    "default": 161,
                    "description": "SNMP port",
                },
                "timeout": {
                    "type": "integer",
                    "default": 30,
                    "description": "Timeout in seconds",
                },
                "max_repetitions": {
                    "type": "integer",
                    "default": 25,
                    "description": "Max repetitions per GETBULK request (higher = faster but more memory)",
                },
            },
            handler=self.bulk_walk,
        )

        self.register_method(
            name="brute_community",
            description="Brute-force SNMP community strings using onesixtyone",
            params={
                "target": {
                    "type": "string",
                    "required": True,
                    "description": "Target hostname or IP address",
                },
                "wordlist": {
                    "type": "array",
                    "description": "Custom community strings to try. If omitted, uses built-in list (public, private, community, manager, admin, etc.)",
                },
                "port": {
                    "type": "integer",
                    "default": 161,
                    "description": "SNMP port",
                },
                "wait": {
                    "type": "integer",
                    "default": 10,
                    "description": "Milliseconds between packets (lower = faster but may miss responses)",
                },
            },
            handler=self.brute_community,
        )

    def _parse_snmp_output(self, output: str) -> List[Dict[str, str]]:
        """Parse snmpwalk/snmpbulkwalk output into structured data."""
        results = []
        for line in output.split("\n"):
            line = line.strip()
            if not line or line.startswith("Timeout") or line.startswith("No SNMP"):
                continue

            # Format: OID = TYPE: VALUE
            match = re.match(r"^(.+?)\s*=\s*(.+?):\s*(.*)$", line)
            if match:
                results.append({
                    "oid": match.group(1).strip(),
                    "type": match.group(2).strip(),
                    "value": match.group(3).strip().strip('"'),
                })
            else:
                # Some lines don't have TYPE: prefix
                match2 = re.match(r"^(.+?)\s*=\s*(.*)$", line)
                if match2:
                    results.append({
                        "oid": match2.group(1).strip(),
                        "type": "unknown",
                        "value": match2.group(2).strip().strip('"'),
                    })

        return results

    def _build_snmp_cmd(
        self,
        tool: str,
        target: str,
        version: str = "2c",
        community: str = "public",
        oid: str = None,
        oid_name: str = None,
        port: int = 161,
        timeout: int = 30,
        retries: int = 1,
        username: str = None,
        auth_protocol: str = None,
        auth_passphrase: str = None,
        priv_protocol: str = None,
        priv_passphrase: str = None,
        security_level: str = None,
        max_repetitions: int = None,
    ) -> List[str]:
        """Build an SNMP command with common options."""
        cmd = [tool, "-v", version]

        if version in ("1", "2c"):
            cmd.extend(["-c", community])
        elif version == "3":
            if username:
                cmd.extend(["-u", username])
            if security_level:
                cmd.extend(["-l", security_level])
            if auth_protocol:
                cmd.extend(["-a", auth_protocol])
            if auth_passphrase:
                cmd.extend(["-A", auth_passphrase])
            if priv_protocol:
                cmd.extend(["-x", priv_protocol])
            if priv_passphrase:
                cmd.extend(["-X", priv_passphrase])

        cmd.extend(["-t", str(timeout)])
        cmd.extend(["-r", str(retries)])

        if max_repetitions and tool == "snmpbulkwalk":
            cmd.extend(["-Cr" + str(max_repetitions)])

        # Target with port
        if port != 161:
            cmd.append(f"{target}:{port}")
        else:
            cmd.append(target)

        # OID
        resolved_oid = oid
        if oid_name and oid_name in COMMON_OIDS:
            resolved_oid = COMMON_OIDS[oid_name]
        if resolved_oid:
            cmd.append(resolved_oid)

        return cmd

    async def walk(
        self,
        target: str,
        community: str = "public",
        version: str = "2c",
        oid: str = None,
        oid_name: str = None,
        port: int = 161,
        timeout: int = 30,
        retries: int = 1,
        username: str = None,
        auth_protocol: str = None,
        auth_passphrase: str = None,
        priv_protocol: str = None,
        priv_passphrase: str = None,
        security_level: str = None,
    ) -> ToolResult:
        """Perform an SNMP walk."""
        resolved_oid = oid or (COMMON_OIDS.get(oid_name) if oid_name else None)
        self.logger.info(f"SNMP walk: {target} community={community} version={version} oid={resolved_oid or 'full'}")

        cmd = self._build_snmp_cmd(
            "snmpwalk", target, version, community, oid, oid_name,
            port, timeout, retries, username, auth_protocol,
            auth_passphrase, priv_protocol, priv_passphrase, security_level,
        )

        try:
            result = await self.run_command(cmd, timeout=timeout * 10 + 30)
            stdout = result.stdout.strip() if result.stdout else ""
            stderr = result.stderr.strip() if result.stderr else ""

            if "Timeout" in stdout or "No Response" in stdout:
                return ToolResult(
                    success=False,
                    data={"target": target, "community": community},
                    error=f"SNMP timeout — target not responding or community string incorrect",
                )

            if "No SNMP response" in stderr or result.returncode == 2:
                return ToolResult(
                    success=False,
                    data={"target": target, "community": community},
                    error=f"No SNMP response from {target} — check community string and SNMP version",
                )

            entries = self._parse_snmp_output(stdout)

            return ToolResult(
                success=True,
                data={
                    "target": target,
                    "community": community,
                    "version": version,
                    "oid": resolved_oid or "full tree",
                    "entries": entries,
                    "entry_count": len(entries),
                },
                raw_output=sanitize_output(stdout, max_length=50000),
            )

        except Exception as e:
            return ToolResult(
                success=False,
                data={},
                error=f"SNMP walk failed: {e}",
            )

    async def get(
        self,
        target: str,
        oid: str,
        community: str = "public",
        version: str = "2c",
        port: int = 161,
        timeout: int = 10,
    ) -> ToolResult:
        """Get a specific SNMP OID value."""
        self.logger.info(f"SNMP get: {target} oid={oid}")

        cmd = self._build_snmp_cmd(
            "snmpget", target, version, community, oid=oid,
            port=port, timeout=timeout,
        )

        try:
            result = await self.run_command(cmd, timeout=timeout + 10)
            stdout = result.stdout.strip() if result.stdout else ""
            stderr = result.stderr.strip() if result.stderr else ""

            if "No Such Object" in stdout or "No Such Instance" in stdout:
                return ToolResult(
                    success=False,
                    data={"target": target, "oid": oid},
                    error=f"OID {oid} does not exist on {target}",
                )

            entries = self._parse_snmp_output(stdout)
            entry = entries[0] if entries else {"oid": oid, "type": "unknown", "value": stdout}

            return ToolResult(
                success=True,
                data={
                    "target": target,
                    "oid": oid,
                    "type": entry.get("type", "unknown"),
                    "value": entry.get("value", ""),
                },
                raw_output=stdout,
            )

        except Exception as e:
            return ToolResult(
                success=False,
                data={},
                error=f"SNMP get failed: {e}",
            )

    async def bulk_walk(
        self,
        target: str,
        community: str = "public",
        oid: str = None,
        oid_name: str = None,
        port: int = 161,
        timeout: int = 30,
        max_repetitions: int = 25,
    ) -> ToolResult:
        """High-performance SNMP bulk walk (v2c/v3 only)."""
        resolved_oid = oid or (COMMON_OIDS.get(oid_name) if oid_name else None)
        self.logger.info(f"SNMP bulk walk: {target} oid={resolved_oid or 'full'}")

        cmd = self._build_snmp_cmd(
            "snmpbulkwalk", target, "2c", community, oid, oid_name,
            port, timeout, max_repetitions=max_repetitions,
        )

        try:
            result = await self.run_command(cmd, timeout=timeout * 10 + 30)
            stdout = result.stdout.strip() if result.stdout else ""

            if "Timeout" in stdout or "No Response" in stdout:
                return ToolResult(
                    success=False,
                    data={"target": target, "community": community},
                    error=f"SNMP timeout — target not responding or community string incorrect",
                )

            entries = self._parse_snmp_output(stdout)

            return ToolResult(
                success=True,
                data={
                    "target": target,
                    "community": community,
                    "oid": resolved_oid or "full tree",
                    "entries": entries,
                    "entry_count": len(entries),
                },
                raw_output=sanitize_output(stdout, max_length=50000),
            )

        except Exception as e:
            return ToolResult(
                success=False,
                data={},
                error=f"SNMP bulk walk failed: {e}",
            )

    async def brute_community(
        self,
        target: str,
        wordlist: list = None,
        port: int = 161,
        wait: int = 10,
    ) -> ToolResult:
        """Brute-force SNMP community strings using onesixtyone."""
        self.logger.info(f"SNMP community brute-force: {target}")

        # Write wordlist to temp file
        wordlist_path = "/app/community-strings.txt"
        if wordlist:
            with tempfile.NamedTemporaryFile(
                mode="w", suffix=".txt", delete=False, dir="/tmp"
            ) as f:
                f.write("\n".join(wordlist) + "\n")
                wordlist_path = f.name

        cmd = [
            "onesixtyone",
            "-c", wordlist_path,
            "-w", str(wait),
        ]

        if port != 161:
            cmd.extend(["-p", str(port)])

        cmd.append(target)

        try:
            result = await self.run_command(cmd, timeout=60)
            stdout = result.stdout.strip() if result.stdout else ""
            stderr = result.stderr.strip() if result.stderr else ""

            # Parse onesixtyone output
            # Format: "10.10.10.5 [public] Linux target 5.4.0 ..."
            found = []
            for line in stdout.split("\n"):
                line = line.strip()
                match = re.match(r"^(\S+)\s+\[(.+?)\]\s*(.*)", line)
                if match:
                    found.append({
                        "host": match.group(1),
                        "community": match.group(2),
                        "sysDescr": match.group(3).strip(),
                    })

            return ToolResult(
                success=True,
                data={
                    "target": target,
                    "found": found,
                    "found_count": len(found),
                    "communities": [f["community"] for f in found],
                    "tested_count": len(wordlist) if wordlist else 17,
                },
                raw_output=stdout,
            )

        except Exception as e:
            return ToolResult(
                success=False,
                data={},
                error=f"Community brute-force failed: {e}",
            )
        finally:
            if wordlist and wordlist_path != "/app/community-strings.txt":
                try:
                    os.unlink(wordlist_path)
                except OSError:
                    pass


if __name__ == "__main__":
    SnmpServer.main()
