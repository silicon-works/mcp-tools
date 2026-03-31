#!/usr/bin/env python3
"""
OpenSploit MCP Server: dns

DNS enumeration via dig — zone transfers, reverse lookups, and record queries.
"""

import asyncio
import re
from typing import Any, Dict, List, Optional

from mcp_common import BaseMCPServer, ToolResult, ToolError, sanitize_output


# Record types that dig supports
RECORD_TYPES = [
    "A", "AAAA", "ANY", "CNAME", "DNSKEY", "DS", "HINFO", "MX",
    "NAPTR", "NS", "PTR", "SOA", "SRV", "TLSA", "TXT",
]


class DnsServer(BaseMCPServer):
    """MCP server wrapping dig for DNS enumeration."""

    def __init__(self):
        super().__init__(
            name="dns",
            description="DNS enumeration via dig — zone transfers, reverse lookups, and record queries",
            version="1.0.0",
        )

        self.register_method(
            name="lookup",
            description="Perform a DNS lookup for a specific record type",
            params={
                "target": {
                    "type": "string",
                    "required": True,
                    "description": "Domain name or IP address to query",
                },
                "record_type": {
                    "type": "string",
                    "enum": RECORD_TYPES,
                    "default": "A",
                    "description": "DNS record type to query (A, AAAA, MX, TXT, NS, SOA, SRV, PTR, CNAME, ANY, etc.)",
                },
                "server": {
                    "type": "string",
                    "description": "DNS server to query (e.g., target's DNS for internal records). Omit to use system default.",
                },
                "reverse": {
                    "type": "boolean",
                    "default": False,
                    "description": "Perform reverse DNS lookup (-x flag). When true, target should be an IP address.",
                },
                "short": {
                    "type": "boolean",
                    "default": False,
                    "description": "Return short-form answer only (+short flag)",
                },
                "tcp": {
                    "type": "boolean",
                    "default": False,
                    "description": "Use TCP instead of UDP (+tcp flag)",
                },
                "timeout": {
                    "type": "integer",
                    "default": 10,
                    "description": "Query timeout in seconds",
                },
            },
            handler=self.lookup,
        )

        self.register_method(
            name="zone_transfer",
            description="Attempt a DNS zone transfer (AXFR) to retrieve all records for a domain",
            params={
                "domain": {
                    "type": "string",
                    "required": True,
                    "description": "Domain to attempt zone transfer on (e.g., 'target.htb')",
                },
                "server": {
                    "type": "string",
                    "required": True,
                    "description": "DNS server to query (the authoritative nameserver for the domain)",
                },
                "timeout": {
                    "type": "integer",
                    "default": 30,
                    "description": "Query timeout in seconds",
                },
            },
            handler=self.zone_transfer,
        )

        self.register_method(
            name="enum",
            description="Enumerate all common DNS record types for a domain",
            params={
                "domain": {
                    "type": "string",
                    "required": True,
                    "description": "Domain to enumerate (e.g., 'target.htb')",
                },
                "server": {
                    "type": "string",
                    "description": "DNS server to query. Omit to use system default.",
                },
                "timeout": {
                    "type": "integer",
                    "default": 10,
                    "description": "Timeout per query in seconds",
                },
            },
            handler=self.enum,
        )

    def _parse_dig_answer(self, output: str) -> List[Dict[str, str]]:
        """Parse dig output into structured records from the ANSWER section."""
        records = []
        in_answer = False
        in_authority = False
        in_additional = False

        for line in output.split("\n"):
            line = line.strip()

            if line.startswith(";; ANSWER SECTION:"):
                in_answer = True
                in_authority = False
                in_additional = False
                continue
            elif line.startswith(";; AUTHORITY SECTION:"):
                in_answer = False
                in_authority = True
                in_additional = False
                continue
            elif line.startswith(";; ADDITIONAL SECTION:"):
                in_answer = False
                in_authority = False
                in_additional = True
                continue
            elif line.startswith(";;") or line == "":
                if in_answer or in_authority or in_additional:
                    in_answer = False
                    in_authority = False
                    in_additional = False
                continue

            if in_answer and not line.startswith(";"):
                parts = line.split()
                if len(parts) >= 5:
                    records.append({
                        "name": parts[0],
                        "ttl": parts[1],
                        "class": parts[2],
                        "type": parts[3],
                        "value": " ".join(parts[4:]),
                    })

        return records

    def _parse_zone_transfer(self, output: str) -> List[Dict[str, str]]:
        """Parse AXFR output into structured records."""
        records = []
        for line in output.split("\n"):
            line = line.strip()
            if not line or line.startswith(";") or line.startswith("<<>>"):
                continue

            parts = line.split()
            if len(parts) >= 5:
                records.append({
                    "name": parts[0].rstrip("."),
                    "ttl": parts[1],
                    "class": parts[2],
                    "type": parts[3],
                    "value": " ".join(parts[4:]),
                })

        return records

    def _parse_short(self, output: str) -> List[str]:
        """Parse dig +short output into a list of values."""
        results = []
        for line in output.strip().split("\n"):
            line = line.strip()
            if line and not line.startswith(";") and not line.startswith("<<>>"):
                results.append(line)
        return results

    async def lookup(
        self,
        target: str,
        record_type: str = "A",
        server: str = None,
        reverse: bool = False,
        short: bool = False,
        tcp: bool = False,
        timeout: int = 10,
    ) -> ToolResult:
        """Perform a DNS lookup."""
        self.logger.info(f"DNS lookup: {target} type={record_type} server={server} reverse={reverse}")

        cmd = ["dig"]

        if server:
            cmd.append(f"@{server}")

        if reverse:
            cmd.extend(["-x", target])
        else:
            cmd.append(target)
            cmd.append(record_type)

        if short:
            cmd.append("+short")
        else:
            cmd.append("+noall")
            cmd.append("+answer")
            cmd.append("+authority")
            cmd.append("+comments")
            cmd.append("+stats")

        if tcp:
            cmd.append("+tcp")

        cmd.append(f"+timeout={timeout}")
        cmd.append("+tries=2")

        try:
            result = await self.run_command(cmd, timeout=timeout + 10)
            stdout = result.stdout.strip() if result.stdout else ""
            stderr = result.stderr.strip() if result.stderr else ""

            if result.returncode != 0:
                return ToolResult(
                    success=False,
                    data={},
                    error=f"dig failed (exit {result.returncode}): {stderr or stdout}",
                )

            if short:
                values = self._parse_short(stdout)
                return ToolResult(
                    success=True,
                    data={
                        "target": target,
                        "record_type": "PTR" if reverse else record_type,
                        "values": values,
                        "count": len(values),
                    },
                    raw_output=stdout,
                )

            records = self._parse_dig_answer(stdout)
            return ToolResult(
                success=True,
                data={
                    "target": target,
                    "record_type": "PTR" if reverse else record_type,
                    "server": server or "system default",
                    "records": records,
                    "count": len(records),
                },
                raw_output=stdout,
            )

        except Exception as e:
            return ToolResult(
                success=False,
                data={},
                error=f"DNS lookup failed: {e}",
            )

    async def zone_transfer(
        self,
        domain: str,
        server: str,
        timeout: int = 30,
    ) -> ToolResult:
        """Attempt a DNS zone transfer (AXFR)."""
        self.logger.info(f"Zone transfer: {domain} via {server}")

        cmd = [
            "dig",
            f"@{server}",
            domain,
            "AXFR",
            f"+timeout={timeout}",
            "+tries=1",
        ]

        try:
            result = await self.run_command(cmd, timeout=timeout + 10)
            stdout = result.stdout.strip() if result.stdout else ""
            stderr = result.stderr.strip() if result.stderr else ""

            # Check for transfer failure indicators
            if "; Transfer failed." in stdout or "connection timed out" in stdout:
                return ToolResult(
                    success=False,
                    data={
                        "domain": domain,
                        "server": server,
                        "transfer_allowed": False,
                    },
                    error=f"Zone transfer denied or failed for {domain} via {server}",
                )

            if "XFR size:" not in stdout and not self._parse_zone_transfer(stdout):
                return ToolResult(
                    success=False,
                    data={
                        "domain": domain,
                        "server": server,
                        "transfer_allowed": False,
                    },
                    error=f"Zone transfer returned no records for {domain} via {server}",
                )

            records = self._parse_zone_transfer(stdout)

            # Extract unique hostnames
            hostnames = sorted(set(
                r["name"] for r in records
                if r["name"] != domain.rstrip(".") and r["type"] in ("A", "AAAA", "CNAME")
            ))

            return ToolResult(
                success=True,
                data={
                    "domain": domain,
                    "server": server,
                    "transfer_allowed": True,
                    "records": records,
                    "record_count": len(records),
                    "hostnames": hostnames,
                    "hostname_count": len(hostnames),
                },
                raw_output=stdout,
            )

        except Exception as e:
            return ToolResult(
                success=False,
                data={},
                error=f"Zone transfer failed: {e}",
            )

    async def enum(
        self,
        domain: str,
        server: str = None,
        timeout: int = 10,
    ) -> ToolResult:
        """Enumerate all common DNS record types for a domain."""
        self.logger.info(f"DNS enumeration: {domain} server={server}")

        query_types = ["A", "AAAA", "CNAME", "MX", "NS", "SOA", "TXT", "SRV", "PTR"]
        all_records = {}
        raw_parts = []

        for qtype in query_types:
            cmd = ["dig"]
            if server:
                cmd.append(f"@{server}")
            cmd.extend([domain, qtype, "+short", f"+timeout={timeout}", "+tries=1"])

            try:
                result = await self.run_command(cmd, timeout=timeout + 5)
                stdout = result.stdout.strip() if result.stdout else ""

                if stdout and result.returncode == 0:
                    values = self._parse_short(stdout)
                    if values:
                        all_records[qtype] = values
                        raw_parts.append(f"--- {qtype} ---\n{stdout}")
            except Exception:
                pass

        total = sum(len(v) for v in all_records.values())
        raw_output = "\n\n".join(raw_parts) if raw_parts else "No records found"

        return ToolResult(
            success=True,
            data={
                "domain": domain,
                "server": server or "system default",
                "records": all_records,
                "record_types_found": list(all_records.keys()),
                "total_records": total,
            },
            raw_output=raw_output,
        )


if __name__ == "__main__":
    DnsServer.main()
