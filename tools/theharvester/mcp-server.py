#!/usr/bin/env python3
"""
OpenSploit MCP Server: theharvester
Email and subdomain OSINT via theHarvester v4.10. Two methods: harvest,
list_sources. Gathers emails, subdomains, IPs from 60+ OSINT sources.
"""

import json
import os
import re
import tempfile
from typing import Any, Dict, List, Optional

from mcp_common.base_server import BaseMCPServer, ToolResult
from mcp_common.output_parsers import sanitize_output

HARVESTER_BIN = "theHarvester"


class TheHarvesterServer(BaseMCPServer):
    """MCP server wrapping theHarvester OSINT tool."""

    def __init__(self):
        super().__init__(
            name="theharvester",
            description="Email and subdomain OSINT via theHarvester",
            version="1.0.0",
        )

        self.register_method(
            name="harvest",
            description="Harvest emails, subdomains, IPs, and URLs for a domain from OSINT sources — queries certificate databases, search engines, DNS aggregators, breach databases, and more",
            params={
                "domain": {
                    "type": "string",
                    "required": True,
                    "description": "Target domain (e.g., 'example.com'). Can also be a company name for some sources.",
                },
                "sources": {
                    "type": "string",
                    "default": "crtsh,hackertarget,rapiddns,urlscan,certspotter",
                    "description": "Comma-separated data sources to query. Use 'all' for all available sources (slow). Recommended fast subset: 'crtsh,hackertarget,rapiddns,urlscan,certspotter'. Use list_sources to see all available sources.",
                },
                "limit": {
                    "type": "integer",
                    "default": 500,
                    "description": "Maximum number of results per source. Default 500.",
                },
                "dns_lookup": {
                    "type": "boolean",
                    "default": False,
                    "description": "Perform DNS resolution on discovered hosts. Default false (faster).",
                },
            },
            handler=self.harvest,
        )

        self.register_method(
            name="list_sources",
            description="List all available theHarvester data sources with descriptions",
            params={},
            handler=self.list_sources,
        )

    # ── Helpers ─────────────────────────────────────────────────

    @staticmethod
    def _clean_domain(domain: str) -> str:
        """Strip protocol prefixes and trailing paths from domain input."""
        domain = domain.strip()
        # Remove protocol prefix
        domain = re.sub(r'^https?://', '', domain)
        # Remove trailing path, query string, fragment
        domain = domain.split('/')[0]
        return domain

    @staticmethod
    def _parse_sources_from_output(raw: str) -> List[str]:
        """Parse actually-queried sources from theHarvester stdout.

        Looks for lines like '[*] Searching CRTsh.' and extracts the source
        name, normalising to lowercase for consistency.
        """
        sources = []
        for match in re.finditer(r'\[\*\]\s+Searching\s+(.+?)\.?\s*$', raw, re.MULTILINE):
            name = match.group(1).strip().rstrip('.').lower()
            sources.append(name)
        return sources

    def _parse_json_output(self, output_file: str) -> Dict[str, Any]:
        """Parse theHarvester JSON output file."""
        json_file = output_file + ".json"
        if not os.path.exists(json_file):
            return {}
        try:
            with open(json_file, "r") as f:
                return json.load(f)
        except (json.JSONDecodeError, Exception):
            return {}

    # ── Method Handlers ────────────────────────────────────────

    async def harvest(
        self,
        domain: str,
        sources: str = "crtsh,hackertarget,rapiddns,urlscan,certspotter",
        limit: int = 500,
        dns_lookup: bool = False,
    ) -> ToolResult:
        """Harvest emails, subdomains, and IPs for a domain."""
        if not domain or not domain.strip():
            return ToolResult(success=False, error="No domain specified.")

        # Clean domain: strip protocol prefix, trailing path, whitespace
        domain = self._clean_domain(domain)

        # Create temp output file (theHarvester appends .json and .xml)
        output_base = tempfile.mktemp(dir="/session", prefix="harvester_")

        cmd = [
            HARVESTER_BIN,
            "-d", domain,
            "-b", sources,
            "-l", str(limit),
            "-f", output_base,
        ]

        if dns_lookup:
            cmd.append("-n")

        try:
            result = await self.run_command(cmd, timeout=300)
            raw = result.stdout + result.stderr

            if result.returncode != 0:
                # Check for common errors
                if "No module named" in raw or "import" in raw.lower():
                    return ToolResult(
                        success=False,
                        error="theHarvester dependency error.",
                        raw_output=sanitize_output(raw[:5000]),
                    )
                return ToolResult(
                    success=False,
                    error=f"theHarvester failed for domain '{domain}'.",
                    raw_output=sanitize_output(raw[:5000]),
                )

            # Parse JSON output
            data = self._parse_json_output(output_base)

            emails = data.get("emails", [])
            hosts = data.get("hosts", [])
            ips = data.get("ips", [])
            asns = data.get("asns", [])
            interesting_urls = data.get("interesting_urls", [])

            # Deduplicate
            emails = list(set(emails))
            hosts = list(set(hosts))
            ips = list(set(ips))

            # Parse sources actually queried from theHarvester output
            sources_used = self._parse_sources_from_output(raw)
            if not sources_used:
                # Fallback to input parsing if output parsing finds nothing
                sources_used = [s.strip() for s in sources.split(",") if s.strip()]

            return ToolResult(
                success=True,
                data={
                    "domain": domain,
                    "emails": emails[:100],
                    "total_emails": len(emails),
                    "hosts": hosts[:200],
                    "total_hosts": len(hosts),
                    "ips": ips[:100],
                    "total_ips": len(ips),
                    "asns": asns[:20],
                    "interesting_urls": interesting_urls[:50],
                    "sources_used": sources_used,
                    "output_file": output_base + ".json" if os.path.exists(output_base + ".json") else "",
                },
                raw_output=sanitize_output(raw[:5000]),
            )
        except Exception as e:
            return ToolResult(success=False, error=str(e), raw_output=sanitize_output(str(e)))

    async def list_sources(self) -> ToolResult:
        """List available theHarvester data sources."""
        cmd = [HARVESTER_BIN, "-h"]

        try:
            result = await self.run_command(cmd, timeout=15)
            raw = result.stdout + result.stderr

            # Parse sources from help output
            sources = []
            in_sources = False
            for line in raw.split("\n"):
                # Look for the source list section
                if "source" in line.lower() and (":" in line or "available" in line.lower()):
                    in_sources = True
                    continue
                if in_sources and line.strip():
                    # Sources are typically listed after the -b flag description
                    pass

            # Hardcode known sources since help parsing is fragile
            known_sources = [
                {"name": "baidu", "type": "search_engine", "api_key": False},
                {"name": "bevigil", "type": "threat_intel", "api_key": True},
                {"name": "brave", "type": "search_engine", "api_key": True},
                {"name": "censys", "type": "certificate", "api_key": True},
                {"name": "certspotter", "type": "certificate", "api_key": False},
                {"name": "crtsh", "type": "certificate", "api_key": False},
                {"name": "dnsdumpster", "type": "dns", "api_key": True},
                {"name": "duckduckgo", "type": "search_engine", "api_key": False},
                {"name": "fullhunt", "type": "threat_intel", "api_key": True},
                {"name": "github-code", "type": "code_repo", "api_key": True},
                {"name": "hackertarget", "type": "dns", "api_key": False},
                {"name": "hunter", "type": "email", "api_key": True},
                {"name": "hunterhow", "type": "threat_intel", "api_key": True},
                {"name": "intelx", "type": "threat_intel", "api_key": True},
                {"name": "netlas", "type": "threat_intel", "api_key": True},
                {"name": "onyphe", "type": "threat_intel", "api_key": True},
                {"name": "otx", "type": "threat_intel", "api_key": False},
                {"name": "projectdiscovery", "type": "threat_intel", "api_key": True},
                {"name": "rapiddns", "type": "dns", "api_key": False},
                {"name": "robtex", "type": "dns", "api_key": False},
                {"name": "securitytrails", "type": "dns", "api_key": True},
                {"name": "shodan", "type": "threat_intel", "api_key": True},
                {"name": "subdomaincenter", "type": "dns", "api_key": False},
                {"name": "subdomainfinderc99", "type": "dns", "api_key": True},
                {"name": "urlscan", "type": "threat_intel", "api_key": False},
                {"name": "virustotal", "type": "threat_intel", "api_key": True},
                {"name": "yahoo", "type": "search_engine", "api_key": False},
                {"name": "zoomeye", "type": "threat_intel", "api_key": True},
            ]

            # Filter: only include sources that don't need API keys for free usage
            free_sources = [s["name"] for s in known_sources if not s["api_key"]]

            return ToolResult(
                success=True,
                data={
                    "sources": known_sources,
                    "total_sources": len(known_sources),
                    "free_sources": free_sources,
                    "recommended_free": "crtsh,hackertarget,rapiddns,urlscan,certspotter,otx,robtex",
                },
                raw_output="",
            )
        except Exception as e:
            return ToolResult(success=False, error=str(e))


if __name__ == "__main__":
    TheHarvesterServer.main()
