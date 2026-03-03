#!/usr/bin/env python3
"""
OpenSploit MCP Server: amass
Subdomain discovery via OWASP Amass v5.0. Two methods: enum_passive,
enum_active. Discovers subdomains via DNS, certificate logs,
web archives, and API sources.
"""

import os
import tempfile
from typing import List

from mcp_common.base_server import BaseMCPServer, ToolResult
from mcp_common.output_parsers import sanitize_output

AMASS_BIN = "/usr/local/bin/amass"


class AmassServer(BaseMCPServer):
    """MCP server wrapping OWASP Amass subdomain discovery."""

    def __init__(self):
        super().__init__(
            name="amass",
            description="Subdomain discovery via OWASP Amass",
            version="1.0.0",
        )

        self.register_method(
            name="enum_passive",
            description="Passive subdomain enumeration — discovers subdomains from certificate transparency logs, DNS databases, web archives, and search engines without touching the target directly",
            params={
                "domain": {
                    "type": "string",
                    "required": True,
                    "description": "Target domain (e.g., 'example.com'). Must be a valid domain name.",
                },
                "timeout": {
                    "type": "integer",
                    "default": 5,
                    "description": "Timeout in minutes. Default 5. Increase for large domains.",
                },
            },
            handler=self.enum_passive,
        )

        self.register_method(
            name="enum_active",
            description="Active subdomain enumeration — passive sources plus DNS brute-force, zone transfers, and certificate crawling. Touches the target's DNS servers directly.",
            params={
                "domain": {
                    "type": "string",
                    "required": True,
                    "description": "Target domain (e.g., 'example.com').",
                },
                "brute": {
                    "type": "boolean",
                    "default": True,
                    "description": "Enable DNS brute-force with built-in wordlist. Default true.",
                },
                "timeout": {
                    "type": "integer",
                    "default": 10,
                    "description": "Timeout in minutes. Default 10. Active enum takes longer than passive.",
                },
            },
            handler=self.enum_active,
        )

    # ── Helpers ─────────────────────────────────────────────────

    def _parse_text_results(self, stdout: str) -> List[str]:
        """Parse amass stdout — one subdomain per line, skip progress/noise."""
        items = []
        for line in stdout.strip().split("\n"):
            line = line.strip()
            # Skip empty, progress bars, OWASP banner, status lines
            if not line:
                continue
            if line.startswith(("0 ", "1 ", "2 ", "3 ", "4 ", "5 ", "6 ", "7 ", "8 ", "9 ")):
                # Progress bar line: "X / Y [===..."
                if "/" in line and ("[" in line or "]" in line):
                    continue
            if line.startswith((".+++", "+W@", "&@", "8@", "WW", "#@", "o@", ":W@", "+o&")):
                continue
            if line.startswith(("v5.", "OWASP", "In-depth")):
                continue
            if "p/s" in line:  # Progress rate
                continue
            # Valid subdomain: contains at least one dot
            if "." in line and " " not in line:
                items.append(line)
        return list(dict.fromkeys(items))  # Deduplicate preserving order

    async def _run_enum(
        self,
        domain: str,
        active: bool = False,
        brute: bool = False,
        timeout: int = 5,
    ) -> ToolResult:
        """Run amass enum with given parameters."""
        if not domain:
            return ToolResult(success=False, error="No domain specified.")

        # Create output file for text results
        output_file = tempfile.mktemp(dir="/session", prefix="amass_", suffix=".txt")

        cmd = [AMASS_BIN, "enum", "-d", domain, "-o", output_file, "-nocolor", "-timeout", str(timeout)]

        if active:
            cmd.append("-active")
            if brute:
                cmd.append("-brute")

        try:
            # Timeout: minutes * 60 + 120s buffer
            result = await self.run_command(cmd, timeout=timeout * 60 + 120)
            raw = result.stderr  # Progress goes to stderr

            # Parse stdout for subdomains
            subdomains_stdout = self._parse_text_results(result.stdout)

            # Also parse output file if it exists
            subdomains_file = []
            if os.path.exists(output_file):
                with open(output_file, "r") as f:
                    for line in f:
                        line = line.strip()
                        if line and "." in line:
                            subdomains_file.append(line)

            # Merge and deduplicate
            all_subs = list(dict.fromkeys(subdomains_stdout + subdomains_file))

            # Build structured results
            subdomains = [{"name": s, "domain": domain} for s in all_subs]

            return ToolResult(
                success=True,
                data={
                    "domain": domain,
                    "mode": "active" if active else "passive",
                    "subdomains": subdomains[:200],
                    "total_found": len(subdomains),
                    "output_file": output_file if os.path.exists(output_file) else "",
                },
                raw_output=sanitize_output(raw[:3000]),
            )
        except Exception as e:
            error_str = str(e)
            # On timeout, try to return partial results
            if "timeout" in error_str.lower() or "timed out" in error_str.lower():
                partial = []
                if os.path.exists(output_file):
                    with open(output_file, "r") as f:
                        for line in f:
                            line = line.strip()
                            if line and "." in line:
                                partial.append({"name": line, "domain": domain})
                if partial:
                    return ToolResult(
                        success=True,
                        data={
                            "domain": domain,
                            "mode": "active" if active else "passive",
                            "subdomains": partial[:200],
                            "total_found": len(partial),
                            "output_file": output_file if os.path.exists(output_file) else "",
                            "timed_out": True,
                        },
                        raw_output=sanitize_output(error_str[:1000]),
                    )
                # Timed out with no partial results
                return ToolResult(
                    success=True,
                    data={
                        "domain": domain,
                        "mode": "active" if active else "passive",
                        "subdomains": [],
                        "total_found": 0,
                        "output_file": "",
                        "timed_out": True,
                    },
                    raw_output=sanitize_output(error_str[:1000]),
                )
            return ToolResult(success=False, error=error_str, raw_output=sanitize_output(error_str))
        finally:
            # Clean up empty output files
            if os.path.exists(output_file) and os.path.getsize(output_file) == 0:
                os.unlink(output_file)

    # ── Method Handlers ────────────────────────────────────────

    async def enum_passive(
        self,
        domain: str,
        timeout: int = 5,
    ) -> ToolResult:
        """Passive subdomain enumeration."""
        return await self._run_enum(domain=domain, active=False, timeout=timeout)

    async def enum_active(
        self,
        domain: str,
        brute: bool = True,
        timeout: int = 10,
    ) -> ToolResult:
        """Active subdomain enumeration."""
        return await self._run_enum(domain=domain, active=True, brute=brute, timeout=timeout)


if __name__ == "__main__":
    AmassServer.main()
