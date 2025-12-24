#!/usr/bin/env python3
"""
OpenSploit MCP Server: nikto

Web server vulnerability scanner for identifying misconfigurations and outdated software.
"""

import asyncio
import json
import re
from typing import Any, Dict, List, Optional

from mcp_common import BaseMCPServer, ToolResult, ToolError, sanitize_output


class NiktoServer(BaseMCPServer):
    """MCP server wrapping nikto web vulnerability scanner."""

    # Tuning options for nikto
    TUNING_OPTIONS = {
        "1": "Interesting File / Seen in logs",
        "2": "Misconfiguration / Default File",
        "3": "Information Disclosure",
        "4": "Injection (XSS/Script/HTML)",
        "5": "Remote File Retrieval - Inside Web Root",
        "6": "Denial of Service",
        "7": "Remote File Retrieval - Server Wide",
        "8": "Command Execution / Remote Shell",
        "9": "SQL Injection",
        "0": "File Upload",
        "a": "Authentication Bypass",
        "b": "Software Identification",
        "c": "Remote Source Inclusion",
        "x": "Reverse Tuning Options (exclude instead of include)",
    }

    def __init__(self):
        super().__init__(
            name="nikto",
            description="Web server vulnerability scanner for identifying misconfigurations and outdated software",
            version="1.0.0",
        )

        self.register_method(
            name="scan",
            description="Scan a web server for vulnerabilities and misconfigurations",
            params={
                "target": {
                    "type": "string",
                    "required": True,
                    "description": "Target URL or IP:port (e.g., http://10.10.10.1 or 10.10.10.1:80)",
                },
                "tuning": {
                    "type": "string",
                    "description": "Scan tuning options (1-9, a-c, x). E.g., '123' for files, misconfig, info disclosure",
                },
                "ssl": {
                    "type": "boolean",
                    "default": False,
                    "description": "Force SSL/TLS connection",
                },
                "timeout": {
                    "type": "integer",
                    "default": 300,
                    "description": "Scan timeout in seconds",
                },
                "max_time": {
                    "type": "integer",
                    "default": 600,
                    "description": "Maximum scan duration in seconds",
                },
            },
            handler=self.scan,
        )

    def _parse_nikto_output(self, output: str) -> Dict[str, Any]:
        """Parse nikto text output into structured data."""
        findings = []
        server_info = {}

        lines = output.split("\n")

        for line in lines:
            line = line.strip()

            # Skip empty lines and headers
            if not line or line.startswith("-") or line.startswith("="):
                continue

            # Parse server info
            if "+ Server:" in line:
                match = re.search(r"\+ Server: (.+)", line)
                if match:
                    server_info["server"] = match.group(1)

            # Parse target info
            elif "+ Target IP:" in line:
                match = re.search(r"\+ Target IP:\s+(.+)", line)
                if match:
                    server_info["target_ip"] = match.group(1)

            elif "+ Target Hostname:" in line:
                match = re.search(r"\+ Target Hostname:\s+(.+)", line)
                if match:
                    server_info["target_hostname"] = match.group(1)

            elif "+ Target Port:" in line:
                match = re.search(r"\+ Target Port:\s+(.+)", line)
                if match:
                    server_info["target_port"] = match.group(1)

            # Parse findings (lines starting with + that contain useful info)
            elif line.startswith("+") and ":" not in line[:20]:
                # This is likely a finding
                finding_text = line.lstrip("+ ").strip()
                if finding_text and len(finding_text) > 10:
                    finding = {"description": finding_text}

                    # Try to extract OSVDB reference
                    osvdb_match = re.search(r"OSVDB-(\d+)", finding_text)
                    if osvdb_match:
                        finding["osvdb"] = osvdb_match.group(1)

                    # Try to extract path
                    path_match = re.search(r"(/[^\s:]+)", finding_text)
                    if path_match:
                        finding["path"] = path_match.group(1)

                    findings.append(finding)

            # Also catch lines with OSVDB that might be formatted differently
            elif "OSVDB-" in line:
                finding_text = line.lstrip("+ ").strip()
                finding = {"description": finding_text}

                osvdb_match = re.search(r"OSVDB-(\d+)", finding_text)
                if osvdb_match:
                    finding["osvdb"] = osvdb_match.group(1)

                path_match = re.search(r"(/[^\s:]+)", finding_text)
                if path_match:
                    finding["path"] = path_match.group(1)

                findings.append(finding)

        return {
            "server_info": server_info,
            "findings": findings,
            "total_findings": len(findings),
        }

    async def scan(
        self,
        target: str,
        tuning: Optional[str] = None,
        ssl: bool = False,
        timeout: int = 300,
        max_time: int = 600,
    ) -> ToolResult:
        """Scan a web server for vulnerabilities and misconfigurations."""
        self.logger.info(f"Starting nikto scan on {target}")

        # Build command
        args = ["nikto", "-h", target, "-Format", "txt", "-nointeractive"]

        if ssl:
            args.append("-ssl")

        if tuning:
            args.extend(["-Tuning", tuning])

        # Set max time for scan
        args.extend(["-maxtime", f"{max_time}s"])

        try:
            self.logger.info(f"Running: {' '.join(args)}")
            result = await self.run_command(args, timeout=max_time + 60)

            output = result.stdout + result.stderr
            parsed = self._parse_nikto_output(output)

            # Add summary
            parsed["summary"] = {
                "target": target,
                "ssl": ssl,
                "tuning": tuning,
                "findings_count": len(parsed["findings"]),
            }

            return ToolResult(
                success=True,
                data=parsed,
                raw_output=sanitize_output(output),
            )

        except ToolError as e:
            return ToolResult(
                success=False,
                data={},
                error=str(e),
            )


if __name__ == "__main__":
    NiktoServer.main()
