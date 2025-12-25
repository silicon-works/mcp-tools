#!/usr/bin/env python3
"""
OpenSploit MCP Server: nuclei

Template-based vulnerability scanner.
"""

import json
from typing import Any, Dict, List, Optional

from mcp_common import BaseMCPServer, ToolResult, ToolError, sanitize_output


class NucleiServer(BaseMCPServer):
    """MCP server wrapping nuclei vulnerability scanner."""

    SEVERITY_LEVELS = ["info", "low", "medium", "high", "critical"]

    def __init__(self):
        super().__init__(
            name="nuclei",
            description="Template-based vulnerability scanner",
            version="1.0.0",
        )

        self.register_method(
            name="scan",
            description="Full scan using nuclei templates (can take several minutes)",
            params={
                "target": {
                    "type": "string",
                    "required": True,
                    "description": "Target URL or IP",
                },
                "templates": {
                    "type": "string",
                    "description": "Specific template or directory (e.g., 'cves/', 'vulnerabilities/')",
                },
                "tags": {
                    "type": "string",
                    "description": "Filter by tags (e.g., 'cve,rce,sqli')",
                },
                "severity": {
                    "type": "string",
                    "description": "Filter by severity (info,low,medium,high,critical)",
                },
                "rate_limit": {
                    "type": "integer",
                    "default": 150,
                    "description": "Maximum requests per second",
                },
                "timeout": {
                    "type": "integer",
                    "default": 600,
                    "description": "Timeout in seconds (default 10 minutes)",
                },
            },
            handler=self.scan,
        )

        self.register_method(
            name="quick_scan",
            description="Quick scan for critical/high severity vulnerabilities only",
            params={
                "target": {
                    "type": "string",
                    "required": True,
                    "description": "Target URL or IP",
                },
                "focus": {
                    "type": "string",
                    "enum": ["cve", "rce", "lfi", "sqli", "xss", "ssrf", "auth-bypass", "default-login"],
                    "default": "cve",
                    "description": "Focus area for quick scan",
                },
                "timeout": {
                    "type": "integer",
                    "default": 120,
                    "description": "Timeout in seconds",
                },
            },
            handler=self.quick_scan,
        )

        self.register_method(
            name="tech_detect",
            description="Detect technologies used by target (fast)",
            params={
                "target": {
                    "type": "string",
                    "required": True,
                    "description": "Target URL or IP",
                },
                "timeout": {
                    "type": "integer",
                    "default": 60,
                    "description": "Timeout in seconds",
                },
            },
            handler=self.tech_detect,
        )

    def _parse_jsonl_output(self, output: str) -> List[Dict[str, Any]]:
        """Parse nuclei JSONL output (one JSON object per line)."""
        findings = []

        for line in output.split("\n"):
            line = line.strip()
            if not line:
                continue

            try:
                finding = json.loads(line)
                findings.append({
                    "template_id": finding.get("template-id", ""),
                    "name": finding.get("info", {}).get("name", ""),
                    "severity": finding.get("info", {}).get("severity", ""),
                    "type": finding.get("type", ""),
                    "host": finding.get("host", ""),
                    "matched_at": finding.get("matched-at", ""),
                    "extracted": finding.get("extracted-results", []),
                    "description": finding.get("info", {}).get("description", ""),
                    "reference": finding.get("info", {}).get("reference", []),
                    "tags": finding.get("info", {}).get("tags", []),
                })
            except json.JSONDecodeError:
                continue

        return findings

    async def scan(
        self,
        target: str,
        templates: Optional[str] = None,
        tags: Optional[str] = None,
        severity: Optional[str] = None,
        rate_limit: int = 150,
        timeout: int = 300,
    ) -> ToolResult:
        """Scan a target using nuclei templates."""
        self.logger.info(f"Starting nuclei scan on {target}")

        args = [
            "nuclei",
            "-u", target,
            "-jsonl",
            "-silent",
            "-rate-limit", str(rate_limit),
        ]

        if templates:
            args.extend(["-t", templates])

        if tags:
            args.extend(["-tags", tags])

        if severity:
            args.extend(["-severity", severity])

        try:
            self.logger.info(f"Running: nuclei -u {target} ...")
            result = await self.run_command(args, timeout=timeout)

            findings = self._parse_jsonl_output(result.stdout)

            # Group by severity
            by_severity = {s: [] for s in self.SEVERITY_LEVELS}
            for finding in findings:
                sev = finding.get("severity", "info").lower()
                if sev in by_severity:
                    by_severity[sev].append(finding)

            return ToolResult(
                success=True,
                data={
                    "target": target,
                    "total_findings": len(findings),
                    "by_severity": {k: len(v) for k, v in by_severity.items()},
                    "findings": findings,
                },
                raw_output=sanitize_output(result.stdout + result.stderr),
            )

        except ToolError as e:
            return ToolResult(
                success=False,
                data={},
                error=str(e),
            )

    async def quick_scan(
        self,
        target: str,
        focus: str = "cve",
        timeout: int = 120,
    ) -> ToolResult:
        """Quick scan for critical/high severity vulnerabilities only."""
        self.logger.info(f"Starting quick nuclei scan on {target} (focus: {focus})")

        args = [
            "nuclei",
            "-u", target,
            "-jsonl",
            "-silent",
            "-rate-limit", "200",
            "-severity", "critical,high",
            "-tags", focus,
        ]

        try:
            result = await self.run_command(args, timeout=timeout)
            findings = self._parse_jsonl_output(result.stdout)

            return ToolResult(
                success=True,
                data={
                    "target": target,
                    "focus": focus,
                    "total_findings": len(findings),
                    "findings": findings,
                },
                raw_output=sanitize_output(result.stdout + result.stderr),
            )

        except ToolError as e:
            return ToolResult(
                success=False,
                data={},
                error=str(e),
            )

    async def tech_detect(
        self,
        target: str,
        timeout: int = 60,
    ) -> ToolResult:
        """Detect technologies used by target."""
        self.logger.info(f"Detecting technologies on {target}")

        args = [
            "nuclei",
            "-u", target,
            "-jsonl",
            "-silent",
            "-tags", "tech",
            "-rate-limit", "100",
        ]

        try:
            result = await self.run_command(args, timeout=timeout)
            findings = self._parse_jsonl_output(result.stdout)

            # Extract technology names
            technologies = []
            for finding in findings:
                tech_name = finding.get("name", "")
                if tech_name and tech_name not in technologies:
                    technologies.append(tech_name)

            return ToolResult(
                success=True,
                data={
                    "target": target,
                    "technologies": technologies,
                    "details": findings,
                },
                raw_output=sanitize_output(result.stdout + result.stderr),
            )

        except ToolError as e:
            return ToolResult(
                success=False,
                data={},
                error=str(e),
            )


if __name__ == "__main__":
    NucleiServer.main()
