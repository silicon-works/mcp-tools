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
                "follow_redirects": {
                    "type": "boolean",
                    "default": True,
                    "description": "Follow HTTP redirects (nuclei -fr flag)",
                },
                "headers": {
                    "type": "string",
                    "description": "Custom headers in 'Header:Value' format, comma-separated for multiple (e.g., 'Authorization:Bearer token123,Cookie:session=abc')",
                },
                "proxy": {
                    "type": "string",
                    "description": "HTTP/SOCKS5 proxy URL (e.g., 'socks5://127.0.0.1:1080', 'http://127.0.0.1:8080')",
                },
                "exclude_tags": {
                    "type": "string",
                    "description": "Tags to exclude from scan (comma-separated, e.g., 'dos,fuzz' to skip denial-of-service and fuzzing templates)",
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
                "follow_redirects": {
                    "type": "boolean",
                    "default": True,
                    "description": "Follow HTTP redirects",
                },
                "headers": {
                    "type": "string",
                    "description": "Custom headers in 'Header:Value' format, comma-separated",
                },
                "proxy": {
                    "type": "string",
                    "description": "HTTP/SOCKS5 proxy URL",
                },
                "timeout": {
                    "type": "integer",
                    "default": 300,
                    "description": "Timeout in seconds (nuclei has ~60-90s startup overhead)",
                },
            },
            handler=self.quick_scan,
        )

        self.register_method(
            name="auto_scan",
            description="Automatic scan using Wappalyzer technology detection to select relevant templates",
            params={
                "target": {
                    "type": "string",
                    "required": True,
                    "description": "Target URL",
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
                "follow_redirects": {
                    "type": "boolean",
                    "default": True,
                    "description": "Follow HTTP redirects",
                },
                "headers": {
                    "type": "string",
                    "description": "Custom headers in 'Header:Value' format, comma-separated",
                },
                "timeout": {
                    "type": "integer",
                    "default": 600,
                    "description": "Timeout in seconds",
                },
            },
            handler=self.auto_scan,
        )

        self.register_method(
            name="dast_scan",
            description="Dynamic application security testing (fuzzing) using nuclei's built-in fuzzer",
            params={
                "target": {
                    "type": "string",
                    "required": True,
                    "description": "Target URL to fuzz",
                },
                "aggression": {
                    "type": "string",
                    "enum": ["low", "medium", "high"],
                    "default": "low",
                    "description": "Fuzzing aggression level — controls payload count (low=fewer, high=comprehensive)",
                },
                "headers": {
                    "type": "string",
                    "description": "Custom headers in 'Header:Value' format, comma-separated",
                },
                "follow_redirects": {
                    "type": "boolean",
                    "default": True,
                    "description": "Follow HTTP redirects",
                },
                "proxy": {
                    "type": "string",
                    "description": "HTTP/SOCKS5 proxy URL",
                },
                "rate_limit": {
                    "type": "integer",
                    "default": 100,
                    "description": "Maximum requests per second (lower default for fuzzing)",
                },
                "timeout": {
                    "type": "integer",
                    "default": 600,
                    "description": "Timeout in seconds",
                },
            },
            handler=self.dast_scan,
        )

        self.register_method(
            name="tech_detect",
            description="Detect technologies using nuclei's ~810 tech-tagged templates",
            params={
                "target": {
                    "type": "string",
                    "required": True,
                    "description": "Target URL or IP",
                },
                "timeout": {
                    "type": "integer",
                    "default": 300,
                    "description": "Timeout in seconds (nuclei has ~60s startup overhead for template loading; 810 tech templates need ~2-3 min)",
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

    def _add_common_args(self, args, follow_redirects=True, headers=None, proxy=None):
        """Add common optional args to nuclei command."""
        args.extend(["-duc", "-ni"])  # Disable update check and interactsh to reduce startup
        if follow_redirects:
            args.extend(["-fr"])
        if headers:
            for header in headers.split(","):
                header = header.strip()
                if header:
                    args.extend(["-H", header])
        if proxy:
            args.extend(["-proxy", proxy])

    async def scan(
        self,
        target: str,
        templates: Optional[str] = None,
        tags: Optional[str] = None,
        severity: Optional[str] = None,
        rate_limit: int = 150,
        follow_redirects: bool = True,
        headers: Optional[str] = None,
        proxy: Optional[str] = None,
        exclude_tags: Optional[str] = None,
        timeout: int = 600,
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

        if exclude_tags:
            args.extend(["-etags", exclude_tags])

        self._add_common_args(args, follow_redirects, headers, proxy)

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
        follow_redirects: bool = True,
        headers: Optional[str] = None,
        proxy: Optional[str] = None,
        timeout: int = 300,
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

        self._add_common_args(args, follow_redirects, headers, proxy)

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
        timeout: int = 300,
    ) -> ToolResult:
        """Detect technologies used by target."""
        self.logger.info(f"Detecting technologies on {target}")

        args = [
            "nuclei",
            "-u", target,
            "-jsonl",
            "-silent",
            "-duc",
            "-ni",
            "-tags", "tech",
            "-rate-limit", "200",
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


    async def auto_scan(
        self,
        target: str,
        severity: Optional[str] = None,
        rate_limit: int = 150,
        follow_redirects: bool = True,
        headers: Optional[str] = None,
        timeout: int = 600,
    ) -> ToolResult:
        """Automatic scan with Wappalyzer tech detection."""
        self.logger.info(f"Starting automatic nuclei scan on {target}")

        args = [
            "nuclei",
            "-u", target,
            "-as",
            "-jsonl",
            "-silent",
            "-rate-limit", str(rate_limit),
        ]

        if severity:
            args.extend(["-severity", severity])

        self._add_common_args(args, follow_redirects, headers)

        try:
            result = await self.run_command(args, timeout=timeout)
            findings = self._parse_jsonl_output(result.stdout)

            by_severity = {s: [] for s in self.SEVERITY_LEVELS}
            for finding in findings:
                sev = finding.get("severity", "info").lower()
                if sev in by_severity:
                    by_severity[sev].append(finding)

            return ToolResult(
                success=True,
                data={
                    "target": target,
                    "mode": "automatic",
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

    async def dast_scan(
        self,
        target: str,
        aggression: str = "low",
        headers: Optional[str] = None,
        follow_redirects: bool = True,
        proxy: Optional[str] = None,
        rate_limit: int = 100,
        timeout: int = 600,
    ) -> ToolResult:
        """DAST/fuzzing scan."""
        self.logger.info(f"Starting DAST scan on {target} (aggression: {aggression})")

        args = [
            "nuclei",
            "-u", target,
            "-dast",
            "-jsonl",
            "-silent",
            "-rate-limit", str(rate_limit),
            "-fuzz-aggression", aggression,
        ]

        self._add_common_args(args, follow_redirects, headers, proxy)

        try:
            result = await self.run_command(args, timeout=timeout)
            findings = self._parse_jsonl_output(result.stdout)

            return ToolResult(
                success=True,
                data={
                    "target": target,
                    "mode": "dast",
                    "aggression": aggression,
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


if __name__ == "__main__":
    NucleiServer.main()
