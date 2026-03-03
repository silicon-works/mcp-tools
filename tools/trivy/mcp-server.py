#!/usr/bin/env python3
"""
OpenSploit MCP Server: trivy
Container, filesystem, and IaC vulnerability scanning via Trivy v0.69.
Five methods: scan_image, scan_filesystem, scan_iac, scan_sbom, list_vulns.
"""

import json
import os
from typing import Any, Dict, List, Optional

from mcp_common.base_server import BaseMCPServer, ToolResult
from mcp_common.output_parsers import sanitize_output

TRIVY_BIN = "/usr/bin/trivy"


class TrivyServer(BaseMCPServer):
    """MCP server wrapping Trivy vulnerability scanner."""

    def __init__(self):
        super().__init__(
            name="trivy",
            description="Container, filesystem, and IaC vulnerability scanning via Trivy",
            version="1.0.0",
        )

        self.register_method(
            name="scan_image",
            description="Scan a Docker image for vulnerabilities — detects CVEs in OS packages and language-specific dependencies",
            params={
                "image": {
                    "type": "string",
                    "required": True,
                    "description": "Docker image to scan (e.g., 'nginx:latest', 'ubuntu:22.04', 'python:3.11-slim'). Must be pullable.",
                },
                "severity": {
                    "type": "string",
                    "default": "UNKNOWN,LOW,MEDIUM,HIGH,CRITICAL",
                    "description": "Comma-separated severity filter (e.g., 'HIGH,CRITICAL' to only show high/critical). Options: UNKNOWN, LOW, MEDIUM, HIGH, CRITICAL.",
                },
            },
            handler=self.scan_image,
        )

        self.register_method(
            name="scan_filesystem",
            description="Scan a local filesystem path for vulnerabilities in installed packages and lock files",
            params={
                "path": {
                    "type": "string",
                    "required": True,
                    "description": "Path to scan (directory under /session/ or /).",
                },
                "severity": {
                    "type": "string",
                    "default": "UNKNOWN,LOW,MEDIUM,HIGH,CRITICAL",
                    "description": "Comma-separated severity filter.",
                },
            },
            handler=self.scan_filesystem,
        )

        self.register_method(
            name="scan_iac",
            description="Scan Infrastructure-as-Code files for misconfigurations — Terraform, Kubernetes YAML, Dockerfile, CloudFormation",
            params={
                "path": {
                    "type": "string",
                    "required": True,
                    "description": "Path to IaC files (directory under /session/).",
                },
            },
            handler=self.scan_iac,
        )

        self.register_method(
            name="scan_sbom",
            description="Generate and scan a Software Bill of Materials (SBOM) for a filesystem path",
            params={
                "path": {
                    "type": "string",
                    "required": True,
                    "description": "Path to scan for SBOM generation.",
                },
            },
            handler=self.scan_sbom,
        )

        self.register_method(
            name="list_vulns",
            description="Quick vulnerability summary for an image — counts by severity level",
            params={
                "image": {
                    "type": "string",
                    "required": True,
                    "description": "Docker image to summarize.",
                },
            },
            handler=self.list_vulns,
        )

    # ── Helpers ─────────────────────────────────────────────────

    def _parse_json_results(self, output: str) -> Dict[str, Any]:
        """Parse Trivy JSON output."""
        try:
            data = json.loads(output)
            return data
        except json.JSONDecodeError:
            return {}

    def _extract_vulns(self, trivy_data: Dict) -> List[Dict]:
        """Extract vulnerability list from Trivy JSON output."""
        vulns = []
        results = trivy_data.get("Results", [])
        for result in results:
            target = result.get("Target", "")
            for vuln in result.get("Vulnerabilities", []):
                vulns.append({
                    "id": vuln.get("VulnerabilityID", ""),
                    "severity": vuln.get("Severity", ""),
                    "package": vuln.get("PkgName", ""),
                    "installed_version": vuln.get("InstalledVersion", ""),
                    "fixed_version": vuln.get("FixedVersion", ""),
                    "title": vuln.get("Title", ""),
                    "target": target,
                })
        return vulns

    def _extract_misconfigs(self, trivy_data: Dict) -> List[Dict]:
        """Extract misconfiguration list from Trivy JSON output."""
        misconfigs = []
        results = trivy_data.get("Results", [])
        for result in results:
            target = result.get("Target", "")
            for mc in result.get("Misconfigurations", []):
                misconfigs.append({
                    "id": mc.get("ID", ""),
                    "severity": mc.get("Severity", ""),
                    "title": mc.get("Title", ""),
                    "description": mc.get("Description", "")[:200],
                    "resolution": mc.get("Resolution", "")[:200],
                    "target": target,
                })
        return misconfigs

    def _severity_summary(self, vulns: List[Dict]) -> Dict[str, int]:
        """Count vulnerabilities by severity."""
        summary = {"CRITICAL": 0, "HIGH": 0, "MEDIUM": 0, "LOW": 0, "UNKNOWN": 0}
        for v in vulns:
            sev = v.get("severity", "UNKNOWN").upper()
            if sev in summary:
                summary[sev] += 1
        return summary

    # ── Method Handlers ────────────────────────────────────────

    async def scan_image(
        self,
        image: str,
        severity: str = "UNKNOWN,LOW,MEDIUM,HIGH,CRITICAL",
    ) -> ToolResult:
        """Scan Docker image for vulnerabilities."""
        if not image:
            return ToolResult(success=False, error="No image specified.")
        severity = severity.upper().strip()

        cmd = [
            TRIVY_BIN, "image",
            "--format", "json",
            "--severity", severity,
            "--skip-db-update",
            image,
        ]

        try:
            result = await self.run_command(cmd, timeout=600)
            raw = result.stdout + result.stderr

            if result.returncode != 0:
                return ToolResult(
                    success=False,
                    error=f"Failed to scan image '{image}'. Verify the image name and that it's accessible.",
                    raw_output=sanitize_output(raw[:5000]),
                )

            trivy_data = self._parse_json_results(result.stdout)
            vulns = self._extract_vulns(trivy_data)
            summary = self._severity_summary(vulns)

            return ToolResult(
                success=True,
                data={
                    "image": image,
                    "vulnerabilities": vulns[:100],  # Cap at 100 for context
                    "total_vulnerabilities": len(vulns),
                    "summary": summary,
                },
                raw_output=sanitize_output(raw[:5000]),
            )
        except Exception as e:
            return ToolResult(success=False, error=str(e), raw_output=sanitize_output(str(e)))

    async def scan_filesystem(
        self,
        path: str,
        severity: str = "UNKNOWN,LOW,MEDIUM,HIGH,CRITICAL",
    ) -> ToolResult:
        """Scan filesystem for vulnerabilities."""
        if not path:
            return ToolResult(success=False, error="No path specified.")
        severity = severity.upper().strip()
        if not os.path.exists(path):
            return ToolResult(success=False, error=f"Path not found: {path}")

        cmd = [
            TRIVY_BIN, "filesystem",
            "--format", "json",
            "--severity", severity,
            "--skip-db-update",
            path,
        ]

        try:
            result = await self.run_command(cmd, timeout=300)
            raw = result.stdout + result.stderr

            if result.returncode != 0:
                return ToolResult(
                    success=False,
                    error=f"Trivy scan failed for '{path}'.",
                    raw_output=sanitize_output(raw[:5000]),
                )

            trivy_data = self._parse_json_results(result.stdout)
            vulns = self._extract_vulns(trivy_data)
            summary = self._severity_summary(vulns)

            return ToolResult(
                success=True,
                data={
                    "path": path,
                    "vulnerabilities": vulns[:100],
                    "total_vulnerabilities": len(vulns),
                    "summary": summary,
                },
                raw_output=sanitize_output(raw[:5000]),
            )
        except Exception as e:
            return ToolResult(success=False, error=str(e), raw_output=sanitize_output(str(e)))

    async def scan_iac(
        self,
        path: str,
    ) -> ToolResult:
        """Scan IaC files for misconfigurations."""
        if not path:
            return ToolResult(success=False, error="No path specified.")
        if not os.path.exists(path):
            return ToolResult(success=False, error=f"Path not found: {path}")

        cmd = [
            TRIVY_BIN, "config",
            "--format", "json",
            path,
        ]

        try:
            result = await self.run_command(cmd, timeout=300)
            raw = result.stdout + result.stderr

            if result.returncode != 0:
                return ToolResult(
                    success=False,
                    error=f"IaC scan failed for '{path}'.",
                    raw_output=sanitize_output(raw[:5000]),
                )

            trivy_data = self._parse_json_results(result.stdout)
            misconfigs = self._extract_misconfigs(trivy_data)
            summary = self._severity_summary(misconfigs)

            return ToolResult(
                success=True,
                data={
                    "path": path,
                    "misconfigurations": misconfigs[:100],
                    "total_misconfigurations": len(misconfigs),
                    "summary": summary,
                },
                raw_output=sanitize_output(raw[:5000]),
            )
        except Exception as e:
            return ToolResult(success=False, error=str(e), raw_output=sanitize_output(str(e)))

    async def scan_sbom(
        self,
        path: str,
    ) -> ToolResult:
        """Generate and scan SBOM for a path."""
        if not path:
            return ToolResult(success=False, error="No path specified.")
        if not os.path.exists(path):
            return ToolResult(success=False, error=f"Path not found: {path}")

        cmd = [
            TRIVY_BIN, "filesystem",
            "--format", "json",
            "--list-all-pkgs",
            "--skip-db-update",
            path,
        ]

        try:
            result = await self.run_command(cmd, timeout=300)
            raw = result.stdout + result.stderr

            if result.returncode != 0:
                return ToolResult(
                    success=False,
                    error=f"SBOM scan failed for '{path}'.",
                    raw_output=sanitize_output(raw[:5000]),
                )

            trivy_data = self._parse_json_results(result.stdout)

            # Extract package list
            packages = []
            results = trivy_data.get("Results", [])
            for r in results:
                for pkg in r.get("Packages", []):
                    packages.append({
                        "name": pkg.get("Name", ""),
                        "version": pkg.get("Version", ""),
                        "type": r.get("Type", ""),
                    })

            vulns = self._extract_vulns(trivy_data)

            return ToolResult(
                success=True,
                data={
                    "path": path,
                    "packages": packages[:200],
                    "total_packages": len(packages),
                    "vulnerabilities": vulns[:50],
                    "total_vulnerabilities": len(vulns),
                },
                raw_output=sanitize_output(raw[:5000]),
            )
        except Exception as e:
            return ToolResult(success=False, error=str(e), raw_output=sanitize_output(str(e)))

    async def list_vulns(
        self,
        image: str,
    ) -> ToolResult:
        """Quick vulnerability summary for an image."""
        if not image:
            return ToolResult(success=False, error="No image specified.")

        cmd = [
            TRIVY_BIN, "image",
            "--format", "json",
            "--skip-db-update",
            image,
        ]

        try:
            result = await self.run_command(cmd, timeout=600)

            if result.returncode != 0:
                raw = result.stdout + result.stderr
                return ToolResult(
                    success=False,
                    error=f"Failed to scan image '{image}'. Verify the image name and that it's accessible.",
                    raw_output=sanitize_output(raw[:5000]),
                )

            trivy_data = self._parse_json_results(result.stdout)
            vulns = self._extract_vulns(trivy_data)
            summary = self._severity_summary(vulns)

            return ToolResult(
                success=True,
                data={
                    "image": image,
                    "summary": summary,
                    "total_vulnerabilities": len(vulns),
                    "top_critical": [v for v in vulns if v['severity'] == 'CRITICAL'][:10],
                },
                raw_output="",
            )
        except Exception as e:
            return ToolResult(success=False, error=str(e))


if __name__ == "__main__":
    TrivyServer.main()
