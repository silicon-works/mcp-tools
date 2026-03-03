#!/usr/bin/env python3
"""
OpenSploit MCP Server: prowler
Multi-cloud security auditing via Prowler v5.18. Three methods: scan,
list_checks, scan_service. Supports AWS, Azure, GCP, Kubernetes.
"""

import glob
import json
import os
import re
import shutil
from typing import Any, Dict, List, Optional

from mcp_common.base_server import BaseMCPServer, ToolResult
from mcp_common.output_parsers import sanitize_output

PROWLER_BIN = "prowler"
PROVIDERS = {
    "aws", "azure", "gcp", "kubernetes",
    "m365", "github", "cloudflare", "oraclecloud",
    "openstack", "alibabacloud", "iac", "llm",
    "nhn", "mongodbatlas",
}


class ProwlerServer(BaseMCPServer):
    """MCP server wrapping Prowler cloud security scanner."""

    def __init__(self):
        super().__init__(
            name="prowler",
            description="Multi-cloud security auditing via Prowler",
            version="1.0.0",
        )

        self.register_method(
            name="scan",
            description="Run a Prowler security audit against a cloud provider — full account/subscription scan with optional severity and service filtering",
            params={
                "provider": {
                    "type": "string",
                    "required": True,
                    "description": "Cloud provider to audit: 'aws', 'azure', 'gcp', or 'kubernetes'. Credentials must be configured via environment variables.",
                },
                "severity": {
                    "type": "string",
                    "description": "Comma-separated severity filter (e.g., 'critical,high'). Options: critical, high, medium, low, informational. Default: all severities.",
                },
                "service": {
                    "type": "string",
                    "description": "Comma-separated services to scan (e.g., 's3,iam,ec2'). Default: all services. Use list_checks to see available services.",
                },
                "compliance": {
                    "type": "string",
                    "description": "Compliance framework to audit against (e.g., 'cis_3.0_aws', 'pci_3.2.1_aws'). Use list_checks with filter 'compliance' to see available frameworks.",
                },
                "region": {
                    "type": "string",
                    "description": "Comma-separated regions to scan (e.g., 'us-east-1,eu-west-1'). AWS only. Default: all regions.",
                },
            },
            handler=self.scan,
        )

        self.register_method(
            name="list_checks",
            description="List available Prowler checks, services, or compliance frameworks for a provider — no credentials required",
            params={
                "provider": {
                    "type": "string",
                    "required": True,
                    "description": "Cloud provider: 'aws', 'azure', 'gcp', or 'kubernetes'.",
                },
                "list_type": {
                    "type": "string",
                    "default": "checks",
                    "description": "'checks' (list all security checks), 'services' (list scannable services), or 'compliance' (list compliance frameworks).",
                },
            },
            handler=self.list_checks,
        )

        self.register_method(
            name="scan_service",
            description="Scan a specific cloud service — focused audit on one service (e.g., s3, iam, ec2) for faster results",
            params={
                "provider": {
                    "type": "string",
                    "required": True,
                    "description": "Cloud provider: 'aws', 'azure', 'gcp', or 'kubernetes'.",
                },
                "service": {
                    "type": "string",
                    "required": True,
                    "description": "Service to scan (e.g., 's3', 'iam', 'ec2', 'rds'). Use list_checks with list_type='services' to see available services.",
                },
                "severity": {
                    "type": "string",
                    "description": "Comma-separated severity filter. Options: critical, high, medium, low, informational.",
                },
            },
            handler=self.scan_service,
        )

    # ── Helpers ─────────────────────────────────────────────────

    def _validate_provider(self, provider: str) -> Optional[ToolResult]:
        """Validate provider is supported."""
        if not provider:
            return ToolResult(success=False, error="No provider specified.")
        if provider.lower() not in PROVIDERS:
            return ToolResult(
                success=False,
                error=f"Unsupported provider '{provider}'. Supported: {', '.join(sorted(PROVIDERS))}.",
            )
        return None

    def _parse_ocsf_findings(self, output_dir: str) -> List[Dict[str, Any]]:
        """Parse Prowler JSON-OCSF output files."""
        findings = []
        # Use a set to deduplicate: *.ocsf.json also matches *.json
        json_files = set(glob.glob(os.path.join(output_dir, "*.json")))
        json_files.update(glob.glob(os.path.join(output_dir, "*.ocsf.json")))

        for jf in json_files:
            try:
                with open(jf, "r") as f:
                    content = f.read().strip()
                    if not content:
                        continue
                    # Prowler OCSF output may be one JSON object per line
                    for line in content.split("\n"):
                        line = line.strip()
                        if not line:
                            continue
                        try:
                            finding = json.loads(line)
                            findings.append(finding)
                        except json.JSONDecodeError:
                            continue
            except Exception:
                continue
        return findings

    def _extract_finding_summary(self, finding: Dict) -> Dict[str, Any]:
        """Extract key fields from an OCSF finding."""
        # OCSF format has nested structure
        metadata = finding.get("metadata", {})
        severity_info = finding.get("severity_id", 0)
        severity_map = {0: "UNKNOWN", 1: "INFORMATIONAL", 2: "LOW", 3: "MEDIUM", 4: "HIGH", 5: "CRITICAL"}
        severity = severity_map.get(severity_info, finding.get("severity", "UNKNOWN"))

        return {
            "check_id": metadata.get("product", {}).get("feature", {}).get("uid", ""),
            "check_title": finding.get("finding_info", {}).get("title", finding.get("message", "")),
            "severity": severity,
            "status": finding.get("status", ""),
            "status_detail": finding.get("status_detail", ""),
            "resource": finding.get("resources", [{}])[0].get("uid", "") if finding.get("resources") else "",
            "service": metadata.get("product", {}).get("feature", {}).get("name", ""),
            "region": finding.get("cloud", {}).get("region", ""),
        }

    def _summarize_findings(self, findings: List[Dict]) -> Dict[str, Any]:
        """Create summary counts from findings."""
        summary = {
            "total": len(findings),
            "by_status": {"PASS": 0, "FAIL": 0, "MANUAL": 0, "MUTED": 0},
            "by_severity": {"CRITICAL": 0, "HIGH": 0, "MEDIUM": 0, "LOW": 0, "INFORMATIONAL": 0},
            "failed_by_service": {},
        }
        for f in findings:
            status = f.get("status", "").upper()
            if status in summary["by_status"]:
                summary["by_status"][status] += 1

            severity = f.get("severity", "UNKNOWN").upper()
            if severity in summary["by_severity"]:
                summary["by_severity"][severity] += 1

            # Track failed checks by service
            if status == "FAIL":
                svc = f.get("service", "unknown")
                summary["failed_by_service"][svc] = summary["failed_by_service"].get(svc, 0) + 1

        return summary

    async def _run_scan(
        self,
        provider: str,
        severity: str = "",
        service: str = "",
        compliance: str = "",
        region: str = "",
    ) -> ToolResult:
        """Run a Prowler scan with given parameters."""
        err = self._validate_provider(provider)
        if err:
            return err

        provider = provider.lower()

        # Create unique output directory
        import tempfile
        output_dir = tempfile.mkdtemp(dir="/session", prefix=f"prowler_{provider}_")

        cmd = [
            PROWLER_BIN, provider,
            "--output-formats", "json-ocsf",
            "--output-directory", output_dir,
            "--no-banner",
        ]

        if severity:
            cmd.extend(["--severity", *severity.lower().replace(",", " ").split()])

        if service:
            cmd.extend(["--service", *service.lower().replace(",", " ").split()])

        if compliance:
            cmd.extend(["--compliance", compliance])

        if region and provider == "aws":
            cmd.extend(["--region", *region.replace(",", " ").split()])

        try:
            result = await self.run_command(cmd, timeout=900)
            raw = result.stdout + result.stderr

            # Check for credential / authentication errors
            if result.returncode != 0:
                raw_lower = raw.lower()
                auth_keywords = [
                    "credentials", "expired", "unauthorized",
                    "nocredentialserror", "authentication",
                    "authenticationmethod", "defaultcredentialserror",
                    "setupsessionerror", "invalidkubeconfigfile",
                    "configexception", "service host/port is not set",
                ]
                if any(kw in raw_lower for kw in auth_keywords):
                    return ToolResult(
                        success=False,
                        error=f"Authentication failed for {provider}. Verify credentials are configured via environment variables.",
                        raw_output=sanitize_output(raw[:5000]),
                    )
                return ToolResult(
                    success=False,
                    error=f"Prowler scan failed for {provider}.",
                    raw_output=sanitize_output(raw[:5000]),
                )

            # Parse output files
            raw_findings = self._parse_ocsf_findings(output_dir)
            findings = [self._extract_finding_summary(f) for f in raw_findings]
            summary = self._summarize_findings(findings)

            # Only return failed findings to save context (pass findings are noise)
            failed = [f for f in findings if f.get("status", "").upper() == "FAIL"]

            # Find output file paths for reference
            output_files = glob.glob(os.path.join(output_dir, "*"))

            return ToolResult(
                success=True,
                data={
                    "provider": provider,
                    "findings": failed[:100],  # Cap at 100 failed findings
                    "total_findings": summary["total"],
                    "total_failed": summary["by_status"].get("FAIL", 0),
                    "summary": summary,
                    "output_directory": output_dir,
                    "output_files": output_files,
                },
                raw_output=sanitize_output(raw[:5000]),
            )
        except Exception as e:
            return ToolResult(success=False, error=str(e), raw_output=sanitize_output(str(e)))

    # ── Method Handlers ────────────────────────────────────────

    async def scan(
        self,
        provider: str,
        severity: str = "",
        service: str = "",
        compliance: str = "",
        region: str = "",
    ) -> ToolResult:
        """Run full Prowler security audit."""
        return await self._run_scan(
            provider=provider,
            severity=severity,
            service=service,
            compliance=compliance,
            region=region,
        )

    async def list_checks(
        self,
        provider: str,
        list_type: str = "checks",
    ) -> ToolResult:
        """List available checks, services, or compliance frameworks."""
        err = self._validate_provider(provider)
        if err:
            return err

        provider = provider.lower()
        list_type = list_type.lower() if list_type else "checks"

        # Validate list_type
        valid_list_types = {"checks", "services", "compliance"}
        if list_type not in valid_list_types:
            return ToolResult(
                success=False,
                error=f"Invalid list_type '{list_type}'. Must be one of: {', '.join(sorted(valid_list_types))}.",
            )

        if list_type == "services":
            cmd = [PROWLER_BIN, provider, "--list-services", "--no-banner"]
        elif list_type == "compliance":
            cmd = [PROWLER_BIN, provider, "--list-compliance", "--no-banner"]
        else:
            # Use --list-checks for rich text output (id, title, service, severity)
            cmd = [PROWLER_BIN, provider, "--list-checks", "--no-banner"]

        # ANSI escape code pattern used for stripping color codes from output
        ansi_re = re.compile(r'\x1b\[[0-9;]*m')

        try:
            result = await self.run_command(cmd, timeout=60)
            raw = result.stdout + result.stderr

            if result.returncode != 0:
                return ToolResult(
                    success=False,
                    error=f"Failed to list {list_type} for {provider}.",
                    raw_output=sanitize_output(raw[:5000]),
                )

            if list_type == "checks":
                # Parse text output: [check_id] Title - service [severity]
                clean = ansi_re.sub('', result.stdout)
                check_re = re.compile(r'\[(\S+)\]\s+(.+?)\s+-\s+(\S+)\s+\[(\w+)\]')
                check_list = []
                for match in check_re.finditer(clean):
                    check_list.append({
                        "id": match.group(1),
                        "title": match.group(2).strip(),
                        "service": match.group(3),
                        "severity": match.group(4),
                    })
                return ToolResult(
                    success=True,
                    data={
                        "provider": provider,
                        "list_type": "checks",
                        "checks": check_list[:200],
                        "total_checks": len(check_list),
                    },
                    raw_output="",
                )
            else:
                # Parse YAML-style list output (services and compliance): "- item_name"
                # Strip ANSI codes first
                clean = ansi_re.sub('', result.stdout)
                items = []
                for line in clean.strip().split("\n"):
                    line = line.strip()
                    if line.startswith("- "):
                        items.append(line[2:].strip())
                    elif line and not line.startswith("[") and not line.startswith("Available") and not line.startswith("Prowler") and not line.startswith("There are"):
                        items.append(line)

                return ToolResult(
                    success=True,
                    data={
                        "provider": provider,
                        "list_type": list_type,
                        "items": items[:200],
                        "total": len(items),
                    },
                    raw_output="",
                )
        except Exception as e:
            return ToolResult(success=False, error=str(e))

    async def scan_service(
        self,
        provider: str,
        service: str,
        severity: str = "",
    ) -> ToolResult:
        """Scan a specific cloud service."""
        if not service:
            return ToolResult(success=False, error="No service specified.")
        return await self._run_scan(
            provider=provider,
            severity=severity,
            service=service,
        )


if __name__ == "__main__":
    ProwlerServer.main()
