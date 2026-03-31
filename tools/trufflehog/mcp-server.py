#!/usr/bin/env python3
"""
OpenSploit MCP Server: trufflehog

Secret and credential discovery via TruffleHog — scans git repos,
filesystems, S3 buckets, and Docker images for leaked credentials.
800+ credential types with auto-verification.
"""

import asyncio
import json
import os
from typing import Any, Dict, List, Optional

from mcp_common import BaseMCPServer, ToolResult, ToolError, sanitize_output


class TrufflehogServer(BaseMCPServer):
    """MCP server wrapping TruffleHog for secret/credential discovery."""

    def __init__(self):
        super().__init__(
            name="trufflehog",
            description="Secret and credential discovery — git repos, filesystems, S3 buckets (800+ types, auto-verification)",
            version="1.0.0",
        )

        _common_params = {
            "json_output": {
                "type": "boolean",
                "default": True,
                "description": "Output in JSON format (structured results)",
            },
            "no_verification": {
                "type": "boolean",
                "default": False,
                "description": "Skip credential verification (faster but no confirmation of validity)",
            },
            "concurrency": {
                "type": "integer",
                "default": 8,
                "description": "Number of concurrent workers",
            },
            "results_filter": {
                "type": "string",
                "enum": ["verified", "unverified", "unknown", "verified,unverified,unknown"],
                "default": "verified,unverified,unknown",
                "description": "Filter results by verification status",
            },
        }

        self.register_method(
            name="scan_git",
            description="Scan a git repository for leaked secrets and credentials",
            params={
                "uri": {
                    "type": "string",
                    "required": True,
                    "description": "Git repository URI — local path (/session/repo) or remote URL (https://github.com/org/repo)",
                },
                **_common_params,
                "branch": {
                    "type": "string",
                    "description": "Specific branch to scan (default: all branches)",
                },
                "max_depth": {
                    "type": "integer",
                    "description": "Maximum commit depth to scan",
                },
                "since_commit": {
                    "type": "string",
                    "description": "Only scan commits after this commit hash",
                },
                "timeout": {
                    "type": "integer",
                    "default": 300,
                    "description": "Scan timeout in seconds",
                },
            },
            handler=self.scan_git,
        )

        self.register_method(
            name="scan_filesystem",
            description="Scan a directory or filesystem for leaked secrets",
            params={
                "path": {
                    "type": "string",
                    "required": True,
                    "description": "Path to scan (e.g., '/session/loot', '/tmp/configs')",
                },
                **_common_params,
                "timeout": {
                    "type": "integer",
                    "default": 300,
                    "description": "Scan timeout in seconds",
                },
            },
            handler=self.scan_filesystem,
        )

        self.register_method(
            name="scan_s3",
            description="Scan an S3 bucket for leaked secrets",
            params={
                "bucket": {
                    "type": "string",
                    "required": True,
                    "description": "S3 bucket name or URI (e.g., 's3://bucket-name')",
                },
                **_common_params,
                "aws_access_key": {
                    "type": "string",
                    "description": "AWS access key ID (for authenticated access)",
                },
                "aws_secret_key": {
                    "type": "string",
                    "description": "AWS secret access key",
                },
                "aws_region": {
                    "type": "string",
                    "default": "us-east-1",
                    "description": "AWS region",
                },
                "timeout": {
                    "type": "integer",
                    "default": 600,
                    "description": "Scan timeout in seconds",
                },
            },
            handler=self.scan_s3,
        )

    def _build_cmd(
        self,
        subcommand: str,
        target: str,
        json_output: bool = True,
        no_verification: bool = False,
        concurrency: int = 8,
        results_filter: str = "verified,unverified,unknown",
        extra_args: list = None,
    ) -> List[str]:
        """Build trufflehog command."""
        cmd = ["trufflehog", subcommand]

        if json_output:
            cmd.append("--json")
        cmd.append("--no-color")
        cmd.append("--no-update")

        if no_verification:
            cmd.append("--no-verification")
        if concurrency != 8:
            cmd.extend(["--concurrency", str(concurrency)])
        if results_filter != "verified,unverified,unknown":
            cmd.extend(["--results", results_filter])

        if extra_args:
            cmd.extend(extra_args)

        cmd.append(target)
        return cmd

    def _parse_json_results(self, output: str) -> List[Dict[str, Any]]:
        """Parse trufflehog JSON output (one JSON object per line)."""
        results = []
        for line in output.split("\n"):
            line = line.strip()
            if not line or not line.startswith("{"):
                continue
            try:
                obj = json.loads(line)
                # Extract key fields
                result = {
                    "detector_type": obj.get("DetectorType", obj.get("SourceMetadata", {}).get("DetectorType", "unknown")),
                    "verified": obj.get("Verified", False),
                    "raw": obj.get("Raw", ""),
                    "redacted": obj.get("Redacted", ""),
                    "source": {},
                }
                # Extract source metadata
                source_meta = obj.get("SourceMetadata", {}).get("Data", {})
                if "Git" in source_meta:
                    git = source_meta["Git"]
                    result["source"] = {
                        "type": "git",
                        "file": git.get("file", ""),
                        "commit": git.get("commit", ""),
                        "email": git.get("email", ""),
                        "repository": git.get("repository", ""),
                        "line": git.get("line", 0),
                    }
                elif "Filesystem" in source_meta:
                    fs = source_meta["Filesystem"]
                    result["source"] = {
                        "type": "filesystem",
                        "file": fs.get("file", ""),
                        "line": fs.get("line", 0),
                    }
                elif "S3" in source_meta:
                    s3 = source_meta["S3"]
                    result["source"] = {
                        "type": "s3",
                        "bucket": s3.get("bucket", ""),
                        "key": s3.get("key", ""),
                    }

                results.append(result)
            except json.JSONDecodeError:
                continue
        return results

    async def scan_git(
        self,
        uri: str,
        json_output: bool = True,
        no_verification: bool = False,
        concurrency: int = 8,
        results_filter: str = "verified,unverified,unknown",
        branch: str = None,
        max_depth: int = None,
        since_commit: str = None,
        timeout: int = 300,
    ) -> ToolResult:
        """Scan a git repository for leaked secrets."""
        self.logger.info(f"TruffleHog git scan: {uri}")

        extra_args = []
        if branch:
            extra_args.extend(["--branch", branch])
        if max_depth:
            extra_args.extend(["--max-depth", str(max_depth)])
        if since_commit:
            extra_args.extend(["--since-commit", since_commit])

        cmd = self._build_cmd(
            "git", uri, json_output, no_verification,
            concurrency, results_filter, extra_args,
        )

        try:
            result = await self.run_command(cmd, timeout=timeout + 30)
            stdout = result.stdout.strip() if result.stdout else ""
            stderr = result.stderr.strip() if result.stderr else ""

            if json_output:
                secrets = self._parse_json_results(stdout)
                verified = [s for s in secrets if s.get("verified")]
                unverified = [s for s in secrets if not s.get("verified")]

                return ToolResult(
                    success=True,
                    data={
                        "uri": uri,
                        "secrets": secrets,
                        "total_found": len(secrets),
                        "verified_count": len(verified),
                        "unverified_count": len(unverified),
                    },
                    raw_output=sanitize_output(stdout, max_length=30000),
                )
            else:
                return ToolResult(
                    success=True,
                    data={"uri": uri},
                    raw_output=sanitize_output(stdout, max_length=30000),
                )

        except Exception as e:
            return ToolResult(success=False, data={}, error=f"Git scan failed: {e}")

    async def scan_filesystem(
        self,
        path: str,
        json_output: bool = True,
        no_verification: bool = False,
        concurrency: int = 8,
        results_filter: str = "verified,unverified,unknown",
        timeout: int = 300,
    ) -> ToolResult:
        """Scan a filesystem directory for leaked secrets."""
        self.logger.info(f"TruffleHog filesystem scan: {path}")

        if not os.path.exists(path):
            return ToolResult(
                success=False, data={},
                error=f"Path does not exist: {path}",
            )

        cmd = self._build_cmd(
            "filesystem", path, json_output, no_verification,
            concurrency, results_filter,
        )

        try:
            result = await self.run_command(cmd, timeout=timeout + 30)
            stdout = result.stdout.strip() if result.stdout else ""

            if json_output:
                secrets = self._parse_json_results(stdout)
                verified = [s for s in secrets if s.get("verified")]

                return ToolResult(
                    success=True,
                    data={
                        "path": path,
                        "secrets": secrets,
                        "total_found": len(secrets),
                        "verified_count": len(verified),
                    },
                    raw_output=sanitize_output(stdout, max_length=30000),
                )
            else:
                return ToolResult(
                    success=True,
                    data={"path": path},
                    raw_output=sanitize_output(stdout, max_length=30000),
                )

        except Exception as e:
            return ToolResult(success=False, data={}, error=f"Filesystem scan failed: {e}")

    async def scan_s3(
        self,
        bucket: str,
        json_output: bool = True,
        no_verification: bool = False,
        concurrency: int = 8,
        results_filter: str = "verified,unverified,unknown",
        aws_access_key: str = None,
        aws_secret_key: str = None,
        aws_region: str = "us-east-1",
        timeout: int = 600,
    ) -> ToolResult:
        """Scan an S3 bucket for leaked secrets."""
        self.logger.info(f"TruffleHog S3 scan: {bucket}")

        # Normalize bucket name
        if not bucket.startswith("s3://"):
            bucket = f"s3://{bucket}"

        extra_args = []
        if aws_access_key:
            extra_args.extend(["--key", aws_access_key])
        if aws_secret_key:
            extra_args.extend(["--secret", aws_secret_key])

        # Set AWS env vars
        env_vars = {}
        if aws_access_key:
            env_vars["AWS_ACCESS_KEY_ID"] = aws_access_key
        if aws_secret_key:
            env_vars["AWS_SECRET_ACCESS_KEY"] = aws_secret_key
        if aws_region:
            env_vars["AWS_DEFAULT_REGION"] = aws_region

        cmd = self._build_cmd(
            "s3", bucket, json_output, no_verification,
            concurrency, results_filter,
        )

        try:
            result = await self.run_command(cmd, timeout=timeout + 30)
            stdout = result.stdout.strip() if result.stdout else ""
            stderr = result.stderr.strip() if result.stderr else ""

            if "error" in stderr.lower() or "denied" in stderr.lower():
                return ToolResult(
                    success=False,
                    data={"bucket": bucket},
                    error=f"S3 scan failed: {stderr}",
                )

            if json_output:
                secrets = self._parse_json_results(stdout)

                return ToolResult(
                    success=True,
                    data={
                        "bucket": bucket,
                        "secrets": secrets,
                        "total_found": len(secrets),
                    },
                    raw_output=sanitize_output(stdout, max_length=30000),
                )
            else:
                return ToolResult(
                    success=True,
                    data={"bucket": bucket},
                    raw_output=sanitize_output(stdout, max_length=30000),
                )

        except Exception as e:
            return ToolResult(success=False, data={}, error=f"S3 scan failed: {e}")


if __name__ == "__main__":
    TrufflehogServer.main()
