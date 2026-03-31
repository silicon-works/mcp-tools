#!/usr/bin/env python3
"""
OpenSploit MCP Server: s3scanner

S3 bucket discovery and misconfiguration testing via S3Scanner.
Tests buckets for anonymous access, listing, reading, and writing.
"""

import asyncio
import json
import os
import tempfile
from typing import Any, Dict, List, Optional

from mcp_common import BaseMCPServer, ToolResult, ToolError, sanitize_output


class S3scannerServer(BaseMCPServer):
    """MCP server wrapping S3Scanner for bucket discovery and testing."""

    def __init__(self):
        super().__init__(
            name="s3scanner",
            description="S3 bucket discovery and misconfiguration testing",
            version="3.0.0",
        )

        self.register_method(
            name="scan",
            description="Scan a list of bucket names for existence and misconfigurations",
            params={
                "buckets": {
                    "type": "array",
                    "required": True,
                    "description": "List of bucket names to test (e.g., ['company-backup', 'company-dev', 'company-prod'])",
                },
                "provider": {
                    "type": "string",
                    "enum": ["aws", "gcp", "digitalocean", "dreamhost", "linode"],
                    "default": "aws",
                    "description": "Cloud storage provider",
                },
                "enumerate": {
                    "type": "boolean",
                    "default": False,
                    "description": "Enumerate bucket objects (can be time-consuming for large buckets)",
                },
                "threads": {
                    "type": "integer",
                    "default": 4,
                    "description": "Number of concurrent threads",
                },
                "json_output": {
                    "type": "boolean",
                    "default": True,
                    "description": "Output in JSON format",
                },
            },
            handler=self.scan,
        )

        self.register_method(
            name="test",
            description="Test a single known bucket for misconfigurations",
            params={
                "bucket": {
                    "type": "string",
                    "required": True,
                    "description": "Bucket name to test (e.g., 'company-backup')",
                },
                "provider": {
                    "type": "string",
                    "enum": ["aws", "gcp", "digitalocean", "dreamhost", "linode"],
                    "default": "aws",
                    "description": "Cloud storage provider",
                },
                "enumerate": {
                    "type": "boolean",
                    "default": True,
                    "description": "Enumerate bucket objects",
                },
            },
            handler=self.test,
        )

    def _parse_json_output(self, output: str) -> List[Dict[str, Any]]:
        """Parse s3scanner JSON output."""
        results = []
        for line in output.split("\n"):
            line = line.strip()
            if not line or not line.startswith("{"):
                continue
            try:
                obj = json.loads(line)
                results.append(obj)
            except json.JSONDecodeError:
                continue
        return results

    def _parse_text_output(self, output: str) -> List[Dict[str, Any]]:
        """Parse s3scanner human-readable output."""
        results = []
        for line in output.split("\n"):
            line = line.strip()
            if not line:
                continue
            # S3Scanner text output varies — capture raw lines
            result = {"raw": line}
            if "exists" in line.lower():
                result["exists"] = True
            if "not exist" in line.lower():
                result["exists"] = False
            if "AuthUsers" in line or "AllUsers" in line:
                result["public_access"] = True
            results.append(result)
        return results

    async def scan(
        self,
        buckets: list,
        provider: str = "aws",
        enumerate: bool = False,
        threads: int = 4,
        json_output: bool = True,
    ) -> ToolResult:
        """Scan a list of bucket names."""
        self.logger.info(f"S3 scan: {len(buckets)} buckets, provider={provider}")

        # Write bucket list to temp file
        with tempfile.NamedTemporaryFile(
            mode="w", suffix=".txt", delete=False, dir="/tmp"
        ) as f:
            f.write("\n".join(buckets) + "\n")
            bucket_file = f.name

        cmd = [
            "s3scanner",
            "-bucket-file", bucket_file,
            "-provider", provider,
            "-threads", str(threads),
        ]

        if enumerate:
            cmd.append("-enumerate")
        if json_output:
            cmd.append("-json")

        try:
            result = await self.run_command(cmd, timeout=120)
            stdout = result.stdout.strip() if result.stdout else ""
            stderr = result.stderr.strip() if result.stderr else ""
            combined = f"{stdout}\n{stderr}".strip()

            if json_output:
                parsed = self._parse_json_output(combined)
            else:
                parsed = self._parse_text_output(combined)

            # Categorize results — S3Scanner uses nested bucket.exists (int: 1=yes)
            existing = [r for r in parsed if r.get("bucket", {}).get("exists") == 1]
            public = [r for r in parsed if r.get("bucket", {}).get("perm_all_users_read") == 1]

            return ToolResult(
                success=True,
                data={
                    "buckets_tested": len(buckets),
                    "results": parsed,
                    "existing_count": len(existing),
                    "public_count": len(public),
                },
                raw_output=sanitize_output(combined, max_length=20000),
            )

        except Exception as e:
            return ToolResult(success=False, data={}, error=f"S3 scan failed: {e}")
        finally:
            try:
                os.unlink(bucket_file)
            except OSError:
                pass

    async def test(
        self,
        bucket: str,
        provider: str = "aws",
        enumerate: bool = True,
    ) -> ToolResult:
        """Test a single bucket for misconfigurations."""
        self.logger.info(f"S3 test: {bucket}")

        cmd = [
            "s3scanner",
            "-bucket", bucket,
            "-provider", provider,
            "-json",
        ]

        if enumerate:
            cmd.append("-enumerate")

        try:
            result = await self.run_command(cmd, timeout=60)
            stdout = result.stdout.strip() if result.stdout else ""
            stderr = result.stderr.strip() if result.stderr else ""
            combined = f"{stdout}\n{stderr}".strip()

            parsed = self._parse_json_output(combined)
            bucket_info = parsed[0] if parsed else {}

            # S3Scanner uses nested "bucket" key with exists as integer (1=yes, 0=no)
            bucket_data = bucket_info.get("bucket", bucket_info)
            exists = bucket_data.get("exists", 0) == 1
            objects = bucket_data.get("objects", []) or []

            return ToolResult(
                success=True,
                data={
                    "bucket": bucket,
                    "exists": exists,
                    "info": bucket_info,
                    "object_count": len(objects) if objects else 0,
                },
                raw_output=sanitize_output(combined, max_length=20000),
            )

        except Exception as e:
            return ToolResult(success=False, data={}, error=f"S3 test failed: {e}")


if __name__ == "__main__":
    S3scannerServer.main()
