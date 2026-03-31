#!/usr/bin/env python3
"""
OpenSploit MCP Server: pacu

AWS exploitation framework via Rhino Security Labs Pacu.
50+ modules for IAM privilege escalation, persistence, enumeration, and evasion.
"""

import asyncio
import json
import os
import re
from typing import Any, Dict, List, Optional

from mcp_common import BaseMCPServer, ToolResult, ToolError, sanitize_output


class PacuServer(BaseMCPServer):
    """MCP server wrapping Pacu for AWS exploitation."""

    def __init__(self):
        super().__init__(
            name="pacu",
            description="AWS exploitation framework — IAM privesc, persistence, enumeration, evasion (50+ modules)",
            version="1.7.0",
        )

        _cred_params = {
            "access_key_id": {
                "type": "string",
                "required": True,
                "description": "AWS access key ID",
            },
            "secret_access_key": {
                "type": "string",
                "required": True,
                "description": "AWS secret access key",
            },
            "session_token": {
                "type": "string",
                "description": "AWS session token (for temporary credentials from STS)",
            },
            "region": {
                "type": "string",
                "default": "us-east-1",
                "description": "AWS region",
            },
        }

        self.register_method(
            name="list_modules",
            description="List all available Pacu modules",
            params={},
            handler=self.list_modules,
        )

        self.register_method(
            name="run_module",
            description="Run a specific Pacu module with given AWS credentials",
            params={
                **_cred_params,
                "module": {
                    "type": "string",
                    "required": True,
                    "description": "Module name (e.g., 'iam__enum_permissions', 'iam__privesc_scan', 'lambda__enum', 's3__enum')",
                },
                "module_args": {
                    "type": "string",
                    "description": "Module arguments as a string (e.g., '--regions us-east-1,us-west-2')",
                },
                "timeout": {
                    "type": "integer",
                    "default": 300,
                    "description": "Module execution timeout in seconds",
                },
            },
            handler=self.run_module,
        )

        self.register_method(
            name="privesc_scan",
            description="Scan for IAM privilege escalation paths (21+ techniques)",
            params={
                **_cred_params,
                "timeout": {
                    "type": "integer",
                    "default": 300,
                    "description": "Scan timeout in seconds",
                },
            },
            handler=self.privesc_scan,
        )

        self.register_method(
            name="whoami",
            description="Identify the current AWS identity and enumerate permissions",
            params=_cred_params,
            handler=self.whoami,
        )

    def _setup_session_cmd(
        self,
        access_key_id: str,
        secret_access_key: str,
        session_token: str = None,
        region: str = "us-east-1",
    ) -> List[str]:
        """Build pacu command with credentials via --exec mode."""
        session_name = f"opensploit-{os.getpid()}"

        # Build key string: alias,access_id,secret_key[,token]
        key_parts = f"opensploit,{access_key_id},{secret_access_key}"
        if session_token:
            key_parts += f",{session_token}"

        return session_name, key_parts

    async def _run_pacu(
        self,
        module: str,
        access_key_id: str,
        secret_access_key: str,
        session_token: str = None,
        region: str = "us-east-1",
        module_args: str = None,
        timeout: int = 300,
    ) -> tuple:
        """Run a pacu module with credentials."""
        session_name, key_parts = self._setup_session_cmd(
            access_key_id, secret_access_key, session_token, region,
        )

        # Set AWS env vars for pacu
        env = os.environ.copy()
        env["AWS_ACCESS_KEY_ID"] = access_key_id
        env["AWS_SECRET_ACCESS_KEY"] = secret_access_key
        if session_token:
            env["AWS_SESSION_TOKEN"] = session_token
        env["AWS_DEFAULT_REGION"] = region

        cmd = [
            "pacu",
            "--new-session", session_name,
            "--set-keys", key_parts,
            "--module-name", module,
            "--exec",
        ]

        if region:
            cmd.extend(["--set-regions", region])

        if module_args:
            cmd.extend(["--module-args", module_args])

        result = await self.run_command(cmd, timeout=timeout)
        stdout = result.stdout.strip() if result.stdout else ""
        stderr = result.stderr.strip() if result.stderr else ""
        return stdout, stderr, result.returncode

    async def list_modules(self) -> ToolResult:
        """List all available Pacu modules."""
        self.logger.info("Listing Pacu modules")

        cmd = ["pacu", "--list-modules"]

        try:
            result = await self.run_command(cmd, timeout=30)
            stdout = result.stdout.strip() if result.stdout else ""
            stderr = result.stderr.strip() if result.stderr else ""
            combined = f"{stdout}\n{stderr}".strip()

            # Parse module list
            modules = []
            for line in combined.split("\n"):
                line = line.strip()
                if line and not line.startswith("No database") and not line.startswith("Database") and not line.startswith("["):
                    # Module lines typically start with the module name
                    if "__" in line or line.startswith("  "):
                        modules.append(line.strip())

            return ToolResult(
                success=True,
                data={
                    "modules": modules,
                    "module_count": len(modules),
                },
                raw_output=sanitize_output(combined, max_length=10000),
            )

        except Exception as e:
            return ToolResult(success=False, data={}, error=f"Failed to list modules: {e}")

    async def run_module(
        self,
        access_key_id: str,
        secret_access_key: str,
        module: str,
        session_token: str = None,
        region: str = "us-east-1",
        module_args: str = None,
        timeout: int = 300,
    ) -> ToolResult:
        """Run a specific Pacu module."""
        self.logger.info(f"Running Pacu module: {module}")

        try:
            stdout, stderr, rc = await self._run_pacu(
                module, access_key_id, secret_access_key,
                session_token, region, module_args, timeout,
            )

            combined = f"{stdout}\n{stderr}".strip()

            # Check for errors
            has_error = False
            error_msg = None
            if "error" in combined.lower() and "credential" in combined.lower():
                has_error = True
                error_msg = "AWS credential error — check access key and secret key"
            elif "InvalidClientTokenId" in combined or "SignatureDoesNotMatch" in combined:
                has_error = True
                error_msg = "Invalid AWS credentials"
            elif "AccessDenied" in combined or "UnauthorizedAccess" in combined:
                has_error = True
                error_msg = "Access denied — insufficient permissions for this module"

            return ToolResult(
                success=not has_error,
                data={
                    "module": module,
                    "region": region,
                },
                raw_output=sanitize_output(combined, max_length=30000),
                error=error_msg,
            )

        except Exception as e:
            return ToolResult(success=False, data={}, error=f"Module execution failed: {e}")

    async def privesc_scan(
        self,
        access_key_id: str,
        secret_access_key: str,
        session_token: str = None,
        region: str = "us-east-1",
        timeout: int = 300,
    ) -> ToolResult:
        """Scan for IAM privilege escalation paths."""
        self.logger.info("Running IAM privesc scan")

        try:
            stdout, stderr, rc = await self._run_pacu(
                "iam__privesc_scan", access_key_id, secret_access_key,
                session_token, region, timeout=timeout,
            )

            combined = f"{stdout}\n{stderr}".strip()

            # Check for privesc paths
            privesc_found = "privilege escalation" in combined.lower() or "privesc" in combined.lower()

            return ToolResult(
                success=True,
                data={
                    "module": "iam__privesc_scan",
                    "privesc_found": privesc_found,
                },
                raw_output=sanitize_output(combined, max_length=30000),
            )

        except Exception as e:
            return ToolResult(success=False, data={}, error=f"Privesc scan failed: {e}")

    async def whoami(
        self,
        access_key_id: str,
        secret_access_key: str,
        session_token: str = None,
        region: str = "us-east-1",
    ) -> ToolResult:
        """Identify current AWS identity."""
        self.logger.info("Running whoami")

        try:
            stdout, stderr, rc = await self._run_pacu(
                "iam__enum_users_roles_policies_groups",
                access_key_id, secret_access_key,
                session_token, region, timeout=60,
            )

            combined = f"{stdout}\n{stderr}".strip()

            return ToolResult(
                success=True,
                data={
                    "module": "whoami",
                },
                raw_output=sanitize_output(combined, max_length=10000),
            )

        except Exception as e:
            return ToolResult(success=False, data={}, error=f"Whoami failed: {e}")


if __name__ == "__main__":
    PacuServer.main()
