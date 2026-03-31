#!/usr/bin/env python3
"""
OpenSploit MCP Server: cloudfox

AWS attack path enumeration via Bishop Fox CloudFox.
Cross-service analysis: IAM principals, permissions, role trusts,
env vars, endpoints, instances, and more.
"""

import asyncio
import os
from typing import Any, Dict, List, Optional

from mcp_common import BaseMCPServer, ToolResult, ToolError, sanitize_output

CLOUDFOX_PATH = "cloudfox"

# Available CloudFox AWS subcommands
CLOUDFOX_COMMANDS = [
    "access-keys", "api-gw", "buckets", "cloudformation", "codebuild",
    "databases", "ecr", "ecs-tasks", "eks", "elastic-network-interfaces",
    "endpoints", "env-vars", "filesystems", "iam-simulator", "instances",
    "inventory", "lambda", "network-ports", "orgs",
    "outbound-assumed-roles", "permissions", "pmapper", "principals",
    "ram", "resource-trusts", "role-trusts", "route53", "secrets",
    "sns", "sqs", "tags", "workloads",
]


class CloudfoxServer(BaseMCPServer):
    """MCP server wrapping CloudFox for AWS attack path enumeration."""

    def __init__(self):
        super().__init__(
            name="cloudfox",
            description="AWS attack path enumeration — cross-service analysis of IAM, compute, network, and data",
            version="1.0.0",
        )

        self.register_method(
            name="run",
            description="Run a CloudFox AWS module for attack path analysis",
            params={
                "command": {
                    "type": "string",
                    "required": True,
                    "description": "CloudFox AWS module to run: principals, permissions, role-trusts, env-vars, endpoints, instances, workloads, inventory, access-keys, buckets, databases, lambda, secrets, etc.",
                },
                "profile": {
                    "type": "string",
                    "description": "AWS CLI profile name to use (if configured in ~/.aws/credentials)",
                },
                "access_key_id": {
                    "type": "string",
                    "description": "AWS access key ID (alternative to profile)",
                },
                "secret_access_key": {
                    "type": "string",
                    "description": "AWS secret access key",
                },
                "session_token": {
                    "type": "string",
                    "description": "AWS session token",
                },
                "region": {
                    "type": "string",
                    "default": "us-east-1",
                    "description": "AWS region",
                },
                "output": {
                    "type": "string",
                    "default": "wide",
                    "description": "Output format: 'brief' (summary) or 'wide' (detailed)",
                },
                "verbosity": {
                    "type": "integer",
                    "default": 2,
                    "description": "Verbosity: 1=control only, 2=+module output, 3=+loot files",
                },
                "timeout": {
                    "type": "integer",
                    "default": 300,
                    "description": "Timeout in seconds",
                },
            },
            handler=self.run_module,
        )

        self.register_method(
            name="list_commands",
            description="List all available CloudFox AWS modules",
            params={},
            handler=self.list_commands,
        )

    async def run_module(
        self,
        command: str,
        profile: str = None,
        access_key_id: str = None,
        secret_access_key: str = None,
        session_token: str = None,
        region: str = "us-east-1",
        output: str = "wide",
        verbosity: int = 2,
        timeout: int = 300,
    ) -> ToolResult:
        """Run a CloudFox AWS module."""
        self.logger.info(f"CloudFox: {command}")

        if command not in CLOUDFOX_COMMANDS:
            return ToolResult(
                success=False, data={},
                error=f"Unknown command: {command}. Use list_commands to see available modules.",
            )

        # Set AWS env vars if credentials provided
        env = os.environ.copy()
        if access_key_id:
            env["AWS_ACCESS_KEY_ID"] = access_key_id
        if secret_access_key:
            env["AWS_SECRET_ACCESS_KEY"] = secret_access_key
        if session_token:
            env["AWS_SESSION_TOKEN"] = session_token
        if region:
            env["AWS_DEFAULT_REGION"] = region

        cmd = [CLOUDFOX_PATH, "aws", command]

        if profile:
            cmd.extend(["-p", profile])
        if output:
            cmd.extend(["-o", output])
        if verbosity:
            cmd.extend(["-v", str(verbosity)])

        # Non-interactive mode
        cmd.append("-y")

        try:
            result = await self.run_command(cmd, timeout=timeout)
            stdout = result.stdout.strip() if result.stdout else ""
            stderr = result.stderr.strip() if result.stderr else ""
            combined = f"{stdout}\n{stderr}".strip()

            # Check for errors
            has_error = False
            error_msg = None
            combined_lower = combined.lower()
            if "no valid credential" in combined_lower or "nosuchprofile" in combined_lower:
                has_error = True
                error_msg = "No valid AWS credentials — provide access_key_id/secret_access_key or a valid profile"
            elif "invalidclienttokenid" in combined_lower or "signaturedoesnotmatch" in combined_lower:
                has_error = True
                error_msg = "Invalid AWS credentials"
            elif "accessdenied" in combined_lower:
                has_error = True
                error_msg = "Access denied — insufficient permissions"

            return ToolResult(
                success=not has_error,
                data={
                    "command": command,
                    "region": region,
                },
                raw_output=sanitize_output(combined, max_length=30000),
                error=error_msg,
            )

        except Exception as e:
            return ToolResult(success=False, data={}, error=f"CloudFox failed: {e}")

    async def list_commands(self) -> ToolResult:
        """List available CloudFox AWS modules."""
        descriptions = {
            "access-keys": "Enumerate IAM access keys",
            "buckets": "Enumerate S3 buckets",
            "databases": "Enumerate RDS databases",
            "endpoints": "Enumerate API endpoints from multiple services",
            "env-vars": "Find secrets in environment variables across services",
            "iam-simulator": "Simulate IAM policy evaluation",
            "instances": "Enumerate EC2 instances with IPs, profiles, user-data",
            "inventory": "Quick account size assessment and preferred regions",
            "lambda": "Enumerate Lambda functions",
            "permissions": "Map IAM permissions per principal",
            "principals": "Enumerate IAM users and roles",
            "role-trusts": "Analyze role trust relationships",
            "resource-trusts": "Find cross-account resource trusts",
            "secrets": "Enumerate Secrets Manager and SSM parameters",
            "workloads": "Find workloads with admin or path to admin",
            "outbound-assumed-roles": "Find roles assumed by principals in this account",
        }

        commands = []
        for cmd in CLOUDFOX_COMMANDS:
            commands.append({
                "name": cmd,
                "description": descriptions.get(cmd, f"CloudFox {cmd} module"),
            })

        return ToolResult(
            success=True,
            data={
                "commands": commands,
                "command_count": len(commands),
            },
            raw_output="\n".join(f"{c['name']}: {c['description']}" for c in commands),
        )


if __name__ == "__main__":
    CloudfoxServer.main()
