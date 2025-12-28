#!/usr/bin/env python3
"""
OpenSploit MCP Server: enum4linux-ng

SMB/Windows enumeration tool.
"""

import json
import os
import tempfile
from typing import Any, Dict, Optional

from mcp_common import BaseMCPServer, ToolResult, ToolError, sanitize_output


class Enum4linuxServer(BaseMCPServer):
    """MCP server wrapping enum4linux-ng for SMB enumeration."""

    def __init__(self):
        super().__init__(
            name="enum4linux-ng",
            description="SMB/Windows enumeration tool",
            version="1.0.0",
        )

        self.register_method(
            name="enumerate",
            description="Enumerate SMB shares, users, groups, and more from a Windows/Samba target",
            params={
                "target": {
                    "type": "string",
                    "required": True,
                    "description": "Target IP or hostname",
                },
                "username": {
                    "type": "string",
                    "description": "Username for authenticated enumeration",
                },
                "password": {
                    "type": "string",
                    "description": "Password for authenticated enumeration",
                },
                "shares": {
                    "type": "boolean",
                    "default": True,
                    "description": "Enumerate shares",
                },
                "users": {
                    "type": "boolean",
                    "default": True,
                    "description": "Enumerate users via RID cycling",
                },
                "groups": {
                    "type": "boolean",
                    "default": True,
                    "description": "Enumerate groups",
                },
                "timeout": {
                    "type": "integer",
                    "default": 300,
                    "description": "Timeout in seconds",
                },
            },
            handler=self.enumerate,
        )

        self.register_method(
            name="enum_users",
            description="Enumerate users via RID cycling on SMB/Windows target",
            params={
                "target": {
                    "type": "string",
                    "required": True,
                    "description": "Target IP or hostname",
                },
                "username": {
                    "type": "string",
                    "description": "Username for authenticated enumeration",
                },
                "password": {
                    "type": "string",
                    "description": "Password for authenticated enumeration",
                },
                "rid_range": {
                    "type": "string",
                    "default": "500-550,1000-1200",
                    "description": "RID range to enumerate (e.g., '500-550,1000-1200')",
                },
                "timeout": {
                    "type": "integer",
                    "default": 300,
                    "description": "Timeout in seconds",
                },
            },
            handler=self.enum_users,
        )

        self.register_method(
            name="enum_shares",
            description="Enumerate SMB shares and check access permissions",
            params={
                "target": {
                    "type": "string",
                    "required": True,
                    "description": "Target IP or hostname",
                },
                "username": {
                    "type": "string",
                    "description": "Username for authenticated enumeration",
                },
                "password": {
                    "type": "string",
                    "description": "Password for authenticated enumeration",
                },
                "timeout": {
                    "type": "integer",
                    "default": 300,
                    "description": "Timeout in seconds",
                },
            },
            handler=self.enum_shares,
        )

        self.register_method(
            name="enum_groups",
            description="Enumerate groups and their members from SMB/Windows target",
            params={
                "target": {
                    "type": "string",
                    "required": True,
                    "description": "Target IP or hostname",
                },
                "username": {
                    "type": "string",
                    "description": "Username for authenticated enumeration",
                },
                "password": {
                    "type": "string",
                    "description": "Password for authenticated enumeration",
                },
                "timeout": {
                    "type": "integer",
                    "default": 300,
                    "description": "Timeout in seconds",
                },
            },
            handler=self.enum_groups,
        )

        self.register_method(
            name="enum_policy",
            description="Enumerate password policy and domain info",
            params={
                "target": {
                    "type": "string",
                    "required": True,
                    "description": "Target IP or hostname",
                },
                "username": {
                    "type": "string",
                    "description": "Username for authenticated enumeration",
                },
                "password": {
                    "type": "string",
                    "description": "Password for authenticated enumeration",
                },
                "timeout": {
                    "type": "integer",
                    "default": 300,
                    "description": "Timeout in seconds",
                },
            },
            handler=self.enum_policy,
        )

    def _parse_json_output(self, json_file: str) -> Dict[str, Any]:
        """Parse enum4linux-ng JSON output."""
        try:
            with open(json_file, "r") as f:
                return json.load(f)
        except (json.JSONDecodeError, FileNotFoundError):
            return {}

    async def enumerate(
        self,
        target: str,
        username: Optional[str] = None,
        password: Optional[str] = None,
        shares: bool = True,
        users: bool = True,
        groups: bool = True,
        timeout: int = 300,
    ) -> ToolResult:
        """Enumerate SMB shares, users, groups from a target."""
        self.logger.info(f"Starting SMB enumeration on {target}")

        # Create temp file for JSON output
        with tempfile.NamedTemporaryFile(mode="w", suffix=".json", delete=False) as f:
            json_file = f.name

        try:
            args = ["enum4linux-ng", "-oJ", json_file]

            if username:
                args.extend(["-u", username])
            if password:
                args.extend(["-p", password])

            # Build module selection
            if not shares and not users and not groups:
                # Default to all if nothing specified
                args.append("-A")
            else:
                if shares:
                    args.append("-S")
                if users:
                    args.append("-U")
                if groups:
                    args.append("-G")

            args.append(target)

            self.logger.info(f"Running: {' '.join(args)}")
            result = await self.run_command(args, timeout=timeout)

            # Parse JSON output
            parsed = self._parse_json_output(json_file)

            # Extract key information
            summary = {
                "target": target,
                "os_info": parsed.get("os_info", {}),
                "shares": [],
                "users": [],
                "groups": [],
            }

            # Extract shares
            if "shares" in parsed:
                for share_name, share_info in parsed["shares"].items():
                    summary["shares"].append({
                        "name": share_name,
                        "type": share_info.get("type", ""),
                        "comment": share_info.get("comment", ""),
                    })

            # Extract users
            if "users" in parsed:
                for user_info in parsed.get("users", {}).values():
                    if isinstance(user_info, dict):
                        summary["users"].append({
                            "username": user_info.get("username", ""),
                            "rid": user_info.get("rid", ""),
                        })

            # Extract groups
            if "groups" in parsed:
                for group_info in parsed.get("groups", {}).values():
                    if isinstance(group_info, dict):
                        summary["groups"].append({
                            "name": group_info.get("groupname", ""),
                            "rid": group_info.get("rid", ""),
                        })

            return ToolResult(
                success=True,
                data={
                    "summary": summary,
                    "full_results": parsed,
                },
                raw_output=sanitize_output(result.stdout + result.stderr),
            )

        except ToolError as e:
            return ToolResult(
                success=False,
                data={},
                error=str(e),
            )
        finally:
            if os.path.exists(json_file):
                os.unlink(json_file)

    async def enum_users(
        self,
        target: str,
        username: Optional[str] = None,
        password: Optional[str] = None,
        rid_range: str = "500-550,1000-1200",
        timeout: int = 300,
    ) -> ToolResult:
        """Enumerate users via RID cycling."""
        self.logger.info(f"Enumerating users on {target}")

        with tempfile.NamedTemporaryFile(mode="w", suffix=".json", delete=False) as f:
            json_file = f.name

        try:
            args = ["enum4linux-ng", "-oJ", json_file, "-R", rid_range, "-U"]

            if username:
                args.extend(["-u", username])
            if password:
                args.extend(["-p", password])

            args.append(target)

            result = await self.run_command(args, timeout=timeout)
            parsed = self._parse_json_output(json_file)

            users = []
            if "users" in parsed:
                for user_info in parsed.get("users", {}).values():
                    if isinstance(user_info, dict):
                        users.append({
                            "username": user_info.get("username", ""),
                            "rid": user_info.get("rid", ""),
                            "domain": user_info.get("domain", ""),
                        })

            return ToolResult(
                success=True,
                data={
                    "target": target,
                    "users": users,
                    "count": len(users),
                },
                raw_output=sanitize_output(result.stdout + result.stderr),
            )

        except ToolError as e:
            return ToolResult(
                success=False,
                data={},
                error=str(e),
            )
        finally:
            if os.path.exists(json_file):
                os.unlink(json_file)

    async def enum_shares(
        self,
        target: str,
        username: Optional[str] = None,
        password: Optional[str] = None,
        timeout: int = 300,
    ) -> ToolResult:
        """Enumerate SMB shares and check access."""
        self.logger.info(f"Enumerating shares on {target}")

        with tempfile.NamedTemporaryFile(mode="w", suffix=".json", delete=False) as f:
            json_file = f.name

        try:
            args = ["enum4linux-ng", "-oJ", json_file, "-S"]

            if username:
                args.extend(["-u", username])
            if password:
                args.extend(["-p", password])

            args.append(target)

            result = await self.run_command(args, timeout=timeout)
            parsed = self._parse_json_output(json_file)

            shares = []
            if "shares" in parsed:
                for share_name, share_info in parsed["shares"].items():
                    shares.append({
                        "name": share_name,
                        "type": share_info.get("type", ""),
                        "comment": share_info.get("comment", ""),
                        "access": share_info.get("access", {}).get("mapping", ""),
                    })

            return ToolResult(
                success=True,
                data={
                    "target": target,
                    "shares": shares,
                    "count": len(shares),
                },
                raw_output=sanitize_output(result.stdout + result.stderr),
            )

        except ToolError as e:
            return ToolResult(
                success=False,
                data={},
                error=str(e),
            )
        finally:
            if os.path.exists(json_file):
                os.unlink(json_file)

    async def enum_groups(
        self,
        target: str,
        username: Optional[str] = None,
        password: Optional[str] = None,
        timeout: int = 300,
    ) -> ToolResult:
        """Enumerate groups and their members."""
        self.logger.info(f"Enumerating groups on {target}")

        with tempfile.NamedTemporaryFile(mode="w", suffix=".json", delete=False) as f:
            json_file = f.name

        try:
            args = ["enum4linux-ng", "-oJ", json_file, "-G"]

            if username:
                args.extend(["-u", username])
            if password:
                args.extend(["-p", password])

            args.append(target)

            result = await self.run_command(args, timeout=timeout)
            parsed = self._parse_json_output(json_file)

            groups = []
            if "groups" in parsed:
                for group_info in parsed.get("groups", {}).values():
                    if isinstance(group_info, dict):
                        groups.append({
                            "name": group_info.get("groupname", ""),
                            "rid": group_info.get("rid", ""),
                            "members": group_info.get("members", []),
                        })

            return ToolResult(
                success=True,
                data={
                    "target": target,
                    "groups": groups,
                    "count": len(groups),
                },
                raw_output=sanitize_output(result.stdout + result.stderr),
            )

        except ToolError as e:
            return ToolResult(
                success=False,
                data={},
                error=str(e),
            )
        finally:
            if os.path.exists(json_file):
                os.unlink(json_file)

    async def enum_policy(
        self,
        target: str,
        username: Optional[str] = None,
        password: Optional[str] = None,
        timeout: int = 300,
    ) -> ToolResult:
        """Enumerate password policy and domain info."""
        self.logger.info(f"Enumerating policy on {target}")

        with tempfile.NamedTemporaryFile(mode="w", suffix=".json", delete=False) as f:
            json_file = f.name

        try:
            args = ["enum4linux-ng", "-oJ", json_file, "-P", "-I"]

            if username:
                args.extend(["-u", username])
            if password:
                args.extend(["-p", password])

            args.append(target)

            result = await self.run_command(args, timeout=timeout)
            parsed = self._parse_json_output(json_file)

            policy = {}
            if "policy" in parsed:
                policy = parsed["policy"]

            domain_info = {}
            if "os_info" in parsed:
                domain_info = parsed["os_info"]

            return ToolResult(
                success=True,
                data={
                    "target": target,
                    "password_policy": policy,
                    "domain_info": domain_info,
                },
                raw_output=sanitize_output(result.stdout + result.stderr),
            )

        except ToolError as e:
            return ToolResult(
                success=False,
                data={},
                error=str(e),
            )
        finally:
            if os.path.exists(json_file):
                os.unlink(json_file)


if __name__ == "__main__":
    Enum4linuxServer.main()
