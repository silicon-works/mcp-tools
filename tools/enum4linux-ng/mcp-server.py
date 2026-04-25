#!/usr/bin/env python3
"""
OpenSploit MCP Server: enum4linux-ng

SMB/Windows enumeration tool.
"""

import json
import os
import re
import tempfile
from typing import Any, Dict, List, Optional, Tuple

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

    def _make_json_output_path(self) -> str:
        """Create a temp file path for enum4linux-ng JSON output.

        enum4linux-ng's -oJ flag auto-appends '.json' to the given path,
        so we return a path WITHOUT .json extension.  The actual output
        file will be at ``<returned_path>.json``.
        """
        # Create a temp file just to get a unique path, then remove it
        fd, path = tempfile.mkstemp(prefix="e4l_")
        os.close(fd)
        os.unlink(path)
        return path

    def _parse_json_output(self, json_file: str) -> Dict[str, Any]:
        """Parse enum4linux-ng JSON output.

        Args:
            json_file: Path to the JSON file (with .json extension).
        """
        try:
            with open(json_file, "r") as f:
                return json.load(f)
        except (json.JSONDecodeError, FileNotFoundError):
            return {}

    def _cleanup_json_files(self, base_path: str) -> None:
        """Remove the base path and the .json output file created by enum4linux-ng."""
        for path in [base_path, base_path + ".json"]:
            try:
                if os.path.exists(path):
                    os.unlink(path)
            except OSError:
                pass

    def _classify_enum_error(self, output: str) -> Tuple[str, bool, List[str]]:
        """Classify enum4linux-ng errors from combined stdout+stderr.

        Returns (error_class, retryable, suggestions).
        """
        if not output:
            return ("unknown", False, [])

        # Strip ANSI escape codes for reliable pattern matching
        clean = re.sub(r"\x1b\[[0-9;]*m", "", output)

        # Usage/argument error (exit code 2 typically)
        if "usage: enum4linux-ng" in clean and "error:" in clean:
            return ("params", False, [
                "Check that arguments match enum4linux-ng's CLI format",
            ])

        # Auth failure patterns (check BEFORE connection-refused because
        # partial connection refusals on one port are normal in auth-fail scenarios)
        if any(p in clean for p in [
            "STATUS_LOGON_FAILURE",
            "LOGON_FAILURE",
            "Could not establish session",
        ]):
            return ("auth", False, [
                "Check username and password",
                "Try null session (omit username/password)",
            ])

        # Aborting + connection refused = all ports unreachable (true network error)
        if "Aborting remainder of tests" in clean:
            if "connection refused" in clean.lower():
                return ("network", True, [
                    "Neither SMB nor LDAP is accessible on the target",
                    "Verify target IP and that SMB (445) or NetBIOS (139) is open",
                    "Run nmap to confirm port status",
                ])
            if "timed out" in clean.lower():
                return ("network", True, [
                    "Target may be unreachable or firewalled",
                    "Increase timeout or verify network connectivity",
                ])
            # Aborting due to session failure (ACCESS_DENIED without LOGON_FAILURE)
            if "STATUS_ACCESS_DENIED" in clean:
                return ("auth", False, [
                    "Access denied - try different credentials or null session",
                ])
            # Generic abort
            return ("network", True, [
                "Neither SMB nor LDAP is accessible on the target",
                "Verify target IP and that SMB (445/139) or LDAP (389/636) is open",
            ])

        return ("unknown", False, [])

    def _build_result_with_classification(
        self,
        success: bool,
        data: Dict[str, Any],
        raw_output: str,
        error: Optional[str] = None,
    ) -> ToolResult:
        """Build a ToolResult with error classification from output."""
        error_class = None
        retryable = False
        suggestions: List[str] = []

        if not success and raw_output:
            error_class, retryable, suggestions = self._classify_enum_error(raw_output)
        elif not success:
            error_class = "unknown"

        return ToolResult(
            success=success,
            data=data,
            raw_output=sanitize_output(raw_output),
            error=error,
            error_class=error_class,
            retryable=retryable,
            suggestions=suggestions,
        )

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

        base_path = self._make_json_output_path()

        try:
            args = ["enum4linux-ng", "-oJ", base_path]

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
            result = await self.run_command_with_progress(args)

            # Parse JSON output (enum4linux-ng appends .json to base_path)
            json_file = base_path + ".json"
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

            raw_output = result.stdout + result.stderr

            # Detect failure conditions from output
            if self._is_abort_output(raw_output) and not parsed.get("sessions_possible", False):
                return self._build_result_with_classification(
                    success=False,
                    data={"summary": summary, "full_results": parsed},
                    raw_output=raw_output,
                    error="Enumeration aborted: SMB/LDAP not accessible or session failed",
                )

            return self._build_result_with_classification(
                success=True,
                data={"summary": summary, "full_results": parsed},
                raw_output=raw_output,
            )

        except ToolError as e:
            return self._build_result_with_classification(
                success=False,
                data={},
                raw_output="",
                error=str(e),
            )
        finally:
            self._cleanup_json_files(base_path)

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

        base_path = self._make_json_output_path()

        try:
            # -R enables RID cycling (optional int BULK_SIZE)
            # -r specifies the RID range string
            # -U enables user enumeration via RPC
            args = ["enum4linux-ng", "-oJ", base_path, "-R", "-r", rid_range, "-U"]

            if username:
                args.extend(["-u", username])
            if password:
                args.extend(["-p", password])

            args.append(target)

            result = await self.run_command_with_progress(args)
            json_file = base_path + ".json"
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

            raw_output = result.stdout + result.stderr

            if self._is_abort_output(raw_output) and not users:
                return self._build_result_with_classification(
                    success=False,
                    data={"target": target, "users": users, "count": len(users)},
                    raw_output=raw_output,
                    error="User enumeration failed: SMB/LDAP not accessible or session failed",
                )

            return self._build_result_with_classification(
                success=True,
                data={"target": target, "users": users, "count": len(users)},
                raw_output=raw_output,
            )

        except ToolError as e:
            return self._build_result_with_classification(
                success=False,
                data={},
                raw_output="",
                error=str(e),
            )
        finally:
            self._cleanup_json_files(base_path)

    async def enum_shares(
        self,
        target: str,
        username: Optional[str] = None,
        password: Optional[str] = None,
        timeout: int = 300,
    ) -> ToolResult:
        """Enumerate SMB shares and check access."""
        self.logger.info(f"Enumerating shares on {target}")

        base_path = self._make_json_output_path()

        try:
            args = ["enum4linux-ng", "-oJ", base_path, "-S"]

            if username:
                args.extend(["-u", username])
            if password:
                args.extend(["-p", password])

            args.append(target)

            result = await self.run_command_with_progress(args)
            json_file = base_path + ".json"
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

            raw_output = result.stdout + result.stderr

            if self._is_abort_output(raw_output) and not shares:
                return self._build_result_with_classification(
                    success=False,
                    data={"target": target, "shares": shares, "count": len(shares)},
                    raw_output=raw_output,
                    error="Share enumeration failed: SMB/LDAP not accessible or session failed",
                )

            return self._build_result_with_classification(
                success=True,
                data={"target": target, "shares": shares, "count": len(shares)},
                raw_output=raw_output,
            )

        except ToolError as e:
            return self._build_result_with_classification(
                success=False,
                data={},
                raw_output="",
                error=str(e),
            )
        finally:
            self._cleanup_json_files(base_path)

    async def enum_groups(
        self,
        target: str,
        username: Optional[str] = None,
        password: Optional[str] = None,
        timeout: int = 300,
    ) -> ToolResult:
        """Enumerate groups and their members."""
        self.logger.info(f"Enumerating groups on {target}")

        base_path = self._make_json_output_path()

        try:
            args = ["enum4linux-ng", "-oJ", base_path, "-G"]

            if username:
                args.extend(["-u", username])
            if password:
                args.extend(["-p", password])

            args.append(target)

            result = await self.run_command_with_progress(args)
            json_file = base_path + ".json"
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

            raw_output = result.stdout + result.stderr

            if self._is_abort_output(raw_output) and not groups:
                return self._build_result_with_classification(
                    success=False,
                    data={"target": target, "groups": groups, "count": len(groups)},
                    raw_output=raw_output,
                    error="Group enumeration failed: SMB/LDAP not accessible or session failed",
                )

            return self._build_result_with_classification(
                success=True,
                data={"target": target, "groups": groups, "count": len(groups)},
                raw_output=raw_output,
            )

        except ToolError as e:
            return self._build_result_with_classification(
                success=False,
                data={},
                raw_output="",
                error=str(e),
            )
        finally:
            self._cleanup_json_files(base_path)

    async def enum_policy(
        self,
        target: str,
        username: Optional[str] = None,
        password: Optional[str] = None,
        timeout: int = 300,
    ) -> ToolResult:
        """Enumerate password policy and domain info."""
        self.logger.info(f"Enumerating policy on {target}")

        base_path = self._make_json_output_path()

        try:
            args = ["enum4linux-ng", "-oJ", base_path, "-P", "-I"]

            if username:
                args.extend(["-u", username])
            if password:
                args.extend(["-p", password])

            args.append(target)

            result = await self.run_command_with_progress(args)
            json_file = base_path + ".json"
            parsed = self._parse_json_output(json_file)

            policy = {}
            if "policy" in parsed:
                policy = parsed["policy"]

            domain_info = {}
            if "os_info" in parsed:
                domain_info = parsed["os_info"]

            raw_output = result.stdout + result.stderr

            if self._is_abort_output(raw_output) and not policy and not domain_info:
                return self._build_result_with_classification(
                    success=False,
                    data={"target": target, "password_policy": policy, "domain_info": domain_info},
                    raw_output=raw_output,
                    error="Policy enumeration failed: SMB/LDAP not accessible or session failed",
                )

            return self._build_result_with_classification(
                success=True,
                data={"target": target, "password_policy": policy, "domain_info": domain_info},
                raw_output=raw_output,
            )

        except ToolError as e:
            return self._build_result_with_classification(
                success=False,
                data={},
                raw_output="",
                error=str(e),
            )
        finally:
            self._cleanup_json_files(base_path)

    def _is_abort_output(self, output: str) -> bool:
        """Check if output contains an abort message from enum4linux-ng."""
        clean = re.sub(r"\x1b\[[0-9;]*m", "", output)
        return "Aborting remainder of tests" in clean


if __name__ == "__main__":
    Enum4linuxServer.main()
