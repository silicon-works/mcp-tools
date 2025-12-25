#!/usr/bin/env python3
"""
OpenSploit MCP Server: privesc

Privilege escalation enumeration and exploit suggestion.
Performs local checks and suggests known CVEs based on installed software.
"""

import asyncio
import base64
import json
import os
import re
from typing import Any, Dict, List, Optional

from mcp_common import BaseMCPServer, ToolResult, ToolError, sanitize_output


class PrivescServer(BaseMCPServer):
    """MCP server for privilege escalation enumeration."""

    def __init__(self):
        super().__init__(
            name="privesc",
            description="Privilege escalation enumeration and exploit suggestion",
            version="1.0.0",
        )

        # Load CVE database
        self.cve_db = {}
        try:
            with open("/app/cve_database.json", "r") as f:
                self.cve_db = json.load(f)
        except Exception as e:
            self.logger.warning(f"Could not load CVE database: {e}")

        self.register_method(
            name="enumerate",
            description="Run comprehensive privilege escalation enumeration",
            params={
                "level": {
                    "type": "string",
                    "enum": ["quick", "standard", "thorough"],
                    "default": "standard",
                    "description": "Enumeration depth: quick (SUID/sudo), standard (+ cron/caps), thorough (full linpeas)",
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
            name="check_suid",
            description="Find SUID/SGID binaries",
            params={
                "timeout": {
                    "type": "integer",
                    "default": 60,
                    "description": "Timeout in seconds",
                },
            },
            handler=self.check_suid,
        )

        self.register_method(
            name="check_sudo",
            description="Check sudo permissions",
            params={
                "password": {
                    "type": "string",
                    "description": "User password for sudo -l",
                },
                "timeout": {
                    "type": "integer",
                    "default": 30,
                    "description": "Timeout in seconds",
                },
            },
            handler=self.check_sudo,
        )

        self.register_method(
            name="check_capabilities",
            description="Find files with special capabilities",
            params={
                "timeout": {
                    "type": "integer",
                    "default": 60,
                    "description": "Timeout in seconds",
                },
            },
            handler=self.check_capabilities,
        )

        self.register_method(
            name="check_cron",
            description="Check cron jobs for weaknesses",
            params={
                "timeout": {
                    "type": "integer",
                    "default": 30,
                    "description": "Timeout in seconds",
                },
            },
            handler=self.check_cron,
        )

        self.register_method(
            name="check_writable",
            description="Find writable sensitive files and directories",
            params={
                "timeout": {
                    "type": "integer",
                    "default": 120,
                    "description": "Timeout in seconds",
                },
            },
            handler=self.check_writable,
        )

        self.register_method(
            name="suggest_exploits",
            description="Suggest exploits based on system information",
            params={
                "kernel_version": {
                    "type": "string",
                    "description": "Kernel version (from uname -r)",
                },
                "distro": {
                    "type": "string",
                    "description": "Distribution info",
                },
                "installed_software": {
                    "type": "array",
                    "description": "List of installed software with versions",
                },
            },
            handler=self.suggest_exploits,
        )

        self.register_method(
            name="get_linpeas",
            description="Get linpeas.sh script as base64 for upload to target",
            params={},
            handler=self.get_linpeas,
        )

        self.register_method(
            name="get_lse",
            description="Get linux-smart-enumeration script as base64",
            params={},
            handler=self.get_lse,
        )

    async def enumerate(
        self,
        level: str = "standard",
        timeout: int = 300,
    ) -> ToolResult:
        """Run comprehensive enumeration."""
        self.logger.info(f"Running {level} enumeration")

        results = {
            "level": level,
            "findings": [],
            "suid": [],
            "capabilities": [],
            "sudo": None,
            "cron": [],
            "writable": [],
            "system_info": {},
        }

        # Get system info
        try:
            proc = await asyncio.create_subprocess_exec(
                "sh", "-c",
                "echo 'KERNEL:' $(uname -r); echo 'ARCH:' $(uname -m); id; hostname",
                stdout=asyncio.subprocess.PIPE,
                stderr=asyncio.subprocess.PIPE,
            )
            stdout, _ = await asyncio.wait_for(proc.communicate(), timeout=10)
            results["system_info"]["raw"] = stdout.decode()
        except Exception as e:
            self.logger.warning(f"Could not get system info: {e}")

        # Quick: SUID + sudo
        suid_result = await self.check_suid(timeout=min(60, timeout))
        if suid_result.success:
            results["suid"] = suid_result.data.get("suid_files", [])
            results["findings"].extend(suid_result.data.get("interesting", []))

        sudo_result = await self.check_sudo(timeout=30)
        if sudo_result.success:
            results["sudo"] = sudo_result.data

        if level in ("standard", "thorough"):
            # Standard: + capabilities + cron
            caps_result = await self.check_capabilities(timeout=min(60, timeout))
            if caps_result.success:
                results["capabilities"] = caps_result.data.get("files", [])
                results["findings"].extend(caps_result.data.get("interesting", []))

            cron_result = await self.check_cron(timeout=30)
            if cron_result.success:
                results["cron"] = cron_result.data.get("jobs", [])
                results["findings"].extend(cron_result.data.get("writable", []))

        if level == "thorough":
            # Thorough: + writable files
            writable_result = await self.check_writable(timeout=min(120, timeout))
            if writable_result.success:
                results["writable"] = writable_result.data.get("files", [])

        return ToolResult(
            success=True,
            data=results,
            raw_output=f"Found {len(results['findings'])} interesting items",
        )

    async def check_suid(self, timeout: int = 60) -> ToolResult:
        """Find SUID/SGID binaries."""
        self.logger.info("Checking SUID/SGID binaries")

        try:
            proc = await asyncio.create_subprocess_exec(
                "find", "/", "-perm", "-4000", "-type", "f",
                stdout=asyncio.subprocess.PIPE,
                stderr=asyncio.subprocess.PIPE,
            )
            stdout, _ = await asyncio.wait_for(proc.communicate(), timeout=timeout)

            suid_files = [f for f in stdout.decode().strip().split("\n") if f]

            # Check for known exploitable SUID binaries
            interesting = []
            gtfobins = [
                "nmap", "vim", "find", "bash", "less", "more", "nano", "cp",
                "mv", "awk", "perl", "python", "ruby", "lua", "php", "node",
                "env", "tar", "zip", "rsync", "git", "ftp", "sftp", "scp",
                "ssh-keysign", "pkexec", "snap", "docker", "lxc", "ndsudo"
            ]

            for suid_file in suid_files:
                basename = os.path.basename(suid_file)
                for gtfo in gtfobins:
                    if gtfo in basename.lower():
                        interesting.append({
                            "file": suid_file,
                            "type": "suid",
                            "note": f"Potentially exploitable: {gtfo}",
                        })
                        break

                # Check for netdata ndsudo specifically
                if "ndsudo" in suid_file:
                    interesting.append({
                        "file": suid_file,
                        "type": "suid",
                        "cve": "CVE-2024-32019",
                        "note": "Netdata ndsudo - PATH injection privesc",
                    })

            return ToolResult(
                success=True,
                data={
                    "suid_files": suid_files,
                    "interesting": interesting,
                    "count": len(suid_files),
                },
                raw_output="\n".join(suid_files),
            )

        except asyncio.TimeoutError:
            return ToolResult(
                success=False,
                data={},
                error=f"SUID search timed out after {timeout}s",
            )

    async def check_sudo(
        self,
        password: Optional[str] = None,
        timeout: int = 30,
    ) -> ToolResult:
        """Check sudo permissions."""
        self.logger.info("Checking sudo permissions")

        try:
            if password:
                proc = await asyncio.create_subprocess_exec(
                    "sh", "-c", f"echo '{password}' | sudo -S -l 2>/dev/null",
                    stdout=asyncio.subprocess.PIPE,
                    stderr=asyncio.subprocess.PIPE,
                )
            else:
                proc = await asyncio.create_subprocess_exec(
                    "sudo", "-l",
                    stdout=asyncio.subprocess.PIPE,
                    stderr=asyncio.subprocess.PIPE,
                )

            stdout, stderr = await asyncio.wait_for(proc.communicate(), timeout=timeout)
            output = stdout.decode()

            # Parse sudo -l output
            can_run = []
            nopasswd = []

            for line in output.split("\n"):
                if "NOPASSWD" in line:
                    nopasswd.append(line.strip())
                elif "may run" in line.lower() or line.strip().startswith("("):
                    can_run.append(line.strip())

            return ToolResult(
                success=True,
                data={
                    "can_run": can_run,
                    "nopasswd": nopasswd,
                    "raw": output,
                },
                raw_output=output,
            )

        except asyncio.TimeoutError:
            return ToolResult(
                success=False,
                data={},
                error="Sudo check timed out (may need password)",
            )

    async def check_capabilities(self, timeout: int = 60) -> ToolResult:
        """Find files with capabilities."""
        self.logger.info("Checking file capabilities")

        try:
            proc = await asyncio.create_subprocess_exec(
                "getcap", "-r", "/",
                stdout=asyncio.subprocess.PIPE,
                stderr=asyncio.subprocess.PIPE,
            )
            stdout, _ = await asyncio.wait_for(proc.communicate(), timeout=timeout)

            files = []
            interesting = []

            for line in stdout.decode().strip().split("\n"):
                if line and "=" in line:
                    files.append(line)

                    # Check for dangerous capabilities
                    dangerous_caps = [
                        "cap_setuid", "cap_setgid", "cap_dac_override",
                        "cap_dac_read_search", "cap_sys_admin", "cap_sys_ptrace",
                        "cap_net_admin", "cap_net_raw"
                    ]

                    for cap in dangerous_caps:
                        if cap in line.lower():
                            interesting.append({
                                "file": line.split()[0] if line.split() else line,
                                "type": "capability",
                                "capability": cap,
                                "note": f"Has {cap} capability",
                            })
                            break

            return ToolResult(
                success=True,
                data={
                    "files": files,
                    "interesting": interesting,
                    "count": len(files),
                },
                raw_output="\n".join(files),
            )

        except asyncio.TimeoutError:
            return ToolResult(
                success=False,
                data={},
                error=f"Capability check timed out after {timeout}s",
            )

    async def check_cron(self, timeout: int = 30) -> ToolResult:
        """Check cron jobs."""
        self.logger.info("Checking cron jobs")

        try:
            proc = await asyncio.create_subprocess_exec(
                "sh", "-c",
                "cat /etc/crontab 2>/dev/null; ls -la /etc/cron.* 2>/dev/null; cat /etc/cron.d/* 2>/dev/null",
                stdout=asyncio.subprocess.PIPE,
                stderr=asyncio.subprocess.PIPE,
            )
            stdout, _ = await asyncio.wait_for(proc.communicate(), timeout=timeout)

            jobs = stdout.decode().strip().split("\n")

            # Check for writable cron scripts
            writable = []
            # This would need actual file permission checks on target

            return ToolResult(
                success=True,
                data={
                    "jobs": jobs,
                    "writable": writable,
                },
                raw_output=stdout.decode(),
            )

        except asyncio.TimeoutError:
            return ToolResult(
                success=False,
                data={},
                error=f"Cron check timed out after {timeout}s",
            )

    async def check_writable(self, timeout: int = 120) -> ToolResult:
        """Find writable sensitive files."""
        self.logger.info("Checking writable files")

        sensitive_paths = [
            "/etc/passwd",
            "/etc/shadow",
            "/etc/sudoers",
            "/etc/crontab",
            "/root",
        ]

        try:
            # Check common sensitive paths
            proc = await asyncio.create_subprocess_exec(
                "sh", "-c",
                "find /etc -writable -type f 2>/dev/null | head -50; "
                "find /var -writable -type f 2>/dev/null | head -50",
                stdout=asyncio.subprocess.PIPE,
                stderr=asyncio.subprocess.PIPE,
            )
            stdout, _ = await asyncio.wait_for(proc.communicate(), timeout=timeout)

            files = [f for f in stdout.decode().strip().split("\n") if f]

            return ToolResult(
                success=True,
                data={
                    "files": files,
                    "count": len(files),
                },
                raw_output="\n".join(files),
            )

        except asyncio.TimeoutError:
            return ToolResult(
                success=False,
                data={},
                error=f"Writable file check timed out after {timeout}s",
            )

    async def suggest_exploits(
        self,
        kernel_version: Optional[str] = None,
        distro: Optional[str] = None,
        installed_software: Optional[List[str]] = None,
    ) -> ToolResult:
        """Suggest exploits based on system info."""
        self.logger.info("Suggesting exploits")

        suggestions = []

        # Check kernel exploits
        if kernel_version:
            version_parts = kernel_version.split(".")
            if len(version_parts) >= 2:
                major = int(version_parts[0])
                minor = int(version_parts[1])

                if major == 5 and 8 <= minor < 17:
                    suggestions.append({
                        "name": "Dirty Pipe",
                        "cve": "CVE-2022-0847",
                        "kernel": kernel_version,
                        "description": "Arbitrary file overwrite via pipe splice",
                    })

                if major < 5 or (major == 5 and minor < 8):
                    suggestions.append({
                        "name": "Dirty COW",
                        "cve": "CVE-2016-5195",
                        "kernel": kernel_version,
                        "description": "Copy-on-write race condition",
                    })

        # Check software-specific CVEs from database
        if installed_software:
            for software in installed_software:
                sw_lower = software.lower()
                for category, items in self.cve_db.items():
                    if category.lower() in sw_lower:
                        for vuln_name, vuln_info in items.items():
                            suggestions.append({
                                "name": vuln_name,
                                "cve": vuln_info.get("cve", "N/A"),
                                "software": software,
                                "description": vuln_info.get("description", ""),
                                "exploit": vuln_info.get("exploit", ""),
                            })

        return ToolResult(
            success=True,
            data={
                "suggestions": suggestions,
                "count": len(suggestions),
            },
            raw_output=f"Found {len(suggestions)} potential exploits",
        )

    async def get_linpeas(self) -> ToolResult:
        """Get linpeas script as base64."""
        self.logger.info("Getting linpeas script")

        try:
            with open("/app/scripts/linpeas.sh", "rb") as f:
                content = f.read()

            b64 = base64.b64encode(content).decode()

            return ToolResult(
                success=True,
                data={
                    "script": "linpeas.sh",
                    "size_bytes": len(content),
                    "base64": b64,
                },
                raw_output=f"linpeas.sh ({len(content)} bytes)",
            )

        except Exception as e:
            return ToolResult(
                success=False,
                data={},
                error=str(e),
            )

    async def get_lse(self) -> ToolResult:
        """Get linux-smart-enumeration script as base64."""
        self.logger.info("Getting LSE script")

        try:
            with open("/app/scripts/lse.sh", "rb") as f:
                content = f.read()

            b64 = base64.b64encode(content).decode()

            return ToolResult(
                success=True,
                data={
                    "script": "lse.sh",
                    "size_bytes": len(content),
                    "base64": b64,
                },
                raw_output=f"lse.sh ({len(content)} bytes)",
            )

        except Exception as e:
            return ToolResult(
                success=False,
                data={},
                error=str(e),
            )


if __name__ == "__main__":
    PrivescServer.main()
