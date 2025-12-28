#!/usr/bin/env python3
"""
OpenSploit MCP Server: wpscan

WordPress vulnerability scanner.
"""

import json
from typing import Any, Dict, List, Optional

from mcp_common import BaseMCPServer, ToolResult, ToolError, sanitize_output


class WpscanServer(BaseMCPServer):
    """MCP server wrapping WPScan WordPress vulnerability scanner."""

    def __init__(self):
        super().__init__(
            name="wpscan",
            description="WordPress vulnerability scanner",
            version="1.0.0",
        )

        self.register_method(
            name="scan",
            description="Scan a WordPress site for vulnerabilities",
            params={
                "url": {
                    "type": "string",
                    "required": True,
                    "description": "Target WordPress URL",
                },
                "enumerate": {
                    "type": "string",
                    "default": "vp,vt,u",
                    "description": "Enumeration options: vp (plugins), vt (themes), u (users), ap (all plugins), at (all themes)",
                },
                "plugins_detection": {
                    "type": "string",
                    "enum": ["passive", "aggressive", "mixed"],
                    "default": "mixed",
                    "description": "Plugin detection mode",
                },
                "api_token": {
                    "type": "string",
                    "description": "WPVulnDB API token for vulnerability data",
                },
                "timeout": {
                    "type": "integer",
                    "default": 300,
                    "description": "Timeout in seconds",
                },
            },
            handler=self.scan,
        )

        self.register_method(
            name="bruteforce",
            description="Brute-force WordPress login",
            params={
                "url": {
                    "type": "string",
                    "required": True,
                    "description": "Target WordPress URL",
                },
                "username": {
                    "type": "string",
                    "required": True,
                    "description": "Username to brute-force",
                },
                "wordlist": {
                    "type": "string",
                    "default": "/usr/share/wordlists/rockyou.txt",
                    "description": "Password wordlist path",
                },
                "timeout": {
                    "type": "integer",
                    "default": 600,
                    "description": "Timeout in seconds",
                },
            },
            handler=self.bruteforce,
        )

        self.register_method(
            name="enumerate_users",
            description="Enumerate WordPress users",
            params={
                "url": {
                    "type": "string",
                    "required": True,
                    "description": "Target WordPress URL",
                },
                "api_token": {
                    "type": "string",
                    "description": "WPVulnDB API token for vulnerability data",
                },
                "timeout": {
                    "type": "integer",
                    "default": 300,
                    "description": "Timeout in seconds",
                },
            },
            handler=self.enumerate_users,
        )

        self.register_method(
            name="enumerate_plugins",
            description="Enumerate WordPress plugins and their vulnerabilities",
            params={
                "url": {
                    "type": "string",
                    "required": True,
                    "description": "Target WordPress URL",
                },
                "detection_mode": {
                    "type": "string",
                    "enum": ["passive", "aggressive", "mixed"],
                    "default": "aggressive",
                    "description": "Plugin detection mode",
                },
                "all_plugins": {
                    "type": "boolean",
                    "default": False,
                    "description": "Enumerate all plugins (not just vulnerable ones)",
                },
                "api_token": {
                    "type": "string",
                    "description": "WPVulnDB API token for vulnerability data",
                },
                "timeout": {
                    "type": "integer",
                    "default": 300,
                    "description": "Timeout in seconds",
                },
            },
            handler=self.enumerate_plugins,
        )

        self.register_method(
            name="enumerate_themes",
            description="Enumerate WordPress themes and their vulnerabilities",
            params={
                "url": {
                    "type": "string",
                    "required": True,
                    "description": "Target WordPress URL",
                },
                "all_themes": {
                    "type": "boolean",
                    "default": False,
                    "description": "Enumerate all themes (not just vulnerable ones)",
                },
                "api_token": {
                    "type": "string",
                    "description": "WPVulnDB API token for vulnerability data",
                },
                "timeout": {
                    "type": "integer",
                    "default": 300,
                    "description": "Timeout in seconds",
                },
            },
            handler=self.enumerate_themes,
        )

    def _parse_json_output(self, output: str) -> Dict[str, Any]:
        """Parse wpscan JSON output."""
        try:
            return json.loads(output)
        except json.JSONDecodeError:
            return {}

    async def scan(
        self,
        url: str,
        enumerate: str = "vp,vt,u",
        plugins_detection: str = "mixed",
        api_token: Optional[str] = None,
        timeout: int = 300,
    ) -> ToolResult:
        """Scan a WordPress site for vulnerabilities."""
        self.logger.info(f"Starting WordPress scan on {url}")

        args = [
            "wpscan",
            "--url", url,
            "--format", "json",
            "--enumerate", enumerate,
            "--plugins-detection", plugins_detection,
            "--random-user-agent",
        ]

        if api_token:
            args.extend(["--api-token", api_token])

        try:
            self.logger.info(f"Running: wpscan --url {url} ...")
            result = await self.run_command(args, timeout=timeout)

            parsed = self._parse_json_output(result.stdout)

            # Extract key findings
            summary = {
                "url": url,
                "wordpress_version": None,
                "theme": None,
                "plugins": [],
                "users": [],
                "vulnerabilities": [],
            }

            if parsed:
                # Version info
                if "version" in parsed:
                    version_info = parsed["version"]
                    summary["wordpress_version"] = version_info.get("number")

                # Theme
                if "main_theme" in parsed:
                    theme = parsed["main_theme"]
                    summary["theme"] = {
                        "name": theme.get("slug"),
                        "version": theme.get("version", {}).get("number"),
                    }

                # Plugins
                for plugin_name, plugin_info in parsed.get("plugins", {}).items():
                    plugin_data = {
                        "name": plugin_name,
                        "version": plugin_info.get("version", {}).get("number"),
                        "vulnerabilities": len(plugin_info.get("vulnerabilities", [])),
                    }
                    summary["plugins"].append(plugin_data)

                    # Add vulnerabilities
                    for vuln in plugin_info.get("vulnerabilities", []):
                        summary["vulnerabilities"].append({
                            "plugin": plugin_name,
                            "title": vuln.get("title"),
                            "type": vuln.get("vuln_type"),
                            "references": vuln.get("references", {}).get("url", []),
                        })

                # Users
                for user_name, user_info in parsed.get("users", {}).items():
                    summary["users"].append({
                        "username": user_name,
                        "id": user_info.get("id"),
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

    async def bruteforce(
        self,
        url: str,
        username: str,
        wordlist: str = "/usr/share/wordlists/rockyou.txt",
        timeout: int = 600,
    ) -> ToolResult:
        """Brute-force WordPress login."""
        self.logger.info(f"Starting WordPress brute-force on {url} for user {username}")

        args = [
            "wpscan",
            "--url", url,
            "--format", "json",
            "--passwords", wordlist,
            "--usernames", username,
            "--random-user-agent",
        ]

        try:
            result = await self.run_command(args, timeout=timeout)

            parsed = self._parse_json_output(result.stdout)

            # Extract password if found
            password_found = None
            if "password_attack" in parsed:
                for user, info in parsed.get("password_attack", {}).items():
                    if info.get("password"):
                        password_found = {
                            "username": user,
                            "password": info["password"],
                        }
                        break

            return ToolResult(
                success=True,
                data={
                    "url": url,
                    "username": username,
                    "password_found": password_found,
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

    async def enumerate_users(
        self,
        url: str,
        api_token: Optional[str] = None,
        timeout: int = 300,
    ) -> ToolResult:
        """Enumerate WordPress users."""
        self.logger.info(f"Enumerating users on {url}")

        args = [
            "wpscan",
            "--url", url,
            "--format", "json",
            "--enumerate", "u",
            "--random-user-agent",
        ]

        if api_token:
            args.extend(["--api-token", api_token])

        try:
            result = await self.run_command(args, timeout=timeout)
            parsed = self._parse_json_output(result.stdout)

            users = []
            for user_name, user_info in parsed.get("users", {}).items():
                users.append({
                    "username": user_name,
                    "id": user_info.get("id"),
                    "slug": user_info.get("slug"),
                })

            return ToolResult(
                success=True,
                data={
                    "url": url,
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

    async def enumerate_plugins(
        self,
        url: str,
        detection_mode: str = "aggressive",
        all_plugins: bool = False,
        api_token: Optional[str] = None,
        timeout: int = 300,
    ) -> ToolResult:
        """Enumerate WordPress plugins and their vulnerabilities."""
        self.logger.info(f"Enumerating plugins on {url}")

        # Use 'ap' for all plugins, 'vp' for vulnerable only
        enum_flag = "ap" if all_plugins else "vp"

        args = [
            "wpscan",
            "--url", url,
            "--format", "json",
            "--enumerate", enum_flag,
            "--plugins-detection", detection_mode,
            "--random-user-agent",
        ]

        if api_token:
            args.extend(["--api-token", api_token])

        try:
            result = await self.run_command(args, timeout=timeout)
            parsed = self._parse_json_output(result.stdout)

            plugins = []
            vulnerabilities = []

            for plugin_name, plugin_info in parsed.get("plugins", {}).items():
                plugin_vulns = plugin_info.get("vulnerabilities", [])
                plugins.append({
                    "name": plugin_name,
                    "version": plugin_info.get("version", {}).get("number"),
                    "outdated": plugin_info.get("outdated", False),
                    "vulnerability_count": len(plugin_vulns),
                })

                for vuln in plugin_vulns:
                    vulnerabilities.append({
                        "plugin": plugin_name,
                        "title": vuln.get("title"),
                        "type": vuln.get("vuln_type"),
                        "cve": vuln.get("references", {}).get("cve", []),
                        "references": vuln.get("references", {}).get("url", []),
                    })

            return ToolResult(
                success=True,
                data={
                    "url": url,
                    "plugins": plugins,
                    "vulnerabilities": vulnerabilities,
                    "plugin_count": len(plugins),
                    "vulnerability_count": len(vulnerabilities),
                },
                raw_output=sanitize_output(result.stdout + result.stderr),
            )

        except ToolError as e:
            return ToolResult(
                success=False,
                data={},
                error=str(e),
            )

    async def enumerate_themes(
        self,
        url: str,
        all_themes: bool = False,
        api_token: Optional[str] = None,
        timeout: int = 300,
    ) -> ToolResult:
        """Enumerate WordPress themes and their vulnerabilities."""
        self.logger.info(f"Enumerating themes on {url}")

        # Use 'at' for all themes, 'vt' for vulnerable only
        enum_flag = "at" if all_themes else "vt"

        args = [
            "wpscan",
            "--url", url,
            "--format", "json",
            "--enumerate", enum_flag,
            "--random-user-agent",
        ]

        if api_token:
            args.extend(["--api-token", api_token])

        try:
            result = await self.run_command(args, timeout=timeout)
            parsed = self._parse_json_output(result.stdout)

            themes = []
            vulnerabilities = []

            # Main theme
            if "main_theme" in parsed:
                theme = parsed["main_theme"]
                theme_vulns = theme.get("vulnerabilities", [])
                themes.append({
                    "name": theme.get("slug"),
                    "version": theme.get("version", {}).get("number"),
                    "is_main_theme": True,
                    "vulnerability_count": len(theme_vulns),
                })

                for vuln in theme_vulns:
                    vulnerabilities.append({
                        "theme": theme.get("slug"),
                        "title": vuln.get("title"),
                        "type": vuln.get("vuln_type"),
                        "cve": vuln.get("references", {}).get("cve", []),
                        "references": vuln.get("references", {}).get("url", []),
                    })

            # Other themes
            for theme_name, theme_info in parsed.get("themes", {}).items():
                theme_vulns = theme_info.get("vulnerabilities", [])
                themes.append({
                    "name": theme_name,
                    "version": theme_info.get("version", {}).get("number"),
                    "is_main_theme": False,
                    "vulnerability_count": len(theme_vulns),
                })

                for vuln in theme_vulns:
                    vulnerabilities.append({
                        "theme": theme_name,
                        "title": vuln.get("title"),
                        "type": vuln.get("vuln_type"),
                        "cve": vuln.get("references", {}).get("cve", []),
                        "references": vuln.get("references", {}).get("url", []),
                    })

            return ToolResult(
                success=True,
                data={
                    "url": url,
                    "themes": themes,
                    "vulnerabilities": vulnerabilities,
                    "theme_count": len(themes),
                    "vulnerability_count": len(vulnerabilities),
                },
                raw_output=sanitize_output(result.stdout + result.stderr),
            )

        except ToolError as e:
            return ToolResult(
                success=False,
                data={},
                error=str(e),
            )


if __name__ == "__main__":
    WpscanServer.main()
