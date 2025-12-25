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


if __name__ == "__main__":
    WpscanServer.main()
