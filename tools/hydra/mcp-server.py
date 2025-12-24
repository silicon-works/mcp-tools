#!/usr/bin/env python3
"""
OpenSploit MCP Server: hydra

Network authentication brute-forcing tool.
"""

import re
from typing import Any, Dict, List, Optional

from mcp_common import BaseMCPServer, ToolResult, ToolError, sanitize_output


class HydraServer(BaseMCPServer):
    """MCP server wrapping hydra authentication brute-forcer."""

    # Default wordlists
    WORDLISTS = {
        "rockyou": "/usr/share/wordlists/rockyou.txt",
        "common-passwords": "/usr/share/seclists/Passwords/Common-Credentials/10k-most-common.txt",
        "default-passwords": "/usr/share/seclists/Passwords/Default-Credentials/default-passwords.txt",
        "usernames": "/usr/share/seclists/Usernames/top-usernames-shortlist.txt",
    }

    # Service default ports
    SERVICE_PORTS = {
        "ssh": 22,
        "ftp": 21,
        "http-get": 80,
        "http-post": 80,
        "https-get": 443,
        "https-post": 443,
        "smb": 445,
        "rdp": 3389,
        "mysql": 3306,
        "postgres": 5432,
        "vnc": 5900,
        "telnet": 23,
        "smtp": 25,
        "pop3": 110,
        "imap": 143,
    }

    def __init__(self):
        super().__init__(
            name="hydra",
            description="Network authentication brute-forcing tool",
            version="1.0.0",
        )

        self.register_method(
            name="bruteforce",
            description="Brute-force login credentials for a service",
            params={
                "target": {
                    "type": "string",
                    "required": True,
                    "description": "Target IP or hostname",
                },
                "service": {
                    "type": "string",
                    "required": True,
                    "enum": list(self.SERVICE_PORTS.keys()),
                    "description": "Service protocol to attack",
                },
                "username": {
                    "type": "string",
                    "description": "Single username to test",
                },
                "userlist": {
                    "type": "string",
                    "description": "Wordlist name (usernames) or path to username list",
                },
                "password": {
                    "type": "string",
                    "description": "Single password to test",
                },
                "passlist": {
                    "type": "string",
                    "default": "common-passwords",
                    "description": "Wordlist name (rockyou, common-passwords) or path",
                },
                "threads": {
                    "type": "integer",
                    "default": 16,
                    "description": "Number of parallel connections",
                },
                "port": {
                    "type": "integer",
                    "description": "Service port (uses default if not specified)",
                },
                "timeout": {
                    "type": "integer",
                    "default": 600,
                    "description": "Timeout in seconds",
                },
                "http_path": {
                    "type": "string",
                    "description": "Path for HTTP auth (e.g., /admin/login)",
                },
                "http_form": {
                    "type": "string",
                    "description": "HTTP form parameters (e.g., 'user=^USER^&pass=^PASS^:F=incorrect')",
                },
            },
            handler=self.bruteforce,
        )

    def _resolve_wordlist(self, wordlist: str) -> str:
        """Resolve wordlist name to path."""
        if wordlist in self.WORDLISTS:
            return self.WORDLISTS[wordlist]
        return wordlist

    def _parse_hydra_output(self, output: str) -> Dict[str, Any]:
        """Parse hydra output for credentials."""
        credentials = []

        for line in output.split("\n"):
            # Hydra outputs found credentials like:
            # [22][ssh] host: 10.10.10.1   login: admin   password: admin123
            match = re.search(
                r"\[(\d+)\]\[(\w+)\]\s+host:\s+(\S+)\s+login:\s+(\S+)\s+password:\s+(\S+)",
                line
            )
            if match:
                credentials.append({
                    "port": int(match.group(1)),
                    "service": match.group(2),
                    "host": match.group(3),
                    "username": match.group(4),
                    "password": match.group(5),
                })

        return {
            "credentials": credentials,
            "found": len(credentials) > 0,
            "count": len(credentials),
        }

    async def bruteforce(
        self,
        target: str,
        service: str,
        username: Optional[str] = None,
        userlist: Optional[str] = None,
        password: Optional[str] = None,
        passlist: str = "common-passwords",
        threads: int = 16,
        port: Optional[int] = None,
        timeout: int = 600,
        http_path: Optional[str] = None,
        http_form: Optional[str] = None,
    ) -> ToolResult:
        """Brute-force login credentials for a service."""
        self.logger.info(f"Starting brute-force on {target} ({service})")

        # Resolve port
        if port is None:
            port = self.SERVICE_PORTS.get(service, 0)

        # Build command
        args = ["hydra", "-t", str(threads), "-V"]

        # Username options
        if username:
            args.extend(["-l", username])
        elif userlist:
            args.extend(["-L", self._resolve_wordlist(userlist)])
        else:
            # Default to common usernames
            args.extend(["-L", self.WORDLISTS["usernames"]])

        # Password options
        if password:
            args.extend(["-p", password])
        else:
            args.extend(["-P", self._resolve_wordlist(passlist)])

        # Add target and service
        if port:
            args.extend(["-s", str(port)])

        args.append(target)

        # Handle HTTP services specially
        if service in ["http-get", "https-get"]:
            path = http_path or "/"
            args.append(f"http-get")
            args.append(path)
        elif service in ["http-post", "https-post"]:
            if http_form:
                args.append("http-post-form")
                args.append(http_form)
            else:
                return ToolResult(
                    success=False,
                    data={},
                    error="http_form parameter required for http-post service",
                )
        else:
            args.append(service)

        try:
            self.logger.info(f"Running: {' '.join(args)}")
            result = await self.run_command(args, timeout=timeout)

            output = result.stdout + result.stderr
            parsed = self._parse_hydra_output(output)

            parsed["summary"] = {
                "target": target,
                "service": service,
                "port": port,
                "found": parsed["found"],
            }

            return ToolResult(
                success=True,
                data=parsed,
                raw_output=sanitize_output(output),
            )

        except ToolError as e:
            return ToolResult(
                success=False,
                data={},
                error=str(e),
            )


if __name__ == "__main__":
    HydraServer.main()
