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

    # SSH-specific usernames for targeted brute-forcing
    SSH_USERNAMES = [
        "root", "admin", "user", "ubuntu", "debian", "kali", "centos", "fedora",
        "ec2-user", "pi", "vagrant", "ansible", "deploy", "git", "jenkins",
        "www-data", "mysql", "postgres", "oracle", "test", "guest", "backup",
        "operator", "ftpuser", "sshuser", "administrator", "support", "service",
    ]

    # Service default ports
    SERVICE_PORTS = {
        "ssh": 22,
        "ftp": 21,
        "http-get": 80,
        "http-post": 80,
        "http-post-form": 80,
        "http-get-form": 80,
        "https-get": 443,
        "https-post": 443,
        "https-post-form": 443,
        "https-get-form": 443,
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

        self.register_method(
            name="ssh_brute",
            description="Brute-force SSH login (convenience method)",
            params={
                "target": {
                    "type": "string",
                    "required": True,
                    "description": "Target IP or hostname",
                },
                "username": {
                    "type": "string",
                    "description": "Single username to test (or use userlist)",
                },
                "userlist": {
                    "type": "string",
                    "description": "Path to username wordlist",
                },
                "passlist": {
                    "type": "string",
                    "default": "common-passwords",
                    "description": "Password wordlist name or path",
                },
                "port": {
                    "type": "integer",
                    "default": 22,
                    "description": "SSH port",
                },
                "timeout": {
                    "type": "integer",
                    "default": 600,
                    "description": "Timeout in seconds",
                },
            },
            handler=self.ssh_brute,
        )

        self.register_method(
            name="ftp_brute",
            description="Brute-force FTP login (convenience method)",
            params={
                "target": {
                    "type": "string",
                    "required": True,
                    "description": "Target IP or hostname",
                },
                "username": {
                    "type": "string",
                    "description": "Single username (default: anonymous, ftp, admin)",
                },
                "passlist": {
                    "type": "string",
                    "default": "common-passwords",
                    "description": "Password wordlist name or path",
                },
                "port": {
                    "type": "integer",
                    "default": 21,
                    "description": "FTP port",
                },
                "timeout": {
                    "type": "integer",
                    "default": 600,
                    "description": "Timeout in seconds",
                },
            },
            handler=self.ftp_brute,
        )

        self.register_method(
            name="web_form_brute",
            description="Brute-force web login form",
            params={
                "target": {
                    "type": "string",
                    "required": True,
                    "description": "Target IP or hostname",
                },
                "path": {
                    "type": "string",
                    "required": True,
                    "description": "Login form path (e.g., /login.php)",
                },
                "user_field": {
                    "type": "string",
                    "default": "username",
                    "description": "Username form field name",
                },
                "pass_field": {
                    "type": "string",
                    "default": "password",
                    "description": "Password form field name",
                },
                "fail_string": {
                    "type": "string",
                    "required": True,
                    "description": "String that appears on failed login (e.g., 'Invalid', 'incorrect')",
                },
                "username": {
                    "type": "string",
                    "description": "Single username to test",
                },
                "userlist": {
                    "type": "string",
                    "description": "Username wordlist",
                },
                "passlist": {
                    "type": "string",
                    "default": "common-passwords",
                    "description": "Password wordlist",
                },
                "https": {
                    "type": "boolean",
                    "default": False,
                    "description": "Use HTTPS",
                },
                "port": {
                    "type": "integer",
                    "description": "Port (default: 80 or 443 for HTTPS)",
                },
                "extra_params": {
                    "type": "string",
                    "description": "Additional POST parameters (e.g., 'submit=Login&csrf=token')",
                },
                "timeout": {
                    "type": "integer",
                    "default": 600,
                    "description": "Timeout in seconds",
                },
            },
            handler=self.web_form_brute,
        )

        self.register_method(
            name="mysql_brute",
            description="Brute-force MySQL login",
            params={
                "target": {
                    "type": "string",
                    "required": True,
                    "description": "Target IP or hostname",
                },
                "username": {
                    "type": "string",
                    "default": "root",
                    "description": "Username to test",
                },
                "passlist": {
                    "type": "string",
                    "default": "common-passwords",
                    "description": "Password wordlist",
                },
                "port": {
                    "type": "integer",
                    "default": 3306,
                    "description": "MySQL port",
                },
                "timeout": {
                    "type": "integer",
                    "default": 600,
                    "description": "Timeout in seconds",
                },
            },
            handler=self.mysql_brute,
        )

    def _resolve_wordlist(self, wordlist: str) -> str:
        """
        Resolve wordlist name to path.

        Built-in wordlists: rockyou, common-passwords, default-passwords, usernames, ssh-usernames
        Custom paths: /session/wordlists/mylist.txt (mounted from session directory)
        """
        if wordlist in self.WORDLISTS:
            return self.WORDLISTS[wordlist]

        # Handle ssh-usernames specially - create temp file with common SSH users
        if wordlist == "ssh-usernames":
            import tempfile
            import os
            tmp_path = "/tmp/ssh-usernames.txt"
            if not os.path.exists(tmp_path):
                with open(tmp_path, "w") as f:
                    f.write("\n".join(self.SSH_USERNAMES))
            return tmp_path

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
            args.append("http-get")
            args.append(path)
        elif service in ["http-post-form", "https-post-form"]:
            if http_form:
                args.append("http-post-form")
                args.append(http_form)
            else:
                return ToolResult(
                    success=False,
                    data={},
                    error="http_form parameter required for http-post-form service (format: '/path:user=^USER^&pass=^PASS^:F=error_message')",
                )
        elif service in ["http-get-form", "https-get-form"]:
            if http_form:
                args.append("http-get-form")
                args.append(http_form)
            else:
                return ToolResult(
                    success=False,
                    data={},
                    error="http_form parameter required for http-get-form service (format: '/path:user=^USER^&pass=^PASS^:F=error_message')",
                )
        elif service in ["http-post", "https-post"]:
            # Basic HTTP POST auth (not form-based)
            path = http_path or "/"
            args.append("http-post")
            args.append(path)
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

    async def ssh_brute(
        self,
        target: str,
        username: Optional[str] = None,
        userlist: Optional[str] = None,
        passlist: str = "common-passwords",
        port: int = 22,
        timeout: int = 600,
    ) -> ToolResult:
        """Brute-force SSH login (convenience method)."""
        return await self.bruteforce(
            target=target,
            service="ssh",
            username=username,
            userlist=userlist,
            passlist=passlist,
            port=port,
            timeout=timeout,
        )

    async def ftp_brute(
        self,
        target: str,
        username: Optional[str] = None,
        passlist: str = "common-passwords",
        port: int = 21,
        timeout: int = 600,
    ) -> ToolResult:
        """Brute-force FTP login (convenience method)."""
        # If no username specified, try common FTP usernames
        if not username:
            # Run with username list for anonymous, ftp, admin
            return await self.bruteforce(
                target=target,
                service="ftp",
                userlist="usernames",
                passlist=passlist,
                port=port,
                timeout=timeout,
            )
        return await self.bruteforce(
            target=target,
            service="ftp",
            username=username,
            passlist=passlist,
            port=port,
            timeout=timeout,
        )

    async def web_form_brute(
        self,
        target: str,
        path: str,
        fail_string: str,
        user_field: str = "username",
        pass_field: str = "password",
        username: Optional[str] = None,
        userlist: Optional[str] = None,
        passlist: str = "common-passwords",
        https: bool = False,
        port: Optional[int] = None,
        extra_params: Optional[str] = None,
        timeout: int = 600,
    ) -> ToolResult:
        """Brute-force web login form."""
        # Build the http_form string for hydra
        # Format: "/path:user=^USER^&pass=^PASS^:F=error_message"
        form_parts = [f"{user_field}=^USER^", f"{pass_field}=^PASS^"]
        if extra_params:
            form_parts.append(extra_params)

        form_string = f"{path}:{'&'.join(form_parts)}:F={fail_string}"

        service = "https-post-form" if https else "http-post-form"
        default_port = 443 if https else 80

        return await self.bruteforce(
            target=target,
            service=service,
            username=username,
            userlist=userlist,
            passlist=passlist,
            port=port or default_port,
            timeout=timeout,
            http_form=form_string,
        )

    async def mysql_brute(
        self,
        target: str,
        username: str = "root",
        passlist: str = "common-passwords",
        port: int = 3306,
        timeout: int = 600,
    ) -> ToolResult:
        """Brute-force MySQL login."""
        return await self.bruteforce(
            target=target,
            service="mysql",
            username=username,
            passlist=passlist,
            port=port,
            timeout=timeout,
        )


if __name__ == "__main__":
    HydraServer.main()
