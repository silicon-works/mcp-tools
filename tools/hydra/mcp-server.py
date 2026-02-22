#!/usr/bin/env python3
"""
OpenSploit MCP Server: hydra

Network authentication brute-forcing tool.
"""

import asyncio
import re
import time
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

    # Password-only services (no username, only -p/-P)
    PASSWORD_ONLY_SERVICES = {"redis", "cisco", "cisco-enable", "oracle-listener", "snmp", "vnc"}

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
        "smb2": 445,
        "rdp": 3389,
        "mysql": 3306,
        "mssql": 1433,
        "postgres": 5432,
        "vnc": 5900,
        "telnet": 23,
        "smtp": 25,
        "pop3": 110,
        "imap": 143,
        "redis": 6379,
        "mongodb": 27017,
        "ldap2": 389,
        "ldap3": 389,
        "snmp": 161,
        "sshkey": 22,
        "http-proxy": 8080,
        "rtsp": 554,
        "sip": 5060,
        "cisco": 23,
        "cisco-enable": 23,
        "svn": 3690,
        "firebird": 3050,
        "oracle-listener": 1521,
        "rsh": 514,
        "rlogin": 513,
        "rexec": 512,
    }

    # Service-specific default threads (encode expert knowledge)
    SERVICE_THREADS = {
        "ssh": 4,       # SSH servers aggressively rate-limit
        "ftp": 8,       # More tolerant than SSH
        "mysql": 4,     # Database connections are expensive
        "postgres": 4,
        "smb": 8,       # Windows can be touchy
        "rdp": 4,       # RDP is sensitive to concurrent attempts
        "vnc": 4,
        "redis": 8,
        "mongodb": 4,
        "smb2": 8,
        "mssql": 4,
        "ldap2": 8,
        "ldap3": 8,
        "sshkey": 4,
        "oracle-listener": 4,
        "firebird": 4,
    }
    DEFAULT_THREADS = 16  # For HTTP and other services

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
                    "description": "Wordlist name (usernames, ssh-usernames) or path to username list",
                },
                "password": {
                    "type": "string",
                    "description": "Single password to test",
                },
                "passlist": {
                    "type": "string",
                    "description": "Wordlist name (rockyou, common-passwords) or path. Ignored if password is set.",
                },
                "threads": {
                    "type": "integer",
                    "description": "Number of parallel connections (default: service-specific, e.g., SSH=4, HTTP=16)",
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
                "wait_time": {
                    "type": "integer",
                    "description": "Seconds to wait between connection attempts (hydra -W flag)",
                },
                "stop_on_first": {
                    "type": "boolean",
                    "default": False,
                    "description": "Stop after finding first valid credential (hydra -f flag)",
                },
                "try_common": {
                    "type": "string",
                    "enum": ["n", "s", "r", "ns", "nr", "sr", "nsr"],
                    "description": "Try common passwords: n=null, s=same as login, r=reversed login (e.g., 'nsr' for all)",
                },
                "verbose": {
                    "type": "boolean",
                    "default": False,
                    "description": "Include verbose output with each attempt (warning: can be large)",
                },
                "http_path": {
                    "type": "string",
                    "description": "Path for HTTP auth (e.g., /admin/login)",
                },
                "http_form": {
                    "type": "string",
                    "description": "HTTP form parameters (e.g., 'user=^USER^&pass=^PASS^:F=incorrect')",
                },
                "loop_users": {
                    "type": "boolean",
                    "default": False,
                    "description": "Loop around users instead of passwords (-u). Try each password against all users before moving to the next password. Critical for avoiding account lockout.",
                },
                "password_gen": {
                    "type": "string",
                    "description": "Generate passwords instead of using a wordlist (hydra -x). Format: 'MIN:MAX:CHARSET'. CHARSET: 'a'=lowercase, 'A'=uppercase, '1'=numbers. Examples: '4:4:1' (4-digit PINs), '3:5:aA1' (3-5 chars mixed). Overrides passlist.",
                },
                "combo_file": {
                    "type": "string",
                    "description": "Colon-separated login:pass file (hydra -C). Each line: 'username:password'. Overrides username/userlist/password/passlist. Useful with default credential lists.",
                },
                "ssl": {
                    "type": "boolean",
                    "default": False,
                    "description": "Use SSL for the connection (hydra -S). Required for IMAPS (993), POP3S (995), SMTPS (465). Not needed for HTTPS (use https-* services instead).",
                },
            },
            handler=self.bruteforce,
        )

        self.register_method(
            name="ssh_brute",
            description="Brute-force SSH login (convenience method with SSH-optimized defaults)",
            params={
                "target": {
                    "type": "string",
                    "required": True,
                    "description": "Target IP or hostname",
                },
                "username": {
                    "type": "string",
                    "description": "Single username to test",
                },
                "userlist": {
                    "type": "string",
                    "description": "Wordlist name (usernames, ssh-usernames) or path",
                },
                "password": {
                    "type": "string",
                    "description": "Single password to test",
                },
                "passlist": {
                    "type": "string",
                    "description": "Password wordlist name or path. Ignored if password is set.",
                },
                "port": {
                    "type": "integer",
                    "default": 22,
                    "description": "SSH port",
                },
                "threads": {
                    "type": "integer",
                    "default": 4,
                    "description": "Parallel connections (default: 4 for SSH to avoid rate limiting)",
                },
                "timeout": {
                    "type": "integer",
                    "default": 600,
                    "description": "Timeout in seconds",
                },
                "wait_time": {
                    "type": "integer",
                    "description": "Seconds to wait between connection attempts",
                },
                "stop_on_first": {
                    "type": "boolean",
                    "default": False,
                    "description": "Stop after finding first valid credential",
                },
                "try_common": {
                    "type": "string",
                    "enum": ["n", "s", "r", "ns", "nr", "sr", "nsr"],
                    "description": "Try common passwords: n=null, s=same as login, r=reversed login",
                },
                "verbose": {
                    "type": "boolean",
                    "default": False,
                    "description": "Include verbose output with each attempt",
                },
                "loop_users": {
                    "type": "boolean",
                    "default": False,
                    "description": "Loop around users instead of passwords (-u). Critical for avoiding account lockout.",
                },
                "password_gen": {
                    "type": "string",
                    "description": "Generate passwords instead of using a wordlist (-x). Format: 'MIN:MAX:CHARSET'. Overrides passlist.",
                },
                "combo_file": {
                    "type": "string",
                    "description": "Colon-separated login:pass file (-C). Overrides username/password options.",
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
                    "description": "Single username to test",
                },
                "userlist": {
                    "type": "string",
                    "description": "Wordlist name or path (default: tries common FTP usernames)",
                },
                "password": {
                    "type": "string",
                    "description": "Single password to test",
                },
                "passlist": {
                    "type": "string",
                    "description": "Password wordlist name or path. Ignored if password is set.",
                },
                "port": {
                    "type": "integer",
                    "default": 21,
                    "description": "FTP port",
                },
                "threads": {
                    "type": "integer",
                    "default": 8,
                    "description": "Parallel connections (default: 8 for FTP)",
                },
                "timeout": {
                    "type": "integer",
                    "default": 600,
                    "description": "Timeout in seconds",
                },
                "wait_time": {
                    "type": "integer",
                    "description": "Seconds to wait between connection attempts",
                },
                "stop_on_first": {
                    "type": "boolean",
                    "default": False,
                    "description": "Stop after finding first valid credential",
                },
                "try_common": {
                    "type": "string",
                    "enum": ["n", "s", "r", "ns", "nr", "sr", "nsr"],
                    "description": "Try common passwords: n=null, s=same as login, r=reversed login",
                },
                "verbose": {
                    "type": "boolean",
                    "default": False,
                    "description": "Include verbose output with each attempt",
                },
                "loop_users": {
                    "type": "boolean",
                    "default": False,
                    "description": "Loop around users instead of passwords (-u). Critical for avoiding account lockout.",
                },
                "password_gen": {
                    "type": "string",
                    "description": "Generate passwords instead of using a wordlist (-x). Format: 'MIN:MAX:CHARSET'. Overrides passlist.",
                },
                "combo_file": {
                    "type": "string",
                    "description": "Colon-separated login:pass file (-C). Overrides username/password options.",
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
                    "description": "Username wordlist name or path",
                },
                "password": {
                    "type": "string",
                    "description": "Single password to test",
                },
                "passlist": {
                    "type": "string",
                    "description": "Password wordlist name or path. Ignored if password is set.",
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
                "threads": {
                    "type": "integer",
                    "default": 16,
                    "description": "Parallel connections (default: 16 for HTTP)",
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
                "wait_time": {
                    "type": "integer",
                    "description": "Seconds to wait between connection attempts",
                },
                "stop_on_first": {
                    "type": "boolean",
                    "default": False,
                    "description": "Stop after finding first valid credential",
                },
                "try_common": {
                    "type": "string",
                    "enum": ["n", "s", "r", "ns", "nr", "sr", "nsr"],
                    "description": "Try common passwords: n=null, s=same as login, r=reversed login",
                },
                "verbose": {
                    "type": "boolean",
                    "default": False,
                    "description": "Include verbose output with each attempt",
                },
                "loop_users": {
                    "type": "boolean",
                    "default": False,
                    "description": "Loop around users instead of passwords (-u). Critical for avoiding account lockout.",
                },
                "password_gen": {
                    "type": "string",
                    "description": "Generate passwords instead of using a wordlist (-x). Format: 'MIN:MAX:CHARSET'. Overrides passlist.",
                },
                "combo_file": {
                    "type": "string",
                    "description": "Colon-separated login:pass file (-C). Overrides username/password options.",
                },
                "ssl": {
                    "type": "boolean",
                    "default": False,
                    "description": "Use SSL for the connection (-S).",
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
                    "description": "Single username to test",
                },
                "userlist": {
                    "type": "string",
                    "description": "Username wordlist name or path",
                },
                "password": {
                    "type": "string",
                    "description": "Single password to test",
                },
                "passlist": {
                    "type": "string",
                    "description": "Password wordlist name or path. Ignored if password is set.",
                },
                "port": {
                    "type": "integer",
                    "default": 3306,
                    "description": "MySQL port",
                },
                "threads": {
                    "type": "integer",
                    "default": 4,
                    "description": "Parallel connections (default: 4 for MySQL)",
                },
                "timeout": {
                    "type": "integer",
                    "default": 600,
                    "description": "Timeout in seconds",
                },
                "wait_time": {
                    "type": "integer",
                    "description": "Seconds to wait between connection attempts",
                },
                "stop_on_first": {
                    "type": "boolean",
                    "default": False,
                    "description": "Stop after finding first valid credential",
                },
                "try_common": {
                    "type": "string",
                    "enum": ["n", "s", "r", "ns", "nr", "sr", "nsr"],
                    "description": "Try common passwords: n=null, s=same as login, r=reversed login",
                },
                "verbose": {
                    "type": "boolean",
                    "default": False,
                    "description": "Include verbose output with each attempt",
                },
                "loop_users": {
                    "type": "boolean",
                    "default": False,
                    "description": "Loop around users instead of passwords (-u). Critical for avoiding account lockout.",
                },
                "password_gen": {
                    "type": "string",
                    "description": "Generate passwords instead of using a wordlist (-x). Format: 'MIN:MAX:CHARSET'. Overrides passlist.",
                },
                "combo_file": {
                    "type": "string",
                    "description": "Colon-separated login:pass file (-C). Overrides username/password options.",
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

    def _parse_hydra_output(self, output: str, include_verbose: bool = False) -> Dict[str, Any]:
        """Parse hydra output for credentials and statistics."""
        credentials = []
        attempts_total = 0
        attempts_completed = 0
        warnings = []
        errors = []

        for line in output.split("\n"):
            # Parse found credentials
            # SSH format: [22][ssh] host: 10.10.10.1   login: admin   password: admin123
            # HTTP form format: [80][http-post-form] host: httpbin.org   misc: /path:...   login: admin   password: admin123
            cred_match = re.search(
                r"\[(\d+)\]\[([\w-]+)\]\s+host:\s+(\S+).*?\s+login:\s+(\S+)\s+password:\s+(\S+)",
                line
            )
            if cred_match:
                credentials.append({
                    "port": int(cred_match.group(1)),
                    "service": cred_match.group(2),
                    "host": cred_match.group(3),
                    "username": cred_match.group(4),
                    "password": cred_match.group(5),
                })
                continue

            # Parse progress info: [STATUS] 1234.00 tries/min, 5678 tries in 00:04h, 9012 to do
            status_match = re.search(
                r"\[STATUS\].*?(\d+)\s+tries\s+in\s+[\d:]+h?,\s+(\d+)\s+to\s+do",
                line
            )
            if status_match:
                attempts_completed = int(status_match.group(1))
                remaining = int(status_match.group(2))
                attempts_total = attempts_completed + remaining
                continue

            # Parse total combinations: [DATA] max 16 tasks per 1 server, overall 16 tasks, 14344398 login tries
            data_match = re.search(r"\[DATA\].*?(\d+)\s+login\s+tries", line)
            if data_match and attempts_total == 0:
                attempts_total = int(data_match.group(1))
                continue

            # Parse warnings
            if line.strip().startswith("[WARNING]"):
                warnings.append(line.strip()[10:].strip())
                continue

            # Parse errors
            if line.strip().startswith("[ERROR]"):
                errors.append(line.strip()[8:].strip())
                continue

        result = {
            "credentials": credentials,
            "found": len(credentials) > 0,
            "count": len(credentials),
            "stats": {
                "attempts_total": attempts_total,
                "attempts_completed": attempts_completed,
                "attempts_successful": len(credentials),
            },
        }

        if warnings:
            result["warnings"] = warnings

        if errors:
            result["errors"] = errors

        if include_verbose:
            # Extract attempt lines for verbose output
            verbose_lines = [
                line for line in output.split("\n")
                if "[ATTEMPT]" in line or "[STATUS]" in line or "[DATA]" in line
            ]
            result["verbose_output"] = "\n".join(verbose_lines[-1000:])  # Last 1000 lines

        return result

    async def bruteforce(
        self,
        target: str,
        service: str,
        username: Optional[str] = None,
        userlist: Optional[str] = None,
        password: Optional[str] = None,
        passlist: Optional[str] = None,
        threads: Optional[int] = None,
        port: Optional[int] = None,
        timeout: int = 600,
        wait_time: Optional[int] = None,
        stop_on_first: bool = False,
        try_common: Optional[str] = None,
        verbose: bool = False,
        http_path: Optional[str] = None,
        http_form: Optional[str] = None,
        loop_users: bool = False,
        password_gen: Optional[str] = None,
        combo_file: Optional[str] = None,
        ssl: bool = False,
    ) -> ToolResult:
        """Brute-force login credentials for a service."""
        start_time = time.time()
        self.logger.info(f"Starting brute-force on {target} ({service})")

        # Resolve port
        if port is None:
            port = self.SERVICE_PORTS.get(service, 0)

        # Resolve threads (service-specific defaults)
        if threads is None:
            threads = self.SERVICE_THREADS.get(service, self.DEFAULT_THREADS)

        # Build command
        args = ["hydra", "-t", str(threads)]

        # Add verbose flag if requested (always use -V for progress tracking)
        args.append("-V")

        # Wait time between connections
        if wait_time is not None:
            args.extend(["-W", str(wait_time)])

        # Stop on first valid credential
        if stop_on_first:
            args.append("-f")

        # Try common passwords (null, same as login, reversed)
        if try_common:
            args.extend(["-e", try_common])

        # Loop around users instead of passwords (avoids account lockout)
        if loop_users:
            args.append("-u")

        # SSL connection
        if ssl:
            args.append("-S")

        # Password-only services (redis, snmp, vnc, cisco, oracle-listener)
        # don't accept -l/-L/-C — only -p/-P
        is_password_only = service in self.PASSWORD_ONLY_SERVICES

        # Combo file overrides all username/password options
        if combo_file and not is_password_only:
            args.extend(["-C", self._resolve_wordlist(combo_file)])
        else:
            # Username options (skip for password-only services)
            if not is_password_only:
                if username:
                    args.extend(["-l", username])
                elif userlist:
                    args.extend(["-L", self._resolve_wordlist(userlist)])
                else:
                    # Default to common usernames
                    args.extend(["-L", self.WORDLISTS["usernames"]])

            # Password options (password_gen overrides passlist)
            if password_gen:
                args.extend(["-x", password_gen])
            elif password:
                args.extend(["-p", password])
            elif passlist:
                args.extend(["-P", self._resolve_wordlist(passlist)])
            else:
                # Default to common passwords if no password specified
                args.extend(["-P", self.WORDLISTS["common-passwords"]])

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

        self.logger.info(f"Running: {' '.join(args)}")

        # Execute with timeout handling that captures partial output
        try:
            proc = await asyncio.create_subprocess_exec(
                *args,
                stdout=asyncio.subprocess.PIPE,
                stderr=asyncio.subprocess.PIPE,
            )

            try:
                stdout_bytes, stderr_bytes = await asyncio.wait_for(
                    proc.communicate(),
                    timeout=timeout,
                )
                stdout = stdout_bytes.decode('utf-8', errors='replace')
                stderr = stderr_bytes.decode('utf-8', errors='replace')
                timed_out = False

            except asyncio.TimeoutError:
                # Terminate the process gracefully first (SIGTERM allows output flush)
                proc.terminate()
                try:
                    stdout_bytes, stderr_bytes = await asyncio.wait_for(
                        proc.communicate(),
                        timeout=5,
                    )
                    stdout = stdout_bytes.decode('utf-8', errors='replace')
                    stderr = stderr_bytes.decode('utf-8', errors='replace')
                except asyncio.TimeoutError:
                    # If still running after 5s, force kill
                    proc.kill()
                    try:
                        stdout_bytes, stderr_bytes = await asyncio.wait_for(
                            proc.communicate(),
                            timeout=2,
                        )
                        stdout = stdout_bytes.decode('utf-8', errors='replace')
                        stderr = stderr_bytes.decode('utf-8', errors='replace')
                    except Exception:
                        stdout = ""
                        stderr = ""
                except Exception:
                    stdout = ""
                    stderr = ""
                timed_out = True

            output = stdout + stderr
            duration_seconds = int(time.time() - start_time)
            parsed = self._parse_hydra_output(output, include_verbose=verbose)

            parsed["summary"] = {
                "target": target,
                "service": service,
                "port": port,
                "threads": threads,
                "found": parsed["found"],
                "duration_seconds": duration_seconds,
            }

            if timed_out:
                parsed["partial"] = True
                parsed["stats"]["duration_seconds"] = duration_seconds
                return ToolResult(
                    success=False,
                    data=parsed,
                    raw_output=sanitize_output(output),
                    error=f"Operation timed out after {timeout} seconds ({len(parsed['credentials'])} credentials found in partial results)",
                )

            # Check for hydra errors (connection failures, etc.)
            if parsed.get("errors"):
                return ToolResult(
                    success=False,
                    data=parsed,
                    raw_output=sanitize_output(output),
                    error=parsed["errors"][0] if parsed["errors"] else "Unknown hydra error",
                )

            return ToolResult(
                success=True,
                data=parsed,
                raw_output=sanitize_output(output),
            )

        except Exception as e:
            return ToolResult(
                success=False,
                data={"summary": {"target": target, "service": service, "port": port}},
                error=str(e),
            )

    async def ssh_brute(
        self,
        target: str,
        username: Optional[str] = None,
        userlist: Optional[str] = None,
        password: Optional[str] = None,
        passlist: Optional[str] = None,
        port: int = 22,
        threads: int = 4,
        timeout: int = 600,
        wait_time: Optional[int] = None,
        stop_on_first: bool = False,
        try_common: Optional[str] = None,
        verbose: bool = False,
        loop_users: bool = False,
        password_gen: Optional[str] = None,
        combo_file: Optional[str] = None,
    ) -> ToolResult:
        """Brute-force SSH login (convenience method with SSH-optimized defaults)."""
        return await self.bruteforce(
            target=target,
            service="ssh",
            username=username,
            userlist=userlist,
            password=password,
            passlist=passlist,
            port=port,
            threads=threads,
            timeout=timeout,
            wait_time=wait_time,
            stop_on_first=stop_on_first,
            try_common=try_common,
            verbose=verbose,
            loop_users=loop_users,
            password_gen=password_gen,
            combo_file=combo_file,
        )

    async def ftp_brute(
        self,
        target: str,
        username: Optional[str] = None,
        userlist: Optional[str] = None,
        password: Optional[str] = None,
        passlist: Optional[str] = None,
        port: int = 21,
        threads: int = 8,
        timeout: int = 600,
        wait_time: Optional[int] = None,
        stop_on_first: bool = False,
        try_common: Optional[str] = None,
        verbose: bool = False,
        loop_users: bool = False,
        password_gen: Optional[str] = None,
        combo_file: Optional[str] = None,
    ) -> ToolResult:
        """Brute-force FTP login (convenience method)."""
        # If no username or userlist specified, try common FTP usernames
        effective_userlist = userlist
        if not username and not userlist and not combo_file:
            effective_userlist = "usernames"

        return await self.bruteforce(
            target=target,
            service="ftp",
            username=username,
            userlist=effective_userlist,
            password=password,
            passlist=passlist,
            port=port,
            threads=threads,
            timeout=timeout,
            wait_time=wait_time,
            stop_on_first=stop_on_first,
            try_common=try_common,
            verbose=verbose,
            loop_users=loop_users,
            password_gen=password_gen,
            combo_file=combo_file,
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
        password: Optional[str] = None,
        passlist: Optional[str] = None,
        https: bool = False,
        port: Optional[int] = None,
        threads: int = 16,
        extra_params: Optional[str] = None,
        timeout: int = 600,
        wait_time: Optional[int] = None,
        stop_on_first: bool = False,
        try_common: Optional[str] = None,
        verbose: bool = False,
        loop_users: bool = False,
        password_gen: Optional[str] = None,
        combo_file: Optional[str] = None,
        ssl: bool = False,
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
            password=password,
            passlist=passlist,
            port=port or default_port,
            threads=threads,
            timeout=timeout,
            wait_time=wait_time,
            stop_on_first=stop_on_first,
            try_common=try_common,
            verbose=verbose,
            http_form=form_string,
            loop_users=loop_users,
            password_gen=password_gen,
            combo_file=combo_file,
            ssl=ssl,
        )

    async def mysql_brute(
        self,
        target: str,
        username: str = "root",
        userlist: Optional[str] = None,
        password: Optional[str] = None,
        passlist: Optional[str] = None,
        port: int = 3306,
        threads: int = 4,
        timeout: int = 600,
        wait_time: Optional[int] = None,
        stop_on_first: bool = False,
        try_common: Optional[str] = None,
        verbose: bool = False,
        loop_users: bool = False,
        password_gen: Optional[str] = None,
        combo_file: Optional[str] = None,
    ) -> ToolResult:
        """Brute-force MySQL login."""
        return await self.bruteforce(
            target=target,
            service="mysql",
            username=username if not userlist and not combo_file else None,
            userlist=userlist,
            password=password,
            passlist=passlist,
            port=port,
            threads=threads,
            timeout=timeout,
            wait_time=wait_time,
            stop_on_first=stop_on_first,
            try_common=try_common,
            verbose=verbose,
            loop_users=loop_users,
            password_gen=password_gen,
            combo_file=combo_file,
        )


if __name__ == "__main__":
    HydraServer.main()
