#!/usr/bin/env python3
"""
OpenSploit MCP Server: smtp

SMTP testing via swaks (email sending, relay testing) and user enumeration
via smtp-user-enum (VRFY/EXPN/RCPT TO methods).
"""

import asyncio
import re
from typing import Any, Dict, List, Optional

from mcp_common import BaseMCPServer, ToolResult, ToolError, sanitize_output


class SmtpServer(BaseMCPServer):
    """MCP server wrapping swaks and smtp-user-enum for SMTP testing."""

    def __init__(self):
        super().__init__(
            name="smtp",
            description="SMTP testing via swaks and user enumeration via smtp-user-enum",
            version="1.0.0",
        )

        self.register_method(
            name="send",
            description="Send a crafted email via SMTP using swaks",
            params={
                "server": {
                    "type": "string",
                    "required": True,
                    "description": "SMTP server hostname or IP address",
                },
                "to": {
                    "type": "string",
                    "required": True,
                    "description": "Recipient email address",
                },
                "from_addr": {
                    "type": "string",
                    "default": "test@test.com",
                    "description": "Sender email address (can be spoofed if server allows)",
                },
                "subject": {
                    "type": "string",
                    "description": "Email subject line",
                },
                "body": {
                    "type": "string",
                    "description": "Email body text",
                },
                "headers": {
                    "type": "array",
                    "description": "Additional headers as list of 'Header: value' strings",
                },
                "port": {
                    "type": "integer",
                    "default": 25,
                    "description": "SMTP port (25=SMTP, 465=SMTPS, 587=submission)",
                },
                "tls": {
                    "type": "boolean",
                    "default": False,
                    "description": "Use STARTTLS",
                },
                "auth_user": {
                    "type": "string",
                    "description": "SMTP auth username (if server requires authentication)",
                },
                "auth_password": {
                    "type": "string",
                    "description": "SMTP auth password",
                },
                "ehlo": {
                    "type": "string",
                    "description": "Custom EHLO/HELO hostname",
                },
                "timeout": {
                    "type": "integer",
                    "default": 30,
                    "description": "Connection timeout in seconds",
                },
            },
            handler=self.send,
        )

        self.register_method(
            name="enum_users",
            description="Enumerate valid SMTP users via VRFY, EXPN, or RCPT TO methods",
            params={
                "server": {
                    "type": "string",
                    "required": True,
                    "description": "SMTP server hostname or IP address",
                },
                "usernames": {
                    "type": "array",
                    "required": True,
                    "description": "List of usernames to test (e.g., ['root', 'admin', 'michael', 'www-data'])",
                },
                "method": {
                    "type": "string",
                    "enum": ["VRFY", "EXPN", "RCPT"],
                    "default": "VRFY",
                    "description": "Enumeration method: VRFY (verify user exists), EXPN (expand mailing list), RCPT (check via RCPT TO)",
                },
                "domain": {
                    "type": "string",
                    "description": "Domain to append to usernames for RCPT method (e.g., 'trick.htb' → user@trick.htb)",
                },
                "port": {
                    "type": "integer",
                    "default": 25,
                    "description": "SMTP port",
                },
                "timeout": {
                    "type": "integer",
                    "default": 10,
                    "description": "Timeout per user check in seconds",
                },
            },
            handler=self.enum_users,
        )

        self.register_method(
            name="relay_test",
            description="Test if an SMTP server is an open relay",
            params={
                "server": {
                    "type": "string",
                    "required": True,
                    "description": "SMTP server hostname or IP address",
                },
                "from_addr": {
                    "type": "string",
                    "default": "test@test.com",
                    "description": "Sender address to use in test",
                },
                "to_addr": {
                    "type": "string",
                    "default": "relay-test@example.com",
                    "description": "External recipient to test relay to",
                },
                "port": {
                    "type": "integer",
                    "default": 25,
                    "description": "SMTP port",
                },
                "timeout": {
                    "type": "integer",
                    "default": 30,
                    "description": "Connection timeout in seconds",
                },
            },
            handler=self.relay_test,
        )

    def _parse_swaks_output(self, output: str) -> Dict[str, Any]:
        """Parse swaks transaction output into structured data."""
        result = {
            "connection": None,
            "ehlo_response": [],
            "mail_from_accepted": False,
            "rcpt_to_accepted": False,
            "data_accepted": False,
            "message_queued": False,
            "smtp_codes": [],
            "transaction_lines": [],
        }

        for line in output.split("\n"):
            line = line.strip()
            if not line:
                continue

            result["transaction_lines"].append(line)

            # Parse connection info
            if line.startswith("==="):
                if "Trying" in line:
                    result["connection"] = line
            # Parse SMTP response codes
            elif line.startswith("<"):
                # Server response lines like "<** 220 smtp.example.com"
                code_match = re.match(r"<[*~\s]*\s*(\d{3})\s*(.*)", line)
                if code_match:
                    code = int(code_match.group(1))
                    message = code_match.group(2).strip()
                    result["smtp_codes"].append({"code": code, "message": message})

                    if code == 250 and "MAIL FROM" in output[:output.index(line)] if line in output else False:
                        result["mail_from_accepted"] = True
            elif line.startswith("~"):
                # Swaks summary lines
                pass

            # Check key status indicators
            if "250" in line and "ok" in line.lower():
                result["message_queued"] = True

        # Simple status detection from raw output
        if "250 " in output and "MAIL FROM" in output:
            result["mail_from_accepted"] = True
        if "250 " in output and "RCPT TO" in output:
            result["rcpt_to_accepted"] = True
        if "354 " in output or "354" in output:
            result["data_accepted"] = True
        if "250 " in output and ("queued" in output.lower() or "ok" in output.lower()):
            result["message_queued"] = True

        return result

    async def send(
        self,
        server: str,
        to: str,
        from_addr: str = "test@test.com",
        subject: str = None,
        body: str = None,
        headers: list = None,
        port: int = 25,
        tls: bool = False,
        auth_user: str = None,
        auth_password: str = None,
        ehlo: str = None,
        timeout: int = 30,
    ) -> ToolResult:
        """Send a crafted email via SMTP using swaks."""
        self.logger.info(f"SMTP send: {from_addr} → {to} via {server}:{port}")

        cmd = [
            "swaks",
            "--to", to,
            "--from", from_addr,
            "--server", server,
            "--port", str(port),
            "--timeout", str(timeout),
        ]

        if subject:
            cmd.extend(["--header", f"Subject: {subject}"])
        if body:
            cmd.extend(["--body", body])
        if headers:
            for h in headers:
                cmd.extend(["--header", h])
        if tls:
            cmd.append("--tls")
        if auth_user:
            cmd.extend(["--auth", "--auth-user", auth_user])
            if auth_password:
                cmd.extend(["--auth-password", auth_password])
        if ehlo:
            cmd.extend(["--ehlo", ehlo])

        try:
            result = await self.run_command(cmd, timeout=timeout + 15)
            stdout = result.stdout.strip() if result.stdout else ""
            stderr = result.stderr.strip() if result.stderr else ""

            if result.returncode != 0:
                return ToolResult(
                    success=False,
                    data={"server": server, "port": port},
                    error=f"swaks failed (exit {result.returncode}): {stderr or stdout}",
                    raw_output=stdout,
                )

            parsed = self._parse_swaks_output(stdout)
            return ToolResult(
                success=True,
                data={
                    "server": server,
                    "port": port,
                    "from": from_addr,
                    "to": to,
                    "mail_from_accepted": parsed["mail_from_accepted"],
                    "rcpt_to_accepted": parsed["rcpt_to_accepted"],
                    "data_accepted": parsed["data_accepted"],
                    "message_queued": parsed["message_queued"],
                    "smtp_codes": parsed["smtp_codes"],
                },
                raw_output=stdout,
            )

        except Exception as e:
            return ToolResult(
                success=False,
                data={},
                error=f"SMTP send failed: {e}",
            )

    async def enum_users(
        self,
        server: str,
        usernames: list,
        method: str = "VRFY",
        domain: str = None,
        port: int = 25,
        timeout: int = 10,
    ) -> ToolResult:
        """Enumerate valid SMTP users via VRFY, EXPN, or RCPT TO."""
        self.logger.info(f"SMTP user enum: {server}:{port} method={method} users={len(usernames)}")

        cmd = [
            "smtp-user-enum",
            "-M", method,
            "-t", server,
            "-p", str(port),
        ]

        # Write usernames to a temp file
        import tempfile
        with tempfile.NamedTemporaryFile(mode="w", suffix=".txt", delete=False, dir="/tmp") as f:
            for user in usernames:
                if domain and method == "RCPT" and "@" not in user:
                    f.write(f"{user}@{domain}\n")
                else:
                    f.write(f"{user}\n")
            userfile = f.name

        cmd.extend(["-U", userfile])

        try:
            result = await self.run_command(cmd, timeout=timeout * len(usernames) + 30)
            stdout = result.stdout.strip() if result.stdout else ""
            stderr = result.stderr.strip() if result.stderr else ""

            # Parse results — smtp-user-enum output format:
            # <target>: <username> exists
            valid_users = []
            invalid_users = []

            for line in stdout.split("\n"):
                line = line.strip()
                if " exists" in line.lower():
                    # Extract username from "host: username exists" format
                    match = re.search(r":\s*(.+?)\s+exists", line, re.IGNORECASE)
                    if match:
                        valid_users.append(match.group(1).strip())
                elif "does not exist" in line.lower():
                    match = re.search(r":\s*(.+?)\s+does not exist", line, re.IGNORECASE)
                    if match:
                        invalid_users.append(match.group(1).strip())

            return ToolResult(
                success=True,
                data={
                    "server": server,
                    "port": port,
                    "method": method,
                    "valid_users": valid_users,
                    "valid_count": len(valid_users),
                    "tested_count": len(usernames),
                },
                raw_output=stdout,
            )

        except Exception as e:
            return ToolResult(
                success=False,
                data={},
                error=f"SMTP user enumeration failed: {e}",
            )
        finally:
            import os
            try:
                os.unlink(userfile)
            except OSError:
                pass

    async def relay_test(
        self,
        server: str,
        from_addr: str = "test@test.com",
        to_addr: str = "relay-test@example.com",
        port: int = 25,
        timeout: int = 30,
    ) -> ToolResult:
        """Test if an SMTP server is an open relay."""
        self.logger.info(f"SMTP relay test: {server}:{port}")

        cmd = [
            "swaks",
            "--to", to_addr,
            "--from", from_addr,
            "--server", server,
            "--port", str(port),
            "--timeout", str(timeout),
            "--quit-after", "RCPT",
        ]

        try:
            result = await self.run_command(cmd, timeout=timeout + 15)
            stdout = result.stdout.strip() if result.stdout else ""
            stderr = result.stderr.strip() if result.stderr else ""
            combined = stdout + "\n" + stderr

            # Check if RCPT TO was accepted for an external domain
            # Parse the specific RCPT TO response, not generic 250s from EHLO/MAIL FROM
            is_open_relay = False
            rcpt_accepted = False

            # Look for relay denied indicators
            if "relay" in combined.lower() and ("denied" in combined.lower() or "not permitted" in combined.lower()):
                is_open_relay = False
                rcpt_accepted = False
            elif any(code in combined for code in ["550", "553", "554", "454", "451"]):
                is_open_relay = False
                rcpt_accepted = False
            else:
                # Check if RCPT TO line was followed by a 250 response
                lines = combined.split("\n")
                for i, line in enumerate(lines):
                    if "RCPT TO" in line and i + 1 < len(lines):
                        next_line = lines[i + 1].strip()
                        if next_line.startswith("<") and "250" in next_line:
                            rcpt_accepted = True
                            is_open_relay = True
                            break

            return ToolResult(
                success=True,
                data={
                    "server": server,
                    "port": port,
                    "is_open_relay": is_open_relay,
                    "from": from_addr,
                    "to": to_addr,
                    "rcpt_accepted": rcpt_accepted,
                },
                raw_output=combined,
            )

        except Exception as e:
            return ToolResult(
                success=False,
                data={},
                error=f"SMTP relay test failed: {e}",
            )


if __name__ == "__main__":
    SmtpServer.main()
