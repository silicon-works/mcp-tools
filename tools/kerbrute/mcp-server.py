#!/usr/bin/env python3
"""
OpenSploit MCP Server: kerbrute
Kerberos username enumeration and password spraying via AS-REQ responses.

Wraps kerbrute v1.0.3 Go binary (github.com/ropnop/kerbrute).
Subcommands: userenum, passwordspray, bruteforce, bruteuser.
"""

import os
import re
import tempfile
from typing import Any, Dict

from mcp_common.base_server import BaseMCPServer, ToolResult
from mcp_common.output_parsers import sanitize_output

# Regex to strip ANSI escape codes from parsed strings
_ANSI_RE = re.compile(r"\x1B(?:[@-Z\\-_]|\[[0-?]*[ -/]*[@-~])")


class KerbruteServer(BaseMCPServer):
    KERBRUTE_BIN = "/app/kerbrute"

    def __init__(self):
        super().__init__(
            name="kerbrute",
            description="Kerberos username enumeration and password spraying",
            version="1.0.3",
        )

        # Shared params for all methods that talk to a DC
        common_params = {
            "dc": {
                "type": "string",
                "required": True,
                "description": "Domain controller IP address or hostname (port 88 must be reachable)",
            },
            "domain": {
                "type": "string",
                "required": True,
                "description": "Full AD domain name (e.g., corp.local). Capitalised internally as the Kerberos realm.",
            },
            "threads": {
                "type": "integer",
                "default": 10,
                "description": "Number of concurrent threads (kerbrute default: 10). Reduce to 1 for stealth or if lockout policies are aggressive.",
            },
            "delay": {
                "type": "integer",
                "description": "Delay in milliseconds between each attempt. Forces single-threaded mode when set. Use to avoid detection or lockout.",
            },
            "safe": {
                "type": "boolean",
                "default": False,
                "description": "Safe mode — abort immediately if any account comes back as locked out. Prevents further lockouts.",
            },
            "timeout": {
                "type": "integer",
                "default": 120,
                "description": "Maximum execution time in seconds.",
            },
        }

        self.register_method(
            name="userenum",
            description="Enumerate valid AD usernames by sending Kerberos AS-REQ packets to the KDC",
            params={
                **common_params,
                "usernames": {
                    "type": "string",
                    "required": True,
                    "description": "Newline-separated list of usernames to test (without @domain suffix)",
                },
            },
            handler=self.userenum,
        )

        self.register_method(
            name="passwordspray",
            description="Test a single password against multiple usernames via Kerberos pre-authentication",
            params={
                **common_params,
                "usernames": {
                    "type": "string",
                    "required": True,
                    "description": "Newline-separated list of usernames to spray",
                },
                "password": {
                    "type": "string",
                    "required": True,
                    "description": "Single password to test against all usernames",
                },
                "user_as_pass": {
                    "type": "boolean",
                    "default": False,
                    "description": "Also try each username as its own password (--user-as-pass flag)",
                },
            },
            handler=self.passwordspray,
        )

        self.register_method(
            name="bruteforce",
            description="Test username:password combinations from a combo list via Kerberos",
            params={
                **common_params,
                "combos": {
                    "type": "string",
                    "required": True,
                    "description": "Newline-separated username:password pairs (e.g., 'admin:Password1\\nuser1:Welcome1')",
                },
            },
            handler=self.bruteforce,
        )

        self.register_method(
            name="bruteuser",
            description="Brute-force a single user's password from a wordlist via Kerberos",
            params={
                **common_params,
                "username": {
                    "type": "string",
                    "required": True,
                    "description": "Single username to brute-force",
                },
                "passwords": {
                    "type": "string",
                    "required": True,
                    "description": "Newline-separated list of passwords to try against the user",
                },
            },
            handler=self.bruteuser,
        )

    # ── Helpers ─────────────────────────────────────────────

    def _write_temp_file(self, content: str) -> str:
        """Write content to a temporary file and return its path."""
        fd, path = tempfile.mkstemp(suffix=".txt", prefix="kerbrute_")
        with os.fdopen(fd, "w") as f:
            f.write(content)
        return path

    def _build_common_args(
        self,
        subcommand: str,
        dc: str,
        domain: str,
        threads: int = 10,
        delay: int | None = None,
        safe: bool = False,
    ) -> list[str]:
        """Build the common CLI args shared by all subcommands."""
        # Clamp threads to a sane range (kerbrute panics on negative values)
        if not isinstance(threads, int) or threads < 1:
            threads = 10
        cmd = [
            self.KERBRUTE_BIN, subcommand,
            "--dc", dc,
            "-d", domain,
            "-v",               # always verbose so we capture failure lines
            "-t", str(threads),
        ]
        if delay is not None:
            cmd.extend(["--delay", str(delay)])
        if safe:
            cmd.append("--safe")
        return cmd

    def _parse_userenum_output(self, output: str, input_count: int) -> Dict[str, Any]:
        """Parse kerbrute userenum output.

        Known output patterns (verified against live AD):
          [+] VALID USERNAME:\t administrator@fries.htb
          [!] guest@fries.htb - USER LOCKED OUT
          [!] fakeuser99999@fries.htb - User does not exist    (with -v)
          Done! Tested 5 usernames (1 valid) in 0.099 seconds
        """
        valid_users = []
        invalid_users = []
        locked_users = []
        errors = []

        for line in output.splitlines():
            # Valid user: [+] VALID USERNAME:\t administrator@fries.htb
            m = re.search(r"\[\+\]\s+VALID USERNAME:\s+(\S+?)@", line, re.IGNORECASE)
            if m:
                valid_users.append(m.group(1))
                continue
            # Locked/disabled account: [!] guest@fries.htb - USER LOCKED OUT
            m = re.search(r"\[!\]\s+(\S+?)@\S+\s+-\s+USER LOCKED OUT", line, re.IGNORECASE)
            if m:
                locked_users.append(m.group(1))
                continue
            # Invalid user (verbose): [!] fakeuser99999@fries.htb - User does not exist
            m = re.search(r"\[!\]\s+(\S+?)@\S+\s+-\s+User does not exist", line)
            if m:
                invalid_users.append(m.group(1))
                continue
            # Network or KDC errors (verbose lines), skip "Using KDC"
            m = re.search(r"\[!\]\s+(.+)", line)
            if m and "Using KDC" not in line:
                errors.append(_ANSI_RE.sub("", m.group(1)).strip())

        # Parse summary line: "Done! Tested 5 usernames (1 valid) in 0.099 seconds"
        total_match = re.search(r"Tested\s+(\d+)\s+usernames\s+\((\d+)\s+valid\)", output)
        if total_match:
            total_tested = int(total_match.group(1))
        else:
            total_tested = input_count

        return {
            "valid_users": valid_users,
            "valid_count": len(valid_users),
            "invalid_users": invalid_users,
            "locked_users": locked_users,
            "locked_count": len(locked_users),
            "total_tested": total_tested,
            "errors": errors if errors else None,
        }

    def _parse_login_output(self, output: str, input_count: int) -> Dict[str, Any]:
        """Parse kerbrute passwordspray/bruteforce/bruteuser output.

        Known output patterns:
          [+] VALID LOGIN:  callen@lab.ropnop.com:Password123
          [!] <user>@domain - account locked / disabled
          [-] <user>@domain:<pass> - <error>                    (with -v)
          Done! Tested 5 logins (1 successes) in 0.122 seconds
        """
        valid_logins = []
        locked_users = []
        failed_count = 0
        errors = []

        for line in output.splitlines():
            # Valid login: [+] VALID LOGIN:  user@domain:password
            m = re.search(r"\[\+\]\s+VALID LOGIN:\s+(\S+?)@\S+?:(.+)", line, re.IGNORECASE)
            if m:
                valid_logins.append({
                    "username": m.group(1),
                    "password": m.group(2).strip(),
                })
                continue
            # Locked/disabled account: [!] user@domain:pass - USER LOCKED OUT
            m = re.search(r"\[!\]\s+(\S+?)@\S+.*USER LOCKED OUT", line, re.IGNORECASE)
            if m:
                locked_users.append(m.group(1))
                continue
            # Invalid password: [!] administrator@fries.htb:WrongPass - Invalid password
            if re.search(r"\[!\].*Invalid password", line, re.IGNORECASE):
                failed_count += 1
                continue
            # Failed login (verbose [-] lines): [-] user@domain:pass - KDC_ERR_PREAUTH_FAILED
            if re.search(r"\[-\]", line):
                failed_count += 1
                continue
            # Network/KDC errors (remaining [!] lines)
            m = re.search(r"\[!\]\s+(.+)", line)
            if m and "Using KDC" not in line:
                errors.append(_ANSI_RE.sub("", m.group(1)).strip())

        # Parse summary: "Done! Tested 5 logins (1 successes) in 0.122 seconds"
        total_match = re.search(r"Tested\s+(\d+)\s+logins?\s+\((\d+)\s+success", output)
        if total_match:
            total_tested = int(total_match.group(1))
        else:
            total_tested = input_count

        return {
            "valid_logins": valid_logins,
            "valid_count": len(valid_logins),
            "failed_count": failed_count,
            "locked_users": locked_users,
            "total_tested": total_tested,
            "errors": errors if errors else None,
        }

    def _count_lines(self, text: str) -> int:
        """Count non-empty lines in text."""
        return len([l for l in text.splitlines() if l.strip()])

    # ── Methods ─────────────────────────────────────────────

    async def userenum(
        self,
        dc: str,
        domain: str,
        usernames: str,
        threads: int = 10,
        delay: int | None = None,
        safe: bool = False,
        timeout: int = 120,
    ) -> ToolResult:
        """Enumerate valid Kerberos usernames."""
        usernames = usernames.strip()
        if not usernames:
            return ToolResult(success=False, error="Empty username list provided. Supply newline-separated usernames.")

        input_count = self._count_lines(usernames)
        tmpfile = self._write_temp_file(usernames)
        try:
            cmd = self._build_common_args("userenum", dc, domain, threads, delay, safe)
            cmd.append(tmpfile)

            result = await self.run_command(cmd, timeout=timeout)
            combined = result.stdout + result.stderr
            parsed = self._parse_userenum_output(combined, input_count)

            return ToolResult(
                success=True,
                data={
                    "method": "userenum",
                    "dc": dc,
                    "domain": domain,
                    **parsed,
                },
                raw_output=sanitize_output(combined),
            )
        except Exception as e:
            return ToolResult(success=False, error=str(e))
        finally:
            if os.path.exists(tmpfile):
                os.unlink(tmpfile)

    async def passwordspray(
        self,
        dc: str,
        domain: str,
        usernames: str,
        password: str,
        user_as_pass: bool = False,
        threads: int = 10,
        delay: int | None = None,
        safe: bool = False,
        timeout: int = 120,
    ) -> ToolResult:
        """Spray a single password against multiple usernames."""
        usernames = usernames.strip()
        if not usernames:
            return ToolResult(success=False, error="Empty username list provided. Supply newline-separated usernames.")
        if not password and not user_as_pass:
            return ToolResult(success=False, error="No password provided. Supply a password or set user_as_pass=true.")

        input_count = self._count_lines(usernames)
        tmpfile = self._write_temp_file(usernames)
        try:
            cmd = self._build_common_args("passwordspray", dc, domain, threads, delay, safe)
            if user_as_pass:
                cmd.append("--user-as-pass")
            cmd.append(tmpfile)
            if password:
                cmd.append(password)

            result = await self.run_command(cmd, timeout=timeout)
            combined = result.stdout + result.stderr
            parsed = self._parse_login_output(combined, input_count)

            return ToolResult(
                success=True,
                data={
                    "method": "passwordspray",
                    "dc": dc,
                    "domain": domain,
                    "password_tested": password or "(user-as-pass)",
                    **parsed,
                },
                raw_output=sanitize_output(combined),
            )
        except Exception as e:
            return ToolResult(success=False, error=str(e))
        finally:
            if os.path.exists(tmpfile):
                os.unlink(tmpfile)

    async def bruteforce(
        self,
        dc: str,
        domain: str,
        combos: str,
        threads: int = 10,
        delay: int | None = None,
        safe: bool = False,
        timeout: int = 120,
    ) -> ToolResult:
        """Test username:password combinations."""
        combos = combos.strip()
        if not combos:
            return ToolResult(success=False, error="Empty combo list provided. Supply newline-separated user:pass pairs.")

        input_count = self._count_lines(combos)
        tmpfile = self._write_temp_file(combos)
        try:
            cmd = self._build_common_args("bruteforce", dc, domain, threads, delay, safe)
            cmd.append(tmpfile)

            result = await self.run_command(cmd, timeout=timeout)
            combined = result.stdout + result.stderr
            parsed = self._parse_login_output(combined, input_count)

            return ToolResult(
                success=True,
                data={
                    "method": "bruteforce",
                    "dc": dc,
                    "domain": domain,
                    **parsed,
                },
                raw_output=sanitize_output(combined),
            )
        except Exception as e:
            return ToolResult(success=False, error=str(e))
        finally:
            if os.path.exists(tmpfile):
                os.unlink(tmpfile)

    async def bruteuser(
        self,
        dc: str,
        domain: str,
        username: str,
        passwords: str,
        threads: int = 10,
        delay: int | None = None,
        safe: bool = False,
        timeout: int = 120,
    ) -> ToolResult:
        """Brute-force a single user's password from a wordlist."""
        username = username.strip()
        if not username:
            return ToolResult(success=False, error="No username provided.")
        passwords = passwords.strip()
        if not passwords:
            return ToolResult(success=False, error="Empty password list provided. Supply newline-separated passwords.")

        input_count = self._count_lines(passwords)
        tmpfile = self._write_temp_file(passwords)
        try:
            cmd = self._build_common_args("bruteuser", dc, domain, threads, delay, safe)
            # bruteuser syntax: kerbrute bruteuser <password_list> <username>
            cmd.append(tmpfile)
            cmd.append(username)

            result = await self.run_command(cmd, timeout=timeout)
            combined = result.stdout + result.stderr
            parsed = self._parse_login_output(combined, input_count)

            return ToolResult(
                success=True,
                data={
                    "method": "bruteuser",
                    "dc": dc,
                    "domain": domain,
                    "target_user": username,
                    **parsed,
                },
                raw_output=sanitize_output(combined),
            )
        except Exception as e:
            return ToolResult(success=False, error=str(e))
        finally:
            if os.path.exists(tmpfile):
                os.unlink(tmpfile)


if __name__ == "__main__":
    KerbruteServer.main()
