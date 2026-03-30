#!/usr/bin/env python3
"""
OpenSploit MCP Server: chisel
HTTP-based tunneling via Chisel v1.11.4 (jpillora/chisel).

Manages long-lived chisel server and client processes for port forwarding,
reverse tunnels, and SOCKS proxies over HTTP/WebSocket. Uses the same
stateful process management pattern as the tunnel MCP server.
"""

import asyncio
import os
import signal
import socket
from typing import Any, Dict, List, Optional

from mcp_common.base_server import BaseMCPServer, ToolResult
from mcp_common.output_parsers import sanitize_output

CHISEL_BIN = "/usr/local/bin/chisel"


class ChiselServer(BaseMCPServer):
    """MCP server for chisel HTTP tunneling."""

    def __init__(self):
        super().__init__(
            name="chisel",
            description="HTTP-based tunneling and SOCKS proxy via chisel",
            version="1.0.0",
        )

        # Track active processes: {id: {"process": proc, "type": ..., ...}}
        self.processes: Dict[str, Dict[str, Any]] = {}
        self.next_id = 1

        self.register_method(
            name="server",
            description="Start a chisel server — listens for client connections over HTTP/WebSocket",
            params={
                "port": {
                    "type": "integer",
                    "default": 8080,
                    "description": "HTTP listening port for the chisel server (default: 8080).",
                },
                "host": {
                    "type": "string",
                    "default": "0.0.0.0",
                    "description": "Network interface to bind to (default: 0.0.0.0 = all interfaces).",
                },
                "reverse": {
                    "type": "boolean",
                    "default": True,
                    "description": "Allow clients to use reverse port forwarding. Enabled by default for pentest workflows.",
                },
                "socks5": {
                    "type": "boolean",
                    "default": True,
                    "description": "Enable internal SOCKS5 proxy for clients. Enabled by default.",
                },
                "auth": {
                    "type": "string",
                    "description": "Optional authentication in 'user:pass' format. Clients must provide matching --auth.",
                },
                "backend": {
                    "type": "string",
                    "description": "URL of a backend HTTP server to proxy non-chisel requests to. Hides chisel behind a legitimate web server.",
                },
                "verbose": {
                    "type": "boolean",
                    "default": False,
                    "description": "Enable verbose logging.",
                },
            },
            handler=self.start_server,
        )

        self.register_method(
            name="client_forward",
            description="Create a forward tunnel — access a remote service via a local port",
            params={
                "server_url": {
                    "type": "string",
                    "required": True,
                    "description": "Chisel server URL (e.g., 'http://attacker-ip:8080' or 'https://...'). Must be a running chisel server.",
                },
                "local_port": {
                    "type": "integer",
                    "default": 0,
                    "description": "Local port to listen on (0 = auto-assign). Traffic to this port is forwarded through the server.",
                },
                "remote_host": {
                    "type": "string",
                    "default": "127.0.0.1",
                    "description": "Remote host to forward to (from the server's perspective). Default: server's localhost.",
                },
                "remote_port": {
                    "type": "integer",
                    "required": True,
                    "description": "Remote port to forward to (e.g., 3306 for MySQL, 8080 for web app).",
                },
                "auth": {
                    "type": "string",
                    "description": "Authentication 'user:pass' matching the server's --auth.",
                },
                "fingerprint": {
                    "type": "string",
                    "description": "Server public key fingerprint for MITM detection (44-char base64 SHA256).",
                },
                "max_retry_count": {
                    "type": "integer",
                    "default": 3,
                    "description": "Max reconnection attempts before giving up (default: 3). Set to 0 for unlimited.",
                },
                "verbose": {
                    "type": "boolean",
                    "default": False,
                    "description": "Enable verbose logging.",
                },
            },
            handler=self.client_forward,
        )

        self.register_method(
            name="client_reverse",
            description="Create a reverse tunnel — expose a client-side service on the server",
            params={
                "server_url": {
                    "type": "string",
                    "required": True,
                    "description": "Chisel server URL. Server must have --reverse enabled.",
                },
                "remote_port": {
                    "type": "integer",
                    "required": True,
                    "description": "Port the SERVER will listen on for incoming connections.",
                },
                "local_host": {
                    "type": "string",
                    "default": "127.0.0.1",
                    "description": "Local host to forward to (from the client's perspective).",
                },
                "local_port": {
                    "type": "integer",
                    "required": True,
                    "description": "Local port to forward to (e.g., 22 for SSH, 80 for HTTP). Traffic arriving at server:remote_port reaches client:local_host:local_port.",
                },
                "auth": {
                    "type": "string",
                    "description": "Authentication 'user:pass' matching the server's --auth.",
                },
                "fingerprint": {
                    "type": "string",
                    "description": "Server public key fingerprint.",
                },
                "max_retry_count": {
                    "type": "integer",
                    "default": 3,
                    "description": "Max reconnection attempts.",
                },
                "verbose": {
                    "type": "boolean",
                    "default": False,
                    "description": "Enable verbose logging.",
                },
            },
            handler=self.client_reverse,
        )

        self.register_method(
            name="client_socks",
            description="Create a SOCKS5 proxy through a chisel server — route all traffic through the server's network",
            params={
                "server_url": {
                    "type": "string",
                    "required": True,
                    "description": "Chisel server URL. Server must have --socks5 enabled.",
                },
                "socks_port": {
                    "type": "integer",
                    "default": 1080,
                    "description": "Local port for the SOCKS5 proxy (default: 1080).",
                },
                "auth": {
                    "type": "string",
                    "description": "Authentication 'user:pass' matching the server's --auth.",
                },
                "fingerprint": {
                    "type": "string",
                    "description": "Server public key fingerprint.",
                },
                "max_retry_count": {
                    "type": "integer",
                    "default": 3,
                    "description": "Max reconnection attempts.",
                },
                "verbose": {
                    "type": "boolean",
                    "default": False,
                    "description": "Enable verbose logging.",
                },
            },
            handler=self.client_socks,
        )

        self.register_method(
            name="list",
            description="List all active chisel servers and client tunnels",
            params={},
            handler=self.list_processes,
        )

        self.register_method(
            name="close",
            description="Close a specific chisel server or client tunnel by ID",
            params={
                "id": {
                    "type": "string",
                    "required": True,
                    "description": "Process ID to close (from list output).",
                },
            },
            handler=self.close_process,
        )

    # ── Helpers ─────────────────────────────────────────────────

    def _get_next_id(self, prefix: str = "chisel") -> str:
        proc_id = f"{prefix}-{self.next_id}"
        self.next_id += 1
        return proc_id

    def _find_free_port(self) -> int:
        """Find an available local port."""
        with socket.socket(socket.AF_INET, socket.SOCK_STREAM) as s:
            s.bind(("", 0))
            return s.getsockname()[1]

    def _is_port_available(self, port: int) -> bool:
        """Check if a port is available for binding."""
        try:
            with socket.socket(socket.AF_INET, socket.SOCK_STREAM) as s:
                s.setsockopt(socket.SOL_SOCKET, socket.SO_REUSEADDR, 1)
                s.bind(("127.0.0.1", port))
                return True
        except OSError:
            return False

    async def _start_process(
        self,
        cmd: List[str],
        proc_id: str,
        metadata: Dict[str, Any],
        startup_wait: float = 2.0,
    ) -> ToolResult:
        """Start a chisel process and track it."""
        self.logger.info(f"Starting {proc_id}: {' '.join(cmd)}")

        try:
            proc = await asyncio.create_subprocess_exec(
                *cmd,
                stdout=asyncio.subprocess.PIPE,
                stderr=asyncio.subprocess.PIPE,
            )

            # Wait briefly to detect immediate failures
            await asyncio.sleep(startup_wait)

            if proc.returncode is not None:
                combined = await self._read_remaining(proc)
                return ToolResult(
                    success=False,
                    error=f"Process exited immediately (code {proc.returncode}): {combined[:500]}",
                    raw_output=sanitize_output(combined),
                )

            # Read any initial output (fingerprint, startup messages)
            initial_output = ""
            try:
                # Non-blocking read of whatever's available
                stderr_data = await asyncio.wait_for(proc.stderr.read(4096), timeout=0.5)
                initial_output = stderr_data.decode()
            except asyncio.TimeoutError:
                pass

            # Extract server fingerprint if present
            fingerprint = None
            for line in initial_output.split("\n"):
                if "Fingerprint" in line:
                    parts = line.split()
                    for p in parts:
                        if len(p) == 44 and p.endswith("="):
                            fingerprint = p
                            break

            metadata["process"] = proc
            metadata["pid"] = proc.pid
            if fingerprint:
                metadata["fingerprint"] = fingerprint

            self.processes[proc_id] = metadata

            data = {k: v for k, v in metadata.items() if k != "process"}
            data["id"] = proc_id
            data["status"] = "running"

            return ToolResult(
                success=True,
                data=data,
                raw_output=sanitize_output(initial_output) if initial_output else f"Started {proc_id}",
            )

        except FileNotFoundError:
            return ToolResult(
                success=False,
                error=f"chisel binary not found at {CHISEL_BIN}",
            )
        except Exception as e:
            return ToolResult(success=False, error=str(e))

    # ── Method Handlers ────────────────────────────────────────

    async def start_server(
        self,
        port: int = 8080,
        host: str = "0.0.0.0",
        reverse: bool = True,
        socks5: bool = True,
        auth: Optional[str] = None,
        backend: Optional[str] = None,
        verbose: bool = False,
    ) -> ToolResult:
        """Start a chisel server."""
        # Check if port is already in use by another chisel server
        for pid, info in self.processes.items():
            if info.get("type") == "server" and info.get("port") == port:
                proc = info.get("process")
                if proc and proc.returncode is None:
                    return ToolResult(
                        success=False,
                        error=f"Port {port} already in use by {pid}",
                    )

        cmd = [CHISEL_BIN, "server", "--host", host, "--port", str(port)]

        if reverse:
            cmd.append("--reverse")
        if socks5:
            cmd.append("--socks5")
        if auth:
            cmd.extend(["--auth", auth])
        if backend:
            cmd.extend(["--backend", backend])
        if verbose:
            cmd.append("-v")

        proc_id = self._get_next_id("server")
        metadata = {
            "type": "server",
            "port": port,
            "host": host,
            "reverse": reverse,
            "socks5": socks5,
            "auth_enabled": auth is not None,
        }

        return await self._start_process(cmd, proc_id, metadata)

    async def client_forward(
        self,
        server_url: str,
        remote_port: int,
        local_port: int = 0,
        remote_host: str = "127.0.0.1",
        auth: Optional[str] = None,
        fingerprint: Optional[str] = None,
        max_retry_count: int = 3,
        verbose: bool = False,
    ) -> ToolResult:
        """Create a forward tunnel via chisel client."""
        if local_port == 0:
            local_port = self._find_free_port()

        # Build remote spec: local_port:remote_host:remote_port
        remote_spec = f"{local_port}:{remote_host}:{remote_port}"

        cmd = [CHISEL_BIN, "client"]
        if auth:
            cmd.extend(["--auth", auth])
        if fingerprint:
            cmd.extend(["--fingerprint", fingerprint])
        if max_retry_count > 0:
            cmd.extend(["--max-retry-count", str(max_retry_count)])
        if verbose:
            cmd.append("-v")

        cmd.extend([server_url, remote_spec])

        proc_id = self._get_next_id("fwd")
        metadata = {
            "type": "forward",
            "server_url": server_url,
            "local_port": local_port,
            "remote_host": remote_host,
            "remote_port": remote_port,
            "mapping": remote_spec,
            "connect_to": f"127.0.0.1:{local_port}",
        }

        return await self._start_process(cmd, proc_id, metadata)

    async def client_reverse(
        self,
        server_url: str,
        remote_port: int,
        local_port: int,
        local_host: str = "127.0.0.1",
        auth: Optional[str] = None,
        fingerprint: Optional[str] = None,
        max_retry_count: int = 3,
        verbose: bool = False,
    ) -> ToolResult:
        """Create a reverse tunnel via chisel client."""
        # Check if remote port is available, find free one if not
        if not self._is_port_available(remote_port):
            self.logger.warning(f"Port {remote_port} unavailable, finding free port")
            remote_port = self._find_free_port()

        # Build reverse remote spec: R:remote_port:local_host:local_port
        remote_spec = f"R:{remote_port}:{local_host}:{local_port}"

        cmd = [CHISEL_BIN, "client"]
        if auth:
            cmd.extend(["--auth", auth])
        if fingerprint:
            cmd.extend(["--fingerprint", fingerprint])
        if max_retry_count > 0:
            cmd.extend(["--max-retry-count", str(max_retry_count)])
        if verbose:
            cmd.append("-v")

        cmd.extend([server_url, remote_spec])

        proc_id = self._get_next_id("rev")
        metadata = {
            "type": "reverse",
            "server_url": server_url,
            "remote_port": remote_port,
            "local_host": local_host,
            "local_port": local_port,
            "mapping": remote_spec,
            "server_listens_on": f"0.0.0.0:{remote_port}",
        }

        return await self._start_process(cmd, proc_id, metadata)

    async def client_socks(
        self,
        server_url: str,
        socks_port: int = 1080,
        auth: Optional[str] = None,
        fingerprint: Optional[str] = None,
        max_retry_count: int = 3,
        verbose: bool = False,
    ) -> ToolResult:
        """Create a SOCKS5 proxy through a chisel server."""
        # Check if requested port is available, find free one if not
        if not self._is_port_available(socks_port):
            self.logger.warning(f"Port {socks_port} unavailable, finding free port")
            socks_port = self._find_free_port()

        # Build socks remote spec: socks_port:socks
        remote_spec = f"{socks_port}:socks"

        cmd = [CHISEL_BIN, "client"]
        if auth:
            cmd.extend(["--auth", auth])
        if fingerprint:
            cmd.extend(["--fingerprint", fingerprint])
        if max_retry_count > 0:
            cmd.extend(["--max-retry-count", str(max_retry_count)])
        if verbose:
            cmd.append("-v")

        cmd.extend([server_url, remote_spec])

        proc_id = self._get_next_id("socks")
        metadata = {
            "type": "socks",
            "server_url": server_url,
            "socks_port": socks_port,
            "mapping": remote_spec,
            "proxy_url": f"socks5://127.0.0.1:{socks_port}",
        }

        return await self._start_process(cmd, proc_id, metadata)

    async def list_processes(self) -> ToolResult:
        """List all active chisel processes."""
        active = []
        dead = []

        for proc_id, info in list(self.processes.items()):
            proc = info.get("process")
            if proc and proc.returncode is None:
                entry = {k: v for k, v in info.items() if k != "process"}
                entry["id"] = proc_id
                # Health check: verify port is actually bound for tunnel processes
                if info.get("type") in ("socks", "reverse"):
                    port = info.get("socks_port") or info.get("remote_port")
                    if port and self._is_port_available(port):
                        entry["status"] = "degraded"
                        entry["warning"] = f"Port {port} not bound — tunnel may be broken"
                    else:
                        entry["status"] = "running"
                else:
                    entry["status"] = "running"
                active.append(entry)
            else:
                dead.append(proc_id)

        # Prune dead entries
        for proc_id in dead:
            del self.processes[proc_id]

        return ToolResult(
            success=True,
            data={
                "processes": active,
                "count": len(active),
            },
            raw_output=f"{len(active)} active chisel process(es)",
        )

    async def close_process(self, id: str) -> ToolResult:
        """Close a specific chisel process."""
        if id not in self.processes:
            return ToolResult(
                success=False,
                error=f"Process {id} not found. Use 'list' to see active processes.",
            )

        info = self.processes[id]
        proc = info.get("process")

        if proc is None:
            del self.processes[id]
            return ToolResult(
                success=False,
                error=f"Process {id} has no associated process object.",
            )

        try:
            proc.terminate()
            await asyncio.wait_for(proc.wait(), timeout=5)
        except asyncio.TimeoutError:
            proc.kill()
            await proc.wait()

        # Wait briefly for port release from TIME_WAIT
        port = info.get("port") or info.get("socks_port") or info.get("remote_port")
        if port:
            for _ in range(5):
                if self._is_port_available(port):
                    break
                await asyncio.sleep(1)

        proc_type = info.get("type", "unknown")
        del self.processes[id]

        return ToolResult(
            success=True,
            data={"id": id, "type": proc_type, "status": "closed"},
            raw_output=f"Closed {proc_type} process {id}",
        )


if __name__ == "__main__":
    ChiselServer.main()
