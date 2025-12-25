#!/usr/bin/env python3
"""
OpenSploit MCP Server: tunnel

SSH tunnel and SOCKS proxy server for accessing remote localhost services.
Establishes persistent tunnels that other MCP tools can use.
"""

import asyncio
import os
import signal
import tempfile
from typing import Any, Dict, List, Optional

from mcp_common import BaseMCPServer, ToolResult, ToolError


class TunnelServer(BaseMCPServer):
    """MCP server for SSH tunneling and SOCKS proxy."""

    def __init__(self):
        super().__init__(
            name="tunnel",
            description="SSH tunnel and SOCKS proxy for accessing remote services",
            version="1.0.0",
        )

        # Track active tunnels: {tunnel_id: {"process": proc, "type": ..., ...}}
        self.tunnels: Dict[str, Dict[str, Any]] = {}
        self.next_id = 1

        self.register_method(
            name="forward",
            description="Create SSH local port forward (access remote service via local port)",
            params={
                "ssh_host": {
                    "type": "string",
                    "required": True,
                    "description": "SSH server hostname or IP",
                },
                "ssh_user": {
                    "type": "string",
                    "required": True,
                    "description": "SSH username",
                },
                "ssh_password": {
                    "type": "string",
                    "description": "SSH password",
                },
                "ssh_key": {
                    "type": "string",
                    "description": "SSH private key content",
                },
                "ssh_port": {
                    "type": "integer",
                    "default": 22,
                    "description": "SSH server port",
                },
                "remote_host": {
                    "type": "string",
                    "default": "127.0.0.1",
                    "description": "Remote host to forward to (default: localhost on SSH server)",
                },
                "remote_port": {
                    "type": "integer",
                    "required": True,
                    "description": "Remote port to forward",
                },
                "local_port": {
                    "type": "integer",
                    "default": 0,
                    "description": "Local port to listen on (0 = auto-assign)",
                },
            },
            handler=self.forward,
        )

        self.register_method(
            name="socks",
            description="Create SOCKS5 proxy through SSH (dynamic port forwarding)",
            params={
                "ssh_host": {
                    "type": "string",
                    "required": True,
                    "description": "SSH server hostname or IP",
                },
                "ssh_user": {
                    "type": "string",
                    "required": True,
                    "description": "SSH username",
                },
                "ssh_password": {
                    "type": "string",
                    "description": "SSH password",
                },
                "ssh_key": {
                    "type": "string",
                    "description": "SSH private key content",
                },
                "ssh_port": {
                    "type": "integer",
                    "default": 22,
                    "description": "SSH server port",
                },
                "local_port": {
                    "type": "integer",
                    "default": 1080,
                    "description": "Local SOCKS port",
                },
            },
            handler=self.socks,
        )

        self.register_method(
            name="list",
            description="List active tunnels",
            params={},
            handler=self.list_tunnels,
        )

        self.register_method(
            name="close",
            description="Close a tunnel",
            params={
                "tunnel_id": {
                    "type": "string",
                    "required": True,
                    "description": "Tunnel ID to close",
                },
            },
            handler=self.close_tunnel,
        )

        self.register_method(
            name="close_all",
            description="Close all tunnels",
            params={},
            handler=self.close_all,
        )

    def _get_next_id(self) -> str:
        tunnel_id = f"tunnel-{self.next_id}"
        self.next_id += 1
        return tunnel_id

    async def _find_free_port(self) -> int:
        """Find an available local port."""
        import socket
        with socket.socket(socket.AF_INET, socket.SOCK_STREAM) as s:
            s.bind(('', 0))
            return s.getsockname()[1]

    async def forward(
        self,
        ssh_host: str,
        ssh_user: str,
        remote_port: int,
        ssh_password: Optional[str] = None,
        ssh_key: Optional[str] = None,
        ssh_port: int = 22,
        remote_host: str = "127.0.0.1",
        local_port: int = 0,
    ) -> ToolResult:
        """Create SSH local port forward."""
        self.logger.info(f"Creating forward: {remote_host}:{remote_port} -> localhost:{local_port}")

        if not ssh_password and not ssh_key:
            return ToolResult(
                success=False,
                data={},
                error="Either ssh_password or ssh_key is required",
            )

        # Find free port if not specified
        if local_port == 0:
            local_port = await self._find_free_port()

        # Build SSH command
        args = [
            "sshpass", "-p", ssh_password,
            "ssh",
            "-o", "StrictHostKeyChecking=no",
            "-o", "UserKnownHostsFile=/dev/null",
            "-o", "ServerAliveInterval=30",
            "-o", "ServerAliveCountMax=3",
            "-N",  # No command
            "-L", f"{local_port}:{remote_host}:{remote_port}",
            "-p", str(ssh_port),
            f"{ssh_user}@{ssh_host}",
        ]

        if ssh_key:
            # Write key to temp file
            key_file = tempfile.NamedTemporaryFile(mode='w', delete=False, suffix='.key')
            key_file.write(ssh_key)
            key_file.close()
            os.chmod(key_file.name, 0o600)
            args = [
                "ssh",
                "-o", "StrictHostKeyChecking=no",
                "-o", "UserKnownHostsFile=/dev/null",
                "-o", "ServerAliveInterval=30",
                "-i", key_file.name,
                "-N",
                "-L", f"{local_port}:{remote_host}:{remote_port}",
                "-p", str(ssh_port),
                f"{ssh_user}@{ssh_host}",
            ]

        try:
            proc = await asyncio.create_subprocess_exec(
                *args,
                stdout=asyncio.subprocess.PIPE,
                stderr=asyncio.subprocess.PIPE,
            )

            # Wait briefly to check if connection succeeds
            await asyncio.sleep(2)

            if proc.returncode is not None:
                _, stderr = await proc.communicate()
                return ToolResult(
                    success=False,
                    data={},
                    error=f"Tunnel failed: {stderr.decode()}",
                )

            tunnel_id = self._get_next_id()
            self.tunnels[tunnel_id] = {
                "process": proc,
                "type": "forward",
                "ssh_host": ssh_host,
                "remote_host": remote_host,
                "remote_port": remote_port,
                "local_port": local_port,
            }

            return ToolResult(
                success=True,
                data={
                    "tunnel_id": tunnel_id,
                    "type": "forward",
                    "local_port": local_port,
                    "remote_host": remote_host,
                    "remote_port": remote_port,
                    "connect_to": f"127.0.0.1:{local_port}",
                },
                raw_output=f"Tunnel {tunnel_id}: localhost:{local_port} -> {remote_host}:{remote_port}",
            )

        except Exception as e:
            return ToolResult(
                success=False,
                data={},
                error=str(e),
            )

    async def socks(
        self,
        ssh_host: str,
        ssh_user: str,
        ssh_password: Optional[str] = None,
        ssh_key: Optional[str] = None,
        ssh_port: int = 22,
        local_port: int = 1080,
    ) -> ToolResult:
        """Create SOCKS5 proxy through SSH."""
        self.logger.info(f"Creating SOCKS proxy on port {local_port}")

        if not ssh_password and not ssh_key:
            return ToolResult(
                success=False,
                data={},
                error="Either ssh_password or ssh_key is required",
            )

        # Build SSH command for dynamic forwarding
        args = [
            "sshpass", "-p", ssh_password,
            "ssh",
            "-o", "StrictHostKeyChecking=no",
            "-o", "UserKnownHostsFile=/dev/null",
            "-o", "ServerAliveInterval=30",
            "-o", "ServerAliveCountMax=3",
            "-N",
            "-D", str(local_port),
            "-p", str(ssh_port),
            f"{ssh_user}@{ssh_host}",
        ]

        if ssh_key:
            key_file = tempfile.NamedTemporaryFile(mode='w', delete=False, suffix='.key')
            key_file.write(ssh_key)
            key_file.close()
            os.chmod(key_file.name, 0o600)
            args = [
                "ssh",
                "-o", "StrictHostKeyChecking=no",
                "-o", "UserKnownHostsFile=/dev/null",
                "-o", "ServerAliveInterval=30",
                "-i", key_file.name,
                "-N",
                "-D", str(local_port),
                "-p", str(ssh_port),
                f"{ssh_user}@{ssh_host}",
            ]

        try:
            proc = await asyncio.create_subprocess_exec(
                *args,
                stdout=asyncio.subprocess.PIPE,
                stderr=asyncio.subprocess.PIPE,
            )

            await asyncio.sleep(2)

            if proc.returncode is not None:
                _, stderr = await proc.communicate()
                return ToolResult(
                    success=False,
                    data={},
                    error=f"SOCKS proxy failed: {stderr.decode()}",
                )

            tunnel_id = self._get_next_id()
            self.tunnels[tunnel_id] = {
                "process": proc,
                "type": "socks",
                "ssh_host": ssh_host,
                "local_port": local_port,
            }

            return ToolResult(
                success=True,
                data={
                    "tunnel_id": tunnel_id,
                    "type": "socks",
                    "local_port": local_port,
                    "proxy_url": f"socks5://127.0.0.1:{local_port}",
                },
                raw_output=f"SOCKS5 proxy on 127.0.0.1:{local_port}",
            )

        except Exception as e:
            return ToolResult(
                success=False,
                data={},
                error=str(e),
            )

    async def list_tunnels(self) -> ToolResult:
        """List active tunnels."""
        active = []
        for tunnel_id, info in list(self.tunnels.items()):
            proc = info["process"]
            if proc.returncode is None:
                active.append({
                    "tunnel_id": tunnel_id,
                    "type": info["type"],
                    "local_port": info.get("local_port"),
                    "remote_host": info.get("remote_host"),
                    "remote_port": info.get("remote_port"),
                    "ssh_host": info.get("ssh_host"),
                })
            else:
                del self.tunnels[tunnel_id]

        return ToolResult(
            success=True,
            data={
                "tunnels": active,
                "count": len(active),
            },
            raw_output=f"{len(active)} active tunnel(s)",
        )

    async def close_tunnel(self, tunnel_id: str) -> ToolResult:
        """Close a specific tunnel."""
        if tunnel_id not in self.tunnels:
            return ToolResult(
                success=False,
                data={},
                error=f"Tunnel {tunnel_id} not found",
            )

        info = self.tunnels[tunnel_id]
        proc = info["process"]

        try:
            proc.terminate()
            await asyncio.wait_for(proc.wait(), timeout=5)
        except asyncio.TimeoutError:
            proc.kill()
            await proc.wait()

        del self.tunnels[tunnel_id]

        return ToolResult(
            success=True,
            data={"tunnel_id": tunnel_id},
            raw_output=f"Closed tunnel {tunnel_id}",
        )

    async def close_all(self) -> ToolResult:
        """Close all tunnels."""
        closed = []
        for tunnel_id in list(self.tunnels.keys()):
            result = await self.close_tunnel(tunnel_id)
            if result.success:
                closed.append(tunnel_id)

        return ToolResult(
            success=True,
            data={"closed": closed},
            raw_output=f"Closed {len(closed)} tunnel(s)",
        )


if __name__ == "__main__":
    TunnelServer.main()
