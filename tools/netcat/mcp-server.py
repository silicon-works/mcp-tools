#!/usr/bin/env python3
"""
OpenSploit MCP Server: netcat

Network utility for reverse shells, bind shells, and network testing.
Uses socat and ncat for flexible connection handling.
"""

import asyncio
import os
import signal
import tempfile
from typing import Any, Dict, Optional

from mcp_common import BaseMCPServer, ToolResult, ToolError, sanitize_output


class NetcatServer(BaseMCPServer):
    """MCP server wrapping netcat/socat for network connections."""

    def __init__(self):
        super().__init__(
            name="netcat",
            description="Network utility for reverse shells, bind shells, and port testing",
            version="1.0.0",
        )

        # Track active listeners and connections
        self._listeners: Dict[int, asyncio.subprocess.Process] = {}
        self._sessions: Dict[str, Dict[str, Any]] = {}

        self.register_method(
            name="listen",
            description="Start a listener for incoming connections (reverse shells)",
            params={
                "port": {
                    "type": "integer",
                    "required": True,
                    "description": "Port to listen on",
                },
                "timeout": {
                    "type": "integer",
                    "default": 300,
                    "description": "Listener timeout in seconds (default 5 minutes)",
                },
            },
            handler=self.listen,
        )

        self.register_method(
            name="exec",
            description="Execute a command on a listening port and return output (one-shot)",
            params={
                "port": {
                    "type": "integer",
                    "required": True,
                    "description": "Port to listen on",
                },
                "timeout": {
                    "type": "integer",
                    "default": 60,
                    "description": "Timeout waiting for connection and command output",
                },
            },
            handler=self.exec_shell,
        )

        self.register_method(
            name="connect",
            description="Connect to a remote host (bind shell or service)",
            params={
                "host": {
                    "type": "string",
                    "required": True,
                    "description": "Target host",
                },
                "port": {
                    "type": "integer",
                    "required": True,
                    "description": "Target port",
                },
                "data": {
                    "type": "string",
                    "description": "Data to send after connecting",
                },
                "timeout": {
                    "type": "integer",
                    "default": 30,
                    "description": "Connection timeout in seconds",
                },
            },
            handler=self.connect,
        )

        self.register_method(
            name="check_port",
            description="Check if a port is open on a host",
            params={
                "host": {
                    "type": "string",
                    "required": True,
                    "description": "Target host",
                },
                "port": {
                    "type": "integer",
                    "required": True,
                    "description": "Target port",
                },
                "timeout": {
                    "type": "integer",
                    "default": 5,
                    "description": "Connection timeout in seconds",
                },
            },
            handler=self.check_port,
        )

        self.register_method(
            name="get_interfaces",
            description="Get network interfaces and their IP addresses (for LHOST)",
            params={},
            handler=self.get_interfaces,
        )

        self.register_method(
            name="stop_listener",
            description="Stop an active listener",
            params={
                "port": {
                    "type": "integer",
                    "required": True,
                    "description": "Port of the listener to stop",
                },
            },
            handler=self.stop_listener,
        )

    async def listen(
        self,
        port: int,
        timeout: int = 300,
    ) -> ToolResult:
        """Start a listener and wait for a connection."""
        self.logger.info(f"Starting listener on port {port}")

        # Use socat for better control
        args = [
            "socat",
            "-d", "-d",  # Debug output
            f"TCP-LISTEN:{port},reuseaddr,fork",
            "STDOUT",
        ]

        try:
            proc = await asyncio.create_subprocess_exec(
                *args,
                stdout=asyncio.subprocess.PIPE,
                stderr=asyncio.subprocess.PIPE,
            )

            self._listeners[port] = proc

            # Wait briefly to check if it started
            await asyncio.sleep(0.5)

            if proc.returncode is not None:
                stderr = await proc.stderr.read()
                return ToolResult(
                    success=False,
                    data={"port": port},
                    error=f"Listener failed to start: {stderr.decode()}",
                )

            return ToolResult(
                success=True,
                data={
                    "port": port,
                    "pid": proc.pid,
                    "status": "listening",
                    "timeout": timeout,
                },
                raw_output=f"Listener started on port {port} (PID: {proc.pid})",
            )

        except Exception as e:
            return ToolResult(
                success=False,
                data={"port": port},
                error=str(e),
            )

    async def exec_shell(
        self,
        port: int,
        timeout: int = 60,
    ) -> ToolResult:
        """
        One-shot shell command execution via reverse shell.
        Listens on port, waits for connection, captures output.
        """
        self.logger.info(f"Setting up one-shot listener on port {port}")

        # Use ncat with -l for listening, timeout for auto-close
        args = [
            "timeout", str(timeout),
            "ncat", "-l", "-p", str(port), "-v",
        ]

        try:
            proc = await asyncio.create_subprocess_exec(
                *args,
                stdout=asyncio.subprocess.PIPE,
                stderr=asyncio.subprocess.PIPE,
            )

            self.logger.info(f"Waiting for connection on port {port}...")

            try:
                stdout, stderr = await asyncio.wait_for(
                    proc.communicate(),
                    timeout=timeout + 5,
                )

                output = stdout.decode("utf-8", errors="replace")
                errors = stderr.decode("utf-8", errors="replace")

                return ToolResult(
                    success=True,
                    data={
                        "port": port,
                        "output": output,
                        "output_length": len(output),
                    },
                    raw_output=output if output else errors,
                )

            except asyncio.TimeoutError:
                proc.kill()
                return ToolResult(
                    success=False,
                    data={"port": port},
                    error=f"Timeout waiting for connection after {timeout} seconds",
                )

        except Exception as e:
            return ToolResult(
                success=False,
                data={"port": port},
                error=str(e),
            )

    async def connect(
        self,
        host: str,
        port: int,
        data: Optional[str] = None,
        timeout: int = 30,
    ) -> ToolResult:
        """Connect to a remote host and optionally send data."""
        self.logger.info(f"Connecting to {host}:{port}")

        try:
            if data:
                # Use ncat with data piped in
                proc = await asyncio.create_subprocess_exec(
                    "timeout", str(timeout),
                    "ncat", host, str(port), "-v",
                    stdin=asyncio.subprocess.PIPE,
                    stdout=asyncio.subprocess.PIPE,
                    stderr=asyncio.subprocess.PIPE,
                )

                stdout, stderr = await asyncio.wait_for(
                    proc.communicate(input=data.encode()),
                    timeout=timeout + 5,
                )
            else:
                # Just connect and read response
                proc = await asyncio.create_subprocess_exec(
                    "timeout", str(timeout),
                    "ncat", host, str(port), "-v",
                    stdout=asyncio.subprocess.PIPE,
                    stderr=asyncio.subprocess.PIPE,
                )

                stdout, stderr = await asyncio.wait_for(
                    proc.communicate(),
                    timeout=timeout + 5,
                )

            output = stdout.decode("utf-8", errors="replace")
            errors = stderr.decode("utf-8", errors="replace")

            return ToolResult(
                success=proc.returncode == 0,
                data={
                    "host": host,
                    "port": port,
                    "output": output,
                    "connection_info": errors,
                },
                raw_output=output if output else errors,
            )

        except asyncio.TimeoutError:
            return ToolResult(
                success=False,
                data={"host": host, "port": port},
                error=f"Connection timed out after {timeout} seconds",
            )
        except Exception as e:
            return ToolResult(
                success=False,
                data={"host": host, "port": port},
                error=str(e),
            )

    async def check_port(
        self,
        host: str,
        port: int,
        timeout: int = 5,
    ) -> ToolResult:
        """Quick port check using ncat."""
        self.logger.info(f"Checking if {host}:{port} is open")

        try:
            proc = await asyncio.create_subprocess_exec(
                "timeout", str(timeout),
                "ncat", "-zv", host, str(port),
                stdout=asyncio.subprocess.PIPE,
                stderr=asyncio.subprocess.PIPE,
            )

            stdout, stderr = await asyncio.wait_for(
                proc.communicate(),
                timeout=timeout + 2,
            )

            output = stderr.decode("utf-8", errors="replace")
            is_open = proc.returncode == 0

            return ToolResult(
                success=True,
                data={
                    "host": host,
                    "port": port,
                    "open": is_open,
                    "details": output.strip(),
                },
                raw_output=f"Port {port} is {'open' if is_open else 'closed'}",
            )

        except asyncio.TimeoutError:
            return ToolResult(
                success=True,
                data={
                    "host": host,
                    "port": port,
                    "open": False,
                    "details": "Connection timed out",
                },
                raw_output=f"Port {port} timed out (likely filtered)",
            )
        except Exception as e:
            return ToolResult(
                success=False,
                data={"host": host, "port": port},
                error=str(e),
            )

    async def get_interfaces(self) -> ToolResult:
        """Get network interfaces for determining LHOST."""
        self.logger.info("Getting network interfaces")

        try:
            result = await self.run_command(
                ["ip", "-j", "addr"],
                timeout=10,
            )

            import json
            interfaces = json.loads(result.stdout)

            # Extract useful info
            iface_info = []
            for iface in interfaces:
                name = iface.get("ifname", "")
                addrs = []
                for addr_info in iface.get("addr_info", []):
                    if addr_info.get("family") == "inet":
                        addrs.append(addr_info.get("local", ""))

                if addrs and name != "lo":
                    iface_info.append({
                        "interface": name,
                        "addresses": addrs,
                    })

            return ToolResult(
                success=True,
                data={"interfaces": iface_info},
                raw_output="\n".join(
                    f"{i['interface']}: {', '.join(i['addresses'])}"
                    for i in iface_info
                ),
            )

        except Exception as e:
            return ToolResult(
                success=False,
                data={},
                error=str(e),
            )

    async def stop_listener(self, port: int) -> ToolResult:
        """Stop an active listener."""
        self.logger.info(f"Stopping listener on port {port}")

        if port in self._listeners:
            proc = self._listeners[port]
            try:
                proc.terminate()
                await asyncio.wait_for(proc.wait(), timeout=5)
            except asyncio.TimeoutError:
                proc.kill()

            del self._listeners[port]

            return ToolResult(
                success=True,
                data={"port": port, "status": "stopped"},
                raw_output=f"Listener on port {port} stopped",
            )
        else:
            return ToolResult(
                success=False,
                data={"port": port},
                error=f"No active listener found on port {port}",
            )


if __name__ == "__main__":
    NetcatServer.main()
