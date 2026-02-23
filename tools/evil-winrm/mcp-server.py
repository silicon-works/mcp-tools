#!/usr/bin/env python3
"""
OpenSploit MCP Server: evil-winrm

WinRM command execution and file transfer using pypsrp.
pypsrp natively supports the PowerShell plugin URI, avoiding the CMD
shell Invoke restriction that blocks pywinrm on Windows Server 2025
for non-admin WinRM users.
"""

import os
from typing import Optional

from mcp_common import BaseMCPServer, ToolResult, ToolError


class EvilWinRMServer(BaseMCPServer):
    """MCP server for WinRM operations using pypsrp."""

    def __init__(self):
        super().__init__(
            name="evil-winrm",
            description="WinRM shell for command execution and file transfer",
            version="2.0.0",
        )

        self.register_method(
            name="exec",
            description="Execute command via WinRM (PowerShell or CMD)",
            params={
                "target": {"type": "string", "required": True, "description": "Target IP or hostname"},
                "username": {"type": "string", "required": True, "description": "Username"},
                "password": {"type": "string", "description": "Password"},
                "hash": {"type": "string", "description": "NTLM hash for pass-the-hash (bare NT hash or LM:NT format)"},
                "domain": {"type": "string", "description": "Active Directory domain"},
                "command": {"type": "string", "required": True, "description": "Command to execute"},
                "shell": {
                    "type": "enum",
                    "values": ["powershell", "cmd"],
                    "description": "Shell to use: 'powershell' (default, native PSRP) or 'cmd' (WinRS CMD shell)",
                },
                "ssl": {"type": "boolean", "description": "Use SSL (port 5986)"},
                "port": {"type": "integer", "description": "Custom port (default: 5985 or 5986 for SSL)"},
            },
            handler=self.exec_cmd,
        )

        self.register_method(
            name="upload",
            description="Upload file to target via WinRM",
            params={
                "target": {"type": "string", "required": True, "description": "Target IP or hostname"},
                "username": {"type": "string", "required": True, "description": "Username"},
                "password": {"type": "string", "description": "Password"},
                "hash": {"type": "string", "description": "NTLM hash for pass-the-hash (bare NT hash or LM:NT format)"},
                "domain": {"type": "string", "description": "Active Directory domain"},
                "local_path": {"type": "string", "required": True, "description": "Local file path to upload"},
                "remote_path": {"type": "string", "required": True, "description": "Remote destination path"},
                "ssl": {"type": "boolean", "description": "Use SSL (port 5986)"},
                "port": {"type": "integer", "description": "Custom port (default: 5985 or 5986 for SSL)"},
            },
            handler=self.upload,
        )

        self.register_method(
            name="download",
            description="Download file from target via WinRM",
            params={
                "target": {"type": "string", "required": True, "description": "Target IP or hostname"},
                "username": {"type": "string", "required": True, "description": "Username"},
                "password": {"type": "string", "description": "Password"},
                "hash": {"type": "string", "description": "NTLM hash for pass-the-hash (bare NT hash or LM:NT format)"},
                "domain": {"type": "string", "description": "Active Directory domain"},
                "remote_path": {"type": "string", "required": True, "description": "Remote file path to download"},
                "local_path": {"type": "string", "description": "Local destination (default: /session/artifacts/)"},
                "ssl": {"type": "boolean", "description": "Use SSL (port 5986)"},
                "port": {"type": "integer", "description": "Custom port (default: 5985 or 5986 for SSL)"},
            },
            handler=self.download,
        )

    def _get_client(self, target: str, username: str, password: Optional[str] = None,
                    hash: Optional[str] = None, domain: Optional[str] = None,
                    ssl: bool = False, port: Optional[int] = None):
        """Create a pypsrp Client.

        Authentication priority: hash (pass-the-hash) > password.
        When hash is provided, it is formatted as LM:NT for pyspnego
        auto-detection of NTLM hash auth.
        """
        from pypsrp.client import Client

        actual_port = port or (5986 if ssl else 5985)

        # Determine auth credential: hash takes priority over password
        if hash:
            # pypsrp/pyspnego auto-detects LM:NT format for pass-the-hash
            if ":" not in hash:
                # Bare NT hash — prepend empty LM hash
                auth_pass = f"00000000000000000000000000000000:{hash}"
            else:
                auth_pass = hash
        else:
            auth_pass = password or ""

        client = Client(
            target,
            username=username,
            password=auth_pass,
            port=actual_port,
            ssl=ssl,
            auth="ntlm",
            cert_validation=False,
            connection_timeout=30,
        )
        return client

    async def exec_cmd(self, target: str, username: str, command: str,
                       password: Optional[str] = None, hash: Optional[str] = None,
                       domain: Optional[str] = None, shell: str = "powershell",
                       ssl: bool = False, port: Optional[int] = None) -> ToolResult:
        """Execute a command via WinRM using PowerShell (PSRP) or CMD (WinRS)."""
        shell_label = "CMD" if shell == "cmd" else "PowerShell"
        # Prepend domain to username for NTLM auth
        auth_user = f"{domain}\\{username}" if domain else username
        self.logger.info(f"WinRM exec ({shell_label}): {target} as {auth_user}")

        try:
            client = self._get_client(target, auth_user, password, hash, None, ssl, port)

            if shell == "cmd":
                stdout, stderr, rc = client.execute_cmd(command)
            else:
                # execute_ps returns (stdout: str, streams: PSDataStreams, had_errors: bool)
                stdout, streams, had_errors = client.execute_ps(command)
                stderr = "\n".join(str(e) for e in streams.error) if streams.error else ""
                rc = 1 if had_errors else 0

            return ToolResult(
                success=rc == 0,
                data={
                    "output": stdout.strip() if stdout else "",
                    "stderr": stderr.strip() if stderr and stderr.strip() else None,
                    "exit_code": rc,
                    "shell": shell_label,
                },
                raw_output=stdout.strip() if stdout else "",
                error=stderr.strip() if rc != 0 and stderr and stderr.strip() else None,
            )
        except Exception as e:
            return ToolResult(
                success=False,
                error=f"WinRM connection failed: {str(e)}",
                data={"error": str(e)},
            )

    async def upload(self, target: str, username: str, local_path: str, remote_path: str,
                     password: Optional[str] = None, hash: Optional[str] = None,
                     domain: Optional[str] = None,
                     ssl: bool = False, port: Optional[int] = None) -> ToolResult:
        """Upload a file to the target via WinRM using native PSRP copy."""
        auth_user = f"{domain}\\{username}" if domain else username
        self.logger.info(f"WinRM upload: {local_path} -> {remote_path} on {target}")

        if not os.path.isfile(local_path):
            return ToolResult(success=False, error=f"Local file not found: {local_path}", data={})

        try:
            client = self._get_client(target, auth_user, password, hash, None, ssl, port)

            file_size = os.path.getsize(local_path)
            client.copy(local_path, remote_path)

            return ToolResult(
                success=True,
                data={
                    "local_path": local_path,
                    "remote_path": remote_path,
                    "size": file_size,
                },
                raw_output=f"Uploaded {file_size} bytes to {remote_path}",
            )
        except Exception as e:
            return ToolResult(success=False, error=f"Upload failed: {str(e)}", data={})

    async def download(self, target: str, username: str, remote_path: str,
                       password: Optional[str] = None, hash: Optional[str] = None,
                       domain: Optional[str] = None, local_path: Optional[str] = None,
                       ssl: bool = False, port: Optional[int] = None) -> ToolResult:
        """Download a file from the target via WinRM using native PSRP fetch."""
        auth_user = f"{domain}\\{username}" if domain else username
        self.logger.info(f"WinRM download: {remote_path} from {target}")

        try:
            client = self._get_client(target, auth_user, password, hash, None, ssl, port)

            # Determine local save path
            if not local_path:
                filename = os.path.basename(remote_path)
                local_path = f"/session/artifacts/{filename}"

            os.makedirs(os.path.dirname(local_path), exist_ok=True)
            client.fetch(remote_path, local_path)

            file_size = os.path.getsize(local_path)

            return ToolResult(
                success=True,
                data={
                    "remote_path": remote_path,
                    "local_path": local_path,
                    "size": file_size,
                },
                raw_output=f"Downloaded {file_size} bytes from {remote_path} to {local_path}",
            )
        except Exception as e:
            return ToolResult(success=False, error=f"Download failed: {str(e)}", data={})


if __name__ == "__main__":
    EvilWinRMServer.main()
