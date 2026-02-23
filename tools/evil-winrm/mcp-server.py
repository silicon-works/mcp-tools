#!/usr/bin/env python3
"""
OpenSploit MCP Server: evil-winrm

WinRM command execution and file transfer using pywinrm.
Named evil-winrm for routing discoverability, but uses pywinrm
under the hood for reliable non-interactive execution.
"""

import base64
import os
from typing import Optional

from mcp_common import BaseMCPServer, ToolResult, ToolError


class EvilWinRMServer(BaseMCPServer):
    """MCP server for WinRM operations using pywinrm."""

    def __init__(self):
        super().__init__(
            name="evil-winrm",
            description="WinRM shell for command execution and file transfer",
            version="1.0.0",
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
                    "description": "Shell to use: 'powershell' (run_ps) or 'cmd' (run_cmd). Default: powershell",
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

    def _get_session(self, target: str, username: str, password: Optional[str] = None,
                     hash: Optional[str] = None, domain: Optional[str] = None,
                     ssl: bool = False, port: Optional[int] = None):
        """Create a pywinrm session.

        Authentication priority: hash (pass-the-hash) > password.
        When hash is provided, it is formatted as LM:NT for pyspnego
        auto-detection of NTLM hash auth.
        """
        import winrm

        scheme = "https" if ssl else "http"
        actual_port = port or (5986 if ssl else 5985)
        endpoint = f"{scheme}://{target}:{actual_port}/wsman"

        # Build username with domain if provided
        auth_user = f"{domain}\\{username}" if domain else username

        # Determine auth credential: hash takes priority over password
        if hash:
            # pywinrm/pyspnego auto-detects LM:NT format for pass-the-hash
            if ":" not in hash:
                # Bare NT hash — prepend empty LM hash
                auth_pass = f"00000000000000000000000000000000:{hash}"
            else:
                auth_pass = hash
        else:
            auth_pass = password or ""

        session = winrm.Session(
            endpoint,
            auth=(auth_user, auth_pass),
            transport="ntlm",
            server_cert_validation="ignore",
        )
        return session

    async def exec_cmd(self, target: str, username: str, command: str,
                       password: Optional[str] = None, hash: Optional[str] = None,
                       domain: Optional[str] = None, shell: str = "powershell",
                       ssl: bool = False, port: Optional[int] = None) -> ToolResult:
        """Execute a command via WinRM using PowerShell or CMD."""
        shell_label = "CMD" if shell == "cmd" else "PowerShell"
        self.logger.info(f"WinRM exec ({shell_label}): {target} as {username}")

        try:
            session = self._get_session(target, username, password, hash, domain, ssl, port)

            if shell == "cmd":
                result = session.run_cmd(command)
            else:
                result = session.run_ps(command)

            stdout = result.std_out.decode("utf-8", errors="replace") if result.std_out else ""
            stderr = result.std_err.decode("utf-8", errors="replace") if result.std_err else ""

            return ToolResult(
                success=result.status_code == 0,
                data={
                    "output": stdout.strip(),
                    "stderr": stderr.strip() if stderr.strip() else None,
                    "exit_code": result.status_code,
                    "shell": shell_label,
                },
                raw_output=stdout.strip(),
                error=stderr.strip() if result.status_code != 0 and stderr.strip() else None,
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
        """Upload a file to the target via WinRM using PowerShell base64 transfer."""
        self.logger.info(f"WinRM upload: {local_path} -> {remote_path} on {target}")

        if not os.path.isfile(local_path):
            return ToolResult(success=False, error=f"Local file not found: {local_path}")

        try:
            session = self._get_session(target, username, password, hash, domain, ssl, port)

            # Read and base64-encode the file
            with open(local_path, "rb") as f:
                content = f.read()

            b64_content = base64.b64encode(content).decode("ascii")

            # Upload via PowerShell in chunks (WinRM has message size limits)
            chunk_size = 50000  # ~50KB per chunk (before base64)
            chunks = [b64_content[i:i + chunk_size] for i in range(0, len(b64_content), chunk_size)]

            # First chunk: create file
            ps_cmd = f'$b64 = "{chunks[0]}"; [IO.File]::WriteAllBytes("{remote_path}", [Convert]::FromBase64String($b64))'
            result = session.run_ps(ps_cmd)

            if result.status_code != 0:
                stderr = result.std_err.decode("utf-8", errors="replace")
                return ToolResult(success=False, error=f"Upload failed: {stderr}")

            # Append remaining chunks
            for chunk in chunks[1:]:
                ps_cmd = (
                    f'$b64 = "{chunk}"; '
                    f'$existing = [IO.File]::ReadAllBytes("{remote_path}"); '
                    f'$new = [Convert]::FromBase64String($b64); '
                    f'$combined = $existing + $new; '
                    f'[IO.File]::WriteAllBytes("{remote_path}", $combined)'
                )
                result = session.run_ps(ps_cmd)
                if result.status_code != 0:
                    stderr = result.std_err.decode("utf-8", errors="replace")
                    return ToolResult(success=False, error=f"Upload chunk failed: {stderr}")

            return ToolResult(
                success=True,
                data={
                    "local_path": local_path,
                    "remote_path": remote_path,
                    "size": len(content),
                },
                raw_output=f"Uploaded {len(content)} bytes to {remote_path}",
            )
        except Exception as e:
            return ToolResult(success=False, error=f"Upload failed: {str(e)}")

    async def download(self, target: str, username: str, remote_path: str,
                       password: Optional[str] = None, hash: Optional[str] = None,
                       domain: Optional[str] = None, local_path: Optional[str] = None,
                       ssl: bool = False, port: Optional[int] = None) -> ToolResult:
        """Download a file from the target via WinRM using PowerShell base64 transfer."""
        self.logger.info(f"WinRM download: {remote_path} from {target}")

        try:
            session = self._get_session(target, username, password, hash, domain, ssl, port)

            # Download via base64 encoding
            ps_cmd = f'[Convert]::ToBase64String([IO.File]::ReadAllBytes("{remote_path}"))'
            result = session.run_ps(ps_cmd)

            if result.status_code != 0:
                stderr = result.std_err.decode("utf-8", errors="replace")
                return ToolResult(success=False, error=f"Download failed: {stderr}")

            b64_content = result.std_out.decode("utf-8").strip()
            content = base64.b64decode(b64_content)

            # Determine local save path
            if not local_path:
                filename = os.path.basename(remote_path)
                local_path = f"/session/artifacts/{filename}"

            os.makedirs(os.path.dirname(local_path), exist_ok=True)
            with open(local_path, "wb") as f:
                f.write(content)

            return ToolResult(
                success=True,
                data={
                    "remote_path": remote_path,
                    "local_path": local_path,
                    "size": len(content),
                },
                raw_output=f"Downloaded {len(content)} bytes from {remote_path} to {local_path}",
            )
        except Exception as e:
            return ToolResult(success=False, error=f"Download failed: {str(e)}")


if __name__ == "__main__":
    EvilWinRMServer.main()
