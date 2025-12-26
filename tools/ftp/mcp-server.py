#!/usr/bin/env python3
"""
OpenSploit MCP Server: ftp

FTP/FTPS client for file operations, directory listing, and file transfers.
"""

import asyncio
import base64
import ftplib
import os
import ssl
import tempfile
from typing import Any, Dict, List, Optional

from mcp_common import BaseMCPServer, ToolResult, ToolError


class FTPServer(BaseMCPServer):
    """MCP server for FTP operations."""

    def __init__(self):
        super().__init__(
            name="ftp",
            description="FTP/FTPS client for file operations and transfers",
            version="1.0.0",
        )

        self.register_method(
            name="connect",
            description="Test FTP connection and list root directory",
            params={
                "host": {
                    "type": "string",
                    "required": True,
                    "description": "FTP server hostname or IP",
                },
                "port": {
                    "type": "integer",
                    "default": 21,
                    "description": "FTP port",
                },
                "username": {
                    "type": "string",
                    "default": "anonymous",
                    "description": "FTP username (default: anonymous)",
                },
                "password": {
                    "type": "string",
                    "default": "anonymous@",
                    "description": "FTP password",
                },
                "ssl": {
                    "type": "boolean",
                    "default": False,
                    "description": "Use FTPS (FTP over SSL/TLS)",
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
            name="list",
            description="List directory contents on FTP server",
            params={
                "host": {
                    "type": "string",
                    "required": True,
                    "description": "FTP server hostname or IP",
                },
                "path": {
                    "type": "string",
                    "default": "/",
                    "description": "Directory path to list",
                },
                "port": {
                    "type": "integer",
                    "default": 21,
                    "description": "FTP port",
                },
                "username": {
                    "type": "string",
                    "default": "anonymous",
                    "description": "FTP username",
                },
                "password": {
                    "type": "string",
                    "default": "anonymous@",
                    "description": "FTP password",
                },
                "ssl": {
                    "type": "boolean",
                    "default": False,
                    "description": "Use FTPS",
                },
                "timeout": {
                    "type": "integer",
                    "default": 30,
                    "description": "Connection timeout",
                },
            },
            handler=self.list_dir,
        )

        self.register_method(
            name="download",
            description="Download a file from FTP server",
            params={
                "host": {
                    "type": "string",
                    "required": True,
                    "description": "FTP server hostname or IP",
                },
                "remote_path": {
                    "type": "string",
                    "required": True,
                    "description": "Remote file path to download",
                },
                "port": {
                    "type": "integer",
                    "default": 21,
                    "description": "FTP port",
                },
                "username": {
                    "type": "string",
                    "default": "anonymous",
                    "description": "FTP username",
                },
                "password": {
                    "type": "string",
                    "default": "anonymous@",
                    "description": "FTP password",
                },
                "ssl": {
                    "type": "boolean",
                    "default": False,
                    "description": "Use FTPS",
                },
                "timeout": {
                    "type": "integer",
                    "default": 60,
                    "description": "Transfer timeout",
                },
            },
            handler=self.download,
        )

        self.register_method(
            name="upload",
            description="Upload a file to FTP server",
            params={
                "host": {
                    "type": "string",
                    "required": True,
                    "description": "FTP server hostname or IP",
                },
                "remote_path": {
                    "type": "string",
                    "required": True,
                    "description": "Remote path to upload to",
                },
                "content": {
                    "type": "string",
                    "required": True,
                    "description": "File content (plain text or base64)",
                },
                "is_base64": {
                    "type": "boolean",
                    "default": False,
                    "description": "Whether content is base64 encoded",
                },
                "port": {
                    "type": "integer",
                    "default": 21,
                    "description": "FTP port",
                },
                "username": {
                    "type": "string",
                    "default": "anonymous",
                    "description": "FTP username",
                },
                "password": {
                    "type": "string",
                    "default": "anonymous@",
                    "description": "FTP password",
                },
                "ssl": {
                    "type": "boolean",
                    "default": False,
                    "description": "Use FTPS",
                },
                "timeout": {
                    "type": "integer",
                    "default": 60,
                    "description": "Transfer timeout",
                },
            },
            handler=self.upload,
        )

        self.register_method(
            name="delete",
            description="Delete a file from FTP server",
            params={
                "host": {
                    "type": "string",
                    "required": True,
                    "description": "FTP server hostname or IP",
                },
                "remote_path": {
                    "type": "string",
                    "required": True,
                    "description": "Remote file path to delete",
                },
                "port": {
                    "type": "integer",
                    "default": 21,
                    "description": "FTP port",
                },
                "username": {
                    "type": "string",
                    "required": True,
                    "description": "FTP username",
                },
                "password": {
                    "type": "string",
                    "required": True,
                    "description": "FTP password",
                },
                "ssl": {
                    "type": "boolean",
                    "default": False,
                    "description": "Use FTPS",
                },
                "timeout": {
                    "type": "integer",
                    "default": 30,
                    "description": "Connection timeout",
                },
            },
            handler=self.delete,
        )

    def _get_ftp_connection(
        self,
        host: str,
        port: int,
        username: str,
        password: str,
        ssl_enabled: bool,
        timeout: int,
    ) -> ftplib.FTP:
        """Create and return an FTP connection."""
        if ssl_enabled:
            context = ssl.create_default_context()
            context.check_hostname = False
            context.verify_mode = ssl.CERT_NONE
            ftp = ftplib.FTP_TLS(context=context)
        else:
            ftp = ftplib.FTP()

        ftp.connect(host, port, timeout=timeout)
        ftp.login(username, password)

        if ssl_enabled:
            ftp.prot_p()  # Enable data connection encryption

        return ftp

    async def connect(
        self,
        host: str,
        port: int = 21,
        username: str = "anonymous",
        password: str = "anonymous@",
        ssl: bool = False,
        timeout: int = 30,
    ) -> ToolResult:
        """Test FTP connection and get server info."""
        self.logger.info(f"Connecting to FTP {host}:{port}")

        try:
            ftp = self._get_ftp_connection(host, port, username, password, ssl, timeout)

            # Get server welcome message
            welcome = ftp.getwelcome()

            # Get current directory
            pwd = ftp.pwd()

            # List root directory
            files = []
            ftp.retrlines('LIST', files.append)

            ftp.quit()

            return ToolResult(
                success=True,
                data={
                    "host": host,
                    "port": port,
                    "username": username,
                    "ssl": ssl,
                    "welcome": welcome,
                    "current_dir": pwd,
                    "listing": files[:50],  # Limit output
                    "file_count": len(files),
                },
                raw_output=f"Connected to {host}:{port} as {username}\n{welcome}",
            )

        except ftplib.error_perm as e:
            return ToolResult(
                success=False,
                data={"host": host, "port": port},
                error=f"FTP permission error: {e}",
            )
        except Exception as e:
            return ToolResult(
                success=False,
                data={"host": host, "port": port},
                error=f"FTP connection failed: {e}",
            )

    async def list_dir(
        self,
        host: str,
        path: str = "/",
        port: int = 21,
        username: str = "anonymous",
        password: str = "anonymous@",
        ssl: bool = False,
        timeout: int = 30,
    ) -> ToolResult:
        """List directory contents."""
        self.logger.info(f"Listing {path} on {host}:{port}")

        try:
            ftp = self._get_ftp_connection(host, port, username, password, ssl, timeout)

            # Change to directory
            ftp.cwd(path)

            # Get detailed listing
            files = []
            ftp.retrlines('LIST', files.append)

            # Also get simple file names
            filenames = ftp.nlst()

            ftp.quit()

            # Parse listing for structured data
            parsed_files = []
            for line in files:
                parts = line.split()
                if len(parts) >= 9:
                    parsed_files.append({
                        "permissions": parts[0],
                        "size": parts[4] if len(parts) > 4 else "0",
                        "name": " ".join(parts[8:]),
                        "is_dir": parts[0].startswith('d'),
                    })

            return ToolResult(
                success=True,
                data={
                    "host": host,
                    "path": path,
                    "files": parsed_files,
                    "filenames": filenames,
                    "raw_listing": files,
                    "count": len(files),
                },
                raw_output="\n".join(files),
            )

        except ftplib.error_perm as e:
            return ToolResult(
                success=False,
                data={"host": host, "path": path},
                error=f"FTP permission error: {e}",
            )
        except Exception as e:
            return ToolResult(
                success=False,
                data={"host": host, "path": path},
                error=f"FTP list failed: {e}",
            )

    async def download(
        self,
        host: str,
        remote_path: str,
        port: int = 21,
        username: str = "anonymous",
        password: str = "anonymous@",
        ssl: bool = False,
        timeout: int = 60,
    ) -> ToolResult:
        """Download a file from FTP server."""
        self.logger.info(f"Downloading {remote_path} from {host}:{port}")

        try:
            ftp = self._get_ftp_connection(host, port, username, password, ssl, timeout)

            # Download to bytes
            data = []
            ftp.retrbinary(f'RETR {remote_path}', data.append)

            ftp.quit()

            content = b''.join(data)
            content_b64 = base64.b64encode(content).decode('utf-8')

            # Try to decode as text
            try:
                text_content = content.decode('utf-8')
                is_text = True
            except:
                text_content = None
                is_text = False

            filename = os.path.basename(remote_path)

            return ToolResult(
                success=True,
                data={
                    "host": host,
                    "remote_path": remote_path,
                    "filename": filename,
                    "size_bytes": len(content),
                    "content_base64": content_b64,
                    "content_text": text_content[:50000] if text_content else None,
                    "is_text": is_text,
                },
                raw_output=f"Downloaded {filename} ({len(content)} bytes)",
            )

        except ftplib.error_perm as e:
            return ToolResult(
                success=False,
                data={"host": host, "remote_path": remote_path},
                error=f"FTP permission error: {e}",
            )
        except Exception as e:
            return ToolResult(
                success=False,
                data={"host": host, "remote_path": remote_path},
                error=f"FTP download failed: {e}",
            )

    async def upload(
        self,
        host: str,
        remote_path: str,
        content: str,
        is_base64: bool = False,
        port: int = 21,
        username: str = "anonymous",
        password: str = "anonymous@",
        ssl: bool = False,
        timeout: int = 60,
    ) -> ToolResult:
        """Upload a file to FTP server."""
        self.logger.info(f"Uploading to {remote_path} on {host}:{port}")

        try:
            # Decode content
            if is_base64:
                file_content = base64.b64decode(content)
            else:
                file_content = content.encode('utf-8')

            ftp = self._get_ftp_connection(host, port, username, password, ssl, timeout)

            # Write to temp file then upload
            with tempfile.NamedTemporaryFile(delete=False) as f:
                f.write(file_content)
                temp_path = f.name

            try:
                with open(temp_path, 'rb') as f:
                    ftp.storbinary(f'STOR {remote_path}', f)
            finally:
                os.unlink(temp_path)

            ftp.quit()

            return ToolResult(
                success=True,
                data={
                    "host": host,
                    "remote_path": remote_path,
                    "size_bytes": len(file_content),
                    "uploaded": True,
                },
                raw_output=f"Uploaded {len(file_content)} bytes to {remote_path}",
            )

        except ftplib.error_perm as e:
            return ToolResult(
                success=False,
                data={"host": host, "remote_path": remote_path},
                error=f"FTP permission error: {e}",
            )
        except Exception as e:
            return ToolResult(
                success=False,
                data={"host": host, "remote_path": remote_path},
                error=f"FTP upload failed: {e}",
            )

    async def delete(
        self,
        host: str,
        remote_path: str,
        port: int = 21,
        username: str = "",
        password: str = "",
        ssl: bool = False,
        timeout: int = 30,
    ) -> ToolResult:
        """Delete a file from FTP server."""
        self.logger.info(f"Deleting {remote_path} on {host}:{port}")

        try:
            ftp = self._get_ftp_connection(host, port, username, password, ssl, timeout)

            ftp.delete(remote_path)

            ftp.quit()

            return ToolResult(
                success=True,
                data={
                    "host": host,
                    "remote_path": remote_path,
                    "deleted": True,
                },
                raw_output=f"Deleted {remote_path}",
            )

        except ftplib.error_perm as e:
            return ToolResult(
                success=False,
                data={"host": host, "remote_path": remote_path},
                error=f"FTP permission error: {e}",
            )
        except Exception as e:
            return ToolResult(
                success=False,
                data={"host": host, "remote_path": remote_path},
                error=f"FTP delete failed: {e}",
            )


if __name__ == "__main__":
    FTPServer.main()
