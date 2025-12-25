#!/usr/bin/env python3
"""
OpenSploit MCP Server: ssh

SSH client for remote shell access with password or key authentication.
"""

import asyncio
import base64
import os
import subprocess
import tempfile
from typing import Optional

from mcp_common import BaseMCPServer, ToolResult, ToolError, sanitize_output


class SSHServer(BaseMCPServer):
    """MCP server wrapping SSH client for remote access."""

    def __init__(self):
        super().__init__(
            name="ssh",
            description="SSH client for remote shell access with credentials",
            version="1.0.0",
        )

        self.register_method(
            name="exec",
            description="Execute a command on a remote host via SSH",
            params={
                "host": {
                    "type": "string",
                    "required": True,
                    "description": "Target hostname or IP",
                },
                "username": {
                    "type": "string",
                    "required": True,
                    "description": "SSH username",
                },
                "password": {
                    "type": "string",
                    "description": "SSH password (use sshpass)",
                },
                "key": {
                    "type": "string",
                    "description": "Private key content (PEM format)",
                },
                "command": {
                    "type": "string",
                    "required": True,
                    "description": "Command to execute",
                },
                "port": {
                    "type": "integer",
                    "default": 22,
                    "description": "SSH port",
                },
                "timeout": {
                    "type": "integer",
                    "default": 30,
                    "description": "Connection timeout in seconds",
                },
            },
            handler=self.exec_command,
        )

        self.register_method(
            name="shell",
            description="Execute multiple commands in sequence on a remote host",
            params={
                "host": {
                    "type": "string",
                    "required": True,
                    "description": "Target hostname or IP",
                },
                "username": {
                    "type": "string",
                    "required": True,
                    "description": "SSH username",
                },
                "password": {
                    "type": "string",
                    "description": "SSH password",
                },
                "key": {
                    "type": "string",
                    "description": "Private key content (PEM format)",
                },
                "commands": {
                    "type": "array",
                    "required": True,
                    "description": "List of commands to execute",
                },
                "port": {
                    "type": "integer",
                    "default": 22,
                    "description": "SSH port",
                },
                "timeout": {
                    "type": "integer",
                    "default": 60,
                    "description": "Total timeout for all commands",
                },
            },
            handler=self.shell,
        )

        self.register_method(
            name="copy_from",
            description="Download a file from remote host via SCP",
            params={
                "host": {
                    "type": "string",
                    "required": True,
                    "description": "Target hostname or IP",
                },
                "username": {
                    "type": "string",
                    "required": True,
                    "description": "SSH username",
                },
                "password": {
                    "type": "string",
                    "description": "SSH password",
                },
                "key": {
                    "type": "string",
                    "description": "Private key content (PEM format)",
                },
                "remote_path": {
                    "type": "string",
                    "required": True,
                    "description": "Path to file on remote host",
                },
                "port": {
                    "type": "integer",
                    "default": 22,
                    "description": "SSH port",
                },
                "timeout": {
                    "type": "integer",
                    "default": 60,
                    "description": "Transfer timeout in seconds",
                },
            },
            handler=self.copy_from,
        )

        self.register_method(
            name="copy_to",
            description="Upload content to remote host via SCP",
            params={
                "host": {
                    "type": "string",
                    "required": True,
                    "description": "Target hostname or IP",
                },
                "username": {
                    "type": "string",
                    "required": True,
                    "description": "SSH username",
                },
                "password": {
                    "type": "string",
                    "description": "SSH password",
                },
                "key": {
                    "type": "string",
                    "description": "Private key content (PEM format)",
                },
                "content": {
                    "type": "string",
                    "required": True,
                    "description": "Content to upload",
                },
                "remote_path": {
                    "type": "string",
                    "required": True,
                    "description": "Destination path on remote host",
                },
                "port": {
                    "type": "integer",
                    "default": 22,
                    "description": "SSH port",
                },
                "timeout": {
                    "type": "integer",
                    "default": 60,
                    "description": "Transfer timeout in seconds",
                },
            },
            handler=self.copy_to,
        )

        self.register_method(
            name="upload_binary",
            description="Upload a binary file via base64 chunking (for large files/exploits)",
            params={
                "host": {
                    "type": "string",
                    "required": True,
                    "description": "Target hostname or IP",
                },
                "username": {
                    "type": "string",
                    "required": True,
                    "description": "SSH username",
                },
                "password": {
                    "type": "string",
                    "description": "SSH password",
                },
                "key": {
                    "type": "string",
                    "description": "Private key content (PEM format)",
                },
                "content_base64": {
                    "type": "string",
                    "required": True,
                    "description": "Base64-encoded binary content",
                },
                "remote_path": {
                    "type": "string",
                    "required": True,
                    "description": "Destination path on remote host",
                },
                "executable": {
                    "type": "boolean",
                    "default": True,
                    "description": "Make the file executable after upload",
                },
                "port": {
                    "type": "integer",
                    "default": 22,
                    "description": "SSH port",
                },
                "chunk_size": {
                    "type": "integer",
                    "default": 50000,
                    "description": "Chunk size for transfer (bytes before base64)",
                },
                "timeout": {
                    "type": "integer",
                    "default": 300,
                    "description": "Total timeout in seconds",
                },
            },
            handler=self.upload_binary,
        )

        self.register_method(
            name="run_script",
            description="Upload and execute a script, return output",
            params={
                "host": {
                    "type": "string",
                    "required": True,
                    "description": "Target hostname or IP",
                },
                "username": {
                    "type": "string",
                    "required": True,
                    "description": "SSH username",
                },
                "password": {
                    "type": "string",
                    "description": "SSH password",
                },
                "key": {
                    "type": "string",
                    "description": "Private key content (PEM format)",
                },
                "script": {
                    "type": "string",
                    "required": True,
                    "description": "Script content to run",
                },
                "interpreter": {
                    "type": "string",
                    "default": "/bin/bash",
                    "description": "Interpreter to use (bash, python3, etc)",
                },
                "port": {
                    "type": "integer",
                    "default": 22,
                    "description": "SSH port",
                },
                "timeout": {
                    "type": "integer",
                    "default": 120,
                    "description": "Execution timeout in seconds",
                },
            },
            handler=self.run_script,
        )

    def _convert_openssh_to_pem(self, key_content: str) -> str:
        """Convert OpenSSH format key to PEM format if needed.

        OpenSSH keys start with '-----BEGIN OPENSSH PRIVATE KEY-----'
        PEM keys start with '-----BEGIN RSA PRIVATE KEY-----' (or DSA, EC, etc.)

        Returns the key content in PEM format.
        """
        # Check if already PEM format
        if "BEGIN RSA PRIVATE KEY" in key_content or \
           "BEGIN DSA PRIVATE KEY" in key_content or \
           "BEGIN EC PRIVATE KEY" in key_content or \
           "BEGIN PRIVATE KEY" in key_content:
            return key_content

        # Check if OpenSSH format that needs conversion
        if "BEGIN OPENSSH PRIVATE KEY" not in key_content:
            # Unknown format, return as-is and let SSH handle it
            return key_content

        self.logger.info("Converting OpenSSH key format to PEM")

        # Write key to temp file
        fd, temp_key = tempfile.mkstemp(prefix="ssh_key_convert_")
        try:
            os.write(fd, key_content.encode())
            os.close(fd)
            os.chmod(temp_key, 0o600)

            # Convert using ssh-keygen
            # -p: change passphrase (but we use empty passphrase)
            # -m PEM: convert to PEM format
            # -f: key file
            # -N "": new passphrase (empty)
            # -P "": old passphrase (empty, assuming unencrypted key)
            result = subprocess.run(
                ["ssh-keygen", "-p", "-m", "PEM", "-f", temp_key, "-N", "", "-P", ""],
                capture_output=True,
                text=True,
            )

            if result.returncode != 0:
                self.logger.warning(f"Key conversion failed: {result.stderr}")
                # Return original key and hope for the best
                return key_content

            # Read converted key
            with open(temp_key, "r") as f:
                converted_key = f.read()

            self.logger.info("Key converted to PEM format successfully")
            return converted_key

        except Exception as e:
            self.logger.warning(f"Key conversion error: {e}")
            return key_content
        finally:
            if os.path.exists(temp_key):
                os.unlink(temp_key)
            # Also remove the .pub file that ssh-keygen might create
            pub_file = temp_key + ".pub"
            if os.path.exists(pub_file):
                os.unlink(pub_file)

    def _build_ssh_args(
        self,
        host: str,
        username: str,
        port: int = 22,
        password: Optional[str] = None,
        key_file: Optional[str] = None,
    ) -> list:
        """Build common SSH arguments."""
        args = []

        if password:
            args.extend(["sshpass", "-p", password])

        args.extend([
            "ssh",
            "-o", "StrictHostKeyChecking=no",
            "-o", "UserKnownHostsFile=/dev/null",
            "-o", "BatchMode=yes" if not password else "BatchMode=no",
            "-o", "ConnectTimeout=10",
            "-p", str(port),
        ])

        if key_file:
            args.extend(["-i", key_file])

        args.append(f"{username}@{host}")

        return args

    async def exec_command(
        self,
        host: str,
        username: str,
        command: str,
        password: Optional[str] = None,
        key: Optional[str] = None,
        port: int = 22,
        timeout: int = 30,
    ) -> ToolResult:
        """Execute a single command via SSH."""
        self.logger.info(f"Executing command on {username}@{host}:{port}")

        key_file = None
        try:
            # Write key to temp file if provided
            if key:
                # Convert OpenSSH format to PEM if needed
                key_content = self._convert_openssh_to_pem(key)
                fd, key_file = tempfile.mkstemp(prefix="ssh_key_")
                os.write(fd, key_content.encode())
                os.close(fd)
                os.chmod(key_file, 0o600)

            args = self._build_ssh_args(host, username, port, password, key_file)
            args.append(command)

            proc = await asyncio.create_subprocess_exec(
                *args,
                stdout=asyncio.subprocess.PIPE,
                stderr=asyncio.subprocess.PIPE,
            )

            try:
                stdout, stderr = await asyncio.wait_for(
                    proc.communicate(),
                    timeout=timeout,
                )

                output = stdout.decode("utf-8", errors="replace")
                errors = stderr.decode("utf-8", errors="replace")

                # Filter out SSH warnings
                errors = "\n".join(
                    line for line in errors.split("\n")
                    if not line.startswith("Warning:")
                    and "Permanently added" not in line
                )

                return ToolResult(
                    success=proc.returncode == 0,
                    data={
                        "host": host,
                        "username": username,
                        "command": command,
                        "exit_code": proc.returncode,
                        "stdout": output,
                        "stderr": errors.strip() if errors.strip() else None,
                    },
                    raw_output=output if output else errors,
                )

            except asyncio.TimeoutError:
                proc.kill()
                return ToolResult(
                    success=False,
                    data={"host": host, "username": username, "command": command},
                    error=f"Command timed out after {timeout} seconds",
                )

        except Exception as e:
            return ToolResult(
                success=False,
                data={"host": host, "username": username, "command": command},
                error=str(e),
            )
        finally:
            if key_file and os.path.exists(key_file):
                os.unlink(key_file)

    async def shell(
        self,
        host: str,
        username: str,
        commands: list,
        password: Optional[str] = None,
        key: Optional[str] = None,
        port: int = 22,
        timeout: int = 60,
    ) -> ToolResult:
        """Execute multiple commands in sequence."""
        self.logger.info(f"Executing {len(commands)} commands on {username}@{host}")

        # Join commands with && for sequential execution
        full_command = " && ".join(commands)

        return await self.exec_command(
            host=host,
            username=username,
            command=full_command,
            password=password,
            key=key,
            port=port,
            timeout=timeout,
        )

    async def copy_from(
        self,
        host: str,
        username: str,
        remote_path: str,
        password: Optional[str] = None,
        key: Optional[str] = None,
        port: int = 22,
        timeout: int = 60,
    ) -> ToolResult:
        """Download a file from remote host."""
        self.logger.info(f"Downloading {remote_path} from {username}@{host}")

        key_file = None
        local_file = None
        try:
            # Write key to temp file if provided
            if key:
                # Convert OpenSSH format to PEM if needed
                key_content = self._convert_openssh_to_pem(key)
                fd, key_file = tempfile.mkstemp(prefix="ssh_key_")
                os.write(fd, key_content.encode())
                os.close(fd)
                os.chmod(key_file, 0o600)

            # Create temp file for download
            fd, local_file = tempfile.mkstemp(prefix="scp_download_")
            os.close(fd)

            args = []
            if password:
                args.extend(["sshpass", "-p", password])

            args.extend([
                "scp",
                "-o", "StrictHostKeyChecking=no",
                "-o", "UserKnownHostsFile=/dev/null",
                "-P", str(port),
            ])

            if key_file:
                args.extend(["-i", key_file])

            args.extend([
                f"{username}@{host}:{remote_path}",
                local_file,
            ])

            proc = await asyncio.create_subprocess_exec(
                *args,
                stdout=asyncio.subprocess.PIPE,
                stderr=asyncio.subprocess.PIPE,
            )

            try:
                stdout, stderr = await asyncio.wait_for(
                    proc.communicate(),
                    timeout=timeout,
                )

                if proc.returncode != 0:
                    return ToolResult(
                        success=False,
                        data={"host": host, "remote_path": remote_path},
                        error=stderr.decode("utf-8", errors="replace"),
                    )

                # Read downloaded content
                with open(local_file, "r", errors="replace") as f:
                    content = f.read()

                return ToolResult(
                    success=True,
                    data={
                        "host": host,
                        "remote_path": remote_path,
                        "content": content,
                        "size": len(content),
                    },
                    raw_output=content,
                )

            except asyncio.TimeoutError:
                proc.kill()
                return ToolResult(
                    success=False,
                    data={"host": host, "remote_path": remote_path},
                    error=f"Transfer timed out after {timeout} seconds",
                )

        except Exception as e:
            return ToolResult(
                success=False,
                data={"host": host, "remote_path": remote_path},
                error=str(e),
            )
        finally:
            if key_file and os.path.exists(key_file):
                os.unlink(key_file)
            if local_file and os.path.exists(local_file):
                os.unlink(local_file)

    async def copy_to(
        self,
        host: str,
        username: str,
        content: str,
        remote_path: str,
        password: Optional[str] = None,
        key: Optional[str] = None,
        port: int = 22,
        timeout: int = 60,
    ) -> ToolResult:
        """Upload content to remote host."""
        self.logger.info(f"Uploading to {remote_path} on {username}@{host}")

        key_file = None
        local_file = None
        try:
            # Write key to temp file if provided
            if key:
                # Convert OpenSSH format to PEM if needed
                key_content = self._convert_openssh_to_pem(key)
                fd, key_file = tempfile.mkstemp(prefix="ssh_key_")
                os.write(fd, key_content.encode())
                os.close(fd)
                os.chmod(key_file, 0o600)

            # Write content to temp file
            fd, local_file = tempfile.mkstemp(prefix="scp_upload_")
            os.write(fd, content.encode())
            os.close(fd)

            args = []
            if password:
                args.extend(["sshpass", "-p", password])

            args.extend([
                "scp",
                "-o", "StrictHostKeyChecking=no",
                "-o", "UserKnownHostsFile=/dev/null",
                "-P", str(port),
            ])

            if key_file:
                args.extend(["-i", key_file])

            args.extend([
                local_file,
                f"{username}@{host}:{remote_path}",
            ])

            proc = await asyncio.create_subprocess_exec(
                *args,
                stdout=asyncio.subprocess.PIPE,
                stderr=asyncio.subprocess.PIPE,
            )

            try:
                stdout, stderr = await asyncio.wait_for(
                    proc.communicate(),
                    timeout=timeout,
                )

                if proc.returncode != 0:
                    return ToolResult(
                        success=False,
                        data={"host": host, "remote_path": remote_path},
                        error=stderr.decode("utf-8", errors="replace"),
                    )

                return ToolResult(
                    success=True,
                    data={
                        "host": host,
                        "remote_path": remote_path,
                        "size": len(content),
                    },
                    raw_output=f"Uploaded {len(content)} bytes to {remote_path}",
                )

            except asyncio.TimeoutError:
                proc.kill()
                return ToolResult(
                    success=False,
                    data={"host": host, "remote_path": remote_path},
                    error=f"Transfer timed out after {timeout} seconds",
                )

        except Exception as e:
            return ToolResult(
                success=False,
                data={"host": host, "remote_path": remote_path},
                error=str(e),
            )
        finally:
            if key_file and os.path.exists(key_file):
                os.unlink(key_file)
            if local_file and os.path.exists(local_file):
                os.unlink(local_file)


    async def upload_binary(
        self,
        host: str,
        username: str,
        content_base64: str,
        remote_path: str,
        password: Optional[str] = None,
        key: Optional[str] = None,
        executable: bool = True,
        port: int = 22,
        chunk_size: int = 50000,
        timeout: int = 300,
    ) -> ToolResult:
        """Upload binary content via base64 chunking."""
        self.logger.info(f"Uploading binary to {remote_path} on {username}@{host}")

        try:
            # Decode the base64 content
            binary_data = base64.b64decode(content_base64)
            total_size = len(binary_data)

            self.logger.info(f"Binary size: {total_size} bytes")

            # Clear any existing file
            await self.exec_command(
                host=host,
                username=username,
                password=password,
                key=key,
                command=f"rm -f {remote_path}",
                port=port,
                timeout=30,
            )

            # Split into chunks and upload
            chunks = []
            for i in range(0, total_size, chunk_size):
                chunk = binary_data[i:i + chunk_size]
                chunks.append(base64.b64encode(chunk).decode())

            self.logger.info(f"Uploading in {len(chunks)} chunks")

            for i, chunk_b64 in enumerate(chunks):
                result = await self.exec_command(
                    host=host,
                    username=username,
                    password=password,
                    key=key,
                    command=f"echo '{chunk_b64}' | base64 -d >> {remote_path}",
                    port=port,
                    timeout=60,
                )
                if not result.success:
                    return ToolResult(
                        success=False,
                        data={"host": host, "remote_path": remote_path, "chunk": i},
                        error=f"Failed uploading chunk {i}: {result.error}",
                    )

            # Make executable if requested
            if executable:
                await self.exec_command(
                    host=host,
                    username=username,
                    password=password,
                    key=key,
                    command=f"chmod +x {remote_path}",
                    port=port,
                    timeout=30,
                )

            # Verify upload
            verify_result = await self.exec_command(
                host=host,
                username=username,
                password=password,
                key=key,
                command=f"ls -la {remote_path} && file {remote_path}",
                port=port,
                timeout=30,
            )

            return ToolResult(
                success=True,
                data={
                    "host": host,
                    "remote_path": remote_path,
                    "size": total_size,
                    "chunks": len(chunks),
                    "executable": executable,
                    "verification": verify_result.data.get("stdout", ""),
                },
                raw_output=f"Uploaded {total_size} bytes to {remote_path}",
            )

        except Exception as e:
            return ToolResult(
                success=False,
                data={"host": host, "remote_path": remote_path},
                error=str(e),
            )

    async def run_script(
        self,
        host: str,
        username: str,
        script: str,
        password: Optional[str] = None,
        key: Optional[str] = None,
        interpreter: str = "/bin/bash",
        port: int = 22,
        timeout: int = 120,
    ) -> ToolResult:
        """Upload and execute a script."""
        self.logger.info(f"Running script on {username}@{host}")

        try:
            # Upload script to temp file
            remote_script = f"/tmp/script_{os.urandom(4).hex()}.sh"

            upload_result = await self.copy_to(
                host=host,
                username=username,
                password=password,
                key=key,
                content=script,
                remote_path=remote_script,
                port=port,
                timeout=60,
            )

            if not upload_result.success:
                return upload_result

            # Make executable and run
            result = await self.exec_command(
                host=host,
                username=username,
                password=password,
                key=key,
                command=f"chmod +x {remote_script} && {interpreter} {remote_script}; rm -f {remote_script}",
                port=port,
                timeout=timeout,
            )

            return result

        except Exception as e:
            return ToolResult(
                success=False,
                data={"host": host},
                error=str(e),
            )


if __name__ == "__main__":
    SSHServer.main()
