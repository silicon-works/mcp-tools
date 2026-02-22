#!/usr/bin/env python3
"""
OpenSploit MCP Server: ssh

SSH client for remote shell access with password or key authentication.
"""

import asyncio
import base64
import os
import shlex
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
                "ssh_options": {
                    "type": "string",
                    "description": "Additional SSH options (e.g., '-o KexAlgorithms=curve25519-sha256' for VPN/MTU issues)",
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
                "ssh_options": {
                    "type": "string",
                    "description": "Additional SSH options (e.g., '-o KexAlgorithms=curve25519-sha256' for VPN/MTU issues)",
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
                "ssh_options": {
                    "type": "string",
                    "description": "Additional SSH options (e.g., '-o KexAlgorithms=curve25519-sha256' for VPN/MTU issues)",
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
                "ssh_options": {
                    "type": "string",
                    "description": "Additional SSH options (e.g., '-o KexAlgorithms=curve25519-sha256' for VPN/MTU issues)",
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
                "ssh_options": {
                    "type": "string",
                    "description": "Additional SSH options (e.g., '-o KexAlgorithms=curve25519-sha256' for VPN/MTU issues)",
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
                "ssh_options": {
                    "type": "string",
                    "description": "Additional SSH options (e.g., '-o KexAlgorithms=curve25519-sha256' for VPN/MTU issues)",
                },
            },
            handler=self.run_script,
        )

        self.register_method(
            name="background",
            description="Execute a detached background process with environment variables. Process survives SSH disconnect.",
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
                "command": {
                    "type": "string",
                    "required": True,
                    "description": "Command to execute in background",
                },
                "password": {
                    "type": "string",
                    "description": "SSH password",
                },
                "key": {
                    "type": "string",
                    "description": "Private key content (PEM format)",
                },
                "port": {
                    "type": "integer",
                    "default": 22,
                    "description": "SSH port",
                },
                "env": {
                    "type": "object",
                    "description": "Environment variables to inject (e.g., {\"PYTHONPATH\": \"/tmp/evil\"})",
                },
                "output_file": {
                    "type": "string",
                    "description": "File to capture stdout/stderr on remote host",
                },
                "pid_file": {
                    "type": "string",
                    "description": "File to write PID for later management",
                },
                "return_check_command": {
                    "type": "boolean",
                    "default": False,
                    "description": "Return command to check if process is still running",
                },
                "ssh_options": {
                    "type": "string",
                    "description": "Additional SSH options",
                },
            },
            handler=self.background,
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
        connect_timeout: int = 30,
        ssh_options: Optional[str] = None,
    ) -> list:
        """Build common SSH arguments with robust connection settings."""
        args = []

        if password:
            args.extend(["sshpass", "-p", password])

        args.extend([
            "ssh",
            "-o", "StrictHostKeyChecking=no",
            "-o", "UserKnownHostsFile=/dev/null",
            "-o", "BatchMode=yes" if not password else "BatchMode=no",
            "-o", f"ConnectTimeout={connect_timeout}",
            "-o", "ServerAliveInterval=15",
            "-o", "ServerAliveCountMax=3",
            "-o", "TCPKeepAlive=yes",
            "-p", str(port),
        ])

        # Add custom SSH options (e.g., "-o KexAlgorithms=curve25519-sha256")
        if ssh_options:
            args.extend(shlex.split(ssh_options))

        if key_file:
            args.extend(["-i", key_file])

        args.append(f"{username}@{host}")

        return args

    def _classify_ssh_error(self, returncode: int, stderr: str) -> str:
        """Classify SSH errors and provide helpful suggestions."""
        stderr_lower = stderr.lower()

        if "connection refused" in stderr_lower:
            return "Connection refused - The SSH port is closed or a firewall is blocking the connection."
        elif "connection timed out" in stderr_lower:
            return "Connection timed out - The host may be unreachable or the SSH service is not responding. Try increasing the timeout or check network connectivity."
        elif "no route to host" in stderr_lower:
            return "No route to host - The target is not reachable. Check your network configuration and target IP."
        elif "permission denied" in stderr_lower:
            return "Permission denied - Invalid credentials. Verify username and password/key."
        elif "host key verification failed" in stderr_lower:
            return "Host key verification failed - SSH host key mismatch."
        elif "network is unreachable" in stderr_lower:
            return "Network unreachable - Check your network connection."
        elif returncode == 255:
            return f"SSH connection failed (exit code 255). This usually indicates a connection or authentication problem. Details: {stderr.strip()}"

        return f"SSH error (exit code {returncode}): {stderr.strip()}"

    async def exec_command(
        self,
        host: str,
        username: str,
        command: str,
        password: Optional[str] = None,
        key: Optional[str] = None,
        port: int = 22,
        timeout: int = 30,
        retries: int = 2,
        ssh_options: Optional[str] = None,
    ) -> ToolResult:
        """Execute a single command via SSH with automatic retry on transient failures."""
        self.logger.info(f"Executing command on {username}@{host}:{port}")

        key_file = None
        last_error = None
        attempt = 0

        try:
            # Write key to temp file if provided
            if key:
                # Convert OpenSSH format to PEM if needed
                key_content = self._convert_openssh_to_pem(key)
                fd, key_file = tempfile.mkstemp(prefix="ssh_key_")
                os.write(fd, key_content.encode())
                os.close(fd)
                os.chmod(key_file, 0o600)

            while attempt <= retries:
                attempt += 1

                # Use a longer connect timeout for first attempt
                connect_timeout = min(30, timeout // 2) if attempt == 1 else min(45, timeout)
                args = self._build_ssh_args(host, username, port, password, key_file, connect_timeout, ssh_options)
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
                    errors_filtered = "\n".join(
                        line for line in errors.split("\n")
                        if not line.startswith("Warning:")
                        and "Permanently added" not in line
                    )

                    # Check for transient failures that can be retried
                    if proc.returncode != 0:
                        errors_lower = errors.lower()
                        is_transient = (
                            "connection timed out" in errors_lower or
                            "connection reset" in errors_lower or
                            "network is unreachable" in errors_lower
                        )

                        if is_transient and attempt <= retries:
                            self.logger.warning(f"SSH connection failed (attempt {attempt}/{retries + 1}), retrying...")
                            await asyncio.sleep(2 * attempt)  # Exponential backoff
                            continue

                        # Non-transient failure or max retries reached
                        classified_error = self._classify_ssh_error(proc.returncode, errors)
                        return ToolResult(
                            success=False,
                            data={
                                "host": host,
                                "username": username,
                                "command": command,
                                "exit_code": proc.returncode,
                                "attempt": attempt,
                            },
                            error=classified_error,
                            raw_output=errors_filtered,
                        )

                    # Success
                    return ToolResult(
                        success=True,
                        data={
                            "host": host,
                            "username": username,
                            "command": command,
                            "exit_code": proc.returncode,
                            "stdout": output,
                            "stderr": errors_filtered.strip() if errors_filtered.strip() else None,
                        },
                        raw_output=output if output else errors_filtered,
                    )

                except asyncio.TimeoutError:
                    proc.kill()
                    last_error = f"Command timed out after {timeout} seconds"
                    if attempt <= retries:
                        self.logger.warning(f"SSH timeout (attempt {attempt}/{retries + 1}), retrying...")
                        await asyncio.sleep(2 * attempt)
                        continue
                    return ToolResult(
                        success=False,
                        data={"host": host, "username": username, "command": command, "attempt": attempt},
                        error=f"{last_error}. The SSH service may be slow or unreachable. Consider using shell-session for persistent connections.",
                    )

            # Should not reach here, but just in case
            return ToolResult(
                success=False,
                data={"host": host, "username": username, "command": command},
                error=last_error or "SSH connection failed after all retries",
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
        ssh_options: Optional[str] = None,
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
            ssh_options=ssh_options,
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
        ssh_options: Optional[str] = None,
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

            # Add custom SSH options
            if ssh_options:
                args.extend(shlex.split(ssh_options))

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
        ssh_options: Optional[str] = None,
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

            # Add custom SSH options
            if ssh_options:
                args.extend(shlex.split(ssh_options))

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
        ssh_options: Optional[str] = None,
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
                ssh_options=ssh_options,
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
                    ssh_options=ssh_options,
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
                    ssh_options=ssh_options,
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
                ssh_options=ssh_options,
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
        ssh_options: Optional[str] = None,
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
                ssh_options=ssh_options,
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
                ssh_options=ssh_options,
            )

            return result

        except Exception as e:
            return ToolResult(
                success=False,
                data={"host": host},
                error=str(e),
            )


    async def background(
        self,
        host: str,
        username: str,
        command: str,
        password: Optional[str] = None,
        key: Optional[str] = None,
        port: int = 22,
        env: Optional[dict] = None,
        output_file: Optional[str] = None,
        pid_file: Optional[str] = None,
        return_check_command: bool = False,
        ssh_options: Optional[str] = None,
    ) -> ToolResult:
        """Execute a command in the background on a remote host.

        The command runs detached from the SSH session and survives disconnect.
        Uses nohup and disown to ensure process persistence.
        """
        self.logger.info(f"Starting background process on {username}@{host}")

        # Build environment variable exports
        env_prefix = ""
        if env:
            env_exports = " ".join(f"{k}={shlex.quote(str(v))}" for k, v in env.items())
            env_prefix = f"export {env_exports} && "

        # Determine output redirection
        if output_file:
            output_redirect = f">{shlex.quote(output_file)} 2>&1"
        else:
            output_redirect = ">/dev/null 2>&1"

        # Escape single quotes in the command for embedding in bash -c
        escaped_command = command.replace("'", "'\\''")

        # Build the full background command
        if pid_file:
            # With PID file: run command, capture PID, then read it back
            pid_file_escaped = shlex.quote(pid_file)
            full_command = (
                f"{env_prefix}"
                f"nohup bash -c '{escaped_command}' {output_redirect} & "
                f"echo $! > {pid_file_escaped} && "
                f"disown && sleep 0.2 && cat {pid_file_escaped}"
            )
        else:
            # Without PID file: just start the background process
            full_command = (
                f"{env_prefix}"
                f"nohup bash -c '{escaped_command}' {output_redirect} & "
                f"disown && echo BACKGROUND_STARTED"
            )

        # Execute via SSH
        result = await self.exec_command(
            host=host,
            username=username,
            password=password,
            key=key,
            port=port,
            command=full_command,
            timeout=30,  # Background start should be quick
            ssh_options=ssh_options,
        )

        if not result.success:
            return ToolResult(
                success=False,
                data={
                    "host": host,
                    "username": username,
                    "command": command,
                },
                error=f"Failed to start background process: {result.error}",
            )

        # Parse the output to get PID if available
        stdout = result.data.get("stdout", "")
        pid = None

        # Try to extract PID from output
        if pid_file and stdout.strip():
            try:
                pid = stdout.strip().split('\n')[-1].strip()
                if not pid.isdigit():
                    pid = None
            except (IndexError, ValueError):
                pid = None

        # Build response
        response_data = {
            "success": True,
            "host": host,
            "username": username,
            "command": command,
            "detached": True,
        }

        if pid:
            response_data["pid"] = pid
        if output_file:
            response_data["output_file"] = output_file
        if pid_file:
            response_data["pid_file"] = pid_file
        if env:
            response_data["env"] = env

        # Add check command if requested
        if return_check_command and pid:
            response_data["check_command"] = f"ps -p {pid} -o comm="
        elif return_check_command and pid_file:
            response_data["check_command"] = f"ps -p $(cat {pid_file}) -o comm="

        return ToolResult(
            success=True,
            data=response_data,
            raw_output=f"Background process started on {host}. Command: {command}" + (f" (PID: {pid})" if pid else ""),
        )


if __name__ == "__main__":
    SSHServer.main()
