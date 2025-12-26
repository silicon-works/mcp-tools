#!/usr/bin/env python3
"""
OpenSploit MCP Server: curl

HTTP client for making web requests, testing exploits, and downloading files.
"""

import asyncio
import base64
import html
import json
import re
from typing import Any, Dict, List, Optional
from urllib.parse import urlparse, quote as url_quote

from mcp_common import BaseMCPServer, ToolResult, ToolError, sanitize_output


class CurlServer(BaseMCPServer):
    """MCP server wrapping curl for HTTP requests."""

    def __init__(self):
        super().__init__(
            name="curl",
            description="HTTP client for web requests, exploit testing, and file downloads",
            version="1.0.0",
        )

        self.register_method(
            name="request",
            description="Make an HTTP request to a URL",
            params={
                "url": {
                    "type": "string",
                    "required": True,
                    "description": "Target URL",
                },
                "method": {
                    "type": "string",
                    "enum": ["GET", "POST", "PUT", "DELETE", "HEAD", "OPTIONS", "PATCH"],
                    "default": "GET",
                    "description": "HTTP method",
                },
                "headers": {
                    "type": "object",
                    "description": "Custom headers as key-value pairs",
                },
                "data": {
                    "type": "string",
                    "description": "Request body data",
                },
                "follow_redirects": {
                    "type": "boolean",
                    "default": True,
                    "description": "Follow HTTP redirects",
                },
                "timeout": {
                    "type": "integer",
                    "default": 30,
                    "description": "Request timeout in seconds",
                },
                "insecure": {
                    "type": "boolean",
                    "default": False,
                    "description": "Skip SSL certificate verification",
                },
                "user_agent": {
                    "type": "string",
                    "description": "Custom User-Agent header",
                },
                "cookie": {
                    "type": "string",
                    "description": "Cookie header value",
                },
                "auth": {
                    "type": "string",
                    "description": "Basic auth in user:password format",
                },
            },
            handler=self.request,
        )

        self.register_method(
            name="inject",
            description="Send a payload to a web RCE endpoint and extract output",
            params={
                "url": {
                    "type": "string",
                    "required": True,
                    "description": "Target URL (use {PAYLOAD} as placeholder for command)",
                },
                "command": {
                    "type": "string",
                    "required": True,
                    "description": "Command to execute",
                },
                "method": {
                    "type": "string",
                    "enum": ["GET", "POST"],
                    "default": "GET",
                    "description": "HTTP method",
                },
                "encoding": {
                    "type": "string",
                    "enum": ["url", "double-url", "base64", "none"],
                    "default": "url",
                    "description": "Payload encoding method",
                },
                "output_markers": {
                    "type": "object",
                    "description": "Start/end markers to extract output: {start: str, end: str}",
                },
                "strip_html": {
                    "type": "boolean",
                    "default": True,
                    "description": "Strip HTML tags from output",
                },
                "headers": {
                    "type": "object",
                    "description": "Custom headers as key-value pairs",
                },
                "data": {
                    "type": "string",
                    "description": "POST body (use {PAYLOAD} as placeholder)",
                },
                "cookie": {
                    "type": "string",
                    "description": "Cookie header value",
                },
                "timeout": {
                    "type": "integer",
                    "default": 30,
                    "description": "Request timeout in seconds",
                },
                "insecure": {
                    "type": "boolean",
                    "default": False,
                    "description": "Skip SSL certificate verification",
                },
            },
            handler=self.inject,
        )

        self.register_method(
            name="upload",
            description="Upload a file using multipart/form-data (for web shell uploads, file injection, etc.)",
            params={
                "url": {
                    "type": "string",
                    "required": True,
                    "description": "Target upload URL",
                },
                "file_field": {
                    "type": "string",
                    "required": True,
                    "description": "Form field name for file (e.g., 'file', 'upload', 'avatar')",
                },
                "filename": {
                    "type": "string",
                    "required": True,
                    "description": "Filename to send (e.g., 'shell.php', 'image.png')",
                },
                "content": {
                    "type": "string",
                    "required": True,
                    "description": "File content (plain text or base64 encoded)",
                },
                "content_type": {
                    "type": "string",
                    "default": "application/octet-stream",
                    "description": "MIME type for the uploaded file",
                },
                "is_base64": {
                    "type": "boolean",
                    "default": False,
                    "description": "Whether content is base64 encoded",
                },
                "extra_fields": {
                    "type": "object",
                    "description": "Additional form fields as key-value pairs",
                },
                "headers": {
                    "type": "object",
                    "description": "Custom HTTP headers",
                },
                "cookie": {
                    "type": "string",
                    "description": "Cookie header value",
                },
                "timeout": {
                    "type": "integer",
                    "default": 60,
                    "description": "Upload timeout in seconds",
                },
                "insecure": {
                    "type": "boolean",
                    "default": False,
                    "description": "Skip SSL certificate verification",
                },
            },
            handler=self.upload,
        )

        self.register_method(
            name="download",
            description="Download a file from a URL",
            params={
                "url": {
                    "type": "string",
                    "required": True,
                    "description": "URL to download from",
                },
                "timeout": {
                    "type": "integer",
                    "default": 120,
                    "description": "Download timeout in seconds",
                },
                "insecure": {
                    "type": "boolean",
                    "default": False,
                    "description": "Skip SSL certificate verification",
                },
            },
            handler=self.download,
        )

    def _parse_headers(self, header_output: str) -> Dict[str, str]:
        """Parse curl header output into a dictionary."""
        headers = {}
        for line in header_output.split("\r\n"):
            if ": " in line:
                key, value = line.split(": ", 1)
                headers[key.lower()] = value
        return headers

    async def request(
        self,
        url: str,
        method: str = "GET",
        headers: Optional[Dict[str, str]] = None,
        data: Optional[str] = None,
        follow_redirects: bool = True,
        timeout: int = 30,
        insecure: bool = False,
        user_agent: Optional[str] = None,
        cookie: Optional[str] = None,
        auth: Optional[str] = None,
    ) -> ToolResult:
        """Make an HTTP request."""
        self.logger.info(f"Making {method} request to {url}")

        args = [
            "curl",
            "-s",  # Silent
            "-S",  # Show errors
            "-i",  # Include response headers
            "-X", method,
            "--max-time", str(timeout),
        ]

        if follow_redirects:
            args.extend(["-L", "--max-redirs", "10"])

        if insecure:
            args.append("-k")

        if user_agent:
            args.extend(["-A", user_agent])
        else:
            args.extend(["-A", "Mozilla/5.0 (Windows NT 10.0; Win64; x64) AppleWebKit/537.36"])

        if cookie:
            args.extend(["-b", cookie])

        if auth:
            args.extend(["-u", auth])

        if headers:
            for key, value in headers.items():
                args.extend(["-H", f"{key}: {value}"])

        if data:
            args.extend(["-d", data])

        args.append(url)

        try:
            result = await self.run_command(args, timeout=timeout + 10)
            output = result.stdout

            # Parse response - headers and body are separated by \r\n\r\n
            status_code = None
            response_headers = {}
            body = output

            if "\r\n\r\n" in output:
                header_section, body = output.split("\r\n\r\n", 1)

                # Parse status line
                lines = header_section.split("\r\n")
                if lines and lines[0].startswith("HTTP/"):
                    status_parts = lines[0].split(" ", 2)
                    if len(status_parts) >= 2:
                        try:
                            status_code = int(status_parts[1])
                        except ValueError:
                            pass

                response_headers = self._parse_headers(header_section)

            return ToolResult(
                success=True,
                data={
                    "url": url,
                    "method": method,
                    "status_code": status_code,
                    "headers": response_headers,
                    "body": body[:50000] if len(body) > 50000 else body,  # Limit body size
                    "body_length": len(body),
                },
                raw_output=sanitize_output(output),
            )

        except ToolError as e:
            return ToolResult(
                success=False,
                data={"url": url, "method": method},
                error=str(e),
            )

    def _encode_payload(self, payload: str, encoding: str) -> str:
        """Encode payload using specified method."""
        if encoding == "url":
            return url_quote(payload, safe="")
        elif encoding == "double-url":
            return url_quote(url_quote(payload, safe=""), safe="")
        elif encoding == "base64":
            return base64.b64encode(payload.encode()).decode()
        else:  # none
            return payload

    def _extract_output(
        self,
        body: str,
        markers: Optional[Dict[str, str]] = None,
        strip_html: bool = True,
    ) -> str:
        """Extract command output from response body."""
        output = body

        # Extract between markers if provided
        if markers:
            start = markers.get("start", "")
            end = markers.get("end", "")
            if start and end:
                pattern = re.escape(start) + r"(.*?)" + re.escape(end)
                match = re.search(pattern, output, re.DOTALL)
                if match:
                    output = match.group(1)
            elif start:
                idx = output.find(start)
                if idx != -1:
                    output = output[idx + len(start):]
            elif end:
                idx = output.find(end)
                if idx != -1:
                    output = output[:idx]

        # Strip HTML tags if requested
        if strip_html:
            # Decode HTML entities
            output = html.unescape(output)
            # Remove HTML tags
            output = re.sub(r"<[^>]+>", "", output)
            # Normalize whitespace
            output = re.sub(r"\s+", " ", output).strip()

        return output

    async def inject(
        self,
        url: str,
        command: str,
        method: str = "GET",
        encoding: str = "url",
        output_markers: Optional[Dict[str, str]] = None,
        strip_html: bool = True,
        headers: Optional[Dict[str, str]] = None,
        data: Optional[str] = None,
        cookie: Optional[str] = None,
        timeout: int = 30,
        insecure: bool = False,
    ) -> ToolResult:
        """Send a payload to a web RCE endpoint and extract output."""
        self.logger.info(f"Injecting command via {method} to {url}")

        # Encode the payload
        encoded_payload = self._encode_payload(command, encoding)

        # Replace {PAYLOAD} placeholder in URL and data
        final_url = url.replace("{PAYLOAD}", encoded_payload)
        final_data = data.replace("{PAYLOAD}", encoded_payload) if data else None

        # Make the request
        result = await self.request(
            url=final_url,
            method=method,
            headers=headers,
            data=final_data,
            follow_redirects=True,
            timeout=timeout,
            insecure=insecure,
            cookie=cookie,
        )

        if not result.success:
            return result

        # Extract output from response
        body = result.data.get("body", "")
        extracted = self._extract_output(body, output_markers, strip_html)

        return ToolResult(
            success=True,
            data={
                "url": final_url,
                "command": command,
                "encoding": encoding,
                "status_code": result.data.get("status_code"),
                "output": extracted,
                "raw_body_length": len(body),
            },
            raw_output=extracted,
        )

    async def upload(
        self,
        url: str,
        file_field: str,
        filename: str,
        content: str,
        content_type: str = "application/octet-stream",
        is_base64: bool = False,
        extra_fields: Optional[Dict[str, str]] = None,
        headers: Optional[Dict[str, str]] = None,
        cookie: Optional[str] = None,
        timeout: int = 60,
        insecure: bool = False,
    ) -> ToolResult:
        """Upload a file using multipart/form-data."""
        self.logger.info(f"Uploading {filename} to {url}")

        import tempfile
        import os

        # Decode content if base64
        if is_base64:
            try:
                file_content = base64.b64decode(content)
            except Exception as e:
                return ToolResult(
                    success=False,
                    data={"url": url},
                    error=f"Failed to decode base64 content: {e}",
                )
        else:
            file_content = content.encode('utf-8')

        # Write content to temp file for curl upload
        with tempfile.NamedTemporaryFile(mode='wb', delete=False, suffix=f"_{filename}") as f:
            f.write(file_content)
            temp_file = f.name

        try:
            args = [
                "curl",
                "-s",
                "-S",
                "-i",
                "-X", "POST",
                "--max-time", str(timeout),
            ]

            if insecure:
                args.append("-k")

            # Add the file field with multipart upload
            args.extend(["-F", f"{file_field}=@{temp_file};filename={filename};type={content_type}"])

            # Add extra form fields
            if extra_fields:
                for key, value in extra_fields.items():
                    args.extend(["-F", f"{key}={value}"])

            # Add custom headers
            if headers:
                for key, value in headers.items():
                    args.extend(["-H", f"{key}: {value}"])

            # Add cookies
            if cookie:
                args.extend(["-b", cookie])

            args.append(url)

            result = await self.run_command(args, timeout=timeout + 10)
            output = result.stdout

            # Parse response
            status_code = None
            response_headers = {}
            body = output

            if "\r\n\r\n" in output:
                header_section, body = output.split("\r\n\r\n", 1)
                lines = header_section.split("\r\n")
                if lines and lines[0].startswith("HTTP/"):
                    status_parts = lines[0].split(" ", 2)
                    if len(status_parts) >= 2:
                        try:
                            status_code = int(status_parts[1])
                        except ValueError:
                            pass
                response_headers = self._parse_headers(header_section)

            return ToolResult(
                success=True,
                data={
                    "url": url,
                    "filename": filename,
                    "file_size": len(file_content),
                    "status_code": status_code,
                    "headers": response_headers,
                    "body": body[:50000] if len(body) > 50000 else body,
                    "body_length": len(body),
                },
                raw_output=sanitize_output(output),
            )

        except ToolError as e:
            return ToolResult(
                success=False,
                data={"url": url, "filename": filename},
                error=str(e),
            )
        finally:
            # Cleanup temp file
            if os.path.exists(temp_file):
                os.unlink(temp_file)

    async def download(
        self,
        url: str,
        timeout: int = 120,
        insecure: bool = False,
    ) -> ToolResult:
        """Download a file and return its contents as base64."""
        self.logger.info(f"Downloading file from {url}")

        # Extract filename from URL
        parsed = urlparse(url)
        filename = parsed.path.split("/")[-1] or "downloaded_file"

        args = [
            "curl",
            "-s",
            "-S",
            "-L",
            "--max-time", str(timeout),
            "-o", "-",  # Output to stdout
        ]

        if insecure:
            args.append("-k")

        args.append(url)

        try:
            # Run curl and capture binary output
            import asyncio
            proc = await asyncio.create_subprocess_exec(
                *args,
                stdout=asyncio.subprocess.PIPE,
                stderr=asyncio.subprocess.PIPE,
            )

            stdout, stderr = await asyncio.wait_for(
                proc.communicate(),
                timeout=timeout + 10,
            )

            if proc.returncode != 0:
                return ToolResult(
                    success=False,
                    data={"url": url},
                    error=f"Download failed: {stderr.decode('utf-8', errors='replace')}",
                )

            # Encode as base64
            content_b64 = base64.b64encode(stdout).decode("utf-8")

            return ToolResult(
                success=True,
                data={
                    "url": url,
                    "filename": filename,
                    "size_bytes": len(stdout),
                    "content_base64": content_b64,
                },
                raw_output=f"Downloaded {len(stdout)} bytes from {url}",
            )

        except asyncio.TimeoutError:
            return ToolResult(
                success=False,
                data={"url": url},
                error=f"Download timed out after {timeout} seconds",
            )
        except Exception as e:
            return ToolResult(
                success=False,
                data={"url": url},
                error=str(e),
            )


if __name__ == "__main__":
    CurlServer.main()
