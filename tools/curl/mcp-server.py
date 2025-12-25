#!/usr/bin/env python3
"""
OpenSploit MCP Server: curl

HTTP client for making web requests, testing exploits, and downloading files.
"""

import base64
import json
from typing import Any, Dict, List, Optional
from urllib.parse import urlparse

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
