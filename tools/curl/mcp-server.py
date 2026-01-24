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

# Curl exit code to error type mapping
CURL_ERROR_TYPES = {
    6: "could_not_resolve_host",
    7: "connection_refused",
    28: "timeout",
    35: "ssl_error",
    47: "too_many_redirects",
    52: "empty_response",
    56: "receive_error",
    60: "ssl_certificate_error",
}

# Curl timing format string for -w option
CURL_TIMING_FORMAT = '''
__TIMING_START__
{"time_namelookup":%{time_namelookup},"time_connect":%{time_connect},"time_appconnect":%{time_appconnect},"time_pretransfer":%{time_pretransfer},"time_starttransfer":%{time_starttransfer},"time_total":%{time_total},"remote_ip":"%{remote_ip}","remote_port":%{remote_port}}
__TIMING_END__
'''


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
                    "type": ["object", "array"],
                    "description": "Custom headers as key-value pairs (object) or array of 'Header: value' strings",
                },
                "data": {
                    "type": "string",
                    "description": "Request body data",
                },
                "body": {
                    "type": "string",
                    "description": "Request body data (alias for 'data')",
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
                "connect_timeout": {
                    "type": "integer",
                    "default": 10,
                    "description": "Connection timeout in seconds",
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
                "debug_level": {
                    "type": "integer",
                    "enum": [0, 1, 2, 3],
                    "default": 0,
                    "description": "Debug level: 0=none, 1=request headers, 2=verbose output, 3=full trace",
                },
                "raw_response": {
                    "type": "boolean",
                    "default": False,
                    "description": "Return raw binary response as base64 (for binary downloads)",
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
                    "type": ["object", "array"],
                    "description": "Custom headers as key-value pairs (object) or array of 'Header: value' strings",
                },
                "data": {
                    "type": "string",
                    "description": "POST body (use {PAYLOAD} as placeholder)",
                },
                "body": {
                    "type": "string",
                    "description": "POST body (alias for 'data', use {PAYLOAD} as placeholder)",
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
                "connect_timeout": {
                    "type": "integer",
                    "default": 10,
                    "description": "Connection timeout in seconds",
                },
                "insecure": {
                    "type": "boolean",
                    "default": False,
                    "description": "Skip SSL certificate verification",
                },
                "debug_level": {
                    "type": "integer",
                    "enum": [0, 1, 2, 3],
                    "default": 0,
                    "description": "Debug level: 0=none, 1=request headers, 2=verbose output, 3=full trace",
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
                    "type": ["object", "array"],
                    "description": "Custom HTTP headers as key-value pairs (object) or array of 'Header: value' strings",
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
                "connect_timeout": {
                    "type": "integer",
                    "default": 10,
                    "description": "Connection timeout in seconds",
                },
                "insecure": {
                    "type": "boolean",
                    "default": False,
                    "description": "Skip SSL certificate verification",
                },
                "debug_level": {
                    "type": "integer",
                    "enum": [0, 1, 2, 3],
                    "default": 0,
                    "description": "Debug level: 0=none, 1=request headers, 2=verbose output, 3=full trace",
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

        self.register_method(
            name="download_to_file",
            description="Download a large file directly to a path (use for wordlists, binaries, etc.)",
            params={
                "url": {
                    "type": "string",
                    "required": True,
                    "description": "URL to download from",
                },
                "output_path": {
                    "type": "string",
                    "required": True,
                    "description": "Path to save file (e.g., /session/wordlists/rockyou.txt)",
                },
                "timeout": {
                    "type": "integer",
                    "default": 600,
                    "description": "Download timeout in seconds (default 10 minutes for large files)",
                },
                "insecure": {
                    "type": "boolean",
                    "default": False,
                    "description": "Skip SSL certificate verification",
                },
                "decompress": {
                    "type": "boolean",
                    "default": True,
                    "description": "Auto-decompress .gz files after download",
                },
            },
            handler=self.download_to_file,
        )

    def _parse_headers(self, header_output: str) -> Dict[str, str]:
        """Parse curl header output into a dictionary."""
        headers = {}
        for line in header_output.split("\r\n"):
            if ": " in line:
                key, value = line.split(": ", 1)
                headers[key.lower()] = value
        return headers

    def _normalize_headers(self, headers: Any) -> Dict[str, str]:
        """Accept both dict and array formats for headers."""
        if headers is None:
            return {}
        if isinstance(headers, dict):
            return headers
        if isinstance(headers, list):
            result = {}
            for h in headers:
                if isinstance(h, str) and ": " in h:
                    key, value = h.split(": ", 1)
                    result[key.strip()] = value.strip()
            return result
        return {}

    def _parse_timing(self, output: str) -> Optional[Dict[str, Any]]:
        """Extract timing JSON from curl output."""
        start_marker = "__TIMING_START__"
        end_marker = "__TIMING_END__"

        start_idx = output.find(start_marker)
        end_idx = output.find(end_marker)

        if start_idx == -1 or end_idx == -1:
            return None

        timing_json = output[start_idx + len(start_marker):end_idx].strip()
        try:
            timing_raw = json.loads(timing_json)
            # Convert seconds to milliseconds and provide friendly names
            # TLS handshake is only relevant for HTTPS (appconnect > connect)
            appconnect = timing_raw.get("time_appconnect", 0)
            connect = timing_raw.get("time_connect", 0)
            tls_handshake = max(0, int((appconnect - connect) * 1000)) if appconnect > 0 else 0

            return {
                "dns_lookup_ms": int(timing_raw.get("time_namelookup", 0) * 1000),
                "connect_ms": int(connect * 1000),
                "tls_handshake_ms": tls_handshake,
                "first_byte_ms": int(timing_raw.get("time_starttransfer", 0) * 1000),
                "total_ms": int(timing_raw.get("time_total", 0) * 1000),
                "remote_ip": timing_raw.get("remote_ip", ""),
                "remote_port": timing_raw.get("remote_port", 0),
            }
        except (json.JSONDecodeError, KeyError, TypeError):
            return None

    def _strip_timing_block(self, output: str) -> str:
        """Remove timing markers from output."""
        start_marker = "__TIMING_START__"
        end_marker = "__TIMING_END__"

        start_idx = output.find(start_marker)
        end_idx = output.find(end_marker)

        if start_idx != -1 and end_idx != -1:
            # Remove the timing block including markers and surrounding newlines
            before = output[:start_idx].rstrip('\n')
            after = output[end_idx + len(end_marker):].lstrip('\n')
            return before + after
        return output

    def _get_error_message(self, error_type: str, stderr: str) -> str:
        """Return human-readable error message for curl error types."""
        messages = {
            "could_not_resolve_host": "Could not resolve hostname - check DNS or hostname spelling",
            "connection_refused": "Connection refused - target may be down or port closed",
            "timeout": "Request timed out - target may be slow or unreachable",
            "ssl_error": "SSL/TLS error - try with insecure=true if appropriate",
            "too_many_redirects": "Too many redirects - possible redirect loop",
            "empty_response": "Server returned empty response",
            "receive_error": "Error receiving data from server",
            "ssl_certificate_error": "SSL certificate verification failed - try with insecure=true",
            "unknown": f"Request failed: {stderr}",
        }
        return messages.get(error_type, messages["unknown"])

    def _parse_verbose_request_headers(self, stderr: str) -> Dict[str, str]:
        """Parse request headers from curl verbose output (> Header: value lines)."""
        headers = {}
        for line in stderr.split('\n'):
            line = line.strip()
            if line.startswith('> ') and ': ' in line:
                header_line = line[2:]  # Remove '> ' prefix
                if ': ' in header_line:
                    key, value = header_line.split(': ', 1)
                    # Skip the request line (GET /path HTTP/1.1)
                    if not key.startswith(('GET', 'POST', 'PUT', 'DELETE', 'HEAD', 'OPTIONS', 'PATCH')):
                        headers[key] = value
        return headers

    async def _execute_curl_request(
        self,
        args: List[str],
        url: str,
        method: str,
        timeout: int,
        debug_level: int = 0,
        raw_response: bool = False,
    ) -> ToolResult:
        """
        Core curl execution with timing capture, structured errors, and debug support.

        Returns structured ToolResult with timing, error details, and optional debug info.
        """
        # Add timing format
        args.extend(["-w", CURL_TIMING_FORMAT])

        # Add verbose flag for debug levels >= 1
        if debug_level >= 1:
            args.append("-v")

        try:
            if raw_response:
                # For binary responses, capture raw stdout
                proc = await asyncio.create_subprocess_exec(
                    *args,
                    stdout=asyncio.subprocess.PIPE,
                    stderr=asyncio.subprocess.PIPE,
                )
                stdout_bytes, stderr_bytes = await asyncio.wait_for(
                    proc.communicate(),
                    timeout=timeout + 10,
                )
                returncode = proc.returncode
                stdout = stdout_bytes.decode('utf-8', errors='replace')
                stderr = stderr_bytes.decode('utf-8', errors='replace')
            else:
                result = await self.run_command(args, timeout=timeout + 10)
                stdout = result.stdout
                stderr = result.stderr if hasattr(result, 'stderr') else ""
                returncode = 0  # run_command raises on non-zero

        except ToolError as e:
            # Extract exit code from error if available
            error_str = str(e)
            exit_code = None
            stderr = error_str

            # Try to extract exit code from error message
            if "exit code" in error_str.lower():
                import re
                match = re.search(r'exit code[:\s]+(\d+)', error_str, re.IGNORECASE)
                if match:
                    exit_code = int(match.group(1))

            error_type = CURL_ERROR_TYPES.get(exit_code, "unknown") if exit_code else "unknown"
            error_message = self._get_error_message(error_type, stderr)

            return ToolResult(
                success=False,
                data={
                    "url": url,
                    "method": method,
                    "status_code": None,
                    "headers": {},
                    "body": "",
                    "body_length": 0,
                    "timing": None,
                    "error": {
                        "type": error_type,
                        "message": error_message,
                        "stderr": stderr[:2000],
                        "curl_exit_code": exit_code,
                    },
                },
                error=error_message,
            )
        except asyncio.TimeoutError:
            return ToolResult(
                success=False,
                data={
                    "url": url,
                    "method": method,
                    "status_code": None,
                    "headers": {},
                    "body": "",
                    "body_length": 0,
                    "timing": None,
                    "error": {
                        "type": "timeout",
                        "message": f"Request timed out after {timeout} seconds",
                        "stderr": "",
                        "curl_exit_code": 28,
                    },
                },
                error=f"Request timed out after {timeout} seconds",
            )

        # Parse timing from output
        timing = self._parse_timing(stdout)

        # Strip timing block from output for body parsing
        output = self._strip_timing_block(stdout)

        # Parse response - headers and body are separated by \r\n\r\n
        # When following redirects, output contains multiple HTTP responses.
        # We need to parse the LAST (final) response.
        status_code = None
        response_headers = {}
        body = output

        if "\r\n\r\n" in output:
            # Find all response boundaries (HTTP status lines)
            # Each new HTTP response starts with "HTTP/1.x" or "HTTP/2"
            # Split by \r\n\r\n to get all sections
            sections = output.split("\r\n\r\n")

            # Find the last section that starts with HTTP/ (final response headers)
            final_header_idx = -1
            for i, section in enumerate(sections[:-1]):  # Exclude last section (body)
                # Check if this section contains an HTTP status line
                # For redirect chains, intermediate sections may have both headers and new HTTP line
                lines = section.split("\r\n")
                for line in lines:
                    if line.startswith("HTTP/"):
                        final_header_idx = i
                        # Don't break - we want the LAST one

            if final_header_idx >= 0:
                # The final response headers are in sections[final_header_idx]
                # But we need the LAST HTTP status line within it (for redirect chains)
                header_section = sections[final_header_idx]

                # Body is everything after this header section
                body = "\r\n\r\n".join(sections[final_header_idx + 1:])

                # Find the last HTTP status line in the header section
                lines = header_section.split("\r\n")
                last_http_idx = -1
                for i, line in enumerate(lines):
                    if line.startswith("HTTP/"):
                        last_http_idx = i

                if last_http_idx >= 0:
                    status_line = lines[last_http_idx]
                    status_parts = status_line.split(" ", 2)
                    if len(status_parts) >= 2:
                        try:
                            status_code = int(status_parts[1])
                        except ValueError:
                            pass

                    # Parse headers from lines after the last HTTP status line
                    final_headers = "\r\n".join(lines[last_http_idx + 1:])
                    response_headers = self._parse_headers(final_headers)
            else:
                # No HTTP line found, fall back to simple split
                header_section, body = output.split("\r\n\r\n", 1)
                lines = header_section.split("\r\n")
                for line in lines:
                    if line.startswith("HTTP/"):
                        status_parts = line.split(" ", 2)
                        if len(status_parts) >= 2:
                            try:
                                status_code = int(status_parts[1])
                            except ValueError:
                                pass
                response_headers = self._parse_headers(header_section)
        else:
            # Fallback: Try to parse status from output start (e.g., HTTP/2 with empty body)
            # Some HTTP/2 responses with empty body may not have clear \r\n\r\n separator
            lines = output.split("\r\n")
            for line in lines:
                if line.startswith("HTTP/"):
                    status_parts = line.split(" ", 2)
                    if len(status_parts) >= 2:
                        try:
                            status_code = int(status_parts[1])
                            # Parse remaining lines as headers
                            header_lines = "\r\n".join(lines[1:])
                            response_headers = self._parse_headers(header_lines)
                            body = ""  # No body when no \r\n\r\n separator
                            break
                        except ValueError:
                            pass

        # Detect curl failures that didn't raise exceptions
        # Indicators:
        # 1. No status code AND (no remote_ip OR negative remote_port) = connection failure
        # 2. No status code AND first_byte_ms=0 AND total_ms > 0 = timeout during transfer
        connection_failed = (
            status_code is None and
            timing and
            (not timing.get("remote_ip") or timing.get("remote_port", 0) < 0)
        )
        transfer_timeout = (
            status_code is None and
            timing and
            timing.get("remote_ip") and  # Connected successfully
            timing.get("first_byte_ms", -1) == 0 and  # No response
            timing.get("total_ms", 0) > 0  # Time elapsed
        )
        curl_failed = connection_failed or transfer_timeout

        if curl_failed:
            # Determine error type from stderr or indicators
            error_type = "unknown"
            if transfer_timeout:
                error_type = "timeout"
            elif stderr:
                stderr_lower = stderr.lower()
                if "could not resolve" in stderr_lower or "couldn't resolve" in stderr_lower:
                    error_type = "could_not_resolve_host"
                elif "connection refused" in stderr_lower:
                    error_type = "connection_refused"
                elif "timed out" in stderr_lower or "timeout" in stderr_lower:
                    error_type = "timeout"
                elif "ssl" in stderr_lower or "certificate" in stderr_lower:
                    error_type = "ssl_error"

            error_message = self._get_error_message(error_type, stderr)

            return ToolResult(
                success=False,
                data={
                    "url": url,
                    "method": method,
                    "status_code": None,
                    "headers": {},
                    "body": "",
                    "body_length": 0,
                    "timing": timing,
                    "error": {
                        "type": error_type,
                        "message": error_message,
                        "stderr": stderr[:2000] if stderr else "",
                        "curl_exit_code": None,
                    },
                },
                error=error_message,
            )

        # Build response data
        response_data = {
            "url": url,
            "method": method,
            "status_code": status_code,
            "headers": response_headers,
            "body": body[:50000] if len(body) > 50000 else body,
            "body_length": len(body),
            "timing": timing,
        }

        # Add debug info if requested
        if debug_level >= 1:
            debug_info = {
                "request_headers": self._parse_verbose_request_headers(stderr),
            }
            if debug_level >= 2:
                debug_info["verbose_output"] = stderr[:10000] if len(stderr) > 10000 else stderr
            response_data["debug"] = debug_info

        # Handle raw binary response
        if raw_response and stdout_bytes:
            response_data["body_base64"] = base64.b64encode(stdout_bytes).decode('utf-8')

        return ToolResult(
            success=True,
            data=response_data,
            raw_output=sanitize_output(output),
        )

    async def request(
        self,
        url: str,
        method: str = "GET",
        headers: Optional[Any] = None,
        data: Optional[str] = None,
        body: Optional[str] = None,
        follow_redirects: bool = True,
        timeout: int = 30,
        connect_timeout: int = 10,
        insecure: bool = False,
        user_agent: Optional[str] = None,
        cookie: Optional[str] = None,
        auth: Optional[str] = None,
        debug_level: int = 0,
        raw_response: bool = False,
    ) -> ToolResult:
        """Make an HTTP request."""
        self.logger.info(f"Making {method} request to {url}")

        # Handle body alias
        request_body = body if body is not None else data

        # Normalize headers (accept dict or array)
        normalized_headers = self._normalize_headers(headers)

        args = [
            "curl",
            "-s",  # Silent
            "-S",  # Show errors
            "-i",  # Include response headers
            "-X", method,
            "--max-time", str(timeout),
            "--connect-timeout", str(connect_timeout),
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

        if normalized_headers:
            for key, value in normalized_headers.items():
                args.extend(["-H", f"{key}: {value}"])

        if request_body:
            args.extend(["-d", request_body])

        args.append(url)

        return await self._execute_curl_request(
            args=args,
            url=url,
            method=method,
            timeout=timeout,
            debug_level=debug_level,
            raw_response=raw_response,
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
        headers: Optional[Any] = None,
        data: Optional[str] = None,
        body: Optional[str] = None,
        cookie: Optional[str] = None,
        timeout: int = 30,
        connect_timeout: int = 10,
        insecure: bool = False,
        debug_level: int = 0,
    ) -> ToolResult:
        """Send a payload to a web RCE endpoint and extract output."""
        self.logger.info(f"Injecting command via {method} to {url}")

        # Handle body alias
        request_body = body if body is not None else data

        # Encode the payload
        encoded_payload = self._encode_payload(command, encoding)

        # Replace {PAYLOAD} placeholder in URL and body
        final_url = url.replace("{PAYLOAD}", encoded_payload)
        final_body = request_body.replace("{PAYLOAD}", encoded_payload) if request_body else None

        # Make the request
        result = await self.request(
            url=final_url,
            method=method,
            headers=headers,
            body=final_body,
            follow_redirects=True,
            timeout=timeout,
            connect_timeout=connect_timeout,
            insecure=insecure,
            cookie=cookie,
            debug_level=debug_level,
        )

        if not result.success:
            # Include timing and error info from the underlying request
            result.data["command"] = command
            result.data["encoding"] = encoding
            return result

        # Extract output from response
        response_body = result.data.get("body", "")
        extracted = self._extract_output(response_body, output_markers, strip_html)

        inject_data = {
            "url": final_url,
            "command": command,
            "encoding": encoding,
            "status_code": result.data.get("status_code"),
            "output": extracted,
            "raw_body_length": len(response_body),
            "timing": result.data.get("timing"),
        }

        # Include debug info if present
        if "debug" in result.data:
            inject_data["debug"] = result.data["debug"]

        return ToolResult(
            success=True,
            data=inject_data,
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
        headers: Optional[Any] = None,
        cookie: Optional[str] = None,
        timeout: int = 60,
        connect_timeout: int = 10,
        insecure: bool = False,
        debug_level: int = 0,
    ) -> ToolResult:
        """Upload a file using multipart/form-data."""
        self.logger.info(f"Uploading {filename} to {url}")

        import tempfile
        import os

        # Normalize headers (accept dict or array)
        normalized_headers = self._normalize_headers(headers)

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
                "--connect-timeout", str(connect_timeout),
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
            if normalized_headers:
                for key, value in normalized_headers.items():
                    args.extend(["-H", f"{key}: {value}"])

            # Add cookies
            if cookie:
                args.extend(["-b", cookie])

            args.append(url)

            # Use core execution method for consistent timing/error handling
            result = await self._execute_curl_request(
                args=args,
                url=url,
                method="POST",
                timeout=timeout,
                debug_level=debug_level,
            )

            # Add upload-specific info to the response
            if result.success:
                result.data["filename"] = filename
                result.data["file_size"] = len(file_content)

            return result

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

    async def download_to_file(
        self,
        url: str,
        output_path: str,
        timeout: int = 600,
        insecure: bool = False,
        decompress: bool = True,
    ) -> ToolResult:
        """Download a large file directly to a path (for wordlists, binaries, etc.)."""
        import os
        import gzip
        import shutil

        self.logger.info(f"Downloading file from {url} to {output_path}")

        # Ensure parent directory exists
        parent_dir = os.path.dirname(output_path)
        if parent_dir and not os.path.exists(parent_dir):
            os.makedirs(parent_dir, exist_ok=True)

        # Determine if we need to decompress
        is_gzip = url.endswith('.gz') or '.gz?' in url
        temp_path = output_path + '.gz' if is_gzip and decompress else output_path

        args = [
            "curl",
            "-s",
            "-S",
            "-L",
            "--max-time", str(timeout),
            "-o", temp_path,
            "--progress-bar",  # Show progress
        ]

        if insecure:
            args.append("-k")

        args.append(url)

        try:
            proc = await asyncio.create_subprocess_exec(
                *args,
                stdout=asyncio.subprocess.PIPE,
                stderr=asyncio.subprocess.PIPE,
            )

            stdout, stderr = await asyncio.wait_for(
                proc.communicate(),
                timeout=timeout + 30,
            )

            if proc.returncode != 0:
                return ToolResult(
                    success=False,
                    data={"url": url, "output_path": output_path},
                    error=f"Download failed: {stderr.decode('utf-8', errors='replace')}",
                )

            # Check file was created
            if not os.path.exists(temp_path):
                return ToolResult(
                    success=False,
                    data={"url": url, "output_path": output_path},
                    error="Download completed but file not found",
                )

            file_size = os.path.getsize(temp_path)

            # Decompress if needed
            if is_gzip and decompress:
                self.logger.info(f"Decompressing {temp_path} to {output_path}")
                try:
                    with gzip.open(temp_path, 'rb') as f_in:
                        with open(output_path, 'wb') as f_out:
                            shutil.copyfileobj(f_in, f_out)
                    os.remove(temp_path)
                    file_size = os.path.getsize(output_path)
                except Exception as e:
                    return ToolResult(
                        success=False,
                        data={"url": url, "output_path": output_path},
                        error=f"Decompression failed: {str(e)}",
                    )

            # Count lines for text files
            line_count = None
            if output_path.endswith('.txt'):
                try:
                    with open(output_path, 'rb') as f:
                        line_count = sum(1 for _ in f)
                except:
                    pass

            return ToolResult(
                success=True,
                data={
                    "url": url,
                    "output_path": output_path,
                    "size_bytes": file_size,
                    "size_mb": round(file_size / (1024 * 1024), 2),
                    "line_count": line_count,
                    "decompressed": is_gzip and decompress,
                },
                raw_output=f"Downloaded to {output_path} ({file_size} bytes, {line_count} lines)" if line_count else f"Downloaded to {output_path} ({file_size} bytes)",
            )

        except asyncio.TimeoutError:
            return ToolResult(
                success=False,
                data={"url": url, "output_path": output_path},
                error=f"Download timed out after {timeout} seconds",
            )
        except Exception as e:
            return ToolResult(
                success=False,
                data={"url": url, "output_path": output_path},
                error=str(e),
            )


if __name__ == "__main__":
    CurlServer.main()
