#!/usr/bin/env python3
"""
OpenSploit MCP Server: web-session

Session state management for web application testing.
Persists cookies and session data across tool calls.
"""

import asyncio
import base64
import hashlib
import json
import os
import re
import ssl
import urllib.request
import urllib.error
from datetime import datetime
from http.cookiejar import CookieJar
from typing import Any, Dict, List, Optional
from urllib.parse import urlparse, urlencode

from mcp_common import BaseMCPServer, ToolResult, ToolError

# Persistent session storage (in-memory for container lifetime)
SESSIONS: Dict[str, Dict[str, Any]] = {}


class WebSessionServer(BaseMCPServer):
    """MCP server for web session management."""

    def __init__(self):
        super().__init__(
            name="web-session",
            description="Web session state management for authenticated testing",
            version="1.0.0",
        )

        self.register_method(
            name="login",
            description="Perform login and capture session cookies",
            params={
                "url": {
                    "type": "string",
                    "required": True,
                    "description": "Login URL endpoint",
                },
                "username_field": {
                    "type": "string",
                    "default": "username",
                    "description": "Form field name for username",
                },
                "password_field": {
                    "type": "string",
                    "default": "password",
                    "description": "Form field name for password",
                },
                "username": {
                    "type": "string",
                    "required": True,
                    "description": "Username to login with",
                },
                "password": {
                    "type": "string",
                    "required": True,
                    "description": "Password to login with",
                },
                "extra_fields": {
                    "type": "object",
                    "description": "Additional form fields (e.g., CSRF token)",
                },
                "session_name": {
                    "type": "string",
                    "default": "default",
                    "description": "Name to store this session under",
                },
                "success_indicator": {
                    "type": "string",
                    "description": "Text that indicates successful login",
                },
                "failure_indicator": {
                    "type": "string",
                    "description": "Text that indicates failed login",
                },
                "headers": {
                    "type": "object",
                    "description": "Custom HTTP headers",
                },
                "timeout": {
                    "type": "integer",
                    "default": 30,
                    "description": "Request timeout in seconds",
                },
            },
            handler=self.login,
        )

        self.register_method(
            name="get_cookies",
            description="Get cookies from a stored session",
            params={
                "session_name": {
                    "type": "string",
                    "default": "default",
                    "description": "Session name to retrieve",
                },
                "format": {
                    "type": "enum",
                    "values": ["header", "dict", "raw"],
                    "default": "header",
                    "description": "Output format (header for Cookie: header, dict for key-value, raw for full cookie data)",
                },
            },
            handler=self.get_cookies,
        )

        self.register_method(
            name="set_cookies",
            description="Manually set cookies for a session",
            params={
                "cookies": {
                    "type": "string",
                    "required": True,
                    "description": "Cookie string (format: 'name1=value1; name2=value2')",
                },
                "session_name": {
                    "type": "string",
                    "default": "default",
                    "description": "Session name to store under",
                },
                "domain": {
                    "type": "string",
                    "description": "Cookie domain",
                },
            },
            handler=self.set_cookies,
        )

        self.register_method(
            name="request",
            description="Make authenticated request using stored session",
            params={
                "url": {
                    "type": "string",
                    "required": True,
                    "description": "URL to request",
                },
                "method": {
                    "type": "enum",
                    "values": ["GET", "POST", "PUT", "DELETE"],
                    "default": "GET",
                    "description": "HTTP method",
                },
                "session_name": {
                    "type": "string",
                    "default": "default",
                    "description": "Session to use",
                },
                "data": {
                    "type": "string",
                    "description": "Request body data",
                },
                "headers": {
                    "type": "object",
                    "description": "Additional HTTP headers",
                },
                "timeout": {
                    "type": "integer",
                    "default": 30,
                    "description": "Request timeout",
                },
            },
            handler=self.request,
        )

        self.register_method(
            name="list_sessions",
            description="List all stored sessions",
            params={},
            handler=self.list_sessions,
        )

        self.register_method(
            name="delete_session",
            description="Delete a stored session",
            params={
                "session_name": {
                    "type": "string",
                    "required": True,
                    "description": "Session name to delete",
                },
            },
            handler=self.delete_session,
        )

        self.register_method(
            name="extract_csrf",
            description="Extract CSRF token from a page",
            params={
                "url": {
                    "type": "string",
                    "required": True,
                    "description": "URL to fetch",
                },
                "session_name": {
                    "type": "string",
                    "default": "default",
                    "description": "Session to use (if any)",
                },
                "token_pattern": {
                    "type": "string",
                    "description": "Regex pattern to extract token (default: common CSRF patterns)",
                },
                "timeout": {
                    "type": "integer",
                    "default": 30,
                    "description": "Request timeout",
                },
            },
            handler=self.extract_csrf,
        )

    def _make_request(
        self,
        url: str,
        method: str = "GET",
        data: Optional[str] = None,
        headers: Optional[Dict[str, str]] = None,
        cookies: Optional[str] = None,
        timeout: int = 30,
    ) -> Dict[str, Any]:
        """Make HTTP request and return response with cookies."""
        ctx = ssl.create_default_context()
        ctx.check_hostname = False
        ctx.verify_mode = ssl.CERT_NONE

        req_headers = {
            "User-Agent": "Mozilla/5.0 (Windows NT 10.0; Win64; x64) AppleWebKit/537.36",
            "Accept": "text/html,application/xhtml+xml,application/xml;q=0.9,*/*;q=0.8",
        }
        if headers:
            req_headers.update(headers)
        if cookies:
            req_headers["Cookie"] = cookies

        req_data = data.encode('utf-8') if data else None
        if req_data and "Content-Type" not in req_headers:
            req_headers["Content-Type"] = "application/x-www-form-urlencoded"

        request = urllib.request.Request(url, data=req_data, headers=req_headers, method=method)

        try:
            response = urllib.request.urlopen(request, timeout=timeout, context=ctx)
            body = response.read().decode('utf-8', errors='replace')
            response_headers = dict(response.headers)

            # Extract Set-Cookie headers
            set_cookies = response.headers.get_all('Set-Cookie') or []

            return {
                "status_code": response.status,
                "headers": response_headers,
                "body": body,
                "url": response.url,
                "set_cookies": set_cookies,
            }

        except urllib.error.HTTPError as e:
            body = e.read().decode('utf-8', errors='replace') if e.fp else ""
            return {
                "status_code": e.code,
                "headers": dict(e.headers),
                "body": body,
                "url": url,
                "set_cookies": e.headers.get_all('Set-Cookie') or [],
                "error": str(e),
            }

    def _parse_cookies(self, set_cookie_headers: List[str]) -> Dict[str, str]:
        """Parse Set-Cookie headers into cookie dict."""
        cookies = {}
        for header in set_cookie_headers:
            # Extract just the cookie name=value part
            parts = header.split(';')
            if parts:
                cookie_part = parts[0].strip()
                if '=' in cookie_part:
                    name, value = cookie_part.split('=', 1)
                    cookies[name.strip()] = value.strip()
        return cookies

    def _cookies_to_header(self, cookies: Dict[str, str]) -> str:
        """Convert cookie dict to Cookie header value."""
        return "; ".join([f"{k}={v}" for k, v in cookies.items()])

    async def login(
        self,
        url: str,
        username: str,
        password: str,
        username_field: str = "username",
        password_field: str = "password",
        extra_fields: Optional[Dict[str, str]] = None,
        session_name: str = "default",
        success_indicator: Optional[str] = None,
        failure_indicator: Optional[str] = None,
        headers: Optional[Dict[str, str]] = None,
        timeout: int = 30,
    ) -> ToolResult:
        """Perform login and capture session."""
        self.logger.info(f"Logging in to {url} as {username}")

        # Build form data
        form_data = {
            username_field: username,
            password_field: password,
        }
        if extra_fields:
            form_data.update(extra_fields)

        encoded_data = urlencode(form_data)

        response = self._make_request(
            url=url,
            method="POST",
            data=encoded_data,
            headers=headers,
            timeout=timeout,
        )

        # Parse cookies
        cookies = self._parse_cookies(response.get("set_cookies", []))

        # Determine success
        body = response.get("body", "")
        success = True
        if failure_indicator and failure_indicator in body:
            success = False
        elif success_indicator and success_indicator not in body:
            success = False
        elif response.get("status_code", 0) >= 400:
            success = False

        # Store session
        if success and cookies:
            SESSIONS[session_name] = {
                "cookies": cookies,
                "username": username,
                "login_url": url,
                "created_at": datetime.now().isoformat(),
                "last_used": datetime.now().isoformat(),
            }

        cookie_header = self._cookies_to_header(cookies) if cookies else ""

        return ToolResult(
            success=success,
            data={
                "session_name": session_name,
                "login_success": success,
                "status_code": response.get("status_code"),
                "cookies": cookies,
                "cookie_header": cookie_header,
                "redirect_url": response.get("url"),
                "response_length": len(body),
            },
            raw_output=f"Login {'successful' if success else 'failed'} - Cookies: {cookie_header}" if success else f"Login failed",
            error=None if success else "Login failed - check credentials or indicators",
        )

    async def get_cookies(
        self,
        session_name: str = "default",
        format: str = "header",
    ) -> ToolResult:
        """Get cookies from stored session."""
        if session_name not in SESSIONS:
            return ToolResult(
                success=False,
                data={"session_name": session_name},
                error=f"Session '{session_name}' not found",
            )

        session = SESSIONS[session_name]
        cookies = session.get("cookies", {})

        if format == "header":
            output = self._cookies_to_header(cookies)
        elif format == "dict":
            output = cookies
        else:  # raw
            output = session

        return ToolResult(
            success=True,
            data={
                "session_name": session_name,
                "cookies": cookies,
                "cookie_header": self._cookies_to_header(cookies),
                "username": session.get("username"),
                "created_at": session.get("created_at"),
            },
            raw_output=self._cookies_to_header(cookies),
        )

    async def set_cookies(
        self,
        cookies: str,
        session_name: str = "default",
        domain: Optional[str] = None,
    ) -> ToolResult:
        """Manually set cookies for a session."""
        # Parse cookie string
        cookie_dict = {}
        for part in cookies.split(';'):
            part = part.strip()
            if '=' in part:
                name, value = part.split('=', 1)
                cookie_dict[name.strip()] = value.strip()

        SESSIONS[session_name] = {
            "cookies": cookie_dict,
            "domain": domain,
            "created_at": datetime.now().isoformat(),
            "last_used": datetime.now().isoformat(),
            "manual": True,
        }

        return ToolResult(
            success=True,
            data={
                "session_name": session_name,
                "cookies": cookie_dict,
                "cookie_header": self._cookies_to_header(cookie_dict),
            },
            raw_output=f"Set {len(cookie_dict)} cookies for session '{session_name}'",
        )

    async def request(
        self,
        url: str,
        method: str = "GET",
        session_name: str = "default",
        data: Optional[str] = None,
        headers: Optional[Dict[str, str]] = None,
        timeout: int = 30,
    ) -> ToolResult:
        """Make authenticated request using session."""
        cookies = None
        if session_name in SESSIONS:
            session = SESSIONS[session_name]
            cookies = self._cookies_to_header(session.get("cookies", {}))
            session["last_used"] = datetime.now().isoformat()

        response = self._make_request(
            url=url,
            method=method,
            data=data,
            headers=headers,
            cookies=cookies,
            timeout=timeout,
        )

        # Update session with any new cookies
        new_cookies = self._parse_cookies(response.get("set_cookies", []))
        if new_cookies and session_name in SESSIONS:
            SESSIONS[session_name]["cookies"].update(new_cookies)

        body = response.get("body", "")

        return ToolResult(
            success=response.get("status_code", 0) < 400,
            data={
                "url": url,
                "method": method,
                "session_name": session_name,
                "status_code": response.get("status_code"),
                "headers": response.get("headers", {}),
                "body": body[:50000] if len(body) > 50000 else body,
                "body_length": len(body),
                "new_cookies": new_cookies,
            },
            raw_output=body[:5000],
        )

    async def list_sessions(self) -> ToolResult:
        """List all stored sessions."""
        sessions = []
        for name, session in SESSIONS.items():
            sessions.append({
                "name": name,
                "username": session.get("username"),
                "cookie_count": len(session.get("cookies", {})),
                "created_at": session.get("created_at"),
                "last_used": session.get("last_used"),
            })

        return ToolResult(
            success=True,
            data={
                "sessions": sessions,
                "count": len(sessions),
            },
            raw_output=f"Found {len(sessions)} sessions",
        )

    async def delete_session(self, session_name: str) -> ToolResult:
        """Delete a stored session."""
        if session_name in SESSIONS:
            del SESSIONS[session_name]
            return ToolResult(
                success=True,
                data={"session_name": session_name, "deleted": True},
                raw_output=f"Deleted session '{session_name}'",
            )
        return ToolResult(
            success=False,
            data={"session_name": session_name},
            error=f"Session '{session_name}' not found",
        )

    async def extract_csrf(
        self,
        url: str,
        session_name: str = "default",
        token_pattern: Optional[str] = None,
        timeout: int = 30,
    ) -> ToolResult:
        """Extract CSRF token from a page."""
        cookies = None
        if session_name in SESSIONS:
            cookies = self._cookies_to_header(SESSIONS[session_name].get("cookies", {}))

        response = self._make_request(url=url, cookies=cookies, timeout=timeout)
        body = response.get("body", "")

        # Common CSRF token patterns
        patterns = [
            token_pattern,
            r'name=["\']csrf[_-]?token["\'][^>]*value=["\']([^"\']+)["\']',
            r'name=["\']_token["\'][^>]*value=["\']([^"\']+)["\']',
            r'name=["\']csrfmiddlewaretoken["\'][^>]*value=["\']([^"\']+)["\']',
            r'<meta\s+name=["\']csrf-token["\'][^>]*content=["\']([^"\']+)["\']',
            r'"csrf[_-]?token"\s*:\s*["\']([^"\']+)["\']',
            r'value=["\']([^"\']+)["\'][^>]*name=["\']csrf[_-]?token["\']',
        ]

        tokens_found = []
        for pattern in patterns:
            if pattern:
                matches = re.findall(pattern, body, re.IGNORECASE)
                tokens_found.extend(matches)

        # Deduplicate
        tokens_found = list(set(tokens_found))

        return ToolResult(
            success=len(tokens_found) > 0,
            data={
                "url": url,
                "tokens": tokens_found,
                "token": tokens_found[0] if tokens_found else None,
                "status_code": response.get("status_code"),
            },
            raw_output=f"Found {len(tokens_found)} CSRF tokens" if tokens_found else "No CSRF tokens found",
            error=None if tokens_found else "No CSRF tokens found in page",
        )


if __name__ == "__main__":
    WebSessionServer.main()
