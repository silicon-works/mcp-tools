#!/usr/bin/env python3
"""
OpenSploit MCP Server: web-fingerprint

Web technology fingerprinting for identifying CMS, frameworks, servers, and more.
"""

import asyncio
import re
import ssl
import urllib.request
import urllib.error
from typing import Any, Dict, List, Optional
from urllib.parse import urlparse

from mcp_common import BaseMCPServer, ToolResult


# Technology signatures for fingerprinting
TECH_SIGNATURES = {
    # CMS
    "WordPress": {
        "headers": {"X-Powered-By": r"PHP"},
        "body": [r"/wp-content/", r"/wp-includes/", r"wp-json", r"wordpress"],
        "meta": {"generator": r"WordPress"},
    },
    "Joomla": {
        "body": [r"/media/jui/", r"/components/com_"],
        "meta": {"generator": r"Joomla"},
    },
    "Drupal": {
        "headers": {"X-Generator": r"Drupal"},
        "body": [r"/sites/default/files/", r"Drupal.settings"],
        "meta": {"generator": r"Drupal"},
    },
    "XWiki": {
        "body": [r"/xwiki/", r"XWiki", r"xwiki-platform"],
        "meta": {"generator": r"XWiki"},
    },
    # Frameworks
    "Laravel": {
        "cookies": {"laravel_session": r".*"},
        "headers": {"Set-Cookie": r"laravel_session"},
    },
    "Django": {
        "cookies": {"csrftoken": r".*"},
        "headers": {"Set-Cookie": r"csrftoken"},
        "body": [r"csrfmiddlewaretoken"],
    },
    "Rails": {
        "headers": {"X-Powered-By": r"Phusion Passenger"},
        "cookies": {"_session_id": r".*"},
    },
    "ASP.NET": {
        "headers": {"X-Powered-By": r"ASP\.NET", "X-AspNet-Version": r".*"},
        "body": [r"__VIEWSTATE", r"__EVENTVALIDATION"],
    },
    "Spring": {
        "headers": {"X-Application-Context": r".*"},
        "body": [r"org\.springframework"],
    },
    "Express": {
        "headers": {"X-Powered-By": r"Express"},
    },
    # Web servers
    "Apache": {
        "headers": {"Server": r"Apache"},
    },
    "Nginx": {
        "headers": {"Server": r"nginx"},
    },
    "IIS": {
        "headers": {"Server": r"Microsoft-IIS"},
    },
    "Tomcat": {
        "headers": {"Server": r"Apache-Coyote"},
        "body": [r"Apache Tomcat"],
    },
    "Jetty": {
        "headers": {"Server": r"Jetty"},
    },
    # JavaScript frameworks
    "React": {
        "body": [r"react\.production\.min\.js", r"_reactRootContainer", r"data-reactroot"],
    },
    "Vue.js": {
        "body": [r"vue\.min\.js", r"vue\.runtime", r"data-v-[a-f0-9]+"],
    },
    "Angular": {
        "body": [r"ng-app", r"ng-controller", r"angular\.min\.js", r"ng-version"],
    },
    "jQuery": {
        "body": [r"jquery.*\.min\.js", r"jquery.*\.js"],
    },
    # Databases (exposed)
    "phpMyAdmin": {
        "body": [r"phpMyAdmin", r"pma_password"],
    },
    "Adminer": {
        "body": [r"adminer\.css", r"Adminer"],
    },
    # Security
    "CloudFlare": {
        "headers": {"Server": r"cloudflare", "CF-RAY": r".*"},
    },
    "AWS ELB": {
        "headers": {"Server": r"awselb"},
    },
    "Varnish": {
        "headers": {"Via": r"varnish", "X-Varnish": r".*"},
    },
    # Other
    "GitLab": {
        "body": [r"gitlab-ce", r"gitlab-ee", r"/users/sign_in"],
        "headers": {"X-Gitlab-Feature-Category": r".*"},
    },
    "Jenkins": {
        "headers": {"X-Jenkins": r".*"},
        "body": [r"Jenkins", r"/jenkins/"],
    },
    "Grafana": {
        "body": [r"grafana-app", r"Grafana"],
    },
    "Kibana": {
        "body": [r"kibana", r"kbn-"],
    },
}


class WebFingerprintServer(BaseMCPServer):
    """MCP server for web technology fingerprinting."""

    def __init__(self):
        super().__init__(
            name="web-fingerprint",
            description="Web technology fingerprinting and identification",
            version="1.0.0",
        )

        self.register_method(
            name="fingerprint",
            description="Fingerprint web technologies on a target URL",
            params={
                "url": {
                    "type": "string",
                    "required": True,
                    "description": "Target URL to fingerprint",
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
                "user_agent": {
                    "type": "string",
                    "description": "Custom User-Agent header",
                },
            },
            handler=self.fingerprint,
        )

        self.register_method(
            name="headers",
            description="Extract and analyze HTTP headers",
            params={
                "url": {
                    "type": "string",
                    "required": True,
                    "description": "Target URL",
                },
                "timeout": {
                    "type": "integer",
                    "default": 30,
                    "description": "Request timeout in seconds",
                },
            },
            handler=self.get_headers,
        )

        self.register_method(
            name="security_headers",
            description="Check for security headers and misconfigurations",
            params={
                "url": {
                    "type": "string",
                    "required": True,
                    "description": "Target URL",
                },
                "timeout": {
                    "type": "integer",
                    "default": 30,
                    "description": "Request timeout in seconds",
                },
            },
            handler=self.check_security_headers,
        )

        self.register_method(
            name="favicon_hash",
            description="Calculate favicon hash for Shodan lookup",
            params={
                "url": {
                    "type": "string",
                    "required": True,
                    "description": "Target URL (will append /favicon.ico)",
                },
                "timeout": {
                    "type": "integer",
                    "default": 30,
                    "description": "Request timeout in seconds",
                },
            },
            handler=self.favicon_hash,
        )

    def _fetch_url(
        self,
        url: str,
        timeout: int = 30,
        user_agent: str = None,
        follow_redirects: bool = True,
    ) -> tuple:
        """Fetch URL and return (status_code, headers, body)."""
        if not user_agent:
            user_agent = "Mozilla/5.0 (Windows NT 10.0; Win64; x64) AppleWebKit/537.36"

        # Create SSL context that doesn't verify
        ctx = ssl.create_default_context()
        ctx.check_hostname = False
        ctx.verify_mode = ssl.CERT_NONE

        request = urllib.request.Request(
            url,
            headers={"User-Agent": user_agent},
        )

        try:
            # Handle redirects
            if not follow_redirects:
                class NoRedirect(urllib.request.HTTPRedirectHandler):
                    def redirect_request(self, req, fp, code, msg, headers, newurl):
                        return None
                opener = urllib.request.build_opener(NoRedirect, urllib.request.HTTPSHandler(context=ctx))
            else:
                opener = urllib.request.build_opener(urllib.request.HTTPSHandler(context=ctx))

            response = opener.open(request, timeout=timeout)
            status = response.getcode()
            headers = dict(response.headers)
            body = response.read().decode("utf-8", errors="ignore")
            return status, headers, body, None

        except urllib.error.HTTPError as e:
            return e.code, dict(e.headers), "", str(e)
        except urllib.error.URLError as e:
            return 0, {}, "", str(e)
        except Exception as e:
            return 0, {}, "", str(e)

    def _match_technologies(
        self, headers: Dict[str, str], body: str, cookies: Dict[str, str]
    ) -> List[Dict[str, Any]]:
        """Match technologies based on signatures."""
        detected = []

        for tech_name, signatures in TECH_SIGNATURES.items():
            confidence = 0
            matches = []

            # Check headers
            if "headers" in signatures:
                for header_name, pattern in signatures["headers"].items():
                    for h_name, h_value in headers.items():
                        if h_name.lower() == header_name.lower():
                            if re.search(pattern, h_value, re.IGNORECASE):
                                confidence += 30
                                matches.append(f"Header: {header_name}")
                                # Extract version if possible
                                version_match = re.search(r"[\d.]+", h_value)
                                if version_match:
                                    matches.append(f"Version: {version_match.group()}")

            # Check body patterns
            if "body" in signatures:
                for pattern in signatures["body"]:
                    if re.search(pattern, body, re.IGNORECASE):
                        confidence += 20
                        matches.append(f"Body: {pattern}")

            # Check meta tags
            if "meta" in signatures:
                for meta_name, pattern in signatures["meta"].items():
                    meta_pattern = rf'<meta[^>]*name=["\']?{meta_name}["\']?[^>]*content=["\']([^"\']+)["\']'
                    meta_match = re.search(meta_pattern, body, re.IGNORECASE)
                    if meta_match:
                        if re.search(pattern, meta_match.group(1), re.IGNORECASE):
                            confidence += 40
                            matches.append(f"Meta: {meta_name}={meta_match.group(1)}")

            # Check cookies
            if "cookies" in signatures:
                for cookie_name, pattern in signatures["cookies"].items():
                    if cookie_name.lower() in [c.lower() for c in cookies.keys()]:
                        confidence += 25
                        matches.append(f"Cookie: {cookie_name}")

            if confidence > 0:
                detected.append({
                    "technology": tech_name,
                    "confidence": min(confidence, 100),
                    "matches": matches,
                })

        # Sort by confidence
        detected.sort(key=lambda x: x["confidence"], reverse=True)
        return detected

    def _parse_cookies(self, headers: Dict[str, str]) -> Dict[str, str]:
        """Parse Set-Cookie headers into a dict."""
        cookies = {}
        for header_name, header_value in headers.items():
            if header_name.lower() == "set-cookie":
                # Handle multiple cookies
                for cookie in header_value.split(","):
                    if "=" in cookie:
                        name = cookie.split("=")[0].strip()
                        cookies[name] = cookie
        return cookies

    async def fingerprint(
        self,
        url: str,
        follow_redirects: bool = True,
        timeout: int = 30,
        user_agent: str = None,
    ) -> ToolResult:
        """Fingerprint web technologies on a target."""
        self.logger.info(f"Fingerprinting: {url}")

        # Ensure URL has scheme
        if not url.startswith(("http://", "https://")):
            url = f"http://{url}"

        status, headers, body, error = self._fetch_url(
            url, timeout=timeout, user_agent=user_agent, follow_redirects=follow_redirects
        )

        if error and status == 0:
            return ToolResult(
                success=False,
                data={},
                error=f"Failed to fetch URL: {error}",
            )

        cookies = self._parse_cookies(headers)
        technologies = self._match_technologies(headers, body, cookies)

        # Extract page title
        title_match = re.search(r"<title[^>]*>([^<]+)</title>", body, re.IGNORECASE)
        title = title_match.group(1).strip() if title_match else None

        # Extract server info
        server = headers.get("Server", headers.get("server", "Unknown"))

        # Check for interesting paths in body
        paths = []
        path_patterns = [
            r'href=["\']([^"\']+)["\']',
            r'src=["\']([^"\']+)["\']',
            r'action=["\']([^"\']+)["\']',
        ]
        for pattern in path_patterns:
            for match in re.finditer(pattern, body[:50000]):  # Limit search
                path = match.group(1)
                if path.startswith("/") and len(path) < 100:
                    if path not in paths:
                        paths.append(path)

        return ToolResult(
            success=True,
            data={
                "url": url,
                "status_code": status,
                "title": title,
                "server": server,
                "technologies": technologies,
                "interesting_paths": paths[:50],  # Limit to 50 paths
                "cookies": list(cookies.keys()),
            },
            raw_output=f"Detected {len(technologies)} technologies on {url}",
        )

    async def get_headers(self, url: str, timeout: int = 30) -> ToolResult:
        """Get and analyze HTTP headers."""
        if not url.startswith(("http://", "https://")):
            url = f"http://{url}"

        status, headers, _, error = self._fetch_url(url, timeout=timeout)

        if error and status == 0:
            return ToolResult(success=False, data={}, error=f"Failed to fetch: {error}")

        # Categorize headers
        security_headers = {}
        server_headers = {}
        cache_headers = {}
        other_headers = {}

        security_header_names = [
            "content-security-policy", "x-content-type-options", "x-frame-options",
            "x-xss-protection", "strict-transport-security", "referrer-policy",
            "permissions-policy", "cross-origin-opener-policy", "cross-origin-embedder-policy",
        ]
        server_header_names = ["server", "x-powered-by", "x-aspnet-version", "x-generator"]
        cache_header_names = ["cache-control", "expires", "pragma", "etag", "last-modified"]

        for name, value in headers.items():
            lower_name = name.lower()
            if lower_name in security_header_names:
                security_headers[name] = value
            elif lower_name in server_header_names:
                server_headers[name] = value
            elif lower_name in cache_header_names:
                cache_headers[name] = value
            else:
                other_headers[name] = value

        return ToolResult(
            success=True,
            data={
                "url": url,
                "status_code": status,
                "security_headers": security_headers,
                "server_headers": server_headers,
                "cache_headers": cache_headers,
                "other_headers": other_headers,
            },
            raw_output=f"Retrieved {len(headers)} headers from {url}",
        )

    async def check_security_headers(self, url: str, timeout: int = 30) -> ToolResult:
        """Check for security headers and misconfigurations."""
        if not url.startswith(("http://", "https://")):
            url = f"http://{url}"

        status, headers, _, error = self._fetch_url(url, timeout=timeout)

        if error and status == 0:
            return ToolResult(success=False, data={}, error=f"Failed to fetch: {error}")

        # Expected security headers
        expected = {
            "Strict-Transport-Security": {
                "description": "HSTS - Forces HTTPS connections",
                "severity": "medium",
            },
            "Content-Security-Policy": {
                "description": "CSP - Prevents XSS and injection attacks",
                "severity": "medium",
            },
            "X-Content-Type-Options": {
                "description": "Prevents MIME type sniffing",
                "severity": "low",
            },
            "X-Frame-Options": {
                "description": "Prevents clickjacking attacks",
                "severity": "medium",
            },
            "X-XSS-Protection": {
                "description": "Legacy XSS filter (deprecated but still useful)",
                "severity": "info",
            },
            "Referrer-Policy": {
                "description": "Controls referrer information leakage",
                "severity": "low",
            },
            "Permissions-Policy": {
                "description": "Controls browser features and APIs",
                "severity": "low",
            },
        }

        missing = []
        present = []
        issues = []

        headers_lower = {k.lower(): v for k, v in headers.items()}

        for header, info in expected.items():
            if header.lower() in headers_lower:
                present.append({
                    "header": header,
                    "value": headers_lower[header.lower()],
                    "description": info["description"],
                })

                # Check for weak values
                value = headers_lower[header.lower()].lower()
                if header.lower() == "x-frame-options" and value not in ["deny", "sameorigin"]:
                    issues.append({
                        "header": header,
                        "issue": f"Weak value: {value}",
                        "severity": "medium",
                    })
                if header.lower() == "strict-transport-security":
                    if "max-age" in value:
                        max_age = re.search(r"max-age=(\d+)", value)
                        if max_age and int(max_age.group(1)) < 31536000:  # Less than 1 year
                            issues.append({
                                "header": header,
                                "issue": f"Short max-age: {max_age.group(1)} seconds",
                                "severity": "low",
                            })
            else:
                missing.append({
                    "header": header,
                    "description": info["description"],
                    "severity": info["severity"],
                })

        # Check for information disclosure headers
        disclosure_headers = ["Server", "X-Powered-By", "X-AspNet-Version", "X-Generator"]
        for dh in disclosure_headers:
            if dh.lower() in headers_lower:
                issues.append({
                    "header": dh,
                    "value": headers_lower[dh.lower()],
                    "issue": "Information disclosure - reveals technology/version",
                    "severity": "info",
                })

        return ToolResult(
            success=True,
            data={
                "url": url,
                "missing_headers": missing,
                "present_headers": present,
                "issues": issues,
                "score": f"{len(present)}/{len(expected)}",
            },
            raw_output=f"Security headers: {len(present)}/{len(expected)} present, {len(issues)} issues found",
        )

    async def favicon_hash(self, url: str, timeout: int = 30) -> ToolResult:
        """Calculate favicon hash for Shodan lookup."""
        import base64
        import hashlib

        parsed = urlparse(url if url.startswith("http") else f"http://{url}")
        favicon_url = f"{parsed.scheme}://{parsed.netloc}/favicon.ico"

        ctx = ssl.create_default_context()
        ctx.check_hostname = False
        ctx.verify_mode = ssl.CERT_NONE

        try:
            request = urllib.request.Request(
                favicon_url,
                headers={"User-Agent": "Mozilla/5.0"},
            )
            opener = urllib.request.build_opener(urllib.request.HTTPSHandler(context=ctx))
            response = opener.open(request, timeout=timeout)
            favicon_data = response.read()

            # Calculate MurmurHash3 (Shodan uses this)
            # Since we don't have mmh3, use a base64+md5 approach for identification
            b64_favicon = base64.b64encode(favicon_data).decode()

            # Shodan favicon hash calculation (simplified)
            # Real implementation would use mmh3.hash(base64.encodebytes(favicon_data))
            md5_hash = hashlib.md5(favicon_data).hexdigest()

            return ToolResult(
                success=True,
                data={
                    "favicon_url": favicon_url,
                    "size_bytes": len(favicon_data),
                    "md5": md5_hash,
                    "shodan_query": f'http.favicon.hash:"{md5_hash}"',
                    "note": "For accurate Shodan lookup, use mmh3 hash",
                },
                raw_output=f"Favicon MD5: {md5_hash}",
            )

        except urllib.error.HTTPError as e:
            return ToolResult(
                success=False,
                data={},
                error=f"Favicon not found: {e.code}",
            )
        except Exception as e:
            return ToolResult(
                success=False,
                data={},
                error=str(e),
            )


if __name__ == "__main__":
    WebFingerprintServer.main()
