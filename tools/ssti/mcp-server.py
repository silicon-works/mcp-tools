#!/usr/bin/env python3
"""
OpenSploit MCP Server: ssti

Server-Side Template Injection detection and exploitation via SSTImap.
Supports 15+ template engines across Python, PHP, Java, JavaScript, Ruby.
"""

import asyncio
import json
import os
import re
from typing import Any, Dict, List, Optional

from mcp_common import BaseMCPServer, ToolResult, ToolError, sanitize_output

SSTIMAP_PATH = "/opt/sstimap/sstimap.py"


class SstiServer(BaseMCPServer):
    """MCP server wrapping SSTImap for SSTI detection and exploitation."""

    def __init__(self):
        super().__init__(
            name="ssti",
            description="Server-Side Template Injection detection and exploitation via SSTImap",
            version="1.0.0",
        )

        self.register_method(
            name="detect",
            description="Test a URL/parameter for Server-Side Template Injection and identify the template engine",
            params={
                "url": {
                    "type": "string",
                    "required": True,
                    "description": "Target URL with injection point marked by * (e.g., 'http://target/page?name=*') or without marker to test all parameters",
                },
                "method": {
                    "type": "string",
                    "enum": ["GET", "POST"],
                    "default": "GET",
                    "description": "HTTP method",
                },
                "data": {
                    "type": "string",
                    "description": "POST data (e.g., 'name=*&submit=1'). Use * to mark injection point.",
                },
                "headers": {
                    "type": "object",
                    "description": "Custom HTTP headers as key-value pairs",
                },
                "cookies": {
                    "type": "string",
                    "description": "Cookie header value",
                },
                "level": {
                    "type": "integer",
                    "default": 1,
                    "description": "Escaping level (1-5). Higher levels try more complex escaping to bypass filters.",
                },
                "engine": {
                    "type": "string",
                    "description": "Comma-separated engines to test (e.g., 'jinja2,twig'). Default: test all.",
                },
                "technique": {
                    "type": "string",
                    "default": "RE",
                    "description": "Detection techniques: R(endered) E(rror-based) B(oolean-blind) T(ime-blind). Default: RE",
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
            handler=self.detect,
        )

        self.register_method(
            name="exploit",
            description="Exploit a confirmed SSTI vulnerability to execute OS commands",
            params={
                "url": {
                    "type": "string",
                    "required": True,
                    "description": "Target URL with injection point marked by * (e.g., 'http://target/page?name=*')",
                },
                "command": {
                    "type": "string",
                    "required": True,
                    "description": "OS command to execute on the target (e.g., 'id', 'cat /etc/passwd', 'whoami')",
                },
                "method": {
                    "type": "string",
                    "enum": ["GET", "POST"],
                    "default": "GET",
                    "description": "HTTP method",
                },
                "data": {
                    "type": "string",
                    "description": "POST data with * marking injection point",
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
                    "description": "Escaping level (1-5)",
                },
                "engine": {
                    "type": "string",
                    "description": "Force specific engine (e.g., 'jinja2', 'twig'). Skips detection.",
                },
                "proxy": {
                    "type": "string",
                    "description": "HTTP proxy",
                },
                "timeout": {
                    "type": "integer",
                    "default": 60,
                    "description": "Overall timeout in seconds",
                },
            },
            handler=self.exploit,
        )

        self.register_method(
            name="list_engines",
            description="List all supported template engines",
            params={},
            handler=self.list_engines,
        )

    def _build_sstimap_cmd(
        self,
        url: str,
        method: str = "GET",
        data: str = None,
        headers: dict = None,
        cookies: str = None,
        level: int = 1,
        engine: str = None,
        technique: str = None,
        proxy: str = None,
    ) -> List[str]:
        """Build base SSTImap command."""
        cmd = ["python3", SSTIMAP_PATH, "-u", url]

        if method == "POST":
            cmd.extend(["-M", "POST"])
        if data:
            cmd.extend(["-d", data])
        if headers:
            for k, v in headers.items():
                cmd.extend(["-H", f"{k}: {v}"])
        if cookies:
            cmd.extend(["-H", f"Cookie: {cookies}"])
        if level and level > 1:
            cmd.extend(["-l", str(level)])
        if engine:
            cmd.extend(["-e", engine])
        if technique:
            cmd.extend(["-r", technique])
        if proxy:
            cmd.extend(["--proxy", proxy])

        return cmd

    def _parse_detection_output(self, output: str) -> Dict[str, Any]:
        """Parse SSTImap detection output."""
        result = {
            "vulnerable": False,
            "engine": None,
            "language": None,
            "os_shell": False,
            "eval_shell": False,
            "tpl_shell": False,
            "technique": None,
        }

        for line in output.split("\n"):
            line_lower = line.lower().strip()

            # Detect confirmed injection
            if "confirmed injection" in line_lower or "identified" in line_lower:
                result["vulnerable"] = True

            # Extract engine name
            engine_match = re.search(r"engine:\s*(.+?)(?:\s*$|\s*\|)", line, re.IGNORECASE)
            if engine_match:
                result["engine"] = engine_match.group(1).strip()

            # Check for Jinja2, Twig, Mako etc. in output
            for eng in ["Jinja2", "Twig", "Mako", "Smarty", "Freemarker", "Velocity",
                        "Jade", "Pug", "Tornado", "Django", "ERB", "Slim", "Nunjucks",
                        "Pebble", "Dust", "EJS", "Handlebars", "Marko"]:
                if eng.lower() in line_lower and ("injected" in line_lower or "confirmed" in line_lower or "detected" in line_lower):
                    result["engine"] = eng
                    result["vulnerable"] = True

            # Check capabilities
            if "os command execution" in line_lower or "os_shell" in line_lower:
                result["os_shell"] = True
            if "code evaluation" in line_lower or "eval_shell" in line_lower:
                result["eval_shell"] = True
            if "template" in line_lower and "shell" in line_lower:
                result["tpl_shell"] = True

            # Technique
            if "rendered" in line_lower:
                result["technique"] = "rendered"
            elif "error" in line_lower and "based" in line_lower:
                result["technique"] = "error-based"
            elif "blind" in line_lower and "time" in line_lower:
                result["technique"] = "time-blind"
            elif "blind" in line_lower and "boolean" in line_lower:
                result["technique"] = "boolean-blind"

        return result

    async def detect(
        self,
        url: str,
        method: str = "GET",
        data: str = None,
        headers: dict = None,
        cookies: str = None,
        level: int = 1,
        engine: str = None,
        technique: str = "RE",
        proxy: str = None,
        timeout: int = 60,
    ) -> ToolResult:
        """Test a URL/parameter for SSTI."""
        self.logger.info(f"SSTI detect: {url} method={method} level={level}")

        cmd = self._build_sstimap_cmd(
            url, method, data, headers, cookies, level, engine, technique, proxy,
        )
        # Detection only — no exploitation flags
        cmd.append("--no-color")

        try:
            result = await self.run_command(cmd, timeout=timeout + 30)
            stdout = result.stdout.strip() if result.stdout else ""
            stderr = result.stderr.strip() if result.stderr else ""
            combined = f"{stdout}\n{stderr}".strip()

            parsed = self._parse_detection_output(combined)

            return ToolResult(
                success=True,
                data={
                    "url": url,
                    "method": method,
                    "vulnerable": parsed["vulnerable"],
                    "engine": parsed["engine"],
                    "os_shell_available": parsed["os_shell"],
                    "eval_shell_available": parsed["eval_shell"],
                    "technique": parsed["technique"],
                },
                raw_output=sanitize_output(combined, max_length=10000),
            )

        except Exception as e:
            return ToolResult(
                success=False,
                data={},
                error=f"SSTI detection failed: {e}",
            )

    async def exploit(
        self,
        url: str,
        command: str,
        method: str = "GET",
        data: str = None,
        headers: dict = None,
        cookies: str = None,
        level: int = 1,
        engine: str = None,
        proxy: str = None,
        timeout: int = 60,
    ) -> ToolResult:
        """Exploit SSTI to execute an OS command."""
        self.logger.info(f"SSTI exploit: {url} command={command}")

        cmd = self._build_sstimap_cmd(
            url, method, data, headers, cookies, level, engine, None, proxy,
        )
        cmd.extend(["-S", command])
        cmd.append("--no-color")

        try:
            result = await self.run_command(cmd, timeout=timeout + 30)
            stdout = result.stdout.strip() if result.stdout else ""
            stderr = result.stderr.strip() if result.stderr else ""
            combined = f"{stdout}\n{stderr}".strip()

            # Extract command output — SSTImap prints the command result after detection
            # Look for the command output in the response
            command_output = ""
            capture = False
            for line in combined.split("\n"):
                # SSTImap outputs command results after "[+]" lines
                if command in line or capture:
                    # Skip SSTImap status lines
                    if not line.startswith("[") and not line.startswith("    ") and line.strip():
                        command_output += line + "\n"
                        capture = True
                    elif capture and line.strip() and not line.startswith("["):
                        command_output += line + "\n"

            parsed = self._parse_detection_output(combined)

            return ToolResult(
                success=parsed["vulnerable"],
                data={
                    "url": url,
                    "command": command,
                    "output": command_output.strip(),
                    "engine": parsed["engine"],
                    "vulnerable": parsed["vulnerable"],
                },
                raw_output=sanitize_output(combined, max_length=10000),
                error=None if parsed["vulnerable"] else "SSTI not confirmed — command may not have executed",
            )

        except Exception as e:
            return ToolResult(
                success=False,
                data={},
                error=f"SSTI exploitation failed: {e}",
            )

    async def list_engines(self) -> ToolResult:
        """List all supported template engines."""
        engines = {
            "Python": ["Jinja2", "Mako", "Tornado", "Django", "Cheetah3"],
            "PHP": ["Twig", "Smarty", "Latte"],
            "Java": ["Freemarker", "Velocity", "Pebble", "Thymeleaf"],
            "JavaScript": ["Nunjucks", "Pug/Jade", "Dust.js", "EJS", "Handlebars", "Marko", "doT"],
            "Ruby": ["ERB", "Slim", "Haml"],
            "Go": ["Go text/template"],
            "Rust": ["Tera"],
        }

        flat_list = []
        for lang, engs in engines.items():
            for eng in engs:
                flat_list.append({"engine": eng, "language": lang})

        return ToolResult(
            success=True,
            data={
                "engines_by_language": engines,
                "engines": flat_list,
                "total": len(flat_list),
            },
            raw_output="\n".join(
                f"{lang}: {', '.join(engs)}" for lang, engs in engines.items()
            ),
        )


if __name__ == "__main__":
    SstiServer.main()
