#!/usr/bin/env python3
"""
OpenSploit MCP Server: ffuf

Fast web fuzzer for directory discovery, parameter fuzzing, and vhost enumeration.
Provides MCP interface to ffuf functionality for the OpenSploit agent.
"""

import asyncio
import json
import os
import tempfile
from typing import Any, Dict, List, Optional

from mcp_common import BaseMCPServer, ToolResult, ToolError, sanitize_output


class FfufServer(BaseMCPServer):
    """MCP server wrapping ffuf web fuzzer."""

    # Default wordlists available in Kali
    WORDLISTS = {
        "common": "/usr/share/dirb/wordlists/common.txt",
        "big": "/usr/share/dirb/wordlists/big.txt",
        "small": "/usr/share/dirb/wordlists/small.txt",
        "dirbuster-small": "/usr/share/seclists/Discovery/Web-Content/directory-list-2.3-small.txt",
        "dirbuster-medium": "/usr/share/seclists/Discovery/Web-Content/directory-list-2.3-medium.txt",
        "raft-small": "/usr/share/seclists/Discovery/Web-Content/raft-small-words.txt",
        "raft-medium": "/usr/share/seclists/Discovery/Web-Content/raft-medium-words.txt",
    }

    def __init__(self):
        super().__init__(
            name="ffuf",
            description="Fast web fuzzer for directory discovery, parameter fuzzing, and vhost enumeration",
            version="1.0.0",
        )

        # Register methods
        self.register_method(
            name="dir_fuzz",
            description="Fuzz directories and files on a web server",
            params={
                "url": {
                    "type": "string",
                    "required": True,
                    "description": "Target URL with FUZZ keyword (e.g., http://target.com/FUZZ)",
                },
                "wordlist": {
                    "type": "string",
                    "default": "common",
                    "description": "Wordlist name (common, big, dirbuster-small, dirbuster-medium) or path",
                },
                "extensions": {
                    "type": "string",
                    "description": "File extensions to append (e.g., 'php,html,txt')",
                },
                "threads": {
                    "type": "integer",
                    "default": 40,
                    "description": "Number of concurrent threads",
                },
                "filter_status": {
                    "type": "string",
                    "description": "Match these status codes (e.g., '200,301,302')",
                },
                "filter_size": {
                    "type": "string",
                    "description": "Filter out responses of this size",
                },
                "timeout": {
                    "type": "integer",
                    "default": 10,
                    "description": "HTTP request timeout in seconds",
                },
                "headers": {
                    "type": "object",
                    "description": "Custom HTTP headers as key-value pairs (e.g., {\"Host\": \"target.htb\"})",
                },
                "cookies": {
                    "type": "string",
                    "description": "Cookie header value for authenticated fuzzing",
                },
            },
            handler=self.dir_fuzz,
        )

        self.register_method(
            name="param_fuzz",
            description="Fuzz GET or POST parameters",
            params={
                "url": {
                    "type": "string",
                    "required": True,
                    "description": "Target URL with FUZZ keyword in parameter (e.g., http://target.com/page?id=FUZZ)",
                },
                "wordlist": {
                    "type": "string",
                    "default": "common",
                    "description": "Wordlist name or path",
                },
                "method": {
                    "type": "string",
                    "enum": ["GET", "POST"],
                    "default": "GET",
                    "description": "HTTP method",
                },
                "data": {
                    "type": "string",
                    "description": "POST data with FUZZ keyword (e.g., 'username=admin&password=FUZZ')",
                },
                "threads": {
                    "type": "integer",
                    "default": 40,
                    "description": "Number of concurrent threads",
                },
                "filter_status": {
                    "type": "string",
                    "description": "Match these status codes",
                },
                "filter_size": {
                    "type": "string",
                    "description": "Filter out responses of this size",
                },
                "headers": {
                    "type": "object",
                    "description": "Custom HTTP headers as key-value pairs",
                },
                "cookies": {
                    "type": "string",
                    "description": "Cookie header value for authenticated fuzzing",
                },
            },
            handler=self.param_fuzz,
        )

        self.register_method(
            name="vhost_fuzz",
            description="Fuzz virtual hosts on a web server",
            params={
                "url": {
                    "type": "string",
                    "required": True,
                    "description": "Target URL (e.g., http://10.10.10.1)",
                },
                "domain": {
                    "type": "string",
                    "required": True,
                    "description": "Base domain for vhost fuzzing (e.g., target.htb)",
                },
                "wordlist": {
                    "type": "string",
                    "default": "common",
                    "description": "Wordlist name or path for subdomain prefixes",
                },
                "threads": {
                    "type": "integer",
                    "default": 40,
                    "description": "Number of concurrent threads",
                },
                "filter_size": {
                    "type": "string",
                    "description": "Filter out responses of this size (use to filter default vhost)",
                },
            },
            handler=self.vhost_fuzz,
        )

    def _resolve_wordlist(self, wordlist: str) -> str:
        """Resolve wordlist name to path."""
        if wordlist in self.WORDLISTS:
            path = self.WORDLISTS[wordlist]
            if os.path.exists(path):
                return path
            # Fallback to common if specified list doesn't exist
            self.logger.warning(f"Wordlist {path} not found, using common")
            return self.WORDLISTS["common"]
        # Assume it's a path
        return wordlist

    def _parse_ffuf_json(self, json_output: str) -> Dict[str, Any]:
        """Parse ffuf JSON output."""
        try:
            data = json.loads(json_output)
            results = []

            for result in data.get("results", []):
                results.append({
                    "input": result.get("input", {}).get("FUZZ", ""),
                    "url": result.get("url", ""),
                    "status": result.get("status", 0),
                    "length": result.get("length", 0),
                    "words": result.get("words", 0),
                    "lines": result.get("lines", 0),
                    "content_type": result.get("content-type", ""),
                    "redirect_location": result.get("redirectlocation", ""),
                })

            return {
                "command": data.get("commandline", ""),
                "time": data.get("time", ""),
                "results": results,
                "total_results": len(results),
            }
        except json.JSONDecodeError:
            return {"error": "Failed to parse ffuf output", "raw": json_output[:500]}

    async def _run_ffuf(
        self,
        args: List[str],
        timeout: int = 300,
    ) -> ToolResult:
        """
        Run ffuf with JSON output and parse results.
        """
        # Create temp file for JSON output
        with tempfile.NamedTemporaryFile(mode="w", suffix=".json", delete=False) as f:
            json_file = f.name

        try:
            # Build command with JSON output
            cmd = ["ffuf", "-o", json_file, "-of", "json", "-s"] + args

            self.logger.info(f"Running: {' '.join(cmd)}")

            # Run ffuf
            result = await self.run_command(cmd, timeout=timeout)

            # Read JSON output
            if os.path.exists(json_file) and os.path.getsize(json_file) > 0:
                with open(json_file, "r") as f:
                    json_output = f.read()

                parsed = self._parse_ffuf_json(json_output)

                return ToolResult(
                    success=True,
                    data=parsed,
                    raw_output=sanitize_output(result.stdout + result.stderr),
                )
            else:
                return ToolResult(
                    success=True,
                    data={"results": [], "total_results": 0, "message": "No results found"},
                    raw_output=sanitize_output(result.stdout + result.stderr),
                )

        except ToolError as e:
            return ToolResult(
                success=False,
                data={},
                error=str(e),
            )
        finally:
            # Cleanup temp file
            if os.path.exists(json_file):
                os.unlink(json_file)

    async def dir_fuzz(
        self,
        url: str,
        wordlist: str = "common",
        extensions: Optional[str] = None,
        threads: int = 40,
        filter_status: Optional[str] = None,
        filter_size: Optional[str] = None,
        timeout: int = 10,
        headers: Optional[Dict[str, str]] = None,
        cookies: Optional[str] = None,
    ) -> ToolResult:
        """
        Fuzz directories and files on a web server.
        """
        self.logger.info(f"Starting directory fuzz on {url}")

        # Validate URL has FUZZ keyword
        if "FUZZ" not in url:
            url = url.rstrip("/") + "/FUZZ"
            self.logger.info(f"Added FUZZ keyword: {url}")

        wordlist_path = self._resolve_wordlist(wordlist)

        args = [
            "-u", url,
            "-w", wordlist_path,
            "-t", str(threads),
            "-timeout", str(timeout),
        ]

        if extensions:
            args.extend(["-e", extensions])

        if filter_status:
            args.extend(["-mc", filter_status])
        else:
            # Default: match common success codes
            args.extend(["-mc", "200,204,301,302,307,401,403,405"])

        if filter_size:
            args.extend(["-fs", filter_size])

        # Add custom headers
        if headers:
            for key, value in headers.items():
                args.extend(["-H", f"{key}: {value}"])

        # Add cookies
        if cookies:
            args.extend(["-b", cookies])

        # Calculate timeout based on wordlist size
        try:
            with open(wordlist_path, "r") as f:
                line_count = sum(1 for _ in f)
            # Rough estimate: 100 requests per second with threads
            estimated_time = max(60, (line_count // 100) + 30)
        except:
            estimated_time = 300

        result = await self._run_ffuf(args, timeout=estimated_time)

        # Add summary
        if result.success and result.data.get("results"):
            result.data["summary"] = {
                "target": url,
                "wordlist": wordlist_path,
                "found": len(result.data["results"]),
                "paths": [r["input"] for r in result.data["results"][:20]],  # Top 20
            }

        return result

    async def param_fuzz(
        self,
        url: str,
        wordlist: str = "common",
        method: str = "GET",
        data: Optional[str] = None,
        threads: int = 40,
        filter_status: Optional[str] = None,
        filter_size: Optional[str] = None,
        headers: Optional[Dict[str, str]] = None,
        cookies: Optional[str] = None,
    ) -> ToolResult:
        """
        Fuzz GET or POST parameters.
        """
        self.logger.info(f"Starting parameter fuzz on {url} ({method})")

        wordlist_path = self._resolve_wordlist(wordlist)

        args = [
            "-u", url,
            "-w", wordlist_path,
            "-t", str(threads),
            "-X", method,
        ]

        if data:
            args.extend(["-d", data])

        if filter_status:
            args.extend(["-mc", filter_status])

        if filter_size:
            args.extend(["-fs", filter_size])

        # Add custom headers
        if headers:
            for key, value in headers.items():
                args.extend(["-H", f"{key}: {value}"])

        # Add cookies
        if cookies:
            args.extend(["-b", cookies])

        result = await self._run_ffuf(args, timeout=300)

        if result.success:
            result.data["summary"] = {
                "target": url,
                "method": method,
                "found": len(result.data.get("results", [])),
            }

        return result

    async def vhost_fuzz(
        self,
        url: str,
        domain: str,
        wordlist: str = "common",
        threads: int = 40,
        filter_size: Optional[str] = None,
    ) -> ToolResult:
        """
        Fuzz virtual hosts on a web server.
        """
        self.logger.info(f"Starting vhost fuzz on {url} for domain {domain}")

        wordlist_path = self._resolve_wordlist(wordlist)

        # For vhost fuzzing, we set Host header to FUZZ.domain
        args = [
            "-u", url,
            "-w", wordlist_path,
            "-t", str(threads),
            "-H", f"Host: FUZZ.{domain}",
        ]

        if filter_size:
            args.extend(["-fs", filter_size])

        # For vhosts, we typically want to filter by size to ignore default responses
        # The user should first check the default response size

        result = await self._run_ffuf(args, timeout=300)

        if result.success:
            vhosts = [f"{r['input']}.{domain}" for r in result.data.get("results", [])]
            result.data["summary"] = {
                "target": url,
                "base_domain": domain,
                "found": len(vhosts),
                "vhosts": vhosts[:20],  # Top 20
            }

        return result


if __name__ == "__main__":
    FfufServer.main()
