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
                "match_status": {
                    "type": "string",
                    "description": "Match ONLY these status codes (e.g., '200,301,302'). Default: 200,204,301,302,307,401,403,405",
                },
                "filter_codes": {
                    "type": "string",
                    "description": "Filter OUT these status codes (e.g., '403,404,429'). Results with these codes are hidden.",
                },
                "auto_calibrate": {
                    "type": "boolean",
                    "default": False,
                    "description": "Auto-calibrate response filtering. Automatically determines and filters default/error responses. Recommended for most scans.",
                },
                "filter_size": {
                    "type": "string",
                    "description": "Filter out responses of this size",
                },
                "filter_words": {
                    "type": "string",
                    "description": "Filter out responses with this word count (e.g., '42' or '10-50')",
                },
                "filter_lines": {
                    "type": "string",
                    "description": "Filter out responses with this line count (e.g., '0' or '5-20')",
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
                "match_status": {
                    "type": "string",
                    "description": "Match ONLY these status codes (e.g., '200,301,302')",
                },
                "filter_codes": {
                    "type": "string",
                    "description": "Filter OUT these status codes (e.g., '403,404,429'). Results with these codes are hidden.",
                },
                "auto_calibrate": {
                    "type": "boolean",
                    "default": False,
                    "description": "Auto-calibrate response filtering. Automatically determines and filters default/error responses.",
                },
                "filter_size": {
                    "type": "string",
                    "description": "Filter out responses of this size",
                },
                "filter_words": {
                    "type": "string",
                    "description": "Filter out responses with this word count (e.g., '42' or '10-50')",
                },
                "filter_lines": {
                    "type": "string",
                    "description": "Filter out responses with this line count (e.g., '0' or '5-20')",
                },
                "timeout": {
                    "type": "integer",
                    "default": 10,
                    "description": "HTTP request timeout in seconds",
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
                "match_status": {
                    "type": "string",
                    "description": "Match ONLY these status codes (e.g., '200,301,302')",
                },
                "filter_codes": {
                    "type": "string",
                    "description": "Filter OUT these status codes (e.g., '403,404,429'). Results with these codes are hidden.",
                },
                "auto_calibrate": {
                    "type": "boolean",
                    "default": False,
                    "description": "Auto-calibrate response filtering. Automatically determines and filters default/error responses.",
                },
                "filter_size": {
                    "type": "string",
                    "description": "Filter out responses of this size (use to filter default vhost)",
                },
                "filter_words": {
                    "type": "string",
                    "description": "Filter out responses with this word count (e.g., '42' or '10-50')",
                },
                "filter_lines": {
                    "type": "string",
                    "description": "Filter out responses with this line count (e.g., '0' or '5-20')",
                },
                "headers": {
                    "type": "object",
                    "description": "Custom HTTP headers as key-value pairs (in addition to Host header used for vhost fuzzing)",
                },
                "cookies": {
                    "type": "string",
                    "description": "Cookie header value for authenticated fuzzing",
                },
            },
            handler=self.vhost_fuzz,
        )

    def _resolve_wordlist(self, wordlist: str) -> str:
        """Resolve wordlist name to path.

        Returns (path, warning) where warning is set when a fallback occurred.
        Callers should include the warning in results so the agent knows.
        """
        if wordlist in self.WORDLISTS:
            path = self.WORDLISTS[wordlist]
            if os.path.exists(path):
                return path
            # Fallback to common if specified list doesn't exist
            common_path = self.WORDLISTS["common"]
            if os.path.exists(common_path):
                self.logger.warning(f"Wordlist '{wordlist}' ({path}) not found, falling back to common")
                return common_path
            # Neither requested nor common exists — return the requested path
            # so ffuf itself will produce a clear "file not found" error
            self.logger.error(f"Wordlist '{wordlist}' ({path}) and common fallback both missing")
            return path
        # Assume it's a path
        return wordlist

    def _estimate_timeout(self, wordlist_path: str, extensions: Optional[str] = None) -> int:
        """Estimate a sane wall-clock timeout based on wordlist size and extensions.

        Extensions multiply the total request count:
          total_requests = line_count * (1 + num_extensions)

        We assume ~100 requests/sec with default thread count (40), then add
        a 30-second buffer.  Floor is 60 s; ceiling is 900 s (15 min) so a
        single scan never blocks the agent for too long.
        """
        try:
            with open(wordlist_path, "rb") as f:
                line_count = sum(1 for _ in f)
        except (OSError, IOError):
            return 300  # safe default if we cannot read the wordlist

        ext_count = 0
        if extensions:
            ext_count = len([e for e in extensions.split(",") if e.strip()])

        total_requests = line_count * (1 + ext_count)
        estimated = (total_requests // 100) + 30
        return max(60, min(estimated, 900))

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

        Uses run_command_with_progress to send heartbeat notifications,
        preventing client-side idle timeouts on long-running scans.
        ffuf runs in silent mode (-s) so there is no meaningful stdout to
        parse for progress, but the heartbeat timer fires every 15 seconds.
        """
        # Create temp file for JSON output
        with tempfile.NamedTemporaryFile(mode="w", suffix=".json", delete=False) as f:
            json_file = f.name

        try:
            # Build command with JSON output
            cmd = ["ffuf", "-o", json_file, "-of", "json", "-s"] + args

            self.logger.info(f"Running: {' '.join(cmd)}")

            # Use run_command_with_progress for heartbeat support.
            # ffuf -s produces no stdout, but the heartbeat timer keeps
            # the MCP connection alive and prevents client idle timeout.
            result = await self.run_command_with_progress(
                cmd,
                heartbeat_interval=15.0,
            )

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
                # Check stderr for connection errors that indicate target is down
                stderr_lower = (result.stderr or "").lower()
                if "connection refused" in stderr_lower:
                    return ToolResult(
                        success=False,
                        data={},
                        error="Target refused connections — is the service running?",
                        error_class="network",
                        retryable=True,
                        suggestions=[
                            "Verify the target URL and port are correct",
                            "Check if the service is running with nmap",
                        ],
                    )
                return ToolResult(
                    success=True,
                    data={"results": [], "total_results": 0, "message": "No results found"},
                    raw_output=sanitize_output(result.stdout + result.stderr),
                )

        except ToolError as e:
            error_msg = str(e)
            error_class = "unknown"
            retryable = False
            suggestions = []

            if "timed out" in error_msg.lower():
                error_class = "timeout"
                retryable = True
                suggestions = [
                    "Use a smaller wordlist (e.g., 'small' or 'common' instead of 'big')",
                    "Reduce extensions to limit request count",
                    "Increase threads or reduce HTTP timeout",
                ]
            elif "connection refused" in error_msg.lower():
                error_class = "network"
                retryable = True
                suggestions = [
                    "Verify the target URL and port are correct",
                    "Check if the service is running with nmap",
                ]

            return ToolResult(
                success=False,
                data={},
                error=error_msg,
                error_class=error_class,
                retryable=retryable,
                suggestions=suggestions,
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
        match_status: Optional[str] = None,
        filter_codes: Optional[str] = None,
        auto_calibrate: bool = False,
        filter_size: Optional[str] = None,
        filter_words: Optional[str] = None,
        filter_lines: Optional[str] = None,
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

        if match_status:
            args.extend(["-mc", match_status])
        else:
            # Default: match common success codes
            args.extend(["-mc", "200,204,301,302,307,401,403,405"])

        if filter_codes:
            args.extend(["-fc", filter_codes])

        if auto_calibrate:
            args.append("-ac")

        if filter_size:
            args.extend(["-fs", filter_size])

        if filter_words:
            args.extend(["-fw", filter_words])

        if filter_lines:
            args.extend(["-fl", filter_lines])

        # Add custom headers
        if headers:
            for key, value in headers.items():
                args.extend(["-H", f"{key}: {value}"])

        # Add cookies
        if cookies:
            args.extend(["-b", cookies])

        estimated_time = self._estimate_timeout(wordlist_path, extensions)
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
        match_status: Optional[str] = None,
        filter_codes: Optional[str] = None,
        auto_calibrate: bool = False,
        filter_size: Optional[str] = None,
        filter_words: Optional[str] = None,
        filter_lines: Optional[str] = None,
        timeout: int = 10,
        headers: Optional[Dict[str, str]] = None,
        cookies: Optional[str] = None,
    ) -> ToolResult:
        """
        Fuzz GET or POST parameters.
        """
        self.logger.info(f"Starting parameter fuzz on {url} ({method})")

        # Validate FUZZ keyword exists in URL or POST data
        has_fuzz = "FUZZ" in url
        if data and "FUZZ" in data:
            has_fuzz = True
        if not has_fuzz:
            return ToolResult(
                success=False,
                data={},
                error="FUZZ keyword not found in url or data. Place FUZZ where you want to inject (e.g., url='http://target/page?FUZZ=test' or data='password=FUZZ')",
                error_class="params",
                retryable=False,
                suggestions=[
                    "For GET param discovery: url='http://target/page?FUZZ=test'",
                    "For GET value fuzzing: url='http://target/page?id=FUZZ'",
                    "For POST fuzzing: data='username=admin&password=FUZZ'",
                ],
            )

        wordlist_path = self._resolve_wordlist(wordlist)

        args = [
            "-u", url,
            "-w", wordlist_path,
            "-t", str(threads),
            "-X", method,
            "-timeout", str(timeout),
        ]

        if data:
            args.extend(["-d", data])

        if match_status:
            args.extend(["-mc", match_status])

        if filter_codes:
            args.extend(["-fc", filter_codes])

        if auto_calibrate:
            args.append("-ac")

        if filter_size:
            args.extend(["-fs", filter_size])

        if filter_words:
            args.extend(["-fw", filter_words])

        if filter_lines:
            args.extend(["-fl", filter_lines])

        # Add custom headers
        if headers:
            for key, value in headers.items():
                args.extend(["-H", f"{key}: {value}"])

        # Add cookies
        if cookies:
            args.extend(["-b", cookies])

        estimated_time = self._estimate_timeout(wordlist_path)
        result = await self._run_ffuf(args, timeout=estimated_time)

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
        match_status: Optional[str] = None,
        filter_codes: Optional[str] = None,
        auto_calibrate: bool = False,
        filter_size: Optional[str] = None,
        filter_words: Optional[str] = None,
        filter_lines: Optional[str] = None,
        headers: Optional[Dict[str, str]] = None,
        cookies: Optional[str] = None,
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

        if match_status:
            args.extend(["-mc", match_status])

        if filter_codes:
            args.extend(["-fc", filter_codes])

        if auto_calibrate:
            args.append("-ac")

        if filter_size:
            args.extend(["-fs", filter_size])

        if filter_words:
            args.extend(["-fw", filter_words])

        if filter_lines:
            args.extend(["-fl", filter_lines])

        # Add custom headers (in addition to the Host header used for vhost fuzzing)
        if headers:
            for key, value in headers.items():
                args.extend(["-H", f"{key}: {value}"])

        # Add cookies
        if cookies:
            args.extend(["-b", cookies])

        estimated_time = self._estimate_timeout(wordlist_path)
        result = await self._run_ffuf(args, timeout=estimated_time)

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
