#!/usr/bin/env python3
"""
OpenSploit MCP Server: OWASP ZAP

Web application security scanner with active vulnerability detection.
Communicates with ZAP daemon via REST API.
"""

import os
import socket
import time
from dataclasses import dataclass
from typing import Any, Dict, List, Optional, Tuple
from urllib.parse import urlparse

import requests

from mcp_common import BaseMCPServer, ToolResult, ToolError


def validate_url(url: str) -> Tuple[bool, Optional[Dict[str, str]]]:
    """
    Validate a URL and check if target is reachable.

    Returns:
        Tuple of (is_valid, error_dict or None)
        error_dict has 'type' and 'message' keys
    """
    # Check URL format
    try:
        parsed = urlparse(url)
        if not parsed.scheme or not parsed.netloc:
            return False, {
                "type": "invalid_url",
                "message": f"Invalid URL format: {url}. Must include scheme (http/https) and host."
            }
        if parsed.scheme not in ("http", "https"):
            return False, {
                "type": "invalid_url",
                "message": f"Invalid URL scheme: {parsed.scheme}. Must be http or https."
            }
    except Exception as e:
        return False, {
            "type": "invalid_url",
            "message": f"Could not parse URL: {str(e)}"
        }

    # Check DNS resolution
    hostname = parsed.netloc.split(":")[0]
    try:
        socket.gethostbyname(hostname)
    except socket.gaierror:
        return False, {
            "type": "dns_error",
            "message": f"Could not resolve hostname: {hostname}"
        }

    # Check if target is reachable (quick connection test)
    port = parsed.port or (443 if parsed.scheme == "https" else 80)
    try:
        sock = socket.socket(socket.AF_INET, socket.SOCK_STREAM)
        sock.settimeout(5)
        result = sock.connect_ex((hostname, port))
        sock.close()
        if result != 0:
            return False, {
                "type": "connection_error",
                "message": f"Could not connect to {hostname}:{port} - target unreachable"
            }
    except socket.timeout:
        return False, {
            "type": "connection_error",
            "message": f"Connection to {hostname}:{port} timed out"
        }
    except Exception as e:
        return False, {
            "type": "connection_error",
            "message": f"Connection error: {str(e)}"
        }

    return True, None


# Default timeouts (seconds)
DEFAULT_SPIDER_TIMEOUT = 300   # 5 minutes
DEFAULT_SCAN_TIMEOUT = 600     # 10 minutes
DEFAULT_QUICK_SCAN_TIMEOUT = 900  # 15 minutes for active scan in quick_scan


@dataclass
class WaitResult:
    """Result from waiting for a scan to complete."""
    completed: bool
    progress: int
    elapsed: float
    message: str


class ZapServer(BaseMCPServer):
    """MCP server for OWASP ZAP web application scanner."""

    def __init__(self):
        super().__init__(
            name="zap",
            description="OWASP ZAP web application security scanner",
            version="1.0.0",
        )

        self.zap_url = f"http://127.0.0.1:{os.environ.get('ZAP_PORT', '8080')}"

        # Spider - crawl target
        self.register_method(
            name="spider",
            description="Crawl a target URL to discover all pages and endpoints",
            params={
                "target": {
                    "type": "string",
                    "required": True,
                    "description": "Target URL to crawl (e.g., http://target.com)",
                },
                "max_depth": {
                    "type": "integer",
                    "default": 5,
                    "description": "Maximum crawl depth",
                },
                "max_children": {
                    "type": "integer",
                    "default": 0,
                    "description": "Maximum child URLs per page (0=unlimited)",
                },
                "wait": {
                    "type": "boolean",
                    "default": True,
                    "description": "Wait for spider to complete (if false, returns immediately with scan_id)",
                },
                "timeout": {
                    "type": "integer",
                    "default": 300,
                    "description": "Maximum seconds to wait for spider (default 300). Returns partial results on timeout.",
                },
                "subtree_only": {
                    "type": "boolean",
                    "default": True,
                    "description": "Only spider URLs under the target path (recommended to avoid crawling external sites)",
                },
            },
            handler=self.spider,
        )

        # Active scan - test for vulnerabilities
        self.register_method(
            name="active_scan",
            description="Actively scan a target for vulnerabilities (SQLi, XSS, etc.)",
            params={
                "target": {
                    "type": "string",
                    "required": True,
                    "description": "Target URL to scan",
                },
                "wait": {
                    "type": "boolean",
                    "default": True,
                    "description": "Wait for scan to complete (if false, returns immediately with scan_id)",
                },
                "timeout": {
                    "type": "integer",
                    "default": 600,
                    "description": "Maximum seconds to wait for scan (default 600). Returns partial results on timeout.",
                },
                "scan_policy": {
                    "type": "string",
                    "description": "Scan policy name: 'Default Policy', or custom policy name. Controls which checks are run.",
                },
            },
            handler=self.active_scan,
        )

        # Quick scan - spider + active scan
        self.register_method(
            name="quick_scan",
            description="Perform a complete scan: spider the target then run active scan. Returns partial results if either phase times out.",
            params={
                "target": {
                    "type": "string",
                    "required": True,
                    "description": "Target URL to scan",
                },
                "max_depth": {
                    "type": "integer",
                    "default": 5,
                    "description": "Maximum spider depth",
                },
                "max_children": {
                    "type": "integer",
                    "default": 0,
                    "description": "Maximum child URLs per page (0=unlimited)",
                },
                "spider_timeout": {
                    "type": "integer",
                    "default": 300,
                    "description": "Maximum seconds for spider phase (default 300)",
                },
                "scan_timeout": {
                    "type": "integer",
                    "default": 900,
                    "description": "Maximum seconds for active scan phase (default 900)",
                },
                "scan_policy": {
                    "type": "string",
                    "description": "Scan policy name for active scan phase",
                },
                "ajax_spider": {
                    "type": "boolean",
                    "default": False,
                    "description": "Run AJAX spider after traditional spider (for JavaScript-heavy sites)",
                },
                "exclude_regex": {
                    "type": "string",
                    "description": "Regex pattern for URLs to exclude from scanning (e.g., 'logout|delete|signout')",
                },
            },
            handler=self.quick_scan,
        )

        # Get alerts (vulnerabilities found)
        self.register_method(
            name="get_alerts",
            description="Get vulnerabilities discovered by ZAP",
            params={
                "target": {
                    "type": "string",
                    "description": "Filter alerts by target URL (optional)",
                },
                "risk": {
                    "type": "string",
                    "description": "Filter by risk level: High, Medium, Low, Informational",
                },
                "limit": {
                    "type": "integer",
                    "default": 100,
                    "description": "Maximum number of alerts to return",
                },
            },
            handler=self.get_alerts,
        )

        # Get discovered URLs
        self.register_method(
            name="get_urls",
            description="Get all URLs discovered by the spider",
            params={
                "target": {
                    "type": "string",
                    "description": "Filter URLs by base URL (optional)",
                },
            },
            handler=self.get_urls,
        )

        # Get scan status
        self.register_method(
            name="scan_status",
            description="Get the status of running scans",
            params={},
            handler=self.scan_status,
        )

        # Stop scan
        self.register_method(
            name="stop_scan",
            description="Stop a running spider or active scan",
            params={
                "scan_type": {
                    "type": "string",
                    "required": True,
                    "description": "Type of scan to stop: 'spider', 'active', 'ajax', or 'all'",
                },
                "scan_id": {
                    "type": "string",
                    "description": "Specific scan ID to stop. If not provided, stops all scans of the type.",
                },
            },
            handler=self.stop_scan,
        )

        # Get summary
        self.register_method(
            name="summary",
            description="Get a summary of all findings by risk level",
            params={
                "target": {
                    "type": "string",
                    "description": "Filter by target URL (optional)",
                },
            },
            handler=self.summary,
        )

        # Proxy history
        self.register_method(
            name="proxy_history",
            description="Get HTTP messages captured by ZAP proxy",
            params={
                "start": {
                    "type": "integer",
                    "default": 0,
                    "description": "Start index",
                },
                "count": {
                    "type": "integer",
                    "default": 50,
                    "description": "Number of messages to return",
                },
                "target": {
                    "type": "string",
                    "description": "Filter by target URL (optional)",
                },
            },
            handler=self.proxy_history,
        )

        # Send request (like Burp Repeater)
        self.register_method(
            name="send_request",
            description="Send an HTTP request through ZAP proxy and get the response (like Burp Repeater)",
            params={
                "url": {
                    "type": "string",
                    "required": True,
                    "description": "Full URL to request (e.g., http://target.com/path)",
                },
                "method": {
                    "type": "string",
                    "default": "GET",
                    "description": "HTTP method (GET, POST, PUT, DELETE, etc.)",
                },
                "headers": {
                    "type": "object",
                    "description": "Custom headers as key-value pairs",
                },
                "body": {
                    "type": "string",
                    "description": "Request body for POST/PUT requests",
                },
                "follow_redirects": {
                    "type": "boolean",
                    "default": True,
                    "description": "Follow HTTP redirects",
                },
            },
            handler=self.send_request,
        )

        # Access proxy URL
        self.register_method(
            name="proxy_info",
            description="Get ZAP proxy connection info for routing traffic through ZAP",
            params={},
            handler=self.proxy_info,
        )

        # AJAX Spider for JavaScript-heavy applications
        self.register_method(
            name="ajax_spider",
            description="Crawl JavaScript-heavy applications using ZAP's built-in browser automation",
            params={
                "target": {
                    "type": "string",
                    "required": True,
                    "description": "Target URL to crawl (e.g., http://target.com)",
                },
                "wait": {
                    "type": "boolean",
                    "default": True,
                    "description": "Wait for spider to complete",
                },
                "timeout": {
                    "type": "integer",
                    "default": 300,
                    "description": "Maximum seconds to wait for spider (default 300)",
                },
                "subtree_only": {
                    "type": "boolean",
                    "default": True,
                    "description": "Only spider URLs under the target path",
                },
                "max_crawl_depth": {
                    "type": "integer",
                    "default": 10,
                    "description": "Maximum crawl depth",
                },
                "max_duration": {
                    "type": "integer",
                    "default": 0,
                    "description": "Maximum duration in minutes (0=unlimited)",
                },
            },
            handler=self.ajax_spider,
        )

    def _zap_request(self, endpoint: str, params: Dict[str, Any] = None) -> Dict:
        """Make a request to ZAP API."""
        url = f"{self.zap_url}{endpoint}"
        try:
            response = requests.get(url, params=params or {}, timeout=30)
            response.raise_for_status()
            return response.json()
        except requests.exceptions.RequestException as e:
            raise ToolError(f"ZAP API error: {e}")

    def _wait_for_spider(self, scan_id: str, timeout: int = 300) -> WaitResult:
        """Wait for spider to complete.

        Returns WaitResult with completed=True if finished, or completed=False
        with partial progress if timeout reached.
        """
        start = time.time()
        progress = 0
        while time.time() - start < timeout:
            try:
                status = self._zap_request("/JSON/spider/view/status/", {"scanId": scan_id})
                progress = int(status.get("status", 0))
                if progress >= 100:
                    elapsed = time.time() - start
                    return WaitResult(
                        completed=True,
                        progress=100,
                        elapsed=elapsed,
                        message=f"Spider completed in {elapsed:.1f}s",
                    )
            except Exception:
                pass  # Continue waiting on API errors
            time.sleep(2)

        elapsed = time.time() - start
        return WaitResult(
            completed=False,
            progress=progress,
            elapsed=elapsed,
            message=f"Spider timed out at {progress}% after {timeout}s",
        )

    def _wait_for_scan(self, scan_id: str, timeout: int = 600) -> WaitResult:
        """Wait for active scan to complete.

        Returns WaitResult with completed=True if finished, or completed=False
        with partial progress if timeout reached.
        """
        start = time.time()
        progress = 0
        while time.time() - start < timeout:
            try:
                status = self._zap_request("/JSON/ascan/view/status/", {"scanId": scan_id})
                progress = int(status.get("status", 0))
                if progress >= 100:
                    elapsed = time.time() - start
                    return WaitResult(
                        completed=True,
                        progress=100,
                        elapsed=elapsed,
                        message=f"Active scan completed in {elapsed:.1f}s",
                    )
            except Exception:
                pass  # Continue waiting on API errors
            time.sleep(5)

        elapsed = time.time() - start
        return WaitResult(
            completed=False,
            progress=progress,
            elapsed=elapsed,
            message=f"Active scan timed out at {progress}% after {timeout}s",
        )

    async def spider(
        self,
        target: str,
        max_depth: int = 5,
        max_children: int = 0,
        wait: bool = True,
        timeout: int = DEFAULT_SPIDER_TIMEOUT,
        subtree_only: bool = True,
    ) -> ToolResult:
        """Crawl a target to discover URLs."""
        # Validate URL first
        is_valid, error = validate_url(target)
        if not is_valid:
            return ToolResult(
                success=True,  # Return True so JSON data is sent, not error text
                data={
                    "success": False,
                    "error": error,
                    "urls": [],
                    "urls_count": 0,
                },
                raw_output=f"Error: {error['message']}",
            )

        # Build spider params
        spider_params = {
            "url": target,
            "recurse": "true",
            "subtreeOnly": "true" if subtree_only else "false",
        }
        if max_children > 0:
            spider_params["maxChildren"] = max_children

        # Set max depth via ZAP option
        if max_depth > 0:
            try:
                self._zap_request("/JSON/spider/action/setOptionMaxDepth/", {"Integer": max_depth})
            except Exception:
                pass  # Continue if setting fails

        # Start spider
        result = self._zap_request("/JSON/spider/action/scan/", spider_params)
        scan_id = result.get("scan")

        if not scan_id:
            raise ToolError("Failed to start spider")

        output = [f"Spider started on {target} (scan ID: {scan_id})"]
        data = {
            "success": True,
            "scan_id": scan_id,
            "target": target,
            "urls": [],
            "urls_count": 0,
            "progress": {"percent": 0},
        }
        partial = False

        if wait:
            output.append(f"Waiting for spider to complete (timeout: {timeout}s)...")
            wait_result = self._wait_for_spider(scan_id, timeout=timeout)

            # Get results regardless of completion
            urls = self._zap_request("/JSON/spider/view/results/", {"scanId": scan_id})
            url_list = urls.get("results", [])
            data["urls"] = url_list
            data["urls_count"] = len(url_list)
            data["progress"] = {"percent": wait_result.progress}
            data["elapsed"] = round(wait_result.elapsed, 1)

            if wait_result.completed:
                data["success"] = True
                output.append(f"\nSpider complete. Discovered {len(url_list)} URLs:")
            else:
                partial = True
                data["success"] = False
                data["partial"] = True
                data["error"] = {
                    "type": "timeout",
                    "message": f"Spider timed out after {timeout} seconds"
                }
                output.append(f"\n⚠️ {wait_result.message}")
                output.append(f"Partial results: discovered {len(url_list)} URLs so far:")

            for url in url_list[:50]:  # Limit output
                output.append(f"  • {url}")
            if len(url_list) > 50:
                output.append(f"  ... and {len(url_list) - 50} more")

            if partial:
                output.append(f"\nUse scan_status to check if spider is still running.")
                output.append(f"Use get_urls to retrieve all discovered URLs.")
        else:
            output.append("Spider running in background. Use scan_status to check progress.")

        return ToolResult(
            success=not partial,
            data=data,
            raw_output="\n".join(output),
            error=data.get("error", {}).get("message") if partial else None,
        )

    async def active_scan(
        self,
        target: str,
        wait: bool = True,
        timeout: int = DEFAULT_SCAN_TIMEOUT,
        scan_policy: str = None,
    ) -> ToolResult:
        """Run active vulnerability scan."""
        # Validate URL first
        is_valid, error = validate_url(target)
        if not is_valid:
            return ToolResult(
                success=True,  # Return True so JSON data is sent, not error text
                data={
                    "success": False,
                    "error": error,
                    "alerts": [],
                    "alerts_count": 0,
                },
                raw_output=f"Error: {error['message']}",
            )

        # Build scan params
        scan_params = {"url": target, "recurse": "true"}
        if scan_policy:
            scan_params["scanPolicyName"] = scan_policy

        # Start active scan
        result = self._zap_request("/JSON/ascan/action/scan/", scan_params)
        scan_id = result.get("scan")

        if not scan_id:
            raise ToolError("Failed to start active scan")

        output = [f"Active scan started on {target} (scan ID: {scan_id})"]
        data = {
            "success": True,
            "scan_id": scan_id,
            "target": target,
            "alerts": [],
            "alerts_count": 0,
            "progress": {"percent": 0},
        }
        partial = False

        if wait:
            output.append(f"Scanning for vulnerabilities (timeout: {timeout}s)...")
            wait_result = self._wait_for_scan(scan_id, timeout=timeout)

            # Get alerts regardless of completion
            alerts = self._zap_request("/JSON/core/view/alerts/", {"baseurl": target})
            alert_list = alerts.get("alerts", [])

            # Format alerts for response
            formatted_alerts = []
            for alert in alert_list:
                formatted_alerts.append({
                    "name": alert.get("alert", "Unknown"),
                    "risk": alert.get("risk", "Informational"),
                    "confidence": alert.get("confidence", "Unknown"),
                    "url": alert.get("url", ""),
                    "param": alert.get("param", ""),
                    "description": alert.get("description", ""),
                    "solution": alert.get("solution", ""),
                    "cweid": alert.get("cweid", ""),
                    "wascid": alert.get("wascid", ""),
                })

            # Group by risk for summary
            by_risk = {"High": [], "Medium": [], "Low": [], "Informational": []}
            for alert in alert_list:
                risk = alert.get("risk", "Informational")
                if risk in by_risk:
                    by_risk[risk].append(alert)

            data["alerts"] = formatted_alerts
            data["alerts_count"] = len(alert_list)
            data["progress"] = {"percent": wait_result.progress}
            data["elapsed"] = round(wait_result.elapsed, 1)
            data["summary"] = {
                "high": len(by_risk["High"]),
                "medium": len(by_risk["Medium"]),
                "low": len(by_risk["Low"]),
                "info": len(by_risk["Informational"]),
                "total": len(alert_list),
            }

            if wait_result.completed:
                data["success"] = True
                output.append(f"\nScan complete. Found {len(alert_list)} issues:")
            else:
                partial = True
                data["success"] = False
                data["partial"] = True
                data["error"] = {
                    "type": "timeout",
                    "message": f"Active scan timed out after {timeout} seconds"
                }
                output.append(f"\n⚠️ {wait_result.message}")
                output.append(f"Partial results: found {len(alert_list)} issues so far:")

            output.append(f"  • High: {len(by_risk['High'])}")
            output.append(f"  • Medium: {len(by_risk['Medium'])}")
            output.append(f"  • Low: {len(by_risk['Low'])}")
            output.append(f"  • Informational: {len(by_risk['Informational'])}")

            # Show high/medium alerts
            for risk in ["High", "Medium"]:
                if by_risk[risk]:
                    output.append(f"\n{risk} Risk Vulnerabilities:")
                    for alert in by_risk[risk][:10]:
                        output.append(f"  [{alert.get('alert')}]")
                        output.append(f"    URL: {alert.get('url', 'N/A')}")
                        output.append(f"    Param: {alert.get('param', 'N/A')}")

            if partial:
                output.append(f"\nUse scan_status to check if scan is still running.")
                output.append(f"Use get_alerts to retrieve all discovered vulnerabilities.")
        else:
            output.append("Active scan running in background. Use scan_status to check progress.")

        return ToolResult(
            success=not partial,
            data=data,
            raw_output="\n".join(output),
            error=data.get("error", {}).get("message") if partial else None,
        )

    async def quick_scan(
        self,
        target: str,
        max_depth: int = 5,
        max_children: int = 0,
        spider_timeout: int = DEFAULT_SPIDER_TIMEOUT,
        scan_timeout: int = DEFAULT_QUICK_SCAN_TIMEOUT,
        scan_policy: str = None,
        ajax_spider: bool = False,
        exclude_regex: str = None,
    ) -> ToolResult:
        """Perform complete scan: spider then active scan."""
        # Validate URL first
        is_valid, error = validate_url(target)
        if not is_valid:
            return ToolResult(
                success=True,  # Return True so JSON data is sent, not error text
                data={
                    "success": False,
                    "error": error,
                    "urls": [],
                    "urls_count": 0,
                    "alerts": [],
                    "alerts_count": 0,
                },
                raw_output=f"Error: {error['message']}",
            )

        output = [f"Starting quick scan of {target}\n"]
        data = {
            "success": True,
            "target": target,
            "urls": [],
            "urls_count": 0,
            "alerts": [],
            "alerts_count": 0,
            "progress": {"spider_percent": 0, "scan_percent": 0},
        }
        spider_partial = False
        scan_partial = False

        # Set exclusion regex if provided
        if exclude_regex:
            try:
                self._zap_request("/JSON/spider/action/excludeFromScan/", {"regex": exclude_regex})
                self._zap_request("/JSON/ascan/action/excludeFromScan/", {"regex": exclude_regex})
                output.append(f"Excluding URLs matching: {exclude_regex}")
            except Exception as e:
                output.append(f"Warning: Could not set exclusion regex: {e}")

        # Set max depth
        if max_depth > 0:
            try:
                self._zap_request("/JSON/spider/action/setOptionMaxDepth/", {"Integer": max_depth})
            except Exception:
                pass

        # Spider first
        output.append(f"Phase 1: Spidering target (timeout: {spider_timeout}s)...")
        spider_params = {
            "url": target,
            "recurse": "true",
            "subtreeOnly": "true",
        }
        if max_children > 0:
            spider_params["maxChildren"] = max_children
        spider_result = self._zap_request("/JSON/spider/action/scan/", spider_params)
        spider_id = spider_result.get("scan")
        if not spider_id:
            raise ToolError("Failed to start spider")

        spider_wait = self._wait_for_spider(spider_id, timeout=spider_timeout)

        urls = self._zap_request("/JSON/spider/view/results/", {"scanId": spider_id})
        url_list = urls.get("results", [])
        data["spider_id"] = spider_id
        data["urls"] = url_list
        data["urls_count"] = len(url_list)
        data["progress"]["spider_percent"] = spider_wait.progress
        data["spider_elapsed"] = round(spider_wait.elapsed, 1)

        if spider_wait.completed:
            output.append(f"  ✓ Discovered {len(url_list)} URLs in {spider_wait.elapsed:.1f}s\n")
        else:
            spider_partial = True
            data["spider_partial"] = True
            output.append(f"  ⚠️ {spider_wait.message}")
            output.append(f"  Proceeding with {len(url_list)} URLs discovered so far\n")

        # AJAX Spider (optional)
        if ajax_spider:
            output.append("Phase 1b: Running AJAX spider for JavaScript content...")
            try:
                ajax_result = self._zap_request("/JSON/ajaxSpider/action/scan/", {"url": target})
                ajax_id = ajax_result.get("scan", "0")
                # Wait for AJAX spider (shorter timeout since it's supplemental)
                ajax_timeout = min(120, spider_timeout // 2)
                start = time.time()
                while time.time() - start < ajax_timeout:
                    status = self._zap_request("/JSON/ajaxSpider/view/status/")
                    if status.get("status") == "stopped":
                        break
                    time.sleep(2)
                # Get updated URL count
                urls = self._zap_request("/JSON/spider/view/results/", {"scanId": spider_id})
                url_list = urls.get("results", [])
                if len(url_list) > data["urls_count"]:
                    output.append(f"  ✓ AJAX spider found {len(url_list) - data['urls_count']} additional URLs\n")
                    data["urls"] = url_list
                    data["urls_count"] = len(url_list)
                else:
                    output.append(f"  ✓ AJAX spider complete (no new URLs)\n")
            except Exception as e:
                output.append(f"  ⚠️ AJAX spider failed: {e}\n")

        # Active scan
        output.append(f"Phase 2: Active vulnerability scanning (timeout: {scan_timeout}s)...")
        scan_params = {"url": target, "recurse": "true"}
        if scan_policy:
            scan_params["scanPolicyName"] = scan_policy
        scan_result = self._zap_request("/JSON/ascan/action/scan/", scan_params)
        scan_id = scan_result.get("scan")
        if not scan_id:
            raise ToolError("Failed to start active scan")

        scan_wait = self._wait_for_scan(scan_id, timeout=scan_timeout)

        # Get alerts
        alerts = self._zap_request("/JSON/core/view/alerts/", {"baseurl": target})
        alert_list = alerts.get("alerts", [])

        # Format alerts for response
        formatted_alerts = []
        for alert in alert_list:
            formatted_alerts.append({
                "name": alert.get("alert", "Unknown"),
                "risk": alert.get("risk", "Informational"),
                "confidence": alert.get("confidence", "Unknown"),
                "url": alert.get("url", ""),
                "param": alert.get("param", ""),
                "description": alert.get("description", ""),
                "solution": alert.get("solution", ""),
            })

        # Group by risk for summary
        by_risk = {"High": [], "Medium": [], "Low": [], "Informational": []}
        for alert in alert_list:
            risk = alert.get("risk", "Informational")
            if risk in by_risk:
                by_risk[risk].append(alert)

        data["scan_id"] = scan_id
        data["alerts"] = formatted_alerts
        data["alerts_count"] = len(alert_list)
        data["progress"]["scan_percent"] = scan_wait.progress
        data["scan_elapsed"] = round(scan_wait.elapsed, 1)
        data["summary"] = {
            "high": len(by_risk["High"]),
            "medium": len(by_risk["Medium"]),
            "low": len(by_risk["Low"]),
            "info": len(by_risk["Informational"]),
            "total": len(alert_list),
        }

        if not scan_wait.completed:
            scan_partial = True
            data["scan_partial"] = True

        output.append(f"\n{'='*50}")
        if spider_partial or scan_partial:
            output.append("SCAN SUMMARY (PARTIAL RESULTS)")
            data["partial"] = True
            data["success"] = False
            # Determine which phase timed out
            if scan_partial:
                data["error"] = {
                    "type": "timeout",
                    "message": f"Active scan timed out after {scan_timeout} seconds",
                    "phase": "active_scan"
                }
            elif spider_partial:
                data["error"] = {
                    "type": "timeout",
                    "message": f"Spider timed out after {spider_timeout} seconds",
                    "phase": "spider"
                }
        else:
            output.append("SCAN COMPLETE - VULNERABILITY SUMMARY")
        output.append(f"{'='*50}")
        output.append(f"Target: {target}")
        output.append(f"URLs Discovered: {len(url_list)}" + (" (partial)" if spider_partial else ""))
        output.append(f"Scan Progress: {scan_wait.progress}%")
        output.append(f"Total Issues: {len(alert_list)}" + (" (partial)" if scan_partial else ""))
        output.append(f"  🔴 High: {len(by_risk['High'])}")
        output.append(f"  🟠 Medium: {len(by_risk['Medium'])}")
        output.append(f"  🟡 Low: {len(by_risk['Low'])}")
        output.append(f"  🔵 Informational: {len(by_risk['Informational'])}")

        # Detail high/medium
        for risk, emoji in [("High", "🔴"), ("Medium", "🟠")]:
            if by_risk[risk]:
                output.append(f"\n{emoji} {risk} Risk Findings:")
                for alert in by_risk[risk]:
                    output.append(f"\n  [{alert.get('alert')}]")
                    output.append(f"  URL: {alert.get('url', 'N/A')}")
                    output.append(f"  Parameter: {alert.get('param', 'N/A')}")
                    desc = alert.get('description', '')[:200]
                    if desc:
                        output.append(f"  Description: {desc}...")

        if spider_partial or scan_partial:
            output.append(f"\n⚠️ Scan did not complete fully.")
            output.append(f"Use scan_status to check if scans are still running.")
            output.append(f"Use get_alerts to retrieve all discovered vulnerabilities.")

        return ToolResult(
            success=not (spider_partial or scan_partial),
            data=data,
            raw_output="\n".join(output),
            error=data.get("error", {}).get("message") if (spider_partial or scan_partial) else None,
        )

    async def get_alerts(
        self,
        target: str = None,
        risk: str = None,
        limit: int = 100,
    ) -> ToolResult:
        """Get discovered vulnerabilities."""
        params = {"start": 0, "count": limit}
        if target:
            params["baseurl"] = target
        if risk:
            params["riskId"] = {"High": 3, "Medium": 2, "Low": 1, "Informational": 0}.get(risk)

        alerts = self._zap_request("/JSON/core/view/alerts/", params)
        alert_list = alerts.get("alerts", [])

        if not alert_list:
            return ToolResult(
                success=True,
                data={
                    "alerts": [],
                    "alerts_count": 0,
                },
                raw_output="No alerts found."
            )

        # Format alerts for response
        formatted_alerts = []
        for alert in alert_list:
            formatted_alerts.append({
                "name": alert.get("alert", "Unknown"),
                "risk": alert.get("risk", "Informational"),
                "confidence": alert.get("confidence", "Unknown"),
                "url": alert.get("url", ""),
                "param": alert.get("param", ""),
                "description": alert.get("description", ""),
                "solution": alert.get("solution", ""),
                "cweid": alert.get("cweid", ""),
                "wascid": alert.get("wascid", ""),
            })

        output = [f"Found {len(alert_list)} alerts:"]

        for alert in alert_list:
            output.append(f"\n[{alert.get('risk', 'Unknown')}] {alert.get('alert', 'Unknown')}")
            output.append(f"  URL: {alert.get('url', 'N/A')}")
            output.append(f"  Param: {alert.get('param', 'N/A')}")
            output.append(f"  CWE: {alert.get('cweid', 'N/A')}")

        return ToolResult(
            success=True,
            data={
                "alerts": formatted_alerts,
                "alerts_count": len(alert_list),
            },
        )

    async def get_urls(self, target: str = None) -> ToolResult:
        """Get discovered URLs."""
        urls = self._zap_request("/JSON/core/view/urls/", {"baseurl": target} if target else {})
        url_list = urls.get("urls", [])

        if not url_list:
            return ToolResult(
                success=True,
                data={
                    "urls": [],
                    "urls_count": 0,
                },
                raw_output="No URLs discovered. Run spider first."
            )

        output = [f"Discovered {len(url_list)} URLs:"]
        for url in url_list[:100]:
            output.append(f"  • {url}")
        if len(url_list) > 100:
            output.append(f"  ... and {len(url_list) - 100} more")

        return ToolResult(
            success=True,
            data={
                "urls": url_list,
                "urls_count": len(url_list),
            },
        )

    async def scan_status(self) -> ToolResult:
        """Get status of running scans."""
        output = ["SCAN STATUS"]
        output.append("=" * 40)
        data = {}

        # Spider status - get all scans
        try:
            spider_scans = self._zap_request("/JSON/spider/view/scans/")
            scans = spider_scans.get("scans", [])
            data["spider_scans"] = []

            if scans:
                output.append("\nSpider Scans:")
                for scan in scans:
                    scan_id = scan.get("id", "?")
                    progress = scan.get("progress", "0")
                    state = scan.get("state", "unknown")
                    urls_found = scan.get("urlsInScope", 0)

                    data["spider_scans"].append({
                        "id": scan_id,
                        "progress": int(progress),
                        "state": state,
                        "urls_found": urls_found,
                    })

                    status_icon = "✓" if state == "FINISHED" else "⏳" if state == "RUNNING" else "○"
                    output.append(f"  {status_icon} Scan {scan_id}: {progress}% ({state})")
                    if urls_found:
                        output.append(f"      URLs found: {urls_found}")
            else:
                output.append("\nSpider: No scans")
        except Exception as e:
            output.append(f"\nSpider: Error checking status ({e})")

        # Active scan status - get all scans
        try:
            ascan_scans = self._zap_request("/JSON/ascan/view/scans/")
            scans = ascan_scans.get("scans", [])
            data["active_scans"] = []

            if scans:
                output.append("\nActive Scans:")
                for scan in scans:
                    scan_id = scan.get("id", "?")
                    progress = scan.get("progress", "0")
                    state = scan.get("state", "unknown")
                    # Get alerts count for this scan's URL
                    alerts_count = scan.get("alertCount", 0)

                    data["active_scans"].append({
                        "id": scan_id,
                        "progress": int(progress),
                        "state": state,
                        "alerts": alerts_count,
                    })

                    status_icon = "✓" if state == "FINISHED" else "⏳" if state == "RUNNING" else "○"
                    output.append(f"  {status_icon} Scan {scan_id}: {progress}% ({state})")
                    if alerts_count:
                        output.append(f"      Alerts found: {alerts_count}")
            else:
                output.append("\nActive Scan: No scans")
        except Exception as e:
            output.append(f"\nActive Scan: Error checking status ({e})")

        # Overall summary
        running_spiders = sum(1 for s in data.get("spider_scans", []) if s.get("state") == "RUNNING")
        running_scans = sum(1 for s in data.get("active_scans", []) if s.get("state") == "RUNNING")

        output.append("\n" + "-" * 40)
        output.append(f"Running: {running_spiders} spider(s), {running_scans} active scan(s)")

        data["running_spiders"] = running_spiders
        data["running_scans"] = running_scans

        return ToolResult(success=True, data=data, raw_output="\n".join(output))

    async def stop_scan(
        self,
        scan_type: str,
        scan_id: str = None,
    ) -> ToolResult:
        """Stop a running spider or active scan."""
        output = []
        data = {"stopped": []}
        errors = []

        scan_type = scan_type.lower()

        if scan_type in ("spider", "all"):
            try:
                if scan_id:
                    self._zap_request("/JSON/spider/action/stop/", {"scanId": scan_id})
                    output.append(f"Stopped spider scan {scan_id}")
                    data["stopped"].append({"type": "spider", "id": scan_id})
                else:
                    self._zap_request("/JSON/spider/action/stopAllScans/")
                    output.append("Stopped all spider scans")
                    data["stopped"].append({"type": "spider", "id": "all"})
            except Exception as e:
                errors.append(f"Spider stop failed: {e}")

        if scan_type in ("active", "all"):
            try:
                if scan_id:
                    self._zap_request("/JSON/ascan/action/stop/", {"scanId": scan_id})
                    output.append(f"Stopped active scan {scan_id}")
                    data["stopped"].append({"type": "active", "id": scan_id})
                else:
                    self._zap_request("/JSON/ascan/action/stopAllScans/")
                    output.append("Stopped all active scans")
                    data["stopped"].append({"type": "active", "id": "all"})
            except Exception as e:
                errors.append(f"Active scan stop failed: {e}")

        if scan_type in ("ajax", "all"):
            try:
                self._zap_request("/JSON/ajaxSpider/action/stop/")
                output.append("Stopped AJAX spider")
                data["stopped"].append({"type": "ajax", "id": "all"})
            except Exception as e:
                errors.append(f"AJAX spider stop failed: {e}")

        if scan_type not in ("spider", "active", "ajax", "all"):
            return ToolResult(
                success=False,
                data={},
                error=f"Invalid scan_type '{scan_type}'. Use: spider, active, ajax, or all",
            )

        if errors:
            output.extend([f"⚠️ {e}" for e in errors])
            data["errors"] = errors

        if not output:
            output.append("No scans to stop")

        return ToolResult(
            success=len(errors) == 0,
            data=data,
            raw_output="\n".join(output),
            error="; ".join(errors) if errors else None,
        )

    async def summary(self, target: str = None) -> ToolResult:
        """Get summary of findings."""
        params = {}
        if target:
            params["baseurl"] = target

        alerts = self._zap_request("/JSON/core/view/alerts/", params)
        alert_list = alerts.get("alerts", [])

        # Group by risk and type
        by_risk = {"High": [], "Medium": [], "Low": [], "Informational": []}
        by_type = {}

        for alert in alert_list:
            risk = alert.get("risk", "Informational")
            alert_type = alert.get("alert", "Unknown")

            if risk in by_risk:
                by_risk[risk].append(alert)

            if alert_type not in by_type:
                by_type[alert_type] = {"count": 0, "risk": risk}
            by_type[alert_type]["count"] += 1

        output = [
            "VULNERABILITY SUMMARY",
            "=" * 40,
            f"Total Issues: {len(alert_list)}",
            f"  🔴 High: {len(by_risk['High'])}",
            f"  🟠 Medium: {len(by_risk['Medium'])}",
            f"  🟡 Low: {len(by_risk['Low'])}",
            f"  🔵 Informational: {len(by_risk['Informational'])}",
            "",
            "By Vulnerability Type:",
        ]

        # Sort by count
        sorted_types = sorted(by_type.items(), key=lambda x: x[1]["count"], reverse=True)
        for alert_type, info in sorted_types[:20]:
            output.append(f"  [{info['risk']}] {alert_type}: {info['count']}")

        return ToolResult(
            success=True,
            data={
                "total": len(alert_list),
                "high": len(by_risk["High"]),
                "medium": len(by_risk["Medium"]),
                "low": len(by_risk["Low"]),
                "info": len(by_risk["Informational"]),
            },
        )

    async def proxy_history(
        self,
        start: int = 0,
        count: int = 50,
        target: str = None,
    ) -> ToolResult:
        """Get HTTP messages from proxy history."""
        params = {"start": start, "count": count}
        if target:
            params["baseurl"] = target

        messages = self._zap_request("/JSON/core/view/messages/", params)
        msg_list = messages.get("messages", [])

        if not msg_list:
            return ToolResult(
                success=True,
                data={"count": 0},
                raw_output="No messages in proxy history.\n\nTo capture traffic, configure your browser/tool to use ZAP as proxy.",
            )

        output = [f"Proxy History ({len(msg_list)} messages):"]

        for msg in msg_list:
            req_header = msg.get("requestHeader", "")
            # Extract method and URL from first line
            first_line = req_header.split("\n")[0] if req_header else "Unknown"
            status = msg.get("responseHeader", "").split(" ")[1] if msg.get("responseHeader") else "N/A"

            output.append(f"\n[{msg.get('id', '?')}] {first_line[:80]}")
            output.append(f"  Status: {status}")
            output.append(f"  Time: {msg.get('timestamp', 'N/A')}")

        return ToolResult(
            success=True,
            data={"count": len(msg_list)},
        )

    async def send_request(
        self,
        url: str,
        method: str = "GET",
        headers: Dict[str, str] = None,
        body: str = None,
        follow_redirects: bool = True,
    ) -> ToolResult:
        """Send an HTTP request through ZAP and get the response."""
        import requests

        # Use requests to send through ZAP proxy
        proxies = {"http": "http://127.0.0.1:8080", "https": "http://127.0.0.1:8080"}

        try:
            resp = requests.request(
                method=method,
                url=url,
                headers=headers or {},
                data=body,
                proxies=proxies,
                allow_redirects=follow_redirects,
                verify=False,
                timeout=30,
            )

            output = [
                "REQUEST SENT",
                "=" * 40,
                f"URL: {url}",
                f"Method: {method}",
                "",
                f"Status: {resp.status_code} {resp.reason}",
                "",
                "Response Headers:",
                "-" * 40,
            ]

            for key, value in resp.headers.items():
                output.append(f"{key}: {value}")

            output.append("")
            output.append("Response Body:")
            output.append("-" * 40)

            body_text = resp.text
            if len(body_text) > 2000:
                output.append(body_text[:2000] + f"\n\n... [truncated, {len(body_text)} bytes total]")
            else:
                output.append(body_text)

            return ToolResult(
                success=True,
                data={
                    "url": url,
                    "status_code": resp.status_code,
                    "content_length": len(resp.content),
                },
                raw_output="\n".join(output),
            )

        except Exception as e:
            return ToolResult(
                success=False,
                data={},
                error=f"Request failed: {str(e)}",
            )

    async def proxy_info(self) -> ToolResult:
        """Get proxy connection info."""
        port = os.environ.get("ZAP_PORT", "8080")

        output = [
            "ZAP PROXY INFORMATION",
            "=" * 40,
            "",
            "To route traffic through ZAP for interception:",
            "",
            f"  Proxy Host: 127.0.0.1 (inside container)",
            f"  Proxy Port: {port}",
            "",
            "For external access (from host machine):",
            "  Run container with: -p 8080:8080",
            "  Then use: http://localhost:8080 as proxy",
            "",
            "Browser Configuration:",
            "  1. Set HTTP/HTTPS proxy to the above address",
            "  2. Browse the target application",
            "  3. Use proxy_history to see captured requests",
            "  4. Use send_request to replay/modify requests",
            "",
            "Note: For HTTPS, you may need to import ZAP's CA certificate",
        ]

        return ToolResult(
            success=True,
            data={"port": port},
        )

    def _wait_for_ajax_spider(self, timeout: int = 300) -> WaitResult:
        """Wait for AJAX spider to complete.

        Returns WaitResult with completed=True if finished, or completed=False
        with status if timeout reached.
        """
        start = time.time()
        status = "running"
        while time.time() - start < timeout:
            try:
                result = self._zap_request("/JSON/ajaxSpider/view/status/")
                status = result.get("status", "unknown")
                if status == "stopped":
                    elapsed = time.time() - start
                    return WaitResult(
                        completed=True,
                        progress=100,
                        elapsed=elapsed,
                        message=f"AJAX spider completed in {elapsed:.1f}s",
                    )
            except Exception:
                pass  # Continue waiting on API errors
            time.sleep(2)

        elapsed = time.time() - start
        return WaitResult(
            completed=False,
            progress=0,  # AJAX spider doesn't report progress %
            elapsed=elapsed,
            message=f"AJAX spider timed out after {timeout}s (status: {status})",
        )

    async def ajax_spider(
        self,
        target: str,
        wait: bool = True,
        timeout: int = 300,
        subtree_only: bool = True,
        max_crawl_depth: int = 10,
        max_duration: int = 0,
    ) -> ToolResult:
        """Crawl a JavaScript-heavy application using ZAP's built-in browser.

        This discovers endpoints that the traditional spider misses by executing
        JavaScript and interacting with the page like a real browser.
        """
        # Validate URL first
        is_valid, error = validate_url(target)
        if not is_valid:
            return ToolResult(
                success=True,  # Return True so JSON data is sent, not error text
                data={
                    "success": False,
                    "error": error,
                    "urls": [],
                    "urls_count": 0,
                },
                raw_output=f"Error: {error['message']}",
            )

        # Configure AJAX spider options
        try:
            if max_crawl_depth > 0:
                self._zap_request("/JSON/ajaxSpider/action/setOptionMaxCrawlDepth/", {"Integer": max_crawl_depth})
            if max_duration > 0:
                self._zap_request("/JSON/ajaxSpider/action/setOptionMaxDuration/", {"Integer": max_duration})
        except Exception as e:
            # Continue even if setting options fails
            pass

        # Build spider params
        spider_params = {"url": target}
        if subtree_only:
            spider_params["subtreeOnly"] = "true"

        # Start AJAX spider
        try:
            result = self._zap_request("/JSON/ajaxSpider/action/scan/", spider_params)
        except Exception as e:
            raise ToolError(f"Failed to start AJAX spider: {e}")

        output = [f"AJAX Spider started on {target}"]
        output.append("Note: Uses ZAP's built-in browser automation (not Playwright)")
        data = {
            "success": True,
            "target": target,
            "urls": [],
            "urls_count": 0,
        }
        partial = False

        if wait:
            output.append(f"Waiting for AJAX spider to complete (timeout: {timeout}s)...")
            wait_result = self._wait_for_ajax_spider(timeout=timeout)

            # Get results
            try:
                results = self._zap_request("/JSON/ajaxSpider/view/results/")
                url_list = results.get("results", [])
                data["urls"] = url_list
                data["urls_count"] = len(url_list)
            except Exception:
                url_list = []

            # Also get full scan results which include more details
            try:
                full_results = self._zap_request("/JSON/ajaxSpider/view/fullResults/")
                data["full_results"] = full_results.get("fullResults", [])
            except Exception:
                pass

            data["elapsed"] = round(wait_result.elapsed, 1)

            if wait_result.completed:
                data["success"] = True
                output.append(f"\nAJAX Spider complete. Discovered {len(url_list)} URLs:")
            else:
                partial = True
                data["success"] = False
                data["partial"] = True
                data["error"] = {
                    "type": "timeout",
                    "message": f"AJAX spider timed out after {timeout} seconds"
                }
                output.append(f"\n⚠️ {wait_result.message}")
                output.append(f"Partial results: discovered {len(url_list)} URLs so far:")

            for url in url_list[:50]:  # Limit output
                output.append(f"  • {url}")
            if len(url_list) > 50:
                output.append(f"  ... and {len(url_list) - 50} more")

            if partial:
                output.append(f"\nUse stop_scan(scan_type='ajax') to stop the spider.")
                output.append(f"Use get_urls to retrieve all discovered URLs.")
        else:
            output.append("AJAX Spider running in background. Use scan_status to check progress.")

        return ToolResult(
            success=not partial,
            data=data,
            raw_output="\n".join(output),
            error=data.get("error", {}).get("message") if partial else None,
        )


if __name__ == "__main__":
    ZapServer.main()
