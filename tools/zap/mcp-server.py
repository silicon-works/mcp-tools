#!/usr/bin/env python3
"""
OpenSploit MCP Server: OWASP ZAP

Web application security scanner with active vulnerability detection.
Communicates with ZAP daemon via REST API.
"""

import os
import time
from typing import Any, Dict, List, Optional

import requests

from mcp_common import BaseMCPServer, ToolResult, ToolError


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
                "wait": {
                    "type": "boolean",
                    "default": True,
                    "description": "Wait for spider to complete",
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
                    "description": "Wait for scan to complete",
                },
            },
            handler=self.active_scan,
        )

        # Quick scan - spider + active scan
        self.register_method(
            name="quick_scan",
            description="Perform a complete scan: spider the target then run active scan",
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
            description="Send an HTTP request through ZAP and get the response (like Burp Repeater)",
            params={
                "request": {
                    "type": "string",
                    "required": True,
                    "description": "Raw HTTP request (headers and body)",
                },
                "target": {
                    "type": "string",
                    "required": True,
                    "description": "Target URL (e.g., https://target.com)",
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

    def _zap_request(self, endpoint: str, params: Dict[str, Any] = None) -> Dict:
        """Make a request to ZAP API."""
        url = f"{self.zap_url}{endpoint}"
        try:
            response = requests.get(url, params=params or {}, timeout=30)
            response.raise_for_status()
            return response.json()
        except requests.exceptions.RequestException as e:
            raise ToolError(f"ZAP API error: {e}")

    def _wait_for_spider(self, scan_id: str, timeout: int = 300) -> None:
        """Wait for spider to complete."""
        start = time.time()
        while time.time() - start < timeout:
            status = self._zap_request("/JSON/spider/view/status/", {"scanId": scan_id})
            if int(status.get("status", 0)) >= 100:
                return
            time.sleep(2)
        raise ToolError(f"Spider timed out after {timeout} seconds")

    def _wait_for_scan(self, scan_id: str, timeout: int = 600) -> None:
        """Wait for active scan to complete."""
        start = time.time()
        while time.time() - start < timeout:
            status = self._zap_request("/JSON/ascan/view/status/", {"scanId": scan_id})
            if int(status.get("status", 0)) >= 100:
                return
            time.sleep(5)
        raise ToolError(f"Active scan timed out after {timeout} seconds")

    async def spider(
        self,
        target: str,
        max_depth: int = 5,
        wait: bool = True,
    ) -> ToolResult:
        """Crawl a target to discover URLs."""
        # Start spider
        result = self._zap_request(
            "/JSON/spider/action/scan/",
            {"url": target, "maxChildren": max_depth}
        )
        scan_id = result.get("scan")

        if not scan_id:
            raise ToolError("Failed to start spider")

        output = [f"Spider started on {target} (scan ID: {scan_id})"]

        if wait:
            output.append("Waiting for spider to complete...")
            self._wait_for_spider(scan_id)

            # Get results
            urls = self._zap_request("/JSON/spider/view/results/", {"scanId": scan_id})
            url_list = urls.get("results", [])

            output.append(f"\nSpider complete. Discovered {len(url_list)} URLs:")
            for url in url_list[:50]:  # Limit output
                output.append(f"  • {url}")
            if len(url_list) > 50:
                output.append(f"  ... and {len(url_list) - 50} more")
        else:
            output.append("Spider running in background. Use scan_status to check progress.")

        return ToolResult(
            success=True,
            data={"scan_id": scan_id, "target": target},
            raw_output="\n".join(output),
        )

    async def active_scan(
        self,
        target: str,
        wait: bool = True,
    ) -> ToolResult:
        """Run active vulnerability scan."""
        # Start active scan
        result = self._zap_request(
            "/JSON/ascan/action/scan/",
            {"url": target, "recurse": "true"}
        )
        scan_id = result.get("scan")

        if not scan_id:
            raise ToolError("Failed to start active scan")

        output = [f"Active scan started on {target} (scan ID: {scan_id})"]

        if wait:
            output.append("Scanning for vulnerabilities (this may take several minutes)...")
            self._wait_for_scan(scan_id)

            # Get alerts
            alerts = self._zap_request("/JSON/core/view/alerts/", {"baseurl": target})
            alert_list = alerts.get("alerts", [])

            # Group by risk
            by_risk = {"High": [], "Medium": [], "Low": [], "Informational": []}
            for alert in alert_list:
                risk = alert.get("risk", "Informational")
                if risk in by_risk:
                    by_risk[risk].append(alert)

            output.append(f"\nScan complete. Found {len(alert_list)} issues:")
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
        else:
            output.append("Active scan running in background. Use scan_status to check progress.")

        return ToolResult(
            success=True,
            data={"scan_id": scan_id, "target": target},
            raw_output="\n".join(output),
        )

    async def quick_scan(
        self,
        target: str,
        max_depth: int = 5,
    ) -> ToolResult:
        """Perform complete scan: spider then active scan."""
        output = [f"Starting quick scan of {target}\n"]

        # Spider first
        output.append("Phase 1: Spidering target...")
        spider_result = self._zap_request(
            "/JSON/spider/action/scan/",
            {"url": target, "maxChildren": max_depth}
        )
        spider_id = spider_result.get("scan")
        self._wait_for_spider(spider_id)

        urls = self._zap_request("/JSON/spider/view/results/", {"scanId": spider_id})
        url_count = len(urls.get("results", []))
        output.append(f"  Discovered {url_count} URLs\n")

        # Active scan
        output.append("Phase 2: Active vulnerability scanning...")
        scan_result = self._zap_request(
            "/JSON/ascan/action/scan/",
            {"url": target, "recurse": "true"}
        )
        scan_id = scan_result.get("scan")
        self._wait_for_scan(scan_id, timeout=900)  # 15 min for full scan

        # Get alerts
        alerts = self._zap_request("/JSON/core/view/alerts/", {"baseurl": target})
        alert_list = alerts.get("alerts", [])

        # Group by risk
        by_risk = {"High": [], "Medium": [], "Low": [], "Informational": []}
        for alert in alert_list:
            risk = alert.get("risk", "Informational")
            if risk in by_risk:
                by_risk[risk].append(alert)

        output.append(f"\n{'='*50}")
        output.append("SCAN COMPLETE - VULNERABILITY SUMMARY")
        output.append(f"{'='*50}")
        output.append(f"Target: {target}")
        output.append(f"URLs Discovered: {url_count}")
        output.append(f"Total Issues: {len(alert_list)}")
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

        return ToolResult(
            success=True,
            data={
                "target": target,
                "urls_found": url_count,
                "alerts": {
                    "high": len(by_risk["High"]),
                    "medium": len(by_risk["Medium"]),
                    "low": len(by_risk["Low"]),
                    "info": len(by_risk["Informational"]),
                }
            },
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
            return ToolResult(success=True, data={}, raw_output="No alerts found.")

        output = [f"Found {len(alert_list)} alerts:"]

        for alert in alert_list:
            output.append(f"\n[{alert.get('risk', 'Unknown')}] {alert.get('alert', 'Unknown')}")
            output.append(f"  URL: {alert.get('url', 'N/A')}")
            output.append(f"  Param: {alert.get('param', 'N/A')}")
            output.append(f"  CWE: {alert.get('cweid', 'N/A')}")

        return ToolResult(
            success=True,
            data={"count": len(alert_list)},
        )

    async def get_urls(self, target: str = None) -> ToolResult:
        """Get discovered URLs."""
        urls = self._zap_request("/JSON/core/view/urls/", {"baseurl": target} if target else {})
        url_list = urls.get("urls", [])

        if not url_list:
            return ToolResult(success=True, data={}, raw_output="No URLs discovered. Run spider first.")

        output = [f"Discovered {len(url_list)} URLs:"]
        for url in url_list[:100]:
            output.append(f"  • {url}")
        if len(url_list) > 100:
            output.append(f"  ... and {len(url_list) - 100} more")

        return ToolResult(
            success=True,
            data={"count": len(url_list)},
        )

    async def scan_status(self) -> ToolResult:
        """Get status of running scans."""
        output = ["Scan Status:"]

        # Spider status
        try:
            spider = self._zap_request("/JSON/spider/view/status/")
            output.append(f"  Spider: {spider.get('status', 'N/A')}% complete")
        except:
            output.append("  Spider: Not running")

        # Active scan status
        try:
            ascan = self._zap_request("/JSON/ascan/view/status/")
            output.append(f"  Active Scan: {ascan.get('status', 'N/A')}% complete")
        except:
            output.append("  Active Scan: Not running")

        return ToolResult(success=True, data={}, raw_output="\n".join(output))

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
        request: str,
        target: str,
        follow_redirects: bool = True,
    ) -> ToolResult:
        """Send an HTTP request through ZAP (like Burp Repeater)."""
        from urllib.parse import urlparse

        parsed = urlparse(target)
        if not parsed.scheme or not parsed.netloc:
            raise ToolError("Invalid target URL. Use format: https://target.com")

        # ZAP's sendRequest API
        result = self._zap_request(
            "/JSON/core/action/sendRequest/",
            {
                "request": request,
                "followRedirects": str(follow_redirects).lower(),
            }
        )

        # Get the response
        if "sendRequest" in result:
            response_data = result["sendRequest"]
            output = [
                "REQUEST SENT",
                "=" * 40,
                f"Target: {target}",
                "",
                "Response:",
                "-" * 40,
            ]

            if isinstance(response_data, dict):
                output.append(response_data.get("responseHeader", ""))
                body = response_data.get("responseBody", "")
                if body:
                    # Truncate long bodies
                    if len(body) > 2000:
                        output.append(body[:2000] + f"\n\n... [truncated, {len(body)} bytes total]")
                    else:
                        output.append(body)
            else:
                output.append(str(response_data))

            return ToolResult(
                success=True,
                data={"target": target},
                raw_output="\n".join(output),
            )
        else:
            return ToolResult(
                success=True,
                data={"target": target},
                raw_output=f"Request sent. Response: {result}",
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


if __name__ == "__main__":
    ZapServer.main()
