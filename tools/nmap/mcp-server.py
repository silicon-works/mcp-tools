#!/usr/bin/env python3
"""
OpenSploit MCP Server: nmap

Network scanner for port discovery, service detection, and OS fingerprinting.
Provides MCP interface to nmap functionality for the OpenSploit agent.
"""

import asyncio
import os
import tempfile
from typing import Any, Dict, List, Optional

from mcp_common import BaseMCPServer, ToolResult, ToolError, parse_nmap_xml, sanitize_output


class NmapServer(BaseMCPServer):
    """MCP server wrapping nmap network scanner."""

    def __init__(self):
        super().__init__(
            name="nmap",
            description="Network scanner for port discovery, service detection, and OS fingerprinting",
            version="1.0.0",
        )

        # Register methods
        self.register_method(
            name="port_scan",
            description="Scan for open ports on a target",
            params={
                "target": {
                    "type": "string",
                    "required": True,
                    "description": "IP address, hostname, or CIDR range",
                },
                "ports": {
                    "type": "string",
                    "default": "1-1000",
                    "description": "Port range (e.g., '22,80,443' or '1-1000')",
                },
                "scan_type": {
                    "type": "string",
                    "enum": ["tcp_connect", "syn", "udp", "ack"],
                    "default": "tcp_connect",
                    "description": "Type of port scan",
                },
                "timing": {
                    "type": "string",
                    "enum": ["paranoid", "sneaky", "polite", "normal", "aggressive", "insane"],
                    "default": "normal",
                    "description": "Scan timing template (T0-T5)",
                },
                "skip_discovery": {
                    "type": "boolean",
                    "default": False,
                    "description": "Skip host discovery (-Pn). Use when target filters ICMP and shows as 'down'.",
                },
                "top_ports": {
                    "type": "integer",
                    "description": "Scan the N most common ports instead of a range. Mutually exclusive with 'ports'. Common values: 100 (fast), 1000 (thorough).",
                },
            },
            handler=self.port_scan,
        )

        self.register_method(
            name="service_scan",
            description="Identify service versions on open ports",
            params={
                "target": {
                    "type": "string",
                    "required": True,
                    "description": "IP address or hostname",
                },
                "ports": {
                    "type": "string",
                    "required": True,
                    "description": "Ports to scan (from previous port_scan results)",
                },
                "skip_discovery": {
                    "type": "boolean",
                    "default": False,
                    "description": "Skip host discovery (-Pn). Use when target filters ICMP and shows as 'down'.",
                },
                "version_intensity": {
                    "type": "integer",
                    "description": "Version detection probe intensity 0-9. Default uses nmap's default 7. Use 2 for fast, 9 for thorough.",
                },
            },
            handler=self.service_scan,
        )

        self.register_method(
            name="os_detection",
            description="Detect operating system of target",
            params={
                "target": {
                    "type": "string",
                    "required": True,
                    "description": "IP address or hostname",
                },
                "skip_discovery": {
                    "type": "boolean",
                    "default": False,
                    "description": "Skip host discovery (-Pn). Use when target filters ICMP and shows as 'down'.",
                },
            },
            handler=self.os_detection,
        )

        self.register_method(
            name="vuln_scan",
            description="Run NSE vulnerability scripts against target",
            params={
                "target": {
                    "type": "string",
                    "required": True,
                    "description": "IP address or hostname",
                },
                "ports": {
                    "type": "string",
                    "required": True,
                    "description": "Ports to scan",
                },
                "scripts": {
                    "type": "string",
                    "default": "vuln",
                    "description": "NSE script category or specific scripts",
                },
                "script_args": {
                    "type": "string",
                    "description": "Arguments for NSE scripts (e.g., 'userdb=users.txt,passdb=pass.txt' for brute scripts)",
                },
                "skip_discovery": {
                    "type": "boolean",
                    "default": False,
                    "description": "Skip host discovery (-Pn). Use when target filters ICMP and shows as 'down'.",
                },
            },
            handler=self.vuln_scan,
        )

        self.register_method(
            name="get_interfaces",
            description="Get local network interfaces and IP addresses (useful for LHOST)",
            params={},
            handler=self.get_interfaces,
        )

        self.register_method(
            name="ping_scan",
            description="Discover live hosts on a network (no port scan)",
            params={
                "target": {
                    "type": "string",
                    "required": True,
                    "description": "CIDR range or target (e.g., '192.168.1.0/24')",
                },
                "timing": {
                    "type": "string",
                    "enum": ["paranoid", "sneaky", "polite", "normal", "aggressive", "insane"],
                    "default": "normal",
                    "description": "Timing template",
                },
            },
            handler=self.ping_scan,
        )

    def _get_timing_flag(self, timing: str) -> str:
        """Convert timing name to nmap flag."""
        timing_map = {
            "paranoid": "-T0",
            "sneaky": "-T1",
            "polite": "-T2",
            "normal": "-T3",
            "aggressive": "-T4",
            "insane": "-T5",
        }
        return timing_map.get(timing, "-T3")

    def _get_scan_type_flags(self, scan_type: str) -> List[str]:
        """Convert scan type to nmap flags."""
        scan_map = {
            "tcp_connect": ["-sT"],
            "syn": ["-sS"],
            "udp": ["-sU"],
            "ack": ["-sA"],
        }
        return scan_map.get(scan_type, ["-sT"])

    async def _run_nmap(
        self,
        target: str,
        extra_args: List[str],
        timeout: int = 300,
    ) -> ToolResult:
        """
        Run nmap with XML output and parse results.

        Args:
            target: Target to scan
            extra_args: Additional nmap arguments
            timeout: Command timeout in seconds

        Returns:
            ToolResult with parsed nmap data
        """
        # Create temp file for XML output
        with tempfile.NamedTemporaryFile(mode="w", suffix=".xml", delete=False) as f:
            xml_file = f.name

        try:
            # Build command
            cmd = ["nmap", "-oX", xml_file] + extra_args + [target]

            # Run nmap
            result = await self.run_command(cmd, timeout=timeout)

            # Read XML output
            if os.path.exists(xml_file):
                with open(xml_file, "r") as f:
                    xml_output = f.read()

                parsed = parse_nmap_xml(xml_output)

                return ToolResult(
                    success=True,
                    data=parsed,
                    raw_output=sanitize_output(result.stdout + result.stderr),
                )
            else:
                return ToolResult(
                    success=False,
                    data={},
                    raw_output=sanitize_output(result.stdout + result.stderr),
                    error="nmap did not produce XML output",
                )

        except ToolError as e:
            return ToolResult(
                success=False,
                data={},
                error=str(e),
            )
        finally:
            # Cleanup temp file
            if os.path.exists(xml_file):
                os.unlink(xml_file)

    async def port_scan(
        self,
        target: str,
        ports: str = "1-1000",
        scan_type: str = "tcp_connect",
        timing: str = "normal",
        skip_discovery: bool = False,
        top_ports: Optional[int] = None,
    ) -> ToolResult:
        """
        Scan for open ports on a target.

        Args:
            target: IP address, hostname, or CIDR range
            ports: Port range to scan
            scan_type: Type of scan (tcp_connect, syn, udp, ack)
            timing: Scan timing (paranoid to insane)
            skip_discovery: Skip host discovery (-Pn)
            top_ports: Scan N most common ports (mutually exclusive with ports)

        Returns:
            ToolResult with discovered ports and services
        """
        self.logger.info(f"Starting port scan on {target}, ports={ports}, type={scan_type}")

        args = self._get_scan_type_flags(scan_type)
        args.append(self._get_timing_flag(timing))
        if skip_discovery:
            args.append("-Pn")
        if top_ports:
            args.extend(["--top-ports", str(top_ports)])
        else:
            args.extend(["-p", ports])

        result = await self._run_nmap(target, args)

        # Extract summary for easier consumption
        if result.success and result.data.get("hosts"):
            host = result.data["hosts"][0]
            open_ports = [
                p["port"] for p in host.get("ports", [])
                if p.get("state") == "open"
            ]
            result.data["summary"] = {
                "target": target,
                "open_ports": open_ports,
                "total_open": len(open_ports),
            }

        return result

    async def service_scan(
        self,
        target: str,
        ports: str,
        skip_discovery: bool = False,
        version_intensity: Optional[int] = None,
    ) -> ToolResult:
        """
        Identify service versions on open ports.

        Args:
            target: IP address or hostname
            ports: Ports to scan (comma-separated or range)
            skip_discovery: Skip host discovery (-Pn)
            version_intensity: Version detection intensity 0-9

        Returns:
            ToolResult with service version information
        """
        self.logger.info(f"Starting service scan on {target}, ports={ports}")

        args = ["-sV", "-p", ports]
        if skip_discovery:
            args.append("-Pn")
        if version_intensity is not None:
            args.extend(["--version-intensity", str(version_intensity)])

        result = await self._run_nmap(target, args, timeout=600)

        # Extract service summary
        if result.success and result.data.get("hosts"):
            host = result.data["hosts"][0]
            services = []
            for port in host.get("ports", []):
                if port.get("state") == "open" and port.get("service"):
                    svc = port["service"]
                    services.append({
                        "port": port["port"],
                        "protocol": port["protocol"],
                        "service": svc.get("name", "unknown"),
                        "product": svc.get("product", ""),
                        "version": svc.get("version", ""),
                        "extrainfo": svc.get("extrainfo", ""),
                    })
            result.data["services_summary"] = services

        return result

    async def os_detection(
        self,
        target: str,
        skip_discovery: bool = False,
    ) -> ToolResult:
        """
        Detect operating system of target.

        Note: OS detection typically requires root/privileged access.

        Args:
            target: IP address or hostname
            skip_discovery: Skip host discovery (-Pn)

        Returns:
            ToolResult with OS detection results
        """
        self.logger.info(f"Starting OS detection on {target}")

        args = ["-O", "--osscan-guess"]
        if skip_discovery:
            args.append("-Pn")

        result = await self._run_nmap(target, args, timeout=300)

        # Extract OS summary
        if result.success and result.data.get("hosts"):
            host = result.data["hosts"][0]
            os_matches = host.get("os_matches", [])
            if os_matches:
                result.data["os_summary"] = {
                    "best_match": os_matches[0]["name"] if os_matches else "unknown",
                    "confidence": os_matches[0]["accuracy"] if os_matches else 0,
                    "all_matches": os_matches,
                }

        return result

    async def vuln_scan(
        self,
        target: str,
        ports: str,
        scripts: str = "vuln",
        script_args: Optional[str] = None,
        skip_discovery: bool = False,
    ) -> ToolResult:
        """
        Run NSE vulnerability scripts against target.

        Args:
            target: IP address or hostname
            ports: Ports to scan
            scripts: NSE script category or specific scripts
            script_args: Arguments for NSE scripts
            skip_discovery: Skip host discovery (-Pn)

        Returns:
            ToolResult with vulnerability findings
        """
        self.logger.info(f"Starting vuln scan on {target}, ports={ports}, scripts={scripts}")

        args = ["-sV", "-p", ports, "--script", scripts]
        if script_args:
            args.extend(["--script-args", script_args])
        if skip_discovery:
            args.append("-Pn")

        result = await self._run_nmap(target, args, timeout=900)

        # Extract vulnerability findings
        if result.success and result.data.get("hosts"):
            host = result.data["hosts"][0]
            vulns = []
            for port in host.get("ports", []):
                for script in port.get("scripts", []):
                    # Check if this looks like a vulnerability finding
                    output = script.get("output", "").lower()
                    if any(word in output for word in ["vulnerable", "cve-", "exploit", "critical", "high"]):
                        vulns.append({
                            "port": port["port"],
                            "script": script["id"],
                            "output": script["output"],
                        })
            result.data["vulnerabilities"] = vulns
            result.data["vuln_count"] = len(vulns)

        return result

    async def ping_scan(
        self,
        target: str,
        timing: str = "normal",
    ) -> ToolResult:
        """
        Discover live hosts on a network without port scanning.

        Args:
            target: CIDR range or target (e.g., '192.168.1.0/24')
            timing: Scan timing (paranoid to insane)

        Returns:
            ToolResult with discovered live hosts
        """
        self.logger.info(f"Starting ping scan on {target}")

        args = ["-sn", self._get_timing_flag(timing)]
        result = await self._run_nmap(target, args, timeout=120)

        if result.success and result.data.get("hosts"):
            live_hosts = [
                h["addresses"][0]["addr"]
                if h.get("addresses")
                else "unknown"
                for h in result.data["hosts"]
                if h.get("status") == "up"
            ]
            result.data["live_hosts"] = live_hosts
            result.data["total_live"] = len(live_hosts)

        return result

    async def get_interfaces(self) -> ToolResult:
        """
        Get local network interfaces and IP addresses.

        Useful for determining LHOST for reverse shells.

        Returns:
            ToolResult with interface information
        """
        self.logger.info("Getting local network interfaces")

        try:
            # Use ip addr to get interface info
            result = await self.run_command(["ip", "-j", "addr"], timeout=10)
            output = result.stdout

            import json as json_module
            import re

            interfaces = []
            try:
                # Parse JSON output from ip -j addr
                data = json_module.loads(output)
                for iface in data:
                    iface_info = {
                        "name": iface.get("ifname", ""),
                        "state": iface.get("operstate", ""),
                        "mac": iface.get("address", ""),
                        "ipv4": [],
                        "ipv6": [],
                    }
                    for addr_info in iface.get("addr_info", []):
                        if addr_info.get("family") == "inet":
                            iface_info["ipv4"].append(addr_info.get("local", ""))
                        elif addr_info.get("family") == "inet6":
                            iface_info["ipv6"].append(addr_info.get("local", ""))

                    # Only include interfaces with IP addresses
                    if iface_info["ipv4"] or iface_info["ipv6"]:
                        interfaces.append(iface_info)
            except json_module.JSONDecodeError:
                # Fallback: parse text output
                pass

            # Find the best LHOST candidate (first non-loopback IPv4)
            lhost = None
            for iface in interfaces:
                if iface["name"] != "lo" and iface["ipv4"]:
                    lhost = iface["ipv4"][0]
                    break

            return ToolResult(
                success=True,
                data={
                    "interfaces": interfaces,
                    "recommended_lhost": lhost,
                },
                raw_output=sanitize_output(output),
            )

        except ToolError as e:
            return ToolResult(
                success=False,
                data={},
                error=str(e),
            )


if __name__ == "__main__":
    NmapServer.main()
