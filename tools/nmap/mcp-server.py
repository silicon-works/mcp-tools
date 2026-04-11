#!/usr/bin/env python3
"""
OpenSploit MCP Server: nmap

Network scanner for port discovery, service detection, and OS fingerprinting.
Provides MCP interface to nmap functionality for the OpenSploit agent.
"""

import asyncio
import os
import re
import shlex
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
                    "enum": ["tcp_connect", "syn", "udp", "ack", "fin", "window", "null", "xmas", "maimon"],
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
                "min_rate": {
                    "type": "integer",
                    "description": "Minimum packets per second (--min-rate). Speeds up scans on reliable networks. Common values: 1000 (fast), 5000 (aggressive), 10000 (insane).",
                },
                "max_rate": {
                    "type": "integer",
                    "description": "Maximum packets per second (--max-rate). Limits scan speed to avoid detection or network overload.",
                },
                "max_retries": {
                    "type": "integer",
                    "description": "Maximum probe retransmissions (--max-retries). Default is 10. Use 1-2 for faster scans on reliable networks, 0 for no retries.",
                },
                "no_dns": {
                    "type": "boolean",
                    "default": False,
                    "description": "Skip DNS resolution (-n). Faster when you already have IP addresses and don't need hostnames.",
                },
                "open_only": {
                    "type": "boolean",
                    "default": False,
                    "description": "Only show open ports (--open). Filters out closed/filtered ports from output for cleaner results.",
                },
                "reason": {
                    "type": "boolean",
                    "default": False,
                    "description": "Show reason each port is in its state (--reason). Useful for understanding firewall behavior (e.g., 'syn-ack' vs 'no-response').",
                },
                "host_timeout": {
                    "type": "string",
                    "description": "Max time per host (--host-timeout). Examples: '30s', '5m', '1h'. Skips hosts that take too long.",
                },
                "exclude": {
                    "type": "string",
                    "description": "Hosts to exclude from scan (--exclude). Comma-separated IPs or CIDR ranges.",
                },
                "input_file": {
                    "type": "string",
                    "description": "Read targets from file (-iL). Path to a file with one target per line. Can reference /session/ files.",
                },
                "extra_args": {
                    "type": "string",
                    "description": "Additional nmap flags appended to the command (e.g., '--min-rate 10000 -D RND:5 -f --source-port 53'). Use for flags not exposed as named parameters. Flags are split by whitespace and appended safely.",
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
                "no_dns": {
                    "type": "boolean",
                    "default": False,
                    "description": "Skip DNS resolution (-n). Faster when you already have IP addresses.",
                },
                "open_only": {
                    "type": "boolean",
                    "default": False,
                    "description": "Only show open ports (--open). Filters out closed/filtered ports from output.",
                },
                "default_scripts": {
                    "type": "boolean",
                    "default": False,
                    "description": "Run default safe scripts alongside version detection (-sC). Equivalent to --script=default. Adds banner grabbing, service enumeration, and safe checks.",
                },
                "extra_args": {
                    "type": "string",
                    "description": "Additional nmap flags appended to the command (e.g., '--min-rate 5000 -n --open'). Use for flags not exposed as named parameters. Flags are split by whitespace and appended safely.",
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
                "no_dns": {
                    "type": "boolean",
                    "default": False,
                    "description": "Skip DNS resolution (-n). Faster when you already have IP addresses.",
                },
                "extra_args": {
                    "type": "string",
                    "description": "Additional nmap flags appended to the command. Use for flags not exposed as named parameters. Flags are split by whitespace and appended safely.",
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
                "no_dns": {
                    "type": "boolean",
                    "default": False,
                    "description": "Skip DNS resolution (-n). Faster when you already have IP addresses.",
                },
                "extra_args": {
                    "type": "string",
                    "description": "Additional nmap flags appended to the command (e.g., '--min-rate 5000 --script-timeout 30s'). Use for flags not exposed as named parameters. Flags are split by whitespace and appended safely.",
                },
            },
            handler=self.vuln_scan,
        )

        self.register_method(
            name="get_interfaces",
            description="Get local network interfaces and IP addresses (useful for LHOST)",
            params={
                "extra_args": {
                    "type": "string",
                    "description": "Additional flags (currently unused for get_interfaces, which uses 'ip addr' not nmap). Reserved for future use.",
                },
            },
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
                "no_dns": {
                    "type": "boolean",
                    "default": False,
                    "description": "Skip DNS resolution (-n). Faster for large subnet sweeps when you don't need hostnames.",
                },
                "exclude": {
                    "type": "string",
                    "description": "Hosts to exclude from scan (--exclude). Comma-separated IPs or CIDR ranges.",
                },
                "input_file": {
                    "type": "string",
                    "description": "Read targets from file (-iL). Path to a file with one target per line. Can reference /session/ files.",
                },
                "extra_args": {
                    "type": "string",
                    "description": "Additional nmap flags appended to the command (e.g., '--min-rate 1000 -PE'). Use for flags not exposed as named parameters. Flags are split by whitespace and appended safely.",
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
            "fin": ["-sF"],
            "window": ["-sW"],
            "null": ["-sN"],
            "xmas": ["-sX"],
            "maimon": ["-sM"],
        }
        return scan_map.get(scan_type, ["-sT"])

    @staticmethod
    def _nmap_progress_filter(line: str) -> Optional[str]:
        """Extract meaningful progress messages from nmap output.

        Returns a short string for MCP progress notifications, or None to skip.
        Matches nmap's progress lines like:
          - 'Stats: 0:01:23 elapsed; 0 hosts completed (1 up), 1 undergoing SYN Stealth Scan'
          - 'SYN Stealth Scan Timing: About 45.00% done; ETC: 12:35 (0:01:20 remaining)'
          - 'Nmap scan report for target.htb (10.10.10.1)'
          - 'Completed SYN Stealth Scan at 12:35, 120.50s elapsed (65535 total ports)'
        """
        line = line.strip()
        # nmap periodic stats (sent to stderr with --stats-every or via -v)
        if line.startswith("Stats:"):
            return line[:80]
        # Scan phase progress percentage (case-insensitive for "Service scan Timing")
        m = re.match(r"([\w\s]+[Ss]can Timing):\s*About\s+([\d.]+%)\s*done", line)
        if m:
            return f"{m.group(1)}: {m.group(2)}"
        # Completed phase
        if line.startswith("Completed "):
            return line[:80]
        # New host report (useful for subnet scans)
        if line.startswith("Nmap scan report for"):
            return line[:80]
        # Discovered open port
        if line.startswith("Discovered open port"):
            return line[:80]
        return None

    def _classify_nmap_error(self, output: str) -> tuple:
        """Classify nmap-specific errors.

        Returns (error_class, retryable, suggestions).
        """
        if not output:
            return ("unknown", False, [])

        # Host down (ICMP blocked)
        if re.search(r"host seems down|Host is down", output, re.IGNORECASE):
            return ("network", True, [
                "Target may be filtering ICMP. Retry with skip_discovery=true (-Pn)."
            ])

        # Network unreachable
        if re.search(r"Network is unreachable|No route to host", output, re.IGNORECASE):
            return ("network", True, [
                "Network is unreachable. Check VPN connection or target IP."
            ])

        # Connection refused (all ports closed or filtered, but host is up)
        if re.search(r"All \d+ scanned ports.*closed", output, re.IGNORECASE | re.DOTALL) or \
           re.search(r"All \d+ scanned ports.*ignored states", output, re.IGNORECASE):
            return ("network", False, [
                "All scanned ports are closed. Target may use non-standard ports. "
                "Try scanning all ports with ports='1-65535'."
            ])

        # Privilege required
        if re.search(
            r"requires? root|requires? privileged|Operation not permitted|QUITTING",
            output, re.IGNORECASE
        ):
            return ("permission", False, [
                "This scan type requires privileged mode (raw sockets)."
            ])

        # DNS resolution failure
        if re.search(r"Failed to resolve|could not resolve", output, re.IGNORECASE):
            return ("config", False, [
                "DNS resolution failed. Use an IP address or check /etc/hosts."
            ])

        return ("unknown", False, [])

    async def _run_nmap(
        self,
        target: str,
        extra_args: List[str],
        timeout: int = 600,
    ) -> ToolResult:
        """
        Run nmap with XML output, progress heartbeats, and parse results.

        Uses run_command_with_progress to send periodic heartbeats that
        prevent the MCP client from killing long-running scans.

        Args:
            target: Target to scan
            extra_args: Additional nmap arguments
            timeout: Command timeout in seconds (default 600, matching registry)

        Returns:
            ToolResult with parsed nmap data
        """
        # Create temp file for XML output
        with tempfile.NamedTemporaryFile(mode="w", suffix=".xml", delete=False) as f:
            xml_file = f.name

        try:
            # Build command — add -v for progress output on stderr
            cmd = ["nmap", "-v", "-oX", xml_file] + extra_args + [target]

            # Run nmap with heartbeat support
            result = await self.run_command_with_progress(
                cmd,
                progress_filter=self._nmap_progress_filter,
                heartbeat_interval=30.0,
            )

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
            # Classify the error
            error_class, retryable, suggestions = self._classify_nmap_error(str(e))
            return ToolResult(
                success=False,
                data={},
                error=str(e),
                error_class=error_class,
                retryable=retryable,
                suggestions=suggestions,
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
        min_rate: Optional[int] = None,
        max_rate: Optional[int] = None,
        max_retries: Optional[int] = None,
        no_dns: bool = False,
        open_only: bool = False,
        reason: bool = False,
        host_timeout: Optional[str] = None,
        exclude: Optional[str] = None,
        input_file: Optional[str] = None,
        extra_args: Optional[str] = None,
    ) -> ToolResult:
        """
        Scan for open ports on a target.

        Args:
            target: IP address, hostname, or CIDR range
            ports: Port range to scan
            scan_type: Type of scan (tcp_connect, syn, udp, ack, fin, window, null, xmas, maimon)
            timing: Scan timing (paranoid to insane)
            skip_discovery: Skip host discovery (-Pn)
            top_ports: Scan N most common ports (mutually exclusive with ports)
            min_rate: Minimum packets per second (--min-rate)
            max_rate: Maximum packets per second (--max-rate)
            max_retries: Maximum probe retransmissions (--max-retries)
            no_dns: Skip DNS resolution (-n)
            open_only: Only show open ports (--open)
            reason: Show reason for port state (--reason)
            host_timeout: Max time per host (--host-timeout)
            exclude: Hosts to exclude (--exclude)
            input_file: Read targets from file (-iL)
            extra_args: Additional nmap flags as a string, split by whitespace

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
        if min_rate is not None:
            args.extend(["--min-rate", str(min_rate)])
        if max_rate is not None:
            args.extend(["--max-rate", str(max_rate)])
        if max_retries is not None:
            args.extend(["--max-retries", str(max_retries)])
        if no_dns:
            args.append("-n")
        if open_only:
            args.append("--open")
        if reason:
            args.append("--reason")
        if host_timeout:
            args.extend(["--host-timeout", host_timeout])
        if exclude:
            args.extend(["--exclude", exclude])
        if input_file:
            args.extend(["-iL", input_file])
        if extra_args:
            args.extend(shlex.split(extra_args))

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
        no_dns: bool = False,
        open_only: bool = False,
        default_scripts: bool = False,
        extra_args: Optional[str] = None,
    ) -> ToolResult:
        """
        Identify service versions on open ports.

        Args:
            target: IP address or hostname
            ports: Ports to scan (comma-separated or range)
            skip_discovery: Skip host discovery (-Pn)
            version_intensity: Version detection intensity 0-9
            no_dns: Skip DNS resolution (-n)
            open_only: Only show open ports (--open)
            default_scripts: Run default safe scripts (-sC) alongside version detection
            extra_args: Additional nmap flags as a string, split by whitespace

        Returns:
            ToolResult with service version information
        """
        self.logger.info(f"Starting service scan on {target}, ports={ports}")

        args = ["-sV", "-p", ports]
        if skip_discovery:
            args.append("-Pn")
        if version_intensity is not None:
            args.extend(["--version-intensity", str(version_intensity)])
        if no_dns:
            args.append("-n")
        if open_only:
            args.append("--open")
        if default_scripts:
            args.append("-sC")
        if extra_args:
            args.extend(shlex.split(extra_args))

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
        no_dns: bool = False,
        extra_args: Optional[str] = None,
    ) -> ToolResult:
        """
        Detect operating system of target.

        Note: OS detection typically requires root/privileged access.

        Args:
            target: IP address or hostname
            skip_discovery: Skip host discovery (-Pn)
            no_dns: Skip DNS resolution (-n)
            extra_args: Additional nmap flags as a string, split by whitespace

        Returns:
            ToolResult with OS detection results
        """
        self.logger.info(f"Starting OS detection on {target}")

        args = ["-O", "--osscan-guess"]
        if skip_discovery:
            args.append("-Pn")
        if no_dns:
            args.append("-n")
        if extra_args:
            args.extend(shlex.split(extra_args))

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
        no_dns: bool = False,
        extra_args: Optional[str] = None,
    ) -> ToolResult:
        """
        Run NSE vulnerability scripts against target.

        Args:
            target: IP address or hostname
            ports: Ports to scan
            scripts: NSE script category or specific scripts
            script_args: Arguments for NSE scripts
            skip_discovery: Skip host discovery (-Pn)
            no_dns: Skip DNS resolution (-n)
            extra_args: Additional nmap flags as a string, split by whitespace

        Returns:
            ToolResult with vulnerability findings
        """
        self.logger.info(f"Starting vuln scan on {target}, ports={ports}, scripts={scripts}")

        args = ["-sV", "-p", ports, "--script", scripts]
        if script_args:
            args.extend(["--script-args", script_args])
        if skip_discovery:
            args.append("-Pn")
        if no_dns:
            args.append("-n")
        if extra_args:
            args.extend(shlex.split(extra_args))

        result = await self._run_nmap(target, args, timeout=600)

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
        no_dns: bool = False,
        exclude: Optional[str] = None,
        input_file: Optional[str] = None,
        extra_args: Optional[str] = None,
    ) -> ToolResult:
        """
        Discover live hosts on a network without port scanning.

        Args:
            target: CIDR range or target (e.g., '192.168.1.0/24')
            timing: Scan timing (paranoid to insane)
            no_dns: Skip DNS resolution (-n)
            exclude: Hosts to exclude (--exclude)
            input_file: Read targets from file (-iL)
            extra_args: Additional nmap flags as a string, split by whitespace

        Returns:
            ToolResult with discovered live hosts
        """
        self.logger.info(f"Starting ping scan on {target}")

        args = ["-sn", self._get_timing_flag(timing)]
        if no_dns:
            args.append("-n")
        if exclude:
            args.extend(["--exclude", exclude])
        if input_file:
            args.extend(["-iL", input_file])
        if extra_args:
            args.extend(shlex.split(extra_args))
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

    async def get_interfaces(self, extra_args: Optional[str] = None) -> ToolResult:
        """
        Get local network interfaces and IP addresses.

        Useful for determining LHOST for reverse shells.

        Returns:
            ToolResult with interface information
        """
        self.logger.info("Getting local network interfaces")

        try:
            # Use ip addr to get interface info
            result = await self.run_command_with_progress(["ip", "-j", "addr"])
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
