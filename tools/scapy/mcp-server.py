#!/usr/bin/env python3
"""
OpenSploit MCP Server: scapy

Packet crafting and protocol testing tool using Scapy.
Supports custom packet construction, UDP testing, and protocol manipulation.
"""

import asyncio
import base64
import struct
from typing import Any, Dict, List, Optional

from mcp_common import BaseMCPServer, ToolResult, ToolError, sanitize_output

# Import scapy with warnings suppressed
import warnings
warnings.filterwarnings("ignore")

from scapy.all import (
    IP, TCP, UDP, ICMP, Raw, Ether, ARP,
    sr1, sr, send, sendp, sniff,
    DNS, DNSQR, DNSRR,
    hexdump, bytes_hex,
    conf,
)


class ScapyServer(BaseMCPServer):
    """MCP server for packet crafting and protocol testing using Scapy."""

    def __init__(self):
        super().__init__(
            name="scapy",
            description="Packet crafting and protocol testing for UDP, custom protocols, and raw socket operations",
            version="1.0.0",
        )

        # Disable Scapy verbosity
        conf.verb = 0

        # Register methods
        self.register_method(
            name="udp_send",
            description="Send a UDP packet to a target",
            params={
                "target": {
                    "type": "string",
                    "required": True,
                    "description": "Target IP address",
                },
                "port": {
                    "type": "integer",
                    "required": True,
                    "description": "Target UDP port",
                },
                "data": {
                    "type": "string",
                    "required": True,
                    "description": "Payload data (string or hex with 0x prefix)",
                },
                "sport": {
                    "type": "integer",
                    "default": 0,
                    "description": "Source port (0 = random)",
                },
                "timeout": {
                    "type": "integer",
                    "default": 5,
                    "description": "Response timeout in seconds",
                },
            },
            handler=self.udp_send,
        )

        self.register_method(
            name="udp_probe",
            description="Send UDP probes to discover services",
            params={
                "target": {
                    "type": "string",
                    "required": True,
                    "description": "Target IP address",
                },
                "ports": {
                    "type": "string",
                    "required": True,
                    "description": "Ports to probe (comma-separated or range)",
                },
                "probe_data": {
                    "type": "string",
                    "default": "",
                    "description": "Custom probe data (empty for default probes)",
                },
                "timeout": {
                    "type": "integer",
                    "default": 3,
                    "description": "Timeout per probe",
                },
            },
            handler=self.udp_probe,
        )

        self.register_method(
            name="tcp_syn",
            description="Send TCP SYN packet (for custom port probing)",
            params={
                "target": {
                    "type": "string",
                    "required": True,
                    "description": "Target IP address",
                },
                "port": {
                    "type": "integer",
                    "required": True,
                    "description": "Target port",
                },
                "timeout": {
                    "type": "integer",
                    "default": 3,
                    "description": "Response timeout",
                },
            },
            handler=self.tcp_syn,
        )

        self.register_method(
            name="icmp_ping",
            description="Send ICMP echo request",
            params={
                "target": {
                    "type": "string",
                    "required": True,
                    "description": "Target IP address",
                },
                "count": {
                    "type": "integer",
                    "default": 1,
                    "description": "Number of pings to send",
                },
                "timeout": {
                    "type": "integer",
                    "default": 3,
                    "description": "Response timeout",
                },
            },
            handler=self.icmp_ping,
        )

        self.register_method(
            name="dns_query",
            description="Send DNS query to a server",
            params={
                "server": {
                    "type": "string",
                    "required": True,
                    "description": "DNS server IP",
                },
                "domain": {
                    "type": "string",
                    "required": True,
                    "description": "Domain to query",
                },
                "query_type": {
                    "type": "string",
                    "enum": ["A", "AAAA", "MX", "NS", "TXT", "SOA", "CNAME", "PTR", "ANY"],
                    "default": "A",
                    "description": "DNS query type",
                },
                "timeout": {
                    "type": "integer",
                    "default": 5,
                    "description": "Response timeout",
                },
            },
            handler=self.dns_query,
        )

        self.register_method(
            name="craft_packet",
            description="Craft and send a custom packet from specification",
            params={
                "target": {
                    "type": "string",
                    "required": True,
                    "description": "Target IP address",
                },
                "protocol": {
                    "type": "string",
                    "enum": ["tcp", "udp", "icmp"],
                    "required": True,
                    "description": "Protocol layer",
                },
                "port": {
                    "type": "integer",
                    "description": "Destination port (for TCP/UDP)",
                },
                "flags": {
                    "type": "string",
                    "default": "S",
                    "description": "TCP flags (S=SYN, A=ACK, F=FIN, R=RST, P=PSH, U=URG)",
                },
                "payload_hex": {
                    "type": "string",
                    "description": "Payload as hex string (without 0x prefix)",
                },
                "payload_ascii": {
                    "type": "string",
                    "description": "Payload as ASCII string",
                },
                "timeout": {
                    "type": "integer",
                    "default": 5,
                    "description": "Response timeout",
                },
            },
            handler=self.craft_packet,
        )

        self.register_method(
            name="arp_scan",
            description="Perform ARP scan on local network",
            params={
                "network": {
                    "type": "string",
                    "required": True,
                    "description": "Network range (e.g., 192.168.1.0/24)",
                },
                "timeout": {
                    "type": "integer",
                    "default": 3,
                    "description": "Response timeout",
                },
            },
            handler=self.arp_scan,
        )

        self.register_method(
            name="snmp_get",
            description="Send SNMP GET request (community string testing)",
            params={
                "target": {
                    "type": "string",
                    "required": True,
                    "description": "Target IP address",
                },
                "community": {
                    "type": "string",
                    "default": "public",
                    "description": "SNMP community string",
                },
                "oid": {
                    "type": "string",
                    "default": "1.3.6.1.2.1.1.1.0",
                    "description": "OID to query (default: sysDescr)",
                },
                "port": {
                    "type": "integer",
                    "default": 161,
                    "description": "SNMP port",
                },
                "timeout": {
                    "type": "integer",
                    "default": 5,
                    "description": "Response timeout",
                },
            },
            handler=self.snmp_get,
        )

    def _parse_hex_payload(self, data: str) -> bytes:
        """Parse payload that may be hex or ascii."""
        if data.startswith("0x"):
            return bytes.fromhex(data[2:])
        return data.encode()

    def _parse_ports(self, ports_str: str) -> List[int]:
        """Parse port specification into list of ports."""
        ports = []
        for part in ports_str.split(","):
            part = part.strip()
            if "-" in part:
                start, end = part.split("-")
                ports.extend(range(int(start), int(end) + 1))
            else:
                ports.append(int(part))
        return ports

    def _packet_summary(self, pkt) -> Dict[str, Any]:
        """Create summary of packet."""
        if pkt is None:
            return {"received": False}

        summary = {
            "received": True,
            "summary": pkt.summary(),
        }

        if IP in pkt:
            summary["src_ip"] = pkt[IP].src
            summary["dst_ip"] = pkt[IP].dst
            summary["ttl"] = pkt[IP].ttl

        if TCP in pkt:
            summary["src_port"] = pkt[TCP].sport
            summary["dst_port"] = pkt[TCP].dport
            summary["tcp_flags"] = pkt[TCP].flags.flagrepr()

        if UDP in pkt:
            summary["src_port"] = pkt[UDP].sport
            summary["dst_port"] = pkt[UDP].dport

        if ICMP in pkt:
            summary["icmp_type"] = pkt[ICMP].type
            summary["icmp_code"] = pkt[ICMP].code

        if Raw in pkt:
            raw_data = bytes(pkt[Raw])
            summary["payload_hex"] = raw_data.hex()
            try:
                summary["payload_ascii"] = raw_data.decode('utf-8', errors='replace')
            except:
                summary["payload_ascii"] = None
            summary["payload_len"] = len(raw_data)

        return summary

    async def udp_send(
        self,
        target: str,
        port: int,
        data: str,
        sport: int = 0,
        timeout: int = 5,
    ) -> ToolResult:
        """
        Send UDP packet and wait for response.

        Args:
            target: Target IP
            port: Target port
            data: Payload data
            sport: Source port (0 = random)
            timeout: Response timeout

        Returns:
            ToolResult with response data
        """
        self.logger.info(f"Sending UDP packet to {target}:{port}")

        try:
            payload = self._parse_hex_payload(data)

            pkt = IP(dst=target) / UDP(sport=sport if sport else 12345, dport=port) / Raw(load=payload)

            # Send and wait for response
            resp = sr1(pkt, timeout=timeout, verbose=0)

            response_data = self._packet_summary(resp)
            response_data["target"] = target
            response_data["port"] = port
            response_data["sent_bytes"] = len(payload)

            return ToolResult(
                success=True,
                data=response_data,
                raw_output=f"Sent {len(payload)} bytes to {target}:{port}, response: {response_data.get('received', False)}",
            )
        except Exception as e:
            return ToolResult(
                success=False,
                data={},
                error=str(e),
            )

    async def udp_probe(
        self,
        target: str,
        ports: str,
        probe_data: str = "",
        timeout: int = 3,
    ) -> ToolResult:
        """
        Probe UDP ports to discover services.

        Args:
            target: Target IP
            ports: Port specification
            probe_data: Custom probe data
            timeout: Timeout per probe

        Returns:
            ToolResult with discovered services
        """
        self.logger.info(f"UDP probing {target} on ports {ports}")

        try:
            port_list = self._parse_ports(ports)
            results = []

            # Default probes for common services
            default_probes = {
                53: b"\x00\x00\x10\x00\x00\x00\x00\x00\x00\x00\x00\x00",  # DNS
                161: b"\x30\x26\x02\x01\x01\x04\x06public",  # SNMP
                123: b"\x1b" + b"\x00" * 47,  # NTP
                137: b"\x80\x94\x00\x00\x00\x01\x00\x00\x00\x00\x00\x00",  # NetBIOS
                500: b"\x00" * 28,  # IKE
            }

            for port in port_list:
                # Use custom probe or default
                if probe_data:
                    payload = self._parse_hex_payload(probe_data)
                else:
                    payload = default_probes.get(port, b"\x00")

                pkt = IP(dst=target) / UDP(dport=port) / Raw(load=payload)
                resp = sr1(pkt, timeout=timeout, verbose=0)

                result = {
                    "port": port,
                    "state": "open|filtered" if resp is None else "open",
                    "response": self._packet_summary(resp) if resp else None,
                }

                if resp and ICMP in resp:
                    if resp[ICMP].type == 3:  # Destination unreachable
                        result["state"] = "closed"

                results.append(result)

            open_ports = [r for r in results if r["state"] in ["open", "open|filtered"]]

            return ToolResult(
                success=True,
                data={
                    "target": target,
                    "results": results,
                    "open_ports": [r["port"] for r in open_ports],
                    "total_probed": len(port_list),
                },
                raw_output=f"Probed {len(port_list)} UDP ports, {len(open_ports)} potentially open",
            )
        except Exception as e:
            return ToolResult(
                success=False,
                data={},
                error=str(e),
            )

    async def tcp_syn(
        self,
        target: str,
        port: int,
        timeout: int = 3,
    ) -> ToolResult:
        """
        Send TCP SYN packet for port probing.

        Args:
            target: Target IP
            port: Target port
            timeout: Response timeout

        Returns:
            ToolResult with port state
        """
        self.logger.info(f"TCP SYN probe to {target}:{port}")

        try:
            pkt = IP(dst=target) / TCP(dport=port, flags="S")
            resp = sr1(pkt, timeout=timeout, verbose=0)

            state = "filtered"
            if resp:
                if TCP in resp:
                    flags = resp[TCP].flags
                    if flags & 0x12:  # SYN-ACK
                        state = "open"
                        # Send RST to close
                        send(IP(dst=target) / TCP(dport=port, flags="R"), verbose=0)
                    elif flags & 0x14:  # RST-ACK
                        state = "closed"
                elif ICMP in resp:
                    state = "filtered"

            return ToolResult(
                success=True,
                data={
                    "target": target,
                    "port": port,
                    "state": state,
                    "response": self._packet_summary(resp),
                },
                raw_output=f"Port {port}: {state}",
            )
        except Exception as e:
            return ToolResult(
                success=False,
                data={},
                error=str(e),
            )

    async def icmp_ping(
        self,
        target: str,
        count: int = 1,
        timeout: int = 3,
    ) -> ToolResult:
        """
        Send ICMP echo request (ping).

        Args:
            target: Target IP
            count: Number of pings
            timeout: Response timeout

        Returns:
            ToolResult with ping results
        """
        self.logger.info(f"ICMP ping to {target}")

        try:
            results = []
            for i in range(count):
                pkt = IP(dst=target) / ICMP(type=8, code=0) / Raw(load=b"A" * 32)
                resp = sr1(pkt, timeout=timeout, verbose=0)

                results.append({
                    "seq": i,
                    "received": resp is not None,
                    "response": self._packet_summary(resp) if resp else None,
                })

            received = sum(1 for r in results if r["received"])

            return ToolResult(
                success=True,
                data={
                    "target": target,
                    "sent": count,
                    "received": received,
                    "loss_percent": ((count - received) / count) * 100,
                    "results": results,
                },
                raw_output=f"Ping {target}: {received}/{count} received",
            )
        except Exception as e:
            return ToolResult(
                success=False,
                data={},
                error=str(e),
            )

    async def dns_query(
        self,
        server: str,
        domain: str,
        query_type: str = "A",
        timeout: int = 5,
    ) -> ToolResult:
        """
        Send DNS query.

        Args:
            server: DNS server IP
            domain: Domain to query
            query_type: Query type
            timeout: Response timeout

        Returns:
            ToolResult with DNS response
        """
        self.logger.info(f"DNS query for {domain} ({query_type}) to {server}")

        try:
            qtype_map = {
                "A": 1, "AAAA": 28, "MX": 15, "NS": 2,
                "TXT": 16, "SOA": 6, "CNAME": 5, "PTR": 12, "ANY": 255,
            }

            pkt = IP(dst=server) / UDP(dport=53) / DNS(
                rd=1,
                qd=DNSQR(qname=domain, qtype=qtype_map.get(query_type, 1))
            )

            resp = sr1(pkt, timeout=timeout, verbose=0)

            if resp and DNS in resp:
                dns_resp = resp[DNS]
                answers = []
                for i in range(dns_resp.ancount):
                    rr = dns_resp.an[i]
                    answers.append({
                        "name": str(rr.rrname),
                        "type": rr.type,
                        "data": str(rr.rdata) if hasattr(rr, 'rdata') else None,
                        "ttl": rr.ttl,
                    })

                return ToolResult(
                    success=True,
                    data={
                        "server": server,
                        "domain": domain,
                        "query_type": query_type,
                        "response_code": dns_resp.rcode,
                        "answers": answers,
                        "answer_count": dns_resp.ancount,
                    },
                    raw_output=f"DNS {query_type} {domain}: {len(answers)} answers",
                )
            else:
                return ToolResult(
                    success=True,
                    data={
                        "server": server,
                        "domain": domain,
                        "query_type": query_type,
                        "response": None,
                    },
                    raw_output=f"No DNS response from {server}",
                )
        except Exception as e:
            return ToolResult(
                success=False,
                data={},
                error=str(e),
            )

    async def craft_packet(
        self,
        target: str,
        protocol: str,
        port: int = None,
        flags: str = "S",
        payload_hex: str = None,
        payload_ascii: str = None,
        timeout: int = 5,
    ) -> ToolResult:
        """
        Craft and send a custom packet.

        Args:
            target: Target IP
            protocol: Protocol (tcp, udp, icmp)
            port: Destination port
            flags: TCP flags
            payload_hex: Payload as hex
            payload_ascii: Payload as ASCII
            timeout: Response timeout

        Returns:
            ToolResult with response
        """
        self.logger.info(f"Crafting {protocol.upper()} packet to {target}")

        try:
            # Build payload
            if payload_hex:
                payload = bytes.fromhex(payload_hex)
            elif payload_ascii:
                payload = payload_ascii.encode()
            else:
                payload = b""

            # Build packet
            ip_layer = IP(dst=target)

            if protocol.lower() == "tcp":
                if not port:
                    return ToolResult(success=False, data={}, error="Port required for TCP")
                pkt = ip_layer / TCP(dport=port, flags=flags)
            elif protocol.lower() == "udp":
                if not port:
                    return ToolResult(success=False, data={}, error="Port required for UDP")
                pkt = ip_layer / UDP(dport=port)
            elif protocol.lower() == "icmp":
                pkt = ip_layer / ICMP()
            else:
                return ToolResult(success=False, data={}, error=f"Unknown protocol: {protocol}")

            if payload:
                pkt = pkt / Raw(load=payload)

            # Send and receive
            resp = sr1(pkt, timeout=timeout, verbose=0)

            return ToolResult(
                success=True,
                data={
                    "target": target,
                    "protocol": protocol,
                    "port": port,
                    "sent_bytes": len(payload),
                    "response": self._packet_summary(resp),
                },
                raw_output=f"Sent {protocol.upper()} packet, response: {resp is not None}",
            )
        except Exception as e:
            return ToolResult(
                success=False,
                data={},
                error=str(e),
            )

    async def arp_scan(
        self,
        network: str,
        timeout: int = 3,
    ) -> ToolResult:
        """
        Perform ARP scan on local network.

        Args:
            network: Network range (CIDR)
            timeout: Response timeout

        Returns:
            ToolResult with discovered hosts
        """
        self.logger.info(f"ARP scanning {network}")

        try:
            pkt = Ether(dst="ff:ff:ff:ff:ff:ff") / ARP(pdst=network)
            answered, _ = srp(pkt, timeout=timeout, verbose=0)

            hosts = []
            for sent, received in answered:
                hosts.append({
                    "ip": received[ARP].psrc,
                    "mac": received[ARP].hwsrc,
                })

            return ToolResult(
                success=True,
                data={
                    "network": network,
                    "hosts": hosts,
                    "host_count": len(hosts),
                },
                raw_output=f"Found {len(hosts)} hosts on {network}",
            )
        except Exception as e:
            return ToolResult(
                success=False,
                data={},
                error=str(e),
            )

    async def snmp_get(
        self,
        target: str,
        community: str = "public",
        oid: str = "1.3.6.1.2.1.1.1.0",
        port: int = 161,
        timeout: int = 5,
    ) -> ToolResult:
        """
        Send SNMP GET request for community string testing.

        Args:
            target: Target IP
            community: SNMP community string
            oid: OID to query
            port: SNMP port
            timeout: Response timeout

        Returns:
            ToolResult with SNMP response
        """
        self.logger.info(f"SNMP GET to {target} with community '{community}'")

        try:
            # Construct a simple SNMP GET request
            # This is a basic implementation - for full SNMP, use pysnmp
            from scapy.layers.snmp import SNMP, SNMPget, SNMPvarbind

            pkt = IP(dst=target) / UDP(dport=port) / SNMP(
                community=community,
                PDU=SNMPget(varbindlist=[SNMPvarbind(oid=oid)])
            )

            resp = sr1(pkt, timeout=timeout, verbose=0)

            if resp and SNMP in resp:
                snmp_resp = resp[SNMP]
                return ToolResult(
                    success=True,
                    data={
                        "target": target,
                        "community": community,
                        "oid": oid,
                        "valid_community": True,
                        "response": str(snmp_resp),
                    },
                    raw_output=f"SNMP response received - community '{community}' is valid",
                )
            else:
                return ToolResult(
                    success=True,
                    data={
                        "target": target,
                        "community": community,
                        "oid": oid,
                        "valid_community": False,
                    },
                    raw_output=f"No SNMP response - community '{community}' may be invalid",
                )
        except ImportError:
            # Fallback without SNMP layer
            return ToolResult(
                success=False,
                data={},
                error="SNMP layer not available, use raw UDP probe instead",
            )
        except Exception as e:
            return ToolResult(
                success=False,
                data={},
                error=str(e),
            )


# Need srp for ARP scan
from scapy.all import srp

if __name__ == "__main__":
    ScapyServer.main()
