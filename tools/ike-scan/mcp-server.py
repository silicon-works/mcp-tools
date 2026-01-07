#!/usr/bin/env python3
"""
OpenSploit MCP Server: ike-scan

IKE/IPsec VPN enumeration tool for aggressive mode testing, transform enumeration,
and PSK cracking preparation.
"""

import asyncio
import re
from typing import Any, Dict, List, Optional

from mcp_common import BaseMCPServer, ToolResult, ToolError, sanitize_output


class IkeScanServer(BaseMCPServer):
    """MCP server wrapping ike-scan for IKE/IPsec enumeration."""

    def __init__(self):
        super().__init__(
            name="ike-scan",
            description="IKE/IPsec VPN enumeration for aggressive mode testing and transform discovery",
            version="1.0.0",
        )

        # Register methods
        self.register_method(
            name="scan",
            description="Basic IKE scan to detect VPN endpoints",
            params={
                "target": {
                    "type": "string",
                    "required": True,
                    "description": "Target IP address or hostname",
                },
                "sport": {
                    "type": "integer",
                    "default": 500,
                    "description": "Source port (default 500)",
                },
                "dport": {
                    "type": "integer",
                    "default": 500,
                    "description": "Destination port (default 500)",
                },
            },
            handler=self.scan,
        )

        self.register_method(
            name="aggressive_mode",
            description="Test IKE aggressive mode with group name enumeration",
            params={
                "target": {
                    "type": "string",
                    "required": True,
                    "description": "Target IP address or hostname",
                },
                "group_name": {
                    "type": "string",
                    "required": True,
                    "description": "IKE group name (VPN ID) to test",
                },
                "dport": {
                    "type": "integer",
                    "default": 500,
                    "description": "Destination port (default 500)",
                },
            },
            handler=self.aggressive_mode,
        )

        self.register_method(
            name="enumerate_transforms",
            description="Enumerate supported IKE transforms/proposals",
            params={
                "target": {
                    "type": "string",
                    "required": True,
                    "description": "Target IP address or hostname",
                },
                "dport": {
                    "type": "integer",
                    "default": 500,
                    "description": "Destination port (default 500)",
                },
            },
            handler=self.enumerate_transforms,
        )

        self.register_method(
            name="brute_group_names",
            description="Brute force IKE group names using aggressive mode",
            params={
                "target": {
                    "type": "string",
                    "required": True,
                    "description": "Target IP address or hostname",
                },
                "wordlist": {
                    "type": "string",
                    "default": "common",
                    "description": "Wordlist to use: 'common', 'company', or custom file path",
                },
                "dport": {
                    "type": "integer",
                    "default": 500,
                    "description": "Destination port (default 500)",
                },
            },
            handler=self.brute_group_names,
        )

        self.register_method(
            name="get_psk_hash",
            description="Capture PSK hash for offline cracking (requires valid group name)",
            params={
                "target": {
                    "type": "string",
                    "required": True,
                    "description": "Target IP address or hostname",
                },
                "group_name": {
                    "type": "string",
                    "required": True,
                    "description": "Valid IKE group name",
                },
                "dport": {
                    "type": "integer",
                    "default": 500,
                    "description": "Destination port (default 500)",
                },
            },
            handler=self.get_psk_hash,
        )

    def _parse_ike_output(self, output: str) -> Dict[str, Any]:
        """Parse ike-scan output into structured data."""
        result = {
            "hosts": [],
            "handshake": None,
            "transforms": [],
            "vendor_id": None,
            "aggressive_mode": False,
        }

        lines = output.strip().split('\n')
        current_host = None

        for line in lines:
            # Match host line
            host_match = re.match(r'^(\d+\.\d+\.\d+\.\d+)\s+(.+)$', line)
            if host_match:
                current_host = {
                    "ip": host_match.group(1),
                    "response": host_match.group(2),
                }
                result["hosts"].append(current_host)

                # Check for aggressive mode response
                if "Aggressive Mode" in line:
                    result["aggressive_mode"] = True

            # Match transform
            transform_match = re.match(r'\s*SA=\((.+)\)', line)
            if transform_match:
                result["transforms"].append(transform_match.group(1))

            # Match vendor ID
            vid_match = re.match(r'\s*VID=(.+)', line)
            if vid_match:
                result["vendor_id"] = vid_match.group(1)

            # Match handshake returned
            if "Handshake returned" in line:
                result["handshake"] = line.strip()

        return result

    async def scan(
        self,
        target: str,
        sport: int = 500,
        dport: int = 500,
    ) -> ToolResult:
        """
        Basic IKE scan to detect VPN endpoints.

        Args:
            target: Target IP or hostname
            sport: Source port
            dport: Destination port

        Returns:
            ToolResult with IKE detection results
        """
        self.logger.info(f"Starting IKE scan on {target}:{dport}")

        cmd = [
            "ike-scan",
            "--sport", str(sport),
            "--dport", str(dport),
            target
        ]

        try:
            result = await self.run_command(cmd, timeout=60)
            output = result.stdout + result.stderr
            parsed = self._parse_ike_output(output)

            return ToolResult(
                success=True,
                data={
                    **parsed,
                    "target": target,
                    "port": dport,
                    "detected": len(parsed["hosts"]) > 0,
                },
                raw_output=sanitize_output(output),
            )
        except ToolError as e:
            return ToolResult(
                success=False,
                data={},
                error=str(e),
            )

    async def aggressive_mode(
        self,
        target: str,
        group_name: str,
        dport: int = 500,
    ) -> ToolResult:
        """
        Test IKE aggressive mode with a specific group name.

        Aggressive mode reveals PSK hash if group name is valid.

        Args:
            target: Target IP or hostname
            group_name: IKE group name (VPN ID) to test
            dport: Destination port

        Returns:
            ToolResult with aggressive mode test results
        """
        self.logger.info(f"Testing aggressive mode on {target} with group '{group_name}'")

        cmd = [
            "ike-scan",
            "--aggressive",
            f"--id={group_name}",
            "--dport", str(dport),
            target
        ]

        try:
            result = await self.run_command(cmd, timeout=60)
            output = result.stdout + result.stderr
            parsed = self._parse_ike_output(output)

            # Check if aggressive mode was successful
            success = parsed["aggressive_mode"] or "Aggressive Mode" in output

            return ToolResult(
                success=True,
                data={
                    **parsed,
                    "target": target,
                    "group_name": group_name,
                    "valid_group": success,
                    "psk_vulnerable": success,  # If aggressive mode works, PSK may be crackable
                },
                raw_output=sanitize_output(output),
            )
        except ToolError as e:
            return ToolResult(
                success=False,
                data={},
                error=str(e),
            )

    async def enumerate_transforms(
        self,
        target: str,
        dport: int = 500,
    ) -> ToolResult:
        """
        Enumerate supported IKE transforms/proposals.

        Tests various encryption, hash, and DH group combinations.

        Args:
            target: Target IP or hostname
            dport: Destination port

        Returns:
            ToolResult with supported transforms
        """
        self.logger.info(f"Enumerating IKE transforms on {target}")

        # Test with showbackoff to see timing-based fingerprinting
        cmd = [
            "ike-scan",
            "--showbackoff",
            "--dport", str(dport),
            target
        ]

        try:
            result = await self.run_command(cmd, timeout=120)
            output = result.stdout + result.stderr
            parsed = self._parse_ike_output(output)

            return ToolResult(
                success=True,
                data={
                    **parsed,
                    "target": target,
                    "port": dport,
                },
                raw_output=sanitize_output(output),
            )
        except ToolError as e:
            return ToolResult(
                success=False,
                data={},
                error=str(e),
            )

    async def brute_group_names(
        self,
        target: str,
        wordlist: str = "common",
        dport: int = 500,
    ) -> ToolResult:
        """
        Brute force IKE group names using aggressive mode.

        Args:
            target: Target IP or hostname
            wordlist: Wordlist type or path
            dport: Destination port

        Returns:
            ToolResult with valid group names found
        """
        self.logger.info(f"Brute forcing IKE group names on {target}")

        # Built-in wordlists
        wordlists = {
            "common": [
                "vpn", "cisco", "ipsec", "group", "admin", "default",
                "test", "lab", "prod", "production", "corp", "corporate",
                "internal", "external", "remote", "site", "branch",
                "headquarters", "hq", "main", "backup", "primary", "secondary",
            ],
            "company": [
                "company", "companyname", "companyvpn", "corpvpn", "sitevpn",
                "remotevpn", "vpngroup", "vpnusers", "employees", "staff",
            ],
        }

        # Get wordlist
        if wordlist in wordlists:
            names_to_test = wordlists[wordlist]
        else:
            # Assume it's a file path
            try:
                with open(wordlist, 'r') as f:
                    names_to_test = [line.strip() for line in f if line.strip()]
            except IOError:
                return ToolResult(
                    success=False,
                    data={},
                    error=f"Could not read wordlist: {wordlist}",
                )

        valid_groups = []
        tested = 0

        for name in names_to_test:
            tested += 1
            cmd = [
                "ike-scan",
                "--aggressive",
                f"--id={name}",
                "--dport", str(dport),
                target
            ]

            try:
                result = await self.run_command(cmd, timeout=30)
                output = result.stdout + result.stderr

                if "Aggressive Mode" in output or "Handshake returned" in output:
                    valid_groups.append(name)
                    self.logger.info(f"Found valid group name: {name}")

                # Small delay to avoid overwhelming target
                await asyncio.sleep(0.5)

            except ToolError:
                continue

        return ToolResult(
            success=True,
            data={
                "target": target,
                "port": dport,
                "tested_count": tested,
                "valid_groups": valid_groups,
                "found_count": len(valid_groups),
            },
            raw_output=f"Tested {tested} group names, found {len(valid_groups)} valid",
        )

    async def get_psk_hash(
        self,
        target: str,
        group_name: str,
        dport: int = 500,
    ) -> ToolResult:
        """
        Capture PSK hash for offline cracking.

        Requires a valid group name discovered via aggressive mode testing.

        Args:
            target: Target IP or hostname
            group_name: Valid IKE group name
            dport: Destination port

        Returns:
            ToolResult with PSK hash data for cracking
        """
        self.logger.info(f"Capturing PSK hash from {target} with group '{group_name}'")

        # Use psk-crack output format
        cmd = [
            "ike-scan",
            "--aggressive",
            f"--id={group_name}",
            "--pskcrack",
            "--dport", str(dport),
            target
        ]

        try:
            result = await self.run_command(cmd, timeout=60)
            output = result.stdout + result.stderr

            # Look for PSK hash in output
            psk_hash = None
            for line in output.split('\n'):
                # ike-scan pskcrack format includes hash data
                if ':' in line and len(line) > 50:
                    psk_hash = line.strip()
                    break

            return ToolResult(
                success=True,
                data={
                    "target": target,
                    "group_name": group_name,
                    "psk_hash": psk_hash,
                    "crackable": psk_hash is not None,
                    "crack_with": "psk-crack or hashcat" if psk_hash else None,
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
    IkeScanServer.main()
