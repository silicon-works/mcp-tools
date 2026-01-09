#!/usr/bin/env python3
"""
OpenSploit MCP Server: ike-scan

IKE/IPsec VPN enumeration tool for aggressive mode testing, transform enumeration,
PSK hash capture, and PSK cracking.
"""

import asyncio
import re
import tempfile
import os
from typing import Any, Dict, List, Optional

from mcp_common import BaseMCPServer, ToolResult, ToolError, sanitize_output


class IkeScanServer(BaseMCPServer):
    """MCP server wrapping ike-scan for IKE/IPsec enumeration."""

    def __init__(self):
        super().__init__(
            name="ike-scan",
            description="IKE/IPsec VPN enumeration for aggressive mode testing, PSK capture and cracking",
            version="1.1.0",
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
            description="Brute force IKE group names using aggressive mode. Supports parallel scanning.",
            params={
                "target": {
                    "type": "string",
                    "required": True,
                    "description": "Target IP address or hostname",
                },
                "wordlist": {
                    "type": "string",
                    "default": "common",
                    "description": "Built-in wordlist: 'common', 'company', 'extensive', or file path",
                },
                "names": {
                    "type": "array",
                    "items": {"type": "string"},
                    "description": "Inline list of group names to test (overrides wordlist parameter)",
                },
                "dport": {
                    "type": "integer",
                    "default": 500,
                    "description": "Destination port (default 500)",
                },
                "concurrency": {
                    "type": "integer",
                    "default": 5,
                    "description": "Number of parallel requests (default 5, max 10)",
                },
                "delay": {
                    "type": "number",
                    "default": 0.1,
                    "description": "Delay between requests in seconds (default 0.1)",
                },
                "stop_on_first": {
                    "type": "boolean",
                    "default": False,
                    "description": "Stop immediately when first valid group is found",
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

        self.register_method(
            name="crack_psk",
            description="Crack a captured PSK hash using psk-crack with dictionary or brute force",
            params={
                "hash_data": {
                    "type": "string",
                    "required": True,
                    "description": "PSK hash data from get_psk_hash (the full hash line)",
                },
                "wordlist": {
                    "type": "string",
                    "default": "common",
                    "description": "Built-in wordlist: 'common', 'rockyou_sample', or file path",
                },
                "passwords": {
                    "type": "array",
                    "items": {"type": "string"},
                    "description": "Inline list of passwords to try (overrides wordlist)",
                },
                "bruteforce": {
                    "type": "boolean",
                    "default": False,
                    "description": "Use brute force mode instead of dictionary",
                },
                "charset": {
                    "type": "string",
                    "default": "alnum",
                    "description": "Charset for brute force: 'alnum', 'alpha', 'numeric', 'special'",
                },
                "min_length": {
                    "type": "integer",
                    "default": 1,
                    "description": "Minimum password length for brute force",
                },
                "max_length": {
                    "type": "integer",
                    "default": 6,
                    "description": "Maximum password length for brute force",
                },
            },
            handler=self.crack_psk,
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

    async def _test_single_group(
        self,
        target: str,
        name: str,
        dport: int,
        semaphore: asyncio.Semaphore,
        delay: float,
    ) -> Optional[str]:
        """Test a single group name, return name if valid, None otherwise."""
        async with semaphore:
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
                    self.logger.info(f"Found valid group name: {name}")
                    return name

                await asyncio.sleep(delay)
                return None

            except ToolError:
                await asyncio.sleep(delay)
                return None

    async def brute_group_names(
        self,
        target: str,
        wordlist: str = "common",
        names: Optional[List[str]] = None,
        dport: int = 500,
        concurrency: int = 5,
        delay: float = 0.1,
        stop_on_first: bool = False,
    ) -> ToolResult:
        """
        Brute force IKE group names using aggressive mode with parallel scanning.

        Args:
            target: Target IP or hostname
            wordlist: Wordlist type or path
            names: Inline list of names (overrides wordlist)
            dport: Destination port
            concurrency: Number of parallel requests (max 10)
            delay: Delay between requests in seconds
            stop_on_first: Stop when first valid group is found

        Returns:
            ToolResult with valid group names found
        """
        self.logger.info(f"Brute forcing IKE group names on {target} (concurrency={concurrency})")

        # Clamp concurrency to reasonable range
        concurrency = max(1, min(10, concurrency))

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
            "extensive": [
                # Common names
                "vpn", "cisco", "ipsec", "group", "admin", "default",
                "test", "lab", "prod", "production", "corp", "corporate",
                "internal", "external", "remote", "site", "branch",
                "headquarters", "hq", "main", "backup", "primary", "secondary",
                # Company patterns
                "company", "companyname", "companyvpn", "corpvpn", "sitevpn",
                "remotevpn", "vpngroup", "vpnusers", "employees", "staff",
                # Network patterns
                "network", "lan", "wan", "dmz", "trusted", "untrusted",
                "guest", "wifi", "wireless", "mobile", "remote-access",
                # Regional
                "us", "eu", "asia", "americas", "emea", "apac",
                "east", "west", "north", "south", "central",
                # Numbered
                "vpn1", "vpn2", "vpn01", "vpn02", "group1", "group2",
                "site1", "site2", "branch1", "branch2",
                # Device patterns
                "firewall", "fw", "router", "rtr", "gateway", "gw",
            ],
        }

        # Determine names to test
        if names:
            names_to_test = names
            self.logger.info(f"Using {len(names_to_test)} inline names")
        elif wordlist in wordlists:
            names_to_test = wordlists[wordlist]
            self.logger.info(f"Using built-in wordlist '{wordlist}' ({len(names_to_test)} names)")
        else:
            # Assume it's a file path
            try:
                with open(wordlist, 'r') as f:
                    names_to_test = [line.strip() for line in f if line.strip()]
                self.logger.info(f"Loaded {len(names_to_test)} names from {wordlist}")
            except IOError:
                return ToolResult(
                    success=False,
                    data={},
                    error=f"Could not read wordlist: {wordlist}. Use inline 'names' parameter instead.",
                )

        # Create semaphore for concurrency control
        semaphore = asyncio.Semaphore(concurrency)
        valid_groups = []
        tested = 0
        stop_flag = False

        async def test_with_early_stop(name: str) -> Optional[str]:
            nonlocal tested, stop_flag
            if stop_flag:
                return None
            result = await self._test_single_group(target, name, dport, semaphore, delay)
            tested += 1
            if result and stop_on_first:
                stop_flag = True
            return result

        # Run tests with controlled concurrency
        if stop_on_first:
            # Sequential with early termination
            for name in names_to_test:
                result = await test_with_early_stop(name)
                if result:
                    valid_groups.append(result)
                    break
        else:
            # Parallel execution
            tasks = [test_with_early_stop(name) for name in names_to_test]
            results = await asyncio.gather(*tasks, return_exceptions=True)
            valid_groups = [r for r in results if r is not None and not isinstance(r, Exception)]

        return ToolResult(
            success=True,
            data={
                "target": target,
                "port": dport,
                "tested_count": len(names_to_test),
                "valid_groups": valid_groups,
                "found_count": len(valid_groups),
                "concurrency_used": concurrency,
            },
            raw_output=f"Tested {len(names_to_test)} group names with concurrency={concurrency}, found {len(valid_groups)} valid: {', '.join(valid_groups) if valid_groups else 'none'}",
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
            # Format: g_xr:g_xi:cky_r:cky_i:sai_b:idir_b:ni_b:nr_b:hash_r
            # 9 colon-separated fields, predominantly hex data
            psk_hash = None
            for line in output.split('\n'):
                line = line.strip()
                # Skip metadata lines
                if line.startswith('Starting') or line.startswith('Ending') or line.startswith('IKE PSK') or not line:
                    continue
                # PSK hash format has 8+ colons (9+ fields) with long hex strings
                parts = line.split(':')
                if len(parts) >= 9:
                    # Check if parts are predominantly hex (at least 3 long hex fields)
                    hex_fields = sum(1 for p in parts if len(p) > 20 and all(c in '0123456789abcdefABCDEF' for c in p))
                    if hex_fields >= 3:
                        psk_hash = line
                        break

            # Check for handshake failure
            no_handshake = "0 returned handshake" in output

            return ToolResult(
                success=True,
                data={
                    "target": target,
                    "group_name": group_name,
                    "psk_hash": psk_hash,
                    "crackable": psk_hash is not None,
                    "handshake_received": not no_handshake,
                    "next_step": "Use crack_psk method with this hash to attempt cracking" if psk_hash else
                                 ("No handshake received - try a different group name or transform" if no_handshake else None),
                },
                raw_output=sanitize_output(output),
            )
        except ToolError as e:
            return ToolResult(
                success=False,
                data={},
                error=str(e),
            )

    async def crack_psk(
        self,
        hash_data: str,
        wordlist: str = "common",
        passwords: Optional[List[str]] = None,
        bruteforce: bool = False,
        charset: str = "alnum",
        min_length: int = 1,
        max_length: int = 6,
    ) -> ToolResult:
        """
        Crack a captured PSK hash using psk-crack.

        Args:
            hash_data: PSK hash data from get_psk_hash
            wordlist: Built-in wordlist or file path for dictionary attack
            passwords: Inline list of passwords to try (overrides wordlist)
            bruteforce: Use brute force mode instead of dictionary
            charset: Character set for brute force
            min_length: Min password length for brute force
            max_length: Max password length for brute force

        Returns:
            ToolResult with cracking results
        """
        self.logger.info("Attempting to crack PSK hash")

        # Write hash to temp file
        with tempfile.NamedTemporaryFile(mode='w', suffix='.hash', delete=False) as f:
            f.write(hash_data.strip() + '\n')
            hash_file = f.name

        try:
            if bruteforce:
                # Brute force mode
                charset_map = {
                    "alnum": "a",     # alphanumeric
                    "alpha": "c",     # alpha only
                    "numeric": "n",   # numeric only
                    "special": "s",   # including special chars
                }
                charset_flag = charset_map.get(charset, "a")

                cmd = [
                    "psk-crack",
                    "-b",  # brute force
                    f"-B{min_length}:{max_length}:{charset_flag}",
                    hash_file
                ]
            else:
                # Dictionary mode
                common_passwords = [
                    "password", "123456", "password123", "admin", "letmein",
                    "welcome", "monkey", "dragon", "master", "qwerty",
                    "login", "passw0rd", "abc123", "admin123", "root",
                    "toor", "vpn", "vpn123", "ipsec", "cisco", "cisco123",
                    "test", "test123", "default", "changeme", "secret",
                ]

                rockyou_sample = [
                    "123456", "12345", "123456789", "password", "iloveyou",
                    "princess", "1234567", "rockyou", "12345678", "abc123",
                    "nicole", "daniel", "babygirl", "monkey", "lovely",
                    "jessica", "654321", "michael", "ashley", "qwerty",
                    "111111", "iloveu", "000000", "michelle", "tigger",
                    "sunshine", "chocolate", "password1", "soccer", "anthony",
                ]

                wordlists_builtin = {
                    "common": common_passwords,
                    "rockyou_sample": rockyou_sample,
                }

                # Determine passwords to try
                if passwords:
                    passwords_to_try = passwords
                elif wordlist in wordlists_builtin:
                    passwords_to_try = wordlists_builtin[wordlist]
                else:
                    # File path - psk-crack can handle it directly
                    cmd = ["psk-crack", "-d", wordlist, hash_file]
                    try:
                        result = await self.run_command(cmd, timeout=300)
                        output = result.stdout + result.stderr
                        cracked = self._parse_crack_output(output)
                        return ToolResult(
                            success=True,
                            data={
                                "cracked": cracked is not None,
                                "password": cracked,
                                "method": "dictionary",
                                "wordlist": wordlist,
                            },
                            raw_output=sanitize_output(output),
                        )
                    except ToolError as e:
                        return ToolResult(
                            success=False,
                            data={},
                            error=str(e),
                        )

                # Write passwords to temp file
                with tempfile.NamedTemporaryFile(mode='w', suffix='.txt', delete=False) as f:
                    for pwd in passwords_to_try:
                        f.write(pwd + '\n')
                    dict_file = f.name

                cmd = ["psk-crack", "-d", dict_file, hash_file]

            # Run psk-crack
            try:
                result = await self.run_command(cmd, timeout=300)
                output = result.stdout + result.stderr
                cracked = self._parse_crack_output(output)

                return ToolResult(
                    success=True,
                    data={
                        "cracked": cracked is not None,
                        "password": cracked,
                        "method": "bruteforce" if bruteforce else "dictionary",
                    },
                    raw_output=sanitize_output(output),
                )
            except ToolError as e:
                return ToolResult(
                    success=False,
                    data={},
                    error=str(e),
                )
        finally:
            # Clean up temp files
            if os.path.exists(hash_file):
                os.unlink(hash_file)
            if 'dict_file' in locals() and os.path.exists(dict_file):
                os.unlink(dict_file)

    def _parse_crack_output(self, output: str) -> Optional[str]:
        """Parse psk-crack output to extract cracked password."""
        # Check for errors first - don't try to parse error output
        if "ERROR:" in output or "error:" in output.lower():
            return None

        # psk-crack outputs: "key "password" matches SHA1 hash"
        match = re.search(r'key\s+"([^"]+)"\s+matches', output, re.IGNORECASE)
        if match:
            return match.group(1)

        # Alternative format: "PSK = password"
        match = re.search(r'PSK\s*=\s*(\S+)', output, re.IGNORECASE)
        if match:
            return match.group(1)

        # psk-crack success format: "key found: password"
        match = re.search(r'key\s+found[:\s]+([^\s]+)', output, re.IGNORECASE)
        if match:
            return match.group(1)

        return None


if __name__ == "__main__":
    IkeScanServer.main()
