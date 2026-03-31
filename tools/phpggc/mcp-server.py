#!/usr/bin/env python3
"""
OpenSploit MCP Server: phpggc

PHP Generic Gadget Chains — generates serialized PHP payloads for
deserialization attacks against 14+ PHP frameworks.
"""

import asyncio
import re
from typing import Any, Dict, List, Optional

from mcp_common import BaseMCPServer, ToolResult, ToolError, sanitize_output

PHPGGC_PATH = "/opt/phpggc/phpggc"


class PhpggcServer(BaseMCPServer):
    """MCP server wrapping phpggc for PHP deserialization payload generation."""

    def __init__(self):
        super().__init__(
            name="phpggc",
            description="PHP Generic Gadget Chains — generate serialized payloads for deserialization attacks",
            version="1.0.0",
        )

        self.register_method(
            name="list_gadgets",
            description="List available PHP gadget chains, optionally filtered by framework",
            params={
                "filter": {
                    "type": "string",
                    "description": "Filter by framework name (e.g., 'symfony', 'laravel', 'monolog', 'drupal', 'wordpress')",
                },
            },
            handler=self.list_gadgets,
        )

        self.register_method(
            name="get_info",
            description="Get detailed information about a specific gadget chain",
            params={
                "chain": {
                    "type": "string",
                    "required": True,
                    "description": "Gadget chain name (e.g., 'Monolog/RCE1', 'Symfony/RCE1', 'Laravel/RCE1')",
                },
            },
            handler=self.get_info,
        )

        self.register_method(
            name="generate",
            description="Generate a serialized PHP payload for a specific gadget chain",
            params={
                "chain": {
                    "type": "string",
                    "required": True,
                    "description": "Gadget chain name (e.g., 'Monolog/RCE1', 'Symfony/RCE4')",
                },
                "arguments": {
                    "type": "array",
                    "required": True,
                    "description": "Arguments for the gadget chain (e.g., ['system', 'id'] for RCE chains, ['/var/www/shell.php', '/path/to/shell.php'] for file write chains)",
                },
                "encoding": {
                    "type": "string",
                    "enum": ["none", "base64", "url", "soft-url", "json"],
                    "default": "none",
                    "description": "Output encoding: none (raw), base64, url (URL-encode), soft-url (soft URL-encode), json",
                },
                "fast_destruct": {
                    "type": "boolean",
                    "default": False,
                    "description": "Apply fast-destruct technique — object is destroyed right after unserialize() instead of at script end",
                },
                "ascii_strings": {
                    "type": "boolean",
                    "default": False,
                    "description": "Replace non-ASCII chars with hex representation (experimental)",
                },
                "phar": {
                    "type": "string",
                    "enum": ["tar", "zip", "phar"],
                    "description": "Generate PHAR file instead of serialized string (for phar:// wrapper attacks)",
                },
                "phar_jpeg": {
                    "type": "string",
                    "description": "Path to JPEG file to create polyglot JPEG/PHAR from",
                },
            },
            handler=self.generate,
        )

    def _parse_chain_list(self, output: str) -> List[Dict[str, str]]:
        """Parse phpggc -l output into structured data."""
        chains = []
        lines = output.strip().split("\n")

        for line in lines:
            # Skip header lines
            if not line.strip() or line.startswith("Gadget") or line.startswith("---") or line.startswith("NAME"):
                continue

            # Parse: NAME  VERSION  TYPE  VECTOR  I
            # Fields are whitespace-separated but VERSION and TYPE can contain spaces
            parts = re.split(r'\s{2,}', line.strip())
            if len(parts) >= 4:
                chain = {
                    "name": parts[0].strip(),
                    "version": parts[1].strip(),
                    "type": parts[2].strip(),
                    "vector": parts[3].strip(),
                }
                if len(parts) > 4 and parts[4].strip() == "*":
                    chain["info_available"] = True
                chains.append(chain)

        return chains

    async def list_gadgets(
        self,
        filter: str = None,
    ) -> ToolResult:
        """List available PHP gadget chains."""
        self.logger.info(f"Listing gadget chains, filter={filter}")

        cmd = [PHPGGC_PATH, "-l"]
        if filter:
            cmd.append(filter)

        try:
            result = await self.run_command(cmd, timeout=10)
            stdout = result.stdout.strip() if result.stdout else ""

            chains = self._parse_chain_list(stdout)

            # Group by framework
            frameworks = {}
            for chain in chains:
                fw = chain["name"].split("/")[0]
                if fw not in frameworks:
                    frameworks[fw] = []
                frameworks[fw].append(chain)

            return ToolResult(
                success=True,
                data={
                    "chains": chains,
                    "chain_count": len(chains),
                    "frameworks": list(frameworks.keys()),
                    "framework_count": len(frameworks),
                },
                raw_output=stdout,
            )

        except Exception as e:
            return ToolResult(
                success=False,
                data={},
                error=f"Failed to list gadget chains: {e}",
            )

    async def get_info(
        self,
        chain: str,
    ) -> ToolResult:
        """Get detailed info about a specific gadget chain."""
        self.logger.info(f"Getting info for chain: {chain}")

        cmd = [PHPGGC_PATH, "-i", chain]

        try:
            result = await self.run_command(cmd, timeout=10)
            stdout = result.stdout.strip() if result.stdout else ""
            stderr = result.stderr.strip() if result.stderr else ""

            if result.returncode != 0 or "Unknown" in stderr:
                return ToolResult(
                    success=False,
                    data={"chain": chain},
                    error=f"Unknown gadget chain: {chain}. Use list_gadgets to see available chains.",
                )

            return ToolResult(
                success=True,
                data={
                    "chain": chain,
                    "info": stdout,
                },
                raw_output=stdout,
            )

        except Exception as e:
            return ToolResult(
                success=False,
                data={},
                error=f"Failed to get chain info: {e}",
            )

    async def generate(
        self,
        chain: str,
        arguments: list,
        encoding: str = "none",
        fast_destruct: bool = False,
        ascii_strings: bool = False,
        phar: str = None,
        phar_jpeg: str = None,
    ) -> ToolResult:
        """Generate a serialized PHP payload."""
        self.logger.info(f"Generating payload: chain={chain} args={arguments} encoding={encoding}")

        cmd = [PHPGGC_PATH]

        # Encoding flags
        if encoding == "base64":
            cmd.append("-b")
        elif encoding == "url":
            cmd.append("-u")
        elif encoding == "soft-url":
            cmd.append("-s")
        elif encoding == "json":
            cmd.append("-j")

        # Enhancement flags
        if fast_destruct:
            cmd.append("-f")
        if ascii_strings:
            cmd.append("-a")

        # PHAR mode
        if phar:
            cmd.extend(["-p", phar])
        if phar_jpeg:
            cmd.extend(["-pj", phar_jpeg])

        # Chain name and arguments
        cmd.append(chain)
        cmd.extend(arguments)

        try:
            result = await self.run_command(cmd, timeout=15)
            stdout = result.stdout if result.stdout else ""
            stderr = result.stderr.strip() if result.stderr else ""

            if result.returncode != 0:
                return ToolResult(
                    success=False,
                    data={"chain": chain},
                    error=f"phpggc failed: {stderr or stdout}",
                )

            payload = stdout.rstrip("\n")

            return ToolResult(
                success=True,
                data={
                    "chain": chain,
                    "arguments": arguments,
                    "encoding": encoding,
                    "fast_destruct": fast_destruct,
                    "payload": payload,
                    "payload_length": len(payload),
                },
                raw_output=payload,
            )

        except Exception as e:
            return ToolResult(
                success=False,
                data={},
                error=f"Payload generation failed: {e}",
            )


if __name__ == "__main__":
    PhpggcServer.main()
