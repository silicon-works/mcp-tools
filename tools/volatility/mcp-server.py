#!/usr/bin/env python3
"""
OpenSploit MCP Server: volatility
Memory forensics via Volatility 3 (v2.27.0). Five methods: analyze (generic
plugin runner), list_plugins, pslist, filescan, hashdump. Operates on memory
dump files in /session/ directory.
"""

import json
import os
import re
from typing import Any, Dict, List, Optional

from mcp_common.base_server import BaseMCPServer, ToolResult
from mcp_common.output_parsers import sanitize_output

VOL_BIN = "vol"


class VolatilityServer(BaseMCPServer):
    """MCP server wrapping Volatility 3 memory forensics framework."""

    def __init__(self):
        super().__init__(
            name="volatility",
            description="Memory forensics via Volatility 3",
            version="1.0.0",
        )

        self.register_method(
            name="analyze",
            description="Run any Volatility 3 plugin against a memory dump — generic method for all 100+ plugins",
            params={
                "dump_file": {
                    "type": "string",
                    "required": True,
                    "description": "Path to memory dump file (must be under /session/). Common formats: raw, vmem, dmp, lime.",
                },
                "plugin": {
                    "type": "string",
                    "required": True,
                    "description": "Volatility 3 plugin name (e.g., 'windows.pslist', 'windows.filescan', 'linux.bash', 'windows.netscan'). Use list_plugins to see all available.",
                },
                "extra_args": {
                    "type": "string",
                    "description": "Additional arguments to pass to the plugin (e.g., '--pid 1234' for process-specific plugins).",
                },
            },
            handler=self.analyze,
        )

        self.register_method(
            name="list_plugins",
            description="List all available Volatility 3 plugins with descriptions",
            params={
                "filter": {
                    "type": "string",
                    "description": "Filter plugins by name substring (e.g., 'windows', 'linux', 'hash', 'net'). Case-insensitive.",
                },
            },
            handler=self.list_plugins,
        )

        self.register_method(
            name="pslist",
            description="List running processes from memory dump — auto-detects Windows (windows.pslist), Linux (linux.pslist), or Mac (mac.pslist)",
            params={
                "dump_file": {
                    "type": "string",
                    "required": True,
                    "description": "Path to memory dump file.",
                },
                "os_type": {
                    "type": "string",
                    "default": "windows",
                    "description": "'windows', 'linux', or 'mac'. Determines which pslist plugin to use.",
                },
            },
            handler=self.pslist,
        )

        self.register_method(
            name="filescan",
            description="Scan memory for file objects — lists open files with their memory offsets (Windows only)",
            params={
                "dump_file": {
                    "type": "string",
                    "required": True,
                    "description": "Path to memory dump file.",
                },
            },
            handler=self.filescan,
        )

        self.register_method(
            name="hashdump",
            description="Extract password hashes from memory dump — reads SAM registry hive (Windows only)",
            params={
                "dump_file": {
                    "type": "string",
                    "required": True,
                    "description": "Path to memory dump file.",
                },
            },
            handler=self.hashdump,
        )

    # ── Helpers ─────────────────────────────────────────────────

    def _validate_dump(self, dump_file: str) -> Optional[ToolResult]:
        """Validate dump file exists."""
        if not dump_file:
            return ToolResult(success=False, error="No dump file path provided.")
        if not os.path.exists(dump_file):
            return ToolResult(success=False, error=f"Dump file not found: {dump_file}")
        return None

    def _parse_json_output(self, output: str) -> List[Dict[str, Any]]:
        """Parse Volatility JSON output."""
        try:
            return json.loads(output)
        except json.JSONDecodeError:
            return []

    def _parse_text_output(self, output: str) -> List[Dict[str, str]]:
        """Parse Volatility text table output into list of dicts."""
        lines = output.strip().split("\n")
        results = []
        headers = []

        for line in lines:
            line = line.strip()
            if not line or line.startswith("*"):
                continue
            # Detect header line (contains column names separated by tabs or multiple spaces)
            if not headers and not line[0].isdigit() and "\t" in line:
                headers = [h.strip() for h in line.split("\t") if h.strip()]
                continue
            if headers:
                values = [v.strip() for v in line.split("\t")]
                row = {}
                for i, h in enumerate(headers):
                    row[h] = values[i] if i < len(values) else ""
                results.append(row)
            else:
                results.append({"line": line})

        return results

    async def _run_plugin(self, dump_file: str, plugin: str, extra_args: str = "", use_json: bool = True) -> ToolResult:
        """Run a volatility plugin and return results."""
        err = self._validate_dump(dump_file)
        if err:
            return err

        cmd = [VOL_BIN, "-f", dump_file, "-q"]

        if use_json:
            cmd.extend(["-r", "json"])

        cmd.append(plugin)

        if extra_args:
            cmd.extend(extra_args.split())

        try:
            result = await self.run_command(cmd, timeout=600)
            raw = result.stdout + result.stderr

            # Check for common volatility errors that still exit 0
            if "Unsatisfied requirement" in raw:
                return ToolResult(
                    success=False,
                    error=f"Plugin '{plugin}' could not process this dump — invalid memory image or wrong OS type. Check that the dump file is a valid memory image.",
                    raw_output=sanitize_output(raw),
                )
            if "usage: vol" in raw and not result.stdout.strip():
                return ToolResult(
                    success=False,
                    error=f"Plugin '{plugin}' not found or invalid arguments. Use list_plugins to see available plugins.",
                    raw_output=sanitize_output(raw),
                )

            if use_json:
                data = self._parse_json_output(result.stdout)
            else:
                data = self._parse_text_output(result.stdout)

            return ToolResult(
                success=True,
                data={
                    "plugin": plugin,
                    "results": data,
                    "result_count": len(data),
                },
                raw_output=sanitize_output(raw),
            )
        except Exception as e:
            error_str = str(e)
            if "Unsatisfied requirement" in error_str:
                return ToolResult(
                    success=False,
                    error=f"Plugin '{plugin}' cannot determine OS type from this dump. Try specifying a different plugin or check that the dump file is valid.",
                    raw_output=sanitize_output(error_str),
                )
            if "not found" in error_str.lower() or "no such plugin" in error_str.lower():
                return ToolResult(
                    success=False,
                    error=f"Plugin '{plugin}' not found. Use list_plugins to see available plugins.",
                    raw_output=sanitize_output(error_str),
                )
            return ToolResult(success=False, error=error_str, raw_output=sanitize_output(error_str))

    # ── Method Handlers ────────────────────────────────────────

    async def analyze(
        self,
        dump_file: str,
        plugin: str,
        extra_args: str = "",
    ) -> ToolResult:
        """Run any Volatility 3 plugin."""
        if not plugin:
            return ToolResult(success=False, error="Plugin name is required.")
        return await self._run_plugin(dump_file, plugin, extra_args)

    async def list_plugins(
        self,
        filter: str = "",
    ) -> ToolResult:
        """List available Volatility 3 plugins."""
        cmd = [VOL_BIN, "--help"]

        try:
            result = await self.run_command(cmd, timeout=30)
            raw = result.stdout + result.stderr

            plugins = []
            in_plugins = False

            for line in raw.split("\n"):
                stripped = line.strip()

                # Look for plugin lines (indented, with format: plugin.name  Description)
                if stripped.startswith("windows.") or stripped.startswith("linux.") or stripped.startswith("mac.") or stripped.startswith("banners.") or stripped.startswith("configwriter") or stripped.startswith("frameworkinfo") or stripped.startswith("isfinfo") or stripped.startswith("layerwriter") or stripped.startswith("timeliner") or stripped.startswith("regexscan") or stripped.startswith("vmscan"):
                    parts = stripped.split(None, 1)
                    name = parts[0]
                    desc = parts[1] if len(parts) > 1 else ""

                    if filter and filter.lower() not in name.lower() and filter.lower() not in desc.lower():
                        continue

                    plugins.append({"name": name, "description": desc})

            return ToolResult(
                success=True,
                data={
                    "plugins": plugins,
                    "plugin_count": len(plugins),
                    "filter": filter if filter else "none",
                },
                raw_output="",
            )
        except Exception as e:
            return ToolResult(success=False, error=str(e))

    async def pslist(
        self,
        dump_file: str,
        os_type: str = "windows",
    ) -> ToolResult:
        """List processes from memory dump."""
        os_lower = os_type.lower()
        if os_lower == "windows":
            plugin = "windows.pslist"
        elif os_lower == "mac":
            plugin = "mac.pslist"
        else:
            plugin = "linux.pslist"
        result = await self._run_plugin(dump_file, plugin)

        if result.success and result.data:
            # Add convenience fields
            result.data["os_type"] = os_type
            processes = result.data.get("results", [])
            result.data["process_count"] = len(processes)

        return result

    async def filescan(
        self,
        dump_file: str,
    ) -> ToolResult:
        """Scan for file objects in memory."""
        return await self._run_plugin(dump_file, "windows.filescan")

    async def hashdump(
        self,
        dump_file: str,
    ) -> ToolResult:
        """Extract password hashes from memory."""
        result = await self._run_plugin(dump_file, "windows.registry.hashdump")

        if result.success and result.data:
            # Label results as hashes
            hashes = result.data.get("results", [])
            result.data["hash_count"] = len(hashes)

        return result


if __name__ == "__main__":
    VolatilityServer.main()
