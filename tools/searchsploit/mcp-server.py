#!/usr/bin/env python3
"""
OpenSploit MCP Server: searchsploit

Search ExploitDB for public exploits and vulnerability information.
"""

import json
import os
from typing import Any, Dict, List, Optional

from mcp_common import BaseMCPServer, ToolResult, ToolError, sanitize_output


class SearchsploitServer(BaseMCPServer):
    """MCP server wrapping searchsploit exploit database search."""

    def __init__(self):
        super().__init__(
            name="searchsploit",
            description="Search ExploitDB for public exploits and vulnerability information",
            version="1.0.0",
        )

        self.register_method(
            name="search",
            description="Search ExploitDB for exploits matching a query",
            params={
                "query": {
                    "type": "string",
                    "description": "Search terms (e.g., 'apache 2.4', 'wordpress 5.0', 'ms17-010'). Mutually exclusive with cve.",
                },
                "cve": {
                    "type": "string",
                    "description": "Search by CVE ID (e.g., '2021-44228' for Log4Shell). Omit the 'CVE-' prefix. Mutually exclusive with query.",
                },
                "exact": {
                    "type": "boolean",
                    "default": False,
                    "description": "Perform exact match search",
                },
                "type": {
                    "type": "string",
                    "enum": ["all", "exploit", "shellcode", "paper"],
                    "default": "all",
                    "description": "Type of results to return",
                },
                "strict": {
                    "type": "boolean",
                    "default": False,
                    "description": "Strict version matching — '1.1' only matches '1.1', not '1.0 < 1.3'.",
                },
                "exclude": {
                    "type": "string",
                    "description": "Exclude results matching these terms (pipe-separated). Examples: '(PoC)|/dos/' (exclude PoCs and DoS), '/windows/' (exclude Windows).",
                },
            },
            handler=self.search,
        )

        self.register_method(
            name="get_exploit",
            description="Get the content of a specific exploit by ID or path",
            params={
                "exploit_id": {
                    "type": "string",
                    "required": True,
                    "description": "Exploit ID number or path from search results",
                },
            },
            handler=self.get_exploit,
        )

        self.register_method(
            name="mirror",
            description="Copy an exploit file to the working directory for modification",
            params={
                "exploit_id": {
                    "type": "string",
                    "required": True,
                    "description": "EDB-ID of the exploit to copy (from search results)",
                },
            },
            handler=self.mirror,
        )

    def _parse_json_output(self, output: str) -> List[Dict[str, Any]]:
        """Parse searchsploit JSON output."""
        try:
            data = json.loads(output)
            exploits = []

            for item in data.get("RESULTS_EXPLOIT", []):
                exploits.append({
                    "id": item.get("EDB-ID", ""),
                    "title": item.get("Title", ""),
                    "path": item.get("Path", ""),
                    "date": item.get("Date", ""),
                    "type": "exploit",
                })

            for item in data.get("RESULTS_SHELLCODE", []):
                exploits.append({
                    "id": item.get("EDB-ID", ""),
                    "title": item.get("Title", ""),
                    "path": item.get("Path", ""),
                    "date": item.get("Date", ""),
                    "type": "shellcode",
                })

            for item in data.get("RESULTS_PAPER", []):
                exploits.append({
                    "id": item.get("EDB-ID", ""),
                    "title": item.get("Title", ""),
                    "path": item.get("Path", ""),
                    "date": item.get("Date", ""),
                    "type": "paper",
                })

            return exploits
        except json.JSONDecodeError:
            return []

    async def search(
        self,
        query: Optional[str] = None,
        cve: Optional[str] = None,
        exact: bool = False,
        type: str = "all",
        strict: bool = False,
        exclude: Optional[str] = None,
    ) -> ToolResult:
        """Search ExploitDB for exploits matching a query or CVE."""
        if not query and not cve:
            return ToolResult(
                success=False,
                data={},
                error="Either 'query' or 'cve' parameter is required.",
            )

        self.logger.info(f"Searching ExploitDB for: {cve or query}")

        if cve:
            # CVE search uses dedicated flag
            args = ["searchsploit", "--json", "--cve", cve]
        else:
            args = ["searchsploit", "--json"]

            if exact:
                args.append("--exact")

            if strict:
                args.append("--strict")

            if exclude:
                args.append(f"--exclude={exclude}")

            # Add search terms
            args.extend(query.split())

        try:
            result = await self.run_command(args, timeout=30)
            output = result.stdout

            exploits = self._parse_json_output(output)

            # Client-side type filtering (--json already returns all types; filter here)
            if type != "all":
                exploits = [e for e in exploits if e.get("type") == type]

            return ToolResult(
                success=True,
                data={
                    "query": cve or query,
                    "search_type": "cve" if cve else "text",
                    "results": exploits,
                    "count": len(exploits),
                },
                raw_output=sanitize_output(output),
            )

        except ToolError as e:
            return ToolResult(
                success=False,
                data={},
                error=str(e),
            )

    async def _resolve_exploit_path(self, exploit_id: str) -> Optional[str]:
        """Resolve an exploit ID to its full filesystem path.

        Uses JSON search instead of 'searchsploit -p' to avoid dependency
        on the 'rev' command which may not be installed.
        """
        if exploit_id.startswith("/"):
            return exploit_id

        # Search for the exploit by ID using JSON output
        args = ["searchsploit", "--json", exploit_id]
        result = await self.run_command(args, timeout=30)
        exploits = self._parse_json_output(result.stdout)

        # Find the matching exploit by EDB-ID
        for exploit in exploits:
            if str(exploit.get("id")) == str(exploit_id):
                return exploit.get("path")

        # If exact match by ID failed, return first result's path if any
        if exploits:
            return exploits[0].get("path")

        return None

    async def get_exploit(
        self,
        exploit_id: str,
    ) -> ToolResult:
        """Get the content of a specific exploit."""
        self.logger.info(f"Fetching exploit: {exploit_id}")

        try:
            exploit_path = await self._resolve_exploit_path(exploit_id)

            if not exploit_path:
                return ToolResult(
                    success=False,
                    data={"exploit_id": exploit_id},
                    error=f"Could not find exploit path for ID: {exploit_id}",
                )

            # Read the exploit file directly
            cat_args = ["cat", exploit_path]
            result = await self.run_command(cat_args, timeout=30)
            content = result.stdout

            return ToolResult(
                success=True,
                data={
                    "exploit_id": exploit_id,
                    "path": exploit_path,
                    "content": content,
                },
                raw_output=sanitize_output(content),
            )

        except ToolError as e:
            return ToolResult(
                success=False,
                data={},
                error=str(e),
            )


    async def mirror(
        self,
        exploit_id: str,
    ) -> ToolResult:
        """Copy an exploit file to the working directory for modification."""
        self.logger.info(f"Mirroring exploit: {exploit_id}")

        try:
            exploit_path = await self._resolve_exploit_path(exploit_id)

            if not exploit_path:
                return ToolResult(
                    success=False,
                    data={"exploit_id": exploit_id},
                    error=f"Could not find exploit for ID: {exploit_id}",
                )

            # Extract filename and copy to working directory
            filename = os.path.basename(exploit_path)
            dest = os.path.join(os.getcwd(), filename)
            cp_args = ["cp", exploit_path, dest]
            await self.run_command(cp_args, timeout=30)

            return ToolResult(
                success=True,
                data={
                    "exploit_id": exploit_id,
                    "source_path": exploit_path,
                    "filename": filename,
                    "message": f"Exploit copied to {dest}",
                },
            )
        except ToolError as e:
            return ToolResult(success=False, data={}, error=str(e))


if __name__ == "__main__":
    SearchsploitServer.main()
