#!/usr/bin/env python3
"""
OpenSploit MCP Server: searchsploit

Search ExploitDB for public exploits and vulnerability information.
"""

import json
import re
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
                    "required": True,
                    "description": "Search terms (e.g., 'apache 2.4', 'wordpress 5.0', 'ms17-010')",
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
        query: str,
        exact: bool = False,
        type: str = "all",
    ) -> ToolResult:
        """Search ExploitDB for exploits matching a query."""
        self.logger.info(f"Searching ExploitDB for: {query}")

        args = ["searchsploit", "--json"]

        if exact:
            args.append("--exact")

        if type == "exploit":
            args.append("--exploit")
        elif type == "shellcode":
            args.append("--shellcode")

        # Add search terms
        args.extend(query.split())

        try:
            result = await self.run_command(args, timeout=30)
            output = result.stdout

            exploits = self._parse_json_output(output)

            return ToolResult(
                success=True,
                data={
                    "query": query,
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

    async def get_exploit(
        self,
        exploit_id: str,
    ) -> ToolResult:
        """Get the content of a specific exploit."""
        self.logger.info(f"Fetching exploit: {exploit_id}")

        try:
            # If exploit_id looks like a path, use it directly
            if exploit_id.startswith("/"):
                exploit_path = exploit_id
            else:
                # Use searchsploit -p to get the full path
                path_args = ["searchsploit", "-p", exploit_id]
                path_result = await self.run_command(path_args, timeout=30)

                # Parse the path from output (format: "Exploit: /path/to/exploit")
                path_output = path_result.stdout
                path_match = re.search(r'Exploit:\s*(/[^\s\n]+)', path_output)
                if not path_match:
                    # Try alternate format for shellcodes
                    path_match = re.search(r'Shellcode:\s*(/[^\s\n]+)', path_output)
                if not path_match:
                    # Try just finding any path
                    path_match = re.search(r'(/usr/share/exploitdb/[^\s\n]+)', path_output)

                if not path_match:
                    return ToolResult(
                        success=False,
                        data={"exploit_id": exploit_id},
                        error=f"Could not find exploit path for ID: {exploit_id}",
                        raw_output=sanitize_output(path_output),
                    )

                exploit_path = path_match.group(1)

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


if __name__ == "__main__":
    SearchsploitServer.main()
