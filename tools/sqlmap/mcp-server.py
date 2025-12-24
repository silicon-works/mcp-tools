#!/usr/bin/env python3
"""
OpenSploit MCP Server: sqlmap

Automatic SQL injection and database takeover tool.
"""

import asyncio
import json
import os
import re
import tempfile
from typing import Any, Dict, List, Optional

from mcp_common import BaseMCPServer, ToolResult, ToolError, sanitize_output


class SqlmapServer(BaseMCPServer):
    """MCP server wrapping sqlmap SQL injection tool."""

    def __init__(self):
        super().__init__(
            name="sqlmap",
            description="Automatic SQL injection and database takeover tool",
            version="1.0.0",
        )

        self.register_method(
            name="test_injection",
            description="Test a URL parameter for SQL injection vulnerabilities",
            params={
                "url": {
                    "type": "string",
                    "required": True,
                    "description": "Target URL with injectable parameter (use * to mark injection point)",
                },
                "data": {
                    "type": "string",
                    "description": "POST data (for POST requests)",
                },
                "cookie": {
                    "type": "string",
                    "description": "HTTP cookie header value",
                },
                "level": {
                    "type": "integer",
                    "default": 1,
                    "description": "Level of tests (1-5, higher = more tests)",
                },
                "risk": {
                    "type": "integer",
                    "default": 1,
                    "description": "Risk of tests (1-3, higher = more intrusive)",
                },
                "technique": {
                    "type": "string",
                    "default": "BEUSTQ",
                    "description": "SQL injection techniques: B=Boolean, E=Error, U=Union, S=Stacked, T=Time, Q=Inline",
                },
                "timeout": {
                    "type": "integer",
                    "default": 300,
                    "description": "Timeout in seconds",
                },
            },
            handler=self.test_injection,
        )

        self.register_method(
            name="enumerate_dbs",
            description="Enumerate databases on a confirmed vulnerable target",
            params={
                "url": {
                    "type": "string",
                    "required": True,
                    "description": "Target URL (previously confirmed vulnerable)",
                },
                "data": {
                    "type": "string",
                    "description": "POST data if needed",
                },
                "cookie": {
                    "type": "string",
                    "description": "HTTP cookie header value",
                },
                "timeout": {
                    "type": "integer",
                    "default": 300,
                    "description": "Timeout in seconds",
                },
            },
            handler=self.enumerate_dbs,
        )

        self.register_method(
            name="dump_table",
            description="Dump contents of a database table",
            params={
                "url": {
                    "type": "string",
                    "required": True,
                    "description": "Target URL",
                },
                "database": {
                    "type": "string",
                    "required": True,
                    "description": "Database name",
                },
                "table": {
                    "type": "string",
                    "required": True,
                    "description": "Table name",
                },
                "columns": {
                    "type": "string",
                    "description": "Specific columns to dump (comma-separated)",
                },
                "data": {
                    "type": "string",
                    "description": "POST data if needed",
                },
                "cookie": {
                    "type": "string",
                    "description": "HTTP cookie header value",
                },
                "limit": {
                    "type": "integer",
                    "default": 100,
                    "description": "Maximum rows to dump",
                },
                "timeout": {
                    "type": "integer",
                    "default": 600,
                    "description": "Timeout in seconds",
                },
            },
            handler=self.dump_table,
        )

    def _parse_sqlmap_output(self, output: str) -> Dict[str, Any]:
        """Parse sqlmap output for injection results."""
        result = {
            "vulnerable": False,
            "injection_type": None,
            "dbms": None,
            "parameters": [],
            "details": [],
        }

        lines = output.split("\n")

        for line in lines:
            # Check for vulnerability confirmation
            if "is vulnerable" in line.lower() or "parameter" in line.lower() and "injectable" in line.lower():
                result["vulnerable"] = True

            # Extract parameter info
            param_match = re.search(r"Parameter: (\S+)", line)
            if param_match:
                param = param_match.group(1)
                if param not in result["parameters"]:
                    result["parameters"].append(param)

            # Extract injection type
            if "Type:" in line:
                type_match = re.search(r"Type: (.+)", line)
                if type_match:
                    result["injection_type"] = type_match.group(1).strip()

            # Extract DBMS
            if "back-end DBMS:" in line.lower():
                dbms_match = re.search(r"back-end DBMS: (.+)", line, re.IGNORECASE)
                if dbms_match:
                    result["dbms"] = dbms_match.group(1).strip()

            # Collect relevant details
            if any(x in line.lower() for x in ["injectable", "payload", "technique", "dbms"]):
                if line.strip() and not line.startswith("["):
                    result["details"].append(line.strip())

        return result

    def _parse_databases(self, output: str) -> List[str]:
        """Parse sqlmap output for database names."""
        databases = []
        in_db_section = False

        for line in output.split("\n"):
            if "available databases" in line.lower():
                in_db_section = True
                continue

            if in_db_section:
                # Database names are listed with [*] prefix
                if line.strip().startswith("[*]"):
                    db = line.strip()[3:].strip()
                    if db:
                        databases.append(db)
                elif line.strip() and not line.startswith("["):
                    # Also catch plain database names
                    db = line.strip()
                    if db and not db.startswith("-"):
                        databases.append(db)

        return databases

    def _parse_table_dump(self, output: str) -> Dict[str, Any]:
        """Parse sqlmap table dump output."""
        result = {
            "columns": [],
            "rows": [],
            "row_count": 0,
        }

        lines = output.split("\n")
        in_table = False
        header_parsed = False

        for line in lines:
            line = line.strip()

            # Detect table start (line of dashes or plus signs)
            if re.match(r"^[\+\-]+$", line):
                in_table = True
                continue

            if in_table and line.startswith("|"):
                # Parse table row
                cells = [c.strip() for c in line.split("|")[1:-1]]

                if not header_parsed:
                    result["columns"] = cells
                    header_parsed = True
                else:
                    if cells and any(c for c in cells):
                        result["rows"].append(dict(zip(result["columns"], cells)))

        result["row_count"] = len(result["rows"])
        return result

    async def test_injection(
        self,
        url: str,
        data: Optional[str] = None,
        cookie: Optional[str] = None,
        level: int = 1,
        risk: int = 1,
        technique: str = "BEUSTQ",
        timeout: int = 300,
    ) -> ToolResult:
        """Test a URL parameter for SQL injection vulnerabilities."""
        self.logger.info(f"Testing SQL injection on {url}")

        args = [
            "sqlmap",
            "-u", url,
            "--batch",  # Non-interactive
            "--level", str(level),
            "--risk", str(risk),
            "--technique", technique,
            "--threads", "4",
        ]

        if data:
            args.extend(["--data", data])

        if cookie:
            args.extend(["--cookie", cookie])

        try:
            self.logger.info(f"Running: {' '.join(args)}")
            result = await self.run_command(args, timeout=timeout)

            output = result.stdout + result.stderr
            parsed = self._parse_sqlmap_output(output)

            parsed["summary"] = {
                "target": url,
                "level": level,
                "risk": risk,
                "vulnerable": parsed["vulnerable"],
            }

            return ToolResult(
                success=True,
                data=parsed,
                raw_output=sanitize_output(output),
            )

        except ToolError as e:
            return ToolResult(
                success=False,
                data={},
                error=str(e),
            )

    async def enumerate_dbs(
        self,
        url: str,
        data: Optional[str] = None,
        cookie: Optional[str] = None,
        timeout: int = 300,
    ) -> ToolResult:
        """Enumerate databases on a confirmed vulnerable target."""
        self.logger.info(f"Enumerating databases on {url}")

        args = [
            "sqlmap",
            "-u", url,
            "--batch",
            "--dbs",  # Enumerate databases
            "--threads", "4",
        ]

        if data:
            args.extend(["--data", data])

        if cookie:
            args.extend(["--cookie", cookie])

        try:
            self.logger.info(f"Running: {' '.join(args)}")
            result = await self.run_command(args, timeout=timeout)

            output = result.stdout + result.stderr
            databases = self._parse_databases(output)

            return ToolResult(
                success=True,
                data={
                    "databases": databases,
                    "count": len(databases),
                    "target": url,
                },
                raw_output=sanitize_output(output),
            )

        except ToolError as e:
            return ToolResult(
                success=False,
                data={},
                error=str(e),
            )

    async def dump_table(
        self,
        url: str,
        database: str,
        table: str,
        columns: Optional[str] = None,
        data: Optional[str] = None,
        cookie: Optional[str] = None,
        limit: int = 100,
        timeout: int = 600,
    ) -> ToolResult:
        """Dump contents of a database table."""
        self.logger.info(f"Dumping table {database}.{table} from {url}")

        args = [
            "sqlmap",
            "-u", url,
            "--batch",
            "-D", database,
            "-T", table,
            "--dump",
            "--threads", "4",
            "--dump-format", "CSV",
        ]

        if columns:
            args.extend(["-C", columns])

        if data:
            args.extend(["--data", data])

        if cookie:
            args.extend(["--cookie", cookie])

        if limit:
            args.extend(["--stop", str(limit)])

        try:
            self.logger.info(f"Running: {' '.join(args)}")
            result = await self.run_command(args, timeout=timeout)

            output = result.stdout + result.stderr
            parsed = self._parse_table_dump(output)

            parsed["database"] = database
            parsed["table"] = table
            parsed["target"] = url

            return ToolResult(
                success=True,
                data=parsed,
                raw_output=sanitize_output(output),
            )

        except ToolError as e:
            return ToolResult(
                success=False,
                data={},
                error=str(e),
            )


if __name__ == "__main__":
    SqlmapServer.main()
