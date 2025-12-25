#!/usr/bin/env python3
"""
OpenSploit MCP Server: mysql

MySQL/MariaDB client for database enumeration and data extraction.
"""

import asyncio
import json
from typing import Optional

from mcp_common import BaseMCPServer, ToolResult, ToolError, sanitize_output


class MySQLServer(BaseMCPServer):
    """MCP server wrapping MySQL client for database operations."""

    def __init__(self):
        super().__init__(
            name="mysql",
            description="MySQL/MariaDB client for database enumeration and data extraction",
            version="1.0.0",
        )

        self.register_method(
            name="query",
            description="Execute a SQL query on a MySQL/MariaDB database",
            params={
                "host": {
                    "type": "string",
                    "required": True,
                    "description": "Database host",
                },
                "username": {
                    "type": "string",
                    "required": True,
                    "description": "Database username",
                },
                "password": {
                    "type": "string",
                    "required": True,
                    "description": "Database password",
                },
                "query": {
                    "type": "string",
                    "required": True,
                    "description": "SQL query to execute",
                },
                "database": {
                    "type": "string",
                    "description": "Database name to use",
                },
                "port": {
                    "type": "integer",
                    "default": 3306,
                    "description": "Database port",
                },
                "timeout": {
                    "type": "integer",
                    "default": 30,
                    "description": "Query timeout in seconds",
                },
            },
            handler=self.query,
        )

        self.register_method(
            name="list_databases",
            description="List all databases on the server",
            params={
                "host": {
                    "type": "string",
                    "required": True,
                    "description": "Database host",
                },
                "username": {
                    "type": "string",
                    "required": True,
                    "description": "Database username",
                },
                "password": {
                    "type": "string",
                    "required": True,
                    "description": "Database password",
                },
                "port": {
                    "type": "integer",
                    "default": 3306,
                    "description": "Database port",
                },
            },
            handler=self.list_databases,
        )

        self.register_method(
            name="list_tables",
            description="List all tables in a database",
            params={
                "host": {
                    "type": "string",
                    "required": True,
                    "description": "Database host",
                },
                "username": {
                    "type": "string",
                    "required": True,
                    "description": "Database username",
                },
                "password": {
                    "type": "string",
                    "required": True,
                    "description": "Database password",
                },
                "database": {
                    "type": "string",
                    "required": True,
                    "description": "Database name",
                },
                "port": {
                    "type": "integer",
                    "default": 3306,
                    "description": "Database port",
                },
            },
            handler=self.list_tables,
        )

        self.register_method(
            name="dump_table",
            description="Dump contents of a table",
            params={
                "host": {
                    "type": "string",
                    "required": True,
                    "description": "Database host",
                },
                "username": {
                    "type": "string",
                    "required": True,
                    "description": "Database username",
                },
                "password": {
                    "type": "string",
                    "required": True,
                    "description": "Database password",
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
                "limit": {
                    "type": "integer",
                    "default": 100,
                    "description": "Maximum rows to return",
                },
                "port": {
                    "type": "integer",
                    "default": 3306,
                    "description": "Database port",
                },
            },
            handler=self.dump_table,
        )

        self.register_method(
            name="find_credentials",
            description="Search for credential-like data in common tables",
            params={
                "host": {
                    "type": "string",
                    "required": True,
                    "description": "Database host",
                },
                "username": {
                    "type": "string",
                    "required": True,
                    "description": "Database username",
                },
                "password": {
                    "type": "string",
                    "required": True,
                    "description": "Database password",
                },
                "database": {
                    "type": "string",
                    "description": "Database to search (searches all if not specified)",
                },
                "port": {
                    "type": "integer",
                    "default": 3306,
                    "description": "Database port",
                },
            },
            handler=self.find_credentials,
        )

    async def _run_mysql(
        self,
        host: str,
        username: str,
        password: str,
        query: str,
        database: Optional[str] = None,
        port: int = 3306,
        timeout: int = 30,
    ) -> tuple:
        """Execute a MySQL query and return results."""
        args = [
            "mysql",
            "-h", host,
            "-P", str(port),
            "-u", username,
            f"-p{password}",
            "-N",  # Skip column names
            "-B",  # Batch mode (tab-separated)
            "-e", query,
        ]

        if database:
            args.extend(["-D", database])

        try:
            proc = await asyncio.create_subprocess_exec(
                *args,
                stdout=asyncio.subprocess.PIPE,
                stderr=asyncio.subprocess.PIPE,
            )

            stdout, stderr = await asyncio.wait_for(
                proc.communicate(),
                timeout=timeout,
            )

            return proc.returncode, stdout.decode("utf-8", errors="replace"), stderr.decode("utf-8", errors="replace")

        except asyncio.TimeoutError:
            proc.kill()
            raise ToolError(f"Query timed out after {timeout} seconds")

    async def query(
        self,
        host: str,
        username: str,
        password: str,
        query: str,
        database: Optional[str] = None,
        port: int = 3306,
        timeout: int = 30,
    ) -> ToolResult:
        """Execute a SQL query."""
        self.logger.info(f"Executing query on {host}:{port}")

        try:
            returncode, stdout, stderr = await self._run_mysql(
                host, username, password, query, database, port, timeout
            )

            if returncode != 0:
                return ToolResult(
                    success=False,
                    data={"host": host, "query": query},
                    error=stderr.strip() or "Query failed",
                )

            # Parse tab-separated output into rows
            rows = []
            for line in stdout.strip().split("\n"):
                if line:
                    rows.append(line.split("\t"))

            return ToolResult(
                success=True,
                data={
                    "host": host,
                    "database": database,
                    "query": query,
                    "rows": rows,
                    "row_count": len(rows),
                },
                raw_output=stdout,
            )

        except ToolError as e:
            return ToolResult(
                success=False,
                data={"host": host, "query": query},
                error=str(e),
            )

    async def list_databases(
        self,
        host: str,
        username: str,
        password: str,
        port: int = 3306,
    ) -> ToolResult:
        """List all databases."""
        self.logger.info(f"Listing databases on {host}:{port}")

        result = await self.query(
            host=host,
            username=username,
            password=password,
            query="SHOW DATABASES",
            port=port,
        )

        if result.success:
            databases = [row[0] for row in result.data.get("rows", [])]
            result.data["databases"] = databases

        return result

    async def list_tables(
        self,
        host: str,
        username: str,
        password: str,
        database: str,
        port: int = 3306,
    ) -> ToolResult:
        """List all tables in a database."""
        self.logger.info(f"Listing tables in {database} on {host}:{port}")

        result = await self.query(
            host=host,
            username=username,
            password=password,
            query="SHOW TABLES",
            database=database,
            port=port,
        )

        if result.success:
            tables = [row[0] for row in result.data.get("rows", [])]
            result.data["tables"] = tables

        return result

    async def dump_table(
        self,
        host: str,
        username: str,
        password: str,
        database: str,
        table: str,
        columns: Optional[str] = None,
        limit: int = 100,
        port: int = 3306,
    ) -> ToolResult:
        """Dump contents of a table."""
        self.logger.info(f"Dumping {database}.{table} on {host}:{port}")

        col_spec = columns if columns else "*"
        query = f"SELECT {col_spec} FROM {table} LIMIT {limit}"

        return await self.query(
            host=host,
            username=username,
            password=password,
            query=query,
            database=database,
            port=port,
            timeout=60,
        )

    async def find_credentials(
        self,
        host: str,
        username: str,
        password: str,
        database: Optional[str] = None,
        port: int = 3306,
    ) -> ToolResult:
        """Search for credential-like data."""
        self.logger.info(f"Searching for credentials on {host}:{port}")

        findings = []

        # Common credential table/column patterns
        patterns = [
            ("users", ["username", "password", "email", "user", "pass", "pwd"]),
            ("accounts", ["username", "password", "email"]),
            ("members", ["username", "password", "email"]),
            ("admin", ["username", "password"]),
            ("credentials", ["username", "password"]),
            ("wp_users", ["user_login", "user_pass", "user_email"]),
            ("user", ["name", "password", "email"]),
        ]

        # Get list of databases to search
        if database:
            databases = [database]
        else:
            db_result = await self.list_databases(host, username, password, port)
            if not db_result.success:
                return db_result
            databases = [db for db in db_result.data.get("databases", [])
                        if db not in ("information_schema", "mysql", "performance_schema", "sys")]

        for db in databases:
            # Get tables in this database
            table_result = await self.list_tables(host, username, password, db, port)
            if not table_result.success:
                continue

            tables = table_result.data.get("tables", [])

            for table_pattern, _ in patterns:
                # Check if any table matches the pattern
                for table in tables:
                    if table_pattern.lower() in table.lower():
                        # Try to dump this table
                        dump_result = await self.dump_table(
                            host, username, password, db, table, limit=50, port=port
                        )
                        if dump_result.success and dump_result.data.get("rows"):
                            findings.append({
                                "database": db,
                                "table": table,
                                "rows": dump_result.data["rows"][:10],  # First 10 rows
                                "total_rows": dump_result.data["row_count"],
                            })

        return ToolResult(
            success=True,
            data={
                "host": host,
                "findings": findings,
                "databases_searched": databases,
            },
            raw_output=f"Found {len(findings)} potential credential tables",
        )


if __name__ == "__main__":
    MySQLServer.main()
