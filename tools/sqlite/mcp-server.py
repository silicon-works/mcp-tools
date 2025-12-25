#!/usr/bin/env python3
"""
OpenSploit MCP Server: sqlite

SQLite database client for extracting data from SQLite database files.
Useful for post-exploitation when database files are accessible.
"""

import base64
import json
import os
import sqlite3
import tempfile
from typing import Any, Dict, List, Optional

from mcp_common import BaseMCPServer, ToolResult


# Common credential-related table/column patterns
CREDENTIAL_TABLE_PATTERNS = [
    "user", "users", "account", "accounts", "member", "members",
    "admin", "admins", "login", "logins", "auth", "credential",
    "customer", "customers", "employee", "employees", "person", "people",
]

CREDENTIAL_COLUMN_PATTERNS = [
    "password", "passwd", "pass", "pwd", "hash", "secret",
    "token", "api_key", "apikey", "auth", "credential",
]

USERNAME_COLUMN_PATTERNS = [
    "username", "user", "login", "email", "name", "account",
    "user_name", "user_id", "userid", "uname",
]


class SQLiteServer(BaseMCPServer):
    """MCP server for SQLite database operations."""

    def __init__(self):
        super().__init__(
            name="sqlite",
            description="SQLite database client for data extraction",
            version="1.0.0",
        )

        self.register_method(
            name="query",
            description="Execute a SQL query on a SQLite database",
            params={
                "database": {
                    "type": "string",
                    "required": True,
                    "description": "Path to SQLite database file, or base64-encoded database content",
                },
                "query": {
                    "type": "string",
                    "required": True,
                    "description": "SQL query to execute",
                },
                "is_base64": {
                    "type": "boolean",
                    "default": False,
                    "description": "If true, database parameter is base64-encoded file content",
                },
                "limit": {
                    "type": "integer",
                    "default": 1000,
                    "description": "Maximum rows to return",
                },
            },
            handler=self.query,
        )

        self.register_method(
            name="list_tables",
            description="List all tables in a SQLite database",
            params={
                "database": {
                    "type": "string",
                    "required": True,
                    "description": "Path to SQLite database file, or base64-encoded content",
                },
                "is_base64": {
                    "type": "boolean",
                    "default": False,
                    "description": "If true, database parameter is base64-encoded file content",
                },
            },
            handler=self.list_tables,
        )

        self.register_method(
            name="describe_table",
            description="Get schema/structure of a table",
            params={
                "database": {
                    "type": "string",
                    "required": True,
                    "description": "Path to SQLite database file, or base64-encoded content",
                },
                "table": {
                    "type": "string",
                    "required": True,
                    "description": "Table name to describe",
                },
                "is_base64": {
                    "type": "boolean",
                    "default": False,
                    "description": "If true, database parameter is base64-encoded file content",
                },
            },
            handler=self.describe_table,
        )

        self.register_method(
            name="dump_table",
            description="Dump all rows from a table",
            params={
                "database": {
                    "type": "string",
                    "required": True,
                    "description": "Path to SQLite database file, or base64-encoded content",
                },
                "table": {
                    "type": "string",
                    "required": True,
                    "description": "Table name to dump",
                },
                "columns": {
                    "type": "array",
                    "description": "Specific columns to select (default: all)",
                },
                "limit": {
                    "type": "integer",
                    "default": 100,
                    "description": "Maximum rows to return",
                },
                "is_base64": {
                    "type": "boolean",
                    "default": False,
                    "description": "If true, database parameter is base64-encoded file content",
                },
            },
            handler=self.dump_table,
        )

        self.register_method(
            name="find_credentials",
            description="Search for credential-related tables and extract potential usernames/passwords",
            params={
                "database": {
                    "type": "string",
                    "required": True,
                    "description": "Path to SQLite database file, or base64-encoded content",
                },
                "is_base64": {
                    "type": "boolean",
                    "default": False,
                    "description": "If true, database parameter is base64-encoded file content",
                },
                "limit": {
                    "type": "integer",
                    "default": 100,
                    "description": "Maximum rows to return per table",
                },
            },
            handler=self.find_credentials,
        )

        self.register_method(
            name="schema",
            description="Get full database schema (all tables and columns)",
            params={
                "database": {
                    "type": "string",
                    "required": True,
                    "description": "Path to SQLite database file, or base64-encoded content",
                },
                "is_base64": {
                    "type": "boolean",
                    "default": False,
                    "description": "If true, database parameter is base64-encoded file content",
                },
            },
            handler=self.schema,
        )

    def _get_connection(self, database: str, is_base64: bool = False) -> tuple:
        """
        Get a SQLite connection.

        Returns (connection, temp_file_path or None)
        If is_base64, writes to temp file and returns path for cleanup.
        """
        temp_path = None

        if is_base64:
            # Decode and write to temp file
            try:
                db_bytes = base64.b64decode(database)
            except Exception as e:
                raise ValueError(f"Invalid base64 encoding: {e}")

            fd, temp_path = tempfile.mkstemp(suffix=".db", prefix="sqlite_")
            os.write(fd, db_bytes)
            os.close(fd)
            database = temp_path

        # Connect to database
        if not os.path.exists(database):
            if temp_path:
                os.unlink(temp_path)
            raise FileNotFoundError(f"Database file not found: {database}")

        try:
            conn = sqlite3.connect(database)
            conn.row_factory = sqlite3.Row
            return conn, temp_path
        except Exception as e:
            if temp_path and os.path.exists(temp_path):
                os.unlink(temp_path)
            raise

    def _cleanup(self, temp_path: Optional[str]) -> None:
        """Clean up temp file if exists."""
        if temp_path and os.path.exists(temp_path):
            os.unlink(temp_path)

    async def query(
        self,
        database: str,
        query: str,
        is_base64: bool = False,
        limit: int = 1000,
    ) -> ToolResult:
        """Execute a SQL query."""
        self.logger.info(f"Executing query on database")

        temp_path = None
        try:
            conn, temp_path = self._get_connection(database, is_base64)
            cursor = conn.cursor()

            # Add LIMIT if not present and query is SELECT
            query_upper = query.strip().upper()
            if query_upper.startswith("SELECT") and "LIMIT" not in query_upper:
                query = f"{query.rstrip(';')} LIMIT {limit}"

            cursor.execute(query)

            # Get column names
            columns = [desc[0] for desc in cursor.description] if cursor.description else []

            # Fetch results
            rows = cursor.fetchall()
            results = [dict(row) for row in rows]

            conn.close()

            return ToolResult(
                success=True,
                data={
                    "columns": columns,
                    "rows": results,
                    "row_count": len(results),
                },
                raw_output=f"Query returned {len(results)} rows",
            )

        except sqlite3.Error as e:
            return ToolResult(
                success=False,
                data={},
                error=f"SQLite error: {e}",
            )
        except Exception as e:
            return ToolResult(
                success=False,
                data={},
                error=str(e),
            )
        finally:
            self._cleanup(temp_path)

    async def list_tables(
        self,
        database: str,
        is_base64: bool = False,
    ) -> ToolResult:
        """List all tables in the database."""
        self.logger.info("Listing tables")

        temp_path = None
        try:
            conn, temp_path = self._get_connection(database, is_base64)
            cursor = conn.cursor()

            cursor.execute(
                "SELECT name FROM sqlite_master WHERE type='table' ORDER BY name"
            )

            tables = [row[0] for row in cursor.fetchall()]

            # Get row counts for each table
            table_info = []
            for table in tables:
                try:
                    cursor.execute(f'SELECT COUNT(*) FROM "{table}"')
                    count = cursor.fetchone()[0]
                    table_info.append({"name": table, "row_count": count})
                except:
                    table_info.append({"name": table, "row_count": "error"})

            conn.close()

            return ToolResult(
                success=True,
                data={
                    "tables": table_info,
                    "count": len(tables),
                },
                raw_output=f"Found {len(tables)} tables: {', '.join(tables)}",
            )

        except Exception as e:
            return ToolResult(
                success=False,
                data={},
                error=str(e),
            )
        finally:
            self._cleanup(temp_path)

    async def describe_table(
        self,
        database: str,
        table: str,
        is_base64: bool = False,
    ) -> ToolResult:
        """Get table schema."""
        self.logger.info(f"Describing table: {table}")

        temp_path = None
        try:
            conn, temp_path = self._get_connection(database, is_base64)
            cursor = conn.cursor()

            cursor.execute(f'PRAGMA table_info("{table}")')
            columns = []
            for row in cursor.fetchall():
                columns.append({
                    "cid": row[0],
                    "name": row[1],
                    "type": row[2],
                    "notnull": bool(row[3]),
                    "default": row[4],
                    "pk": bool(row[5]),
                })

            # Get row count
            cursor.execute(f'SELECT COUNT(*) FROM "{table}"')
            row_count = cursor.fetchone()[0]

            conn.close()

            return ToolResult(
                success=True,
                data={
                    "table": table,
                    "columns": columns,
                    "column_count": len(columns),
                    "row_count": row_count,
                },
                raw_output=f"Table {table}: {len(columns)} columns, {row_count} rows",
            )

        except Exception as e:
            return ToolResult(
                success=False,
                data={},
                error=str(e),
            )
        finally:
            self._cleanup(temp_path)

    async def dump_table(
        self,
        database: str,
        table: str,
        columns: Optional[List[str]] = None,
        limit: int = 100,
        is_base64: bool = False,
    ) -> ToolResult:
        """Dump table contents."""
        self.logger.info(f"Dumping table: {table}")

        temp_path = None
        try:
            conn, temp_path = self._get_connection(database, is_base64)
            cursor = conn.cursor()

            # Build column list
            if columns:
                col_str = ", ".join(f'"{c}"' for c in columns)
            else:
                col_str = "*"

            cursor.execute(f'SELECT {col_str} FROM "{table}" LIMIT {limit}')

            # Get column names from cursor
            col_names = [desc[0] for desc in cursor.description]

            rows = cursor.fetchall()
            results = [dict(row) for row in rows]

            conn.close()

            return ToolResult(
                success=True,
                data={
                    "table": table,
                    "columns": col_names,
                    "rows": results,
                    "row_count": len(results),
                },
                raw_output=f"Dumped {len(results)} rows from {table}",
            )

        except Exception as e:
            return ToolResult(
                success=False,
                data={},
                error=str(e),
            )
        finally:
            self._cleanup(temp_path)

    async def find_credentials(
        self,
        database: str,
        is_base64: bool = False,
        limit: int = 100,
    ) -> ToolResult:
        """Search for credential-related tables and data."""
        self.logger.info("Searching for credentials")

        temp_path = None
        try:
            conn, temp_path = self._get_connection(database, is_base64)
            cursor = conn.cursor()

            # Get all tables
            cursor.execute(
                "SELECT name FROM sqlite_master WHERE type='table'"
            )
            all_tables = [row[0] for row in cursor.fetchall()]

            # Find credential-related tables
            credential_tables = []
            for table in all_tables:
                table_lower = table.lower()
                for pattern in CREDENTIAL_TABLE_PATTERNS:
                    if pattern in table_lower:
                        credential_tables.append(table)
                        break

            # If no obvious credential tables, check all tables for credential columns
            if not credential_tables:
                credential_tables = all_tables

            # Extract credentials from matching tables
            found_credentials = []

            for table in credential_tables:
                try:
                    # Get columns
                    cursor.execute(f'PRAGMA table_info("{table}")')
                    columns = [row[1] for row in cursor.fetchall()]

                    # Find username and password columns
                    username_cols = []
                    password_cols = []

                    for col in columns:
                        col_lower = col.lower()
                        for pattern in USERNAME_COLUMN_PATTERNS:
                            if pattern in col_lower:
                                username_cols.append(col)
                                break
                        for pattern in CREDENTIAL_COLUMN_PATTERNS:
                            if pattern in col_lower:
                                password_cols.append(col)
                                break

                    # If we found potential credential columns, extract data
                    if username_cols or password_cols:
                        select_cols = list(set(username_cols + password_cols))
                        if not select_cols:
                            continue

                        col_str = ", ".join(f'"{c}"' for c in select_cols)
                        cursor.execute(f'SELECT {col_str} FROM "{table}" LIMIT {limit}')

                        rows = cursor.fetchall()
                        for row in rows:
                            cred = {
                                "table": table,
                            }
                            for i, col in enumerate(select_cols):
                                cred[col] = row[i]
                            found_credentials.append(cred)

                except Exception as e:
                    self.logger.warning(f"Error processing table {table}: {e}")
                    continue

            conn.close()

            # Format for easy viewing
            formatted_creds = []
            for cred in found_credentials:
                parts = []
                for k, v in cred.items():
                    if k != "table" and v is not None:
                        parts.append(f"{k}:{v}")
                if parts:
                    formatted_creds.append(f"[{cred['table']}] " + " | ".join(parts))

            return ToolResult(
                success=True,
                data={
                    "credential_tables": credential_tables,
                    "credentials": found_credentials,
                    "count": len(found_credentials),
                },
                raw_output="\n".join(formatted_creds) if formatted_creds else "No credentials found",
            )

        except Exception as e:
            return ToolResult(
                success=False,
                data={},
                error=str(e),
            )
        finally:
            self._cleanup(temp_path)

    async def schema(
        self,
        database: str,
        is_base64: bool = False,
    ) -> ToolResult:
        """Get full database schema."""
        self.logger.info("Getting database schema")

        temp_path = None
        try:
            conn, temp_path = self._get_connection(database, is_base64)
            cursor = conn.cursor()

            # Get all tables with their CREATE statements
            cursor.execute(
                "SELECT name, sql FROM sqlite_master WHERE type='table' ORDER BY name"
            )

            tables = {}
            for row in cursor.fetchall():
                table_name = row[0]
                create_sql = row[1]

                # Get column info
                cursor.execute(f'PRAGMA table_info("{table_name}")')
                columns = []
                for col_row in cursor.fetchall():
                    columns.append({
                        "name": col_row[1],
                        "type": col_row[2],
                        "notnull": bool(col_row[3]),
                        "pk": bool(col_row[5]),
                    })

                # Get row count
                cursor.execute(f'SELECT COUNT(*) FROM "{table_name}"')
                row_count = cursor.fetchone()[0]

                tables[table_name] = {
                    "columns": columns,
                    "row_count": row_count,
                    "create_sql": create_sql,
                }

            conn.close()

            # Format output
            output_lines = []
            for table_name, info in tables.items():
                col_strs = [f"{c['name']} ({c['type']})" for c in info["columns"]]
                output_lines.append(f"{table_name} ({info['row_count']} rows): {', '.join(col_strs)}")

            return ToolResult(
                success=True,
                data={
                    "tables": tables,
                    "table_count": len(tables),
                },
                raw_output="\n".join(output_lines),
            )

        except Exception as e:
            return ToolResult(
                success=False,
                data={},
                error=str(e),
            )
        finally:
            self._cleanup(temp_path)


if __name__ == "__main__":
    SQLiteServer.main()
