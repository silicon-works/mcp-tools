#!/usr/bin/env python3
"""
OpenSploit MCP Server: sqlmap

Automatic SQL injection and database takeover tool.
"""

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
            version="2.0.0",
        )

        # ── Common optional params reused across ALL methods ──────────────
        _common_params = {
            # -- Request params --
            "data": {
                "type": "string",
                "description": "POST request body data. Switches sqlmap to POST method. Format: 'param1=value1&param2=value2'. Use * to mark injection point.",
            },
            "cookie": {
                "type": "string",
                "description": "HTTP Cookie header value (e.g., 'PHPSESSID=abc123; session=xyz'). At level >= 2, sqlmap also tests cookies for injection.",
            },
            "headers": {
                "type": "string",
                "description": "Additional HTTP headers, semicolon-separated. Example: 'Authorization: Bearer eyJ...;X-Custom: value'.",
            },
            "method": {
                "type": "enum",
                "values": ["GET", "POST", "PUT", "PATCH", "DELETE"],
                "description": "Force HTTP method. By default sqlmap uses GET (or POST if --data is set).",
            },
            "auth_type": {
                "type": "enum",
                "values": ["Basic", "Digest", "NTLM", "PKI"],
                "description": "HTTP authentication type.",
            },
            "auth_cred": {
                "type": "string",
                "description": "HTTP authentication credentials. Format: 'user:password'.",
            },
            "csrf_token": {
                "type": "string",
                "description": "Parameter name holding the anti-CSRF token (e.g., 'csrf_token', '_token').",
            },
            "csrf_url": {
                "type": "string",
                "description": "URL to fetch the anti-CSRF token from, if different from the target URL.",
            },
            # -- Detection/fingerprinting --
            "dbms": {
                "type": "string",
                "description": "Force DBMS type to skip detection. Values: 'MySQL', 'PostgreSQL', 'Oracle', 'Microsoft SQL Server', 'SQLite'. Speeds up exploitation when DBMS is known.",
            },
            "ignore_code": {
                "type": "string",
                "description": "Ignore problematic HTTP status codes (e.g., '401' or '401,500'). Critical when the target endpoint returns non-200 status — without this, sqlmap may refuse to test.",
            },
            "string": {
                "type": "string",
                "description": "String that is always present in TRUE responses (boolean-based detection). Dramatically speeds up blind injection when set correctly.",
            },
            "not_string": {
                "type": "string",
                "description": "String that is always present in FALSE responses.",
            },
            "code": {
                "type": "integer",
                "description": "HTTP status code that indicates TRUE response (e.g., 200). Alternative to --string for boolean-based detection.",
            },
            "text_only": {
                "type": "boolean",
                "default": False,
                "description": "Compare pages based only on textual content (strip HTML tags). Useful when pages have dynamic non-text content.",
            },
            "titles": {
                "type": "boolean",
                "default": False,
                "description": "Compare pages based only on their titles. Useful when page body is highly dynamic but title changes predictably.",
            },
            # -- Injection tuning --
            "level": {
                "type": "integer",
                "default": 1,
                "description": "Test level 1-5. Level 1: GET/POST params. Level 2: +Cookie. Level 3: +User-Agent/Referer. Higher = more payloads, slower.",
            },
            "risk": {
                "type": "integer",
                "default": 1,
                "description": "Risk level 1-3. Risk 1: safe only. Risk 2: +heavy time-based. Risk 3: +OR-based (can modify data).",
            },
            "technique": {
                "type": "string",
                "default": "BEUSTQ",
                "description": "Injection techniques: B=Boolean, E=Error, U=Union, S=Stacked, T=Time, Q=Inline. Default 'BEUSTQ' = all.",
            },
            "param": {
                "type": "string",
                "description": "Specific parameter to test (e.g., 'id'). Without this, sqlmap tests all parameters.",
            },
            "tamper": {
                "type": "string",
                "description": "Tamper script(s) for WAF bypass. Comma-separated. Common: 'space2comment', 'between', 'charencode', 'randomcase'.",
            },
            "prefix": {
                "type": "string",
                "description": "Injection payload prefix (e.g., \"')\" ). Use when you know the exact SQL context.",
            },
            "suffix": {
                "type": "string",
                "description": "Injection payload suffix (e.g., '-- -'). Use when you know the exact SQL context.",
            },
            "union_cols": {
                "type": "string",
                "description": "Range of columns to test for UNION query injection (e.g., '5-10'). Narrows search when you know approximate column count.",
            },
            "second_url": {
                "type": "string",
                "description": "URL where the injection result appears (second-order injection). The injection is sent to the target URL but the result is read from this URL.",
            },
            "eval": {
                "type": "string",
                "description": "Python code evaluated before each request (e.g., \"import hashlib; token=hashlib.md5(id.encode()).hexdigest()\"). Use for computed parameters.",
            },
            "time_sec": {
                "type": "integer",
                "default": 5,
                "description": "Seconds to delay for time-based blind injection. Increase to 10-15 on high-latency targets to avoid false negatives.",
            },
            # -- Performance/reliability --
            "threads": {
                "type": "integer",
                "default": 4,
                "description": "Number of concurrent HTTP requests (1-10). Default 4. Increase for faster extraction on stable targets.",
            },
            "delay": {
                "type": "number",
                "default": 0,
                "description": "Delay in seconds between each HTTP request. Use 1-3 to avoid rate limiting or WAF bans.",
            },
            "retries": {
                "type": "integer",
                "default": 3,
                "description": "Retries on connection failure.",
            },
            "safe_url": {
                "type": "string",
                "description": "URL to visit between injection requests to keep session alive or avoid detection patterns.",
            },
            "safe_freq": {
                "type": "integer",
                "description": "How often to visit --safe-url (every N requests).",
            },
            "null_connection": {
                "type": "boolean",
                "default": False,
                "description": "Use HTTP Range/HEAD to detect boolean responses without downloading full pages. Faster but may not work on all targets.",
            },
            # -- Connection --
            "proxy": {
                "type": "string",
                "description": "HTTP/SOCKS proxy (e.g., 'http://127.0.0.1:8080', 'socks5://127.0.0.1:1080'). Use for scanning through tunnels or Burp interception.",
            },
            "random_agent": {
                "type": "boolean",
                "default": False,
                "description": "Use a random HTTP User-Agent to avoid WAF detection. Sqlmap's default UA is commonly blocked.",
            },
            # -- Session --
            "flush_session": {
                "type": "boolean",
                "default": False,
                "description": "Clear cached session data and re-test from scratch.",
            },
        }

        # ── Method registrations ──────────────────────────────────────────

        self.register_method(
            name="test_injection",
            description="Test a URL parameter for SQL injection vulnerabilities",
            params={
                "url": {
                    "type": "string",
                    "required": True,
                    "description": "Target URL with injectable parameter (use * to mark injection point)",
                },
                **_common_params,
                "timeout": {
                    "type": "integer",
                    "default": 1800,
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
                **_common_params,
                "timeout": {
                    "type": "integer",
                    "default": 1800,
                    "description": "Timeout in seconds",
                },
            },
            handler=self.enumerate_dbs,
        )

        self.register_method(
            name="enumerate_tables",
            description="List all tables in a database",
            params={
                "url": {
                    "type": "string",
                    "required": True,
                    "description": "Target URL (previously confirmed vulnerable)",
                },
                "database": {
                    "type": "string",
                    "required": True,
                    "description": "Database name from enumerate_dbs",
                },
                **_common_params,
                "timeout": {
                    "type": "integer",
                    "default": 1800,
                    "description": "Timeout in seconds",
                },
            },
            handler=self.enumerate_tables,
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
                "limit": {
                    "type": "integer",
                    "default": 100,
                    "description": "Maximum rows to dump (maps to --stop)",
                },
                "where": {
                    "type": "string",
                    "description": "SQL WHERE clause for targeted extraction (e.g., \"role='admin'\"). Reduces extraction time vs full table dump.",
                },
                **_common_params,
                "timeout": {
                    "type": "integer",
                    "default": 3600,
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
                **_common_params,
                "timeout": {
                    "type": "integer",
                    "default": 7200,
                    "description": "Timeout in seconds",
                },
            },
            handler=self.dump_all,
        )

        self.register_method(
            name="dump_passwords",
            description="Dump database user password hashes",
            params={
                "url": {
                    "type": "string",
                    "required": True,
                    "description": "Target URL (previously confirmed vulnerable)",
                },
                **_common_params,
                "timeout": {
                    "type": "integer",
                    "default": 3600,
                    "description": "Timeout in seconds",
                },
            },
            handler=self.dump_passwords,
        )

        self.register_method(
            name="os_shell",
            description="Execute an OS command via SQL injection (requires stacked queries or specific DBMS)",
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
                **_common_params,
                "timeout": {
                    "type": "integer",
                    "default": 600,
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
                **_common_params,
                "timeout": {
                    "type": "integer",
                    "default": 600,
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
                **_common_params,
                "timeout": {
                    "type": "integer",
                    "default": 600,
                    "description": "Timeout in seconds",
                },
            },
            handler=self.file_write,
        )

        self.register_method(
            name="sql_query",
            description="Execute a raw SQL query via injection and return the result",
            params={
                "url": {
                    "type": "string",
                    "required": True,
                    "description": "Target URL (previously confirmed vulnerable)",
                },
                "query": {
                    "type": "string",
                    "required": True,
                    "description": "SQL query to execute (e.g., 'SELECT @@version', 'SELECT user,password FROM mysql.user')",
                },
                **_common_params,
                "timeout": {
                    "type": "integer",
                    "default": 1800,
                    "description": "Timeout in seconds",
                },
            },
            handler=self.sql_query,
        )

    # ── Common arg builder ────────────────────────────────────────────────

    @staticmethod
    def _append_common_args(args: list, **kwargs) -> None:
        """Append common optional args to a sqlmap command.

        Each kwarg maps 1:1 to a sqlmap flag.  Only emits flags when the
        value differs from sqlmap's own built-in default so that callers
        with no new params produce identical CLI commands.
        """
        # -- Request params --
        if kwargs.get("data"):
            args.extend(["--data", kwargs["data"]])
        if kwargs.get("cookie"):
            args.extend(["--cookie", kwargs["cookie"]])
        if kwargs.get("headers"):
            for header in kwargs["headers"].replace(";", "\n").split("\n"):
                header = header.strip()
                if header:
                    args.extend(["-H", header])
        if kwargs.get("method"):
            args.extend(["--method", kwargs["method"]])
        if kwargs.get("auth_type"):
            args.extend(["--auth-type", kwargs["auth_type"]])
        if kwargs.get("auth_cred"):
            args.extend(["--auth-cred", kwargs["auth_cred"]])
        if kwargs.get("csrf_token"):
            args.extend(["--csrf-token", kwargs["csrf_token"]])
        if kwargs.get("csrf_url"):
            args.extend(["--csrf-url", kwargs["csrf_url"]])

        # -- Detection/fingerprinting --
        if kwargs.get("dbms"):
            args.extend(["--dbms", kwargs["dbms"]])
        if kwargs.get("ignore_code"):
            args.extend(["--ignore-code", kwargs["ignore_code"]])
        if kwargs.get("string"):
            args.extend(["--string", kwargs["string"]])
        if kwargs.get("not_string"):
            args.extend(["--not-string", kwargs["not_string"]])
        if kwargs.get("code"):
            args.extend(["--code", str(kwargs["code"])])
        if kwargs.get("text_only"):
            args.append("--text-only")
        if kwargs.get("titles"):
            args.append("--titles")

        # -- Injection tuning (only emit when non-default) --
        level = kwargs.get("level", 1)
        if level != 1:
            args.extend(["--level", str(level)])
        risk = kwargs.get("risk", 1)
        if risk != 1:
            args.extend(["--risk", str(risk)])
        technique = kwargs.get("technique", "BEUSTQ")
        if technique != "BEUSTQ":
            args.extend(["--technique", technique])
        if kwargs.get("param"):
            args.extend(["-p", kwargs["param"]])
        if kwargs.get("tamper"):
            args.extend(["--tamper", kwargs["tamper"]])
        if kwargs.get("prefix"):
            args.extend(["--prefix", kwargs["prefix"]])
        if kwargs.get("suffix"):
            args.extend(["--suffix", kwargs["suffix"]])
        if kwargs.get("union_cols"):
            args.extend(["--union-cols", kwargs["union_cols"]])
        if kwargs.get("second_url"):
            args.extend(["--second-url", kwargs["second_url"]])
        if kwargs.get("eval"):
            args.extend(["--eval", kwargs["eval"]])
        time_sec = kwargs.get("time_sec", 5)
        if time_sec != 5:
            args.extend(["--time-sec", str(time_sec)])

        # -- Performance/reliability --
        threads = kwargs.get("threads", 4)
        args.extend(["--threads", str(threads)])
        delay = kwargs.get("delay", 0)
        if delay:
            args.extend(["--delay", str(delay)])
        retries = kwargs.get("retries", 3)
        if retries != 3:
            args.extend(["--retries", str(retries)])
        if kwargs.get("safe_url"):
            args.extend(["--safe-url", kwargs["safe_url"]])
        if kwargs.get("safe_freq"):
            args.extend(["--safe-freq", str(kwargs["safe_freq"])])
        if kwargs.get("null_connection"):
            args.append("--null-connection")

        # -- Connection --
        if kwargs.get("proxy"):
            args.extend(["--proxy", kwargs["proxy"]])
        if kwargs.get("random_agent"):
            args.append("--random-agent")

        # -- Session --
        if kwargs.get("flush_session"):
            args.append("--flush-session")

    # ── Progress filter ───────────────────────────────────────────────────

    _SQLMAP_PROGRESS_RE = re.compile(r"^\[(\d{2}:\d{2}:\d{2})\]\s+\[(INFO|WARNING|CRITICAL)\]\s+(.+)")
    _SQLMAP_NOISY_PATTERNS = re.compile(
        r"testing connection|heuristic|loaded tamper|starting at|ending at|legal disclaimer|"
        r"flushing session|cleaning up|shutting down",
        re.IGNORECASE,
    )

    @staticmethod
    def _sqlmap_progress_filter(line: str) -> str | None:
        """Return a short progress message for [INFO]/[WARNING]/[CRITICAL] lines, or None."""
        m = SqlmapServer._SQLMAP_PROGRESS_RE.match(line.strip())
        if m is None:
            return None
        severity, msg = m.group(2), m.group(3)
        if SqlmapServer._SQLMAP_NOISY_PATTERNS.search(msg):
            return None
        label = f"[{severity}] {msg}"
        return label[:120]

    # ── Output parsers ────────────────────────────────────────────────────

    def _parse_sqlmap_output(self, output: str) -> Dict[str, Any]:
        """Parse sqlmap output for injection results."""
        result: Dict[str, Any] = {
            "vulnerable": False,
            "injection_type": None,
            "dbms": None,
            "parameters": [],
            "details": [],
        }

        for line in output.split("\n"):
            if "is vulnerable" in line.lower() or ("parameter" in line.lower() and "injectable" in line.lower() and "not appear" not in line.lower()):
                result["vulnerable"] = True

            param_match = re.search(r"Parameter: (\S+)", line)
            if param_match:
                param = param_match.group(1)
                if param not in result["parameters"]:
                    result["parameters"].append(param)

            if "Type:" in line:
                type_match = re.search(r"Type: (.+)", line)
                if type_match:
                    result["injection_type"] = type_match.group(1).strip()

            if "back-end dbms:" in line.lower():
                dbms_match = re.search(r"back-end DBMS: (.+)", line, re.IGNORECASE)
                if dbms_match:
                    result["dbms"] = dbms_match.group(1).strip()

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
                if line.strip().startswith("[*]"):
                    db = line.strip()[3:].strip()
                    if db:
                        databases.append(db)
                elif line.strip() and not line.startswith("["):
                    db = line.strip()
                    if db and not db.startswith("-"):
                        databases.append(db)

        return databases

    def _parse_table_dump(self, output: str) -> Dict[str, Any]:
        """Parse sqlmap table dump output."""
        result: Dict[str, Any] = {
            "columns": [],
            "rows": [],
            "row_count": 0,
        }

        in_table = False
        header_parsed = False

        for line in output.split("\n"):
            line = line.strip()

            if re.match(r"^[\+\-]+$", line):
                in_table = True
                continue

            if in_table and line.startswith("|"):
                cells = [c.strip() for c in line.split("|")[1:-1]]

                if not header_parsed:
                    result["columns"] = cells
                    header_parsed = True
                else:
                    if cells and any(c for c in cells):
                        result["rows"].append(dict(zip(result["columns"], cells)))

        result["row_count"] = len(result["rows"])
        return result

    # ── Handlers ──────────────────────────────────────────────────────────

    async def test_injection(self, url: str, **kwargs) -> ToolResult:
        """Test a URL parameter for SQL injection vulnerabilities."""
        timeout = kwargs.pop("timeout", 1800)
        self.logger.info(f"Testing SQL injection on {url}")

        args = ["sqlmap", "-u", url, "--batch"]
        self._append_common_args(args, **kwargs)

        try:
            self.logger.info(f"Running: {' '.join(args)}")
            result = await self.run_command_with_progress(
                args, timeout=timeout,
                progress_filter=self._sqlmap_progress_filter,
            )

            output = result.stdout + result.stderr
            parsed = self._parse_sqlmap_output(output)

            parsed["summary"] = {
                "target": url,
                "level": kwargs.get("level", 1),
                "risk": kwargs.get("risk", 1),
                "vulnerable": parsed["vulnerable"],
            }

            return ToolResult(
                success=True,
                data=parsed,
                raw_output=sanitize_output(output),
            )

        except ToolError as e:
            return ToolResult(success=False, data={}, error=str(e))

    async def enumerate_dbs(self, url: str, **kwargs) -> ToolResult:
        """Enumerate databases on a confirmed vulnerable target."""
        timeout = kwargs.pop("timeout", 1800)
        self.logger.info(f"Enumerating databases on {url}")

        args = ["sqlmap", "-u", url, "--batch", "--dbs"]
        self._append_common_args(args, **kwargs)

        try:
            self.logger.info(f"Running: {' '.join(args)}")
            result = await self.run_command_with_progress(
                args, timeout=timeout,
                progress_filter=self._sqlmap_progress_filter,
            )

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
            return ToolResult(success=False, data={}, error=str(e))

    async def enumerate_tables(self, url: str, database: str, **kwargs) -> ToolResult:
        """List all tables in a database."""
        timeout = kwargs.pop("timeout", 1800)
        self.logger.info(f"Enumerating tables in {database} on {url}")

        args = ["sqlmap", "-u", url, "--batch", "-D", database, "--tables"]
        self._append_common_args(args, **kwargs)

        try:
            result = await self.run_command_with_progress(
                args, timeout=timeout,
                progress_filter=self._sqlmap_progress_filter,
            )
            output = result.stdout + result.stderr

            tables = []
            in_table_section = False
            for line in output.split("\n"):
                if "Database:" in line and database in line:
                    in_table_section = True
                    continue
                if in_table_section:
                    line_s = line.strip()
                    if line_s.startswith("[") and "tables" in line_s:
                        continue
                    if line_s.startswith("+") or line_s.startswith("-"):
                        continue
                    if line_s.startswith("|"):
                        table = line_s.strip("|").strip()
                        if table:
                            tables.append(table)
                    elif line_s == "" and tables:
                        break

            return ToolResult(
                success=True,
                data={
                    "database": database,
                    "tables": tables,
                    "count": len(tables),
                    "target": url,
                },
                raw_output=sanitize_output(output),
            )
        except ToolError as e:
            return ToolResult(success=False, data={}, error=str(e))

    async def dump_table(self, url: str, database: str, table: str, **kwargs) -> ToolResult:
        """Dump contents of a database table."""
        timeout = kwargs.pop("timeout", 3600)
        columns = kwargs.pop("columns", None)
        limit = kwargs.pop("limit", 100)
        where = kwargs.pop("where", None)
        self.logger.info(f"Dumping table {database}.{table} from {url}")

        args = [
            "sqlmap", "-u", url, "--batch",
            "-D", database, "-T", table,
            "--dump", "--dump-format", "CSV",
        ]

        if columns:
            args.extend(["-C", columns])
        if limit:
            args.extend(["--stop", str(limit)])
        if where:
            args.extend(["--where", where])

        self._append_common_args(args, **kwargs)

        try:
            self.logger.info(f"Running: {' '.join(args)}")
            result = await self.run_command_with_progress(
                args, timeout=timeout,
                progress_filter=self._sqlmap_progress_filter,
            )

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
            return ToolResult(success=False, data={}, error=str(e))

    async def dump_all(self, url: str, database: str, **kwargs) -> ToolResult:
        """Dump all tables from a database."""
        timeout = kwargs.pop("timeout", 7200)
        self.logger.info(f"Dumping all tables from {database} on {url}")

        args = ["sqlmap", "-u", url, "--batch", "-D", database, "--dump-all"]
        self._append_common_args(args, **kwargs)

        try:
            self.logger.info(f"Running: {' '.join(args)}")
            result = await self.run_command_with_progress(
                args, timeout=timeout,
                progress_filter=self._sqlmap_progress_filter,
            )

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
            return ToolResult(success=False, data={}, error=str(e))

    async def dump_passwords(self, url: str, **kwargs) -> ToolResult:
        """Dump database user password hashes."""
        timeout = kwargs.pop("timeout", 3600)
        self.logger.info(f"Dumping password hashes from {url}")

        args = ["sqlmap", "-u", url, "--batch", "--passwords"]
        self._append_common_args(args, **kwargs)

        try:
            result = await self.run_command_with_progress(
                args, timeout=timeout,
                progress_filter=self._sqlmap_progress_filter,
            )
            output = result.stdout + result.stderr

            hashes = []
            current_user = None
            for line in output.split("\n"):
                if "database management system users password hashes" in line.lower():
                    continue
                user_match = re.match(r"\[\*\]\s+(\S+)", line)
                if user_match:
                    current_user = user_match.group(1)
                    continue
                hash_match = re.match(r"\s+password hash:\s+(.+)", line)
                if hash_match and current_user:
                    hashes.append({
                        "user": current_user,
                        "hash": hash_match.group(1).strip(),
                    })

            return ToolResult(
                success=True,
                data={
                    "hashes": hashes,
                    "count": len(hashes),
                    "target": url,
                },
                raw_output=sanitize_output(output),
            )
        except ToolError as e:
            return ToolResult(success=False, data={}, error=str(e))

    async def os_shell(self, url: str, command: str, **kwargs) -> ToolResult:
        """Execute an OS command via SQL injection."""
        timeout = kwargs.pop("timeout", 600)
        self.logger.info(f"Executing OS command on {url}: {command}")

        args = ["sqlmap", "-u", url, "--batch", "--os-cmd", command]
        self._append_common_args(args, **kwargs)

        try:
            self.logger.info(f"Running: {' '.join(args)}")
            result = await self.run_command_with_progress(
                args, timeout=timeout,
                progress_filter=self._sqlmap_progress_filter,
            )

            output = result.stdout + result.stderr

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
            return ToolResult(success=False, data={}, error=str(e))

    async def file_read(self, url: str, file_path: str, **kwargs) -> ToolResult:
        """Read a file from the target server."""
        timeout = kwargs.pop("timeout", 600)
        self.logger.info(f"Reading file {file_path} from {url}")

        args = ["sqlmap", "-u", url, "--batch", "--file-read", file_path]
        self._append_common_args(args, **kwargs)

        try:
            self.logger.info(f"Running: {' '.join(args)}")
            result = await self.run_command_with_progress(
                args, timeout=timeout,
                progress_filter=self._sqlmap_progress_filter,
            )

            output = result.stdout + result.stderr

            file_content = ""
            for line in output.split("\n"):
                if "file saved to" in line.lower():
                    match = re.search(r"'([^']+)'", line)
                    if match:
                        local_path = match.group(1)
                        try:
                            with open(local_path, 'r') as f:
                                file_content = f.read()
                        except Exception:
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
            return ToolResult(success=False, data={}, error=str(e))

    async def file_write(self, url: str, local_file: str, remote_path: str, **kwargs) -> ToolResult:
        """Write a file to the target server."""
        timeout = kwargs.pop("timeout", 600)
        self.logger.info(f"Writing file to {remote_path} on {url}")

        # If local_file is content (not a path), write to temp file
        if not os.path.exists(local_file):
            with tempfile.NamedTemporaryFile(mode='w', delete=False, suffix='.txt') as f:
                f.write(local_file)
                local_file = f.name

        args = [
            "sqlmap", "-u", url, "--batch",
            "--file-write", local_file,
            "--file-dest", remote_path,
        ]
        self._append_common_args(args, **kwargs)

        try:
            self.logger.info(f"Running: {' '.join(args)}")
            result = await self.run_command_with_progress(
                args, timeout=timeout,
                progress_filter=self._sqlmap_progress_filter,
            )

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
            return ToolResult(success=False, data={}, error=str(e))

    async def sql_query(self, url: str, query: str, **kwargs) -> ToolResult:
        """Execute a raw SQL query via injection and return the result."""
        timeout = kwargs.pop("timeout", 1800)
        self.logger.info(f"Executing SQL query on {url}: {query}")

        args = ["sqlmap", "-u", url, "--batch", "--sql-query", query]
        self._append_common_args(args, **kwargs)

        try:
            self.logger.info(f"Running: {' '.join(args)}")
            result = await self.run_command_with_progress(
                args, timeout=timeout,
                progress_filter=self._sqlmap_progress_filter,
            )

            output = result.stdout + result.stderr

            # Extract query result from sqlmap output
            query_result = ""
            in_result = False
            for line in output.split("\n"):
                # sqlmap prints the query result after "[INFO] retrieved:" or as table output
                if "sql-query" in line.lower() and "output" in line.lower():
                    in_result = True
                    continue
                if in_result:
                    if line.startswith("[") and not line.startswith("[*]"):
                        if "INFO" not in line and "WARNING" not in line:
                            in_result = False
                            continue
                    stripped = line.strip()
                    if stripped:
                        query_result += stripped + "\n"

            # Also try to catch inline results like "[INFO] retrieved: value"
            if not query_result:
                for line in output.split("\n"):
                    m = re.search(r"\[INFO\]\s+retrieved:\s+(.+)", line)
                    if m:
                        query_result += m.group(1).strip() + "\n"

            return ToolResult(
                success=True,
                data={
                    "query": query,
                    "result": query_result.strip(),
                    "target": url,
                },
                raw_output=sanitize_output(output),
            )

        except ToolError as e:
            return ToolResult(success=False, data={}, error=str(e))


if __name__ == "__main__":
    SqlmapServer.main()
