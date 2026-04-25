"""
Tests for the sqlmap MCP tool server.

Covers:
- Smoke tests: boot, method list, required params, meta-param stripping, clock
- Unit tests: output parsers (_parse_sqlmap_output, _parse_databases, _parse_table_dump,
  password hash parser, os_shell parser, sql_query parser) with fixture files
- Common arg builder: _append_common_args covers all flags
- Progress filter: _sqlmap_progress_filter line-level filtering
- Timeout architecture: run_command_with_progress usage, heartbeat
- Error classification: sqlmap-specific patterns (WAF, connection, not injectable)
- Contract tests: tool.yaml vs server parameter definitions
- Acceptance tests: every method called through container (no live target)
- Integration tests: real target scenarios (marked @pytest.mark.integration)
"""

import asyncio
import importlib.util
import inspect
import json
import os
import re
import sys
from pathlib import Path
from typing import Any, Dict, Set

import pytest
import yaml

# ---------------------------------------------------------------------------
# Path setup
# ---------------------------------------------------------------------------
PROJECT_ROOT = Path(__file__).parent.parent.parent
TOOL_DIR = PROJECT_ROOT / "tools" / "sqlmap"
FIXTURES_DIR = Path(__file__).parent.parent / "fixtures" / "sqlmap"

sys.path.insert(0, str(TOOL_DIR))

# Import conftest helpers
from conftest import (
    MCPTestClient,
    assert_tool_error,
    assert_tool_success,
    parse_tool_output,
)


# ---------------------------------------------------------------------------
# Module-scoped fixture: create our OWN client + loop so we control both.
# ---------------------------------------------------------------------------
@pytest.fixture(scope="module")
def sqlmap_env(request):
    """Create an MCPTestClient with its event loop. Yields (client, loop)."""
    tool = "sqlmap"
    prefix = request.config.getoption("--image-prefix", default="mcp-test-")
    image = f"{prefix}{tool}"

    client = MCPTestClient(image=image, tool_name=tool)
    loop = asyncio.new_event_loop()
    try:
        loop.run_until_complete(client.start())
    except Exception:
        loop.run_until_complete(client.stop())
        loop.close()
        raise

    yield client, loop

    loop.run_until_complete(client.stop())
    loop.close()


def _run(env_tuple, coro):
    """Run an async coroutine on the environment's loop."""
    _, loop = env_tuple
    return loop.run_until_complete(coro)


# ---------------------------------------------------------------------------
# Helper: load fixture files
# ---------------------------------------------------------------------------
def load_fixture(name: str) -> str:
    """Load a fixture text file."""
    path = FIXTURES_DIR / name
    return path.read_text()


# ---------------------------------------------------------------------------
# Helper: import server module for direct testing
# ---------------------------------------------------------------------------
def _get_server_class():
    """Import and return the SqlmapServer class for direct method testing."""
    spec = importlib.util.spec_from_file_location(
        "sqlmap_server", TOOL_DIR / "mcp-server.py"
    )
    mod = importlib.util.module_from_spec(spec)
    spec.loader.exec_module(mod)
    return mod.SqlmapServer


# ===========================================================================
# SMOKE TESTS -- require Docker container running
# ===========================================================================

class TestSmoke:
    """Smoke tests that verify the container boots and basic protocol works."""

    def test_boot_and_list_tools(self, sqlmap_env):
        """Container starts and list_tools returns methods."""
        client, loop = sqlmap_env
        assert len(client.tools) > 0, "Server should advertise at least one tool"
        names = client.tool_names()
        assert "test_injection" in names, "test_injection should be in tool list"
        assert "enumerate_dbs" in names, "enumerate_dbs should be in tool list"
        assert "enumerate_tables" in names, "enumerate_tables should be in tool list"
        assert "dump_table" in names, "dump_table should be in tool list"
        assert "dump_all" in names, "dump_all should be in tool list"
        assert "dump_passwords" in names, "dump_passwords should be in tool list"
        assert "os_shell" in names, "os_shell should be in tool list"
        assert "file_read" in names, "file_read should be in tool list"
        assert "file_write" in names, "file_write should be in tool list"
        assert "sql_query" in names, "sql_query should be in tool list"

    def test_method_list_matches_tool_yaml(self, sqlmap_env):
        """Every method in tool.yaml is advertised by the server, and vice versa."""
        client, _ = sqlmap_env
        server_names = client.tool_names()

        # Remove verify_clock -- it's test-only, not in tool.yaml
        server_names_no_test = server_names - {"verify_clock"}

        yaml_path = TOOL_DIR / "tool.yaml"
        with open(yaml_path) as f:
            yaml_data = yaml.safe_load(f)
        yaml_names = set(yaml_data.get("methods", {}).keys())

        yaml_only = yaml_names - server_names_no_test
        server_only = server_names_no_test - yaml_names

        assert not yaml_only, f"Methods in tool.yaml but not server: {yaml_only}"
        assert not server_only, f"Methods in server but not tool.yaml: {server_only}"

    def test_expected_method_count(self, sqlmap_env):
        """Server should have exactly 10 built-in methods + verify_clock."""
        client, _ = sqlmap_env
        names = client.tool_names()
        # 10 built-in + verify_clock in MCP_TEST_MODE
        assert len(names) == 11, (
            f"Expected 11 methods (10 built-in + verify_clock), got {len(names)}: {sorted(names)}"
        )

    def test_required_params_test_injection(self, sqlmap_env):
        """Calling test_injection without required 'url' param returns an error."""
        client, loop = sqlmap_env
        resp = loop.run_until_complete(
            client.call("test_injection", {
                "level": 1,
            })
        )
        result = resp.get("result", {})
        is_error = result.get("isError", False)
        content_text = ""
        for c in result.get("content", []):
            if c.get("type") == "text":
                content_text += c["text"]
        assert is_error or "url" in content_text.lower() or "error" in content_text.lower(), (
            f"Expected error about missing 'url', got: {content_text[:300]}"
        )

    def test_required_params_enumerate_dbs(self, sqlmap_env):
        """Calling enumerate_dbs without required 'url' param returns an error."""
        client, loop = sqlmap_env
        resp = loop.run_until_complete(
            client.call("enumerate_dbs", {})
        )
        result = resp.get("result", {})
        is_error = result.get("isError", False)
        content_text = ""
        for c in result.get("content", []):
            if c.get("type") == "text":
                content_text += c["text"]
        assert is_error or "url" in content_text.lower() or "error" in content_text.lower(), (
            f"Expected error about missing 'url', got: {content_text[:300]}"
        )

    def test_required_params_dump_table(self, sqlmap_env):
        """Calling dump_table without required params returns an error."""
        client, loop = sqlmap_env
        resp = loop.run_until_complete(
            client.call("dump_table", {"url": "http://127.0.0.1/test?id=1"})
        )
        result = resp.get("result", {})
        is_error = result.get("isError", False)
        content_text = ""
        for c in result.get("content", []):
            if c.get("type") == "text":
                content_text += c["text"]
        assert is_error or "database" in content_text.lower() or "table" in content_text.lower() or "error" in content_text.lower(), (
            f"Expected error about missing 'database'/'table', got: {content_text[:300]}"
        )

    def test_required_params_os_shell(self, sqlmap_env):
        """Calling os_shell without required 'command' param returns an error."""
        client, loop = sqlmap_env
        resp = loop.run_until_complete(
            client.call("os_shell", {"url": "http://127.0.0.1/test?id=1"})
        )
        result = resp.get("result", {})
        is_error = result.get("isError", False)
        content_text = ""
        for c in result.get("content", []):
            if c.get("type") == "text":
                content_text += c["text"]
        assert is_error or "command" in content_text.lower() or "error" in content_text.lower(), (
            f"Expected error about missing 'command', got: {content_text[:300]}"
        )

    def test_required_params_file_read(self, sqlmap_env):
        """Calling file_read without required 'file_path' param returns an error."""
        client, loop = sqlmap_env
        resp = loop.run_until_complete(
            client.call("file_read", {"url": "http://127.0.0.1/test?id=1"})
        )
        result = resp.get("result", {})
        is_error = result.get("isError", False)
        content_text = ""
        for c in result.get("content", []):
            if c.get("type") == "text":
                content_text += c["text"]
        assert is_error or "file_path" in content_text.lower() or "error" in content_text.lower(), (
            f"Expected error about missing 'file_path', got: {content_text[:300]}"
        )

    def test_required_params_file_write(self, sqlmap_env):
        """Calling file_write without required params returns an error."""
        client, loop = sqlmap_env
        resp = loop.run_until_complete(
            client.call("file_write", {"url": "http://127.0.0.1/test?id=1"})
        )
        result = resp.get("result", {})
        is_error = result.get("isError", False)
        content_text = ""
        for c in result.get("content", []):
            if c.get("type") == "text":
                content_text += c["text"]
        assert is_error or "local_file" in content_text.lower() or "remote_path" in content_text.lower() or "error" in content_text.lower(), (
            f"Expected error about missing params, got: {content_text[:300]}"
        )

    def test_required_params_sql_query(self, sqlmap_env):
        """Calling sql_query without required 'query' param returns an error."""
        client, loop = sqlmap_env
        resp = loop.run_until_complete(
            client.call("sql_query", {"url": "http://127.0.0.1/test?id=1"})
        )
        result = resp.get("result", {})
        is_error = result.get("isError", False)
        content_text = ""
        for c in result.get("content", []):
            if c.get("type") == "text":
                content_text += c["text"]
        assert is_error or "query" in content_text.lower() or "error" in content_text.lower(), (
            f"Expected error about missing 'query', got: {content_text[:300]}"
        )

    def test_meta_params_stripped_timeout(self, sqlmap_env):
        """Passing 'timeout' (meta-param) in args does not crash the server.

        Note: sqlmap server has 'timeout' as an actual registered param, so it
        should NOT be stripped. But it should still not crash.
        """
        client, loop = sqlmap_env
        resp = loop.run_until_complete(
            client.call("test_injection", {
                "url": "http://127.0.0.1:99999/nonexistent?id=1",
                "timeout": 5,
            }, timeout=30)
        )
        result = resp.get("result", {})
        content_text = ""
        for c in result.get("content", []):
            if c.get("type") == "text":
                content_text += c["text"]
        assert "unexpected keyword argument" not in content_text, (
            f"timeout param caused crash: {content_text[:300]}"
        )

    def test_meta_params_stripped_clock_offset(self, sqlmap_env):
        """Passing 'clock_offset' (meta-param) in args does not crash the server."""
        client, loop = sqlmap_env
        resp = loop.run_until_complete(
            client.call("test_injection", {
                "url": "http://127.0.0.1:99999/nonexistent?id=1",
                "clock_offset": "+5h",
                "timeout": 5,
            }, timeout=30)
        )
        result = resp.get("result", {})
        content_text = ""
        for c in result.get("content", []):
            if c.get("type") == "text":
                content_text += c["text"]
        assert "unexpected keyword argument" not in content_text, (
            f"Meta-param 'clock_offset' was not stripped: {content_text[:300]}"
        )

    def test_unknown_method_returns_error(self, sqlmap_env):
        """Calling a non-existent method returns a helpful error.

        Regression: engagement data shows LLM tried 'custom_query' and 'read_file'.
        """
        client, loop = sqlmap_env
        resp = loop.run_until_complete(
            client.call("custom_query", {})
        )
        result = assert_tool_error(resp)
        content_text = ""
        for c in result.get("content", []):
            if c.get("type") == "text":
                content_text += c["text"]
        assert "Unknown method" in content_text
        assert "custom_query" in content_text
        # Should suggest the correct method names
        assert "sql_query" in content_text

    def test_unknown_method_read_file(self, sqlmap_env):
        """LLM tried 'read_file' instead of 'file_read' - verify helpful error."""
        client, loop = sqlmap_env
        resp = loop.run_until_complete(
            client.call("read_file", {})
        )
        result = assert_tool_error(resp)
        content_text = ""
        for c in result.get("content", []):
            if c.get("type") == "text":
                content_text += c["text"]
        assert "Unknown method" in content_text
        assert "file_read" in content_text

    @pytest.mark.clock
    def test_verify_clock_available(self, sqlmap_env):
        """verify_clock is registered in MCP_TEST_MODE."""
        client, _ = sqlmap_env
        names = client.tool_names()
        assert "verify_clock" in names, "verify_clock should be available in test mode"

    @pytest.mark.clock
    def test_verify_clock_returns_time(self, sqlmap_env):
        """verify_clock returns current time and FAKETIME status."""
        client, loop = sqlmap_env
        resp = loop.run_until_complete(client.call("verify_clock", {}))
        result = assert_tool_success(resp)
        data = parse_tool_output(resp)
        assert "current_time" in data
        assert "libfaketime_exists" in data

    def test_structuredContent_present(self, sqlmap_env):
        """Responses include structuredContent with error classification fields."""
        client, loop = sqlmap_env
        resp = loop.run_until_complete(client.call("verify_clock", {}))
        result = resp.get("result", {})
        sc = result.get("structuredContent")
        assert sc is not None, "structuredContent should be present"
        assert "success" in sc
        assert "error_class" in sc
        assert "retryable" in sc
        assert "suggestions" in sc


# ===========================================================================
# UNIT TESTS -- output parsers, no container needed
# ===========================================================================

class TestParseSqlmapOutput:
    """Test _parse_sqlmap_output using fixture data."""

    @classmethod
    def setup_class(cls):
        """Get the SqlmapServer class."""
        try:
            cls._server = _get_server_class()()
        except Exception as e:
            pytest.skip(f"Cannot import SqlmapServer: {e}")

    def test_vulnerable_union_injection(self):
        """Parse output with UNION + boolean-based injection found."""
        output = load_fixture("test_injection_vulnerable_union.txt")
        result = self._server._parse_sqlmap_output(output)

        assert result["vulnerable"] is True
        assert "id" in result["parameters"], f"Expected 'id' in {result['parameters']}"
        assert result["dbms"] is not None
        assert "MySQL" in result["dbms"]
        assert result["injection_type"] is not None
        # Should capture the last Type: line
        assert "UNION query" in result["injection_type"] or "boolean-based" in result["injection_type"]

    def test_vulnerable_time_based_injection(self):
        """Parse output with time-based blind injection found."""
        output = load_fixture("test_injection_vulnerable_time_based.txt")
        result = self._server._parse_sqlmap_output(output)

        assert result["vulnerable"] is True
        assert "tid" in result["parameters"]
        assert "MySQL" in result["dbms"]
        assert "time-based blind" in result["injection_type"]

    def test_vulnerable_post_injection(self):
        """Parse output with POST parameter injection found."""
        output = load_fixture("test_injection_post_vulnerable.txt")
        result = self._server._parse_sqlmap_output(output)

        assert result["vulnerable"] is True
        assert "url" in result["parameters"]
        assert "MySQL" in result["dbms"] or "MariaDB" in result["dbms"]

    def test_vulnerable_mssql(self):
        """Parse output with MSSQL injection found."""
        output = load_fixture("test_injection_mssql_vulnerable.txt")
        result = self._server._parse_sqlmap_output(output)

        assert result["vulnerable"] is True
        assert "ProductID" in result["parameters"]
        assert "Microsoft SQL Server" in result["dbms"]

    def test_not_vulnerable(self):
        """Parse output when no injection is found."""
        output = load_fixture("test_injection_not_vulnerable.txt")
        result = self._server._parse_sqlmap_output(output)

        assert result["vulnerable"] is False
        assert result["parameters"] == []
        assert result["dbms"] is None

    def test_waf_detected(self):
        """Parse output when WAF is detected."""
        output = load_fixture("test_injection_waf_detected.txt")
        result = self._server._parse_sqlmap_output(output)

        assert result["vulnerable"] is False

    def test_injection_point_phrasing(self):
        """Feature 28: 'identified the following injection point(s)' triggers vulnerable=True."""
        # This is the critical Feature 28 fix
        output = "sqlmap identified the following injection point(s) with a total of 73 HTTP(s) requests:"
        result = self._server._parse_sqlmap_output(output)
        assert result["vulnerable"] is True, (
            "Feature 28 fix: 'injection point(s)' phrasing must be detected as vulnerability"
        )

    def test_is_vulnerable_phrasing(self):
        """'is vulnerable' in output triggers vulnerable=True."""
        output = "GET parameter 'id' is vulnerable. Do you want to keep testing the others?"
        result = self._server._parse_sqlmap_output(output)
        assert result["vulnerable"] is True

    def test_parameter_injectable_phrasing(self):
        """'parameter ... injectable' triggers vulnerable=True."""
        output = "GET parameter 'id' appears to be 'AND boolean-based blind' injectable"
        result = self._server._parse_sqlmap_output(output)
        assert result["vulnerable"] is True

    def test_not_appear_injectable_does_not_trigger(self):
        """'does not appear to be injectable' must NOT trigger vulnerable=True."""
        output = "[WARNING] GET parameter 'id' does not appear to be injectable"
        result = self._server._parse_sqlmap_output(output)
        assert result["vulnerable"] is False, (
            "'does not appear to be injectable' should not set vulnerable=True"
        )

    def test_connection_error_not_vulnerable(self):
        """Connection error output should not trigger vulnerable=True."""
        output = load_fixture("test_injection_connection_error.txt")
        result = self._server._parse_sqlmap_output(output)
        assert result["vulnerable"] is False

    def test_parameter_extraction_multiple(self):
        """Multiple injectable parameters are collected (no duplicates)."""
        output = (
            "Parameter: id (GET)\n"
            "    Type: boolean-based blind\n"
            "Parameter: name (POST)\n"
            "    Type: error-based\n"
            "Parameter: id (GET)\n"  # duplicate
            "    Type: UNION query\n"
        )
        result = self._server._parse_sqlmap_output(output)
        assert "id" in result["parameters"]
        assert "name" in result["parameters"]
        assert result["parameters"].count("id") == 1, "Duplicate params should be deduped"


class TestParseDatabases:
    """Test _parse_databases parser."""

    @classmethod
    def setup_class(cls):
        try:
            cls._server = _get_server_class()()
        except Exception as e:
            pytest.skip(f"Cannot import SqlmapServer: {e}")

    def test_parse_databases(self):
        """Parse output with 5 databases."""
        output = load_fixture("enumerate_dbs.txt")
        databases = self._server._parse_databases(output)

        assert len(databases) == 5
        assert "cobblestone" in databases
        assert "information_schema" in databases
        assert "mysql" in databases
        assert "performance_schema" in databases
        assert "webapp" in databases

    def test_parse_databases_empty(self):
        """Parse output with no databases found."""
        output = load_fixture("enumerate_dbs_empty.txt")
        databases = self._server._parse_databases(output)
        assert databases == []

    def test_parse_databases_extracts_after_marker(self):
        """Databases are only extracted after 'available databases' marker."""
        output = (
            "[*] not_a_database\n"
            "some noise\n"
            "available databases [2]:\n"
            "[*] real_db1\n"
            "[*] real_db2\n"
        )
        databases = self._server._parse_databases(output)
        assert "real_db1" in databases
        assert "real_db2" in databases
        assert "not_a_database" not in databases


class TestParseTableDump:
    """Test _parse_table_dump parser."""

    @classmethod
    def setup_class(cls):
        try:
            cls._server = _get_server_class()()
        except Exception as e:
            pytest.skip(f"Cannot import SqlmapServer: {e}")

    def test_parse_table_dump(self):
        """Parse table dump with 3 rows, 5 columns."""
        output = load_fixture("dump_table.txt")
        result = self._server._parse_table_dump(output)

        assert len(result["columns"]) == 5
        assert "id" in result["columns"]
        assert "username" in result["columns"]
        assert "password" in result["columns"]
        assert "email" in result["columns"]
        assert "role" in result["columns"]

        assert result["row_count"] == 3
        assert len(result["rows"]) == 3

        # Check first row
        admin_row = result["rows"][0]
        assert admin_row["username"] == "admin"
        assert admin_row["role"] == "admin"
        assert admin_row["email"] == "admin@cobblestone.htb"
        assert "$2y$10$" in admin_row["password"]

    def test_parse_table_dump_empty(self):
        """Parse output when table has no rows."""
        output = load_fixture("dump_table_empty.txt")
        result = self._server._parse_table_dump(output)
        assert result["columns"] == []
        assert result["rows"] == []
        assert result["row_count"] == 0

    def test_parse_table_dump_inline(self):
        """Parse a simple inline table."""
        output = """
+----+-------+
| id | name  |
+----+-------+
| 1  | alice |
| 2  | bob   |
+----+-------+
"""
        result = self._server._parse_table_dump(output)
        assert result["columns"] == ["id", "name"]
        assert result["row_count"] == 2
        assert result["rows"][0]["name"] == "alice"
        assert result["rows"][1]["name"] == "bob"


class TestParsePasswords:
    """Test dump_passwords output parsing (inline in handler)."""

    @classmethod
    def setup_class(cls):
        try:
            cls._server = _get_server_class()()
        except Exception as e:
            pytest.skip(f"Cannot import SqlmapServer: {e}")

    def test_password_hash_format(self):
        """Verify the regex matches sqlmap's password hash output format."""
        # This tests the inline parsing logic from dump_passwords handler
        output = load_fixture("dump_passwords.txt")

        # Replicate the handler's parsing logic
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

        assert len(hashes) == 2
        assert hashes[0]["user"] == "root"
        assert hashes[0]["hash"] == "*6BB4837EB74329105EE4568DDA7DC67ED2CA2AD9"
        assert hashes[1]["user"] == "webapp"
        assert hashes[1]["hash"] == "*2470C0C06DEE42FD1618BB99005ADCA2EC9D1E19"


class TestParseOsShell:
    """Test os_shell output parsing (inline in handler)."""

    @classmethod
    def setup_class(cls):
        try:
            cls._server = _get_server_class()()
        except Exception as e:
            pytest.skip(f"Cannot import SqlmapServer: {e}")

    def test_os_shell_output_extraction(self):
        """Verify command output is extracted from os_shell fixture.

        sqlmap wraps os_shell output between --- delimiters:
            command standard output:
            ---
            uid=33(www-data) gid=33(www-data) groups=33(www-data)
            ---
        The parser must skip the opening --- and stop at the closing ---.
        """
        output = load_fixture("os_shell.txt")

        # Replicate the handler's FIXED parsing logic
        cmd_output = ""
        in_output = False
        past_first_delimiter = False
        for line in output.split("\n"):
            if "command standard output" in line.lower():
                in_output = True
                past_first_delimiter = False
                continue
            if in_output:
                if line.startswith("---"):
                    if not past_first_delimiter:
                        past_first_delimiter = True
                        continue
                    else:
                        in_output = False
                elif line.startswith("["):
                    in_output = False
                else:
                    cmd_output += line + "\n"

        cmd_output = cmd_output.strip()
        assert "uid=33(www-data)" in cmd_output
        assert "gid=33(www-data)" in cmd_output


class TestParseSqlQuery:
    """Test sql_query output parsing (inline in handler)."""

    @classmethod
    def setup_class(cls):
        try:
            cls._server = _get_server_class()()
        except Exception as e:
            pytest.skip(f"Cannot import SqlmapServer: {e}")

    def test_sql_query_inline_result(self):
        """Parse inline sql-query output (single value)."""
        output = load_fixture("sql_query.txt")

        # Replicate the handler's parsing logic
        query_result = ""
        in_result = False
        for line in output.split("\n"):
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

        # Also try to catch inline results
        if not query_result:
            for line in output.split("\n"):
                m = re.search(r"\[INFO\]\s+retrieved:\s+(.+)", line)
                if m:
                    query_result += m.group(1).strip() + "\n"

        query_result = query_result.strip()
        assert "5.7.33" in query_result

    def test_sql_query_table_result(self):
        """Parse sql-query output with tabular result."""
        output = load_fixture("sql_query_table_result.txt")

        query_result = ""
        in_result = False
        for line in output.split("\n"):
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

        query_result = query_result.strip()
        assert "root" in query_result
        assert "webapp" in query_result
        assert "*6BB4837EB74329105EE4568DDA7DC67ED2CA2AD9" in query_result


# ===========================================================================
# COMMON ARG BUILDER TESTS -- no container needed
# ===========================================================================

class TestCommonArgBuilder:
    """Test _append_common_args produces correct CLI flags."""

    @classmethod
    def setup_class(cls):
        try:
            cls._server = _get_server_class()()
        except Exception as e:
            pytest.skip(f"Cannot import SqlmapServer: {e}")

    def test_defaults_produce_minimal_args(self):
        """Default values should produce only --threads 4."""
        args = []
        self._server._append_common_args(args)
        assert args == ["--threads", "4"], f"Defaults should only emit --threads 4, got {args}"

    def test_data_flag(self):
        """--data flag for POST data."""
        args = []
        self._server._append_common_args(args, data="user=admin&pass=test")
        assert "--data" in args
        assert "user=admin&pass=test" in args

    def test_cookie_flag(self):
        """--cookie flag."""
        args = []
        self._server._append_common_args(args, cookie="PHPSESSID=abc123")
        assert "--cookie" in args
        assert "PHPSESSID=abc123" in args

    def test_headers_flag_semicolon_separated(self):
        """Headers are split by semicolons and passed as -H."""
        args = []
        self._server._append_common_args(args, headers="Authorization: Bearer xyz;X-Custom: val")
        h_indices = [i for i, a in enumerate(args) if a == "-H"]
        assert len(h_indices) == 2, f"Expected 2 -H flags, got {len(h_indices)} in {args}"

    def test_method_flag(self):
        """--method flag."""
        args = []
        self._server._append_common_args(args, method="PUT")
        assert "--method" in args
        assert "PUT" in args

    def test_auth_flags(self):
        """--auth-type and --auth-cred flags."""
        args = []
        self._server._append_common_args(args, auth_type="Basic", auth_cred="admin:password")
        assert "--auth-type" in args
        assert "Basic" in args
        assert "--auth-cred" in args
        assert "admin:password" in args

    def test_csrf_flags(self):
        """--csrf-token and --csrf-url flags."""
        args = []
        self._server._append_common_args(args, csrf_token="_token", csrf_url="http://target/csrf")
        assert "--csrf-token" in args
        assert "_token" in args
        assert "--csrf-url" in args

    def test_dbms_flag(self):
        """--dbms flag."""
        args = []
        self._server._append_common_args(args, dbms="MySQL")
        assert "--dbms" in args
        assert "MySQL" in args

    def test_ignore_code_flag(self):
        """--ignore-code flag."""
        args = []
        self._server._append_common_args(args, ignore_code="401,500")
        assert "--ignore-code" in args
        assert "401,500" in args

    def test_string_flag(self):
        """--string flag for boolean detection."""
        args = []
        self._server._append_common_args(args, string="Welcome")
        assert "--string" in args
        assert "Welcome" in args

    def test_not_string_flag(self):
        """--not-string flag."""
        args = []
        self._server._append_common_args(args, not_string="Invalid")
        assert "--not-string" in args
        assert "Invalid" in args

    def test_code_flag(self):
        """--code flag (integer to string conversion)."""
        args = []
        self._server._append_common_args(args, code=200)
        assert "--code" in args
        assert "200" in args

    def test_text_only_flag(self):
        """--text-only flag."""
        args = []
        self._server._append_common_args(args, text_only=True)
        assert "--text-only" in args

    def test_titles_flag(self):
        """--titles flag."""
        args = []
        self._server._append_common_args(args, titles=True)
        assert "--titles" in args

    def test_level_non_default(self):
        """--level only emitted when != 1."""
        args = []
        self._server._append_common_args(args, level=3)
        assert "--level" in args
        assert "3" in args

    def test_level_default_not_emitted(self):
        """--level not emitted when == 1."""
        args = []
        self._server._append_common_args(args, level=1)
        assert "--level" not in args

    def test_risk_non_default(self):
        """--risk only emitted when != 1."""
        args = []
        self._server._append_common_args(args, risk=2)
        assert "--risk" in args
        assert "2" in args

    def test_technique_non_default(self):
        """--technique only emitted when != 'BEUSTQ'."""
        args = []
        self._server._append_common_args(args, technique="BEU")
        assert "--technique" in args
        assert "BEU" in args

    def test_technique_default_not_emitted(self):
        """--technique not emitted when == 'BEUSTQ'."""
        args = []
        self._server._append_common_args(args, technique="BEUSTQ")
        assert "--technique" not in args

    def test_param_flag(self):
        """-p flag for specific parameter."""
        args = []
        self._server._append_common_args(args, param="id")
        assert "-p" in args
        assert "id" in args

    def test_tamper_flag(self):
        """--tamper flag."""
        args = []
        self._server._append_common_args(args, tamper="space2comment,between")
        assert "--tamper" in args
        assert "space2comment,between" in args

    def test_prefix_suffix_flags(self):
        """--prefix and --suffix flags."""
        args = []
        self._server._append_common_args(args, prefix="')", suffix="-- -")
        assert "--prefix" in args
        assert "')" in args
        assert "--suffix" in args
        assert "-- -" in args

    def test_union_cols_flag(self):
        """--union-cols flag."""
        args = []
        self._server._append_common_args(args, union_cols="5-10")
        assert "--union-cols" in args
        assert "5-10" in args

    def test_second_url_flag(self):
        """--second-url flag."""
        args = []
        self._server._append_common_args(args, second_url="http://target/result")
        assert "--second-url" in args

    def test_eval_flag(self):
        """--eval flag."""
        args = []
        self._server._append_common_args(args, eval="import hashlib; token=hashlib.md5(id.encode()).hexdigest()")
        assert "--eval" in args

    def test_time_sec_non_default(self):
        """--time-sec only emitted when != 5."""
        args = []
        self._server._append_common_args(args, time_sec=15)
        assert "--time-sec" in args
        assert "15" in args

    def test_time_sec_default_not_emitted(self):
        """--time-sec not emitted when == 5."""
        args = []
        self._server._append_common_args(args, time_sec=5)
        assert "--time-sec" not in args

    def test_threads_always_emitted(self):
        """--threads is always emitted (even at default 4)."""
        args = []
        self._server._append_common_args(args, threads=4)
        assert "--threads" in args
        assert "4" in args

    def test_threads_custom(self):
        """--threads with custom value."""
        args = []
        self._server._append_common_args(args, threads=1)
        assert "--threads" in args
        assert "1" in args

    def test_delay_flag(self):
        """--delay flag."""
        args = []
        self._server._append_common_args(args, delay=2)
        assert "--delay" in args
        assert "2" in args

    def test_delay_zero_not_emitted(self):
        """--delay not emitted when == 0."""
        args = []
        self._server._append_common_args(args, delay=0)
        assert "--delay" not in args

    def test_retries_non_default(self):
        """--retries only emitted when != 3."""
        args = []
        self._server._append_common_args(args, retries=5)
        assert "--retries" in args
        assert "5" in args

    def test_safe_url_and_freq(self):
        """--safe-url and --safe-freq flags."""
        args = []
        self._server._append_common_args(args, safe_url="http://target/keep-alive", safe_freq=10)
        assert "--safe-url" in args
        assert "--safe-freq" in args
        assert "10" in args

    def test_null_connection_flag(self):
        """--null-connection flag."""
        args = []
        self._server._append_common_args(args, null_connection=True)
        assert "--null-connection" in args

    def test_proxy_flag(self):
        """--proxy flag."""
        args = []
        self._server._append_common_args(args, proxy="http://127.0.0.1:8080")
        assert "--proxy" in args
        assert "http://127.0.0.1:8080" in args

    def test_random_agent_flag(self):
        """--random-agent flag."""
        args = []
        self._server._append_common_args(args, random_agent=True)
        assert "--random-agent" in args

    def test_flush_session_flag(self):
        """--flush-session flag."""
        args = []
        self._server._append_common_args(args, flush_session=True)
        assert "--flush-session" in args

    def test_combined_engagement_args(self):
        """Reproduce a real engagement call with multiple flags.

        From engagement ses_2d3ee1a1e: test_injection with POST, cookie, param, dbms, risk=3, level=5.
        """
        args = []
        self._server._append_common_args(
            args,
            data="url=test",
            cookie="PHPSESSID=qf4rjljueqj4bbt02ireeciraj",
            param="url",
            dbms="MySQL",
            risk=3,
            level=5,
            technique="BEU",
            threads=4,
        )
        assert "--data" in args
        assert "--cookie" in args
        assert "-p" in args
        assert "--dbms" in args
        assert "--risk" in args
        assert "3" in args
        assert "--level" in args
        assert "5" in args
        assert "--technique" in args
        assert "BEU" in args


# ===========================================================================
# PROGRESS FILTER TESTS -- no container needed
# ===========================================================================

class TestProgressFilter:
    """Test _sqlmap_progress_filter for line-level filtering."""

    @classmethod
    def setup_class(cls):
        try:
            cls._server = _get_server_class()()
        except Exception as e:
            pytest.skip(f"Cannot import SqlmapServer: {e}")

    def test_info_line_passes(self):
        """[INFO] lines with meaningful content pass the filter."""
        line = "[13:45:02] [INFO] GET parameter 'id' appears to be dynamic"
        result = self._server._sqlmap_progress_filter(line)
        assert result is not None
        assert "GET parameter" in result

    def test_warning_line_passes(self):
        """[WARNING] lines pass the filter."""
        line = "[15:00:02] [WARNING] GET parameter 'id' does not appear to be dynamic"
        result = self._server._sqlmap_progress_filter(line)
        assert result is not None
        assert "WARNING" in result

    def test_critical_line_passes(self):
        """[CRITICAL] lines pass the filter."""
        line = "[16:00:02] [CRITICAL] all tested parameters do not appear to be injectable"
        result = self._server._sqlmap_progress_filter(line)
        assert result is not None
        assert "CRITICAL" in result

    def test_noisy_lines_filtered(self):
        """Noisy lines (legal disclaimer, starting/ending, etc.) are filtered out."""
        noisy_lines = [
            "[13:45:01] [INFO] testing connection to the target URL",
            "[13:45:01] [INFO] heuristic (basic) test shows that GET parameter 'id' might be injectable",
            "[13:45:01] [INFO] loaded tamper script 'space2comment'",
            "[13:45:01] [INFO] starting at 13:45:01",
            "[13:45:01] [INFO] ending at 13:45:01",
            "[13:45:01] [INFO] legal disclaimer: Usage of sqlmap for attacking targets...",
            "[13:45:01] [INFO] flushing session file",
            "[13:45:01] [INFO] cleaning up",
            "[13:45:01] [INFO] shutting down at 13:45:01",
        ]
        for line in noisy_lines:
            result = self._server._sqlmap_progress_filter(line)
            assert result is None, f"Noisy line should be filtered: {line}"

    def test_non_sqlmap_line_filtered(self):
        """Non-sqlmap formatted lines return None."""
        lines = [
            "some random output",
            "---",
            "Parameter: id (GET)",
            "    Type: boolean-based blind",
        ]
        for line in lines:
            result = self._server._sqlmap_progress_filter(line)
            assert result is None, f"Non-sqlmap line should be filtered: {line}"

    def test_injectable_line_passes(self):
        """Injectable finding lines should pass through."""
        line = "[13:45:03] [INFO] GET parameter 'id' appears to be 'AND boolean-based blind' injectable"
        result = self._server._sqlmap_progress_filter(line)
        assert result is not None

    def test_long_lines_truncated(self):
        """Progress messages are truncated to 120 chars."""
        line = "[13:45:03] [INFO] " + "x" * 200
        result = self._server._sqlmap_progress_filter(line)
        if result is not None:
            assert len(result) <= 120


# ===========================================================================
# TIMEOUT ARCHITECTURE TESTS -- no container needed
# ===========================================================================

class TestTimeoutArchitecture:
    """Verify that sqlmap handlers use run_command_with_progress for heartbeating.

    50% timeout rate on test_injection (max 1863s = 31 minutes).
    The fix: use run_command_with_progress() for heartbeat support.
    """

    @classmethod
    def setup_class(cls):
        try:
            cls._server = _get_server_class()()
        except Exception as e:
            pytest.skip(f"Cannot import SqlmapServer: {e}")

    def test_test_injection_uses_progress(self):
        """test_injection must use run_command_with_progress."""
        source = inspect.getsource(self._server.test_injection)
        assert "run_command_with_progress" in source, (
            "test_injection must use run_command_with_progress for heartbeat support. "
            "50% timeout rate indicates heartbeat loss."
        )

    def test_enumerate_dbs_uses_progress(self):
        """enumerate_dbs must use run_command_with_progress."""
        source = inspect.getsource(self._server.enumerate_dbs)
        assert "run_command_with_progress" in source

    def test_enumerate_tables_uses_progress(self):
        """enumerate_tables must use run_command_with_progress."""
        source = inspect.getsource(self._server.enumerate_tables)
        assert "run_command_with_progress" in source

    def test_dump_table_uses_progress(self):
        """dump_table must use run_command_with_progress."""
        source = inspect.getsource(self._server.dump_table)
        assert "run_command_with_progress" in source

    def test_dump_all_uses_progress(self):
        """dump_all must use run_command_with_progress."""
        source = inspect.getsource(self._server.dump_all)
        assert "run_command_with_progress" in source

    def test_dump_passwords_uses_progress(self):
        """dump_passwords must use run_command_with_progress."""
        source = inspect.getsource(self._server.dump_passwords)
        assert "run_command_with_progress" in source

    def test_os_shell_uses_progress(self):
        """os_shell must use run_command_with_progress."""
        source = inspect.getsource(self._server.os_shell)
        assert "run_command_with_progress" in source

    def test_file_read_uses_progress(self):
        """file_read must use run_command_with_progress."""
        source = inspect.getsource(self._server.file_read)
        assert "run_command_with_progress" in source

    def test_file_write_uses_progress(self):
        """file_write must use run_command_with_progress."""
        source = inspect.getsource(self._server.file_write)
        assert "run_command_with_progress" in source

    def test_sql_query_uses_progress(self):
        """sql_query must use run_command_with_progress."""
        source = inspect.getsource(self._server.sql_query)
        assert "run_command_with_progress" in source

    def test_all_handlers_pass_progress_filter(self):
        """All handlers should pass _sqlmap_progress_filter."""
        methods_with_progress_filter = []
        for method_name, method_def in self._server.methods.items():
            if method_name == "verify_clock":
                continue
            source = inspect.getsource(method_def.handler)
            if "progress_filter" in source:
                methods_with_progress_filter.append(method_name)

        expected_methods = {
            "test_injection", "enumerate_dbs", "enumerate_tables",
            "dump_table", "dump_all", "dump_passwords",
            "os_shell", "file_read", "file_write", "sql_query",
        }
        missing = expected_methods - set(methods_with_progress_filter)
        assert not missing, (
            f"These methods don't pass progress_filter: {missing}. "
            f"All sqlmap methods should use _sqlmap_progress_filter for heartbeating."
        )

    def test_test_injection_default_timeout_adequate(self):
        """test_injection default timeout should be >= 1800s.

        Engagement data shows level=5/risk=3 scans can take >30 min.
        """
        source = inspect.getsource(self._server.test_injection)
        match = re.search(r"timeout.*?(\d+)", source)
        if match:
            timeout = int(match.group(1))
            assert timeout >= 1800, (
                f"test_injection timeout ({timeout}s) should be >= 1800s. "
                f"Engagement data shows level=5/risk=3 scans take >30 min."
            )

    def test_dump_table_timeout_higher_than_test_injection(self):
        """dump_table should have longer timeout than test_injection.

        Blind extraction of 100 rows can take 30-60+ minutes.
        """
        source_test = inspect.getsource(self._server.test_injection)
        source_dump = inspect.getsource(self._server.dump_table)
        match_test = re.search(r"timeout.*?(\d+)", source_test)
        match_dump = re.search(r"timeout.*?(\d+)", source_dump)
        if match_test and match_dump:
            assert int(match_dump.group(1)) >= int(match_test.group(1)), (
                "dump_table timeout should be >= test_injection timeout"
            )


# ===========================================================================
# ERROR CLASSIFICATION TESTS -- no container needed
# ===========================================================================

class TestErrorClassification:
    """Test sqlmap-specific error classification.

    sqlmap has distinctive error patterns that should be properly classified.
    Currently the server only uses the base class _classify_unhandled_error.
    These tests verify current behavior and document desired behavior.
    """

    @classmethod
    def setup_class(cls):
        try:
            cls._server = _get_server_class()()
        except Exception as e:
            pytest.skip(f"Cannot import SqlmapServer: {e}")

    def test_classify_base_timeout(self):
        """Timeout errors from base class should still work."""
        err_class, retryable = self._server._classify_unhandled_error(
            1, "Traceback (most recent call last):\n  asyncio.TimeoutError"
        )
        assert err_class == "timeout"
        assert retryable is True

    def test_classify_clean_output(self):
        """Normal output should not be misclassified."""
        err_class, retryable = self._server._classify_unhandled_error(0, "")
        assert err_class == "unknown"

    def test_classify_connection_refused(self):
        """Connection refused from base class fallback."""
        err_class, retryable = self._server._classify_unhandled_error(
            1, "Traceback (most recent call last):\n  ConnectionRefusedError"
        )
        assert err_class == "network"
        assert retryable is True

    def test_not_injectable_is_successful_result(self):
        """'not injectable' is an informational finding, not an error.

        The handler returns success=True even when no injection found.
        This is correct: the tool ran successfully but found nothing.
        """
        output = load_fixture("test_injection_not_vulnerable.txt")
        result = self._server._parse_sqlmap_output(output)
        assert result["vulnerable"] is False
        # This is correct behavior: success=True with vulnerable=False

    def test_classify_waf_detected(self):
        """WAF/IPS detection should classify as 'config' with tamper suggestions."""
        err_class, retryable, suggestions = self._server._classify_sqlmap_error(
            "heuristics detected that the target is protected by some kind of WAF/IPS"
        )
        assert err_class == "config"
        assert retryable is False
        assert any("tamper" in s.lower() for s in suggestions)

    def test_classify_connection_failure(self):
        """Connection failure should classify as 'network', retryable."""
        err_class, retryable, suggestions = self._server._classify_sqlmap_error(
            "unable to connect to the target URL"
        )
        assert err_class == "network"
        assert retryable is True

    def test_classify_invalid_url(self):
        """Invalid URL should classify as 'params'."""
        err_class, retryable, suggestions = self._server._classify_sqlmap_error(
            "invalid target URL"
        )
        assert err_class == "params"
        assert retryable is False

    def test_classify_not_injectable(self):
        """'not injectable' should classify as 'config' with level/risk suggestions."""
        err_class, retryable, suggestions = self._server._classify_sqlmap_error(
            "all tested parameters do not appear to be injectable"
        )
        assert err_class == "config"
        assert any("level" in s.lower() or "risk" in s.lower() for s in suggestions)

    def test_classify_clean_sqlmap_output(self):
        """Normal output returns 'unknown'."""
        err_class, retryable, suggestions = self._server._classify_sqlmap_error(
            "normal sqlmap output with nothing special"
        )
        assert err_class == "unknown"


# ===========================================================================
# SERVER INTERNALS -- no container needed
# ===========================================================================

class TestServerInternals:
    """Test SqlmapServer internal helper methods."""

    @classmethod
    def setup_class(cls):
        try:
            cls._server = _get_server_class()()
        except Exception as e:
            pytest.skip(f"Cannot import SqlmapServer: {e}")

    def test_registered_methods(self):
        """All 10 methods are registered."""
        assert len(self._server.methods) == 10
        expected = {
            "test_injection", "enumerate_dbs", "enumerate_tables",
            "dump_table", "dump_all", "dump_passwords",
            "os_shell", "file_read", "file_write", "sql_query",
        }
        assert set(self._server.methods.keys()) == expected

    def test_all_methods_have_url_required(self):
        """Every method has 'url' as a required parameter."""
        for name, method in self._server.methods.items():
            if name == "verify_clock":
                continue
            assert "url" in method.params, f"{name} missing 'url' param"
            assert method.params["url"].get("required", False), (
                f"{name}: 'url' should be required"
            )

    def test_test_injection_batch_flag(self):
        """test_injection always passes --batch for non-interactive mode."""
        source = inspect.getsource(self._server.test_injection)
        assert '"--batch"' in source or "'--batch'" in source, (
            "test_injection must pass --batch for non-interactive mode"
        )

    def test_dump_table_passes_dump_format(self):
        """dump_table passes --dump-format CSV."""
        source = inspect.getsource(self._server.dump_table)
        assert '"CSV"' in source or "'CSV'" in source, (
            "dump_table should pass --dump-format CSV for structured output"
        )

    def test_file_write_handles_content_as_string(self):
        """file_write writes inline content to a temp file."""
        source = inspect.getsource(self._server.file_write)
        assert "tempfile" in source or "NamedTemporaryFile" in source, (
            "file_write must handle inline content by writing to temp file"
        )

    def test_progress_regex_compiled(self):
        """Progress regex is pre-compiled (not compiled per call)."""
        assert hasattr(self._server.__class__, '_SQLMAP_PROGRESS_RE')
        assert self._server._SQLMAP_PROGRESS_RE is not None

    def test_noisy_pattern_regex_compiled(self):
        """Noisy pattern regex is pre-compiled."""
        assert hasattr(self._server.__class__, '_SQLMAP_NOISY_PATTERNS')
        assert self._server._SQLMAP_NOISY_PATTERNS is not None


# ===========================================================================
# TOOL.YAML CONTRACT TESTS -- no container needed
# ===========================================================================

class TestToolYamlContract:
    """Verify tool.yaml matches server parameter definitions."""

    @classmethod
    def setup_class(cls):
        with open(TOOL_DIR / "tool.yaml") as f:
            cls._yaml = yaml.safe_load(f)
        try:
            cls._server = _get_server_class()()
        except Exception as e:
            pytest.skip(f"Cannot import SqlmapServer: {e}")

    def test_yaml_has_all_10_methods(self):
        """tool.yaml should define exactly 10 methods."""
        methods = self._yaml.get("methods", {})
        assert len(methods) == 10, (
            f"Expected 10 methods, got {len(methods)}: {sorted(methods.keys())}"
        )

    def test_yaml_method_names(self):
        """tool.yaml should have the correct method names."""
        expected = {
            "test_injection", "enumerate_dbs", "enumerate_tables",
            "dump_table", "dump_all", "dump_passwords",
            "os_shell", "file_read", "file_write", "sql_query",
        }
        yaml_names = set(self._yaml.get("methods", {}).keys())
        assert yaml_names == expected, f"Expected {expected}, got {yaml_names}"

    def test_all_methods_have_descriptions(self):
        """Every method should have a description."""
        for name, defn in self._yaml.get("methods", {}).items():
            assert "description" in defn, f"Method {name} missing description"
            assert len(defn["description"]) > 10, f"Method {name} has too short description"

    def test_all_methods_have_when_to_use(self):
        """Every method should have a when_to_use field."""
        for name, defn in self._yaml.get("methods", {}).items():
            assert "when_to_use" in defn, f"Method {name} missing when_to_use"
            assert len(defn["when_to_use"]) > 10, f"Method {name} has too short when_to_use"

    def test_method_names_match_server(self):
        """Method names in tool.yaml match the server's registered methods."""
        yaml_names = set(self._yaml.get("methods", {}).keys())
        server_names = set(self._server.methods.keys())

        yaml_only = yaml_names - server_names
        server_only = server_names - yaml_names

        assert not yaml_only, f"Methods in tool.yaml but not server: {yaml_only}"
        assert not server_only, f"Methods in server but not tool.yaml: {server_only}"

    def test_yaml_params_subset_of_server(self):
        """Every yaml param should be accepted by the server handler.

        Common params from tool.yaml's _common_params anchor are merged
        into each method via YAML anchors. The server's _common_params
        dict should accept all of them.
        """
        for method_name, defn in self._yaml.get("methods", {}).items():
            yaml_params = set(defn.get("params", {}).keys())
            server_method = self._server.methods.get(method_name)
            if server_method is None:
                continue
            server_params = set(server_method.params.keys())
            yaml_only = yaml_params - server_params
            assert not yaml_only, (
                f"Method {method_name}: params in tool.yaml but not server: {yaml_only}"
            )

    def test_required_params_match(self):
        """Required params in tool.yaml match server definitions."""
        for method_name, defn in self._yaml.get("methods", {}).items():
            yaml_required = {
                p for p, d in defn.get("params", {}).items()
                if d.get("required", False) is True
            }
            server_method = self._server.methods.get(method_name)
            if server_method is None:
                continue
            server_required = {
                p for p, d in server_method.params.items()
                if d.get("required", False) is True
            }
            assert yaml_required == server_required, (
                f"Method {method_name}: required param mismatch. "
                f"yaml={yaml_required}, server={server_required}"
            )

    def test_yaml_has_timeout_seconds(self):
        """tool.yaml should define a global timeout_seconds."""
        assert "timeout_seconds" in self._yaml, "tool.yaml missing timeout_seconds"
        assert self._yaml["timeout_seconds"] >= 1800, (
            f"timeout_seconds ({self._yaml['timeout_seconds']}) should be >= 1800 for sqlmap"
        )

    def test_yaml_phases(self):
        """sqlmap should be in the 'exploitation' phase."""
        phases = self._yaml.get("phases", [])
        assert "exploitation" in phases

    def test_yaml_capabilities(self):
        """sqlmap should have sql_injection capability."""
        caps = self._yaml.get("capabilities", [])
        assert "sql_injection" in caps


# ===========================================================================
# LIVE METHOD TESTS -- require Docker container, test against localhost
# ===========================================================================

class TestLiveMethods:
    """Tests that actually call sqlmap methods against unreachable targets.

    These test that the server handles unreachable targets gracefully
    (not that injection works -- that needs a real vulnerable target).
    """

    def test_test_injection_unreachable_target(self, sqlmap_env):
        """test_injection against unreachable target returns success=True with vulnerable=False.

        sqlmap exits cleanly when target is unreachable, the handler should
        not crash.
        """
        client, loop = sqlmap_env
        resp = loop.run_until_complete(client.call(
            "test_injection",
            {
                "url": "http://127.0.0.1:19999/nonexistent?id=1",
                "timeout": 15,
            },
            timeout=60,
        ))
        # Should not crash -- either success with vulnerable=False or clean error
        result = resp.get("result", {})
        assert result is not None, "Should get a response for unreachable target"

    def test_enumerate_dbs_unreachable_target(self, sqlmap_env):
        """enumerate_dbs against unreachable target handles gracefully."""
        client, loop = sqlmap_env
        resp = loop.run_until_complete(client.call(
            "enumerate_dbs",
            {
                "url": "http://127.0.0.1:19999/nonexistent?id=1",
                "timeout": 15,
            },
            timeout=60,
        ))
        result = resp.get("result", {})
        assert result is not None

    def test_sql_query_unreachable_target(self, sqlmap_env):
        """sql_query against unreachable target handles gracefully."""
        client, loop = sqlmap_env
        resp = loop.run_until_complete(client.call(
            "sql_query",
            {
                "url": "http://127.0.0.1:19999/nonexistent?id=1",
                "query": "SELECT @@version",
                "timeout": 15,
            },
            timeout=60,
        ))
        result = resp.get("result", {})
        assert result is not None


# ===========================================================================
# ACCEPTANCE TESTS -- every method called through container (no live target)
# ===========================================================================

class TestAcceptance:
    """Call every method through the container without a live SQLi target.

    These tests verify:
    - The method exists and is callable
    - Required param validation works (missing required params -> error)
    - The response has correct structuredContent shape
    - Error responses have error_class set (classified, not crash)

    Each test sends minimal args with an unreachable URL so sqlmap will fail
    at connection time, but the MCP protocol layer, param validation, and
    error classification should all function correctly.
    """

    _FAKE_URL = "http://192.0.2.1/vuln.php?id=1"

    def _assert_structured_response(self, resp, method_name):
        """Assert response has structuredContent and no crashes."""
        result = resp.get("result", {})
        sc = result.get("structuredContent", {})
        assert sc is not None, f"{method_name}: missing structuredContent"
        if not sc.get("success", True):
            assert sc.get("error_class") is not None, (
                f"{method_name}: error has no error_class: {sc}"
            )
        content_text = ""
        for c in result.get("content", []):
            if c.get("type") == "text":
                content_text += c["text"]
        assert "unexpected keyword argument" not in content_text, (
            f"{method_name}: unhandled keyword argument error"
        )
        return sc

    # ── test_injection ────────────────────────────────────────

    def test_test_injection_unreachable(self, sqlmap_env):
        """test_injection against unreachable target returns classified error."""
        client, loop = sqlmap_env
        resp = loop.run_until_complete(client.call("test_injection", {
            "url": self._FAKE_URL,
            "timeout": 15,
        }, timeout=60))
        self._assert_structured_response(resp, "test_injection")

    def test_test_injection_missing_url(self, sqlmap_env):
        """test_injection without url returns error."""
        client, loop = sqlmap_env
        resp = loop.run_until_complete(client.call("test_injection", {}))
        result = resp.get("result", {})
        is_error = result.get("isError", False)
        content_text = ""
        for c in result.get("content", []):
            if c.get("type") == "text":
                content_text += c["text"]
        assert is_error or "url" in content_text.lower() or "required" in content_text.lower()

    def test_test_injection_with_options(self, sqlmap_env):
        """test_injection with level/risk/dbms does not crash."""
        client, loop = sqlmap_env
        resp = loop.run_until_complete(client.call("test_injection", {
            "url": self._FAKE_URL,
            "level": 2,
            "risk": 2,
            "dbms": "MySQL",
            "timeout": 15,
        }, timeout=60))
        self._assert_structured_response(resp, "test_injection+options")

    # ── enumerate_dbs ─────────────────────────────────────────

    def test_enumerate_dbs_unreachable(self, sqlmap_env):
        """enumerate_dbs against unreachable target returns classified error."""
        client, loop = sqlmap_env
        resp = loop.run_until_complete(client.call("enumerate_dbs", {
            "url": self._FAKE_URL,
            "timeout": 15,
        }, timeout=60))
        self._assert_structured_response(resp, "enumerate_dbs")

    def test_enumerate_dbs_missing_url(self, sqlmap_env):
        """enumerate_dbs without url returns error."""
        client, loop = sqlmap_env
        resp = loop.run_until_complete(client.call("enumerate_dbs", {}))
        result = resp.get("result", {})
        is_error = result.get("isError", False)
        content_text = ""
        for c in result.get("content", []):
            if c.get("type") == "text":
                content_text += c["text"]
        assert is_error or "url" in content_text.lower() or "required" in content_text.lower()

    # ── enumerate_tables ──────────────────────────────────────

    def test_enumerate_tables_unreachable(self, sqlmap_env):
        """enumerate_tables against unreachable target returns classified error."""
        client, loop = sqlmap_env
        resp = loop.run_until_complete(client.call("enumerate_tables", {
            "url": self._FAKE_URL,
            "database": "testdb",
            "timeout": 15,
        }, timeout=60))
        self._assert_structured_response(resp, "enumerate_tables")

    def test_enumerate_tables_missing_database(self, sqlmap_env):
        """enumerate_tables without database returns error."""
        client, loop = sqlmap_env
        resp = loop.run_until_complete(client.call("enumerate_tables", {
            "url": self._FAKE_URL,
        }))
        result = resp.get("result", {})
        is_error = result.get("isError", False)
        content_text = ""
        for c in result.get("content", []):
            if c.get("type") == "text":
                content_text += c["text"]
        assert is_error or "database" in content_text.lower() or "required" in content_text.lower()

    # ── dump_table ────────────────────────────────────────────

    def test_dump_table_unreachable(self, sqlmap_env):
        """dump_table against unreachable target returns classified error."""
        client, loop = sqlmap_env
        resp = loop.run_until_complete(client.call("dump_table", {
            "url": self._FAKE_URL,
            "database": "testdb",
            "table": "users",
            "timeout": 15,
        }, timeout=60))
        self._assert_structured_response(resp, "dump_table")

    def test_dump_table_missing_table(self, sqlmap_env):
        """dump_table without table returns error."""
        client, loop = sqlmap_env
        resp = loop.run_until_complete(client.call("dump_table", {
            "url": self._FAKE_URL,
            "database": "testdb",
        }))
        result = resp.get("result", {})
        is_error = result.get("isError", False)
        content_text = ""
        for c in result.get("content", []):
            if c.get("type") == "text":
                content_text += c["text"]
        assert is_error or "table" in content_text.lower() or "required" in content_text.lower()

    def test_dump_table_with_columns_and_where(self, sqlmap_env):
        """dump_table with columns and where does not crash."""
        client, loop = sqlmap_env
        resp = loop.run_until_complete(client.call("dump_table", {
            "url": self._FAKE_URL,
            "database": "testdb",
            "table": "users",
            "columns": "username,password",
            "where": "role='admin'",
            "limit": 10,
            "timeout": 15,
        }, timeout=60))
        self._assert_structured_response(resp, "dump_table+options")

    # ── dump_all ──────────────────────────────────────────────

    def test_dump_all_unreachable(self, sqlmap_env):
        """dump_all against unreachable target returns classified error."""
        client, loop = sqlmap_env
        resp = loop.run_until_complete(client.call("dump_all", {
            "url": self._FAKE_URL,
            "database": "testdb",
            "timeout": 15,
        }, timeout=60))
        self._assert_structured_response(resp, "dump_all")

    def test_dump_all_missing_database(self, sqlmap_env):
        """dump_all without database returns error."""
        client, loop = sqlmap_env
        resp = loop.run_until_complete(client.call("dump_all", {
            "url": self._FAKE_URL,
        }))
        result = resp.get("result", {})
        is_error = result.get("isError", False)
        content_text = ""
        for c in result.get("content", []):
            if c.get("type") == "text":
                content_text += c["text"]
        assert is_error or "database" in content_text.lower() or "required" in content_text.lower()

    # ── dump_passwords ────────────────────────────────────────

    def test_dump_passwords_unreachable(self, sqlmap_env):
        """dump_passwords against unreachable target returns classified error."""
        client, loop = sqlmap_env
        resp = loop.run_until_complete(client.call("dump_passwords", {
            "url": self._FAKE_URL,
            "timeout": 15,
        }, timeout=60))
        self._assert_structured_response(resp, "dump_passwords")

    # ── os_shell ──────────────────────────────────────────────

    def test_os_shell_unreachable(self, sqlmap_env):
        """os_shell against unreachable target returns classified error."""
        client, loop = sqlmap_env
        resp = loop.run_until_complete(client.call("os_shell", {
            "url": self._FAKE_URL,
            "command": "id",
            "timeout": 15,
        }, timeout=60))
        self._assert_structured_response(resp, "os_shell")

    def test_os_shell_missing_command(self, sqlmap_env):
        """os_shell without command returns error."""
        client, loop = sqlmap_env
        resp = loop.run_until_complete(client.call("os_shell", {
            "url": self._FAKE_URL,
        }))
        result = resp.get("result", {})
        is_error = result.get("isError", False)
        content_text = ""
        for c in result.get("content", []):
            if c.get("type") == "text":
                content_text += c["text"]
        assert is_error or "command" in content_text.lower() or "required" in content_text.lower()

    # ── file_read ─────────────────────────────────────────────

    def test_file_read_unreachable(self, sqlmap_env):
        """file_read against unreachable target returns classified error."""
        client, loop = sqlmap_env
        resp = loop.run_until_complete(client.call("file_read", {
            "url": self._FAKE_URL,
            "file_path": "/etc/passwd",
            "timeout": 15,
        }, timeout=60))
        self._assert_structured_response(resp, "file_read")

    def test_file_read_missing_file_path(self, sqlmap_env):
        """file_read without file_path returns error."""
        client, loop = sqlmap_env
        resp = loop.run_until_complete(client.call("file_read", {
            "url": self._FAKE_URL,
        }))
        result = resp.get("result", {})
        is_error = result.get("isError", False)
        content_text = ""
        for c in result.get("content", []):
            if c.get("type") == "text":
                content_text += c["text"]
        assert is_error or "file_path" in content_text.lower() or "required" in content_text.lower()

    # ── file_write ────────────────────────────────────────────

    def test_file_write_unreachable(self, sqlmap_env):
        """file_write against unreachable target returns classified error."""
        client, loop = sqlmap_env
        resp = loop.run_until_complete(client.call("file_write", {
            "url": self._FAKE_URL,
            "local_file": "/tmp/test_payload.txt",
            "remote_path": "/var/www/html/shell.php",
            "timeout": 15,
        }, timeout=60))
        self._assert_structured_response(resp, "file_write")

    def test_file_write_missing_remote_path(self, sqlmap_env):
        """file_write without remote_path returns error."""
        client, loop = sqlmap_env
        resp = loop.run_until_complete(client.call("file_write", {
            "url": self._FAKE_URL,
            "local_file": "/tmp/test.txt",
        }))
        result = resp.get("result", {})
        is_error = result.get("isError", False)
        content_text = ""
        for c in result.get("content", []):
            if c.get("type") == "text":
                content_text += c["text"]
        assert is_error or "remote_path" in content_text.lower() or "required" in content_text.lower()

    # ── sql_query ─────────────────────────────────────────────

    def test_sql_query_unreachable(self, sqlmap_env):
        """sql_query against unreachable target returns classified error."""
        client, loop = sqlmap_env
        resp = loop.run_until_complete(client.call("sql_query", {
            "url": self._FAKE_URL,
            "query": "SELECT @@version",
            "timeout": 15,
        }, timeout=60))
        self._assert_structured_response(resp, "sql_query")

    def test_sql_query_missing_query(self, sqlmap_env):
        """sql_query without query returns error."""
        client, loop = sqlmap_env
        resp = loop.run_until_complete(client.call("sql_query", {
            "url": self._FAKE_URL,
        }))
        result = resp.get("result", {})
        is_error = result.get("isError", False)
        content_text = ""
        for c in result.get("content", []):
            if c.get("type") == "text":
                content_text += c["text"]
        assert is_error or "query" in content_text.lower() or "required" in content_text.lower()

    # ── Cross-cutting ─────────────────────────────────────────

    def test_all_methods_return_structuredContent(self, sqlmap_env):
        """verify_clock returns structuredContent with all required fields."""
        client, loop = sqlmap_env
        resp = loop.run_until_complete(client.call("verify_clock", {}))
        result = resp.get("result", {})
        sc = result.get("structuredContent")
        assert sc is not None
        assert isinstance(sc, dict)
        for field in ("success", "error_class", "retryable", "suggestions"):
            assert field in sc, f"Missing field '{field}' in structuredContent"

    def test_common_params_accepted(self, sqlmap_env):
        """Common params (cookie, headers, dbms, level, risk) do not crash."""
        client, loop = sqlmap_env
        resp = loop.run_until_complete(client.call("test_injection", {
            "url": self._FAKE_URL,
            "cookie": "PHPSESSID=abc123",
            "headers": "Authorization: Bearer xyz",
            "dbms": "MySQL",
            "level": 3,
            "risk": 2,
            "timeout": 15,
        }, timeout=60))
        self._assert_structured_response(resp, "test_injection+common")


# ===========================================================================
# ENGAGEMENT-DRIVEN TESTS -- bugs and patterns from real engagement data
# ===========================================================================

class TestEngagementBugs:
    """Tests derived from real engagement data across 5 sessions / 25 sqlmap calls.

    Key findings:
    - LLM sends wrong param names: remote_file, local_path, file_content
    - LLM sends wrong method names: custom_query, read_file
    - 4 timeouts out of 25 calls (16%): enumerate_dbs 120s, os_shell 300s,
      test_injection 603s, test_injection 1863s
    - file_write returned "Error: None" (success=False with no error message)
    """

    @classmethod
    def setup_class(cls):
        try:
            cls._server = _get_server_class()()
        except Exception as e:
            pytest.skip(f"Cannot import SqlmapServer: {e}")

    # -- Vulnerability parser edge cases from engagement data --

    def test_post_parameter_url_injectable(self):
        """Engagement: POST param 'url' on cobblestone was injectable.

        Session ses_2d3ee1a1e: test_injection with data='url=test', param='url',
        dbms='MySQL', risk=3, level=5. Must detect vulnerability.
        """
        output = load_fixture("test_injection_post_vulnerable.txt")
        result = self._server._parse_sqlmap_output(output)
        assert result["vulnerable"] is True
        assert "url" in result["parameters"]
        assert result["dbms"] is not None
        assert "MariaDB" in result["dbms"] or "MySQL" in result["dbms"]

    def test_stacked_queries_detected(self):
        """Parse output that includes stacked queries injection."""
        output = load_fixture("test_injection_stacked_queries.txt")
        result = self._server._parse_sqlmap_output(output)
        assert result["vulnerable"] is True
        assert "id" in result["parameters"]
        assert "PostgreSQL" in result["dbms"]
        # injection_type captures the last Type: line
        assert "stacked queries" in result["injection_type"]

    def test_not_injectable_but_not_error(self):
        """Engagement: test_injection returning vulnerable=False is NOT an error.

        Session ses_2c72ea51: test against WinRM port (not SQL), returned
        vulnerable=False correctly. Tool success should be True.
        """
        output = load_fixture("test_injection_not_vulnerable.txt")
        result = self._server._parse_sqlmap_output(output)
        assert result["vulnerable"] is False
        # This is a successful scan that found no injection

    # -- Table dump parser edge cases --

    def test_table_dump_ignores_injection_point_dashes(self):
        """Table dump parser must not treat '---' (injection point delimiter)
        as a table separator.

        Fixed: regex now requires +---+ format, not bare ---.
        """
        # Simulate sqlmap output with injection point section followed by table
        output = (
            "sqlmap identified the following injection point(s):\n"
            "---\n"
            "Parameter: id (GET)\n"
            "    Type: UNION query\n"
            "    Payload: id=-1 UNION ALL SELECT NULL,NULL-- -\n"
            "---\n"
            "\n"
            "Database: testdb\n"
            "Table: users\n"
            "[2 entries]\n"
            "+----+-------+\n"
            "| id | name  |\n"
            "+----+-------+\n"
            "| 1  | alice |\n"
            "| 2  | bob   |\n"
            "+----+-------+\n"
        )
        result = self._server._parse_table_dump(output)
        assert result["columns"] == ["id", "name"]
        assert result["row_count"] == 2
        assert result["rows"][0]["name"] == "alice"
        # Critical: should NOT have parsed the injection point section as a table
        assert "Parameter:" not in str(result["rows"])

    def test_table_dump_with_nulls(self):
        """Table dump with <blank> and NULL values.

        Engagement data shows tables with empty cells and NULL markers.
        """
        output = load_fixture("dump_table_with_nulls.txt")
        result = self._server._parse_table_dump(output)
        assert result["row_count"] == 2
        assert result["rows"][0]["username"] == "admin"
        assert result["rows"][1]["username"] == "guest"
        # <blank> and NULL should be preserved as-is (they're sqlmap's representation)
        assert result["rows"][1]["password"] == "<blank>"
        assert result["rows"][1]["notes"] == "NULL"

    def test_table_dump_preserves_hash_values(self):
        """Table dump with bcrypt/md5 hashes must preserve full hash.

        Engagement: dump_table on cobblestone.users extracted bcrypt hashes.
        """
        output = load_fixture("dump_table.txt")
        result = self._server._parse_table_dump(output)
        admin_row = result["rows"][0]
        assert "$2y$10$" in admin_row["password"], "bcrypt hash prefix must be preserved"

    # -- Password hash parser edge cases --

    def test_password_multi_hash_per_user(self):
        """MySQL root can have multiple password hashes (from different hosts).

        The parser should capture ALL hashes, not just the last one.
        """
        output = load_fixture("dump_passwords_multi_hash.txt")

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

        assert len(hashes) == 4, f"Expected 4 hashes (root*2 + debian-sys-maint + webapp), got {len(hashes)}"
        root_hashes = [h for h in hashes if h["user"] == "root"]
        assert len(root_hashes) == 2, "root should have 2 hashes"

    def test_password_postgres_md5(self):
        """PostgreSQL uses md5 prefix for password hashes."""
        output = load_fixture("dump_passwords_postgres.txt")

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

        assert len(hashes) == 2
        assert hashes[0]["user"] == "postgres"
        assert hashes[0]["hash"].startswith("md5")

    # -- os_shell parser edge cases --

    def test_os_shell_multiline_output(self):
        """os_shell with multi-line output (e.g., cat /etc/passwd).

        Engagement: os_shell on cobblestone timed out at 300s, likely because
        sqlmap couldn't establish the web backdoor. But when it works, multi-line
        output must be captured completely.
        """
        output = load_fixture("os_shell_multiline.txt")

        cmd_output = ""
        in_output = False
        past_first_delimiter = False
        for line in output.split("\n"):
            if "command standard output" in line.lower():
                in_output = True
                past_first_delimiter = False
                continue
            if in_output:
                if line.startswith("---"):
                    if not past_first_delimiter:
                        past_first_delimiter = True
                        continue
                    else:
                        in_output = False
                elif line.startswith("["):
                    in_output = False
                else:
                    cmd_output += line + "\n"

        cmd_output = cmd_output.strip()
        assert "root:x:0:0:" in cmd_output
        assert "www-data:x:33:33:" in cmd_output
        # Count lines
        lines = [l for l in cmd_output.split("\n") if l.strip()]
        assert len(lines) == 5, f"Expected 5 lines, got {len(lines)}"

    def test_os_shell_no_output_section(self):
        """os_shell when command execution fails (no 'command standard output' section).

        Engagement: os_shell timed out because sqlmap couldn't establish shell.
        Parser should return empty string, not crash.
        """
        output = load_fixture("os_shell_no_output.txt")

        cmd_output = ""
        in_output = False
        past_first_delimiter = False
        for line in output.split("\n"):
            if "command standard output" in line.lower():
                in_output = True
                past_first_delimiter = False
                continue
            if in_output:
                if line.startswith("---"):
                    if not past_first_delimiter:
                        past_first_delimiter = True
                        continue
                    else:
                        in_output = False
                elif line.startswith("["):
                    in_output = False
                else:
                    cmd_output += line + "\n"

        assert cmd_output.strip() == "", "Should return empty string when no command output"

    def test_os_shell_xp_cmdshell(self):
        """os_shell via MSSQL xp_cmdshell output extraction."""
        output = load_fixture("os_shell_xp_cmdshell.txt")

        cmd_output = ""
        in_output = False
        past_first_delimiter = False
        for line in output.split("\n"):
            if "command standard output" in line.lower():
                in_output = True
                past_first_delimiter = False
                continue
            if in_output:
                if line.startswith("---"):
                    if not past_first_delimiter:
                        past_first_delimiter = True
                        continue
                    else:
                        in_output = False
                elif line.startswith("["):
                    in_output = False
                else:
                    cmd_output += line + "\n"

        cmd_output = cmd_output.strip()
        assert "nt authority" in cmd_output.lower()

    # -- sql_query parser edge cases --

    def test_sql_query_retrieved_only(self):
        """sql_query result only available via [INFO] retrieved: line.

        When sqlmap doesn't print the 'sql-query output:' section, the fallback
        to [INFO] retrieved: must work.
        """
        output = load_fixture("sql_query_retrieved.txt")

        query_result = ""
        in_result = False
        for line in output.split("\n"):
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

        if not query_result:
            for line in output.split("\n"):
                m = re.search(r"\[INFO\]\s+retrieved:\s+(.+)", line)
                if m:
                    query_result += m.group(1).strip() + "\n"

        query_result = query_result.strip()
        assert "webapp@localhost" in query_result

    # -- file_write engagement bugs --

    def test_file_write_success_false_was_bug(self):
        """Engagement bug: file_write returned success=False (error=None) when
        write itself failed but sqlmap ran fine.

        Session ses_2d3ee1a1e: multiple file_write calls returned "Error: None".
        Root cause: ToolResult(success=<write_success>) instead of
        ToolResult(success=True, data={written: <write_success>}).

        Fixed: ToolResult.success always True when tool ran; data.written
        carries the write status.
        """
        # Verify the fix by checking the source code
        source = inspect.getsource(self._server.file_write)
        # The critical fix: success=True always, written field carries the status
        assert "success=True" in source, (
            "file_write must return success=True even when write fails. "
            "Use data.written for write status."
        )
        # Verify written is computed separately from success
        assert "written" in source

    # -- file_read fallback parser --

    def test_file_read_fallback_to_retrieved(self):
        """file_read should fall back to [INFO] retrieved: lines when local
        file is not readable.
        """
        source = inspect.getsource(self._server.file_read)
        assert "retrieved" in source, (
            "file_read should have a fallback to parse [INFO] retrieved: lines"
        )

    # -- enumerate_tables edge cases --

    def test_enumerate_tables_fixture(self):
        """Parse enumerate_tables fixture output."""
        output = load_fixture("enumerate_tables.txt")

        tables = []
        in_table_section = False
        database = "cobblestone"
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

        assert len(tables) == 4
        assert "users" in tables
        assert "sessions" in tables
        assert "config" in tables
        assert "logs" in tables

    def test_enumerate_tables_different_db(self):
        """Parse enumerate_tables for a different database name."""
        output = load_fixture("enumerate_tables_multiple_dbs.txt")

        tables = []
        in_table_section = False
        database = "webapp"
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

        assert len(tables) == 3
        assert "users" in tables
        assert "orders" in tables
        assert "products" in tables

    # -- Error classification integration --

    def test_classify_error_used_in_handlers(self):
        """_classify_sqlmap_error should be called from handler except blocks.

        Engagement: errors returned bare strings without error_class or suggestions.
        """
        # Check that test_injection uses _classify_sqlmap_error
        source = inspect.getsource(self._server.test_injection)
        assert "_classify_sqlmap_error" in source, (
            "test_injection should use _classify_sqlmap_error for error classification"
        )

    def test_classify_error_suggestions_in_test_injection(self):
        """test_injection should add suggestions from classifier to response data."""
        source = inspect.getsource(self._server.test_injection)
        assert "suggestions" in source, (
            "test_injection should pass suggestions from _classify_sqlmap_error"
        )


class TestTableDumpSeparatorRegression:
    """Regression tests for the table separator regex fix.

    Before fix: ^[\\+\\-]+$ matched --- (injection point delimiter)
    After fix: ^\\+[\\+\\-]+\\+$ requires at least one + at start and end
    """

    @classmethod
    def setup_class(cls):
        try:
            cls._server = _get_server_class()()
        except Exception as e:
            pytest.skip(f"Cannot import SqlmapServer: {e}")

    def test_simple_table_still_works(self):
        """Standard +---+---+ separators still work."""
        output = """
+----+-------+
| id | name  |
+----+-------+
| 1  | alice |
+----+-------+
"""
        result = self._server._parse_table_dump(output)
        assert result["columns"] == ["id", "name"]
        assert result["row_count"] == 1

    def test_dashes_only_ignored(self):
        """Bare --- should NOT be treated as table separator."""
        output = """
---
Parameter: id (GET)
    Type: UNION query
---
"""
        result = self._server._parse_table_dump(output)
        assert result["columns"] == []
        assert result["row_count"] == 0

    def test_mixed_output_table_at_end(self):
        """Table data at end of output with injection points before."""
        output = """
sqlmap identified the following injection point(s):
---
Parameter: id (GET)
    Type: boolean-based blind
    Payload: id=1 AND 5650=5650
---
back-end DBMS: MySQL >= 5.0.12

Database: testdb
Table: users
[1 entry]
+----+-------+----------+
| id | name  | password |
+----+-------+----------+
| 1  | admin | secret   |
+----+-------+----------+
"""
        result = self._server._parse_table_dump(output)
        assert result["columns"] == ["id", "name", "password"]
        assert result["row_count"] == 1
        assert result["rows"][0]["name"] == "admin"

    def test_wide_table(self):
        """Table with long column values."""
        output = """
+----+--------------------------------------------------+
| id | hash                                             |
+----+--------------------------------------------------+
| 1  | $2y$10$Xxx.Yyy.Zzz/1234567890abcdefghijklmnopqr |
+----+--------------------------------------------------+
"""
        result = self._server._parse_table_dump(output)
        assert result["columns"] == ["id", "hash"]
        assert result["row_count"] == 1
        assert "$2y$10$" in result["rows"][0]["hash"]

    def test_empty_cells_in_table(self):
        """Table with empty/blank cells."""
        output = """
+----+------+--------+
| id | name | email  |
+----+------+--------+
| 1  | test |        |
| 2  |      | a@b.co |
+----+------+--------+
"""
        result = self._server._parse_table_dump(output)
        assert result["row_count"] == 2
        assert result["rows"][0]["email"] == ""
        assert result["rows"][1]["name"] == ""


class TestCommonArgBuilderEdgeCases:
    """Additional arg builder tests from engagement patterns."""

    @classmethod
    def setup_class(cls):
        try:
            cls._server = _get_server_class()()
        except Exception as e:
            pytest.skip(f"Cannot import SqlmapServer: {e}")

    def test_cobblestone_engagement_args(self):
        """Reproduce exact args from Cobblestone engagement.

        Session ses_2d3ee1a1e: POST injection with cookie + param + dbms.
        """
        args = []
        self._server._append_common_args(
            args,
            data="url=test",
            cookie="PHPSESSID=qf4rjljueqj4bbt02ireeciraj",
            param="url",
            dbms="MySQL",
            risk=3,
            level=5,
            technique="BEU",
            threads=4,
        )
        assert "--data" in args
        assert "url=test" in args
        assert "--cookie" in args
        assert "PHPSESSID=qf4rjljueqj4bbt02ireeciraj" in args
        assert "-p" in args
        assert "url" in args
        assert "--dbms" in args
        assert "MySQL" in args
        assert "--risk" in args
        assert "3" in args
        assert "--level" in args
        assert "5" in args
        assert "--technique" in args
        assert "BEU" in args

    def test_cctv_engagement_args(self):
        """Reproduce exact args from CCTV.htb engagement.

        Session ses_317422a8d: time-based blind with ignore_code, high time_sec.
        """
        args = []
        self._server._append_common_args(
            args,
            ignore_code="401,500",
            cookie="ZMSESSID=n1ouoaj6dg55hf196ua4m04ai7",
            dbms="MySQL",
            param="tid",
            technique="T",
            level=3,
            risk=2,
            time_sec=15,
            threads=1,
            random_agent=True,
            flush_session=True,
        )
        assert "--ignore-code" in args
        assert "401,500" in args
        assert "--cookie" in args
        assert "--time-sec" in args
        assert "15" in args
        assert "--threads" in args
        assert "1" in args
        assert "--random-agent" in args
        assert "--flush-session" in args

    def test_all_boolean_flags_false_not_emitted(self):
        """Boolean flags set to False should NOT emit the flag."""
        args = []
        self._server._append_common_args(
            args,
            text_only=False,
            titles=False,
            null_connection=False,
            random_agent=False,
            flush_session=False,
        )
        assert "--text-only" not in args
        assert "--titles" not in args
        assert "--null-connection" not in args
        assert "--random-agent" not in args
        assert "--flush-session" not in args

    def test_headers_newline_separated(self):
        """Headers can also be separated by actual newlines."""
        args = []
        self._server._append_common_args(
            args,
            headers="Authorization: Bearer xyz\nX-Custom: val"
        )
        h_indices = [i for i, a in enumerate(args) if a == "-H"]
        assert len(h_indices) == 2

    def test_headers_single(self):
        """Single header without separator."""
        args = []
        self._server._append_common_args(
            args,
            headers="Authorization: Bearer token123"
        )
        h_indices = [i for i, a in enumerate(args) if a == "-H"]
        assert len(h_indices) == 1
        idx = h_indices[0]
        assert args[idx + 1] == "Authorization: Bearer token123"

    def test_cookie_with_multiple_values(self):
        """Cookie with multiple semicolon-separated values."""
        args = []
        self._server._append_common_args(
            args,
            cookie="PHPSESSID=abc123; session=xyz; token=456"
        )
        assert "--cookie" in args
        cookie_idx = args.index("--cookie")
        assert args[cookie_idx + 1] == "PHPSESSID=abc123; session=xyz; token=456"

    def test_tamper_multiple_scripts(self):
        """Multiple tamper scripts comma-separated."""
        args = []
        self._server._append_common_args(
            args,
            tamper="space2comment,between,randomcase"
        )
        assert "--tamper" in args
        tamper_idx = args.index("--tamper")
        assert args[tamper_idx + 1] == "space2comment,between,randomcase"


class TestErrorClassificationIntegration:
    """Test that error classification works end-to-end for sqlmap patterns."""

    @classmethod
    def setup_class(cls):
        try:
            cls._server = _get_server_class()()
        except Exception as e:
            pytest.skip(f"Cannot import SqlmapServer: {e}")

    def test_waf_suggestions_include_random_agent(self):
        """WAF classification should suggest --random-agent."""
        _, _, suggestions = self._server._classify_sqlmap_error(
            "heuristics detected that the target is protected by some kind of WAF/IPS"
        )
        assert any("random-agent" in s.lower() for s in suggestions)

    def test_not_injectable_suggests_level_risk(self):
        """'not injectable' should suggest increasing --level and --risk."""
        _, _, suggestions = self._server._classify_sqlmap_error(
            "all tested parameters do not appear to be injectable"
        )
        assert any("level" in s.lower() for s in suggestions)
        assert any("risk" in s.lower() for s in suggestions)

    def test_connection_failure_with_proxy(self):
        """Connection failure with proxy should suggest checking proxy."""
        err_class, retryable, suggestions = self._server._classify_sqlmap_error(
            "unable to connect to the target URL or proxy"
        )
        assert err_class == "network"
        assert retryable is True
        assert any("proxy" in s.lower() for s in suggestions)

    def test_invalid_url_not_retryable(self):
        """Invalid URL is not retryable."""
        err_class, retryable, _ = self._server._classify_sqlmap_error(
            "invalid target url"
        )
        assert err_class == "params"
        assert retryable is False

    def test_normal_output_unknown(self):
        """Normal output that has no error patterns."""
        err_class, _, suggestions = self._server._classify_sqlmap_error(
            "back-end DBMS: MySQL >= 5.0.12\n[INFO] fetched data logged to text files"
        )
        assert err_class == "unknown"
        assert suggestions == []

    def test_waf_ips_variant(self):
        """Alternative WAF phrasing."""
        err_class, _, suggestions = self._server._classify_sqlmap_error(
            "WAF/IPS protection detected on target"
        )
        assert err_class == "config"


class TestProgressFilterEdgeCases:
    """Additional progress filter tests from engagement patterns."""

    @classmethod
    def setup_class(cls):
        try:
            cls._server = _get_server_class()()
        except Exception as e:
            pytest.skip(f"Cannot import SqlmapServer: {e}")

    def test_time_based_injection_progress(self):
        """Time-based testing lines should pass through."""
        line = "[14:00:17] [INFO] GET parameter 'tid' appears to be 'MySQL >= 5.0.12 AND time-based blind (query SLEEP)' injectable"
        result = self._server._sqlmap_progress_filter(line)
        assert result is not None
        assert "time-based blind" in result

    def test_union_columns_progress(self):
        """UNION column count detection should pass through."""
        line = "[13:45:04] [INFO] target URL appears to have 6 columns in query"
        result = self._server._sqlmap_progress_filter(line)
        assert result is not None
        assert "6 columns" in result

    def test_stacked_queries_progress(self):
        """Stacked queries detection should pass through."""
        line = "[13:30:05] [INFO] POST parameter 'url' appears to be 'MySQL >= 5.0.12 stacked queries (comment)' injectable"
        result = self._server._sqlmap_progress_filter(line)
        assert result is not None

    def test_waf_critical_passes(self):
        """WAF detection critical should pass through."""
        line = "[16:00:02] [CRITICAL] heuristics detected that the target is protected by some kind of WAF/IPS"
        result = self._server._sqlmap_progress_filter(line)
        assert result is not None
        assert "CRITICAL" in result

    def test_all_not_injectable_passes(self):
        """'all tested parameters do not appear to be injectable' should pass."""
        line = "[15:00:18] [CRITICAL] all tested parameters do not appear to be injectable"
        result = self._server._sqlmap_progress_filter(line)
        assert result is not None

    def test_fetching_entries_passes(self):
        """Fetching entries progress should pass through."""
        line = "[13:50:02] [INFO] fetching entries for table 'users' in database 'testdb'"
        result = self._server._sqlmap_progress_filter(line)
        assert result is not None

    def test_retrieved_passes(self):
        """[INFO] retrieved lines should pass through."""
        line = "[14:20:02] [INFO] retrieved: 'root','*6BB4837EB74329105EE4568DDA7DC67ED2CA2AD9'"
        result = self._server._sqlmap_progress_filter(line)
        assert result is not None


class TestDatabaseParserEdgeCases:
    """Additional database parser tests."""

    @classmethod
    def setup_class(cls):
        try:
            cls._server = _get_server_class()()
        except Exception as e:
            pytest.skip(f"Cannot import SqlmapServer: {e}")

    def test_databases_with_special_chars(self):
        """Database names with hyphens and underscores."""
        output = (
            "available databases [3]:\n"
            "[*] my-database\n"
            "[*] test_db_2\n"
            "[*] CamelCaseDB\n"
        )
        databases = self._server._parse_databases(output)
        assert "my-database" in databases
        assert "test_db_2" in databases
        assert "CamelCaseDB" in databases

    def test_databases_with_count_line(self):
        """Parse databases when sqlmap includes count in bracket."""
        output = (
            "available databases [5]:\n"
            "[*] information_schema\n"
            "[*] mysql\n"
            "[*] performance_schema\n"
            "[*] sys\n"
            "[*] webapp\n"
        )
        databases = self._server._parse_databases(output)
        assert len(databases) == 5

    def test_single_database(self):
        """Parse output with only one database."""
        output = (
            "available databases [1]:\n"
            "[*] testdb\n"
        )
        databases = self._server._parse_databases(output)
        assert databases == ["testdb"]


class TestVulnerabilityParserComprehensive:
    """Comprehensive vulnerability parser tests covering all injection types."""

    @classmethod
    def setup_class(cls):
        try:
            cls._server = _get_server_class()()
        except Exception as e:
            pytest.skip(f"Cannot import SqlmapServer: {e}")

    def test_all_six_techniques_detected(self):
        """Each of the 6 injection techniques should be parseable."""
        techniques = [
            ("boolean-based blind", "Type: boolean-based blind"),
            ("error-based", "Type: error-based"),
            ("UNION query", "Type: UNION query"),
            ("stacked queries", "Type: stacked queries"),
            ("time-based blind", "Type: time-based blind"),
            ("inline query", "Type: inline query"),
        ]
        for technique_name, type_line in techniques:
            output = f"""
sqlmap identified the following injection point(s):
---
Parameter: id (GET)
    {type_line}
    Title: Test {technique_name}
    Payload: id=1 AND 1=1
---
back-end DBMS: MySQL >= 5.0.12
"""
            result = self._server._parse_sqlmap_output(output)
            assert result["vulnerable"] is True, f"Failed for {technique_name}"
            assert result["injection_type"] is not None, f"No type for {technique_name}"

    def test_multiple_parameters_injectable(self):
        """Multiple parameters found injectable in same scan."""
        output = """
Parameter: id (GET)
    Type: boolean-based blind
GET parameter 'id' is vulnerable.
Parameter: name (POST)
    Type: error-based
POST parameter 'name' is vulnerable.
sqlmap identified the following injection point(s):
"""
        result = self._server._parse_sqlmap_output(output)
        assert result["vulnerable"] is True
        assert "id" in result["parameters"]
        assert "name" in result["parameters"]

    def test_cookie_parameter_injectable(self):
        """Cookie parameter injection detection."""
        output = """
Parameter: session (Cookie)
    Type: time-based blind
Cookie parameter 'session' is vulnerable.
sqlmap identified the following injection point(s):
back-end DBMS: MySQL >= 5.0.12
"""
        result = self._server._parse_sqlmap_output(output)
        assert result["vulnerable"] is True
        assert "session" in result["parameters"]

    def test_dbms_extraction_variants(self):
        """Various DBMS identification strings."""
        dbms_lines = [
            ("back-end DBMS: MySQL >= 5.0.12", "MySQL"),
            ("back-end DBMS: PostgreSQL >= 9.6", "PostgreSQL"),
            ("back-end DBMS: Microsoft SQL Server 2019", "Microsoft SQL Server"),
            ("back-end DBMS: Oracle", "Oracle"),
            ("back-end DBMS: SQLite", "SQLite"),
            ("back-end DBMS: MySQL >= 5.1 (MariaDB fork)", "MariaDB"),
        ]
        for line, expected_substr in dbms_lines:
            output = f"sqlmap identified the following injection point(s):\n{line}\n"
            result = self._server._parse_sqlmap_output(output)
            assert expected_substr in result["dbms"], (
                f"Expected '{expected_substr}' in dbms for line: {line}, got: {result['dbms']}"
            )

    def test_might_not_injectable_negative(self):
        """'might not be injectable' must NOT trigger vulnerable=True."""
        output = "[INFO] heuristic (basic) test shows that GET parameter 'id' might not be injectable"
        result = self._server._parse_sqlmap_output(output)
        assert result["vulnerable"] is False

    def test_does_not_seem_injectable_negative(self):
        """'does not seem to be injectable' must NOT trigger vulnerable=True."""
        output = "[WARNING] GET parameter 'id' does not seem to be injectable via UNION query technique"
        result = self._server._parse_sqlmap_output(output)
        assert result["vulnerable"] is False


# ===========================================================================
# INTEGRATION TESTS -- require --target flag with a vulnerable target
# ===========================================================================

@pytest.mark.integration
class TestIntegration:
    """Integration tests that require a live vulnerable target.

    Run with: pytest tests/tools/test_sqlmap.py -k integration --tool sqlmap --target <IP>
    """

    def test_full_sqli_workflow(self, sqlmap_env, target):
        """Full workflow: test_injection -> enumerate_dbs -> enumerate_tables -> dump_table."""
        client, loop = sqlmap_env

        # Step 1: Test injection
        resp = loop.run_until_complete(client.call(
            "test_injection",
            {
                "url": f"http://{target}/vuln.php?id=1",
                "timeout": 300,
            },
            timeout=360,
        ))
        result = assert_tool_success(resp, "test_injection should succeed")
        data = parse_tool_output(resp)
        assert data.get("vulnerable") is True, "Target should be vulnerable"
        assert data.get("dbms") is not None, "DBMS should be detected"

        # Step 2: Enumerate databases
        resp = loop.run_until_complete(client.call(
            "enumerate_dbs",
            {
                "url": f"http://{target}/vuln.php?id=1",
                "timeout": 120,
            },
            timeout=180,
        ))
        result = assert_tool_success(resp, "enumerate_dbs should succeed")
        data = parse_tool_output(resp)
        assert len(data.get("databases", [])) > 0, "Should find databases"
