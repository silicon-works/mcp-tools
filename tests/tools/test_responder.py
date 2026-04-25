"""
Tests for the responder MCP tool server.

Covers:
- Smoke tests: boot, method list, required params, meta-param stripping
- Unit tests: hash parsing (DB + file), config management, duration validation,
              error classification, port bind error detection, ANSI stripping
- Contract tests: tool.yaml vs server parameter definitions
- Integration tests: real target scenarios (marked @pytest.mark.integration)
"""

import asyncio
import configparser
import json
import os
import shutil
import sqlite3
import sys
import tempfile
from pathlib import Path
from typing import Any, Dict
from unittest.mock import AsyncMock, MagicMock, patch

import pytest
import yaml

# ---------------------------------------------------------------------------
# Path setup
# ---------------------------------------------------------------------------
PROJECT_ROOT = Path(__file__).parent.parent.parent
TOOL_DIR = PROJECT_ROOT / "tools" / "responder"
FIXTURES_DIR = Path(__file__).parent.parent / "fixtures" / "responder"

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
def responder_env(request):
    """Create an MCPTestClient with its event loop. Yields (client, loop)."""
    tool = "responder"
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
# Helper: import server module for direct parser testing
# ---------------------------------------------------------------------------
def _get_server_class():
    """Import and return the ResponderServer class for direct method testing."""
    import importlib.util
    spec = importlib.util.spec_from_file_location(
        "responder_server", TOOL_DIR / "mcp-server.py"
    )
    mod = importlib.util.module_from_spec(spec)
    spec.loader.exec_module(mod)
    return mod.ResponderServer


def _get_module():
    """Import the responder module and return it."""
    import importlib.util
    spec = importlib.util.spec_from_file_location(
        "responder_server", TOOL_DIR / "mcp-server.py"
    )
    mod = importlib.util.module_from_spec(spec)
    spec.loader.exec_module(mod)
    return mod


# ===========================================================================
# SMOKE TESTS -- require Docker container running
# ===========================================================================

class TestSmoke:
    """Smoke tests that verify the container boots and basic protocol works."""

    def test_boot_and_list_tools(self, responder_env):
        """Container starts and list_tools returns methods."""
        client, loop = responder_env
        assert len(client.tools) > 0, "Server should advertise at least one tool"
        names = client.tool_names()
        assert "poison" in names, "poison should be in tool list"
        assert "analyze" in names, "analyze should be in tool list"
        assert "capture_smb" in names, "capture_smb should be in tool list"

    def test_method_list_matches_tool_yaml(self, responder_env):
        """Every method in tool.yaml is advertised by the server, and vice versa."""
        client, _ = responder_env
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

    def test_expected_method_count(self, responder_env):
        """Server should have exactly 3 built-in methods + verify_clock."""
        client, _ = responder_env
        names = client.tool_names()
        # 3 built-in + verify_clock in MCP_TEST_MODE
        assert len(names) == 4, (
            f"Expected 4 methods (3 built-in + verify_clock), got {len(names)}: {sorted(names)}"
        )

    def test_required_params_enforced_poison(self, responder_env):
        """Calling poison without required 'duration' returns an error."""
        client, loop = responder_env
        resp = loop.run_until_complete(
            client.call("poison", {"verbose": True})
        )
        result = resp.get("result", {})
        is_error = result.get("isError", False)
        content_text = ""
        for c in result.get("content", []):
            if c.get("type") == "text":
                content_text += c["text"]
        assert is_error or "duration" in content_text.lower() or "missing" in content_text.lower(), (
            f"Expected error about missing 'duration', got: {content_text[:300]}"
        )

    def test_required_params_enforced_analyze(self, responder_env):
        """Calling analyze without required 'duration' returns an error."""
        client, loop = responder_env
        resp = loop.run_until_complete(
            client.call("analyze", {})
        )
        result = resp.get("result", {})
        is_error = result.get("isError", False)
        content_text = ""
        for c in result.get("content", []):
            if c.get("type") == "text":
                content_text += c["text"]
        assert is_error or "duration" in content_text.lower() or "missing" in content_text.lower(), (
            f"Expected error about missing 'duration', got: {content_text[:300]}"
        )

    def test_required_params_enforced_capture_smb(self, responder_env):
        """Calling capture_smb without required 'duration' returns an error."""
        client, loop = responder_env
        resp = loop.run_until_complete(
            client.call("capture_smb", {})
        )
        result = resp.get("result", {})
        is_error = result.get("isError", False)
        content_text = ""
        for c in result.get("content", []):
            if c.get("type") == "text":
                content_text += c["text"]
        assert is_error or "duration" in content_text.lower() or "missing" in content_text.lower(), (
            f"Expected error about missing 'duration', got: {content_text[:300]}"
        )

    def test_meta_params_stripped(self, responder_env):
        """Passing 'clock_offset' (meta-param) in args does not crash the server."""
        client, loop = responder_env
        resp = loop.run_until_complete(
            client.call("poison", {
                "duration": 3,
                "clock_offset": "5h",  # meta-param -- should be stripped
            })
        )
        result = resp.get("result", {})
        content_text = ""
        for c in result.get("content", []):
            if c.get("type") == "text":
                content_text += c["text"]
        assert "unexpected keyword argument" not in content_text, (
            f"Meta-param 'clock_offset' was not stripped: {content_text[:300]}"
        )

    def test_unknown_method_returns_error(self, responder_env):
        """Calling a non-existent method returns a helpful error."""
        client, loop = responder_env
        resp = loop.run_until_complete(
            client.call("nonexistent_method", {})
        )
        result = assert_tool_error(resp)
        content_text = ""
        for c in result.get("content", []):
            if c.get("type") == "text":
                content_text += c["text"]
        assert "Unknown method" in content_text
        assert "nonexistent_method" in content_text

    @pytest.mark.clock
    def test_verify_clock_available(self, responder_env):
        """verify_clock is registered in MCP_TEST_MODE."""
        client, _ = responder_env
        names = client.tool_names()
        assert "verify_clock" in names, "verify_clock should be available in test mode"

    @pytest.mark.clock
    def test_verify_clock_returns_time(self, responder_env):
        """verify_clock returns current time and FAKETIME status."""
        client, loop = responder_env
        resp = loop.run_until_complete(client.call("verify_clock", {}))
        result = assert_tool_success(resp)
        data = parse_tool_output(resp)
        assert "current_time" in data
        assert "libfaketime_exists" in data
        # Responder image does NOT install libfaketime (no Kerberos clock offset needed)
        # Just check the field exists
        assert isinstance(data["libfaketime_exists"], bool)

    def test_structuredContent_present(self, responder_env):
        """Responses include structuredContent with error classification fields."""
        client, loop = responder_env
        resp = loop.run_until_complete(client.call("verify_clock", {}))
        result = resp.get("result", {})
        sc = result.get("structuredContent")
        assert sc is not None, "structuredContent should be present"
        assert "success" in sc
        assert "error_class" in sc
        assert "retryable" in sc
        assert "suggestions" in sc

    def test_duration_too_short_poison(self, responder_env):
        """Poison with duration < 5 returns a clear error."""
        client, loop = responder_env
        resp = loop.run_until_complete(
            client.call("poison", {"duration": 2})
        )
        result = assert_tool_error(resp)
        content_text = ""
        for c in result.get("content", []):
            if c.get("type") == "text":
                content_text += c["text"]
        assert "at least 5" in content_text.lower(), (
            f"Expected min duration error, got: {content_text[:300]}"
        )

    def test_duration_too_long_poison(self, responder_env):
        """Poison with duration > MAX_DURATION returns a clear error."""
        client, loop = responder_env
        resp = loop.run_until_complete(
            client.call("poison", {"duration": 600})
        )
        result = assert_tool_error(resp)
        content_text = ""
        for c in result.get("content", []):
            if c.get("type") == "text":
                content_text += c["text"]
        assert "540" in content_text or "at most" in content_text.lower(), (
            f"Expected max duration error, got: {content_text[:300]}"
        )

    def test_duration_too_short_analyze(self, responder_env):
        """Analyze with duration < 5 returns a clear error."""
        client, loop = responder_env
        resp = loop.run_until_complete(
            client.call("analyze", {"duration": 1})
        )
        result = assert_tool_error(resp)
        content_text = ""
        for c in result.get("content", []):
            if c.get("type") == "text":
                content_text += c["text"]
        assert "at least 5" in content_text.lower()

    def test_duration_too_long_capture_smb(self, responder_env):
        """capture_smb with duration > MAX_DURATION returns a clear error."""
        client, loop = responder_env
        resp = loop.run_until_complete(
            client.call("capture_smb", {"duration": 999})
        )
        result = assert_tool_error(resp)
        content_text = ""
        for c in result.get("content", []):
            if c.get("type") == "text":
                content_text += c["text"]
        assert "540" in content_text or "at most" in content_text.lower()

    def test_empty_interface_rejected(self, responder_env):
        """Passing an empty string for interface returns a clear error."""
        client, loop = responder_env
        resp = loop.run_until_complete(
            client.call("poison", {"duration": 10, "interface": ""})
        )
        result = assert_tool_error(resp)
        content_text = ""
        for c in result.get("content", []):
            if c.get("type") == "text":
                content_text += c["text"]
        assert "empty" in content_text.lower() or "interface" in content_text.lower(), (
            f"Expected interface error, got: {content_text[:300]}"
        )

    def test_invalid_interface_rejected(self, responder_env):
        """Passing an invalid interface name returns a clear error."""
        client, loop = responder_env
        resp = loop.run_until_complete(
            client.call("poison", {"duration": 10, "interface": "nonexistent_iface99"})
        )
        result = assert_tool_error(resp)
        content_text = ""
        for c in result.get("content", []):
            if c.get("type") == "text":
                content_text += c["text"]
        assert "not found" in content_text.lower() or "interface" in content_text.lower(), (
            f"Expected interface not found error, got: {content_text[:300]}"
        )


# ===========================================================================
# UNIT TESTS -- output parsers and helpers, no container needed
# ===========================================================================

class TestHashParsing:
    """Test hash parsing functions using fixture data and mock DB/files."""

    @pytest.fixture(autouse=True, scope="class")
    def server(self):
        """Create a server instance for parser testing."""
        try:
            cls = _get_server_class()
            self.__class__._server = cls()
        except Exception as e:
            pytest.skip(f"Cannot import ResponderServer: {e}")

    def test_parse_hashes_from_db_with_ntlmv2(self, tmp_path):
        """Parse NTLMv2 hashes from a mock Responder SQLite database."""
        db_path = tmp_path / "Responder.db"
        conn = sqlite3.connect(str(db_path))
        conn.execute(
            "CREATE TABLE responder ("
            "timestamp TEXT, module TEXT, type TEXT, client TEXT, "
            "hostname TEXT, user TEXT, cleartext TEXT, hash TEXT, fullhash TEXT)"
        )
        conn.execute(
            "INSERT INTO responder VALUES (?, ?, ?, ?, ?, ?, ?, ?, ?)",
            (
                "2026-03-16 22:39:59",
                "SMB",
                "NTLMv2-SSP",
                "10.129.10.50",
                "WORKSTATION01",
                "CORP\\john.doe",
                "",
                "short_hash",
                "john.doe::CORP:1122334455667788:AABB:0101",
            ),
        )
        conn.commit()
        conn.close()

        # Temporarily override the DB path
        mod = _get_module()
        orig_db = mod.RESPONDER_DB
        mod.RESPONDER_DB = str(db_path)
        try:
            server = mod.ResponderServer()
            hashes = server._parse_hashes_from_db()
        finally:
            mod.RESPONDER_DB = orig_db

        assert len(hashes) == 1
        assert hashes[0]["module"] == "SMB"
        assert hashes[0]["hash_type"] == "NTLMv2-SSP"
        assert hashes[0]["client_ip"] == "10.129.10.50"
        assert hashes[0]["username"] == "CORP\\john.doe"
        assert hashes[0]["hash"] == "john.doe::CORP:1122334455667788:AABB:0101"
        # fullhash takes precedence over hash
        assert "short_hash" not in hashes[0]["hash"]

    def test_parse_hashes_from_db_cleartext(self, tmp_path):
        """Parse cleartext credentials from the DB."""
        db_path = tmp_path / "Responder.db"
        conn = sqlite3.connect(str(db_path))
        conn.execute(
            "CREATE TABLE responder ("
            "timestamp TEXT, module TEXT, type TEXT, client TEXT, "
            "hostname TEXT, user TEXT, cleartext TEXT, hash TEXT, fullhash TEXT)"
        )
        conn.execute(
            "INSERT INTO responder VALUES (?, ?, ?, ?, ?, ?, ?, ?, ?)",
            (
                "2026-03-16 22:39:59",
                "MSSQL",
                "Cleartext",
                "10.129.10.137",
                "SQL07 ()",
                "sqlmgmt",
                "bIhBbzMMnB82yx",
                "sqlmgmt:bIhBbzMMnB82yx",
                "",
            ),
        )
        conn.commit()
        conn.close()

        mod = _get_module()
        orig_db = mod.RESPONDER_DB
        mod.RESPONDER_DB = str(db_path)
        try:
            server = mod.ResponderServer()
            hashes = server._parse_hashes_from_db()
        finally:
            mod.RESPONDER_DB = orig_db

        assert len(hashes) == 1
        assert hashes[0]["module"] == "MSSQL"
        assert hashes[0]["cleartext"] == "bIhBbzMMnB82yx"
        # When fullhash is empty, falls back to hash
        assert hashes[0]["hash"] == "sqlmgmt:bIhBbzMMnB82yx"

    def test_parse_hashes_from_db_empty(self, tmp_path):
        """Empty DB (no responder table) returns empty list."""
        db_path = tmp_path / "Responder.db"
        conn = sqlite3.connect(str(db_path))
        conn.close()

        mod = _get_module()
        orig_db = mod.RESPONDER_DB
        mod.RESPONDER_DB = str(db_path)
        try:
            server = mod.ResponderServer()
            hashes = server._parse_hashes_from_db()
        finally:
            mod.RESPONDER_DB = orig_db

        assert hashes == []

    def test_parse_hashes_from_db_nonexistent(self):
        """Non-existent DB path returns empty list."""
        mod = _get_module()
        orig_db = mod.RESPONDER_DB
        mod.RESPONDER_DB = "/nonexistent/path/Responder.db"
        try:
            server = mod.ResponderServer()
            hashes = server._parse_hashes_from_db()
        finally:
            mod.RESPONDER_DB = orig_db

        assert hashes == []

    def test_parse_hashes_from_db_locked(self, tmp_path):
        """DB with a write lock is handled gracefully (timeout)."""
        db_path = tmp_path / "Responder.db"
        # Create DB with table
        conn = sqlite3.connect(str(db_path))
        conn.execute(
            "CREATE TABLE responder ("
            "timestamp TEXT, module TEXT, type TEXT, client TEXT, "
            "hostname TEXT, user TEXT, cleartext TEXT, hash TEXT, fullhash TEXT)"
        )
        conn.commit()
        # Keep an exclusive lock open
        conn.execute("BEGIN EXCLUSIVE")

        mod = _get_module()
        orig_db = mod.RESPONDER_DB
        mod.RESPONDER_DB = str(db_path)
        try:
            server = mod.ResponderServer()
            # Should not crash -- returns empty after timeout
            hashes = server._parse_hashes_from_db()
            assert hashes == []
        finally:
            mod.RESPONDER_DB = orig_db
            conn.close()

    def test_parse_hashes_from_files_ntlmv2(self, tmp_path):
        """Parse NTLMv2 hashes from log files."""
        logs_dir = tmp_path / "logs"
        logs_dir.mkdir()
        hash_file = logs_dir / "SMB-NTLMv2-SSP-10.129.10.50.txt"
        hash_file.write_text(
            "john.doe::CORP:1122334455667788:A1B2C3D4:0101000000000000\n"
            "jane.smith::CORP:AABBCCDD11223344:B2C3D4E5:0101000000000000\n"
        )

        mod = _get_module()
        orig_logs = mod.RESPONDER_LOGS
        mod.RESPONDER_LOGS = str(logs_dir)
        try:
            server = mod.ResponderServer()
            hashes = server._parse_hashes_from_files()
        finally:
            mod.RESPONDER_LOGS = orig_logs

        assert len(hashes) == 2
        assert hashes[0]["module"] == "SMB"
        assert hashes[0]["username"] == "john.doe"
        assert hashes[0]["domain"] == "CORP"
        assert "NTLMv2" in hashes[0]["hash_type"]

    def test_parse_hashes_from_files_cleartext(self, tmp_path):
        """Parse cleartext credentials from log files."""
        logs_dir = tmp_path / "logs"
        logs_dir.mkdir()
        ct_file = logs_dir / "MSSQL-ClearText-10.129.10.137.txt"
        ct_file.write_text("sqlmgmt:bIhBbzMMnB82yx\n")

        mod = _get_module()
        orig_logs = mod.RESPONDER_LOGS
        mod.RESPONDER_LOGS = str(logs_dir)
        try:
            server = mod.ResponderServer()
            hashes = server._parse_hashes_from_files()
        finally:
            mod.RESPONDER_LOGS = orig_logs

        assert len(hashes) == 1
        assert hashes[0]["module"] == "MSSQL"
        assert hashes[0]["hash_type"] == "ClearText"
        assert hashes[0]["username"] == "sqlmgmt"
        assert hashes[0]["cleartext"] == "bIhBbzMMnB82yx"

    def test_parse_hashes_from_files_empty_dir(self, tmp_path):
        """Empty logs directory returns empty list."""
        logs_dir = tmp_path / "logs"
        logs_dir.mkdir()

        mod = _get_module()
        orig_logs = mod.RESPONDER_LOGS
        mod.RESPONDER_LOGS = str(logs_dir)
        try:
            server = mod.ResponderServer()
            hashes = server._parse_hashes_from_files()
        finally:
            mod.RESPONDER_LOGS = orig_logs

        assert hashes == []

    def test_parse_hashes_from_files_nonexistent_dir(self):
        """Non-existent logs directory returns empty list."""
        mod = _get_module()
        orig_logs = mod.RESPONDER_LOGS
        mod.RESPONDER_LOGS = "/nonexistent/logs"
        try:
            server = mod.ResponderServer()
            hashes = server._parse_hashes_from_files()
        finally:
            mod.RESPONDER_LOGS = orig_logs

        assert hashes == []

    def test_parse_hashes_from_files_skips_comments(self, tmp_path):
        """Lines starting with # are skipped."""
        logs_dir = tmp_path / "logs"
        logs_dir.mkdir()
        hash_file = logs_dir / "HTTP-NTLMv2-10.0.0.1.txt"
        hash_file.write_text(
            "# Comment line\n"
            "user1::DOMAIN:challenge:response:blob\n"
            "\n"  # empty line
            "# Another comment\n"
        )

        mod = _get_module()
        orig_logs = mod.RESPONDER_LOGS
        mod.RESPONDER_LOGS = str(logs_dir)
        try:
            server = mod.ResponderServer()
            hashes = server._parse_hashes_from_files()
        finally:
            mod.RESPONDER_LOGS = orig_logs

        assert len(hashes) == 1
        assert hashes[0]["username"] == "user1"

    def test_parse_analyze_log(self, tmp_path):
        """Parse analyzer session log."""
        logs_dir = tmp_path / "logs"
        logs_dir.mkdir()
        log_file = logs_dir / "Analyzer-Session.log"
        log_file.write_text(
            "[LLMNR] Request by 10.0.0.1 for FILESERVER\n"
            "[NBT-NS] Request by 10.0.0.2 for PRINTSERVER\n"
            "\n"
        )

        mod = _get_module()
        orig_logs = mod.RESPONDER_LOGS
        mod.RESPONDER_LOGS = str(logs_dir)
        try:
            server = mod.ResponderServer()
            detections = server._parse_analyze_log()
        finally:
            mod.RESPONDER_LOGS = orig_logs

        assert len(detections) == 2
        assert "FILESERVER" in detections[0]
        assert "PRINTSERVER" in detections[1]

    def test_parse_analyze_log_missing(self):
        """Missing analyzer log returns empty list."""
        mod = _get_module()
        orig_logs = mod.RESPONDER_LOGS
        mod.RESPONDER_LOGS = "/nonexistent/logs"
        try:
            server = mod.ResponderServer()
            detections = server._parse_analyze_log()
        finally:
            mod.RESPONDER_LOGS = orig_logs

        assert detections == []


# ===========================================================================
# CONFIG MANAGEMENT TESTS
# ===========================================================================

class TestConfigManagement:
    """Test Responder.conf backup, restore, and SMB-only rewrite."""

    @pytest.fixture(autouse=True)
    def setup_config(self, tmp_path):
        """Set up a temporary config file for each test."""
        self.config_dir = tmp_path / "responder"
        self.config_dir.mkdir()
        self.config_path = self.config_dir / "Responder.conf"

        # Write a realistic Responder.conf
        config = configparser.ConfigParser()
        config["Responder Core"] = {
            "LLMNR": "On",
            "NBTNS": "On",
            "MDNS": "On",
            "SQL": "On",
            "SMB": "On",
            "QUIC": "On",
            "RDP": "On",
            "Kerberos": "On",
            "FTP": "On",
            "POP": "On",
            "SMTP": "On",
            "IMAP": "On",
            "HTTP": "On",
            "HTTPS": "On",
            "DNS": "On",
            "LDAP": "On",
            "DCERPC": "On",
            "WINRM": "On",
            "SNMP": "On",
            "MQTT": "On",
            "MYSQL": "On",
        }
        with open(self.config_path, "w") as f:
            config.write(f)

        # Patch the module-level constant
        self.mod = _get_module()
        self._orig_conf = self.mod.RESPONDER_CONF
        self.mod.RESPONDER_CONF = str(self.config_path)

        self.server = self.mod.ResponderServer()

        yield

        self.mod.RESPONDER_CONF = self._orig_conf

    def test_write_smb_only_config(self):
        """SMB-only config disables all poisoners and servers except SMB."""
        self.server._write_smb_only_config()

        config = configparser.ConfigParser()
        config.read(str(self.config_path))

        section = "Responder Core"
        # Poisoners should be off
        assert config.get(section, "LLMNR").lower() == "off"
        assert config.get(section, "NBTNS").lower() == "off"
        assert config.get(section, "MDNS").lower() == "off"

        # SMB should be on
        assert config.get(section, "SMB").lower() == "on"

        # Other servers should be off
        for srv in ["SQL", "HTTP", "HTTPS", "DNS", "LDAP", "FTP",
                     "POP", "SMTP", "IMAP", "DCERPC", "WINRM", "SNMP",
                     "MQTT", "MYSQL", "Kerberos", "RDP", "QUIC"]:
            assert config.get(section, srv).lower() == "off", (
                f"Server {srv} should be Off, got {config.get(section, srv)}"
            )

    def test_backup_config(self):
        """Backup creates a .bak file."""
        backup_path = self.server._backup_config()
        assert backup_path is not None
        assert os.path.exists(backup_path)

        # Content should match original
        with open(str(self.config_path)) as f:
            original = f.read()
        with open(backup_path) as f:
            backup = f.read()
        assert original == backup

    def test_restore_config(self):
        """Restore recovers the original config from backup."""
        # First backup
        self.server._backup_config()

        # Read original content
        with open(str(self.config_path)) as f:
            original_content = f.read()

        # Modify config
        self.server._write_smb_only_config()

        # Verify it changed
        with open(str(self.config_path)) as f:
            modified_content = f.read()
        assert modified_content != original_content

        # Restore
        result = self.server._restore_config()
        assert result is True

        # Verify restored
        with open(str(self.config_path)) as f:
            restored_content = f.read()
        assert restored_content == original_content

        # Backup file should be cleaned up
        assert not os.path.exists(str(self.config_path) + ".bak")

    def test_restore_without_backup(self):
        """Restore without a prior backup returns False."""
        result = self.server._restore_config()
        assert result is False

    def test_backup_restore_roundtrip(self):
        """Full backup -> modify -> restore cycle preserves original config."""
        # Read original
        config_orig = configparser.ConfigParser()
        config_orig.read(str(self.config_path))
        orig_smb = config_orig.get("Responder Core", "SMB")
        orig_sql = config_orig.get("Responder Core", "SQL")

        assert orig_smb.lower() == "on"
        assert orig_sql.lower() == "on"

        # Backup, modify, restore
        self.server._backup_config()
        self.server._write_smb_only_config()

        # SQL should now be off
        config_mod = configparser.ConfigParser()
        config_mod.read(str(self.config_path))
        assert config_mod.get("Responder Core", "SQL").lower() == "off"

        self.server._restore_config()

        # SQL should be back on
        config_restored = configparser.ConfigParser()
        config_restored.read(str(self.config_path))
        assert config_restored.get("Responder Core", "SQL").lower() == "on"


# ===========================================================================
# DURATION VALIDATION TESTS
# ===========================================================================

class TestDurationValidation:
    """Test duration validation logic."""

    @pytest.fixture(autouse=True, scope="class")
    def server(self):
        """Create a server instance."""
        try:
            cls = _get_server_class()
            self.__class__._server = cls()
        except Exception as e:
            pytest.skip(f"Cannot import ResponderServer: {e}")

    def test_valid_duration_5(self):
        assert self._server._validate_duration(5) is None

    def test_valid_duration_30(self):
        assert self._server._validate_duration(30) is None

    def test_valid_duration_300(self):
        assert self._server._validate_duration(300) is None

    def test_valid_duration_540(self):
        assert self._server._validate_duration(540) is None

    def test_invalid_duration_too_short_0(self):
        err = self._server._validate_duration(0)
        assert err is not None
        assert "at least 5" in err.lower()

    def test_invalid_duration_too_short_4(self):
        err = self._server._validate_duration(4)
        assert err is not None
        assert "at least 5" in err.lower()

    def test_invalid_duration_negative(self):
        err = self._server._validate_duration(-10)
        assert err is not None
        assert "at least 5" in err.lower()

    def test_invalid_duration_too_long_541(self):
        err = self._server._validate_duration(541)
        assert err is not None
        assert "540" in err

    def test_invalid_duration_too_long_600(self):
        err = self._server._validate_duration(600)
        assert err is not None
        assert "540" in err

    def test_invalid_duration_too_long_9999(self):
        err = self._server._validate_duration(9999)
        assert err is not None
        assert "540" in err


# ===========================================================================
# ERROR CLASSIFICATION TESTS
# ===========================================================================

class TestErrorClassification:
    """Test the _classify_responder_error helper."""

    @pytest.fixture(autouse=True, scope="class")
    def server(self):
        """Create a server instance."""
        try:
            cls = _get_server_class()
            self.__class__._server = cls()
        except Exception as e:
            pytest.skip(f"Cannot import ResponderServer: {e}")

    def test_classify_port_bind_error(self):
        """Port binding failure should be 'config', retryable."""
        text = load_fixture("smb_port_bind_error.txt")
        err_class, retryable, suggestions = self._server._classify_responder_error(text)
        assert err_class == "config", f"Expected 'config', got '{err_class}'"
        assert retryable is True
        assert len(suggestions) > 0
        assert any("445" in s for s in suggestions), (
            f"Should mention port 445, got: {suggestions}"
        )

    def test_classify_multiple_port_bind_errors(self):
        """Multiple port binding failures still classified as 'config'."""
        text = load_fixture("multiple_port_bind_errors.txt")
        err_class, retryable, suggestions = self._server._classify_responder_error(text)
        assert err_class == "config"
        assert retryable is True
        # Should mention multiple ports
        suggestion_text = " ".join(suggestions)
        assert "445" in suggestion_text

    def test_classify_permission_denied(self):
        """Permission denied should be 'permission', not retryable."""
        text = load_fixture("permission_denied.txt")
        err_class, retryable, suggestions = self._server._classify_responder_error(text)
        assert err_class == "permission", f"Expected 'permission', got '{err_class}'"
        assert retryable is False
        assert len(suggestions) > 0

    def test_classify_timeout(self):
        """Timeout error should be 'timeout', retryable."""
        err_class, retryable, suggestions = self._server._classify_responder_error(
            "", "Operation timed out"
        )
        assert err_class == "timeout"
        assert retryable is True

    def test_classify_clean_output(self):
        """Clean output (no error) should be 'unknown', not retryable."""
        text = load_fixture("poison_ntlmv2_capture.txt")
        err_class, retryable, suggestions = self._server._classify_responder_error(text)
        assert err_class == "unknown"
        assert retryable is False
        assert suggestions == []

    def test_classify_interface_not_found(self):
        """Interface not found classified as 'config'."""
        err_class, retryable, suggestions = self._server._classify_responder_error(
            "", "Interface 'eth99' not found"
        )
        assert err_class == "config"
        assert retryable is False


# ===========================================================================
# PORT BIND ERROR DETECTION TESTS
# ===========================================================================

class TestPortBindDetection:
    """Test _detect_port_bind_errors."""

    @pytest.fixture(autouse=True, scope="class")
    def server(self):
        """Create a server instance."""
        try:
            cls = _get_server_class()
            self.__class__._server = cls()
        except Exception as e:
            pytest.skip(f"Cannot import ResponderServer: {e}")

    def test_detect_single_port_failure(self):
        text = load_fixture("smb_port_bind_error.txt")
        ports = self._server._detect_port_bind_errors(text)
        assert ports == [445]

    def test_detect_multiple_port_failures(self):
        text = load_fixture("multiple_port_bind_errors.txt")
        ports = self._server._detect_port_bind_errors(text)
        assert 445 in ports
        assert 80 in ports
        assert 443 in ports
        assert 389 in ports
        assert len(ports) == 4

    def test_detect_no_failures(self):
        text = load_fixture("poison_ntlmv2_capture.txt")
        ports = self._server._detect_port_bind_errors(text)
        assert ports == []

    def test_detect_no_failures_empty(self):
        ports = self._server._detect_port_bind_errors("")
        assert ports == []

    def test_smb_port_445_in_failures(self):
        """Verify SMB port 445 is specifically detectable for capture_smb logic."""
        text = "[!] Error starting TCP server on port 445, check permissions or other servers running."
        ports = self._server._detect_port_bind_errors(text)
        assert 445 in ports


# ===========================================================================
# ANSI STRIPPING TESTS
# ===========================================================================

class TestANSIStripping:
    """Test ANSI color code removal."""

    def test_strip_ansi_from_fixture(self):
        """ANSI codes in fixture output should be stripped by ANSI_RE."""
        mod = _get_module()
        text = "\x1b[32m[+] Listening for events...\x1b[0m"
        result = mod.ANSI_RE.sub("", text)
        assert "\x1b" not in result
        assert "[+] Listening for events..." in result

    def test_strip_mixed_ansi(self):
        mod = _get_module()
        text = "\x1b[1;31m[!] Error\x1b[0m \x1b[33mwarning\x1b[0m"
        result = mod.ANSI_RE.sub("", text)
        assert "\x1b" not in result
        assert "[!] Error" in result
        assert "warning" in result

    def test_no_ansi_passthrough(self):
        mod = _get_module()
        text = "[+] No color codes here"
        result = mod.ANSI_RE.sub("", text)
        assert result == text


# ===========================================================================
# COPY TO SESSION TESTS
# ===========================================================================

class TestCopyToSession:
    """Test file copying to /session/responder/."""

    def test_copy_hash_files(self, tmp_path):
        """Hash and log files are copied to session dir."""
        logs_dir = tmp_path / "logs"
        logs_dir.mkdir()
        session_dir = tmp_path / "session"
        session_dir.mkdir()

        # Create mock files
        (logs_dir / "SMB-NTLMv2-SSP-10.0.0.1.txt").write_text("hash1")
        (logs_dir / "Responder-Session.log").write_text("log data")
        (logs_dir / "Analyzer-Session.log").write_text("analyzer data")

        mod = _get_module()
        orig_logs = mod.RESPONDER_LOGS
        orig_session = mod.SESSION_DIR
        orig_db = mod.RESPONDER_DB
        mod.RESPONDER_LOGS = str(logs_dir)
        mod.SESSION_DIR = str(session_dir)
        mod.RESPONDER_DB = str(tmp_path / "nonexistent.db")
        try:
            server = mod.ResponderServer()
            copied = server._copy_to_session()
        finally:
            mod.RESPONDER_LOGS = orig_logs
            mod.SESSION_DIR = orig_session
            mod.RESPONDER_DB = orig_db

        assert len(copied) >= 2
        # Check files exist in destination
        dest_dir = session_dir / "responder"
        assert (dest_dir / "SMB-NTLMv2-SSP-10.0.0.1.txt").exists()
        assert (dest_dir / "Responder-Session.log").exists()

    def test_copy_db_file(self, tmp_path):
        """SQLite DB is copied to session dir."""
        logs_dir = tmp_path / "logs"
        logs_dir.mkdir()
        session_dir = tmp_path / "session"
        session_dir.mkdir()

        db_path = tmp_path / "Responder.db"
        db_path.write_text("fake db")

        mod = _get_module()
        orig_logs = mod.RESPONDER_LOGS
        orig_session = mod.SESSION_DIR
        orig_db = mod.RESPONDER_DB
        mod.RESPONDER_LOGS = str(logs_dir)
        mod.SESSION_DIR = str(session_dir)
        mod.RESPONDER_DB = str(db_path)
        try:
            server = mod.ResponderServer()
            copied = server._copy_to_session()
        finally:
            mod.RESPONDER_LOGS = orig_logs
            mod.SESSION_DIR = orig_session
            mod.RESPONDER_DB = orig_db

        dest_dir = session_dir / "responder"
        assert (dest_dir / "Responder.db").exists()

    def test_copy_empty_logs_dir(self, tmp_path):
        """Empty logs directory returns empty list."""
        logs_dir = tmp_path / "logs"
        logs_dir.mkdir()
        session_dir = tmp_path / "session"
        session_dir.mkdir()

        mod = _get_module()
        orig_logs = mod.RESPONDER_LOGS
        orig_session = mod.SESSION_DIR
        orig_db = mod.RESPONDER_DB
        mod.RESPONDER_LOGS = str(logs_dir)
        mod.SESSION_DIR = str(session_dir)
        mod.RESPONDER_DB = str(tmp_path / "nonexistent.db")
        try:
            server = mod.ResponderServer()
            copied = server._copy_to_session()
        finally:
            mod.RESPONDER_LOGS = orig_logs
            mod.SESSION_DIR = orig_session
            mod.RESPONDER_DB = orig_db

        assert copied == []


# ===========================================================================
# TOOL.YAML CONTRACT TESTS -- no container needed
# ===========================================================================

class TestToolYamlContract:
    """Verify tool.yaml matches server parameter definitions."""

    @pytest.fixture(autouse=True, scope="class")
    def load_data(self):
        """Load tool.yaml and server class."""
        with open(TOOL_DIR / "tool.yaml") as f:
            self.__class__._yaml = yaml.safe_load(f)
        try:
            self.__class__._server_cls = _get_server_class()
        except Exception as e:
            pytest.skip(f"Cannot import ResponderServer: {e}")

    def test_yaml_has_all_3_methods(self):
        """tool.yaml should define exactly 3 methods."""
        methods = self._yaml.get("methods", {})
        assert len(methods) == 3, (
            f"Expected 3 methods, got {len(methods)}: {sorted(methods.keys())}"
        )

    def test_yaml_method_names(self):
        """tool.yaml should define poison, analyze, capture_smb."""
        methods = set(self._yaml.get("methods", {}).keys())
        expected = {"poison", "analyze", "capture_smb"}
        assert methods == expected, f"Expected {expected}, got {methods}"

    def test_all_methods_have_descriptions(self):
        """Every method should have a description."""
        for name, defn in self._yaml.get("methods", {}).items():
            assert "description" in defn, f"Method {name} missing description"
            assert len(defn["description"]) > 20, (
                f"Method {name} has too short description"
            )

    def test_all_methods_have_duration_param(self):
        """All methods should have a required 'duration' parameter."""
        for name, defn in self._yaml.get("methods", {}).items():
            params = defn.get("params", {})
            assert "duration" in params, f"Method {name} missing 'duration' param"
            assert params["duration"].get("required", False), (
                f"Method {name}: 'duration' should be required"
            )

    def test_all_methods_have_interface_param(self):
        """All methods should have an 'interface' parameter."""
        for name, defn in self._yaml.get("methods", {}).items():
            params = defn.get("params", {})
            assert "interface" in params, f"Method {name} missing 'interface' param"

    def test_all_methods_have_verbose_param(self):
        """All methods should have a 'verbose' parameter."""
        for name, defn in self._yaml.get("methods", {}).items():
            params = defn.get("params", {})
            assert "verbose" in params, f"Method {name} missing 'verbose' param"

    def test_poison_has_advanced_params(self):
        """Poison method should have WPAD, basic_auth, and other advanced params."""
        poison = self._yaml.get("methods", {}).get("poison", {})
        params = poison.get("params", {})
        expected_params = [
            "wpad", "force_wpad_auth", "basic_auth", "lm_downgrade",
            "disable_ess", "dhcp", "external_ip", "proxy_auth",
            "dhcpv6", "rdnss", "error_code", "ttl",
        ]
        for ep in expected_params:
            assert ep in params, f"Poison missing param '{ep}'"

    def test_capture_smb_has_returns_smb_only(self):
        """capture_smb should document smb_only in returns."""
        capture = self._yaml.get("methods", {}).get("capture_smb", {})
        returns = capture.get("returns", {})
        assert "smb_only" in returns, "capture_smb should document smb_only return field"

    def test_yaml_param_types_valid(self):
        """All param types should be valid JSON Schema types."""
        valid_types = {"string", "integer", "boolean", "number", "array", "object", "enum"}
        for method_name, defn in self._yaml.get("methods", {}).items():
            for param_name, param_def in defn.get("params", {}).items():
                ptype = param_def.get("type", "string")
                assert ptype in valid_types, (
                    f"{method_name}.{param_name}: invalid type '{ptype}'"
                )

    def test_yaml_has_capabilities(self):
        """tool.yaml should list capabilities."""
        caps = self._yaml.get("capabilities", [])
        assert len(caps) > 0, "Should have at least one capability"
        assert "hash_capture" in caps

    def test_yaml_requires_privileged(self):
        """tool.yaml should require privileged mode."""
        reqs = self._yaml.get("requirements", {})
        assert reqs.get("privileged", False) is True, (
            "Responder requires --privileged"
        )

    def test_yaml_requires_network(self):
        """tool.yaml should require network access."""
        reqs = self._yaml.get("requirements", {})
        assert reqs.get("network", False) is True, (
            "Responder requires network access"
        )

    def test_yaml_phases_include_exploitation(self):
        """tool.yaml should include exploitation phase."""
        phases = self._yaml.get("phases", [])
        assert "exploitation" in phases

    def test_yaml_see_also_references(self):
        """tool.yaml should reference related tools."""
        see_also = self._yaml.get("see_also", [])
        assert len(see_also) >= 3, "Should reference at least 3 related tools"
        tool_names = [sa["tool"] for sa in see_also]
        assert "impacket" in tool_names, "Should reference impacket"

    def test_yaml_routing_triggers(self):
        """tool.yaml should have routing triggers."""
        triggers = self._yaml.get("routing", {}).get("triggers", [])
        assert len(triggers) > 0, "Should have routing triggers"
        assert "responder" in triggers
        assert "LLMNR" in triggers

    def test_yaml_server_params_match_yaml_params(self):
        """Server method params should be a superset of tool.yaml params for each method."""
        server = self._server_cls()
        for method_name, defn in self._yaml.get("methods", {}).items():
            yaml_params = set(defn.get("params", {}).keys())
            server_method = server.methods.get(method_name)
            if server_method is None:
                continue
            server_params = set(server_method.params.keys())
            yaml_only = yaml_params - server_params
            assert not yaml_only, (
                f"Method {method_name}: params in YAML but not server: {yaml_only}"
            )


# ===========================================================================
# INTERFACE RESOLUTION TESTS (unit, mocked)
# ===========================================================================

class TestInterfaceResolution:
    """Test _resolve_interface, _detect_interface, _validate_interface."""

    @pytest.fixture(autouse=True, scope="class")
    def server(self):
        try:
            cls = _get_server_class()
            self.__class__._server = cls()
        except Exception as e:
            pytest.skip(f"Cannot import ResponderServer: {e}")

    def test_resolve_none_detects(self):
        """Passing None triggers auto-detection."""
        loop = asyncio.new_event_loop()
        try:
            # Mock _detect_interface to return 'eth0'
            self._server._detect_interface = AsyncMock(return_value="eth0")
            self._server._validate_interface = AsyncMock(return_value=True)
            result = loop.run_until_complete(self._server._resolve_interface(None))
            assert result == "eth0"
        finally:
            loop.close()

    def test_resolve_valid_interface(self):
        """Valid interface name is returned as-is."""
        loop = asyncio.new_event_loop()
        try:
            self._server._validate_interface = AsyncMock(return_value=True)
            result = loop.run_until_complete(self._server._resolve_interface("tun0"))
            assert result == "tun0"
        finally:
            loop.close()

    def test_resolve_invalid_interface_raises(self):
        """Invalid interface raises ValueError."""
        loop = asyncio.new_event_loop()
        try:
            self._server._validate_interface = AsyncMock(return_value=False)
            with pytest.raises(ValueError, match="not found"):
                loop.run_until_complete(
                    self._server._resolve_interface("bad_iface")
                )
        finally:
            loop.close()

    def test_resolve_empty_string_raises(self):
        """Empty string raises ValueError."""
        loop = asyncio.new_event_loop()
        try:
            with pytest.raises(ValueError, match="empty"):
                loop.run_until_complete(self._server._resolve_interface(""))
        finally:
            loop.close()

    def test_resolve_none_no_interface_found_raises(self):
        """Auto-detection failure raises ValueError."""
        loop = asyncio.new_event_loop()
        try:
            self._server._detect_interface = AsyncMock(return_value=None)
            with pytest.raises(ValueError, match="auto-detect"):
                loop.run_until_complete(self._server._resolve_interface(None))
        finally:
            loop.close()


# ===========================================================================
# ACCEPTANCE TESTS -- every method through the Docker container
# ===========================================================================

class TestAcceptance:
    """Call every method through the container without a live network target.

    These tests verify:
    - The method exists and is callable through the MCP protocol
    - Required param validation works end-to-end (missing required -> error)
    - The response has correct structuredContent shape
    - Error responses have error_class set (classified, not crash)
    - Duration validation is enforced at the protocol layer
    - All optional params are accepted without crashing

    Each test sends valid params but targets the loopback interface or
    triggers validation errors. Responder will fail (no broadcast traffic
    on loopback), but the MCP layer, param validation, error classification,
    and structured response shape should all function correctly.
    """

    def _assert_structured_response(self, resp, method_name):
        """Assert response has well-formed structuredContent."""
        result = resp.get("result", {})
        sc = result.get("structuredContent")
        assert sc is not None, f"{method_name}: missing structuredContent"
        assert "success" in sc, f"{method_name}: structuredContent missing 'success'"
        assert "error_class" in sc, f"{method_name}: structuredContent missing 'error_class'"
        assert "retryable" in sc, f"{method_name}: structuredContent missing 'retryable'"
        assert "suggestions" in sc, f"{method_name}: structuredContent missing 'suggestions'"
        # Should NOT be an unhandled crash
        content_text = ""
        for c in result.get("content", []):
            if c.get("type") == "text":
                content_text += c["text"]
        assert "unexpected keyword argument" not in content_text, (
            f"{method_name}: unhandled keyword argument error"
        )
        assert "Traceback" not in content_text, (
            f"{method_name}: unhandled Python traceback in response"
        )
        return sc

    def _get_content_text(self, resp):
        """Extract text content from MCP response."""
        result = resp.get("result", {})
        content_text = ""
        for c in result.get("content", []):
            if c.get("type") == "text":
                content_text += c["text"]
        return content_text

    # ── poison method ─────────────────────────────────────────

    def test_poison_with_valid_duration(self, responder_env):
        """poison with min duration (5s) completes without crash.

        On loopback there's no broadcast traffic, so we expect success=true
        with hash_count=0, or a classified error if the interface has issues.
        """
        client, loop = responder_env
        resp = loop.run_until_complete(client.call("poison", {
            "duration": 5,
            "interface": "lo",
            "verbose": False,
        }))
        sc = self._assert_structured_response(resp, "poison")
        # Whether success or failure, it should be classified
        if sc.get("success"):
            data = sc.get("data", {})
            assert data.get("method") == "poison"
            assert data.get("duration_seconds") == 5
            assert "captured_hashes" in data
            assert "hash_count" in data
            assert isinstance(data["hash_count"], int)
            assert "copied_files" in data

    def test_poison_structuredContent_shape(self, responder_env):
        """poison response structuredContent has all required fields."""
        client, loop = responder_env
        resp = loop.run_until_complete(client.call("poison", {
            "duration": 5,
            "interface": "lo",
        }))
        sc = self._assert_structured_response(resp, "poison")
        assert isinstance(sc.get("retryable"), bool)
        assert isinstance(sc.get("suggestions"), list)

    def test_poison_missing_duration(self, responder_env):
        """poison without required 'duration' returns error."""
        client, loop = responder_env
        resp = loop.run_until_complete(client.call("poison", {
            "interface": "lo",
        }))
        result = resp.get("result", {})
        is_error = result.get("isError", False)
        content_text = self._get_content_text(resp)
        assert is_error or "duration" in content_text.lower() or "required" in content_text.lower() or "missing" in content_text.lower(), (
            f"Expected error about missing 'duration', got: {content_text[:300]}"
        )

    def test_poison_duration_too_short(self, responder_env):
        """poison with duration < 5 returns params error."""
        client, loop = responder_env
        resp = loop.run_until_complete(client.call("poison", {
            "duration": 3,
            "interface": "lo",
        }))
        sc = self._assert_structured_response(resp, "poison")
        assert sc.get("success") is False
        assert sc.get("error_class") == "params"

    def test_poison_duration_too_long(self, responder_env):
        """poison with duration > 540 returns params error."""
        client, loop = responder_env
        resp = loop.run_until_complete(client.call("poison", {
            "duration": 600,
            "interface": "lo",
        }))
        sc = self._assert_structured_response(resp, "poison")
        assert sc.get("success") is False
        assert sc.get("error_class") == "params"

    def test_poison_empty_interface_rejected(self, responder_env):
        """poison with empty string interface returns config error."""
        client, loop = responder_env
        resp = loop.run_until_complete(client.call("poison", {
            "duration": 10,
            "interface": "",
        }))
        sc = self._assert_structured_response(resp, "poison")
        assert sc.get("success") is False
        assert sc.get("error_class") == "config"

    def test_poison_invalid_interface_rejected(self, responder_env):
        """poison with nonexistent interface returns config error."""
        client, loop = responder_env
        resp = loop.run_until_complete(client.call("poison", {
            "duration": 10,
            "interface": "nonexistent_iface42",
        }))
        sc = self._assert_structured_response(resp, "poison")
        assert sc.get("success") is False
        assert sc.get("error_class") == "config"

    def test_poison_with_wpad_flag(self, responder_env):
        """poison with wpad=true is accepted without crash."""
        client, loop = responder_env
        resp = loop.run_until_complete(client.call("poison", {
            "duration": 5,
            "interface": "lo",
            "wpad": True,
        }))
        self._assert_structured_response(resp, "poison (wpad)")

    def test_poison_with_basic_auth_flag(self, responder_env):
        """poison with basic_auth=true is accepted without crash."""
        client, loop = responder_env
        resp = loop.run_until_complete(client.call("poison", {
            "duration": 5,
            "interface": "lo",
            "basic_auth": True,
        }))
        self._assert_structured_response(resp, "poison (basic_auth)")

    def test_poison_with_lm_downgrade_flag(self, responder_env):
        """poison with lm_downgrade=true is accepted without crash."""
        client, loop = responder_env
        resp = loop.run_until_complete(client.call("poison", {
            "duration": 5,
            "interface": "lo",
            "lm_downgrade": True,
        }))
        self._assert_structured_response(resp, "poison (lm_downgrade)")

    def test_poison_with_disable_ess_flag(self, responder_env):
        """poison with disable_ess=true is accepted without crash."""
        client, loop = responder_env
        resp = loop.run_until_complete(client.call("poison", {
            "duration": 5,
            "interface": "lo",
            "disable_ess": True,
        }))
        self._assert_structured_response(resp, "poison (disable_ess)")

    def test_poison_with_external_ip(self, responder_env):
        """poison with external_ip is accepted without crash."""
        client, loop = responder_env
        resp = loop.run_until_complete(client.call("poison", {
            "duration": 5,
            "interface": "lo",
            "external_ip": "10.10.14.5",
        }))
        self._assert_structured_response(resp, "poison (external_ip)")

    def test_poison_with_external_ip6(self, responder_env):
        """poison with external_ip6 is accepted without crash."""
        client, loop = responder_env
        resp = loop.run_until_complete(client.call("poison", {
            "duration": 5,
            "interface": "lo",
            "external_ip6": "fe80::1",
        }))
        self._assert_structured_response(resp, "poison (external_ip6)")

    def test_poison_with_ttl(self, responder_env):
        """poison with custom ttl is accepted without crash."""
        client, loop = responder_env
        resp = loop.run_until_complete(client.call("poison", {
            "duration": 5,
            "interface": "lo",
            "ttl": 30,
        }))
        self._assert_structured_response(resp, "poison (ttl)")

    def test_poison_with_dhcp_flag(self, responder_env):
        """poison with dhcp=true is accepted without crash."""
        client, loop = responder_env
        resp = loop.run_until_complete(client.call("poison", {
            "duration": 5,
            "interface": "lo",
            "dhcp": True,
        }))
        self._assert_structured_response(resp, "poison (dhcp)")

    def test_poison_with_dhcpv6_flag(self, responder_env):
        """poison with dhcpv6=true is accepted without crash."""
        client, loop = responder_env
        resp = loop.run_until_complete(client.call("poison", {
            "duration": 5,
            "interface": "lo",
            "dhcpv6": True,
        }))
        self._assert_structured_response(resp, "poison (dhcpv6)")

    def test_poison_with_rdnss_flag(self, responder_env):
        """poison with rdnss=true is accepted without crash."""
        client, loop = responder_env
        resp = loop.run_until_complete(client.call("poison", {
            "duration": 5,
            "interface": "lo",
            "rdnss": True,
        }))
        self._assert_structured_response(resp, "poison (rdnss)")

    def test_poison_with_proxy_auth_flag(self, responder_env):
        """poison with proxy_auth=true is accepted without crash."""
        client, loop = responder_env
        resp = loop.run_until_complete(client.call("poison", {
            "duration": 5,
            "interface": "lo",
            "proxy_auth": True,
        }))
        self._assert_structured_response(resp, "poison (proxy_auth)")

    def test_poison_with_error_code_flag(self, responder_env):
        """poison with error_code=true is accepted without crash."""
        client, loop = responder_env
        resp = loop.run_until_complete(client.call("poison", {
            "duration": 5,
            "interface": "lo",
            "error_code": True,
        }))
        self._assert_structured_response(resp, "poison (error_code)")

    def test_poison_with_force_wpad_auth_flag(self, responder_env):
        """poison with force_wpad_auth=true is accepted without crash."""
        client, loop = responder_env
        resp = loop.run_until_complete(client.call("poison", {
            "duration": 5,
            "interface": "lo",
            "wpad": True,
            "force_wpad_auth": True,
        }))
        self._assert_structured_response(resp, "poison (force_wpad_auth)")

    def test_poison_with_all_flags_combined(self, responder_env):
        """poison with many optional flags combined is accepted without crash."""
        client, loop = responder_env
        resp = loop.run_until_complete(client.call("poison", {
            "duration": 5,
            "interface": "lo",
            "verbose": True,
            "wpad": True,
            "basic_auth": True,
            "lm_downgrade": True,
            "disable_ess": True,
            "external_ip": "10.10.14.5",
            "ttl": 60,
            "error_code": True,
        }))
        self._assert_structured_response(resp, "poison (all flags)")

    # ── analyze method ────────────────────────────────────────

    def test_analyze_with_valid_duration(self, responder_env):
        """analyze with min duration (5s) on loopback completes without crash."""
        client, loop = responder_env
        resp = loop.run_until_complete(client.call("analyze", {
            "duration": 5,
            "interface": "lo",
            "verbose": False,
        }))
        sc = self._assert_structured_response(resp, "analyze")
        if sc.get("success"):
            data = sc.get("data", {})
            assert data.get("method") == "analyze"
            assert data.get("duration_seconds") == 5
            assert "detected_protocols" in data
            assert "detection_count" in data
            assert isinstance(data["detection_count"], int)

    def test_analyze_structuredContent_shape(self, responder_env):
        """analyze response structuredContent has all required fields."""
        client, loop = responder_env
        resp = loop.run_until_complete(client.call("analyze", {
            "duration": 5,
            "interface": "lo",
        }))
        sc = self._assert_structured_response(resp, "analyze")
        assert isinstance(sc.get("retryable"), bool)
        assert isinstance(sc.get("suggestions"), list)

    def test_analyze_missing_duration(self, responder_env):
        """analyze without required 'duration' returns error."""
        client, loop = responder_env
        resp = loop.run_until_complete(client.call("analyze", {
            "interface": "lo",
        }))
        result = resp.get("result", {})
        is_error = result.get("isError", False)
        content_text = self._get_content_text(resp)
        assert is_error or "duration" in content_text.lower() or "required" in content_text.lower() or "missing" in content_text.lower()

    def test_analyze_duration_too_short(self, responder_env):
        """analyze with duration < 5 returns params error."""
        client, loop = responder_env
        resp = loop.run_until_complete(client.call("analyze", {
            "duration": 2,
            "interface": "lo",
        }))
        sc = self._assert_structured_response(resp, "analyze")
        assert sc.get("success") is False
        assert sc.get("error_class") == "params"

    def test_analyze_duration_too_long(self, responder_env):
        """analyze with duration > 540 returns params error."""
        client, loop = responder_env
        resp = loop.run_until_complete(client.call("analyze", {
            "duration": 999,
            "interface": "lo",
        }))
        sc = self._assert_structured_response(resp, "analyze")
        assert sc.get("success") is False
        assert sc.get("error_class") == "params"

    def test_analyze_empty_interface_rejected(self, responder_env):
        """analyze with empty string interface returns config error."""
        client, loop = responder_env
        resp = loop.run_until_complete(client.call("analyze", {
            "duration": 10,
            "interface": "",
        }))
        sc = self._assert_structured_response(resp, "analyze")
        assert sc.get("success") is False
        assert sc.get("error_class") == "config"

    def test_analyze_invalid_interface_rejected(self, responder_env):
        """analyze with nonexistent interface returns config error."""
        client, loop = responder_env
        resp = loop.run_until_complete(client.call("analyze", {
            "duration": 10,
            "interface": "fake_iface99",
        }))
        sc = self._assert_structured_response(resp, "analyze")
        assert sc.get("success") is False
        assert sc.get("error_class") == "config"

    # ── capture_smb method ────────────────────────────────────

    def test_capture_smb_with_valid_duration(self, responder_env):
        """capture_smb with min duration (5s) on loopback completes without crash.

        Verifies config backup/restore cycle and response shape.
        """
        client, loop = responder_env
        resp = loop.run_until_complete(client.call("capture_smb", {
            "duration": 5,
            "interface": "lo",
            "verbose": False,
        }))
        sc = self._assert_structured_response(resp, "capture_smb")
        # capture_smb may fail if port 445 cannot bind, which is expected
        # in CI. The key assertion is that structuredContent is well-formed.
        if sc.get("success"):
            data = sc.get("data", {})
            assert data.get("method") == "capture_smb"
            assert data.get("duration_seconds") == 5
            assert data.get("smb_only") is True
            assert "captured_hashes" in data
            assert "hash_count" in data
            assert isinstance(data["hash_count"], int)
            assert "copied_files" in data

    def test_capture_smb_structuredContent_shape(self, responder_env):
        """capture_smb response structuredContent has all required fields."""
        client, loop = responder_env
        resp = loop.run_until_complete(client.call("capture_smb", {
            "duration": 5,
            "interface": "lo",
        }))
        sc = self._assert_structured_response(resp, "capture_smb")
        assert isinstance(sc.get("retryable"), bool)
        assert isinstance(sc.get("suggestions"), list)

    def test_capture_smb_missing_duration(self, responder_env):
        """capture_smb without required 'duration' returns error."""
        client, loop = responder_env
        resp = loop.run_until_complete(client.call("capture_smb", {
            "interface": "lo",
        }))
        result = resp.get("result", {})
        is_error = result.get("isError", False)
        content_text = self._get_content_text(resp)
        assert is_error or "duration" in content_text.lower() or "required" in content_text.lower() or "missing" in content_text.lower()

    def test_capture_smb_duration_too_short(self, responder_env):
        """capture_smb with duration < 5 returns params error."""
        client, loop = responder_env
        resp = loop.run_until_complete(client.call("capture_smb", {
            "duration": 1,
            "interface": "lo",
        }))
        sc = self._assert_structured_response(resp, "capture_smb")
        assert sc.get("success") is False
        assert sc.get("error_class") == "params"

    def test_capture_smb_duration_too_long(self, responder_env):
        """capture_smb with duration > 540 returns params error."""
        client, loop = responder_env
        resp = loop.run_until_complete(client.call("capture_smb", {
            "duration": 541,
            "interface": "lo",
        }))
        sc = self._assert_structured_response(resp, "capture_smb")
        assert sc.get("success") is False
        assert sc.get("error_class") == "params"

    def test_capture_smb_empty_interface_rejected(self, responder_env):
        """capture_smb with empty string interface returns config error."""
        client, loop = responder_env
        resp = loop.run_until_complete(client.call("capture_smb", {
            "duration": 10,
            "interface": "",
        }))
        sc = self._assert_structured_response(resp, "capture_smb")
        assert sc.get("success") is False
        assert sc.get("error_class") == "config"

    def test_capture_smb_invalid_interface_rejected(self, responder_env):
        """capture_smb with nonexistent interface returns config error."""
        client, loop = responder_env
        resp = loop.run_until_complete(client.call("capture_smb", {
            "duration": 10,
            "interface": "no_such_iface",
        }))
        sc = self._assert_structured_response(resp, "capture_smb")
        assert sc.get("success") is False
        assert sc.get("error_class") == "config"

    # ── Cross-cutting acceptance tests ────────────────────────

    def test_meta_param_clock_offset_stripped(self, responder_env):
        """clock_offset meta-param is stripped and does not crash any method."""
        client, loop = responder_env
        for method in ["poison", "analyze", "capture_smb"]:
            resp = loop.run_until_complete(client.call(method, {
                "duration": 5,
                "interface": "lo",
                "clock_offset": "5h",
            }))
            content_text = self._get_content_text(resp)
            assert "unexpected keyword argument" not in content_text, (
                f"{method}: meta-param 'clock_offset' was not stripped"
            )

    def test_verbose_false_accepted(self, responder_env):
        """All methods accept verbose=false without crashing."""
        client, loop = responder_env
        for method in ["poison", "analyze", "capture_smb"]:
            resp = loop.run_until_complete(client.call(method, {
                "duration": 5,
                "interface": "lo",
                "verbose": False,
            }))
            self._assert_structured_response(resp, f"{method} (verbose=false)")

    def test_unknown_param_returns_error(self, responder_env):
        """Unknown params return a clear error (not a crash/traceback)."""
        client, loop = responder_env
        resp = loop.run_until_complete(client.call("poison", {
            "duration": 5,
            "interface": "lo",
            "totally_fake_param": "should_be_rejected",
        }))
        result = resp.get("result", {})
        # Server should report the bad param, either via isError or content
        content_text = self._get_content_text(resp)
        assert "totally_fake_param" in content_text, (
            f"Expected error mentioning unknown param, got: {content_text[:300]}"
        )

    def test_all_methods_return_valid_json(self, responder_env):
        """All methods return valid JSON in content text."""
        client, loop = responder_env
        for method in ["poison", "analyze", "capture_smb"]:
            resp = loop.run_until_complete(client.call(method, {
                "duration": 5,
                "interface": "lo",
            }))
            content_text = self._get_content_text(resp)
            if content_text:
                try:
                    parsed = json.loads(content_text)
                    assert isinstance(parsed, dict), (
                        f"{method}: JSON content should be a dict"
                    )
                except json.JSONDecodeError:
                    # Some error messages may not be JSON -- that's OK
                    pass


# ===========================================================================
# ADDITIONAL UNIT TESTS -- edge cases for parsers and helpers
# ===========================================================================

class TestHashParsingEdgeCases:
    """Additional edge-case tests for hash parsing not covered above."""

    def test_parse_hashes_from_db_fullhash_empty_falls_back_to_hash(self, tmp_path):
        """When fullhash is empty, parser falls back to hash column."""
        db_path = tmp_path / "Responder.db"
        conn = sqlite3.connect(str(db_path))
        conn.execute(
            "CREATE TABLE responder ("
            "timestamp TEXT, module TEXT, type TEXT, client TEXT, "
            "hostname TEXT, user TEXT, cleartext TEXT, hash TEXT, fullhash TEXT)"
        )
        conn.execute(
            "INSERT INTO responder VALUES (?, ?, ?, ?, ?, ?, ?, ?, ?)",
            (
                "2026-04-08 12:00:00",
                "HTTP",
                "NTLMv2",
                "10.0.0.1",
                "WEB01",
                "DOMAIN\\webuser",
                "",
                "webuser::DOMAIN:short:challenge:blob",
                "",  # fullhash empty
            ),
        )
        conn.commit()
        conn.close()

        mod = _get_module()
        orig_db = mod.RESPONDER_DB
        mod.RESPONDER_DB = str(db_path)
        try:
            server = mod.ResponderServer()
            hashes = server._parse_hashes_from_db()
        finally:
            mod.RESPONDER_DB = orig_db

        assert len(hashes) == 1
        assert hashes[0]["hash"] == "webuser::DOMAIN:short:challenge:blob"
        assert "cleartext" not in hashes[0]

    def test_parse_hashes_from_db_multiple_entries(self, tmp_path):
        """Parse multiple hash entries from the DB."""
        db_path = tmp_path / "Responder.db"
        conn = sqlite3.connect(str(db_path))
        conn.execute(
            "CREATE TABLE responder ("
            "timestamp TEXT, module TEXT, type TEXT, client TEXT, "
            "hostname TEXT, user TEXT, cleartext TEXT, hash TEXT, fullhash TEXT)"
        )
        for i in range(5):
            conn.execute(
                "INSERT INTO responder VALUES (?, ?, ?, ?, ?, ?, ?, ?, ?)",
                (
                    f"2026-04-08 12:0{i}:00",
                    "SMB",
                    "NTLMv2-SSP",
                    f"10.0.0.{i + 1}",
                    f"HOST{i:02d}",
                    f"CORP\\user{i}",
                    "",
                    f"short{i}",
                    f"user{i}::CORP:challenge{i}:proof{i}:blob{i}",
                ),
            )
        conn.commit()
        conn.close()

        mod = _get_module()
        orig_db = mod.RESPONDER_DB
        mod.RESPONDER_DB = str(db_path)
        try:
            server = mod.ResponderServer()
            hashes = server._parse_hashes_from_db()
        finally:
            mod.RESPONDER_DB = orig_db

        assert len(hashes) == 5
        usernames = [h["username"] for h in hashes]
        assert "CORP\\user0" in usernames
        assert "CORP\\user4" in usernames

    def test_parse_hashes_from_files_ntlmv1(self, tmp_path):
        """Parse NTLMv1 hashes from log files (not just NTLMv2)."""
        logs_dir = tmp_path / "logs"
        logs_dir.mkdir()
        hash_file = logs_dir / "SMB-NTLMv1-SSP-10.0.0.1.txt"
        hash_file.write_text(
            "admin::CORP:lm_response:nt_response:challenge\n"
        )

        mod = _get_module()
        orig_logs = mod.RESPONDER_LOGS
        mod.RESPONDER_LOGS = str(logs_dir)
        try:
            server = mod.ResponderServer()
            hashes = server._parse_hashes_from_files()
        finally:
            mod.RESPONDER_LOGS = orig_logs

        assert len(hashes) == 1
        assert hashes[0]["module"] == "SMB"
        assert "NTLMv1" in hashes[0]["hash_type"]
        assert hashes[0]["username"] == "admin"

    def test_parse_hashes_from_files_multiple_protocols(self, tmp_path):
        """Parse hashes from multiple protocol files in one directory."""
        logs_dir = tmp_path / "logs"
        logs_dir.mkdir()
        (logs_dir / "SMB-NTLMv2-SSP-10.0.0.1.txt").write_text(
            "smb_user::CORP:c1:p1:b1\n"
        )
        (logs_dir / "HTTP-NTLMv2-10.0.0.2.txt").write_text(
            "http_user::CORP:c2:p2:b2\n"
        )
        (logs_dir / "LDAP-NTLMv2-10.0.0.3.txt").write_text(
            "ldap_user::CORP:c3:p3:b3\n"
        )
        (logs_dir / "MSSQL-ClearText-10.0.0.4.txt").write_text(
            "sa:P@ssw0rd\n"
        )

        mod = _get_module()
        orig_logs = mod.RESPONDER_LOGS
        mod.RESPONDER_LOGS = str(logs_dir)
        try:
            server = mod.ResponderServer()
            hashes = server._parse_hashes_from_files()
        finally:
            mod.RESPONDER_LOGS = orig_logs

        assert len(hashes) == 4
        modules = {h["module"] for h in hashes}
        assert "SMB" in modules
        assert "HTTP" in modules
        assert "LDAP" in modules
        assert "MSSQL" in modules
        # One should be cleartext
        cleartext_entries = [h for h in hashes if h.get("hash_type") == "ClearText"]
        assert len(cleartext_entries) == 1
        assert cleartext_entries[0]["cleartext"] == "P@ssw0rd"

    def test_parse_hashes_unreadable_file(self, tmp_path):
        """File permission error is handled gracefully."""
        logs_dir = tmp_path / "logs"
        logs_dir.mkdir()
        hash_file = logs_dir / "SMB-NTLMv2-SSP-10.0.0.1.txt"
        hash_file.write_text("user::DOMAIN:c:p:b\n")
        hash_file.chmod(0o000)

        mod = _get_module()
        orig_logs = mod.RESPONDER_LOGS
        mod.RESPONDER_LOGS = str(logs_dir)
        try:
            server = mod.ResponderServer()
            hashes = server._parse_hashes_from_files()
        finally:
            mod.RESPONDER_LOGS = orig_logs
            hash_file.chmod(0o644)  # restore for cleanup

        # Should return empty (OSError caught) rather than crash
        assert hashes == []


class TestCopyToSessionEdgeCases:
    """Additional edge-case tests for file copy logic."""

    def test_copy_creates_responder_subdirectory(self, tmp_path):
        """_copy_to_session creates the /session/responder/ directory if missing."""
        logs_dir = tmp_path / "logs"
        logs_dir.mkdir()
        session_dir = tmp_path / "session"
        session_dir.mkdir()
        (logs_dir / "SMB-NTLMv2-SSP-10.0.0.1.txt").write_text("hash_data")

        mod = _get_module()
        orig_logs = mod.RESPONDER_LOGS
        orig_session = mod.SESSION_DIR
        orig_db = mod.RESPONDER_DB
        mod.RESPONDER_LOGS = str(logs_dir)
        mod.SESSION_DIR = str(session_dir)
        mod.RESPONDER_DB = str(tmp_path / "nonexistent.db")
        try:
            server = mod.ResponderServer()
            copied = server._copy_to_session()
        finally:
            mod.RESPONDER_LOGS = orig_logs
            mod.SESSION_DIR = orig_session
            mod.RESPONDER_DB = orig_db

        assert len(copied) == 1
        assert (session_dir / "responder").is_dir()

    def test_copy_multiple_hash_files(self, tmp_path):
        """Multiple hash files from different IPs are all copied."""
        logs_dir = tmp_path / "logs"
        logs_dir.mkdir()
        session_dir = tmp_path / "session"
        session_dir.mkdir()

        for i in range(3):
            (logs_dir / f"SMB-NTLMv2-SSP-10.0.0.{i + 1}.txt").write_text(f"hash{i}")

        mod = _get_module()
        orig_logs = mod.RESPONDER_LOGS
        orig_session = mod.SESSION_DIR
        orig_db = mod.RESPONDER_DB
        mod.RESPONDER_LOGS = str(logs_dir)
        mod.SESSION_DIR = str(session_dir)
        mod.RESPONDER_DB = str(tmp_path / "nonexistent.db")
        try:
            server = mod.ResponderServer()
            copied = server._copy_to_session()
        finally:
            mod.RESPONDER_LOGS = orig_logs
            mod.SESSION_DIR = orig_session
            mod.RESPONDER_DB = orig_db

        assert len(copied) == 3
        dest_dir = session_dir / "responder"
        for i in range(3):
            assert (dest_dir / f"SMB-NTLMv2-SSP-10.0.0.{i + 1}.txt").exists()


class TestConfigManagementEdgeCases:
    """Additional edge-case tests for Responder.conf manipulation."""

    def test_write_smb_only_config_missing_section(self, tmp_path):
        """SMB-only config handles missing 'Responder Core' section gracefully."""
        config_path = tmp_path / "Responder.conf"
        config = configparser.ConfigParser()
        config["Other Section"] = {"key": "value"}
        with open(config_path, "w") as f:
            config.write(f)

        mod = _get_module()
        orig_conf = mod.RESPONDER_CONF
        mod.RESPONDER_CONF = str(config_path)
        try:
            server = mod.ResponderServer()
            # Should not crash when section is missing
            server._write_smb_only_config()
        finally:
            mod.RESPONDER_CONF = orig_conf

        # Verify the file is unchanged (no crash, no modification)
        config_after = configparser.ConfigParser()
        config_after.read(str(config_path))
        assert config_after.has_section("Other Section")

    def test_backup_config_nonexistent_file(self, tmp_path):
        """Backup of nonexistent config returns None."""
        mod = _get_module()
        orig_conf = mod.RESPONDER_CONF
        mod.RESPONDER_CONF = str(tmp_path / "nonexistent" / "Responder.conf")
        try:
            server = mod.ResponderServer()
            result = server._backup_config()
        finally:
            mod.RESPONDER_CONF = orig_conf

        assert result is None

    def test_restore_config_nonexistent_backup(self, tmp_path):
        """Restore when no .bak file exists returns False."""
        config_path = tmp_path / "Responder.conf"
        config_path.write_text("[Responder Core]\nSMB = On\n")

        mod = _get_module()
        orig_conf = mod.RESPONDER_CONF
        mod.RESPONDER_CONF = str(config_path)
        try:
            server = mod.ResponderServer()
            result = server._restore_config()
        finally:
            mod.RESPONDER_CONF = orig_conf

        assert result is False


class TestErrorClassificationEdgeCases:
    """Additional error classification edge cases."""

    @pytest.fixture(autouse=True, scope="class")
    def server(self):
        try:
            cls = _get_server_class()
            self.__class__._server = cls()
        except Exception as e:
            pytest.skip(f"Cannot import ResponderServer: {e}")

    def test_classify_permission_error_in_error_msg(self):
        """PermissionError in error_msg (not raw_output) is classified."""
        err_class, retryable, suggestions = self._server._classify_responder_error(
            "", "PermissionError: binding to port 445"
        )
        assert err_class == "permission"
        assert retryable is False

    def test_classify_timeout_error_in_raw_output(self):
        """TimeoutError in raw_output is classified."""
        err_class, retryable, suggestions = self._server._classify_responder_error(
            "TimeoutError: operation timed out after 300s", ""
        )
        assert err_class == "timeout"
        assert retryable is True

    def test_classify_combined_port_and_permission(self):
        """When both port bind and permission errors are present, port bind wins (checked first)."""
        combined = (
            "[!] Error starting TCP server on port 445, check permissions\n"
            "PermissionError: raw socket denied"
        )
        err_class, retryable, suggestions = self._server._classify_responder_error(combined)
        assert err_class == "config"  # port bind error matched first

    def test_classify_empty_input(self):
        """Empty raw_output and error_msg returns 'unknown'."""
        err_class, retryable, suggestions = self._server._classify_responder_error("", "")
        assert err_class == "unknown"
        assert retryable is False
        assert suggestions == []

    def test_detect_port_bind_errors_udp(self):
        """UDP port bind errors are also detected."""
        text = "[!] Error starting UDP server on port 5355, check permissions or other servers running."
        ports = self._server._detect_port_bind_errors(text)
        assert 5355 in ports

    def test_detect_port_bind_errors_mixed_tcp_udp(self):
        """Both TCP and UDP port bind errors are detected together."""
        text = (
            "[!] Error starting TCP server on port 445, check permissions or other servers running.\n"
            "[!] Error starting UDP server on port 137, check permissions or other servers running.\n"
            "[!] Error starting UDP server on port 5355, check permissions or other servers running."
        )
        ports = self._server._detect_port_bind_errors(text)
        assert sorted(ports) == [137, 445, 5355]


class TestDurationValidationEdgeCases:
    """Additional duration edge cases."""

    @pytest.fixture(autouse=True, scope="class")
    def server(self):
        try:
            cls = _get_server_class()
            self.__class__._server = cls()
        except Exception as e:
            pytest.skip(f"Cannot import ResponderServer: {e}")

    def test_boundary_duration_5_valid(self):
        """Duration exactly 5 is valid (boundary)."""
        assert self._server._validate_duration(5) is None

    def test_boundary_duration_540_valid(self):
        """Duration exactly 540 is valid (boundary)."""
        assert self._server._validate_duration(540) is None

    def test_boundary_duration_4_invalid(self):
        """Duration 4 is invalid (just below boundary)."""
        err = self._server._validate_duration(4)
        assert err is not None

    def test_boundary_duration_541_invalid(self):
        """Duration 541 is invalid (just above boundary)."""
        err = self._server._validate_duration(541)
        assert err is not None

    def test_very_large_duration(self):
        """Very large duration returns error."""
        err = self._server._validate_duration(999999)
        assert err is not None
        assert "540" in err


# ===========================================================================
# INTEGRATION TESTS -- require --target or live container run
# ===========================================================================

@pytest.mark.integration
class TestIntegration:
    """Integration tests that need a real network target.

    Run with: pytest tests/tools/test_responder.py --tool=responder -m integration -v
    """

    def test_analyze_on_loopback(self, responder_env):
        """Run analyze mode on the loopback interface for 5 seconds.

        This won't find any real broadcasts but verifies end-to-end flow.
        """
        client, loop = responder_env
        resp = loop.run_until_complete(client.call("analyze", {
            "interface": "lo",
            "duration": 5,
        }))
        # May fail because lo is loopback — that's OK, we just verify the flow
        result = resp.get("result", {})
        content_text = ""
        for c in result.get("content", []):
            if c.get("type") == "text":
                content_text += c["text"]
        # Either succeeds with empty detections or fails due to interface
        assert "analyze" in content_text.lower() or "error" in content_text.lower(), (
            f"Expected analyze result or error, got: {content_text[:500]}"
        )
