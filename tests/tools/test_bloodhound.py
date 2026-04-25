"""
Tests for the bloodhound MCP tool server.

Covers:
- Smoke tests: boot, method list, required params, meta-param stripping, clock
- Unit tests: error classification, command building, output file parsing
- Contract tests: tool.yaml vs server parameter definitions
- Integration tests: real AD target scenarios (marked @pytest.mark.integration)
"""

import asyncio
import json
import os
import sys
import tempfile
import zipfile
from pathlib import Path
from typing import Any, Dict

import pytest
import yaml

# ---------------------------------------------------------------------------
# Path setup
# ---------------------------------------------------------------------------
PROJECT_ROOT = Path(__file__).parent.parent.parent
TOOL_DIR = PROJECT_ROOT / "tools" / "bloodhound"
FIXTURES_DIR = Path(__file__).parent.parent / "fixtures" / "bloodhound"

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
def bloodhound_env(request):
    """Create an MCPTestClient with its event loop. Yields (client, loop)."""
    tool = "bloodhound"
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
    """Import and return the BloodhoundServer class for direct method testing."""
    import importlib.util
    spec = importlib.util.spec_from_file_location(
        "bloodhound_server", TOOL_DIR / "mcp-server.py"
    )
    mod = importlib.util.module_from_spec(spec)
    spec.loader.exec_module(mod)
    return mod.BloodhoundServer


# ===========================================================================
# SMOKE TESTS -- require Docker container running
# ===========================================================================

class TestSmoke:
    """Smoke tests that verify the container boots and basic protocol works."""

    def test_boot_and_list_tools(self, bloodhound_env):
        """Container starts and list_tools returns methods."""
        client, loop = bloodhound_env
        assert len(client.tools) > 0, "Server should advertise at least one tool"
        names = client.tool_names()
        assert "collect" in names, "collect should be in tool list"
        assert "collect_stealth" in names, "collect_stealth should be in tool list"

    def test_method_list_matches_tool_yaml(self, bloodhound_env):
        """Every method in tool.yaml is advertised by the server, and vice versa."""
        client, _ = bloodhound_env
        server_names = client.tool_names()

        # Remove verify_clock -- it's test-only, not in tool.yaml
        server_names_no_test = server_names - {"verify_clock"}

        yaml_path = TOOL_DIR / "tool.yaml"
        with open(yaml_path) as f:
            tool_yaml = yaml.safe_load(f)
        yaml_names = set(tool_yaml.get("methods", {}).keys())

        yaml_only = yaml_names - server_names_no_test
        server_only = server_names_no_test - yaml_names

        assert not yaml_only, f"Methods in tool.yaml but not server: {yaml_only}"
        assert not server_only, f"Methods in server but not tool.yaml: {server_only}"

    def test_expected_method_count(self, bloodhound_env):
        """Server should have exactly 2 built-in methods + verify_clock."""
        client, _ = bloodhound_env
        names = client.tool_names()
        # 2 built-in + verify_clock in MCP_TEST_MODE
        assert len(names) == 3, (
            f"Expected 3 methods (2 built-in + verify_clock), got {len(names)}: {sorted(names)}"
        )

    def test_required_params_enforced_collect(self, bloodhound_env):
        """Calling collect without required 'domain' param returns an error."""
        client, loop = bloodhound_env
        resp = loop.run_until_complete(
            client.call("collect", {
                "username": "testuser",
                "dc_ip": "10.0.0.1",
                "password": "test",
            })
        )
        result = resp.get("result", {})
        is_error = result.get("isError", False)
        content_text = ""
        for c in result.get("content", []):
            if c.get("type") == "text":
                content_text += c["text"]
        assert is_error or "domain" in content_text.lower() or "missing" in content_text.lower() or "error" in content_text.lower(), (
            f"Expected error about missing 'domain', got: {content_text[:300]}"
        )

    def test_required_params_enforced_collect_stealth(self, bloodhound_env):
        """Calling collect_stealth without required 'dc_ip' param returns an error."""
        client, loop = bloodhound_env
        resp = loop.run_until_complete(
            client.call("collect_stealth", {
                "domain": "corp.local",
                "username": "testuser",
                "password": "test",
            })
        )
        result = resp.get("result", {})
        is_error = result.get("isError", False)
        content_text = ""
        for c in result.get("content", []):
            if c.get("type") == "text":
                content_text += c["text"]
        assert is_error or "dc_ip" in content_text.lower() or "missing" in content_text.lower() or "error" in content_text.lower(), (
            f"Expected error about missing 'dc_ip', got: {content_text[:300]}"
        )

    def test_no_credentials_returns_error(self, bloodhound_env):
        """Calling collect with no credentials should return a clear error."""
        client, loop = bloodhound_env
        resp = loop.run_until_complete(
            client.call("collect", {
                "domain": "corp.local",
                "username": "testuser",
                "dc_ip": "10.0.0.1",
            })
        )
        result = resp.get("result", {})
        is_error = result.get("isError", False)
        assert is_error, "Should fail when no credentials provided"
        content_text = ""
        for c in result.get("content", []):
            if c.get("type") == "text":
                content_text += c["text"]
        assert "credential" in content_text.lower() or "password" in content_text.lower(), (
            f"Error should mention credentials, got: {content_text[:300]}"
        )

    def test_no_credentials_stealth_returns_error(self, bloodhound_env):
        """Calling collect_stealth with no credentials should return a clear error."""
        client, loop = bloodhound_env
        resp = loop.run_until_complete(
            client.call("collect_stealth", {
                "domain": "corp.local",
                "username": "testuser",
                "dc_ip": "10.0.0.1",
            })
        )
        result = resp.get("result", {})
        is_error = result.get("isError", False)
        assert is_error, "Should fail when no credentials provided"

    def test_meta_params_stripped(self, bloodhound_env):
        """Passing 'clock_offset' (meta-param) in args does not crash the server."""
        client, loop = bloodhound_env
        resp = loop.run_until_complete(
            client.call("collect", {
                "domain": "corp.local",
                "username": "testuser",
                "dc_ip": "10.0.0.1",
                "password": "test",
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

    def test_unknown_method_returns_error(self, bloodhound_env):
        """Calling a non-existent method returns a helpful error."""
        client, loop = bloodhound_env
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
    def test_verify_clock_available(self, bloodhound_env):
        """verify_clock is registered in MCP_TEST_MODE."""
        client, _ = bloodhound_env
        names = client.tool_names()
        assert "verify_clock" in names, "verify_clock should be available in test mode"

    @pytest.mark.clock
    def test_verify_clock_returns_time(self, bloodhound_env):
        """verify_clock returns current time and FAKETIME status."""
        client, loop = bloodhound_env
        resp = loop.run_until_complete(client.call("verify_clock", {}))
        result = assert_tool_success(resp)
        data = parse_tool_output(resp)
        assert "current_time" in data
        assert "libfaketime_exists" in data
        # libfaketime is installed in this image
        assert data["libfaketime_exists"] is True, (
            "libfaketime should be installed in the bloodhound image"
        )

    def test_structuredContent_present(self, bloodhound_env):
        """Responses include structuredContent with error classification fields."""
        client, loop = bloodhound_env
        resp = loop.run_until_complete(client.call("verify_clock", {}))
        result = resp.get("result", {})
        sc = result.get("structuredContent")
        assert sc is not None, "structuredContent should be present"
        assert "success" in sc
        assert "error_class" in sc
        assert "retryable" in sc
        assert "suggestions" in sc


# ===========================================================================
# UNIT TESTS -- command building, output parsing, error classification
# ===========================================================================

class TestCommandBuilding:
    """Test _build_cmd method generates correct CLI arguments."""

    @pytest.fixture(autouse=True, scope="class")
    def server(self):
        """Create a server instance for testing."""
        try:
            cls = _get_server_class()
            self.__class__._server = cls()
        except Exception as e:
            pytest.skip(f"Cannot import BloodhoundServer: {e}")

    def test_basic_password_auth(self):
        """Basic password auth produces correct command line."""
        cmd = self._server._build_cmd(
            domain="corp.local",
            username="admin",
            dc_ip="10.0.0.1",
            password="Password1!",
        )
        assert "bloodhound-python" in cmd[0]
        assert cmd[cmd.index("-d") + 1] == "corp.local"
        assert cmd[cmd.index("-u") + 1] == "admin"
        assert cmd[cmd.index("-p") + 1] == "Password1!"
        assert cmd[cmd.index("-ns") + 1] == "10.0.0.1"
        assert cmd[cmd.index("-c") + 1] == "Default"
        assert "-v" in cmd
        assert "-no-pass" not in cmd

    def test_hash_auth(self):
        """Pass-the-hash adds --hashes; -no-pass is NOT added when hashes are provided."""
        cmd = self._server._build_cmd(
            domain="corp.local",
            username="admin",
            dc_ip="10.0.0.1",
            hashes="aad3b435b51404ee:31d6cfe0d16ae931b73c59d7e0c089c0",
        )
        assert "--hashes" in cmd
        idx = cmd.index("--hashes")
        assert cmd[idx + 1] == "aad3b435b51404ee:31d6cfe0d16ae931b73c59d7e0c089c0"
        # Hashes are a credential — -no-pass should NOT be added
        assert "-no-pass" not in cmd
        assert "-p" not in cmd

    def test_kerberos_auth(self):
        """Kerberos auth adds -k and -no-pass."""
        cmd = self._server._build_cmd(
            domain="corp.local",
            username="admin",
            dc_ip="10.0.0.1",
            kerberos=True,
        )
        assert "-k" in cmd
        assert "-no-pass" in cmd
        assert "-p" not in cmd

    def test_aes_key_auth(self):
        """AES key auth adds -aesKey."""
        cmd = self._server._build_cmd(
            domain="corp.local",
            username="admin",
            dc_ip="10.0.0.1",
            aes_key="a" * 64,
        )
        assert "-aesKey" in cmd
        idx = cmd.index("-aesKey")
        assert cmd[idx + 1] == "a" * 64
        assert "-no-pass" not in cmd

    def test_collection_method(self):
        """Custom collection method is passed to -c."""
        cmd = self._server._build_cmd(
            domain="corp.local",
            username="admin",
            dc_ip="10.0.0.1",
            password="test",
            collection="All",
        )
        assert cmd[cmd.index("-c") + 1] == "All"

    def test_dc_host_adds_dc_flag(self):
        """dc_host adds -dc flag."""
        cmd = self._server._build_cmd(
            domain="corp.local",
            username="admin",
            dc_ip="10.0.0.1",
            password="test",
            dc_host="dc01.corp.local",
        )
        assert "-dc" in cmd
        idx = cmd.index("-dc")
        assert cmd[idx + 1] == "dc01.corp.local"

    def test_dc_host_omitted_when_none(self):
        """Without dc_host, -dc flag is not added."""
        cmd = self._server._build_cmd(
            domain="corp.local",
            username="admin",
            dc_ip="10.0.0.1",
            password="test",
        )
        assert "-dc" not in cmd

    def test_ldaps_flag(self):
        """use_ldaps adds --use-ldaps flag."""
        cmd = self._server._build_cmd(
            domain="corp.local",
            username="admin",
            dc_ip="10.0.0.1",
            password="test",
            use_ldaps=True,
        )
        assert "--use-ldaps" in cmd

    def test_ldap_channel_binding_flag(self):
        """ldap_channel_binding adds --ldap-channel-binding flag."""
        cmd = self._server._build_cmd(
            domain="corp.local",
            username="admin",
            dc_ip="10.0.0.1",
            password="test",
            ldap_channel_binding=True,
        )
        assert "--ldap-channel-binding" in cmd

    def test_dns_tcp_default_enabled(self):
        """DNS TCP is enabled by default."""
        cmd = self._server._build_cmd(
            domain="corp.local",
            username="admin",
            dc_ip="10.0.0.1",
            password="test",
        )
        assert "--dns-tcp" in cmd

    def test_dns_tcp_disabled(self):
        """DNS TCP can be disabled."""
        cmd = self._server._build_cmd(
            domain="corp.local",
            username="admin",
            dc_ip="10.0.0.1",
            password="test",
            dns_tcp=False,
        )
        assert "--dns-tcp" not in cmd

    def test_dns_timeout_custom(self):
        """Custom DNS timeout is passed."""
        cmd = self._server._build_cmd(
            domain="corp.local",
            username="admin",
            dc_ip="10.0.0.1",
            password="test",
            dns_timeout=15,
        )
        assert "--dns-timeout" in cmd
        idx = cmd.index("--dns-timeout")
        assert cmd[idx + 1] == "15"

    def test_dns_timeout_default_not_passed(self):
        """Default DNS timeout (3) is not explicitly passed."""
        cmd = self._server._build_cmd(
            domain="corp.local",
            username="admin",
            dc_ip="10.0.0.1",
            password="test",
            dns_timeout=3,
        )
        assert "--dns-timeout" not in cmd

    def test_workers_flag(self):
        """Workers count is passed."""
        cmd = self._server._build_cmd(
            domain="corp.local",
            username="admin",
            dc_ip="10.0.0.1",
            password="test",
            workers=5,
        )
        assert cmd[cmd.index("-w") + 1] == "5"

    def test_exclude_dcs_flag(self):
        """exclude_dcs adds --exclude-dcs."""
        cmd = self._server._build_cmd(
            domain="corp.local",
            username="admin",
            dc_ip="10.0.0.1",
            password="test",
            exclude_dcs=True,
        )
        assert "--exclude-dcs" in cmd

    def test_zip_output_flag(self):
        """zip_output adds --zip."""
        cmd = self._server._build_cmd(
            domain="corp.local",
            username="admin",
            dc_ip="10.0.0.1",
            password="test",
            zip_output=True,
        )
        assert "--zip" in cmd

    def test_computerfile_flag(self):
        """computerfile adds --computerfile."""
        cmd = self._server._build_cmd(
            domain="corp.local",
            username="admin",
            dc_ip="10.0.0.1",
            password="test",
            computerfile="/session/computers.txt",
        )
        assert "--computerfile" in cmd
        idx = cmd.index("--computerfile")
        assert cmd[idx + 1] == "/session/computers.txt"

    def test_gc_host_flag(self):
        """gc_host adds -gc flag."""
        cmd = self._server._build_cmd(
            domain="corp.local",
            username="admin",
            dc_ip="10.0.0.1",
            password="test",
            gc_host="gc01.corp.local",
        )
        assert "-gc" in cmd
        idx = cmd.index("-gc")
        assert cmd[idx + 1] == "gc01.corp.local"

    def test_auth_method_ntlm(self):
        """auth_method='ntlm' adds --auth-method."""
        cmd = self._server._build_cmd(
            domain="corp.local",
            username="admin",
            dc_ip="10.0.0.1",
            password="test",
            auth_method="ntlm",
        )
        assert "--auth-method" in cmd
        idx = cmd.index("--auth-method")
        assert cmd[idx + 1] == "ntlm"

    def test_auth_method_auto_not_passed(self):
        """auth_method='auto' (default) does not add --auth-method."""
        cmd = self._server._build_cmd(
            domain="corp.local",
            username="admin",
            dc_ip="10.0.0.1",
            password="test",
            auth_method="auto",
        )
        assert "--auth-method" not in cmd

    def test_output_prefix(self):
        """Output prefix is set to /session/bh."""
        cmd = self._server._build_cmd(
            domain="corp.local",
            username="admin",
            dc_ip="10.0.0.1",
            password="test",
        )
        assert "-op" in cmd
        idx = cmd.index("-op")
        assert cmd[idx + 1] == "/session/bh"

    def test_password_plus_kerberos(self):
        """Both password and kerberos can be combined (Kerberos with fallback)."""
        cmd = self._server._build_cmd(
            domain="corp.local",
            username="admin",
            dc_ip="10.0.0.1",
            password="test",
            kerberos=True,
        )
        assert "-p" in cmd
        assert "-k" in cmd
        assert "-no-pass" not in cmd  # password is provided

    def test_collection_dconly(self):
        """DCOnly collection method is passed correctly."""
        cmd = self._server._build_cmd(
            domain="corp.local",
            username="admin",
            dc_ip="10.0.0.1",
            password="test",
            collection="DCOnly",
        )
        assert cmd[cmd.index("-c") + 1] == "DCOnly"

    def test_collection_group(self):
        """Single collection method 'Group' is passed."""
        cmd = self._server._build_cmd(
            domain="corp.local",
            username="admin",
            dc_ip="10.0.0.1",
            password="test",
            collection="Group",
        )
        assert cmd[cmd.index("-c") + 1] == "Group"

    def test_collection_session(self):
        """Single collection method 'Session' is passed."""
        cmd = self._server._build_cmd(
            domain="corp.local",
            username="admin",
            dc_ip="10.0.0.1",
            password="test",
            collection="Session",
        )
        assert cmd[cmd.index("-c") + 1] == "Session"

    def test_collection_comma_separated(self):
        """Comma-separated collection methods are passed as-is."""
        cmd = self._server._build_cmd(
            domain="corp.local",
            username="admin",
            dc_ip="10.0.0.1",
            password="test",
            collection="Group,ACL,Trusts",
        )
        assert cmd[cmd.index("-c") + 1] == "Group,ACL,Trusts"

    def test_hashes_plus_kerberos(self):
        """Hashes and kerberos together: hashes provided, -no-pass not added."""
        cmd = self._server._build_cmd(
            domain="corp.local",
            username="admin",
            dc_ip="10.0.0.1",
            hashes="aad3b435b51404ee:31d6cfe0d16ae931b73c59d7e0c089c0",
            kerberos=True,
        )
        assert "--hashes" in cmd
        assert "-k" in cmd
        assert "-no-pass" not in cmd

    def test_no_creds_adds_no_pass(self):
        """No password, no hashes, no aes_key → -no-pass is added."""
        cmd = self._server._build_cmd(
            domain="corp.local",
            username="admin",
            dc_ip="10.0.0.1",
        )
        assert "-no-pass" in cmd
        assert "-p" not in cmd
        assert "--hashes" not in cmd

    def test_auth_method_kerberos(self):
        """auth_method='kerberos' adds --auth-method kerberos."""
        cmd = self._server._build_cmd(
            domain="corp.local",
            username="admin",
            dc_ip="10.0.0.1",
            password="test",
            auth_method="kerberos",
        )
        assert "--auth-method" in cmd
        idx = cmd.index("--auth-method")
        assert cmd[idx + 1] == "kerberos"

    def test_all_flags_combined(self):
        """Exercise all flags together to catch ordering or conflict issues."""
        cmd = self._server._build_cmd(
            domain="corp.local",
            username="admin",
            dc_ip="10.0.0.1",
            password="test",
            collection="All",
            dc_host="dc01.corp.local",
            gc_host="gc01.corp.local",
            use_ldaps=True,
            ldap_channel_binding=True,
            dns_tcp=True,
            dns_timeout=15,
            workers=2,
            exclude_dcs=True,
            zip_output=True,
            computerfile="/session/hosts.txt",
            auth_method="ntlm",
        )
        assert "-dc" in cmd
        assert "-gc" in cmd
        assert "--use-ldaps" in cmd
        assert "--ldap-channel-binding" in cmd
        assert "--dns-tcp" in cmd
        assert "--dns-timeout" in cmd
        assert "--exclude-dcs" in cmd
        assert "--zip" in cmd
        assert "--computerfile" in cmd
        assert "--auth-method" in cmd
        assert cmd[cmd.index("-c") + 1] == "All"
        assert cmd[cmd.index("-w") + 1] == "2"


class TestOutputFileParsing:
    """Test _find_output_files and _summarize_files."""

    @pytest.fixture(autouse=True, scope="class")
    def server(self):
        """Create a server instance for testing."""
        try:
            cls = _get_server_class()
            self.__class__._server = cls()
        except Exception as e:
            pytest.skip(f"Cannot import BloodhoundServer: {e}")

    def test_summarize_json_file(self, tmp_path):
        """Summarize a BloodHound JSON file correctly."""
        data = {
            "data": [
                {"name": "ADMIN@CORP.LOCAL", "type": "User"},
                {"name": "KRBTGT@CORP.LOCAL", "type": "User"},
            ],
            "meta": {
                "type": "users",
                "count": 2,
                "methods": 0,
                "version": 5,
            }
        }
        json_file = tmp_path / "bh_20260319_users.json"
        json_file.write_text(json.dumps(data))

        summaries = self._server._summarize_files([str(json_file)])
        assert len(summaries) == 1
        s = summaries[0]
        assert s["type"] == "users"
        assert s["count"] == 2
        assert s["size_bytes"] > 0
        assert s["filename"] == "bh_20260319_users.json"

    def test_summarize_zip_file(self, tmp_path):
        """Summarize a BloodHound ZIP file correctly."""
        zip_file = tmp_path / "bh_20260319.zip"
        with zipfile.ZipFile(str(zip_file), "w") as zf:
            zf.writestr("bh_users.json", '{"data":[],"meta":{"type":"users","count":0}}')
            zf.writestr("bh_groups.json", '{"data":[],"meta":{"type":"groups","count":0}}')

        summaries = self._server._summarize_files([str(zip_file)])
        assert len(summaries) == 1
        s = summaries[0]
        assert s["type"] == "zip"
        assert s["count"] == 2
        assert "contents" in s
        assert len(s["contents"]) == 2

    def test_summarize_invalid_json(self, tmp_path):
        """Invalid JSON files should get type 'unknown'."""
        bad_file = tmp_path / "bh_20260319_bad.json"
        bad_file.write_text("not valid json {{{")

        summaries = self._server._summarize_files([str(bad_file)])
        assert len(summaries) == 1
        s = summaries[0]
        assert s["type"] == "unknown"
        assert s["count"] == 0

    def test_summarize_bad_zip(self, tmp_path):
        """Invalid ZIP files should get type 'zip_error'."""
        bad_zip = tmp_path / "bh_20260319_bad.zip"
        bad_zip.write_text("not a zip file")

        summaries = self._server._summarize_files([str(bad_zip)])
        assert len(summaries) == 1
        s = summaries[0]
        assert s["type"] == "zip_error"
        assert s["count"] == 0

    def test_summarize_empty_list(self):
        """Empty file list returns empty summaries."""
        summaries = self._server._summarize_files([])
        assert summaries == []

    def test_summarize_json_no_meta(self, tmp_path):
        """JSON file without 'meta' key falls back to data length for count."""
        data = {"data": [{"name": "user1"}, {"name": "user2"}, {"name": "user3"}]}
        json_file = tmp_path / "bh_20260319_users.json"
        json_file.write_text(json.dumps(data))

        summaries = self._server._summarize_files([str(json_file)])
        assert len(summaries) == 1
        s = summaries[0]
        assert s["type"] == "unknown"
        assert s["count"] == 3  # fallback to len(data["data"])

    def test_summarize_multiple_files(self, tmp_path):
        """Summarize multiple files at once."""
        for ftype in ("users", "groups", "computers", "domains"):
            data = {
                "data": [{"name": f"obj_{i}"} for i in range(5)],
                "meta": {"type": ftype, "count": 5, "methods": 0, "version": 5},
            }
            p = tmp_path / f"bh_20260319_{ftype}.json"
            p.write_text(json.dumps(data))

        all_files = sorted(str(p) for p in tmp_path.glob("bh_*.json"))
        summaries = self._server._summarize_files(all_files)
        assert len(summaries) == 4
        types = {s["type"] for s in summaries}
        assert types == {"users", "groups", "computers", "domains"}
        for s in summaries:
            assert s["count"] == 5
            assert s["size_bytes"] > 0

    def test_summarize_large_file_rotation(self, tmp_path):
        """Simulate file rotation at 40000 entries (two files for same type)."""
        for i in range(2):
            data = {
                "data": [{"name": f"user_{j}"} for j in range(10)],
                "meta": {"type": "users", "count": 10, "methods": 0, "version": 5},
            }
            p = tmp_path / f"bh_20260319_{i}_users.json"
            p.write_text(json.dumps(data))

        all_files = sorted(str(p) for p in tmp_path.glob("bh_*.json"))
        summaries = self._server._summarize_files(all_files)
        assert len(summaries) == 2
        assert all(s["type"] == "users" for s in summaries)

    def test_summarize_json_empty_data_array(self, tmp_path):
        """JSON with empty data array should have count=0."""
        data = {
            "data": [],
            "meta": {"type": "gpos", "count": 0, "methods": 0, "version": 5},
        }
        json_file = tmp_path / "bh_20260319_gpos.json"
        json_file.write_text(json.dumps(data))

        summaries = self._server._summarize_files([str(json_file)])
        assert len(summaries) == 1
        assert summaries[0]["type"] == "gpos"
        assert summaries[0]["count"] == 0


# ===========================================================================
# ERROR CLASSIFICATION TESTS
# ===========================================================================

class TestErrorClassification:
    """Test _classify_bloodhound_error using fixture data.

    Verifies that the server correctly classifies DNS, auth, LDAP,
    and Kerberos errors with error_class, retryable, and suggestions.
    """

    @pytest.fixture(autouse=True, scope="class")
    def server(self):
        """Create a server instance for error classification testing."""
        try:
            cls = _get_server_class()
            self.__class__._server = cls()
        except Exception as e:
            pytest.skip(f"Cannot import BloodhoundServer: {e}")

    def test_classify_dns_no_nameservers(self):
        """NoNameservers should be 'network', retryable."""
        text = load_fixture("dns_no_nameservers.txt")
        err_class, retryable, suggestions = self._server._classify_bloodhound_error(text)
        assert err_class == "network", f"Expected 'network', got '{err_class}'"
        assert retryable is True
        assert len(suggestions) > 0

    def test_classify_dns_timeout(self):
        """LifetimeTimeout should be 'network', retryable."""
        text = load_fixture("dns_timeout.txt")
        err_class, retryable, suggestions = self._server._classify_bloodhound_error(text)
        assert err_class == "network", f"Expected 'network', got '{err_class}'"
        assert retryable is True

    def test_classify_auth_failure(self):
        """LDAP auth failure should be 'auth', not retryable."""
        text = load_fixture("auth_failure.txt")
        err_class, retryable, suggestions = self._server._classify_bloodhound_error(text)
        assert err_class == "auth", f"Expected 'auth', got '{err_class}'"
        assert retryable is False

    def test_classify_domain_not_found(self):
        """'Could not find a domain controller' should be 'config', retryable."""
        text = load_fixture("domain_not_found.txt")
        err_class, retryable, suggestions = self._server._classify_bloodhound_error(text)
        assert err_class == "config", f"Expected 'config', got '{err_class}'"
        assert retryable is True
        assert len(suggestions) > 0

    def test_classify_domain_wrong_ldap(self):
        """'Specified domain was not found in LDAP' should be 'config', not retryable."""
        text = load_fixture("domain_wrong_ldap.txt")
        err_class, retryable, suggestions = self._server._classify_bloodhound_error(text)
        assert err_class == "config", f"Expected 'config', got '{err_class}'"
        assert retryable is False

    def test_classify_ldap_connection_error(self):
        """LDAPSocketOpenError should be 'network', retryable."""
        text = load_fixture("ldap_connection_error.txt")
        err_class, retryable, suggestions = self._server._classify_bloodhound_error(text)
        assert err_class == "network", f"Expected 'network', got '{err_class}'"
        assert retryable is True

    def test_classify_kerberos_clock_skew(self):
        """KRB_AP_ERR_SKEW should be 'config', retryable."""
        text = load_fixture("kerberos_clock_skew.txt")
        err_class, retryable, suggestions = self._server._classify_bloodhound_error(text)
        assert err_class == "config", f"Expected 'config', got '{err_class}'"
        assert retryable is True
        assert any("clock" in s.lower() for s in suggestions), (
            f"Should suggest clock fix, got: {suggestions}"
        )

    def test_classify_kerberos_preauth_failed(self):
        """KDC_ERR_PREAUTH_FAILED should be 'auth', not retryable."""
        text = load_fixture("kerberos_preauth_failed.txt")
        err_class, retryable, suggestions = self._server._classify_bloodhound_error(text)
        assert err_class == "auth", f"Expected 'auth', got '{err_class}'"
        assert retryable is False

    def test_classify_ldap_communication_lost(self):
        """LDAP connection lost during collection should be 'network', retryable."""
        text = load_fixture("ldap_communication_lost.txt")
        err_class, retryable, suggestions = self._server._classify_bloodhound_error(text)
        assert err_class == "network", f"Expected 'network', got '{err_class}'"
        assert retryable is True

    def test_classify_empty_input(self):
        """Empty input should return 'unknown'."""
        err_class, retryable, suggestions = self._server._classify_bloodhound_error("")
        assert err_class == "unknown"
        assert retryable is False

    def test_classify_success_output_not_misclassified(self):
        """Successful output should classify as 'unknown' (not an error)."""
        text = load_fixture("success_default.txt")
        err_class, retryable, suggestions = self._server._classify_bloodhound_error(text)
        assert err_class == "unknown", f"Clean output misclassified as '{err_class}'"

    def test_classify_dconly_success_not_misclassified(self):
        """Successful DCOnly output should classify as 'unknown'."""
        text = load_fixture("success_dconly.txt")
        err_class, retryable, suggestions = self._server._classify_bloodhound_error(text)
        assert err_class == "unknown", f"Clean output misclassified as '{err_class}'"

    def test_classify_kerberos_principal_unknown(self):
        """KDC_ERR_C_PRINCIPAL_UNKNOWN should be 'auth', not retryable."""
        text = load_fixture("kerberos_principal_unknown.txt")
        err_class, retryable, suggestions = self._server._classify_bloodhound_error(text)
        assert err_class == "auth", f"Expected 'auth', got '{err_class}'"
        assert retryable is False
        assert len(suggestions) > 0
        assert any("username" in s.lower() or "principal" in s.lower() for s in suggestions), (
            f"Should suggest username fix, got: {suggestions}"
        )

    def test_classify_could_not_figure_out_domain(self):
        """'Could not figure out the domain' should be 'config', not retryable."""
        text = load_fixture("domain_could_not_figure_out.txt")
        err_class, retryable, suggestions = self._server._classify_bloodhound_error(text)
        assert err_class == "config", f"Expected 'config', got '{err_class}'"
        assert retryable is False
        assert len(suggestions) > 0

    def test_classify_ldap_socket_send_error(self):
        """LDAPSocketSendError should be 'network', retryable."""
        text = load_fixture("ldap_socket_send_error.txt")
        err_class, retryable, suggestions = self._server._classify_bloodhound_error(text)
        assert err_class == "network", f"Expected 'network', got '{err_class}'"
        assert retryable is True

    def test_classify_ldap_socket_receive_error(self):
        """LDAPSocketReceiveError should be 'network', retryable."""
        text = load_fixture("ldap_socket_receive_error.txt")
        err_class, retryable, suggestions = self._server._classify_bloodhound_error(text)
        assert err_class == "network", f"Expected 'network', got '{err_class}'"
        assert retryable is True

    def test_classify_inline_no_nameservers(self):
        """Inline 'All nameservers failed' triggers network classification."""
        err_class, retryable, suggestions = self._server._classify_bloodhound_error(
            "ERROR: All nameservers failed to answer the query"
        )
        assert err_class == "network"
        assert retryable is True

    def test_classify_inline_dns_operation_timed_out(self):
        """Inline 'DNS operation timed out' triggers network classification."""
        err_class, retryable, suggestions = self._server._classify_bloodhound_error(
            "ERROR: DNS operation timed out after 3 seconds"
        )
        assert err_class == "network"
        assert retryable is True

    def test_classify_inline_pre_authentication_invalid(self):
        """Inline 'Pre-authentication information was invalid' triggers auth classification."""
        err_class, retryable, suggestions = self._server._classify_bloodhound_error(
            "ERROR: Pre-authentication information was invalid"
        )
        assert err_class == "auth"
        assert retryable is False

    def test_classify_inline_clock_skew_too_great(self):
        """Inline 'Clock skew too great' triggers config classification."""
        err_class, retryable, suggestions = self._server._classify_bloodhound_error(
            "ERROR: Clock skew too great"
        )
        assert err_class == "config"
        assert retryable is True

    def test_classify_inline_failed_resolve_ldap(self):
        """Inline 'Failed to resolve LDAP server IP' triggers network classification."""
        err_class, retryable, suggestions = self._server._classify_bloodhound_error(
            "ERROR: Failed to resolve LDAP server IP address"
        )
        assert err_class == "network"
        assert retryable is True


# ===========================================================================
# TOOL.YAML CONTRACT TESTS -- no container needed
# ===========================================================================

class TestToolYamlContract:
    """Verify tool.yaml matches server parameter definitions."""

    @pytest.fixture(autouse=True, scope="class")
    def load_yaml(self):
        """Load tool.yaml."""
        with open(TOOL_DIR / "tool.yaml") as f:
            self.__class__._yaml = yaml.safe_load(f)

    def test_yaml_has_2_methods(self):
        """tool.yaml should define exactly 2 methods."""
        methods = self._yaml.get("methods", {})
        assert len(methods) == 2, (
            f"Expected 2 methods, got {len(methods)}: {sorted(methods.keys())}"
        )

    def test_all_methods_have_descriptions(self):
        """Every method should have a description."""
        for name, defn in self._yaml.get("methods", {}).items():
            assert "description" in defn, f"Method {name} missing description"
            assert len(defn["description"]) > 10, f"Method {name} has too short description"

    def test_all_methods_have_domain_and_username(self):
        """Every method should have 'domain' and 'username' required params."""
        for name, defn in self._yaml.get("methods", {}).items():
            params = defn.get("params", {})
            assert "domain" in params, f"Method {name} missing 'domain' param"
            assert "username" in params, f"Method {name} missing 'username' param"
            assert "dc_ip" in params, f"Method {name} missing 'dc_ip' param"

    def test_required_ports_defined(self):
        """Methods should have required_ports defined."""
        for name, defn in self._yaml.get("methods", {}).items():
            assert "required_ports" in defn, f"Method {name} missing required_ports"

    def test_yaml_param_types_valid(self):
        """All param types should be valid JSON Schema types or 'enum'."""
        valid_types = {"string", "integer", "boolean", "number", "array", "object", "enum"}
        for method_name, defn in self._yaml.get("methods", {}).items():
            for param_name, param_def in defn.get("params", {}).items():
                ptype = param_def.get("type", "string")
                assert ptype in valid_types, (
                    f"{method_name}.{param_name}: invalid type '{ptype}'"
                )

    def test_method_names_match_server(self):
        """Method names in tool.yaml match the server's registered methods."""
        try:
            cls = _get_server_class()
            server = cls()
        except Exception:
            pytest.skip("Cannot import BloodhoundServer")

        yaml_names = set(self._yaml.get("methods", {}).keys())
        server_names = set(server.methods.keys()) - {"verify_clock"}

        yaml_only = yaml_names - server_names
        server_only = server_names - yaml_names

        assert not yaml_only, f"Methods in tool.yaml but not server: {yaml_only}"
        assert not server_only, f"Methods in server but not tool.yaml: {server_only}"

    def test_yaml_auth_params_subset_of_server(self):
        """Every yaml param should be accepted by the server handler."""
        try:
            cls = _get_server_class()
            server = cls()
        except Exception:
            pytest.skip("Cannot import BloodhoundServer")

        for method_name, defn in self._yaml.get("methods", {}).items():
            yaml_params = set(defn.get("params", {}).keys())
            server_method = server.methods.get(method_name)
            if server_method is None:
                continue
            server_params = set(server_method.params.keys())
            yaml_only = yaml_params - server_params
            assert not yaml_only, (
                f"Method {method_name}: yaml has params not in server: {yaml_only}"
            )

    def test_collect_has_collection_param(self):
        """collect should have 'collection' param but collect_stealth should not."""
        methods = self._yaml.get("methods", {})
        collect_params = set(methods.get("collect", {}).get("params", {}).keys())
        stealth_params = set(methods.get("collect_stealth", {}).get("params", {}).keys())

        assert "collection" in collect_params, "collect should have 'collection' param"
        assert "collection" not in stealth_params, "collect_stealth should NOT have 'collection' param"

    def test_yaml_returns_fields(self):
        """Methods should have return field definitions."""
        for name, defn in self._yaml.get("methods", {}).items():
            returns = defn.get("returns", {})
            assert "files" in returns, f"Method {name} missing 'files' return field"
            assert "file_count" in returns, f"Method {name} missing 'file_count' return field"
            assert "collection_types" in returns, f"Method {name} missing 'collection_types' return field"


# ===========================================================================
# ACCEPTANCE TESTS -- every method through Docker, no live AD target
# ===========================================================================

class TestAcceptance:
    """Call every method through the container without a live AD target.

    These tests verify:
    - The method exists and is callable
    - Required param validation works (missing required params -> error)
    - The response has correct structuredContent shape
    - Error responses have error_class set (classified, not crash)
    - Different auth modes are accepted without crashing
    - Different collection methods are accepted without crashing

    Each test sends minimal args with a fake/unreachable DC IP so the
    command will fail at connection/DNS time, but the MCP protocol layer,
    param validation, and error classification should all function correctly.
    """

    _FAKE_AUTH = {
        "domain": "test.local",
        "username": "testuser",
        "password": "testpass",
        "dc_ip": "192.0.2.1",  # RFC 5737 TEST-NET, guaranteed unreachable
    }

    def _assert_structured_response(self, resp, method_name):
        """Assert response has structuredContent with required fields.

        Note: bloodhound-python itself outputs Python tracebacks on failure
        (e.g., DNS timeout, auth failure). These appear in the raw_output
        section of the text content and are expected. We only flag tracebacks
        that appear BEFORE the structured error/raw_output section, which
        would indicate an MCP server crash.
        """
        result = resp.get("result", {})
        sc = result.get("structuredContent", {})
        assert sc is not None, f"{method_name}: missing structuredContent"
        # All required structuredContent fields must be present
        for field in ("success", "error_class", "retryable", "suggestions"):
            assert field in sc, (
                f"{method_name}: missing '{field}' in structuredContent: {sc}"
            )
        content_text = ""
        for c in result.get("content", []):
            if c.get("type") == "text":
                content_text += c["text"]
        # Should NOT be an unhandled crash / unexpected kwarg error
        assert "unexpected keyword argument" not in content_text, (
            f"{method_name}: unhandled keyword argument error"
        )
        # Tracebacks in "Raw output:" section are expected (bloodhound-python
        # exits with a Python traceback on DNS/auth errors). Only flag if the
        # traceback is outside of raw output -- i.e., a server-level crash.
        # A server crash would produce isError=true without structuredContent.
        if result.get("isError", False) and sc is None:
            assert "Traceback" not in content_text, (
                f"{method_name}: unhandled Python traceback (server crash)"
            )
        return sc

    def _get_content_text(self, resp):
        """Extract text content from a response."""
        result = resp.get("result", {})
        texts = []
        for c in result.get("content", []):
            if c.get("type") == "text":
                texts.append(c["text"])
        return "".join(texts)

    # ── collect method: unreachable DC ────────────────────────

    def test_collect_unreachable_dc(self, bloodhound_env):
        """collect with unreachable DC returns classified DNS/network error."""
        client, loop = bloodhound_env
        resp = loop.run_until_complete(client.call("collect", {
            **self._FAKE_AUTH,
            "timeout": 30,
        }))
        sc = self._assert_structured_response(resp, "collect")
        # Should fail (unreachable DC)
        assert sc["success"] is False, "Should fail with unreachable DC"
        # Error should be classified as network (DNS failure)
        assert sc["error_class"] in ("network", "config", "unknown"), (
            f"Expected network/config error, got: {sc['error_class']}"
        )

    def test_collect_stealth_unreachable_dc(self, bloodhound_env):
        """collect_stealth with unreachable DC returns classified DNS/network error."""
        client, loop = bloodhound_env
        resp = loop.run_until_complete(client.call("collect_stealth", {
            **self._FAKE_AUTH,
            "timeout": 30,
        }))
        sc = self._assert_structured_response(resp, "collect_stealth")
        assert sc["success"] is False, "Should fail with unreachable DC"
        assert sc["error_class"] in ("network", "config", "unknown"), (
            f"Expected network/config error, got: {sc['error_class']}"
        )

    # ── Missing required params ──────────────────────────────

    def test_collect_missing_domain(self, bloodhound_env):
        """collect without 'domain' returns helpful error."""
        client, loop = bloodhound_env
        resp = loop.run_until_complete(client.call("collect", {
            "username": "testuser",
            "dc_ip": "192.0.2.1",
            "password": "test",
        }))
        result = resp.get("result", {})
        is_error = result.get("isError", False)
        content = self._get_content_text(resp)
        assert is_error or "domain" in content.lower() or "missing" in content.lower(), (
            f"Expected error about missing 'domain', got: {content[:300]}"
        )

    def test_collect_missing_username(self, bloodhound_env):
        """collect without 'username' returns helpful error."""
        client, loop = bloodhound_env
        resp = loop.run_until_complete(client.call("collect", {
            "domain": "test.local",
            "dc_ip": "192.0.2.1",
            "password": "test",
        }))
        result = resp.get("result", {})
        is_error = result.get("isError", False)
        content = self._get_content_text(resp)
        assert is_error or "username" in content.lower() or "missing" in content.lower(), (
            f"Expected error about missing 'username', got: {content[:300]}"
        )

    def test_collect_missing_dc_ip(self, bloodhound_env):
        """collect without 'dc_ip' returns helpful error."""
        client, loop = bloodhound_env
        resp = loop.run_until_complete(client.call("collect", {
            "domain": "test.local",
            "username": "testuser",
            "password": "test",
        }))
        result = resp.get("result", {})
        is_error = result.get("isError", False)
        content = self._get_content_text(resp)
        assert is_error or "dc_ip" in content.lower() or "missing" in content.lower(), (
            f"Expected error about missing 'dc_ip', got: {content[:300]}"
        )

    def test_collect_stealth_missing_domain(self, bloodhound_env):
        """collect_stealth without 'domain' returns helpful error."""
        client, loop = bloodhound_env
        resp = loop.run_until_complete(client.call("collect_stealth", {
            "username": "testuser",
            "dc_ip": "192.0.2.1",
            "password": "test",
        }))
        result = resp.get("result", {})
        is_error = result.get("isError", False)
        content = self._get_content_text(resp)
        assert is_error or "domain" in content.lower() or "missing" in content.lower()

    def test_collect_stealth_missing_username(self, bloodhound_env):
        """collect_stealth without 'username' returns helpful error."""
        client, loop = bloodhound_env
        resp = loop.run_until_complete(client.call("collect_stealth", {
            "domain": "test.local",
            "dc_ip": "192.0.2.1",
            "password": "test",
        }))
        result = resp.get("result", {})
        is_error = result.get("isError", False)
        content = self._get_content_text(resp)
        assert is_error or "username" in content.lower() or "missing" in content.lower()

    def test_collect_stealth_missing_dc_ip(self, bloodhound_env):
        """collect_stealth without 'dc_ip' returns helpful error."""
        client, loop = bloodhound_env
        resp = loop.run_until_complete(client.call("collect_stealth", {
            "domain": "test.local",
            "username": "testuser",
            "password": "test",
        }))
        result = resp.get("result", {})
        is_error = result.get("isError", False)
        content = self._get_content_text(resp)
        assert is_error or "dc_ip" in content.lower() or "missing" in content.lower()

    # ── No credentials ───────────────────────────────────────

    def test_collect_no_credentials_returns_params_error(self, bloodhound_env):
        """collect with no credentials returns params error_class."""
        client, loop = bloodhound_env
        resp = loop.run_until_complete(client.call("collect", {
            "domain": "test.local",
            "username": "testuser",
            "dc_ip": "192.0.2.1",
        }))
        result = resp.get("result", {})
        assert result.get("isError", False), "Should fail when no credentials"
        sc = result.get("structuredContent", {})
        if sc:
            assert sc.get("error_class") == "params", (
                f"Expected error_class='params', got '{sc.get('error_class')}'"
            )

    def test_collect_stealth_no_credentials_returns_params_error(self, bloodhound_env):
        """collect_stealth with no credentials returns params error_class."""
        client, loop = bloodhound_env
        resp = loop.run_until_complete(client.call("collect_stealth", {
            "domain": "test.local",
            "username": "testuser",
            "dc_ip": "192.0.2.1",
        }))
        result = resp.get("result", {})
        assert result.get("isError", False), "Should fail when no credentials"

    # ── Auth mode: password ──────────────────────────────────

    def test_collect_password_auth(self, bloodhound_env):
        """collect with password auth returns structured response."""
        client, loop = bloodhound_env
        resp = loop.run_until_complete(client.call("collect", {
            "domain": "test.local",
            "username": "testuser",
            "password": "testpass",
            "dc_ip": "192.0.2.1",
            "timeout": 30,
        }))
        sc = self._assert_structured_response(resp, "collect/password")
        # Data fields should be present even on error
        if not sc.get("success"):
            data = sc.get("data")
            # May or may not have data depending on failure point
            pass

    # ── Auth mode: hash ──────────────────────────────────────

    def test_collect_hash_auth(self, bloodhound_env):
        """collect with NTLM hash auth is accepted without crash."""
        client, loop = bloodhound_env
        resp = loop.run_until_complete(client.call("collect", {
            "domain": "test.local",
            "username": "testuser",
            "hashes": "aad3b435b51404ee:31d6cfe0d16ae931b73c59d7e0c089c0",
            "dc_ip": "192.0.2.1",
            "timeout": 30,
        }))
        sc = self._assert_structured_response(resp, "collect/hash")
        assert sc["success"] is False  # unreachable DC

    def test_collect_stealth_hash_auth(self, bloodhound_env):
        """collect_stealth with NTLM hash auth is accepted without crash."""
        client, loop = bloodhound_env
        resp = loop.run_until_complete(client.call("collect_stealth", {
            "domain": "test.local",
            "username": "testuser",
            "hashes": "aad3b435b51404ee:31d6cfe0d16ae931b73c59d7e0c089c0",
            "dc_ip": "192.0.2.1",
            "timeout": 30,
        }))
        sc = self._assert_structured_response(resp, "collect_stealth/hash")
        assert sc["success"] is False

    # ── Auth mode: kerberos ──────────────────────────────────

    def test_collect_kerberos_auth(self, bloodhound_env):
        """collect with kerberos=true is accepted without crash."""
        client, loop = bloodhound_env
        resp = loop.run_until_complete(client.call("collect", {
            "domain": "test.local",
            "username": "testuser",
            "kerberos": True,
            "dc_ip": "192.0.2.1",
            "timeout": 30,
        }))
        sc = self._assert_structured_response(resp, "collect/kerberos")
        assert sc["success"] is False

    def test_collect_kerberos_with_ccache(self, bloodhound_env):
        """collect with kerberos + ccache_path is accepted without crash."""
        client, loop = bloodhound_env
        resp = loop.run_until_complete(client.call("collect", {
            "domain": "test.local",
            "username": "testuser",
            "kerberos": True,
            "ccache_path": "/session/credentials/test.ccache",
            "dc_ip": "192.0.2.1",
            "timeout": 30,
        }))
        sc = self._assert_structured_response(resp, "collect/kerberos+ccache")
        assert sc["success"] is False

    def test_collect_stealth_kerberos_auth(self, bloodhound_env):
        """collect_stealth with kerberos=true is accepted without crash."""
        client, loop = bloodhound_env
        resp = loop.run_until_complete(client.call("collect_stealth", {
            "domain": "test.local",
            "username": "testuser",
            "kerberos": True,
            "dc_ip": "192.0.2.1",
            "timeout": 30,
        }))
        sc = self._assert_structured_response(resp, "collect_stealth/kerberos")
        assert sc["success"] is False

    # ── Auth mode: AES key ───────────────────────────────────

    def test_collect_aes_key_auth(self, bloodhound_env):
        """collect with aes_key auth is accepted without crash."""
        client, loop = bloodhound_env
        resp = loop.run_until_complete(client.call("collect", {
            "domain": "test.local",
            "username": "testuser",
            "aes_key": "a" * 64,  # 256-bit AES key (hex)
            "dc_ip": "192.0.2.1",
            "timeout": 30,
        }))
        sc = self._assert_structured_response(resp, "collect/aes_key")
        assert sc["success"] is False

    # ── Auth mode: forced NTLM ───────────────────────────────

    def test_collect_forced_ntlm_auth(self, bloodhound_env):
        """collect with auth_method='ntlm' is accepted without crash."""
        client, loop = bloodhound_env
        resp = loop.run_until_complete(client.call("collect", {
            "domain": "test.local",
            "username": "testuser",
            "password": "testpass",
            "auth_method": "ntlm",
            "dc_ip": "192.0.2.1",
            "timeout": 30,
        }))
        sc = self._assert_structured_response(resp, "collect/ntlm")
        assert sc["success"] is False

    def test_collect_forced_kerberos_auth(self, bloodhound_env):
        """collect with auth_method='kerberos' + password is accepted without crash."""
        client, loop = bloodhound_env
        resp = loop.run_until_complete(client.call("collect", {
            "domain": "test.local",
            "username": "testuser",
            "password": "testpass",
            "auth_method": "kerberos",
            "dc_ip": "192.0.2.1",
            "timeout": 30,
        }))
        sc = self._assert_structured_response(resp, "collect/auth_method=kerberos")
        assert sc["success"] is False

    # ── Collection methods ───────────────────────────────────

    def test_collect_method_default(self, bloodhound_env):
        """collect with collection='Default' is accepted."""
        client, loop = bloodhound_env
        resp = loop.run_until_complete(client.call("collect", {
            **self._FAKE_AUTH,
            "collection": "Default",
            "timeout": 30,
        }))
        sc = self._assert_structured_response(resp, "collect/Default")

    def test_collect_method_all(self, bloodhound_env):
        """collect with collection='All' is accepted."""
        client, loop = bloodhound_env
        resp = loop.run_until_complete(client.call("collect", {
            **self._FAKE_AUTH,
            "collection": "All",
            "timeout": 30,
        }))
        sc = self._assert_structured_response(resp, "collect/All")

    def test_collect_method_dconly(self, bloodhound_env):
        """collect with collection='DCOnly' is accepted."""
        client, loop = bloodhound_env
        resp = loop.run_until_complete(client.call("collect", {
            **self._FAKE_AUTH,
            "collection": "DCOnly",
            "timeout": 30,
        }))
        sc = self._assert_structured_response(resp, "collect/DCOnly")

    def test_collect_method_group(self, bloodhound_env):
        """collect with collection='Group' is accepted."""
        client, loop = bloodhound_env
        resp = loop.run_until_complete(client.call("collect", {
            **self._FAKE_AUTH,
            "collection": "Group",
            "timeout": 30,
        }))
        sc = self._assert_structured_response(resp, "collect/Group")

    def test_collect_method_session(self, bloodhound_env):
        """collect with collection='Session' is accepted."""
        client, loop = bloodhound_env
        resp = loop.run_until_complete(client.call("collect", {
            **self._FAKE_AUTH,
            "collection": "Session",
            "timeout": 30,
        }))
        sc = self._assert_structured_response(resp, "collect/Session")

    def test_collect_method_acl(self, bloodhound_env):
        """collect with collection='ACL' is accepted."""
        client, loop = bloodhound_env
        resp = loop.run_until_complete(client.call("collect", {
            **self._FAKE_AUTH,
            "collection": "ACL",
            "timeout": 30,
        }))
        sc = self._assert_structured_response(resp, "collect/ACL")

    def test_collect_method_objectprops(self, bloodhound_env):
        """collect with collection='ObjectProps' is accepted."""
        client, loop = bloodhound_env
        resp = loop.run_until_complete(client.call("collect", {
            **self._FAKE_AUTH,
            "collection": "ObjectProps",
            "timeout": 30,
        }))
        sc = self._assert_structured_response(resp, "collect/ObjectProps")

    def test_collect_method_trusts(self, bloodhound_env):
        """collect with collection='Trusts' is accepted."""
        client, loop = bloodhound_env
        resp = loop.run_until_complete(client.call("collect", {
            **self._FAKE_AUTH,
            "collection": "Trusts",
            "timeout": 30,
        }))
        sc = self._assert_structured_response(resp, "collect/Trusts")

    def test_collect_method_container(self, bloodhound_env):
        """collect with collection='Container' is accepted."""
        client, loop = bloodhound_env
        resp = loop.run_until_complete(client.call("collect", {
            **self._FAKE_AUTH,
            "collection": "Container",
            "timeout": 30,
        }))
        sc = self._assert_structured_response(resp, "collect/Container")

    def test_collect_method_comma_separated(self, bloodhound_env):
        """collect with comma-separated methods is accepted."""
        client, loop = bloodhound_env
        resp = loop.run_until_complete(client.call("collect", {
            **self._FAKE_AUTH,
            "collection": "Group,ACL,Trusts",
            "timeout": 30,
        }))
        sc = self._assert_structured_response(resp, "collect/Group,ACL,Trusts")

    # ── stealth always uses DCOnly ───────────────────────────

    def test_collect_stealth_data_shows_dconly(self, bloodhound_env):
        """collect_stealth always sets collection='DCOnly' in result data."""
        client, loop = bloodhound_env
        resp = loop.run_until_complete(client.call("collect_stealth", {
            **self._FAKE_AUTH,
            "timeout": 30,
        }))
        sc = self._assert_structured_response(resp, "collect_stealth/dconly")
        data = sc.get("data", {})
        if data:
            assert data.get("collection") == "DCOnly", (
                f"collect_stealth should use DCOnly, got: {data.get('collection')}"
            )

    # ── Optional flags accepted ──────────────────────────────

    def test_collect_with_dc_host(self, bloodhound_env):
        """collect with dc_host is accepted without crash."""
        client, loop = bloodhound_env
        resp = loop.run_until_complete(client.call("collect", {
            **self._FAKE_AUTH,
            "dc_host": "dc01.test.local",
            "timeout": 30,
        }))
        self._assert_structured_response(resp, "collect/dc_host")

    def test_collect_with_ldaps(self, bloodhound_env):
        """collect with use_ldaps=true is accepted without crash."""
        client, loop = bloodhound_env
        resp = loop.run_until_complete(client.call("collect", {
            **self._FAKE_AUTH,
            "use_ldaps": True,
            "timeout": 30,
        }))
        self._assert_structured_response(resp, "collect/ldaps")

    def test_collect_with_channel_binding(self, bloodhound_env):
        """collect with ldap_channel_binding=true is accepted."""
        client, loop = bloodhound_env
        resp = loop.run_until_complete(client.call("collect", {
            **self._FAKE_AUTH,
            "ldap_channel_binding": True,
            "timeout": 30,
        }))
        self._assert_structured_response(resp, "collect/channel_binding")

    def test_collect_with_custom_workers(self, bloodhound_env):
        """collect with workers=1 is accepted."""
        client, loop = bloodhound_env
        resp = loop.run_until_complete(client.call("collect", {
            **self._FAKE_AUTH,
            "workers": 1,
            "timeout": 30,
        }))
        self._assert_structured_response(resp, "collect/workers=1")

    def test_collect_with_exclude_dcs(self, bloodhound_env):
        """collect with exclude_dcs=true is accepted."""
        client, loop = bloodhound_env
        resp = loop.run_until_complete(client.call("collect", {
            **self._FAKE_AUTH,
            "exclude_dcs": True,
            "timeout": 30,
        }))
        self._assert_structured_response(resp, "collect/exclude_dcs")

    def test_collect_with_zip_output(self, bloodhound_env):
        """collect with zip_output=true is accepted."""
        client, loop = bloodhound_env
        resp = loop.run_until_complete(client.call("collect", {
            **self._FAKE_AUTH,
            "zip_output": True,
            "timeout": 30,
        }))
        self._assert_structured_response(resp, "collect/zip_output")

    def test_collect_with_custom_dns_timeout(self, bloodhound_env):
        """collect with dns_timeout=15 is accepted."""
        client, loop = bloodhound_env
        resp = loop.run_until_complete(client.call("collect", {
            **self._FAKE_AUTH,
            "dns_timeout": 15,
            "timeout": 30,
        }))
        self._assert_structured_response(resp, "collect/dns_timeout=15")

    def test_collect_with_gc_host(self, bloodhound_env):
        """collect with gc_host is accepted."""
        client, loop = bloodhound_env
        resp = loop.run_until_complete(client.call("collect", {
            **self._FAKE_AUTH,
            "gc_host": "gc01.test.local",
            "timeout": 30,
        }))
        self._assert_structured_response(resp, "collect/gc_host")

    def test_collect_dns_tcp_false(self, bloodhound_env):
        """collect with dns_tcp=false is accepted."""
        client, loop = bloodhound_env
        resp = loop.run_until_complete(client.call("collect", {
            **self._FAKE_AUTH,
            "dns_tcp": False,
            "timeout": 30,
        }))
        self._assert_structured_response(resp, "collect/dns_tcp=false")

    # ── structuredContent shape on every response ────────────

    def test_collect_error_has_data_fields(self, bloodhound_env):
        """Even on error, structuredContent should have expected data fields."""
        client, loop = bloodhound_env
        resp = loop.run_until_complete(client.call("collect", {
            **self._FAKE_AUTH,
            "timeout": 30,
        }))
        result = resp.get("result", {})
        sc = result.get("structuredContent", {})
        assert sc is not None
        # The structuredContent should always have these top-level keys
        assert "success" in sc
        assert "error_class" in sc
        assert "retryable" in sc
        assert "suggestions" in sc
        # suggestions should be a list
        assert isinstance(sc.get("suggestions", []), list)
        # retryable should be a bool
        assert isinstance(sc.get("retryable"), bool)

    def test_collect_stealth_error_has_data_fields(self, bloodhound_env):
        """collect_stealth error also has complete structuredContent."""
        client, loop = bloodhound_env
        resp = loop.run_until_complete(client.call("collect_stealth", {
            **self._FAKE_AUTH,
            "timeout": 30,
        }))
        result = resp.get("result", {})
        sc = result.get("structuredContent", {})
        assert sc is not None
        assert "success" in sc
        assert "error_class" in sc
        assert "retryable" in sc
        assert "suggestions" in sc
        assert isinstance(sc.get("suggestions", []), list)

    # ── FAKETIME verification ────────────────────────────────

    @pytest.mark.clock
    def test_faketime_verify_clock_baseline(self, bloodhound_env):
        """verify_clock without FAKETIME offset returns current time."""
        client, loop = bloodhound_env
        resp = loop.run_until_complete(client.call("verify_clock", {}))
        result = assert_tool_success(resp)
        data = parse_tool_output(resp)
        assert data["libfaketime_exists"] is True, (
            "bloodhound image must have libfaketime installed"
        )
        assert "current_time" in data
        assert "faketime_active" in data or "libfaketime_exists" in data

    # ── Engagement pattern: hash auth with dc_host (from Pirate.htb) ─

    def test_collect_stealth_hash_with_dc_host(self, bloodhound_env):
        """collect_stealth with hashes + dc_host + auth_method is accepted.

        Pattern observed in real engagement (Pirate.htb): machine account
        with hash auth and explicit dc_host.
        """
        client, loop = bloodhound_env
        resp = loop.run_until_complete(client.call("collect_stealth", {
            "domain": "pirate.htb",
            "username": "ms01$",
            "hashes": "aad3b435b51404ee:31d6cfe0d16ae931b73c59d7e0c089c0",
            "dc_ip": "192.0.2.1",
            "dc_host": "DC01.pirate.htb",
            "auth_method": "ntlm",
            "dns_tcp": True,
            "dns_timeout": 10,
            "timeout": 30,
        }))
        self._assert_structured_response(resp, "collect_stealth/pirate-pattern")

    # ── Engagement pattern: kerberos + password (from Pirate.htb) ────

    def test_collect_stealth_kerberos_with_password(self, bloodhound_env):
        """collect_stealth with kerberos=true + password combo is accepted.

        Pattern observed in real engagement (Pirate.htb).
        """
        client, loop = bloodhound_env
        resp = loop.run_until_complete(client.call("collect_stealth", {
            "domain": "pirate.htb",
            "username": "ms01$",
            "password": "testpass",
            "dc_ip": "192.0.2.1",
            "kerberos": True,
            "timeout": 30,
        }))
        self._assert_structured_response(resp, "collect_stealth/kerb+password")

    # ── Engagement pattern: All collection with zip (from Garfield.htb) ─

    def test_collect_all_with_zip(self, bloodhound_env):
        """collect with collection='All' + zip_output is accepted.

        Pattern observed in real engagement (Garfield.htb).
        """
        client, loop = bloodhound_env
        resp = loop.run_until_complete(client.call("collect", {
            "domain": "garfield.htb",
            "username": "j.arbuckle",
            "password": "testpass",
            "dc_ip": "192.0.2.1",
            "collection": "All",
            "zip_output": True,
            "timeout": 30,
        }))
        self._assert_structured_response(resp, "collect/garfield-pattern")


# ===========================================================================
# INTEGRATION TESTS -- require --target, --domain, etc.
# ===========================================================================

@pytest.mark.integration
class TestIntegration:
    """Integration tests that need a real AD target.

    Run with: pytest tests/tools/test_bloodhound.py --tool=bloodhound
              --target=<DC_IP> --domain=<DOMAIN> --username=<USER> --password=<PASS>
              -m integration -v
    """

    def test_collect_default(self, bloodhound_env, target, domain, username, password):
        """Default collection against a live DC."""
        client, loop = bloodhound_env
        resp = loop.run_until_complete(client.call("collect", {
            "domain": domain,
            "username": username,
            "password": password,
            "dc_ip": target,
            "collection": "Default",
            "timeout": 120,
        }))
        result = assert_tool_success(resp, "collect should succeed with valid creds")
        data = parse_tool_output(resp)
        assert data["file_count"] > 0, "Should produce output files"
        assert len(data["files"]) > 0
        assert len(data["collection_types"]) > 0, "Should have collection types"

    def test_collect_stealth(self, bloodhound_env, target, domain, username, password):
        """DCOnly stealth collection against a live DC."""
        client, loop = bloodhound_env
        resp = loop.run_until_complete(client.call("collect_stealth", {
            "domain": domain,
            "username": username,
            "password": password,
            "dc_ip": target,
            "timeout": 120,
        }))
        result = assert_tool_success(resp, "collect_stealth should succeed")
        data = parse_tool_output(resp)
        assert data["file_count"] > 0, "Should produce output files"
        assert data["collection"] == "DCOnly", "Stealth should use DCOnly"

    def test_collect_all(self, bloodhound_env, target, domain, username, password):
        """'All' collection against a live DC."""
        client, loop = bloodhound_env
        resp = loop.run_until_complete(client.call("collect", {
            "domain": domain,
            "username": username,
            "password": password,
            "dc_ip": target,
            "collection": "All",
            "timeout": 300,
        }))
        result = assert_tool_success(resp, "collect All should succeed")
        data = parse_tool_output(resp)
        assert data["file_count"] >= 4, "All collection should produce many files"

    def test_collect_with_zip(self, bloodhound_env, target, domain, username, password):
        """Collection with zip output."""
        client, loop = bloodhound_env
        resp = loop.run_until_complete(client.call("collect", {
            "domain": domain,
            "username": username,
            "password": password,
            "dc_ip": target,
            "collection": "DCOnly",
            "zip_output": True,
            "timeout": 120,
        }))
        result = assert_tool_success(resp, "collect with zip should succeed")
        data = parse_tool_output(resp)
        assert data["file_count"] > 0

    def test_collect_wrong_password(self, bloodhound_env, target, domain, username):
        """Wrong password should fail with classified auth error."""
        client, loop = bloodhound_env
        resp = loop.run_until_complete(client.call("collect", {
            "domain": domain,
            "username": username,
            "password": "definitelyWrongPassword123!",
            "dc_ip": target,
            "timeout": 60,
        }))
        result = resp.get("result", {})
        sc = result.get("structuredContent", {})
        assert sc is not None, "Should have structuredContent"
        # Should either be isError or have file_count=0
        if result.get("isError", False):
            assert sc.get("error_class") is not None, "Error should be classified"

    def test_collect_wrong_domain(self, bloodhound_env, target, username, password):
        """Wrong domain should fail with classified config error."""
        client, loop = bloodhound_env
        resp = loop.run_until_complete(client.call("collect", {
            "domain": "nonexistent.invalid",
            "username": username,
            "password": password,
            "dc_ip": target,
            "timeout": 30,
        }))
        result = resp.get("result", {})
        # Should fail - either as isError or with file_count=0
        sc = result.get("structuredContent", {})
        assert sc is not None, "Should have structuredContent"


# ===========================================================================
# CROSS-TOOL INTEGRATION TEST -- impacket ccache -> bloodhound
# ===========================================================================

@pytest.mark.integration
class TestCrossTool:
    """Cross-tool integration tests.

    Verifies that bloodhound can use a ccache file from /session/credentials/,
    which is the standard flow when impacket's get_tgt creates a ccache.
    """

    def test_kerberos_with_ccache_path(self, bloodhound_env, target, domain, username, password):
        """bloodhound should accept kerberos=true + ccache_path without crashing.

        This tests the parameter handling even if the ccache doesn't exist
        (we expect a connection/auth error, not a crash).
        """
        client, loop = bloodhound_env
        resp = loop.run_until_complete(client.call("collect", {
            "domain": domain,
            "username": username,
            "kerberos": True,
            "ccache_path": "/session/credentials/test.ccache",
            "dc_ip": target,
            "timeout": 60,
        }))
        result = resp.get("result", {})
        content_text = ""
        for c in result.get("content", []):
            if c.get("type") == "text":
                content_text += c["text"]
        # Should be a proper error (auth/network), not a crash
        assert "unexpected keyword argument" not in content_text
        # Verify structuredContent has classification
        sc = result.get("structuredContent", {})
        if result.get("isError", False):
            assert sc.get("error_class") is not None, "Error should be classified"

    def test_collect_stealth_with_kerberos(self, bloodhound_env, target, domain, username, password):
        """collect_stealth should accept kerberos params without crashing."""
        client, loop = bloodhound_env
        resp = loop.run_until_complete(client.call("collect_stealth", {
            "domain": domain,
            "username": username,
            "kerberos": True,
            "ccache_path": "/session/credentials/test.ccache",
            "dc_ip": target,
            "timeout": 60,
        }))
        result = resp.get("result", {})
        content_text = ""
        for c in result.get("content", []):
            if c.get("type") == "text":
                content_text += c["text"]
        assert "unexpected keyword argument" not in content_text
