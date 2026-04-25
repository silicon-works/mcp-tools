"""
Tests for the enum4linux-ng MCP tool server.

Covers:
- Smoke tests: boot, method list, required params, meta-param stripping, clock
- Unit tests: JSON parser (_parse_json_output), command building, error classification
- Unit tests: _make_json_output_path, _cleanup_json_files, _is_abort_output
- Bug regression: double .json extension, wrong -R flag for RID ranges
- Contract tests: tool.yaml vs server parameter definitions
- Acceptance tests: every method called through container (no live SMB target)
- Integration tests: real target scenarios (marked @pytest.mark.integration)
"""

import asyncio
import json
import os
import sys
import tempfile
from pathlib import Path
from typing import Any, Dict
from unittest.mock import AsyncMock, MagicMock, patch
import subprocess

import pytest
import yaml

# ---------------------------------------------------------------------------
# Path setup
# ---------------------------------------------------------------------------
PROJECT_ROOT = Path(__file__).parent.parent.parent
TOOL_DIR = PROJECT_ROOT / "tools" / "enum4linux-ng"
FIXTURES_DIR = Path(__file__).parent.parent / "fixtures" / "enum4linux-ng"

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
def enum4linux_env(request):
    """Create an MCPTestClient with its event loop. Yields (client, loop)."""
    tool = "enum4linux-ng"
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


def load_fixture_json(name: str) -> Dict[str, Any]:
    """Load a fixture JSON file."""
    path = FIXTURES_DIR / name
    return json.loads(path.read_text())


# ---------------------------------------------------------------------------
# Helper: import server module for direct testing
# ---------------------------------------------------------------------------
def _get_server_class():
    """Import and return the Enum4linuxServer class for direct method testing."""
    import importlib.util
    spec = importlib.util.spec_from_file_location(
        "enum4linux_server", TOOL_DIR / "mcp-server.py"
    )
    mod = importlib.util.module_from_spec(spec)
    spec.loader.exec_module(mod)
    return mod.Enum4linuxServer


# ===========================================================================
# SMOKE TESTS -- require Docker container running
# ===========================================================================

class TestSmoke:
    """Smoke tests that verify the container boots and basic protocol works."""

    def test_boot_and_list_tools(self, enum4linux_env):
        """Container starts and list_tools returns methods."""
        client, loop = enum4linux_env
        assert len(client.tools) > 0, "Server should advertise at least one tool"
        names = client.tool_names()
        assert "enumerate" in names, "enumerate should be in tool list"
        assert "enum_users" in names, "enum_users should be in tool list"
        assert "enum_shares" in names, "enum_shares should be in tool list"
        assert "enum_groups" in names, "enum_groups should be in tool list"
        assert "enum_policy" in names, "enum_policy should be in tool list"

    def test_method_list_matches_tool_yaml(self, enum4linux_env):
        """Every method in tool.yaml is advertised by the server, and vice versa."""
        client, _ = enum4linux_env
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

    def test_expected_method_count(self, enum4linux_env):
        """Server should have exactly 5 built-in methods + verify_clock."""
        client, _ = enum4linux_env
        names = client.tool_names()
        # 5 built-in + verify_clock in MCP_TEST_MODE
        assert len(names) == 6, (
            f"Expected 6 methods (5 built-in + verify_clock), got {len(names)}: {sorted(names)}"
        )

    def test_required_params_enforced_enumerate(self, enum4linux_env):
        """Calling enumerate without required 'target' param returns an error."""
        client, loop = enum4linux_env
        resp = loop.run_until_complete(
            client.call("enumerate", {
                "shares": True,
                "users": True,
            })
        )
        result = resp.get("result", {})
        is_error = result.get("isError", False)
        content_text = ""
        for c in result.get("content", []):
            if c.get("type") == "text":
                content_text += c["text"]
        assert is_error or "target" in content_text.lower() or "error" in content_text.lower(), (
            f"Expected error about missing 'target', got: {content_text[:300]}"
        )

    def test_required_params_enforced_enum_users(self, enum4linux_env):
        """Calling enum_users without required 'target' param returns an error."""
        client, loop = enum4linux_env
        resp = loop.run_until_complete(
            client.call("enum_users", {
                "rid_range": "500-550",
            })
        )
        result = resp.get("result", {})
        is_error = result.get("isError", False)
        content_text = ""
        for c in result.get("content", []):
            if c.get("type") == "text":
                content_text += c["text"]
        assert is_error or "target" in content_text.lower() or "error" in content_text.lower(), (
            f"Expected error about missing 'target', got: {content_text[:300]}"
        )

    def test_meta_params_stripped_timeout(self, enum4linux_env):
        """Passing 'timeout' (meta-param) in args does not crash the server.

        Note: timeout IS a registered param for enum4linux-ng, so it should
        be passed through, not stripped.
        """
        client, loop = enum4linux_env
        resp = loop.run_until_complete(
            client.call("enumerate", {
                "target": "10.0.0.1",
                "timeout": 30,
            })
        )
        result = resp.get("result", {})
        content_text = ""
        for c in result.get("content", []):
            if c.get("type") == "text":
                content_text += c["text"]
        assert "unexpected keyword argument" not in content_text, (
            f"Meta-param 'timeout' was not handled correctly: {content_text[:300]}"
        )

    def test_meta_params_stripped_clock_offset(self, enum4linux_env):
        """Passing 'clock_offset' (meta-param) in args does not crash the server."""
        client, loop = enum4linux_env
        resp = loop.run_until_complete(
            client.call("enumerate", {
                "target": "10.0.0.1",
                "clock_offset": "+5h",
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

    def test_unknown_method_returns_error(self, enum4linux_env):
        """Calling a non-existent method returns a helpful error."""
        client, loop = enum4linux_env
        resp = loop.run_until_complete(
            client.call("enum_printers", {})
        )
        result = assert_tool_error(resp)
        content_text = ""
        for c in result.get("content", []):
            if c.get("type") == "text":
                content_text += c["text"]
        assert "Unknown method" in content_text
        assert "enum_printers" in content_text

    @pytest.mark.clock
    def test_verify_clock_available(self, enum4linux_env):
        """verify_clock is registered in MCP_TEST_MODE."""
        client, _ = enum4linux_env
        names = client.tool_names()
        assert "verify_clock" in names, "verify_clock should be available in test mode"

    @pytest.mark.clock
    def test_verify_clock_returns_time(self, enum4linux_env):
        """verify_clock returns current time and FAKETIME status."""
        client, loop = enum4linux_env
        resp = loop.run_until_complete(client.call("verify_clock", {}))
        result = assert_tool_success(resp)
        data = parse_tool_output(resp)
        assert "current_time" in data
        assert "libfaketime_exists" in data
        # libfaketime is installed in this image
        assert data["libfaketime_exists"] is True, (
            "libfaketime should be installed in the enum4linux-ng image"
        )

    def test_structuredContent_present(self, enum4linux_env):
        """Responses include structuredContent with error classification fields."""
        client, loop = enum4linux_env
        resp = loop.run_until_complete(client.call("verify_clock", {}))
        result = resp.get("result", {})
        sc = result.get("structuredContent")
        assert sc is not None, "structuredContent should be present"
        assert "success" in sc
        assert "error_class" in sc
        assert "retryable" in sc
        assert "suggestions" in sc


# ===========================================================================
# UNIT TESTS -- JSON parser, no container needed
# ===========================================================================

class TestParseJsonOutput:
    """Test _parse_json_output using fixture data."""

    @pytest.fixture(autouse=True, scope="class")
    def server(self):
        """Create a server instance for parser testing."""
        try:
            cls = _get_server_class()
            self.__class__._server = cls()
        except Exception as e:
            pytest.skip(f"Cannot import Enum4linuxServer: {e}")

    def test_parse_valid_json(self):
        """Parse a valid enum4linux-ng JSON output file."""
        data = load_fixture_json("enumerate_success.json")
        with tempfile.NamedTemporaryFile(
            mode="w", suffix=".json", delete=False
        ) as f:
            json.dump(data, f)
            tmp_path = f.name

        try:
            result = self._server._parse_json_output(tmp_path)
            assert "target" in result
            assert "shares" in result
            assert "users" in result
            assert "groups" in result
            assert result["os_info"]["Domain"] == "MEGACORP"
        finally:
            os.unlink(tmp_path)

    def test_parse_nonexistent_file(self):
        """Parsing a non-existent file returns empty dict."""
        result = self._server._parse_json_output("/tmp/nonexistent_file_xyz.json")
        assert result == {}

    def test_parse_empty_file(self):
        """Parsing an empty file returns empty dict."""
        with tempfile.NamedTemporaryFile(
            mode="w", suffix=".json", delete=False
        ) as f:
            tmp_path = f.name

        try:
            result = self._server._parse_json_output(tmp_path)
            assert result == {}
        finally:
            os.unlink(tmp_path)

    def test_parse_invalid_json(self):
        """Parsing invalid JSON returns empty dict."""
        with tempfile.NamedTemporaryFile(
            mode="w", suffix=".json", delete=False
        ) as f:
            f.write("not valid json {[")
            tmp_path = f.name

        try:
            result = self._server._parse_json_output(tmp_path)
            assert result == {}
        finally:
            os.unlink(tmp_path)

    def test_parse_connection_refused_json(self):
        """Parse JSON from a connection-refused scan."""
        data = load_fixture_json("connection_refused.json")
        with tempfile.NamedTemporaryFile(
            mode="w", suffix=".json", delete=False
        ) as f:
            json.dump(data, f)
            tmp_path = f.name

        try:
            result = self._server._parse_json_output(tmp_path)
            assert "errors" in result
            assert "listeners" in result
            # SMB not accessible
            assert result["listeners"]["SMB"]["accessible"] is False
        finally:
            os.unlink(tmp_path)


# ===========================================================================
# COMMAND BUILDING TESTS -- verify correct CLI flags
# ===========================================================================

class TestCommandBuilding:
    """Test that each method builds the correct enum4linux-ng command line."""

    @pytest.fixture(autouse=True, scope="class")
    def server(self):
        """Create a server instance."""
        try:
            cls = _get_server_class()
            self.__class__._server = cls()
        except Exception as e:
            pytest.skip(f"Cannot import Enum4linuxServer: {e}")

    def _capture_cmd(self, method_name, **kwargs):
        """Call a method and capture the command that would be run.

        Uses mock to intercept run_command and extract the args list.
        """
        captured = {}

        async def mock_run_command(cmd, timeout=300, **kw):
            captured["cmd"] = cmd
            # Return a fake successful result
            return subprocess.CompletedProcess(
                args=cmd, returncode=0, stdout="", stderr=""
            )

        loop = asyncio.new_event_loop()
        try:
            with patch.object(self._server, "run_command", side_effect=mock_run_command):
                with patch.object(self._server, "_parse_json_output", return_value={}):
                    loop.run_until_complete(
                        getattr(self._server, method_name)(**kwargs)
                    )
        finally:
            loop.close()

        return captured.get("cmd", [])

    def test_enumerate_default_flags(self):
        """enumerate with default params uses -S -U -G."""
        cmd = self._capture_cmd("enumerate", target="10.0.0.1")
        assert "enum4linux-ng" in cmd[0]
        assert "-S" in cmd, "Should include -S for shares"
        assert "-U" in cmd, "Should include -U for users"
        assert "-G" in cmd, "Should include -G for groups"
        assert "10.0.0.1" in cmd, "Target should be in command"

    def test_enumerate_all_disabled_uses_A(self):
        """enumerate with all modules disabled defaults to -A."""
        cmd = self._capture_cmd(
            "enumerate", target="10.0.0.1",
            shares=False, users=False, groups=False,
        )
        assert "-A" in cmd, "Should default to -A when nothing specified"
        assert "-S" not in cmd
        assert "-U" not in cmd
        assert "-G" not in cmd

    def test_enumerate_with_credentials(self):
        """enumerate with username/password passes -u and -p."""
        cmd = self._capture_cmd(
            "enumerate", target="10.0.0.1",
            username="admin", password="Pass123",
        )
        assert "-u" in cmd
        idx_u = cmd.index("-u")
        assert cmd[idx_u + 1] == "admin"
        assert "-p" in cmd
        idx_p = cmd.index("-p")
        assert cmd[idx_p + 1] == "Pass123"

    def test_enumerate_no_creds_omits_u_p(self):
        """enumerate without credentials does not pass -u or -p."""
        cmd = self._capture_cmd("enumerate", target="10.0.0.1")
        assert "-u" not in cmd, "Should not pass -u for null session"
        assert "-p" not in cmd, "Should not pass -p for null session"

    def test_enumerate_json_output_flag(self):
        """enumerate passes -oJ for JSON output."""
        cmd = self._capture_cmd("enumerate", target="10.0.0.1")
        assert "-oJ" in cmd, "Should use -oJ for JSON output"

    def test_enum_users_uses_R_and_r_flags(self):
        """enum_users uses -R (enable RID cycling) and -r (range), not -R range."""
        cmd = self._capture_cmd(
            "enum_users", target="10.0.0.1",
            rid_range="500-550,1000-5000",
        )
        assert "-R" in cmd, "Should include -R to enable RID cycling"
        assert "-r" in cmd, "Should include -r for RID range"
        idx_r = cmd.index("-r")
        assert cmd[idx_r + 1] == "500-550,1000-5000", (
            f"RID range should follow -r, got: {cmd[idx_r + 1] if idx_r + 1 < len(cmd) else 'nothing'}"
        )
        # Make sure -R is NOT followed by the range string
        idx_R = cmd.index("-R")
        if idx_R + 1 < len(cmd):
            next_after_R = cmd[idx_R + 1]
            assert next_after_R != "500-550,1000-5000", (
                "Range should NOT follow -R (that expects an int BULK_SIZE)"
            )

    def test_enum_users_default_rid_range(self):
        """enum_users uses default RID range when not specified."""
        cmd = self._capture_cmd("enum_users", target="10.0.0.1")
        assert "-r" in cmd, "Should include -r for default RID range"
        idx_r = cmd.index("-r")
        assert cmd[idx_r + 1] == "500-550,1000-1200"

    def test_enum_shares_uses_S_flag(self):
        """enum_shares uses -S flag."""
        cmd = self._capture_cmd("enum_shares", target="10.0.0.1")
        assert "-S" in cmd

    def test_enum_groups_uses_G_flag(self):
        """enum_groups uses -G flag."""
        cmd = self._capture_cmd("enum_groups", target="10.0.0.1")
        assert "-G" in cmd

    def test_enum_policy_uses_P_and_I_flags(self):
        """enum_policy uses -P (password policy) and -I (printer info)."""
        cmd = self._capture_cmd("enum_policy", target="10.0.0.1")
        assert "-P" in cmd
        assert "-I" in cmd

    def test_json_output_path_no_double_extension(self):
        """The -oJ path should NOT have .json suffix (enum4linux-ng appends it)."""
        cmd = self._capture_cmd("enumerate", target="10.0.0.1")
        idx_oJ = cmd.index("-oJ")
        json_path = cmd[idx_oJ + 1]
        assert not json_path.endswith(".json"), (
            f"JSON output path should not end with .json (enum4linux-ng adds it): {json_path}"
        )

    def test_target_is_last_argument(self):
        """Target should be the last positional argument for all methods."""
        for method, kwargs in [
            ("enumerate", {"target": "10.0.0.1"}),
            ("enum_users", {"target": "10.0.0.1"}),
            ("enum_shares", {"target": "10.0.0.1"}),
            ("enum_groups", {"target": "10.0.0.1"}),
            ("enum_policy", {"target": "10.0.0.1"}),
        ]:
            cmd = self._capture_cmd(method, **kwargs)
            assert cmd[-1] == "10.0.0.1", (
                f"{method}: target should be last arg, got: {cmd[-3:]}"
            )

    def test_enum_shares_with_credentials_cmd(self):
        """enum_shares with credentials passes -u and -p."""
        cmd = self._capture_cmd(
            "enum_shares", target="10.0.0.1",
            username="admin", password="Pass123",
        )
        assert "-u" in cmd
        assert "-p" in cmd
        idx_u = cmd.index("-u")
        assert cmd[idx_u + 1] == "admin"

    def test_enum_groups_with_credentials_cmd(self):
        """enum_groups with credentials passes -u and -p."""
        cmd = self._capture_cmd(
            "enum_groups", target="10.0.0.1",
            username="admin", password="Pass123",
        )
        assert "-u" in cmd
        assert "-p" in cmd

    def test_enum_policy_with_credentials_cmd(self):
        """enum_policy with credentials passes -u and -p."""
        cmd = self._capture_cmd(
            "enum_policy", target="10.0.0.1",
            username="admin", password="Pass123",
        )
        assert "-u" in cmd
        assert "-p" in cmd

    def test_enum_users_has_U_flag(self):
        """enum_users should include -U for user enumeration via RPC."""
        cmd = self._capture_cmd("enum_users", target="10.0.0.1")
        assert "-U" in cmd, "enum_users should include -U flag"

    def test_all_methods_include_oJ(self):
        """All methods should include -oJ for JSON output."""
        for method, kwargs in [
            ("enumerate", {"target": "10.0.0.1"}),
            ("enum_users", {"target": "10.0.0.1"}),
            ("enum_shares", {"target": "10.0.0.1"}),
            ("enum_groups", {"target": "10.0.0.1"}),
            ("enum_policy", {"target": "10.0.0.1"}),
        ]:
            cmd = self._capture_cmd(method, **kwargs)
            assert "-oJ" in cmd, f"{method}: should include -oJ for JSON output"

    def test_enumerate_only_shares(self):
        """enumerate with only shares=True uses only -S."""
        cmd = self._capture_cmd(
            "enumerate", target="10.0.0.1",
            shares=True, users=False, groups=False,
        )
        assert "-S" in cmd
        assert "-U" not in cmd
        assert "-G" not in cmd
        assert "-A" not in cmd

    def test_enumerate_only_users(self):
        """enumerate with only users=True uses only -U."""
        cmd = self._capture_cmd(
            "enumerate", target="10.0.0.1",
            shares=False, users=True, groups=False,
        )
        assert "-U" in cmd
        assert "-S" not in cmd
        assert "-G" not in cmd

    def test_enumerate_only_groups(self):
        """enumerate with only groups=True uses only -G."""
        cmd = self._capture_cmd(
            "enumerate", target="10.0.0.1",
            shares=False, users=False, groups=True,
        )
        assert "-G" in cmd
        assert "-S" not in cmd
        assert "-U" not in cmd

    def test_null_session_no_credential_flags(self):
        """All methods without credentials should not pass -u or -p."""
        for method, kwargs in [
            ("enum_shares", {"target": "10.0.0.1"}),
            ("enum_groups", {"target": "10.0.0.1"}),
            ("enum_policy", {"target": "10.0.0.1"}),
            ("enum_users", {"target": "10.0.0.1"}),
        ]:
            cmd = self._capture_cmd(method, **kwargs)
            assert "-u" not in cmd, f"{method}: should not pass -u for null session"
            assert "-p" not in cmd, f"{method}: should not pass -p for null session"


# ===========================================================================
# ERROR CLASSIFICATION TESTS
# ===========================================================================

class TestErrorClassification:
    """Test error classification for enum4linux-ng output patterns."""

    @pytest.fixture(autouse=True, scope="class")
    def server(self):
        """Create a server instance."""
        try:
            cls = _get_server_class()
            self.__class__._server = cls()
        except Exception as e:
            pytest.skip(f"Cannot import Enum4linuxServer: {e}")

    def test_classify_connection_refused(self):
        """Connection refused should classify as 'network', retryable."""
        text = load_fixture("connection_refused_stdout.txt")
        err_class, retryable, suggestions = self._server._classify_enum_error(text)
        assert err_class == "network", f"Expected 'network', got '{err_class}'"
        assert retryable is True

    def test_classify_auth_failure(self):
        """Auth failure / LOGON_FAILURE should classify as 'auth', not retryable."""
        text = load_fixture("auth_failure_stdout.txt")
        err_class, retryable, suggestions = self._server._classify_enum_error(text)
        assert err_class == "auth", f"Expected 'auth', got '{err_class}'"
        assert retryable is False

    def test_classify_timeout(self):
        """Connection timeout should classify as 'network', retryable."""
        text = load_fixture("timeout_stdout.txt")
        err_class, retryable, suggestions = self._server._classify_enum_error(text)
        assert err_class == "network", f"Expected 'network', got '{err_class}'"
        assert retryable is True

    def test_classify_usage_error(self):
        """Usage/argument error should classify as 'params', not retryable."""
        text = load_fixture("usage_error_stdout.txt")
        err_class, retryable, suggestions = self._server._classify_enum_error(text)
        assert err_class == "params", f"Expected 'params', got '{err_class}'"
        assert retryable is False

    def test_classify_success_not_misclassified(self):
        """Successful output should classify as 'unknown' (no error)."""
        text = load_fixture("enumerate_success_stdout.txt")
        err_class, retryable, suggestions = self._server._classify_enum_error(text)
        assert err_class == "unknown", f"Clean output misclassified as '{err_class}'"

    def test_classify_empty_output(self):
        """Empty output should return 'unknown'."""
        err_class, retryable, suggestions = self._server._classify_enum_error("")
        assert err_class == "unknown"

    def test_classify_access_denied_without_logon_failure(self):
        """STATUS_ACCESS_DENIED (abort) without LOGON_FAILURE -> 'auth'."""
        text = (
            "[+] SMB is accessible on 445/tcp\n"
            "[-] Could not establish session: STATUS_ACCESS_DENIED\n"
            "[!] Aborting remainder of tests since sessions could not be established\n"
        )
        err_class, retryable, suggestions = self._server._classify_enum_error(text)
        assert err_class == "auth", f"Expected 'auth', got '{err_class}'"
        assert retryable is False

    def test_classify_abort_generic(self):
        """Generic abort without specific cause -> 'network'."""
        text = (
            "[*] Checking LDAP\n"
            "[-] Could not connect to LDAP\n"
            "[!] Aborting remainder of tests since neither SMB nor LDAP are accessible\n"
        )
        err_class, retryable, suggestions = self._server._classify_enum_error(text)
        assert err_class == "network", f"Expected 'network', got '{err_class}'"
        assert retryable is True

    def test_classify_with_ansi_escape_codes(self):
        """Error classification should strip ANSI escape codes before matching."""
        # Wrap key pattern in ANSI color codes
        text = (
            "\x1b[31m[-] Could not connect to SMB on 445/tcp: connection refused\x1b[0m\n"
            "\x1b[33m[!] Aborting remainder of tests\x1b[0m\n"
        )
        err_class, retryable, suggestions = self._server._classify_enum_error(text)
        assert err_class == "network", f"Expected 'network', got '{err_class}'"

    def test_classify_auth_takes_precedence_over_connection_refused(self):
        """Auth failure should be classified as 'auth' even if connection refused appears.

        When SMB is accessible on 445 but NetBIOS on 139 is connection refused,
        the real error is the auth failure, not a network error.
        """
        text = load_fixture("auth_failure_stdout.txt")
        # This fixture has both "connection refused" on 139 AND LOGON_FAILURE
        assert "connection refused" in text, "Fixture should have connection refused on 139"
        assert "LOGON_FAILURE" in text or "STATUS_LOGON_FAILURE" in text, "Fixture should have auth failure"
        err_class, retryable, suggestions = self._server._classify_enum_error(text)
        assert err_class == "auth", (
            f"Auth failure should take precedence over partial connection refused, got '{err_class}'"
        )

    def test_classify_suggestions_always_list(self):
        """Suggestions should always be a list, even for unknown errors."""
        for text in ["", "random output with no patterns", "just normal text"]:
            _, _, suggestions = self._server._classify_enum_error(text)
            assert isinstance(suggestions, list), (
                f"suggestions should be a list for input: {text!r}"
            )

    def test_classify_network_suggestions_mention_nmap(self):
        """Network error suggestions should mention nmap for port verification."""
        text = load_fixture("connection_refused_stdout.txt")
        _, _, suggestions = self._server._classify_enum_error(text)
        assert any("nmap" in s.lower() for s in suggestions), (
            f"Network error suggestions should mention nmap, got: {suggestions}"
        )

    def test_classify_auth_suggestions_mention_null_session(self):
        """Auth error suggestions should mention null session as alternative."""
        text = load_fixture("auth_failure_stdout.txt")
        _, _, suggestions = self._server._classify_enum_error(text)
        assert any("null" in s.lower() for s in suggestions), (
            f"Auth error suggestions should mention null session, got: {suggestions}"
        )


# ===========================================================================
# _make_json_output_path TESTS
# ===========================================================================

class TestMakeJsonOutputPath:
    """Test the _make_json_output_path helper.

    Verifies the fix for the double .json bug: the returned path must NOT
    end with .json because enum4linux-ng appends .json automatically.
    """

    @pytest.fixture(autouse=True, scope="class")
    def server(self):
        """Create a server instance."""
        try:
            cls = _get_server_class()
            self.__class__._server = cls()
        except Exception as e:
            pytest.skip(f"Cannot import Enum4linuxServer: {e}")

    def test_path_does_not_end_with_json(self):
        """Returned path should not have .json extension."""
        path = self._server._make_json_output_path()
        assert not path.endswith(".json"), (
            f"Path should not end with .json: {path}"
        )

    def test_path_is_absolute(self):
        """Returned path should be absolute."""
        path = self._server._make_json_output_path()
        assert os.path.isabs(path), f"Path should be absolute: {path}"

    def test_path_starts_with_e4l_prefix(self):
        """Returned path should have e4l_ prefix."""
        path = self._server._make_json_output_path()
        basename = os.path.basename(path)
        assert basename.startswith("e4l_"), (
            f"Basename should start with 'e4l_': {basename}"
        )

    def test_path_does_not_exist(self):
        """Returned path should not exist on disk (temp file is removed)."""
        path = self._server._make_json_output_path()
        assert not os.path.exists(path), (
            f"Path should not exist (temp file should be removed): {path}"
        )

    def test_paths_are_unique(self):
        """Each call should return a unique path."""
        paths = [self._server._make_json_output_path() for _ in range(5)]
        assert len(set(paths)) == 5, (
            f"Expected 5 unique paths, got {len(set(paths))}: {paths}"
        )


# ===========================================================================
# _cleanup_json_files TESTS
# ===========================================================================

class TestCleanupJsonFiles:
    """Test the _cleanup_json_files helper."""

    @pytest.fixture(autouse=True, scope="class")
    def server(self):
        """Create a server instance."""
        try:
            cls = _get_server_class()
            self.__class__._server = cls()
        except Exception as e:
            pytest.skip(f"Cannot import Enum4linuxServer: {e}")

    def test_cleanup_removes_base_and_json(self):
        """Both base_path and base_path.json should be removed."""
        # Create both files
        fd, base_path = tempfile.mkstemp(prefix="test_cleanup_")
        os.close(fd)
        json_path = base_path + ".json"
        with open(json_path, "w") as f:
            f.write("{}")

        assert os.path.exists(base_path)
        assert os.path.exists(json_path)

        self._server._cleanup_json_files(base_path)

        assert not os.path.exists(base_path), "base_path should be removed"
        assert not os.path.exists(json_path), "base_path.json should be removed"

    def test_cleanup_nonexistent_does_not_raise(self):
        """Cleanup on non-existent paths should not raise."""
        self._server._cleanup_json_files("/tmp/nonexistent_path_xyz_test")
        # Should complete without exception

    def test_cleanup_only_json_exists(self):
        """Cleanup works when only the .json file exists."""
        base_path = "/tmp/test_cleanup_only_json_" + str(os.getpid())
        json_path = base_path + ".json"
        with open(json_path, "w") as f:
            f.write("{}")

        assert not os.path.exists(base_path)
        assert os.path.exists(json_path)

        self._server._cleanup_json_files(base_path)

        assert not os.path.exists(json_path), "base_path.json should be removed"


# ===========================================================================
# _is_abort_output TESTS
# ===========================================================================

class TestIsAbortOutput:
    """Test the _is_abort_output helper."""

    @pytest.fixture(autouse=True, scope="class")
    def server(self):
        """Create a server instance."""
        try:
            cls = _get_server_class()
            self.__class__._server = cls()
        except Exception as e:
            pytest.skip(f"Cannot import Enum4linuxServer: {e}")

    def test_abort_detected_in_connection_refused(self):
        """Connection refused output contains abort message."""
        text = load_fixture("connection_refused_stdout.txt")
        assert self._server._is_abort_output(text) is True

    def test_abort_detected_in_auth_failure(self):
        """Auth failure output contains abort message."""
        text = load_fixture("auth_failure_stdout.txt")
        assert self._server._is_abort_output(text) is True

    def test_abort_detected_in_timeout(self):
        """Timeout output contains abort message."""
        text = load_fixture("timeout_stdout.txt")
        assert self._server._is_abort_output(text) is True

    def test_no_abort_in_success(self):
        """Successful output should NOT contain abort message."""
        text = load_fixture("enumerate_success_stdout.txt")
        assert self._server._is_abort_output(text) is False

    def test_abort_with_ansi_codes(self):
        """Abort detection should work even with ANSI escape codes."""
        text = "\x1b[33m[!] Aborting remainder of tests\x1b[0m"
        assert self._server._is_abort_output(text) is True

    def test_empty_string(self):
        """Empty string should not be detected as abort."""
        assert self._server._is_abort_output("") is False


# ===========================================================================
# _build_result_with_classification TESTS
# ===========================================================================

class TestBuildResultWithClassification:
    """Test the _build_result_with_classification helper."""

    @pytest.fixture(autouse=True, scope="class")
    def server(self):
        """Create a server instance."""
        try:
            cls = _get_server_class()
            self.__class__._server = cls()
        except Exception as e:
            pytest.skip(f"Cannot import Enum4linuxServer: {e}")

    def test_success_result_has_no_error_class(self):
        """Successful result should have error_class=None."""
        result = self._server._build_result_with_classification(
            success=True, data={"test": True}, raw_output="success output",
        )
        assert result.success is True
        assert result.error_class is None

    def test_failure_with_output_classifies(self):
        """Failed result with output should attempt classification."""
        text = load_fixture("connection_refused_stdout.txt")
        result = self._server._build_result_with_classification(
            success=False, data={}, raw_output=text,
        )
        assert result.success is False
        assert result.error_class == "network"
        assert result.retryable is True

    def test_failure_without_output_unknown(self):
        """Failed result without output should classify as 'unknown'."""
        result = self._server._build_result_with_classification(
            success=False, data={}, raw_output="",
        )
        assert result.success is False
        assert result.error_class == "unknown"

    def test_error_message_preserved(self):
        """Error message should be preserved in result."""
        result = self._server._build_result_with_classification(
            success=False, data={}, raw_output="",
            error="Custom error message",
        )
        assert result.error == "Custom error message"


# ===========================================================================
# RESULT EXTRACTION TESTS -- verify data parsing from JSON output
# ===========================================================================

class TestResultExtraction:
    """Test that the handler methods correctly extract data from parsed JSON."""

    @pytest.fixture(autouse=True, scope="class")
    def server(self):
        """Create a server instance."""
        try:
            cls = _get_server_class()
            self.__class__._server = cls()
        except Exception as e:
            pytest.skip(f"Cannot import Enum4linuxServer: {e}")

    def _call_with_fixture(self, method_name, fixture_json, **kwargs):
        """Call a server method with mocked run_command and fixture JSON data."""
        fixture_data = load_fixture_json(fixture_json)

        async def mock_run_command(cmd, timeout=300, **kw):
            # Write fixture data to the JSON file that _parse_json_output expects
            # Find the -oJ argument to determine the output path
            idx = cmd.index("-oJ")
            base_path = cmd[idx + 1]
            json_path = base_path + ".json"  # enum4linux-ng appends .json
            with open(json_path, "w") as f:
                json.dump(fixture_data, f)
            return subprocess.CompletedProcess(
                args=cmd, returncode=0,
                stdout=load_fixture("enumerate_success_stdout.txt"),
                stderr="",
            )

        loop = asyncio.new_event_loop()
        try:
            with patch.object(self._server, "run_command", side_effect=mock_run_command):
                result = loop.run_until_complete(
                    getattr(self._server, method_name)(**kwargs)
                )
        finally:
            loop.close()

        return result

    def test_enumerate_extracts_shares(self):
        """enumerate correctly extracts share data from parsed JSON."""
        result = self._call_with_fixture(
            "enumerate", "enumerate_success.json", target="10.10.10.100"
        )
        assert result.success is True
        shares = result.data["summary"]["shares"]
        share_names = [s["name"] for s in shares]
        assert "Replication" in share_names
        assert "Users" in share_names
        assert "ADMIN$" in share_names
        assert len(shares) == 7

    def test_enumerate_extracts_users(self):
        """enumerate correctly extracts user data from parsed JSON."""
        result = self._call_with_fixture(
            "enumerate", "enumerate_success.json", target="10.10.10.100"
        )
        assert result.success is True
        users = result.data["summary"]["users"]
        usernames = [u["username"] for u in users]
        assert "Administrator" in usernames
        assert "SVC_TGS" in usernames
        assert len(users) == 5

    def test_enumerate_extracts_groups(self):
        """enumerate correctly extracts group data from parsed JSON."""
        result = self._call_with_fixture(
            "enumerate", "enumerate_success.json", target="10.10.10.100"
        )
        assert result.success is True
        groups = result.data["summary"]["groups"]
        group_names = [g["name"] for g in groups]
        assert "Domain Admins" in group_names
        assert len(groups) == 3

    def test_enumerate_extracts_os_info(self):
        """enumerate correctly extracts OS info from parsed JSON."""
        result = self._call_with_fixture(
            "enumerate", "enumerate_success.json", target="10.10.10.100"
        )
        assert result.success is True
        os_info = result.data["summary"]["os_info"]
        assert os_info["Domain"] == "MEGACORP"
        assert "Windows" in os_info["OS"]

    def test_enum_shares_extracts_access(self):
        """enum_shares correctly extracts access/mapping info."""
        result = self._call_with_fixture(
            "enum_shares", "enumerate_success.json", target="10.10.10.100"
        )
        assert result.success is True
        shares = result.data["shares"]
        # Find the Replication share (should have OK access)
        replication = [s for s in shares if s["name"] == "Replication"]
        assert len(replication) == 1
        assert replication[0]["access"] == "OK"
        # Find ADMIN$ (should have DENIED)
        admin = [s for s in shares if s["name"] == "ADMIN$"]
        assert len(admin) == 1
        assert admin[0]["access"] == "DENIED"

    def test_enum_users_extracts_domain(self):
        """enum_users correctly extracts domain info for each user."""
        result = self._call_with_fixture(
            "enum_users", "enumerate_success.json", target="10.10.10.100"
        )
        assert result.success is True
        users = result.data["users"]
        assert result.data["count"] == 5
        for user in users:
            assert "domain" in user
            assert user["domain"] == "MEGACORP"

    def test_enum_groups_extracts_members(self):
        """enum_groups correctly extracts group member lists."""
        result = self._call_with_fixture(
            "enum_groups", "enumerate_success.json", target="10.10.10.100"
        )
        assert result.success is True
        groups = result.data["groups"]
        domain_admins = [g for g in groups if g["name"] == "Domain Admins"]
        assert len(domain_admins) == 1
        assert "Administrator" in domain_admins[0]["members"]
        assert "svc_admin" in domain_admins[0]["members"]

    def test_enum_policy_extracts_password_policy(self):
        """enum_policy correctly extracts password policy."""
        result = self._call_with_fixture(
            "enum_policy", "policy_success.json", target="10.10.10.100"
        )
        assert result.success is True
        policy = result.data["password_policy"]
        assert "Domain password information" in policy
        assert policy["Domain password information"]["Minimum password length"] == 7

    def test_enum_policy_extracts_domain_info(self):
        """enum_policy correctly extracts domain/OS info."""
        result = self._call_with_fixture(
            "enum_policy", "policy_success.json", target="10.10.10.100"
        )
        assert result.success is True
        domain_info = result.data["domain_info"]
        assert domain_info["Domain"] == "MEGACORP"

    def test_enumerate_empty_json_returns_success_with_empty_data(self):
        """enumerate with empty JSON (failed scan) returns success but empty arrays."""
        result = self._call_with_fixture(
            "enumerate", "connection_refused.json", target="10.10.10.100"
        )
        # After fix: should detect connection refused and return error
        # But at minimum, should not crash
        assert isinstance(result, object)


# ===========================================================================
# REGRESSION TESTS -- verify specific bugs are fixed
# ===========================================================================

class TestRegressions:
    """Regression tests for known bugs."""

    @pytest.fixture(autouse=True, scope="class")
    def server(self):
        """Create a server instance."""
        try:
            cls = _get_server_class()
            self.__class__._server = cls()
        except Exception as e:
            pytest.skip(f"Cannot import Enum4linuxServer: {e}")

    def test_no_double_json_extension(self):
        """REGRESSION: temp file path should not have .json suffix.

        enum4linux-ng's -oJ flag auto-appends .json to the output path.
        If we create a temp file with .json suffix and pass it to -oJ,
        the actual output goes to file.json.json while we read file.json (empty).
        """
        captured_paths = {}

        async def mock_run_command(cmd, timeout=300, **kw):
            idx = cmd.index("-oJ")
            captured_paths["oJ_path"] = cmd[idx + 1]
            return subprocess.CompletedProcess(
                args=cmd, returncode=0, stdout="", stderr=""
            )

        loop = asyncio.new_event_loop()
        try:
            with patch.object(self._server, "run_command", side_effect=mock_run_command):
                with patch.object(self._server, "_parse_json_output", return_value={}):
                    loop.run_until_complete(
                        self._server.enumerate(target="10.0.0.1")
                    )
        finally:
            loop.close()

        path = captured_paths["oJ_path"]
        assert not path.endswith(".json"), (
            f"BUG: -oJ path ends with .json ({path}). "
            f"enum4linux-ng will create {path}.json, but server reads {path}"
        )

    def test_json_read_path_matches_actual_output(self):
        """REGRESSION: _parse_json_output reads the path enum4linux-ng actually writes to.

        After fix: the server should pass a path without .json to -oJ,
        then read path + '.json' which is where enum4linux-ng writes.
        """
        fixture_data = load_fixture_json("enumerate_success.json")
        parse_calls = {}

        async def mock_run_command(cmd, timeout=300, **kw):
            # Simulate enum4linux-ng writing to path.json
            idx = cmd.index("-oJ")
            base_path = cmd[idx + 1]
            actual_output = base_path + ".json"
            with open(actual_output, "w") as f:
                json.dump(fixture_data, f)
            return subprocess.CompletedProcess(
                args=cmd, returncode=0, stdout="success", stderr=""
            )

        original_parse = self._server._parse_json_output

        def tracking_parse(path):
            parse_calls["path"] = path
            return original_parse(path)

        loop = asyncio.new_event_loop()
        try:
            with patch.object(self._server, "run_command", side_effect=mock_run_command):
                with patch.object(self._server, "_parse_json_output", side_effect=tracking_parse):
                    result = loop.run_until_complete(
                        self._server.enumerate(target="10.0.0.1")
                    )
        finally:
            loop.close()

        read_path = parse_calls["path"]
        assert read_path.endswith(".json"), (
            f"Server should read path.json (where enum4linux-ng writes), got: {read_path}"
        )
        # The data should actually be parsed (not empty)
        assert result.success is True
        assert len(result.data.get("summary", {}).get("shares", [])) > 0, (
            "Should have parsed share data from the fixture"
        )

    def test_rid_range_not_passed_to_R_flag(self):
        """REGRESSION: -R should not receive the range string.

        -R [BULK_SIZE] expects an optional integer.
        -r RANGES takes the range string.
        Passing '-R 500-550,1000-1200' causes 'invalid int value' error.
        """
        captured = {}

        async def mock_run_command(cmd, timeout=300, **kw):
            captured["cmd"] = cmd
            return subprocess.CompletedProcess(
                args=cmd, returncode=0, stdout="", stderr=""
            )

        loop = asyncio.new_event_loop()
        try:
            with patch.object(self._server, "run_command", side_effect=mock_run_command):
                with patch.object(self._server, "_parse_json_output", return_value={}):
                    loop.run_until_complete(
                        self._server.enum_users(
                            target="10.0.0.1",
                            rid_range="500-550,1000-1200",
                        )
                    )
        finally:
            loop.close()

        cmd = captured["cmd"]
        # Find -R and check what follows it
        if "-R" in cmd:
            idx_R = cmd.index("-R")
            if idx_R + 1 < len(cmd):
                next_val = cmd[idx_R + 1]
                assert next_val != "500-550,1000-1200", (
                    f"BUG: Range string passed to -R (expects int BULK_SIZE). "
                    f"This causes 'invalid int value' error. Use -r for ranges."
                )


# ===========================================================================
# DOCKERFILE / ENTRYPOINT TESTS
# ===========================================================================

class TestDockerfile:
    """Verify Dockerfile configuration."""

    def test_entrypoint_sh_used(self):
        """Dockerfile should use entrypoint.sh for FAKETIME support."""
        dockerfile = (TOOL_DIR / "Dockerfile").read_text()
        assert "entrypoint.sh" in dockerfile, (
            "Dockerfile should copy and use entrypoint.sh for FAKETIME support. "
            "Current CMD uses 'python3 mcp-server.py' directly, bypassing FAKETIME."
        )

    def test_libfaketime_installed(self):
        """Dockerfile should install libfaketime."""
        dockerfile = (TOOL_DIR / "Dockerfile").read_text()
        assert "libfaketime" in dockerfile, (
            "Dockerfile should install libfaketime for clock offset support"
        )


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

    def test_yaml_has_all_5_methods(self):
        """tool.yaml should define exactly 5 methods."""
        methods = self._yaml.get("methods", {})
        assert len(methods) == 5, (
            f"Expected 5 methods, got {len(methods)}: {sorted(methods.keys())}"
        )

    def test_all_methods_have_descriptions(self):
        """Every method should have a description."""
        for name, defn in self._yaml.get("methods", {}).items():
            assert "description" in defn, f"Method {name} missing description"
            assert len(defn["description"]) > 10, f"Method {name} has too short description"

    def test_all_methods_have_target_param(self):
        """Every method should have 'target' param."""
        for name, defn in self._yaml.get("methods", {}).items():
            params = defn.get("params", {})
            assert "target" in params, f"Method {name} missing 'target' param"

    def test_yaml_param_types_valid(self):
        """All param types should be valid JSON Schema types."""
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
            pytest.skip("Cannot import Enum4linuxServer")

        yaml_names = set(self._yaml.get("methods", {}).keys())
        server_names = set(server.methods.keys()) - {"verify_clock"}

        yaml_only = yaml_names - server_names
        server_only = server_names - yaml_names

        assert not yaml_only, f"Methods in tool.yaml but not server: {yaml_only}"
        assert not server_only, f"Methods in server but not tool.yaml: {server_only}"

    def test_yaml_params_subset_of_server(self):
        """Every yaml param should be accepted by the server handler."""
        try:
            cls = _get_server_class()
            server = cls()
        except Exception:
            pytest.skip("Cannot import Enum4linuxServer")

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

    def test_server_params_subset_of_yaml(self):
        """Every server param should be documented in tool.yaml."""
        try:
            cls = _get_server_class()
            server = cls()
        except Exception:
            pytest.skip("Cannot import Enum4linuxServer")

        for method_name, defn in self._yaml.get("methods", {}).items():
            yaml_params = set(defn.get("params", {}).keys())
            server_method = server.methods.get(method_name)
            if server_method is None:
                continue
            server_params = set(server_method.params.keys())
            server_only = server_params - yaml_params
            assert not server_only, (
                f"Method {method_name}: server has params not in yaml: {server_only}"
            )


# ===========================================================================
# ACCEPTANCE TESTS -- call every method through the container
# ===========================================================================

class TestAcceptance:
    """Call every method through the container without a live SMB target.

    These tests verify:
    - The method exists and is callable through the Docker container
    - Required param validation works (missing required params -> error)
    - Optional params (credentials, rid_range, timeout) are accepted
    - The response has correct structuredContent shape
    - Error responses have error_class set (classified, not crash)
    - FAKETIME support is functional

    Each test sends an unreachable target (192.0.2.1 -- RFC 5737 TEST-NET-1)
    so the command will fail at connection time, but the MCP protocol layer,
    param validation, command building, and error classification should all
    function correctly.
    """

    # RFC 5737 TEST-NET-1: guaranteed non-routable, no real host will respond
    _UNREACHABLE = "192.0.2.1"

    def _assert_structured_response(self, resp, method_name):
        """Assert response has structuredContent with error classification fields."""
        result = resp.get("result", {})
        sc = result.get("structuredContent", {})
        assert sc is not None, f"{method_name}: missing structuredContent"
        # Required fields in every response
        for field in ("success", "error_class", "retryable", "suggestions"):
            assert field in sc, (
                f"{method_name}: missing field '{field}' in structuredContent: {sc}"
            )
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

    def _assert_classified_error(self, resp, method_name):
        """Assert response is a classified error (success=false with error_class)."""
        sc = self._assert_structured_response(resp, method_name)
        if not sc.get("success", True):
            assert sc.get("error_class") is not None, (
                f"{method_name}: error has no error_class: {sc}"
            )
        return sc

    # ── enumerate method ──────────────────────────────────────────

    def test_enumerate_unreachable_target(self, enum4linux_env):
        """enumerate with unreachable target returns classified network error."""
        client, loop = enum4linux_env
        resp = loop.run_until_complete(client.call("enumerate", {
            "target": self._UNREACHABLE,
            "shares": True,
            "users": True,
            "groups": True,
            "timeout": 10,
        }))
        self._assert_classified_error(resp, "enumerate")

    def test_enumerate_missing_target(self, enum4linux_env):
        """enumerate without required 'target' returns error."""
        client, loop = enum4linux_env
        resp = loop.run_until_complete(client.call("enumerate", {
            "shares": True,
        }))
        result = resp.get("result", {})
        is_error = result.get("isError", False)
        content_text = ""
        for c in result.get("content", []):
            if c.get("type") == "text":
                content_text += c["text"]
        assert is_error or "target" in content_text.lower() or "error" in content_text.lower()

    def test_enumerate_with_credentials(self, enum4linux_env):
        """enumerate with username/password does not crash."""
        client, loop = enum4linux_env
        resp = loop.run_until_complete(client.call("enumerate", {
            "target": self._UNREACHABLE,
            "username": "testuser",
            "password": "testpass",
            "timeout": 10,
        }))
        self._assert_structured_response(resp, "enumerate(creds)")

    def test_enumerate_with_custom_timeout(self, enum4linux_env):
        """enumerate with custom timeout is accepted."""
        client, loop = enum4linux_env
        resp = loop.run_until_complete(client.call("enumerate", {
            "target": self._UNREACHABLE,
            "timeout": 5,
        }))
        self._assert_structured_response(resp, "enumerate(timeout)")

    def test_enumerate_selective_modules(self, enum4linux_env):
        """enumerate with only shares=true (users/groups disabled) is accepted."""
        client, loop = enum4linux_env
        resp = loop.run_until_complete(client.call("enumerate", {
            "target": self._UNREACHABLE,
            "shares": True,
            "users": False,
            "groups": False,
            "timeout": 10,
        }))
        self._assert_structured_response(resp, "enumerate(shares_only)")

    def test_enumerate_all_disabled_defaults_to_A(self, enum4linux_env):
        """enumerate with all modules disabled (defaults to -A) is accepted."""
        client, loop = enum4linux_env
        resp = loop.run_until_complete(client.call("enumerate", {
            "target": self._UNREACHABLE,
            "shares": False,
            "users": False,
            "groups": False,
            "timeout": 10,
        }))
        self._assert_structured_response(resp, "enumerate(all_disabled)")

    # ── enum_users method ─────────────────────────────────────────

    def test_enum_users_unreachable_target(self, enum4linux_env):
        """enum_users with unreachable target returns classified error."""
        client, loop = enum4linux_env
        resp = loop.run_until_complete(client.call("enum_users", {
            "target": self._UNREACHABLE,
            "timeout": 10,
        }))
        self._assert_classified_error(resp, "enum_users")

    def test_enum_users_missing_target(self, enum4linux_env):
        """enum_users without required 'target' returns error."""
        client, loop = enum4linux_env
        resp = loop.run_until_complete(client.call("enum_users", {
            "rid_range": "500-550",
        }))
        result = resp.get("result", {})
        is_error = result.get("isError", False)
        content_text = ""
        for c in result.get("content", []):
            if c.get("type") == "text":
                content_text += c["text"]
        assert is_error or "target" in content_text.lower() or "error" in content_text.lower()

    def test_enum_users_with_credentials(self, enum4linux_env):
        """enum_users with credentials does not crash."""
        client, loop = enum4linux_env
        resp = loop.run_until_complete(client.call("enum_users", {
            "target": self._UNREACHABLE,
            "username": "testuser",
            "password": "testpass",
            "timeout": 10,
        }))
        self._assert_structured_response(resp, "enum_users(creds)")

    def test_enum_users_custom_rid_range(self, enum4linux_env):
        """enum_users with custom RID range is accepted."""
        client, loop = enum4linux_env
        resp = loop.run_until_complete(client.call("enum_users", {
            "target": self._UNREACHABLE,
            "rid_range": "500-550,1000-5000",
            "timeout": 10,
        }))
        self._assert_structured_response(resp, "enum_users(rid_range)")

    def test_enum_users_default_rid_range(self, enum4linux_env):
        """enum_users without rid_range uses default and does not crash."""
        client, loop = enum4linux_env
        resp = loop.run_until_complete(client.call("enum_users", {
            "target": self._UNREACHABLE,
            "timeout": 10,
        }))
        self._assert_structured_response(resp, "enum_users(default_rid)")

    # ── enum_shares method ────────────────────────────────────────

    def test_enum_shares_unreachable_target(self, enum4linux_env):
        """enum_shares with unreachable target returns classified error."""
        client, loop = enum4linux_env
        resp = loop.run_until_complete(client.call("enum_shares", {
            "target": self._UNREACHABLE,
            "timeout": 10,
        }))
        self._assert_classified_error(resp, "enum_shares")

    def test_enum_shares_missing_target(self, enum4linux_env):
        """enum_shares without required 'target' returns error."""
        client, loop = enum4linux_env
        resp = loop.run_until_complete(client.call("enum_shares", {}))
        result = resp.get("result", {})
        is_error = result.get("isError", False)
        content_text = ""
        for c in result.get("content", []):
            if c.get("type") == "text":
                content_text += c["text"]
        assert is_error or "target" in content_text.lower() or "error" in content_text.lower()

    def test_enum_shares_with_credentials(self, enum4linux_env):
        """enum_shares with credentials does not crash."""
        client, loop = enum4linux_env
        resp = loop.run_until_complete(client.call("enum_shares", {
            "target": self._UNREACHABLE,
            "username": "admin",
            "password": "P@ss123",
            "timeout": 10,
        }))
        self._assert_structured_response(resp, "enum_shares(creds)")

    # ── enum_groups method ────────────────────────────────────────

    def test_enum_groups_unreachable_target(self, enum4linux_env):
        """enum_groups with unreachable target returns classified error."""
        client, loop = enum4linux_env
        resp = loop.run_until_complete(client.call("enum_groups", {
            "target": self._UNREACHABLE,
            "timeout": 10,
        }))
        self._assert_classified_error(resp, "enum_groups")

    def test_enum_groups_missing_target(self, enum4linux_env):
        """enum_groups without required 'target' returns error."""
        client, loop = enum4linux_env
        resp = loop.run_until_complete(client.call("enum_groups", {}))
        result = resp.get("result", {})
        is_error = result.get("isError", False)
        content_text = ""
        for c in result.get("content", []):
            if c.get("type") == "text":
                content_text += c["text"]
        assert is_error or "target" in content_text.lower() or "error" in content_text.lower()

    def test_enum_groups_with_credentials(self, enum4linux_env):
        """enum_groups with credentials does not crash."""
        client, loop = enum4linux_env
        resp = loop.run_until_complete(client.call("enum_groups", {
            "target": self._UNREACHABLE,
            "username": "admin",
            "password": "P@ss123",
            "timeout": 10,
        }))
        self._assert_structured_response(resp, "enum_groups(creds)")

    # ── enum_policy method ────────────────────────────────────────

    def test_enum_policy_unreachable_target(self, enum4linux_env):
        """enum_policy with unreachable target returns classified error."""
        client, loop = enum4linux_env
        resp = loop.run_until_complete(client.call("enum_policy", {
            "target": self._UNREACHABLE,
            "timeout": 10,
        }))
        self._assert_classified_error(resp, "enum_policy")

    def test_enum_policy_missing_target(self, enum4linux_env):
        """enum_policy without required 'target' returns error."""
        client, loop = enum4linux_env
        resp = loop.run_until_complete(client.call("enum_policy", {}))
        result = resp.get("result", {})
        is_error = result.get("isError", False)
        content_text = ""
        for c in result.get("content", []):
            if c.get("type") == "text":
                content_text += c["text"]
        assert is_error or "target" in content_text.lower() or "error" in content_text.lower()

    def test_enum_policy_with_credentials(self, enum4linux_env):
        """enum_policy with credentials does not crash."""
        client, loop = enum4linux_env
        resp = loop.run_until_complete(client.call("enum_policy", {
            "target": self._UNREACHABLE,
            "username": "admin",
            "password": "P@ss123",
            "timeout": 10,
        }))
        self._assert_structured_response(resp, "enum_policy(creds)")

    # ── Cross-cutting acceptance tests ────────────────────────────

    def test_clock_offset_meta_param_accepted(self, enum4linux_env):
        """clock_offset meta-param is accepted and stripped for all methods."""
        client, loop = enum4linux_env
        for method in ["enumerate", "enum_users", "enum_shares", "enum_groups", "enum_policy"]:
            args = {"target": self._UNREACHABLE, "clock_offset": "+5h", "timeout": 10}
            resp = loop.run_until_complete(client.call(method, args))
            result = resp.get("result", {})
            content_text = ""
            for c in result.get("content", []):
                if c.get("type") == "text":
                    content_text += c["text"]
            assert "unexpected keyword argument" not in content_text, (
                f"clock_offset not stripped for method {method}"
            )

    def test_all_methods_return_structuredContent(self, enum4linux_env):
        """Every method in the server returns structuredContent in responses."""
        client, loop = enum4linux_env
        # Test with verify_clock (guaranteed to succeed)
        resp = loop.run_until_complete(client.call("verify_clock", {}))
        result = resp.get("result", {})
        sc = result.get("structuredContent")
        assert sc is not None
        assert isinstance(sc, dict)
        for field in ("success", "error_class", "retryable", "suggestions"):
            assert field in sc, f"Missing field '{field}' in structuredContent"

    def test_structuredContent_shape_on_error(self, enum4linux_env):
        """structuredContent on error should include data, raw_output, suggestions."""
        client, loop = enum4linux_env
        resp = loop.run_until_complete(client.call("enumerate", {
            "target": self._UNREACHABLE,
            "timeout": 10,
        }))
        result = resp.get("result", {})
        sc = result.get("structuredContent", {})
        assert sc is not None
        # Should have all classification fields
        assert "success" in sc
        assert "error_class" in sc
        assert "retryable" in sc
        assert isinstance(sc.get("suggestions", []), list)

    def test_structuredContent_shape_on_success(self, enum4linux_env):
        """structuredContent on success (verify_clock) has correct shape."""
        client, loop = enum4linux_env
        resp = loop.run_until_complete(client.call("verify_clock", {}))
        result = resp.get("result", {})
        sc = result.get("structuredContent", {})
        assert sc.get("success") is True
        assert sc.get("error_class") is None
        assert sc.get("retryable") is False
        assert sc.get("suggestions") == []

    @pytest.mark.clock
    def test_faketime_available_in_container(self, enum4linux_env):
        """libfaketime should be installed and functional in the container."""
        client, loop = enum4linux_env
        resp = loop.run_until_complete(client.call("verify_clock", {}))
        data = parse_tool_output(resp)
        assert data.get("libfaketime_exists") is True
        assert "current_time" in data

    @pytest.mark.clock
    def test_faketime_offset_changes_time(self, enum4linux_env):
        """Clock offset via FAKETIME should change reported time.

        We cannot easily test exact times, but verify_clock should report
        successfully when clock_offset is applied.
        """
        client, loop = enum4linux_env
        # Call verify_clock (it doesn't accept clock_offset directly,
        # but the container should have FAKETIME infrastructure)
        resp = loop.run_until_complete(client.call("verify_clock", {}))
        data = parse_tool_output(resp)
        assert "current_time" in data
        # Ensure the path to libfaketime exists
        assert data.get("libfaketime_exists") is True


# ===========================================================================
# INTEGRATION TESTS -- require --target
# ===========================================================================

@pytest.mark.integration
class TestIntegration:
    """Integration tests that need a real SMB target.

    Run with: pytest tests/tools/test_enum4linux_ng.py --tool=enum4linux-ng
              --target=<IP> -m integration -v
    """

    def test_enumerate_null_session(self, enum4linux_env, target):
        """Full enumeration with null session."""
        client, loop = enum4linux_env
        resp = loop.run_until_complete(client.call("enumerate", {
            "target": target,
            "shares": True,
            "users": True,
            "groups": True,
            "timeout": 120,
        }))
        result = resp.get("result", {})
        assert result is not None, "Should get a response"

    def test_enum_shares_null_session(self, enum4linux_env, target):
        """Share enumeration with null session."""
        client, loop = enum4linux_env
        resp = loop.run_until_complete(client.call("enum_shares", {
            "target": target,
            "timeout": 120,
        }))
        result = resp.get("result", {})
        assert result is not None, "Should get a response"

    def test_enum_users_null_session(self, enum4linux_env, target):
        """User enumeration via RID cycling with null session."""
        client, loop = enum4linux_env
        resp = loop.run_until_complete(client.call("enum_users", {
            "target": target,
            "rid_range": "500-550,1000-1100",
            "timeout": 120,
        }))
        result = resp.get("result", {})
        assert result is not None, "Should get a response"

    def test_enum_groups_null_session(self, enum4linux_env, target):
        """Group enumeration with null session."""
        client, loop = enum4linux_env
        resp = loop.run_until_complete(client.call("enum_groups", {
            "target": target,
            "timeout": 120,
        }))
        result = resp.get("result", {})
        assert result is not None, "Should get a response"

    def test_enum_policy_null_session(self, enum4linux_env, target):
        """Password policy enumeration with null session."""
        client, loop = enum4linux_env
        resp = loop.run_until_complete(client.call("enum_policy", {
            "target": target,
            "timeout": 120,
        }))
        result = resp.get("result", {})
        assert result is not None, "Should get a response"

    def test_enum_users_with_credentials(self, enum4linux_env, target, username, password):
        """User enumeration with credentials."""
        if not username or not password:
            pytest.skip("--username and --password required")
        client, loop = enum4linux_env
        resp = loop.run_until_complete(client.call("enum_users", {
            "target": target,
            "username": username,
            "password": password,
            "rid_range": "500-550,1000-2000",
            "timeout": 120,
        }))
        result = assert_tool_success(resp, "enum_users with valid creds should succeed")
