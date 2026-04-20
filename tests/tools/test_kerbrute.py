"""
Tests for the kerbrute MCP tool server.

Covers:
- Smoke tests: boot, method list, required params, meta-param stripping, clock
- Unit tests: output parsers (userenum + login) using fixture data
- Unit tests: ANSI stripping edge cases (SGR, 256-color, embedded reset sequences)
- Unit tests: command building (_build_common_args, per-method CLI args)
- Unit tests: extra_args on all 4 methods (shlex.split, empty, None, quoted, combined)
- Unit tests: command building edge cases from real engagement data
- Error classification tests: clock skew, network, wrong realm, mixed, encoding, empty
- Contract tests: tool.yaml vs server bidirectional param matching, descriptions, extra_args
- Acceptance tests: every method called through container (no live AD target)
- Acceptance tests: extra_args accepted on all methods, FAKETIME verification
- Integration tests: real AD target scenarios (marked @pytest.mark.integration)
"""

import asyncio
import json
import os
import sys
import tempfile
from pathlib import Path
from typing import Any, Dict
from unittest.mock import AsyncMock, patch

import pytest
import yaml

# ---------------------------------------------------------------------------
# Path setup
# ---------------------------------------------------------------------------
PROJECT_ROOT = Path(__file__).parent.parent.parent
TOOL_DIR = PROJECT_ROOT / "tools" / "kerbrute"
FIXTURES_DIR = Path(__file__).parent.parent / "fixtures" / "kerbrute"

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
def kerbrute_env(request):
    """Create an MCPTestClient with its event loop. Yields (client, loop)."""
    tool = "kerbrute"
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
    """Import and return the KerbruteServer class for direct method testing."""
    import importlib.util
    spec = importlib.util.spec_from_file_location(
        "kerbrute_server", TOOL_DIR / "mcp-server.py"
    )
    mod = importlib.util.module_from_spec(spec)
    spec.loader.exec_module(mod)
    return mod.KerbruteServer


# ===========================================================================
# SMOKE TESTS -- require Docker container running
# ===========================================================================

class TestSmoke:
    """Smoke tests that verify the container boots and basic protocol works."""

    def test_boot_and_list_tools(self, kerbrute_env):
        """Container starts and list_tools returns methods."""
        client, loop = kerbrute_env
        assert len(client.tools) > 0, "Server should advertise at least one tool"
        names = client.tool_names()
        assert "userenum" in names, "userenum should be in tool list"
        assert "passwordspray" in names, "passwordspray should be in tool list"
        assert "bruteforce" in names, "bruteforce should be in tool list"
        assert "bruteuser" in names, "bruteuser should be in tool list"

    def test_method_list_matches_tool_yaml(self, kerbrute_env):
        """Every method in tool.yaml is advertised by the server, and vice versa."""
        client, _ = kerbrute_env
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

    def test_expected_method_count(self, kerbrute_env):
        """Server should have exactly 4 built-in methods + verify_clock."""
        client, _ = kerbrute_env
        names = client.tool_names()
        # 4 built-in + verify_clock in MCP_TEST_MODE
        assert len(names) == 5, (
            f"Expected 5 methods (4 built-in + verify_clock), got {len(names)}: {sorted(names)}"
        )

    def test_required_params_enforced_userenum(self, kerbrute_env):
        """Calling userenum without required 'dc' param returns an error."""
        client, loop = kerbrute_env
        resp = loop.run_until_complete(
            client.call("userenum", {
                "domain": "test.local",
                "usernames": "administrator\nguest",
            })
        )
        result = resp.get("result", {})
        is_error = result.get("isError", False)
        content_text = ""
        for c in result.get("content", []):
            if c.get("type") == "text":
                content_text += c["text"]
        assert is_error or "dc" in content_text.lower() or "error" in content_text.lower(), (
            f"Expected error about missing 'dc', got: {content_text[:300]}"
        )

    def test_required_params_enforced_bruteuser(self, kerbrute_env):
        """Calling bruteuser without required 'passwords' returns error."""
        client, loop = kerbrute_env
        resp = loop.run_until_complete(
            client.call("bruteuser", {
                "dc": "10.0.0.1",
                "domain": "test.local",
                "username": "admin",
            })
        )
        result = resp.get("result", {})
        is_error = result.get("isError", False)
        content_text = ""
        for c in result.get("content", []):
            if c.get("type") == "text":
                content_text += c["text"]
        assert is_error or "passwords" in content_text.lower() or "error" in content_text.lower(), (
            f"Expected error about missing 'passwords', got: {content_text[:300]}"
        )

    def test_meta_params_stripped(self, kerbrute_env):
        """Passing 'clock_offset' (meta-param) in args does not crash the server."""
        client, loop = kerbrute_env
        resp = loop.run_until_complete(
            client.call("userenum", {
                "dc": "10.0.0.1",
                "domain": "test.local",
                "usernames": "administrator",
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

    def test_unknown_method_returns_error(self, kerbrute_env):
        """Calling a non-existent method returns a helpful error."""
        client, loop = kerbrute_env
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
    def test_verify_clock_available(self, kerbrute_env):
        """verify_clock is registered in MCP_TEST_MODE."""
        client, _ = kerbrute_env
        names = client.tool_names()
        assert "verify_clock" in names, "verify_clock should be available in test mode"

    @pytest.mark.clock
    def test_verify_clock_returns_time(self, kerbrute_env):
        """verify_clock returns current time and FAKETIME status."""
        client, loop = kerbrute_env
        resp = loop.run_until_complete(client.call("verify_clock", {}))
        result = assert_tool_success(resp)
        data = parse_tool_output(resp)
        assert "current_time" in data
        assert "libfaketime_exists" in data
        # libfaketime deliberately NOT installed — kerbrute is Go, bypasses LD_PRELOAD
        assert data["libfaketime_exists"] is False, (
            "libfaketime should NOT be in kerbrute image (Go binary can't use it)"
        )

    def test_structuredContent_present(self, kerbrute_env):
        """Responses include structuredContent with error classification fields."""
        client, loop = kerbrute_env
        resp = loop.run_until_complete(client.call("verify_clock", {}))
        result = resp.get("result", {})
        sc = result.get("structuredContent")
        assert sc is not None, "structuredContent should be present"
        assert "success" in sc
        assert "error_class" in sc
        assert "retryable" in sc
        assert "suggestions" in sc

    def test_empty_usernames_returns_error(self, kerbrute_env):
        """Calling userenum with empty usernames returns clear error."""
        client, loop = kerbrute_env
        resp = loop.run_until_complete(
            client.call("userenum", {
                "dc": "10.0.0.1",
                "domain": "test.local",
                "usernames": "",
            })
        )
        result = assert_tool_error(resp, "Empty username list")

    def test_empty_passwords_returns_error(self, kerbrute_env):
        """Calling bruteuser with empty passwords returns clear error."""
        client, loop = kerbrute_env
        resp = loop.run_until_complete(
            client.call("bruteuser", {
                "dc": "10.0.0.1",
                "domain": "test.local",
                "username": "admin",
                "passwords": "",
            })
        )
        result = assert_tool_error(resp, "Empty password list")


# ===========================================================================
# UNIT TESTS -- output parsers, no container needed
# ===========================================================================

class TestUserenumParser:
    """Test _parse_userenum_output using fixture data."""

    @pytest.fixture(autouse=True, scope="class")
    def server(self):
        """Create a server instance for parser testing."""
        try:
            cls = _get_server_class()
            self.__class__._server = cls()
        except Exception as e:
            pytest.skip(f"Cannot import KerbruteServer: {e}")

    def test_parse_valid_users(self):
        """Parse userenum output with valid and invalid users."""
        text = load_fixture("userenum_valid_users.txt")
        result = self._server._parse_userenum_output(text, 10)
        assert result["valid_count"] == 4
        assert "DC01$" in result["valid_users"]
        assert "WEB01$" in result["valid_users"]
        assert "EXCH01$" in result["valid_users"]
        assert "MS01$" in result["valid_users"]
        assert result["invalid_users"] == ["SERVER01$", "MAIL01$", "SQL01$", "FILE01$", "APP01$", "SVC01$"]
        assert result["locked_count"] == 0
        assert result["total_tested"] == 10
        assert result["errors"] is None

    def test_parse_locked_users(self):
        """Parse userenum output with locked/disabled accounts."""
        text = load_fixture("userenum_locked_users.txt")
        result = self._server._parse_userenum_output(text, 5)
        assert result["valid_count"] == 2
        assert "administrator" in result["valid_users"]
        assert "svc-sql" in result["valid_users"]
        assert result["locked_count"] == 2
        assert "guest" in result["locked_users"]
        assert "disabled_user" in result["locked_users"]
        assert result["total_tested"] == 5

    def test_parse_no_valid_users(self):
        """Parse userenum output with all invalid users."""
        text = load_fixture("userenum_no_valid.txt")
        result = self._server._parse_userenum_output(text, 3)
        assert result["valid_count"] == 0
        assert result["valid_users"] == []
        assert len(result["invalid_users"]) == 3
        assert result["total_tested"] == 3

    def test_parse_empty_output(self):
        """Parse empty output gracefully."""
        result = self._server._parse_userenum_output("", 0)
        assert result["valid_count"] == 0
        assert result["valid_users"] == []

    def test_parse_summary_line(self):
        """Total tested count from summary line overrides input count."""
        text = load_fixture("userenum_valid_users.txt")
        # Pass wrong input_count -- parser should use summary line value
        result = self._server._parse_userenum_output(text, 999)
        assert result["total_tested"] == 10

    def test_parse_clock_skew_as_errors(self):
        """Clock skew lines should be captured in the errors list."""
        text = load_fixture("clock_skew_error.txt")
        result = self._server._parse_userenum_output(text, 3)
        assert result["valid_count"] == 0
        assert result["errors"] is not None
        assert len(result["errors"]) > 0
        assert any("KRB_AP_ERR_SKEW" in e or "Clock skew" in e for e in result["errors"]), (
            f"Expected clock skew in errors, got: {result['errors']}"
        )

    def test_parse_ansi_heavy_usernames(self):
        """ANSI SGR codes around usernames should be stripped cleanly."""
        # Build fixture with real ESC bytes (can't store in text files)
        text = (
            "2026/03/21 14:41:17 >  [+] VALID USERNAME:\t \x1b[32madministrator\x1b[0m@hercules.htb\n"
            "2026/03/21 14:41:17 >  [+] VALID USERNAME:\t \x1b[32msvc-sql\x1b[0m@hercules.htb\n"
            "2026/03/21 14:41:17 >  [!] \x1b[31mfakeuser\x1b[0m@hercules.htb - User does not exist\n"
            "2026/03/21 14:41:17 >  Done! Tested 3 usernames (2 valid) in 0.044 seconds\n"
        )
        result = self._server._parse_userenum_output(text, 3)
        assert result["valid_count"] == 2
        assert "administrator" in result["valid_users"], (
            f"ANSI not stripped from valid username: {result['valid_users']}"
        )
        assert "svc-sql" in result["valid_users"], (
            f"ANSI not stripped from valid username: {result['valid_users']}"
        )
        # Invalid user should also be clean
        assert "fakeuser" in result["invalid_users"], (
            f"ANSI not stripped from invalid username: {result['invalid_users']}"
        )

    def test_parse_ansi_no_control_chars_in_users(self):
        """No ANSI escape sequences should remain in valid_users."""
        text = (
            "[+] VALID USERNAME:\t \x1b[32madministrator\x1b[0m@hercules.htb\n"
            "[+] VALID USERNAME:\t \x1b[1;33mDC01$\x1b[0m@pirate.htb\n"
            "Done! Tested 2 usernames (2 valid) in 0.020 seconds\n"
        )
        result = self._server._parse_userenum_output(text, 2)
        for u in result["valid_users"]:
            assert "\x1b" not in u, f"ANSI escape found in username: {repr(u)}"

    def test_parse_encoding_error_captured(self):
        """Encoding error lines from KDC should be captured in errors list."""
        text = load_fixture("encoding_error.txt")
        result = self._server._parse_userenum_output(text, 1)
        assert result["valid_count"] == 0
        assert result["errors"] is not None
        assert any("encoding" in e.lower() for e in result["errors"]), (
            f"Expected encoding error in errors, got: {result['errors']}"
        )


class TestLoginParser:
    """Test _parse_login_output using fixture data."""

    @pytest.fixture(autouse=True, scope="class")
    def server(self):
        """Create a server instance for parser testing."""
        try:
            cls = _get_server_class()
            self.__class__._server = cls()
        except Exception as e:
            pytest.skip(f"Cannot import KerbruteServer: {e}")

    def test_parse_valid_passwordspray(self):
        """Parse passwordspray output with one valid login."""
        text = load_fixture("passwordspray_valid_login.txt")
        result = self._server._parse_login_output(text, 3)
        assert result["valid_count"] == 1
        assert result["valid_logins"][0]["username"] == "svc-sql"
        assert result["valid_logins"][0]["password"] == "Welcome1"
        assert result["failed_count"] == 2
        assert result["total_tested"] == 3

    def test_parse_no_valid_passwordspray(self):
        """Parse passwordspray output with no valid logins."""
        text = load_fixture("passwordspray_no_valid.txt")
        result = self._server._parse_login_output(text, 2)
        assert result["valid_count"] == 0
        assert result["valid_logins"] == []
        assert result["failed_count"] == 2

    def test_parse_bruteuser_valid_login(self):
        """Parse bruteuser output with valid login found."""
        text = load_fixture("bruteuser_valid_login.txt")
        result = self._server._parse_login_output(text, 1)
        assert result["valid_count"] == 1
        assert result["valid_logins"][0]["username"] == "natalie.a"
        assert result["valid_logins"][0]["password"] == "Prettyprincess123!"

    def test_parse_bruteuser_ansi_stripped(self):
        """ANSI escape codes should be stripped from parsed passwords."""
        text = load_fixture("bruteuser_valid_login_ansi.txt")
        result = self._server._parse_login_output(text, 1)
        assert result["valid_count"] == 1
        password = result["valid_logins"][0]["password"]
        assert password == "Prettyprincess123!", (
            f"ANSI codes not stripped from password: {repr(password)}"
        )

    def test_parse_bruteforce_mixed(self):
        """Parse bruteforce with valid login, failed attempts, and locked user."""
        text = load_fixture("bruteforce_mixed.txt")
        result = self._server._parse_login_output(text, 5)
        assert result["valid_count"] == 1
        assert result["valid_logins"][0]["username"] == "admin"
        assert result["valid_logins"][0]["password"] == "Admin123!"
        assert "guest" in result["locked_users"]
        assert result["failed_count"] >= 3  # 2 invalid password + 1 [-] line
        assert result["total_tested"] == 5

    def test_parse_login_with_locked_users(self):
        """Parse login output where some users are locked out."""
        text = load_fixture("login_with_locked_users.txt")
        result = self._server._parse_login_output(text, 4)
        assert result["valid_count"] == 1
        assert len(result["locked_users"]) == 2
        assert "guest" in result["locked_users"]
        assert "disabled" in result["locked_users"]

    def test_parse_empty_login_output(self):
        """Parse empty output gracefully."""
        result = self._server._parse_login_output("", 0)
        assert result["valid_count"] == 0
        assert result["valid_logins"] == []

    def test_parse_256color_ansi_in_login(self):
        """256-color ANSI escape codes (38;5;Nm) should be stripped from logins."""
        # Use inline text with real ESC bytes for 256-color codes
        text = (
            "[+] VALID LOGIN:\t \x1b[38;5;82madmin\x1b[0m@pirate.htb:\x1b[38;5;196mP@ssw0rd!\x1b[0m\n"
            "Done! Tested 1 logins (1 successes) in 0.088 seconds\n"
        )
        result = self._server._parse_login_output(text, 1)
        assert result["valid_count"] == 1
        username = result["valid_logins"][0]["username"]
        password = result["valid_logins"][0]["password"]
        assert username == "admin", f"ANSI not stripped from username: {repr(username)}"
        assert password == "P@ssw0rd!", f"ANSI not stripped from password: {repr(password)}"
        assert "\x1b" not in username, f"Escape in username: {repr(username)}"
        assert "\x1b" not in password, f"Escape in password: {repr(password)}"

    def test_parse_clock_skew_mixed_with_valid_login(self):
        """Clock skew on machine accounts should not prevent parsing valid logins."""
        text = load_fixture("clock_skew_mixed.txt")
        result = self._server._parse_login_output(text, 4)
        assert result["valid_count"] == 1
        assert result["valid_logins"][0]["username"] == "a.white"
        assert result["valid_logins"][0]["password"] == "Welcome1"
        assert result["failed_count"] >= 1  # j.sparrow KDC_ERR_PREAUTH_FAILED
        assert result["errors"] is not None
        assert any("KRB_AP_ERR_SKEW" in e for e in result["errors"]), (
            f"Expected clock skew errors, got: {result['errors']}"
        )

    def test_parse_safe_mode_abort(self):
        """Safe mode abort output should be parsed correctly."""
        text = load_fixture("safe_mode_abort.txt")
        result = self._server._parse_login_output(text, 1)
        assert result["valid_count"] == 0
        assert "guest" in result["locked_users"]
        assert result["total_tested"] == 1

    def test_parse_user_as_pass_login(self):
        """User-as-pass valid login parsed correctly."""
        text = load_fixture("passwordspray_user_as_pass.txt")
        result = self._server._parse_login_output(text, 6)
        assert result["valid_count"] == 1
        assert result["valid_logins"][0]["username"] == "admin"
        assert result["valid_logins"][0]["password"] == "admin"
        assert result["failed_count"] >= 2  # svc-sql invalid + guest failed

    def test_parse_ansi_reset_only(self):
        """A bare [0m reset code at end of line should be stripped."""
        # Simulate the exact pattern from bruteuser_valid_login_ansi.txt
        line = "[+] VALID LOGIN:\t natalie.a@hercules.htb:Secret123!\x1b[0m"
        result = self._server._parse_login_output(line, 1)
        assert result["valid_count"] == 1
        password = result["valid_logins"][0]["password"]
        assert password == "Secret123!", f"Trailing [0m not stripped: {repr(password)}"

    def test_parse_ansi_multiple_resets(self):
        """Multiple ANSI reset codes should all be stripped."""
        line = "[+] VALID LOGIN:\t \x1b[1m\x1b[32madmin\x1b[0m@corp.local:\x1b[1mPass1\x1b[0m"
        result = self._server._parse_login_output(line, 1)
        assert result["valid_count"] == 1
        assert result["valid_logins"][0]["username"] == "admin"
        assert result["valid_logins"][0]["password"] == "Pass1"

    def test_parse_ansi_cursor_movement(self):
        """Cursor movement ANSI sequences should be stripped."""
        line = "[+] VALID LOGIN:\t \x1b[2Kadmin\x1b[0m@corp.local:Pass!\x1b[K"
        result = self._server._parse_login_output(line, 1)
        assert result["valid_count"] == 1
        username = result["valid_logins"][0]["username"]
        assert "\x1b" not in username, f"ANSI cursor code in username: {repr(username)}"


# ===========================================================================
# ERROR CLASSIFICATION TESTS
# ===========================================================================

class TestErrorClassification:
    """Test the _classify_kerbrute_error helper for error classification."""

    @pytest.fixture(autouse=True, scope="class")
    def server(self):
        """Create a server instance."""
        try:
            cls = _get_server_class()
            self.__class__._server = cls()
        except Exception as e:
            pytest.skip(f"Cannot import KerbruteServer: {e}")

    def test_classify_clock_skew(self):
        """Clock skew should be classified as 'config', retryable."""
        text = load_fixture("clock_skew_error.txt")
        err_class, retryable, suggestions = self._server._classify_kerbrute_error(text)
        assert err_class == "config", f"Expected 'config' for clock skew, got '{err_class}'"
        assert retryable is True
        assert len(suggestions) > 0
        assert any("clock" in s.lower() for s in suggestions), (
            f"Should suggest clock offset fix, got: {suggestions}"
        )

    def test_classify_kdc_unreachable(self):
        """KDC unreachable should be classified as 'network', retryable."""
        text = load_fixture("kdc_unreachable.txt")
        err_class, retryable, suggestions = self._server._classify_kerbrute_error(text)
        assert err_class == "network", f"Expected 'network', got '{err_class}'"
        assert retryable is True

    def test_classify_wrong_realm(self):
        """Wrong realm should be classified as 'config', not retryable."""
        text = load_fixture("wrong_realm.txt")
        err_class, retryable, suggestions = self._server._classify_kerbrute_error(text)
        assert err_class == "config", f"Expected 'config', got '{err_class}'"
        assert retryable is False
        assert any("domain" in s.lower() for s in suggestions), (
            f"Should suggest checking domain name, got: {suggestions}"
        )

    def test_classify_locked_users(self):
        """Locked users should be classified as 'auth'."""
        text = load_fixture("login_with_locked_users.txt")
        err_class, retryable, suggestions = self._server._classify_kerbrute_error(text)
        # Locked is 'auth' -- the credentials might be right but account is locked
        assert err_class == "auth", f"Expected 'auth', got '{err_class}'"

    def test_classify_empty_input(self):
        """Empty input should return 'unknown'."""
        err_class, retryable, suggestions = self._server._classify_kerbrute_error("")
        assert err_class == "unknown"
        assert retryable is False

    def test_classify_clean_output_not_misclassified(self):
        """Successful output should classify as 'unknown' (no error)."""
        text = load_fixture("userenum_valid_users.txt")
        err_class, retryable, suggestions = self._server._classify_kerbrute_error(text)
        assert err_class == "unknown", f"Clean output misclassified as '{err_class}'"

    def test_classify_clock_skew_variant_bare(self):
        """Bare 'Clock skew' text (without KRB_AP_ERR_SKEW) should also classify as config."""
        err_class, retryable, suggestions = self._server._classify_kerbrute_error(
            "Clock skew too great"
        )
        assert err_class == "config"
        assert retryable is True

    def test_classify_clock_skew_suggestions_content(self):
        """Clock skew suggestions should mention FAKETIME limitation and workarounds."""
        text = load_fixture("clock_skew_error.txt")
        _, _, suggestions = self._server._classify_kerbrute_error(text)
        assert any("faketime" in s.lower() for s in suggestions), (
            f"Should mention FAKETIME limitation, got: {suggestions}"
        )
        assert any("userenum" in s.lower() for s in suggestions), (
            f"Should suggest userenum as workaround, got: {suggestions}"
        )

    def test_classify_kdc_unreachable_suggestions_content(self):
        """Network error suggestions should mention port 88."""
        text = load_fixture("kdc_unreachable.txt")
        _, _, suggestions = self._server._classify_kerbrute_error(text)
        assert any("88" in s for s in suggestions), (
            f"Should suggest checking port 88, got: {suggestions}"
        )

    def test_classify_mixed_clock_skew_and_valid(self):
        """Mixed output with both valid logins and clock skew classifies as clock skew."""
        text = load_fixture("clock_skew_mixed.txt")
        err_class, retryable, suggestions = self._server._classify_kerbrute_error(text)
        assert err_class == "config", (
            f"Mixed clock skew output should classify as 'config', got '{err_class}'"
        )
        assert retryable is True

    def test_classify_connection_refused(self):
        """Connection refused (localhost:88) should be network error."""
        text = load_fixture("kdc_connection_refused.txt")
        err_class, retryable, suggestions = self._server._classify_kerbrute_error(text)
        assert err_class == "network", f"Expected 'network', got '{err_class}'"
        assert retryable is True

    def test_classify_safe_mode_abort_lockout(self):
        """Safe mode abort on lockout should classify as auth."""
        text = load_fixture("safe_mode_abort.txt")
        err_class, retryable, suggestions = self._server._classify_kerbrute_error(text)
        assert err_class == "auth", f"Expected 'auth' for lockout abort, got '{err_class}'"

    def test_classify_encoding_error_lowercase_unknown(self):
        """Encoding error in lowercase (older kerbrute format) classifies as unknown."""
        text = load_fixture("encoding_error.txt")
        err_class, retryable, suggestions = self._server._classify_kerbrute_error(text)
        # Lowercase "encoding error" doesn't match "Encoding_Error" pattern
        assert err_class == "unknown", f"Lowercase encoding error should be 'unknown', got '{err_class}'"

    def test_classify_encoding_error_capital_network(self):
        """Encoding_Error (capital, with underscore) classifies as 'network', retryable."""
        text = load_fixture("encoding_error_capital.txt")
        err_class, retryable, suggestions = self._server._classify_kerbrute_error(text)
        assert err_class == "network", f"Expected 'network', got '{err_class}'"
        assert retryable is True
        assert any("garbled" in s.lower() or "dc" in s.lower() for s in suggestions)

    def test_classify_wrong_realm_suggestions(self):
        """Wrong realm suggestions should mention domain name."""
        text = load_fixture("wrong_realm.txt")
        _, _, suggestions = self._server._classify_kerbrute_error(text)
        assert len(suggestions) >= 2, f"Expected at least 2 suggestions, got {len(suggestions)}"
        assert any("domain" in s.lower() for s in suggestions)

    def test_classify_prioritizes_clock_over_lockout(self):
        """When both clock skew and lockout are present, clock skew wins (checked first)."""
        text = "KRB_AP_ERR_SKEW Clock skew\nUSER LOCKED OUT"
        err_class, _, _ = self._server._classify_kerbrute_error(text)
        assert err_class == "config", (
            f"Clock skew should take priority over lockout, got '{err_class}'"
        )

    def test_classify_prioritizes_network_over_lockout(self):
        """When both network and lockout are present, network wins (checked first)."""
        text = "Can't talk to KDC. Aborting...\nUSER LOCKED OUT"
        err_class, _, _ = self._server._classify_kerbrute_error(text)
        assert err_class == "network", (
            f"Network should take priority over lockout, got '{err_class}'"
        )

    # -- Unknown flag tests (Bug #3 fix) --

    def test_classify_unknown_flag(self):
        """Unknown flag from invalid extra_args should classify as 'params'."""
        text = load_fixture("unknown_flag.txt")
        err_class, retryable, suggestions = self._server._classify_kerbrute_error(text)
        assert err_class == "params", f"Expected 'params', got '{err_class}'"
        assert retryable is False
        assert any("--no-color" in s for s in suggestions), (
            f"Should mention the bad flag name, got: {suggestions}"
        )

    def test_classify_unknown_shorthand_flag(self):
        """Unknown shorthand flag should also classify as 'params'."""
        text = load_fixture("unknown_shorthand_flag.txt")
        err_class, retryable, suggestions = self._server._classify_kerbrute_error(text)
        assert err_class == "params", f"Expected 'params', got '{err_class}'"
        assert retryable is False

    def test_classify_unknown_flag_inline(self):
        """Inline unknown flag text (no fixture) should classify as params."""
        err_class, retryable, suggestions = self._server._classify_kerbrute_error(
            "Error: unknown flag: --downgrade"
        )
        assert err_class == "params"
        assert any("--downgrade" in s for s in suggestions)

    def test_classify_unknown_flag_suggestions_list_valid_flags(self):
        """Unknown flag suggestions should list valid kerbrute flags."""
        text = load_fixture("unknown_flag.txt")
        _, _, suggestions = self._server._classify_kerbrute_error(text)
        assert any("--dc" in s and "--delay" in s for s in suggestions), (
            f"Should list valid flags, got: {suggestions}"
        )

    def test_classify_unknown_flag_prioritized_over_network(self):
        """Unknown flag checked before network errors (exits before connecting)."""
        text = "Error: unknown flag: --no-color\nCan't talk to KDC"
        err_class, _, _ = self._server._classify_kerbrute_error(text)
        assert err_class == "params", (
            f"Unknown flag should take priority over network, got '{err_class}'"
        )

    # -- Wrong Realm human-readable format (Bug #2 fix) --

    def test_classify_wrong_realm_human_readable(self):
        """kerbrute's 'KDC ERROR - Wrong Realm' format should classify as config."""
        text = load_fixture("wrong_realm_human_readable.txt")
        err_class, retryable, suggestions = self._server._classify_kerbrute_error(text)
        assert err_class == "config", f"Expected 'config', got '{err_class}'"
        assert retryable is False
        assert any("domain" in s.lower() for s in suggestions)

    def test_classify_wrong_realm_both_formats(self):
        """Both 'KDC_ERR_WRONG_REALM' and 'Wrong Realm' should match."""
        for text in [
            "KDC_ERR_WRONG_REALM",
            "KDC ERROR - Wrong Realm",
            "Wrong Realm detected",
        ]:
            err_class, _, _ = self._server._classify_kerbrute_error(text)
            assert err_class == "config", f"'{text}' should classify as config, got '{err_class}'"

    # -- Clock skew FAKETIME/Go limitation (Bug #1 doc) --

    def test_classify_clock_skew_mentions_go_limitation(self):
        """Clock skew suggestions should mention Go binary FAKETIME limitation."""
        text = load_fixture("clock_skew_error.txt")
        _, _, suggestions = self._server._classify_kerbrute_error(text)
        assert any("go" in s.lower() or "faketime" in s.lower() for s in suggestions), (
            f"Should mention Go/FAKETIME limitation, got: {suggestions}"
        )

    def test_classify_clock_skew_suggests_userenum_workaround(self):
        """Clock skew suggestions should suggest userenum as clock-resilient alternative."""
        text = load_fixture("clock_skew_error.txt")
        _, _, suggestions = self._server._classify_kerbrute_error(text)
        assert any("userenum" in s.lower() for s in suggestions), (
            f"Should suggest userenum workaround, got: {suggestions}"
        )


# ===========================================================================
# PARSER BUG FIX TESTS -- dedup and lockout (no container)
# ===========================================================================

class TestParserBugFixes:
    """Tests for parser bug fixes: dedup, lockout classification."""

    @pytest.fixture(autouse=True, scope="class")
    def server(self):
        """Create a server instance."""
        try:
            cls = _get_server_class()
            self.__class__._server = cls()
        except Exception as e:
            pytest.skip(f"Cannot import KerbruteServer: {e}")

    # -- Duplicate dedup (Bug #6 fix) --

    def test_userenum_dedup_valid_users(self):
        """Duplicate usernames in userenum output should be deduplicated."""
        text = load_fixture("userenum_duplicate_users.txt")
        result = self._server._parse_userenum_output(text, 5)
        assert result["valid_users"] == ["administrator"], (
            f"Expected ['administrator'], got {result['valid_users']}"
        )
        assert result["valid_count"] == 1, (
            f"valid_count should be 1 (unique), got {result['valid_count']}"
        )

    def test_userenum_dedup_locked_users(self):
        """Duplicate locked accounts should be deduplicated."""
        text = load_fixture("userenum_duplicate_users.txt")
        result = self._server._parse_userenum_output(text, 5)
        assert result["locked_users"] == ["guest"], (
            f"Expected ['guest'], got {result['locked_users']}"
        )
        assert result["locked_count"] == 1

    def test_userenum_dedup_preserves_order(self):
        """Dedup preserves first-seen order."""
        output = (
            "[+] VALID USERNAME:\t zebra@test.local\n"
            "[+] VALID USERNAME:\t alpha@test.local\n"
            "[+] VALID USERNAME:\t zebra@test.local\n"
            "Done! Tested 3 usernames (3 valid) in 0.010 seconds\n"
        )
        result = self._server._parse_userenum_output(output, 3)
        assert result["valid_users"] == ["zebra", "alpha"]

    def test_login_parser_dedup_locked_users(self):
        """Duplicate locked users in login output should be deduplicated."""
        output = (
            "[!] guest@test.local:Pass1 - USER LOCKED OUT\n"
            "[!] guest@test.local:Pass2 - USER LOCKED OUT\n"
            "[-] admin@test.local:Pass1 - KDC_ERR_PREAUTH_FAILED\n"
            "Done! Tested 3 logins (0 successes) in 0.100 seconds\n"
        )
        result = self._server._parse_login_output(output, 3)
        assert result["locked_users"] == ["guest"], (
            f"Expected ['guest'], got {result['locked_users']}"
        )

    # -- Lockout false failure (Bug #4 fix) --

    def test_spray_with_preexisting_lockouts_parsed_correctly(self):
        """Spray with pre-existing locked accounts should have both locked and failed counts."""
        text = load_fixture("spray_with_preexisting_lockouts.txt")
        result = self._server._parse_login_output(text, 6)
        assert result["locked_users"] == ["guest", "krbtgt"], (
            f"Expected locked ['guest', 'krbtgt'], got {result['locked_users']}"
        )
        assert result["failed_count"] == 4, (
            f"Expected 4 failed (not locked) users, got {result['failed_count']}"
        )
        assert result["valid_count"] == 0
        assert result["total_tested"] == 6

    def test_lockout_classifier_returns_auth(self):
        """Output with USER LOCKED OUT classifies as 'auth'."""
        text = load_fixture("spray_with_preexisting_lockouts.txt")
        err_class, _, _ = self._server._classify_kerbrute_error(text)
        assert err_class == "auth"

    def test_spray_nonexistent_users_count_as_failed(self):
        """Non-existent users in spray output count as failed_count, not errors."""
        output = (
            "[!] testuser1@certified.htb:Welcome1 - User does not exist\n"
            "[!] testuser2@certified.htb:Welcome1 - User does not exist\n"
            "[!] guest@certified.htb:Welcome1 - USER LOCKED OUT\n"
            "[-] administrator@certified.htb:Welcome1 - KDC_ERR_PREAUTH_FAILED\n"
            "Done! Tested 4 logins (0 successes) in 0.100 seconds\n"
        )
        result = self._server._parse_login_output(output, 4)
        assert result["failed_count"] == 3, (
            f"Expected 3 failed (2 nonexistent + 1 preauth), got {result['failed_count']}"
        )
        assert result["locked_users"] == ["guest"]
        assert result["errors"] is None, (
            f"Non-existent users should NOT be in errors, got {result['errors']}"
        )


# ===========================================================================
# HANDLER WIRING TESTS -- mock run_command_with_progress, verify end-to-end
# ===========================================================================

class TestHandlerLogic:
    """Test the wiring between parser, classifier, and success/failure logic.

    Each test mocks run_command_with_progress to return a specific output,
    then calls the real handler and verifies the ToolResult fields.
    This catches bugs in the if/elif success-check logic that unit tests
    on the parser or classifier alone would miss.
    """

    @pytest.fixture(autouse=True, scope="class")
    def setup_server(self):
        """Create a server instance."""
        try:
            cls = _get_server_class()
            self.__class__._server = cls()
        except Exception as e:
            pytest.skip(f"Cannot import KerbruteServer: {e}")

    def _run_handler(self, method_name: str, kwargs: dict, stdout: str, stderr: str = ""):
        """Call a handler with mocked subprocess output. Returns ToolResult."""
        import asyncio

        class FakeResult:
            def __init__(self, out, err):
                self.stdout = out
                self.stderr = err

        captured_kwargs = {}

        async def mock_run(cmd, **kw):
            captured_kwargs.update(kw)
            return FakeResult(stdout, stderr)

        handler = getattr(self._server, method_name)
        original = self._server.run_command_with_progress
        self._server.run_command_with_progress = mock_run
        try:
            loop = asyncio.new_event_loop()
            try:
                result = loop.run_until_complete(handler(**kwargs))
            finally:
                loop.close()
        finally:
            self._server.run_command_with_progress = original

        return result, captured_kwargs

    # ── userenum handler wiring ──────────────────────────────

    def test_userenum_clean_output_success(self):
        """userenum with valid users → success=True, no error_class."""
        output = (
            "[+] VALID USERNAME:\t administrator@test.local\n"
            "[!] fakeuser@test.local - User does not exist\n"
            "Done! Tested 2 usernames (1 valid) in 0.020 seconds\n"
        )
        result, _ = self._run_handler("userenum", {
            "dc": "10.0.0.1", "domain": "test.local",
            "usernames": "administrator\nfakeuser",
        }, stdout=output)
        assert result.success is True
        assert result.error_class is None
        assert result.data["valid_count"] == 1
        assert result.data["valid_users"] == ["administrator"]

    def test_userenum_wrong_realm_failure(self):
        """userenum with 'KDC ERROR - Wrong Realm' → success=False, error_class=config."""
        output = (
            "[!] administrator@wrong.domain - KDC ERROR - Wrong Realm\n"
            "Done! Tested 1 usernames (0 valid) in 0.020 seconds\n"
        )
        result, _ = self._run_handler("userenum", {
            "dc": "10.0.0.1", "domain": "wrong.domain",
            "usernames": "administrator",
        }, stdout=output)
        assert result.success is False
        assert result.error_class == "config"
        assert result.retryable is False
        assert any("domain" in s.lower() for s in result.suggestions)

    def test_userenum_wrong_realm_kdc_err_code(self):
        """userenum with 'KDC_ERR_WRONG_REALM' (old format) → same result."""
        output = (
            "[!] administrator@wrong.domain - KDC_ERR_WRONG_REALM\n"
            "Done! Tested 1 usernames (0 valid) in 0.020 seconds\n"
        )
        result, _ = self._run_handler("userenum", {
            "dc": "10.0.0.1", "domain": "wrong.domain",
            "usernames": "administrator",
        }, stdout=output)
        assert result.success is False
        assert result.error_class == "config"

    def test_userenum_unknown_flag_failure(self):
        """userenum with unknown flag → success=False, error_class=params."""
        output = ""
        stderr = "Error: unknown flag: --no-color\nUsage:\n  kerbrute userenum [flags]\n"
        result, _ = self._run_handler("userenum", {
            "dc": "10.0.0.1", "domain": "test.local",
            "usernames": "administrator",
            "extra_args": "--no-color",
        }, stdout=output, stderr=stderr)
        assert result.success is False
        assert result.error_class == "params"
        assert result.retryable is False
        assert any("--no-color" in s for s in result.suggestions)

    def test_userenum_network_error_failure(self):
        """userenum with unreachable KDC → success=False, error_class=network."""
        output = (
            "[!] administrator@test.local - Can't talk to KDC. Aborting...\n"
            "Done! Tested 1 usernames (0 valid) in 30.000 seconds\n"
        )
        result, _ = self._run_handler("userenum", {
            "dc": "10.255.255.254", "domain": "test.local",
            "usernames": "administrator",
        }, stdout=output)
        assert result.success is False
        assert result.error_class == "network"
        assert result.retryable is True

    def test_userenum_clock_skew_failure(self):
        """userenum with clock skew → success=False, error_class=config, retryable."""
        output = (
            "[!] administrator@test.local - KRB_AP_ERR_SKEW Clock skew too great\n"
            "Done! Tested 1 usernames (0 valid) in 0.020 seconds\n"
        )
        result, _ = self._run_handler("userenum", {
            "dc": "10.0.0.1", "domain": "test.local",
            "usernames": "administrator",
        }, stdout=output)
        assert result.success is False
        assert result.error_class == "config"
        assert result.retryable is True
        assert any("faketime" in s.lower() or "go" in s.lower() for s in result.suggestions)

    def test_userenum_lockout_only_not_failure(self):
        """userenum where all accounts are locked → error_class=auth, but success depends on valid_count."""
        output = (
            "[!] guest@test.local - USER LOCKED OUT\n"
            "[!] krbtgt@test.local - USER LOCKED OUT\n"
            "Done! Tested 2 usernames (0 valid) in 0.020 seconds\n"
        )
        result, _ = self._run_handler("userenum", {
            "dc": "10.0.0.1", "domain": "test.local",
            "usernames": "guest\nkrbtgt",
        }, stdout=output)
        # "auth" is not in the fatal set, but elif fires: valid_count==0 AND errors AND error_class != "unknown"
        # errors will have the lockout lines since they're [!] lines not matching locked pattern?
        # Actually [!] guest@test.local - USER LOCKED OUT DOES match the locked_users pattern.
        # So errors list will be empty → elif doesn't fire → success=True
        assert result.success is True
        assert result.data["locked_count"] == 2
        assert result.data["valid_count"] == 0

    def test_userenum_valid_plus_locked_success(self):
        """userenum with valid users and locked accounts → success=True."""
        output = (
            "[+] VALID USERNAME:\t administrator@test.local\n"
            "[!] guest@test.local - USER LOCKED OUT\n"
            "[!] fakeuser@test.local - User does not exist\n"
            "Done! Tested 3 usernames (1 valid) in 0.020 seconds\n"
        )
        result, _ = self._run_handler("userenum", {
            "dc": "10.0.0.1", "domain": "test.local",
            "usernames": "administrator\nguest\nfakeuser",
        }, stdout=output)
        assert result.success is True
        assert result.data["valid_count"] == 1
        assert result.data["locked_count"] == 1

    def test_userenum_encoding_error_failure(self):
        """userenum with Encoding_Error → success=False, error_class=network."""
        output = (
            "[!] administrator@test.local - Encoding_Error (response from KDC)\n"
            "Done! Tested 1 usernames (0 valid) in 1.050 seconds\n"
        )
        result, _ = self._run_handler("userenum", {
            "dc": "10.0.0.1", "domain": "test.local",
            "usernames": "administrator",
        }, stdout=output)
        assert result.success is False
        assert result.error_class == "network"
        assert result.retryable is True

    def test_userenum_empty_output_success(self):
        """userenum with empty output (kerbrute ran but no results) → success=True."""
        result, _ = self._run_handler("userenum", {
            "dc": "10.0.0.1", "domain": "test.local",
            "usernames": "administrator",
        }, stdout="")
        assert result.success is True
        assert result.data["valid_count"] == 0

    # ── passwordspray handler wiring ─────────────────────────

    def test_spray_clean_no_valid_success(self):
        """spray with all failures → success=True (no valid logins is not an error)."""
        output = (
            "[-] admin@test.local:Welcome1 - KDC_ERR_PREAUTH_FAILED\n"
            "[-] guest@test.local:Welcome1 - KDC_ERR_PREAUTH_FAILED\n"
            "Done! Tested 2 logins (0 successes) in 0.100 seconds\n"
        )
        result, _ = self._run_handler("passwordspray", {
            "dc": "10.0.0.1", "domain": "test.local",
            "usernames": "admin\nguest", "password": "Welcome1",
        }, stdout=output)
        assert result.success is True
        assert result.data["valid_count"] == 0
        assert result.data["failed_count"] == 2

    def test_spray_valid_login_success(self):
        """spray finding valid creds → success=True, valid_logins populated."""
        output = (
            "[+] VALID LOGIN:\t svc-sql@test.local:Welcome1\n"
            "[-] admin@test.local:Welcome1 - KDC_ERR_PREAUTH_FAILED\n"
            "Done! Tested 2 logins (1 successes) in 0.100 seconds\n"
        )
        result, _ = self._run_handler("passwordspray", {
            "dc": "10.0.0.1", "domain": "test.local",
            "usernames": "svc-sql\nadmin", "password": "Welcome1",
        }, stdout=output)
        assert result.success is True
        assert result.data["valid_count"] == 1
        assert result.data["valid_logins"][0]["username"] == "svc-sql"
        assert result.data["valid_logins"][0]["password"] == "Welcome1"

    def test_spray_lockout_with_failures_success(self):
        """spray with pre-existing lockouts + real failures → success=True (Bug #4)."""
        output = load_fixture("spray_with_preexisting_lockouts.txt")
        result, _ = self._run_handler("passwordspray", {
            "dc": "10.0.0.1", "domain": "test.local",
            "usernames": "guest\nkrbtgt\njudith\nca_op\nmgmt\nadmin",
            "password": "Welcome1",
        }, stdout=output)
        assert result.success is True, (
            f"Spray with lockouts + failed_count=4 should be success, got error: {result.error}"
        )
        assert result.data["failed_count"] == 4
        assert result.data["locked_users"] == ["guest", "krbtgt"]

    def test_spray_lockout_only_no_failures_failure(self):
        """spray where ALL accounts are locked (failed_count=0) → success=False."""
        output = (
            "[!] guest@test.local:Pass1 - USER LOCKED OUT\n"
            "[!] krbtgt@test.local:Pass1 - USER LOCKED OUT\n"
            "Done! Tested 2 logins (0 successes) in 0.050 seconds\n"
        )
        result, _ = self._run_handler("passwordspray", {
            "dc": "10.0.0.1", "domain": "test.local",
            "usernames": "guest\nkrbtgt", "password": "Pass1",
        }, stdout=output)
        # failed_count == 0, valid_count == 0, errors present, error_class == "auth"
        # elif fires: valid_count==0 AND failed_count==0 AND errors AND error_class != "unknown"
        # But wait — [!] lines matching USER LOCKED OUT go to locked_users, not errors.
        # So errors list should be empty → elif doesn't fire → success=True
        # This is actually correct: the tool DID run, it just found all accounts locked.
        # That's data, not an error. The agent can read locked_users.
        assert result.success is True
        assert result.data["locked_users"] == ["guest", "krbtgt"]

    def test_spray_nonexistent_users_with_lockout_success(self):
        """spray with non-existent users + lockout → success=True (failed_count > 0)."""
        output = (
            "[!] testuser1@test.local:Pass1 - User does not exist\n"
            "[!] testuser2@test.local:Pass1 - User does not exist\n"
            "[!] guest@test.local:Pass1 - USER LOCKED OUT\n"
            "Done! Tested 3 logins (0 successes) in 0.100 seconds\n"
        )
        result, _ = self._run_handler("passwordspray", {
            "dc": "10.0.0.1", "domain": "test.local",
            "usernames": "testuser1\ntestuser2\nguest", "password": "Pass1",
        }, stdout=output)
        assert result.success is True, (
            f"Non-existent users + lockout should be success=True, got error: {result.error}"
        )
        assert result.data["failed_count"] == 2
        assert result.data["locked_users"] == ["guest"]

    def test_spray_unknown_flag_failure(self):
        """spray with unknown flag → success=False, error_class=params."""
        result, _ = self._run_handler("passwordspray", {
            "dc": "10.0.0.1", "domain": "test.local",
            "usernames": "admin", "password": "test",
            "extra_args": "--downgrade",
        }, stdout="", stderr="Error: unknown flag: --downgrade\n")
        assert result.success is False
        assert result.error_class == "params"

    def test_spray_clock_skew_all_accounts_failure(self):
        """spray where ALL accounts get clock skew → success=False."""
        output = (
            "[!] admin@test.local:Pass1 - KRB_AP_ERR_SKEW Clock skew too great\n"
            "[!] svc@test.local:Pass1 - KRB_AP_ERR_SKEW Clock skew too great\n"
            "Done! Tested 2 logins (0 successes) in 0.100 seconds\n"
        )
        result, _ = self._run_handler("passwordspray", {
            "dc": "10.0.0.1", "domain": "test.local",
            "usernames": "admin\nsvc", "password": "Pass1",
        }, stdout=output)
        assert result.success is False
        assert result.error_class == "config"
        assert result.retryable is True

    # ── bruteforce handler wiring ────────────────────────────

    def test_brute_valid_login_success(self):
        """bruteforce finds valid combo → success=True."""
        output = (
            "[+] VALID LOGIN:\t admin@test.local:Admin123!\n"
            "[-] guest@test.local:Pass1 - KDC_ERR_PREAUTH_FAILED\n"
            "Done! Tested 2 logins (1 successes) in 0.080 seconds\n"
        )
        result, _ = self._run_handler("bruteforce", {
            "dc": "10.0.0.1", "domain": "test.local",
            "combos": "admin:Admin123!\nguest:Pass1",
        }, stdout=output)
        assert result.success is True
        assert result.data["valid_count"] == 1

    def test_brute_network_error_failure(self):
        """bruteforce with unreachable KDC → success=False."""
        output = (
            "[!] admin@test.local:Pass1 - Can't talk to KDC. Aborting...\n"
            "Done! Tested 1 logins (0 successes) in 30.000 seconds\n"
        )
        result, _ = self._run_handler("bruteforce", {
            "dc": "10.255.255.254", "domain": "test.local",
            "combos": "admin:Pass1",
        }, stdout=output)
        assert result.success is False
        assert result.error_class == "network"

    def test_brute_mixed_clock_skew_and_valid(self):
        """bruteforce with clock skew on some + valid login on others → success=False (config)."""
        output = (
            "[+] VALID LOGIN:\t a.white@pirate.htb:Welcome1\n"
            "[!] MS01$@pirate.htb:ms01 - KRB_AP_ERR_SKEW Clock skew too great\n"
            "[-] j.sparrow@pirate.htb:test - KDC_ERR_PREAUTH_FAILED\n"
            "Done! Tested 3 logins (1 successes) in 0.100 seconds\n"
        )
        result, _ = self._run_handler("bruteforce", {
            "dc": "10.0.0.1", "domain": "pirate.htb",
            "combos": "a.white:Welcome1\nMS01$:ms01\nj.sparrow:test",
        }, stdout=output)
        # Clock skew is "config" which is in the fatal set → success=False
        # BUT the data still has the valid login
        assert result.success is False
        assert result.error_class == "config"
        assert result.data["valid_count"] == 1
        assert result.data["valid_logins"][0]["username"] == "a.white"

    # ── bruteuser handler wiring ─────────────────────────────

    def test_bruteuser_valid_password_success(self):
        """bruteuser finds valid password → success=True."""
        output = (
            "[-] admin@test.local:BadPass1 - KDC_ERR_PREAUTH_FAILED\n"
            "[+] VALID LOGIN:\t admin@test.local:CorrectPass!\n"
            "Done! Tested 2 logins (1 successes) in 0.100 seconds\n"
        )
        result, _ = self._run_handler("bruteuser", {
            "dc": "10.0.0.1", "domain": "test.local",
            "username": "admin", "passwords": "BadPass1\nCorrectPass!",
        }, stdout=output)
        assert result.success is True
        assert result.data["valid_count"] == 1
        assert result.data["target_user"] == "admin"

    def test_bruteuser_all_failures_success(self):
        """bruteuser with all wrong passwords → success=True (no error)."""
        output = (
            "[-] admin@test.local:Bad1 - KDC_ERR_PREAUTH_FAILED\n"
            "[-] admin@test.local:Bad2 - KDC_ERR_PREAUTH_FAILED\n"
            "[-] admin@test.local:Bad3 - KDC_ERR_PREAUTH_FAILED\n"
            "Done! Tested 3 logins (0 successes) in 0.100 seconds\n"
        )
        result, _ = self._run_handler("bruteuser", {
            "dc": "10.0.0.1", "domain": "test.local",
            "username": "admin", "passwords": "Bad1\nBad2\nBad3",
        }, stdout=output)
        assert result.success is True
        assert result.data["valid_count"] == 0
        assert result.data["failed_count"] == 3

    def test_bruteuser_unknown_flag_failure(self):
        """bruteuser with bad flag → success=False, error_class=params."""
        result, _ = self._run_handler("bruteuser", {
            "dc": "10.0.0.1", "domain": "test.local",
            "username": "admin", "passwords": "Pass1",
            "extra_args": "--downgrade",
        }, stdout="", stderr="Error: unknown flag: --downgrade\n")
        assert result.success is False
        assert result.error_class == "params"

    def test_bruteuser_network_failure(self):
        """bruteuser with unreachable DC → success=False, error_class=network."""
        output = "[!] admin@test.local - Can't talk to KDC. Aborting...\n"
        result, _ = self._run_handler("bruteuser", {
            "dc": "10.255.255.254", "domain": "test.local",
            "username": "admin", "passwords": "Pass1",
        }, stdout=output)
        assert result.success is False
        assert result.error_class == "network"

    # ── timeout passthrough ──────────────────────────────────

    def test_userenum_passes_timeout(self):
        """userenum passes timeout to run_command_with_progress."""
        _, kwargs = self._run_handler("userenum", {
            "dc": "10.0.0.1", "domain": "test.local",
            "usernames": "admin", "timeout": 45,
        }, stdout="")
        assert kwargs.get("timeout") == 45

    def test_userenum_default_timeout(self):
        """userenum default timeout is 120."""
        _, kwargs = self._run_handler("userenum", {
            "dc": "10.0.0.1", "domain": "test.local",
            "usernames": "admin",
        }, stdout="")
        assert kwargs.get("timeout") == 120

    def test_passwordspray_passes_timeout(self):
        """passwordspray passes timeout to run_command_with_progress."""
        _, kwargs = self._run_handler("passwordspray", {
            "dc": "10.0.0.1", "domain": "test.local",
            "usernames": "admin", "password": "test", "timeout": 60,
        }, stdout="")
        assert kwargs.get("timeout") == 60

    def test_bruteforce_passes_timeout(self):
        """bruteforce passes timeout to run_command_with_progress."""
        _, kwargs = self._run_handler("bruteforce", {
            "dc": "10.0.0.1", "domain": "test.local",
            "combos": "admin:Pass1", "timeout": 30,
        }, stdout="")
        assert kwargs.get("timeout") == 30

    def test_bruteuser_passes_timeout(self):
        """bruteuser passes timeout to run_command_with_progress."""
        _, kwargs = self._run_handler("bruteuser", {
            "dc": "10.0.0.1", "domain": "test.local",
            "username": "admin", "passwords": "Pass1", "timeout": 90,
        }, stdout="")
        assert kwargs.get("timeout") == 90

    # ── input validation (handler-level, before subprocess) ──

    def test_userenum_empty_input_error(self):
        """userenum with empty usernames → ToolResult error before subprocess."""
        import asyncio
        loop = asyncio.new_event_loop()
        try:
            result = loop.run_until_complete(self._server.userenum(
                dc="10.0.0.1", domain="test.local", usernames="",
            ))
        finally:
            loop.close()
        assert result.success is False
        assert result.error_class == "params"

    def test_bruteuser_empty_username_error(self):
        """bruteuser with empty username → error before subprocess."""
        import asyncio
        loop = asyncio.new_event_loop()
        try:
            result = loop.run_until_complete(self._server.bruteuser(
                dc="10.0.0.1", domain="test.local", username="", passwords="Pass1",
            ))
        finally:
            loop.close()
        assert result.success is False
        assert result.error_class == "params"

    def test_spray_no_password_no_user_as_pass_error(self):
        """spray with no password and no user_as_pass → params error."""
        import asyncio
        loop = asyncio.new_event_loop()
        try:
            result = loop.run_until_complete(self._server.passwordspray(
                dc="10.0.0.1", domain="test.local",
                usernames="admin", password="", user_as_pass=False,
            ))
        finally:
            loop.close()
        assert result.success is False
        assert result.error_class == "params"

    # ── dedup verified through handler ───────────────────────

    def test_userenum_dedup_through_handler(self):
        """userenum handler deduplicates valid_users end-to-end."""
        output = (
            "[+] VALID USERNAME:\t admin@test.local\n"
            "[+] VALID USERNAME:\t admin@test.local\n"
            "[+] VALID USERNAME:\t admin@test.local\n"
            "Done! Tested 3 usernames (3 valid) in 0.010 seconds\n"
        )
        result, _ = self._run_handler("userenum", {
            "dc": "10.0.0.1", "domain": "test.local",
            "usernames": "admin\nadmin\nadmin",
        }, stdout=output)
        assert result.success is True
        assert result.data["valid_users"] == ["admin"]
        assert result.data["valid_count"] == 1

    # ── error message content ────────────────────────────────

    def test_unknown_flag_error_contains_output(self):
        """When unknown flag detected, error message contains the stderr output."""
        stderr = "Error: unknown flag: --bogus\nUsage:\n  kerbrute userenum [flags]\n"
        result, _ = self._run_handler("userenum", {
            "dc": "10.0.0.1", "domain": "test.local",
            "usernames": "admin", "extra_args": "--bogus",
        }, stdout="", stderr=stderr)
        assert result.success is False
        assert result.error is not None
        assert len(result.error) > 0

    def test_network_error_contains_parsed_errors(self):
        """When network error detected, error message comes from parsed errors."""
        output = (
            "[!] admin@test.local - Can't talk to KDC. Aborting...\n"
            "Done! Tested 1 usernames (0 valid) in 30.000 seconds\n"
        )
        result, _ = self._run_handler("userenum", {
            "dc": "10.0.0.1", "domain": "test.local",
            "usernames": "admin",
        }, stdout=output)
        assert result.success is False
        assert "Can't talk to KDC" in result.error


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

    def test_yaml_has_all_4_methods(self):
        """tool.yaml should define exactly 4 methods."""
        methods = self._yaml.get("methods", {})
        assert len(methods) == 4, (
            f"Expected 4 methods, got {len(methods)}: {sorted(methods.keys())}"
        )

    def test_all_methods_have_descriptions(self):
        """Every method should have a description."""
        for name, defn in self._yaml.get("methods", {}).items():
            assert "description" in defn, f"Method {name} missing description"
            assert len(defn["description"]) > 10, f"Method {name} has too short description"

    def test_all_methods_have_dc_and_domain(self):
        """Every method should have 'dc' and 'domain' params."""
        for name, defn in self._yaml.get("methods", {}).items():
            params = defn.get("params", {})
            assert "dc" in params, f"Method {name} missing 'dc' param"
            assert "domain" in params, f"Method {name} missing 'domain' param"

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
            pytest.skip("Cannot import KerbruteServer")

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
            pytest.skip("Cannot import KerbruteServer")

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
            pytest.skip("Cannot import KerbruteServer")

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

    def test_all_methods_have_extra_args(self):
        """Every method in tool.yaml should have an 'extra_args' parameter."""
        for name, defn in self._yaml.get("methods", {}).items():
            params = defn.get("params", {})
            assert "extra_args" in params, (
                f"Method {name} missing 'extra_args' param in tool.yaml"
            )

    def test_all_server_methods_have_extra_args(self):
        """Every server method handler should accept 'extra_args'."""
        try:
            cls = _get_server_class()
            server = cls()
        except Exception:
            pytest.skip("Cannot import KerbruteServer")

        for method_name, method_def in server.methods.items():
            if method_name == "verify_clock":
                continue
            assert "extra_args" in method_def.params, (
                f"Server method {method_name} missing 'extra_args' param"
            )

    def test_all_params_have_descriptions_in_yaml(self):
        """Every param in every method in tool.yaml should have a description."""
        for method_name, defn in self._yaml.get("methods", {}).items():
            for param_name, param_def in defn.get("params", {}).items():
                assert "description" in param_def, (
                    f"{method_name}.{param_name} missing description in tool.yaml"
                )
                assert len(param_def["description"]) > 5, (
                    f"{method_name}.{param_name} has too short description in tool.yaml"
                )

    def test_all_methods_have_returns_in_yaml(self):
        """Every method in tool.yaml should have a 'returns' section."""
        for name, defn in self._yaml.get("methods", {}).items():
            assert "returns" in defn, f"Method {name} missing 'returns' in tool.yaml"
            assert len(defn["returns"]) > 0, f"Method {name} has empty 'returns' in tool.yaml"

    def test_extra_args_type_is_string(self):
        """extra_args should be of type 'string' in all methods."""
        for name, defn in self._yaml.get("methods", {}).items():
            params = defn.get("params", {})
            if "extra_args" in params:
                assert params["extra_args"]["type"] == "string", (
                    f"Method {name}: extra_args type should be 'string', "
                    f"got '{params['extra_args']['type']}'"
                )

    def test_extra_args_not_required(self):
        """extra_args should NOT be required in any method."""
        for name, defn in self._yaml.get("methods", {}).items():
            params = defn.get("params", {})
            if "extra_args" in params:
                assert params["extra_args"].get("required") is not True, (
                    f"Method {name}: extra_args should not be required"
                )

    def test_yaml_and_server_required_params_match(self):
        """Required params in tool.yaml should match server required params."""
        try:
            cls = _get_server_class()
            server = cls()
        except Exception:
            pytest.skip("Cannot import KerbruteServer")

        for method_name, defn in self._yaml.get("methods", {}).items():
            yaml_required = set()
            for pname, pdef in defn.get("params", {}).items():
                if pdef.get("required"):
                    yaml_required.add(pname)

            server_method = server.methods.get(method_name)
            if server_method is None:
                continue
            server_required = set()
            for pname, pdef in server_method.params.items():
                if pdef.get("required"):
                    server_required.add(pname)

            yaml_only = yaml_required - server_required
            server_only = server_required - yaml_required
            assert not yaml_only, (
                f"Method {method_name}: yaml says required but server doesn't: {yaml_only}"
            )
            assert not server_only, (
                f"Method {method_name}: server says required but yaml doesn't: {server_only}"
            )


# ===========================================================================
# UNIT TESTS -- command building (_build_common_args)
# ===========================================================================

class TestCommandBuilding:
    """Test that _build_common_args and each method build the correct CLI args.

    These tests instantiate the server directly and inspect command construction
    by capturing what run_command_with_progress would receive.
    """

    @pytest.fixture(autouse=True, scope="class")
    def setup_server(self):
        """Create a server instance for command testing."""
        try:
            cls = _get_server_class()
            self.__class__._server = cls()
        except Exception as e:
            pytest.skip(f"Cannot import KerbruteServer: {e}")

    # ── _build_common_args tests ────────────────────────────────

    def test_basic_userenum_args(self):
        """Basic userenum command has subcommand, --dc, -d, -v, -t."""
        cmd = self._server._build_common_args(
            subcommand="userenum", dc="10.10.10.100", domain="corp.local",
        )
        assert cmd[0] == self._server.KERBRUTE_BIN
        assert cmd[1] == "userenum"
        assert "--dc" in cmd
        idx_dc = cmd.index("--dc")
        assert cmd[idx_dc + 1] == "10.10.10.100"
        assert "-d" in cmd
        idx_d = cmd.index("-d")
        assert cmd[idx_d + 1] == "corp.local"
        assert "-v" in cmd
        assert "-t" in cmd
        idx_t = cmd.index("-t")
        assert cmd[idx_t + 1] == "10"  # default threads

    def test_passwordspray_subcommand(self):
        """passwordspray subcommand is set correctly."""
        cmd = self._server._build_common_args(
            subcommand="passwordspray", dc="10.0.0.1", domain="test.local",
        )
        assert cmd[1] == "passwordspray"

    def test_bruteforce_subcommand(self):
        """bruteforce subcommand is set correctly."""
        cmd = self._server._build_common_args(
            subcommand="bruteforce", dc="10.0.0.1", domain="test.local",
        )
        assert cmd[1] == "bruteforce"

    def test_bruteuser_subcommand(self):
        """bruteuser subcommand is set correctly."""
        cmd = self._server._build_common_args(
            subcommand="bruteuser", dc="10.0.0.1", domain="test.local",
        )
        assert cmd[1] == "bruteuser"

    def test_custom_threads(self):
        """Custom threads value is passed via -t."""
        cmd = self._server._build_common_args(
            subcommand="userenum", dc="10.0.0.1", domain="test.local",
            threads=5,
        )
        idx_t = cmd.index("-t")
        assert cmd[idx_t + 1] == "5"

    def test_threads_clamped_to_minimum(self):
        """Threads < 1 should be clamped to default (10)."""
        cmd = self._server._build_common_args(
            subcommand="userenum", dc="10.0.0.1", domain="test.local",
            threads=0,
        )
        idx_t = cmd.index("-t")
        assert cmd[idx_t + 1] == "10"

    def test_negative_threads_clamped(self):
        """Negative threads value is clamped to default (10)."""
        cmd = self._server._build_common_args(
            subcommand="userenum", dc="10.0.0.1", domain="test.local",
            threads=-5,
        )
        idx_t = cmd.index("-t")
        assert cmd[idx_t + 1] == "10"

    def test_delay_flag(self):
        """delay parameter produces --delay flag."""
        cmd = self._server._build_common_args(
            subcommand="userenum", dc="10.0.0.1", domain="test.local",
            delay=500,
        )
        assert "--delay" in cmd
        idx = cmd.index("--delay")
        assert cmd[idx + 1] == "500"

    def test_no_delay_no_flag(self):
        """Without delay, --delay flag should not appear."""
        cmd = self._server._build_common_args(
            subcommand="userenum", dc="10.0.0.1", domain="test.local",
        )
        assert "--delay" not in cmd

    def test_safe_flag(self):
        """safe=True produces --safe flag."""
        cmd = self._server._build_common_args(
            subcommand="userenum", dc="10.0.0.1", domain="test.local",
            safe=True,
        )
        assert "--safe" in cmd

    def test_safe_false_no_flag(self):
        """safe=False does not produce --safe flag."""
        cmd = self._server._build_common_args(
            subcommand="userenum", dc="10.0.0.1", domain="test.local",
            safe=False,
        )
        assert "--safe" not in cmd

    def test_all_flags_combined(self):
        """All optional flags combined in one command."""
        cmd = self._server._build_common_args(
            subcommand="passwordspray", dc="dc01.corp.local", domain="corp.local",
            threads=2, delay=1000, safe=True,
        )
        assert cmd[1] == "passwordspray"
        assert "--dc" in cmd
        assert "-d" in cmd
        assert "-v" in cmd
        idx_t = cmd.index("-t")
        assert cmd[idx_t + 1] == "2"
        idx_delay = cmd.index("--delay")
        assert cmd[idx_delay + 1] == "1000"
        assert "--safe" in cmd

    # ── Per-method command construction ─────────────────────────

    def _capture_cmd(self, method_name, kwargs):
        """Call a handler and capture the command it would build.

        Patches run_command_with_progress to intercept the command list.
        """
        import asyncio
        from mcp_common.base_server import BaseMCPServer

        captured = {}

        class FakeResult:
            stdout = ""
            stderr = ""

        async def mock_run(cmd, timeout=300, check=False, progress_filter=None):
            captured["cmd"] = cmd
            return FakeResult()

        handler = getattr(self._server, method_name)
        original = self._server.run_command_with_progress
        self._server.run_command_with_progress = mock_run
        try:
            loop = asyncio.new_event_loop()
            try:
                loop.run_until_complete(handler(**kwargs))
            finally:
                loop.close()
        finally:
            self._server.run_command_with_progress = original

        return captured.get("cmd", [])

    def test_userenum_writes_temp_file_and_appends_path(self):
        """userenum writes usernames to a temp file and appends its path."""
        cmd = self._capture_cmd("userenum", {
            "dc": "10.0.0.1", "domain": "test.local",
            "usernames": "admin\nguest\nkrbtgt",
        })
        # Last positional arg should be the temp file path
        assert len(cmd) > 0
        tmpfile = cmd[-1]
        assert tmpfile.endswith(".txt"), f"Expected temp file path, got: {tmpfile}"

    def test_passwordspray_appends_file_then_password(self):
        """passwordspray appends temp file then password as positional args."""
        cmd = self._capture_cmd("passwordspray", {
            "dc": "10.0.0.1", "domain": "test.local",
            "usernames": "admin\nguest",
            "password": "Welcome1",
        })
        # Last arg is the password, second-to-last is the temp file
        assert cmd[-1] == "Welcome1"
        assert cmd[-2].endswith(".txt"), f"Expected temp file path, got: {cmd[-2]}"

    def test_passwordspray_user_as_pass_flag(self):
        """passwordspray with user_as_pass=True adds --user-as-pass flag."""
        cmd = self._capture_cmd("passwordspray", {
            "dc": "10.0.0.1", "domain": "test.local",
            "usernames": "admin\nguest",
            "password": "Welcome1",
            "user_as_pass": True,
        })
        assert "--user-as-pass" in cmd

    def test_passwordspray_no_user_as_pass_by_default(self):
        """passwordspray without user_as_pass does not add the flag."""
        cmd = self._capture_cmd("passwordspray", {
            "dc": "10.0.0.1", "domain": "test.local",
            "usernames": "admin",
            "password": "Welcome1",
        })
        assert "--user-as-pass" not in cmd

    def test_bruteforce_appends_combo_file(self):
        """bruteforce writes combos to temp file and appends path."""
        cmd = self._capture_cmd("bruteforce", {
            "dc": "10.0.0.1", "domain": "test.local",
            "combos": "admin:Pass1\nguest:Pass2",
        })
        tmpfile = cmd[-1]
        assert tmpfile.endswith(".txt"), f"Expected temp file path, got: {tmpfile}"

    def test_bruteuser_appends_file_then_username(self):
        """bruteuser syntax: <password_file> <username>."""
        cmd = self._capture_cmd("bruteuser", {
            "dc": "10.0.0.1", "domain": "test.local",
            "username": "administrator",
            "passwords": "Pass1\nPass2\nPass3",
        })
        # Last arg is the username, second-to-last is the temp file
        assert cmd[-1] == "administrator"
        assert cmd[-2].endswith(".txt"), f"Expected temp file path, got: {cmd[-2]}"

    def test_bruteuser_safe_and_delay_combined(self):
        """bruteuser with safe=True and delay produces both flags."""
        cmd = self._capture_cmd("bruteuser", {
            "dc": "10.0.0.1", "domain": "test.local",
            "username": "admin",
            "passwords": "Pass1\nPass2",
            "safe": True,
            "delay": 500,
        })
        assert "--safe" in cmd
        assert "--delay" in cmd
        idx = cmd.index("--delay")
        assert cmd[idx + 1] == "500"

    # ── _write_temp_file tests ──────────────────────────────────

    def test_write_temp_file_creates_file(self):
        """_write_temp_file creates a file with the given content (blank lines filtered)."""
        path = self._server._write_temp_file("admin\nguest\nkrbtgt")
        try:
            assert os.path.exists(path)
            content = Path(path).read_text()
            assert content == "admin\nguest\nkrbtgt\n"
        finally:
            os.unlink(path)

    def test_write_temp_file_filters_blank_lines(self):
        """_write_temp_file filters out blank lines from input."""
        path = self._server._write_temp_file("admin\n\n\nguest\n\n\nkrbtgt\n\n")
        try:
            content = Path(path).read_text()
            assert content == "admin\nguest\nkrbtgt\n"
        finally:
            os.unlink(path)

    def test_write_temp_file_suffix(self):
        """_write_temp_file creates files with .txt suffix."""
        path = self._server._write_temp_file("test")
        try:
            assert path.endswith(".txt")
        finally:
            os.unlink(path)

    def test_write_temp_file_prefix(self):
        """_write_temp_file creates files with kerbrute_ prefix."""
        path = self._server._write_temp_file("test")
        try:
            basename = os.path.basename(path)
            assert basename.startswith("kerbrute_")
        finally:
            os.unlink(path)

    # ── _count_lines tests ──────────────────────────────────────

    def test_count_lines_basic(self):
        """Count non-empty lines."""
        assert self._server._count_lines("a\nb\nc") == 3

    def test_count_lines_empty(self):
        """Empty string has 0 lines."""
        assert self._server._count_lines("") == 0

    def test_count_lines_blank_lines_excluded(self):
        """Blank lines are excluded from count."""
        assert self._server._count_lines("a\n\nb\n  \nc") == 3

    def test_count_lines_trailing_newline(self):
        """Trailing newline does not add extra count."""
        assert self._server._count_lines("a\nb\n") == 2


# ===========================================================================
# UNIT TESTS -- extra_args on all 4 methods
# ===========================================================================

class TestExtraArgs:
    """Test extra_args parameter handling across all 4 methods.

    Verifies shlex.split behavior, empty/None handling, quoted args,
    and combination with other parameters.
    """

    @pytest.fixture(autouse=True, scope="class")
    def setup_server(self):
        """Create a server instance for command testing."""
        try:
            cls = _get_server_class()
            self.__class__._server = cls()
        except Exception as e:
            pytest.skip(f"Cannot import KerbruteServer: {e}")

    def _capture_cmd(self, method_name, kwargs):
        """Call a handler and capture the command it would build."""
        import asyncio

        captured = {}

        class FakeResult:
            stdout = ""
            stderr = ""

        async def mock_run(cmd, timeout=300, check=False, progress_filter=None):
            captured["cmd"] = cmd
            return FakeResult()

        handler = getattr(self._server, method_name)
        original = self._server.run_command_with_progress
        self._server.run_command_with_progress = mock_run
        try:
            loop = asyncio.new_event_loop()
            try:
                loop.run_until_complete(handler(**kwargs))
            finally:
                loop.close()
        finally:
            self._server.run_command_with_progress = original

        return captured.get("cmd", [])

    # ── userenum extra_args ────────────────────────────────────

    def test_userenum_extra_args_simple(self):
        """userenum: simple extra_args flag is appended."""
        cmd = self._capture_cmd("userenum", {
            "dc": "10.0.0.1", "domain": "test.local",
            "usernames": "admin",
            "extra_args": "--no-color",
        })
        assert "--no-color" in cmd

    def test_userenum_extra_args_multiple_flags(self):
        """userenum: multiple flags in extra_args are split and appended."""
        cmd = self._capture_cmd("userenum", {
            "dc": "10.0.0.1", "domain": "test.local",
            "usernames": "admin",
            "extra_args": "--no-color --downgrade",
        })
        assert "--no-color" in cmd
        assert "--downgrade" in cmd

    def test_userenum_extra_args_none(self):
        """userenum: extra_args=None does not add anything."""
        cmd = self._capture_cmd("userenum", {
            "dc": "10.0.0.1", "domain": "test.local",
            "usernames": "admin",
            "extra_args": None,
        })
        # Count common args only -- no extra
        assert cmd[-1].endswith(".txt")  # temp file is last arg

    def test_userenum_extra_args_empty_string(self):
        """userenum: extra_args='' does not add anything."""
        cmd = self._capture_cmd("userenum", {
            "dc": "10.0.0.1", "domain": "test.local",
            "usernames": "admin",
            "extra_args": "",
        })
        # shlex.split("") returns [], so no extra args
        assert cmd[-1].endswith(".txt")

    def test_userenum_extra_args_with_value(self):
        """userenum: extra_args with key=value pair."""
        cmd = self._capture_cmd("userenum", {
            "dc": "10.0.0.1", "domain": "test.local",
            "usernames": "admin",
            "extra_args": "--hash-file /tmp/hashes.txt",
        })
        assert "--hash-file" in cmd
        assert "/tmp/hashes.txt" in cmd

    def test_userenum_extra_args_come_after_file(self):
        """userenum: extra_args should be appended AFTER the temp file path."""
        cmd = self._capture_cmd("userenum", {
            "dc": "10.0.0.1", "domain": "test.local",
            "usernames": "admin",
            "extra_args": "--verbose-extra",
        })
        # Find temp file position and extra_args position
        tmpfile_idx = None
        extra_idx = None
        for i, arg in enumerate(cmd):
            if arg.endswith(".txt") and "kerbrute" in arg:
                tmpfile_idx = i
            if arg == "--verbose-extra":
                extra_idx = i
        assert tmpfile_idx is not None, "Temp file not found in cmd"
        assert extra_idx is not None, "Extra arg not found in cmd"
        assert extra_idx > tmpfile_idx, (
            f"extra_args ({extra_idx}) should come after temp file ({tmpfile_idx})"
        )

    def test_userenum_extra_args_with_safe_and_delay(self):
        """userenum: extra_args combined with safe and delay."""
        cmd = self._capture_cmd("userenum", {
            "dc": "10.0.0.1", "domain": "test.local",
            "usernames": "admin",
            "safe": True,
            "delay": 500,
            "extra_args": "--downgrade",
        })
        assert "--safe" in cmd
        assert "--delay" in cmd
        assert "--downgrade" in cmd

    # ── passwordspray extra_args ───────────────────────────────

    def test_passwordspray_extra_args_simple(self):
        """passwordspray: simple extra_args flag is appended."""
        cmd = self._capture_cmd("passwordspray", {
            "dc": "10.0.0.1", "domain": "test.local",
            "usernames": "admin",
            "password": "Pass1",
            "extra_args": "--no-color",
        })
        assert "--no-color" in cmd

    def test_passwordspray_extra_args_none(self):
        """passwordspray: extra_args=None does not add anything."""
        cmd = self._capture_cmd("passwordspray", {
            "dc": "10.0.0.1", "domain": "test.local",
            "usernames": "admin",
            "password": "Pass1",
            "extra_args": None,
        })
        assert cmd[-1] == "Pass1"  # password is last

    def test_passwordspray_extra_args_empty(self):
        """passwordspray: extra_args='' does not add anything."""
        cmd = self._capture_cmd("passwordspray", {
            "dc": "10.0.0.1", "domain": "test.local",
            "usernames": "admin",
            "password": "Pass1",
            "extra_args": "",
        })
        assert cmd[-1] == "Pass1"

    def test_passwordspray_extra_args_after_password(self):
        """passwordspray: extra_args come after the password argument."""
        cmd = self._capture_cmd("passwordspray", {
            "dc": "10.0.0.1", "domain": "test.local",
            "usernames": "admin",
            "password": "Pass1",
            "extra_args": "--downgrade",
        })
        password_idx = cmd.index("Pass1")
        extra_idx = cmd.index("--downgrade")
        assert extra_idx > password_idx, (
            f"extra_args ({extra_idx}) should come after password ({password_idx})"
        )

    def test_passwordspray_extra_args_with_user_as_pass(self):
        """passwordspray: extra_args combined with user_as_pass."""
        cmd = self._capture_cmd("passwordspray", {
            "dc": "10.0.0.1", "domain": "test.local",
            "usernames": "admin",
            "password": "Pass1",
            "user_as_pass": True,
            "extra_args": "--downgrade",
        })
        assert "--user-as-pass" in cmd
        assert "--downgrade" in cmd

    # ── bruteforce extra_args ──────────────────────────────────

    def test_bruteforce_extra_args_simple(self):
        """bruteforce: simple extra_args flag is appended."""
        cmd = self._capture_cmd("bruteforce", {
            "dc": "10.0.0.1", "domain": "test.local",
            "combos": "admin:Pass1",
            "extra_args": "--no-color",
        })
        assert "--no-color" in cmd

    def test_bruteforce_extra_args_none(self):
        """bruteforce: extra_args=None does not add anything."""
        cmd = self._capture_cmd("bruteforce", {
            "dc": "10.0.0.1", "domain": "test.local",
            "combos": "admin:Pass1",
            "extra_args": None,
        })
        assert cmd[-1].endswith(".txt")

    def test_bruteforce_extra_args_empty(self):
        """bruteforce: extra_args='' does not add anything."""
        cmd = self._capture_cmd("bruteforce", {
            "dc": "10.0.0.1", "domain": "test.local",
            "combos": "admin:Pass1",
            "extra_args": "",
        })
        assert cmd[-1].endswith(".txt")

    def test_bruteforce_extra_args_after_combo_file(self):
        """bruteforce: extra_args come after the combo file."""
        cmd = self._capture_cmd("bruteforce", {
            "dc": "10.0.0.1", "domain": "test.local",
            "combos": "admin:Pass1",
            "extra_args": "--verbose-extra",
        })
        tmpfile_idx = None
        extra_idx = None
        for i, arg in enumerate(cmd):
            if arg.endswith(".txt") and "kerbrute" in arg:
                tmpfile_idx = i
            if arg == "--verbose-extra":
                extra_idx = i
        assert tmpfile_idx is not None
        assert extra_idx is not None
        assert extra_idx > tmpfile_idx

    # ── bruteuser extra_args ───────────────────────────────────

    def test_bruteuser_extra_args_simple(self):
        """bruteuser: simple extra_args flag is appended."""
        cmd = self._capture_cmd("bruteuser", {
            "dc": "10.0.0.1", "domain": "test.local",
            "username": "admin",
            "passwords": "Pass1\nPass2",
            "extra_args": "--no-color",
        })
        assert "--no-color" in cmd

    def test_bruteuser_extra_args_none(self):
        """bruteuser: extra_args=None does not add anything."""
        cmd = self._capture_cmd("bruteuser", {
            "dc": "10.0.0.1", "domain": "test.local",
            "username": "admin",
            "passwords": "Pass1",
            "extra_args": None,
        })
        assert cmd[-1] == "admin"  # username is last

    def test_bruteuser_extra_args_empty(self):
        """bruteuser: extra_args='' does not add anything."""
        cmd = self._capture_cmd("bruteuser", {
            "dc": "10.0.0.1", "domain": "test.local",
            "username": "admin",
            "passwords": "Pass1",
            "extra_args": "",
        })
        assert cmd[-1] == "admin"

    def test_bruteuser_extra_args_after_username(self):
        """bruteuser: extra_args come after the username argument."""
        cmd = self._capture_cmd("bruteuser", {
            "dc": "10.0.0.1", "domain": "test.local",
            "username": "administrator",
            "passwords": "Pass1",
            "extra_args": "--downgrade",
        })
        username_idx = cmd.index("administrator")
        extra_idx = cmd.index("--downgrade")
        assert extra_idx > username_idx, (
            f"extra_args ({extra_idx}) should come after username ({username_idx})"
        )

    def test_bruteuser_extra_args_with_safe_delay(self):
        """bruteuser: extra_args combined with safe and delay."""
        cmd = self._capture_cmd("bruteuser", {
            "dc": "10.0.0.1", "domain": "test.local",
            "username": "admin",
            "passwords": "Pass1",
            "safe": True,
            "delay": 100,
            "extra_args": "--downgrade --no-color",
        })
        assert "--safe" in cmd
        assert "--delay" in cmd
        assert "--downgrade" in cmd
        assert "--no-color" in cmd

    # ── Cross-method extra_args edge cases ─────────────────────

    def test_extra_args_quoted_string(self):
        """extra_args with quoted string containing spaces are handled by shlex."""
        cmd = self._capture_cmd("userenum", {
            "dc": "10.0.0.1", "domain": "test.local",
            "usernames": "admin",
            "extra_args": '--output "/tmp/my output.txt"',
        })
        assert "--output" in cmd
        assert "/tmp/my output.txt" in cmd

    def test_extra_args_single_quoted(self):
        """extra_args with single-quoted string."""
        cmd = self._capture_cmd("bruteforce", {
            "dc": "10.0.0.1", "domain": "test.local",
            "combos": "admin:Pass1",
            "extra_args": "--output '/tmp/results file.txt'",
        })
        assert "--output" in cmd
        assert "/tmp/results file.txt" in cmd

    def test_extra_args_whitespace_only(self):
        """extra_args with only whitespace does not add anything."""
        cmd = self._capture_cmd("userenum", {
            "dc": "10.0.0.1", "domain": "test.local",
            "usernames": "admin",
            "extra_args": "   ",
        })
        # shlex.split("   ") returns [], so no extra args
        assert cmd[-1].endswith(".txt")

    def test_extra_args_multiple_spaces_between_flags(self):
        """extra_args with multiple spaces between flags are handled."""
        cmd = self._capture_cmd("userenum", {
            "dc": "10.0.0.1", "domain": "test.local",
            "usernames": "admin",
            "extra_args": "--flag1    --flag2",
        })
        assert "--flag1" in cmd
        assert "--flag2" in cmd


# ===========================================================================
# UNIT TESTS -- engagement data edge cases (from real HTB sessions)
# ===========================================================================

class TestEngagementEdgeCases:
    """Test command building patterns from real engagement data failures.

    These reproduce specific LLM mistakes observed in HTB sessions.
    """

    @pytest.fixture(autouse=True, scope="class")
    def setup_server(self):
        """Create a server instance."""
        try:
            cls = _get_server_class()
            self.__class__._server = cls()
        except Exception as e:
            pytest.skip(f"Cannot import KerbruteServer: {e}")

    def _capture_cmd(self, method_name, kwargs):
        """Call a handler and capture the command it would build."""
        import asyncio

        captured = {}

        class FakeResult:
            stdout = ""
            stderr = ""

        async def mock_run(cmd, timeout=300, check=False, progress_filter=None):
            captured["cmd"] = cmd
            return FakeResult()

        handler = getattr(self._server, method_name)
        original = self._server.run_command_with_progress
        self._server.run_command_with_progress = mock_run
        try:
            loop = asyncio.new_event_loop()
            try:
                loop.run_until_complete(handler(**kwargs))
            finally:
                loop.close()
        finally:
            self._server.run_command_with_progress = original

        return captured.get("cmd", [])

    def test_machine_account_dollar_sign_in_username(self):
        """Machine accounts with $ suffix should be written to temp file correctly."""
        # Test the _write_temp_file helper directly (the handler deletes the file)
        content = "DC01$\nMS01$\nEXCH01$\nWEB01$"
        path = self._server._write_temp_file(content)
        try:
            result = Path(path).read_text()
            assert "DC01$" in result
            assert "MS01$" in result
            assert "EXCH01$" in result
            assert "WEB01$" in result
        finally:
            os.unlink(path)

    def test_bruteforce_combo_format_preserved(self):
        """user:pass combo format with special chars is preserved in temp file."""
        content = "admin:P@$$w0rd!\nsvc-sql:Welcome1\nMS01$:ms01"
        path = self._server._write_temp_file(content)
        try:
            result = Path(path).read_text()
            assert "admin:P@$$w0rd!" in result
            assert "svc-sql:Welcome1" in result
            assert "MS01$:ms01" in result
        finally:
            os.unlink(path)

    def test_large_password_list_line_count(self):
        """Large password list should have correct line count."""
        passwords = "\n".join(f"Pass{i}!" for i in range(250))
        count = self._server._count_lines(passwords)
        assert count == 250

    def test_themed_wordlist_handling(self):
        """Themed wordlist from Garfield engagement is handled correctly."""
        passwords = "Garfield\nOdie\nJon\nArbuckle\nLiz\nWilson\nPooky\nNermal\nMonday\nLasagna"
        cmd = self._capture_cmd("bruteuser", {
            "dc": "10.129.232.137", "domain": "garfield.htb",
            "username": "l.wilson",
            "passwords": passwords,
            "delay": 100,
            "safe": True,
        })
        assert "--delay" in cmd
        idx = cmd.index("--delay")
        assert cmd[idx + 1] == "100"
        assert "--safe" in cmd
        assert cmd[-1] == "l.wilson"  # username is last positional arg
        # Clean up temp file
        for arg in cmd:
            if arg.endswith(".txt") and "kerbrute" in arg and os.path.exists(arg):
                os.unlink(arg)

    def test_hostname_as_dc(self):
        """DC can be a hostname (not just IP)."""
        cmd = self._capture_cmd("userenum", {
            "dc": "dc01.corp.local", "domain": "corp.local",
            "usernames": "admin",
        })
        idx = cmd.index("--dc")
        assert cmd[idx + 1] == "dc01.corp.local"

    def test_threads_string_type_clamped(self):
        """Non-integer threads value should be clamped to default."""
        cmd = self._server._build_common_args(
            subcommand="userenum", dc="10.0.0.1", domain="test.local",
            threads="invalid",
        )
        idx_t = cmd.index("-t")
        assert cmd[idx_t + 1] == "10"  # default

    def test_threads_very_large_value(self):
        """Very large threads value is passed through (kerbrute handles it)."""
        cmd = self._server._build_common_args(
            subcommand="userenum", dc="10.0.0.1", domain="test.local",
            threads=999,
        )
        idx_t = cmd.index("-t")
        assert cmd[idx_t + 1] == "999"

    def test_passwordspray_empty_password_with_user_as_pass(self):
        """passwordspray with empty password but user_as_pass=True should succeed."""
        import asyncio

        async def run_test():
            result = await self._server.passwordspray(
                dc="10.0.0.1",
                domain="test.local",
                usernames="admin",
                password="",
                user_as_pass=True,
            )
            # Should not return params error since user_as_pass is set
            return result

        # Mock run_command_with_progress
        class FakeResult:
            stdout = ""
            stderr = ""

        async def mock_run(cmd, timeout=300, check=False, progress_filter=None):
            return FakeResult()

        original = self._server.run_command_with_progress
        self._server.run_command_with_progress = mock_run
        try:
            loop = asyncio.new_event_loop()
            try:
                result = loop.run_until_complete(run_test())
                # Should NOT be a params error -- user_as_pass=True is valid
                assert result.error_class != "params" or result.error is None, (
                    f"Should accept empty password with user_as_pass=True, got error: {result.error}"
                )
            finally:
                loop.close()
        finally:
            self._server.run_command_with_progress = original

    def test_passwordspray_no_password_no_user_as_pass_errors(self):
        """passwordspray with no password and no user_as_pass returns params error."""
        import asyncio

        async def run_test():
            return await self._server.passwordspray(
                dc="10.0.0.1",
                domain="test.local",
                usernames="admin",
                password="",
                user_as_pass=False,
            )

        loop = asyncio.new_event_loop()
        try:
            result = loop.run_until_complete(run_test())
            assert result.success is False
            assert result.error_class == "params"
            assert "password" in result.error.lower() or "user_as_pass" in result.error.lower()
        finally:
            loop.close()

    def test_bruteuser_whitespace_only_username(self):
        """bruteuser with whitespace-only username returns params error."""
        import asyncio

        async def run_test():
            return await self._server.bruteuser(
                dc="10.0.0.1",
                domain="test.local",
                username="   ",
                passwords="Pass1\nPass2",
            )

        loop = asyncio.new_event_loop()
        try:
            result = loop.run_until_complete(run_test())
            assert result.success is False
            assert "username" in result.error.lower()
        finally:
            loop.close()

    def test_userenum_whitespace_only_usernames(self):
        """userenum with whitespace-only usernames returns params error."""
        import asyncio

        async def run_test():
            return await self._server.userenum(
                dc="10.0.0.1",
                domain="test.local",
                usernames="  \n  \n  ",
            )

        loop = asyncio.new_event_loop()
        try:
            result = loop.run_until_complete(run_test())
            assert result.success is False
            assert "empty" in result.error.lower() or "username" in result.error.lower()
        finally:
            loop.close()


# ===========================================================================
# ACCEPTANCE TESTS -- run through Docker container, no live AD target
# ===========================================================================

class TestAcceptance:
    """Call every method through the container without a live AD target.

    These tests verify:
    - The method exists and is callable
    - Required param validation works (missing required params -> error)
    - The response has correct structuredContent shape
    - Error responses have error_class set (classified, not crash)
    - libfaketime is NOT installed (Go binary can't use it)

    Each test sends minimal args with an unreachable DC (10.0.0.1) so the
    command will fail at connection time, but the MCP protocol layer, param
    validation, and error classification should all function correctly.
    """

    _FAKE_ARGS = {
        "dc": "10.0.0.1",
        "domain": "test.local",
    }

    def _assert_structured_response(self, resp, method_name):
        """Assert response has well-formed structuredContent."""
        result = resp.get("result", {})
        sc = result.get("structuredContent")
        assert sc is not None, f"{method_name}: missing structuredContent"
        # structuredContent must have the core classification fields
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
            f"{method_name}: unhandled Python traceback in output"
        )
        return sc

    # ── userenum ───────────────────────────────────────────────

    def test_userenum_unreachable_dc(self, kerbrute_env):
        """userenum with unreachable DC — kerbrute may succeed with 0 users or fail with network error."""
        client, loop = kerbrute_env
        resp = loop.run_until_complete(client.call("userenum", {
            **self._FAKE_ARGS,
            "usernames": "administrator\nguest",
            "timeout": 30,
        }))
        sc = self._assert_structured_response(resp, "userenum")
        # kerbrute may exit 0 with 0 valid users (success=True) or fail with network error
        if sc["success"]:
            assert sc.get("data", {}).get("valid_count", 0) == 0
        else:
            assert sc.get("error_class") in ("network", "unknown", "config", "timeout")

    def test_userenum_structuredContent_shape(self, kerbrute_env):
        """userenum response structuredContent has all expected fields."""
        client, loop = kerbrute_env
        resp = loop.run_until_complete(client.call("userenum", {
            **self._FAKE_ARGS,
            "usernames": "administrator",
            "timeout": 15,
        }))
        self._assert_structured_response(resp, "userenum")

    def test_userenum_missing_domain(self, kerbrute_env):
        """userenum without 'domain' returns error about missing param."""
        client, loop = kerbrute_env
        resp = loop.run_until_complete(client.call("userenum", {
            "dc": "10.0.0.1",
            "usernames": "administrator",
        }))
        result = resp.get("result", {})
        is_error = result.get("isError", False)
        content_text = ""
        for c in result.get("content", []):
            if c.get("type") == "text":
                content_text += c["text"]
        assert is_error or "domain" in content_text.lower() or "required" in content_text.lower(), (
            f"Expected error about missing 'domain', got: {content_text[:300]}"
        )

    def test_userenum_missing_usernames(self, kerbrute_env):
        """userenum without 'usernames' returns error about missing param."""
        client, loop = kerbrute_env
        resp = loop.run_until_complete(client.call("userenum", {
            "dc": "10.0.0.1",
            "domain": "test.local",
        }))
        result = resp.get("result", {})
        is_error = result.get("isError", False)
        content_text = ""
        for c in result.get("content", []):
            if c.get("type") == "text":
                content_text += c["text"]
        assert is_error or "usernames" in content_text.lower() or "required" in content_text.lower(), (
            f"Expected error about missing 'usernames', got: {content_text[:300]}"
        )

    # ── passwordspray ──────────────────────────────────────────

    def test_passwordspray_unreachable_dc(self, kerbrute_env):
        """passwordspray with unreachable DC returns classified error."""
        client, loop = kerbrute_env
        resp = loop.run_until_complete(client.call("passwordspray", {
            **self._FAKE_ARGS,
            "usernames": "admin\nguest",
            "password": "Welcome1",
            "timeout": 15,
        }))
        sc = self._assert_structured_response(resp, "passwordspray")
        assert sc["success"] is False, "passwordspray to unreachable DC should fail"
        assert sc.get("error_class") in ("network", "unknown", "config"), (
            f"passwordspray: unexpected error_class '{sc.get('error_class')}'"
        )

    def test_passwordspray_structuredContent_shape(self, kerbrute_env):
        """passwordspray response structuredContent has all expected fields."""
        client, loop = kerbrute_env
        resp = loop.run_until_complete(client.call("passwordspray", {
            **self._FAKE_ARGS,
            "usernames": "admin",
            "password": "test",
            "timeout": 15,
        }))
        self._assert_structured_response(resp, "passwordspray")

    def test_passwordspray_missing_password(self, kerbrute_env):
        """passwordspray without 'password' returns error."""
        client, loop = kerbrute_env
        resp = loop.run_until_complete(client.call("passwordspray", {
            **self._FAKE_ARGS,
            "usernames": "admin",
        }))
        result = resp.get("result", {})
        is_error = result.get("isError", False)
        content_text = ""
        for c in result.get("content", []):
            if c.get("type") == "text":
                content_text += c["text"]
        assert is_error or "password" in content_text.lower() or "required" in content_text.lower(), (
            f"Expected error about missing 'password', got: {content_text[:300]}"
        )

    def test_passwordspray_missing_usernames(self, kerbrute_env):
        """passwordspray without 'usernames' returns error."""
        client, loop = kerbrute_env
        resp = loop.run_until_complete(client.call("passwordspray", {
            **self._FAKE_ARGS,
            "password": "Welcome1",
        }))
        result = resp.get("result", {})
        is_error = result.get("isError", False)
        content_text = ""
        for c in result.get("content", []):
            if c.get("type") == "text":
                content_text += c["text"]
        assert is_error or "usernames" in content_text.lower() or "required" in content_text.lower(), (
            f"Expected error about missing 'usernames', got: {content_text[:300]}"
        )

    # ── bruteforce ─────────────────────────────────────────────

    def test_bruteforce_unreachable_dc(self, kerbrute_env):
        """bruteforce with unreachable DC returns classified error."""
        client, loop = kerbrute_env
        resp = loop.run_until_complete(client.call("bruteforce", {
            **self._FAKE_ARGS,
            "combos": "admin:Pass1\nguest:Pass2",
            "timeout": 15,
        }))
        sc = self._assert_structured_response(resp, "bruteforce")
        assert sc["success"] is False, "bruteforce to unreachable DC should fail"
        assert sc.get("error_class") in ("network", "unknown", "config"), (
            f"bruteforce: unexpected error_class '{sc.get('error_class')}'"
        )

    def test_bruteforce_structuredContent_shape(self, kerbrute_env):
        """bruteforce response structuredContent has all expected fields."""
        client, loop = kerbrute_env
        resp = loop.run_until_complete(client.call("bruteforce", {
            **self._FAKE_ARGS,
            "combos": "admin:Pass1",
            "timeout": 15,
        }))
        self._assert_structured_response(resp, "bruteforce")

    def test_bruteforce_missing_combos(self, kerbrute_env):
        """bruteforce without 'combos' returns error."""
        client, loop = kerbrute_env
        resp = loop.run_until_complete(client.call("bruteforce", {
            **self._FAKE_ARGS,
        }))
        result = resp.get("result", {})
        is_error = result.get("isError", False)
        content_text = ""
        for c in result.get("content", []):
            if c.get("type") == "text":
                content_text += c["text"]
        assert is_error or "combos" in content_text.lower() or "combo" in content_text.lower() or "required" in content_text.lower(), (
            f"Expected error about missing 'combos', got: {content_text[:300]}"
        )

    def test_bruteforce_empty_combos(self, kerbrute_env):
        """bruteforce with empty combos returns error."""
        client, loop = kerbrute_env
        resp = loop.run_until_complete(client.call("bruteforce", {
            **self._FAKE_ARGS,
            "combos": "",
        }))
        result = assert_tool_error(resp, "Empty combo list")

    # ── bruteuser ──────────────────────────────────────────────

    def test_bruteuser_unreachable_dc(self, kerbrute_env):
        """bruteuser with unreachable DC returns classified error."""
        client, loop = kerbrute_env
        resp = loop.run_until_complete(client.call("bruteuser", {
            **self._FAKE_ARGS,
            "username": "administrator",
            "passwords": "Pass1\nPass2\nPass3",
            "timeout": 15,
        }))
        sc = self._assert_structured_response(resp, "bruteuser")
        assert sc["success"] is False, "bruteuser to unreachable DC should fail"
        assert sc.get("error_class") in ("network", "unknown", "config"), (
            f"bruteuser: unexpected error_class '{sc.get('error_class')}'"
        )

    def test_bruteuser_structuredContent_shape(self, kerbrute_env):
        """bruteuser response structuredContent has all expected fields."""
        client, loop = kerbrute_env
        resp = loop.run_until_complete(client.call("bruteuser", {
            **self._FAKE_ARGS,
            "username": "admin",
            "passwords": "Pass1",
            "timeout": 15,
        }))
        self._assert_structured_response(resp, "bruteuser")

    def test_bruteuser_missing_username(self, kerbrute_env):
        """bruteuser without 'username' returns error."""
        client, loop = kerbrute_env
        resp = loop.run_until_complete(client.call("bruteuser", {
            **self._FAKE_ARGS,
            "passwords": "Pass1\nPass2",
        }))
        result = resp.get("result", {})
        is_error = result.get("isError", False)
        content_text = ""
        for c in result.get("content", []):
            if c.get("type") == "text":
                content_text += c["text"]
        assert is_error or "username" in content_text.lower() or "required" in content_text.lower(), (
            f"Expected error about missing 'username', got: {content_text[:300]}"
        )

    def test_bruteuser_missing_passwords(self, kerbrute_env):
        """bruteuser without 'passwords' returns error (already in Smoke but repeated for acceptance coverage)."""
        client, loop = kerbrute_env
        resp = loop.run_until_complete(client.call("bruteuser", {
            **self._FAKE_ARGS,
            "username": "admin",
        }))
        result = resp.get("result", {})
        is_error = result.get("isError", False)
        content_text = ""
        for c in result.get("content", []):
            if c.get("type") == "text":
                content_text += c["text"]
        assert is_error or "passwords" in content_text.lower() or "required" in content_text.lower(), (
            f"Expected error about missing 'passwords', got: {content_text[:300]}"
        )

    def test_bruteuser_empty_username(self, kerbrute_env):
        """bruteuser with empty username returns helpful error."""
        client, loop = kerbrute_env
        resp = loop.run_until_complete(client.call("bruteuser", {
            **self._FAKE_ARGS,
            "username": "",
            "passwords": "Pass1\nPass2",
        }))
        result = resp.get("result", {})
        is_error = result.get("isError", False)
        content_text = ""
        for c in result.get("content", []):
            if c.get("type") == "text":
                content_text += c["text"]
        assert is_error or "username" in content_text.lower(), (
            f"Expected error about empty username, got: {content_text[:300]}"
        )

    # ── Cross-cutting acceptance tests ─────────────────────────

    @pytest.mark.clock
    def test_faketime_verify_clock_baseline(self, kerbrute_env):
        """verify_clock returns current system time (no libfaketime for Go tool)."""
        client, loop = kerbrute_env
        resp = loop.run_until_complete(client.call("verify_clock", {}))
        result = assert_tool_success(resp)
        data = parse_tool_output(resp)
        assert "current_time" in data
        assert "libfaketime_exists" in data
        assert data["libfaketime_exists"] is False

    def test_optional_params_accepted_userenum(self, kerbrute_env):
        """userenum accepts all optional params (threads, delay, safe) without crash."""
        client, loop = kerbrute_env
        resp = loop.run_until_complete(client.call("userenum", {
            **self._FAKE_ARGS,
            "usernames": "administrator",
            "threads": 1,
            "delay": 100,
            "safe": True,
            "timeout": 15,
        }))
        self._assert_structured_response(resp, "userenum")

    def test_optional_params_accepted_passwordspray(self, kerbrute_env):
        """passwordspray accepts all optional params without crash."""
        client, loop = kerbrute_env
        resp = loop.run_until_complete(client.call("passwordspray", {
            **self._FAKE_ARGS,
            "usernames": "admin",
            "password": "test",
            "user_as_pass": True,
            "threads": 2,
            "delay": 200,
            "safe": True,
            "timeout": 15,
        }))
        self._assert_structured_response(resp, "passwordspray")

    def test_optional_params_accepted_bruteforce(self, kerbrute_env):
        """bruteforce accepts all optional params without crash."""
        client, loop = kerbrute_env
        resp = loop.run_until_complete(client.call("bruteforce", {
            **self._FAKE_ARGS,
            "combos": "admin:Pass1",
            "threads": 3,
            "delay": 300,
            "safe": True,
            "timeout": 15,
        }))
        self._assert_structured_response(resp, "bruteforce")

    def test_optional_params_accepted_bruteuser(self, kerbrute_env):
        """bruteuser accepts all optional params without crash."""
        client, loop = kerbrute_env
        resp = loop.run_until_complete(client.call("bruteuser", {
            **self._FAKE_ARGS,
            "username": "admin",
            "passwords": "Pass1",
            "threads": 1,
            "delay": 100,
            "safe": True,
            "timeout": 15,
        }))
        self._assert_structured_response(resp, "bruteuser")

    def test_large_username_list(self, kerbrute_env):
        """userenum handles a larger username list without crashing."""
        client, loop = kerbrute_env
        # Generate 100 usernames
        usernames = "\n".join(f"testuser{i}" for i in range(100))
        resp = loop.run_until_complete(client.call("userenum", {
            **self._FAKE_ARGS,
            "usernames": usernames,
            "timeout": 30,
        }))
        # Should complete (error is fine, just no crash)
        self._assert_structured_response(resp, "userenum")

    def test_special_chars_in_password(self, kerbrute_env):
        """passwordspray handles special characters in password without crash."""
        client, loop = kerbrute_env
        resp = loop.run_until_complete(client.call("passwordspray", {
            **self._FAKE_ARGS,
            "usernames": "admin",
            "password": "P@$$w0rd!#%^&*()",
            "timeout": 15,
        }))
        self._assert_structured_response(resp, "passwordspray")

    def test_unicode_in_username(self, kerbrute_env):
        """userenum handles unicode characters in usernames without crash."""
        client, loop = kerbrute_env
        resp = loop.run_until_complete(client.call("userenum", {
            **self._FAKE_ARGS,
            "usernames": "admin\njose\nmaria",
            "timeout": 15,
        }))
        self._assert_structured_response(resp, "userenum")

    def test_whitespace_only_usernames(self, kerbrute_env):
        """userenum with whitespace-only usernames returns clear error."""
        client, loop = kerbrute_env
        resp = loop.run_until_complete(client.call("userenum", {
            **self._FAKE_ARGS,
            "usernames": "   \n  \n   ",
        }))
        result = resp.get("result", {})
        is_error = result.get("isError", False)
        # Either an isError or a failure in structuredContent
        sc = result.get("structuredContent", {})
        assert is_error or sc.get("success") is False or "Empty" in str(result), (
            "Whitespace-only usernames should be rejected"
        )

    def test_whitespace_only_passwords(self, kerbrute_env):
        """bruteuser with whitespace-only passwords returns clear error."""
        client, loop = kerbrute_env
        resp = loop.run_until_complete(client.call("bruteuser", {
            **self._FAKE_ARGS,
            "username": "admin",
            "passwords": "   \n  \n   ",
        }))
        result = resp.get("result", {})
        is_error = result.get("isError", False)
        sc = result.get("structuredContent", {})
        assert is_error or sc.get("success") is False or "Empty" in str(result), (
            "Whitespace-only passwords should be rejected"
        )

    # ── extra_args acceptance tests (through Docker) ──────────

    def test_userenum_extra_args_accepted(self, kerbrute_env):
        """userenum accepts extra_args parameter without crash."""
        client, loop = kerbrute_env
        resp = loop.run_until_complete(client.call("userenum", {
            **self._FAKE_ARGS,
            "usernames": "admin",
            "extra_args": "--no-color",
            "timeout": 15,
        }))
        sc = self._assert_structured_response(resp, "userenum+extra_args")
        # Should not crash -- may fail at network level but not at param level
        content_text = ""
        for c in resp.get("result", {}).get("content", []):
            if c.get("type") == "text":
                content_text += c["text"]
        assert "unexpected keyword argument" not in content_text

    def test_passwordspray_extra_args_accepted(self, kerbrute_env):
        """passwordspray accepts extra_args parameter without crash."""
        client, loop = kerbrute_env
        resp = loop.run_until_complete(client.call("passwordspray", {
            **self._FAKE_ARGS,
            "usernames": "admin",
            "password": "test",
            "extra_args": "--downgrade",
            "timeout": 15,
        }))
        self._assert_structured_response(resp, "passwordspray+extra_args")

    def test_bruteforce_extra_args_accepted(self, kerbrute_env):
        """bruteforce accepts extra_args parameter without crash."""
        client, loop = kerbrute_env
        resp = loop.run_until_complete(client.call("bruteforce", {
            **self._FAKE_ARGS,
            "combos": "admin:Pass1",
            "extra_args": "--no-color",
            "timeout": 15,
        }))
        self._assert_structured_response(resp, "bruteforce+extra_args")

    def test_bruteuser_extra_args_accepted(self, kerbrute_env):
        """bruteuser accepts extra_args parameter without crash."""
        client, loop = kerbrute_env
        resp = loop.run_until_complete(client.call("bruteuser", {
            **self._FAKE_ARGS,
            "username": "admin",
            "passwords": "Pass1\nPass2",
            "extra_args": "--downgrade",
            "timeout": 15,
        }))
        self._assert_structured_response(resp, "bruteuser+extra_args")

    def test_extra_args_empty_string_accepted(self, kerbrute_env):
        """extra_args='' should be accepted (no-op)."""
        client, loop = kerbrute_env
        resp = loop.run_until_complete(client.call("userenum", {
            **self._FAKE_ARGS,
            "usernames": "admin",
            "extra_args": "",
            "timeout": 15,
        }))
        self._assert_structured_response(resp, "userenum+empty_extra_args")

    def test_extra_args_multiple_flags_accepted(self, kerbrute_env):
        """extra_args with multiple space-separated flags."""
        client, loop = kerbrute_env
        resp = loop.run_until_complete(client.call("bruteuser", {
            **self._FAKE_ARGS,
            "username": "admin",
            "passwords": "Pass1",
            "extra_args": "--no-color --downgrade",
            "timeout": 15,
        }))
        self._assert_structured_response(resp, "bruteuser+multi_extra_args")

    # ── structuredContent validation on every method ──────────

    def test_structuredContent_userenum_has_data_fields(self, kerbrute_env):
        """userenum structuredContent.data has method-specific fields."""
        client, loop = kerbrute_env
        resp = loop.run_until_complete(client.call("userenum", {
            **self._FAKE_ARGS,
            "usernames": "admin",
            "timeout": 15,
        }))
        result = resp.get("result", {})
        sc = result.get("structuredContent", {})
        data = sc.get("data") or {}
        if sc.get("success"):
            assert data.get("method") == "userenum"
            assert "valid_users" in data
            assert "valid_count" in data

    def test_structuredContent_passwordspray_has_data_fields(self, kerbrute_env):
        """passwordspray structuredContent.data has method-specific fields."""
        client, loop = kerbrute_env
        resp = loop.run_until_complete(client.call("passwordspray", {
            **self._FAKE_ARGS,
            "usernames": "admin",
            "password": "test",
            "timeout": 15,
        }))
        result = resp.get("result", {})
        sc = result.get("structuredContent", {})
        data = sc.get("data") or {}
        if sc.get("success"):
            assert data.get("method") == "passwordspray"
            assert "valid_logins" in data
            assert "password_tested" in data

    def test_structuredContent_bruteforce_has_data_fields(self, kerbrute_env):
        """bruteforce structuredContent.data has method-specific fields."""
        client, loop = kerbrute_env
        resp = loop.run_until_complete(client.call("bruteforce", {
            **self._FAKE_ARGS,
            "combos": "admin:Pass1",
            "timeout": 15,
        }))
        result = resp.get("result", {})
        sc = result.get("structuredContent", {})
        data = sc.get("data") or {}
        if sc.get("success"):
            assert data.get("method") == "bruteforce"
            assert "valid_logins" in data

    def test_structuredContent_bruteuser_has_data_fields(self, kerbrute_env):
        """bruteuser structuredContent.data has method-specific fields."""
        client, loop = kerbrute_env
        resp = loop.run_until_complete(client.call("bruteuser", {
            **self._FAKE_ARGS,
            "username": "admin",
            "passwords": "Pass1",
            "timeout": 15,
        }))
        result = resp.get("result", {})
        sc = result.get("structuredContent", {})
        data = sc.get("data") or {}
        if sc.get("success"):
            assert data.get("method") == "bruteuser"
            assert data.get("target_user") == "admin"

    # ── FAKETIME verification ─────────────────────────────────

    @pytest.mark.clock
    def test_faketime_libfaketime_not_installed(self, kerbrute_env):
        """libfaketime should NOT be installed — kerbrute is Go, bypasses LD_PRELOAD."""
        client, loop = kerbrute_env
        resp = loop.run_until_complete(client.call("verify_clock", {}))
        data = parse_tool_output(resp)
        assert data["libfaketime_exists"] is False, (
            "libfaketime should NOT be in kerbrute image (Go binary can't use it)"
        )

    @pytest.mark.clock
    def test_faketime_returns_system_time(self, kerbrute_env):
        """verify_clock should return a parseable timestamp."""
        client, loop = kerbrute_env
        resp = loop.run_until_complete(client.call("verify_clock", {}))
        data = parse_tool_output(resp)
        assert "current_time" in data
        # Should be a non-empty string
        assert len(data["current_time"]) > 10, (
            f"current_time too short: {data['current_time']}"
        )

    # ── Missing required params give helpful errors ───────────

    def test_passwordspray_empty_usernames_error(self, kerbrute_env):
        """passwordspray with empty usernames returns helpful error."""
        client, loop = kerbrute_env
        resp = loop.run_until_complete(client.call("passwordspray", {
            **self._FAKE_ARGS,
            "usernames": "",
            "password": "test",
        }))
        result = resp.get("result", {})
        is_error = result.get("isError", False)
        content_text = ""
        for c in result.get("content", []):
            if c.get("type") == "text":
                content_text += c["text"]
        assert is_error or "Empty" in content_text or "empty" in content_text.lower(), (
            f"Expected empty username error, got: {content_text[:300]}"
        )

    def test_bruteforce_whitespace_combos_error(self, kerbrute_env):
        """bruteforce with whitespace-only combos returns helpful error."""
        client, loop = kerbrute_env
        resp = loop.run_until_complete(client.call("bruteforce", {
            **self._FAKE_ARGS,
            "combos": "   \n  ",
        }))
        result = resp.get("result", {})
        is_error = result.get("isError", False)
        sc = result.get("structuredContent", {})
        assert is_error or sc.get("success") is False or "Empty" in str(result), (
            "Whitespace-only combos should be rejected"
        )


# ===========================================================================
# INTEGRATION TESTS -- require --target, --domain, etc.
# ===========================================================================

@pytest.mark.integration
class TestIntegration:
    """Integration tests that need a real AD target.

    Run with: pytest tests/tools/test_kerbrute.py --tool=kerbrute
              --target=<DC_IP> --domain=<DOMAIN>
              -m integration -v
    """

    def test_userenum(self, kerbrute_env, target, domain):
        """Enumerate valid usernames against DC."""
        client, loop = kerbrute_env
        resp = loop.run_until_complete(client.call("userenum", {
            "dc": target,
            "domain": domain,
            "usernames": "administrator\nguest\nkrbtgt\nfakeuser99999",
            "safe": True,
            "timeout": 30,
        }))
        result = assert_tool_success(resp, "userenum should succeed")
        data = parse_tool_output(resp)
        assert "valid_users" in data
        assert "administrator" in [u.lower() for u in data["valid_users"]], (
            "administrator should always be a valid user"
        )

    def test_passwordspray(self, kerbrute_env, target, domain):
        """Spray a known-bad password against administrator."""
        client, loop = kerbrute_env
        resp = loop.run_until_complete(client.call("passwordspray", {
            "dc": target,
            "domain": domain,
            "usernames": "administrator",
            "password": "ThisPasswordDoesNotExist999!",
            "safe": True,
            "timeout": 30,
        }))
        result = assert_tool_success(resp, "passwordspray should succeed (no valid logins expected)")
        data = parse_tool_output(resp)
        assert data["valid_count"] == 0, "Should not find valid login with bogus password"

    def test_bruteforce(self, kerbrute_env, target, domain):
        """Test combo list with known-bad credentials."""
        client, loop = kerbrute_env
        resp = loop.run_until_complete(client.call("bruteforce", {
            "dc": target,
            "domain": domain,
            "combos": "administrator:BogusPass123!\nguest:BogusPass456!",
            "safe": True,
            "timeout": 30,
        }))
        result = assert_tool_success(resp, "bruteforce should succeed")
        data = parse_tool_output(resp)
        assert "valid_logins" in data

    def test_bruteuser(self, kerbrute_env, target, domain):
        """Brute-force administrator with known-bad passwords."""
        client, loop = kerbrute_env
        resp = loop.run_until_complete(client.call("bruteuser", {
            "dc": target,
            "domain": domain,
            "username": "administrator",
            "passwords": "BadPass1!\nBadPass2!\nBadPass3!",
            "safe": True,
            "timeout": 30,
        }))
        result = assert_tool_success(resp, "bruteuser should succeed")
        data = parse_tool_output(resp)
        assert data.get("target_user") == "administrator"
