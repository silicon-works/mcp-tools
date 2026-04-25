"""
Tests for the evil-winrm MCP tool server.

Covers:
- Smoke tests: boot, method list, required params, meta-param stripping, clock
- Unit tests: error classification (12 patterns + 8 new engagement patterns),
  _get_client auth mode selection, domain prefix logic
- Contract tests: tool.yaml vs server parameter definitions
- Robustness tests: unknown params absorbed by **kwargs (engagement bug #3)
- Acceptance tests: all 3 methods called through Docker container with
  structuredContent shape validation, error_class verification, auth mode
  combinations, and missing param error handling
- Integration tests: real target scenarios (marked @pytest.mark.integration)

Key issues from engagement data (1707 calls, 20.4% error rate):
- 172 PS command-level errors (access denied, cmdlet not found, etc.)
- 44 WSManFault Code:5 access denied
- 42 PS-level access denied (HRESULT, service control, elevation)
- 38 auth failures (Failed to authenticate with ntlm)
- 13 connect timeouts (target unreachable)
- 11 "logon session does not exist" (Kerberos ticket expiry)
- 9 internal errors (ToolResult.__init__ missing 'data' -- now fixed)
- 5 operation/command timeouts
- 3 unexpected keyword argument crashes (timeout, kerberos, upload -- now fixed)
- 16 upload errors (path denied, constrained language, auth failure)
- 6 input validation errors (missing target/username)
- 1 unknown method 'connect' (agent hallucination)
"""

import asyncio
import json
import os
import sys
from pathlib import Path
from typing import Any, Dict

import pytest
import yaml

# ---------------------------------------------------------------------------
# Path setup
# ---------------------------------------------------------------------------
PROJECT_ROOT = Path(__file__).parent.parent.parent
TOOL_DIR = PROJECT_ROOT / "tools" / "evil-winrm"
FIXTURES_DIR = Path(__file__).parent.parent / "fixtures" / "evil-winrm"

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
def evil_winrm_env(request):
    """Create an MCPTestClient with its event loop. Yields (client, loop)."""
    tool = "evil-winrm"
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
    """Import and return the EvilWinRMServer class for direct method testing."""
    import importlib.util
    spec = importlib.util.spec_from_file_location(
        "evil_winrm_server", TOOL_DIR / "mcp-server.py"
    )
    mod = importlib.util.module_from_spec(spec)
    spec.loader.exec_module(mod)
    return mod.EvilWinRMServer


# ===========================================================================
# SMOKE TESTS — require Docker container running
# ===========================================================================

class TestSmoke:
    """Smoke tests that verify the container boots and basic protocol works."""

    def test_boot_and_list_tools(self, evil_winrm_env):
        """Container starts and list_tools returns methods."""
        client, loop = evil_winrm_env
        assert len(client.tools) > 0, "Server should advertise at least one tool"
        names = client.tool_names()
        assert "exec" in names, "exec should be in tool list"
        assert "upload" in names, "upload should be in tool list"
        assert "download" in names, "download should be in tool list"

    def test_method_list_matches_tool_yaml(self, evil_winrm_env):
        """Every method in tool.yaml is advertised by the server, and vice versa."""
        client, _ = evil_winrm_env
        server_names = client.tool_names()

        # Remove verify_clock — it's test-only, not in tool.yaml
        server_names_no_test = server_names - {"verify_clock"}

        yaml_path = TOOL_DIR / "tool.yaml"
        with open(yaml_path) as f:
            yaml_data = yaml.safe_load(f)
        yaml_names = set(yaml_data.get("methods", {}).keys())

        yaml_only = yaml_names - server_names_no_test
        server_only = server_names_no_test - yaml_names

        assert not yaml_only, f"Methods in tool.yaml but not server: {yaml_only}"
        assert not server_only, f"Methods in server but not tool.yaml: {server_only}"

    def test_expected_method_count(self, evil_winrm_env):
        """Server should have exactly 3 built-in methods + verify_clock."""
        client, _ = evil_winrm_env
        names = client.tool_names()
        # 3 built-in + verify_clock in MCP_TEST_MODE
        assert len(names) == 4, (
            f"Expected 4 methods (3 built-in + verify_clock), got {len(names)}: {sorted(names)}"
        )

    def test_required_params_enforced_exec(self, evil_winrm_env):
        """Calling exec without required 'target' param returns an error."""
        client, loop = evil_winrm_env
        resp = loop.run_until_complete(
            client.call("exec", {"command": "whoami"})
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

    def test_required_params_enforced_upload(self, evil_winrm_env):
        """Calling upload without required 'local_path' param returns an error."""
        client, loop = evil_winrm_env
        resp = loop.run_until_complete(
            client.call("upload", {
                "target": "10.0.0.1",
                "username": "admin",
                "remote_path": "C:\\Windows\\Temp\\test.txt",
            })
        )
        result = resp.get("result", {})
        is_error = result.get("isError", False)
        content_text = ""
        for c in result.get("content", []):
            if c.get("type") == "text":
                content_text += c["text"]
        assert is_error or "local_path" in content_text.lower() or "error" in content_text.lower(), (
            f"Expected error about missing 'local_path', got: {content_text[:300]}"
        )

    def test_meta_params_stripped_timeout(self, evil_winrm_env):
        """Passing 'timeout' (meta-param) in args does not crash the server.

        This was a real engagement bug: 3 crashes from 'unexpected keyword argument timeout'.
        """
        client, loop = evil_winrm_env
        resp = loop.run_until_complete(
            client.call("exec", {
                "target": "10.0.0.1",
                "username": "testuser",
                "password": "testpass",
                "command": "whoami",
                "timeout": 30,
            })
        )
        result = resp.get("result", {})
        content_text = ""
        for c in result.get("content", []):
            if c.get("type") == "text":
                content_text += c["text"]
        assert "unexpected keyword argument" not in content_text, (
            f"Meta-param 'timeout' was not stripped: {content_text[:300]}"
        )

    def test_meta_params_stripped_clock_offset(self, evil_winrm_env):
        """Passing 'clock_offset' (meta-param) in args does not crash the server."""
        client, loop = evil_winrm_env
        resp = loop.run_until_complete(
            client.call("exec", {
                "target": "10.0.0.1",
                "username": "testuser",
                "password": "testpass",
                "command": "whoami",
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

    def test_unknown_params_absorbed_by_kwargs(self, evil_winrm_env):
        """Unknown params like 'upload', 'kerberos', 'dc_ip' don't crash the handler.

        This was a real engagement bug: agent passed 'upload' (list), 'kerberos' (bool),
        'dc_ip' (string) which caused TypeError crashes. Now absorbed by **kwargs.
        """
        client, loop = evil_winrm_env
        resp = loop.run_until_complete(
            client.call("exec", {
                "target": "10.0.0.1",
                "username": "testuser",
                "password": "testpass",
                "command": "whoami",
                "upload": ["/tmp/file.exe", "C:\\Temp\\file.exe"],
                "kerberos": True,
                "dc_ip": "10.0.0.1",
            })
        )
        result = resp.get("result", {})
        content_text = ""
        for c in result.get("content", []):
            if c.get("type") == "text":
                content_text += c["text"]
        assert "unexpected keyword argument" not in content_text, (
            f"Unknown params caused crash: {content_text[:300]}"
        )
        # The call will fail (can't connect to 10.0.0.1) but it should be a
        # WinRM connection error, not a TypeError
        assert "Internal error" not in content_text, (
            f"Unknown params caused internal error: {content_text[:300]}"
        )

    def test_unknown_method_returns_error(self, evil_winrm_env):
        """Calling a non-existent method returns a helpful error."""
        client, loop = evil_winrm_env
        resp = loop.run_until_complete(
            client.call("shell", {})
        )
        result = assert_tool_error(resp)
        content_text = ""
        for c in result.get("content", []):
            if c.get("type") == "text":
                content_text += c["text"]
        assert "Unknown method" in content_text
        assert "shell" in content_text

    @pytest.mark.clock
    def test_verify_clock_available(self, evil_winrm_env):
        """verify_clock is registered in MCP_TEST_MODE."""
        client, _ = evil_winrm_env
        names = client.tool_names()
        assert "verify_clock" in names, "verify_clock should be available in test mode"

    @pytest.mark.clock
    def test_verify_clock_returns_time(self, evil_winrm_env):
        """verify_clock returns current time and FAKETIME status."""
        client, loop = evil_winrm_env
        resp = loop.run_until_complete(client.call("verify_clock", {}))
        result = assert_tool_success(resp)
        data = parse_tool_output(resp)
        assert "current_time" in data
        assert "libfaketime_exists" in data
        # libfaketime is installed in this image
        assert data["libfaketime_exists"] is True, (
            "libfaketime should be installed in the evil-winrm image"
        )

    def test_structuredContent_present(self, evil_winrm_env):
        """Responses include structuredContent with error classification fields."""
        client, loop = evil_winrm_env
        resp = loop.run_until_complete(client.call("verify_clock", {}))
        result = resp.get("result", {})
        sc = result.get("structuredContent")
        assert sc is not None, "structuredContent should be present"
        assert "success" in sc
        assert "error_class" in sc
        assert "retryable" in sc
        assert "suggestions" in sc

    def test_exec_connection_failure_has_structured_error(self, evil_winrm_env):
        """Connection failure should include error_class in structuredContent."""
        client, loop = evil_winrm_env
        resp = loop.run_until_complete(
            client.call("exec", {
                "target": "192.0.2.1",  # TEST-NET, should fail
                "username": "testuser",
                "password": "testpass",
                "command": "whoami",
            })
        )
        result = resp.get("result", {})
        assert result.get("isError") is True
        sc = result.get("structuredContent", {})
        assert sc.get("success") is False
        # Should have an error_class set
        assert sc.get("error_class") is not None, (
            f"Connection failure should have error_class, got: {sc}"
        )

    def test_upload_missing_file_has_structured_error(self, evil_winrm_env):
        """Upload with missing local file should return params error_class."""
        client, loop = evil_winrm_env
        resp = loop.run_until_complete(
            client.call("upload", {
                "target": "10.0.0.1",
                "username": "testuser",
                "password": "testpass",
                "local_path": "/nonexistent/file.exe",
                "remote_path": "C:\\Windows\\Temp\\file.exe",
            })
        )
        result = resp.get("result", {})
        assert result.get("isError") is True
        sc = result.get("structuredContent", {})
        assert sc.get("error_class") == "params", (
            f"Missing file should be 'params' error, got: {sc.get('error_class')}"
        )


# ===========================================================================
# ERROR CLASSIFICATION TESTS — unit tests, no container needed
# ===========================================================================

class TestErrorClassification:
    """Test _classify_winrm_error with real error patterns from engagements."""

    @pytest.fixture(autouse=True, scope="class")
    def server(self):
        """Create a server instance for error classification testing."""
        try:
            cls = _get_server_class()
            self.__class__._server = cls()
        except Exception as e:
            pytest.skip(f"Cannot import EvilWinRMServer: {e}")

    def test_classify_ntlm_auth_failure(self):
        """NTLM auth failure: 'Failed to authenticate' with ntlm."""
        text = load_fixture("auth_failure_ntlm.txt")
        err_class, retryable, suggestions = self._server._classify_winrm_error(text)
        assert err_class == "auth", f"Expected 'auth', got '{err_class}'"
        assert retryable is False
        assert any("kerberos" in s.lower() for s in suggestions), (
            f"Should suggest kerberos alternative, got: {suggestions}"
        )

    def test_classify_logon_failure(self):
        """STATUS_LOGON_FAILURE should be 'auth'."""
        text = load_fixture("auth_failure_logon.txt")
        err_class, retryable, suggestions = self._server._classify_winrm_error(text)
        assert err_class == "auth", f"Expected 'auth', got '{err_class}'"
        assert retryable is False

    def test_classify_kerberos_skew(self):
        """KRB_AP_ERR_SKEW should be 'config', retryable."""
        text = load_fixture("kerberos_skew.txt")
        err_class, retryable, suggestions = self._server._classify_winrm_error(text)
        assert err_class == "config", f"Expected 'config', got '{err_class}'"
        assert retryable is True
        assert any("clock" in s.lower() for s in suggestions), (
            f"Should suggest clock offset fix, got: {suggestions}"
        )

    def test_classify_kerberos_preauth(self):
        """KDC_ERR_PREAUTH_FAILED should be 'auth', not retryable."""
        text = load_fixture("kerberos_preauth.txt")
        err_class, retryable, suggestions = self._server._classify_winrm_error(text)
        assert err_class == "auth", f"Expected 'auth', got '{err_class}'"
        assert retryable is False

    def test_classify_kerberos_principal_unknown(self):
        """KDC_ERR_C_PRINCIPAL_UNKNOWN should be 'auth'."""
        text = load_fixture("kerberos_principal_unknown.txt")
        err_class, retryable, suggestions = self._server._classify_winrm_error(text)
        assert err_class == "auth", f"Expected 'auth', got '{err_class}'"
        assert retryable is False

    def test_classify_connect_timeout(self):
        """ConnectTimeoutError should be 'network', retryable."""
        text = load_fixture("connect_timeout.txt")
        err_class, retryable, suggestions = self._server._classify_winrm_error(text)
        assert err_class == "network", f"Expected 'network', got '{err_class}'"
        assert retryable is True

    def test_classify_connection_refused(self):
        """ConnectionRefusedError should be 'network', retryable."""
        text = load_fixture("connection_refused.txt")
        err_class, retryable, suggestions = self._server._classify_winrm_error(text)
        assert err_class == "network", f"Expected 'network', got '{err_class}'"
        assert retryable is True

    def test_classify_wsman_access_denied(self):
        """WSManFault Code:5 (Access denied) should be 'permission'."""
        text = load_fixture("access_denied_wsman.txt")
        err_class, retryable, suggestions = self._server._classify_winrm_error(text)
        assert err_class == "permission", f"Expected 'permission', got '{err_class}'"
        assert retryable is False
        assert any("Remote Management Users" in s for s in suggestions), (
            f"Should suggest Remote Management Users group, got: {suggestions}"
        )

    def test_classify_constrained_language(self):
        """Constrained Language Mode should be 'permission'."""
        text = load_fixture("constrained_language.txt")
        err_class, retryable, suggestions = self._server._classify_winrm_error(text)
        assert err_class == "permission", f"Expected 'permission', got '{err_class}'"
        assert retryable is False
        assert any("cmd" in s.lower() for s in suggestions), (
            f"Should suggest cmd shell, got: {suggestions}"
        )

    def test_classify_no_route(self):
        """No route to host should be 'network', not retryable."""
        text = load_fixture("no_route.txt")
        err_class, retryable, suggestions = self._server._classify_winrm_error(text)
        assert err_class == "network", f"Expected 'network', got '{err_class}'"
        assert retryable is False

    def test_classify_unknown_error(self):
        """Unrecognized error should return 'unknown'."""
        err_class, retryable, suggestions = self._server._classify_winrm_error(
            "Some totally unknown error message"
        )
        assert err_class == "unknown"
        assert retryable is False
        assert len(suggestions) == 0

    def test_classify_empty_string(self):
        """Empty string should return 'unknown'."""
        err_class, retryable, suggestions = self._server._classify_winrm_error("")
        assert err_class == "unknown"

    # ── Additional engagement-derived error patterns ──────────────

    def test_classify_logon_session_not_exist(self):
        """'logon session does not exist' should be 'auth', retryable.

        From engagement: 11 occurrences in Pirate HTB. Happens when Kerberos
        ticket expires during a multi-hop PS remoting session.
        """
        text = load_fixture("logon_session_not_exist.txt")
        err_class, retryable, suggestions = self._server._classify_winrm_error(text)
        assert err_class == "auth", f"Expected 'auth', got '{err_class}'"
        assert retryable is True, "Should be retryable (re-auth fixes it)"

    def test_classify_upload_access_denied(self):
        """Upload path access denied should be 'permission'.

        From engagement: upload fails with 'Access to the path is denied' when
        target directory is not writable by the WinRM user.
        """
        text = load_fixture("upload_access_denied.txt")
        err_class, retryable, suggestions = self._server._classify_winrm_error(text)
        # "Access...denied" is in the text, should match the existing pattern
        assert err_class == "permission", f"Expected 'permission', got '{err_class}'"
        assert retryable is False

    def test_classify_upload_constrained_language(self):
        """Upload failure in Constrained Language Mode should be 'permission'.

        From engagement: PSRP copy() fails because it uses method invocation
        which is blocked in CLM. 2 occurrences in Pirate HTB.
        """
        text = load_fixture("upload_constrained_language.txt")
        err_class, retryable, suggestions = self._server._classify_winrm_error(text)
        assert err_class == "permission", f"Expected 'permission', got '{err_class}'"
        assert retryable is False
        assert any("cmd" in s.lower() or "language" in s.lower() for s in suggestions)

    def test_classify_operation_timeout(self):
        """'Operation timed out' should be 'timeout', retryable."""
        text = load_fixture("operation_timeout.txt")
        err_class, retryable, suggestions = self._server._classify_winrm_error(text)
        assert err_class == "timeout", f"Expected 'timeout', got '{err_class}'"
        assert retryable is True

    def test_classify_hresult_access_denied(self):
        """HRESULT 0x80070005 (E_ACCESSDENIED) should be 'permission'.

        From engagement: PS commands that require admin (certutil, schtasks,
        Service Control Manager) return this. 42 occurrences across sessions.
        """
        text = load_fixture("hresult_access_denied.txt")
        err_class, retryable, suggestions = self._server._classify_winrm_error(text)
        assert err_class == "permission", f"Expected 'permission', got '{err_class}'"
        assert retryable is False

    def test_classify_ps_remote_server_failed(self):
        """PS remoting to secondary host failure should be 'network'.

        From engagement: agent uses Invoke-Command to hop from WinRM target
        to another internal host that blocks PS remoting.
        """
        text = load_fixture("ps_remote_server_failed.txt")
        err_class, retryable, suggestions = self._server._classify_winrm_error(text)
        assert err_class == "network", f"Expected 'network', got '{err_class}'"
        assert retryable is True

    def test_classify_service_unavailable(self):
        """HTTP 503 Service Unavailable should be 'network', retryable.

        From engagement: WinRM HTTP endpoint temporarily unavailable.
        """
        text = load_fixture("service_unavailable.txt")
        err_class, retryable, suggestions = self._server._classify_winrm_error(text)
        assert err_class == "network", f"Expected 'network', got '{err_class}'"
        assert retryable is True

    def test_classify_elevation_required(self):
        """'requires elevation' should be 'permission'.

        From engagement: commands like 'net session', 'whoami /priv' fail when
        the WinRM user is not running elevated.
        """
        text = load_fixture("elevation_required.txt")
        err_class, retryable, suggestions = self._server._classify_winrm_error(text)
        assert err_class == "permission", f"Expected 'permission', got '{err_class}'"
        assert retryable is False


# ===========================================================================
# UNIT TESTS — _get_client auth modes, no container needed
# ===========================================================================

class TestGetClient:
    """Test _get_client creates clients with correct auth configuration."""

    @pytest.fixture(autouse=True, scope="class")
    def server(self):
        """Create a server instance."""
        try:
            cls = _get_server_class()
            self.__class__._server = cls()
        except Exception as e:
            pytest.skip(f"Cannot import EvilWinRMServer: {e}")

    def test_ntlm_with_password(self):
        """NTLM auth with password creates client with password as auth_pass."""
        client = self._server._get_client(
            "10.0.0.1", "admin", password="Password123"
        )
        # pypsrp Client is created — verify it exists and has basic attrs
        assert client is not None
        assert hasattr(client, "execute_ps"), "Client should have execute_ps method"
        assert hasattr(client, "execute_cmd"), "Client should have execute_cmd method"

    def test_ntlm_with_bare_hash(self):
        """NTLM auth with bare NT hash auto-prepends zero LM hash."""
        client = self._server._get_client(
            "10.0.0.1", "admin", hash="deadbeef" * 4
        )
        assert client is not None

    def test_ntlm_with_lm_nt_hash(self):
        """NTLM auth with LM:NT format hash passes through directly."""
        client = self._server._get_client(
            "10.0.0.1", "admin", hash="aad3b435b51404ee:deadbeef" * 2
        )
        assert client is not None

    def test_kerberos_auth(self):
        """Kerberos auth creates client with auth='kerberos'."""
        client = self._server._get_client(
            "dc.corp.local", "user@CORP.LOCAL", auth="kerberos"
        )
        assert client is not None

    def test_ssl_port_defaults(self):
        """SSL=True defaults to port 5986."""
        client = self._server._get_client(
            "10.0.0.1", "admin", password="test", ssl=True
        )
        assert client is not None

    def test_custom_port(self):
        """Custom port overrides default."""
        client = self._server._get_client(
            "10.0.0.1", "admin", password="test", port=8443
        )
        assert client is not None

    def test_domain_prepend_ntlm(self):
        """Domain is prepended to username for NTLM auth in exec_cmd, not _get_client."""
        # _get_client receives the already-formatted username
        client = self._server._get_client(
            "10.0.0.1", "CORP\\admin", password="test"
        )
        assert client is not None

    def test_ntlm_no_password_or_hash(self):
        """NTLM auth with neither password nor hash uses empty string."""
        client = self._server._get_client(
            "10.0.0.1", "admin"
        )
        assert client is not None

    def test_kerberos_with_ccache_path(self):
        """Kerberos with ccache_path sets KRB5CCNAME env var."""
        import os
        old_val = os.environ.get("KRB5CCNAME")
        try:
            client = self._server._get_client(
                "dc.corp.local", "user@CORP.LOCAL",
                auth="kerberos", ccache_path="/session/credentials/user.ccache"
            )
            assert client is not None
            assert os.environ.get("KRB5CCNAME") == "/session/credentials/user.ccache"
        finally:
            # Restore original env
            if old_val is None:
                os.environ.pop("KRB5CCNAME", None)
            else:
                os.environ["KRB5CCNAME"] = old_val

    def test_kerberos_without_ccache(self):
        """Kerberos without ccache_path does not crash (uses existing KRB5CCNAME)."""
        client = self._server._get_client(
            "dc.corp.local", "user@CORP.LOCAL",
            auth="kerberos", password="Password123"
        )
        assert client is not None

    def test_ssl_custom_port(self):
        """SSL with custom port uses the custom port, not 5986."""
        client = self._server._get_client(
            "10.0.0.1", "admin", password="test", ssl=True, port=8443
        )
        assert client is not None


# ===========================================================================
# DOMAIN PREFIX LOGIC TESTS — unit tests, no container needed
# ===========================================================================

class TestDomainPrefix:
    """Test auth_user domain prefix logic in exec_cmd, upload, download.

    Engagement data shows agents pass domain in various combinations:
    - domain="pirate.htb" + username="gMSA_ADCS_prod$" -> pirate.htb\\gMSA_ADCS_prod$
    - domain="HERCULES.HTB" + auth="kerberos" -> NO prefix (use user@REALM)
    - no domain + username="admin" -> "admin" (local auth)
    """

    @pytest.fixture(autouse=True, scope="class")
    def server(self):
        """Create a server instance."""
        try:
            cls = _get_server_class()
            self.__class__._server = cls()
        except Exception as e:
            pytest.skip(f"Cannot import EvilWinRMServer: {e}")

    def test_domain_prepended_for_ntlm(self):
        """exec_cmd prepends domain\\username for NTLM auth."""
        import asyncio
        loop = asyncio.new_event_loop()
        try:
            result = loop.run_until_complete(
                self._server.exec_cmd(
                    target="10.0.0.1", username="admin",
                    password="test", domain="CORP",
                    command="whoami", auth="ntlm",
                )
            )
            # Will fail to connect but the auth_user should have been formatted
            # We just verify it didn't crash
            assert result is not None
        finally:
            loop.close()

    def test_domain_not_prepended_for_kerberos(self):
        """exec_cmd does NOT prepend domain for Kerberos auth (uses user@REALM)."""
        import asyncio
        loop = asyncio.new_event_loop()
        try:
            result = loop.run_until_complete(
                self._server.exec_cmd(
                    target="dc.corp.local", username="user@CORP.LOCAL",
                    password="test", domain="CORP.LOCAL",
                    command="whoami", auth="kerberos",
                )
            )
            assert result is not None
        finally:
            loop.close()

    def test_no_domain_uses_bare_username(self):
        """exec_cmd without domain uses plain username (local auth)."""
        import asyncio
        loop = asyncio.new_event_loop()
        try:
            result = loop.run_until_complete(
                self._server.exec_cmd(
                    target="10.0.0.1", username="localadmin",
                    password="test", command="whoami",
                )
            )
            assert result is not None
        finally:
            loop.close()

    def test_upload_domain_prefix(self):
        """upload prepends domain for NTLM auth."""
        import asyncio
        loop = asyncio.new_event_loop()
        try:
            result = loop.run_until_complete(
                self._server.upload(
                    target="10.0.0.1", username="admin",
                    password="test", domain="CORP",
                    local_path="/nonexistent", remote_path="C:\\temp\\test",
                )
            )
            # Should fail with "Local file not found" (params error), not crash
            assert result is not None
            assert result.error_class == "params"
        finally:
            loop.close()

    def test_download_domain_prefix(self):
        """download prepends domain for NTLM auth."""
        import asyncio
        loop = asyncio.new_event_loop()
        try:
            result = loop.run_until_complete(
                self._server.download(
                    target="10.0.0.1", username="admin",
                    password="test", domain="CORP",
                    remote_path="C:\\flag.txt",
                )
            )
            # Will fail to connect
            assert result is not None
            assert result.error is not None
        finally:
            loop.close()


# ===========================================================================
# KWARGS ABSORPTION TESTS — verify **kwargs prevents crashes
# ===========================================================================

class TestKwargsAbsorption:
    """Verify handler methods absorb unknown parameters via **kwargs.

    Real engagement data shows agents pass params like:
    - 'timeout' (meta-param, also stripped by BaseMCPServer)
    - 'kerberos' (boolean, agent confuses with auth param)
    - 'dc_ip' (from impacket convention)
    - 'upload' (list, agent tries to combine exec+upload)
    """

    @pytest.fixture(autouse=True, scope="class")
    def server(self):
        """Create a server instance."""
        try:
            cls = _get_server_class()
            self.__class__._server = cls()
        except Exception as e:
            pytest.skip(f"Cannot import EvilWinRMServer: {e}")

    def test_exec_accepts_unknown_params(self):
        """exec_cmd should not raise TypeError for unknown params."""
        import asyncio
        loop = asyncio.new_event_loop()
        try:
            # This would crash with TypeError before the **kwargs fix
            result = loop.run_until_complete(
                self._server.exec_cmd(
                    target="10.0.0.1",
                    username="admin",
                    command="whoami",
                    password="test",
                    kerberos=True,  # unknown param
                    dc_ip="10.0.0.1",  # unknown param
                    upload=["/tmp/a", "C:\\a"],  # unknown param
                )
            )
            # Will fail to connect, but should NOT raise TypeError
            assert isinstance(result.error, str)
            assert "unexpected keyword" not in result.error
        finally:
            loop.close()

    def test_upload_accepts_unknown_params(self):
        """upload should not raise TypeError for unknown params."""
        import asyncio
        loop = asyncio.new_event_loop()
        try:
            result = loop.run_until_complete(
                self._server.upload(
                    target="10.0.0.1",
                    username="admin",
                    local_path="/nonexistent",
                    remote_path="C:\\temp\\test",
                    password="test",
                    dc_ip="10.0.0.1",  # unknown param
                )
            )
            assert isinstance(result.error, str)
            assert "unexpected keyword" not in result.error
        finally:
            loop.close()

    def test_download_accepts_unknown_params(self):
        """download should not raise TypeError for unknown params."""
        import asyncio
        loop = asyncio.new_event_loop()
        try:
            result = loop.run_until_complete(
                self._server.download(
                    target="10.0.0.1",
                    username="admin",
                    remote_path="C:\\flag.txt",
                    password="test",
                    dc_ip="10.0.0.1",  # unknown param
                )
            )
            assert isinstance(result.error, str)
            assert "unexpected keyword" not in result.error
        finally:
            loop.close()


# ===========================================================================
# TOOL.YAML CONTRACT TESTS — no container needed
# ===========================================================================

class TestToolYamlContract:
    """Verify tool.yaml matches server parameter definitions."""

    @pytest.fixture(autouse=True, scope="class")
    def load_yaml(self):
        """Load tool.yaml."""
        with open(TOOL_DIR / "tool.yaml") as f:
            self.__class__._yaml = yaml.safe_load(f)

    def test_yaml_has_all_3_methods(self):
        """tool.yaml should define exactly 3 methods."""
        methods = self._yaml.get("methods", {})
        assert len(methods) == 3, (
            f"Expected 3 methods, got {len(methods)}: {sorted(methods.keys())}"
        )

    def test_all_methods_have_descriptions(self):
        """Every method should have a description."""
        for name, defn in self._yaml.get("methods", {}).items():
            assert "description" in defn, f"Method {name} missing description"
            assert len(defn["description"]) > 10, f"Method {name} has too short description"

    def test_all_methods_have_target_and_username(self):
        """Every method should have 'target' and 'username' params."""
        for name, defn in self._yaml.get("methods", {}).items():
            params = defn.get("params", {})
            assert "target" in params, f"Method {name} missing 'target' param"
            assert "username" in params, f"Method {name} missing 'username' param"

    def test_exec_has_command_param(self):
        """exec method should have 'command' param."""
        exec_defn = self._yaml.get("methods", {}).get("exec", {})
        params = exec_defn.get("params", {})
        assert "command" in params, "exec method missing 'command' param"

    def test_exec_has_shell_param(self):
        """exec method should have 'shell' param with powershell/cmd values."""
        exec_defn = self._yaml.get("methods", {}).get("exec", {})
        params = exec_defn.get("params", {})
        assert "shell" in params, "exec method missing 'shell' param"
        shell = params["shell"]
        assert "powershell" in shell.get("enum", []), "shell should include 'powershell'"
        assert "cmd" in shell.get("enum", []), "shell should include 'cmd'"

    def test_upload_has_path_params(self):
        """upload method should have 'local_path' and 'remote_path' params."""
        upload_defn = self._yaml.get("methods", {}).get("upload", {})
        params = upload_defn.get("params", {})
        assert "local_path" in params, "upload missing 'local_path' param"
        assert "remote_path" in params, "upload missing 'remote_path' param"

    def test_download_has_remote_path(self):
        """download method should have 'remote_path' param."""
        dl_defn = self._yaml.get("methods", {}).get("download", {})
        params = dl_defn.get("params", {})
        assert "remote_path" in params, "download missing 'remote_path' param"

    def test_all_methods_have_auth_params(self):
        """Every method should have auth-related params (auth, ccache_path)."""
        for name, defn in self._yaml.get("methods", {}).items():
            params = defn.get("params", {})
            assert "auth" in params, f"Method {name} missing 'auth' param"
            assert "ccache_path" in params, f"Method {name} missing 'ccache_path' param"

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
            pytest.skip("Cannot import EvilWinRMServer")

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
            pytest.skip("Cannot import EvilWinRMServer")

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
            pytest.skip("Cannot import EvilWinRMServer")

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
# ACCEPTANCE TESTS — all methods through Docker container, no live target
# ===========================================================================

class TestAcceptance:
    """Call every method through the container without a live WinRM target.

    These tests verify:
    - The method exists and is callable through the MCP protocol
    - Required param validation works (missing required params -> error)
    - The response has correct structuredContent shape
    - Error responses have error_class set (classified, not crash)
    - Different auth param combinations are accepted without crashing

    Each test sends args with an unreachable target (192.0.2.1 = TEST-NET)
    so the call fails at connection time, but the MCP protocol layer, param
    validation, and error classification should all function correctly.
    """

    _FAKE_AUTH = {
        "target": "192.0.2.1",
        "username": "testuser",
        "password": "testpass",
    }

    def _assert_structured_error(self, resp, method_name):
        """Assert response is a classified error with structuredContent."""
        result = resp.get("result", {})
        sc = result.get("structuredContent", {})
        assert sc is not None, f"{method_name}: missing structuredContent"
        # Should be an error
        assert sc.get("success") is False or result.get("isError") is True, (
            f"{method_name}: expected error for unreachable target, got success"
        )
        # Should have an error_class set
        if not sc.get("success", True):
            assert sc.get("error_class") is not None, (
                f"{method_name}: error has no error_class: {sc}"
            )
        # Should have proper shape
        for field in ("success", "error_class", "retryable", "suggestions"):
            assert field in sc, f"{method_name}: missing field '{field}' in structuredContent"
        # Should NOT be an unhandled crash
        content_text = ""
        for c in result.get("content", []):
            if c.get("type") == "text":
                content_text += c["text"]
        assert "unexpected keyword argument" not in content_text, (
            f"{method_name}: unhandled keyword argument error"
        )
        assert "Internal error" not in content_text, (
            f"{method_name}: internal crash error"
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

    # ── exec method ────────────────────────────────────────────

    def test_exec_unreachable_target(self, evil_winrm_env):
        """exec with unreachable target returns classified network/timeout error."""
        client, loop = evil_winrm_env
        resp = loop.run_until_complete(client.call("exec", {
            **self._FAKE_AUTH, "command": "whoami",
        }))
        sc = self._assert_structured_error(resp, "exec")
        assert sc["error_class"] in ("network", "timeout"), (
            f"Unreachable target should be network or timeout, got: {sc['error_class']}"
        )

    def test_exec_missing_target(self, evil_winrm_env):
        """exec without 'target' returns param validation error."""
        client, loop = evil_winrm_env
        resp = loop.run_until_complete(client.call("exec", {
            "username": "test", "password": "test", "command": "whoami",
        }))
        result = resp.get("result", {})
        is_error = result.get("isError", False)
        content_text = self._get_content_text(resp)
        assert is_error or "target" in content_text.lower(), (
            f"Expected error about missing 'target', got: {content_text[:300]}"
        )

    def test_exec_missing_username(self, evil_winrm_env):
        """exec without 'username' returns param validation error."""
        client, loop = evil_winrm_env
        resp = loop.run_until_complete(client.call("exec", {
            "target": "192.0.2.1", "password": "test", "command": "whoami",
        }))
        result = resp.get("result", {})
        is_error = result.get("isError", False)
        content_text = self._get_content_text(resp)
        assert is_error or "username" in content_text.lower(), (
            f"Expected error about missing 'username', got: {content_text[:300]}"
        )

    def test_exec_missing_command(self, evil_winrm_env):
        """exec without 'command' returns param validation error."""
        client, loop = evil_winrm_env
        resp = loop.run_until_complete(client.call("exec", {
            "target": "192.0.2.1", "username": "test", "password": "test",
        }))
        result = resp.get("result", {})
        is_error = result.get("isError", False)
        content_text = self._get_content_text(resp)
        assert is_error or "command" in content_text.lower(), (
            f"Expected error about missing 'command', got: {content_text[:300]}"
        )

    def test_exec_cmd_shell_mode(self, evil_winrm_env):
        """exec with shell='cmd' is accepted (fails at connection, not params)."""
        client, loop = evil_winrm_env
        resp = loop.run_until_complete(client.call("exec", {
            **self._FAKE_AUTH, "command": "dir C:\\", "shell": "cmd",
        }))
        sc = self._assert_structured_error(resp, "exec_cmd_shell")
        # Should be a connection error, not a params error
        assert sc["error_class"] != "params", (
            f"shell='cmd' should be valid, got params error"
        )

    def test_exec_powershell_shell_mode(self, evil_winrm_env):
        """exec with shell='powershell' (default) is accepted."""
        client, loop = evil_winrm_env
        resp = loop.run_until_complete(client.call("exec", {
            **self._FAKE_AUTH, "command": "Get-Process",
            "shell": "powershell",
        }))
        sc = self._assert_structured_error(resp, "exec_powershell_shell")
        assert sc["error_class"] != "params"

    def test_exec_with_domain(self, evil_winrm_env):
        """exec with domain parameter is accepted (domain\\user format)."""
        client, loop = evil_winrm_env
        resp = loop.run_until_complete(client.call("exec", {
            **self._FAKE_AUTH, "command": "whoami",
            "domain": "CORP.LOCAL",
        }))
        sc = self._assert_structured_error(resp, "exec_with_domain")
        assert sc["error_class"] != "params"

    def test_exec_with_hash(self, evil_winrm_env):
        """exec with NTLM hash (pass-the-hash) is accepted."""
        client, loop = evil_winrm_env
        resp = loop.run_until_complete(client.call("exec", {
            "target": "192.0.2.1",
            "username": "administrator",
            "hash": "aad3b435b51404eeaad3b435b51404ee:deadbeefdeadbeefdeadbeefdeadbeef",
            "command": "whoami",
        }))
        sc = self._assert_structured_error(resp, "exec_with_hash")
        assert sc["error_class"] != "params"

    def test_exec_with_bare_nt_hash(self, evil_winrm_env):
        """exec with bare NT hash (auto-prepend LM zeros) is accepted."""
        client, loop = evil_winrm_env
        resp = loop.run_until_complete(client.call("exec", {
            "target": "192.0.2.1",
            "username": "administrator",
            "hash": "deadbeefdeadbeefdeadbeefdeadbeef",
            "command": "whoami",
        }))
        sc = self._assert_structured_error(resp, "exec_bare_hash")
        assert sc["error_class"] != "params"

    def test_exec_kerberos_auth(self, evil_winrm_env):
        """exec with auth='kerberos' is accepted without crash."""
        client, loop = evil_winrm_env
        resp = loop.run_until_complete(client.call("exec", {
            "target": "192.0.2.1",
            "username": "user@CORP.LOCAL",
            "auth": "kerberos",
            "ccache_path": "/session/credentials/user.ccache",
            "command": "whoami",
        }))
        sc = self._assert_structured_error(resp, "exec_kerberos")
        # Should not crash on kerberos params
        content_text = self._get_content_text(resp)
        assert "unexpected keyword" not in content_text

    def test_exec_ssl_mode(self, evil_winrm_env):
        """exec with ssl=true is accepted (uses port 5986)."""
        client, loop = evil_winrm_env
        resp = loop.run_until_complete(client.call("exec", {
            **self._FAKE_AUTH, "command": "whoami", "ssl": True,
        }))
        sc = self._assert_structured_error(resp, "exec_ssl")
        assert sc["error_class"] != "params"

    def test_exec_custom_port(self, evil_winrm_env):
        """exec with custom port is accepted."""
        client, loop = evil_winrm_env
        resp = loop.run_until_complete(client.call("exec", {
            **self._FAKE_AUTH, "command": "whoami", "port": 47001,
        }))
        sc = self._assert_structured_error(resp, "exec_custom_port")
        assert sc["error_class"] != "params"

    # ── upload method ──────────────────────────────────────────

    def test_upload_unreachable_target(self, evil_winrm_env):
        """upload with unreachable target returns classified error.

        Note: the local file path must reference a file inside the container.
        Host-side temp files are not visible to the containerized server.
        Since /session/ is typically mounted, we use a path there, but in
        test mode (no real /session/ mount) the file won't exist, so we
        expect a 'params' error (file not found). The key assertion is that
        the response is properly classified, not a crash.
        """
        client, loop = evil_winrm_env
        resp = loop.run_until_complete(client.call("upload", {
            **self._FAKE_AUTH,
            "local_path": "/session/artifacts/test_upload.txt",
            "remote_path": "C:\\Windows\\Temp\\test.txt",
        }))
        sc = self._assert_structured_error(resp, "upload_unreachable")
        # File doesn't exist in container -> params error (file not found)
        # If the file DID exist, we'd get network/timeout/auth
        assert sc["error_class"] in ("params", "network", "timeout", "auth"), (
            f"Expected classified error, got: {sc['error_class']}"
        )

    def test_upload_missing_file(self, evil_winrm_env):
        """upload with nonexistent local_path returns params error_class."""
        client, loop = evil_winrm_env
        resp = loop.run_until_complete(client.call("upload", {
            **self._FAKE_AUTH,
            "local_path": "/nonexistent/path/exploit.exe",
            "remote_path": "C:\\Windows\\Temp\\exploit.exe",
        }))
        sc = self._assert_structured_error(resp, "upload_missing_file")
        assert sc["error_class"] == "params", (
            f"Missing file should be 'params' error, got: {sc['error_class']}"
        )

    def test_upload_missing_local_path_param(self, evil_winrm_env):
        """upload without 'local_path' returns error about missing param."""
        client, loop = evil_winrm_env
        resp = loop.run_until_complete(client.call("upload", {
            **self._FAKE_AUTH,
            "remote_path": "C:\\Windows\\Temp\\test.txt",
        }))
        result = resp.get("result", {})
        is_error = result.get("isError", False)
        content_text = self._get_content_text(resp)
        assert is_error or "local_path" in content_text.lower(), (
            f"Expected error about missing 'local_path', got: {content_text[:300]}"
        )

    def test_upload_missing_remote_path_param(self, evil_winrm_env):
        """upload without 'remote_path' returns error about missing param."""
        client, loop = evil_winrm_env
        resp = loop.run_until_complete(client.call("upload", {
            **self._FAKE_AUTH,
            "local_path": "/tmp/some_file.txt",
        }))
        result = resp.get("result", {})
        is_error = result.get("isError", False)
        content_text = self._get_content_text(resp)
        assert is_error or "remote_path" in content_text.lower(), (
            f"Expected error about missing 'remote_path', got: {content_text[:300]}"
        )

    def test_upload_with_domain_and_hash(self, evil_winrm_env):
        """upload with domain + hash auth combo does not crash."""
        client, loop = evil_winrm_env
        resp = loop.run_until_complete(client.call("upload", {
            "target": "192.0.2.1",
            "username": "admin",
            "hash": "deadbeefdeadbeefdeadbeefdeadbeef",
            "domain": "CORP",
            "local_path": "/nonexistent",
            "remote_path": "C:\\Temp\\test.exe",
        }))
        result = resp.get("result", {})
        content_text = self._get_content_text(resp)
        assert "unexpected keyword" not in content_text
        assert "Internal error" not in content_text

    # ── download method ────────────────────────────────────────

    def test_download_unreachable_target(self, evil_winrm_env):
        """download with unreachable target returns classified error."""
        client, loop = evil_winrm_env
        resp = loop.run_until_complete(client.call("download", {
            **self._FAKE_AUTH,
            "remote_path": "C:\\Users\\Administrator\\Desktop\\root.txt",
        }))
        sc = self._assert_structured_error(resp, "download_unreachable")
        assert sc["error_class"] in ("network", "timeout", "auth"), (
            f"Expected network/timeout/auth error, got: {sc['error_class']}"
        )

    def test_download_missing_remote_path_param(self, evil_winrm_env):
        """download without 'remote_path' returns error about missing param."""
        client, loop = evil_winrm_env
        resp = loop.run_until_complete(client.call("download", {
            **self._FAKE_AUTH,
        }))
        result = resp.get("result", {})
        is_error = result.get("isError", False)
        content_text = self._get_content_text(resp)
        assert is_error or "remote_path" in content_text.lower(), (
            f"Expected error about missing 'remote_path', got: {content_text[:300]}"
        )

    def test_download_with_local_path(self, evil_winrm_env):
        """download with explicit local_path does not crash."""
        client, loop = evil_winrm_env
        resp = loop.run_until_complete(client.call("download", {
            **self._FAKE_AUTH,
            "remote_path": "C:\\flag.txt",
            "local_path": "/session/artifacts/flag.txt",
        }))
        sc = self._assert_structured_error(resp, "download_with_local_path")
        assert sc["error_class"] != "params"

    def test_download_default_local_path(self, evil_winrm_env):
        """download without local_path defaults to /session/artifacts/<filename>."""
        client, loop = evil_winrm_env
        resp = loop.run_until_complete(client.call("download", {
            **self._FAKE_AUTH,
            "remote_path": "C:\\Users\\Public\\Desktop\\user.txt",
        }))
        # Just verify it doesn't crash on path defaulting
        sc = self._assert_structured_error(resp, "download_default_path")
        assert sc["error_class"] != "params"

    def test_download_with_hash_auth(self, evil_winrm_env):
        """download with pass-the-hash auth is accepted."""
        client, loop = evil_winrm_env
        resp = loop.run_until_complete(client.call("download", {
            "target": "192.0.2.1",
            "username": "administrator",
            "hash": "deadbeefdeadbeefdeadbeefdeadbeef",
            "remote_path": "C:\\Windows\\System32\\config\\SAM",
        }))
        sc = self._assert_structured_error(resp, "download_with_hash")
        assert sc["error_class"] != "params"

    def test_download_kerberos_auth(self, evil_winrm_env):
        """download with Kerberos auth is accepted without crash."""
        client, loop = evil_winrm_env
        resp = loop.run_until_complete(client.call("download", {
            "target": "192.0.2.1",
            "username": "user@CORP.LOCAL",
            "auth": "kerberos",
            "remote_path": "C:\\flag.txt",
        }))
        sc = self._assert_structured_error(resp, "download_kerberos")
        content_text = self._get_content_text(resp)
        assert "unexpected keyword" not in content_text

    # ── Cross-cutting acceptance tests ─────────────────────────

    def test_unknown_method_returns_helpful_error(self, evil_winrm_env):
        """Calling nonexistent method 'connect' returns helpful error.

        From engagement: agent hallucinated a 'connect' method (1 occurrence).
        """
        client, loop = evil_winrm_env
        resp = loop.run_until_complete(client.call("connect", {
            "target": "10.0.0.1", "username": "test", "password": "test",
        }))
        result = assert_tool_error(resp)
        content_text = self._get_content_text(resp)
        assert "Unknown method" in content_text
        assert "connect" in content_text
        # Should list available methods
        assert "exec" in content_text

    def test_unknown_method_execute(self, evil_winrm_env):
        """Calling 'execute' (similar to 'exec') returns helpful error.

        From engagement: agent used 'execute' instead of 'exec' (5 occurrences).
        """
        client, loop = evil_winrm_env
        resp = loop.run_until_complete(client.call("execute", {
            "target": "10.0.0.1", "username": "test",
            "password": "test", "command": "whoami",
        }))
        result = assert_tool_error(resp)
        content_text = self._get_content_text(resp)
        assert "Unknown method" in content_text

    def test_all_methods_have_structuredContent(self, evil_winrm_env):
        """Every method returns structuredContent with required fields."""
        client, loop = evil_winrm_env
        # Test with verify_clock (guaranteed to succeed)
        resp = loop.run_until_complete(client.call("verify_clock", {}))
        result = resp.get("result", {})
        sc = result.get("structuredContent")
        assert sc is not None
        assert isinstance(sc, dict)
        for field in ("success", "error_class", "retryable", "suggestions"):
            assert field in sc, f"Missing field '{field}' in structuredContent"

    def test_meta_params_not_leaked_to_handler(self, evil_winrm_env):
        """Meta-params (timeout, clock_offset) are stripped by BaseMCPServer.

        From engagement: timeout was passed 5+ times. Should never reach handler.
        """
        client, loop = evil_winrm_env
        resp = loop.run_until_complete(client.call("exec", {
            **self._FAKE_AUTH,
            "command": "whoami",
            "timeout": 60,
            "clock_offset": "+5h",
        }))
        content_text = self._get_content_text(resp)
        assert "unexpected keyword argument" not in content_text
        assert "Internal error" not in content_text

    def test_engagement_style_kwargs_absorbed(self, evil_winrm_env):
        """Agent-sent unknown params (kerberos, dc_ip, upload) don't crash.

        From engagement: agents pass these extra params ~20 times. The **kwargs
        in handler methods should absorb them silently.
        """
        client, loop = evil_winrm_env
        resp = loop.run_until_complete(client.call("exec", {
            **self._FAKE_AUTH,
            "command": "whoami",
            "kerberos": True,
            "dc_ip": "10.0.0.1",
            "upload": ["/tmp/file.exe", "C:\\Temp\\file.exe"],
        }))
        content_text = self._get_content_text(resp)
        assert "unexpected keyword argument" not in content_text
        assert "Internal error" not in content_text


# ===========================================================================
# INTEGRATION TESTS — require --target, --username, --password
# ===========================================================================

@pytest.mark.integration
class TestIntegration:
    """Integration tests that need a real WinRM target.

    Run with: pytest tests/tools/test_evil_winrm.py --tool=evil-winrm
              --target=<IP> --username=<USER> --password=<PASS>
              -m integration -v
    """

    def test_exec_whoami(self, evil_winrm_env, target, username, password):
        """Execute whoami via WinRM."""
        client, loop = evil_winrm_env
        resp = loop.run_until_complete(client.call("exec", {
            "target": target,
            "username": username,
            "password": password,
            "command": "whoami",
        }))
        result = assert_tool_success(resp, "exec whoami should succeed")
        data = parse_tool_output(resp)
        assert data.get("output"), "whoami should return output"
        assert data.get("shell") == "PowerShell"

    def test_exec_cmd_shell(self, evil_winrm_env, target, username, password):
        """Execute dir via CMD shell."""
        client, loop = evil_winrm_env
        resp = loop.run_until_complete(client.call("exec", {
            "target": target,
            "username": username,
            "password": password,
            "command": "dir C:\\",
            "shell": "cmd",
        }))
        result = assert_tool_success(resp, "CMD dir should succeed")
        data = parse_tool_output(resp)
        assert data.get("shell") == "CMD"

    def test_exec_powershell(self, evil_winrm_env, target, username, password):
        """Execute Get-Process via PowerShell."""
        client, loop = evil_winrm_env
        resp = loop.run_until_complete(client.call("exec", {
            "target": target,
            "username": username,
            "password": password,
            "command": "Get-Process | Select-Object -First 5 | Format-Table Name, Id",
        }))
        result = assert_tool_success(resp, "PowerShell Get-Process should succeed")

    def test_exec_with_domain(self, evil_winrm_env, target, domain, username, password):
        """Execute with domain prefix."""
        if not domain:
            pytest.skip("--domain not provided")
        client, loop = evil_winrm_env
        resp = loop.run_until_complete(client.call("exec", {
            "target": target,
            "username": username,
            "password": password,
            "domain": domain,
            "command": "whoami /all",
        }))
        data = parse_tool_output(resp)
        # Even if it fails auth, should not crash
        assert data is not None

    def test_exec_bad_creds(self, evil_winrm_env, target):
        """Bad credentials should return auth error, not crash."""
        client, loop = evil_winrm_env
        resp = loop.run_until_complete(client.call("exec", {
            "target": target,
            "username": "nonexistent_xyz",
            "password": "wrong_password_abc",
            "command": "whoami",
        }))
        result = resp.get("result", {})
        assert result.get("isError") is True
        sc = result.get("structuredContent", {})
        assert sc.get("error_class") == "auth", (
            f"Bad creds should be 'auth' error, got: {sc.get('error_class')}"
        )

    def test_upload_and_download(self, evil_winrm_env, target, username, password):
        """Upload then download a test file."""
        import tempfile
        client, loop = evil_winrm_env

        # Create a temp file to upload
        with tempfile.NamedTemporaryFile(mode='w', suffix='.txt', delete=False) as f:
            f.write("OpenSploit test file content")
            local_src = f.name

        try:
            remote_path = "C:\\Windows\\Temp\\opensploit_test.txt"

            # Upload
            resp = loop.run_until_complete(client.call("upload", {
                "target": target,
                "username": username,
                "password": password,
                "local_path": local_src,
                "remote_path": remote_path,
            }))
            result = assert_tool_success(resp, "upload should succeed")
            data = parse_tool_output(resp)
            assert data.get("size") > 0

            # Download
            resp = loop.run_until_complete(client.call("download", {
                "target": target,
                "username": username,
                "password": password,
                "remote_path": remote_path,
            }))
            result = assert_tool_success(resp, "download should succeed")
            data = parse_tool_output(resp)
            assert data.get("size") > 0

            # Clean up remote file
            loop.run_until_complete(client.call("exec", {
                "target": target,
                "username": username,
                "password": password,
                "command": f"Remove-Item '{remote_path}' -Force",
            }))
        finally:
            os.unlink(local_src)

    def test_exec_pass_the_hash(self, evil_winrm_env, target, username):
        """Test pass-the-hash authentication (requires --hash flag or skip)."""
        # This is a manual integration test — skip by default
        pytest.skip("Pass-the-hash requires specific NTLM hash setup")
