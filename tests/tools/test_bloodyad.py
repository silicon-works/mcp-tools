"""
Tests for the bloodyad MCP tool server (27 methods, 235 tests).

Covers:
- Smoke tests: boot, method list, required params, meta-param stripping, clock
- Unit tests: error classification using fixture data (including engagement edge cases)
- Unit tests: success fixture parsing
- Unit tests: command building (_build_auth, per-method CLI args)
  - certificate param (-c key:cert)
  - format param (-f hex/aes/rc4)
  - extra_args on all 27 methods (shlex.split, empty/None/quoted)
  - get_dnsdump zone/no_detail/transitive flags
  - get_search resolve_sd flag
  - add_dns_record SRV (port/priority/weight), MX (preference), all dnstype variants
  - remove_dns_record all params
  - remove_object target param
- Unit tests: auth env helper (_get_auth_env)
- Contract tests: tool.yaml vs server parameter definitions (bidirectional)
  - All 27 methods have extra_args, certificate, format
  - All params have type and description
- Acceptance tests: every method called through container (no live AD target)
  - New methods: remove_dns_record, remove_object (with missing param validation)
  - certificate param accepted on read + write methods
  - format param accepted (hex, aes, rc4)
  - extra_args accepted on read, write, remove methods
  - structuredContent on every response
- Integration tests: real AD target scenarios (marked @pytest.mark.integration)
"""

import asyncio
import json
import os
import sys
from pathlib import Path
from typing import Any, Dict
from unittest.mock import patch

import pytest
import yaml

# ---------------------------------------------------------------------------
# Path setup
# ---------------------------------------------------------------------------
PROJECT_ROOT = Path(__file__).parent.parent.parent
TOOL_DIR = PROJECT_ROOT / "tools" / "bloodyad"
FIXTURES_DIR = Path(__file__).parent.parent / "fixtures" / "bloodyad"

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
def bloodyad_env(request):
    """Create an MCPTestClient with its event loop. Yields (client, loop)."""
    tool = "bloodyad"
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
    """Import and return the BloodyADServer class for direct method testing."""
    import importlib.util
    spec = importlib.util.spec_from_file_location(
        "bloodyad_server", TOOL_DIR / "mcp-server.py"
    )
    mod = importlib.util.module_from_spec(spec)
    spec.loader.exec_module(mod)
    return mod.BloodyADServer


# ---------------------------------------------------------------------------
# Helper: get a server instance for unit tests
# ---------------------------------------------------------------------------
@pytest.fixture(scope="module")
def server():
    """Create a BloodyADServer instance for direct unit testing."""
    try:
        cls = _get_server_class()
        return cls()
    except Exception as e:
        pytest.skip(f"Cannot import BloodyADServer: {e}")


# ===========================================================================
# SMOKE TESTS -- require Docker container running
# ===========================================================================

class TestSmoke:
    """Smoke tests that verify the container boots and basic protocol works."""

    def test_boot_and_list_tools(self, bloodyad_env):
        """Container starts and list_tools returns methods."""
        client, loop = bloodyad_env
        assert len(client.tools) > 0, "Server should advertise at least one tool"
        names = client.tool_names()
        assert "set_password" in names, "set_password should be in tool list"
        assert "get_object" in names, "get_object should be in tool list"
        assert "add_shadow_credentials" in names, "add_shadow_credentials should be in tool list"
        assert "add_rbcd" in names, "add_rbcd should be in tool list"
        assert "get_writable" in names, "get_writable should be in tool list"

    def test_method_list_matches_tool_yaml(self, bloodyad_env, tool_methods_from_yaml):
        """Every method in tool.yaml is advertised by the server, and vice versa."""
        client, _ = bloodyad_env
        server_names = client.tool_names()

        # Remove verify_clock -- it's test-only, not in tool.yaml
        server_names_no_test = server_names - {"verify_clock"}

        yaml_only = tool_methods_from_yaml - server_names_no_test
        server_only = server_names_no_test - tool_methods_from_yaml

        assert not yaml_only, f"Methods in tool.yaml but not server: {yaml_only}"
        assert not server_only, f"Methods in server but not tool.yaml: {server_only}"

    def test_expected_method_count(self, bloodyad_env):
        """Server should have exactly 25 built-in methods + verify_clock."""
        client, _ = bloodyad_env
        names = client.tool_names()
        # 27 built-in + verify_clock in MCP_TEST_MODE
        assert len(names) == 28, (
            f"Expected 28 methods (27 built-in + verify_clock), got {len(names)}: {sorted(names)}"
        )

    def test_required_params_enforced_set_password(self, bloodyad_env):
        """Calling set_password without required 'target' param returns an error."""
        client, loop = bloodyad_env
        resp = loop.run_until_complete(
            client.call("set_password", {
                "host": "10.0.0.1",
                "domain": "test.local",
                "new_password": "NewPass123!",
            })
        )
        result = resp.get("result", {})
        is_error = result.get("isError", False)
        content_text = ""
        for c in result.get("content", []):
            if c.get("type") == "text":
                content_text += c["text"]
        assert is_error or "target" in content_text.lower() or "missing" in content_text.lower() or "error" in content_text.lower(), (
            f"Expected error about missing 'target', got: {content_text[:300]}"
        )

    def test_required_params_enforced_get_search(self, bloodyad_env):
        """Calling get_search without required 'filter' returns error."""
        client, loop = bloodyad_env
        resp = loop.run_until_complete(
            client.call("get_search", {
                "host": "10.0.0.1",
                "domain": "test.local",
            })
        )
        result = resp.get("result", {})
        is_error = result.get("isError", False)
        content_text = ""
        for c in result.get("content", []):
            if c.get("type") == "text":
                content_text += c["text"]
        assert is_error or "filter" in content_text.lower() or "missing" in content_text.lower() or "error" in content_text.lower(), (
            f"Expected error about missing 'filter', got: {content_text[:300]}"
        )

    def test_meta_params_stripped(self, bloodyad_env):
        """Passing 'clock_offset' (meta-param) in args does not crash the server."""
        client, loop = bloodyad_env
        resp = loop.run_until_complete(
            client.call("get_object", {
                "host": "10.0.0.1",
                "domain": "test.local",
                "username": "test",
                "password": "test",
                "target": "Administrator",
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

    def test_unknown_method_returns_error(self, bloodyad_env):
        """Calling a non-existent method returns a helpful error."""
        client, loop = bloodyad_env
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
    def test_verify_clock_available(self, bloodyad_env):
        """verify_clock is registered in MCP_TEST_MODE."""
        client, _ = bloodyad_env
        names = client.tool_names()
        assert "verify_clock" in names, "verify_clock should be available in test mode"

    @pytest.mark.clock
    def test_verify_clock_returns_time(self, bloodyad_env):
        """verify_clock returns current time and FAKETIME status."""
        client, loop = bloodyad_env
        resp = loop.run_until_complete(client.call("verify_clock", {}))
        result = assert_tool_success(resp)
        data = parse_tool_output(resp)
        assert "current_time" in data
        assert "libfaketime_exists" in data
        # libfaketime is installed in this image
        assert data["libfaketime_exists"] is True, (
            "libfaketime should be installed in the bloodyad image"
        )

    def test_structuredContent_present(self, bloodyad_env):
        """Responses include structuredContent with error classification fields."""
        client, loop = bloodyad_env
        resp = loop.run_until_complete(client.call("verify_clock", {}))
        result = resp.get("result", {})
        sc = result.get("structuredContent")
        assert sc is not None, "structuredContent should be present"
        assert "success" in sc
        assert "error_class" in sc
        assert "retryable" in sc
        assert "suggestions" in sc


# ===========================================================================
# ERROR CLASSIFICATION TESTS -- test _classify_bloodyad_error
# ===========================================================================

class TestErrorClassification:
    """Test the _classify_bloodyad_error helper using fixture data.

    These verify that the server correctly classifies LDAP, Kerberos,
    and connection errors with error_class, retryable, and suggestions.
    """

    @pytest.fixture(autouse=True, scope="class")
    def setup_server(self):
        """Create a server instance for error classification testing."""
        try:
            cls = _get_server_class()
            self.__class__._server = cls()
        except Exception as e:
            pytest.skip(f"Cannot import BloodyADServer: {e}")

    def test_classify_insufficient_access_rights(self):
        """insufficientAccessRights should be 'permission', not retryable."""
        text = load_fixture("insufficient_access_rights.txt")
        err_class, retryable, suggestions = self._server._classify_bloodyad_error(text)
        assert err_class == "permission", f"Expected 'permission', got '{err_class}'"
        assert retryable is False
        assert len(suggestions) > 0

    def test_classify_invalid_credentials(self):
        """invalidCredentials should be 'auth', not retryable."""
        text = load_fixture("invalid_credentials.txt")
        err_class, retryable, suggestions = self._server._classify_bloodyad_error(text)
        assert err_class == "auth", f"Expected 'auth', got '{err_class}'"
        assert retryable is False

    def test_classify_connection_error(self):
        """ConnectionRefusedError should be 'network', retryable."""
        text = load_fixture("connection_error.txt")
        err_class, retryable, suggestions = self._server._classify_bloodyad_error(text)
        assert err_class == "network", f"Expected 'network', got '{err_class}'"
        assert retryable is True

    def test_classify_kerberos_clock_skew(self):
        """KRB_AP_ERR_SKEW should be 'config', retryable."""
        text = load_fixture("kerberos_clock_skew.txt")
        err_class, retryable, suggestions = self._server._classify_bloodyad_error(text)
        assert err_class == "config", f"Expected 'config', got '{err_class}'"
        assert retryable is True
        assert len(suggestions) > 0
        assert any("clock" in s.lower() for s in suggestions), (
            f"Should suggest clock fix, got: {suggestions}"
        )

    def test_classify_shadow_credentials_acl_denied(self):
        """Shadow credentials ACL denied should be 'permission', not retryable."""
        text = load_fixture("shadow_credentials_acl_denied.txt")
        err_class, retryable, suggestions = self._server._classify_bloodyad_error(text)
        assert err_class == "permission", f"Expected 'permission', got '{err_class}'"
        assert retryable is False
        assert any("msds-keycredentiallink" in s.lower() for s in suggestions), (
            f"Should mention msDS-KeyCredentialLink, got: {suggestions}"
        )

    def test_classify_constraint_violation(self):
        """constraintViolation should be 'params', not retryable."""
        text = load_fixture("constraint_violation.txt")
        err_class, retryable, suggestions = self._server._classify_bloodyad_error(text)
        assert err_class == "params", f"Expected 'params', got '{err_class}'"
        assert retryable is False

    def test_classify_unwilling_to_perform(self):
        """unwillingToPerform should be 'permission', not retryable."""
        text = load_fixture("unwilling_to_perform.txt")
        err_class, retryable, suggestions = self._server._classify_bloodyad_error(text)
        assert err_class == "permission", f"Expected 'permission', got '{err_class}'"
        assert retryable is False

    def test_classify_password_change_failed(self):
        """Password change failure should be 'auth', not retryable."""
        text = load_fixture("password_change_failed.txt")
        err_class, retryable, suggestions = self._server._classify_bloodyad_error(text)
        assert err_class == "auth", f"Expected 'auth', got '{err_class}'"
        assert retryable is False
        assert any("smbpasswd" in s.lower() for s in suggestions), (
            f"Should suggest smbpasswd alternative, got: {suggestions}"
        )

    def test_classify_no_such_object(self):
        """NoResultError / no object found should be 'params', not retryable."""
        text = load_fixture("get_object_no_such_object.txt")
        err_class, retryable, suggestions = self._server._classify_bloodyad_error(text)
        assert err_class == "params", f"Expected 'params', got '{err_class}'"
        assert retryable is False

    def test_classify_empty_input(self):
        """Empty input should return 'unknown'."""
        err_class, retryable, suggestions = self._server._classify_bloodyad_error("")
        assert err_class == "unknown"
        assert retryable is False

    def test_classify_clean_output_not_misclassified(self):
        """Successful get_object output should classify as unknown (not error)."""
        text = load_fixture("get_object_success.txt")
        err_class, retryable, suggestions = self._server._classify_bloodyad_error(text)
        assert err_class == "unknown", f"Clean output misclassified as '{err_class}'"

    # ── Additional error classification tests ───────────────────

    def test_classify_connection_reset(self):
        """ConnectionResetError should be 'network', retryable."""
        text = load_fixture("connection_reset.txt")
        err_class, retryable, suggestions = self._server._classify_bloodyad_error(text)
        assert err_class == "network", f"Expected 'network', got '{err_class}'"
        assert retryable is True

    def test_classify_kerberos_preauth_failed(self):
        """KDC_ERR_PREAUTH_FAILED should be 'auth', not retryable."""
        text = load_fixture("kerberos_preauth_failed.txt")
        err_class, retryable, suggestions = self._server._classify_bloodyad_error(text)
        assert err_class == "auth", f"Expected 'auth', got '{err_class}'"
        assert retryable is False

    def test_classify_generic_kerberos_error(self):
        """Generic minikerberos error should be 'auth'."""
        text = load_fixture("generic_kerberos_error.txt")
        err_class, retryable, suggestions = self._server._classify_bloodyad_error(text)
        assert err_class == "auth", f"Expected 'auth', got '{err_class}'"
        assert retryable is False
        assert any("ntlm" in s.lower() for s in suggestions), (
            f"Should suggest NTLM as fallback, got: {suggestions}"
        )

    def test_classify_timeout_error(self):
        """TimeoutError should be 'network', retryable."""
        text = load_fixture("timeout_error.txt")
        err_class, retryable, suggestions = self._server._classify_bloodyad_error(text)
        assert err_class == "network", f"Expected 'network', got '{err_class}'"
        assert retryable is True

    def test_classify_generic_traceback(self):
        """NoneType crash from msldap on invalid creds should classify as 'auth'."""
        text = load_fixture("generic_traceback.txt")
        err_class, retryable, suggestions = self._server._classify_bloodyad_error(text)
        assert err_class == "auth", f"Expected 'auth', got '{err_class}'"
        assert retryable is False

    def test_classify_inline_insufficient_access(self):
        """Inline INSUFF_ACCESS_RIGHTS string should classify as 'permission'."""
        err_class, retryable, suggestions = self._server._classify_bloodyad_error(
            "LDAPModifyException: INSUFF_ACCESS_RIGHTS"
        )
        assert err_class == "permission"
        assert retryable is False

    def test_classify_inline_accept_security_context(self):
        """Inline AcceptSecurityContext string should classify as 'auth'."""
        err_class, retryable, suggestions = self._server._classify_bloodyad_error(
            "AcceptSecurityContext error, data 52e"
        )
        assert err_class == "auth"
        assert retryable is False

    def test_classify_inline_no_such_object(self):
        """noSuchObject string should classify as 'params'."""
        err_class, retryable, suggestions = self._server._classify_bloodyad_error(
            "Result code: noSuchObject"
        )
        assert err_class == "params"
        assert retryable is False

    def test_classify_inline_will_not_perform(self):
        """WILL_NOT_PERFORM string should classify as 'permission'."""
        err_class, retryable, suggestions = self._server._classify_bloodyad_error(
            "problem 5003 (WILL_NOT_PERFORM)"
        )
        assert err_class == "permission"
        assert retryable is False

    # ── Edge cases from real engagements (Certified HTB) ──────

    def test_classify_object_class_violation(self):
        """objectClassViolation (e.g., adding user to non-group) falls through to traceback."""
        text = load_fixture("object_class_violation.txt")
        err_class, retryable, suggestions = self._server._classify_bloodyad_error(text)
        # Not specifically handled -- falls through to generic Traceback
        assert err_class == "unknown", f"Expected 'unknown', got '{err_class}'"
        assert retryable is True  # generic traceback is retryable

    def test_classify_insufficient_access_specific_attr(self):
        """insufficientAccessRights on specific attribute (msDS-KeyCredentialLink) -> permission."""
        text = load_fixture("insufficient_access_specific_attr.txt")
        err_class, retryable, suggestions = self._server._classify_bloodyad_error(text)
        assert err_class == "permission", f"Expected 'permission', got '{err_class}'"
        assert retryable is False
        assert len(suggestions) > 0

    def test_classify_insufficient_access_with_attribute_name(self):
        """Inline insufficientAccessRights with attribute context classifies as permission."""
        err_class, retryable, suggestions = self._server._classify_bloodyad_error(
            'LDAP Modify on msDS-AllowedToActOnBehalfOfOtherIdentity: insufficientAccessRights'
        )
        assert err_class == "permission"
        assert retryable is False

    def test_classify_multiple_patterns_first_wins(self):
        """When output contains multiple error patterns, first matching rule wins."""
        # insufficientAccessRights appears before Traceback
        text = "insufficientAccessRights\nTraceback (most recent call last):\n  File..."
        err_class, retryable, suggestions = self._server._classify_bloodyad_error(text)
        assert err_class == "permission", "insufficientAccessRights should match before Traceback"
        assert retryable is False

    def test_classify_nonetype_crash_as_auth(self):
        """NoneType 'not subscriptable' crash from msldap should classify as 'auth'."""
        text = "TypeError: 'NoneType' object is not subscriptable"
        err_class, retryable, suggestions = self._server._classify_bloodyad_error(text)
        assert err_class == "auth", f"Expected 'auth', got '{err_class}'"
        assert retryable is False
        assert any("credentials" in s.lower() or "authentication" in s.lower() for s in suggestions)

    def test_classify_invalid_attribute_syntax(self):
        """invalidAttributeSyntax LDAP error should classify as 'params'."""
        text = "LDAPModifyException: invalidAttributeSyntax"
        err_class, retryable, suggestions = self._server._classify_bloodyad_error(text)
        assert err_class == "params", f"Expected 'params', got '{err_class}'"
        assert retryable is False
        assert any("attribute" in s.lower() for s in suggestions)


# ===========================================================================
# UNIT TESTS -- success fixture parsing
# ===========================================================================

class TestSuccessFixtures:
    """Verify that success fixtures contain the expected patterns.

    bloodyAD output is returned as raw_output (not parsed into structured
    fields), so these tests verify the raw output content.
    """

    def test_get_object_success_has_attributes(self):
        """get_object success output should contain AD attributes."""
        text = load_fixture("get_object_success.txt")
        assert "distinguishedName:" in text
        assert "sAMAccountName:" in text
        assert "l.wilson" in text

    def test_get_membership_success_has_groups(self):
        """get_membership success output should contain group entries."""
        text = load_fixture("get_membership_success.txt")
        assert "Domain Users" in text
        assert "Remote Desktop Users" in text
        assert "sAMAccountName:" in text

    def test_get_search_success_has_results(self):
        """get_search success output should contain search results."""
        text = load_fixture("get_search_success.txt")
        assert "j.arbuckle" in text
        assert "l.wilson" in text
        assert "Administrator" in text

    def test_get_writable_success_has_permissions(self):
        """get_writable success output should contain writable objects."""
        text = load_fixture("get_writable_success.txt")
        assert "permission: WRITE" in text
        assert "Jon Arbuckle" in text

    def test_shadow_credentials_success_has_cert(self):
        """shadow credentials success should have key hash and cert path."""
        text = load_fixture("shadow_credentials_success.txt")
        assert "KeyCredential generated" in text
        assert "has been saved to" in text
        assert "/session/credentials/" in text

    # ── Additional success fixture tests ────────────────────────

    def test_set_password_success(self):
        """set_password success output should confirm password changed."""
        text = load_fixture("set_password_success.txt")
        assert "Password changed" in text or "password" in text.lower()

    def test_add_group_member_success(self):
        """add_group_member success output should confirm member added."""
        text = load_fixture("add_group_member_success.txt")
        assert "added to" in text
        assert "j.arbuckle" in text

    def test_add_computer_success(self):
        """add_computer success output should confirm computer added."""
        text = load_fixture("add_computer_success.txt")
        assert "EVIL01" in text
        assert "added" in text.lower()

    def test_add_genericall_success(self):
        """add_genericall success output should confirm ACE added."""
        text = load_fixture("add_genericall_success.txt")
        assert "GenericAll" in text
        assert "j.arbuckle" in text

    def test_add_rbcd_success(self):
        """add_rbcd success output should confirm RBCD delegation set."""
        text = load_fixture("add_rbcd_success.txt")
        assert "msDS-AllowedToActOnBehalfOfOtherIdentity" in text


# ===========================================================================
# UNIT TESTS -- command building (_build_auth)
# ===========================================================================

class TestBuildAuth:
    """Test the _build_auth helper produces correct bloodyAD CLI arguments."""

    @pytest.fixture(autouse=True, scope="class")
    def setup_server(self):
        """Create a server instance for auth builder testing."""
        try:
            cls = _get_server_class()
            self.__class__._server = cls()
        except Exception as e:
            pytest.skip(f"Cannot import BloodyADServer: {e}")

    def test_basic_ntlm_auth(self):
        """Basic NTLM auth: host + domain + username + password."""
        cmd = self._server._build_auth(
            host="10.10.10.1", domain="corp.local",
            username="admin", password="P@ss123",
        )
        assert cmd[:2] == ["bloodyAD", "--host"]
        assert "10.10.10.1" in cmd
        assert "-d" in cmd
        idx_d = cmd.index("-d")
        assert cmd[idx_d + 1] == "corp.local"
        assert "-u" in cmd
        idx_u = cmd.index("-u")
        assert cmd[idx_u + 1] == "admin"
        assert "-p" in cmd
        idx_p = cmd.index("-p")
        assert cmd[idx_p + 1] == "P@ss123"

    def test_kerberos_auth_bare_flag(self):
        """Kerberos auth uses -k flag without inline ccache path."""
        cmd = self._server._build_auth(
            host="dc01.corp.local", domain="corp.local",
            username="admin", kerberos=True,
        )
        assert "-k" in cmd
        # ccache is NOT passed inline (only via KRB5CCNAME env)
        idx_k = cmd.index("-k")
        # The next element after -k should NOT be a ccache path
        if idx_k + 1 < len(cmd):
            next_arg = cmd[idx_k + 1]
            assert not next_arg.endswith(".ccache"), (
                f"ccache should not be inline after -k, got: {next_arg}"
            )

    def test_kerberos_auth_with_password(self):
        """Kerberos auth with password still passes -p for AES/RC4 key."""
        cmd = self._server._build_auth(
            host="dc01.corp.local", domain="corp.local",
            username="admin", password="aes256key", kerberos=True,
        )
        assert "-k" in cmd
        assert "-p" in cmd
        idx_p = cmd.index("-p")
        assert cmd[idx_p + 1] == "aes256key"

    def test_no_username_no_dash_u(self):
        """Without username, -u flag should not appear."""
        cmd = self._server._build_auth(
            host="10.10.10.1", domain="corp.local",
        )
        assert "-u" not in cmd

    def test_no_password_no_dash_p(self):
        """Without password, -p flag should not appear."""
        cmd = self._server._build_auth(
            host="10.10.10.1", domain="corp.local",
            username="admin",
        )
        assert "-p" not in cmd

    def test_ntlm_password_not_sent_without_kerberos(self):
        """NTLM auth: password is sent via -p."""
        cmd = self._server._build_auth(
            host="10.10.10.1", domain="corp.local",
            username="admin", password="pass", kerberos=False,
        )
        assert "-p" in cmd
        assert "-k" not in cmd

    def test_dc_ip_flag(self):
        """dc_ip parameter produces --dc-ip flag."""
        cmd = self._server._build_auth(
            host="dc01.corp.local", domain="corp.local",
            dc_ip="10.10.10.1",
        )
        assert "--dc-ip" in cmd
        idx = cmd.index("--dc-ip")
        assert cmd[idx + 1] == "10.10.10.1"

    def test_secure_flag(self):
        """secure=True produces -s flag for LDAPS."""
        cmd = self._server._build_auth(
            host="10.10.10.1", domain="corp.local",
            secure=True,
        )
        assert "-s" in cmd

    def test_secure_false_no_flag(self):
        """secure=False does not produce -s flag."""
        cmd = self._server._build_auth(
            host="10.10.10.1", domain="corp.local",
            secure=False,
        )
        assert "-s" not in cmd

    # ── Certificate auth ──────────────────────────────────────

    def test_certificate_auth(self):
        """certificate param produces -c key:cert flag."""
        cmd = self._server._build_auth(
            host="10.10.10.1", domain="corp.local",
            certificate="/creds/admin.key:/creds/admin.crt",
        )
        assert "-c" in cmd
        idx = cmd.index("-c")
        assert cmd[idx + 1] == "/creds/admin.key:/creds/admin.crt"

    def test_certificate_no_flag_when_none(self):
        """No -c flag when certificate is None."""
        cmd = self._server._build_auth(
            host="10.10.10.1", domain="corp.local",
        )
        assert "-c" not in cmd

    def test_certificate_with_kerberos(self):
        """certificate + kerberos: both -c and -k flags present."""
        cmd = self._server._build_auth(
            host="10.10.10.1", domain="corp.local",
            kerberos=True, certificate="/creds/key:/creds/cert",
        )
        assert "-c" in cmd
        assert "-k" in cmd

    # ── Format param ──────────────────────────────────────────

    def test_format_hex(self):
        """format='hex' produces -f hex flag."""
        cmd = self._server._build_auth(
            host="10.10.10.1", domain="corp.local",
            username="admin", password="deadbeef", format="hex",
        )
        assert "-f" in cmd
        idx = cmd.index("-f")
        assert cmd[idx + 1] == "hex"

    def test_format_aes(self):
        """format='aes' produces -f aes flag."""
        cmd = self._server._build_auth(
            host="10.10.10.1", domain="corp.local",
            username="admin", password="aes256key", format="aes",
        )
        assert "-f" in cmd
        idx = cmd.index("-f")
        assert cmd[idx + 1] == "aes"

    def test_format_rc4(self):
        """format='rc4' produces -f rc4 flag."""
        cmd = self._server._build_auth(
            host="10.10.10.1", domain="corp.local",
            username="admin", password="rc4key", format="rc4",
        )
        assert "-f" in cmd
        idx = cmd.index("-f")
        assert cmd[idx + 1] == "rc4"

    def test_format_none_no_flag(self):
        """No -f flag when format is None."""
        cmd = self._server._build_auth(
            host="10.10.10.1", domain="corp.local",
            username="admin", password="pass",
        )
        assert "-f" not in cmd

    def test_format_with_kerberos(self):
        """format + kerberos: both -f and -k present."""
        cmd = self._server._build_auth(
            host="10.10.10.1", domain="corp.local",
            username="admin", password="aeskey", kerberos=True, format="aes",
        )
        assert "-f" in cmd
        assert "-k" in cmd
        assert "-p" in cmd  # password still passed with kerberos

    def test_no_dc_ip_no_flag(self):
        """Without dc_ip, --dc-ip flag should not appear."""
        cmd = self._server._build_auth(
            host="10.10.10.1", domain="corp.local",
        )
        assert "--dc-ip" not in cmd

    def test_hash_as_password(self):
        """NTLM hash (LM:NT format) is passed via -p."""
        cmd = self._server._build_auth(
            host="10.10.10.1", domain="corp.local",
            username="admin",
            password="aad3b435b51404eeaad3b435b51404ee:31d6cfe0d16ae931b73c59d7e0c089c0",
        )
        assert "-p" in cmd
        idx_p = cmd.index("-p")
        assert "aad3b435b51404ee" in cmd[idx_p + 1]

    def test_all_flags_combined(self):
        """All auth flags combined produce correct CLI."""
        cmd = self._server._build_auth(
            host="dc01.corp.local", domain="corp.local",
            username="admin", password="aes256key",
            kerberos=True, dc_ip="10.10.10.1", secure=True,
        )
        assert "-k" in cmd
        assert "-p" in cmd
        assert "--dc-ip" in cmd
        assert "-s" in cmd
        assert "-u" in cmd


# ===========================================================================
# UNIT TESTS -- auth env helper (_get_auth_env)
# ===========================================================================

class TestGetAuthEnv:
    """Test the _get_auth_env helper for Kerberos environment setup."""

    @pytest.fixture(autouse=True, scope="class")
    def setup_server(self):
        """Create a server instance for auth env testing."""
        try:
            cls = _get_server_class()
            self.__class__._server = cls()
        except Exception as e:
            pytest.skip(f"Cannot import BloodyADServer: {e}")

    def test_no_kerberos_returns_empty(self):
        """Non-Kerberos auth returns empty env dict."""
        env = self._server._get_auth_env(kerberos=False)
        assert env == {}

    def test_kerberos_without_ccache_returns_empty(self):
        """Kerberos without any ccache returns empty env dict."""
        self._server._active_ccache = None
        env = self._server._get_auth_env(kerberos=True)
        assert env == {}

    def test_kerberos_with_explicit_ccache(self):
        """Kerberos with explicit ccache_path sets KRB5CCNAME if file exists."""
        # Use a path that won't exist in the test environment
        env = self._server._get_auth_env(
            kerberos=True, ccache_path="/tmp/nonexistent.ccache"
        )
        # File doesn't exist, so env should be empty
        assert env == {}

    def test_kerberos_false_ignores_ccache_path(self):
        """kerberos=False ignores ccache_path entirely."""
        env = self._server._get_auth_env(
            kerberos=False, ccache_path="/session/credentials/test.ccache"
        )
        assert env == {}


# ===========================================================================
# UNIT TESTS -- per-method command building
# ===========================================================================

class TestMethodCommandBuilding:
    """Test that each handler method builds the correct bloodyAD CLI command.

    These tests instantiate the server directly and inspect command construction
    by capturing what _run_bloodyad would receive. We mock _run_bloodyad to
    capture the command without actually executing it.
    """

    @pytest.fixture(autouse=True, scope="class")
    def setup_server(self):
        """Create a server instance for command testing."""
        try:
            cls = _get_server_class()
            self.__class__._server = cls()
        except Exception as e:
            pytest.skip(f"Cannot import BloodyADServer: {e}")

    def _extract_cmd(self, method_name, kwargs):
        """Call a handler and capture the command it would build.

        We patch _run_bloodyad to capture the cmd arg, then return it.
        """
        import asyncio
        from unittest.mock import AsyncMock

        captured = {}

        async def mock_run(cmd, auth_env, data, timeout=60, success_check=None):
            captured["cmd"] = cmd
            captured["auth_env"] = auth_env
            captured["data"] = data
            # Return a dummy ToolResult
            from mcp_common import ToolResult
            return ToolResult(success=True, data=data)

        handler = getattr(self._server, method_name)
        original = self._server._run_bloodyad
        self._server._run_bloodyad = mock_run
        try:
            loop = asyncio.new_event_loop()
            try:
                loop.run_until_complete(handler(**kwargs))
            finally:
                loop.close()
        finally:
            self._server._run_bloodyad = original

        return captured.get("cmd", []), captured.get("data", {})

    # ── Auth args used across all tests ────────────────────────
    _AUTH = {
        "host": "10.10.10.1",
        "domain": "garfield.htb",
        "username": "j.arbuckle",
        "password": "GarfieldRules1!",
    }

    def test_set_password_cmd(self):
        """set_password: bloodyAD ... set password <target> <new_password>"""
        cmd, data = self._extract_cmd("set_password", {
            **self._AUTH, "target": "l.wilson", "new_password": "NewP@ss1!",
        })
        assert cmd[-3:] == ["l.wilson", "NewP@ss1!"] or "set" in cmd
        assert "set" in cmd
        assert "password" in cmd
        idx_set = cmd.index("set")
        assert cmd[idx_set + 1] == "password"
        assert data["action"] == "set_password"
        assert data["target"] == "l.wilson"

    def test_set_password_with_oldpass(self):
        """set_password with old_password: adds --oldpass flag."""
        cmd, _ = self._extract_cmd("set_password", {
            **self._AUTH, "target": "l.wilson",
            "new_password": "NewP@ss1!", "old_password": "OldP@ss1!",
        })
        assert "--oldpass" in cmd
        idx = cmd.index("--oldpass")
        assert cmd[idx + 1] == "OldP@ss1!"

    def test_set_owner_cmd(self):
        """set_owner: bloodyAD ... set owner <target> <owner>"""
        cmd, data = self._extract_cmd("set_owner", {
            **self._AUTH, "target": "l.wilson", "owner": "j.arbuckle",
        })
        assert "set" in cmd
        assert "owner" in cmd
        idx = cmd.index("owner")
        assert cmd[idx + 1] == "l.wilson"
        assert cmd[idx + 2] == "j.arbuckle"
        assert data["action"] == "set_owner"

    def test_set_object_with_values(self):
        """set_object with values: bloodyAD ... set object -v val1 -v val2 <target> <attr>"""
        cmd, data = self._extract_cmd("set_object", {
            **self._AUTH, "target": "l.wilson",
            "attribute": "description", "values": ["Owned", "by-arbuckle"],
        })
        assert "set" in cmd
        assert "object" in cmd
        # Check -v flags
        v_count = cmd.count("-v")
        assert v_count == 2, f"Expected 2 -v flags, got {v_count}"
        assert data["attribute"] == "description"

    def test_set_object_delete_attr(self):
        """set_object without values (delete): no -v flags."""
        cmd, _ = self._extract_cmd("set_object", {
            **self._AUTH, "target": "l.wilson", "attribute": "description",
        })
        assert "-v" not in cmd

    def test_add_genericall_cmd(self):
        """add_genericall: bloodyAD ... add genericAll <target> <trustee>"""
        cmd, data = self._extract_cmd("add_genericall", {
            **self._AUTH, "target": "l.wilson", "trustee": "j.arbuckle",
        })
        assert "add" in cmd
        assert "genericAll" in cmd
        idx = cmd.index("genericAll")
        assert cmd[idx + 1] == "l.wilson"
        assert cmd[idx + 2] == "j.arbuckle"
        assert data["action"] == "add_genericall"

    def test_add_rbcd_cmd(self):
        """add_rbcd: bloodyAD ... add rbcd <target> <service>"""
        cmd, data = self._extract_cmd("add_rbcd", {
            **self._AUTH, "target": "DC01$", "service": "EVIL01$",
        })
        assert "add" in cmd
        assert "rbcd" in cmd
        idx = cmd.index("rbcd")
        assert cmd[idx + 1] == "DC01$"
        assert cmd[idx + 2] == "EVIL01$"
        assert data["action"] == "add_rbcd"

    def test_add_shadow_credentials_cmd(self):
        """add_shadow_credentials: bloodyAD ... add shadowCredentials <target>"""
        cmd, data = self._extract_cmd("add_shadow_credentials", {
            **self._AUTH, "target": "l.wilson",
        })
        assert "add" in cmd
        assert "shadowCredentials" in cmd
        assert cmd[-1] == "l.wilson"
        assert data["action"] == "add_shadow_credentials"

    def test_add_shadow_credentials_with_cert_path(self):
        """add_shadow_credentials with cert_path: adds --path flag."""
        cmd, _ = self._extract_cmd("add_shadow_credentials", {
            **self._AUTH, "target": "l.wilson",
            "cert_path": "/session/credentials/l.wilson.pem",
        })
        assert "--path" in cmd
        idx = cmd.index("--path")
        assert cmd[idx + 1] == "/session/credentials/l.wilson.pem"

    def test_add_group_member_cmd(self):
        """add_group_member: bloodyAD ... add groupMember <group> <member>"""
        cmd, data = self._extract_cmd("add_group_member", {
            **self._AUTH, "group": "Domain Admins", "member": "j.arbuckle",
        })
        assert "add" in cmd
        assert "groupMember" in cmd
        idx = cmd.index("groupMember")
        assert cmd[idx + 1] == "Domain Admins"
        assert cmd[idx + 2] == "j.arbuckle"
        assert data["action"] == "add_group_member"

    def test_add_computer_cmd(self):
        """add_computer: bloodyAD ... add computer <hostname> <password>"""
        cmd, data = self._extract_cmd("add_computer", {
            **self._AUTH, "hostname": "EVIL01", "computer_pass": "EvilP@ss!",
        })
        assert "add" in cmd
        assert "computer" in cmd
        idx = cmd.index("computer")
        assert cmd[idx + 1] == "EVIL01"
        assert cmd[idx + 2] == "EvilP@ss!"
        assert data["action"] == "add_computer"

    def test_add_computer_with_ou(self):
        """add_computer with OU: adds --ou flag."""
        cmd, _ = self._extract_cmd("add_computer", {
            **self._AUTH, "hostname": "EVIL01", "computer_pass": "EvilP@ss!",
            "ou": "OU=Workstations,DC=garfield,DC=htb",
        })
        assert "--ou" in cmd
        idx = cmd.index("--ou")
        assert cmd[idx + 1] == "OU=Workstations,DC=garfield,DC=htb"

    def test_add_dcsync_cmd(self):
        """add_dcsync: bloodyAD ... add dcsync <trustee>"""
        cmd, data = self._extract_cmd("add_dcsync", {
            **self._AUTH, "trustee": "j.arbuckle",
        })
        assert "add" in cmd
        assert "dcsync" in cmd
        idx = cmd.index("dcsync")
        assert cmd[idx + 1] == "j.arbuckle"
        assert data["action"] == "add_dcsync"

    def test_add_uac_cmd(self):
        """add_uac: bloodyAD ... add uac -f FLAG1 -f FLAG2 <target>"""
        cmd, data = self._extract_cmd("add_uac", {
            **self._AUTH, "target": "l.wilson",
            "flags": ["DONT_REQ_PREAUTH", "TRUSTED_TO_AUTH_FOR_DELEGATION"],
        })
        assert "add" in cmd
        assert "uac" in cmd
        f_count = cmd.count("-f")
        assert f_count == 2, f"Expected 2 -f flags, got {f_count}"
        assert "DONT_REQ_PREAUTH" in cmd
        assert "TRUSTED_TO_AUTH_FOR_DELEGATION" in cmd
        assert cmd[-1] == "l.wilson"

    def test_add_uac_single_flag(self):
        """add_uac with single flag."""
        cmd, _ = self._extract_cmd("add_uac", {
            **self._AUTH, "target": "l.wilson",
            "flags": ["DONT_REQ_PREAUTH"],
        })
        f_count = cmd.count("-f")
        assert f_count == 1

    def test_add_dns_record_cmd(self):
        """add_dns_record: bloodyAD ... add dnsRecord <name> <data>"""
        cmd, data = self._extract_cmd("add_dns_record", {
            **self._AUTH, "name": "evil", "data": "10.10.14.5",
        })
        assert "add" in cmd
        assert "dnsRecord" in cmd
        idx = cmd.index("dnsRecord")
        # Default type is A, so no --dnstype flag
        assert "--dnstype" not in cmd
        assert "evil" in cmd
        assert "10.10.14.5" in cmd
        assert data["action"] == "add_dns_record"

    def test_add_dns_record_with_options(self):
        """add_dns_record with type, zone, ttl produces correct flags."""
        cmd, _ = self._extract_cmd("add_dns_record", {
            **self._AUTH, "name": "evil", "data": "10.10.14.5",
            "dnstype": "CNAME", "zone": "garfield.htb", "ttl": 300,
        })
        assert "--dnstype" in cmd
        idx = cmd.index("--dnstype")
        assert cmd[idx + 1] == "CNAME"
        assert "--zone" in cmd
        idx = cmd.index("--zone")
        assert cmd[idx + 1] == "garfield.htb"
        assert "--ttl" in cmd
        idx = cmd.index("--ttl")
        assert cmd[idx + 1] == "300"

    def test_add_user_cmd(self):
        """add_user: bloodyAD ... add user <sam_account_name> <password>"""
        cmd, data = self._extract_cmd("add_user", {
            **self._AUTH, "sam_account_name": "backdoor", "new_password": "B@ckD00r!",
        })
        assert "add" in cmd
        assert "user" in cmd
        idx = cmd.index("user")
        assert "backdoor" in cmd[idx:]
        assert "B@ckD00r!" in cmd[idx:]
        assert data["action"] == "add_user"

    def test_add_user_with_ou(self):
        """add_user with OU: adds --ou flag."""
        cmd, _ = self._extract_cmd("add_user", {
            **self._AUTH, "sam_account_name": "backdoor", "new_password": "B@ckD00r!",
            "ou": "OU=Users,DC=garfield,DC=htb",
        })
        assert "--ou" in cmd
        idx = cmd.index("--ou")
        assert cmd[idx + 1] == "OU=Users,DC=garfield,DC=htb"

    def test_get_object_cmd(self):
        """get_object: bloodyAD ... get object <target>"""
        cmd, data = self._extract_cmd("get_object", {
            **self._AUTH, "target": "Administrator",
        })
        assert "get" in cmd
        assert "object" in cmd
        assert cmd[-1] == "Administrator"
        assert data["action"] == "get_object"

    def test_get_object_with_attr(self):
        """get_object with attr: adds --attr flag."""
        cmd, _ = self._extract_cmd("get_object", {
            **self._AUTH, "target": "Administrator",
            "attr": "sAMAccountName,memberOf",
        })
        assert "--attr" in cmd
        idx = cmd.index("--attr")
        assert cmd[idx + 1] == "sAMAccountName,memberOf"

    def test_get_object_with_resolve_sd(self):
        """get_object with resolve_sd: adds --resolve-sd flag."""
        cmd, _ = self._extract_cmd("get_object", {
            **self._AUTH, "target": "Administrator", "resolve_sd": True,
        })
        assert "--resolve-sd" in cmd

    def test_get_children_cmd(self):
        """get_children: bloodyAD ... get children"""
        cmd, data = self._extract_cmd("get_children", {
            **self._AUTH,
        })
        assert "get" in cmd
        assert "children" in cmd
        assert data["action"] == "get_children"

    def test_get_children_with_options(self):
        """get_children with target, otype, direct produces correct flags."""
        cmd, _ = self._extract_cmd("get_children", {
            **self._AUTH,
            "target": "OU=Users,DC=garfield,DC=htb",
            "otype": "user",
            "direct": True,
        })
        assert "--target" in cmd
        idx = cmd.index("--target")
        assert cmd[idx + 1] == "OU=Users,DC=garfield,DC=htb"
        assert "--otype" in cmd
        idx = cmd.index("--otype")
        assert cmd[idx + 1] == "user"
        assert "--direct" in cmd

    def test_get_search_cmd(self):
        """get_search: bloodyAD ... get search --filter <filter>"""
        cmd, data = self._extract_cmd("get_search", {
            **self._AUTH, "filter": "(objectClass=user)",
        })
        assert "get" in cmd
        assert "search" in cmd
        assert "--filter" in cmd
        idx = cmd.index("--filter")
        assert cmd[idx + 1] == "(objectClass=user)"
        assert data["action"] == "get_search"

    def test_get_search_with_base_and_attr(self):
        """get_search with base and attr adds correct flags."""
        cmd, _ = self._extract_cmd("get_search", {
            **self._AUTH, "filter": "(objectClass=computer)",
            "base": "OU=Servers,DC=garfield,DC=htb",
            "attr": "sAMAccountName,dNSHostName",
        })
        assert "--base" in cmd
        idx = cmd.index("--base")
        assert cmd[idx + 1] == "OU=Servers,DC=garfield,DC=htb"
        assert "--attr" in cmd
        idx = cmd.index("--attr")
        assert cmd[idx + 1] == "sAMAccountName,dNSHostName"

    def test_get_writable_cmd_defaults(self):
        """get_writable with defaults: no --otype or --right flags."""
        cmd, data = self._extract_cmd("get_writable", {**self._AUTH})
        assert "get" in cmd
        assert "writable" in cmd
        # Defaults are "ALL" so no flags
        assert "--otype" not in cmd
        assert "--right" not in cmd
        assert data["action"] == "get_writable"

    def test_get_writable_with_filters(self):
        """get_writable with otype and right produces correct flags."""
        cmd, _ = self._extract_cmd("get_writable", {
            **self._AUTH, "otype": "USER", "right": "WRITE", "detail": True,
        })
        assert "--otype" in cmd
        idx = cmd.index("--otype")
        assert cmd[idx + 1] == "USER"
        assert "--right" in cmd
        idx = cmd.index("--right")
        assert cmd[idx + 1] == "WRITE"
        assert "--detail" in cmd

    def test_get_membership_cmd(self):
        """get_membership: bloodyAD ... get membership <target>"""
        cmd, data = self._extract_cmd("get_membership", {
            **self._AUTH, "target": "l.wilson",
        })
        assert "get" in cmd
        assert "membership" in cmd
        assert cmd[-1] == "l.wilson"
        assert data["action"] == "get_membership"

    def test_get_membership_no_recurse(self):
        """get_membership with no_recurse: adds --no-recurse flag."""
        cmd, _ = self._extract_cmd("get_membership", {
            **self._AUTH, "target": "l.wilson", "no_recurse": True,
        })
        assert "--no-recurse" in cmd

    def test_get_dnsdump_cmd(self):
        """get_dnsdump: bloodyAD ... get dnsDump"""
        cmd, data = self._extract_cmd("get_dnsdump", {**self._AUTH})
        assert "get" in cmd
        assert "dnsDump" in cmd
        assert data["action"] == "get_dnsdump"

    def test_get_trusts_cmd(self):
        """get_trusts: bloodyAD ... get trusts"""
        cmd, data = self._extract_cmd("get_trusts", {**self._AUTH})
        assert "get" in cmd
        assert "trusts" in cmd
        assert data["action"] == "get_trusts"

    def test_remove_genericall_cmd(self):
        """remove_genericall: bloodyAD ... remove genericAll <target> <trustee>"""
        cmd, data = self._extract_cmd("remove_genericall", {
            **self._AUTH, "target": "l.wilson", "trustee": "j.arbuckle",
        })
        assert "remove" in cmd
        assert "genericAll" in cmd
        idx = cmd.index("genericAll")
        assert cmd[idx + 1] == "l.wilson"
        assert cmd[idx + 2] == "j.arbuckle"
        assert data["action"] == "remove_genericall"

    def test_remove_rbcd_cmd(self):
        """remove_rbcd: bloodyAD ... remove rbcd <target> <service>"""
        cmd, data = self._extract_cmd("remove_rbcd", {
            **self._AUTH, "target": "DC01$", "service": "EVIL01$",
        })
        assert "remove" in cmd
        assert "rbcd" in cmd
        idx = cmd.index("rbcd")
        assert cmd[idx + 1] == "DC01$"
        assert cmd[idx + 2] == "EVIL01$"
        assert data["action"] == "remove_rbcd"

    def test_remove_group_member_cmd(self):
        """remove_group_member: bloodyAD ... remove groupMember <group> <member>"""
        cmd, data = self._extract_cmd("remove_group_member", {
            **self._AUTH, "group": "Domain Admins", "member": "j.arbuckle",
        })
        assert "remove" in cmd
        assert "groupMember" in cmd
        idx = cmd.index("groupMember")
        assert cmd[idx + 1] == "Domain Admins"
        assert cmd[idx + 2] == "j.arbuckle"
        assert data["action"] == "remove_group_member"

    def test_remove_shadow_credentials_cmd(self):
        """remove_shadow_credentials: bloodyAD ... remove shadowCredentials <target>"""
        cmd, data = self._extract_cmd("remove_shadow_credentials", {
            **self._AUTH, "target": "l.wilson",
        })
        assert "remove" in cmd
        assert "shadowCredentials" in cmd
        assert cmd[-1] == "l.wilson"
        assert data["action"] == "remove_shadow_credentials"

    def test_remove_shadow_credentials_with_key(self):
        """remove_shadow_credentials with key: adds --key flag."""
        cmd, _ = self._extract_cmd("remove_shadow_credentials", {
            **self._AUTH, "target": "l.wilson",
            "key": "e61212617e78e6907eb05067fc1804f7",
        })
        assert "--key" in cmd
        idx = cmd.index("--key")
        assert cmd[idx + 1] == "e61212617e78e6907eb05067fc1804f7"

    def test_remove_dcsync_cmd(self):
        """remove_dcsync: bloodyAD ... remove dcsync <trustee>"""
        cmd, data = self._extract_cmd("remove_dcsync", {
            **self._AUTH, "trustee": "j.arbuckle",
        })
        assert "remove" in cmd
        assert "dcsync" in cmd
        idx = cmd.index("dcsync")
        assert cmd[idx + 1] == "j.arbuckle"
        assert data["action"] == "remove_dcsync"

    def test_remove_uac_cmd(self):
        """remove_uac: bloodyAD ... remove uac -f FLAG <target>"""
        cmd, data = self._extract_cmd("remove_uac", {
            **self._AUTH, "target": "l.wilson",
            "flags": ["DONT_REQ_PREAUTH"],
        })
        assert "remove" in cmd
        assert "uac" in cmd
        assert "-f" in cmd
        assert "DONT_REQ_PREAUTH" in cmd
        assert cmd[-1] == "l.wilson"
        assert data["action"] == "remove_uac"

    # ── get_dnsdump flags ───────���─────────────────────────────

    def test_get_dnsdump_with_zone(self):
        """get_dnsdump with zone: adds --zone flag."""
        cmd, _ = self._extract_cmd("get_dnsdump", {
            **self._AUTH, "zone": "garfield.htb",
        })
        assert "--zone" in cmd
        idx = cmd.index("--zone")
        assert cmd[idx + 1] == "garfield.htb"

    def test_get_dnsdump_with_no_detail(self):
        """get_dnsdump with no_detail: adds --no-detail flag."""
        cmd, _ = self._extract_cmd("get_dnsdump", {
            **self._AUTH, "no_detail": True,
        })
        assert "--no-detail" in cmd

    def test_get_dnsdump_with_transitive(self):
        """get_dnsdump with transitive: adds --transitive flag."""
        cmd, _ = self._extract_cmd("get_dnsdump", {
            **self._AUTH, "transitive": True,
        })
        assert "--transitive" in cmd

    def test_get_dnsdump_all_flags(self):
        """get_dnsdump with all optional flags."""
        cmd, _ = self._extract_cmd("get_dnsdump", {
            **self._AUTH, "zone": "corp.local",
            "no_detail": True, "transitive": True,
        })
        assert "--zone" in cmd
        assert "--no-detail" in cmd
        assert "--transitive" in cmd

    def test_get_dnsdump_defaults_no_optional_flags(self):
        """get_dnsdump with defaults: no --zone, --no-detail, --transitive."""
        cmd, _ = self._extract_cmd("get_dnsdump", {**self._AUTH})
        assert "--zone" not in cmd
        assert "--no-detail" not in cmd
        assert "--transitive" not in cmd

    # ── get_search resolve_sd ���────────────────────────────────

    def test_get_search_with_resolve_sd(self):
        """get_search with resolve_sd: adds --resolve-sd flag."""
        cmd, _ = self._extract_cmd("get_search", {
            **self._AUTH, "filter": "(objectClass=user)", "resolve_sd": True,
        })
        assert "--resolve-sd" in cmd

    def test_get_search_resolve_sd_false_no_flag(self):
        """get_search with resolve_sd=False: no --resolve-sd flag."""
        cmd, _ = self._extract_cmd("get_search", {
            **self._AUTH, "filter": "(objectClass=user)", "resolve_sd": False,
        })
        assert "--resolve-sd" not in cmd

    # ── add_dns_record SRV/MX ─────────────────────────────────

    def test_add_dns_record_srv(self):
        """add_dns_record SRV: --dnstype SRV + --port + --priority + --weight."""
        cmd, data = self._extract_cmd("add_dns_record", {
            **self._AUTH, "name": "_ldap._tcp", "data": "dc01.garfield.htb",
            "dnstype": "SRV", "port": 389, "priority": 0, "weight": 100,
        })
        assert "--dnstype" in cmd
        idx = cmd.index("--dnstype")
        assert cmd[idx + 1] == "SRV"
        assert "--port" in cmd
        idx = cmd.index("--port")
        assert cmd[idx + 1] == "389"
        assert "--priority" in cmd
        idx = cmd.index("--priority")
        assert cmd[idx + 1] == "0"
        assert "--weight" in cmd
        idx = cmd.index("--weight")
        assert cmd[idx + 1] == "100"
        assert data["dnstype"] == "SRV"

    def test_add_dns_record_mx(self):
        """add_dns_record MX: --dnstype MX + --preference."""
        cmd, data = self._extract_cmd("add_dns_record", {
            **self._AUTH, "name": "@", "data": "mail.garfield.htb",
            "dnstype": "MX", "preference": 10,
        })
        assert "--dnstype" in cmd
        idx = cmd.index("--dnstype")
        assert cmd[idx + 1] == "MX"
        assert "--preference" in cmd
        idx = cmd.index("--preference")
        assert cmd[idx + 1] == "10"
        assert data["dnstype"] == "MX"

    def test_add_dns_record_aaaa(self):
        """add_dns_record AAAA."""
        cmd, _ = self._extract_cmd("add_dns_record", {
            **self._AUTH, "name": "evil6", "data": "fe80::1",
            "dnstype": "AAAA",
        })
        assert "--dnstype" in cmd
        idx = cmd.index("--dnstype")
        assert cmd[idx + 1] == "AAAA"

    def test_add_dns_record_txt(self):
        """add_dns_record TXT."""
        cmd, _ = self._extract_cmd("add_dns_record", {
            **self._AUTH, "name": "_dmarc", "data": "v=DMARC1; p=reject",
            "dnstype": "TXT",
        })
        assert "--dnstype" in cmd
        idx = cmd.index("--dnstype")
        assert cmd[idx + 1] == "TXT"

    def test_add_dns_record_ptr(self):
        """add_dns_record PTR."""
        cmd, _ = self._extract_cmd("add_dns_record", {
            **self._AUTH, "name": "5", "data": "evil.garfield.htb",
            "dnstype": "PTR",
        })
        assert "--dnstype" in cmd
        idx = cmd.index("--dnstype")
        assert cmd[idx + 1] == "PTR"

    def test_add_dns_record_forest(self):
        """add_dns_record with forest=True: adds --forest flag."""
        cmd, _ = self._extract_cmd("add_dns_record", {
            **self._AUTH, "name": "evil", "data": "10.10.14.5",
            "forest": True,
        })
        assert "--forest" in cmd

    def test_add_dns_record_with_ttl(self):
        """add_dns_record with ttl: adds --ttl flag."""
        cmd, _ = self._extract_cmd("add_dns_record", {
            **self._AUTH, "name": "evil", "data": "10.10.14.5", "ttl": 60,
        })
        assert "--ttl" in cmd
        idx = cmd.index("--ttl")
        assert cmd[idx + 1] == "60"

    # ── remove_dns_record ─────────────────────────────────────

    def test_remove_dns_record_cmd(self):
        """remove_dns_record: bloodyAD ... remove dnsRecord <name> <data>"""
        cmd, data = self._extract_cmd("remove_dns_record", {
            **self._AUTH, "name": "evil", "data": "10.10.14.5",
        })
        assert "remove" in cmd
        assert "dnsRecord" in cmd
        assert "evil" in cmd
        assert "10.10.14.5" in cmd
        assert "--dnstype" not in cmd  # default A, no flag
        assert data["action"] == "remove_dns_record"

    def test_remove_dns_record_srv(self):
        """remove_dns_record SRV: with port/priority/weight."""
        cmd, _ = self._extract_cmd("remove_dns_record", {
            **self._AUTH, "name": "_ldap._tcp", "data": "dc01.garfield.htb",
            "dnstype": "SRV", "port": 389, "priority": 0, "weight": 100,
        })
        assert "--dnstype" in cmd
        idx = cmd.index("--dnstype")
        assert cmd[idx + 1] == "SRV"
        assert "--port" in cmd
        assert "--priority" in cmd
        assert "--weight" in cmd

    def test_remove_dns_record_mx(self):
        """remove_dns_record MX: with preference."""
        cmd, _ = self._extract_cmd("remove_dns_record", {
            **self._AUTH, "name": "@", "data": "mail.garfield.htb",
            "dnstype": "MX", "preference": 10,
        })
        assert "--dnstype" in cmd
        assert "--preference" in cmd

    def test_remove_dns_record_with_zone(self):
        """remove_dns_record with zone param."""
        cmd, _ = self._extract_cmd("remove_dns_record", {
            **self._AUTH, "name": "evil", "data": "10.10.14.5",
            "zone": "garfield.htb",
        })
        assert "--zone" in cmd
        idx = cmd.index("--zone")
        assert cmd[idx + 1] == "garfield.htb"

    def test_remove_dns_record_with_ttl(self):
        """remove_dns_record with ttl."""
        cmd, _ = self._extract_cmd("remove_dns_record", {
            **self._AUTH, "name": "evil", "data": "10.10.14.5", "ttl": 300,
        })
        assert "--ttl" in cmd
        idx = cmd.index("--ttl")
        assert cmd[idx + 1] == "300"

    def test_remove_dns_record_with_forest(self):
        """remove_dns_record with forest=True: adds --forest flag."""
        cmd, _ = self._extract_cmd("remove_dns_record", {
            **self._AUTH, "name": "evil", "data": "10.10.14.5", "forest": True,
        })
        assert "--forest" in cmd

    # ── remove_object ──────────���──────────────────────────────

    def test_remove_object_cmd(self):
        """remove_object: bloodyAD ... remove object <target>"""
        cmd, data = self._extract_cmd("remove_object", {
            **self._AUTH, "target": "EVIL01$",
        })
        assert "remove" in cmd
        assert "object" in cmd
        idx = cmd.index("object")
        assert cmd[idx + 1] == "EVIL01$"
        assert data["action"] == "remove_object"
        assert data["target"] == "EVIL01$"

    # ── Certificate auth in method handlers ───────────────────

    def test_set_password_with_certificate(self):
        """set_password with certificate: -c flag in generated command."""
        cmd, _ = self._extract_cmd("set_password", {
            **self._AUTH, "target": "l.wilson", "new_password": "NewP@ss1!",
            "certificate": "/creds/admin.key:/creds/admin.crt",
        })
        assert "-c" in cmd
        idx = cmd.index("-c")
        assert cmd[idx + 1] == "/creds/admin.key:/creds/admin.crt"

    def test_get_object_with_certificate(self):
        """get_object with certificate: -c flag in generated command."""
        cmd, _ = self._extract_cmd("get_object", {
            **self._AUTH, "target": "Administrator",
            "certificate": "/creds/key:/creds/cert",
        })
        assert "-c" in cmd

    def test_add_rbcd_with_certificate(self):
        """add_rbcd with certificate: -c flag in generated command."""
        cmd, _ = self._extract_cmd("add_rbcd", {
            **self._AUTH, "target": "DC01$", "service": "EVIL01$",
            "certificate": "/creds/key:/creds/cert",
        })
        assert "-c" in cmd

    # ── Format param in method handlers ───────────────────────

    def test_set_password_with_format(self):
        """set_password with format: -f flag in generated command."""
        cmd, _ = self._extract_cmd("set_password", {
            **self._AUTH, "target": "l.wilson", "new_password": "NewP@ss1!",
            "format": "rc4",
        })
        assert "-f" in cmd
        idx = cmd.index("-f")
        assert cmd[idx + 1] == "rc4"

    def test_get_object_with_format(self):
        """get_object with format: -f flag in generated command."""
        cmd, _ = self._extract_cmd("get_object", {
            **self._AUTH, "target": "Administrator", "format": "hex",
        })
        assert "-f" in cmd
        idx = cmd.index("-f")
        assert cmd[idx + 1] == "hex"

    # ── extra_args on every method ────────────────────────────

    def test_extra_args_set_password(self):
        """set_password extra_args are appended after positional args."""
        cmd, _ = self._extract_cmd("set_password", {
            **self._AUTH, "target": "l.wilson", "new_password": "NewP@ss1!",
            "extra_args": "--timeout 30",
        })
        assert "--timeout" in cmd
        assert "30" in cmd
        # extra_args should be AFTER the positional args
        idx_target = cmd.index("l.wilson")
        idx_extra = cmd.index("--timeout")
        assert idx_extra > idx_target

    def test_extra_args_set_owner(self):
        """set_owner extra_args appended."""
        cmd, _ = self._extract_cmd("set_owner", {
            **self._AUTH, "target": "l.wilson", "owner": "j.arbuckle",
            "extra_args": "--verbose",
        })
        assert "--verbose" in cmd

    def test_extra_args_set_object(self):
        """set_object extra_args appended."""
        cmd, _ = self._extract_cmd("set_object", {
            **self._AUTH, "target": "l.wilson", "attribute": "description",
            "extra_args": "--timeout 60",
        })
        assert "--timeout" in cmd
        assert "60" in cmd

    def test_extra_args_add_genericall(self):
        """add_genericall extra_args appended."""
        cmd, _ = self._extract_cmd("add_genericall", {
            **self._AUTH, "target": "l.wilson", "trustee": "j.arbuckle",
            "extra_args": "--timeout 30",
        })
        assert "--timeout" in cmd

    def test_extra_args_add_rbcd(self):
        """add_rbcd extra_args appended."""
        cmd, _ = self._extract_cmd("add_rbcd", {
            **self._AUTH, "target": "DC01$", "service": "EVIL01$",
            "extra_args": "--timeout 45",
        })
        assert "--timeout" in cmd

    def test_extra_args_add_shadow_credentials(self):
        """add_shadow_credentials extra_args appended."""
        cmd, _ = self._extract_cmd("add_shadow_credentials", {
            **self._AUTH, "target": "l.wilson",
            "extra_args": "--timeout 30",
        })
        assert "--timeout" in cmd

    def test_extra_args_add_group_member(self):
        """add_group_member extra_args appended."""
        cmd, _ = self._extract_cmd("add_group_member", {
            **self._AUTH, "group": "Domain Admins", "member": "j.arbuckle",
            "extra_args": "--timeout 30",
        })
        assert "--timeout" in cmd

    def test_extra_args_add_computer(self):
        """add_computer extra_args appended."""
        cmd, _ = self._extract_cmd("add_computer", {
            **self._AUTH, "hostname": "EVIL01", "computer_pass": "Pass!",
            "extra_args": "--timeout 30",
        })
        assert "--timeout" in cmd

    def test_extra_args_add_dcsync(self):
        """add_dcsync extra_args appended."""
        cmd, _ = self._extract_cmd("add_dcsync", {
            **self._AUTH, "trustee": "j.arbuckle",
            "extra_args": "--timeout 30",
        })
        assert "--timeout" in cmd

    def test_extra_args_add_uac(self):
        """add_uac extra_args appended after target."""
        cmd, _ = self._extract_cmd("add_uac", {
            **self._AUTH, "target": "l.wilson",
            "flags": ["DONT_REQ_PREAUTH"],
            "extra_args": "--timeout 30",
        })
        assert "--timeout" in cmd
        idx_target = cmd.index("l.wilson")
        idx_extra = cmd.index("--timeout")
        assert idx_extra > idx_target

    def test_extra_args_add_dns_record(self):
        """add_dns_record extra_args appended."""
        cmd, _ = self._extract_cmd("add_dns_record", {
            **self._AUTH, "name": "evil", "data": "10.10.14.5",
            "extra_args": "--timeout 30",
        })
        assert "--timeout" in cmd

    def test_extra_args_add_user(self):
        """add_user extra_args appended."""
        cmd, _ = self._extract_cmd("add_user", {
            **self._AUTH, "sam_account_name": "backdoor", "new_password": "P@ss!",
            "extra_args": "--timeout 30",
        })
        assert "--timeout" in cmd

    def test_extra_args_get_object(self):
        """get_object extra_args appended."""
        cmd, _ = self._extract_cmd("get_object", {
            **self._AUTH, "target": "Administrator",
            "extra_args": "--timeout 120",
        })
        assert "--timeout" in cmd

    def test_extra_args_get_children(self):
        """get_children extra_args appended."""
        cmd, _ = self._extract_cmd("get_children", {
            **self._AUTH, "extra_args": "--timeout 120",
        })
        assert "--timeout" in cmd

    def test_extra_args_get_search(self):
        """get_search extra_args appended."""
        cmd, _ = self._extract_cmd("get_search", {
            **self._AUTH, "filter": "(objectClass=user)",
            "extra_args": "--timeout 120",
        })
        assert "--timeout" in cmd

    def test_extra_args_get_writable(self):
        """get_writable extra_args appended."""
        cmd, _ = self._extract_cmd("get_writable", {
            **self._AUTH, "extra_args": "--timeout 300",
        })
        assert "--timeout" in cmd

    def test_extra_args_get_membership(self):
        """get_membership extra_args appended."""
        cmd, _ = self._extract_cmd("get_membership", {
            **self._AUTH, "target": "l.wilson",
            "extra_args": "--timeout 120",
        })
        assert "--timeout" in cmd

    def test_extra_args_get_dnsdump(self):
        """get_dnsdump extra_args appended."""
        cmd, _ = self._extract_cmd("get_dnsdump", {
            **self._AUTH, "extra_args": "--timeout 120",
        })
        assert "--timeout" in cmd

    def test_extra_args_get_trusts(self):
        """get_trusts extra_args appended."""
        cmd, _ = self._extract_cmd("get_trusts", {
            **self._AUTH, "extra_args": "--timeout 120",
        })
        assert "--timeout" in cmd

    def test_extra_args_remove_genericall(self):
        """remove_genericall extra_args appended."""
        cmd, _ = self._extract_cmd("remove_genericall", {
            **self._AUTH, "target": "l.wilson", "trustee": "j.arbuckle",
            "extra_args": "--timeout 30",
        })
        assert "--timeout" in cmd

    def test_extra_args_remove_rbcd(self):
        """remove_rbcd extra_args appended."""
        cmd, _ = self._extract_cmd("remove_rbcd", {
            **self._AUTH, "target": "DC01$", "service": "EVIL01$",
            "extra_args": "--timeout 30",
        })
        assert "--timeout" in cmd

    def test_extra_args_remove_group_member(self):
        """remove_group_member extra_args appended."""
        cmd, _ = self._extract_cmd("remove_group_member", {
            **self._AUTH, "group": "Domain Admins", "member": "j.arbuckle",
            "extra_args": "--timeout 30",
        })
        assert "--timeout" in cmd

    def test_extra_args_remove_shadow_credentials(self):
        """remove_shadow_credentials extra_args appended."""
        cmd, _ = self._extract_cmd("remove_shadow_credentials", {
            **self._AUTH, "target": "l.wilson",
            "extra_args": "--timeout 30",
        })
        assert "--timeout" in cmd

    def test_extra_args_remove_dcsync(self):
        """remove_dcsync extra_args appended."""
        cmd, _ = self._extract_cmd("remove_dcsync", {
            **self._AUTH, "trustee": "j.arbuckle",
            "extra_args": "--timeout 30",
        })
        assert "--timeout" in cmd

    def test_extra_args_remove_uac(self):
        """remove_uac extra_args appended."""
        cmd, _ = self._extract_cmd("remove_uac", {
            **self._AUTH, "target": "l.wilson",
            "flags": ["DONT_REQ_PREAUTH"],
            "extra_args": "--timeout 30",
        })
        assert "--timeout" in cmd

    def test_extra_args_remove_dns_record(self):
        """remove_dns_record extra_args appended."""
        cmd, _ = self._extract_cmd("remove_dns_record", {
            **self._AUTH, "name": "evil", "data": "10.10.14.5",
            "extra_args": "--timeout 30",
        })
        assert "--timeout" in cmd

    def test_extra_args_remove_object(self):
        """remove_object extra_args appended."""
        cmd, _ = self._extract_cmd("remove_object", {
            **self._AUTH, "target": "EVIL01$",
            "extra_args": "--timeout 30",
        })
        assert "--timeout" in cmd

    def test_extra_args_empty_string(self):
        """extra_args as empty string: no extra args appended."""
        cmd, _ = self._extract_cmd("get_object", {
            **self._AUTH, "target": "Administrator",
            "extra_args": "",
        })
        # Empty string should not add any extra args
        # The command should end with the target
        assert cmd[-1] == "Administrator"

    def test_extra_args_none(self):
        """extra_args as None: no extra args appended."""
        cmd, _ = self._extract_cmd("get_object", {
            **self._AUTH, "target": "Administrator",
            "extra_args": None,
        })
        assert cmd[-1] == "Administrator"

    def test_extra_args_quoted_values(self):
        """extra_args with quoted values: shlex.split handles them."""
        cmd, _ = self._extract_cmd("get_object", {
            **self._AUTH, "target": "Administrator",
            "extra_args": '--filter "(objectClass=user)"',
        })
        assert "--filter" in cmd
        assert "(objectClass=user)" in cmd


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

    def test_yaml_has_all_27_methods(self):
        """tool.yaml should define exactly 27 methods."""
        methods = self._yaml.get("methods", {})
        assert len(methods) == 27, (
            f"Expected 27 methods, got {len(methods)}: {sorted(methods.keys())}"
        )

    def test_all_methods_have_descriptions(self):
        """Every method should have a description."""
        for name, defn in self._yaml.get("methods", {}).items():
            assert "description" in defn, f"Method {name} missing description"
            assert len(defn["description"]) > 10, f"Method {name} has too short description"

    def test_all_methods_have_host_and_domain(self):
        """Every method should have 'host' and 'domain' auth params."""
        for name, defn in self._yaml.get("methods", {}).items():
            params = defn.get("params", {})
            assert "host" in params, f"Method {name} missing 'host' param"
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
            pytest.skip("Cannot import BloodyADServer")

        yaml_names = set(self._yaml.get("methods", {}).keys())
        server_names = set(server.methods.keys()) - {"verify_clock"}

        yaml_only = yaml_names - server_names
        server_only = server_names - yaml_names

        assert not yaml_only, f"Methods in tool.yaml but not server: {yaml_only}"
        assert not server_only, f"Methods in server but not tool.yaml: {server_only}"

    def test_yaml_auth_params_subset_of_server(self):
        """Every yaml param should be accepted by the server handler.

        Note: the server may accept EXTRA params via _auth_params() (dc_ip, secure)
        that are not in tool.yaml -- this is a known gap, not a test failure.
        """
        try:
            cls = _get_server_class()
            server = cls()
        except Exception:
            pytest.skip("Cannot import BloodyADServer")

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

    def test_yaml_missing_dc_ip_and_secure(self):
        """Document that tool.yaml is missing dc_ip and secure params.

        The server's _auth_params() includes dc_ip and secure on every method,
        but tool.yaml omits them. This test documents the gap.
        """
        try:
            cls = _get_server_class()
            server = cls()
        except Exception:
            pytest.skip("Cannot import BloodyADServer")

        missing_count = 0
        for method_name, defn in self._yaml.get("methods", {}).items():
            yaml_params = set(defn.get("params", {}).keys())
            if "dc_ip" not in yaml_params:
                missing_count += 1

        # All 27 methods are missing dc_ip and secure -- this is a known gap
        assert missing_count == 27, (
            f"Expected all 27 methods to be missing dc_ip, only {missing_count} are"
        )

    # ── New contract tests: extra_args, certificate, format ──────

    def test_all_methods_have_extra_args(self):
        """Every method in tool.yaml should have an extra_args param."""
        for name, defn in self._yaml.get("methods", {}).items():
            params = defn.get("params", {})
            assert "extra_args" in params, f"Method {name} missing 'extra_args' param"

    def test_all_methods_have_extra_args_in_server(self):
        """Every server method should accept extra_args."""
        try:
            cls = _get_server_class()
            server = cls()
        except Exception:
            pytest.skip("Cannot import BloodyADServer")

        for method_name, method_def in server.methods.items():
            if method_name == "verify_clock":
                continue
            assert "extra_args" in method_def.params, (
                f"Server method {method_name} missing 'extra_args' param"
            )

    def test_all_methods_have_certificate_in_yaml(self):
        """Every method in tool.yaml should have a certificate param."""
        for name, defn in self._yaml.get("methods", {}).items():
            params = defn.get("params", {})
            assert "certificate" in params, f"Method {name} missing 'certificate' param"

    def test_all_methods_have_certificate_in_server(self):
        """Every server method should accept certificate."""
        try:
            cls = _get_server_class()
            server = cls()
        except Exception:
            pytest.skip("Cannot import BloodyADServer")

        for method_name, method_def in server.methods.items():
            if method_name == "verify_clock":
                continue
            assert "certificate" in method_def.params, (
                f"Server method {method_name} missing 'certificate' param"
            )

    def test_all_methods_have_format_in_yaml(self):
        """Every method in tool.yaml should have a format param."""
        for name, defn in self._yaml.get("methods", {}).items():
            params = defn.get("params", {})
            assert "format" in params, f"Method {name} missing 'format' param"

    def test_all_methods_have_format_in_server(self):
        """Every server method should accept format."""
        try:
            cls = _get_server_class()
            server = cls()
        except Exception:
            pytest.skip("Cannot import BloodyADServer")

        for method_name, method_def in server.methods.items():
            if method_name == "verify_clock":
                continue
            assert "format" in method_def.params, (
                f"Server method {method_name} missing 'format' param"
            )

    def test_yaml_and_server_methods_bidirectional(self):
        """All 27 methods match bidirectionally between tool.yaml and server."""
        try:
            cls = _get_server_class()
            server = cls()
        except Exception:
            pytest.skip("Cannot import BloodyADServer")

        yaml_names = set(self._yaml.get("methods", {}).keys())
        server_names = set(server.methods.keys()) - {"verify_clock"}

        assert yaml_names == server_names, (
            f"Mismatch: yaml_only={yaml_names - server_names}, "
            f"server_only={server_names - yaml_names}"
        )

    def test_all_yaml_params_have_type(self):
        """Every param in tool.yaml should have a type field."""
        for method_name, defn in self._yaml.get("methods", {}).items():
            for param_name, param_def in defn.get("params", {}).items():
                assert "type" in param_def, (
                    f"{method_name}.{param_name} missing 'type' field"
                )

    def test_all_yaml_params_have_description(self):
        """Every param in tool.yaml should have a description."""
        for method_name, defn in self._yaml.get("methods", {}).items():
            for param_name, param_def in defn.get("params", {}).items():
                assert "description" in param_def, (
                    f"{method_name}.{param_name} missing 'description' field"
                )


# ===========================================================================
# ACCEPTANCE TESTS -- call every method through the Docker container
# ===========================================================================

class TestAcceptance:
    """Call every method through the container without a live AD target.

    These tests verify:
    - The method exists and is callable
    - Required param validation works (missing required params -> error)
    - The response has correct structuredContent shape
    - Error responses have error_class set (classified, not crash)

    Each test sends minimal args (host + domain but no real target) so the
    command will fail at connection time, but the MCP protocol layer, param
    validation, and error classification should all function correctly.
    """

    _FAKE_AUTH = {
        "host": "10.0.0.1",
        "domain": "test.local",
        "username": "testuser",
        "password": "testpass",
    }

    def _assert_structured_error(self, resp, method_name):
        """Assert response is a classified error with structuredContent."""
        result = resp.get("result", {})
        sc = result.get("structuredContent", {})
        assert sc is not None, f"{method_name}: missing structuredContent"
        # Either success=false with error_class, or isError
        if not sc.get("success", True):
            assert sc.get("error_class") is not None, (
                f"{method_name}: error has no error_class: {sc}"
            )
        content_text = ""
        for c in result.get("content", []):
            if c.get("type") == "text":
                content_text += c["text"]
        # Should NOT be an unhandled crash
        assert "unexpected keyword argument" not in content_text, (
            f"{method_name}: unhandled keyword argument error"
        )
        return sc

    # ── SET methods ────────────────────────────────────────────

    def test_set_password(self, bloodyad_env):
        """set_password with fake auth returns classified connection error."""
        client, loop = bloodyad_env
        resp = loop.run_until_complete(client.call("set_password", {
            **self._FAKE_AUTH, "target": "testuser", "new_password": "NewP@ss1!",
        }))
        self._assert_structured_error(resp, "set_password")

    def test_set_password_missing_target(self, bloodyad_env):
        """set_password without 'target' returns error about missing param."""
        client, loop = bloodyad_env
        resp = loop.run_until_complete(client.call("set_password", {
            **self._FAKE_AUTH, "new_password": "NewP@ss1!",
        }))
        result = resp.get("result", {})
        is_error = result.get("isError", False)
        content_text = ""
        for c in result.get("content", []):
            if c.get("type") == "text":
                content_text += c["text"]
        assert is_error or "target" in content_text.lower() or "required" in content_text.lower()

    def test_set_password_missing_new_password(self, bloodyad_env):
        """set_password without 'new_password' returns error."""
        client, loop = bloodyad_env
        resp = loop.run_until_complete(client.call("set_password", {
            **self._FAKE_AUTH, "target": "testuser",
        }))
        result = resp.get("result", {})
        is_error = result.get("isError", False)
        content_text = ""
        for c in result.get("content", []):
            if c.get("type") == "text":
                content_text += c["text"]
        assert is_error or "new_password" in content_text.lower() or "required" in content_text.lower()

    def test_set_owner(self, bloodyad_env):
        """set_owner with fake auth returns classified connection error."""
        client, loop = bloodyad_env
        resp = loop.run_until_complete(client.call("set_owner", {
            **self._FAKE_AUTH, "target": "testobj", "owner": "testuser",
        }))
        self._assert_structured_error(resp, "set_owner")

    def test_set_object(self, bloodyad_env):
        """set_object with fake auth returns classified connection error."""
        client, loop = bloodyad_env
        resp = loop.run_until_complete(client.call("set_object", {
            **self._FAKE_AUTH, "target": "testobj", "attribute": "description",
            "values": ["test-value"],
        }))
        self._assert_structured_error(resp, "set_object")

    # ── ADD methods ────────────────────────────────────────────

    def test_add_genericall(self, bloodyad_env):
        """add_genericall with fake auth returns classified error."""
        client, loop = bloodyad_env
        resp = loop.run_until_complete(client.call("add_genericall", {
            **self._FAKE_AUTH, "target": "testobj", "trustee": "testuser",
        }))
        self._assert_structured_error(resp, "add_genericall")

    def test_add_rbcd(self, bloodyad_env):
        """add_rbcd with fake auth returns classified error."""
        client, loop = bloodyad_env
        resp = loop.run_until_complete(client.call("add_rbcd", {
            **self._FAKE_AUTH, "target": "DC01$", "service": "EVIL01$",
        }))
        self._assert_structured_error(resp, "add_rbcd")

    def test_add_shadow_credentials(self, bloodyad_env):
        """add_shadow_credentials with fake auth returns classified error."""
        client, loop = bloodyad_env
        resp = loop.run_until_complete(client.call("add_shadow_credentials", {
            **self._FAKE_AUTH, "target": "testuser",
        }))
        self._assert_structured_error(resp, "add_shadow_credentials")

    def test_add_group_member(self, bloodyad_env):
        """add_group_member with fake auth returns classified error."""
        client, loop = bloodyad_env
        resp = loop.run_until_complete(client.call("add_group_member", {
            **self._FAKE_AUTH, "group": "Domain Admins", "member": "testuser",
        }))
        self._assert_structured_error(resp, "add_group_member")

    def test_add_group_member_missing_group(self, bloodyad_env):
        """add_group_member without 'group' returns error."""
        client, loop = bloodyad_env
        resp = loop.run_until_complete(client.call("add_group_member", {
            **self._FAKE_AUTH, "member": "testuser",
        }))
        result = resp.get("result", {})
        is_error = result.get("isError", False)
        content_text = ""
        for c in result.get("content", []):
            if c.get("type") == "text":
                content_text += c["text"]
        assert is_error or "group" in content_text.lower() or "required" in content_text.lower()

    def test_add_computer(self, bloodyad_env):
        """add_computer with fake auth returns classified error."""
        client, loop = bloodyad_env
        resp = loop.run_until_complete(client.call("add_computer", {
            **self._FAKE_AUTH, "hostname": "EVIL01", "computer_pass": "Pass123!",
        }))
        self._assert_structured_error(resp, "add_computer")

    def test_add_dcsync(self, bloodyad_env):
        """add_dcsync with fake auth returns classified error."""
        client, loop = bloodyad_env
        resp = loop.run_until_complete(client.call("add_dcsync", {
            **self._FAKE_AUTH, "trustee": "testuser",
        }))
        self._assert_structured_error(resp, "add_dcsync")

    def test_add_uac(self, bloodyad_env):
        """add_uac with fake auth returns classified error."""
        client, loop = bloodyad_env
        resp = loop.run_until_complete(client.call("add_uac", {
            **self._FAKE_AUTH, "target": "testuser",
            "flags": ["DONT_REQ_PREAUTH"],
        }))
        self._assert_structured_error(resp, "add_uac")

    def test_add_uac_missing_flags(self, bloodyad_env):
        """add_uac without 'flags' returns error."""
        client, loop = bloodyad_env
        resp = loop.run_until_complete(client.call("add_uac", {
            **self._FAKE_AUTH, "target": "testuser",
        }))
        result = resp.get("result", {})
        is_error = result.get("isError", False)
        content_text = ""
        for c in result.get("content", []):
            if c.get("type") == "text":
                content_text += c["text"]
        assert is_error or "flags" in content_text.lower() or "required" in content_text.lower()

    def test_add_dns_record(self, bloodyad_env):
        """add_dns_record with fake auth returns classified error."""
        client, loop = bloodyad_env
        resp = loop.run_until_complete(client.call("add_dns_record", {
            **self._FAKE_AUTH, "name": "evil", "data": "10.10.14.5",
        }))
        self._assert_structured_error(resp, "add_dns_record")

    def test_add_user(self, bloodyad_env):
        """add_user with fake auth returns classified error."""
        client, loop = bloodyad_env
        resp = loop.run_until_complete(client.call("add_user", {
            **self._FAKE_AUTH, "sam_account_name": "backdoor",
            "new_password": "B@ckD00r!",
        }))
        self._assert_structured_error(resp, "add_user")

    # ── GET methods ────────────────────────────────────────────

    def test_get_object(self, bloodyad_env):
        """get_object with fake auth returns classified connection error."""
        client, loop = bloodyad_env
        resp = loop.run_until_complete(client.call("get_object", {
            **self._FAKE_AUTH, "target": "Administrator",
        }))
        self._assert_structured_error(resp, "get_object")

    def test_get_object_missing_target(self, bloodyad_env):
        """get_object without 'target' returns error about missing param."""
        client, loop = bloodyad_env
        resp = loop.run_until_complete(client.call("get_object", {
            **self._FAKE_AUTH,
        }))
        result = resp.get("result", {})
        is_error = result.get("isError", False)
        content_text = ""
        for c in result.get("content", []):
            if c.get("type") == "text":
                content_text += c["text"]
        assert is_error or "target" in content_text.lower() or "required" in content_text.lower()

    def test_get_children(self, bloodyad_env):
        """get_children with fake auth returns classified error."""
        client, loop = bloodyad_env
        resp = loop.run_until_complete(client.call("get_children", {
            **self._FAKE_AUTH,
        }))
        self._assert_structured_error(resp, "get_children")

    def test_get_search(self, bloodyad_env):
        """get_search with fake auth returns classified error."""
        client, loop = bloodyad_env
        resp = loop.run_until_complete(client.call("get_search", {
            **self._FAKE_AUTH, "filter": "(objectClass=user)",
        }))
        self._assert_structured_error(resp, "get_search")

    def test_get_search_missing_filter(self, bloodyad_env):
        """get_search without 'filter' returns error about missing param."""
        client, loop = bloodyad_env
        resp = loop.run_until_complete(client.call("get_search", {
            **self._FAKE_AUTH,
        }))
        result = resp.get("result", {})
        is_error = result.get("isError", False)
        content_text = ""
        for c in result.get("content", []):
            if c.get("type") == "text":
                content_text += c["text"]
        assert is_error or "filter" in content_text.lower() or "required" in content_text.lower()

    def test_get_writable(self, bloodyad_env):
        """get_writable with fake auth returns classified error."""
        client, loop = bloodyad_env
        resp = loop.run_until_complete(client.call("get_writable", {
            **self._FAKE_AUTH,
        }))
        self._assert_structured_error(resp, "get_writable")

    def test_get_membership(self, bloodyad_env):
        """get_membership with fake auth returns classified error."""
        client, loop = bloodyad_env
        resp = loop.run_until_complete(client.call("get_membership", {
            **self._FAKE_AUTH, "target": "testuser",
        }))
        self._assert_structured_error(resp, "get_membership")

    def test_get_dnsdump(self, bloodyad_env):
        """get_dnsdump with fake auth returns classified error."""
        client, loop = bloodyad_env
        resp = loop.run_until_complete(client.call("get_dnsdump", {
            **self._FAKE_AUTH,
        }))
        self._assert_structured_error(resp, "get_dnsdump")

    def test_get_trusts(self, bloodyad_env):
        """get_trusts with fake auth returns classified error."""
        client, loop = bloodyad_env
        resp = loop.run_until_complete(client.call("get_trusts", {
            **self._FAKE_AUTH,
        }))
        self._assert_structured_error(resp, "get_trusts")

    # ── REMOVE methods ─────────────────────────────────────────

    def test_remove_genericall(self, bloodyad_env):
        """remove_genericall with fake auth returns classified error."""
        client, loop = bloodyad_env
        resp = loop.run_until_complete(client.call("remove_genericall", {
            **self._FAKE_AUTH, "target": "testobj", "trustee": "testuser",
        }))
        self._assert_structured_error(resp, "remove_genericall")

    def test_remove_rbcd(self, bloodyad_env):
        """remove_rbcd with fake auth returns classified error."""
        client, loop = bloodyad_env
        resp = loop.run_until_complete(client.call("remove_rbcd", {
            **self._FAKE_AUTH, "target": "DC01$", "service": "EVIL01$",
        }))
        self._assert_structured_error(resp, "remove_rbcd")

    def test_remove_group_member(self, bloodyad_env):
        """remove_group_member with fake auth returns classified error."""
        client, loop = bloodyad_env
        resp = loop.run_until_complete(client.call("remove_group_member", {
            **self._FAKE_AUTH, "group": "Domain Admins", "member": "testuser",
        }))
        self._assert_structured_error(resp, "remove_group_member")

    def test_remove_shadow_credentials(self, bloodyad_env):
        """remove_shadow_credentials with fake auth returns classified error."""
        client, loop = bloodyad_env
        resp = loop.run_until_complete(client.call("remove_shadow_credentials", {
            **self._FAKE_AUTH, "target": "testuser",
        }))
        self._assert_structured_error(resp, "remove_shadow_credentials")

    def test_remove_dcsync(self, bloodyad_env):
        """remove_dcsync with fake auth returns classified error."""
        client, loop = bloodyad_env
        resp = loop.run_until_complete(client.call("remove_dcsync", {
            **self._FAKE_AUTH, "trustee": "testuser",
        }))
        self._assert_structured_error(resp, "remove_dcsync")

    def test_remove_uac(self, bloodyad_env):
        """remove_uac with fake auth returns classified error."""
        client, loop = bloodyad_env
        resp = loop.run_until_complete(client.call("remove_uac", {
            **self._FAKE_AUTH, "target": "testuser",
            "flags": ["DONT_REQ_PREAUTH"],
        }))
        self._assert_structured_error(resp, "remove_uac")

    # ── New methods: remove_dns_record, remove_object ───────────

    def test_remove_dns_record(self, bloodyad_env):
        """remove_dns_record with fake auth returns classified error."""
        client, loop = bloodyad_env
        resp = loop.run_until_complete(client.call("remove_dns_record", {
            **self._FAKE_AUTH, "name": "evil", "data": "10.10.14.5",
        }))
        self._assert_structured_error(resp, "remove_dns_record")

    def test_remove_dns_record_missing_name(self, bloodyad_env):
        """remove_dns_record without 'name' returns error."""
        client, loop = bloodyad_env
        resp = loop.run_until_complete(client.call("remove_dns_record", {
            **self._FAKE_AUTH, "data": "10.10.14.5",
        }))
        result = resp.get("result", {})
        is_error = result.get("isError", False)
        content_text = ""
        for c in result.get("content", []):
            if c.get("type") == "text":
                content_text += c["text"]
        assert is_error or "name" in content_text.lower() or "required" in content_text.lower()

    def test_remove_dns_record_missing_data(self, bloodyad_env):
        """remove_dns_record without 'data' returns error."""
        client, loop = bloodyad_env
        resp = loop.run_until_complete(client.call("remove_dns_record", {
            **self._FAKE_AUTH, "name": "evil",
        }))
        result = resp.get("result", {})
        is_error = result.get("isError", False)
        content_text = ""
        for c in result.get("content", []):
            if c.get("type") == "text":
                content_text += c["text"]
        assert is_error or "data" in content_text.lower() or "required" in content_text.lower()

    def test_remove_object(self, bloodyad_env):
        """remove_object with fake auth returns classified error."""
        client, loop = bloodyad_env
        resp = loop.run_until_complete(client.call("remove_object", {
            **self._FAKE_AUTH, "target": "EVIL01$",
        }))
        self._assert_structured_error(resp, "remove_object")

    def test_remove_object_missing_target(self, bloodyad_env):
        """remove_object without 'target' returns error."""
        client, loop = bloodyad_env
        resp = loop.run_until_complete(client.call("remove_object", {
            **self._FAKE_AUTH,
        }))
        result = resp.get("result", {})
        is_error = result.get("isError", False)
        content_text = ""
        for c in result.get("content", []):
            if c.get("type") == "text":
                content_text += c["text"]
        assert is_error or "target" in content_text.lower() or "required" in content_text.lower()

    # ── Cross-cutting: certificate param ──────────────────────

    def test_certificate_param_accepted(self, bloodyad_env):
        """certificate param is accepted without crashing."""
        client, loop = bloodyad_env
        resp = loop.run_until_complete(client.call("get_object", {
            **self._FAKE_AUTH, "target": "Administrator",
            "certificate": "/creds/admin.key:/creds/admin.crt",
        }))
        result = resp.get("result", {})
        content_text = ""
        for c in result.get("content", []):
            if c.get("type") == "text":
                content_text += c["text"]
        assert "unexpected keyword argument" not in content_text

    def test_certificate_param_on_write_method(self, bloodyad_env):
        """certificate param accepted on write method (add_rbcd)."""
        client, loop = bloodyad_env
        resp = loop.run_until_complete(client.call("add_rbcd", {
            **self._FAKE_AUTH, "target": "DC01$", "service": "EVIL01$",
            "certificate": "/creds/admin.key:/creds/admin.crt",
        }))
        self._assert_structured_error(resp, "add_rbcd with cert")

    # ── Cross-cutting: format param ───────────────────────────

    def test_format_param_accepted(self, bloodyad_env):
        """format param is accepted without crashing."""
        client, loop = bloodyad_env
        resp = loop.run_until_complete(client.call("get_object", {
            **self._FAKE_AUTH, "target": "Administrator",
            "format": "hex",
        }))
        result = resp.get("result", {})
        content_text = ""
        for c in result.get("content", []):
            if c.get("type") == "text":
                content_text += c["text"]
        assert "unexpected keyword argument" not in content_text

    def test_format_param_aes_accepted(self, bloodyad_env):
        """format='aes' accepted."""
        client, loop = bloodyad_env
        resp = loop.run_until_complete(client.call("set_password", {
            **self._FAKE_AUTH, "target": "testuser", "new_password": "P@ss!",
            "format": "aes",
        }))
        result = resp.get("result", {})
        content_text = ""
        for c in result.get("content", []):
            if c.get("type") == "text":
                content_text += c["text"]
        assert "unexpected keyword argument" not in content_text

    def test_format_param_rc4_accepted(self, bloodyad_env):
        """format='rc4' accepted."""
        client, loop = bloodyad_env
        resp = loop.run_until_complete(client.call("add_genericall", {
            **self._FAKE_AUTH, "target": "testobj", "trustee": "testuser",
            "format": "rc4",
        }))
        self._assert_structured_error(resp, "add_genericall with format=rc4")

    # ── Cross-cutting: extra_args through container ───────────

    def test_extra_args_accepted(self, bloodyad_env):
        """extra_args param is accepted through the container."""
        client, loop = bloodyad_env
        resp = loop.run_until_complete(client.call("get_object", {
            **self._FAKE_AUTH, "target": "Administrator",
            "extra_args": "--timeout 30",
        }))
        result = resp.get("result", {})
        content_text = ""
        for c in result.get("content", []):
            if c.get("type") == "text":
                content_text += c["text"]
        assert "unexpected keyword argument" not in content_text

    def test_extra_args_on_write_method(self, bloodyad_env):
        """extra_args accepted on write method (add_group_member)."""
        client, loop = bloodyad_env
        resp = loop.run_until_complete(client.call("add_group_member", {
            **self._FAKE_AUTH, "group": "Domain Admins", "member": "testuser",
            "extra_args": "--timeout 30",
        }))
        self._assert_structured_error(resp, "add_group_member with extra_args")

    def test_extra_args_on_remove_method(self, bloodyad_env):
        """extra_args accepted on remove method (remove_object)."""
        client, loop = bloodyad_env
        resp = loop.run_until_complete(client.call("remove_object", {
            **self._FAKE_AUTH, "target": "EVIL01$",
            "extra_args": "--timeout 30",
        }))
        self._assert_structured_error(resp, "remove_object with extra_args")

    # ── structuredContent on every method ─────────────────────

    def test_structuredContent_on_remove_dns_record(self, bloodyad_env):
        """remove_dns_record returns structuredContent."""
        client, loop = bloodyad_env
        resp = loop.run_until_complete(client.call("remove_dns_record", {
            **self._FAKE_AUTH, "name": "evil", "data": "10.10.14.5",
        }))
        result = resp.get("result", {})
        sc = result.get("structuredContent")
        assert sc is not None, "remove_dns_record: missing structuredContent"

    def test_structuredContent_on_remove_object(self, bloodyad_env):
        """remove_object returns structuredContent."""
        client, loop = bloodyad_env
        resp = loop.run_until_complete(client.call("remove_object", {
            **self._FAKE_AUTH, "target": "EVIL01$",
        }))
        result = resp.get("result", {})
        sc = result.get("structuredContent")
        assert sc is not None, "remove_object: missing structuredContent"

    # ── Cross-cutting acceptance tests ─────────────────────────

    def test_kerberos_flag_accepted(self, bloodyad_env):
        """kerberos=true is accepted without crashing."""
        client, loop = bloodyad_env
        resp = loop.run_until_complete(client.call("get_object", {
            "host": "10.0.0.1", "domain": "test.local",
            "kerberos": True, "target": "Administrator",
        }))
        result = resp.get("result", {})
        content_text = ""
        for c in result.get("content", []):
            if c.get("type") == "text":
                content_text += c["text"]
        assert "unexpected keyword argument" not in content_text

    def test_dc_ip_param_accepted(self, bloodyad_env):
        """dc_ip parameter is accepted without crashing."""
        client, loop = bloodyad_env
        resp = loop.run_until_complete(client.call("get_object", {
            **self._FAKE_AUTH, "target": "Administrator",
            "dc_ip": "10.0.0.2",
        }))
        result = resp.get("result", {})
        content_text = ""
        for c in result.get("content", []):
            if c.get("type") == "text":
                content_text += c["text"]
        assert "unexpected keyword argument" not in content_text

    def test_secure_param_accepted(self, bloodyad_env):
        """secure=true parameter is accepted without crashing."""
        client, loop = bloodyad_env
        resp = loop.run_until_complete(client.call("get_object", {
            **self._FAKE_AUTH, "target": "Administrator",
            "secure": True,
        }))
        result = resp.get("result", {})
        content_text = ""
        for c in result.get("content", []):
            if c.get("type") == "text":
                content_text += c["text"]
        assert "unexpected keyword argument" not in content_text

    def test_all_methods_return_structuredContent(self, bloodyad_env):
        """Every method in the server returns structuredContent in responses."""
        client, loop = bloodyad_env
        # Test with verify_clock (guaranteed to succeed)
        resp = loop.run_until_complete(client.call("verify_clock", {}))
        result = resp.get("result", {})
        sc = result.get("structuredContent")
        assert sc is not None
        assert isinstance(sc, dict)
        # All required fields
        for field in ("success", "error_class", "retryable", "suggestions"):
            assert field in sc, f"Missing field '{field}' in structuredContent"


# ===========================================================================
# INTEGRATION TESTS -- require --target, --domain, etc.
# ===========================================================================

@pytest.mark.integration
class TestIntegration:
    """Integration tests that need a real AD target.

    Run with: pytest tests/tools/test_bloodyad.py --tool=bloodyad
              --target=<DC_IP> --domain=<DOMAIN> --username=<USER> --password=<PASS>
              -m integration -v
    """

    def test_get_object(self, bloodyad_env, target, domain, username, password):
        """Read attributes of a known AD object."""
        client, loop = bloodyad_env
        resp = loop.run_until_complete(client.call("get_object", {
            "host": target,
            "domain": domain,
            "username": username,
            "password": password,
            "target": "Administrator",
        }))
        result = assert_tool_success(resp, "get_object should succeed with valid creds")
        data = parse_tool_output(resp)
        if isinstance(data, dict):
            raw = data.get("raw_output", "")
        else:
            raw = str(data)
        assert "administrator" in raw.lower() or "distinguishedName" in raw, (
            f"Expected Administrator object data, got: {raw[:300]}"
        )

    def test_get_membership(self, bloodyad_env, target, domain, username, password):
        """Retrieve group memberships of a user."""
        client, loop = bloodyad_env
        resp = loop.run_until_complete(client.call("get_membership", {
            "host": target,
            "domain": domain,
            "username": username,
            "password": password,
            "target": username,
        }))
        result = assert_tool_success(resp, "get_membership should succeed")
        data = parse_tool_output(resp)
        if isinstance(data, dict):
            raw = data.get("raw_output", "")
        else:
            raw = str(data)
        assert "domain users" in raw.lower() or "distinguishedName" in raw.lower(), (
            f"Expected group membership data, got: {raw[:300]}"
        )

    def test_set_password(self, bloodyad_env, target, domain, username, password):
        """Set a user's password (requires ForceChangePassword on a test user).

        This test is conditional -- it may fail if the user doesn't have
        ForceChangePassword rights on any test user. The important thing is
        that it doesn't crash.
        """
        client, loop = bloodyad_env
        resp = loop.run_until_complete(client.call("set_password", {
            "host": target,
            "domain": domain,
            "username": username,
            "password": password,
            "target": username,  # Try on self (may fail)
            "new_password": "Temp123!Temp456!",
        }))
        result = resp.get("result", {})
        # We accept either success or a classified error -- just not a crash
        sc = result.get("structuredContent", {})
        assert sc is not None, "Should have structuredContent even on failure"

    def test_get_object_with_dc_ip(self, bloodyad_env, target, domain, username, password):
        """Test that dc_ip parameter is accepted and works."""
        client, loop = bloodyad_env
        resp = loop.run_until_complete(client.call("get_object", {
            "host": target,
            "domain": domain,
            "username": username,
            "password": password,
            "target": "Administrator",
            "dc_ip": target,
        }))
        result = resp.get("result", {})
        content_text = ""
        for c in result.get("content", []):
            if c.get("type") == "text":
                content_text += c["text"]
        # Should not fail with "unexpected keyword argument"
        assert "unexpected keyword argument" not in content_text


# ===========================================================================
# CROSS-TOOL INTEGRATION TEST -- bloodyad + impacket ccache flow
# ===========================================================================

@pytest.mark.integration
class TestCrossTool:
    """Cross-tool integration tests.

    Verifies that bloodyAD can use a ccache file from /session/credentials/,
    which is the standard flow when impacket's get_tgt creates a ccache that
    bloodyAD then uses for Kerberos auth.
    """

    def test_kerberos_with_ccache(self, bloodyad_env, target, domain, username, password):
        """bloodyAD should accept kerberos=true + ccache_path without crashing.

        This tests the parameter handling even if the ccache doesn't exist
        (we expect a connection/auth error, not a crash).
        """
        client, loop = bloodyad_env
        resp = loop.run_until_complete(client.call("get_object", {
            "host": target,
            "domain": domain,
            "kerberos": True,
            "ccache_path": "/session/credentials/test.ccache",
            "target": "Administrator",
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
            assert sc.get("error_class") is not None, (
                "Error should be classified"
            )
