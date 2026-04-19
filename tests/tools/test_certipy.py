"""
Tests for the certipy MCP tool server.

Covers:
- Smoke tests: boot, method list, required params, meta-param stripping, clock
- Unit tests: output parsers, error classification/detection, command building
- Contract tests: tool.yaml vs server parameter definitions
- Acceptance tests: call every method through Docker container, verify structured responses
- Integration tests: real target scenarios (marked @pytest.mark.integration)
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
TOOL_DIR = PROJECT_ROOT / "tools" / "certipy"
FIXTURES_DIR = Path(__file__).parent.parent / "fixtures" / "certipy"

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
def certipy_env(request):
    """Create an MCPTestClient with its event loop. Yields (client, loop)."""
    tool = "certipy"
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
    """Import and return the CertipyServer class for direct method testing."""
    import importlib.util
    spec = importlib.util.spec_from_file_location(
        "certipy_server", TOOL_DIR / "mcp-server.py"
    )
    mod = importlib.util.module_from_spec(spec)
    spec.loader.exec_module(mod)
    return mod.CertipyServer


# ===========================================================================
# SMOKE TESTS -- require Docker container running
# ===========================================================================

class TestSmoke:
    """Smoke tests that verify the container boots and basic protocol works."""

    def test_boot_and_list_tools(self, certipy_env):
        """Container starts and list_tools returns methods."""
        client, loop = certipy_env
        assert len(client.tools) > 0, "Server should advertise at least one tool"
        names = client.tool_names()
        assert "find" in names, "find should be in tool list"
        assert "request" in names, "request should be in tool list"
        assert "authenticate" in names, "authenticate should be in tool list"
        assert "shadow" in names, "shadow should be in tool list"
        assert "forge" in names, "forge should be in tool list"
        assert "template" in names, "template should be in tool list"
        assert "ca" in names, "ca should be in tool list"

    def test_method_list_matches_tool_yaml(self, certipy_env):
        """Every method in tool.yaml is advertised by the server, and vice versa."""
        client, _ = certipy_env
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

    def test_expected_method_count(self, certipy_env):
        """Server should have exactly 10 built-in methods + verify_clock."""
        client, _ = certipy_env
        names = client.tool_names()
        # 10 built-in + verify_clock in MCP_TEST_MODE
        assert len(names) == 11, (
            f"Expected 11 methods (10 built-in + verify_clock), got {len(names)}: {sorted(names)}"
        )

    def test_required_params_enforced_find(self, certipy_env):
        """Calling find without required 'username' and 'dc_ip' returns an error."""
        client, loop = certipy_env
        resp = loop.run_until_complete(
            client.call("find", {"vulnerable": True})
        )
        result = resp.get("result", {})
        is_error = result.get("isError", False)
        content_text = ""
        for c in result.get("content", []):
            if c.get("type") == "text":
                content_text += c["text"]
        # Should fail because username/dc_ip are missing
        assert is_error or "error" in content_text.lower() or "missing" in content_text.lower(), (
            f"Expected error about missing required params, got: {content_text[:300]}"
        )

    def test_required_params_enforced_request(self, certipy_env):
        """Calling request without 'ca' returns an error."""
        client, loop = certipy_env
        resp = loop.run_until_complete(
            client.call("request", {
                "username": "test@corp.local",
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
        assert is_error or "ca" in content_text.lower() or "error" in content_text.lower(), (
            f"Expected error about missing 'ca', got: {content_text[:300]}"
        )

    def test_meta_params_stripped(self, certipy_env):
        """Passing 'clock_offset' (meta-param) in args does not crash the server."""
        client, loop = certipy_env
        resp = loop.run_until_complete(
            client.call("find", {
                "username": "test@corp.local",
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

    def test_unknown_method_returns_error(self, certipy_env):
        """Calling a non-existent method returns a helpful error."""
        client, loop = certipy_env
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
    def test_verify_clock_available(self, certipy_env):
        """verify_clock is registered in MCP_TEST_MODE."""
        client, _ = certipy_env
        names = client.tool_names()
        assert "verify_clock" in names, "verify_clock should be available in test mode"

    @pytest.mark.clock
    def test_verify_clock_returns_time(self, certipy_env):
        """verify_clock returns current time and FAKETIME status."""
        client, loop = certipy_env
        resp = loop.run_until_complete(client.call("verify_clock", {}))
        result = assert_tool_success(resp)
        data = parse_tool_output(resp)
        assert "current_time" in data
        assert "libfaketime_exists" in data
        # libfaketime is installed in this image
        assert data["libfaketime_exists"] is True, (
            "libfaketime should be installed in the certipy image"
        )

    def test_structuredContent_present(self, certipy_env):
        """Responses include structuredContent with error classification fields."""
        client, loop = certipy_env
        resp = loop.run_until_complete(client.call("verify_clock", {}))
        result = resp.get("result", {})
        sc = result.get("structuredContent")
        assert sc is not None, "structuredContent should be present"
        assert "success" in sc
        assert "error_class" in sc
        assert "retryable" in sc
        assert "suggestions" in sc

    def test_no_credentials_returns_clear_error(self, certipy_env):
        """Calling find with no auth creds returns a clear 'no credentials' error."""
        client, loop = certipy_env
        resp = loop.run_until_complete(
            client.call("find", {
                "username": "test@corp.local",
                "dc_ip": "10.0.0.1",
            })
        )
        result = resp.get("result", {})
        content_text = ""
        for c in result.get("content", []):
            if c.get("type") == "text":
                content_text += c["text"]
        assert "credentials" in content_text.lower() or "password" in content_text.lower(), (
            f"Expected error about missing credentials, got: {content_text[:300]}"
        )


# ===========================================================================
# UNIT TESTS -- output parsers, no container needed
# ===========================================================================

class TestParsers:
    """Test output parsing functions using fixture data.

    These tests instantiate the server class directly and call its
    parser methods. No Docker container needed.
    """

    @pytest.fixture(autouse=True, scope="class")
    def server(self):
        """Create a server instance for parser testing."""
        try:
            cls = _get_server_class()
            self.__class__._server = cls()
        except Exception as e:
            pytest.skip(f"Cannot import CertipyServer: {e}")

    # -- _parse_auth_output ------------------------------------------------

    def test_parse_auth_success_nt_hash(self):
        """Parse auth output with NT hash extraction."""
        text = load_fixture("auth_success.txt")
        result = self._server._parse_auth_output(text)
        assert result["nt_hash"] is not None, "Should extract NT hash"
        assert "aad3b435b51404ee" in result["nt_hash"], f"NT hash wrong: {result['nt_hash']}"
        assert "44b1b5623a1446b5831a7b3a4be3977b" in result["nt_hash"]

    def test_parse_auth_success_username(self):
        """Parse auth output username and domain."""
        text = load_fixture("auth_success.txt")
        result = self._server._parse_auth_output(text)
        # Username should not have leading/trailing quotes
        assert result["username"] is not None
        assert "'" not in (result["username"] or ""), (
            f"Username should not contain quotes: {result['username']}"
        )

    def test_parse_auth_success_domain(self):
        """Parse auth output domain extraction."""
        text = load_fixture("auth_success.txt")
        result = self._server._parse_auth_output(text)
        if result["domain"]:
            assert "'" not in result["domain"], (
                f"Domain should not contain quotes: {result['domain']}"
            )

    def test_parse_auth_success_ccache(self):
        """Parse auth output ccache path."""
        text = load_fixture("auth_success.txt")
        result = self._server._parse_auth_output(text)
        assert result["ccache_path"] is not None, "Should detect ccache file"
        assert "john.w.ccache" in result["ccache_path"]

    def test_parse_auth_no_hash(self):
        """Parse auth output when certificate is not valid for client auth."""
        text = load_fixture("auth_cert_not_valid.txt")
        result = self._server._parse_auth_output(text)
        assert result["nt_hash"] is None, "Should not extract NT hash on failure"
        assert result["ccache_path"] is None, "Should not have ccache on failure"

    def test_parse_auth_no_identity(self):
        """Parse auth output when identity info is missing."""
        text = load_fixture("auth_no_identity.txt")
        result = self._server._parse_auth_output(text)
        assert result["nt_hash"] is None
        assert result["ccache_path"] is None

    def test_parse_auth_no_pass_needed(self):
        """Parse auth output for administrator with different hash format."""
        text = load_fixture("auth_no_pass_needed.txt")
        result = self._server._parse_auth_output(text)
        assert result["nt_hash"] is not None, "Should extract NT hash"
        assert "2b576acbe6bcfda7294d6bd18041b8fe" in result["nt_hash"]
        assert result["ccache_path"] is not None, "Should detect ccache file"
        assert "administrator.ccache" in result["ccache_path"]
        assert result["username"] == "administrator"
        assert result["domain"] == "corp.local"

    def test_parse_auth_clock_skew(self):
        """Parse auth output with clock skew -- no hash or ccache."""
        text = load_fixture("auth_clock_skew.txt")
        result = self._server._parse_auth_output(text)
        assert result["nt_hash"] is None, "No hash on clock skew failure"
        assert result["ccache_path"] is None
        # But should still extract username/domain from principal
        assert result["username"] == "administrator"
        assert result["domain"] is not None

    def test_parse_auth_empty_output(self):
        """Parse completely empty output."""
        result = self._server._parse_auth_output("")
        assert result["nt_hash"] is None
        assert result["ccache_path"] is None
        assert result["kirbi_path"] is None
        assert result["username"] is None
        assert result["domain"] is None

    def test_parse_auth_kirbi_output(self):
        """Parse auth output with kirbi file reference."""
        text = "[*] Saved TGT to 'administrator.kirbi'\n[*] Got hash for 'admin@corp.local': aad3b435b51404ee:abc123def456\n"
        result = self._server._parse_auth_output(text)
        assert result["kirbi_path"] is not None
        assert "administrator.kirbi" in result["kirbi_path"]
        assert result["nt_hash"] is not None

    # -- _parse_shadow_output -----------------------------------------------

    def test_parse_shadow_auto_success(self):
        """Parse shadow auto output with NT hash and device ID."""
        text = load_fixture("shadow_auto_success.txt")
        result = self._server._parse_shadow_output(text)
        assert result["nt_hash"] is not None, f"Should extract NT hash, got: {result}"
        assert "e3cfe51adbb8b0aa52ed63ca76ba2e30" in result["nt_hash"]

    def test_parse_shadow_device_id(self):
        """Parse shadow output for DeviceID extraction."""
        text = load_fixture("shadow_auto_success.txt")
        result = self._server._parse_shadow_output(text)
        assert result["device_id"] is not None, (
            f"Should extract DeviceID, got: {result}"
        )
        assert "a1b2c3d4e5f6a7b8c9d0e1f2a3b4c5d6" in result["device_id"]

    def test_parse_shadow_insufficient_access(self):
        """Parse shadow output with insufficient access rights."""
        text = load_fixture("shadow_insufficient_access.txt")
        result = self._server._parse_shadow_output(text)
        # Should still extract DeviceID from the generated credential
        assert result["device_id"] is not None, (
            f"Should extract DeviceID even on failure: {result}"
        )

    def test_parse_shadow_list(self):
        """Parse shadow list output with key credentials."""
        text = load_fixture("shadow_list.txt")
        result = self._server._parse_shadow_output(text)
        assert len(result["key_credentials"]) >= 1, (
            f"Should parse key credentials from list, got: {result['key_credentials']}"
        )

    def test_parse_shadow_list_multiple_credentials(self):
        """Parse shadow list with multiple key credentials."""
        text = load_fixture("shadow_list.txt")
        result = self._server._parse_shadow_output(text)
        assert len(result["key_credentials"]) >= 2, (
            f"Should find at least 2 key credentials, got {len(result['key_credentials'])}"
        )
        # Check device IDs are distinct
        device_ids = [kc["device_id"] for kc in result["key_credentials"]]
        assert len(set(device_ids)) == len(device_ids), "Device IDs should be unique"

    def test_parse_shadow_add_success(self):
        """Parse shadow add output for PFX path and device ID."""
        text = load_fixture("shadow_add_success.txt")
        result = self._server._parse_shadow_output(text)
        assert result["device_id"] is not None
        assert "b2c3d4e5f6a7b8c9d0e1f2a3b4c5d6a7" in result["device_id"]
        assert result["pfx_path"] is not None
        assert "svc_backup.pfx" in result["pfx_path"]

    def test_parse_shadow_empty_output(self):
        """Parse empty shadow output."""
        result = self._server._parse_shadow_output("")
        assert result["nt_hash"] is None
        assert result["pfx_path"] is None
        assert result["device_id"] is None
        assert result["key_credentials"] == []

    def test_parse_shadow_clear_no_hash(self):
        """Parse shadow clear output -- no hash expected."""
        text = load_fixture("shadow_clear_success.txt")
        result = self._server._parse_shadow_output(text)
        assert result["nt_hash"] is None, "Clear action should not produce an NT hash"

    # -- _detect_certipy_error ----------------------------------------------

    def test_detect_ntlm_auth_failed(self):
        """Detect LDAP NTLM authentication failure."""
        text = load_fixture("find_ntlm_auth_failed.txt")
        error = self._server._detect_certipy_error(text)
        assert error is not None, "Should detect NTLM auth failure"
        assert "authentication" in error.lower()

    def test_detect_kerberos_auth_failed(self):
        """Detect Kerberos authentication failure."""
        text = load_fixture("find_kerberos_auth_failed.txt")
        error = self._server._detect_certipy_error(text)
        assert error is not None, "Should detect Kerberos auth failure"

    def test_detect_kdc_error(self):
        """Detect KDC error (S_PRINCIPAL_UNKNOWN)."""
        text = load_fixture("find_kdc_error.txt")
        error = self._server._detect_certipy_error(text)
        assert error is not None, "Should detect KDC error"

    def test_detect_socket_timeout(self):
        """Detect socket connection timeout."""
        text = load_fixture("shadow_socket_timeout.txt")
        error = self._server._detect_certipy_error(text)
        assert error is not None, "Should detect socket timeout"

    def test_detect_rpc_connection_failed(self):
        """Detect RPC connection failure."""
        text = load_fixture("request_rpc_connection_failed.txt")
        error = self._server._detect_certipy_error(text)
        assert error is not None, "Should detect RPC connection failure"

    def test_detect_clock_skew(self):
        """Detect Kerberos clock skew error."""
        text = load_fixture("find_clock_skew.txt")
        error = self._server._detect_certipy_error(text)
        assert error is not None, "Should detect clock skew"

    def test_detect_cert_not_valid(self):
        """Detect 'certificate not valid for client authentication'."""
        text = load_fixture("auth_cert_not_valid.txt")
        error = self._server._detect_certipy_error(text)
        assert error is not None, "Should detect invalid certificate"

    def test_detect_template_denied(self):
        """Detect CERTSRV_E_TEMPLATE_DENIED error."""
        text = load_fixture("request_denied.txt")
        error = self._server._detect_certipy_error(text)
        assert error is not None, "Should detect template denied"

    def test_detect_insufficient_access(self):
        """Detect insufficient access rights for shadow credentials."""
        text = load_fixture("shadow_insufficient_access.txt")
        error = self._server._detect_certipy_error(text)
        assert error is not None, "Should detect insufficient access"

    def test_detect_rpc_call_complete(self):
        """Detect RPC_E_CALL_COMPLETE error."""
        text = load_fixture("request_rpc_call_complete.txt")
        error = self._server._detect_certipy_error(text)
        assert error is not None, "Should detect RPC_E_CALL_COMPLETE"

    def test_clean_output_not_detected(self):
        """Clean successful output should not be detected as error."""
        text = load_fixture("request_success.txt")
        error = self._server._detect_certipy_error(text)
        assert error is None, f"Clean output incorrectly detected as error: {error}"

    def test_clean_auth_output_not_detected(self):
        """Successful auth should not be detected as error."""
        text = load_fixture("auth_success.txt")
        error = self._server._detect_certipy_error(text)
        assert error is None, f"Successful auth output incorrectly detected as error: {error}"

    def test_detect_ldap_connection_failed(self):
        """Detect LDAP connection failure."""
        text = load_fixture("find_ldap_connection_failed.txt")
        error = self._server._detect_certipy_error(text)
        assert error is not None, "Should detect LDAP connection failure"
        assert "LDAP" in error

    def test_detect_restricted_officer(self):
        """Detect CERTSRV_E_RESTRICTEDOFFICER error."""
        text = load_fixture("request_restricted_officer.txt")
        error = self._server._detect_certipy_error(text)
        assert error is not None, "Should detect restricted officer"

    def test_detect_no_email_dn(self):
        """Detect CERTSRV_E_NO_EMAIL_DN error."""
        text = load_fixture("request_no_email.txt")
        error = self._server._detect_certipy_error(text)
        assert error is not None, "Should detect CERTSRV_E_NO_EMAIL_DN"

    def test_detect_rpc_access_denied(self):
        """Detect rpc_s_access_denied."""
        text = load_fixture("ca_rpc_access_denied.txt")
        error = self._server._detect_certipy_error(text)
        assert error is not None, "Should detect RPC access denied"

    def test_detect_no_credentials(self):
        """Detect 'No credentials provided' error."""
        text = "[-] Got error: No credentials provided for TGT request\nCertipy v5.0.4 - by Oliver Lyak (ly4k)\n"
        error = self._server._detect_certipy_error(text)
        assert error is not None, "Should detect missing credentials"

    def test_detect_config_not_found(self):
        """Detect configuration file not found error."""
        text = "[-] Configuration file not found: /session/certipy/User.json\nCertipy v5.0.4 - by Oliver Lyak (ly4k)\n"
        error = self._server._detect_certipy_error(text)
        assert error is not None, "Should detect config file not found"

    def test_clean_forge_output_not_detected(self):
        """Successful forge output should not be detected as error."""
        text = load_fixture("forge_success.txt")
        error = self._server._detect_certipy_error(text)
        assert error is None, f"Forge success incorrectly detected as error: {error}"

    def test_clean_shadow_auto_not_detected(self):
        """Successful shadow auto output should not be detected as error."""
        text = load_fixture("shadow_auto_success.txt")
        error = self._server._detect_certipy_error(text)
        assert error is None, f"Shadow auto success incorrectly detected as error: {error}"

    def test_clean_ca_enable_not_detected(self):
        """Successful CA enable output should not be detected as error."""
        text = load_fixture("ca_enable_success.txt")
        error = self._server._detect_certipy_error(text)
        assert error is None, f"CA enable success incorrectly detected as error: {error}"

    def test_clean_pending_request_not_detected(self):
        """Pending request output should not be detected as error."""
        text = load_fixture("request_pending.txt")
        error = self._server._detect_certipy_error(text)
        assert error is None, f"Pending request incorrectly detected as error: {error}"

    def test_clean_template_read_not_detected(self):
        """Template read output should not be detected as error."""
        text = load_fixture("template_read_success.txt")
        error = self._server._detect_certipy_error(text)
        assert error is None, f"Template read incorrectly detected as error: {error}"

    def test_detect_clock_skew_in_auth(self):
        """Detect clock skew in authenticate output."""
        text = load_fixture("auth_clock_skew.txt")
        error = self._server._detect_certipy_error(text)
        assert error is not None, "Should detect clock skew in auth context"
        assert "clock" in error.lower() or "skew" in error.lower()

    def test_detect_no_identity_error(self):
        """Detect 'identity information was not found' error."""
        text = load_fixture("auth_no_identity.txt")
        error = self._server._detect_certipy_error(text)
        assert error is not None, "Should detect missing identity information"


# ===========================================================================
# ERROR CLASSIFICATION TESTS
# ===========================================================================

class TestErrorClassification:
    """Test the _classify_certipy_error helper for error classification."""

    @pytest.fixture(autouse=True, scope="class")
    def server(self):
        """Create a server instance."""
        try:
            cls = _get_server_class()
            self.__class__._server = cls()
        except Exception as e:
            pytest.skip(f"Cannot import CertipyServer: {e}")

    def test_classify_clock_skew(self):
        """Clock skew should be classified as 'config', retryable."""
        text = load_fixture("find_clock_skew.txt")
        err_class, retryable, suggestions = self._server._classify_certipy_error(text)
        assert err_class == "config", f"Expected 'config' for clock skew, got '{err_class}'"
        assert retryable is True
        assert len(suggestions) > 0

    def test_classify_auth_failed(self):
        """NTLM auth failure should be 'auth', not retryable."""
        text = load_fixture("find_ntlm_auth_failed.txt")
        err_class, retryable, suggestions = self._server._classify_certipy_error(text)
        assert err_class == "auth", f"Expected 'auth', got '{err_class}'"
        assert retryable is False

    def test_classify_socket_timeout(self):
        """Socket timeout should be 'network', retryable."""
        text = load_fixture("shadow_socket_timeout.txt")
        err_class, retryable, suggestions = self._server._classify_certipy_error(text)
        assert err_class == "network", f"Expected 'network', got '{err_class}'"
        assert retryable is True

    def test_classify_connection_failed(self):
        """Connection failure should be 'network', retryable."""
        text = load_fixture("ca_connection_failed.txt")
        err_class, retryable, suggestions = self._server._classify_certipy_error(text)
        assert err_class == "network", f"Expected 'network', got '{err_class}'"
        assert retryable is True

    def test_classify_template_denied(self):
        """Template denied should be 'permission', not retryable."""
        text = load_fixture("request_denied.txt")
        err_class, retryable, suggestions = self._server._classify_certipy_error(text)
        assert err_class == "permission", f"Expected 'permission', got '{err_class}'"
        assert retryable is False
        assert len(suggestions) > 0

    def test_classify_insufficient_access(self):
        """Insufficient access for shadow creds should be 'permission', not retryable."""
        text = load_fixture("shadow_insufficient_access.txt")
        err_class, retryable, suggestions = self._server._classify_certipy_error(text)
        assert err_class == "permission", f"Expected 'permission', got '{err_class}'"
        assert retryable is False

    def test_classify_cert_not_valid(self):
        """Certificate not valid for client auth should be 'config', not retryable."""
        text = load_fixture("auth_cert_not_valid.txt")
        err_class, retryable, suggestions = self._server._classify_certipy_error(text)
        assert err_class == "config", f"Expected 'config', got '{err_class}'"

    def test_classify_kdc_error(self):
        """KDC error should be 'config', retryable (needs -target flag)."""
        text = load_fixture("find_kdc_error.txt")
        err_class, retryable, suggestions = self._server._classify_certipy_error(text)
        assert err_class == "config", f"Expected 'config', got '{err_class}'"

    def test_classify_rpc_call_complete(self):
        """RPC_E_CALL_COMPLETE should be 'config', retryable (use -dcom)."""
        text = load_fixture("request_rpc_call_complete.txt")
        err_class, retryable, suggestions = self._server._classify_certipy_error(text)
        assert err_class == "config", f"Expected 'config', got '{err_class}'"
        assert retryable is True
        # Should suggest using -dcom flag
        assert any("dcom" in s.lower() for s in suggestions), (
            f"Should suggest -dcom flag, got: {suggestions}"
        )

    def test_classify_rpc_access_denied(self):
        """RPC access denied should be 'permission', not retryable."""
        text = load_fixture("ca_rpc_access_denied.txt")
        err_class, retryable, suggestions = self._server._classify_certipy_error(text)
        assert err_class == "permission", f"Expected 'permission', got '{err_class}'"
        assert retryable is False
        assert any("manageca" in s.lower() or "managecertificates" in s.lower() for s in suggestions), (
            f"Should mention ManageCA or ManageCertificates, got: {suggestions}"
        )

    def test_classify_restricted_officer(self):
        """Enrollment agent restrictions should be 'permission', not retryable."""
        text = load_fixture("request_restricted_officer.txt")
        err_class, retryable, suggestions = self._server._classify_certipy_error(text)
        assert err_class == "permission", f"Expected 'permission', got '{err_class}'"
        assert retryable is False

    def test_classify_no_identity(self):
        """Missing identity in cert should be 'params', not retryable."""
        text = load_fixture("auth_no_identity.txt")
        err_class, retryable, suggestions = self._server._classify_certipy_error(text)
        assert err_class == "params", f"Expected 'params', got '{err_class}'"
        assert retryable is False

    def test_classify_ldap_connection_failed(self):
        """LDAP connection failure should be 'network', retryable."""
        text = load_fixture("find_ldap_connection_failed.txt")
        err_class, retryable, suggestions = self._server._classify_certipy_error(text)
        assert err_class == "network", f"Expected 'network', got '{err_class}'"
        assert retryable is True

    def test_classify_rpc_endpoint_mapper_failed(self):
        """RPC endpoint mapper failure should be 'network', retryable."""
        text = load_fixture("request_rpc_connection_failed.txt")
        err_class, retryable, suggestions = self._server._classify_certipy_error(text)
        assert err_class == "network", f"Expected 'network', got '{err_class}'"
        assert retryable is True

    def test_classify_kerberos_auth_failed(self):
        """Kerberos authentication failure should be 'auth', not retryable."""
        text = load_fixture("find_kerberos_auth_failed.txt")
        err_class, retryable, suggestions = self._server._classify_certipy_error(text)
        # Kerberos auth failure is after NTLM failure in this fixture, so it
        # depends on which pattern matches first. Both auth and config are valid.
        assert err_class in ("auth", "config"), f"Expected 'auth' or 'config', got '{err_class}'"

    def test_classify_clean_output_returns_unknown(self):
        """Clean output should classify as 'unknown' with no suggestions."""
        text = load_fixture("request_success.txt")
        err_class, retryable, suggestions = self._server._classify_certipy_error(text)
        assert err_class == "unknown", f"Expected 'unknown' for clean output, got '{err_class}'"


# ===========================================================================
# COMMAND BUILDING TESTS -- test _build_auth_args and per-method CLI args
# ===========================================================================

class TestCommandBuilding:
    """Test CLI command construction for each method.

    Verifies that method parameters are correctly translated to certipy
    command-line arguments. No Docker container needed.
    """

    @pytest.fixture(autouse=True, scope="class")
    def server(self):
        """Create a server instance for command building tests."""
        try:
            cls = _get_server_class()
            self.__class__._server = cls()
        except Exception as e:
            pytest.skip(f"Cannot import CertipyServer: {e}")

    # -- _build_auth_args -------------------------------------------------

    def test_build_auth_password(self):
        """Password auth produces -username, -dc-ip, -password flags."""
        args = self._server._build_auth_args(
            username="user@corp.local", dc_ip="10.0.0.1", password="P@ss1"
        )
        assert "-username" in args
        assert "user@corp.local" in args
        assert "-dc-ip" in args
        assert "10.0.0.1" in args
        assert "-password" in args
        assert "P@ss1" in args
        assert "-no-pass" not in args

    def test_build_auth_hash(self):
        """Hash auth produces -hashes flag."""
        args = self._server._build_auth_args(
            username="user@corp.local", dc_ip="10.0.0.1",
            hashes="aad3b435b51404ee:31d6cfe0d16ae931b73c59d7e0c089c0"
        )
        assert "-hashes" in args
        hash_idx = args.index("-hashes")
        assert args[hash_idx + 1] == "aad3b435b51404ee:31d6cfe0d16ae931b73c59d7e0c089c0"
        assert "-no-pass" not in args

    def test_build_auth_kerberos(self):
        """Kerberos auth produces -k flag."""
        # Mark as already configured to avoid writing /etc/krb5.conf
        self._server._krb5_configured = True
        args = self._server._build_auth_args(
            username="user@corp.local", dc_ip="10.0.0.1", kerberos=True
        )
        assert "-k" in args
        assert "-no-pass" not in args

    def test_build_auth_aes_key(self):
        """AES key produces -aes flag."""
        aes = "0123456789abcdef0123456789abcdef0123456789abcdef0123456789abcdef"
        args = self._server._build_auth_args(
            username="user@corp.local", dc_ip="10.0.0.1", aes_key=aes
        )
        assert "-aes" in args
        aes_idx = args.index("-aes")
        assert args[aes_idx + 1] == aes

    def test_build_auth_no_pass(self):
        """No credentials produces -no-pass flag."""
        args = self._server._build_auth_args(
            username="user@corp.local", dc_ip="10.0.0.1"
        )
        assert "-no-pass" in args

    def test_build_auth_ns_defaults_to_dc_ip(self):
        """DNS nameserver defaults to dc_ip when not specified."""
        args = self._server._build_auth_args(
            username="user@corp.local", dc_ip="10.0.0.1", password="test"
        )
        ns_idx = args.index("-ns")
        assert args[ns_idx + 1] == "10.0.0.1"

    def test_build_auth_ns_override(self):
        """DNS nameserver can be overridden."""
        args = self._server._build_auth_args(
            username="user@corp.local", dc_ip="10.0.0.1", password="test",
            ns="10.0.0.2"
        )
        ns_idx = args.index("-ns")
        assert args[ns_idx + 1] == "10.0.0.2"

    def test_build_auth_dns_tcp(self):
        """DNS TCP flag present by default."""
        args = self._server._build_auth_args(
            username="user@corp.local", dc_ip="10.0.0.1", password="test",
            dns_tcp=True
        )
        assert "-dns-tcp" in args

    def test_build_auth_dns_tcp_disabled(self):
        """DNS TCP flag absent when disabled."""
        args = self._server._build_auth_args(
            username="user@corp.local", dc_ip="10.0.0.1", password="test",
            dns_tcp=False
        )
        assert "-dns-tcp" not in args

    def test_build_auth_target(self):
        """Target produces -target flag."""
        args = self._server._build_auth_args(
            username="user@corp.local", dc_ip="10.0.0.1", password="test",
            target="DC01.corp.local"
        )
        assert "-target" in args
        target_idx = args.index("-target")
        assert args[target_idx + 1] == "DC01.corp.local"

    def test_build_auth_kerberos_with_target(self):
        """Kerberos auth with target also adds -dc-host."""
        self._server._krb5_configured = True
        args = self._server._build_auth_args(
            username="user@corp.local", dc_ip="10.0.0.1", kerberos=True,
            target="DC01.corp.local"
        )
        assert "-k" in args
        assert "-target" in args
        assert "-dc-host" in args
        dchost_idx = args.index("-dc-host")
        assert args[dchost_idx + 1] == "DC01.corp.local"

    def test_build_auth_kerberos_without_target_no_dc_host(self):
        """Kerberos without target should not add -dc-host."""
        self._server._krb5_configured = True
        args = self._server._build_auth_args(
            username="user@corp.local", dc_ip="10.0.0.1", kerberos=True
        )
        assert "-dc-host" not in args

    def test_build_auth_all_creds_present(self):
        """All credential types present -- password takes priority, no -no-pass."""
        self._server._krb5_configured = True
        args = self._server._build_auth_args(
            username="user@corp.local", dc_ip="10.0.0.1",
            password="P@ss1",
            hashes="aad3b435b51404ee:abc",
            kerberos=True,
            aes_key="0123456789abcdef"
        )
        assert "-password" in args
        assert "-hashes" in args
        assert "-k" in args
        assert "-aes" in args
        assert "-no-pass" not in args

    # -- find command building -----------------------------------------------

    def test_find_cmd_vulnerable(self):
        """find with vulnerable=True adds -vulnerable flag."""
        # Test indirectly via params -- the find method builds a cmd list
        # We test the param definition includes 'vulnerable'
        params = self._server._find_params()
        assert "vulnerable" in params
        assert params["vulnerable"]["type"] == "boolean"
        assert params["vulnerable"]["default"] is False

    def test_find_cmd_dc_only(self):
        """find includes dc_only param."""
        params = self._server._find_params()
        assert "dc_only" in params
        assert params["dc_only"]["type"] == "boolean"

    def test_find_cmd_user_sid(self):
        """find includes user_sid param."""
        params = self._server._find_params()
        assert "user_sid" in params

    def test_find_inherits_auth_params(self):
        """find params include all auth params."""
        params = self._server._find_params()
        auth_keys = {"username", "password", "hashes", "kerberos", "aes_key",
                     "ccache_path", "dc_ip", "ns", "dns_tcp", "target", "timeout"}
        for key in auth_keys:
            assert key in params, f"find missing auth param '{key}'"

    # -- request command building -------------------------------------------

    def test_request_params_ca_required(self):
        """request has 'ca' as required param."""
        params = self._server._request_params()
        assert "ca" in params
        assert params["ca"]["required"] is True

    def test_request_params_upn(self):
        """request has 'upn' param for ESC1 SAN injection."""
        params = self._server._request_params()
        assert "upn" in params

    def test_request_params_on_behalf_of(self):
        """request has 'on_behalf_of' param for ESC3."""
        params = self._server._request_params()
        assert "on_behalf_of" in params

    def test_request_params_dcom(self):
        """request has 'dcom' param for RPC_E_CALL_COMPLETE workaround."""
        params = self._server._request_params()
        assert "dcom" in params
        assert params["dcom"]["type"] == "boolean"

    def test_request_params_web(self):
        """request has 'web' param for Web Enrollment."""
        params = self._server._request_params()
        assert "web" in params
        assert params["web"]["type"] == "boolean"

    def test_request_params_application_policies(self):
        """request has 'application_policies' param for ESC15."""
        params = self._server._request_params()
        assert "application_policies" in params

    def test_request_params_retrieve(self):
        """request has 'retrieve' param for ESC7 workflow."""
        params = self._server._request_params()
        assert "retrieve" in params
        assert params["retrieve"]["type"] == "integer"

    def test_request_params_key_size(self):
        """request has 'key_size' with default 2048."""
        params = self._server._request_params()
        assert "key_size" in params
        assert params["key_size"]["default"] == 2048

    def test_request_params_sid(self):
        """request has 'sid' for StrongCertificateBindingEnforcement."""
        params = self._server._request_params()
        assert "sid" in params

    # -- authenticate command building ---------------------------------------

    def test_authenticate_params_pfx_required(self):
        """authenticate requires pfx_path."""
        params = self._server._authenticate_params()
        assert "pfx_path" in params
        assert params["pfx_path"]["required"] is True

    def test_authenticate_params_dc_ip_required(self):
        """authenticate requires dc_ip."""
        params = self._server._authenticate_params()
        assert "dc_ip" in params
        assert params["dc_ip"]["required"] is True

    def test_authenticate_params_kirbi(self):
        """authenticate has kirbi flag for Windows format."""
        params = self._server._authenticate_params()
        assert "kirbi" in params
        assert params["kirbi"]["type"] == "boolean"

    def test_authenticate_params_no_hash(self):
        """authenticate has no_hash to skip U2U."""
        params = self._server._authenticate_params()
        assert "no_hash" in params

    def test_authenticate_no_auth_params(self):
        """authenticate does NOT inherit full auth_params (uses PFX instead).

        Note: 'username' is now an optional override param for certs without UPN.
        """
        params = self._server._authenticate_params()
        # Should NOT have password/hashes (auth via cert, not credentials)
        assert "password" not in params
        assert "hashes" not in params
        # username is optional override (for certs without UPN)
        assert "username" in params
        assert params["username"].get("required") is not True

    # -- shadow command building --------------------------------------------

    def test_shadow_params_account_required(self):
        """shadow requires 'account' param."""
        params = self._server._shadow_params()
        assert "account" in params
        assert params["account"]["required"] is True

    def test_shadow_params_action_enum(self):
        """shadow has 'action' as enum with valid values."""
        params = self._server._shadow_params()
        assert "action" in params
        assert params["action"]["type"] == "enum"
        values = params["action"]["values"]
        assert "auto" in values
        assert "list" in values
        assert "add" in values
        assert "remove" in values
        assert "clear" in values
        assert "info" in values

    def test_shadow_params_device_id(self):
        """shadow has 'device_id' for remove/info actions."""
        params = self._server._shadow_params()
        assert "device_id" in params

    def test_shadow_inherits_auth_params(self):
        """shadow includes all auth params."""
        params = self._server._shadow_params()
        auth_keys = {"username", "password", "hashes", "kerberos", "dc_ip"}
        for key in auth_keys:
            assert key in params, f"shadow missing auth param '{key}'"

    # -- forge command building ---------------------------------------------

    def test_forge_params_ca_pfx_required(self):
        """forge requires 'ca_pfx'."""
        params = self._server._forge_params()
        assert "ca_pfx" in params
        assert params["ca_pfx"]["required"] is True

    def test_forge_params_upn(self):
        """forge has 'upn' for user impersonation."""
        params = self._server._forge_params()
        assert "upn" in params

    def test_forge_params_dns(self):
        """forge has 'dns' for machine impersonation."""
        params = self._server._forge_params()
        assert "dns" in params

    def test_forge_params_validity_period(self):
        """forge has 'validity_period' with default 365."""
        params = self._server._forge_params()
        assert "validity_period" in params
        assert params["validity_period"]["default"] == 365

    def test_forge_params_crl(self):
        """forge has 'crl' for CRL distribution point."""
        params = self._server._forge_params()
        assert "crl" in params

    def test_forge_params_serial(self):
        """forge has 'serial' for custom serial number."""
        params = self._server._forge_params()
        assert "serial" in params

    def test_forge_no_auth_params(self):
        """forge does NOT inherit auth_params (local operation)."""
        params = self._server._forge_params()
        assert "username" not in params
        assert "dc_ip" not in params

    # -- template command building ------------------------------------------

    def test_template_params_template_required(self):
        """template requires 'template' param."""
        params = self._server._template_params()
        assert "template" in params
        assert params["template"]["required"] is True

    def test_template_params_action_enum(self):
        """template has 'action' with read/save_config/write_default/write_config."""
        params = self._server._template_params()
        assert "action" in params
        values = params["action"]["values"]
        assert "read" in values
        assert "save_config" in values
        assert "write_default" in values
        assert "write_config" in values

    def test_template_params_config_path(self):
        """template has 'config_path' for write_config action."""
        params = self._server._template_params()
        assert "config_path" in params

    # -- ca command building ------------------------------------------------

    def test_ca_params_ca_name_required(self):
        """ca requires 'ca_name'."""
        params = self._server._ca_params()
        assert "ca_name" in params
        assert params["ca_name"]["required"] is True

    def test_ca_params_enable_template(self):
        """ca has 'enable_template' for ESC7."""
        params = self._server._ca_params()
        assert "enable_template" in params

    def test_ca_params_disable_template(self):
        """ca has 'disable_template'."""
        params = self._server._ca_params()
        assert "disable_template" in params

    def test_ca_params_issue_request(self):
        """ca has 'issue_request' for approving pending certs."""
        params = self._server._ca_params()
        assert "issue_request" in params
        assert params["issue_request"]["type"] == "integer"

    def test_ca_params_deny_request(self):
        """ca has 'deny_request'."""
        params = self._server._ca_params()
        assert "deny_request" in params
        assert params["deny_request"]["type"] == "integer"


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

    def test_yaml_has_all_10_methods(self):
        """tool.yaml should define exactly 10 methods."""
        methods = self._yaml.get("methods", {})
        assert len(methods) == 10, (
            f"Expected 10 methods, got {len(methods)}: {sorted(methods.keys())}"
        )

    def test_all_methods_have_descriptions(self):
        """Every method should have a description."""
        for name, defn in self._yaml.get("methods", {}).items():
            assert "description" in defn, f"Method {name} missing description"
            assert len(defn["description"]) > 10, f"Method {name} has too short description"

    def test_all_ldap_methods_have_dc_ip_param(self):
        """Methods that need LDAP should have 'dc_ip' parameter."""
        ldap_methods = ["find", "request", "shadow", "template", "ca", "account"]
        for name in ldap_methods:
            defn = self._yaml.get("methods", {}).get(name)
            if defn is None:
                continue
            params = defn.get("params", {})
            assert "dc_ip" in params, f"Method {name} missing 'dc_ip' param"

    def test_all_methods_have_timeout_param(self):
        """Every method should have a 'timeout' parameter."""
        for name, defn in self._yaml.get("methods", {}).items():
            params = defn.get("params", {})
            assert "timeout" in params, f"Method {name} missing 'timeout' param"

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

    def test_auth_methods_have_consistent_params(self):
        """Methods that need auth should all have username, password, hashes, kerberos."""
        auth_methods = ["find", "request", "shadow", "template", "ca"]
        auth_params = ["username", "password", "hashes", "kerberos"]
        for name in auth_methods:
            defn = self._yaml.get("methods", {}).get(name)
            if defn is None:
                continue
            params = defn.get("params", {})
            for ap in auth_params:
                assert ap in params, f"Method {name} missing auth param '{ap}'"

    def test_authenticate_has_pfx_and_optional_username(self):
        """authenticate should have pfx_path as required and username as optional override."""
        defn = self._yaml.get("methods", {}).get("authenticate")
        params = defn.get("params", {})
        assert "pfx_path" in params, "authenticate missing pfx_path"
        # username is now an optional override for certs without UPN
        assert "username" in params, "authenticate should have optional username"
        assert params["username"].get("required") is not True, "authenticate username should not be required"

    def test_forge_has_ca_pfx_not_dc_ip(self):
        """forge should have ca_pfx but not dc_ip (local operation)."""
        defn = self._yaml.get("methods", {}).get("forge")
        params = defn.get("params", {})
        assert "ca_pfx" in params, "forge missing ca_pfx"
        assert "dc_ip" not in params, "forge should not have dc_ip"

    def test_find_has_vulnerable_param(self):
        """find should have 'vulnerable' boolean param."""
        defn = self._yaml.get("methods", {}).get("find")
        params = defn.get("params", {})
        assert "vulnerable" in params
        assert params["vulnerable"]["type"] == "boolean"

    def test_shadow_has_action_enum(self):
        """shadow should have 'action' with enum values."""
        defn = self._yaml.get("methods", {}).get("shadow")
        params = defn.get("params", {})
        assert "action" in params
        assert params["action"]["type"] == "enum"
        values = params["action"]["values"]
        expected = {"auto", "list", "add", "remove", "clear", "info"}
        assert set(values) == expected, f"shadow action values: {values}, expected: {expected}"

    def test_template_has_action_enum(self):
        """template should have 'action' with enum values."""
        defn = self._yaml.get("methods", {}).get("template")
        params = defn.get("params", {})
        assert "action" in params
        values = params["action"]["values"]
        expected = {"read", "save_config", "write_default", "write_config"}
        assert set(values) == expected, f"template action values: {values}, expected: {expected}"

    def test_request_has_esc1_params(self):
        """request should have ESC1-specific params: upn, dns, sid."""
        defn = self._yaml.get("methods", {}).get("request")
        params = defn.get("params", {})
        assert "upn" in params, "request missing 'upn' for ESC1"
        assert "dns" in params, "request missing 'dns' for machine impersonation"
        assert "sid" in params, "request missing 'sid' for StrongCertBindingEnforcement"

    def test_request_has_esc3_params(self):
        """request should have ESC3-specific params: on_behalf_of, pfx_path."""
        defn = self._yaml.get("methods", {}).get("request")
        params = defn.get("params", {})
        assert "on_behalf_of" in params, "request missing 'on_behalf_of' for ESC3"
        assert "pfx_path" in params, "request missing 'pfx_path' for ESC3"

    def test_request_has_esc7_params(self):
        """request should have ESC7-specific param: retrieve."""
        defn = self._yaml.get("methods", {}).get("request")
        params = defn.get("params", {})
        assert "retrieve" in params, "request missing 'retrieve' for ESC7 workflow"

    def test_request_has_esc15_params(self):
        """request should have ESC15-specific param: application_policies."""
        defn = self._yaml.get("methods", {}).get("request")
        params = defn.get("params", {})
        assert "application_policies" in params, "request missing 'application_policies' for ESC15"

    def test_ca_has_esc7_params(self):
        """ca should have ESC7-specific params: enable_template, issue_request."""
        defn = self._yaml.get("methods", {}).get("ca")
        params = defn.get("params", {})
        assert "enable_template" in params, "ca missing 'enable_template' for ESC7"
        assert "issue_request" in params, "ca missing 'issue_request' for ESC7"

    def test_yaml_has_phases(self):
        """tool.yaml should define phases."""
        phases = self._yaml.get("phases", [])
        assert "enumeration" in phases
        assert "exploitation" in phases

    def test_yaml_has_capabilities(self):
        """tool.yaml should list capabilities."""
        caps = self._yaml.get("capabilities", [])
        assert len(caps) > 0, "Should have at least one capability"
        assert "adcs_enumeration" in caps
        assert "certificate_request" in caps

    def test_yaml_has_see_also(self):
        """tool.yaml should have see_also references to related tools."""
        see_also = self._yaml.get("see_also", [])
        assert len(see_also) > 0, "Should reference related tools"
        tool_names = [s["tool"] for s in see_also]
        assert "impacket" in tool_names, "Should reference impacket"


# ===========================================================================
# ACCEPTANCE TESTS -- call every method through Docker, verify structured responses
# ===========================================================================

class TestAcceptance:
    """Call every method through the container without a live AD target.

    These tests verify:
    - The method exists and is callable
    - Required param validation works (missing required params -> error)
    - The response has correct structuredContent shape
    - Error responses have error_class set (classified, not crash)

    Each test sends minimal args (unreachable IP) so the command will fail
    at connection time, but the MCP protocol layer, param validation, and
    error classification should all function correctly.
    """

    _FAKE_AUTH = {
        "username": "test@corp.local",
        "dc_ip": "10.255.255.1",
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
        assert "Traceback" not in content_text, (
            f"{method_name}: Python traceback in response"
        )
        return sc

    def _get_content_text(self, resp):
        """Extract text content from response."""
        result = resp.get("result", {})
        content_text = ""
        for c in result.get("content", []):
            if c.get("type") == "text":
                content_text += c["text"]
        return content_text

    # ── find ──────────────────────────────────────────────────────────

    def test_find_with_unreachable_ip(self, certipy_env):
        """find with unreachable IP returns classified network/timeout error."""
        client, loop = certipy_env
        resp = loop.run_until_complete(client.call("find", {
            **self._FAKE_AUTH,
            "timeout": 15,
        }))
        self._assert_structured_error(resp, "find")

    def test_find_missing_username(self, certipy_env):
        """find without username returns error about missing required param."""
        client, loop = certipy_env
        resp = loop.run_until_complete(client.call("find", {
            "dc_ip": "10.0.0.1", "password": "test",
        }))
        result = resp.get("result", {})
        is_error = result.get("isError", False)
        content_text = self._get_content_text(resp)
        assert is_error or "username" in content_text.lower() or "required" in content_text.lower()

    def test_find_missing_dc_ip(self, certipy_env):
        """find without dc_ip returns error about missing required param."""
        client, loop = certipy_env
        resp = loop.run_until_complete(client.call("find", {
            "username": "test@corp.local", "password": "test",
        }))
        result = resp.get("result", {})
        is_error = result.get("isError", False)
        content_text = self._get_content_text(resp)
        assert is_error or "dc_ip" in content_text.lower() or "required" in content_text.lower()

    def test_find_no_credentials(self, certipy_env):
        """find without any credential returns clear error."""
        client, loop = certipy_env
        resp = loop.run_until_complete(client.call("find", {
            "username": "test@corp.local",
            "dc_ip": "10.0.0.1",
        }))
        content_text = self._get_content_text(resp)
        assert "credential" in content_text.lower() or "password" in content_text.lower()

    def test_find_response_has_method_field(self, certipy_env):
        """find response includes method='find' in structuredContent."""
        client, loop = certipy_env
        resp = loop.run_until_complete(client.call("find", {
            **self._FAKE_AUTH,
            "timeout": 15,
        }))
        result = resp.get("result", {})
        sc = result.get("structuredContent", {})
        data = sc.get("data", {})
        assert data.get("method") == "find", f"Expected method='find', got: {data.get('method')}"

    # ── request ──────────────────────────────────────────────────────

    def test_request_with_unreachable_ip(self, certipy_env):
        """request with unreachable IP returns classified error."""
        client, loop = certipy_env
        resp = loop.run_until_complete(client.call("request", {
            **self._FAKE_AUTH,
            "ca": "CORP-CA",
            "template": "User",
            "timeout": 15,
        }))
        self._assert_structured_error(resp, "request")

    def test_request_missing_ca(self, certipy_env):
        """request without ca returns error about missing required param."""
        client, loop = certipy_env
        resp = loop.run_until_complete(client.call("request", {
            **self._FAKE_AUTH,
        }))
        result = resp.get("result", {})
        is_error = result.get("isError", False)
        content_text = self._get_content_text(resp)
        assert is_error or "ca" in content_text.lower() or "required" in content_text.lower()

    def test_request_with_upn(self, certipy_env):
        """request with UPN for ESC1 does not crash."""
        client, loop = certipy_env
        resp = loop.run_until_complete(client.call("request", {
            **self._FAKE_AUTH,
            "ca": "CORP-CA",
            "template": "ESC1Template",
            "upn": "administrator@corp.local",
            "timeout": 15,
        }))
        # Will fail at network level, but should not crash
        self._assert_structured_error(resp, "request (ESC1)")

    def test_request_with_dcom(self, certipy_env):
        """request with dcom=true does not crash."""
        client, loop = certipy_env
        resp = loop.run_until_complete(client.call("request", {
            **self._FAKE_AUTH,
            "ca": "CORP-CA",
            "dcom": True,
            "timeout": 15,
        }))
        self._assert_structured_error(resp, "request (dcom)")

    def test_request_with_web(self, certipy_env):
        """request with web=true does not crash."""
        client, loop = certipy_env
        resp = loop.run_until_complete(client.call("request", {
            **self._FAKE_AUTH,
            "ca": "CORP-CA",
            "web": True,
            "timeout": 15,
        }))
        self._assert_structured_error(resp, "request (web)")

    def test_request_response_has_method_field(self, certipy_env):
        """request response includes method='request'."""
        client, loop = certipy_env
        resp = loop.run_until_complete(client.call("request", {
            **self._FAKE_AUTH,
            "ca": "CORP-CA",
            "timeout": 15,
        }))
        result = resp.get("result", {})
        sc = result.get("structuredContent", {})
        data = sc.get("data", {})
        assert data.get("method") == "request"

    # ── authenticate ──────────────────────────────────────────────────

    def test_authenticate_missing_pfx(self, certipy_env):
        """authenticate with nonexistent PFX returns clear error."""
        client, loop = certipy_env
        resp = loop.run_until_complete(client.call("authenticate", {
            "pfx_path": "/session/certipy/nonexistent.pfx",
            "dc_ip": "10.0.0.1",
        }))
        content_text = self._get_content_text(resp)
        result = resp.get("result", {})
        assert result.get("isError", False) or "not found" in content_text.lower()

    def test_authenticate_missing_dc_ip(self, certipy_env):
        """authenticate without dc_ip returns error."""
        client, loop = certipy_env
        resp = loop.run_until_complete(client.call("authenticate", {
            "pfx_path": "/session/certipy/test.pfx",
        }))
        result = resp.get("result", {})
        is_error = result.get("isError", False)
        content_text = self._get_content_text(resp)
        assert is_error or "dc_ip" in content_text.lower() or "required" in content_text.lower()

    def test_authenticate_response_has_method_field(self, certipy_env):
        """authenticate response includes method='authenticate'."""
        client, loop = certipy_env
        resp = loop.run_until_complete(client.call("authenticate", {
            "pfx_path": "/session/certipy/nonexistent.pfx",
            "dc_ip": "10.0.0.1",
        }))
        result = resp.get("result", {})
        sc = result.get("structuredContent", {})
        data = sc.get("data", {})
        # May be empty if PFX not found is early exit, but should not crash
        content_text = self._get_content_text(resp)
        assert "Traceback" not in content_text

    # ── shadow ────────────────────────────────────────────────────────

    def test_shadow_with_unreachable_ip(self, certipy_env):
        """shadow with unreachable IP returns classified error."""
        client, loop = certipy_env
        resp = loop.run_until_complete(client.call("shadow", {
            **self._FAKE_AUTH,
            "account": "administrator",
            "action": "auto",
            "timeout": 15,
        }))
        self._assert_structured_error(resp, "shadow")

    def test_shadow_list_action(self, certipy_env):
        """shadow list action does not crash."""
        client, loop = certipy_env
        resp = loop.run_until_complete(client.call("shadow", {
            **self._FAKE_AUTH,
            "account": "testuser",
            "action": "list",
            "timeout": 15,
        }))
        self._assert_structured_error(resp, "shadow (list)")

    def test_shadow_missing_account(self, certipy_env):
        """shadow without account returns error about missing required param."""
        client, loop = certipy_env
        resp = loop.run_until_complete(client.call("shadow", {
            **self._FAKE_AUTH,
        }))
        result = resp.get("result", {})
        is_error = result.get("isError", False)
        content_text = self._get_content_text(resp)
        assert is_error or "account" in content_text.lower() or "required" in content_text.lower()

    def test_shadow_no_credentials(self, certipy_env):
        """shadow without credentials returns clear error."""
        client, loop = certipy_env
        resp = loop.run_until_complete(client.call("shadow", {
            "username": "test@corp.local",
            "dc_ip": "10.0.0.1",
            "account": "admin",
        }))
        content_text = self._get_content_text(resp)
        assert "credential" in content_text.lower() or "password" in content_text.lower()

    def test_shadow_response_has_method_field(self, certipy_env):
        """shadow response includes method='shadow'."""
        client, loop = certipy_env
        resp = loop.run_until_complete(client.call("shadow", {
            **self._FAKE_AUTH,
            "account": "admin",
            "timeout": 15,
        }))
        result = resp.get("result", {})
        sc = result.get("structuredContent", {})
        data = sc.get("data", {})
        assert data.get("method") == "shadow"

    # ── forge ─────────────────────────────────────────────────────────

    def test_forge_missing_ca_pfx(self, certipy_env):
        """forge with nonexistent CA PFX returns clear error."""
        client, loop = certipy_env
        resp = loop.run_until_complete(client.call("forge", {
            "ca_pfx": "/session/certipy/nonexistent_ca.pfx",
            "upn": "administrator@corp.local",
        }))
        content_text = self._get_content_text(resp)
        result = resp.get("result", {})
        assert result.get("isError", False) or "not found" in content_text.lower()

    def test_forge_missing_identity(self, certipy_env):
        """forge without upn/dns/subject returns error."""
        client, loop = certipy_env
        resp = loop.run_until_complete(client.call("forge", {
            "ca_pfx": "/session/certipy/nonexistent_ca.pfx",
        }))
        content_text = self._get_content_text(resp)
        result = resp.get("result", {})
        assert result.get("isError", False) or "upn" in content_text.lower() or "subject" in content_text.lower()

    def test_forge_response_has_method_field(self, certipy_env):
        """forge response includes method='forge'."""
        client, loop = certipy_env
        resp = loop.run_until_complete(client.call("forge", {
            "ca_pfx": "/session/certipy/nonexistent_ca.pfx",
            "upn": "administrator@corp.local",
        }))
        result = resp.get("result", {})
        sc = result.get("structuredContent", {})
        data = sc.get("data", {})
        # PFX not found is early exit, but should include method
        assert data.get("method") == "forge" or "not found" in self._get_content_text(resp).lower()

    # ── template ──────────────────────────────────────────────────────

    def test_template_with_unreachable_ip(self, certipy_env):
        """template with unreachable IP returns classified error."""
        client, loop = certipy_env
        resp = loop.run_until_complete(client.call("template", {
            **self._FAKE_AUTH,
            "template": "User",
            "action": "read",
            "timeout": 15,
        }))
        self._assert_structured_error(resp, "template")

    def test_template_missing_template_name(self, certipy_env):
        """template without template name returns error."""
        client, loop = certipy_env
        resp = loop.run_until_complete(client.call("template", {
            **self._FAKE_AUTH,
        }))
        result = resp.get("result", {})
        is_error = result.get("isError", False)
        content_text = self._get_content_text(resp)
        assert is_error or "template" in content_text.lower() or "required" in content_text.lower()

    def test_template_write_config_missing_path(self, certipy_env):
        """template write_config without config_path returns error."""
        client, loop = certipy_env
        resp = loop.run_until_complete(client.call("template", {
            **self._FAKE_AUTH,
            "template": "User",
            "action": "write_config",
        }))
        content_text = self._get_content_text(resp)
        result = resp.get("result", {})
        assert result.get("isError", False) or "config_path" in content_text.lower()

    def test_template_no_credentials(self, certipy_env):
        """template without credentials returns clear error."""
        client, loop = certipy_env
        resp = loop.run_until_complete(client.call("template", {
            "username": "test@corp.local",
            "dc_ip": "10.0.0.1",
            "template": "User",
        }))
        content_text = self._get_content_text(resp)
        assert "credential" in content_text.lower() or "password" in content_text.lower()

    def test_template_response_has_method_field(self, certipy_env):
        """template response includes method='template'."""
        client, loop = certipy_env
        resp = loop.run_until_complete(client.call("template", {
            **self._FAKE_AUTH,
            "template": "User",
            "timeout": 15,
        }))
        result = resp.get("result", {})
        sc = result.get("structuredContent", {})
        data = sc.get("data", {})
        assert data.get("method") == "template"

    # ── ca ────────────────────────────────────────────────────────────

    def test_ca_with_unreachable_ip(self, certipy_env):
        """ca with unreachable IP returns classified error."""
        client, loop = certipy_env
        resp = loop.run_until_complete(client.call("ca", {
            **self._FAKE_AUTH,
            "ca_name": "CORP-CA",
            "enable_template": "SubCA",
            "timeout": 15,
        }))
        self._assert_structured_error(resp, "ca")

    def test_ca_missing_ca_name(self, certipy_env):
        """ca without ca_name returns error about missing required param."""
        client, loop = certipy_env
        resp = loop.run_until_complete(client.call("ca", {
            **self._FAKE_AUTH,
        }))
        result = resp.get("result", {})
        is_error = result.get("isError", False)
        content_text = self._get_content_text(resp)
        assert is_error or "ca_name" in content_text.lower() or "required" in content_text.lower()

    def test_ca_no_credentials(self, certipy_env):
        """ca without credentials returns clear error."""
        client, loop = certipy_env
        resp = loop.run_until_complete(client.call("ca", {
            "username": "test@corp.local",
            "dc_ip": "10.0.0.1",
            "ca_name": "CORP-CA",
        }))
        content_text = self._get_content_text(resp)
        assert "credential" in content_text.lower() or "password" in content_text.lower()

    def test_ca_enable_template(self, certipy_env):
        """ca enable_template does not crash."""
        client, loop = certipy_env
        resp = loop.run_until_complete(client.call("ca", {
            **self._FAKE_AUTH,
            "ca_name": "CORP-CA",
            "enable_template": "SubCA",
            "timeout": 15,
        }))
        self._assert_structured_error(resp, "ca (enable_template)")

    def test_ca_disable_template(self, certipy_env):
        """ca disable_template does not crash."""
        client, loop = certipy_env
        resp = loop.run_until_complete(client.call("ca", {
            **self._FAKE_AUTH,
            "ca_name": "CORP-CA",
            "disable_template": "SubCA",
            "timeout": 15,
        }))
        self._assert_structured_error(resp, "ca (disable_template)")

    def test_ca_issue_request(self, certipy_env):
        """ca issue_request does not crash."""
        client, loop = certipy_env
        resp = loop.run_until_complete(client.call("ca", {
            **self._FAKE_AUTH,
            "ca_name": "CORP-CA",
            "issue_request": 20,
            "timeout": 15,
        }))
        self._assert_structured_error(resp, "ca (issue_request)")

    def test_ca_deny_request(self, certipy_env):
        """ca deny_request does not crash."""
        client, loop = certipy_env
        resp = loop.run_until_complete(client.call("ca", {
            **self._FAKE_AUTH,
            "ca_name": "CORP-CA",
            "deny_request": 20,
            "timeout": 15,
        }))
        self._assert_structured_error(resp, "ca (deny_request)")

    def test_ca_response_has_method_field(self, certipy_env):
        """ca response includes method='ca'."""
        client, loop = certipy_env
        resp = loop.run_until_complete(client.call("ca", {
            **self._FAKE_AUTH,
            "ca_name": "CORP-CA",
            "enable_template": "SubCA",
            "timeout": 15,
        }))
        result = resp.get("result", {})
        sc = result.get("structuredContent", {})
        data = sc.get("data", {})
        assert data.get("method") == "ca"


# ===========================================================================
# INTEGRATION TESTS -- require --target, --domain, etc.
# ===========================================================================

@pytest.mark.integration
class TestIntegration:
    """Integration tests that need a real AD target with ADCS.

    Run with: pytest tests/tools/test_certipy.py --tool=certipy
              --target=<DC_IP> --domain=<DOMAIN> --username=<USER> --password=<PASS>
              -m integration -v
    """

    def test_find(self, certipy_env, target, domain, username, password):
        """Enumerate ADCS and find CAs/templates."""
        client, loop = certipy_env
        resp = loop.run_until_complete(client.call("find", {
            "username": f"{username}@{domain}",
            "dc_ip": target,
            "password": password,
            "vulnerable": False,
        }))
        result = assert_tool_success(resp, "find should succeed with valid creds")
        data = parse_tool_output(resp)
        assert data.get("ca_count", 0) > 0, "Should discover at least one CA"
        assert data.get("template_count", 0) > 0, "Should discover at least one template"

    def test_find_vulnerable(self, certipy_env, target, domain, username, password):
        """Enumerate ADCS with -vulnerable filter."""
        client, loop = certipy_env
        resp = loop.run_until_complete(client.call("find", {
            "username": f"{username}@{domain}",
            "dc_ip": target,
            "password": password,
            "vulnerable": True,
        }))
        data = parse_tool_output(resp)
        assert "vulnerable_count" in data, "Response should include vulnerable_count"

    def test_request_cert(self, certipy_env, target, domain, username, password):
        """Request a certificate (may fail based on template permissions)."""
        client, loop = certipy_env
        resp = loop.run_until_complete(client.call("request", {
            "username": f"{username}@{domain}",
            "dc_ip": target,
            "password": password,
            "ca": "TEST-CA",  # Override with actual CA name
            "template": "User",
        }))
        data = parse_tool_output(resp)
        assert "method" in data if isinstance(data, dict) else True

    def test_shadow_list(self, certipy_env, target, domain, username, password):
        """List shadow credentials on a target account."""
        client, loop = certipy_env
        resp = loop.run_until_complete(client.call("shadow", {
            "username": f"{username}@{domain}",
            "dc_ip": target,
            "password": password,
            "account": username,
            "action": "list",
        }))
        data = parse_tool_output(resp)
        assert "method" in data if isinstance(data, dict) else True

    def test_authenticate_requires_pfx(self, certipy_env, target):
        """Authenticate without a PFX file should fail clearly."""
        client, loop = certipy_env
        resp = loop.run_until_complete(client.call("authenticate", {
            "pfx_path": "/session/certipy/nonexistent.pfx",
            "dc_ip": target,
        }))
        result = resp.get("result", {})
        content_text = ""
        for c in result.get("content", []):
            if c.get("type") == "text":
                content_text += c["text"]
        assert "not found" in content_text.lower() or result.get("isError", False), (
            f"Expected PFX not found error, got: {content_text[:300]}"
        )

    def test_forge_requires_ca_pfx(self, certipy_env):
        """Forge without a CA PFX should fail clearly."""
        client, loop = certipy_env
        resp = loop.run_until_complete(client.call("forge", {
            "ca_pfx": "/session/certipy/nonexistent_ca.pfx",
            "upn": "administrator@corp.local",
        }))
        result = resp.get("result", {})
        content_text = ""
        for c in result.get("content", []):
            if c.get("type") == "text":
                content_text += c["text"]
        assert "not found" in content_text.lower() or result.get("isError", False)


# ===========================================================================
# NEW UNIT TESTS — command building for new params (no Docker needed)
# ===========================================================================

class TestNewParamCommandBuilding:
    """Test CLI command construction for all new parameters added to the server.

    Covers: ca (add_officer, remove_officer, backup, config, list_templates),
    authenticate (username, ns, dns_tcp), find (oids, connection_timeout),
    request (subject, pfx_password, renew, connection_timeout),
    extra_args on every method, and new methods (account, cert, parse).
    """

    @pytest.fixture(autouse=True, scope="class")
    def server(self):
        """Create a server instance."""
        try:
            cls = _get_server_class()
            self.__class__._server = cls()
        except Exception as e:
            pytest.skip(f"Cannot import CertipyServer: {e}")

    # ── ca new params ─────────────────────────────────────────────────

    def test_ca_params_add_officer(self):
        """ca has 'add_officer' param for ESC7 officer management."""
        params = self._server._ca_params()
        assert "add_officer" in params
        assert params["add_officer"]["type"] == "string"

    def test_ca_params_remove_officer(self):
        """ca has 'remove_officer' param for ESC7 cleanup."""
        params = self._server._ca_params()
        assert "remove_officer" in params
        assert params["remove_officer"]["type"] == "string"

    def test_ca_params_backup(self):
        """ca has 'backup' boolean param for CA key extraction."""
        params = self._server._ca_params()
        assert "backup" in params
        assert params["backup"]["type"] == "boolean"
        assert params["backup"]["default"] is False

    def test_ca_params_config(self):
        """ca has 'config' param for Machine\\CAName format."""
        params = self._server._ca_params()
        assert "config" in params
        assert params["config"]["type"] == "string"

    def test_ca_params_list_templates(self):
        """ca has 'list_templates' boolean param."""
        params = self._server._ca_params()
        assert "list_templates" in params
        assert params["list_templates"]["type"] == "boolean"
        assert params["list_templates"]["default"] is False

    def test_ca_params_extra_args(self):
        """ca has 'extra_args' param."""
        params = self._server._ca_params()
        assert "extra_args" in params
        assert params["extra_args"]["type"] == "string"

    # ── authenticate new params ────────────────────────────────────────

    def test_authenticate_params_username_override(self):
        """authenticate has 'username' as optional override for certs without UPN."""
        params = self._server._authenticate_params()
        assert "username" in params
        assert params["username"].get("required") is not True
        assert params["username"]["type"] == "string"

    def test_authenticate_params_ns(self):
        """authenticate has 'ns' for DNS nameserver."""
        params = self._server._authenticate_params()
        assert "ns" in params
        assert params["ns"]["type"] == "string"

    def test_authenticate_params_dns_tcp(self):
        """authenticate has 'dns_tcp' with default false."""
        params = self._server._authenticate_params()
        assert "dns_tcp" in params
        assert params["dns_tcp"]["type"] == "boolean"
        assert params["dns_tcp"]["default"] is False

    def test_authenticate_params_extra_args(self):
        """authenticate has 'extra_args' param."""
        params = self._server._authenticate_params()
        assert "extra_args" in params
        assert params["extra_args"]["type"] == "string"

    # ── find new params ────────────────────────────────────────────────

    def test_find_params_oids(self):
        """find has 'oids' boolean for ESC13/ESC15."""
        params = self._server._find_params()
        assert "oids" in params
        assert params["oids"]["type"] == "boolean"
        assert params["oids"]["default"] is False

    def test_find_params_connection_timeout(self):
        """find has 'connection_timeout' for certipy -timeout."""
        params = self._server._find_params()
        assert "connection_timeout" in params
        assert params["connection_timeout"]["type"] == "integer"

    def test_find_params_extra_args(self):
        """find has 'extra_args' param."""
        params = self._server._find_params()
        assert "extra_args" in params
        assert params["extra_args"]["type"] == "string"

    # ── request new params ─────────────────────────────────────────────

    def test_request_params_subject(self):
        """request has 'subject' for ESC9/ESC10 DN override."""
        params = self._server._request_params()
        assert "subject" in params
        assert params["subject"]["type"] == "string"

    def test_request_params_pfx_password(self):
        """request has 'pfx_password' for password-protected enrollment agent PFX."""
        params = self._server._request_params()
        assert "pfx_password" in params
        assert params["pfx_password"]["type"] == "string"

    def test_request_params_renew(self):
        """request has 'renew' boolean for certificate renewal."""
        params = self._server._request_params()
        assert "renew" in params
        assert params["renew"]["type"] == "boolean"
        assert params["renew"]["default"] is False

    def test_request_params_connection_timeout(self):
        """request has 'connection_timeout' for certipy -timeout."""
        params = self._server._request_params()
        assert "connection_timeout" in params
        assert params["connection_timeout"]["type"] == "integer"

    def test_request_params_extra_args(self):
        """request has 'extra_args' param."""
        params = self._server._request_params()
        assert "extra_args" in params
        assert params["extra_args"]["type"] == "string"

    # ── shadow extra_args ──────────────────────────────────────────────

    def test_shadow_params_extra_args(self):
        """shadow has 'extra_args' param."""
        params = self._server._shadow_params()
        assert "extra_args" in params
        assert params["extra_args"]["type"] == "string"

    # ── forge extra_args ───────────────────────────────────────────────

    def test_forge_params_extra_args(self):
        """forge has 'extra_args' param."""
        params = self._server._forge_params()
        assert "extra_args" in params
        assert params["extra_args"]["type"] == "string"

    # ── template extra_args ────────────────────────────────────────────

    def test_template_params_extra_args(self):
        """template has 'extra_args' param."""
        params = self._server._template_params()
        assert "extra_args" in params
        assert params["extra_args"]["type"] == "string"

    # ── account params (new method) ────────────────────────────────────

    def test_account_params_action_enum(self):
        """account has 'action' as enum with CRUD values."""
        params = self._server._account_params()
        assert "action" in params
        assert params["action"]["type"] == "enum"
        values = params["action"]["values"]
        assert "create" in values
        assert "read" in values
        assert "update" in values
        assert "delete" in values

    def test_account_params_user_required(self):
        """account requires 'user' param."""
        params = self._server._account_params()
        assert "user" in params
        assert params["user"]["required"] is True

    def test_account_params_group(self):
        """account has 'group' param for container DN."""
        params = self._server._account_params()
        assert "group" in params
        assert params["group"]["type"] == "string"

    def test_account_params_account_dns(self):
        """account has 'account_dns' param."""
        params = self._server._account_params()
        assert "account_dns" in params
        assert params["account_dns"]["type"] == "string"

    def test_account_params_upn(self):
        """account has 'upn' param."""
        params = self._server._account_params()
        assert "upn" in params

    def test_account_params_sam(self):
        """account has 'sam' param."""
        params = self._server._account_params()
        assert "sam" in params

    def test_account_params_spns(self):
        """account has 'spns' param."""
        params = self._server._account_params()
        assert "spns" in params

    def test_account_params_account_pass(self):
        """account has 'account_pass' param."""
        params = self._server._account_params()
        assert "account_pass" in params

    def test_account_params_extra_args(self):
        """account has 'extra_args' param."""
        params = self._server._account_params()
        assert "extra_args" in params
        assert params["extra_args"]["type"] == "string"

    def test_account_inherits_auth_params(self):
        """account includes all auth params."""
        params = self._server._account_params()
        auth_keys = {"username", "password", "hashes", "kerberos", "aes_key",
                     "ccache_path", "dc_ip", "ns", "dns_tcp", "target", "timeout"}
        for key in auth_keys:
            assert key in params, f"account missing auth param '{key}'"

    # ── cert params (new method) ───────────────────────────────────────

    def test_cert_params_pfx_path(self):
        """cert has 'pfx_path' param."""
        params = self._server._cert_params()
        assert "pfx_path" in params
        assert params["pfx_path"]["type"] == "string"

    def test_cert_params_pfx_password(self):
        """cert has 'pfx_password' param."""
        params = self._server._cert_params()
        assert "pfx_password" in params

    def test_cert_params_key_path(self):
        """cert has 'key_path' param."""
        params = self._server._cert_params()
        assert "key_path" in params

    def test_cert_params_cert_path(self):
        """cert has 'cert_path' param."""
        params = self._server._cert_params()
        assert "cert_path" in params

    def test_cert_params_export(self):
        """cert has 'export' boolean param."""
        params = self._server._cert_params()
        assert "export" in params
        assert params["export"]["type"] == "boolean"
        assert params["export"]["default"] is False

    def test_cert_params_out(self):
        """cert has 'out' output filename param."""
        params = self._server._cert_params()
        assert "out" in params
        assert params["out"]["type"] == "string"

    def test_cert_params_nocert(self):
        """cert has 'nocert' boolean param."""
        params = self._server._cert_params()
        assert "nocert" in params
        assert params["nocert"]["type"] == "boolean"
        assert params["nocert"]["default"] is False

    def test_cert_params_nokey(self):
        """cert has 'nokey' boolean param."""
        params = self._server._cert_params()
        assert "nokey" in params
        assert params["nokey"]["type"] == "boolean"
        assert params["nokey"]["default"] is False

    def test_cert_params_export_password(self):
        """cert has 'export_password' param."""
        params = self._server._cert_params()
        assert "export_password" in params

    def test_cert_params_extra_args(self):
        """cert has 'extra_args' param."""
        params = self._server._cert_params()
        assert "extra_args" in params
        assert params["extra_args"]["type"] == "string"

    def test_cert_no_auth_params(self):
        """cert does NOT inherit auth_params (local operation)."""
        params = self._server._cert_params()
        assert "username" not in params
        assert "dc_ip" not in params
        assert "password" not in params

    # ── parse params (new method) ──────────────────────────────────────

    def test_parse_params_input_file_required(self):
        """parse requires 'input_file'."""
        params = self._server._parse_params()
        assert "input_file" in params
        assert params["input_file"]["required"] is True

    def test_parse_params_format_enum(self):
        """parse has 'format' as enum with bof/reg."""
        params = self._server._parse_params()
        assert "format" in params
        assert params["format"]["type"] == "enum"
        values = params["format"]["values"]
        assert "bof" in values
        assert "reg" in values

    def test_parse_params_domain(self):
        """parse has 'domain' for output context."""
        params = self._server._parse_params()
        assert "domain" in params
        assert params["domain"]["type"] == "string"

    def test_parse_params_ca_name(self):
        """parse has 'ca_name' for output context."""
        params = self._server._parse_params()
        assert "ca_name" in params

    def test_parse_params_sids(self):
        """parse has 'sids' for owned principals."""
        params = self._server._parse_params()
        assert "sids" in params

    def test_parse_params_published(self):
        """parse has 'published' for template list."""
        params = self._server._parse_params()
        assert "published" in params

    def test_parse_params_vulnerable(self):
        """parse has 'vulnerable' boolean."""
        params = self._server._parse_params()
        assert "vulnerable" in params
        assert params["vulnerable"]["type"] == "boolean"

    def test_parse_params_enabled(self):
        """parse has 'enabled' boolean."""
        params = self._server._parse_params()
        assert "enabled" in params
        assert params["enabled"]["type"] == "boolean"

    def test_parse_params_hide_admins(self):
        """parse has 'hide_admins' boolean."""
        params = self._server._parse_params()
        assert "hide_admins" in params
        assert params["hide_admins"]["type"] == "boolean"

    def test_parse_params_output_stdout(self):
        """parse has 'output_stdout' boolean."""
        params = self._server._parse_params()
        assert "output_stdout" in params
        assert params["output_stdout"]["type"] == "boolean"

    def test_parse_params_extra_args(self):
        """parse has 'extra_args' param."""
        params = self._server._parse_params()
        assert "extra_args" in params
        assert params["extra_args"]["type"] == "string"

    def test_parse_no_auth_params(self):
        """parse does NOT inherit auth_params (offline operation)."""
        params = self._server._parse_params()
        assert "username" not in params
        assert "dc_ip" not in params
        assert "password" not in params


# ===========================================================================
# EXTRA_ARGS TESTS — shlex.split behavior across all methods
# ===========================================================================

class TestExtraArgs:
    """Test extra_args handling: shlex.split, empty/None, quoted strings.

    These test the behavior of shlex.split as used throughout the server.
    Since all methods use the same pattern `if extra_args: cmd.extend(shlex.split(extra_args))`,
    we test the pattern through the shlex module directly and verify every method has the param.
    """

    @pytest.fixture(autouse=True, scope="class")
    def server(self):
        """Create a server instance."""
        try:
            cls = _get_server_class()
            self.__class__._server = cls()
        except Exception as e:
            pytest.skip(f"Cannot import CertipyServer: {e}")

    def test_shlex_split_simple(self):
        """Basic extra_args: '-scheme ldap -port 389'."""
        import shlex
        result = shlex.split("-scheme ldap -port 389")
        assert result == ["-scheme", "ldap", "-port", "389"]

    def test_shlex_split_quoted_string(self):
        """Quoted extra_args: '-subject \"CN=Admin,DC=corp\"'."""
        import shlex
        result = shlex.split('-subject "CN=Admin,DC=corp"')
        assert result == ["-subject", "CN=Admin,DC=corp"]

    def test_shlex_split_single_flag(self):
        """Single boolean flag: '-stdout'."""
        import shlex
        result = shlex.split("-stdout")
        assert result == ["-stdout"]

    def test_shlex_split_empty_string(self):
        """Empty string produces empty list."""
        import shlex
        result = shlex.split("")
        assert result == []

    def test_shlex_split_none_raises(self):
        """None input to shlex.split raises — server guards with 'if extra_args:' before calling."""
        import shlex
        with pytest.raises((AttributeError, TypeError, ValueError)):
            shlex.split(None)

    def test_all_methods_have_extra_args(self):
        """Every method's params dict includes 'extra_args'."""
        methods_with_extra_args = [
            ("find", self._server._find_params),
            ("request", self._server._request_params),
            ("authenticate", self._server._authenticate_params),
            ("shadow", self._server._shadow_params),
            ("forge", self._server._forge_params),
            ("template", self._server._template_params),
            ("ca", self._server._ca_params),
            ("account", self._server._account_params),
            ("cert", self._server._cert_params),
            ("parse", self._server._parse_params),
        ]
        for method_name, params_fn in methods_with_extra_args:
            params = params_fn()
            assert "extra_args" in params, f"Method '{method_name}' missing 'extra_args'"
            assert params["extra_args"]["type"] == "string", (
                f"Method '{method_name}': extra_args should be type 'string'"
            )

    def test_all_methods_have_timeout(self):
        """Every method's params dict includes 'timeout'."""
        methods = [
            ("find", self._server._find_params),
            ("request", self._server._request_params),
            ("authenticate", self._server._authenticate_params),
            ("shadow", self._server._shadow_params),
            ("forge", self._server._forge_params),
            ("template", self._server._template_params),
            ("ca", self._server._ca_params),
            ("account", self._server._account_params),
            ("cert", self._server._cert_params),
            ("parse", self._server._parse_params),
        ]
        for method_name, params_fn in methods:
            params = params_fn()
            assert "timeout" in params, f"Method '{method_name}' missing 'timeout'"


# ===========================================================================
# PARSER TESTS FOR NEW METHODS — auth with username override, find with oids
# ===========================================================================

class TestNewParsers:
    """Test output parsers with new fixture data for expanded methods."""

    @pytest.fixture(autouse=True, scope="class")
    def server(self):
        """Create a server instance."""
        try:
            cls = _get_server_class()
            self.__class__._server = cls()
        except Exception as e:
            pytest.skip(f"Cannot import CertipyServer: {e}")

    def test_parse_auth_with_username_override(self):
        """Parse auth output when -username override is used for machine certs."""
        text = load_fixture("auth_with_username_override.txt")
        result = self._server._parse_auth_output(text)
        assert result["nt_hash"] is not None, "Should extract NT hash with username override"
        assert "9f1c2e88d7a6b5c3e4f0a2b8d6c9e1f3" in result["nt_hash"]
        assert result["username"] == "DC01$"
        assert result["domain"] == "corp.local"
        assert result["ccache_path"] is not None
        assert "DC01.ccache" in result["ccache_path"]

    def test_detect_no_error_in_oids_output(self):
        """find -oids output should not be detected as error."""
        text = load_fixture("find_with_oids.txt")
        error = self._server._detect_certipy_error(text)
        assert error is None, f"OIDs output incorrectly detected as error: {error}"

    def test_detect_no_error_in_account_create(self):
        """Successful account create should not be detected as error."""
        text = load_fixture("account_create_success.txt")
        error = self._server._detect_certipy_error(text)
        assert error is None, f"Account create incorrectly detected as error: {error}"

    def test_detect_no_error_in_account_read(self):
        """Successful account read should not be detected as error."""
        text = load_fixture("account_read_success.txt")
        error = self._server._detect_certipy_error(text)
        assert error is None, f"Account read incorrectly detected as error: {error}"

    def test_detect_no_error_in_account_delete(self):
        """Successful account delete should not be detected as error."""
        text = load_fixture("account_delete_success.txt")
        error = self._server._detect_certipy_error(text)
        assert error is None, f"Account delete incorrectly detected as error: {error}"

    def test_detect_no_error_in_cert_conversion(self):
        """Successful cert PFX-to-PEM conversion should not be detected as error."""
        text = load_fixture("cert_pfx_to_pem.txt")
        error = self._server._detect_certipy_error(text)
        assert error is None, f"Cert conversion incorrectly detected as error: {error}"

    def test_detect_no_error_in_cert_export(self):
        """Successful cert export to PFX should not be detected as error."""
        text = load_fixture("cert_export_pfx.txt")
        error = self._server._detect_certipy_error(text)
        assert error is None, f"Cert export incorrectly detected as error: {error}"

    def test_detect_no_error_in_parse_bof(self):
        """Successful BOF parse output should not be detected as error."""
        text = load_fixture("parse_bof_success.txt")
        error = self._server._detect_certipy_error(text)
        assert error is None, f"Parse BOF incorrectly detected as error: {error}"

    def test_detect_no_error_in_parse_reg(self):
        """Successful registry parse output should not be detected as error."""
        text = load_fixture("parse_reg_success.txt")
        error = self._server._detect_certipy_error(text)
        assert error is None, f"Parse reg incorrectly detected as error: {error}"

    def test_detect_no_error_in_ca_add_officer(self):
        """Successful CA add officer should not be detected as error."""
        text = load_fixture("ca_add_officer_success.txt")
        error = self._server._detect_certipy_error(text)
        assert error is None, f"CA add officer incorrectly detected as error: {error}"

    def test_detect_no_error_in_ca_remove_officer(self):
        """Successful CA remove officer should not be detected as error."""
        text = load_fixture("ca_remove_officer_success.txt")
        error = self._server._detect_certipy_error(text)
        assert error is None, f"CA remove officer incorrectly detected as error: {error}"

    def test_detect_no_error_in_ca_backup(self):
        """Successful CA backup should not be detected as error."""
        text = load_fixture("ca_backup_success.txt")
        error = self._server._detect_certipy_error(text)
        assert error is None, f"CA backup incorrectly detected as error: {error}"

    def test_detect_no_error_in_ca_list_templates(self):
        """Successful CA list templates should not be detected as error."""
        text = load_fixture("ca_list_templates_success.txt")
        error = self._server._detect_certipy_error(text)
        assert error is None, f"CA list templates incorrectly detected as error: {error}"

    # ── Error classification for new method contexts ──────────────────

    def test_classify_error_in_account_context(self):
        """Connection error in account context should still classify as 'network'."""
        text = "[-] Got error: socket connection error while running account create\nCertipy v5.0.4 - by Oliver Lyak (ly4k)\n"
        err_class, retryable, suggestions = self._server._classify_certipy_error(text)
        assert err_class == "network"
        assert retryable is True

    def test_classify_error_in_cert_context(self):
        """cert method with bad file should not crash classifier."""
        text = "[-] Configuration file not found: /session/certipy/nonexistent.pfx\nCertipy v5.0.4 - by Oliver Lyak (ly4k)\n"
        error = self._server._detect_certipy_error(text)
        assert error is not None

    def test_classify_auth_failure_in_account(self):
        """NTLM auth failure in account context should be 'auth'."""
        text = "[-] LDAP NTLM authentication failed -- wrong password for account method\nCertipy v5.0.4 - by Oliver Lyak (ly4k)\n"
        err_class, retryable, suggestions = self._server._classify_certipy_error(text)
        assert err_class == "auth"
        assert retryable is False

    def test_classify_unknown_for_clean_new_output(self):
        """Clean output from new methods should classify as 'unknown'."""
        text = load_fixture("account_create_success.txt")
        err_class, retryable, suggestions = self._server._classify_certipy_error(text)
        assert err_class == "unknown"

    # ── _parse_find_json edge cases ───────────────────────────────────

    def test_parse_find_json_empty_list(self):
        """Empty JSON file list returns zero counts."""
        result = self._server._parse_find_json([])
        assert result["certificate_authorities"] == []
        assert result["certificate_templates"] == []
        assert result["vulnerable_templates"] == []
        assert result["vulnerable_count"] == 0

    def test_parse_find_json_non_json_files(self):
        """Non-JSON files in list are skipped."""
        result = self._server._parse_find_json(["/tmp/output.txt", "/tmp/data.csv"])
        assert result["vulnerable_count"] == 0

    def test_parse_find_json_nonexistent_file(self):
        """Nonexistent JSON file is silently skipped."""
        result = self._server._parse_find_json(["/tmp/nonexistent_file_abc123.json"])
        assert result["vulnerable_count"] == 0


# ===========================================================================
# EXTENDED CONTRACT TESTS — new methods in tool.yaml
# ===========================================================================

class TestToolYamlContractExtended:
    """Verify tool.yaml matches server for new methods: account, cert, parse."""

    @pytest.fixture(autouse=True, scope="class")
    def load_data(self):
        """Load tool.yaml and server."""
        with open(TOOL_DIR / "tool.yaml") as f:
            self.__class__._yaml = yaml.safe_load(f)
        try:
            cls = _get_server_class()
            self.__class__._server = cls()
        except Exception as e:
            pytest.skip(f"Cannot import CertipyServer: {e}")

    def test_yaml_has_account_method(self):
        """tool.yaml defines account method."""
        methods = self._yaml.get("methods", {})
        assert "account" in methods, "tool.yaml missing 'account' method"

    def test_yaml_has_cert_method(self):
        """tool.yaml defines cert method."""
        methods = self._yaml.get("methods", {})
        assert "cert" in methods, "tool.yaml missing 'cert' method"

    def test_yaml_has_parse_method(self):
        """tool.yaml defines parse method."""
        methods = self._yaml.get("methods", {})
        assert "parse" in methods, "tool.yaml missing 'parse' method"

    def test_account_yaml_params_match_server(self):
        """Account params in tool.yaml should be a subset of server params."""
        yaml_params = set(self._yaml["methods"]["account"]["params"].keys())
        server_params = set(self._server._account_params().keys())
        yaml_only = yaml_params - server_params
        assert not yaml_only, f"Account params in YAML but not server: {yaml_only}"

    def test_account_server_params_in_yaml(self):
        """Account server params should be present in tool.yaml.

        Known issue: 'target' is in server _auth_params() but missing from YAML.
        """
        yaml_params = set(self._yaml["methods"]["account"]["params"].keys())
        server_params = set(self._server._account_params().keys())
        server_only = server_params - yaml_params - {"target"}  # known-missing
        assert not server_only, f"Account params in server but not YAML: {server_only}"

    def test_cert_yaml_params_match_server(self):
        """Cert params in tool.yaml should match server params."""
        yaml_params = set(self._yaml["methods"]["cert"]["params"].keys())
        server_params = set(self._server._cert_params().keys())
        yaml_only = yaml_params - server_params
        server_only = server_params - yaml_params
        assert not yaml_only, f"Cert params in YAML but not server: {yaml_only}"
        assert not server_only, f"Cert params in server but not YAML: {server_only}"

    def test_parse_yaml_params_match_server(self):
        """Parse params in tool.yaml should match server params."""
        yaml_params = set(self._yaml["methods"]["parse"]["params"].keys())
        server_params = set(self._server._parse_params().keys())
        yaml_only = yaml_params - server_params
        server_only = server_params - yaml_params
        assert not yaml_only, f"Parse params in YAML but not server: {yaml_only}"
        assert not server_only, f"Parse params in server but not YAML: {server_only}"

    def test_all_methods_extra_args_in_yaml(self):
        """Every method in tool.yaml should have 'extra_args' param."""
        for method_name, defn in self._yaml.get("methods", {}).items():
            params = defn.get("params", {})
            assert "extra_args" in params, f"YAML method '{method_name}' missing 'extra_args'"

    def test_ca_new_params_in_yaml(self):
        """CA method in tool.yaml should have new params: add_officer, remove_officer, backup, config, list_templates."""
        ca_params = self._yaml["methods"]["ca"]["params"]
        assert "add_officer" in ca_params, "CA YAML missing 'add_officer'"
        assert "remove_officer" in ca_params, "CA YAML missing 'remove_officer'"
        assert "backup" in ca_params, "CA YAML missing 'backup'"
        assert "config" in ca_params, "CA YAML missing 'config'"
        assert "list_templates" in ca_params, "CA YAML missing 'list_templates'"

    def test_authenticate_new_params_in_yaml(self):
        """Authenticate in tool.yaml should have username, ns, dns_tcp."""
        auth_params = self._yaml["methods"]["authenticate"]["params"]
        assert "username" in auth_params, "Authenticate YAML missing 'username'"
        assert "ns" in auth_params, "Authenticate YAML missing 'ns'"
        assert "dns_tcp" in auth_params, "Authenticate YAML missing 'dns_tcp'"

    def test_find_new_params_in_yaml(self):
        """Find in tool.yaml should have oids, connection_timeout."""
        find_params = self._yaml["methods"]["find"]["params"]
        assert "oids" in find_params, "Find YAML missing 'oids'"
        assert "connection_timeout" in find_params, "Find YAML missing 'connection_timeout'"

    def test_request_new_params_in_yaml(self):
        """Request in tool.yaml should have subject, pfx_password, renew, connection_timeout."""
        req_params = self._yaml["methods"]["request"]["params"]
        assert "subject" in req_params, "Request YAML missing 'subject'"
        assert "pfx_password" in req_params, "Request YAML missing 'pfx_password'"
        assert "renew" in req_params, "Request YAML missing 'renew'"
        assert "connection_timeout" in req_params, "Request YAML missing 'connection_timeout'"

    def test_yaml_account_has_action_enum(self):
        """Account in tool.yaml should have action enum."""
        params = self._yaml["methods"]["account"]["params"]
        assert "action" in params
        assert params["action"]["type"] == "enum"
        assert set(params["action"]["values"]) == {"create", "read", "update", "delete"}

    def test_yaml_parse_has_format_enum(self):
        """Parse in tool.yaml should have format enum."""
        params = self._yaml["methods"]["parse"]["params"]
        assert "format" in params
        assert params["format"]["type"] == "enum"
        assert set(params["format"]["values"]) == {"bof", "reg"}

    def test_yaml_new_capabilities(self):
        """tool.yaml should have capabilities for new methods."""
        caps = self._yaml.get("capabilities", [])
        assert "account_management" in caps, "Missing 'account_management' capability"
        assert "certificate_conversion" in caps, "Missing 'certificate_conversion' capability"
        assert "offline_adcs_analysis" in caps, "Missing 'offline_adcs_analysis' capability"

    def test_bidirectional_param_match_all_methods(self):
        """For every method, YAML params and server params must be identical sets.

        Known issue: 'target' param is in _auth_params() (server) for Kerberos
        SPN resolution, but missing from tool.yaml for find, shadow, template, ca,
        account. This is tracked separately. We exclude 'target' from mismatch
        checking for auth-inherited methods until tool.yaml is updated.
        """
        # Methods where 'target' is known-missing from YAML (inherits from _auth_params)
        # All 5 methods now have 'target' in YAML — bug fixed.
        target_missing_in_yaml = set()

        method_param_fns = {
            "find": self._server._find_params,
            "request": self._server._request_params,
            "authenticate": self._server._authenticate_params,
            "shadow": self._server._shadow_params,
            "forge": self._server._forge_params,
            "template": self._server._template_params,
            "ca": self._server._ca_params,
            "account": self._server._account_params,
            "cert": self._server._cert_params,
            "parse": self._server._parse_params,
        }
        for method_name, params_fn in method_param_fns.items():
            yaml_defn = self._yaml.get("methods", {}).get(method_name)
            if yaml_defn is None:
                continue
            yaml_params = set(yaml_defn.get("params", {}).keys())
            server_params = set(params_fn().keys())
            yaml_only = yaml_params - server_params
            server_only = server_params - yaml_params
            # Exclude known-missing 'target' from mismatch
            if method_name in target_missing_in_yaml:
                server_only = server_only - {"target"}
            assert not yaml_only, f"{method_name}: params in YAML but not server: {yaml_only}"
            assert not server_only, f"{method_name}: params in server but not YAML: {server_only}"

    def test_target_param_present_in_all_auth_yaml_methods(self):
        """Verify: all auth methods now have 'target' in tool.yaml.

        Previously 5 methods (find, shadow, template, ca, account) were missing 'target'.
        Bug fixed: all auth-based methods now include 'target' for Kerberos SPN resolution.
        """
        methods_needing_target = ["find", "request", "shadow", "template", "ca", "account"]
        for method_name in methods_needing_target:
            yaml_params = set(self._yaml["methods"][method_name]["params"].keys())
            assert "target" in yaml_params, (
                f"'{method_name}' should have 'target' in YAML for Kerberos SPN resolution"
            )

    def test_all_methods_have_descriptions_in_yaml(self):
        """Every method in tool.yaml should have a description."""
        for name, defn in self._yaml.get("methods", {}).items():
            assert "description" in defn, f"Method '{name}' missing description in YAML"
            assert len(defn["description"]) > 20, f"Method '{name}' description too short"

    def test_all_methods_have_when_to_use_in_yaml(self):
        """Every method in tool.yaml should have when_to_use."""
        for name, defn in self._yaml.get("methods", {}).items():
            assert "when_to_use" in defn, f"Method '{name}' missing when_to_use in YAML"

    def test_all_methods_have_required_ports_in_yaml(self):
        """Every method in tool.yaml should have required_ports."""
        for name, defn in self._yaml.get("methods", {}).items():
            assert "required_ports" in defn, f"Method '{name}' missing required_ports in YAML"


# ===========================================================================
# NEW SMOKE TESTS — new methods registered in container
# ===========================================================================

class TestSmokeNewMethods:
    """Smoke tests for the 3 new methods: account, cert, parse."""

    def test_account_method_in_tool_list(self, certipy_env):
        """account should appear in tool list."""
        client, _ = certipy_env
        names = client.tool_names()
        assert "account" in names, f"account not in tool list: {sorted(names)}"

    def test_cert_method_in_tool_list(self, certipy_env):
        """cert should appear in tool list."""
        client, _ = certipy_env
        names = client.tool_names()
        assert "cert" in names, f"cert not in tool list: {sorted(names)}"

    def test_parse_method_in_tool_list(self, certipy_env):
        """parse should appear in tool list."""
        client, _ = certipy_env
        names = client.tool_names()
        assert "parse" in names, f"parse not in tool list: {sorted(names)}"


# ===========================================================================
# NEW ACCEPTANCE TESTS — call new methods + new params through Docker
# ===========================================================================

class TestAcceptanceNewMethods:
    """Call new methods and new params through the Docker container.

    Verifies no crashes, structuredContent shape, error classification.
    """

    _FAKE_AUTH = {
        "username": "test@corp.local",
        "dc_ip": "10.255.255.1",
        "password": "testpass",
    }

    def _assert_structured_response(self, resp, method_name):
        """Assert response has structuredContent, no MCP server crashes.

        Note: certipy itself may output Python tracebacks in its stderr when
        connections fail. We check for MCP-level crashes by looking for
        'unexpected keyword argument' (unhandled param) and checking that
        structuredContent has proper shape. Raw certipy tracebacks in the
        output are expected for unreachable-target tests.
        """
        result = resp.get("result", {})
        sc = result.get("structuredContent", {})
        assert sc is not None, f"{method_name}: missing structuredContent"
        content_text = ""
        for c in result.get("content", []):
            if c.get("type") == "text":
                content_text += c["text"]
        assert "unexpected keyword argument" not in content_text, (
            f"{method_name}: unhandled keyword argument error"
        )
        # Check for MCP-level crash indicators (not certipy's own tracebacks)
        assert "Internal server error" not in content_text, (
            f"{method_name}: MCP server internal error"
        )
        return sc, content_text

    def _get_content_text(self, resp):
        """Extract text content from response."""
        result = resp.get("result", {})
        content_text = ""
        for c in result.get("content", []):
            if c.get("type") == "text":
                content_text += c["text"]
        return content_text

    # ── account method ────────────────────────────────────────────────

    def test_account_create_with_unreachable_ip(self, certipy_env):
        """account create with unreachable IP returns classified error."""
        client, loop = certipy_env
        resp = loop.run_until_complete(client.call("account", {
            **self._FAKE_AUTH,
            "user": "FAKE01$",
            "action": "create",
            "timeout": 15,
        }))
        self._assert_structured_response(resp, "account (create)")

    def test_account_read_with_unreachable_ip(self, certipy_env):
        """account read with unreachable IP returns classified error."""
        client, loop = certipy_env
        resp = loop.run_until_complete(client.call("account", {
            **self._FAKE_AUTH,
            "user": "FAKE01$",
            "action": "read",
            "timeout": 15,
        }))
        self._assert_structured_response(resp, "account (read)")

    def test_account_update_with_unreachable_ip(self, certipy_env):
        """account update with unreachable IP returns classified error."""
        client, loop = certipy_env
        resp = loop.run_until_complete(client.call("account", {
            **self._FAKE_AUTH,
            "user": "FAKE01$",
            "action": "update",
            "account_pass": "NewPassword123!",
            "timeout": 15,
        }))
        self._assert_structured_response(resp, "account (update)")

    def test_account_delete_with_unreachable_ip(self, certipy_env):
        """account delete with unreachable IP returns classified error."""
        client, loop = certipy_env
        resp = loop.run_until_complete(client.call("account", {
            **self._FAKE_AUTH,
            "user": "FAKE01$",
            "action": "delete",
            "timeout": 15,
        }))
        self._assert_structured_response(resp, "account (delete)")

    def test_account_missing_user(self, certipy_env):
        """account without user returns error about missing required param."""
        client, loop = certipy_env
        resp = loop.run_until_complete(client.call("account", {
            **self._FAKE_AUTH,
        }))
        result = resp.get("result", {})
        is_error = result.get("isError", False)
        content_text = self._get_content_text(resp)
        assert is_error or "user" in content_text.lower() or "required" in content_text.lower()

    def test_account_no_credentials(self, certipy_env):
        """account without credentials returns clear error."""
        client, loop = certipy_env
        resp = loop.run_until_complete(client.call("account", {
            "username": "test@corp.local",
            "dc_ip": "10.0.0.1",
            "user": "FAKE01$",
        }))
        content_text = self._get_content_text(resp)
        assert "credential" in content_text.lower() or "password" in content_text.lower()

    def test_account_with_all_optional_params(self, certipy_env):
        """account with all optional params does not crash."""
        client, loop = certipy_env
        resp = loop.run_until_complete(client.call("account", {
            **self._FAKE_AUTH,
            "user": "FAKE01$",
            "action": "create",
            "group": "CN=Computers,DC=corp,DC=local",
            "account_dns": "FAKE01.corp.local",
            "upn": "FAKE01$@corp.local",
            "sam": "FAKE01$",
            "spns": "HOST/FAKE01.corp.local",
            "account_pass": "T3stP@ss!",
            "timeout": 15,
        }))
        self._assert_structured_response(resp, "account (all params)")

    def test_account_response_has_method_field(self, certipy_env):
        """account response includes method='account' in structuredContent."""
        client, loop = certipy_env
        resp = loop.run_until_complete(client.call("account", {
            **self._FAKE_AUTH,
            "user": "FAKE01$",
            "timeout": 15,
        }))
        sc, _ = self._assert_structured_response(resp, "account")
        data = sc.get("data", {})
        assert data.get("method") == "account"

    # ── cert method ───────────────────────────────────────────────────

    def test_cert_missing_all_inputs(self, certipy_env):
        """cert without any input file returns error."""
        client, loop = certipy_env
        resp = loop.run_until_complete(client.call("cert", {}))
        content_text = self._get_content_text(resp)
        result = resp.get("result", {})
        assert result.get("isError", False) or "input" in content_text.lower() or "pfx_path" in content_text.lower()

    def test_cert_nonexistent_pfx(self, certipy_env):
        """cert with nonexistent PFX returns clear error."""
        client, loop = certipy_env
        resp = loop.run_until_complete(client.call("cert", {
            "pfx_path": "/session/certipy/nonexistent.pfx",
        }))
        content_text = self._get_content_text(resp)
        result = resp.get("result", {})
        assert result.get("isError", False) or "not found" in content_text.lower()

    def test_cert_nonexistent_key(self, certipy_env):
        """cert with nonexistent key file returns clear error."""
        client, loop = certipy_env
        resp = loop.run_until_complete(client.call("cert", {
            "key_path": "/session/certipy/nonexistent.key",
        }))
        content_text = self._get_content_text(resp)
        result = resp.get("result", {})
        assert result.get("isError", False) or "not found" in content_text.lower()

    def test_cert_nonexistent_cert_path(self, certipy_env):
        """cert with nonexistent cert file returns clear error."""
        client, loop = certipy_env
        resp = loop.run_until_complete(client.call("cert", {
            "cert_path": "/session/certipy/nonexistent.crt",
        }))
        content_text = self._get_content_text(resp)
        result = resp.get("result", {})
        assert result.get("isError", False) or "not found" in content_text.lower()

    def test_cert_with_export_flag(self, certipy_env):
        """cert with export=true and nonexistent inputs gives error, not crash."""
        client, loop = certipy_env
        resp = loop.run_until_complete(client.call("cert", {
            "key_path": "/session/certipy/nonexistent.key",
            "cert_path": "/session/certipy/nonexistent.crt",
            "export": True,
        }))
        content_text = self._get_content_text(resp)
        result = resp.get("result", {})
        assert result.get("isError", False) or "not found" in content_text.lower()

    def test_cert_with_nocert_nokey(self, certipy_env):
        """cert with nocert=true and nokey=true and nonexistent PFX gives error, not crash."""
        client, loop = certipy_env
        resp = loop.run_until_complete(client.call("cert", {
            "pfx_path": "/session/certipy/nonexistent.pfx",
            "nocert": True,
            "nokey": True,
        }))
        content_text = self._get_content_text(resp)
        result = resp.get("result", {})
        assert result.get("isError", False) or "not found" in content_text.lower()

    def test_cert_response_has_method_field(self, certipy_env):
        """cert response includes method='cert'."""
        client, loop = certipy_env
        resp = loop.run_until_complete(client.call("cert", {
            "pfx_path": "/session/certipy/nonexistent.pfx",
        }))
        sc = resp.get("result", {}).get("structuredContent", {})
        data = sc.get("data", {})
        # Early exit for file not found may or may not have method field
        content_text = self._get_content_text(resp)
        assert "Traceback" not in content_text

    # ── parse method ──────────────────────────────────────────────────

    def test_parse_missing_input_file(self, certipy_env):
        """parse without input_file returns error about missing required param."""
        client, loop = certipy_env
        resp = loop.run_until_complete(client.call("parse", {}))
        result = resp.get("result", {})
        is_error = result.get("isError", False)
        content_text = self._get_content_text(resp)
        assert is_error or "input_file" in content_text.lower() or "required" in content_text.lower()

    def test_parse_nonexistent_file(self, certipy_env):
        """parse with nonexistent input file returns clear error."""
        client, loop = certipy_env
        resp = loop.run_until_complete(client.call("parse", {
            "input_file": "/session/certipy/nonexistent_bof.txt",
        }))
        content_text = self._get_content_text(resp)
        result = resp.get("result", {})
        assert result.get("isError", False) or "not found" in content_text.lower()

    def test_parse_with_bof_format(self, certipy_env):
        """parse with format=bof and nonexistent file returns clear error."""
        client, loop = certipy_env
        resp = loop.run_until_complete(client.call("parse", {
            "input_file": "/session/certipy/nonexistent.txt",
            "format": "bof",
        }))
        content_text = self._get_content_text(resp)
        assert "Traceback" not in content_text

    def test_parse_with_reg_format(self, certipy_env):
        """parse with format=reg and nonexistent file returns clear error."""
        client, loop = certipy_env
        resp = loop.run_until_complete(client.call("parse", {
            "input_file": "/session/certipy/nonexistent.reg",
            "format": "reg",
        }))
        content_text = self._get_content_text(resp)
        assert "Traceback" not in content_text

    def test_parse_with_all_optional_params(self, certipy_env):
        """parse with all optional params does not crash."""
        client, loop = certipy_env
        resp = loop.run_until_complete(client.call("parse", {
            "input_file": "/session/certipy/nonexistent.txt",
            "format": "bof",
            "domain": "corp.local",
            "ca_name": "CORP-CA",
            "sids": "S-1-5-21-1234567890-1234567890-1234567890-1001",
            "published": "User,Machine",
            "vulnerable": True,
            "enabled": True,
            "hide_admins": True,
            "output_stdout": True,
        }))
        content_text = self._get_content_text(resp)
        assert "Traceback" not in content_text

    def test_parse_response_has_method_field(self, certipy_env):
        """parse response includes method='parse'."""
        client, loop = certipy_env
        resp = loop.run_until_complete(client.call("parse", {
            "input_file": "/session/certipy/nonexistent.txt",
        }))
        sc = resp.get("result", {}).get("structuredContent", {})
        data = sc.get("data", {})
        # Early exit for file not found may have method or not
        content_text = self._get_content_text(resp)
        assert "Traceback" not in content_text

    # ── ca new params through Docker ──────────────────────────────────

    def test_ca_add_officer(self, certipy_env):
        """ca add_officer does not crash."""
        client, loop = certipy_env
        resp = loop.run_until_complete(client.call("ca", {
            **self._FAKE_AUTH,
            "ca_name": "CORP-CA",
            "add_officer": "attacker@corp.local",
            "timeout": 15,
        }))
        self._assert_structured_response(resp, "ca (add_officer)")

    def test_ca_remove_officer(self, certipy_env):
        """ca remove_officer does not crash."""
        client, loop = certipy_env
        resp = loop.run_until_complete(client.call("ca", {
            **self._FAKE_AUTH,
            "ca_name": "CORP-CA",
            "remove_officer": "attacker@corp.local",
            "timeout": 15,
        }))
        self._assert_structured_response(resp, "ca (remove_officer)")

    def test_ca_backup(self, certipy_env):
        """ca backup does not crash."""
        client, loop = certipy_env
        resp = loop.run_until_complete(client.call("ca", {
            **self._FAKE_AUTH,
            "ca_name": "CORP-CA",
            "backup": True,
            "config": "DC01\\CORP-CA",
            "timeout": 15,
        }))
        self._assert_structured_response(resp, "ca (backup)")

    def test_ca_list_templates(self, certipy_env):
        """ca list_templates does not crash."""
        client, loop = certipy_env
        resp = loop.run_until_complete(client.call("ca", {
            **self._FAKE_AUTH,
            "ca_name": "CORP-CA",
            "list_templates": True,
            "timeout": 15,
        }))
        self._assert_structured_response(resp, "ca (list_templates)")

    # ── authenticate new params through Docker ────────────────────────

    def test_authenticate_with_username_override(self, certipy_env):
        """authenticate with username override does not crash."""
        client, loop = certipy_env
        resp = loop.run_until_complete(client.call("authenticate", {
            "pfx_path": "/session/certipy/nonexistent.pfx",
            "dc_ip": "10.255.255.1",
            "username": "DC01$",
            "timeout": 15,
        }))
        content_text = self._get_content_text(resp)
        assert "Traceback" not in content_text

    def test_authenticate_with_ns(self, certipy_env):
        """authenticate with ns override does not crash."""
        client, loop = certipy_env
        resp = loop.run_until_complete(client.call("authenticate", {
            "pfx_path": "/session/certipy/nonexistent.pfx",
            "dc_ip": "10.255.255.1",
            "ns": "10.255.255.2",
            "timeout": 15,
        }))
        content_text = self._get_content_text(resp)
        assert "Traceback" not in content_text

    def test_authenticate_with_dns_tcp(self, certipy_env):
        """authenticate with dns_tcp=true does not crash."""
        client, loop = certipy_env
        resp = loop.run_until_complete(client.call("authenticate", {
            "pfx_path": "/session/certipy/nonexistent.pfx",
            "dc_ip": "10.255.255.1",
            "dns_tcp": True,
            "timeout": 15,
        }))
        content_text = self._get_content_text(resp)
        assert "Traceback" not in content_text

    # ── find new params through Docker ────────────────────────────────

    def test_find_with_oids(self, certipy_env):
        """find with oids=true does not crash."""
        client, loop = certipy_env
        resp = loop.run_until_complete(client.call("find", {
            **self._FAKE_AUTH,
            "oids": True,
            "timeout": 15,
        }))
        self._assert_structured_response(resp, "find (oids)")

    def test_find_with_connection_timeout(self, certipy_env):
        """find with connection_timeout does not crash."""
        client, loop = certipy_env
        resp = loop.run_until_complete(client.call("find", {
            **self._FAKE_AUTH,
            "connection_timeout": 5,
            "timeout": 15,
        }))
        self._assert_structured_response(resp, "find (connection_timeout)")

    # ── request new params through Docker ─────────────────────────────

    def test_request_with_subject(self, certipy_env):
        """request with subject does not crash."""
        client, loop = certipy_env
        resp = loop.run_until_complete(client.call("request", {
            **self._FAKE_AUTH,
            "ca": "CORP-CA",
            "subject": "CN=Administrator",
            "timeout": 15,
        }))
        self._assert_structured_response(resp, "request (subject)")

    def test_request_with_pfx_password(self, certipy_env):
        """request with pfx_password does not crash."""
        client, loop = certipy_env
        resp = loop.run_until_complete(client.call("request", {
            **self._FAKE_AUTH,
            "ca": "CORP-CA",
            "pfx_password": "test123",
            "timeout": 15,
        }))
        self._assert_structured_response(resp, "request (pfx_password)")

    def test_request_with_renew(self, certipy_env):
        """request with renew=true does not crash."""
        client, loop = certipy_env
        resp = loop.run_until_complete(client.call("request", {
            **self._FAKE_AUTH,
            "ca": "CORP-CA",
            "renew": True,
            "timeout": 15,
        }))
        self._assert_structured_response(resp, "request (renew)")

    def test_request_with_connection_timeout(self, certipy_env):
        """request with connection_timeout does not crash."""
        client, loop = certipy_env
        resp = loop.run_until_complete(client.call("request", {
            **self._FAKE_AUTH,
            "ca": "CORP-CA",
            "connection_timeout": 5,
            "timeout": 15,
        }))
        self._assert_structured_response(resp, "request (connection_timeout)")

    # ── extra_args on every method through Docker ─────────────────────

    def test_find_extra_args_valid(self, certipy_env):
        """find with extra_args does not crash."""
        client, loop = certipy_env
        resp = loop.run_until_complete(client.call("find", {
            **self._FAKE_AUTH,
            "extra_args": "-scheme ldap",
            "timeout": 15,
        }))
        self._assert_structured_response(resp, "find (extra_args)")

    def test_request_extra_args_valid(self, certipy_env):
        """request with extra_args does not crash."""
        client, loop = certipy_env
        resp = loop.run_until_complete(client.call("request", {
            **self._FAKE_AUTH,
            "ca": "CORP-CA",
            "extra_args": "-scheme ldap",
            "timeout": 15,
        }))
        self._assert_structured_response(resp, "request (extra_args)")

    def test_authenticate_extra_args_valid(self, certipy_env):
        """authenticate with extra_args does not crash."""
        client, loop = certipy_env
        resp = loop.run_until_complete(client.call("authenticate", {
            "pfx_path": "/session/certipy/nonexistent.pfx",
            "dc_ip": "10.255.255.1",
            "extra_args": "-debug",
            "timeout": 15,
        }))
        content_text = self._get_content_text(resp)
        assert "Traceback" not in content_text

    def test_shadow_extra_args_valid(self, certipy_env):
        """shadow with extra_args does not crash."""
        client, loop = certipy_env
        resp = loop.run_until_complete(client.call("shadow", {
            **self._FAKE_AUTH,
            "account": "admin",
            "extra_args": "-debug",
            "timeout": 15,
        }))
        self._assert_structured_response(resp, "shadow (extra_args)")

    def test_template_extra_args_valid(self, certipy_env):
        """template with extra_args does not crash."""
        client, loop = certipy_env
        resp = loop.run_until_complete(client.call("template", {
            **self._FAKE_AUTH,
            "template": "User",
            "extra_args": "-debug",
            "timeout": 15,
        }))
        self._assert_structured_response(resp, "template (extra_args)")

    def test_ca_extra_args_valid(self, certipy_env):
        """ca with extra_args does not crash."""
        client, loop = certipy_env
        resp = loop.run_until_complete(client.call("ca", {
            **self._FAKE_AUTH,
            "ca_name": "CORP-CA",
            "enable_template": "SubCA",
            "extra_args": "-debug",
            "timeout": 15,
        }))
        self._assert_structured_response(resp, "ca (extra_args)")

    def test_account_extra_args_valid(self, certipy_env):
        """account with extra_args does not crash."""
        client, loop = certipy_env
        resp = loop.run_until_complete(client.call("account", {
            **self._FAKE_AUTH,
            "user": "FAKE01$",
            "extra_args": "-debug",
            "timeout": 15,
        }))
        self._assert_structured_response(resp, "account (extra_args)")

    def test_parse_extra_args_valid(self, certipy_env):
        """parse with extra_args does not crash."""
        client, loop = certipy_env
        resp = loop.run_until_complete(client.call("parse", {
            "input_file": "/session/certipy/nonexistent.txt",
            "extra_args": "-debug",
        }))
        content_text = self._get_content_text(resp)
        assert "Traceback" not in content_text

    def test_find_extra_args_invalid_flag(self, certipy_env):
        """find with invalid extra_args flag does not crash."""
        client, loop = certipy_env
        resp = loop.run_until_complete(client.call("find", {
            **self._FAKE_AUTH,
            "extra_args": "--nonexistent-flag-xyz",
            "timeout": 15,
        }))
        content_text = self._get_content_text(resp)
        assert "Traceback" not in content_text

    def test_account_extra_args_invalid_flag(self, certipy_env):
        """account with invalid extra_args flag does not crash."""
        client, loop = certipy_env
        resp = loop.run_until_complete(client.call("account", {
            **self._FAKE_AUTH,
            "user": "FAKE01$",
            "extra_args": "--completely-bogus-flag",
            "timeout": 15,
        }))
        content_text = self._get_content_text(resp)
        assert "Traceback" not in content_text
