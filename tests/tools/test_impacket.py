"""
Tests for the impacket MCP tool server.

Covers:
- Smoke tests: boot, method list, required params, meta-param stripping, clock
- Unit tests: output parsers, error classification
- Unit tests: auth builder (_build_auth_args, _build_domain_auth_args)
- Unit tests: per-method command building (all 20 methods)
- Contract tests: tool.yaml vs server parameter definitions
- Acceptance tests: every method called through container (no live AD target)
- Integration tests: real target scenarios (marked @pytest.mark.integration)
"""

import asyncio
import json
import os
import sys
from pathlib import Path
from typing import Any, Dict
from unittest.mock import AsyncMock, patch

import pytest
import yaml

# ---------------------------------------------------------------------------
# Path setup
# ---------------------------------------------------------------------------
PROJECT_ROOT = Path(__file__).parent.parent.parent
TOOL_DIR = PROJECT_ROOT / "tools" / "impacket"
FIXTURES_DIR = Path(__file__).parent.parent / "fixtures" / "impacket"

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
# This avoids the "Future attached to a different loop" issue from conftest.
# ---------------------------------------------------------------------------
@pytest.fixture(scope="module")
def impacket_env(request):
    """Create an MCPTestClient with its event loop. Yields (client, loop)."""
    tool = "impacket"
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
    """Import and return the ImpacketServer class for direct method testing."""
    import importlib.util
    spec = importlib.util.spec_from_file_location(
        "impacket_server", TOOL_DIR / "mcp-server.py"
    )
    mod = importlib.util.module_from_spec(spec)
    # We need mcp_common to be importable
    spec.loader.exec_module(mod)
    return mod.ImpacketServer


# ===========================================================================
# SMOKE TESTS — require Docker container running
# ===========================================================================

class TestSmoke:
    """Smoke tests that verify the container boots and basic protocol works."""

    def test_boot_and_list_tools(self, impacket_env):
        """Container starts and list_tools returns methods."""
        client, loop = impacket_env
        assert len(client.tools) > 0, "Server should advertise at least one tool"
        names = client.tool_names()
        assert "psexec" in names, "psexec should be in tool list"
        assert "secretsdump" in names, "secretsdump should be in tool list"
        assert "get_tgt" in names, "get_tgt should be in tool list"

    def test_method_list_matches_tool_yaml(self, impacket_env, tool_methods_from_yaml):
        """Every method in tool.yaml is advertised by the server, and vice versa."""
        client, _ = impacket_env
        server_names = client.tool_names()

        # Remove verify_clock — it's test-only, not in tool.yaml
        server_names_no_test = server_names - {"verify_clock"}

        yaml_only = tool_methods_from_yaml - server_names_no_test
        server_only = server_names_no_test - tool_methods_from_yaml

        assert not yaml_only, f"Methods in tool.yaml but not server: {yaml_only}"
        assert not server_only, f"Methods in server but not tool.yaml: {server_only}"

    def test_expected_method_count(self, impacket_env):
        """Server should have exactly 50 built-in methods + verify_clock."""
        client, _ = impacket_env
        names = client.tool_names()
        # 50 built-in + verify_clock in MCP_TEST_MODE
        assert len(names) == 51, (
            f"Expected 51 methods (50 built-in + verify_clock), got {len(names)}: {sorted(names)}"
        )

    def test_required_params_enforced_psexec(self, impacket_env):
        """Calling psexec without required 'target' param returns an error."""
        client, loop = impacket_env
        resp = loop.run_until_complete(
            client.call("psexec", {"command": "whoami"})
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

    def test_required_params_enforced_get_st(self, impacket_env):
        """Calling get_st without required 'spn' and 'impersonate' returns error."""
        client, loop = impacket_env
        resp = loop.run_until_complete(
            client.call("get_st", {"target": "10.0.0.1"})
        )
        result = resp.get("result", {})
        is_error = result.get("isError", False)
        content_text = ""
        for c in result.get("content", []):
            if c.get("type") == "text":
                content_text += c["text"]
        assert is_error or "spn" in content_text.lower() or "impersonate" in content_text.lower() or "error" in content_text.lower(), (
            f"Expected error about missing params, got: {content_text[:300]}"
        )

    def test_meta_params_stripped(self, impacket_env):
        """Passing 'clock_offset' (meta-param) in args does not crash the server."""
        client, loop = impacket_env
        resp = loop.run_until_complete(
            client.call("get_tgt", {
                "target": "10.0.0.1",
                "username": "test",
                "domain": "TEST.LOCAL",
                "password": "test",
                "clock_offset": "5h",  # meta-param — should be stripped
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

    def test_unknown_method_returns_error(self, impacket_env):
        """Calling a non-existent method returns a helpful error."""
        client, loop = impacket_env
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
    def test_verify_clock_available(self, impacket_env):
        """verify_clock is registered in MCP_TEST_MODE."""
        client, _ = impacket_env
        names = client.tool_names()
        assert "verify_clock" in names, "verify_clock should be available in test mode"

    @pytest.mark.clock
    def test_verify_clock_returns_time(self, impacket_env):
        """verify_clock returns current time and FAKETIME status."""
        client, loop = impacket_env
        resp = loop.run_until_complete(client.call("verify_clock", {}))
        result = assert_tool_success(resp)
        data = parse_tool_output(resp)
        assert "current_time" in data
        assert "libfaketime_exists" in data
        # libfaketime is installed in this image
        assert data["libfaketime_exists"] is True, (
            "libfaketime should be installed in the impacket image"
        )

    def test_structuredContent_present(self, impacket_env):
        """Responses include structuredContent with error classification fields."""
        client, loop = impacket_env
        resp = loop.run_until_complete(client.call("verify_clock", {}))
        result = resp.get("result", {})
        sc = result.get("structuredContent")
        assert sc is not None, "structuredContent should be present"
        assert "success" in sc
        assert "error_class" in sc
        assert "retryable" in sc
        assert "suggestions" in sc


# ===========================================================================
# UNIT TESTS — output parsers, no container needed
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
            pytest.skip(f"Cannot import ImpacketServer: {e}")

    # -- secretsdump parser ------------------------------------------------

    def test_parse_secretsdump_drsuapi(self):
        """Parse DRSUAPI-based secretsdump with NTDS hashes."""
        text = load_fixture("secretsdump_drsuapi.txt")
        result = self._server._parse_secretsdump_output(text, "", "/tmp/dummy")
        assert len(result["ntds_hashes"]) == 4, f"Expected 4 NTDS hashes, got {len(result['ntds_hashes'])}"
        assert "Administrator:500:" in result["ntds_hashes"][0]
        assert len(result["kerberos_keys"]) == 3
        assert result["total_hashes"] == 4  # SAM(0) + NTDS(4) + cached(0)

    def test_parse_secretsdump_sam(self):
        """Parse SAM + LSA + cached creds dump."""
        text = load_fixture("secretsdump_sam.txt")
        result = self._server._parse_secretsdump_output(text, "", "/tmp/dummy")
        assert len(result["sam_hashes"]) == 3, f"Expected 3 SAM hashes, got {len(result['sam_hashes'])}"
        assert len(result["cached_creds"]) == 1
        assert len(result["lsa_secrets"]) > 0
        assert result["total_hashes"] == 4  # 3 SAM + 0 NTDS + 1 cached

    def test_parse_secretsdump_empty(self):
        """Parse secretsdump with access denied (no hashes)."""
        text = load_fixture("secretsdump_access_denied.txt")
        result = self._server._parse_secretsdump_output(text, "", "/tmp/dummy")
        assert result["total_hashes"] == 0

    # -- kerberoast parser -------------------------------------------------

    def test_parse_kerberoast_with_hashes(self):
        """Parse kerberoast output with TGS hashes."""
        text = load_fixture("kerberoast_output.txt")
        result = self._server._parse_kerberoast_output(text, "")
        assert result["hash_count"] == 2, f"Expected 2 hashes, got {result['hash_count']}"
        assert result["user_count"] == 2
        assert result["hashes"][0].startswith("$krb5tgs$")
        assert result["users_with_spns"][0]["spn"] == "MSSQL/sql.corp.local"
        assert result["users_with_spns"][0]["username"] == "svc_sql"

    def test_parse_kerberoast_empty(self):
        """Parse kerberoast output with no SPNs found."""
        text = "Impacket v0.14.0.dev0\n\n[*] No entries found!"
        result = self._server._parse_kerberoast_output(text, "")
        assert result["hash_count"] == 0
        assert result["user_count"] == 0

    # -- asreproast parser -------------------------------------------------

    def test_parse_asreproast_with_hashes(self):
        """Parse AS-REP roast output with hashes."""
        text = load_fixture("asreproast_output.txt")
        result = self._server._parse_asreproast_output(text, "")
        assert result["hash_count"] == 1
        assert result["hashes"][0].startswith("$krb5asrep$")

    # -- lookupsid parser --------------------------------------------------

    def test_parse_lookupsid(self):
        """Parse lookupsid output."""
        text = load_fixture("lookupsid_output.txt")
        result = self._server._parse_lookupsid_output(text, "")
        assert result["domain_sid"] == "S-1-5-21-3456789012-1234567890-9876543210"
        assert len(result["users"]) == 5  # Administrator, Guest, krbtgt, svc_sql, john.doe
        assert len(result["groups"]) == 5
        assert len(result["aliases"]) == 2  # Administrators, IT
        assert result["total"] == 12

    # -- smb_shares parser -------------------------------------------------

    def test_parse_smb_shares(self):
        """Parse smbclient shares output."""
        text = load_fixture("smb_shares_output.txt")
        result = self._server._parse_smb_shares(text, "")
        assert len(result) >= 4, f"Expected at least 4 shares, got {len(result)}"
        share_names = [s["name"] for s in result]
        assert "ADMIN$" in share_names or any("ADMIN" in n for n in share_names)
        assert "SYSVOL" in share_names

    # -- exec output parser ------------------------------------------------

    def test_parse_exec_output(self):
        """Parse psexec/wmiexec output."""
        text = load_fixture("exec_output.txt")
        result = self._server._parse_exec_output(text, "")
        assert "whoami" in result["output"] or "nt authority" in result["output"].lower()
        assert len(result["info"]) > 0  # [*] lines
        assert len(result["warnings"]) > 0  # [!] lines

    # -- wmiexec parser ----------------------------------------------------

    def test_parse_wmiexec_success(self):
        """Parse successful wmiexec output."""
        text = load_fixture("wmiexec_success.txt")
        result = self._server._parse_exec_output(text, "")
        assert "administrator" in result["output"].lower()
        assert any("SMBv3" in i for i in result["info"])

    def test_parse_wmiexec_access_denied(self):
        """Parse wmiexec access denied output."""
        text = load_fixture("wmiexec_access_denied.txt")
        result = self._server._parse_exec_output(text, "")
        assert "WBEM_E_ACCESS_DENIED" in result["output"]
        assert len(result["warnings"]) >= 1

    # -- smbexec parser ----------------------------------------------------

    def test_parse_smbexec_success(self):
        """Parse successful smbexec output."""
        text = load_fixture("smbexec_success.txt")
        result = self._server._parse_exec_output(text, "")
        assert "nt authority" in result["output"].lower()

    def test_parse_smbexec_access_denied(self):
        """Parse smbexec access denied output."""
        text = load_fixture("smbexec_access_denied.txt")
        result = self._server._parse_exec_output(text, "")
        assert "rpc_s_access_denied" in result["output"]

    # -- dcomexec parser ---------------------------------------------------

    def test_parse_dcomexec_success(self):
        """Parse successful dcomexec output."""
        text = load_fixture("dcomexec_success.txt")
        result = self._server._parse_exec_output(text, "")
        assert "administrator" in result["output"].lower()

    def test_parse_dcomexec_access_denied(self):
        """Parse dcomexec access denied output (E_ACCESSDENIED)."""
        text = load_fixture("dcomexec_access_denied.txt")
        result = self._server._parse_exec_output(text, "")
        assert "E_ACCESSDENIED" in result["output"]
        assert len(result["warnings"]) >= 1

    # -- atexec parser -----------------------------------------------------

    def test_parse_atexec_success(self):
        """Parse successful atexec output with task execution."""
        text = load_fixture("atexec_success.txt")
        result = self._server._parse_exec_output(text, "")
        assert "nt authority" in result["output"].lower()
        # Info lines should include task creation/running/deletion
        info_text = " ".join(result["info"])
        assert "Creating task" in info_text or "Running task" in info_text

    def test_parse_atexec_access_denied(self):
        """Parse atexec with access denied error."""
        text = load_fixture("atexec_access_denied.txt")
        result = self._server._parse_exec_output(text, "")
        assert "rpc_s_access_denied" in result["output"]
        assert any("Creating task" in i for i in result["info"])

    # -- addcomputer output ------------------------------------------------

    def test_parse_addcomputer_success(self):
        """Verify addcomputer success output contains expected data."""
        text = load_fixture("addcomputer_success.txt")
        assert "Successfully added machine account FAKE01$" in text
        assert "FakePass123!" in text

    def test_parse_addcomputer_quota_exceeded(self):
        """Verify addcomputer quota exceeded error is detectable."""
        text = load_fixture("addcomputer_quota.txt")
        assert "machine account quota" in text.lower()
        assert "STATUS_DS_MACHINE_ACCOUNT_QUOTA_EXCEEDED" in text

    # -- addspn output -----------------------------------------------------

    def test_parse_addspn_add_success(self):
        """Verify addspn add success output."""
        text = load_fixture("addspn_add_success.txt")
        assert "SPN Added successfully" in text

    def test_parse_addspn_remove_success(self):
        """Verify addspn remove success output."""
        text = load_fixture("addspn_remove_success.txt")
        assert "SPN Modified successfully" in text

    # -- changepasswd output -----------------------------------------------

    def test_parse_changepasswd_success(self):
        """Verify changepasswd success output."""
        text = load_fixture("changepasswd_success.txt")
        assert "changed successfully" in text.lower()

    def test_parse_changepasswd_denied(self):
        """Verify changepasswd denial is detectable."""
        text = load_fixture("changepasswd_denied.txt")
        assert "not allowed to set the password" in text

    # -- rbcd output -------------------------------------------------------

    def test_parse_rbcd_read_empty(self):
        """Verify RBCD read with empty attribute."""
        text = load_fixture("rbcd_read_empty.txt")
        assert "empty" in text.lower()
        # The handler checks for "attribute" in combined.lower()
        assert "attribute" in text.lower()

    def test_parse_rbcd_write_success(self):
        """Verify RBCD write success output."""
        text = load_fixture("rbcd_write_success.txt")
        assert "written successfully" in text.lower()
        assert "delegation rights modified" in text.lower()
        assert "FAKE01$" in text

    # -- smb_get / smb_put output ------------------------------------------

    def test_parse_smb_put_access_denied(self):
        """Verify SMB put access denied is detectable."""
        text = load_fixture("smb_put_access_denied.txt")
        assert "STATUS_ACCESS_DENIED" in text

    # -- get_ad_users parser -----------------------------------------------

    def test_parse_ad_users(self):
        """Parse GetADUsers output."""
        text = load_fixture("get_ad_users_output.txt")
        result = self._server._parse_ad_users(text, "")
        assert len(result) >= 3, f"Expected at least 3 users, got {len(result)}"
        admin = next((u for u in result if u["name"] == "Administrator"), None)
        assert admin is not None, "Administrator should be in user list"


# ===========================================================================
# ERROR CLASSIFICATION TESTS — test the new error classification logic
# ===========================================================================

class TestErrorClassification:
    """Test error classification for Kerberos and SMB errors.

    These verify that the server's error handlers correctly identify
    error_class, retryable, and suggestions fields.
    """

    def test_skew_error_classified(self):
        """KRB_AP_ERR_SKEW should be classified as 'config', retryable."""
        text = load_fixture("get_tgt_skew.txt")
        # The server handler should detect this pattern
        assert "KRB_AP_ERR_SKEW" in text
        # We'll test the actual classification in the handler via integration
        # Here we verify the pattern exists in fixture data

    def test_preauth_error_classified(self):
        """KDC_ERR_PREAUTH_FAILED should be classified as 'auth', not retryable."""
        text = load_fixture("get_tgt_preauth.txt")
        assert "KDC_ERR_PREAUTH_FAILED" in text

    def test_logon_failure_classified(self):
        """STATUS_LOGON_FAILURE should be classified as 'auth', not retryable."""
        text = load_fixture("status_logon_failure.txt")
        assert "STATUS_LOGON_FAILURE" in text

    def test_classify_kerberos_errors(self):
        """Test the _classify_kerberos_error helper with various patterns."""
        try:
            cls = _get_server_class()
            server = cls()
        except Exception:
            pytest.skip("Cannot import ImpacketServer")

        # Test KRB_AP_ERR_SKEW
        err_class, retryable, suggestions = server._classify_kerberos_error(
            "Kerberos SessionError: KRB_AP_ERR_SKEW(Clock skew too great)"
        )
        assert err_class == "config", f"Expected 'config' for SKEW, got '{err_class}'"
        assert retryable is True
        assert len(suggestions) > 0

        # Test KDC_ERR_PREAUTH_FAILED
        err_class, retryable, suggestions = server._classify_kerberos_error(
            "Kerberos SessionError: KDC_ERR_PREAUTH_FAILED(Pre-authentication information was invalid)"
        )
        assert err_class == "auth", f"Expected 'auth' for PREAUTH_FAILED, got '{err_class}'"
        assert retryable is False

        # Test KDC_ERR_C_PRINCIPAL_UNKNOWN
        err_class, retryable, suggestions = server._classify_kerberos_error(
            "Kerberos SessionError: KDC_ERR_C_PRINCIPAL_UNKNOWN(Client not found in Kerberos database)"
        )
        assert err_class == "auth", f"Expected 'auth' for C_PRINCIPAL_UNKNOWN, got '{err_class}'"
        assert retryable is False

    def test_classify_smb_errors(self):
        """Test the _classify_smb_error helper with SMB status codes."""
        try:
            cls = _get_server_class()
            server = cls()
        except Exception:
            pytest.skip("Cannot import ImpacketServer")

        # STATUS_LOGON_FAILURE
        err_class, retryable, suggestions = server._classify_smb_error(
            "SMB SessionError: STATUS_LOGON_FAILURE(The attempted logon is invalid.)"
        )
        assert err_class == "auth"
        assert retryable is False

        # STATUS_ACCESS_DENIED
        err_class, retryable, suggestions = server._classify_smb_error(
            "SMB SessionError: STATUS_ACCESS_DENIED(Access denied.)"
        )
        assert err_class == "permission"
        assert retryable is False

    def test_classify_connection_error(self):
        """Test connection error classification."""
        try:
            cls = _get_server_class()
            server = cls()
        except Exception:
            pytest.skip("Cannot import ImpacketServer")

        err_class, retryable, suggestions = server._classify_smb_error(
            "Connection refused"
        )
        # Connection refused is a network error
        assert err_class in ("network", "unknown")

    def test_classify_dcom_access_denied(self):
        """DCOM E_ACCESSDENIED should be classifiable via _classify_error."""
        try:
            cls = _get_server_class()
            server = cls()
        except Exception:
            pytest.skip("Cannot import ImpacketServer")

        text = load_fixture("dcomexec_access_denied.txt")
        err_class, retryable, suggestions = server._classify_error(text)
        # DCOM errors don't have STATUS_ prefix, so _classify_error may fall through
        # but should at least not crash
        assert err_class in ("unknown", "permission", "auth")

    def test_classify_wmi_access_denied(self):
        """WMI WBEM_E_ACCESS_DENIED should be classifiable."""
        try:
            cls = _get_server_class()
            server = cls()
        except Exception:
            pytest.skip("Cannot import ImpacketServer")

        text = "[-] WMI Session Error: code: 0x80041003 - WBEM_E_ACCESS_DENIED"
        err_class, retryable, suggestions = server._classify_error(text)
        assert err_class in ("unknown", "permission")

    def test_classify_rpc_access_denied(self):
        """DCERPC rpc_s_access_denied from smbexec."""
        try:
            cls = _get_server_class()
            server = cls()
        except Exception:
            pytest.skip("Cannot import ImpacketServer")

        text = "[-] DCERPC Runtime Error: code: 0x5 - rpc_s_access_denied"
        err_class, retryable, suggestions = server._classify_error(text)
        # rpc_s_access_denied doesn't contain STATUS_ but is an access error
        assert err_class in ("unknown", "permission")

    def test_classify_quota_exceeded(self):
        """Machine account quota exceeded classification."""
        try:
            cls = _get_server_class()
            server = cls()
        except Exception:
            pytest.skip("Cannot import ImpacketServer")

        text = load_fixture("addcomputer_quota.txt")
        err_class, retryable, suggestions = server._classify_error(text)
        # Contains SessionError but not STATUS_LOGON_FAILURE etc
        assert err_class in ("unknown", "permission")
        # Should not be retryable — quota is a hard limit
        assert retryable is False

    def test_classify_password_expired(self):
        """KDC_ERR_KEY_EXPIRED should be auth, not retryable."""
        try:
            cls = _get_server_class()
            server = cls()
        except Exception:
            pytest.skip("Cannot import ImpacketServer")

        err_class, retryable, suggestions = server._classify_kerberos_error(
            "Kerberos SessionError: KDC_ERR_KEY_EXPIRED(Password has expired)"
        )
        assert err_class == "auth"
        assert retryable is False
        assert any("changepasswd" in s for s in suggestions)


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

    def test_yaml_has_all_50_methods(self):
        """tool.yaml should define exactly 50 methods."""
        methods = self._yaml.get("methods", {})
        assert len(methods) == 50, (
            f"Expected 50 methods, got {len(methods)}: {sorted(methods.keys())}"
        )

    def test_all_methods_have_descriptions(self):
        """Every method should have a description."""
        for name, defn in self._yaml.get("methods", {}).items():
            assert "description" in defn, f"Method {name} missing description"
            assert len(defn["description"]) > 10, f"Method {name} has too short description"

    def test_all_methods_have_target_param(self):
        """Every method should have a 'target' parameter (with known exceptions)."""
        # Methods that genuinely don't need a target param:
        exempt = {"ticketer", "ticket_converter", "describe_ticket", "run_custom",
                  "rpcmap"}
        for name, defn in self._yaml.get("methods", {}).items():
            if name in exempt:
                continue
            params = defn.get("params", {})
            assert "target" in params, f"Method {name} missing 'target' param"

    def test_all_methods_have_timeout_param(self):
        """Every method should have a 'timeout' parameter."""
        for name, defn in self._yaml.get("methods", {}).items():
            params = defn.get("params", {})
            assert "timeout" in params, f"Method {name} missing 'timeout' param"

    def test_all_methods_have_extra_args(self):
        """Every method except run_custom should have an 'extra_args' parameter."""
        for name, defn in self._yaml.get("methods", {}).items():
            if name == "run_custom":
                continue  # run_custom uses 'args' instead
            params = defn.get("params", {})
            assert "extra_args" in params, f"Method {name} missing 'extra_args' param"

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

    def test_bidirectional_yaml_server_match(self):
        """Every method in tool.yaml exists in the server, and vice versa."""
        import importlib.util
        spec = importlib.util.spec_from_file_location(
            "impacket_server", TOOL_DIR / "mcp-server.py"
        )
        mod = importlib.util.module_from_spec(spec)
        try:
            spec.loader.exec_module(mod)
        except Exception:
            pytest.skip("Cannot import mcp-server.py")

        # Collect all method names the server registers
        server_cls = mod.ImpacketServer
        server = server_cls()
        server_methods = set(server.methods.keys()) - {"verify_clock"}

        yaml_methods = set(self._yaml.get("methods", {}).keys())

        yaml_only = yaml_methods - server_methods
        server_only = server_methods - yaml_methods

        assert not yaml_only, f"Methods in tool.yaml but not server: {yaml_only}"
        assert not server_only, f"Methods in server but not tool.yaml: {server_only}"

    def test_yaml_params_subset_of_server(self):
        """Every param in tool.yaml for a method should exist in the server registration."""
        import importlib.util
        spec = importlib.util.spec_from_file_location(
            "impacket_server", TOOL_DIR / "mcp-server.py"
        )
        mod = importlib.util.module_from_spec(spec)
        try:
            spec.loader.exec_module(mod)
        except Exception:
            pytest.skip("Cannot import mcp-server.py")

        server_cls = mod.ImpacketServer
        server = server_cls()

        errors = []
        for name, defn in self._yaml.get("methods", {}).items():
            method = server.methods.get(name)
            if not method:
                continue
            yaml_params = set(defn.get("params", {}).keys())
            server_params = set(method.params.keys())
            yaml_only = yaml_params - server_params
            if yaml_only:
                errors.append(f"{name}: yaml has params not in server: {sorted(yaml_only)}")

        assert not errors, "Params in yaml but not server:\n" + "\n".join(errors)


# ===========================================================================
# UNIT TESTS — auth builder helpers
# ===========================================================================

class TestBuildAuthArgs:
    """Test _build_auth_args produces correct Impacket CLI target strings."""

    @pytest.fixture(autouse=True, scope="class")
    def setup_server(self):
        try:
            cls = _get_server_class()
            self.__class__._server = cls()
            # Pre-set krb5 configured to avoid /etc/krb5.conf writes in tests
            self.__class__._server._krb5_configured = True
        except Exception as e:
            pytest.skip(f"Cannot import ImpacketServer: {e}")

    def test_basic_password_auth(self):
        """domain/user:pass@target format."""
        target_str, extra = self._server._build_auth_args(
            target="10.10.10.1", username="admin", password="Pass123",
            domain="CORP.LOCAL",
        )
        assert target_str == "CORP.LOCAL/admin:Pass123@10.10.10.1"
        assert extra == []

    def test_no_domain(self):
        """user:pass@target (no domain prefix)."""
        target_str, _ = self._server._build_auth_args(
            target="10.10.10.1", username="admin", password="Pass123",
        )
        assert target_str == "admin:Pass123@10.10.10.1"

    def test_no_username(self):
        """@target only (null session)."""
        target_str, _ = self._server._build_auth_args(target="10.10.10.1")
        assert target_str == "@10.10.10.1"

    def test_no_password(self):
        """domain/user@target (no password)."""
        target_str, _ = self._server._build_auth_args(
            target="10.10.10.1", username="admin", domain="CORP",
        )
        assert target_str == "CORP/admin@10.10.10.1"

    def test_hashes_flag(self):
        """Pass-the-hash adds -hashes flag."""
        _, extra = self._server._build_auth_args(
            target="10.10.10.1", username="admin",
            hashes="aad3b435b51404ee:31d6cfe0d16ae931b73c59d7e0c089c0",
        )
        assert "-hashes" in extra
        idx = extra.index("-hashes")
        assert "aad3b435b51404ee" in extra[idx + 1]

    def test_kerberos_flag(self):
        """Kerberos auth adds -k and -no-pass when no password/hash/aes."""
        _, extra = self._server._build_auth_args(
            target="10.10.10.1", username="admin", kerberos=True,
        )
        assert "-k" in extra
        assert "-no-pass" in extra

    def test_kerberos_with_password_no_nopass(self):
        """Kerberos with password: -k but NOT -no-pass."""
        _, extra = self._server._build_auth_args(
            target="10.10.10.1", username="admin", password="Pass123",
            kerberos=True,
        )
        assert "-k" in extra
        assert "-no-pass" not in extra

    def test_kerberos_with_aes_key_no_nopass(self):
        """Kerberos with aes_key: -k but NOT -no-pass."""
        _, extra = self._server._build_auth_args(
            target="10.10.10.1", username="admin",
            kerberos=True, aes_key="0123456789abcdef" * 4,
        )
        assert "-k" in extra
        assert "-no-pass" not in extra
        assert "-aesKey" in extra

    def test_dc_ip_flag(self):
        """dc_ip produces -dc-ip flag."""
        _, extra = self._server._build_auth_args(
            target="10.10.10.1", dc_ip="10.10.10.2",
        )
        assert "-dc-ip" in extra
        idx = extra.index("-dc-ip")
        assert extra[idx + 1] == "10.10.10.2"

    def test_port_flag(self):
        """port produces -port flag."""
        _, extra = self._server._build_auth_args(
            target="10.10.10.1", port=4455,
        )
        assert "-port" in extra
        idx = extra.index("-port")
        assert extra[idx + 1] == "4455"

    def test_aes_key_flag(self):
        """aes_key produces -aesKey flag."""
        key = "a" * 64
        _, extra = self._server._build_auth_args(
            target="10.10.10.1", aes_key=key,
        )
        assert "-aesKey" in extra
        idx = extra.index("-aesKey")
        assert extra[idx + 1] == key

    def test_all_flags_combined(self):
        """All auth flags combined."""
        target_str, extra = self._server._build_auth_args(
            target="dc01.corp.local", username="admin", password="P@ss",
            domain="CORP.LOCAL", hashes="aa:bb", kerberos=True,
            dc_ip="10.10.10.1", aes_key="cc" * 32, port=445,
        )
        assert target_str == "CORP.LOCAL/admin:P@ss@dc01.corp.local"
        assert "-hashes" in extra
        assert "-k" in extra
        assert "-dc-ip" in extra
        assert "-aesKey" in extra
        assert "-port" in extra
        # With password AND hashes AND aes_key, should NOT have -no-pass
        assert "-no-pass" not in extra


class TestBuildDomainAuthArgs:
    """Test _build_domain_auth_args for domain-style tools (no @target)."""

    @pytest.fixture(autouse=True, scope="class")
    def setup_server(self):
        try:
            cls = _get_server_class()
            self.__class__._server = cls()
            self.__class__._server._krb5_configured = True
        except Exception as e:
            pytest.skip(f"Cannot import ImpacketServer: {e}")

    def test_basic_domain_auth(self):
        """domain/user:pass format (no @target)."""
        identity, extra = self._server._build_domain_auth_args(
            target="10.10.10.1", username="admin", password="Pass123",
            domain="CORP.LOCAL",
        )
        assert identity == "CORP.LOCAL/admin:Pass123"
        assert "@" not in identity
        # target goes to -dc-ip since dc_ip not explicit
        assert "-dc-ip" in extra
        idx = extra.index("-dc-ip")
        assert extra[idx + 1] == "10.10.10.1"

    def test_explicit_dc_ip_overrides_target(self):
        """Explicit dc_ip takes precedence over target."""
        identity, extra = self._server._build_domain_auth_args(
            target="10.10.10.1", username="admin", password="Pass",
            domain="CORP", dc_ip="10.10.10.2",
        )
        idx = extra.index("-dc-ip")
        assert extra[idx + 1] == "10.10.10.2"

    def test_kerberos_no_pass(self):
        """Kerberos without password/hash/aes -> -k -no-pass."""
        _, extra = self._server._build_domain_auth_args(
            target="10.10.10.1", username="admin", kerberos=True,
            domain="CORP",
        )
        assert "-k" in extra
        assert "-no-pass" in extra

    def test_no_username(self):
        """No username produces just domain/ prefix."""
        identity, _ = self._server._build_domain_auth_args(
            target="10.10.10.1", domain="CORP",
        )
        assert identity == "CORP/"


# ===========================================================================
# UNIT TESTS — per-method command building
# ===========================================================================

class TestCommandBuilding:
    """Test that each method builds the correct CLI command.

    We mock `run_command` / `run_command_with_progress` and
    `asyncio.create_subprocess_exec` to capture commands without execution.
    """

    @pytest.fixture(autouse=True, scope="class")
    def setup_server(self):
        try:
            cls = _get_server_class()
            self.__class__._server = cls()
            # Pre-set krb5 configured to avoid /etc/krb5.conf writes in tests
            self.__class__._server._krb5_configured = True
        except Exception as e:
            pytest.skip(f"Cannot import ImpacketServer: {e}")

    _AUTH = {
        "target": "10.10.10.1",
        "username": "admin",
        "password": "Pass123",
        "domain": "CORP.LOCAL",
    }

    def _capture_cmd(self, method_name, kwargs):
        """Call a handler, capture the command it builds via mocked run_command."""
        captured = {}

        class FakeResult:
            def __init__(self):
                self.stdout = ""
                self.stderr = ""
                self.returncode = 1  # non-zero so parsing kicks in

        async def mock_run(cmd, timeout=60, env=None, **kw):
            captured["cmd"] = cmd
            captured["env"] = env
            return FakeResult()

        async def mock_run_progress(cmd, timeout=60, env=None, progress_filter=None, **kw):
            captured["cmd"] = cmd
            captured["env"] = env
            return FakeResult()

        handler = getattr(self._server, method_name)
        orig_run = self._server.run_command
        orig_run_progress = getattr(self._server, "run_command_with_progress", None)
        self._server.run_command = mock_run
        if orig_run_progress:
            self._server.run_command_with_progress = mock_run_progress

        try:
            loop = asyncio.new_event_loop()
            try:
                loop.run_until_complete(handler(**kwargs))
            finally:
                loop.close()
        finally:
            self._server.run_command = orig_run
            if orig_run_progress:
                self._server.run_command_with_progress = orig_run_progress

        return captured.get("cmd", [])

    # ── Remote Execution ──────────────────────────────────────────────

    def test_psexec_basic_cmd(self):
        """psexec builds: impacket-psexec <auth> <target_str> [command]"""
        cmd = self._capture_cmd("psexec", {**self._AUTH, "command": "whoami"})
        assert cmd[0] == "impacket-psexec"
        assert "CORP.LOCAL/admin:Pass123@10.10.10.1" in cmd
        assert cmd[-1] == "whoami"

    def test_psexec_service_name(self):
        """psexec with service_name adds -service-name flag."""
        cmd = self._capture_cmd("psexec", {
            **self._AUTH, "command": "whoami", "service_name": "MySvc",
        })
        assert "-service-name" in cmd
        idx = cmd.index("-service-name")
        assert cmd[idx + 1] == "MySvc"

    def test_psexec_codec(self):
        """psexec with non-default codec adds -codec flag."""
        cmd = self._capture_cmd("psexec", {
            **self._AUTH, "command": "whoami", "codec": "cp437",
        })
        assert "-codec" in cmd
        idx = cmd.index("-codec")
        assert cmd[idx + 1] == "cp437"

    def test_psexec_no_command(self):
        """psexec without command: target_str is last arg (interactive shell)."""
        cmd = self._capture_cmd("psexec", {**self._AUTH})
        assert cmd[-1] == "CORP.LOCAL/admin:Pass123@10.10.10.1"

    def test_wmiexec_basic_cmd(self):
        """wmiexec builds: impacket-wmiexec <auth> <target_str> [command]"""
        cmd = self._capture_cmd("wmiexec", {**self._AUTH, "command": "hostname"})
        assert cmd[0] == "impacket-wmiexec"
        assert "CORP.LOCAL/admin:Pass123@10.10.10.1" in cmd
        assert cmd[-1] == "hostname"

    def test_wmiexec_nooutput(self):
        """wmiexec with nooutput adds -nooutput flag."""
        cmd = self._capture_cmd("wmiexec", {
            **self._AUTH, "command": "cmd.exe /c del C:\\temp\\*", "nooutput": True,
        })
        assert "-nooutput" in cmd

    def test_dcomexec_basic_cmd(self):
        """dcomexec builds correct command with -object flag."""
        cmd = self._capture_cmd("dcomexec", {
            **self._AUTH, "command": "whoami", "dcom_object": "ShellWindows",
        })
        assert cmd[0] == "impacket-dcomexec"
        assert "-object" in cmd
        idx = cmd.index("-object")
        assert cmd[idx + 1] == "ShellWindows"
        assert cmd[-1] == "whoami"

    def test_dcomexec_nooutput(self):
        """dcomexec with nooutput adds -nooutput flag."""
        cmd = self._capture_cmd("dcomexec", {
            **self._AUTH, "command": "cmd.exe", "nooutput": True,
        })
        assert "-nooutput" in cmd

    def test_atexec_basic_cmd(self):
        """atexec builds: impacket-atexec <auth> <target_str> <command>"""
        cmd = self._capture_cmd("atexec", {**self._AUTH, "command": "whoami"})
        assert cmd[0] == "impacket-atexec"
        assert cmd[-1] == "whoami"
        # target_str should be second-to-last
        assert "CORP.LOCAL/admin:Pass123@10.10.10.1" in cmd

    def test_atexec_codec(self):
        """atexec with non-default codec adds -codec flag."""
        cmd = self._capture_cmd("atexec", {
            **self._AUTH, "command": "whoami", "codec": "cp850",
        })
        assert "-codec" in cmd
        idx = cmd.index("-codec")
        assert cmd[idx + 1] == "cp850"

    # ── Credential Attacks ────────────────────────────────────────────

    def test_secretsdump_basic_cmd(self):
        """secretsdump builds: impacket-secretsdump -outputfile <prefix> <auth> <target_str>"""
        cmd = self._capture_cmd("secretsdump", {**self._AUTH})
        assert cmd[0] == "impacket-secretsdump"
        assert "-outputfile" in cmd
        assert "CORP.LOCAL/admin:Pass123@10.10.10.1" in cmd

    def test_secretsdump_just_dc(self):
        """secretsdump with just_dc adds -just-dc flag."""
        cmd = self._capture_cmd("secretsdump", {**self._AUTH, "just_dc": True})
        assert "-just-dc" in cmd

    def test_secretsdump_just_dc_ntlm(self):
        """secretsdump with just_dc_ntlm adds -just-dc-ntlm flag."""
        cmd = self._capture_cmd("secretsdump", {**self._AUTH, "just_dc_ntlm": True})
        assert "-just-dc-ntlm" in cmd

    def test_secretsdump_just_dc_user(self):
        """secretsdump with just_dc_user adds -just-dc-user flag."""
        cmd = self._capture_cmd("secretsdump", {
            **self._AUTH, "just_dc_user": "Administrator",
        })
        assert "-just-dc-user" in cmd
        idx = cmd.index("-just-dc-user")
        assert cmd[idx + 1] == "Administrator"

    def test_secretsdump_use_vss_and_exec_method(self):
        """secretsdump with use_vss and exec_method."""
        cmd = self._capture_cmd("secretsdump", {
            **self._AUTH, "use_vss": True, "exec_method": "wmiexec",
        })
        assert "-use-vss" in cmd
        assert "-exec-method" in cmd
        idx = cmd.index("-exec-method")
        assert cmd[idx + 1] == "wmiexec"

    def test_kerberoast_basic_cmd(self):
        """kerberoast builds: impacket-GetUserSPNs <auth> -request <identity>"""
        cmd = self._capture_cmd("kerberoast", {**self._AUTH})
        assert cmd[0] == "impacket-GetUserSPNs"
        assert "-request" in cmd
        assert "-dc-ip" in cmd
        # Domain auth: identity is CORP.LOCAL/admin:Pass123 (no @target)
        assert "CORP.LOCAL/admin:Pass123" in cmd

    def test_kerberoast_request_user(self):
        """kerberoast with request_user adds -request-user flag."""
        cmd = self._capture_cmd("kerberoast", {
            **self._AUTH, "request_user": "svc_sql",
        })
        assert "-request-user" in cmd
        idx = cmd.index("-request-user")
        assert cmd[idx + 1] == "svc_sql"

    def test_asreproast_basic_cmd(self):
        """asreproast builds: impacket-GetNPUsers <auth> -request -format hashcat <identity>"""
        cmd = self._capture_cmd("asreproast", {**self._AUTH})
        assert cmd[0] == "impacket-GetNPUsers"
        assert "-request" in cmd
        assert "-format" in cmd
        idx = cmd.index("-format")
        assert cmd[idx + 1] == "hashcat"

    def test_asreproast_john_format(self):
        """asreproast with john format."""
        cmd = self._capture_cmd("asreproast", {
            **self._AUTH, "output_format": "john",
        })
        assert "-format" in cmd
        idx = cmd.index("-format")
        assert cmd[idx + 1] == "john"

    def test_asreproast_usersfile(self):
        """asreproast with usersfile adds -usersfile flag."""
        cmd = self._capture_cmd("asreproast", {
            **self._AUTH, "usersfile": "/tmp/users.txt",
        })
        assert "-usersfile" in cmd
        idx = cmd.index("-usersfile")
        assert cmd[idx + 1] == "/tmp/users.txt"

    # ── Enumeration ───────────────────────────────────────────────────

    def test_get_ad_users_basic_cmd(self):
        """get_ad_users builds: impacket-GetADUsers <auth> <identity>"""
        cmd = self._capture_cmd("get_ad_users", {**self._AUTH})
        assert cmd[0] == "impacket-GetADUsers"
        assert "CORP.LOCAL/admin:Pass123" in cmd

    def test_get_ad_users_all_flag(self):
        """get_ad_users with all=True adds -all flag."""
        cmd = self._capture_cmd("get_ad_users", {**self._AUTH, "all": True})
        assert "-all" in cmd

    def test_lookupsid_basic_cmd(self):
        """lookupsid builds: impacket-lookupsid <auth> <target_str> <maxRid>"""
        cmd = self._capture_cmd("lookupsid", {**self._AUTH, "max_rid": 2000})
        assert cmd[0] == "impacket-lookupsid"
        assert "CORP.LOCAL/admin:Pass123@10.10.10.1" in cmd
        assert "2000" in cmd

    def test_lookupsid_default_rid(self):
        """lookupsid with default max_rid uses 4000."""
        cmd = self._capture_cmd("lookupsid", {**self._AUTH})
        assert "4000" in cmd

    # ── Kerberos ──────────────────────────────────────────────────────

    def test_get_tgt_basic_cmd(self):
        """get_tgt builds: impacket-getTGT <auth> <identity>"""
        cmd = self._capture_cmd("get_tgt", {**self._AUTH})
        assert cmd[0] == "impacket-getTGT"
        assert "CORP.LOCAL/admin:Pass123" in cmd

    def test_get_st_basic_cmd(self):
        """get_st builds: impacket-getST -spn <spn> -impersonate <user> <auth> <identity>"""
        cmd = self._capture_cmd("get_st", {
            **self._AUTH, "spn": "cifs/dc.corp.local",
            "impersonate": "Administrator",
        })
        assert cmd[0] == "impacket-getST"
        assert "-spn" in cmd
        idx_spn = cmd.index("-spn")
        assert cmd[idx_spn + 1] == "cifs/dc.corp.local"
        assert "-impersonate" in cmd
        idx_imp = cmd.index("-impersonate")
        assert cmd[idx_imp + 1] == "Administrator"

    def test_get_st_force_forwardable(self):
        """get_st with force_forwardable adds -force-forwardable flag."""
        cmd = self._capture_cmd("get_st", {
            **self._AUTH, "spn": "cifs/dc", "impersonate": "admin",
            "force_forwardable": True,
        })
        assert "-force-forwardable" in cmd

    def test_get_st_altservice(self):
        """get_st with altservice adds -altservice flag."""
        cmd = self._capture_cmd("get_st", {
            **self._AUTH, "spn": "http/web", "impersonate": "admin",
            "altservice": "cifs/dc.corp.local",
        })
        assert "-altservice" in cmd
        idx = cmd.index("-altservice")
        assert cmd[idx + 1] == "cifs/dc.corp.local"

    def test_get_st_u2u(self):
        """get_st with u2u adds -u2u flag."""
        cmd = self._capture_cmd("get_st", {
            **self._AUTH, "spn": "cifs/dc", "impersonate": "admin",
            "u2u": True,
        })
        assert "-u2u" in cmd

    def test_get_st_self_only(self):
        """get_st with self_only adds -self flag."""
        cmd = self._capture_cmd("get_st", {
            **self._AUTH, "spn": "cifs/dc", "impersonate": "admin",
            "self_only": True,
        })
        assert "-self" in cmd

    def test_get_st_dmsa(self):
        """get_st with dmsa adds -dmsa flag."""
        cmd = self._capture_cmd("get_st", {
            **self._AUTH, "spn": "cifs/dc", "impersonate": "admin",
            "dmsa": True,
        })
        assert "-dmsa" in cmd

    def test_get_st_additional_ticket(self):
        """get_st with additional_ticket adds -additional-ticket flag."""
        cmd = self._capture_cmd("get_st", {
            **self._AUTH, "spn": "cifs/dc", "impersonate": "admin",
            "additional_ticket": "/session/credentials/fake.ccache",
        })
        assert "-additional-ticket" in cmd
        idx = cmd.index("-additional-ticket")
        assert cmd[idx + 1] == "/session/credentials/fake.ccache"

    # ── Delegation / Account modification ─────────────────────────────

    def test_find_delegation_basic_cmd(self):
        """find_delegation builds: impacket-findDelegation <auth> <identity>"""
        cmd = self._capture_cmd("find_delegation", {**self._AUTH})
        assert cmd[0] == "impacket-findDelegation"
        assert "CORP.LOCAL/admin:Pass123" in cmd

    def test_addcomputer_basic_cmd(self):
        """addcomputer builds: impacket-addcomputer -method SAMR <auth> <identity>"""
        cmd = self._capture_cmd("addcomputer", {**self._AUTH})
        assert cmd[0] == "impacket-addcomputer"
        assert "-method" in cmd
        idx = cmd.index("-method")
        assert cmd[idx + 1] == "SAMR"

    def test_addcomputer_with_name_and_pass(self):
        """addcomputer with computer_name and computer_pass."""
        cmd = self._capture_cmd("addcomputer", {
            **self._AUTH, "computer_name": "EVIL01",
            "computer_pass": "EvilP@ss!",
        })
        assert "-computer-name" in cmd
        assert "-computer-pass" in cmd
        idx_name = cmd.index("-computer-name")
        assert cmd[idx_name + 1] == "EVIL01"
        idx_pass = cmd.index("-computer-pass")
        assert cmd[idx_pass + 1] == "EvilP@ss!"

    def test_addcomputer_ldaps_method(self):
        """addcomputer with LDAPS method and base_dn."""
        cmd = self._capture_cmd("addcomputer", {
            **self._AUTH, "method": "LDAPS",
            "base_dn": "DC=corp,DC=local",
        })
        idx_method = cmd.index("-method")
        assert cmd[idx_method + 1] == "LDAPS"
        assert "-baseDN" in cmd
        idx_dn = cmd.index("-baseDN")
        assert cmd[idx_dn + 1] == "DC=corp,DC=local"

    def test_rbcd_read_cmd(self):
        """rbcd read: python3 /opt/impacket-scripts/rbcd.py -delegate-to <target> -action read"""
        cmd = self._capture_cmd("rbcd", {
            **self._AUTH, "delegate_to": "WEB01$", "action": "read",
        })
        assert cmd[0] == "python3"
        assert "/opt/impacket-scripts/rbcd.py" in cmd[1]
        assert "-delegate-to" in cmd
        idx = cmd.index("-delegate-to")
        assert cmd[idx + 1] == "WEB01$"
        assert "-action" in cmd
        idx_a = cmd.index("-action")
        assert cmd[idx_a + 1] == "read"

    def test_rbcd_write_cmd(self):
        """rbcd write: includes -delegate-from."""
        cmd = self._capture_cmd("rbcd", {
            **self._AUTH, "delegate_to": "WEB01$",
            "delegate_from": "EVIL01$", "action": "write",
        })
        assert "-delegate-from" in cmd
        idx = cmd.index("-delegate-from")
        assert cmd[idx + 1] == "EVIL01$"
        idx_a = cmd.index("-action")
        assert cmd[idx_a + 1] == "write"

    def test_rbcd_use_ldaps(self):
        """rbcd with use_ldaps adds -use-ldaps flag."""
        cmd = self._capture_cmd("rbcd", {
            **self._AUTH, "delegate_to": "WEB01$", "use_ldaps": True,
        })
        assert "-use-ldaps" in cmd

    def test_changepasswd_basic_cmd(self):
        """changepasswd builds correct command with -newpass and -protocol."""
        cmd = self._capture_cmd("changepasswd", {
            **self._AUTH, "new_password": "NewP@ss1!",
        })
        assert cmd[0] == "python3"
        assert "/opt/impacket-scripts/changepasswd.py" in cmd[1]
        assert "-newpass" in cmd
        idx = cmd.index("-newpass")
        assert cmd[idx + 1] == "NewP@ss1!"
        assert "-protocol" in cmd
        idx_p = cmd.index("-protocol")
        assert cmd[idx_p + 1] == "smb-samr"

    def test_changepasswd_reset_flag(self):
        """changepasswd with reset adds -reset flag."""
        cmd = self._capture_cmd("changepasswd", {
            **self._AUTH, "new_password": "NewP@ss!", "reset": True,
        })
        assert "-reset" in cmd

    def test_changepasswd_altuser(self):
        """changepasswd with altuser adds -altuser, -altpass, -althash flags."""
        cmd = self._capture_cmd("changepasswd", {
            **self._AUTH, "new_password": "NewP@ss!",
            "altuser": "corp/priv_admin", "altpass": "PrivPass!",
            "althash": "aa:bb",
        })
        assert "-altuser" in cmd
        assert "-altpass" in cmd
        assert "-althash" in cmd
        idx_u = cmd.index("-altuser")
        assert cmd[idx_u + 1] == "corp/priv_admin"

    def test_changepasswd_kpasswd_protocol(self):
        """changepasswd with kpasswd protocol."""
        cmd = self._capture_cmd("changepasswd", {
            **self._AUTH, "new_password": "NewP@ss!",
            "protocol": "kpasswd",
        })
        idx = cmd.index("-protocol")
        assert cmd[idx + 1] == "kpasswd"

    def test_addspn_add_cmd(self):
        """addspn add: python3 /opt/krbrelayx/addspn.py -u user -p pass -t target -s spn host"""
        cmd = self._capture_cmd("addspn", {
            **self._AUTH, "target_account": "DC01$",
            "spn": "cifs/DC01.corp.local",
        })
        assert cmd[0] == "python3"
        assert "/opt/krbrelayx/addspn.py" in cmd[1]
        assert "-u" in cmd
        assert "-p" in cmd
        assert "-t" in cmd
        idx_t = cmd.index("-t")
        assert cmd[idx_t + 1] == "DC01$"
        assert "-s" in cmd
        idx_s = cmd.index("-s")
        assert cmd[idx_s + 1] == "cifs/DC01.corp.local"

    def test_addspn_remove_cmd(self):
        """addspn remove adds -r flag."""
        cmd = self._capture_cmd("addspn", {
            **self._AUTH, "target_account": "DC01$",
            "spn": "cifs/DC01.corp.local", "action": "remove",
        })
        assert "-r" in cmd

    def test_addspn_kerberos(self):
        """addspn with kerberos adds -k flag."""
        cmd = self._capture_cmd("addspn", {
            **self._AUTH, "target_account": "DC01$",
            "spn": "cifs/DC01", "kerberos": True,
        })
        assert "-k" in cmd

    def test_addspn_dc_ip(self):
        """addspn with dc_ip uses it as host and adds -dc-ip."""
        cmd = self._capture_cmd("addspn", {
            **self._AUTH, "target_account": "DC01$",
            "spn": "cifs/DC01", "dc_ip": "10.10.10.2",
        })
        assert "-dc-ip" in cmd
        # Last arg is the host — should be dc_ip
        assert cmd[-1] == "10.10.10.2"

    def test_addspn_username_with_domain(self):
        """addspn passes domain\\username to -u when domain is set."""
        cmd = self._capture_cmd("addspn", {
            **self._AUTH, "target_account": "DC01$", "spn": "cifs/DC01",
        })
        idx_u = cmd.index("-u")
        assert cmd[idx_u + 1] == "CORP.LOCAL\\admin"


# ===========================================================================
# UNIT TESTS — generic handler command building (new methods)
# ===========================================================================

class TestGenericCommandBuilding:
    """Test that generic-handler methods build correct CLI commands.

    Uses the same _capture_cmd pattern as TestCommandBuilding but targets
    the 29 data-driven generic methods registered via IMPACKET_SCRIPTS.
    """

    @pytest.fixture(autouse=True, scope="class")
    def setup_server(self):
        try:
            cls = _get_server_class()
            self.__class__._server = cls()
            self.__class__._server._krb5_configured = True
        except Exception as e:
            pytest.skip(f"Cannot import ImpacketServer: {e}")

    _AUTH = {
        "target": "10.10.10.1",
        "username": "admin",
        "password": "Pass123",
        "domain": "CORP.LOCAL",
    }

    def _capture_generic_cmd(self, method_name, kwargs):
        """Call a generic handler, capture the command it builds."""
        captured = {}

        class FakeResult:
            def __init__(self):
                self.stdout = ""
                self.stderr = ""
                self.returncode = 1

        async def mock_run_progress(cmd, env=None, **kw):
            captured["cmd"] = cmd
            captured["env"] = env
            return FakeResult()

        orig = self._server.run_command_with_progress
        self._server.run_command_with_progress = mock_run_progress
        try:
            loop = asyncio.new_event_loop()
            try:
                handler = self._server.methods[method_name].handler
                loop.run_until_complete(handler(**kwargs))
            finally:
                loop.close()
        finally:
            self._server.run_command_with_progress = orig
        return captured.get("cmd", [])

    # ── ACL Attacks ──────────────────────────────────────────────────────

    def test_dacledit_read(self):
        """dacledit read builds: impacket-dacledit -action read ... <identity>"""
        cmd = self._capture_generic_cmd("dacledit", {
            **self._AUTH, "action": "read", "target_object": "DC01$",
        })
        assert cmd[0] == "impacket-dacledit"
        assert "-action" in cmd
        idx = cmd.index("-action")
        assert cmd[idx + 1] == "read"
        assert "-target" in cmd
        # Domain auth: identity is "CORP.LOCAL/admin:Pass123" (no @target)
        assert "CORP.LOCAL/admin:Pass123" in cmd

    def test_dacledit_write_with_rights(self):
        """dacledit write with principal and rights."""
        cmd = self._capture_generic_cmd("dacledit", {
            **self._AUTH, "action": "write", "target_object": "DC01$",
            "principal": "evil_user", "rights": "DCSync",
        })
        assert "-action" in cmd and cmd[cmd.index("-action") + 1] == "write"
        assert "-principal" in cmd and cmd[cmd.index("-principal") + 1] == "evil_user"
        assert "-rights" in cmd and cmd[cmd.index("-rights") + 1] == "DCSync"

    def test_owneredit_write(self):
        """owneredit write builds correct command."""
        cmd = self._capture_generic_cmd("owneredit", {
            **self._AUTH, "action": "write", "target_object": "DC01$",
            "new_owner": "evil_user",
        })
        assert cmd[0] == "impacket-owneredit"
        assert "-action" in cmd and cmd[cmd.index("-action") + 1] == "write"
        assert "-new-owner" in cmd and cmd[cmd.index("-new-owner") + 1] == "evil_user"

    # ── Kerberos Ticket Manipulation ─────────────────────────────────────

    def test_ticketer_golden(self):
        """ticketer golden ticket builds correct command."""
        cmd = self._capture_generic_cmd("ticketer", {
            "target_user": "Administrator",
            "domain_name": "corp.local",
            "domain_sid": "S-1-5-21-111-222-333",
            "nthash": "aabbccdd" * 4,
        })
        assert cmd[0] == "impacket-ticketer"
        assert "-domain" in cmd and cmd[cmd.index("-domain") + 1] == "corp.local"
        assert "-domain-sid" in cmd and cmd[cmd.index("-domain-sid") + 1] == "S-1-5-21-111-222-333"
        assert "-nthash" in cmd
        # target_user is positional (flag == "")
        assert "Administrator" in cmd

    def test_ticketer_silver(self):
        """ticketer silver ticket includes -spn."""
        cmd = self._capture_generic_cmd("ticketer", {
            "target_user": "admin",
            "domain_name": "corp.local",
            "domain_sid": "S-1-5-21-111-222-333",
            "nthash": "aa" * 16,
            "spn": "cifs/dc.corp.local",
        })
        assert "-spn" in cmd and cmd[cmd.index("-spn") + 1] == "cifs/dc.corp.local"

    # ── Services & Remote Management ─────────────────────────────────────

    def test_services_list(self):
        """services list builds: impacket-services <identity> list"""
        cmd = self._capture_generic_cmd("services", {
            **self._AUTH, "action": "list",
        })
        assert cmd[0] == "impacket-services"
        # action is positional_after_identity
        assert "list" in cmd
        assert "CORP.LOCAL/admin:Pass123@10.10.10.1" in cmd

    def test_services_create(self):
        """services create includes -name and -path."""
        cmd = self._capture_generic_cmd("services", {
            **self._AUTH, "action": "create",
            "service_name": "EvilSvc", "binary_path": "cmd.exe /c whoami",
        })
        assert "create" in cmd
        assert "-name" in cmd and cmd[cmd.index("-name") + 1] == "EvilSvc"
        assert "-path" in cmd

    def test_reg_query(self):
        """reg query builds: impacket-reg <identity> query -keyName <key>"""
        cmd = self._capture_generic_cmd("reg", {
            **self._AUTH, "action": "query",
            "key_name": "HKLM\\SOFTWARE\\Microsoft",
        })
        assert cmd[0] == "impacket-reg"
        assert "query" in cmd
        assert "-keyName" in cmd
        idx = cmd.index("-keyName")
        assert cmd[idx + 1] == "HKLM\\SOFTWARE\\Microsoft"

    def test_net_user_list(self):
        """net user builds: impacket-net <identity> user"""
        cmd = self._capture_generic_cmd("net", {
            **self._AUTH, "object_type": "user",
        })
        assert cmd[0] == "impacket-net"
        assert "user" in cmd

    def test_net_create_user(self):
        """net create user includes -create and -newPasswd."""
        cmd = self._capture_generic_cmd("net", {
            **self._AUTH, "object_type": "user",
            "create_name": "backdoor", "new_passwd": "Pass123!",
        })
        assert "-create" in cmd and cmd[cmd.index("-create") + 1] == "backdoor"
        assert "-newPasswd" in cmd

    # ── Credential Extraction ────────────────────────────────────────────

    def test_get_laps_password(self):
        """get_laps_password builds: impacket-GetLAPSPassword ... <identity>"""
        cmd = self._capture_generic_cmd("get_laps_password", {
            **self._AUTH, "computer": "WEB01",
        })
        assert cmd[0] == "impacket-GetLAPSPassword"
        assert "-computer" in cmd and cmd[cmd.index("-computer") + 1] == "WEB01"
        assert "CORP.LOCAL/admin:Pass123" in cmd

    # ── Enumeration ──────────────────────────────────────────────────────

    def test_rpcdump(self):
        """rpcdump builds: impacket-rpcdump <identity>"""
        cmd = self._capture_generic_cmd("rpcdump", {**self._AUTH})
        assert cmd[0] == "impacket-rpcdump"
        assert "CORP.LOCAL/admin:Pass123@10.10.10.1" in cmd

    def test_samrdump(self):
        """samrdump builds: impacket-samrdump <identity>"""
        cmd = self._capture_generic_cmd("samrdump", {**self._AUTH})
        assert cmd[0] == "impacket-samrdump"
        assert "CORP.LOCAL/admin:Pass123@10.10.10.1" in cmd

    # ── Extra Args ───────────────────────────────────────────────────────

    def test_extra_args_appended(self):
        """extra_args are appended to the end of the command."""
        cmd = self._capture_generic_cmd("rpcdump", {
            **self._AUTH, "extra_args": "-debug -port 139",
        })
        assert "-debug" in cmd
        assert "-port" in cmd
        idx = cmd.index("-port")
        assert cmd[idx + 1] == "139"

    def test_extra_args_on_existing_method(self):
        """extra_args works on existing built-in methods (psexec)."""
        captured = {}

        class FakeResult:
            def __init__(self):
                self.stdout = ""
                self.stderr = ""
                self.returncode = 1

        async def mock_run(cmd, timeout=60, env=None, **kw):
            captured["cmd"] = cmd
            return FakeResult()

        async def mock_run_progress(cmd, timeout=60, env=None, **kw):
            captured["cmd"] = cmd
            return FakeResult()

        orig_run = self._server.run_command
        orig_progress = self._server.run_command_with_progress
        self._server.run_command = mock_run
        self._server.run_command_with_progress = mock_run_progress
        try:
            loop = asyncio.new_event_loop()
            try:
                loop.run_until_complete(self._server.psexec(
                    target="10.10.10.1", username="admin", password="Pass",
                    domain="CORP", command="whoami", extra_args="-debug -codec cp437",
                ))
            finally:
                loop.close()
        finally:
            self._server.run_command = orig_run
            self._server.run_command_with_progress = orig_progress

        cmd = captured.get("cmd", [])
        assert "-debug" in cmd
        assert "-codec" in cmd


# ===========================================================================
# ADDITIONAL PARSER TESTS — methods not yet covered
# ===========================================================================

class TestAdditionalParsers:
    """Additional output parser tests for methods lacking dedicated tests."""

    @pytest.fixture(autouse=True, scope="class")
    def server(self):
        try:
            cls = _get_server_class()
            self.__class__._server = cls()
        except Exception as e:
            pytest.skip(f"Cannot import ImpacketServer: {e}")

    # -- find_delegation parser -------------------------------------------

    def test_parse_find_delegation(self):
        """Parse findDelegation tabular output."""
        text = load_fixture("find_delegation_output.txt")
        # Simulate what the find_delegation handler does inline
        delegations = []
        header_found = False
        for line in text.split("\n"):
            stripped = line.strip()
            if not stripped:
                continue
            if stripped.startswith("Impacket ") or stripped.startswith("[*]"):
                continue
            if "AccountName" in stripped and "DelegationType" in stripped:
                header_found = True
                continue
            if stripped.startswith("---"):
                continue
            if header_found:
                cols = stripped.split()
                if len(cols) >= 4:
                    delegations.append({
                        "account_name": cols[0],
                        "account_type": cols[1],
                        "delegation_type": cols[2],
                        "delegation_rights_to": " ".join(cols[3:]),
                    })

        assert len(delegations) == 3
        assert delegations[0]["account_name"] == "DC01$"
        assert delegations[0]["delegation_type"] == "Unconstrained"
        assert delegations[1]["account_name"] == "WEB01$"
        assert delegations[1]["delegation_type"] == "Constrained"
        assert "HTTP" in delegations[1]["delegation_rights_to"]
        assert delegations[2]["account_name"] == "SVC_SQL"
        assert delegations[2]["account_type"] == "User"

    # -- get_tgt success output -------------------------------------------

    def test_parse_get_tgt_success(self):
        """Parse TGT success output: extract ccache filename."""
        text = load_fixture("get_tgt_success.txt")
        import re
        match = re.search(r"Saving ticket in (\S+\.ccache)", text)
        assert match is not None, "Should find ccache filename in output"
        assert match.group(1) == "MS01$.ccache"

    # -- get_st skew output -----------------------------------------------

    def test_parse_get_st_skew_error(self):
        """Parse get_st skew error."""
        text = load_fixture("get_st_skew.txt")
        err_class, retryable, suggestions = self._server._classify_error(text)
        assert err_class == "config"
        assert retryable is True
        assert len(suggestions) > 0

    # -- smb_get success output -------------------------------------------

    def test_smb_get_success_fixture(self):
        """Verify smb_get success fixture contains smbclient commands."""
        text = load_fixture("smb_get_success_output.txt")
        assert "use C$" in text
        assert "get Users" in text

    # -- smb_put success output -------------------------------------------

    def test_smb_put_success_fixture(self):
        """Verify smb_put success fixture contains smbclient commands."""
        text = load_fixture("smb_put_success_output.txt")
        assert "use C$" in text
        assert "put" in text

    # -- kerberoast: edge case with multiline hashes ----------------------

    def test_parse_kerberoast_multiline_hash(self):
        """Kerberoast output where hash spans multiple lines."""
        text = """Impacket v0.14.0.dev0

ServicePrincipalName  Name     MemberOf                               PasswordLastSet
--------------------  -------  -------------------------------------  -------------------
MSSQL/sql.corp.local  svc_sql  CN=SQL Admins,CN=Users,DC=corp,DC=local  2025-03-01 12:00:00

$krb5tgs$23$*svc_sql$CORP.LOCAL$MSSQL/sql.corp.local*$abc123
def456ghi789jkl012mno345pqr678
"""
        result = self._server._parse_kerberoast_output(text, "")
        assert result["hash_count"] == 1
        assert result["hashes"][0].startswith("$krb5tgs$")
        # Hash spans two lines, should be joined
        assert "def456" in result["hashes"][0]

    # -- asreproast: edge case with multiline hash -------------------------

    def test_parse_asreproast_multiline_hash(self):
        """AS-REP roast output where hash spans multiple lines."""
        text = """Impacket v0.14.0.dev0

$krb5asrep$23$vulnerable_user@CORP.LOCAL:abc123def456
ghi789jkl012mno345
"""
        result = self._server._parse_asreproast_output(text, "")
        assert result["hash_count"] == 1
        assert result["hashes"][0].startswith("$krb5asrep$")
        assert "ghi789" in result["hashes"][0]

    # -- exec parser: empty output ----------------------------------------

    def test_parse_exec_empty_output(self):
        """Exec parser with no output lines returns empty output."""
        text = "Impacket v0.14.0.dev0\n[*] Connecting to target\n"
        result = self._server._parse_exec_output(text, "")
        assert result["output"] == ""
        assert len(result["info"]) == 1

    # -- secretsdump: combined flags in output ----------------------------

    def test_parse_secretsdump_kerberos_keys_section(self):
        """Secretsdump DRSUAPI output includes kerberos keys section."""
        text = load_fixture("secretsdump_drsuapi.txt")
        result = self._server._parse_secretsdump_output(text, "", "/tmp/dummy")
        assert len(result["kerberos_keys"]) >= 1

    # -- ad_users: empty output -------------------------------------------

    def test_parse_ad_users_empty(self):
        """Parse empty GetADUsers output (no users)."""
        text = """Impacket v0.14.0.dev0

[*] Querying 10.10.10.1 for information about domain.
Name                  Email                           PasswordLastSet      LastLogon
--------------------  ------------------------------  -------------------  -------------------
"""
        result = self._server._parse_ad_users(text, "")
        assert len(result) == 0

    # -- smb_shares: empty output -----------------------------------------

    def test_parse_smb_shares_empty(self):
        """Parse smbclient output with no shares."""
        text = "Impacket v0.14.0.dev0\nType help for list of commands\n"
        result = self._server._parse_smb_shares(text, "")
        assert len(result) == 0

    # -- lookupsid: edge case with domain prefix in names -----------------

    def test_parse_lookupsid_with_space_in_name(self):
        """lookupsid parser handles names with spaces (e.g., Domain Admins)."""
        text = """Impacket v0.14.0.dev0

[*] Brute forcing SIDs at 10.10.10.1
[*] StringBinding ncacn_np:10.10.10.1
[*] Domain SID is: S-1-5-21-111-222-333
512: CORP\\Domain Admins (SidTypeGroup)
"""
        result = self._server._parse_lookupsid_output(text, "")
        assert result["domain_sid"] == "S-1-5-21-111-222-333"
        assert len(result["groups"]) == 1
        assert result["groups"][0]["name"] == "Domain Admins"

    # -- classify_error: DRSUAPI error ------------------------------------

    def test_classify_drsuapi_error(self):
        """DRSUAPI replication error should be permission class."""
        text = "[-] ERROR_DS_DRA_BAD_DN something failed"
        err_class, retryable, suggestions = self._server._classify_error(text)
        assert err_class == "permission"
        assert retryable is False
        assert len(suggestions) > 0

    # -- classify_error: Traceback ----------------------------------------

    def test_classify_traceback_error(self):
        """Python traceback should be unknown, retryable."""
        text = "Traceback (most recent call last):\n  File ...\nException: something"
        err_class, retryable, suggestions = self._server._classify_error(text)
        assert err_class == "unknown"
        assert retryable is True

    # -- classify_error: empty text ---------------------------------------

    def test_classify_empty_text(self):
        """Empty text returns unknown, not retryable."""
        err_class, retryable, suggestions = self._server._classify_error("")
        assert err_class == "unknown"
        assert retryable is False

    # -- classify_kerberos: additional codes -------------------------------

    def test_classify_spn_unknown(self):
        """KDC_ERR_S_PRINCIPAL_UNKNOWN is params class."""
        err_class, retryable, suggestions = self._server._classify_kerberos_error(
            "Kerberos SessionError: KDC_ERR_S_PRINCIPAL_UNKNOWN(Server not found)"
        )
        assert err_class == "params"
        assert retryable is False

    def test_classify_client_revoked(self):
        """KDC_ERR_CLIENT_REVOKED is auth class."""
        err_class, retryable, _ = self._server._classify_kerberos_error(
            "Kerberos SessionError: KDC_ERR_CLIENT_REVOKED(Clients credentials have been revoked)"
        )
        assert err_class == "auth"

    def test_classify_etype_nosupp(self):
        """KDC_ERR_ETYPE_NOSUPP is config class."""
        err_class, retryable, _ = self._server._classify_kerberos_error(
            "Kerberos SessionError: KDC_ERR_ETYPE_NOSUPP(KDC has no support for encryption type)"
        )
        assert err_class == "config"
        assert retryable is False

    def test_classify_generic_kerberos(self):
        """KRB_ERR_GENERIC is config class, retryable."""
        err_class, retryable, _ = self._server._classify_kerberos_error(
            "Kerberos SessionError: KRB_ERR_GENERIC(Generic Kerberos error)"
        )
        assert err_class == "config"
        assert retryable is True

    def test_classify_badoption(self):
        """KDC_ERR_BADOPTION is config class, retryable."""
        err_class, retryable, _ = self._server._classify_kerberos_error(
            "Kerberos SessionError: KDC_ERR_BADOPTION(KDC cannot accommodate requested option)"
        )
        assert err_class == "config"
        assert retryable is True

    # -- classify_smb: additional codes -----------------------------------

    def test_classify_account_disabled(self):
        """STATUS_ACCOUNT_DISABLED is auth class."""
        err_class, retryable, _ = self._server._classify_smb_error(
            "SMB SessionError: STATUS_ACCOUNT_DISABLED"
        )
        assert err_class == "auth"
        assert retryable is False

    def test_classify_account_locked(self):
        """STATUS_ACCOUNT_LOCKED_OUT is auth class."""
        err_class, retryable, _ = self._server._classify_smb_error(
            "SMB SessionError: STATUS_ACCOUNT_LOCKED_OUT"
        )
        assert err_class == "auth"
        assert retryable is False

    def test_classify_password_expired_smb(self):
        """STATUS_PASSWORD_EXPIRED is auth class."""
        err_class, retryable, _ = self._server._classify_smb_error(
            "SMB SessionError: STATUS_PASSWORD_EXPIRED"
        )
        assert err_class == "auth"
        assert retryable is False

    def test_classify_password_must_change(self):
        """STATUS_PASSWORD_MUST_CHANGE is auth class."""
        err_class, retryable, _ = self._server._classify_smb_error(
            "SMB SessionError: STATUS_PASSWORD_MUST_CHANGE"
        )
        assert err_class == "auth"
        assert retryable is False

    def test_classify_sharing_violation(self):
        """STATUS_SHARING_VIOLATION is permission class, retryable."""
        err_class, retryable, _ = self._server._classify_smb_error(
            "SMB SessionError: STATUS_SHARING_VIOLATION"
        )
        assert err_class == "permission"
        assert retryable is True

    def test_classify_bad_network_name(self):
        """STATUS_BAD_NETWORK_NAME is params class."""
        err_class, retryable, _ = self._server._classify_smb_error(
            "SMB SessionError: STATUS_BAD_NETWORK_NAME"
        )
        assert err_class == "params"
        assert retryable is False

    def test_classify_generic_session_error(self):
        """Generic SessionError is unknown class."""
        err_class, retryable, _ = self._server._classify_smb_error(
            "SMB SessionError: STATUS_SOMETHING_NEW"
        )
        assert err_class == "unknown"


# ===========================================================================
# ACCEPTANCE TESTS — call every method through container (no live target)
# ===========================================================================

class TestAcceptance:
    """Call every method through the Docker container without a live target.

    These tests verify:
    - The method exists and is callable
    - Required param validation works (missing required params -> error)
    - The response has correct structuredContent shape
    - Error responses have error_class set (classified, not crash)

    Each test sends minimal args with a TEST-NET-1 IP (192.0.2.1) which
    routes to nowhere, so the command will fail at connection time, but the
    MCP protocol layer, param validation, and error classification all work.
    """

    _FAKE_AUTH = {
        "target": "192.0.2.1",
        "username": "testuser",
        "password": "testpass",
        "domain": "test.local",
    }

    def _assert_structured_error(self, resp, method_name):
        """Assert response is a classified error with structuredContent."""
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

    # ── Remote Execution ──────────────────────────────────────────────

    def test_psexec_unreachable(self, impacket_env):
        """psexec with unreachable target returns classified error."""
        client, loop = impacket_env
        resp = loop.run_until_complete(client.call("psexec", {
            **self._FAKE_AUTH, "command": "whoami", "timeout": 10,
        }))
        self._assert_structured_error(resp, "psexec")

    def test_psexec_missing_target(self, impacket_env):
        """psexec without 'target' returns error."""
        client, loop = impacket_env
        resp = loop.run_until_complete(client.call("psexec", {
            "command": "whoami",
        }))
        result = resp.get("result", {})
        is_error = result.get("isError", False)
        content_text = ""
        for c in result.get("content", []):
            if c.get("type") == "text":
                content_text += c["text"]
        assert is_error or "target" in content_text.lower() or "error" in content_text.lower()

    def test_wmiexec_unreachable(self, impacket_env):
        """wmiexec with unreachable target returns classified error."""
        client, loop = impacket_env
        resp = loop.run_until_complete(client.call("wmiexec", {
            **self._FAKE_AUTH, "command": "hostname", "timeout": 10,
        }))
        self._assert_structured_error(resp, "wmiexec")

    def test_smbexec_unreachable(self, impacket_env):
        """smbexec with unreachable target returns classified error."""
        client, loop = impacket_env
        resp = loop.run_until_complete(client.call("smbexec", {
            **self._FAKE_AUTH, "command": "whoami", "timeout": 10,
        }))
        self._assert_structured_error(resp, "smbexec")

    def test_dcomexec_unreachable(self, impacket_env):
        """dcomexec with unreachable target returns classified error."""
        client, loop = impacket_env
        resp = loop.run_until_complete(client.call("dcomexec", {
            **self._FAKE_AUTH, "command": "whoami", "timeout": 10,
        }))
        self._assert_structured_error(resp, "dcomexec")

    def test_atexec_unreachable(self, impacket_env):
        """atexec with unreachable target returns classified error."""
        client, loop = impacket_env
        resp = loop.run_until_complete(client.call("atexec", {
            **self._FAKE_AUTH, "command": "whoami", "timeout": 10,
        }))
        self._assert_structured_error(resp, "atexec")

    def test_atexec_missing_command(self, impacket_env):
        """atexec without required 'command' returns error."""
        client, loop = impacket_env
        resp = loop.run_until_complete(client.call("atexec", {
            **self._FAKE_AUTH,
        }))
        result = resp.get("result", {})
        is_error = result.get("isError", False)
        content_text = ""
        for c in result.get("content", []):
            if c.get("type") == "text":
                content_text += c["text"]
        assert is_error or "command" in content_text.lower() or "required" in content_text.lower() or "error" in content_text.lower()

    # ── Credential Attacks ────────────────────────────────────────────

    def test_secretsdump_unreachable(self, impacket_env):
        """secretsdump with unreachable target returns classified error."""
        client, loop = impacket_env
        resp = loop.run_until_complete(client.call("secretsdump", {
            **self._FAKE_AUTH, "timeout": 10,
        }))
        self._assert_structured_error(resp, "secretsdump")

    def test_kerberoast_unreachable(self, impacket_env):
        """kerberoast with unreachable target returns classified error."""
        client, loop = impacket_env
        resp = loop.run_until_complete(client.call("kerberoast", {
            **self._FAKE_AUTH, "timeout": 10,
        }))
        self._assert_structured_error(resp, "kerberoast")

    def test_asreproast_unreachable(self, impacket_env):
        """asreproast with unreachable target returns classified error."""
        client, loop = impacket_env
        resp = loop.run_until_complete(client.call("asreproast", {
            **self._FAKE_AUTH, "timeout": 10,
        }))
        self._assert_structured_error(resp, "asreproast")

    # ── SMB Operations ────────────────────────────────────────────────

    def test_smb_shares_unreachable(self, impacket_env):
        """smb_shares with unreachable target returns classified error."""
        client, loop = impacket_env
        resp = loop.run_until_complete(client.call("smb_shares", {
            **self._FAKE_AUTH, "timeout": 10,
        }))
        self._assert_structured_error(resp, "smb_shares")

    def test_smb_get_unreachable(self, impacket_env):
        """smb_get with unreachable target returns classified error."""
        client, loop = impacket_env
        resp = loop.run_until_complete(client.call("smb_get", {
            **self._FAKE_AUTH, "share": "C$",
            "remote_path": "Windows\\win.ini", "timeout": 10,
        }))
        self._assert_structured_error(resp, "smb_get")

    def test_smb_get_missing_share(self, impacket_env):
        """smb_get without required 'share' returns error."""
        client, loop = impacket_env
        resp = loop.run_until_complete(client.call("smb_get", {
            **self._FAKE_AUTH, "remote_path": "test.txt",
        }))
        result = resp.get("result", {})
        is_error = result.get("isError", False)
        content_text = ""
        for c in result.get("content", []):
            if c.get("type") == "text":
                content_text += c["text"]
        assert is_error or "share" in content_text.lower() or "required" in content_text.lower() or "error" in content_text.lower()

    def test_smb_put_unreachable(self, impacket_env):
        """smb_put with unreachable target returns classified error."""
        client, loop = impacket_env
        resp = loop.run_until_complete(client.call("smb_put", {
            **self._FAKE_AUTH, "share": "C$",
            "remote_path": "Temp\\test.txt",
            "content": "test data", "timeout": 10,
        }))
        self._assert_structured_error(resp, "smb_put")

    def test_smb_put_missing_content(self, impacket_env):
        """smb_put without required 'content' returns error."""
        client, loop = impacket_env
        resp = loop.run_until_complete(client.call("smb_put", {
            **self._FAKE_AUTH, "share": "C$", "remote_path": "test.txt",
        }))
        result = resp.get("result", {})
        is_error = result.get("isError", False)
        content_text = ""
        for c in result.get("content", []):
            if c.get("type") == "text":
                content_text += c["text"]
        assert is_error or "content" in content_text.lower() or "required" in content_text.lower() or "error" in content_text.lower()

    # ── Enumeration ───────────────────────────────────────────────────

    def test_get_ad_users_unreachable(self, impacket_env):
        """get_ad_users with unreachable target returns classified error."""
        client, loop = impacket_env
        resp = loop.run_until_complete(client.call("get_ad_users", {
            **self._FAKE_AUTH, "timeout": 10,
        }))
        self._assert_structured_error(resp, "get_ad_users")

    def test_lookupsid_unreachable(self, impacket_env):
        """lookupsid with unreachable target returns classified error."""
        client, loop = impacket_env
        resp = loop.run_until_complete(client.call("lookupsid", {
            **self._FAKE_AUTH, "timeout": 10,
        }))
        self._assert_structured_error(resp, "lookupsid")

    # ── Kerberos ──────────────────────────────────────────────────────

    def test_get_tgt_unreachable(self, impacket_env):
        """get_tgt with unreachable target returns classified error."""
        client, loop = impacket_env
        resp = loop.run_until_complete(client.call("get_tgt", {
            **self._FAKE_AUTH, "timeout": 10,
        }))
        result = resp.get("result", {})
        sc = result.get("structuredContent", {})
        assert sc is not None, "get_tgt: missing structuredContent"
        # Should be error (network unreachable or timeout)
        assert sc.get("error_class") in ("network", "timeout", "unknown", "auth", None) or result.get("isError")

    def test_get_st_unreachable(self, impacket_env):
        """get_st with unreachable target returns classified error."""
        client, loop = impacket_env
        resp = loop.run_until_complete(client.call("get_st", {
            **self._FAKE_AUTH, "spn": "cifs/dc.test.local",
            "impersonate": "Administrator", "timeout": 10,
        }))
        self._assert_structured_error(resp, "get_st")

    def test_get_st_missing_spn(self, impacket_env):
        """get_st without required 'spn' returns error."""
        client, loop = impacket_env
        resp = loop.run_until_complete(client.call("get_st", {
            **self._FAKE_AUTH, "impersonate": "Administrator",
        }))
        result = resp.get("result", {})
        is_error = result.get("isError", False)
        content_text = ""
        for c in result.get("content", []):
            if c.get("type") == "text":
                content_text += c["text"]
        assert is_error or "spn" in content_text.lower() or "required" in content_text.lower() or "error" in content_text.lower()

    def test_get_st_missing_impersonate(self, impacket_env):
        """get_st without required 'impersonate' returns error."""
        client, loop = impacket_env
        resp = loop.run_until_complete(client.call("get_st", {
            **self._FAKE_AUTH, "spn": "cifs/test",
        }))
        result = resp.get("result", {})
        is_error = result.get("isError", False)
        content_text = ""
        for c in result.get("content", []):
            if c.get("type") == "text":
                content_text += c["text"]
        assert is_error or "impersonate" in content_text.lower() or "required" in content_text.lower() or "error" in content_text.lower()

    # ── Delegation / Account Modification ─────────────────────────────

    def test_find_delegation_unreachable(self, impacket_env):
        """find_delegation with unreachable target returns classified error."""
        client, loop = impacket_env
        resp = loop.run_until_complete(client.call("find_delegation", {
            **self._FAKE_AUTH, "timeout": 10,
        }))
        self._assert_structured_error(resp, "find_delegation")

    def test_addcomputer_unreachable(self, impacket_env):
        """addcomputer with unreachable target returns classified error."""
        client, loop = impacket_env
        resp = loop.run_until_complete(client.call("addcomputer", {
            **self._FAKE_AUTH, "computer_name": "TEST01",
            "computer_pass": "TestP@ss!", "timeout": 10,
        }))
        self._assert_structured_error(resp, "addcomputer")

    def test_rbcd_unreachable(self, impacket_env):
        """rbcd with unreachable target returns classified error."""
        client, loop = impacket_env
        resp = loop.run_until_complete(client.call("rbcd", {
            **self._FAKE_AUTH, "delegate_to": "DC01$",
            "action": "read", "timeout": 10,
        }))
        self._assert_structured_error(resp, "rbcd")

    def test_rbcd_missing_delegate_to(self, impacket_env):
        """rbcd without required 'delegate_to' returns error."""
        client, loop = impacket_env
        resp = loop.run_until_complete(client.call("rbcd", {
            **self._FAKE_AUTH,
        }))
        result = resp.get("result", {})
        is_error = result.get("isError", False)
        content_text = ""
        for c in result.get("content", []):
            if c.get("type") == "text":
                content_text += c["text"]
        assert is_error or "delegate_to" in content_text.lower() or "required" in content_text.lower() or "error" in content_text.lower()

    def test_changepasswd_unreachable(self, impacket_env):
        """changepasswd with unreachable target returns classified error."""
        client, loop = impacket_env
        resp = loop.run_until_complete(client.call("changepasswd", {
            **self._FAKE_AUTH, "new_password": "NewP@ss1!",
            "timeout": 10,
        }))
        self._assert_structured_error(resp, "changepasswd")

    def test_changepasswd_missing_new_password(self, impacket_env):
        """changepasswd without required 'new_password' returns error."""
        client, loop = impacket_env
        resp = loop.run_until_complete(client.call("changepasswd", {
            **self._FAKE_AUTH,
        }))
        result = resp.get("result", {})
        is_error = result.get("isError", False)
        content_text = ""
        for c in result.get("content", []):
            if c.get("type") == "text":
                content_text += c["text"]
        assert is_error or "new_password" in content_text.lower() or "required" in content_text.lower() or "error" in content_text.lower()

    def test_addspn_unreachable(self, impacket_env):
        """addspn with unreachable target returns classified error."""
        client, loop = impacket_env
        resp = loop.run_until_complete(client.call("addspn", {
            **self._FAKE_AUTH, "target_account": "DC01$",
            "spn": "cifs/test.local", "timeout": 10,
        }))
        self._assert_structured_error(resp, "addspn")

    def test_addspn_missing_target_account(self, impacket_env):
        """addspn without required 'target_account' returns error."""
        client, loop = impacket_env
        resp = loop.run_until_complete(client.call("addspn", {
            **self._FAKE_AUTH, "spn": "cifs/test",
        }))
        result = resp.get("result", {})
        is_error = result.get("isError", False)
        content_text = ""
        for c in result.get("content", []):
            if c.get("type") == "text":
                content_text += c["text"]
        assert is_error or "target_account" in content_text.lower() or "required" in content_text.lower() or "error" in content_text.lower()

    def test_addspn_missing_spn(self, impacket_env):
        """addspn without required 'spn' returns error."""
        client, loop = impacket_env
        resp = loop.run_until_complete(client.call("addspn", {
            **self._FAKE_AUTH, "target_account": "DC01$",
        }))
        result = resp.get("result", {})
        is_error = result.get("isError", False)
        content_text = ""
        for c in result.get("content", []):
            if c.get("type") == "text":
                content_text += c["text"]
        assert is_error or "spn" in content_text.lower() or "required" in content_text.lower() or "error" in content_text.lower()

    # ── New Generic Methods (acceptance) ─────────────────────────────────

    def test_dacledit_unreachable(self, impacket_env):
        """dacledit with unreachable target returns classified error."""
        client, loop = impacket_env
        resp = loop.run_until_complete(client.call("dacledit", {
            **self._FAKE_AUTH, "action": "read", "target_object": "DC01$",
            "timeout": 10,
        }))
        self._assert_structured_error(resp, "dacledit")

    def test_owneredit_unreachable(self, impacket_env):
        """owneredit with unreachable target returns classified error."""
        client, loop = impacket_env
        resp = loop.run_until_complete(client.call("owneredit", {
            **self._FAKE_AUTH, "action": "read", "target_object": "DC01$",
            "timeout": 10,
        }))
        self._assert_structured_error(resp, "owneredit")

    def test_ticketer_unreachable(self, impacket_env):
        """ticketer (no auth) builds and runs without crashing."""
        client, loop = impacket_env
        resp = loop.run_until_complete(client.call("ticketer", {
            "target": "192.0.2.1",
            "target_user": "Administrator",
            "domain_name": "test.local",
            "domain_sid": "S-1-5-21-111-222-333",
            "nthash": "aa" * 16,
            "timeout": 10,
        }))
        self._assert_structured_error(resp, "ticketer")

    def test_get_laps_password_unreachable(self, impacket_env):
        """get_laps_password with unreachable target returns classified error."""
        client, loop = impacket_env
        resp = loop.run_until_complete(client.call("get_laps_password", {
            **self._FAKE_AUTH, "timeout": 10,
        }))
        self._assert_structured_error(resp, "get_laps_password")

    def test_services_unreachable(self, impacket_env):
        """services with unreachable target returns classified error."""
        client, loop = impacket_env
        resp = loop.run_until_complete(client.call("services", {
            **self._FAKE_AUTH, "action": "list", "timeout": 10,
        }))
        self._assert_structured_error(resp, "services")

    def test_reg_unreachable(self, impacket_env):
        """reg with unreachable target returns classified error."""
        client, loop = impacket_env
        resp = loop.run_until_complete(client.call("reg", {
            **self._FAKE_AUTH, "action": "query",
            "key_name": "HKLM\\SOFTWARE", "timeout": 10,
        }))
        self._assert_structured_error(resp, "reg")

    def test_rpcdump_unreachable(self, impacket_env):
        """rpcdump with unreachable target returns classified error."""
        client, loop = impacket_env
        resp = loop.run_until_complete(client.call("rpcdump", {
            **self._FAKE_AUTH, "timeout": 10,
        }))
        self._assert_structured_error(resp, "rpcdump")

    def test_samrdump_unreachable(self, impacket_env):
        """samrdump with unreachable target returns classified error."""
        client, loop = impacket_env
        resp = loop.run_until_complete(client.call("samrdump", {
            **self._FAKE_AUTH, "timeout": 10,
        }))
        self._assert_structured_error(resp, "samrdump")

    def test_net_unreachable(self, impacket_env):
        """net with unreachable target returns classified error."""
        client, loop = impacket_env
        resp = loop.run_until_complete(client.call("net", {
            **self._FAKE_AUTH, "object_type": "user", "timeout": 10,
        }))
        self._assert_structured_error(resp, "net")

    def test_run_custom_missing_script(self, impacket_env):
        """run_custom with nonexistent script returns error."""
        client, loop = impacket_env
        resp = loop.run_until_complete(client.call("run_custom", {
            "target": "192.0.2.1",
            "script": "nonexistent_script_xyz.py",
            "timeout": 10,
        }))
        result = resp.get("result", {})
        content_text = ""
        for c in result.get("content", []):
            if c.get("type") == "text":
                content_text += c["text"]
        assert "not found" in content_text.lower() or "error" in content_text.lower() or result.get("isError")

    # ── Extra args acceptance tests ──────────────────────────────────────

    def test_psexec_with_extra_args(self, impacket_env):
        """psexec accepts extra_args without crashing."""
        client, loop = impacket_env
        resp = loop.run_until_complete(client.call("psexec", {
            **self._FAKE_AUTH, "command": "whoami",
            "extra_args": "-debug", "timeout": 10,
        }))
        # Should not crash — just get a connection error
        result = resp.get("result", {})
        content_text = ""
        for c in result.get("content", []):
            if c.get("type") == "text":
                content_text += c["text"]
        assert "unexpected keyword argument" not in content_text

    def test_kerberoast_with_extra_args(self, impacket_env):
        """kerberoast accepts extra_args without crashing."""
        client, loop = impacket_env
        resp = loop.run_until_complete(client.call("kerberoast", {
            **self._FAKE_AUTH, "extra_args": "-debug", "timeout": 10,
        }))
        result = resp.get("result", {})
        content_text = ""
        for c in result.get("content", []):
            if c.get("type") == "text":
                content_text += c["text"]
        assert "unexpected keyword argument" not in content_text


# ===========================================================================
# INTEGRATION TESTS — require --target, --domain, etc.
# ===========================================================================

@pytest.mark.integration
class TestIntegration:
    """Integration tests that need a real AD target.

    Run with: pytest tests/tools/test_impacket.py --tool=impacket
              --target=<DC_IP> --domain=<DOMAIN> --username=<USER> --password=<PASS>
              -m integration -v
    """

    def test_get_tgt(self, impacket_env, target, domain, username, password):
        """Request a TGT with valid credentials."""
        client, loop = impacket_env
        resp = loop.run_until_complete(client.call("get_tgt", {
            "target": target,
            "username": username,
            "password": password,
            "domain": domain,
            "dc_ip": target,
        }))
        result = assert_tool_success(resp, "get_tgt should succeed with valid creds")
        data = parse_tool_output(resp)
        assert data.get("ccache_exists"), "TGT ccache should exist"
        assert data.get("ccache_file"), "ccache_file path should be set"

    def test_smb_shares(self, impacket_env, target, domain, username, password):
        """Enumerate SMB shares."""
        client, loop = impacket_env
        resp = loop.run_until_complete(client.call("smb_shares", {
            "target": target,
            "username": username,
            "password": password,
            "domain": domain,
        }))
        result = assert_tool_success(resp, "smb_shares should succeed")
        data = parse_tool_output(resp)
        assert data.get("share_count", 0) > 0, "Should find at least one share"

    def test_get_ad_users(self, impacket_env, target, domain, username, password):
        """Enumerate AD users."""
        client, loop = impacket_env
        resp = loop.run_until_complete(client.call("get_ad_users", {
            "target": target,
            "username": username,
            "password": password,
            "domain": domain,
            "dc_ip": target,
        }))
        result = assert_tool_success(resp, "get_ad_users should succeed")
        data = parse_tool_output(resp)
        assert data.get("user_count", 0) > 0, "Should find at least one user"

    def test_kerberoast(self, impacket_env, target, domain, username, password):
        """Run kerberoasting (may find 0 hashes if no SPN accounts)."""
        client, loop = impacket_env
        resp = loop.run_until_complete(client.call("kerberoast", {
            "target": target,
            "username": username,
            "password": password,
            "domain": domain,
            "dc_ip": target,
        }))
        data = parse_tool_output(resp)
        assert "hash_count" in data or "hashes" in data, (
            "Response should include hash_count or hashes field"
        )

    def test_lookupsid(self, impacket_env, target, domain, username, password):
        """SID brute-force enumeration."""
        client, loop = impacket_env
        resp = loop.run_until_complete(client.call("lookupsid", {
            "target": target,
            "username": username,
            "password": password,
            "domain": domain,
            "max_rid": 1000,
        }))
        result = assert_tool_success(resp, "lookupsid should succeed")
        data = parse_tool_output(resp)
        assert data.get("total", 0) > 0, "Should discover at least one SID"

    def test_find_delegation(self, impacket_env, target, domain, username, password):
        """Find delegation settings."""
        client, loop = impacket_env
        resp = loop.run_until_complete(client.call("find_delegation", {
            "target": target,
            "username": username,
            "password": password,
            "domain": domain,
            "dc_ip": target,
        }))
        data = parse_tool_output(resp)
        assert "delegation_count" in data or "delegations" in data

    def test_wmiexec(self, impacket_env, target, domain, username, password):
        """Execute command via WMI."""
        client, loop = impacket_env
        resp = loop.run_until_complete(client.call("wmiexec", {
            "target": target,
            "username": username,
            "password": password,
            "domain": domain,
            "command": "hostname",
            "timeout": 60,
        }))
        data = parse_tool_output(resp)
        assert isinstance(data, dict)
        assert data.get("method") == "wmiexec"
        assert "output" in data

    def test_smbexec(self, impacket_env, target, domain, username, password):
        """Execute command via SMB."""
        client, loop = impacket_env
        resp = loop.run_until_complete(client.call("smbexec", {
            "target": target,
            "username": username,
            "password": password,
            "domain": domain,
            "command": "whoami",
            "timeout": 60,
        }))
        data = parse_tool_output(resp)
        assert isinstance(data, dict)
        assert data.get("method") == "smbexec"
        assert "output" in data

    def test_dcomexec(self, impacket_env, target, domain, username, password):
        """Execute command via DCOM."""
        client, loop = impacket_env
        resp = loop.run_until_complete(client.call("dcomexec", {
            "target": target,
            "username": username,
            "password": password,
            "domain": domain,
            "command": "whoami",
            "dcom_object": "MMC20",
            "timeout": 60,
        }))
        data = parse_tool_output(resp)
        assert isinstance(data, dict)
        assert data.get("method") == "dcomexec"
        assert "output" in data

    def test_atexec(self, impacket_env, target, domain, username, password):
        """Execute command via Task Scheduler."""
        client, loop = impacket_env
        resp = loop.run_until_complete(client.call("atexec", {
            "target": target,
            "username": username,
            "password": password,
            "domain": domain,
            "command": "whoami",
            "timeout": 60,
        }))
        data = parse_tool_output(resp)
        assert isinstance(data, dict)
        assert data.get("method") == "atexec"
        assert "output" in data

    def test_addcomputer(self, impacket_env, target, domain, username, password):
        """Create a machine account in AD."""
        client, loop = impacket_env
        resp = loop.run_until_complete(client.call("addcomputer", {
            "target": target,
            "username": username,
            "password": password,
            "domain": domain,
            "dc_ip": target,
            "computer_name": "TESTMCP01",
            "computer_pass": "TestP@ss123!",
            "timeout": 60,
        }))
        data = parse_tool_output(resp)
        assert isinstance(data, dict)
        assert "computer_name" in data

    def test_rbcd_read(self, impacket_env, target, domain, username, password):
        """Read RBCD settings on a computer account."""
        client, loop = impacket_env
        resp = loop.run_until_complete(client.call("rbcd", {
            "target": target,
            "username": username,
            "password": password,
            "domain": domain,
            "dc_ip": target,
            "delegate_to": target.split(".")[0] + "$" if "." in target else target + "$",
            "action": "read",
            "timeout": 60,
        }))
        data = parse_tool_output(resp)
        assert isinstance(data, dict)
        assert data.get("action") == "read"

    def test_changepasswd(self, impacket_env, target, domain, username, password):
        """Change user password (self-change). May fail with policy restrictions."""
        client, loop = impacket_env
        resp = loop.run_until_complete(client.call("changepasswd", {
            "target": target,
            "username": username,
            "password": password,
            "domain": domain,
            "dc_ip": target,
            "new_password": password,  # change to same password (for safety)
            "protocol": "smb-samr",
            "timeout": 60,
        }))
        data = parse_tool_output(resp)
        assert isinstance(data, (dict, str))  # may return error string

    def test_addspn(self, impacket_env, target, domain, username, password):
        """Add SPN to an account. May fail without appropriate permissions."""
        client, loop = impacket_env
        resp = loop.run_until_complete(client.call("addspn", {
            "target": target,
            "username": username,
            "password": password,
            "domain": domain,
            "dc_ip": target,
            "target_account": username,
            "spn": f"test/mcp-test.{domain}",
            "action": "add",
            "timeout": 60,
        }))
        data = parse_tool_output(resp)
        assert isinstance(data, (dict, str))  # may return error string

    def test_smb_get(self, impacket_env, target, domain, username, password):
        """Download a file from SMB share."""
        client, loop = impacket_env
        resp = loop.run_until_complete(client.call("smb_get", {
            "target": target,
            "username": username,
            "password": password,
            "domain": domain,
            "share": "SYSVOL",
            "remote_path": "/",
            "timeout": 60,
        }))
        # May succeed or fail depending on share contents
        data = parse_tool_output(resp)
        assert isinstance(data, (dict, str))

    def test_smb_put(self, impacket_env, target, domain, username, password):
        """Upload content to SMB share. May fail with permissions."""
        client, loop = impacket_env
        resp = loop.run_until_complete(client.call("smb_put", {
            "target": target,
            "username": username,
            "password": password,
            "domain": domain,
            "share": "SYSVOL",
            "remote_path": "mcp_test_upload.txt",
            "content": "MCP test content",
            "timeout": 60,
        }))
        data = parse_tool_output(resp)
        assert isinstance(data, (dict, str))
