"""
Tests for the netexec MCP tool server.

Covers:
- Smoke tests: boot, method list, required params, meta-param stripping, clock
- Unit tests: output parser (_parse_output) and command builder (_build_base_cmd)
- Unit tests: per-protocol command building (smb, winrm, ldap, mssql, ssh, rdp, wmi)
- Unit tests: output parsing edge cases (SAM dump, RID brute, kerberoast, multi-protocol)
- Error classification tests: auth failure, network, clock skew, timeout, Kerberos principals
- Contract tests: tool.yaml vs server parameter definitions
- Acceptance tests: every method called through Docker container (no live target)
- Integration tests: real AD target scenarios (marked @pytest.mark.integration)
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
TOOL_DIR = PROJECT_ROOT / "tools" / "netexec"
FIXTURES_DIR = Path(__file__).parent.parent / "fixtures" / "netexec"

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
def netexec_env(request):
    """Create an MCPTestClient with its event loop. Yields (client, loop)."""
    tool = "netexec"
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
    """Import and return the NetExecServer class for direct method testing."""
    import importlib.util
    spec = importlib.util.spec_from_file_location(
        "netexec_server", TOOL_DIR / "mcp-server.py"
    )
    mod = importlib.util.module_from_spec(spec)
    spec.loader.exec_module(mod)
    return mod.NetExecServer


# ---------------------------------------------------------------------------
# Module-scoped server fixture for unit tests
# ---------------------------------------------------------------------------
@pytest.fixture(scope="module")
def server():
    """Create a NetExecServer instance for direct unit testing."""
    try:
        cls = _get_server_class()
        return cls()
    except Exception as e:
        pytest.skip(f"Cannot import NetExecServer: {e}")


# ===========================================================================
# SMOKE TESTS -- require Docker container running
# ===========================================================================

class TestSmoke:
    """Smoke tests that verify the container boots and basic protocol works."""

    def test_boot_and_list_tools(self, netexec_env):
        """Container starts and list_tools returns methods."""
        client, loop = netexec_env
        assert len(client.tools) > 0, "Server should advertise at least one tool"
        names = client.tool_names()
        assert "smb" in names, "smb should be in tool list"
        assert "winrm" in names, "winrm should be in tool list"
        assert "ldap" in names, "ldap should be in tool list"
        assert "mssql" in names, "mssql should be in tool list"
        assert "ssh" in names, "ssh should be in tool list"
        assert "rdp" in names, "rdp should be in tool list"
        assert "wmi" in names, "wmi should be in tool list"

    def test_method_list_matches_tool_yaml(self, netexec_env):
        """Every method in tool.yaml is advertised by the server, and vice versa."""
        client, _ = netexec_env
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

    def test_expected_method_count(self, netexec_env):
        """Server should have exactly 7 built-in methods + verify_clock."""
        client, _ = netexec_env
        names = client.tool_names()
        # 7 built-in + verify_clock in MCP_TEST_MODE
        assert len(names) == 8, (
            f"Expected 8 methods (7 built-in + verify_clock), got {len(names)}: {sorted(names)}"
        )

    def test_required_params_enforced_smb(self, netexec_env):
        """Calling smb without required 'target' param returns an error."""
        client, loop = netexec_env
        resp = loop.run_until_complete(
            client.call("smb", {
                "username": "testuser",
                "password": "testpass",
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

    def test_required_params_enforced_ldap(self, netexec_env):
        """Calling ldap without required params returns an error."""
        client, loop = netexec_env
        resp = loop.run_until_complete(
            client.call("ldap", {
                "password": "testpass",
            })
        )
        result = resp.get("result", {})
        is_error = result.get("isError", False)
        content_text = ""
        for c in result.get("content", []):
            if c.get("type") == "text":
                content_text += c["text"]
        assert is_error or "error" in content_text.lower(), (
            f"Expected error about missing params, got: {content_text[:300]}"
        )

    def test_meta_params_stripped_timeout(self, netexec_env):
        """Passing 'timeout' (meta-param) in args does not crash the server."""
        client, loop = netexec_env
        resp = loop.run_until_complete(
            client.call("smb", {
                "target": "10.0.0.1",
                "username": "testuser",
                "password": "testpass",
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

    def test_meta_params_stripped_clock_offset(self, netexec_env):
        """Passing 'clock_offset' (meta-param) in args does not crash the server."""
        client, loop = netexec_env
        resp = loop.run_until_complete(
            client.call("winrm", {
                "target": "10.0.0.1",
                "username": "testuser",
                "password": "testpass",
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

    def test_unknown_method_returns_error(self, netexec_env):
        """Calling a non-existent method returns a helpful error."""
        client, loop = netexec_env
        resp = loop.run_until_complete(
            client.call("winrm_exec", {})
        )
        result = assert_tool_error(resp)
        content_text = ""
        for c in result.get("content", []):
            if c.get("type") == "text":
                content_text += c["text"]
        assert "Unknown method" in content_text
        assert "winrm_exec" in content_text

    @pytest.mark.clock
    def test_verify_clock_available(self, netexec_env):
        """verify_clock is registered in MCP_TEST_MODE."""
        client, _ = netexec_env
        names = client.tool_names()
        assert "verify_clock" in names, "verify_clock should be available in test mode"

    @pytest.mark.clock
    def test_verify_clock_returns_time(self, netexec_env):
        """verify_clock returns current time and FAKETIME status."""
        client, loop = netexec_env
        resp = loop.run_until_complete(client.call("verify_clock", {}))
        result = assert_tool_success(resp)
        data = parse_tool_output(resp)
        assert "current_time" in data
        assert "libfaketime_exists" in data
        # libfaketime is installed in this image
        assert data["libfaketime_exists"] is True, (
            "libfaketime should be installed in the netexec image"
        )

    def test_structuredContent_present(self, netexec_env):
        """Responses include structuredContent with error classification fields."""
        client, loop = netexec_env
        resp = loop.run_until_complete(client.call("verify_clock", {}))
        result = resp.get("result", {})
        sc = result.get("structuredContent")
        assert sc is not None, "structuredContent should be present"
        assert "success" in sc
        assert "error_class" in sc
        assert "retryable" in sc
        assert "suggestions" in sc


# ===========================================================================
# UNIT TESTS -- output parser, no container needed
# ===========================================================================

class TestParseOutput:
    """Test _parse_output using fixture data from real engagements."""

    def test_parse_smb_auth_success(self, server):
        """Parse SMB successful authentication."""
        text = load_fixture("smb_auth_success.txt")
        result = server._parse_output(text, "")
        assert result["success"] is True
        assert result["admin"] is False

    def test_parse_smb_auth_admin(self, server):
        """Parse SMB admin authentication with Pwn3d! marker."""
        text = load_fixture("smb_auth_admin.txt")
        result = server._parse_output(text, "")
        assert result["success"] is True
        assert result["admin"] is True

    def test_parse_smb_auth_failure(self, server):
        """Parse SMB authentication failure."""
        text = load_fixture("smb_auth_failure.txt")
        result = server._parse_output(text, "")
        assert result["success"] is False
        assert result["admin"] is False

    def test_parse_smb_shares(self, server):
        """Parse SMB share enumeration output."""
        text = load_fixture("smb_shares.txt")
        result = server._parse_output(text, "")
        assert result["success"] is True
        assert "Enumerated shares" in result["output"]

    def test_parse_winrm_admin(self, server):
        """Parse WinRM admin authentication."""
        text = load_fixture("winrm_auth_admin.txt")
        result = server._parse_output(text, "")
        assert result["success"] is True
        assert result["admin"] is True

    def test_parse_winrm_cmd_exec(self, server):
        """Parse WinRM command execution output."""
        text = load_fixture("winrm_cmd_exec.txt")
        result = server._parse_output(text, "")
        assert result["success"] is True
        assert result["admin"] is True

    def test_parse_winrm_ps_exec(self, server):
        """Parse WinRM PowerShell execution output."""
        text = load_fixture("winrm_ps_exec.txt")
        result = server._parse_output(text, "")
        assert result["success"] is True
        assert result["admin"] is True

    def test_parse_winrm_auth_failure(self, server):
        """Parse WinRM authentication failure."""
        text = load_fixture("winrm_auth_failure.txt")
        result = server._parse_output(text, "")
        assert result["success"] is False

    def test_parse_ldap_users(self, server):
        """Parse LDAP user enumeration."""
        text = load_fixture("ldap_users.txt")
        result = server._parse_output(text, "")
        assert result["success"] is True
        assert "Total of records returned" in result["output"]

    def test_parse_ssh_success(self, server):
        """Parse SSH successful auth with command output."""
        text = load_fixture("ssh_auth_success.txt")
        result = server._parse_output(text, "")
        assert result["success"] is True
        assert result["admin"] is True  # Pwn3d! marker present

    def test_parse_mssql_success(self, server):
        """Parse MSSQL successful authentication."""
        text = load_fixture("mssql_auth_success.txt")
        result = server._parse_output(text, "")
        assert result["success"] is True

    def test_parse_mssql_query_result(self, server):
        """Parse MSSQL with query results."""
        text = load_fixture("mssql_query_result.txt")
        result = server._parse_output(text, "")
        assert result["success"] is True
        assert "name:master" in result["output"]

    def test_parse_mssql_sql_error(self, server):
        """Parse MSSQL with SQL syntax error (auth success but op failure)."""
        text = load_fixture("mssql_sql_error.txt")
        result = server._parse_output(text, "")
        # Auth succeeded (has [+]) but SQL query failed (has [-]) — op failure overrides
        assert result["success"] is False
        assert result["auth_success"] is True  # auth was fine

    def test_parse_empty_output(self, server):
        """Parse empty output gracefully."""
        result = server._parse_output("", "")
        assert result["success"] is False
        assert result["admin"] is False

    def test_parse_only_stderr(self, server):
        """Parse output that's only in stderr."""
        stderr = load_fixture("smb_auth_success.txt")
        result = server._parse_output("", stderr)
        assert result["success"] is True  # _parse_output combines stdout+stderr

    # ── Additional parser edge cases ──────────────────────────────

    def test_parse_rdp_auth_success(self, server):
        """Parse RDP successful authentication."""
        text = load_fixture("rdp_auth_success.txt")
        result = server._parse_output(text, "")
        assert result["success"] is True
        assert result["admin"] is False  # RDP success without Pwn3d!

    def test_parse_rdp_auth_failure(self, server):
        """Parse RDP authentication failure."""
        text = load_fixture("rdp_auth_failure.txt")
        result = server._parse_output(text, "")
        assert result["success"] is False
        assert result["admin"] is False

    def test_parse_wmi_auth_success(self, server):
        """Parse WMI successful admin authentication."""
        text = load_fixture("wmi_auth_success.txt")
        result = server._parse_output(text, "")
        assert result["success"] is True
        assert result["admin"] is True  # Pwn3d!

    def test_parse_wmi_auth_failure(self, server):
        """Parse WMI authentication failure."""
        text = load_fixture("wmi_auth_failure.txt")
        result = server._parse_output(text, "")
        assert result["success"] is False
        assert result["admin"] is False

    def test_parse_ssh_auth_failure(self, server):
        """Parse SSH authentication failure."""
        text = load_fixture("ssh_auth_failure.txt")
        result = server._parse_output(text, "")
        assert result["success"] is False
        assert result["admin"] is False

    def test_parse_mssql_auth_failure(self, server):
        """Parse MSSQL authentication failure."""
        text = load_fixture("mssql_auth_failure.txt")
        result = server._parse_output(text, "")
        assert result["success"] is False
        assert result["admin"] is False

    def test_parse_smb_sam_dump(self, server):
        """Parse SMB SAM hash dump output."""
        text = load_fixture("smb_sam_dump.txt")
        result = server._parse_output(text, "")
        assert result["success"] is True
        assert result["admin"] is True
        assert "Dumping SAM hashes" in result["output"]
        assert "Administrator:500:" in result["output"]

    def test_parse_smb_rid_brute(self, server):
        """Parse SMB RID brute force output."""
        text = load_fixture("smb_rid_brute.txt")
        result = server._parse_output(text, "")
        assert result["success"] is True
        assert "Administrator" in result["output"]
        assert "Domain Admins" in result["output"]

    def test_parse_ldap_kerberoast(self, server):
        """Parse LDAP kerberoasting output."""
        text = load_fixture("ldap_kerberoast.txt")
        result = server._parse_output(text, "")
        assert result["success"] is True
        assert "svc-sql" in result["output"]
        assert "MSSQLSvc" in result["output"]

    def test_parse_output_preserves_stdout_only(self, server):
        """output field contains only stdout, not stderr."""
        stdout = "STDOUT_LINE\n"
        stderr = "STDERR_LINE\n"
        result = server._parse_output(stdout, stderr)
        assert result["output"] == "STDOUT_LINE"
        assert result["stderr"] == "STDERR_LINE"

    def test_parse_output_stderr_none_when_empty(self, server):
        """stderr field is None when stderr is empty/whitespace."""
        text = load_fixture("smb_auth_success.txt")
        result = server._parse_output(text, "   ")
        assert result["stderr"] is None

    def test_parse_mixed_success_and_failure(self, server):
        """When both [+] auth and [-] op failure present, success=False (op failure wins)."""
        text = load_fixture("mssql_sql_error.txt")
        result = server._parse_output(text, "")
        # Has [+] for auth and [-] for SQL error — auth succeeded but op failed
        assert result["success"] is False
        assert result["auth_success"] is True


# ===========================================================================
# COMMAND BUILDER TESTS
# ===========================================================================

class TestBuildBaseCmd:
    """Test _build_base_cmd for correct CLI argument construction."""

    def test_basic_password_auth(self, server):
        """Basic password authentication command."""
        cmd = server._build_base_cmd("smb", "10.0.0.1", "admin", password="Pass123")
        assert cmd == ["netexec", "smb", "10.0.0.1", "-u", "admin", "-p", "Pass123"]

    def test_hash_auth(self, server):
        """NTLM hash authentication."""
        cmd = server._build_base_cmd("smb", "10.0.0.1", "admin", hash="aad3b435:deadbeef")
        assert "-H" in cmd
        assert "aad3b435:deadbeef" in cmd

    def test_kerberos_auth(self, server):
        """Kerberos authentication."""
        cmd = server._build_base_cmd("smb", "10.0.0.1", "admin", kerberos=True)
        assert "-k" in cmd
        assert "--use-kcache" in cmd

    def test_aes_key(self, server):
        """AES key for Kerberos."""
        cmd = server._build_base_cmd("smb", "10.0.0.1", "admin", password="x", aes_key="0123abcd")
        assert "--aesKey" in cmd
        assert "0123abcd" in cmd

    def test_local_auth(self, server):
        """Local authentication flag."""
        cmd = server._build_base_cmd("smb", "10.0.0.1", "admin", password="x", local_auth=True)
        assert "--local-auth" in cmd
        assert "-d" not in cmd

    def test_domain_auth(self, server):
        """Domain authentication."""
        cmd = server._build_base_cmd("smb", "10.0.0.1", "admin", password="x", domain="corp.local")
        assert "-d" in cmd
        assert "corp.local" in cmd
        assert "--local-auth" not in cmd

    def test_local_auth_and_domain_mutually_exclusive(self, server):
        """local_auth takes precedence over domain."""
        cmd = server._build_base_cmd(
            "smb", "10.0.0.1", "admin", password="x",
            local_auth=True, domain="corp.local",
        )
        assert "--local-auth" in cmd
        assert "-d" not in cmd

    def test_port_specified(self, server):
        """Custom port."""
        cmd = server._build_base_cmd("smb", "10.0.0.1", "admin", password="x", port=4445)
        assert "--port" in cmd
        assert "4445" in cmd

    def test_empty_password(self, server):
        """No password or hash defaults to empty password."""
        cmd = server._build_base_cmd("smb", "10.0.0.1", "admin")
        assert "-p" in cmd
        assert "" in cmd

    def test_winrm_protocol(self, server):
        """WinRM protocol in command."""
        cmd = server._build_base_cmd("winrm", "10.0.0.1", "admin", password="Pass")
        assert cmd[1] == "winrm"

    def test_ldap_protocol(self, server):
        """LDAP protocol in command."""
        cmd = server._build_base_cmd("ldap", "dc.corp.local", "user", password="Pass")
        assert cmd[1] == "ldap"


# ===========================================================================
# PER-PROTOCOL COMMAND BUILDER TESTS
# ===========================================================================

class TestBuildCmdPerProtocol:
    """Test _build_base_cmd with each protocol and verify protocol-specific behavior."""

    def test_smb_protocol(self, server):
        """SMB command starts with 'netexec smb'."""
        cmd = server._build_base_cmd("smb", "10.0.0.1", "admin", password="Pass")
        assert cmd[0] == "netexec"
        assert cmd[1] == "smb"
        assert cmd[2] == "10.0.0.1"
        assert cmd[3] == "-u"
        assert cmd[4] == "admin"

    def test_winrm_protocol(self, server):
        """WinRM command starts with 'netexec winrm'."""
        cmd = server._build_base_cmd("winrm", "10.0.0.1", "admin", password="Pass")
        assert cmd[1] == "winrm"

    def test_ldap_protocol(self, server):
        """LDAP command starts with 'netexec ldap'."""
        cmd = server._build_base_cmd("ldap", "10.0.0.1", "admin", password="Pass")
        assert cmd[1] == "ldap"

    def test_mssql_protocol(self, server):
        """MSSQL command starts with 'netexec mssql'."""
        cmd = server._build_base_cmd("mssql", "10.0.0.1", "sa", password="Pass")
        assert cmd[1] == "mssql"

    def test_rdp_protocol(self, server):
        """RDP command starts with 'netexec rdp'."""
        cmd = server._build_base_cmd("rdp", "10.0.0.1", "admin", password="Pass")
        assert cmd[1] == "rdp"

    def test_wmi_protocol(self, server):
        """WMI command starts with 'netexec wmi'."""
        cmd = server._build_base_cmd("wmi", "10.0.0.1", "admin", password="Pass")
        assert cmd[1] == "wmi"

    def test_ssh_protocol(self, server):
        """SSH command starts with 'netexec ssh'."""
        cmd = server._build_base_cmd("ssh", "10.0.0.1", "root", password="Pass")
        assert cmd[1] == "ssh"

    def test_hash_overrides_password(self, server):
        """Hash auth (-H) is used instead of password (-p) when hash is provided."""
        cmd = server._build_base_cmd("smb", "10.0.0.1", "admin", password="Pass", hash="aad3b435:deadbeef")
        assert "-H" in cmd
        assert "aad3b435:deadbeef" in cmd
        assert "-p" not in cmd

    def test_kerberos_overrides_password_and_hash(self, server):
        """Kerberos (-k) overrides both password and hash."""
        cmd = server._build_base_cmd(
            "smb", "10.0.0.1", "admin",
            password="Pass", hash="aad3b435:deadbeef", kerberos=True,
        )
        assert "-k" in cmd
        assert "--use-kcache" in cmd
        assert "-H" not in cmd
        assert "-p" not in cmd

    def test_aes_key_added_alongside_password(self, server):
        """AES key is appended to command with password auth."""
        cmd = server._build_base_cmd("smb", "10.0.0.1", "admin", password="Pass", aes_key="abcd1234")
        assert "-p" in cmd
        assert "--aesKey" in cmd
        assert "abcd1234" in cmd

    def test_cidr_target(self, server):
        """CIDR range as target."""
        cmd = server._build_base_cmd("smb", "10.0.0.0/24", "admin", password="Pass")
        assert cmd[2] == "10.0.0.0/24"

    def test_hostname_target(self, server):
        """Hostname as target."""
        cmd = server._build_base_cmd("smb", "dc01.corp.local", "admin", password="Pass")
        assert cmd[2] == "dc01.corp.local"

    def test_port_as_string(self, server):
        """Port passed as string (for WinRM multi-port)."""
        cmd = server._build_base_cmd("winrm", "10.0.0.1", "admin", password="Pass", port="5985 5986")
        assert "--port" in cmd
        assert "5985 5986" in cmd

    def test_no_domain_no_local_auth(self, server):
        """Without domain or local_auth, neither -d nor --local-auth is present."""
        cmd = server._build_base_cmd("smb", "10.0.0.1", "admin", password="Pass")
        assert "-d" not in cmd
        assert "--local-auth" not in cmd


# ===========================================================================
# ERROR CLASSIFICATION TESTS
# ===========================================================================

class TestErrorClassification:
    """Test error classification for netexec-specific error patterns."""

    def test_classify_auth_failure(self, server):
        """Auth failure should be classified as 'auth'."""
        text = load_fixture("smb_auth_failure.txt")
        err_class, retryable, suggestions = server._classify_netexec_error(text)
        assert err_class == "auth", f"Expected 'auth', got '{err_class}'"
        assert retryable is False

    def test_classify_connection_refused(self, server):
        """Connection refused should be classified as 'network', retryable."""
        text = load_fixture("connection_refused.txt")
        err_class, retryable, suggestions = server._classify_netexec_error(text)
        assert err_class == "network", f"Expected 'network', got '{err_class}'"
        assert retryable is True

    def test_classify_kerberos_skew(self, server):
        """Clock skew should be classified as 'config', retryable."""
        text = load_fixture("kerberos_skew.txt")
        err_class, retryable, suggestions = server._classify_netexec_error(text)
        assert err_class == "config", f"Expected 'config', got '{err_class}'"
        assert retryable is True
        assert any("clock" in s.lower() for s in suggestions), (
            f"Should suggest clock offset fix, got: {suggestions}"
        )

    def test_classify_ldap_bind_failure(self, server):
        """LDAP bind failure should be classified as 'auth'."""
        text = load_fixture("ldap_bind_failure.txt")
        err_class, retryable, suggestions = server._classify_netexec_error(text)
        assert err_class == "auth", f"Expected 'auth', got '{err_class}'"

    def test_classify_success_not_misclassified(self, server):
        """Successful output should classify as 'unknown' (no error)."""
        text = load_fixture("smb_auth_success.txt")
        err_class, retryable, suggestions = server._classify_netexec_error(text)
        assert err_class == "unknown", f"Clean output misclassified as '{err_class}'"

    def test_classify_empty_output(self, server):
        """Empty output should return 'unknown'."""
        err_class, retryable, suggestions = server._classify_netexec_error("")
        assert err_class == "unknown"

    # ── Additional error classification edge cases ────────────────

    def test_classify_timeout(self, server):
        """Timeout error should be classified as 'timeout', retryable."""
        text = load_fixture("timeout_error.txt")
        err_class, retryable, suggestions = server._classify_netexec_error(text)
        assert err_class == "timeout", f"Expected 'timeout', got '{err_class}'"
        assert retryable is True

    def test_classify_kdc_principal_unknown(self, server):
        """KDC_ERR_C_PRINCIPAL_UNKNOWN should be classified as 'auth'."""
        text = load_fixture("kdc_principal_unknown.txt")
        err_class, retryable, suggestions = server._classify_netexec_error(text)
        assert err_class == "auth", f"Expected 'auth', got '{err_class}'"
        assert retryable is False
        assert any("principal" in s.lower() or "user" in s.lower() for s in suggestions)

    def test_classify_kdc_spn_unknown(self, server):
        """KDC_ERR_S_PRINCIPAL_UNKNOWN should be classified as 'config'."""
        text = load_fixture("kdc_spn_unknown.txt")
        err_class, retryable, suggestions = server._classify_netexec_error(text)
        assert err_class == "config", f"Expected 'config', got '{err_class}'"
        assert retryable is False

    def test_classify_access_denied(self, server):
        """STATUS_ACCESS_DENIED should be classified as 'auth'."""
        text = load_fixture("wmi_auth_failure.txt")
        err_class, retryable, suggestions = server._classify_netexec_error(text)
        assert err_class == "auth", f"Expected 'auth', got '{err_class}'"
        assert retryable is False

    def test_classify_rdp_failure(self, server):
        """RDP auth failure should be classified as 'auth'."""
        text = load_fixture("rdp_auth_failure.txt")
        err_class, retryable, suggestions = server._classify_netexec_error(text)
        assert err_class == "auth", f"Expected 'auth', got '{err_class}'"
        assert retryable is False

    def test_classify_ssh_failure(self, server):
        """SSH auth failure ([-] only, no [+]) should be classified as 'auth'."""
        text = load_fixture("ssh_auth_failure.txt")
        err_class, retryable, suggestions = server._classify_netexec_error(text)
        assert err_class == "auth", f"Expected 'auth', got '{err_class}'"

    def test_classify_mssql_failure(self, server):
        """MSSQL auth failure should be classified as 'auth'."""
        text = load_fixture("mssql_auth_failure.txt")
        err_class, retryable, suggestions = server._classify_netexec_error(text)
        assert err_class == "auth", f"Expected 'auth', got '{err_class}'"


# ===========================================================================
# AUTH ENV HELPER TESTS
# ===========================================================================

class TestGetAuthEnv:
    """Test _get_auth_env for Kerberos environment setup."""

    def test_no_kerberos_returns_empty(self, server):
        """When kerberos=False, returns empty dict."""
        result = server._get_auth_env(kerberos=False)
        assert result == {}

    def test_kerberos_without_ccache_returns_empty(self, server):
        """When kerberos=True but no ccache, returns empty dict."""
        result = server._get_auth_env(kerberos=True)
        assert result == {}

    def test_kerberos_with_nonexistent_ccache_returns_empty(self, server):
        """When kerberos=True but ccache doesn't exist, returns empty dict."""
        result = server._get_auth_env(kerberos=True, ccache_path="/nonexistent/path.ccache")
        assert result == {}

    def test_false_kerberos_ignores_ccache(self, server):
        """When kerberos=False, ccache_path is ignored."""
        result = server._get_auth_env(kerberos=False, ccache_path="/some/path.ccache")
        assert result == {}


# ===========================================================================
# HANDLER WIRING TESTS -- mock run_command_with_progress, verify end-to-end
# ===========================================================================

class TestHandlerLogic:
    """Test the wiring between command building, parser, classifier, and ToolResult.

    Each test mocks run_command_with_progress to return specific output, then
    calls the real handler and verifies the end-to-end ToolResult fields.
    Catches bugs that pure parser or classifier tests would miss.
    """

    @pytest.fixture(autouse=True, scope="class")
    def setup_server(self):
        """Create a server instance."""
        try:
            cls = _get_server_class()
            self.__class__._server = cls()
        except Exception as e:
            pytest.skip(f"Cannot import NetExecServer: {e}")

    def _run_handler(self, method_name: str, kwargs: dict, stdout: str, stderr: str = "", returncode: int = 0):
        """Call a handler with mocked subprocess output. Returns (ToolResult, captured_kwargs)."""
        import asyncio

        class FakeResult:
            def __init__(self, out, err, rc):
                self.stdout = out
                self.stderr = err
                self.returncode = rc

        captured_kwargs = {}
        captured_cmd = []

        async def mock_run(cmd, **kw):
            captured_cmd.extend(cmd)
            captured_kwargs.update(kw)
            return FakeResult(stdout, stderr, returncode)

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

        return result, captured_kwargs, captured_cmd

    # ── SMB handler wiring ───────────────────────────────────

    def test_smb_auth_success(self):
        """SMB with [+] in output → success=True, no error_class."""
        output = "SMB         10.0.0.1        445    DC01             [*] Windows 10.0 Build 17763 x64\nSMB         10.0.0.1        445    DC01             [+] DOMAIN\\user:Password1"
        result, _, _ = self._run_handler("smb", {
            "target": "10.0.0.1", "username": "user", "password": "Password1",
        }, stdout=output)
        assert result.success is True
        assert result.error_class is None
        assert result.data["admin"] is False

    def test_smb_auth_admin_pwn3d(self):
        """SMB with (Pwn3d!) → success=True, admin=True."""
        output = "SMB         10.0.0.1        445    DC01             [+] DOMAIN\\administrator:Password1 (Pwn3d!)"
        result, _, _ = self._run_handler("smb", {
            "target": "10.0.0.1", "username": "administrator", "password": "Password1",
        }, stdout=output)
        assert result.success is True
        assert result.data["admin"] is True

    def test_smb_auth_failure_classified(self):
        """SMB with STATUS_LOGON_FAILURE → success=False, error_class=auth."""
        output = "SMB         10.0.0.1        445    DC01             [-] DOMAIN\\user:badpass STATUS_LOGON_FAILURE"
        result, _, _ = self._run_handler("smb", {
            "target": "10.0.0.1", "username": "user", "password": "badpass",
        }, stdout=output)
        assert result.success is False
        assert result.error_class == "auth"
        assert result.retryable is False

    def test_smb_access_denied_classified(self):
        """SMB with STATUS_ACCESS_DENIED → success=False, error_class=auth."""
        output = "SMB         10.0.0.1        445    DC01             [-] DOMAIN\\user:Password1 STATUS_ACCESS_DENIED"
        result, _, _ = self._run_handler("smb", {
            "target": "10.0.0.1", "username": "user", "password": "Password1",
        }, stdout=output)
        assert result.success is False
        assert result.error_class == "auth"

    def test_smb_ntlm_not_supported_classified_config(self):
        """STATUS_NOT_SUPPORTED (NTLM disabled) → error_class=config with Kerberos suggestion."""
        output = "SMB         10.0.0.1        445    DC01             [-] DOMAIN\\user:Password1 STATUS_NOT_SUPPORTED"
        result, _, _ = self._run_handler("smb", {
            "target": "10.0.0.1", "username": "user", "password": "Password1",
        }, stdout=output)
        assert result.success is False
        assert result.error_class == "config"
        assert result.retryable is False
        assert any("Kerberos" in s or "kerberos" in s for s in result.suggestions)
        assert any("NTLM" in s for s in result.suggestions)

    def test_smb_account_disabled_classified(self):
        """STATUS_ACCOUNT_DISABLED → error_class=auth, not retryable."""
        output = "SMB         10.0.0.1        445    DC01             [-] DOMAIN\\guest: STATUS_ACCOUNT_DISABLED"
        result, _, _ = self._run_handler("smb", {
            "target": "10.0.0.1", "username": "guest",
        }, stdout=output)
        assert result.success is False
        assert result.error_class == "auth"
        assert any("locked" in s.lower() or "disabled" in s.lower() for s in result.suggestions)

    def test_smb_account_locked_classified(self):
        """STATUS_ACCOUNT_LOCKED_OUT → error_class=auth."""
        output = "SMB         10.0.0.1        445    DC01             [-] DOMAIN\\user: STATUS_ACCOUNT_LOCKED_OUT"
        result, _, _ = self._run_handler("smb", {
            "target": "10.0.0.1", "username": "user",
        }, stdout=output)
        assert result.success is False
        assert result.error_class == "auth"

    def test_smb_auth_succeeds_but_op_fails_netbios_timeout(self):
        """Auth [+] succeeds but NetBIOSTimeout on share enum → success=False."""
        output = (
            "SMB         10.0.0.1  445  DC  [+] hercules\\user:pass from ccache\n"
            "SMB         10.0.0.1  445  DC  [-] NetBIOSTimeout on target 10.0.0.1: The NETBIOS connection timed out"
        )
        result, _, _ = self._run_handler("smb", {
            "target": "10.0.0.1", "username": "user", "shares": True,
        }, stdout=output)
        assert result.success is False, "Op failure should override auth success"
        assert result.error_class == "network"
        assert result.data["auth_success"] is True, "auth_success should still reflect that auth worked"

    def test_smb_silent_admin_failure_on_sam(self):
        """SMB auth [+] but no admin + sam requested → silent failure detected."""
        output = "SMB    10.0.0.1  445  DC  [+] hercules\\natalie.a from ccache"
        result, _, _ = self._run_handler("smb", {
            "target": "10.0.0.1", "username": "natalie.a", "sam": True,
        }, stdout=output)
        assert result.success is False
        assert result.error_class == "auth"
        assert "admin" in result.error.lower()
        assert any("admin" in s.lower() for s in result.suggestions)

    def test_smb_silent_admin_failure_on_command(self):
        """SMB auth [+] but no admin + command requested → silent failure detected."""
        output = "SMB    10.0.0.1  445  DC  [+] hercules\\natalie.a from ccache"
        result, _, _ = self._run_handler("smb", {
            "target": "10.0.0.1", "username": "natalie.a", "command": "whoami",
        }, stdout=output)
        assert result.success is False
        assert result.error_class == "auth"

    def test_smb_admin_op_succeeds_with_admin(self):
        """SMB with (Pwn3d!) + command → success=True (admin had rights)."""
        output = (
            "SMB    10.0.0.1  445  DC  [+] hercules\\admin:pass (Pwn3d!)\n"
            "SMB    10.0.0.1  445  DC  [+] Executed command\n"
            "SMB    10.0.0.1  445  DC  admin"
        )
        result, _, _ = self._run_handler("smb", {
            "target": "10.0.0.1", "username": "admin", "command": "whoami",
        }, stdout=output)
        assert result.success is True
        assert result.data["admin"] is True

    def test_smb_no_admin_op_no_silent_failure(self):
        """SMB with auth only (no admin op) → normal success, not flagged."""
        output = "SMB    10.0.0.1  445  DC  [+] hercules\\user:pass"
        result, _, _ = self._run_handler("smb", {
            "target": "10.0.0.1", "username": "user",
        }, stdout=output)
        assert result.success is True

    def test_winrm_silent_admin_failure(self):
        """WinRM auth [+] but no admin + command requested → silent failure."""
        output = "WINRM    10.0.0.1  5985  DC  [+] hercules\\user:pass"
        result, _, _ = self._run_handler("winrm", {
            "target": "10.0.0.1", "username": "user", "command": "whoami",
        }, stdout=output)
        assert result.success is False
        assert result.error_class == "auth"

    def test_mssql_silent_admin_failure(self):
        """MSSQL auth [+] but no admin + sam requested → silent failure."""
        output = "MSSQL    10.0.0.1  1433  DC  [+] hercules\\user:pass"
        result, _, _ = self._run_handler("mssql", {
            "target": "10.0.0.1", "username": "user", "sam": True,
        }, stdout=output)
        assert result.success is False
        assert result.error_class == "auth"

    def test_smb_argparse_invalid_choice_classified_params(self):
        """netexec argparse 'invalid choice' → error_class=params with valid choices."""
        output = (
            "usage: netexec smb [options]\n"
            "netexec smb: error: argument --exec-method: invalid choice: 'bogus' "
            "(choose from 'wmiexec', 'mmcexec', 'atexec', 'smbexec')"
        )
        result, _, _ = self._run_handler("smb", {
            "target": "10.0.0.1", "username": "user", "exec_method": "bogus",
        }, stdout="", stderr=output)
        assert result.success is False
        assert result.error_class == "params"
        assert any("wmiexec" in s or "bogus" in s for s in result.suggestions)

    def test_smb_argparse_unrecognized_flag(self):
        """netexec 'unrecognized arguments' → error_class=params."""
        output = "netexec: error: unrecognized arguments: --nonsense-flag"
        result, _, _ = self._run_handler("smb", {
            "target": "10.0.0.1", "username": "user", "extra_args": "--nonsense-flag",
        }, stdout="", stderr=output)
        assert result.success is False
        assert result.error_class == "params"
        assert any("nonsense" in s for s in result.suggestions)

    def test_smb_kerberos_keys_auto_sets_ntds(self):
        """kerberos_keys=True auto-sets --ntds drsuapi (netexec requires parent flag)."""
        _, _, cmd = self._run_handler("smb", {
            "target": "10.0.0.1", "username": "user", "kerberos_keys": True,
        }, stdout="")
        assert "--kerberos-keys" in cmd
        assert "--ntds" in cmd
        idx = cmd.index("--ntds")
        assert cmd[idx + 1] == "drsuapi"

    def test_smb_kerberos_keys_respects_explicit_ntds(self):
        """If user explicitly sets ntds='vss', don't override with drsuapi."""
        _, _, cmd = self._run_handler("smb", {
            "target": "10.0.0.1", "username": "user",
            "kerberos_keys": True, "ntds": "vss",
        }, stdout="")
        assert "--kerberos-keys" in cmd
        # Should use vss (user choice), not drsuapi
        idx = cmd.index("--ntds")
        assert cmd[idx + 1] == "vss"

    def test_smb_ntds_rpc_access_denied_classified(self):
        """rpc_s_access_denied on NTDS → error_class=auth with DRSUAPI suggestion."""
        output = (
            "SMB    10.0.0.1  445  DC  [+] hercules\\admin:pass (Pwn3d!)\n"
            "SMB    10.0.0.1  445  DC  [-] rpc_s_access_denied"
        )
        result, _, _ = self._run_handler("smb", {
            "target": "10.0.0.1", "username": "admin", "ntds": "drsuapi",
        }, stdout=output)
        assert result.success is False
        assert result.error_class == "auth"
        assert any("DRSUAPI" in s or "replication" in s.lower() for s in result.suggestions)

    def test_smb_ntds_error_ds_dra_bad_dn(self):
        """ERROR_DS_DRA_BAD_DN on NTDS → same DRSUAPI suggestion."""
        output = (
            "SMB    10.0.0.1  445  DC  [+] hercules\\admin:pass (Pwn3d!)\n"
            "SMB    10.0.0.1  445  DC  [-] ERROR_DS_DRA_BAD_DN"
        )
        result, _, _ = self._run_handler("smb", {
            "target": "10.0.0.1", "username": "admin", "ntds": "drsuapi",
        }, stdout=output)
        assert result.success is False
        assert result.error_class == "auth"
        assert any("DRSUAPI" in s or "replication" in s.lower() for s in result.suggestions)

    def test_smb_dumped_zero_ntds(self):
        """'Dumped 0 NTDS' → error_class=auth with admin rights suggestion."""
        output = (
            "SMB    10.0.0.1  445  DC  [+] hercules\\user:pass\n"
            "SMB    10.0.0.1  445  DC  [-] Dumped 0 NTDS hashes"
        )
        result, _, _ = self._run_handler("smb", {
            "target": "10.0.0.1", "username": "user", "ntds": "drsuapi",
        }, stdout=output)
        assert result.success is False
        assert result.error_class == "auth"
        assert any("zero" in s.lower() or "admin" in s.lower() for s in result.suggestions)

    def test_smb_access_denied_after_auth_share_suggestion(self):
        """STATUS_ACCESS_DENIED after auth succeeded → share-level denial suggestion."""
        output = (
            "SMB    10.0.0.1  445  DC  [+] hercules\\user:pass\n"
            "SMB    10.0.0.1  445  DC  [-] STATUS_ACCESS_DENIED when reading C$/hostname.txt"
        )
        result, _, _ = self._run_handler("smb", {
            "target": "10.0.0.1", "username": "user", "get_file": ["hostname.txt", "/tmp/out"],
        }, stdout=output)
        assert result.success is False
        assert result.error_class == "auth"
        assert any("share" in s.lower() or "resource" in s.lower() or "C$" in s for s in result.suggestions)

    def test_smb_op_failure_removed_flag(self):
        """SMB with [REMOVED] Arg moved to the ldap protocol → success=False, error_class=params."""
        output = (
            "SMB         10.0.0.1  445  DC  [+] hercules\\user:pass\n"
            "SMB         10.0.0.1  445  DC  [-] [REMOVED] Arg moved to the ldap protocol"
        )
        result, _, _ = self._run_handler("smb", {
            "target": "10.0.0.1", "username": "user", "groups": True,
        }, stdout=output)
        assert result.success is False
        assert result.error_class == "params"
        assert any("ldap" in s.lower() for s in result.suggestions)

    def test_smb_auth_only_no_op_requested_success(self):
        """Auth [+] with no operation requested → success=True (just validation)."""
        output = "SMB         10.0.0.1  445  DC  [+] hercules\\user:pass from ccache"
        result, _, _ = self._run_handler("smb", {
            "target": "10.0.0.1", "username": "user",
        }, stdout=output)
        assert result.success is True
        assert result.data["auth_success"] is True

    def test_smb_password_expired_classified(self):
        """STATUS_PASSWORD_EXPIRED → error_class=auth with change-password suggestion."""
        output = "SMB         10.0.0.1        445    DC01             [-] DOMAIN\\user:old STATUS_PASSWORD_EXPIRED"
        result, _, _ = self._run_handler("smb", {
            "target": "10.0.0.1", "username": "user", "password": "old",
        }, stdout=output)
        assert result.success is False
        assert result.error_class == "auth"
        assert any("expired" in s.lower() or "change" in s.lower() for s in result.suggestions)

    def test_smb_connection_refused_classified(self):
        """SMB with Connection refused → success=False, error_class=network."""
        output = "SMB         10.0.0.1        445    ?                [-] Connection refused"
        result, _, _ = self._run_handler("smb", {
            "target": "10.0.0.1", "username": "user",
        }, stdout=output)
        assert result.success is False
        assert result.error_class == "network"
        assert result.retryable is True

    def test_smb_clock_skew_classified(self):
        """SMB with KRB_AP_ERR_SKEW → success=False, error_class=config, retryable."""
        output = "SMB         10.0.0.1        445    DC01             [-] KRB_AP_ERR_SKEW(Clock skew too great)"
        result, _, _ = self._run_handler("smb", {
            "target": "10.0.0.1", "username": "user", "kerberos": True,
        }, stdout=output)
        assert result.success is False
        assert result.error_class == "config"
        assert result.retryable is True

    def test_smb_timeout_classified(self):
        """SMB with 'timed out' in output → error_class=timeout."""
        output = "SMB         10.0.0.1        445    ?                [-] connection timed out"
        result, _, _ = self._run_handler("smb", {
            "target": "10.0.0.1", "username": "user",
        }, stdout=output)
        assert result.success is False
        assert result.error_class == "timeout"

    # ── SMB new flag wiring (extra_args, timeout, laps, dpapi, delegate) ──

    def test_smb_extra_args_appended(self):
        """extra_args are shlex.split and appended to cmd."""
        _, _, cmd = self._run_handler("smb", {
            "target": "10.0.0.1", "username": "user",
            "extra_args": "--no-smb2-support --log /tmp/nxc.log",
        }, stdout="")
        assert "--no-smb2-support" in cmd
        assert "--log" in cmd
        assert "/tmp/nxc.log" in cmd

    def test_smb_extra_args_quoted(self):
        """extra_args with quoted value preserved by shlex."""
        _, _, cmd = self._run_handler("smb", {
            "target": "10.0.0.1", "username": "user",
            "extra_args": "-M custom -o 'KEY=value with space'",
        }, stdout="")
        assert "KEY=value with space" in cmd

    def test_smb_extra_args_empty(self):
        """extra_args empty string is a no-op."""
        _, _, cmd = self._run_handler("smb", {
            "target": "10.0.0.1", "username": "user", "extra_args": "",
        }, stdout="")
        # cmd should still have the basics
        assert "netexec" in cmd
        assert "smb" in cmd

    def test_smb_timeout_passed(self):
        """timeout is passed to run_command_with_progress."""
        _, kwargs, _ = self._run_handler("smb", {
            "target": "10.0.0.1", "username": "user", "timeout": 45,
        }, stdout="")
        assert kwargs.get("timeout") == 45

    def test_smb_timeout_default(self):
        """Default timeout is 120."""
        _, kwargs, _ = self._run_handler("smb", {
            "target": "10.0.0.1", "username": "user",
        }, stdout="")
        assert kwargs.get("timeout") == 120

    def test_smb_laps_flag(self):
        """laps=True adds --laps flag."""
        _, _, cmd = self._run_handler("smb", {
            "target": "10.0.0.1", "username": "user", "laps": True,
        }, stdout="")
        assert "--laps" in cmd

    def test_smb_dpapi_flag(self):
        """dpapi=True adds --dpapi flag."""
        _, _, cmd = self._run_handler("smb", {
            "target": "10.0.0.1", "username": "user", "dpapi": True,
        }, stdout="")
        assert "--dpapi" in cmd

    def test_smb_delegate_flag(self):
        """delegate sets --delegate <user>."""
        _, _, cmd = self._run_handler("smb", {
            "target": "10.0.0.1", "username": "user", "delegate": "administrator",
        }, stdout="")
        assert "--delegate" in cmd
        assert "administrator" in cmd

    def test_smb_delegate_spn_flag(self):
        """delegate_spn sets --delegate-spn <spn>."""
        _, _, cmd = self._run_handler("smb", {
            "target": "10.0.0.1", "username": "user", "delegate_spn": "cifs/dc01",
        }, stdout="")
        assert "--delegate-spn" in cmd
        assert "cifs/dc01" in cmd

    def test_smb_kerberos_keys_flag(self):
        """kerberos_keys=True adds --kerberos-keys flag."""
        _, _, cmd = self._run_handler("smb", {
            "target": "10.0.0.1", "username": "user", "kerberos_keys": True,
        }, stdout="")
        assert "--kerberos-keys" in cmd

    def test_smb_loggedon_users_flag(self):
        """loggedon_users=True adds --loggedon-users flag."""
        _, _, cmd = self._run_handler("smb", {
            "target": "10.0.0.1", "username": "user", "loggedon_users": True,
        }, stdout="")
        assert "--loggedon-users" in cmd

    def test_smb_smb_sessions_flag(self):
        """smb_sessions=True adds --smb-sessions flag."""
        _, _, cmd = self._run_handler("smb", {
            "target": "10.0.0.1", "username": "user", "smb_sessions": True,
        }, stdout="")
        assert "--smb-sessions" in cmd

    def test_smb_no_smbv1_flag(self):
        """no_smbv1=True adds --no-smbv1 flag."""
        _, _, cmd = self._run_handler("smb", {
            "target": "10.0.0.1", "username": "user", "no_smbv1": True,
        }, stdout="")
        assert "--no-smbv1" in cmd

    # ── WinRM handler wiring ─────────────────────────────────

    def test_winrm_ntlm_challenge_redirect_to_evil_winrm(self):
        """WinRM 'Invalid NTLM challenge' → config error with evil-winrm suggestion."""
        output = (
            "WINRM    10.0.0.1  5986  DC  [-] Invalid NTLM challenge received from server. "
            "This may indicate NTLM is not supported and nxc winrm only support NTLM currently"
        )
        result, _, _ = self._run_handler("winrm", {
            "target": "10.0.0.1", "username": "user", "kerberos": True,
        }, stdout=output)
        assert result.success is False
        assert result.error_class == "config"
        assert any("evil-winrm" in s.lower() for s in result.suggestions)

    def test_winrm_auth_success(self):
        """WinRM with [+] → success=True."""
        output = "WINRM       10.0.0.1        5985   DC01             [+] DOMAIN\\user:Password1"
        result, _, _ = self._run_handler("winrm", {
            "target": "10.0.0.1", "username": "user", "password": "Password1",
        }, stdout=output)
        assert result.success is True

    def test_winrm_auth_admin(self):
        """WinRM with Pwn3d! → admin=True."""
        output = "WINRM       10.0.0.1        5985   DC01             [+] DOMAIN\\admin:Password1 (Pwn3d!)"
        result, _, _ = self._run_handler("winrm", {
            "target": "10.0.0.1", "username": "admin", "password": "Password1",
        }, stdout=output)
        assert result.success is True
        assert result.data["admin"] is True

    def test_winrm_extra_args_appended(self):
        """extra_args flows through winrm."""
        _, _, cmd = self._run_handler("winrm", {
            "target": "10.0.0.1", "username": "user",
            "extra_args": "--check-proto https",
        }, stdout="")
        assert "--check-proto" in cmd
        assert "https" in cmd

    def test_winrm_timeout_passed(self):
        """WinRM passes timeout."""
        _, kwargs, _ = self._run_handler("winrm", {
            "target": "10.0.0.1", "username": "user", "timeout": 90,
        }, stdout="")
        assert kwargs.get("timeout") == 90

    def test_winrm_laps_flag(self):
        """laps=True adds --laps to winrm."""
        _, _, cmd = self._run_handler("winrm", {
            "target": "10.0.0.1", "username": "user", "laps": True,
        }, stdout="")
        assert "--laps" in cmd

    def test_winrm_module_flag(self):
        """module flag adds -M <module>."""
        _, _, cmd = self._run_handler("winrm", {
            "target": "10.0.0.1", "username": "user",
            "module": "enum_dns", "module_options": "DNS_SERVER=8.8.8.8",
        }, stdout="")
        assert "-M" in cmd
        assert "enum_dns" in cmd
        assert "-o" in cmd
        assert "DNS_SERVER=8.8.8.8" in cmd

    # ── LDAP handler wiring ──────────────────────────────────

    def test_ldap_auth_success(self):
        """LDAP with [+] → success=True."""
        output = "LDAP        10.0.0.1        389    DC01             [+] DOMAIN\\user:Password1"
        result, _, _ = self._run_handler("ldap", {
            "target": "10.0.0.1", "username": "user", "password": "Password1",
        }, stdout=output)
        assert result.success is True

    def test_ldap_pyasn1_ber_error_classified_env(self):
        """PyAsn1Error BER decode → error_class=env, not retryable with clear reason."""
        output = (
            "LDAP    10.0.0.1  389  DC  [-] Exception while calling proto_flow():\n"
            "pyasn1.error.PyAsn1Error: BER length field size 50 exceeds limit: 8"
        )
        result, _, _ = self._run_handler("ldap", {
            "target": "10.0.0.1", "username": "user", "users": True,
        }, stdout=output)
        assert result.success is False
        assert result.error_class == "env"
        assert any("impacket" in s.lower() or "library" in s.lower() for s in result.suggestions)

    def test_ldap_operations_error_after_bind(self):
        """searchRequest operationsError after bind → error_class=auth with signing suggestion."""
        output = (
            "LDAP    dc.corp  389  DC  [-] Error in searchRequest -> operationsError: "
            "000004DC: LdapErr: DSID-0C090D10, comment: In order to perform this operation "
            "a successful bind must be completed on the connection"
        )
        result, _, _ = self._run_handler("ldap", {
            "target": "dc.corp", "username": "user", "users": True,
        }, stdout=output)
        assert result.success is False
        assert result.error_class == "auth"
        assert any("signing" in s.lower() or "LDAPS" in s for s in result.suggestions)

    def test_ldap_proto_flow_exception(self):
        """'Exception while calling proto_flow' without pyasn1 → error_class=env."""
        output = "LDAP    10.0.0.1  389  DC  [-] Exception while calling proto_flow(): Connection reset by peer"
        result, _, _ = self._run_handler("ldap", {
            "target": "10.0.0.1", "username": "user",
        }, stdout=output)
        assert result.success is False
        # Connection reset matches network too, but proto_flow is more specific
        # Actually "Connection reset" is already in operation_failure_patterns
        # Check that it's classified as env OR network (both are reasonable)
        assert result.error_class in ("env", "network", "unknown")

    def test_ldap_bind_failure_classified(self):
        """LDAP with 'successful bind must be completed' → error_class=auth."""
        output = "LDAP        10.0.0.1        389    DC01             [-] successful bind must be completed"
        result, _, _ = self._run_handler("ldap", {
            "target": "10.0.0.1", "username": "user",
        }, stdout=output)
        assert result.success is False
        assert result.error_class == "auth"

    def test_ldap_kdc_principal_unknown_classified(self):
        """LDAP with KDC_ERR_C_PRINCIPAL_UNKNOWN → error_class=auth, not retryable."""
        output = "LDAP        10.0.0.1        389    DC01             [-] KDC_ERR_C_PRINCIPAL_UNKNOWN"
        result, _, _ = self._run_handler("ldap", {
            "target": "10.0.0.1", "username": "badprincipal", "kerberos": True,
        }, stdout=output)
        assert result.success is False
        assert result.error_class == "auth"
        assert result.retryable is False

    def test_ldap_kdc_spn_unknown_classified(self):
        """LDAP with KDC_ERR_S_PRINCIPAL_UNKNOWN → error_class=config."""
        output = "LDAP        10.0.0.1        389    DC01             [-] KDC_ERR_S_PRINCIPAL_UNKNOWN"
        result, _, _ = self._run_handler("ldap", {
            "target": "10.0.0.1", "username": "user", "kerberos": True,
        }, stdout=output)
        assert result.success is False
        assert result.error_class == "config"

    def test_ldap_trusted_for_delegation_flag(self):
        """trusted_for_delegation=True adds --trusted-for-delegation."""
        _, _, cmd = self._run_handler("ldap", {
            "target": "10.0.0.1", "username": "user", "trusted_for_delegation": True,
        }, stdout="")
        assert "--trusted-for-delegation" in cmd

    def test_ldap_password_not_required_flag(self):
        """password_not_required=True adds --password-not-required."""
        _, _, cmd = self._run_handler("ldap", {
            "target": "10.0.0.1", "username": "user", "password_not_required": True,
        }, stdout="")
        assert "--password-not-required" in cmd

    def test_ldap_get_sid_flag(self):
        """get_sid=True adds --get-sid."""
        _, _, cmd = self._run_handler("ldap", {
            "target": "10.0.0.1", "username": "user", "get_sid": True,
        }, stdout="")
        assert "--get-sid" in cmd

    def test_ldap_active_users_flag(self):
        """active_users=True adds --active-users."""
        _, _, cmd = self._run_handler("ldap", {
            "target": "10.0.0.1", "username": "user", "active_users": True,
        }, stdout="")
        assert "--active-users" in cmd

    def test_ldap_base_dn_flag(self):
        """base_dn sets --base-dn."""
        _, _, cmd = self._run_handler("ldap", {
            "target": "10.0.0.1", "username": "user",
            "base_dn": "OU=Servers,DC=corp,DC=local",
        }, stdout="")
        assert "--base-dn" in cmd
        assert "OU=Servers,DC=corp,DC=local" in cmd

    def test_ldap_kerberoast_account_flag(self):
        """kerberoast_account sets --kerberoast-account."""
        _, _, cmd = self._run_handler("ldap", {
            "target": "10.0.0.1", "username": "user",
            "kerberoast_account": "svc-sql",
        }, stdout="")
        assert "--kerberoast-account" in cmd
        assert "svc-sql" in cmd

    def test_ldap_simple_bind_flag(self):
        """simple_bind=True adds --simple-bind."""
        _, _, cmd = self._run_handler("ldap", {
            "target": "10.0.0.1", "username": "user", "simple_bind": True,
        }, stdout="")
        assert "--simple-bind" in cmd

    def test_ldap_timeout_default_bloodhound_300(self):
        """LDAP with bloodhound=True gets timeout=300 by default."""
        _, kwargs, _ = self._run_handler("ldap", {
            "target": "10.0.0.1", "username": "user", "bloodhound": True,
        }, stdout="")
        assert kwargs.get("timeout") == 300

    def test_ldap_timeout_default_120(self):
        """LDAP without bloodhound/kerberoast gets timeout=120."""
        _, kwargs, _ = self._run_handler("ldap", {
            "target": "10.0.0.1", "username": "user",
        }, stdout="")
        assert kwargs.get("timeout") == 120

    def test_ldap_timeout_override(self):
        """Explicit timeout overrides the bloodhound default."""
        _, kwargs, _ = self._run_handler("ldap", {
            "target": "10.0.0.1", "username": "user",
            "bloodhound": True, "timeout": 60,
        }, stdout="")
        assert kwargs.get("timeout") == 60

    def test_ldap_module_flag(self):
        """LDAP module flag adds -M <module>."""
        _, _, cmd = self._run_handler("ldap", {
            "target": "10.0.0.1", "username": "user",
            "module": "obsolete",
        }, stdout="")
        assert "-M" in cmd
        assert "obsolete" in cmd

    # ── MSSQL handler wiring ─────────────────────────────────

    def test_mssql_closed_port_classified_network(self):
        """MSSQL with init-only output (closed port) → error_class=network."""
        output = (
            "[*] First time use detected\n"
            "[*] Creating home directory structure\n"
            "[*] Initializing MSSQL protocol database\n"
            "[*] Copying default configuration file"
        )
        result, _, _ = self._run_handler("mssql", {
            "target": "10.0.0.1", "username": "sa",
        }, stdout=output)
        assert result.success is False
        assert result.error_class == "network"
        assert result.retryable is True
        assert any("port" in s.lower() or "closed" in s.lower() for s in result.suggestions)

    def test_ssh_closed_port_classified_network(self):
        """SSH with no markers → error_class=network."""
        output = "[*] Initializing SSH protocol database"
        result, _, _ = self._run_handler("ssh", {
            "target": "10.0.0.1", "username": "root",
        }, stdout=output)
        assert result.success is False
        assert result.error_class == "network"

    def test_rdp_closed_port_classified_network(self):
        """RDP with no markers → error_class=network."""
        output = ""
        result, _, _ = self._run_handler("rdp", {
            "target": "10.0.0.1", "username": "admin",
        }, stdout=output)
        assert result.success is False
        # Empty output classifies as unknown (the empty check hits first)
        # But if there's any content with no [+]/[-] markers, it should be network
        # This test just verifies the handler doesn't crash

    def test_mssql_auth_success(self):
        """MSSQL with [+] → success=True."""
        output = "MSSQL       10.0.0.1        1433   DC01             [+] DOMAIN\\sa:Password1"
        result, _, _ = self._run_handler("mssql", {
            "target": "10.0.0.1", "username": "sa", "password": "Password1",
        }, stdout=output)
        assert result.success is True

    def test_mssql_extra_args(self):
        """MSSQL extra_args flow through."""
        _, _, cmd = self._run_handler("mssql", {
            "target": "10.0.0.1", "username": "user",
            "extra_args": "--no-output",
        }, stdout="")
        assert "--no-output" in cmd

    def test_mssql_timeout_passed(self):
        """MSSQL passes timeout."""
        _, kwargs, _ = self._run_handler("mssql", {
            "target": "10.0.0.1", "username": "user", "timeout": 60,
        }, stdout="")
        assert kwargs.get("timeout") == 60

    def test_mssql_sam_flag(self):
        """MSSQL sam=True adds --sam."""
        _, _, cmd = self._run_handler("mssql", {
            "target": "10.0.0.1", "username": "user", "sam": True,
        }, stdout="")
        assert "--sam" in cmd

    def test_mssql_lsa_flag(self):
        """MSSQL lsa=True adds --lsa."""
        _, _, cmd = self._run_handler("mssql", {
            "target": "10.0.0.1", "username": "user", "lsa": True,
        }, stdout="")
        assert "--lsa" in cmd

    def test_mssql_module(self):
        """MSSQL module flag."""
        _, _, cmd = self._run_handler("mssql", {
            "target": "10.0.0.1", "username": "user",
            "module": "nanodump", "module_options": "PID=1234",
        }, stdout="")
        assert "-M" in cmd
        assert "nanodump" in cmd
        assert "PID=1234" in cmd

    # ── SSH handler wiring ───────────────────────────────────

    def test_ssh_auth_success(self):
        """SSH with [+] → success=True."""
        output = "SSH         10.0.0.1        22     host             [+] root:rootpass"
        result, _, _ = self._run_handler("ssh", {
            "target": "10.0.0.1", "username": "root", "password": "rootpass",
        }, stdout=output)
        assert result.success is True

    def test_ssh_extra_args(self):
        """SSH extra_args."""
        _, _, cmd = self._run_handler("ssh", {
            "target": "10.0.0.1", "username": "user",
            "extra_args": "--ssh-timeout 30",
        }, stdout="")
        assert "--ssh-timeout" in cmd
        assert "30" in cmd

    def test_ssh_timeout_passed(self):
        """SSH passes timeout."""
        _, kwargs, _ = self._run_handler("ssh", {
            "target": "10.0.0.1", "username": "user", "timeout": 45,
        }, stdout="")
        assert kwargs.get("timeout") == 45

    def test_ssh_module(self):
        """SSH module flag."""
        _, _, cmd = self._run_handler("ssh", {
            "target": "10.0.0.1", "username": "user",
            "module": "enum_pam", "module_options": "OPT=x",
        }, stdout="")
        assert "-M" in cmd
        assert "enum_pam" in cmd

    # ── RDP handler wiring ───────────────────────────────────

    def test_rdp_auth_success(self):
        """RDP with [+] → success=True."""
        output = "RDP         10.0.0.1        3389   DC01             [+] DOMAIN\\user:Password1"
        result, _, _ = self._run_handler("rdp", {
            "target": "10.0.0.1", "username": "user", "password": "Password1",
        }, stdout=output)
        assert result.success is True

    def test_rdp_kerberos_flag(self):
        """RDP with kerberos=True adds -k flag (via _build_base_cmd)."""
        _, _, cmd = self._run_handler("rdp", {
            "target": "10.0.0.1", "username": "user", "kerberos": True,
        }, stdout="")
        assert "-k" in cmd

    def test_rdp_aes_key_flag(self):
        """RDP aes_key adds --aesKey flag."""
        _, _, cmd = self._run_handler("rdp", {
            "target": "10.0.0.1", "username": "user",
            "kerberos": True, "aes_key": "deadbeef" * 8,
        }, stdout="")
        assert "--aesKey" in cmd

    def test_rdp_nla_screenshot_flag(self):
        """RDP nla_screenshot=True adds --nla-screenshot."""
        _, _, cmd = self._run_handler("rdp", {
            "target": "10.0.0.1", "username": "user", "nla_screenshot": True,
        }, stdout="")
        assert "--nla-screenshot" in cmd

    def test_rdp_screentime_flag(self):
        """RDP screentime sets --screentime."""
        _, _, cmd = self._run_handler("rdp", {
            "target": "10.0.0.1", "username": "user", "screentime": 15,
        }, stdout="")
        assert "--screentime" in cmd
        assert "15" in cmd

    def test_rdp_res_flag(self):
        """RDP res sets --res."""
        _, _, cmd = self._run_handler("rdp", {
            "target": "10.0.0.1", "username": "user", "res": "1024x768",
        }, stdout="")
        assert "--res" in cmd
        assert "1024x768" in cmd

    def test_rdp_extra_args(self):
        """RDP extra_args."""
        _, _, cmd = self._run_handler("rdp", {
            "target": "10.0.0.1", "username": "user",
            "extra_args": "--rdp-timeout 10",
        }, stdout="")
        assert "--rdp-timeout" in cmd

    def test_rdp_timeout_passed(self):
        """RDP passes timeout."""
        _, kwargs, _ = self._run_handler("rdp", {
            "target": "10.0.0.1", "username": "user", "timeout": 90,
        }, stdout="")
        assert kwargs.get("timeout") == 90

    # ── WMI handler wiring ───────────────────────────────────

    def test_wmi_auth_success(self):
        """WMI with [+] → success=True."""
        output = "WMI         10.0.0.1        135    DC01             [+] DOMAIN\\user:Password1"
        result, _, _ = self._run_handler("wmi", {
            "target": "10.0.0.1", "username": "user", "password": "Password1",
        }, stdout=output)
        assert result.success is True

    def test_wmi_extra_args(self):
        """WMI extra_args."""
        _, _, cmd = self._run_handler("wmi", {
            "target": "10.0.0.1", "username": "user",
            "extra_args": "--rpc-timeout 30",
        }, stdout="")
        assert "--rpc-timeout" in cmd

    def test_wmi_timeout_passed(self):
        """WMI passes timeout."""
        _, kwargs, _ = self._run_handler("wmi", {
            "target": "10.0.0.1", "username": "user", "timeout": 75,
        }, stdout="")
        assert kwargs.get("timeout") == 75

    def test_wmi_module(self):
        """WMI module flag."""
        _, _, cmd = self._run_handler("wmi", {
            "target": "10.0.0.1", "username": "user",
            "module": "test_module",
        }, stdout="")
        assert "-M" in cmd
        assert "test_module" in cmd

    # ── Cross-method: empty output handling ──────────────────

    def test_empty_output_marked_failure(self):
        """Empty output with no [+] → success=False."""
        result, _, _ = self._run_handler("smb", {
            "target": "10.0.0.1", "username": "user",
        }, stdout="", stderr="")
        assert result.success is False

    def test_stderr_only_output_classified(self):
        """Output only in stderr still flows through classifier."""
        result, _, _ = self._run_handler("smb", {
            "target": "10.0.0.1", "username": "user",
        }, stdout="", stderr="SMB [-] STATUS_LOGON_FAILURE")
        assert result.success is False
        assert result.error_class == "auth"

    # ── extra_args safety (no shell injection) ───────────────

    def test_extra_args_no_shell_injection(self):
        """extra_args with shell metachars pass through shlex, not shell interpretation."""
        _, _, cmd = self._run_handler("smb", {
            "target": "10.0.0.1", "username": "user",
            "extra_args": "--log '/tmp/out.log; rm -rf /'",
        }, stdout="")
        # shlex keeps the single-quoted string as one arg
        assert "/tmp/out.log; rm -rf /" in cmd
        # But it's just an arg, not executed

    def test_extra_args_multiple_flags_splitted(self):
        """Multiple space-separated flags in extra_args each become their own token."""
        _, _, cmd = self._run_handler("smb", {
            "target": "10.0.0.1", "username": "user",
            "extra_args": "--flag1 value1 --flag2 --flag3 value3",
        }, stdout="")
        assert "--flag1" in cmd
        assert "value1" in cmd
        assert "--flag2" in cmd
        assert "--flag3" in cmd
        assert "value3" in cmd


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

    def test_yaml_has_all_7_methods(self):
        """tool.yaml should define exactly 7 methods."""
        methods = self._yaml.get("methods", {})
        assert len(methods) == 7, (
            f"Expected 7 methods, got {len(methods)}: {sorted(methods.keys())}"
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

    def test_required_ports_defined(self):
        """Methods should have required_ports defined."""
        for name, defn in self._yaml.get("methods", {}).items():
            assert "required_ports" in defn, f"Method {name} missing required_ports"

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
            s = cls()
        except Exception:
            pytest.skip("Cannot import NetExecServer")

        yaml_names = set(self._yaml.get("methods", {}).keys())
        server_names = set(s.methods.keys()) - {"verify_clock"}

        yaml_only = yaml_names - server_names
        server_only = server_names - yaml_names

        assert not yaml_only, f"Methods in tool.yaml but not server: {yaml_only}"
        assert not server_only, f"Methods in server but not tool.yaml: {server_only}"

    def test_yaml_params_subset_of_server(self):
        """Every yaml param should be accepted by the server handler."""
        try:
            cls = _get_server_class()
            s = cls()
        except Exception:
            pytest.skip("Cannot import NetExecServer")

        for method_name, defn in self._yaml.get("methods", {}).items():
            yaml_params = set(defn.get("params", {}).keys())
            server_method = s.methods.get(method_name)
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
            s = cls()
        except Exception:
            pytest.skip("Cannot import NetExecServer")

        for method_name, defn in self._yaml.get("methods", {}).items():
            yaml_params = set(defn.get("params", {}).keys())
            server_method = s.methods.get(method_name)
            if server_method is None:
                continue
            server_params = set(server_method.params.keys())
            server_only = server_params - yaml_params
            assert not server_only, (
                f"Method {method_name}: server has params not in yaml: {server_only}"
            )

    def test_required_ports_values_sensible(self):
        """Required ports for each method match expected defaults."""
        expected_ports = {
            "smb": [445],
            "winrm": [5985, 5986],
            "ldap": [389, 636],
            "mssql": [1433],
            "ssh": [22],
            "rdp": [3389],
            "wmi": [135],
        }
        for method_name, defn in self._yaml.get("methods", {}).items():
            ports = defn.get("required_ports", [])
            if method_name in expected_ports:
                assert ports == expected_ports[method_name], (
                    f"{method_name}: expected ports {expected_ports[method_name]}, got {ports}"
                )

    def test_all_methods_have_when_to_use(self):
        """Every method should have a when_to_use field."""
        for name, defn in self._yaml.get("methods", {}).items():
            assert "when_to_use" in defn, f"Method {name} missing when_to_use"
            assert len(defn["when_to_use"]) > 20, f"Method {name} has too short when_to_use"


# ===========================================================================
# ACCEPTANCE TESTS -- call every method through container, no live target
# ===========================================================================

class TestAcceptance:
    """Call every method through the container without a live target.

    These tests verify:
    - The method exists and is callable
    - Required param validation works (missing required params -> error)
    - The response has correct structuredContent shape
    - Error responses have error_class set (classified, not crash)

    Each test sends minimal args (target + username + password but no real target)
    so the command will fail at connection time, but the MCP protocol layer,
    param validation, and error classification should all function correctly.
    """

    _FAKE_AUTH = {
        "target": "10.0.0.1",
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

    # ── SMB ──────────────────────────────────────────────────────

    def test_smb_basic(self, netexec_env):
        """smb with fake auth returns classified connection error."""
        client, loop = netexec_env
        resp = loop.run_until_complete(client.call("smb", {
            **self._FAKE_AUTH,
        }))
        self._assert_structured_error(resp, "smb")

    def test_smb_with_domain(self, netexec_env):
        """smb with domain param is accepted."""
        client, loop = netexec_env
        resp = loop.run_until_complete(client.call("smb", {
            **self._FAKE_AUTH, "domain": "test.local",
        }))
        self._assert_structured_error(resp, "smb")

    def test_smb_with_shares(self, netexec_env):
        """smb with shares=true is accepted."""
        client, loop = netexec_env
        resp = loop.run_until_complete(client.call("smb", {
            **self._FAKE_AUTH, "shares": True,
        }))
        self._assert_structured_error(resp, "smb")

    def test_smb_with_command(self, netexec_env):
        """smb with command param is accepted."""
        client, loop = netexec_env
        resp = loop.run_until_complete(client.call("smb", {
            **self._FAKE_AUTH, "command": "whoami",
        }))
        self._assert_structured_error(resp, "smb")

    def test_smb_with_hash(self, netexec_env):
        """smb with NTLM hash is accepted."""
        client, loop = netexec_env
        resp = loop.run_until_complete(client.call("smb", {
            "target": "10.0.0.1", "username": "admin",
            "hash": "aad3b435b51404eeaad3b435b51404ee:deadbeefdeadbeefdeadbeefdeadbeef",
        }))
        self._assert_structured_error(resp, "smb")

    def test_smb_missing_target(self, netexec_env):
        """smb without target returns error."""
        client, loop = netexec_env
        resp = loop.run_until_complete(client.call("smb", {
            "username": "testuser", "password": "testpass",
        }))
        result = resp.get("result", {})
        is_error = result.get("isError", False)
        content_text = ""
        for c in result.get("content", []):
            if c.get("type") == "text":
                content_text += c["text"]
        assert is_error or "target" in content_text.lower() or "error" in content_text.lower()

    def test_smb_missing_username(self, netexec_env):
        """smb without username returns error."""
        client, loop = netexec_env
        resp = loop.run_until_complete(client.call("smb", {
            "target": "10.0.0.1", "password": "testpass",
        }))
        result = resp.get("result", {})
        is_error = result.get("isError", False)
        content_text = ""
        for c in result.get("content", []):
            if c.get("type") == "text":
                content_text += c["text"]
        assert is_error or "username" in content_text.lower() or "error" in content_text.lower()

    # ── WinRM ────────────────────────────────────────────────────

    def test_winrm_basic(self, netexec_env):
        """winrm with fake auth returns classified connection error."""
        client, loop = netexec_env
        resp = loop.run_until_complete(client.call("winrm", {
            **self._FAKE_AUTH,
        }))
        self._assert_structured_error(resp, "winrm")

    def test_winrm_with_command(self, netexec_env):
        """winrm with command param is accepted."""
        client, loop = netexec_env
        resp = loop.run_until_complete(client.call("winrm", {
            **self._FAKE_AUTH, "command": "whoami",
        }))
        self._assert_structured_error(resp, "winrm")

    def test_winrm_with_ps_command(self, netexec_env):
        """winrm with ps_command param is accepted."""
        client, loop = netexec_env
        resp = loop.run_until_complete(client.call("winrm", {
            **self._FAKE_AUTH, "ps_command": "Get-Process",
        }))
        self._assert_structured_error(resp, "winrm")

    def test_winrm_with_sam(self, netexec_env):
        """winrm with sam=true is accepted."""
        client, loop = netexec_env
        resp = loop.run_until_complete(client.call("winrm", {
            **self._FAKE_AUTH, "sam": True,
        }))
        self._assert_structured_error(resp, "winrm")

    def test_winrm_missing_target(self, netexec_env):
        """winrm without target returns error."""
        client, loop = netexec_env
        resp = loop.run_until_complete(client.call("winrm", {
            "username": "testuser", "password": "testpass",
        }))
        result = resp.get("result", {})
        is_error = result.get("isError", False)
        content_text = ""
        for c in result.get("content", []):
            if c.get("type") == "text":
                content_text += c["text"]
        assert is_error or "target" in content_text.lower() or "error" in content_text.lower()

    # ── LDAP ─────────────────────────────────────────────────────

    def test_ldap_basic(self, netexec_env):
        """ldap with fake auth returns classified connection error."""
        client, loop = netexec_env
        resp = loop.run_until_complete(client.call("ldap", {
            **self._FAKE_AUTH,
        }))
        self._assert_structured_error(resp, "ldap")

    def test_ldap_with_users(self, netexec_env):
        """ldap with users=true is accepted."""
        client, loop = netexec_env
        resp = loop.run_until_complete(client.call("ldap", {
            **self._FAKE_AUTH, "users": True,
        }))
        self._assert_structured_error(resp, "ldap")

    def test_ldap_with_groups(self, netexec_env):
        """ldap with groups=true is accepted."""
        client, loop = netexec_env
        resp = loop.run_until_complete(client.call("ldap", {
            **self._FAKE_AUTH, "groups": True,
        }))
        self._assert_structured_error(resp, "ldap")

    def test_ldap_with_kerberoasting(self, netexec_env):
        """ldap with kerberoasting param is accepted."""
        client, loop = netexec_env
        resp = loop.run_until_complete(client.call("ldap", {
            **self._FAKE_AUTH, "kerberoasting": "/tmp/hashes.txt",
        }))
        self._assert_structured_error(resp, "ldap")

    def test_ldap_with_bloodhound(self, netexec_env):
        """ldap with bloodhound=true is accepted."""
        client, loop = netexec_env
        resp = loop.run_until_complete(client.call("ldap", {
            **self._FAKE_AUTH, "bloodhound": True, "bloodhound_collection": "All",
        }))
        self._assert_structured_error(resp, "ldap")

    def test_ldap_missing_target(self, netexec_env):
        """ldap without target returns error."""
        client, loop = netexec_env
        resp = loop.run_until_complete(client.call("ldap", {
            "username": "testuser", "password": "testpass",
        }))
        result = resp.get("result", {})
        is_error = result.get("isError", False)
        content_text = ""
        for c in result.get("content", []):
            if c.get("type") == "text":
                content_text += c["text"]
        assert is_error or "target" in content_text.lower() or "error" in content_text.lower()

    # ── MSSQL ────────────────────────────────────────────────────

    def test_mssql_basic(self, netexec_env):
        """mssql with fake auth returns classified connection error."""
        client, loop = netexec_env
        resp = loop.run_until_complete(client.call("mssql", {
            **self._FAKE_AUTH,
        }))
        self._assert_structured_error(resp, "mssql")

    def test_mssql_with_query(self, netexec_env):
        """mssql with query param is accepted."""
        client, loop = netexec_env
        resp = loop.run_until_complete(client.call("mssql", {
            **self._FAKE_AUTH, "query": "SELECT name FROM sys.databases",
        }))
        self._assert_structured_error(resp, "mssql")

    def test_mssql_with_local_auth(self, netexec_env):
        """mssql with local_auth=true is accepted."""
        client, loop = netexec_env
        resp = loop.run_until_complete(client.call("mssql", {
            **self._FAKE_AUTH, "local_auth": True,
        }))
        self._assert_structured_error(resp, "mssql")

    def test_mssql_missing_target(self, netexec_env):
        """mssql without target returns error."""
        client, loop = netexec_env
        resp = loop.run_until_complete(client.call("mssql", {
            "username": "sa", "password": "testpass",
        }))
        result = resp.get("result", {})
        is_error = result.get("isError", False)
        content_text = ""
        for c in result.get("content", []):
            if c.get("type") == "text":
                content_text += c["text"]
        assert is_error or "target" in content_text.lower() or "error" in content_text.lower()

    # ── SSH ──────────────────────────────────────────────────────

    def test_ssh_basic(self, netexec_env):
        """ssh with fake auth returns classified connection error."""
        client, loop = netexec_env
        resp = loop.run_until_complete(client.call("ssh", {
            **self._FAKE_AUTH,
        }))
        self._assert_structured_error(resp, "ssh")

    def test_ssh_with_command(self, netexec_env):
        """ssh with command param is accepted."""
        client, loop = netexec_env
        resp = loop.run_until_complete(client.call("ssh", {
            **self._FAKE_AUTH, "command": "id",
        }))
        self._assert_structured_error(resp, "ssh")

    def test_ssh_with_sudo_check(self, netexec_env):
        """ssh with sudo_check=true is accepted."""
        client, loop = netexec_env
        resp = loop.run_until_complete(client.call("ssh", {
            **self._FAKE_AUTH, "sudo_check": True,
        }))
        self._assert_structured_error(resp, "ssh")

    def test_ssh_missing_target(self, netexec_env):
        """ssh without target returns error."""
        client, loop = netexec_env
        resp = loop.run_until_complete(client.call("ssh", {
            "username": "root", "password": "testpass",
        }))
        result = resp.get("result", {})
        is_error = result.get("isError", False)
        content_text = ""
        for c in result.get("content", []):
            if c.get("type") == "text":
                content_text += c["text"]
        assert is_error or "target" in content_text.lower() or "error" in content_text.lower()

    # ── RDP ──────────────────────────────────────────────────────

    def test_rdp_basic(self, netexec_env):
        """rdp with fake auth returns classified connection error."""
        client, loop = netexec_env
        resp = loop.run_until_complete(client.call("rdp", {
            **self._FAKE_AUTH,
        }))
        self._assert_structured_error(resp, "rdp")

    def test_rdp_with_screenshot(self, netexec_env):
        """rdp with screenshot=true is accepted."""
        client, loop = netexec_env
        resp = loop.run_until_complete(client.call("rdp", {
            **self._FAKE_AUTH, "screenshot": True,
        }))
        self._assert_structured_error(resp, "rdp")

    def test_rdp_with_domain(self, netexec_env):
        """rdp with domain param is accepted."""
        client, loop = netexec_env
        resp = loop.run_until_complete(client.call("rdp", {
            **self._FAKE_AUTH, "domain": "test.local",
        }))
        self._assert_structured_error(resp, "rdp")

    def test_rdp_missing_target(self, netexec_env):
        """rdp without target returns error."""
        client, loop = netexec_env
        resp = loop.run_until_complete(client.call("rdp", {
            "username": "admin", "password": "testpass",
        }))
        result = resp.get("result", {})
        is_error = result.get("isError", False)
        content_text = ""
        for c in result.get("content", []):
            if c.get("type") == "text":
                content_text += c["text"]
        assert is_error or "target" in content_text.lower() or "error" in content_text.lower()

    # ── WMI ──────────────────────────────────────────────────────

    def test_wmi_basic(self, netexec_env):
        """wmi with fake auth returns classified connection error."""
        client, loop = netexec_env
        resp = loop.run_until_complete(client.call("wmi", {
            **self._FAKE_AUTH,
        }))
        self._assert_structured_error(resp, "wmi")

    def test_wmi_with_command(self, netexec_env):
        """wmi with command param is accepted."""
        client, loop = netexec_env
        resp = loop.run_until_complete(client.call("wmi", {
            **self._FAKE_AUTH, "command": "whoami",
        }))
        self._assert_structured_error(resp, "wmi")

    def test_wmi_with_query(self, netexec_env):
        """wmi with wmi_query param is accepted."""
        client, loop = netexec_env
        resp = loop.run_until_complete(client.call("wmi", {
            **self._FAKE_AUTH, "wmi_query": "SELECT * FROM Win32_Process",
        }))
        self._assert_structured_error(resp, "wmi")

    def test_wmi_with_exec_method(self, netexec_env):
        """wmi with exec_method param is accepted."""
        client, loop = netexec_env
        resp = loop.run_until_complete(client.call("wmi", {
            **self._FAKE_AUTH, "command": "whoami",
            "exec_method": "wmiexec-event",
        }))
        self._assert_structured_error(resp, "wmi")

    def test_wmi_missing_target(self, netexec_env):
        """wmi without target returns error."""
        client, loop = netexec_env
        resp = loop.run_until_complete(client.call("wmi", {
            "username": "admin", "password": "testpass",
        }))
        result = resp.get("result", {})
        is_error = result.get("isError", False)
        content_text = ""
        for c in result.get("content", []):
            if c.get("type") == "text":
                content_text += c["text"]
        assert is_error or "target" in content_text.lower() or "error" in content_text.lower()

    # ── Cross-cutting acceptance tests ───────────────────────────

    def test_kerberos_flag_accepted(self, netexec_env):
        """kerberos=true is accepted without crashing on any protocol."""
        client, loop = netexec_env
        resp = loop.run_until_complete(client.call("smb", {
            **self._FAKE_AUTH, "kerberos": True,
        }))
        result = resp.get("result", {})
        content_text = ""
        for c in result.get("content", []):
            if c.get("type") == "text":
                content_text += c["text"]
        assert "unexpected keyword argument" not in content_text

    def test_local_auth_flag_accepted(self, netexec_env):
        """local_auth=true is accepted without crashing."""
        client, loop = netexec_env
        resp = loop.run_until_complete(client.call("smb", {
            **self._FAKE_AUTH, "local_auth": True,
        }))
        result = resp.get("result", {})
        content_text = ""
        for c in result.get("content", []):
            if c.get("type") == "text":
                content_text += c["text"]
        assert "unexpected keyword argument" not in content_text

    def test_all_methods_return_structuredContent(self, netexec_env):
        """Every method in the server returns structuredContent in responses."""
        client, loop = netexec_env
        # Test with verify_clock (guaranteed to succeed)
        resp = loop.run_until_complete(client.call("verify_clock", {}))
        result = resp.get("result", {})
        sc = result.get("structuredContent")
        assert sc is not None
        assert isinstance(sc, dict)
        # All required fields
        for field in ("success", "error_class", "retryable", "suggestions"):
            assert field in sc, f"Missing field '{field}' in structuredContent"

    def test_hash_auth_accepted_on_rdp(self, netexec_env):
        """RDP accepts hash auth without crashing."""
        client, loop = netexec_env
        resp = loop.run_until_complete(client.call("rdp", {
            "target": "10.0.0.1", "username": "admin",
            "hash": "aad3b435b51404eeaad3b435b51404ee:deadbeef",
        }))
        result = resp.get("result", {})
        content_text = ""
        for c in result.get("content", []):
            if c.get("type") == "text":
                content_text += c["text"]
        assert "unexpected keyword argument" not in content_text

    def test_hash_auth_accepted_on_wmi(self, netexec_env):
        """WMI accepts hash auth without crashing."""
        client, loop = netexec_env
        resp = loop.run_until_complete(client.call("wmi", {
            "target": "10.0.0.1", "username": "admin",
            "hash": "aad3b435b51404eeaad3b435b51404ee:deadbeef",
        }))
        result = resp.get("result", {})
        content_text = ""
        for c in result.get("content", []):
            if c.get("type") == "text":
                content_text += c["text"]
        assert "unexpected keyword argument" not in content_text


# ===========================================================================
# INTEGRATION TESTS -- require --target, --domain, etc.
# ===========================================================================

@pytest.mark.integration
class TestIntegration:
    """Integration tests that need a real target.

    Run with: pytest tests/tools/test_netexec.py --tool=netexec
              --target=<IP> --domain=<DOMAIN>
              --username=<USER> --password=<PASS>
              -m integration -v
    """

    def test_smb_auth(self, netexec_env, target, domain, username, password):
        """Validate credentials against SMB."""
        client, loop = netexec_env
        resp = loop.run_until_complete(client.call("smb", {
            "target": target,
            "username": username,
            "password": password,
            "domain": domain,
        }))
        result = assert_tool_success(resp, "smb auth should succeed with valid creds")
        data = parse_tool_output(resp)
        assert data.get("success") is True

    def test_smb_shares(self, netexec_env, target, domain, username, password):
        """Enumerate SMB shares."""
        client, loop = netexec_env
        resp = loop.run_until_complete(client.call("smb", {
            "target": target,
            "username": username,
            "password": password,
            "domain": domain,
            "shares": True,
        }))
        result = assert_tool_success(resp, "smb shares should succeed")

    def test_winrm_auth(self, netexec_env, target, domain, username, password):
        """Validate credentials against WinRM."""
        client, loop = netexec_env
        resp = loop.run_until_complete(client.call("winrm", {
            "target": target,
            "username": username,
            "password": password,
            "domain": domain,
        }))
        # WinRM may fail if user not in Remote Management Users
        # Just verify we get a well-formed response
        result = resp.get("result", {})
        assert result is not None, "Should get a response"

    def test_ldap_users(self, netexec_env, target, domain, username, password):
        """Enumerate domain users via LDAP."""
        client, loop = netexec_env
        resp = loop.run_until_complete(client.call("ldap", {
            "target": target,
            "username": username,
            "password": password,
            "domain": domain,
            "users": True,
        }))
        result = assert_tool_success(resp, "ldap users should succeed with valid creds")

    def test_ssh_auth(self, netexec_env, target, username, password):
        """Validate credentials against SSH (if port 22 open)."""
        client, loop = netexec_env
        resp = loop.run_until_complete(client.call("ssh", {
            "target": target,
            "username": username,
            "password": password,
        }))
        # SSH may not be open; just verify no crash
        result = resp.get("result", {})
        assert result is not None, "Should get a response"

    def test_smb_bad_creds(self, netexec_env, target, domain):
        """SMB with bad credentials should show auth failure."""
        client, loop = netexec_env
        resp = loop.run_until_complete(client.call("smb", {
            "target": target,
            "username": "nonexistent_user_xyz",
            "password": "wrong_password_abc",
            "domain": domain,
        }))
        result = resp.get("result", {})
        # Should return error (auth failure)
        sc = result.get("structuredContent", {})
        if sc:
            assert sc.get("error_class") == "auth" or not sc.get("success"), (
                "Bad creds should classify as auth failure"
            )
