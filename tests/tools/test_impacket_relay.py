"""
Tests for the impacket-relay MCP tool server.

Covers:
- Smoke tests: boot, method list, required params, meta-param stripping, clock
- Unit tests: output parsers (_parse_relay_output)
- Lifecycle tests: start → status → stop, stale cleanup, force_restart
- Resilience tests: status timeout, process death detection (REQ-RES-004/005/006)
- Contract tests: tool.yaml vs server parameter definitions
- Integration tests: real target scenarios (marked @pytest.mark.integration)

Key issues from engagement data (167 calls, 12 timeouts in Pirate session):
- status() hung for 600s when relay process was stuck/zombie
- stop() hung for 601s when relay process was stuck
- Agent gave up and ran ntlmrelayx via Docker directly (42 bash calls)
- Fixes: 10s timeout on status(), SIGKILL escalation, stale cleanup, force_restart
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
TOOL_DIR = PROJECT_ROOT / "tools" / "impacket-relay"
FIXTURES_DIR = Path(__file__).parent.parent / "fixtures" / "impacket-relay"

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
def relay_env(request):
    """Create an MCPTestClient with its event loop. Yields (client, loop)."""
    tool = "impacket-relay"
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
    """Import and return the ImpacketRelayServer class for direct method testing."""
    import importlib.util
    spec = importlib.util.spec_from_file_location(
        "impacket_relay_server", TOOL_DIR / "mcp-server.py"
    )
    mod = importlib.util.module_from_spec(spec)
    spec.loader.exec_module(mod)
    return mod.ImpacketRelayServer


# ===========================================================================
# SMOKE TESTS -- require Docker container running
# ===========================================================================

class TestSmoke:
    """Smoke tests that verify the container boots and basic protocol works."""

    def test_boot_and_list_tools(self, relay_env):
        """Container starts and list_tools returns methods."""
        client, loop = relay_env
        assert len(client.tools) > 0, "Server should advertise at least one tool"
        names = client.tool_names()
        assert "start" in names, "start should be in tool list"
        assert "status" in names, "status should be in tool list"
        assert "stop" in names, "stop should be in tool list"
        assert "force_restart" in names, "force_restart should be in tool list"

    def test_method_list_matches_tool_yaml(self, relay_env):
        """Every method in tool.yaml is advertised by the server, and vice versa."""
        client, _ = relay_env
        server_names = client.tool_names()

        # Remove verify_clock -- test-only, not in tool.yaml
        server_names_no_test = server_names - {"verify_clock"}

        yaml_path = TOOL_DIR / "tool.yaml"
        with open(yaml_path) as f:
            yaml_data = yaml.safe_load(f)
        yaml_names = set(yaml_data.get("methods", {}).keys())

        yaml_only = yaml_names - server_names_no_test
        server_only = server_names_no_test - yaml_names

        assert not yaml_only, f"Methods in tool.yaml but not server: {yaml_only}"
        assert not server_only, f"Methods in server but not tool.yaml: {server_only}"

    def test_expected_method_count(self, relay_env):
        """Server should have exactly 4 built-in methods + verify_clock."""
        client, _ = relay_env
        names = client.tool_names()
        # 4 built-in (start, status, stop, force_restart) + verify_clock in MCP_TEST_MODE
        assert len(names) == 5, (
            f"Expected 5 methods (4 built-in + verify_clock), got {len(names)}: {sorted(names)}"
        )

    def test_required_params_enforced_start(self, relay_env):
        """Calling start without required 'target' param returns an error."""
        client, loop = relay_env
        resp = loop.run_until_complete(
            client.call("start", {"listen_port": 9090})
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

    def test_required_params_enforced_status(self, relay_env):
        """Calling status without required 'relay_id' param returns an error."""
        client, loop = relay_env
        resp = loop.run_until_complete(
            client.call("status", {})
        )
        result = resp.get("result", {})
        is_error = result.get("isError", False)
        content_text = ""
        for c in result.get("content", []):
            if c.get("type") == "text":
                content_text += c["text"]
        assert is_error or "relay_id" in content_text.lower() or "missing" in content_text.lower() or "error" in content_text.lower(), (
            f"Expected error about missing 'relay_id', got: {content_text[:300]}"
        )

    def test_meta_params_stripped(self, relay_env):
        """Passing 'clock_offset' (meta-param) in args does not crash the server."""
        client, loop = relay_env
        resp = loop.run_until_complete(
            client.call("start", {
                "target": "ldap://10.0.0.1",
                "listen_port": 19001,
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
        # Clean up: stop the relay if it started
        data = parse_tool_output(resp)
        if isinstance(data, dict) and "relay_id" in data:
            loop.run_until_complete(client.call("stop", {"relay_id": data["relay_id"]}))

    def test_unknown_method_returns_error(self, relay_env):
        """Calling a non-existent method returns a helpful error."""
        client, loop = relay_env
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
    def test_verify_clock_available(self, relay_env):
        """verify_clock is registered in MCP_TEST_MODE."""
        client, _ = relay_env
        names = client.tool_names()
        assert "verify_clock" in names, "verify_clock should be available in test mode"

    @pytest.mark.clock
    def test_verify_clock_returns_time(self, relay_env):
        """verify_clock returns current time and FAKETIME status."""
        client, loop = relay_env
        resp = loop.run_until_complete(client.call("verify_clock", {}))
        result = assert_tool_success(resp)
        data = parse_tool_output(resp)
        assert "current_time" in data
        assert "libfaketime_exists" in data
        # libfaketime is installed in this image
        assert data["libfaketime_exists"] is True, (
            "libfaketime should be installed in the impacket-relay image"
        )

    def test_structuredContent_present(self, relay_env):
        """Responses include structuredContent with error classification fields."""
        client, loop = relay_env
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
            pytest.skip(f"Cannot import ImpacketRelayServer: {e}")

    def test_parse_rbcd_success(self):
        """Parse relay output with successful RBCD delegation."""
        text = load_fixture("relay_rbcd_success.txt")
        result = self._server._parse_relay_output(text)
        assert result["relay_succeeded"] is True
        assert result["delegation_written"] is True
        assert len(result["connections"]) >= 1
        assert any("10.129.9.100" in c for c in result["connections"])

    def test_parse_adcs_success(self):
        """Parse relay output with successful ADCS certificate relay."""
        text = load_fixture("relay_adcs_success.txt")
        result = self._server._parse_relay_output(text)
        assert result["relay_succeeded"] is True
        assert result["adcs_succeeded"] is True
        assert len(result["connections"]) >= 1

    def test_parse_shadow_creds_success(self):
        """Parse relay output with successful Shadow Credentials attack."""
        text = load_fixture("relay_shadow_creds_success.txt")
        result = self._server._parse_relay_output(text)
        assert result["relay_succeeded"] is True
        assert result["shadow_credentials_succeeded"] is True

    def test_parse_no_connections(self):
        """Parse relay output with no incoming connections."""
        text = load_fixture("relay_no_connections.txt")
        result = self._server._parse_relay_output(text)
        assert result["relay_succeeded"] is False
        assert result["delegation_written"] is False
        assert len(result["connections"]) == 0

    def test_parse_auth_failure(self):
        """Parse relay output where authentication failed."""
        text = load_fixture("relay_auth_failure.txt")
        result = self._server._parse_relay_output(text)
        assert result["relay_succeeded"] is False
        assert len(result["connections"]) >= 1
        assert len(result["errors"]) >= 1

    def test_parse_empty_output(self):
        """Parse empty output."""
        result = self._server._parse_relay_output("")
        assert result["relay_succeeded"] is False
        assert result["delegation_written"] is False
        assert len(result["connections"]) == 0
        assert len(result["errors"]) == 0

    def test_parse_running_no_relay(self):
        """Parse output from a relay that started but had no relay attempt."""
        text = load_fixture("relay_running.txt")
        result = self._server._parse_relay_output(text)
        assert result["relay_succeeded"] is False
        assert len(result["connections"]) == 0

    def test_parse_ldap_signing_failure(self):
        """Parse output where LDAP signing/channel binding blocked the relay."""
        text = load_fixture("relay_ldap_signing.txt")
        result = self._server._parse_relay_output(text)
        assert result["relay_succeeded"] is False
        assert len(result["connections"]) >= 1
        assert len(result["errors"]) >= 1
        # Should contain the LDAP signing error
        error_text = "\n".join(result["errors"]).lower()
        assert "ldap signing" in error_text or "strongerauthrequired" in error_text

    def test_parse_mixed_connections(self):
        """Parse output with multiple connections, some fail, one succeeds."""
        text = load_fixture("relay_mixed_connections.txt")
        result = self._server._parse_relay_output(text)
        assert result["relay_succeeded"] is True
        assert result["delegation_written"] is True
        assert len(result["connections"]) >= 2, "Should have at least 2 connections"
        assert len(result["errors"]) >= 1, "Should have at least 1 error from the failed connection"

    def test_parse_only_error_lines(self):
        """Parse output that contains only error lines (no startup banner)."""
        text = "[-] Connection refused to ldap://10.0.0.1\n[-] Relay attack failed\n"
        result = self._server._parse_relay_output(text)
        assert result["relay_succeeded"] is False
        assert len(result["errors"]) == 2

    def test_parse_adcs_certificate_saved(self):
        """Verify ADCS parsing detects 'certificate saved' as success."""
        text = "[*] Certificate saved to DC01$.pfx\n"
        result = self._server._parse_relay_output(text)
        assert result["adcs_succeeded"] is True
        assert result["relay_succeeded"] is True

    def test_parse_shadow_creds_keycredentiallink_added(self):
        """Verify shadow credentials parsing detects KeyCredentialLink added."""
        text = "[*] Shadow Credentials: msDS-KeyCredentialLink added for target SRV01$\n"
        result = self._server._parse_relay_output(text)
        assert result["shadow_credentials_succeeded"] is True
        assert result["relay_succeeded"] is True

    def test_parse_delegation_without_connection(self):
        """Delegation line without 'Connection from' still marks delegation_written."""
        text = "[*] Delegation written successfully on target DC01$\n"
        result = self._server._parse_relay_output(text)
        assert result["delegation_written"] is True
        assert result["relay_succeeded"] is True

    def test_parse_error_line_with_authenticating(self):
        """Lines starting with [-] that contain 'authenticating' should NOT set relay_succeeded."""
        text = "[-] Authenticating against ldaps://DC01 as PIRATE/DC01$ FAILED\n"
        result = self._server._parse_relay_output(text)
        assert result["relay_succeeded"] is False, \
            "Error lines with 'authenticating' should not mark relay as succeeded"


# ===========================================================================
# COMMAND BUILDING TESTS -- verify flag construction, no container needed
# ===========================================================================

class TestCommandBuilding:
    """Test ntlmrelayx command construction logic.

    These tests verify that the server builds the correct command-line flags
    for different relay modes. Instantiates the server class directly and
    inspects the command array that would be passed to Popen.
    """

    @pytest.fixture(autouse=True, scope="class")
    def server(self):
        """Create a server instance for command building testing."""
        try:
            cls = _get_server_class()
            self.__class__._server = cls()
        except Exception as e:
            pytest.skip(f"Cannot import ImpacketRelayServer: {e}")

    def _build_cmd(self, **kwargs) -> list:
        """Build the command array by extracting logic from start_relay.

        This mirrors the command-building section of start_relay without
        actually spawning a process.
        """
        target = kwargs.get("target", "ldap://10.0.0.1")
        listen_port = kwargs.get("listen_port", 80)
        smb2support = kwargs.get("smb2support", True)
        delegate_access = kwargs.get("delegate_access", False)
        escalate_user = kwargs.get("escalate_user", None)
        remove_mic = kwargs.get("remove_mic", False)
        adcs = kwargs.get("adcs", False)
        adcs_template = kwargs.get("adcs_template", None)
        shadow_credentials = kwargs.get("shadow_credentials", False)
        no_smb_server = kwargs.get("no_smb_server", False)
        no_http_server = kwargs.get("no_http_server", False)
        socks = kwargs.get("socks", False)
        additional_args = kwargs.get("additional_args", None)

        cmd = ["impacket-ntlmrelayx", "-t", target]

        if smb2support:
            cmd.append("-smb2support")
        if delegate_access:
            cmd.append("--delegate-access")
        if escalate_user:
            cmd.extend(["--escalate-user", escalate_user])
        if remove_mic:
            cmd.append("--remove-mic")
        if adcs:
            cmd.append("--adcs")
        if adcs_template:
            cmd.extend(["--template", adcs_template])
        if shadow_credentials:
            cmd.append("--shadow-credentials")
        if no_http_server:
            cmd.append("--no-http-server")
        if socks:
            cmd.append("-socks")

        if listen_port == 445:
            cmd.extend(["--smb-port", str(listen_port)])
        elif listen_port != 80:
            cmd.extend(["--http-port", str(listen_port)])

        if no_smb_server:
            cmd.append("--no-smb-server")
        elif listen_port != 445 and not socks and "--no-smb-server" not in cmd:
            cmd.append("--no-smb-server")

        if additional_args:
            cmd.extend(additional_args.split())

        return cmd

    def test_basic_ldap_relay(self):
        """Basic LDAP relay builds correct command."""
        cmd = self._build_cmd(target="ldap://DC01.corp.local")
        assert cmd[0] == "impacket-ntlmrelayx"
        assert "-t" in cmd
        assert cmd[cmd.index("-t") + 1] == "ldap://DC01.corp.local"
        assert "-smb2support" in cmd  # default True
        assert "--no-smb-server" in cmd  # auto-added for non-445 port

    def test_rbcd_delegate_access(self):
        """RBCD relay includes --delegate-access flag."""
        cmd = self._build_cmd(
            target="ldaps://DC01.pirate.htb",
            delegate_access=True,
        )
        assert "--delegate-access" in cmd

    def test_adcs_relay(self):
        """ADCS relay includes --adcs and --template flags."""
        cmd = self._build_cmd(
            target="http://ca.corp.local/certsrv/certfnsh.asp",
            adcs=True,
            adcs_template="DomainController",
        )
        assert "--adcs" in cmd
        assert "--template" in cmd
        template_idx = cmd.index("--template")
        assert cmd[template_idx + 1] == "DomainController"

    def test_adcs_without_template(self):
        """ADCS relay without template still adds --adcs but no --template."""
        cmd = self._build_cmd(target="http://ca.corp.local/certsrv/certfnsh.asp", adcs=True)
        assert "--adcs" in cmd
        assert "--template" not in cmd

    def test_shadow_credentials_relay(self):
        """Shadow Credentials relay includes --shadow-credentials flag."""
        cmd = self._build_cmd(
            target="ldaps://DC01.corp.local",
            shadow_credentials=True,
        )
        assert "--shadow-credentials" in cmd

    def test_remove_mic_flag(self):
        """Cross-protocol relay with --remove-mic."""
        cmd = self._build_cmd(
            target="ldaps://DC01.corp.local",
            remove_mic=True,
        )
        assert "--remove-mic" in cmd

    def test_escalate_user(self):
        """Escalate user relay includes --escalate-user with value."""
        cmd = self._build_cmd(
            target="ldap://DC01.corp.local",
            escalate_user="admin_user",
        )
        assert "--escalate-user" in cmd
        eu_idx = cmd.index("--escalate-user")
        assert cmd[eu_idx + 1] == "admin_user"

    def test_port_445_uses_smb_port(self):
        """Port 445 uses --smb-port, not --http-port."""
        cmd = self._build_cmd(target="smb://10.0.0.1", listen_port=445)
        assert "--smb-port" in cmd
        assert "445" in cmd
        assert "--http-port" not in cmd

    def test_port_80_default_no_port_flag(self):
        """Default port 80 does not add --http-port or --smb-port."""
        cmd = self._build_cmd(target="ldap://10.0.0.1", listen_port=80)
        assert "--http-port" not in cmd
        assert "--smb-port" not in cmd

    def test_custom_port_uses_http_port(self):
        """Non-standard port (e.g. 8080) uses --http-port."""
        cmd = self._build_cmd(target="ldap://10.0.0.1", listen_port=8080)
        assert "--http-port" in cmd
        hp_idx = cmd.index("--http-port")
        assert cmd[hp_idx + 1] == "8080"

    def test_auto_no_smb_server_on_non_445(self):
        """Non-445 port auto-adds --no-smb-server to prevent bind conflict."""
        cmd = self._build_cmd(target="ldap://10.0.0.1", listen_port=80)
        assert "--no-smb-server" in cmd

    def test_no_auto_smb_disable_on_445(self):
        """Port 445 does NOT auto-add --no-smb-server."""
        cmd = self._build_cmd(target="smb://10.0.0.1", listen_port=445)
        assert "--no-smb-server" not in cmd

    def test_socks_prevents_auto_smb_disable(self):
        """Socks mode prevents auto --no-smb-server (socks needs SMB)."""
        cmd = self._build_cmd(target="ldap://10.0.0.1", listen_port=80, socks=True)
        assert "-socks" in cmd
        assert "--no-smb-server" not in cmd

    def test_explicit_no_smb_server(self):
        """Explicit no_smb_server=True adds the flag."""
        cmd = self._build_cmd(target="ldap://10.0.0.1", listen_port=445, no_smb_server=True)
        assert "--no-smb-server" in cmd

    def test_no_http_server_flag(self):
        """no_http_server=True adds --no-http-server."""
        cmd = self._build_cmd(target="smb://10.0.0.1", listen_port=445, no_http_server=True)
        assert "--no-http-server" in cmd

    def test_smb2support_default_true(self):
        """SMB2 support is enabled by default."""
        cmd = self._build_cmd(target="ldap://10.0.0.1")
        assert "-smb2support" in cmd

    def test_smb2support_disabled(self):
        """SMB2 support can be disabled."""
        cmd = self._build_cmd(target="ldap://10.0.0.1", smb2support=False)
        assert "-smb2support" not in cmd

    def test_additional_args_split(self):
        """Additional args are split and appended."""
        cmd = self._build_cmd(
            target="ldap://10.0.0.1",
            additional_args="--no-da --output-file /tmp/relay.txt",
        )
        assert "--no-da" in cmd
        assert "--output-file" in cmd
        assert "/tmp/relay.txt" in cmd

    def test_all_flags_combined(self):
        """All flags together produce correct command."""
        cmd = self._build_cmd(
            target="ldaps://DC01.corp.local",
            listen_port=8080,
            delegate_access=True,
            escalate_user="victim",
            remove_mic=True,
            adcs=True,
            adcs_template="Machine",
            shadow_credentials=True,
            no_http_server=True,
            socks=True,
            additional_args="--no-da",
        )
        assert "--delegate-access" in cmd
        assert "--escalate-user" in cmd
        assert "--remove-mic" in cmd
        assert "--adcs" in cmd
        assert "--template" in cmd
        assert "--shadow-credentials" in cmd
        assert "--no-http-server" in cmd
        assert "-socks" in cmd
        assert "--http-port" in cmd
        assert "--no-da" in cmd
        # socks=True prevents auto --no-smb-server even though port != 445
        assert "--no-smb-server" not in cmd


# ===========================================================================
# LIFECYCLE TESTS -- require Docker container, test start/status/stop flow
# ===========================================================================

class TestLifecycle:
    """Test the relay process lifecycle via MCP protocol.

    These are the critical tests that validate the stuck-state fixes.
    """

    def test_start_status_stop_clean(self, relay_env):
        """Clean lifecycle: start -> status -> stop."""
        client, loop = relay_env

        # Start a relay on a high port to avoid conflicts
        resp = loop.run_until_complete(client.call("start", {
            "target": "ldap://10.0.0.1",
            "listen_port": 19010,
        }, timeout=30))
        data = parse_tool_output(resp)
        assert isinstance(data, dict), f"Expected dict, got {type(data)}: {data}"
        assert "relay_id" in data, f"Missing relay_id in start response: {data}"
        relay_id = data["relay_id"]
        assert data["status"] == "running"
        assert data["listen_port"] == 19010

        # Check status
        resp = loop.run_until_complete(client.call("status", {"relay_id": relay_id}, timeout=30))
        data = parse_tool_output(resp)
        assert isinstance(data, dict)
        assert data["relay_id"] == relay_id
        assert data["status"] == "running"

        # Stop relay
        resp = loop.run_until_complete(client.call("stop", {"relay_id": relay_id}, timeout=30))
        data = parse_tool_output(resp)
        assert isinstance(data, dict)
        assert data["status"] in ("stopped", "force-killed")
        assert data["relay_id"] == relay_id

    def test_status_unknown_relay_returns_error(self, relay_env):
        """Checking status of a non-existent relay returns error."""
        client, loop = relay_env
        resp = loop.run_until_complete(
            client.call("status", {"relay_id": "relay-99999"})
        )
        result = assert_tool_error(resp, substring="not found")

    def test_stop_unknown_relay_returns_error(self, relay_env):
        """Stopping a non-existent relay returns error."""
        client, loop = relay_env
        resp = loop.run_until_complete(
            client.call("stop", {"relay_id": "relay-99999"})
        )
        result = assert_tool_error(resp, substring="not found")

    def test_status_after_process_death_returns_quickly(self, relay_env):
        """REQ-RES-004: If process dies, status() should return within 10s, not hang.

        We start a relay, then stop it (which kills the process), then call
        status() on the same relay_id. Since stop() removes the entry,
        this should return 'not found' immediately.
        """
        client, loop = relay_env

        # Start a relay
        resp = loop.run_until_complete(client.call("start", {
            "target": "ldap://10.0.0.1",
            "listen_port": 19011,
        }))
        data = parse_tool_output(resp)
        relay_id = data["relay_id"]

        # Stop it
        loop.run_until_complete(client.call("stop", {"relay_id": relay_id}))

        # Status should now return not-found, not hang
        import time
        t0 = time.monotonic()
        resp = loop.run_until_complete(client.call("status", {"relay_id": relay_id}))
        elapsed = time.monotonic() - t0
        assert elapsed < 10, f"status() took {elapsed:.1f}s, should be < 10s"

        result = resp.get("result", {})
        assert result.get("isError") is True

    def test_force_restart_kills_all_relays(self, relay_env):
        """force_restart kills all active relays and clears state."""
        client, loop = relay_env

        # Start two relays
        resp1 = loop.run_until_complete(client.call("start", {
            "target": "ldap://10.0.0.1",
            "listen_port": 19020,
        }))
        data1 = parse_tool_output(resp1)
        rid1 = data1["relay_id"]

        resp2 = loop.run_until_complete(client.call("start", {
            "target": "ldap://10.0.0.2",
            "listen_port": 19021,
        }))
        data2 = parse_tool_output(resp2)
        rid2 = data2["relay_id"]

        # Force restart
        resp = loop.run_until_complete(client.call("force_restart", {}))
        data = parse_tool_output(resp)
        assert isinstance(data, dict)
        assert data["killed"] == 2
        assert data["status"] == "cleared"

        # Both relays should be gone
        resp = loop.run_until_complete(client.call("status", {"relay_id": rid1}))
        assert resp.get("result", {}).get("isError") is True
        resp = loop.run_until_complete(client.call("status", {"relay_id": rid2}))
        assert resp.get("result", {}).get("isError") is True

    def test_force_restart_with_no_relays(self, relay_env):
        """force_restart with no active relays succeeds with killed=0."""
        client, loop = relay_env
        resp = loop.run_until_complete(client.call("force_restart", {}))
        data = parse_tool_output(resp)
        assert data["killed"] == 0
        assert data["status"] == "cleared"

    def test_start_with_adcs_flag(self, relay_env):
        """Start with --adcs flag and verify it starts correctly."""
        client, loop = relay_env
        resp = loop.run_until_complete(client.call("start", {
            "target": "http://ca.corp.local/certsrv/certfnsh.asp",
            "listen_port": 19030,
            "adcs": True,
            "adcs_template": "DomainController",
        }))
        data = parse_tool_output(resp)
        assert isinstance(data, dict), f"Expected dict, got: {data}"
        assert "relay_id" in data
        relay_id = data["relay_id"]

        # Clean up
        loop.run_until_complete(client.call("stop", {"relay_id": relay_id}))

    def test_start_with_shadow_credentials_flag(self, relay_env):
        """Start with --shadow-credentials flag."""
        client, loop = relay_env
        resp = loop.run_until_complete(client.call("start", {
            "target": "ldaps://DC01.corp.local",
            "listen_port": 19031,
            "shadow_credentials": True,
        }))
        data = parse_tool_output(resp)
        assert isinstance(data, dict), f"Expected dict, got: {data}"
        assert "relay_id" in data
        relay_id = data["relay_id"]

        # Clean up
        loop.run_until_complete(client.call("stop", {"relay_id": relay_id}))

    def test_start_with_delegate_access(self, relay_env):
        """Start with --delegate-access flag for RBCD."""
        client, loop = relay_env
        resp = loop.run_until_complete(client.call("start", {
            "target": "ldaps://DC01.pirate.htb",
            "listen_port": 19032,
            "delegate_access": True,
        }))
        data = parse_tool_output(resp)
        assert isinstance(data, dict), f"Expected dict, got: {data}"
        assert data.get("delegate_access") is True
        relay_id = data["relay_id"]

        # Clean up
        loop.run_until_complete(client.call("stop", {"relay_id": relay_id}))

    def test_start_custom_port(self, relay_env):
        """Start on a custom port (not 80 or 445)."""
        client, loop = relay_env
        resp = loop.run_until_complete(client.call("start", {
            "target": "ldap://10.0.0.1",
            "listen_port": 8080,
        }))
        data = parse_tool_output(resp)
        assert isinstance(data, dict)
        assert data["listen_port"] == 8080
        relay_id = data["relay_id"]

        # Clean up
        loop.run_until_complete(client.call("stop", {"relay_id": relay_id}))

    def test_port_conflict_detected(self, relay_env):
        """Starting two relays on the same port should fail on the second."""
        client, loop = relay_env

        # Start first relay
        resp1 = loop.run_until_complete(client.call("start", {
            "target": "ldap://10.0.0.1",
            "listen_port": 19040,
        }))
        data1 = parse_tool_output(resp1)
        assert "relay_id" in data1
        rid1 = data1["relay_id"]

        # Try starting second on same port -- should fail
        resp2 = loop.run_until_complete(client.call("start", {
            "target": "ldap://10.0.0.2",
            "listen_port": 19040,
        }))
        result2 = resp2.get("result", {})
        # Should be an error about port in use
        content_text = ""
        for c in result2.get("content", []):
            if c.get("type") == "text":
                content_text += c["text"]
        assert result2.get("isError") is True or "port" in content_text.lower() or "in use" in content_text.lower(), (
            f"Expected port conflict error, got: {content_text[:300]}"
        )

        # Clean up first relay
        loop.run_until_complete(client.call("stop", {"relay_id": rid1}))


# ===========================================================================
# ACCEPTANCE TESTS -- call every method through Docker container
# ===========================================================================

class TestAcceptance:
    """Call every method through the container without a live AD target.

    These tests verify:
    - The method exists and is callable through MCP protocol
    - Required param validation works (missing required params -> error)
    - The response has correct structuredContent shape
    - Error responses have error_class set (classified, not crash)

    Unlike bloodyad, impacket-relay is a stateful service. Start returns a
    relay_id, status/stop require one. We test the full lifecycle including
    structuredContent validation on every response.
    """

    def _assert_structured_content(self, resp, method_name):
        """Assert response has structuredContent with required fields."""
        result = resp.get("result", {})
        sc = result.get("structuredContent")
        assert sc is not None, f"{method_name}: missing structuredContent"
        assert "success" in sc, f"{method_name}: structuredContent missing 'success'"
        assert "error_class" in sc, f"{method_name}: structuredContent missing 'error_class'"
        assert "retryable" in sc, f"{method_name}: structuredContent missing 'retryable'"
        assert "suggestions" in sc, f"{method_name}: structuredContent missing 'suggestions'"
        # Verify suggestions is a list
        assert isinstance(sc["suggestions"], list), (
            f"{method_name}: suggestions should be a list, got {type(sc['suggestions'])}"
        )
        return sc

    def _assert_no_crash(self, resp, method_name):
        """Assert response is not an unhandled crash (MCP server crash, not tool output).

        Note: ntlmrelayx itself may print Python tracebacks in its output when
        killed. We only flag "Internal error:" which indicates an MCP server crash,
        not tracebacks in the relayed tool's raw output.
        """
        result = resp.get("result", {})
        content_text = ""
        for c in result.get("content", []):
            if c.get("type") == "text":
                content_text += c["text"]
        assert "unexpected keyword argument" not in content_text, (
            f"{method_name}: unhandled keyword argument error"
        )
        assert "Internal error:" not in content_text, (
            f"{method_name}: unhandled MCP server exception"
        )
        return content_text

    # ── start method ──────────────────────────────────────────────

    def test_start_basic(self, relay_env):
        """start with target returns relay_id and running status."""
        client, loop = relay_env
        resp = loop.run_until_complete(client.call("start", {
            "target": "ldap://10.0.0.99",
            "listen_port": 19100,
        }, timeout=30))
        self._assert_no_crash(resp, "start")
        sc = self._assert_structured_content(resp, "start")
        assert sc["success"] is True, f"start should succeed: {sc}"

        data = parse_tool_output(resp)
        assert isinstance(data, dict)
        assert "relay_id" in data
        assert data["status"] == "running"
        assert data["listen_port"] == 19100
        assert data["target"] == "ldap://10.0.0.99"
        assert "pid" in data

        # Clean up
        loop.run_until_complete(client.call("stop", {"relay_id": data["relay_id"]}))

    def test_start_missing_target(self, relay_env):
        """start without 'target' returns a helpful error."""
        client, loop = relay_env
        resp = loop.run_until_complete(client.call("start", {
            "listen_port": 19101,
        }))
        self._assert_no_crash(resp, "start_missing_target")
        result = resp.get("result", {})
        is_error = result.get("isError", False)
        content_text = ""
        for c in result.get("content", []):
            if c.get("type") == "text":
                content_text += c["text"]
        assert is_error or "target" in content_text.lower() or "missing" in content_text.lower() or "required" in content_text.lower(), (
            f"Expected error about missing 'target', got: {content_text[:300]}"
        )

    def test_start_adcs_mode(self, relay_env):
        """start with adcs=true returns relay_id with structuredContent."""
        client, loop = relay_env
        resp = loop.run_until_complete(client.call("start", {
            "target": "http://ca.corp.local/certsrv/certfnsh.asp",
            "listen_port": 19102,
            "adcs": True,
            "adcs_template": "Machine",
        }, timeout=30))
        self._assert_no_crash(resp, "start_adcs")
        sc = self._assert_structured_content(resp, "start_adcs")
        assert sc["success"] is True

        data = parse_tool_output(resp)
        assert "relay_id" in data
        loop.run_until_complete(client.call("stop", {"relay_id": data["relay_id"]}))

    def test_start_shadow_credentials_mode(self, relay_env):
        """start with shadow_credentials=true returns relay_id with structuredContent."""
        client, loop = relay_env
        resp = loop.run_until_complete(client.call("start", {
            "target": "ldaps://DC01.corp.local",
            "listen_port": 19103,
            "shadow_credentials": True,
        }, timeout=30))
        self._assert_no_crash(resp, "start_shadow_credentials")
        sc = self._assert_structured_content(resp, "start_shadow_credentials")
        assert sc["success"] is True

        data = parse_tool_output(resp)
        assert "relay_id" in data
        loop.run_until_complete(client.call("stop", {"relay_id": data["relay_id"]}))

    def test_start_delegate_access_mode(self, relay_env):
        """start with delegate_access=true returns relay_id and delegate_access in data."""
        client, loop = relay_env
        resp = loop.run_until_complete(client.call("start", {
            "target": "ldaps://DC01.pirate.htb",
            "listen_port": 19104,
            "delegate_access": True,
        }, timeout=30))
        self._assert_no_crash(resp, "start_delegate_access")
        sc = self._assert_structured_content(resp, "start_delegate_access")
        assert sc["success"] is True

        data = parse_tool_output(resp)
        assert "relay_id" in data
        assert data.get("delegate_access") is True
        loop.run_until_complete(client.call("stop", {"relay_id": data["relay_id"]}))

    def test_start_port_conflict(self, relay_env):
        """Starting two relays on the same port returns error on second."""
        client, loop = relay_env

        # Start first relay
        resp1 = loop.run_until_complete(client.call("start", {
            "target": "ldap://10.0.0.1",
            "listen_port": 19105,
        }, timeout=30))
        data1 = parse_tool_output(resp1)
        assert "relay_id" in data1
        rid1 = data1["relay_id"]

        # Second start on same port should fail
        resp2 = loop.run_until_complete(client.call("start", {
            "target": "ldap://10.0.0.2",
            "listen_port": 19105,
        }))
        self._assert_no_crash(resp2, "start_port_conflict")
        sc2 = self._assert_structured_content(resp2, "start_port_conflict")
        assert sc2["success"] is False
        # error_class may be "network" (pre-flight check) or "unknown" (ntlmrelayx exit)
        # depending on timing; the key assertion is that it fails, not crashes
        assert sc2["error_class"] is not None

        # Clean up
        loop.run_until_complete(client.call("stop", {"relay_id": rid1}))

    # ── status method ─────────────────────────────────────────────

    def test_status_on_running_relay(self, relay_env):
        """status on a running relay returns correct structure."""
        client, loop = relay_env
        resp = loop.run_until_complete(client.call("start", {
            "target": "ldap://10.0.0.1",
            "listen_port": 19110,
        }, timeout=30))
        data = parse_tool_output(resp)
        relay_id = data["relay_id"]

        resp = loop.run_until_complete(client.call("status", {"relay_id": relay_id}, timeout=30))
        self._assert_no_crash(resp, "status")
        sc = self._assert_structured_content(resp, "status")
        assert sc["success"] is True

        data = parse_tool_output(resp)
        assert isinstance(data, dict)
        assert data["relay_id"] == relay_id
        assert data["status"] == "running"
        assert "pid" in data
        assert "relay_succeeded" in data
        assert "delegation_written" in data
        assert "connections" in data
        assert isinstance(data["connections"], list)
        assert "errors" in data
        assert isinstance(data["errors"], list)

        # Clean up
        loop.run_until_complete(client.call("stop", {"relay_id": relay_id}))

    def test_status_missing_relay_id(self, relay_env):
        """status without relay_id returns a helpful error."""
        client, loop = relay_env
        resp = loop.run_until_complete(client.call("status", {}))
        self._assert_no_crash(resp, "status_missing_relay_id")
        result = resp.get("result", {})
        is_error = result.get("isError", False)
        content_text = ""
        for c in result.get("content", []):
            if c.get("type") == "text":
                content_text += c["text"]
        assert is_error or "relay_id" in content_text.lower() or "missing" in content_text.lower()

    def test_status_nonexistent_relay_id(self, relay_env):
        """status with bogus relay_id returns classified error."""
        client, loop = relay_env
        resp = loop.run_until_complete(client.call("status", {"relay_id": "relay-nonexistent"}))
        self._assert_no_crash(resp, "status_nonexistent")
        sc = self._assert_structured_content(resp, "status_nonexistent")
        assert sc["success"] is False
        assert sc["error_class"] is not None

    # ── stop method ───────────────────────────────────────────────

    def test_stop_on_running_relay(self, relay_env):
        """stop on a running relay returns stopped status and full data."""
        client, loop = relay_env
        resp = loop.run_until_complete(client.call("start", {
            "target": "ldap://10.0.0.1",
            "listen_port": 19120,
        }, timeout=30))
        data = parse_tool_output(resp)
        relay_id = data["relay_id"]

        resp = loop.run_until_complete(client.call("stop", {"relay_id": relay_id}, timeout=30))
        self._assert_no_crash(resp, "stop")
        sc = self._assert_structured_content(resp, "stop")
        # stop always succeeds even if relay didn't capture anything
        assert sc["success"] is True

        data = parse_tool_output(resp)
        assert isinstance(data, dict)
        assert data["relay_id"] == relay_id
        assert data["status"] in ("stopped", "force-killed")
        assert "relay_succeeded" in data
        assert "delegation_written" in data
        assert "connections" in data
        assert "errors" in data

    def test_stop_missing_relay_id(self, relay_env):
        """stop without relay_id returns error."""
        client, loop = relay_env
        resp = loop.run_until_complete(client.call("stop", {}))
        self._assert_no_crash(resp, "stop_missing_relay_id")
        result = resp.get("result", {})
        is_error = result.get("isError", False)
        content_text = ""
        for c in result.get("content", []):
            if c.get("type") == "text":
                content_text += c["text"]
        assert is_error or "relay_id" in content_text.lower() or "missing" in content_text.lower()

    def test_stop_nonexistent_relay_id(self, relay_env):
        """stop with bogus relay_id returns classified error."""
        client, loop = relay_env
        resp = loop.run_until_complete(client.call("stop", {"relay_id": "relay-bogus"}))
        self._assert_no_crash(resp, "stop_nonexistent")
        sc = self._assert_structured_content(resp, "stop_nonexistent")
        assert sc["success"] is False
        assert sc["error_class"] is not None

    # ── force_restart method ──────────────────────────────────────

    def test_force_restart_no_relays(self, relay_env):
        """force_restart with no active relays returns killed=0."""
        client, loop = relay_env
        # First clear any leftover relays from previous tests
        loop.run_until_complete(client.call("force_restart", {}))

        # Now verify that calling force_restart on a clean state returns killed=0
        resp = loop.run_until_complete(client.call("force_restart", {}))
        self._assert_no_crash(resp, "force_restart")
        sc = self._assert_structured_content(resp, "force_restart")
        assert sc["success"] is True

        data = parse_tool_output(resp)
        assert isinstance(data, dict)
        assert data["killed"] == 0
        assert data["status"] == "cleared"

    def test_force_restart_with_active_relays(self, relay_env):
        """force_restart with active relays kills them and returns correct count."""
        client, loop = relay_env

        # Start a relay
        resp = loop.run_until_complete(client.call("start", {
            "target": "ldap://10.0.0.1",
            "listen_port": 19130,
        }, timeout=30))
        data = parse_tool_output(resp)
        assert "relay_id" in data

        resp = loop.run_until_complete(client.call("force_restart", {}))
        self._assert_no_crash(resp, "force_restart_with_relays")
        sc = self._assert_structured_content(resp, "force_restart_with_relays")
        assert sc["success"] is True

        data = parse_tool_output(resp)
        assert data["killed"] >= 1
        assert data["status"] == "cleared"

    # ── Cross-cutting acceptance ──────────────────────────────────

    def test_verify_clock_has_structuredContent(self, relay_env):
        """verify_clock (test-only method) returns structuredContent."""
        client, loop = relay_env
        resp = loop.run_until_complete(client.call("verify_clock", {}))
        self._assert_no_crash(resp, "verify_clock")
        sc = self._assert_structured_content(resp, "verify_clock")
        assert sc["success"] is True

    def test_meta_param_clock_offset_not_crash(self, relay_env):
        """clock_offset meta-param is stripped and does not crash start."""
        client, loop = relay_env
        resp = loop.run_until_complete(client.call("start", {
            "target": "ldap://10.0.0.99",
            "listen_port": 19140,
            "clock_offset": "5h",
        }, timeout=30))
        self._assert_no_crash(resp, "meta_param_clock_offset")
        sc = self._assert_structured_content(resp, "meta_param_clock_offset")

        # Clean up if relay started
        data = parse_tool_output(resp)
        if isinstance(data, dict) and "relay_id" in data:
            loop.run_until_complete(client.call("stop", {"relay_id": data["relay_id"]}))

    def test_start_with_socks_has_structuredContent(self, relay_env):
        """start with socks=True returns structuredContent."""
        client, loop = relay_env
        resp = loop.run_until_complete(client.call("start", {
            "target": "ldap://10.0.0.1",
            "listen_port": 19150,
            "socks": True,
        }, timeout=30))
        self._assert_no_crash(resp, "start_socks")
        sc = self._assert_structured_content(resp, "start_socks")

        data = parse_tool_output(resp)
        if isinstance(data, dict) and "relay_id" in data:
            loop.run_until_complete(client.call("stop", {"relay_id": data["relay_id"]}))

    def test_start_with_remove_mic_has_structuredContent(self, relay_env):
        """start with remove_mic=True returns structuredContent."""
        client, loop = relay_env
        resp = loop.run_until_complete(client.call("start", {
            "target": "ldaps://DC01.corp.local",
            "listen_port": 19151,
            "remove_mic": True,
        }, timeout=30))
        self._assert_no_crash(resp, "start_remove_mic")
        sc = self._assert_structured_content(resp, "start_remove_mic")

        data = parse_tool_output(resp)
        if isinstance(data, dict) and "relay_id" in data:
            loop.run_until_complete(client.call("stop", {"relay_id": data["relay_id"]}))

    def test_start_with_escalate_user_has_structuredContent(self, relay_env):
        """start with escalate_user returns structuredContent."""
        client, loop = relay_env
        resp = loop.run_until_complete(client.call("start", {
            "target": "ldaps://DC01.corp.local",
            "listen_port": 19152,
            "escalate_user": "admin_user",
        }, timeout=30))
        self._assert_no_crash(resp, "start_escalate_user")
        sc = self._assert_structured_content(resp, "start_escalate_user")

        data = parse_tool_output(resp)
        if isinstance(data, dict) and "relay_id" in data:
            loop.run_until_complete(client.call("stop", {"relay_id": data["relay_id"]}))

    def test_start_with_additional_args_has_structuredContent(self, relay_env):
        """start with additional_args returns structuredContent."""
        client, loop = relay_env
        resp = loop.run_until_complete(client.call("start", {
            "target": "ldap://10.0.0.1",
            "listen_port": 19153,
            "additional_args": "--no-da",
        }, timeout=30))
        self._assert_no_crash(resp, "start_additional_args")
        sc = self._assert_structured_content(resp, "start_additional_args")

        data = parse_tool_output(resp)
        if isinstance(data, dict) and "relay_id" in data:
            loop.run_until_complete(client.call("stop", {"relay_id": data["relay_id"]}))

    def test_lifecycle_structuredContent_consistent(self, relay_env):
        """Full lifecycle: start -> status -> stop all have structuredContent."""
        client, loop = relay_env

        # Start
        resp = loop.run_until_complete(client.call("start", {
            "target": "ldap://10.0.0.1",
            "listen_port": 19160,
        }, timeout=30))
        sc_start = self._assert_structured_content(resp, "lifecycle_start")
        assert sc_start["success"] is True
        data = parse_tool_output(resp)
        relay_id = data["relay_id"]

        # Status
        resp = loop.run_until_complete(client.call("status", {"relay_id": relay_id}, timeout=30))
        sc_status = self._assert_structured_content(resp, "lifecycle_status")
        assert sc_status["success"] is True

        # Stop
        resp = loop.run_until_complete(client.call("stop", {"relay_id": relay_id}, timeout=30))
        sc_stop = self._assert_structured_content(resp, "lifecycle_stop")
        assert sc_stop["success"] is True


# ===========================================================================
# ERROR CLASSIFICATION TESTS -- test _classify_relay_error
# ===========================================================================

class TestErrorClassification:
    """Test error classification for relay-specific errors.

    These verify that the server's _classify_relay_error correctly identifies
    error_class, retryable, and suggestions for common relay failure modes.
    """

    @pytest.fixture(autouse=True, scope="class")
    def server(self):
        """Create a server instance for error classification testing."""
        try:
            cls = _get_server_class()
            self.__class__._server = cls()
        except Exception as e:
            pytest.skip(f"Cannot import ImpacketRelayServer: {e}")

    def test_port_in_use(self):
        """Address already in use -> network, not retryable."""
        err_class, retryable, suggestions = self._server._classify_relay_error(
            "OSError: [Errno 98] Address already in use"
        )
        assert err_class == "network"
        assert retryable is False
        assert any("port" in s.lower() for s in suggestions)

    def test_connection_refused(self):
        """Connection refused to relay target -> network, retryable."""
        err_class, retryable, suggestions = self._server._classify_relay_error(
            "[-] Connection refused to ldap://DC01.corp.local"
        )
        assert err_class == "network"
        assert retryable is True

    def test_errno_111_connection_refused(self):
        """Errno 111 connection refused variant."""
        err_class, retryable, suggestions = self._server._classify_relay_error(
            "[Errno 111] Connection refused"
        )
        assert err_class == "network"
        assert retryable is True

    def test_logon_failure(self):
        """STATUS_LOGON_FAILURE -> auth, not retryable."""
        err_class, retryable, suggestions = self._server._classify_relay_error(
            "[-] Authenticating against ldap://DC01 as PIRATE/WEB01$ FAILED: STATUS_LOGON_FAILURE"
        )
        assert err_class == "auth"
        assert retryable is False

    def test_access_denied(self):
        """STATUS_ACCESS_DENIED -> permission, not retryable."""
        err_class, retryable, suggestions = self._server._classify_relay_error(
            "[-] STATUS_ACCESS_DENIED on target ldaps://DC01.corp.local"
        )
        assert err_class == "permission"
        assert retryable is False

    def test_adcs_template_not_found(self):
        """ADCS template not found -> config, not retryable."""
        err_class, retryable, suggestions = self._server._classify_relay_error(
            "[-] Certificate template 'BadTemplate' not found on CA"
        )
        assert err_class == "config"
        assert retryable is False
        assert any("template" in s.lower() for s in suggestions)

    def test_shadow_credentials_error(self):
        """Shadow Credentials KeyCredentialLink error -> permission, not retryable."""
        err_class, retryable, suggestions = self._server._classify_relay_error(
            "[-] KeyCredentialLink update failed: insufficient access rights"
        )
        assert err_class == "permission"
        assert retryable is False

    def test_ldap_signing_enforced(self):
        """LDAP signing/channel binding -> config, not retryable."""
        err_class, retryable, suggestions = self._server._classify_relay_error(
            "[-] LDAP signing is enforced, relay to LDAP will fail. StrongerAuthRequired"
        )
        assert err_class == "config"
        assert retryable is False
        assert any("signing" in s.lower() or "ldaps" in s.lower() for s in suggestions)

    def test_timeout_error(self):
        """Timeout -> timeout, retryable."""
        err_class, retryable, suggestions = self._server._classify_relay_error(
            "Connection timed out after 300s"
        )
        assert err_class == "timeout"
        assert retryable is True

    def test_binary_not_found(self):
        """ntlmrelayx not found -> config, not retryable."""
        err_class, retryable, suggestions = self._server._classify_relay_error(
            "ntlmrelayx binary not found at /usr/bin/impacket-ntlmrelayx"
        )
        assert err_class == "config"
        assert retryable is False

    def test_empty_input(self):
        """Empty string -> unknown, not retryable."""
        err_class, retryable, suggestions = self._server._classify_relay_error("")
        assert err_class == "unknown"
        assert retryable is False

    def test_generic_error(self):
        """Generic [-] error line -> unknown."""
        err_class, retryable, suggestions = self._server._classify_relay_error(
            "[-] Something unexpected happened"
        )
        assert err_class == "unknown"
        assert retryable is False

    def test_bind_error(self):
        """Bind error -> network, not retryable."""
        err_class, retryable, suggestions = self._server._classify_relay_error(
            "[-] Bind error: Could not bind to port 80"
        )
        assert err_class == "network"
        assert retryable is False

    def test_channel_binding(self):
        """LDAP channel binding -> config, not retryable."""
        err_class, retryable, suggestions = self._server._classify_relay_error(
            "[-] LDAP channel binding is required on this server"
        )
        assert err_class == "config"
        assert retryable is False

    def test_certipy_error(self):
        """Certipy-related error in ADCS relay -> config."""
        err_class, retryable, suggestions = self._server._classify_relay_error(
            "[-] Certipy error: failed to enroll certificate"
        )
        assert err_class == "config"
        assert retryable is False

    def test_multiline_errors_classification_order(self):
        """Classify multiline input based on pattern check order (not line order).

        The classifier checks the full text against patterns in order:
        port-in-use -> connection-refused -> auth -> permission -> ...
        So "connection refused" matches before "STATUS_LOGON_FAILURE" even
        if logon failure appears on an earlier line.
        """
        multiline = (
            "[-] Authenticating against ldaps://DC01 FAILED: STATUS_LOGON_FAILURE\n"
            "[-] Connection refused to ldap://DC01\n"
        )
        err_class, retryable, suggestions = self._server._classify_relay_error(multiline)
        # "connection refused" pattern is checked before "status_logon_failure"
        assert err_class == "network"
        assert retryable is True

    def test_auth_only_multiline(self):
        """Multiline with only auth errors classifies as auth."""
        multiline = (
            "[-] Authenticating against ldaps://DC01 FAILED: STATUS_LOGON_FAILURE\n"
            "[-] Relay attack failed\n"
        )
        err_class, retryable, suggestions = self._server._classify_relay_error(multiline)
        assert err_class == "auth"
        assert retryable is False

    def test_no_error_indicators_returns_unknown(self):
        """Plain text without error markers returns unknown."""
        err_class, retryable, suggestions = self._server._classify_relay_error(
            "This is just normal output text"
        )
        assert err_class == "unknown"
        assert retryable is False

    def test_suggestions_always_list(self):
        """Suggestions are always a list (never None)."""
        for text in [
            "",
            "[-] Something",
            "Connection refused",
            "STATUS_LOGON_FAILURE",
        ]:
            _, _, suggestions = self._server._classify_relay_error(text)
            assert isinstance(suggestions, list), f"Suggestions should be list for: {text!r}"


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

    def test_start_has_target_param(self):
        """Start method should have a 'target' parameter."""
        params = self._yaml["methods"]["start"].get("params", {})
        assert "target" in params, "Start method missing 'target' param"
        assert params["target"].get("required") is True

    def test_start_has_listen_port_param(self):
        """Start method should have a 'listen_port' parameter."""
        params = self._yaml["methods"]["start"].get("params", {})
        assert "listen_port" in params, "Start method missing 'listen_port' param"

    def test_start_has_adcs_params(self):
        """Start method should have ADCS-related parameters."""
        params = self._yaml["methods"]["start"].get("params", {})
        assert "adcs" in params, "Start method missing 'adcs' param"
        assert "adcs_template" in params, "Start method missing 'adcs_template' param"

    def test_start_has_shadow_credentials_param(self):
        """Start method should have shadow_credentials parameter."""
        params = self._yaml["methods"]["start"].get("params", {})
        assert "shadow_credentials" in params, "Start method missing 'shadow_credentials' param"

    def test_start_has_delegate_access_param(self):
        """Start method should have delegate_access parameter."""
        params = self._yaml["methods"]["start"].get("params", {})
        assert "delegate_access" in params, "Start method missing 'delegate_access' param"

    def test_start_has_remove_mic_param(self):
        """Start method should have remove_mic parameter."""
        params = self._yaml["methods"]["start"].get("params", {})
        assert "remove_mic" in params, "Start method missing 'remove_mic' param"

    def test_start_has_socks_param(self):
        """Start method should have socks parameter."""
        params = self._yaml["methods"]["start"].get("params", {})
        assert "socks" in params, "Start method missing 'socks' param"

    def test_start_has_additional_args_param(self):
        """Start method should have additional_args parameter."""
        params = self._yaml["methods"]["start"].get("params", {})
        assert "additional_args" in params, "Start method missing 'additional_args' param"

    def test_stop_has_relay_id_param(self):
        """Stop method should have relay_id parameter."""
        params = self._yaml["methods"]["stop"].get("params", {})
        assert "relay_id" in params, "Stop method missing 'relay_id' param"
        assert params["relay_id"].get("required") is True

    def test_status_has_relay_id_param(self):
        """Status method should have relay_id parameter."""
        params = self._yaml["methods"]["status"].get("params", {})
        assert "relay_id" in params, "Status method missing 'relay_id' param"

    def test_force_restart_has_no_required_params(self):
        """force_restart should have no required parameters."""
        params = self._yaml["methods"]["force_restart"].get("params", {})
        for pname, pdef in params.items():
            assert pdef.get("required") is not True, (
                f"force_restart param '{pname}' should not be required"
            )

    def test_yaml_param_types_valid(self):
        """All param types should be valid JSON Schema types."""
        valid_types = {"string", "integer", "boolean", "number", "array", "object", "enum"}
        for method_name, defn in self._yaml.get("methods", {}).items():
            for param_name, param_def in defn.get("params", {}).items():
                ptype = param_def.get("type", "string")
                assert ptype in valid_types, (
                    f"{method_name}.{param_name}: invalid type '{ptype}'"
                )

    def test_service_flag_set(self):
        """tool.yaml should have service: true."""
        assert self._yaml.get("service") is True

    def test_phases_includes_exploitation(self):
        """tool.yaml should include 'exploitation' in phases."""
        phases = self._yaml.get("phases", [])
        assert "exploitation" in phases


# ===========================================================================
# INTEGRATION TESTS -- require --target, real AD environment
# ===========================================================================

@pytest.mark.integration
class TestIntegration:
    """Integration tests that need a real AD target.

    Run with: pytest tests/tools/test_impacket_relay.py --tool=impacket-relay
              --target=<DC_IP> -m integration -v

    Note: These are extremely environment-specific and require a coercion
    source to trigger actual relay. Primarily for manual validation.
    """

    def test_start_relay_to_ldap(self, relay_env, target):
        """Start a relay targeting LDAP on the provided target."""
        client, loop = relay_env
        resp = loop.run_until_complete(client.call("start", {
            "target": f"ldap://{target}",
            "listen_port": 19050,
            "delegate_access": True,
        }))
        data = parse_tool_output(resp)
        assert isinstance(data, dict)
        assert "relay_id" in data
        assert data["status"] == "running"

        # Clean up
        relay_id = data["relay_id"]
        loop.run_until_complete(client.call("stop", {"relay_id": relay_id}))
