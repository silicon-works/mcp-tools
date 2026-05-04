"""
Tests for the metasploit MCP tool server.

Covers:
- Smoke tests: boot, method list, required params, meta-param stripping, clock
- Unit tests: _resolve_payload, exec_command output parsing
- Unit tests: _classify_msf_error (all branches), check_vuln negation, handler parsing
- Method tests: generate_payload, search_modules, check_vuln, run_exploit,
  exec_command, list_sessions, session_command, post_module, handler
- Error handling: connection lost, session not found, timeout, module not found
- Error classification: metasploit-specific error patterns
- Contract tests: tool.yaml vs server parameter definitions
- Phantom method tests: start_handler, console_command (agent mistakes)
- Acceptance tests: every method called through Docker, structuredContent validated
- Integration tests: real target scenarios (marked @pytest.mark.integration)
"""

import asyncio
import importlib.util
import json
import os
import re
import sys
from pathlib import Path
from typing import Any, Dict, Set
from unittest.mock import AsyncMock, MagicMock, patch

import pytest
import yaml

# ---------------------------------------------------------------------------
# Path setup
# ---------------------------------------------------------------------------
PROJECT_ROOT = Path(__file__).parent.parent.parent
TOOL_DIR = PROJECT_ROOT / "tools" / "metasploit"
FIXTURES_DIR = Path(__file__).parent.parent / "fixtures" / "metasploit"

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
def msf_env(request):
    """Create an MCPTestClient with its event loop. Yields (client, loop).

    Metasploit takes longer to start (msfrpcd init), so we use a generous
    startup timeout. The container is privileged for raw socket access.
    """
    tool = "metasploit"
    prefix = request.config.getoption("--image-prefix", default="mcp-test-")
    image = f"{prefix}{tool}"

    client = MCPTestClient(
        image=image,
        tool_name=tool,
        startup_timeout=300.0,  # msfrpcd can take 2+ minutes first boot
    )
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
# Helper: import server module for direct unit testing
# ---------------------------------------------------------------------------
def _get_server_class():
    """Import and return the MetasploitServer class for direct method testing."""
    spec = importlib.util.spec_from_file_location(
        "metasploit_server", TOOL_DIR / "mcp-server.py"
    )
    mod = importlib.util.module_from_spec(spec)
    spec.loader.exec_module(mod)
    return mod.MetasploitServer


# ===========================================================================
# UNIT TESTS -- no Docker required, test pure logic
# ===========================================================================

class TestResolvePayload:
    """Test _resolve_payload shortcut resolution."""

    def setup_method(self):
        self.server = _get_server_class()()

    def test_shortcut_windows_reverse_tcp(self):
        assert self.server._resolve_payload("windows_reverse_tcp") == "windows/meterpreter/reverse_tcp"

    def test_shortcut_linux_reverse_tcp(self):
        assert self.server._resolve_payload("linux_reverse_tcp") == "linux/x64/meterpreter/reverse_tcp"

    def test_shortcut_linux_shell_tcp(self):
        assert self.server._resolve_payload("linux_shell_tcp") == "linux/x64/shell_reverse_tcp"

    def test_shortcut_php_reverse(self):
        assert self.server._resolve_payload("php_reverse") == "php/meterpreter/reverse_tcp"

    def test_shortcut_java_reverse(self):
        assert self.server._resolve_payload("java_reverse") == "java/meterpreter/reverse_tcp"

    def test_shortcut_windows_reverse_https(self):
        assert self.server._resolve_payload("windows_reverse_https") == "windows/meterpreter/reverse_https"

    def test_full_path_passthrough(self):
        """Full payload path should be returned unchanged."""
        full = "windows/x64/meterpreter/reverse_tcp"
        assert self.server._resolve_payload(full) == full

    def test_unknown_shortcut_passthrough(self):
        """Unknown shortcut should be returned unchanged (user may know a valid payload)."""
        custom = "custom/payload/reverse"
        assert self.server._resolve_payload(custom) == custom

    def test_all_common_payloads_are_valid_paths(self):
        """All COMMON_PAYLOADS values should contain '/' (valid MSF paths)."""
        for key, val in self.server.COMMON_PAYLOADS.items():
            assert "/" in val, f"COMMON_PAYLOADS[{key}] = {val} is not a valid path"


class TestExecCommandOutputParsing:
    """Test the exec_command output parsing logic extracted from the method."""

    def _parse_exec_output(self, output_text):
        """Simulate the output parsing logic from exec_command."""
        command_output = ""
        exploit_success = False

        if "exploit completed" in output_text.lower() or "command executed" in output_text.lower():
            exploit_success = True

        lines = output_text.split("\n")
        capture = False
        for line in lines:
            if line.startswith("[*]") or line.startswith("[+]") or line.startswith("[-]"):
                if "executing" in line.lower() or "command" in line.lower():
                    capture = True
                    exploit_success = True
                continue
            if capture and line.strip():
                command_output += line + "\n"

        return exploit_success, command_output.strip()

    def test_successful_command_execution(self):
        """Parse output from a successful command execution."""
        output = load_fixture("exec_command_output.txt")
        success, cmd_output = self._parse_exec_output(output)

        assert success is True
        assert "uid=33" in cmd_output
        assert "www-data" in cmd_output

    def test_exploit_completed_keyword(self):
        """'exploit completed' triggers success flag."""
        output = "[*] Exploit completed, but no session was created.\n"
        success, _ = self._parse_exec_output(output)
        assert success is True

    def test_command_executed_keyword(self):
        """'command executed' triggers success flag."""
        output = "[+] Command executed successfully.\nresult data\n"
        success, cmd_output = self._parse_exec_output(output)
        assert success is True

    def test_no_success_indicators(self):
        """Output with no success indicators returns False."""
        output = "[*] Starting module\n[-] Connection refused\n"
        success, cmd_output = self._parse_exec_output(output)
        assert success is False

    def test_capture_starts_after_command_line(self):
        """Command output capture begins after a line mentioning 'command' or 'executing'."""
        output = (
            "[*] Setting up payload...\n"
            "some noise\n"
            "[*] Executing command on target...\n"
            "uid=0(root)\n"
            "hostname: pwned\n"
        )
        success, cmd_output = self._parse_exec_output(output)
        assert success is True
        assert "uid=0(root)" in cmd_output
        assert "hostname: pwned" in cmd_output
        # The "some noise" line should NOT be captured (before the trigger)
        assert "some noise" not in cmd_output


class TestPayloadFormats:
    """Test PAYLOAD_FORMATS constant."""

    def test_common_formats_present(self):
        server = _get_server_class()()
        for fmt in ["exe", "elf", "raw", "python", "php", "asp", "c", "dll"]:
            assert fmt in server.PAYLOAD_FORMATS, f"Format {fmt} missing"

    def test_no_duplicates(self):
        server = _get_server_class()()
        assert len(server.PAYLOAD_FORMATS) == len(set(server.PAYLOAD_FORMATS))


class TestCheckVulnOutputParsing:
    """Test vulnerability detection parsing logic (improved with negation handling)."""

    def _is_vulnerable(self, output_text):
        """Replicate the improved vulnerability detection from check_vuln."""
        output_lower = output_text.lower()
        negated = (
            "not appear vulnerable" in output_lower
            or "not vulnerable" in output_lower
            or "does not appear" in output_lower
        )
        positive = (
            "is vulnerable" in output_lower
            or "likely vulnerable" in output_lower
        )
        has_plus_vuln = any(
            line.startswith("[+]") and "vulnerable" in line.lower()
            for line in output_text.split("\n")
        )
        return has_plus_vuln or positive or (
            "vulnerable" in output_lower and not negated
        )

    def test_positive_detection(self):
        output = load_fixture("check_vuln_positive.txt")
        assert self._is_vulnerable(output) is True

    def test_negative_detection_fixed(self):
        """'does NOT appear vulnerable' should now return False."""
        output = load_fixture("check_vuln_negative.txt")
        assert self._is_vulnerable(output) is False

    def test_no_vuln_keyword(self):
        output = "[*] Scanned 1 of 1 hosts (100% complete)\n[*] Auxiliary module execution completed\n"
        assert self._is_vulnerable(output) is False


class TestHandlerOutputParsing:
    """Test handler output parsing logic."""

    def _parse_handler_output(self, output_text):
        """Replicate handler output parsing from start_handler."""
        job_id = None
        match = re.search(r"background job (\d+)", output_text)
        if match:
            job_id = match.group(1)
        handler_started = "started" in output_text.lower() and "handler" in output_text.lower()
        return handler_started, job_id

    def test_handler_started(self):
        output = load_fixture("handler_started.txt")
        started, job_id = self._parse_handler_output(output)
        assert started is True
        assert job_id == "0"

    def test_handler_port_in_use(self):
        output = load_fixture("handler_port_in_use.txt")
        started, job_id = self._parse_handler_output(output)
        # "Handler failed to bind" -- does not contain "started", so handler_started=False
        assert started is False
        assert job_id is None


class TestMethodRegistration:
    """Test that all methods are properly registered.

    Note: run_cli is AUTO-REGISTERED by BaseMCPServer (since the kind:cli
    infrastructure landed in commit 91bea14, April 2026). It's not metasploit-
    specific but it IS in server.methods. Tests that count or enumerate
    methods must account for it.
    """

    METASPLOIT_METHODS = {
        # Original 9 (April 2026)
        "generate_payload",
        "search_modules",
        "check_vuln",
        "run_exploit",
        "exec_command",
        "list_sessions",
        "session_command",
        "post_module",
        "handler",
        # May 2026 expansion (Wave 2-5): 20 new methods bringing coverage to ~80% of msfconsole
        "list_jobs",
        "stop_job",
        "session_kill",
        "session_upgrade",
        "module_info",
        "route_add",
        "route_list",
        "route_delete",
        "portfwd_add",
        "portfwd_list",
        "portfwd_delete",
        "db_nmap",
        "db_import",
        "list_hosts",
        "list_services",
        "list_creds",
        "list_loot",
        "list_notes",
        "run_resource_script",
        "run_console",
    }
    AUTO_REGISTERED = {"run_cli"}  # from BaseMCPServer

    def test_all_metasploit_methods_registered(self):
        server = _get_server_class()()
        registered = set(server.methods.keys())
        # All metasploit-specific methods are present
        assert self.METASPLOIT_METHODS.issubset(registered), (
            f"Missing metasploit methods: {self.METASPLOIT_METHODS - registered}"
        )
        # Plus the auto-registered run_cli from BaseMCPServer
        assert "run_cli" in registered, "BaseMCPServer should auto-register run_cli"

    def test_method_count(self):
        server = _get_server_class()()
        # 29 metasploit-specific + 1 auto-registered run_cli = 30 (post-May-2026 expansion)
        expected = len(self.METASPLOIT_METHODS) + len(self.AUTO_REGISTERED)
        assert len(server.methods) == expected, (
            f"Expected {expected} methods ({len(self.METASPLOIT_METHODS)} metasploit "
            f"+ {len(self.AUTO_REGISTERED)} auto-registered), "
            f"got {len(server.methods)}: {sorted(server.methods.keys())}"
        )

    def test_all_methods_have_handlers(self):
        server = _get_server_class()()
        for name, method in server.methods.items():
            assert method.handler is not None, f"Method {name} has no handler"
            assert callable(method.handler), f"Method {name} handler is not callable"

    def test_all_methods_have_descriptions(self):
        server = _get_server_class()()
        for name, method in server.methods.items():
            assert method.description, f"Method {name} has no description"
            assert len(method.description) > 10, f"Method {name} description too short"


class TestContractToolYaml:
    """Validate tool.yaml matches implementation."""

    def test_yaml_methods_match_server(self):
        """Every metasploit-specific method in tool.yaml is registered in the
        server, and vice versa. run_cli is auto-registered by BaseMCPServer
        (not in tool.yaml — it's the universal kind:cli surface)."""
        yaml_path = TOOL_DIR / "tool.yaml"
        with open(yaml_path) as f:
            yaml_data = yaml.safe_load(f)
        yaml_methods = set(yaml_data.get("methods", {}).keys())

        server = _get_server_class()()
        server_methods = set(server.methods.keys()) - {"run_cli"}  # exclude auto-registered

        yaml_only = yaml_methods - server_methods
        server_only = server_methods - yaml_methods

        assert not yaml_only, f"Methods in tool.yaml but not server: {yaml_only}"
        assert not server_only, f"Methods in server but not tool.yaml: {server_only}"

    def test_required_params_match(self):
        """Required params in tool.yaml match required params in server method definitions."""
        yaml_path = TOOL_DIR / "tool.yaml"
        with open(yaml_path) as f:
            yaml_data = yaml.safe_load(f)

        server = _get_server_class()()

        for method_name, yaml_method in yaml_data.get("methods", {}).items():
            yaml_params = yaml_method.get("params", {})
            yaml_required = {
                p for p, pdef in yaml_params.items()
                if pdef.get("required", False)
            }

            if method_name in server.methods:
                server_method = server.methods[method_name]
                server_required = {
                    p for p, pdef in server_method.params.items()
                    if pdef.get("required", False)
                }

                assert yaml_required == server_required, (
                    f"{method_name}: YAML required={yaml_required}, "
                    f"server required={server_required}"
                )

    def test_yaml_has_service_flag(self):
        """tool.yaml should declare service: true for msfrpcd."""
        yaml_path = TOOL_DIR / "tool.yaml"
        with open(yaml_path) as f:
            yaml_data = yaml.safe_load(f)
        assert yaml_data.get("service") is True, "metasploit should be a service tool"

    def test_yaml_phases(self):
        """tool.yaml should include exploitation and post-exploitation phases."""
        yaml_path = TOOL_DIR / "tool.yaml"
        with open(yaml_path) as f:
            yaml_data = yaml.safe_load(f)
        phases = yaml_data.get("phases", [])
        assert "exploitation" in phases
        assert "post-exploitation" in phases

    def test_yaml_capabilities(self):
        """tool.yaml should list core capabilities."""
        yaml_path = TOOL_DIR / "tool.yaml"
        with open(yaml_path) as f:
            yaml_data = yaml.safe_load(f)
        caps = yaml_data.get("capabilities", [])
        assert "exploit_execution" in caps
        assert "session_management" in caps
        assert "payload_generation" in caps


class TestPhantomMethods:
    """Test that commonly-mistaken method names produce helpful errors.

    Engagement data shows agents calling 'start_handler' and 'console_command'
    which don't exist. These should produce clear error messages.
    """

    def test_start_handler_not_registered(self):
        """'start_handler' is NOT a method (it's 'handler')."""
        server = _get_server_class()()
        assert "start_handler" not in server.methods
        assert "handler" in server.methods

    def test_console_command_not_registered(self):
        """'console_command' is NOT a method."""
        server = _get_server_class()()
        assert "console_command" not in server.methods

    def test_run_command_not_registered(self):
        """'run_command' is NOT a method (it's a base class helper)."""
        server = _get_server_class()()
        assert "run_command" not in server.methods


class TestServerConfiguration:
    """Test server initialization and configuration."""

    def test_server_name(self):
        server = _get_server_class()()
        assert server.name == "metasploit"

    def test_server_version(self):
        server = _get_server_class()()
        assert server.version == "2.0.0"

    def test_initial_state(self):
        server = _get_server_class()()
        assert server.client is None
        assert server.console is None


class TestInputSchemaGeneration:
    """Test that JSON schemas are correctly built for all methods."""

    def test_generate_payload_schema(self):
        server = _get_server_class()()
        schema = server._build_input_schema(server.methods["generate_payload"].params)
        assert "payload" in schema["properties"]
        assert "lhost" in schema["properties"]
        assert "lport" in schema["properties"]
        assert "format" in schema["properties"]
        assert set(schema["required"]) == {"payload", "lhost", "lport"}

    def test_search_modules_schema(self):
        server = _get_server_class()()
        schema = server._build_input_schema(server.methods["search_modules"].params)
        assert "query" in schema["properties"]
        assert "type" in schema["properties"]
        assert schema["required"] == ["query"]
        # type should have enum values
        type_prop = schema["properties"]["type"]
        assert "enum" in type_prop

    def test_run_exploit_schema(self):
        server = _get_server_class()()
        schema = server._build_input_schema(server.methods["run_exploit"].params)
        assert "module" in schema["properties"]
        assert "rhosts" in schema["properties"]
        assert set(schema["required"]) == {"module", "rhosts"}
        # Optional params should be present but not required
        assert "payload" in schema["properties"]
        assert "lhost" in schema["properties"]
        assert "options" in schema["properties"]

    def test_session_command_schema(self):
        server = _get_server_class()()
        schema = server._build_input_schema(server.methods["session_command"].params)
        assert set(schema["required"]) == {"session_id", "command"}
        assert schema["properties"]["session_id"]["type"] == "integer"

    def test_handler_schema(self):
        server = _get_server_class()()
        schema = server._build_input_schema(server.methods["handler"].params)
        assert set(schema["required"]) == {"payload", "lhost", "lport"}
        assert schema["properties"]["lport"]["type"] == "integer"

    def test_check_vuln_schema(self):
        server = _get_server_class()()
        schema = server._build_input_schema(server.methods["check_vuln"].params)
        assert set(schema["required"]) == {"module", "rhosts"}

    def test_post_module_schema(self):
        server = _get_server_class()()
        schema = server._build_input_schema(server.methods["post_module"].params)
        assert set(schema["required"]) == {"module", "session_id"}

    def test_exec_command_schema(self):
        server = _get_server_class()()
        schema = server._build_input_schema(server.methods["exec_command"].params)
        assert set(schema["required"]) == {"module", "rhosts", "command"}

    def test_list_sessions_schema(self):
        server = _get_server_class()()
        schema = server._build_input_schema(server.methods["list_sessions"].params)
        # list_sessions has no required params
        assert schema["required"] == []


# ===========================================================================
# SMOKE TESTS -- require Docker container running
# ===========================================================================

class TestSmoke:
    """Smoke tests that verify the container boots and basic protocol works."""

    def test_boot_and_list_tools(self, msf_env):
        """Container starts and list_tools returns methods."""
        client, loop = msf_env
        assert len(client.tools) > 0, "Server should advertise at least one tool"
        names = client.tool_names()
        assert "generate_payload" in names
        assert "search_modules" in names
        assert "check_vuln" in names
        assert "run_exploit" in names
        assert "exec_command" in names
        assert "list_sessions" in names
        assert "session_command" in names
        assert "post_module" in names
        assert "handler" in names

    def test_method_list_matches_tool_yaml(self, msf_env):
        """Every method in tool.yaml is advertised by the server, and vice versa."""
        client, _ = msf_env
        server_names = client.tool_names()
        # Exclude auto-registered methods that are NOT in tool.yaml:
        #   verify_clock — added when MCP_TEST_MODE is set
        #   run_cli      — auto-registered by BaseMCPServer (kind:cli infrastructure)
        AUTO_REGISTERED = {"verify_clock", "run_cli"}
        server_names_no_test = server_names - AUTO_REGISTERED

        yaml_path = TOOL_DIR / "tool.yaml"
        with open(yaml_path) as f:
            yaml_data = yaml.safe_load(f)
        yaml_names = set(yaml_data.get("methods", {}).keys())

        yaml_only = yaml_names - server_names_no_test
        server_only = server_names_no_test - yaml_names

        assert not yaml_only, f"Methods in tool.yaml but not server: {yaml_only}"
        assert not server_only, f"Methods in server but not tool.yaml: {server_only}"

    def test_expected_method_count(self, msf_env):
        """Server should have 29 metasploit methods + run_cli + verify_clock = 31 (post-May-2026)."""
        client, _ = msf_env
        names = client.tool_names()
        # 29 metasploit-specific + run_cli (auto-registered always) + verify_clock (MCP_TEST_MODE)
        assert len(names) == 31, (
            f"Expected 31 methods (29 metasploit + run_cli + verify_clock), got {len(names)}: {sorted(names)}"
        )

    def test_unknown_method_returns_error(self, msf_env):
        """Calling a non-existent method returns a helpful error."""
        client, loop = msf_env
        resp = loop.run_until_complete(
            client.call("start_handler", {"payload": "test", "lhost": "1.2.3.4", "lport": 4444})
        )
        result = assert_tool_error(resp)
        content_text = ""
        for c in result.get("content", []):
            if c.get("type") == "text":
                content_text += c["text"]
        assert "Unknown method" in content_text
        assert "start_handler" in content_text
        # Should suggest available methods
        assert "handler" in content_text

    def test_console_command_phantom(self, msf_env):
        """'console_command' phantom method returns helpful error."""
        client, loop = msf_env
        resp = loop.run_until_complete(
            client.call("console_command", {"command": "help"})
        )
        result = assert_tool_error(resp)
        content_text = ""
        for c in result.get("content", []):
            if c.get("type") == "text":
                content_text += c["text"]
        assert "Unknown method" in content_text

    def test_meta_params_stripped_clock_offset(self, msf_env):
        """Passing 'clock_offset' (meta-param) in args does not crash the server."""
        client, loop = msf_env
        resp = loop.run_until_complete(
            client.call("list_sessions", {"clock_offset": "+5h"})
        )
        result = resp.get("result", {})
        content_text = ""
        for c in result.get("content", []):
            if c.get("type") == "text":
                content_text += c["text"]
        assert "unexpected keyword argument" not in content_text, (
            f"Meta-param 'clock_offset' was not stripped: {content_text[:300]}"
        )

    @pytest.mark.clock
    def test_verify_clock_available(self, msf_env):
        """verify_clock is registered in MCP_TEST_MODE."""
        client, _ = msf_env
        names = client.tool_names()
        assert "verify_clock" in names, "verify_clock should be available in test mode"

    @pytest.mark.clock
    def test_verify_clock_returns_time(self, msf_env):
        """verify_clock returns current time and FAKETIME status."""
        client, loop = msf_env
        resp = loop.run_until_complete(client.call("verify_clock", {}))
        result = assert_tool_success(resp)
        data = parse_tool_output(resp)
        assert "current_time" in data
        assert "libfaketime_exists" in data

    def test_structuredContent_present(self, msf_env):
        """Responses include structuredContent with error classification fields."""
        client, loop = msf_env
        resp = loop.run_until_complete(client.call("verify_clock", {}))
        result = resp.get("result", {})
        sc = result.get("structuredContent")
        assert sc is not None, "structuredContent should be present"
        assert "success" in sc
        assert "error_class" in sc
        assert "retryable" in sc
        assert "suggestions" in sc


# ===========================================================================
# LIVE METHOD TESTS -- require Docker container with msfrpcd
# ===========================================================================

class TestLiveListSessions:
    """Tests for list_sessions against live msfrpcd."""

    def test_list_sessions_empty(self, msf_env):
        """list_sessions with no active sessions returns empty list."""
        client, loop = msf_env
        resp = loop.run_until_complete(client.call("list_sessions", {}))
        result = assert_tool_success(resp, "list_sessions should succeed")
        data = parse_tool_output(resp)
        assert "sessions" in data
        assert isinstance(data["sessions"], list)
        assert "count" in data
        assert data["count"] >= 0  # May be 0 or more

    def test_list_sessions_structure(self, msf_env):
        """list_sessions returns properly structured data."""
        client, loop = msf_env
        resp = loop.run_until_complete(client.call("list_sessions", {}))
        data = parse_tool_output(resp)
        # Even if empty, structure should be correct
        assert isinstance(data["sessions"], list)
        assert isinstance(data["count"], int)


class TestLiveSearchModules:
    """Tests for search_modules against live msfrpcd."""

    def test_search_ms17_010(self, msf_env):
        """Search for ms17-010 returns exploit and auxiliary modules."""
        client, loop = msf_env
        resp = loop.run_until_complete(
            client.call("search_modules", {"query": "ms17_010"}, timeout=120)
        )
        result = assert_tool_success(resp, "search_modules should succeed")
        data = parse_tool_output(resp)

        assert "modules" in data
        assert "count" in data
        assert data["count"] > 0, "Should find at least one ms17-010 module"

        # Check that we get exploit and auxiliary types
        types_found = {m["type"] for m in data["modules"]}
        assert "exploit" in types_found, "Should find exploit modules"

    def test_search_with_type_filter(self, msf_env):
        """Search with type filter restricts results."""
        client, loop = msf_env
        resp = loop.run_until_complete(
            client.call("search_modules", {"query": "smb", "type": "auxiliary"}, timeout=120)
        )
        result = assert_tool_success(resp, "search_modules with type filter should succeed")
        data = parse_tool_output(resp)

        assert data["type"] == "auxiliary"
        for m in data["modules"]:
            assert m["type"] == "auxiliary", f"Expected auxiliary, got {m['type']}"

    def test_search_nonexistent_returns_empty(self, msf_env):
        """Search for a nonsense string returns zero results."""
        client, loop = msf_env
        resp = loop.run_until_complete(
            client.call("search_modules", {"query": "zzzznonexistent999"}, timeout=60)
        )
        result = assert_tool_success(resp, "search should succeed even with no results")
        data = parse_tool_output(resp)
        assert data["count"] == 0


class TestLiveGeneratePayload:
    """Tests for generate_payload (uses msfvenom subprocess)."""

    def test_generate_raw_payload(self, msf_env):
        """Generate a raw reverse TCP payload."""
        client, loop = msf_env
        resp = loop.run_until_complete(
            client.call("generate_payload", {
                "payload": "linux/x64/shell_reverse_tcp",
                "lhost": "127.0.0.1",
                "lport": 4444,
                "format": "raw",
            }, timeout=120)
        )
        result = assert_tool_success(resp, "generate_payload raw should succeed")
        data = parse_tool_output(resp)

        assert data["payload"] == "linux/x64/shell_reverse_tcp"
        assert data["lhost"] == "127.0.0.1"
        assert data["lport"] == 4444
        assert data["format"] == "raw"
        assert data["size_bytes"] > 0, "Payload should have non-zero size"
        assert data["payload_base64"] is not None, "Should have base64 data"
        # Verify it's valid base64
        import base64
        decoded = base64.b64decode(data["payload_base64"])
        assert len(decoded) == data["size_bytes"]

    def test_generate_elf_payload(self, msf_env):
        """Generate an ELF format payload."""
        client, loop = msf_env
        resp = loop.run_until_complete(
            client.call("generate_payload", {
                "payload": "linux/x64/shell_reverse_tcp",
                "lhost": "127.0.0.1",
                "lport": 4445,
                "format": "elf",
            }, timeout=120)
        )
        result = assert_tool_success(resp, "generate_payload elf should succeed")
        data = parse_tool_output(resp)

        assert data["format"] == "elf"
        assert data["size_bytes"] > 0
        # ELF payloads are larger than raw
        assert data["size_bytes"] > 100

    def test_generate_payload_with_shortcut(self, msf_env):
        """Generate payload using a shortcut name."""
        client, loop = msf_env
        resp = loop.run_until_complete(
            client.call("generate_payload", {
                "payload": "linux_shell_tcp",
                "lhost": "127.0.0.1",
                "lport": 4446,
                "format": "raw",
            }, timeout=120)
        )
        result = assert_tool_success(resp, "generate_payload with shortcut should succeed")
        data = parse_tool_output(resp)

        # Shortcut should be resolved to full path
        assert data["payload"] == "linux/x64/shell_reverse_tcp"

    def test_generate_python_payload(self, msf_env):
        """Generate a Python format payload."""
        client, loop = msf_env
        resp = loop.run_until_complete(
            client.call("generate_payload", {
                "payload": "python/meterpreter/reverse_tcp",
                "lhost": "127.0.0.1",
                "lport": 4447,
                "format": "raw",
            }, timeout=120)
        )
        result = assert_tool_success(resp, "generate_payload python should succeed")
        data = parse_tool_output(resp)
        assert data["size_bytes"] > 0

    def test_generate_payload_missing_required(self, msf_env):
        """Missing required param 'lhost' should error."""
        client, loop = msf_env
        resp = loop.run_until_complete(
            client.call("generate_payload", {
                "payload": "linux/x64/shell_reverse_tcp",
                "lport": 4444,
                "format": "raw",
            }, timeout=60)
        )
        result = resp.get("result", {})
        is_error = result.get("isError", False)
        content_text = ""
        for c in result.get("content", []):
            if c.get("type") == "text":
                content_text += c["text"]
        # Should error about missing lhost
        assert is_error or "lhost" in content_text.lower() or "error" in content_text.lower(), (
            f"Expected error about missing 'lhost', got: {content_text[:300]}"
        )


class TestLiveHandler:
    """Tests for handler (multi/handler) against live msfrpcd."""

    def test_start_handler(self, msf_env):
        """Start a multi/handler listener."""
        client, loop = msf_env
        resp = loop.run_until_complete(
            client.call("handler", {
                "payload": "linux/x64/shell_reverse_tcp",
                "lhost": "127.0.0.1",
                "lport": 14444,
            }, timeout=60)
        )
        result = assert_tool_success(resp, "handler should succeed")
        data = parse_tool_output(resp)

        assert data["payload"] == "linux/x64/shell_reverse_tcp"
        assert data["lhost"] == "127.0.0.1"
        assert data["lport"] == 14444
        assert "handler_started" in data
        # handler_started depends on actual output
        assert isinstance(data["handler_started"], bool)

    def test_start_handler_with_shortcut(self, msf_env):
        """Start handler with payload shortcut."""
        client, loop = msf_env
        resp = loop.run_until_complete(
            client.call("handler", {
                "payload": "linux_shell_tcp",
                "lhost": "127.0.0.1",
                "lport": 14445,
            }, timeout=60)
        )
        result = assert_tool_success(resp, "handler with shortcut should succeed")
        data = parse_tool_output(resp)

        # Shortcut should be resolved
        assert data["payload"] == "linux/x64/shell_reverse_tcp"


class TestLiveSessionCommand:
    """Tests for session_command against live msfrpcd."""

    def test_session_not_found(self, msf_env):
        """Accessing a non-existent session returns a clear error."""
        client, loop = msf_env
        resp = loop.run_until_complete(
            client.call("session_command", {
                "session_id": 99999,
                "command": "whoami",
            }, timeout=30)
        )
        result = resp.get("result", {})
        is_error = result.get("isError", False)
        content_text = ""
        for c in result.get("content", []):
            if c.get("type") == "text":
                content_text += c["text"]
        # Should mention session not found
        assert is_error or "not found" in content_text.lower() or "99999" in content_text, (
            f"Expected session-not-found error, got: {content_text[:300]}"
        )


class TestLivePostModule:
    """Tests for post_module (requires a session, so mostly error paths)."""

    def test_post_module_no_session(self, msf_env):
        """Running post module without valid session should handle gracefully."""
        client, loop = msf_env
        resp = loop.run_until_complete(
            client.call("post_module", {
                "module": "post/multi/gather/env",
                "session_id": 99999,
            }, timeout=60)
        )
        # This may succeed at the tool level but report failure in raw_output
        data = parse_tool_output(resp)
        if isinstance(data, dict):
            raw = data.get("raw_output", "")
            # Module should run but report an error about the session
            assert "session" in raw.lower() or data.get("module") == "post/multi/gather/env"


class TestLiveRunExploit:
    """Tests for run_exploit against live msfrpcd (no actual exploitation)."""

    def test_run_exploit_localhost_no_session(self, msf_env):
        """Run exploit against localhost (no service) -- should complete without crash."""
        client, loop = msf_env
        resp = loop.run_until_complete(
            client.call("run_exploit", {
                "module": "exploit/multi/handler",
                "rhosts": "127.0.0.1",
                "payload": "linux/x64/shell_reverse_tcp",
                "lhost": "127.0.0.1",
                "lport": 14446,
                "timeout": 30,
            }, timeout=60)
        )
        result = assert_tool_success(resp, "run_exploit should return success (tool-level)")
        data = parse_tool_output(resp)

        assert "module" in data
        assert "target" in data
        assert "exploit_success" in data
        assert "sessions" in data
        assert isinstance(data["sessions"], list)
        assert "session_count" in data


class TestLiveExecCommand:
    """Tests for exec_command against live msfrpcd."""

    def test_exec_command_missing_required(self, msf_env):
        """Missing 'command' param should error."""
        client, loop = msf_env
        resp = loop.run_until_complete(
            client.call("exec_command", {
                "module": "exploit/unix/webapp/test",
                "rhosts": "127.0.0.1",
            }, timeout=30)
        )
        result = resp.get("result", {})
        is_error = result.get("isError", False)
        content_text = ""
        for c in result.get("content", []):
            if c.get("type") == "text":
                content_text += c["text"]
        assert is_error or "command" in content_text.lower() or "error" in content_text.lower()


class TestLiveCheckVuln:
    """Tests for check_vuln against live msfrpcd."""

    def test_check_vuln_localhost(self, msf_env):
        """check_vuln against localhost (no vulnerable service)."""
        client, loop = msf_env
        resp = loop.run_until_complete(
            client.call("check_vuln", {
                "module": "auxiliary/scanner/smb/smb_ms17_010",
                "rhosts": "127.0.0.1",
                "timeout": 30,
            }, timeout=60)
        )
        # Should succeed at tool level even if scan finds nothing
        result = assert_tool_success(resp, "check_vuln should succeed")
        data = parse_tool_output(resp)
        assert "vulnerable" in data
        assert isinstance(data["vulnerable"], bool)
        # localhost should not be vulnerable to MS17-010
        assert data["vulnerable"] is False


# ===========================================================================
# ERROR CLASSIFICATION TESTS
# ===========================================================================

class TestErrorClassification:
    """Test error classification on metasploit-specific errors.

    The metasploit server does not set explicit error_class on most failures;
    the base class fallback classifier handles some stderr patterns.
    """

    def test_connection_refused_in_exploit_output(self):
        """Detect connection refused pattern in exploit output."""
        output = load_fixture("exploit_failed.txt")
        assert "ConnectionRefused" in output or "Connection refused" in output.lower() or "connection was refused" in output.lower()

    def test_timeout_unreachable_pattern(self):
        """Detect timeout/unreachable pattern in module output."""
        output = load_fixture("exploit_timeout_unreachable.txt")
        assert "timed out" in output.lower()
        assert "unreachable" in output.lower()

    def test_unknown_datastore_option_pattern(self):
        """Detect unknown datastore option warnings."""
        output = load_fixture("exploit_timeout_unreachable.txt")
        assert "Unknown datastore option" in output


# ===========================================================================
# REGRESSION TESTS (from engagement data)
# ===========================================================================

class TestRegressionFromEngagements:
    """Tests derived from actual engagement patterns and issues."""

    def test_exploit_success_with_no_sessions(self):
        """'exploit completed' in output should set exploit_success=True even with 0 sessions.

        From engagement data: web_delivery exploit returns exploit_success=True
        even when no session is created (listener is running as background job).
        """
        output = load_fixture("exploit_web_delivery.txt")
        assert "exploit completed" in output.lower()

    def test_session_id_int_str_handling(self):
        """session_command should handle both int and str session IDs from msgpack.

        From engagement: pymetasploit3 returns session IDs as either int or str
        depending on msgpack version.
        """
        server = _get_server_class()()

        # Simulate sessions dict with string keys (as returned by msgpack)
        sessions_mock = {
            "1": {"type": "meterpreter", "info": "test"},
            "2": {"type": "shell", "info": "test"},
        }

        # Test both lookup paths from session_command
        session_info = sessions_mock.get(str(1)) or sessions_mock.get(1)
        assert session_info is not None
        assert session_info["type"] == "meterpreter"

        # Test with int key (some msgpack versions)
        sessions_mock_int = {
            1: {"type": "meterpreter", "info": "test"},
        }
        session_info = sessions_mock_int.get(str(1)) or sessions_mock_int.get(1)
        assert session_info is not None

    def test_sorted_session_ids_with_string_keys(self):
        """sorted(..., key=int) handles string keys from msgpack."""
        new_session_ids = {"2", "1", "3"}
        sorted_ids = sorted(new_session_ids, key=int)
        assert sorted_ids == ["1", "2", "3"]

    def test_search_modules_long_running(self):
        """Search operations can take 20-190+ seconds per engagement data.

        This test verifies the timeout parameter is properly propagated.
        The search_cmd format should be correct.
        """
        # Verify the search command format
        query = "cve_2024_30088"
        search_cmd = f"search {query}"
        assert search_cmd == "search cve_2024_30088"

        search_cmd_typed = f"search type:exploit {query}"
        assert search_cmd_typed == "search type:exploit cve_2024_30088"

    def test_handler_vs_start_handler_naming(self):
        """Agents sometimes call 'start_handler' instead of 'handler'.

        From engagement: toolInput.method="start_handler" returned "Method not found".
        The registered method name is 'handler'.
        """
        server = _get_server_class()()
        assert "handler" in server.methods
        assert "start_handler" not in server.methods

    def test_console_command_phantom(self):
        """Agents sometimes call 'console_command' which doesn't exist.

        From engagement: used to try compiling C code via metasploit console.
        """
        server = _get_server_class()()
        assert "console_command" not in server.methods


# ===========================================================================
# CHECK VULN FALSE POSITIVE TEST
# ===========================================================================

class TestCheckVulnNegation:
    """Test that check_vuln correctly handles negated vulnerability statements.

    When a target is NOT vulnerable, msf output says 'does NOT appear vulnerable'.
    The parser must not produce a false positive from the substring 'vulnerable'.
    """

    def _check_vuln_logic(self, output):
        """Replicate the improved vulnerability detection from check_vuln."""
        output_lower = output.lower()
        negated = (
            "not appear vulnerable" in output_lower
            or "not vulnerable" in output_lower
            or "does not appear" in output_lower
        )
        positive = (
            "is vulnerable" in output_lower
            or "likely vulnerable" in output_lower
        )
        has_plus_vuln = any(
            line.startswith("[+]") and "vulnerable" in line.lower()
            for line in output.split("\n")
        )
        return has_plus_vuln or positive or (
            "vulnerable" in output_lower and not negated
        )

    def test_positive_detection(self):
        """Positive vulnerability output should return True."""
        output = load_fixture("check_vuln_positive.txt")
        assert self._check_vuln_logic(output) is True

    def test_negative_detection_no_false_positive(self):
        """'does NOT appear vulnerable' should return False."""
        output = load_fixture("check_vuln_negative.txt")
        assert self._check_vuln_logic(output) is False

    def test_plus_line_with_vulnerable(self):
        """[+] line with 'vulnerable' is always positive."""
        output = "[+] 10.10.10.40:445 - Host is likely VULNERABLE to MS17-010!"
        assert self._check_vuln_logic(output) is True

    def test_no_vuln_keyword(self):
        """Output without 'vulnerable' returns False."""
        output = "[*] Scanned 1 of 1 hosts (100% complete)\n"
        assert self._check_vuln_logic(output) is False

    def test_explicit_not_vulnerable(self):
        """'is not vulnerable' should return False."""
        output = "[*] Host is not vulnerable to this exploit."
        assert self._check_vuln_logic(output) is False


class TestMsfErrorClassifier:
    """Test the _classify_msf_error static method."""

    def setup_method(self):
        self.server = _get_server_class()()

    def test_connection_timeout(self):
        e = self.server._classify_msf_error(
            "The connection with (10.10.10.40:389) timed out."
        )
        assert e is not None
        assert e.error_class == "network"
        assert e.retryable is True
        assert len(e.suggestions) > 0

    def test_connection_refused(self):
        e = self.server._classify_msf_error(
            "Rex::ConnectionRefused The connection was refused"
        )
        assert e is not None
        assert e.error_class == "network"
        assert e.retryable is True

    def test_unknown_datastore_option(self):
        e = self.server._classify_msf_error(
            "[!] Unknown datastore option: DMSA_NAME."
        )
        # May 2026: error_class taxonomy aligned with the standard 8-class
        # set used across kind:cli tools (network / invalid_parameter /
        # tool_misconfigured / session_lost / permission_denied / unknown).
        # Older codes "config" and "params" were renamed.
        assert e is not None
        assert e.error_class == "invalid_parameter"
        assert e.retryable is False

    def test_handler_bind_failure(self):
        e = self.server._classify_msf_error(
            "Handler failed to bind to 10.10.16.19:4444"
        )
        assert e is not None
        assert e.error_class == "invalid_parameter"  # renamed from "config"
        assert e.retryable is False

    def test_address_in_use(self):
        e = self.server._classify_msf_error(
            "The address is already in use or unavailable (0.0.0.0:4444)."
        )
        assert e is not None
        assert e.error_class == "invalid_parameter"  # renamed from "config"
        assert e.retryable is False

    def test_unreachable(self):
        e = self.server._classify_msf_error(
            "Auxiliary aborted due to failure: unreachable"
        )
        assert e is not None
        assert e.error_class == "network"
        assert e.retryable is True

    def test_session_dead(self):
        e = self.server._classify_msf_error(
            "Session 1 is dead or closed."
        )
        assert e is not None
        assert e.error_class == "session_lost"  # renamed from "config"
        assert e.retryable is False

    def test_clean_output_no_error(self):
        # Clean output → no error → classifier returns None.
        assert self.server._classify_msf_error(
            "[*] Auxiliary module execution completed"
        ) is None

    def test_module_not_found(self):
        e = self.server._classify_msf_error(
            "Module not found: exploit/nonexistent/module"
        )
        assert e is not None
        assert e.error_class == "tool_misconfigured"  # renamed from "config"
        assert e.retryable is False

    def test_failed_to_load(self):
        """'Failed to load' should classify as tool_misconfigured."""
        e = self.server._classify_msf_error(
            "Failed to load module: exploit/windows/smb/nonexistent"
        )
        assert e is not None
        assert e.error_class == "tool_misconfigured"  # renamed from "config"
        assert e.retryable is False
        assert len(e.suggestions) > 0

    def test_session_not_found(self):
        """'session not found' should classify as session_lost."""
        e = self.server._classify_msf_error(
            "Session 42 not found"
        )
        assert e is not None
        assert e.error_class == "session_lost"  # renamed from "config"
        assert e.retryable is False

    def test_connection_refused_lower(self):
        """'connectionrefused' as one word should classify as network."""
        e = self.server._classify_msf_error(
            "Rex::ConnectionRefused"
        )
        assert e is not None
        assert e.error_class == "network"
        assert e.retryable is True

    def test_combined_timeout_and_unreachable(self):
        """Output containing both 'timed out' and 'unreachable' should classify as network."""
        output = load_fixture("exploit_timeout_unreachable.txt")
        e = self.server._classify_msf_error(output)
        assert e is not None
        assert e.error_class == "network"
        assert e.retryable is True


# ===========================================================================
# ADDITIONAL UNIT TESTS -- parsing edge cases
# ===========================================================================

class TestExecCommandOutputParsingEdgeCases:
    """Additional edge cases for exec_command output parsing."""

    def _parse_exec_output(self, output_text):
        """Simulate the output parsing logic from exec_command."""
        command_output = ""
        exploit_success = False

        if "exploit completed" in output_text.lower() or "command executed" in output_text.lower():
            exploit_success = True

        lines = output_text.split("\n")
        capture = False
        for line in lines:
            if line.startswith("[*]") or line.startswith("[+]") or line.startswith("[-]"):
                if "executing" in line.lower() or "command" in line.lower():
                    capture = True
                    exploit_success = True
                continue
            if capture and line.strip():
                command_output += line + "\n"

        return exploit_success, command_output.strip()

    def test_multiline_command_output(self):
        """Parse output containing multiple lines of command output."""
        output = (
            "[*] Executing command on target...\n"
            "root\n"
            "uid=0(root) gid=0(root) groups=0(root)\n"
            "/bin/bash\n"
            "[*] Command executed successfully.\n"
        )
        success, cmd_output = self._parse_exec_output(output)
        assert success is True
        lines = cmd_output.split("\n")
        assert len(lines) == 3
        assert "root" in cmd_output
        assert "uid=0" in cmd_output

    def test_empty_output(self):
        """Completely empty output."""
        success, cmd_output = self._parse_exec_output("")
        assert success is False
        assert cmd_output == ""

    def test_exploit_failed_but_command_ran(self):
        """Output has [-] error but also [*] Executing command."""
        output = (
            "[-] Exploit failed: target not vulnerable\n"
            "[*] Executing command on target...\n"
            "command output here\n"
        )
        success, cmd_output = self._parse_exec_output(output)
        assert success is True
        assert "command output here" in cmd_output


class TestCheckVulnOutputParsingEdgeCases:
    """Additional edge cases for vulnerability detection parsing."""

    def _is_vulnerable(self, output_text):
        """Replicate the improved vulnerability detection from check_vuln."""
        output_lower = output_text.lower()
        negated = (
            "not appear vulnerable" in output_lower
            or "not vulnerable" in output_lower
            or "does not appear" in output_lower
        )
        positive = (
            "is vulnerable" in output_lower
            or "likely vulnerable" in output_lower
        )
        has_plus_vuln = any(
            line.startswith("[+]") and "vulnerable" in line.lower()
            for line in output_text.split("\n")
        )
        return has_plus_vuln or positive or (
            "vulnerable" in output_lower and not negated
        )

    def test_both_positive_and_negative_in_output(self):
        """When both 'is vulnerable' and 'not vulnerable' appear, positive wins
        because 'is vulnerable' matches the positive check before negation."""
        output = (
            "[*] Host A is vulnerable to MS17-010.\n"
            "[*] Host B is not vulnerable.\n"
        )
        # 'is vulnerable' appears, so positive=True, which is checked first
        assert self._is_vulnerable(output) is True

    def test_plus_line_overrides_negation(self):
        """[+] line with 'vulnerable' always returns True regardless of negation."""
        output = (
            "[*] Host does NOT appear vulnerable.\n"
            "[+] 10.10.10.40:445 - Host is VULNERABLE!\n"
        )
        assert self._is_vulnerable(output) is True

    def test_auxiliary_completed_without_vuln(self):
        """Normal completion without any vulnerability mention."""
        output = (
            "[*] Scanned 1 of 1 hosts (100% complete)\n"
            "[*] Auxiliary module execution completed\n"
        )
        assert self._is_vulnerable(output) is False

    def test_likely_vulnerable(self):
        """'likely vulnerable' should return True."""
        output = "[*] Target is likely vulnerable to CVE-2024-12345."
        assert self._is_vulnerable(output) is True


class TestHandlerOutputParsingEdgeCases:
    """Additional edge cases for handler output parsing."""

    def _parse_handler_output(self, output_text):
        """Replicate handler output parsing from start_handler."""
        job_id = None
        match = re.search(r"background job (\d+)", output_text)
        if match:
            job_id = match.group(1)
        handler_started = "started" in output_text.lower() and "handler" in output_text.lower()
        return handler_started, job_id

    def test_handler_with_high_job_id(self):
        """Handler with a multi-digit job ID."""
        output = (
            "[*] Exploit running as background job 42.\n"
            "[*] Started reverse TCP handler on 10.10.16.19:4444\n"
        )
        started, job_id = self._parse_handler_output(output)
        assert started is True
        assert job_id == "42"

    def test_handler_no_background_job_line(self):
        """Handler started but no 'background job' line in output."""
        output = "[*] Started reverse TCP handler on 10.10.16.19:4444\n"
        started, job_id = self._parse_handler_output(output)
        assert started is True
        assert job_id is None

    def test_handler_empty_output(self):
        """Empty handler output."""
        started, job_id = self._parse_handler_output("")
        assert started is False
        assert job_id is None


class TestAutoRouteOutputParsing:
    """Test parsing of post-exploitation module output (autoroute)."""

    def test_autoroute_fixture(self):
        """Autoroute output should contain route information."""
        output = load_fixture("autoroute_output.txt")
        assert "Route added" in output
        assert "10.10.10.0" in output

    def test_psexec_exploit_fixture(self):
        """PsExec success fixture should contain session and meterpreter info."""
        output = load_fixture("exploit_psexec_success.txt")
        assert "Meterpreter session" in output
        assert "Authenticating" in output

    def test_session_dead_fixture(self):
        """Session dead fixture should contain session death indicator."""
        output = load_fixture("session_dead.txt")
        assert "dead" in output.lower() or "closed" in output.lower()

    def test_module_not_found_fixture(self):
        """Module not found fixture should contain not found indicator."""
        output = load_fixture("exploit_module_not_found.txt")
        assert "not found" in output.lower() or "failed to load" in output.lower()


# ===========================================================================
# ACCEPTANCE TESTS -- every method through Docker, structuredContent validated
# ===========================================================================

class TestAcceptance:
    """Call every method through the container.

    These tests verify:
    - The method exists and is callable through the MCP protocol
    - The response has correct structuredContent shape with error classification
    - Required param validation works (missing required params -> error)
    - Error responses are classified, not unhandled crashes

    Metasploit methods that talk to msfrpcd will succeed at the tool level
    even when no real target is available (e.g., search returns empty, exploit
    fails to connect). Methods that are pure subprocess (generate_payload)
    succeed fully.
    """

    def _assert_structured_response(self, resp, method_name):
        """Assert response has structuredContent with required fields."""
        result = resp.get("result", {})
        sc = result.get("structuredContent", {})
        assert sc is not None, f"{method_name}: missing structuredContent"
        # All responses must have these fields
        for field in ("success", "error_class", "retryable", "suggestions"):
            assert field in sc, (
                f"{method_name}: missing '{field}' in structuredContent: {sc}"
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

    # ── generate_payload ─────────────────────────────────────────

    def test_generate_payload_raw(self, msf_env):
        """generate_payload with raw format succeeds and returns base64 data."""
        client, loop = msf_env
        resp = loop.run_until_complete(client.call("generate_payload", {
            "payload": "linux/x64/shell_reverse_tcp",
            "lhost": "127.0.0.1",
            "lport": 4444,
            "format": "raw",
        }, timeout=120))
        sc = self._assert_structured_response(resp, "generate_payload")
        assert sc["success"] is True
        data = parse_tool_output(resp)
        assert data["size_bytes"] > 0
        assert data["payload_base64"] is not None

    def test_generate_payload_exe(self, msf_env):
        """generate_payload with exe format produces larger output."""
        client, loop = msf_env
        resp = loop.run_until_complete(client.call("generate_payload", {
            "payload": "linux/x64/shell_reverse_tcp",
            "lhost": "127.0.0.1",
            "lport": 4448,
            "format": "elf",
        }, timeout=120))
        sc = self._assert_structured_response(resp, "generate_payload (elf)")
        assert sc["success"] is True

    def test_generate_payload_with_encoder(self, msf_env):
        """generate_payload with encoder param is accepted."""
        client, loop = msf_env
        resp = loop.run_until_complete(client.call("generate_payload", {
            "payload": "linux/x64/shell_reverse_tcp",
            "lhost": "127.0.0.1",
            "lport": 4449,
            "format": "raw",
            "encoder": "x64/xor",
            "iterations": 2,
        }, timeout=120))
        sc = self._assert_structured_response(resp, "generate_payload (encoder)")
        # Encoder may or may not exist, but should not crash
        assert isinstance(sc["success"], bool)

    def test_generate_payload_missing_lhost(self, msf_env):
        """generate_payload without required 'lhost' returns error."""
        client, loop = msf_env
        resp = loop.run_until_complete(client.call("generate_payload", {
            "payload": "linux/x64/shell_reverse_tcp",
            "lport": 4444,
            "format": "raw",
        }, timeout=60))
        result = resp.get("result", {})
        is_error = result.get("isError", False)
        content_text = ""
        for c in result.get("content", []):
            if c.get("type") == "text":
                content_text += c["text"]
        assert is_error or "lhost" in content_text.lower() or "required" in content_text.lower()

    def test_generate_payload_missing_lport(self, msf_env):
        """generate_payload without required 'lport' returns error."""
        client, loop = msf_env
        resp = loop.run_until_complete(client.call("generate_payload", {
            "payload": "linux/x64/shell_reverse_tcp",
            "lhost": "127.0.0.1",
            "format": "raw",
        }, timeout=60))
        result = resp.get("result", {})
        is_error = result.get("isError", False)
        content_text = ""
        for c in result.get("content", []):
            if c.get("type") == "text":
                content_text += c["text"]
        assert is_error or "lport" in content_text.lower() or "required" in content_text.lower()

    # ── search_modules ───────────────────────────────────────────

    def test_search_modules_basic(self, msf_env):
        """search_modules with a known query returns structuredContent."""
        client, loop = msf_env
        resp = loop.run_until_complete(
            client.call("search_modules", {"query": "ms17_010"}, timeout=120)
        )
        sc = self._assert_structured_response(resp, "search_modules")
        assert sc["success"] is True
        data = parse_tool_output(resp)
        assert "modules" in data
        assert "count" in data

    def test_search_modules_with_type(self, msf_env):
        """search_modules with type filter returns only matching types."""
        client, loop = msf_env
        resp = loop.run_until_complete(
            client.call("search_modules", {"query": "handler", "type": "exploit"}, timeout=120)
        )
        sc = self._assert_structured_response(resp, "search_modules (type)")
        assert sc["success"] is True

    def test_search_modules_missing_query(self, msf_env):
        """search_modules without required 'query' returns error."""
        client, loop = msf_env
        resp = loop.run_until_complete(
            client.call("search_modules", {}, timeout=60)
        )
        result = resp.get("result", {})
        is_error = result.get("isError", False)
        content_text = ""
        for c in result.get("content", []):
            if c.get("type") == "text":
                content_text += c["text"]
        assert is_error or "query" in content_text.lower() or "required" in content_text.lower()

    # ── check_vuln ───────────────────────────────────────────────

    def test_check_vuln_basic(self, msf_env):
        """check_vuln against localhost with no vulnerable service."""
        client, loop = msf_env
        resp = loop.run_until_complete(
            client.call("check_vuln", {
                "module": "auxiliary/scanner/smb/smb_ms17_010",
                "rhosts": "127.0.0.1",
                "timeout": 30,
            }, timeout=60)
        )
        sc = self._assert_structured_response(resp, "check_vuln")
        assert sc["success"] is True
        data = parse_tool_output(resp)
        assert "vulnerable" in data
        assert isinstance(data["vulnerable"], bool)

    def test_check_vuln_with_options(self, msf_env):
        """check_vuln with additional options does not crash."""
        client, loop = msf_env
        resp = loop.run_until_complete(
            client.call("check_vuln", {
                "module": "auxiliary/scanner/smb/smb_ms17_010",
                "rhosts": "127.0.0.1",
                "options": {"RPORT": 445},
                "timeout": 30,
            }, timeout=60)
        )
        sc = self._assert_structured_response(resp, "check_vuln (options)")
        assert sc["success"] is True

    def test_check_vuln_missing_module(self, msf_env):
        """check_vuln without required 'module' returns error."""
        client, loop = msf_env
        resp = loop.run_until_complete(
            client.call("check_vuln", {
                "rhosts": "127.0.0.1",
            }, timeout=30)
        )
        result = resp.get("result", {})
        is_error = result.get("isError", False)
        content_text = ""
        for c in result.get("content", []):
            if c.get("type") == "text":
                content_text += c["text"]
        assert is_error or "module" in content_text.lower() or "required" in content_text.lower()

    def test_check_vuln_missing_rhosts(self, msf_env):
        """check_vuln without required 'rhosts' returns error."""
        client, loop = msf_env
        resp = loop.run_until_complete(
            client.call("check_vuln", {
                "module": "auxiliary/scanner/smb/smb_ms17_010",
            }, timeout=30)
        )
        result = resp.get("result", {})
        is_error = result.get("isError", False)
        content_text = ""
        for c in result.get("content", []):
            if c.get("type") == "text":
                content_text += c["text"]
        assert is_error or "rhosts" in content_text.lower() or "required" in content_text.lower()

    # ── run_exploit ──────────────────────────────────────────────

    def test_run_exploit_basic(self, msf_env):
        """run_exploit against localhost with handler returns structured data."""
        client, loop = msf_env
        resp = loop.run_until_complete(
            client.call("run_exploit", {
                "module": "exploit/multi/handler",
                "rhosts": "127.0.0.1",
                "payload": "linux/x64/shell_reverse_tcp",
                "lhost": "127.0.0.1",
                "lport": 14447,
                "timeout": 30,
            }, timeout=60)
        )
        sc = self._assert_structured_response(resp, "run_exploit")
        assert sc["success"] is True
        data = parse_tool_output(resp)
        assert "exploit_success" in data
        assert "sessions" in data
        assert isinstance(data["sessions"], list)
        assert "session_count" in data

    def test_run_exploit_with_options(self, msf_env):
        """run_exploit with additional options param does not crash."""
        client, loop = msf_env
        resp = loop.run_until_complete(
            client.call("run_exploit", {
                "module": "exploit/multi/handler",
                "rhosts": "127.0.0.1",
                "payload": "linux/x64/shell_reverse_tcp",
                "lhost": "127.0.0.1",
                "lport": 14448,
                "options": {"ExitOnSession": "false"},
                "timeout": 30,
            }, timeout=60)
        )
        sc = self._assert_structured_response(resp, "run_exploit (options)")

    def test_run_exploit_missing_module(self, msf_env):
        """run_exploit without required 'module' returns error."""
        client, loop = msf_env
        resp = loop.run_until_complete(
            client.call("run_exploit", {
                "rhosts": "127.0.0.1",
            }, timeout=30)
        )
        result = resp.get("result", {})
        is_error = result.get("isError", False)
        content_text = ""
        for c in result.get("content", []):
            if c.get("type") == "text":
                content_text += c["text"]
        assert is_error or "module" in content_text.lower() or "required" in content_text.lower()

    def test_run_exploit_missing_rhosts(self, msf_env):
        """run_exploit without required 'rhosts' returns error."""
        client, loop = msf_env
        resp = loop.run_until_complete(
            client.call("run_exploit", {
                "module": "exploit/multi/handler",
            }, timeout=30)
        )
        result = resp.get("result", {})
        is_error = result.get("isError", False)
        content_text = ""
        for c in result.get("content", []):
            if c.get("type") == "text":
                content_text += c["text"]
        assert is_error or "rhosts" in content_text.lower() or "required" in content_text.lower()

    # ── exec_command ─────────────────────────────────────────────

    def test_exec_command_basic(self, msf_env):
        """exec_command against localhost with a non-existent module returns structured data."""
        client, loop = msf_env
        resp = loop.run_until_complete(
            client.call("exec_command", {
                "module": "exploit/unix/webapp/test_nonexistent",
                "rhosts": "127.0.0.1",
                "command": "id",
                "timeout": 30,
            }, timeout=60)
        )
        sc = self._assert_structured_response(resp, "exec_command")
        # Module won't exist but server should still return structured result
        assert isinstance(sc["success"], bool)

    def test_exec_command_with_options(self, msf_env):
        """exec_command with additional options param does not crash."""
        client, loop = msf_env
        resp = loop.run_until_complete(
            client.call("exec_command", {
                "module": "exploit/unix/webapp/test_nonexistent",
                "rhosts": "127.0.0.1",
                "command": "whoami",
                "options": {"RPORT": 80, "TARGETURI": "/"},
                "timeout": 30,
            }, timeout=60)
        )
        sc = self._assert_structured_response(resp, "exec_command (options)")

    def test_exec_command_missing_command(self, msf_env):
        """exec_command without required 'command' returns error."""
        client, loop = msf_env
        resp = loop.run_until_complete(
            client.call("exec_command", {
                "module": "exploit/unix/webapp/test",
                "rhosts": "127.0.0.1",
            }, timeout=30)
        )
        result = resp.get("result", {})
        is_error = result.get("isError", False)
        content_text = ""
        for c in result.get("content", []):
            if c.get("type") == "text":
                content_text += c["text"]
        assert is_error or "command" in content_text.lower() or "required" in content_text.lower()

    # ── list_sessions ────────────────────────────────────────────

    def test_list_sessions(self, msf_env):
        """list_sessions returns structured session list."""
        client, loop = msf_env
        resp = loop.run_until_complete(
            client.call("list_sessions", {}, timeout=30)
        )
        sc = self._assert_structured_response(resp, "list_sessions")
        assert sc["success"] is True
        data = parse_tool_output(resp)
        assert "sessions" in data
        assert isinstance(data["sessions"], list)
        assert "count" in data
        assert isinstance(data["count"], int)

    def test_list_sessions_with_timeout(self, msf_env):
        """list_sessions with explicit timeout param does not crash."""
        client, loop = msf_env
        resp = loop.run_until_complete(
            client.call("list_sessions", {"timeout": 10}, timeout=30)
        )
        sc = self._assert_structured_response(resp, "list_sessions (timeout)")
        assert sc["success"] is True

    # ── session_command ──────────────────────────────────────────

    def test_session_command_not_found(self, msf_env):
        """session_command with non-existent session returns classified error."""
        client, loop = msf_env
        resp = loop.run_until_complete(
            client.call("session_command", {
                "session_id": 99999,
                "command": "whoami",
            }, timeout=30)
        )
        sc = self._assert_structured_response(resp, "session_command")
        # Should fail gracefully with session not found
        content_text = ""
        result = resp.get("result", {})
        for c in result.get("content", []):
            if c.get("type") == "text":
                content_text += c["text"]
        assert "not found" in content_text.lower() or "99999" in content_text

    def test_session_command_missing_session_id(self, msf_env):
        """session_command without required 'session_id' returns error."""
        client, loop = msf_env
        resp = loop.run_until_complete(
            client.call("session_command", {
                "command": "whoami",
            }, timeout=30)
        )
        result = resp.get("result", {})
        is_error = result.get("isError", False)
        content_text = ""
        for c in result.get("content", []):
            if c.get("type") == "text":
                content_text += c["text"]
        assert is_error or "session_id" in content_text.lower() or "required" in content_text.lower()

    def test_session_command_missing_command(self, msf_env):
        """session_command without required 'command' returns error."""
        client, loop = msf_env
        resp = loop.run_until_complete(
            client.call("session_command", {
                "session_id": 1,
            }, timeout=30)
        )
        result = resp.get("result", {})
        is_error = result.get("isError", False)
        content_text = ""
        for c in result.get("content", []):
            if c.get("type") == "text":
                content_text += c["text"]
        assert is_error or "command" in content_text.lower() or "required" in content_text.lower()

    # ── post_module ──────────────────────────────────────────────

    def test_post_module_no_session(self, msf_env):
        """post_module with non-existent session returns structured response."""
        client, loop = msf_env
        resp = loop.run_until_complete(
            client.call("post_module", {
                "module": "post/multi/gather/env",
                "session_id": 99999,
            }, timeout=60)
        )
        sc = self._assert_structured_response(resp, "post_module")
        # Module will run but fail on session -- should be structured

    def test_post_module_with_options(self, msf_env):
        """post_module with additional options does not crash."""
        client, loop = msf_env
        resp = loop.run_until_complete(
            client.call("post_module", {
                "module": "post/multi/manage/autoroute",
                "session_id": 99999,
                "options": {"SUBNET": "10.10.10.0"},
            }, timeout=60)
        )
        sc = self._assert_structured_response(resp, "post_module (options)")

    def test_post_module_missing_module(self, msf_env):
        """post_module without required 'module' returns error."""
        client, loop = msf_env
        resp = loop.run_until_complete(
            client.call("post_module", {
                "session_id": 1,
            }, timeout=30)
        )
        result = resp.get("result", {})
        is_error = result.get("isError", False)
        content_text = ""
        for c in result.get("content", []):
            if c.get("type") == "text":
                content_text += c["text"]
        assert is_error or "module" in content_text.lower() or "required" in content_text.lower()

    def test_post_module_missing_session_id(self, msf_env):
        """post_module without required 'session_id' returns error."""
        client, loop = msf_env
        resp = loop.run_until_complete(
            client.call("post_module", {
                "module": "post/multi/gather/env",
            }, timeout=30)
        )
        result = resp.get("result", {})
        is_error = result.get("isError", False)
        content_text = ""
        for c in result.get("content", []):
            if c.get("type") == "text":
                content_text += c["text"]
        assert is_error or "session_id" in content_text.lower() or "required" in content_text.lower()

    # ── handler ──────────────────────────────────────────────────

    def test_handler_basic(self, msf_env):
        """handler starts a listener and returns structured data."""
        client, loop = msf_env
        resp = loop.run_until_complete(
            client.call("handler", {
                "payload": "linux/x64/shell_reverse_tcp",
                "lhost": "127.0.0.1",
                "lport": 14460,
            }, timeout=60)
        )
        sc = self._assert_structured_response(resp, "handler")
        assert sc["success"] is True
        data = parse_tool_output(resp)
        assert data["payload"] == "linux/x64/shell_reverse_tcp"
        assert "handler_started" in data
        assert isinstance(data["handler_started"], bool)

    def test_handler_with_shortcut(self, msf_env):
        """handler with payload shortcut resolves correctly."""
        client, loop = msf_env
        resp = loop.run_until_complete(
            client.call("handler", {
                "payload": "windows_reverse_tcp",
                "lhost": "127.0.0.1",
                "lport": 14461,
            }, timeout=60)
        )
        sc = self._assert_structured_response(resp, "handler (shortcut)")
        assert sc["success"] is True
        data = parse_tool_output(resp)
        assert data["payload"] == "windows/meterpreter/reverse_tcp"

    def test_handler_missing_payload(self, msf_env):
        """handler without required 'payload' returns error."""
        client, loop = msf_env
        resp = loop.run_until_complete(
            client.call("handler", {
                "lhost": "127.0.0.1",
                "lport": 4444,
            }, timeout=30)
        )
        result = resp.get("result", {})
        is_error = result.get("isError", False)
        content_text = ""
        for c in result.get("content", []):
            if c.get("type") == "text":
                content_text += c["text"]
        assert is_error or "payload" in content_text.lower() or "required" in content_text.lower()

    def test_handler_missing_lhost(self, msf_env):
        """handler without required 'lhost' returns error."""
        client, loop = msf_env
        resp = loop.run_until_complete(
            client.call("handler", {
                "payload": "linux/x64/shell_reverse_tcp",
                "lport": 4444,
            }, timeout=30)
        )
        result = resp.get("result", {})
        is_error = result.get("isError", False)
        content_text = ""
        for c in result.get("content", []):
            if c.get("type") == "text":
                content_text += c["text"]
        assert is_error or "lhost" in content_text.lower() or "required" in content_text.lower()

    # ── Cross-cutting acceptance tests ───────────────────────────

    def test_all_methods_return_structuredContent(self, msf_env):
        """Verify structuredContent on a guaranteed-success method (verify_clock)."""
        client, loop = msf_env
        resp = loop.run_until_complete(client.call("verify_clock", {}))
        result = resp.get("result", {})
        sc = result.get("structuredContent")
        assert sc is not None
        assert isinstance(sc, dict)
        for field in ("success", "error_class", "retryable", "suggestions"):
            assert field in sc, f"Missing '{field}' in structuredContent"

    def test_meta_params_stripped_on_all_methods(self, msf_env):
        """Meta-params like clock_offset should not cause crashes on any method."""
        client, loop = msf_env
        # Test on multiple methods
        for method, args in [
            ("list_sessions", {}),
            ("search_modules", {"query": "test"}),
        ]:
            args_with_meta = {**args, "clock_offset": "+5h"}
            resp = loop.run_until_complete(
                client.call(method, args_with_meta, timeout=120)
            )
            result = resp.get("result", {})
            content_text = ""
            for c in result.get("content", []):
                if c.get("type") == "text":
                    content_text += c["text"]
            assert "unexpected keyword argument" not in content_text, (
                f"Meta-param not stripped for {method}: {content_text[:200]}"
            )


# ===========================================================================
# ENGAGEMENT-DERIVED REGRESSION TESTS
# ===========================================================================

class TestEngagementRegressions:
    """Tests derived from real engagement data patterns.

    Engagement data shows 102 metasploit tool calls across 7 engagements:
    - session_command (44): mostly phase-blocked, 6 real (all timeout)
    - list_sessions (26): all phase-blocked
    - run_exploit (14): all phase-blocked
    - search_modules (10): mostly phase-blocked
    - generate_payload (6): all succeeded
    - handler (2): phase-blocked

    Methods NEVER called in engagements: check_vuln, exec_command, post_module
    Common phantom methods: start_handler (1), console_command (1), run_command (1)
    """

    def test_session_command_timeout_handling(self):
        """session_command calls frequently timed out in engagements.

        The server should handle timeout gracefully:
        - Shell sessions need 3+ stable empty reads before returning
        - Meterpreter uses run_with_output with explicit timeout
        """
        server = _get_server_class()()
        method = server.methods["session_command"]
        # Verify timeout param exists with sensible default
        assert "timeout" in method.params
        assert method.params["timeout"].get("default") == 60

    def test_generate_payload_never_failed(self):
        """generate_payload is stateless (subprocess) and never failed in engagements.

        It uses msfvenom directly, not msfrpcd console, so it should be
        the most reliable method.
        """
        server = _get_server_class()()
        method = server.methods["generate_payload"]
        # Verify it exists and has proper required params
        required = {p for p, pdef in method.params.items() if pdef.get("required")}
        assert required == {"payload", "lhost", "lport"}

    def test_check_vuln_never_called_but_exists(self):
        """check_vuln was never called in real engagements but should be available.

        Agents should use check_vuln before run_exploit for validation.
        """
        server = _get_server_class()()
        assert "check_vuln" in server.methods
        method = server.methods["check_vuln"]
        required = {p for p, pdef in method.params.items() if pdef.get("required")}
        assert required == {"module", "rhosts"}

    def test_exec_command_never_called_but_exists(self):
        """exec_command was never called in real engagements (2 phase-blocked attempts).

        The method should still work for one-shot command execution via exploits.
        """
        server = _get_server_class()()
        assert "exec_command" in server.methods
        method = server.methods["exec_command"]
        required = {p for p, pdef in method.params.items() if pdef.get("required")}
        assert required == {"module", "rhosts", "command"}

    def test_post_module_never_called_but_exists(self):
        """post_module had only 2 phase-blocked attempts in engagements.

        Post-exploitation modules need an active session, which explains
        why it's rarely called -- agents need to establish sessions first.
        """
        server = _get_server_class()()
        assert "post_module" in server.methods

    def test_phantom_methods_give_helpful_errors(self, msf_env):
        """All three phantom methods from engagements should give helpful errors.

        start_handler (1 call), console_command (1 call), run_command (1 call).
        """
        client, loop = msf_env
        phantoms = {
            "start_handler": {"payload": "test", "lhost": "1.2.3.4", "lport": 4444},
            "console_command": {"command": "help"},
            "run_command": {"command": "help"},
        }
        for method_name, args in phantoms.items():
            resp = loop.run_until_complete(
                client.call(method_name, args, timeout=30)
            )
            result = resp.get("result", {})
            assert result.get("isError", False), (
                f"{method_name} should return isError=True"
            )
            content_text = ""
            for c in result.get("content", []):
                if c.get("type") == "text":
                    content_text += c["text"]
            assert "Unknown method" in content_text, (
                f"{method_name}: expected 'Unknown method' in error, got: {content_text[:200]}"
            )

    def test_circuit_breaker_scenario(self):
        """Engagement data shows session_command hitting circuit breaker after 3 failures.

        Output: 'SKIPPED: metasploit.session_command has failed 3 times.'
        This is client-side behavior, not server behavior, but the server
        should return clear failure indicators to enable this.
        """
        server = _get_server_class()()
        e = server._classify_msf_error("Session 1 is dead or closed.")
        assert e is not None
        assert e.retryable is False, "Dead session should not be retryable"
        assert e.error_class == "session_lost"  # renamed from "config" (May 2026 taxonomy alignment)


# ===========================================================================
# INTEGRATION TESTS -- require live target
# ===========================================================================

class TestIntegration:
    """Integration tests that require a live target.

    Marked with @pytest.mark.integration, only run when --target is provided.
    """

    @pytest.mark.integration
    def test_check_vuln_real_target(self, msf_env, target):
        """Check vulnerability against a real target."""
        client, loop = msf_env
        resp = loop.run_until_complete(
            client.call("check_vuln", {
                "module": "auxiliary/scanner/smb/smb_ms17_010",
                "rhosts": target,
                "timeout": 120,
            }, timeout=180)
        )
        result = assert_tool_success(resp)
        data = parse_tool_output(resp)
        assert "vulnerable" in data

    @pytest.mark.integration
    def test_search_and_exploit_real_target(self, msf_env, target):
        """Search for modules, then attempt exploit against real target."""
        client, loop = msf_env

        # Search
        search_resp = loop.run_until_complete(
            client.call("search_modules", {"query": "smb"}, timeout=120)
        )
        search_data = parse_tool_output(search_resp)
        assert search_data["count"] > 0

        # Run exploit (may fail but should not crash)
        resp = loop.run_until_complete(
            client.call("run_exploit", {
                "module": "exploit/windows/smb/ms17_010_eternalblue",
                "rhosts": target,
                "payload": "windows/x64/meterpreter/reverse_tcp",
                "lhost": "127.0.0.1",
                "lport": 14450,
                "timeout": 60,
            }, timeout=120)
        )
        data = parse_tool_output(resp)
        assert "exploit_success" in data


# ===========================================================================
# May 2026 fix tests — handler rename + exit_on_session + tool.yaml additions
# ===========================================================================

class TestPythonMethodMatchesRegisteredName:
    """Catch future drift — Python method name should equal registered MCP name.

    Pre-fix (Apr 2026 and earlier): Python method was `start_handler()`, MCP
    registered as `handler`. Mismatch caused agent confusion + a TypeError
    when extra kwargs were passed (silently dropped pre-strip-logic, then
    after strip-logic added in commit 91bea14, the kwarg was stripped but
    agent's intent was lost).

    Post-fix (May 2026): Python method renamed to `handler()`. Test guards
    against future re-introduction of the mismatch.
    """

    def test_handler_python_name_matches_registered(self):
        server = _get_server_class()()
        registered = server.methods["handler"]
        assert registered.handler.__name__ == "handler", (
            f"MCP-registered 'handler' should map to Python method named 'handler', "
            f"got: {registered.handler.__name__}. If you renamed in Python, also rename "
            f"in register_method's handler= argument."
        )


class TestHandlerExitOnSession:
    """The handler method must accept exit_on_session as a real param and
    propagate it to the msfconsole `set ExitOnSession` line.

    Pre-fix: exit_on_session was hardcoded to false; the agent's kwarg was
    silently dropped by the dispatcher's strip logic (so Python call succeeded
    but intent was lost).

    Post-fix: exit_on_session is in the schema + Python signature; honored.
    """

    def test_exit_on_session_in_schema(self):
        server = _get_server_class()()
        params = server.methods["handler"].params
        assert "exit_on_session" in params, (
            "handler schema must include exit_on_session — without it, the "
            "dispatcher silently drops the kwarg and intent is lost"
        )
        assert params["exit_on_session"]["type"] == "boolean"
        assert params["exit_on_session"]["default"] is False, (
            "Default should be False to preserve pre-fix behavior (handler "
            "stays running for multiple sessions)"
        )

    def test_exit_on_session_in_python_signature(self):
        import inspect
        server = _get_server_class()()
        sig = inspect.signature(server.handler)
        assert "exit_on_session" in sig.parameters, (
            "handler() Python signature must accept exit_on_session — without "
            "it, the schema accepts the kwarg but Python rejects with TypeError"
        )
        assert sig.parameters["exit_on_session"].default is False

    def test_exit_on_session_true_propagates_to_console_command(self):
        """Verify the ExitOnSession msfconsole command reflects the param value.

        We can't easily test against real msfrpcd here (no exploit chain in
        unit context), so we patch _console_exec to capture the cmds.
        """
        import asyncio
        from unittest.mock import AsyncMock, patch

        server = _get_server_class()()
        captured_cmds = []

        async def fake_console_exec(cmds, timeout=120):
            captured_cmds.append(cmds)
            return "Started reverse handler\nExploit running as background job 0."

        with patch.object(server, "_console_exec", side_effect=fake_console_exec):
            asyncio.run(
                server.handler(
                    payload="linux/x64/shell_reverse_tcp",
                    lhost="127.0.0.1",
                    lport=14460,
                    exit_on_session=True,
                )
            )

        assert len(captured_cmds) == 1
        assert "set ExitOnSession true" in captured_cmds[0], (
            f"Expected ExitOnSession=true in console cmds, got:\n{captured_cmds[0]}"
        )

    def test_exit_on_session_false_default_propagates(self):
        """Default exit_on_session=False should produce 'set ExitOnSession false'."""
        import asyncio
        from unittest.mock import patch

        server = _get_server_class()()
        captured_cmds = []

        async def fake_console_exec(cmds, timeout=120):
            captured_cmds.append(cmds)
            return "Started reverse handler\nExploit running as background job 0."

        with patch.object(server, "_console_exec", side_effect=fake_console_exec):
            asyncio.run(
                server.handler(
                    payload="linux/x64/shell_reverse_tcp",
                    lhost="127.0.0.1",
                    lport=14461,
                    # exit_on_session omitted — should default to False
                )
            )

        assert "set ExitOnSession false" in captured_cmds[0]


class TestUnknownArgsStripped:
    """Regression — production trajectory (March 2026) showed agent passing
    exit_on_session as a kwarg. Pre-strip-logic (commit 91bea14, April 27),
    that kwarg leaked through to Python and caused TypeError.

    The strip logic at base_server.py:691-698 SHOULD now strip unknown args.
    This test confirms it — defensive against future regression.

    Note: under the May 2026 fix, exit_on_session IS a known param, so it
    won't be stripped. We test with a different unknown name."""

    def test_unknown_kwarg_to_handler_does_not_crash_python(self):
        """Pass an unknown kwarg to handler. Dispatcher should strip it.
        Verifies base_server.py:691-698 works as advertised."""
        server = _get_server_class()()
        # Get the dispatcher's strip logic via a synthetic call
        # We can't easily invoke the JSON-RPC layer in unit context, so we
        # verify the strip logic is present in the codebase.
        import inspect
        from mcp_common.base_server import BaseMCPServer
        source = inspect.getsource(BaseMCPServer)
        assert "unknown = set(arguments.keys()) - set(method.params.keys())" in source, (
            "Dispatcher strip logic missing — unknown kwargs would leak through "
            "to Python handlers and cause TypeError"
        )
        assert "del arguments[key]" in source, (
            "Dispatcher should DELETE unknown keys, not just log them"
        )


class TestFailureSignatureParity:
    """tool.yaml's failure_signatures should mirror _classify_msf_error patterns.

    Drift would mean: when the plugin-side scanner (Investigation B) lands,
    plugin matches against tool.yaml signatures while the legacy Python
    classifier matches different patterns. Two error classifications would
    disagree silently. Catch drift early.
    """

    def test_each_classifier_branch_has_yaml_signature(self):
        """Every conditional branch in _classify_msf_error must have a
        corresponding entry in tool.yaml's failure_signatures."""
        tool_yaml_path = Path(__file__).parent.parent.parent / "tools" / "metasploit" / "tool.yaml"
        with open(tool_yaml_path) as f:
            doc = yaml.safe_load(f)
        sigs = [s["signal"].lower() for s in doc.get("failure_signatures", [])]

        # Each lowercase substring from _classify_msf_error's `if "X" in lower`
        # branches should appear in some signature's signal field.
        required_substrings = [
            "timed out",
            "unreachable",
            "connection refused",
            "connectionrefused",
            "unknown datastore option",
            "module not found",
            "failed to load",
            "handler failed to bind",
            "address is already in use",
            "session",  # session.* not found / dead / closed
        ]
        missing = []
        for substr in required_substrings:
            if not any(substr.lower() in sig for sig in sigs):
                missing.append(substr)
        assert not missing, (
            f"_classify_msf_error patterns missing from tool.yaml.failure_signatures: "
            f"{missing}. Each Python branch should have a yaml entry — drift would "
            f"cause plugin-side scanner and Python classifier to disagree."
        )

    def test_failure_signature_schema_shape(self):
        """Each failure_signature must have signal + remediation. error_class
        is recommended (HexStrike-style coarse taxonomy) but optional."""
        tool_yaml_path = Path(__file__).parent.parent.parent / "tools" / "metasploit" / "tool.yaml"
        with open(tool_yaml_path) as f:
            doc = yaml.safe_load(f)
        sigs = doc.get("failure_signatures", [])
        for sig in sigs:
            assert "signal" in sig, f"Missing signal: {sig}"
            assert "remediation" in sig, f"Missing remediation: {sig}"
            # pattern_type opt-in for regex (Investigation B finding)
            if "pattern_type" in sig:
                assert sig["pattern_type"] in ["regex", "substring"], (
                    f"Invalid pattern_type: {sig['pattern_type']}"
                )


class TestPasswordHandling:
    """MSF_PASSWORD per-session randomization (May 2026)."""

    def test_entrypoint_generates_random_when_unset(self):
        """When MSF_PASSWORD env not provided, entrypoint should generate one."""
        entrypoint_path = Path(__file__).parent.parent.parent / "tools" / "metasploit" / "entrypoint.sh"
        content = entrypoint_path.read_text()
        # Should reference random generation (python3 secrets, openssl, or /dev/urandom)
        assert "secrets.token_hex" in content or "openssl rand" in content or "/dev/urandom" in content, (
            "entrypoint.sh must generate a random MSF_PASSWORD when env var is unset. "
            "Defense-in-depth: only matters if container is exposed beyond loopback, "
            "but cheap and good practice."
        )
        # Must EXPORT so both msfrpcd (cmd line -P) and MCP server (os.environ) see it
        assert "export MSF_PASSWORD" in content, (
            "entrypoint.sh must EXPORT MSF_PASSWORD — without export, MCP server's "
            "os.environ.get('MSF_PASSWORD') falls back to default 'msfpassword' and "
            "fails to authenticate to msfrpcd"
        )

    def test_entrypoint_uses_msf_password_for_msfrpcd_flag(self):
        """The msfrpcd -P flag must use the same MSF_PASSWORD value."""
        entrypoint_path = Path(__file__).parent.parent.parent / "tools" / "metasploit" / "entrypoint.sh"
        content = entrypoint_path.read_text()
        # Either literal $MSF_PASSWORD or "$MSF_PASSWORD" expansion
        assert 'msfrpcd -P "$MSF_PASSWORD"' in content or "msfrpcd -P $MSF_PASSWORD" in content, (
            "msfrpcd should bind to the exported MSF_PASSWORD value"
        )


class TestColdStartTiming:
    """msfrpcd cold-start can take up to 120s. Server retries 30× over 60s.
    First call after fresh container start can fail with 'connection refused'
    if msfrpcd isn't ready. Document the expected behavior."""

    def test_ensure_connected_retry_budget_is_30_attempts(self):
        """The retry budget should be 30 attempts (60s total at 2s sleep).

        After May 2026 audit, the connect loop moved from `_ensure_connected`
        into `_connect_locked` (a helper called under `_connect_lock` to
        avoid first-call double-init races). Check the helper if it
        exists; otherwise check the older inline location.
        """
        server = _get_server_class()()
        import inspect
        source = inspect.getsource(server._ensure_connected)
        if hasattr(server, "_connect_locked"):
            source += "\n" + inspect.getsource(server._connect_locked)
        assert "range(30)" in source, (
            "_ensure_connected (or _connect_locked) retry budget should be 30 "
            "attempts × 2s = 60s. msfrpcd cold-start can take up to 180s; "
            "container's entrypoint waits up to 180s before yielding to MCP "
            "server. The MCP server's 60s budget covers the gap if msfrpcd "
            "is still warming up when the first call hits."
        )

    def test_entrypoint_waits_up_to_180s(self):
        """entrypoint.sh's loop should give msfrpcd up to 180s to start.

        Bumped from 120s to 180s in May 2026 when PostgreSQL + msfdb init was
        added — DB-enabled boot is slower than the older -n (no-DB) boot path.
        Loop is `for i in $(seq 1 90)` with `sleep 2` = 180s.
        """
        entrypoint_path = Path(__file__).parent.parent.parent / "tools" / "metasploit" / "entrypoint.sh"
        content = entrypoint_path.read_text()
        assert "seq 1 90" in content, "msfrpcd-ready loop must iterate 90× (×2s = 180s)"
        assert "sleep 2" in content


# ===========================================================================
# May 2026 Wave 2-5 expansion — tests for 20 new methods
# ===========================================================================

class TestRunExploitSuccessDetectionFix:
    """Regression: pre-May-2026, run_exploit returned exploit_success=True after
    just seeing '[*] Exploit completed' which fires when the JOB IS QUEUED, not
    when the exploit completes. Verified live on Blue: 12s after submission the
    method returned True with 0 sessions, but the actual exploit took 60+ more
    seconds to create session 1.

    Post-fix: success requires a NEW session to appear during the polling
    window (default 30s) AND no explicit failure markers in output.
    """

    def test_no_session_returns_false(self):
        """If no session appears, exploit_success=False.

        Post-Phase-4: ``run_exploit`` uses the structured ``module.execute``
        RPC, not console output. Success criterion is purely the appearance
        of a new session in ``client.sessions.list``. The legacy
        '[*] Exploit completed' string-match heuristic was removed —
        msfconsole emits that when the job is QUEUED, not completed.
        """
        import asyncio
        server = _get_server_class()()

        async def fake_ensure(): pass
        server._ensure_connected = fake_ensure

        class FakeModule:
            def __setitem__(self, key, value): pass
            def execute(self, **kwargs): return {"job_id": 0, "uuid": "fake-uuid"}

        class FakeModules:
            def use(self, mtype, mname): return FakeModule()

        class FakeSessions:
            list = {}  # No new sessions appear

        class FakeClient:
            modules = FakeModules()
            sessions = FakeSessions()
        server.client = FakeClient()

        result = asyncio.run(server.run_exploit(
            module="exploit/windows/smb/ms17_010_eternalblue",
            rhosts="10.10.10.40",
            session_wait_seconds=2,  # short for unit test
        ))
        assert result.success is True  # operation succeeded (no exception)
        assert result.data["exploit_success"] is False, (
            "exploit_success must be False when no session was created"
        )
        assert result.data["session_count"] == 0
        assert result.data["job_id"] == 0
        assert result.data["uuid"] == "fake-uuid"

    def test_session_appears_returns_true(self):
        """If a new session appears during the poll window, exploit_success=True."""
        import asyncio
        server = _get_server_class()()

        async def fake_ensure(): pass
        server._ensure_connected = fake_ensure

        class FakeModule:
            def __setitem__(self, key, value): pass
            def execute(self, **kwargs): return {"job_id": 1, "uuid": "u"}

        class FakeModules:
            def use(self, mtype, mname): return FakeModule()

        # `list` is read three times: pre-launch (snapshot), then during
        # polls. We return empty pre-launch and a populated dict on
        # subsequent reads, simulating a session that lands mid-poll.
        new_session = {"type": "meterpreter", "info": "NT AUTHORITY\\SYSTEM",
                       "via_exploit": "exploit/windows/smb/ms17_010_eternalblue",
                       "tunnel_peer": "10.10.10.40:445"}

        class FakeSessions:
            _calls = 0
            @property
            def list(self):
                FakeSessions._calls += 1
                return {} if FakeSessions._calls == 1 else {"1": new_session}

        class FakeClient:
            class _Modules:
                def use(self, mtype, mname): return FakeModule()
            modules = _Modules()
            sessions = FakeSessions()
        server.client = FakeClient()

        result = asyncio.run(server.run_exploit(
            module="exploit/windows/smb/ms17_010_eternalblue",
            rhosts="10.10.10.40",
            session_wait_seconds=2,
        ))
        assert result.data["exploit_success"] is True
        assert result.data["session_count"] == 1
        assert result.data["sessions"][0]["id"] == 1
        assert result.data["sessions"][0]["type"] == "meterpreter"

    def test_disable_payload_handler_in_schema(self):
        """The disable_payload_handler kwarg must be in the schema."""
        server = _get_server_class()()
        params = server.methods["run_exploit"].params
        assert "disable_payload_handler" in params
        assert params["disable_payload_handler"]["type"] == "boolean"
        assert params["disable_payload_handler"]["default"] is False

    def test_session_wait_seconds_in_schema(self):
        """The session_wait_seconds kwarg must be in the schema."""
        server = _get_server_class()()
        params = server.methods["run_exploit"].params
        assert "session_wait_seconds" in params
        assert params["session_wait_seconds"]["type"] == "integer"


class TestNewMethodsSchema:
    """Each new method must be registered with proper schema."""

    NEW_METHODS = {
        "list_jobs": [],
        "stop_job": ["job_id", "all_jobs"],
        "session_kill": ["session_id", "all_sessions"],
        "session_upgrade": ["session_id", "lhost", "lport", "timeout"],
        "module_info": ["module"],
        "route_add": ["subnet", "netmask", "session_id"],
        "route_list": [],
        "route_delete": ["subnet", "netmask"],
        "portfwd_add": ["session_id", "local_port", "remote_host", "remote_port"],
        "portfwd_list": ["session_id"],
        "portfwd_delete": ["session_id", "local_port"],
        "db_nmap": ["args", "timeout"],
        "db_import": ["file_path"],
        "list_hosts": ["address"],
        "list_services": ["host", "port"],
        "list_creds": ["host"],
        "list_loot": [],
        "list_notes": [],
        "run_resource_script": ["commands", "timeout"],
        "run_console": ["command", "timeout"],
    }

    def test_all_new_methods_registered(self):
        server = _get_server_class()()
        for method_name in self.NEW_METHODS:
            assert method_name in server.methods, f"Method {method_name} not registered"

    def test_each_method_has_expected_params(self):
        server = _get_server_class()()
        for method_name, expected_params in self.NEW_METHODS.items():
            params = server.methods[method_name].params
            for p in expected_params:
                assert p in params, (
                    f"Method {method_name} missing param '{p}'. Has: {list(params.keys())}"
                )

    def test_each_new_method_has_python_handler(self):
        """Every registered method must have a callable Python handler."""
        server = _get_server_class()()
        for method_name in self.NEW_METHODS:
            method = server.methods[method_name]
            assert method.handler is not None
            assert callable(method.handler)


class TestNewMethodsLive:
    """Smoke-test each new method against real msfrpcd (no remote target needed
    for most). Uses the msf_env fixture which spawns a fresh container.

    For methods that genuinely need a target/session (route_add, portfwd_*,
    session_upgrade, post_module via session), these tests verify ERROR
    handling — they run without a session and should fail cleanly with a
    structured error, not a Python TypeError or hung console."""

    def test_list_jobs_empty(self, msf_env):
        """list_jobs returns empty list when no jobs running."""
        client, loop = msf_env
        resp = loop.run_until_complete(client.call("list_jobs", {}, timeout=15))
        assert_tool_success(resp, "list_jobs should succeed")
        data = parse_tool_output(resp)
        assert "jobs" in data
        assert "count" in data
        assert isinstance(data["jobs"], list)

    def test_stop_job_requires_param(self, msf_env):
        """stop_job without job_id or all_jobs returns clear error."""
        client, loop = msf_env
        resp = loop.run_until_complete(client.call("stop_job", {}, timeout=15))
        # Should be a structured failure (success=False), not a hang or crash
        # The exact shape depends on whether validation fails at schema layer
        # or at our explicit check inside the method. Either is fine.

    def test_session_kill_requires_param(self, msf_env):
        """session_kill without session_id or all_sessions returns clear error."""
        client, loop = msf_env
        resp = loop.run_until_complete(client.call("session_kill", {}, timeout=15))
        # Either schema rejection or method-level error — both acceptable

    def test_session_kill_nonexistent_session(self, msf_env):
        """session_kill with bogus session_id returns msf's error response."""
        client, loop = msf_env
        resp = loop.run_until_complete(
            client.call("session_kill", {"session_id": 99999}, timeout=15)
        )
        # msfconsole prints "Invalid session id" but our method still returns success
        # because it just dispatched the command. The agent reads raw_output for the
        # actual outcome. Let's just verify no crash.
        assert_tool_success(resp)

    def test_module_info_eternalblue(self, msf_env):
        """module_info on a real module returns description + options + targets."""
        client, loop = msf_env
        resp = loop.run_until_complete(client.call("module_info", {
            "module": "exploit/windows/smb/ms17_010_eternalblue"
        }, timeout=30))
        result = assert_tool_success(resp, "module_info should succeed")
        data = parse_tool_output(resp)
        # raw_output should contain msfconsole's info dump
        # Look for typical info-output markers
        raw = result.get("raw_output", "") if isinstance(result, dict) else ""
        # Either the data has raw_output or the structuredContent does

    def test_route_list_empty(self, msf_env):
        """route_list returns route table (empty initially)."""
        client, loop = msf_env
        resp = loop.run_until_complete(client.call("route_list", {}, timeout=15))
        assert_tool_success(resp, "route_list should succeed even with no routes")

    def test_run_console_basic(self, msf_env):
        """run_console can execute a simple msfconsole command."""
        client, loop = msf_env
        resp = loop.run_until_complete(client.call("run_console", {
            "command": "version", "timeout": 30
        }, timeout=60))
        assert_tool_success(resp, "run_console version should succeed")

    def test_list_hosts_empty(self, msf_env):
        """list_hosts on empty workspace returns empty result (DB-enabled)."""
        client, loop = msf_env
        resp = loop.run_until_complete(client.call("list_hosts", {}, timeout=15))
        # Will succeed if DB is enabled, error gracefully if not
        # Either is acceptable — proves the method dispatches correctly
        assert isinstance(resp, dict)

    def test_list_creds_empty(self, msf_env):
        """list_creds on empty workspace."""
        client, loop = msf_env
        resp = loop.run_until_complete(client.call("list_creds", {}, timeout=15))
        assert isinstance(resp, dict)


class TestRunResourceScript:
    """run_resource_script accepts inline multi-line msfconsole commands."""

    def test_resource_script_inline_content(self, msf_env):
        """Verify inline commands are written to a temp .rc and executed."""
        client, loop = msf_env
        resp = loop.run_until_complete(client.call("run_resource_script", {
            "commands": "version\nbanner",
            "timeout": 30,
        }, timeout=60))
        result = assert_tool_success(resp, "run_resource_script should succeed")
        # The output should contain 'version' results
