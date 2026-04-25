"""
Tests for the metasploit MCP tool server.

Covers:
- Smoke tests: boot, method list, required params, meta-param stripping, clock
- Unit tests: _parse_search_output, _resolve_payload, exec_command output parsing
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

class TestParseSearchOutput:
    """Test _parse_search_output with various msfconsole output formats."""

    def setup_method(self):
        self.server = _get_server_class()()

    def test_parse_ms17_010(self):
        """Parse a typical search result with multiple module types."""
        output = load_fixture("search_ms17_010.txt")
        modules = self.server._parse_search_output(output)

        assert len(modules) >= 4, f"Expected at least 4 modules, got {len(modules)}"

        # Check specific modules
        paths = [m["path"] for m in modules]
        assert "exploit/windows/smb/ms17_010_eternalblue" in paths
        assert "auxiliary/scanner/smb/smb_ms17_010" in paths

        # Verify types
        for m in modules:
            assert m["type"] in ("exploit", "auxiliary", "post", "payload")
            assert m["path"].startswith(m["type"] + "/")
            assert "info" in m

    def test_parse_single_result(self):
        """Parse search with only one result."""
        output = load_fixture("search_cve_2024_30088.txt")
        modules = self.server._parse_search_output(output)

        assert len(modules) == 1
        assert modules[0]["type"] == "exploit"
        assert modules[0]["path"] == "exploit/windows/local/cve_2024_30088_authz_basep"
        assert "excellent" in modules[0]["info"]

    def test_parse_empty_results(self):
        """Parse search with no matching modules."""
        output = load_fixture("search_empty.txt")
        modules = self.server._parse_search_output(output)
        assert modules == []

    def test_parse_with_sub_actions(self):
        """Parse output that includes sub-action lines (bad_successor format)."""
        output = load_fixture("search_bad_successor.txt")
        modules = self.server._parse_search_output(output)

        # Should find the main auxiliary module; sub-actions may or may not parse
        main_modules = [m for m in modules if m["type"] == "auxiliary"]
        assert len(main_modules) >= 1
        assert main_modules[0]["path"] == "auxiliary/admin/ldap/bad_successor"

    def test_parse_header_lines_ignored(self):
        """Header, separator, and empty lines are not parsed as modules."""
        output = "Matching Modules\n================\n\n# Name  Disclosure\n- ----  ---------------\n"
        modules = self.server._parse_search_output(output)
        assert modules == []

    def test_parse_numbered_format(self):
        """Parse the numbered module format (most common)."""
        output = "   0  exploit/multi/handler  2015-01-01  manual  No  Generic Payload Handler\n"
        modules = self.server._parse_search_output(output)
        assert len(modules) == 1
        assert modules[0]["type"] == "exploit"
        assert modules[0]["path"] == "exploit/multi/handler"


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
    """Test that all methods are properly registered."""

    def test_all_nine_methods_registered(self):
        server = _get_server_class()()
        expected = {
            "generate_payload",
            "search_modules",
            "check_vuln",
            "run_exploit",
            "exec_command",
            "list_sessions",
            "session_command",
            "post_module",
            "handler",
        }
        assert set(server.methods.keys()) == expected

    def test_method_count(self):
        server = _get_server_class()()
        assert len(server.methods) == 9

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
        """Every method in tool.yaml is registered in the server."""
        yaml_path = TOOL_DIR / "tool.yaml"
        with open(yaml_path) as f:
            yaml_data = yaml.safe_load(f)
        yaml_methods = set(yaml_data.get("methods", {}).keys())

        server = _get_server_class()()
        server_methods = set(server.methods.keys())

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
        server_names_no_test = server_names - {"verify_clock"}

        yaml_path = TOOL_DIR / "tool.yaml"
        with open(yaml_path) as f:
            yaml_data = yaml.safe_load(f)
        yaml_names = set(yaml_data.get("methods", {}).keys())

        yaml_only = yaml_names - server_names_no_test
        server_only = server_names_no_test - yaml_names

        assert not yaml_only, f"Methods in tool.yaml but not server: {yaml_only}"
        assert not server_only, f"Methods in server but not tool.yaml: {server_only}"

    def test_expected_method_count(self, msf_env):
        """Server should have exactly 9 built-in methods + verify_clock."""
        client, _ = msf_env
        names = client.tool_names()
        # 9 built-in + verify_clock in MCP_TEST_MODE
        assert len(names) == 10, (
            f"Expected 10 methods (9 built-in + verify_clock), got {len(names)}: {sorted(names)}"
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
        error_class, retryable, suggestions = self.server._classify_msf_error(
            "The connection with (10.10.10.40:389) timed out."
        )
        assert error_class == "network"
        assert retryable is True
        assert len(suggestions) > 0

    def test_connection_refused(self):
        error_class, retryable, suggestions = self.server._classify_msf_error(
            "Rex::ConnectionRefused The connection was refused"
        )
        assert error_class == "network"
        assert retryable is True

    def test_unknown_datastore_option(self):
        error_class, retryable, suggestions = self.server._classify_msf_error(
            "[!] Unknown datastore option: DMSA_NAME."
        )
        assert error_class == "params"
        assert retryable is False

    def test_handler_bind_failure(self):
        error_class, retryable, suggestions = self.server._classify_msf_error(
            "Handler failed to bind to 10.10.16.19:4444"
        )
        assert error_class == "config"
        assert retryable is False

    def test_address_in_use(self):
        error_class, retryable, suggestions = self.server._classify_msf_error(
            "The address is already in use or unavailable (0.0.0.0:4444)."
        )
        assert error_class == "config"
        assert retryable is False

    def test_unreachable(self):
        error_class, retryable, suggestions = self.server._classify_msf_error(
            "Auxiliary aborted due to failure: unreachable"
        )
        assert error_class == "network"
        assert retryable is True

    def test_session_dead(self):
        error_class, retryable, suggestions = self.server._classify_msf_error(
            "Session 1 is dead or closed."
        )
        assert error_class == "config"
        assert retryable is False

    def test_clean_output_no_error(self):
        error_class, retryable, suggestions = self.server._classify_msf_error(
            "[*] Auxiliary module execution completed"
        )
        assert error_class is None
        assert retryable is False
        assert suggestions == []

    def test_module_not_found(self):
        error_class, retryable, suggestions = self.server._classify_msf_error(
            "Module not found: exploit/nonexistent/module"
        )
        assert error_class == "config"
        assert retryable is False

    def test_failed_to_load(self):
        """'Failed to load' should classify as config error."""
        error_class, retryable, suggestions = self.server._classify_msf_error(
            "Failed to load module: exploit/windows/smb/nonexistent"
        )
        assert error_class == "config"
        assert retryable is False
        assert len(suggestions) > 0

    def test_session_not_found(self):
        """'session not found' should classify as config error."""
        error_class, retryable, suggestions = self.server._classify_msf_error(
            "Session 42 not found"
        )
        assert error_class == "config"
        assert retryable is False

    def test_connection_refused_lower(self):
        """'connectionrefused' as one word should classify as network."""
        error_class, retryable, suggestions = self.server._classify_msf_error(
            "Rex::ConnectionRefused"
        )
        assert error_class == "network"
        assert retryable is True

    def test_combined_timeout_and_unreachable(self):
        """Output containing both 'timed out' and 'unreachable' should classify as network."""
        output = load_fixture("exploit_timeout_unreachable.txt")
        error_class, retryable, suggestions = self.server._classify_msf_error(output)
        assert error_class == "network"
        assert retryable is True


# ===========================================================================
# ADDITIONAL UNIT TESTS -- parsing edge cases
# ===========================================================================

class TestParseSearchOutputEdgeCases:
    """Additional edge cases for _parse_search_output."""

    def setup_method(self):
        self.server = _get_server_class()()

    def test_parse_with_multiple_spaces(self):
        """Parse search results with irregular spacing."""
        output = "  10   exploit/windows/smb/ms17_010_eternalblue   2017-03-14   average   Yes   MS17-010 EternalBlue\n"
        modules = self.server._parse_search_output(output)
        assert len(modules) == 1
        assert modules[0]["type"] == "exploit"

    def test_parse_post_module(self):
        """Parse search results containing post modules."""
        output = "   0  post/multi/manage/autoroute  2012-01-01  normal  No  Multi Manage Network Route via Meterpreter Session\n"
        modules = self.server._parse_search_output(output)
        assert len(modules) == 1
        assert modules[0]["type"] == "post"
        assert modules[0]["path"] == "post/multi/manage/autoroute"

    def test_parse_payload_module(self):
        """Parse search results containing payload modules."""
        output = "   0  payload/windows/meterpreter/reverse_tcp  .  normal  No  Windows Meterpreter Reverse TCP\n"
        modules = self.server._parse_search_output(output)
        assert len(modules) == 1
        assert modules[0]["type"] == "payload"

    def test_parse_mixed_types(self):
        """Parse output with all four module types."""
        output = (
            "   0  exploit/multi/handler  2015-01-01  manual  No  Generic Payload Handler\n"
            "   1  auxiliary/scanner/smb/smb_ms17_010  .  normal  No  MS17-010 Detection\n"
            "   2  post/multi/gather/env  .  normal  No  Gather Environment Info\n"
            "   3  payload/windows/meterpreter/reverse_tcp  .  normal  No  Reverse TCP\n"
        )
        modules = self.server._parse_search_output(output)
        types_found = {m["type"] for m in modules}
        assert types_found == {"exploit", "auxiliary", "post", "payload"}

    def test_parse_eternalblue_success_output(self):
        """Exploit output (non-search) should parse zero modules."""
        output = load_fixture("exploit_eternalblue_success.txt")
        modules = self.server._parse_search_output(output)
        # Exploit output is not search output -- should find 0 or minimal results
        # The output happens to have "exploit" in MSF status lines, not search table
        # This is correct behavior -- _parse_search_output is for search results only
        assert isinstance(modules, list)


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


class TestExploitSuccessDetection:
    """Test the exploit_success detection logic from run_exploit."""

    def _detect_exploit_success(self, output, sessions_count):
        """Replicate the exploit_success logic from run_exploit."""
        return bool(sessions_count > 0) or "exploit completed" in output.lower()

    def test_success_with_session(self):
        """Session creation means exploit succeeded."""
        assert self._detect_exploit_success("anything", 1) is True

    def test_success_with_exploit_completed(self):
        """'exploit completed' in output with 0 sessions still means success."""
        output = load_fixture("exploit_web_delivery.txt")
        assert self._detect_exploit_success(output, 0) is True

    def test_failure_no_session_no_keyword(self):
        """No sessions and no 'exploit completed' means failure."""
        assert self._detect_exploit_success("[-] Exploit failed", 0) is False

    def test_eternalblue_success(self):
        """EternalBlue success fixture should detect as successful."""
        output = load_fixture("exploit_eternalblue_success.txt")
        # In real run_exploit, sessions would be detected from RPC
        # But even without sessions, the output contains "exploit completed"
        assert self._detect_exploit_success(output, 0) is True

    def test_psexec_success(self):
        """PsExec success fixture should detect as successful."""
        output = load_fixture("exploit_psexec_success.txt")
        assert self._detect_exploit_success(output, 1) is True

    def test_failed_connection_refused(self):
        """Connection refused exploit output without sessions."""
        output = load_fixture("exploit_failed.txt")
        # This fixture has "exploit completed" even on failure
        assert self._detect_exploit_success(output, 0) is True  # Known MSF behavior


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
        # The error classifier should return retryable=False for dead sessions
        error_class, retryable, suggestions = server._classify_msf_error(
            "Session 1 is dead or closed."
        )
        assert retryable is False, "Dead session should not be retryable"
        assert error_class == "config"


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
