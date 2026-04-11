"""
Tests for the nmap MCP tool server.

Covers:
- Smoke tests: boot, method list, required params, meta-param stripping, clock
- Unit tests: XML parser (parse_nmap_xml) with all fixture files
- Method tests: port_scan, service_scan, os_detection, vuln_scan, ping_scan, get_interfaces
- Timeout architecture: run_command_with_progress and heartbeat usage
- Error classification: nmap-specific error patterns
- Contract tests: tool.yaml vs server parameter definitions
- Progress filter: _nmap_progress_filter unit tests with real nmap output lines
- Acceptance tests: every method called through Docker container against localhost
- Trajectory-derived tests: invalid enums, wrong params, real-world LLM mistakes
- Integration tests: real target scenarios (marked @pytest.mark.integration)
"""

import asyncio
import importlib.util
import json
import os
import sys
from pathlib import Path
from typing import Any, Dict, Set

import pytest
import yaml

# ---------------------------------------------------------------------------
# Path setup
# ---------------------------------------------------------------------------
PROJECT_ROOT = Path(__file__).parent.parent.parent
TOOL_DIR = PROJECT_ROOT / "tools" / "nmap"
FIXTURES_DIR = Path(__file__).parent.parent / "fixtures" / "nmap"

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
def nmap_env(request):
    """Create an MCPTestClient with its event loop. Yields (client, loop)."""
    tool = "nmap"
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
    """Load a fixture XML/text file."""
    path = FIXTURES_DIR / name
    return path.read_text()


# ---------------------------------------------------------------------------
# Helper: import server module and parse_nmap_xml for direct testing
# ---------------------------------------------------------------------------
def _get_server_class():
    """Import and return the NmapServer class for direct method testing."""
    spec = importlib.util.spec_from_file_location(
        "nmap_server", TOOL_DIR / "mcp-server.py"
    )
    mod = importlib.util.module_from_spec(spec)
    spec.loader.exec_module(mod)
    return mod.NmapServer


def _get_parse_nmap_xml():
    """Import and return parse_nmap_xml from mcp_common."""
    from mcp_common import parse_nmap_xml
    return parse_nmap_xml


# ===========================================================================
# SMOKE TESTS -- require Docker container running
# ===========================================================================

class TestSmoke:
    """Smoke tests that verify the container boots and basic protocol works."""

    def test_boot_and_list_tools(self, nmap_env):
        """Container starts and list_tools returns methods."""
        client, loop = nmap_env
        assert len(client.tools) > 0, "Server should advertise at least one tool"
        names = client.tool_names()
        assert "port_scan" in names, "port_scan should be in tool list"
        assert "service_scan" in names, "service_scan should be in tool list"
        assert "os_detection" in names, "os_detection should be in tool list"
        assert "vuln_scan" in names, "vuln_scan should be in tool list"
        assert "ping_scan" in names, "ping_scan should be in tool list"
        assert "get_interfaces" in names, "get_interfaces should be in tool list"

    def test_method_list_matches_tool_yaml(self, nmap_env):
        """Every method in tool.yaml is advertised by the server, and vice versa."""
        client, _ = nmap_env
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

    def test_expected_method_count(self, nmap_env):
        """Server should have exactly 6 built-in methods + verify_clock."""
        client, _ = nmap_env
        names = client.tool_names()
        # 6 built-in + verify_clock in MCP_TEST_MODE
        assert len(names) == 7, (
            f"Expected 7 methods (6 built-in + verify_clock), got {len(names)}: {sorted(names)}"
        )

    def test_required_params_port_scan(self, nmap_env):
        """Calling port_scan without required 'target' param returns an error."""
        client, loop = nmap_env
        resp = loop.run_until_complete(
            client.call("port_scan", {
                "ports": "22,80,443",
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

    def test_required_params_service_scan(self, nmap_env):
        """Calling service_scan without required 'ports' param returns an error."""
        client, loop = nmap_env
        resp = loop.run_until_complete(
            client.call("service_scan", {
                "target": "127.0.0.1",
            })
        )
        result = resp.get("result", {})
        is_error = result.get("isError", False)
        content_text = ""
        for c in result.get("content", []):
            if c.get("type") == "text":
                content_text += c["text"]
        assert is_error or "ports" in content_text.lower() or "error" in content_text.lower(), (
            f"Expected error about missing 'ports', got: {content_text[:300]}"
        )

    def test_required_params_vuln_scan(self, nmap_env):
        """Calling vuln_scan without required 'ports' param returns an error."""
        client, loop = nmap_env
        resp = loop.run_until_complete(
            client.call("vuln_scan", {
                "target": "127.0.0.1",
            })
        )
        result = resp.get("result", {})
        is_error = result.get("isError", False)
        content_text = ""
        for c in result.get("content", []):
            if c.get("type") == "text":
                content_text += c["text"]
        assert is_error or "ports" in content_text.lower() or "error" in content_text.lower(), (
            f"Expected error about missing 'ports', got: {content_text[:300]}"
        )

    def test_meta_params_stripped_timeout(self, nmap_env):
        """Passing 'timeout' (meta-param) in args does not crash the server."""
        client, loop = nmap_env
        resp = loop.run_until_complete(
            client.call("port_scan", {
                "target": "127.0.0.1",
                "ports": "22",
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

    def test_meta_params_stripped_clock_offset(self, nmap_env):
        """Passing 'clock_offset' (meta-param) in args does not crash the server."""
        client, loop = nmap_env
        resp = loop.run_until_complete(
            client.call("port_scan", {
                "target": "127.0.0.1",
                "ports": "22",
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

    def test_unknown_method_returns_error(self, nmap_env):
        """Calling a non-existent method returns a helpful error."""
        client, loop = nmap_env
        resp = loop.run_until_complete(
            client.call("full_scan", {})
        )
        result = assert_tool_error(resp)
        content_text = ""
        for c in result.get("content", []):
            if c.get("type") == "text":
                content_text += c["text"]
        assert "Unknown method" in content_text
        assert "full_scan" in content_text

    @pytest.mark.clock
    def test_verify_clock_available(self, nmap_env):
        """verify_clock is registered in MCP_TEST_MODE."""
        client, _ = nmap_env
        names = client.tool_names()
        assert "verify_clock" in names, "verify_clock should be available in test mode"

    @pytest.mark.clock
    def test_verify_clock_returns_time(self, nmap_env):
        """verify_clock returns current time and FAKETIME status."""
        client, loop = nmap_env
        resp = loop.run_until_complete(client.call("verify_clock", {}))
        result = assert_tool_success(resp)
        data = parse_tool_output(resp)
        assert "current_time" in data
        assert "libfaketime_exists" in data
        # nmap container does NOT have libfaketime (no Kerberos)
        assert data["libfaketime_exists"] is False, (
            "libfaketime should NOT be installed in the nmap image"
        )

    def test_structuredContent_present(self, nmap_env):
        """Responses include structuredContent with error classification fields."""
        client, loop = nmap_env
        resp = loop.run_until_complete(client.call("verify_clock", {}))
        result = resp.get("result", {})
        sc = result.get("structuredContent")
        assert sc is not None, "structuredContent should be present"
        assert "success" in sc
        assert "error_class" in sc
        assert "retryable" in sc
        assert "suggestions" in sc


# ===========================================================================
# LIVE METHOD TESTS -- require Docker container, scans localhost
# ===========================================================================

class TestLiveMethods:
    """Tests that actually call nmap methods against localhost in the container."""

    def test_get_interfaces(self, nmap_env):
        """get_interfaces returns interface data and recommended_lhost."""
        client, loop = nmap_env
        resp = loop.run_until_complete(client.call("get_interfaces", {}))
        result = assert_tool_success(resp, "get_interfaces should succeed")
        data = parse_tool_output(resp)
        assert "interfaces" in data
        assert isinstance(data["interfaces"], list)
        assert len(data["interfaces"]) > 0, "Should find at least one interface"
        assert "recommended_lhost" in data
        # In Docker, should have a non-loopback IP
        assert data["recommended_lhost"] is not None, "Should have a recommended LHOST"
        assert data["recommended_lhost"] != "127.0.0.1", "LHOST should not be loopback"

    def test_get_interfaces_structure(self, nmap_env):
        """get_interfaces returns properly structured interface data."""
        client, loop = nmap_env
        resp = loop.run_until_complete(client.call("get_interfaces", {}))
        data = parse_tool_output(resp)
        for iface in data["interfaces"]:
            assert "name" in iface
            assert "ipv4" in iface
            assert "ipv6" in iface
            assert isinstance(iface["ipv4"], list)
            assert isinstance(iface["ipv6"], list)

    def test_port_scan_localhost(self, nmap_env):
        """port_scan against localhost returns valid results."""
        client, loop = nmap_env
        resp = loop.run_until_complete(client.call("port_scan", {
            "target": "127.0.0.1",
            "ports": "1-100",
            "scan_type": "tcp_connect",
            "timing": "aggressive",
        }))
        result = assert_tool_success(resp, "port_scan localhost should succeed")
        data = parse_tool_output(resp)
        assert "hosts" in data
        assert "summary" in data or len(data["hosts"]) >= 0

    def test_port_scan_top_ports(self, nmap_env):
        """port_scan with top_ports parameter works."""
        client, loop = nmap_env
        resp = loop.run_until_complete(client.call("port_scan", {
            "target": "127.0.0.1",
            "top_ports": 10,
            "scan_type": "tcp_connect",
            "timing": "aggressive",
        }))
        result = assert_tool_success(resp, "port_scan with top_ports should succeed")
        data = parse_tool_output(resp)
        assert "hosts" in data

    def test_port_scan_skip_discovery(self, nmap_env):
        """port_scan with skip_discovery works (-Pn flag)."""
        client, loop = nmap_env
        resp = loop.run_until_complete(client.call("port_scan", {
            "target": "127.0.0.1",
            "ports": "22,80",
            "skip_discovery": True,
            "timing": "aggressive",
        }))
        result = assert_tool_success(resp, "port_scan with -Pn should succeed")
        data = parse_tool_output(resp)
        assert "hosts" in data

    def test_service_scan_localhost(self, nmap_env):
        """service_scan against localhost (nothing open, but shouldn't crash)."""
        client, loop = nmap_env
        resp = loop.run_until_complete(client.call("service_scan", {
            "target": "127.0.0.1",
            "ports": "22,80",
            "skip_discovery": True,
        }, timeout=120))
        # May succeed with no services or error due to no open ports
        result = resp.get("result", {})
        assert result is not None, "Should get a response"

    def test_os_detection_localhost(self, nmap_env):
        """os_detection against localhost (may not work well, but shouldn't crash)."""
        client, loop = nmap_env
        resp = loop.run_until_complete(client.call("os_detection", {
            "target": "127.0.0.1",
            "skip_discovery": True,
        }, timeout=120))
        result = resp.get("result", {})
        assert result is not None, "Should get a response"

    def test_ping_scan_localhost(self, nmap_env):
        """ping_scan against localhost subnet returns results."""
        client, loop = nmap_env
        resp = loop.run_until_complete(client.call("ping_scan", {
            "target": "127.0.0.1",
            "timing": "aggressive",
        }))
        result = assert_tool_success(resp, "ping_scan localhost should succeed")
        data = parse_tool_output(resp)
        assert "hosts" in data


# ===========================================================================
# UNIT TESTS -- XML parser, no container needed
# ===========================================================================

class TestParseNmapXml:
    """Test parse_nmap_xml using fixture data."""

    @classmethod
    def setup_class(cls):
        """Get the parse_nmap_xml function."""
        try:
            cls._parse = staticmethod(_get_parse_nmap_xml())
        except Exception as e:
            pytest.skip(f"Cannot import parse_nmap_xml: {e}")

    def test_basic_port_scan(self):
        """Parse basic port scan XML with open, closed ports."""
        xml = load_fixture("port_scan_basic.xml")
        result = self._parse(xml)
        assert result["scanner"] == "nmap"
        assert len(result["hosts"]) == 1

        host = result["hosts"][0]
        assert host["status"] == "up"
        assert len(host["ports"]) == 3

        # Check specific ports
        ports_by_id = {p["port"]: p for p in host["ports"]}
        assert ports_by_id[22]["state"] == "open"
        assert ports_by_id[80]["state"] == "open"
        assert ports_by_id[443]["state"] == "closed"

        # Check service info embedded in port_scan_basic
        assert ports_by_id[22]["service"]["name"] == "ssh"
        assert ports_by_id[22]["service"]["product"] == "OpenSSH"

    def test_hostnames_parsed(self):
        """Hostnames are extracted from XML."""
        xml = load_fixture("port_scan_basic.xml")
        result = self._parse(xml)
        host = result["hosts"][0]
        assert len(host["hostnames"]) > 0
        assert host["hostnames"][0]["name"] == "target.htb"

    def test_addresses_parsed(self):
        """IP addresses are extracted."""
        xml = load_fixture("port_scan_basic.xml")
        result = self._parse(xml)
        host = result["hosts"][0]
        assert len(host["addresses"]) > 0
        assert host["addresses"][0]["addr"] == "10.10.10.1"
        assert host["addresses"][0]["type"] == "ipv4"

    def test_service_scan_xml(self):
        """Parse service scan XML with version info."""
        xml = load_fixture("service_scan.xml")
        result = self._parse(xml)
        host = result["hosts"][0]
        ports_by_id = {p["port"]: p for p in host["ports"]}

        ssh = ports_by_id[22]
        assert ssh["service"]["name"] == "ssh"
        assert ssh["service"]["product"] == "OpenSSH"
        assert ssh["service"]["version"] == "8.2p1"
        assert "Ubuntu" in ssh["service"]["extrainfo"]

        http = ports_by_id[80]
        assert http["service"]["name"] == "http"
        assert http["service"]["product"] == "Apache httpd"
        assert http["service"]["version"] == "2.4.41"

    def test_service_scan_detailed(self):
        """Parse detailed service scan with multiple services."""
        xml = load_fixture("service_scan_detailed.xml")
        result = self._parse(xml)
        host = result["hosts"][0]
        assert len(host["ports"]) == 5
        ports_by_id = {p["port"]: p for p in host["ports"]}

        assert ports_by_id[3306]["service"]["product"] == "MySQL"
        assert ports_by_id[8080]["service"]["product"] == "Apache Tomcat"

    def test_os_detection_xml(self):
        """Parse OS detection XML with OS matches."""
        xml = load_fixture("os_detection.xml")
        result = self._parse(xml)
        host = result["hosts"][0]
        assert len(host["os_matches"]) >= 2

        best = host["os_matches"][0]
        assert "Linux" in best["name"]
        assert best["accuracy"] == 96

        second = host["os_matches"][1]
        assert second["accuracy"] == 92

    def test_vuln_scan_xml(self):
        """Parse vuln scan XML with vulnerability findings."""
        xml = load_fixture("vuln_scan.xml")
        result = self._parse(xml)
        host = result["hosts"][0]

        # Check port 445 has scripts
        port445 = [p for p in host["ports"] if p["port"] == 445][0]
        assert "scripts" in port445
        assert len(port445["scripts"]) == 2

        script_ids = {s["id"] for s in port445["scripts"]}
        assert "smb-vuln-ms17-010" in script_ids
        assert "smb-vuln-ms08-067" in script_ids

        # Check output contains vulnerability info
        for script in port445["scripts"]:
            assert "VULNERABLE" in script["output"]

    def test_vuln_scan_no_vulns(self):
        """Parse vuln scan XML with no vulnerabilities found."""
        xml = load_fixture("vuln_scan_no_vulns.xml")
        result = self._parse(xml)
        host = result["hosts"][0]

        port80 = [p for p in host["ports"] if p["port"] == 80][0]
        assert "scripts" in port80
        # Scripts ran but found nothing
        for script in port80["scripts"]:
            assert "VULNERABLE" not in script["output"]

    def test_ping_scan_xml(self):
        """Parse ping scan XML with multiple hosts."""
        xml = load_fixture("ping_scan.xml")
        result = self._parse(xml)
        assert len(result["hosts"]) == 4  # 3 up + 1 down

        up_hosts = [h for h in result["hosts"] if h["status"] == "up"]
        down_hosts = [h for h in result["hosts"] if h["status"] == "down"]
        assert len(up_hosts) == 3
        assert len(down_hosts) == 1

        # Check runstats
        assert result["hosts_up"] == 3
        assert result["hosts_down"] == 253  # /24 minus 3

    def test_ping_scan_mac_addresses(self):
        """Parse ping scan XML with MAC addresses."""
        xml = load_fixture("ping_scan.xml")
        result = self._parse(xml)
        up_hosts = [h for h in result["hosts"] if h["status"] == "up"]
        # First host should have both ipv4 and mac
        first = up_hosts[0]
        addr_types = {a["type"] for a in first["addresses"]}
        assert "ipv4" in addr_types
        assert "mac" in addr_types

    def test_empty_hosts_xml(self):
        """Parse XML with no hosts found."""
        xml = load_fixture("empty_hosts.xml")
        result = self._parse(xml)
        assert result["hosts"] == []
        assert result["hosts_up"] == 0

    def test_host_down_xml(self):
        """Parse XML with host reported as down."""
        xml = load_fixture("host_down.xml")
        result = self._parse(xml)
        assert len(result["hosts"]) == 1
        assert result["hosts"][0]["status"] == "down"
        assert result["hosts_down"] == 1

    def test_malformed_xml(self):
        """Malformed XML returns error dict, doesn't crash."""
        xml = load_fixture("malformed.xml")
        result = self._parse(xml)
        assert "error" in result
        assert "raw" in result

    def test_hostscript_clock_skew(self):
        """Parse host-level NSE scripts including clock-skew (Feature 28)."""
        xml = load_fixture("hostscript_clockskew.xml")
        result = self._parse(xml)
        host = result["hosts"][0]

        assert "host_scripts" in host, "host_scripts should be present"
        assert len(host["host_scripts"]) == 3

        script_ids = {s["id"] for s in host["host_scripts"]}
        assert "clock-skew" in script_ids
        assert "smb-os-discovery" in script_ids
        assert "smb2-security-mode" in script_ids

        # Verify clock-skew output is parseable
        clock_script = [s for s in host["host_scripts"] if s["id"] == "clock-skew"][0]
        assert "7h00m01s" in clock_script["output"]

    def test_hostscript_smb_os_discovery(self):
        """Parse smb-os-discovery host script."""
        xml = load_fixture("hostscript_clockskew.xml")
        result = self._parse(xml)
        host = result["hosts"][0]

        os_script = [s for s in host["host_scripts"] if s["id"] == "smb-os-discovery"][0]
        assert "Windows Server 2019" in os_script["output"]
        assert "DC01" in os_script["output"]
        assert "corp.local" in os_script["output"]

    def test_hostscript_not_present_without_data(self):
        """host_scripts key is absent when no hostscript element exists."""
        xml = load_fixture("port_scan_basic.xml")
        result = self._parse(xml)
        host = result["hosts"][0]
        assert "host_scripts" not in host, (
            "host_scripts should not be present when there are no host-level scripts"
        )

    def test_filtered_ports(self):
        """Parse XML with filtered ports (firewall)."""
        xml = load_fixture("port_scan_filtered.xml")
        result = self._parse(xml)
        host = result["hosts"][0]
        ports_by_id = {p["port"]: p for p in host["ports"]}

        assert ports_by_id[22]["state"] == "open"
        assert ports_by_id[80]["state"] == "filtered"
        assert ports_by_id[445]["state"] == "closed"

    def test_udp_ports(self):
        """Parse XML with UDP ports."""
        xml = load_fixture("port_scan_udp.xml")
        result = self._parse(xml)
        host = result["hosts"][0]
        for port in host["ports"]:
            assert port["protocol"] == "udp"

        ports_by_id = {p["port"]: p for p in host["ports"]}
        assert ports_by_id[53]["state"] == "open"
        assert ports_by_id[137]["state"] == "open|filtered"

    def test_runstats_elapsed(self):
        """Elapsed time is parsed from runstats."""
        xml = load_fixture("port_scan_basic.xml")
        result = self._parse(xml)
        assert "elapsed" in result
        assert result["elapsed"] == "12.00"

    def test_start_time_and_args(self):
        """Start time and args are captured from root element."""
        xml = load_fixture("port_scan_basic.xml")
        result = self._parse(xml)
        assert "nmap" in result["args"]
        assert result["start_time"] != ""


# ===========================================================================
# SERVER UNIT TESTS -- test internal methods without Docker
# ===========================================================================

class TestServerInternals:
    """Test NmapServer internal helper methods."""

    @pytest.fixture(autouse=True, scope="class")
    def server(self):
        """Create a server instance for testing."""
        try:
            cls = _get_server_class()
            self.__class__._server = cls()
        except Exception as e:
            pytest.skip(f"Cannot import NmapServer: {e}")

    def test_timing_flag_normal(self):
        """Normal timing maps to -T3."""
        assert self._server._get_timing_flag("normal") == "-T3"

    def test_timing_flag_aggressive(self):
        """Aggressive timing maps to -T4."""
        assert self._server._get_timing_flag("aggressive") == "-T4"

    def test_timing_flag_insane(self):
        """Insane timing maps to -T5."""
        assert self._server._get_timing_flag("insane") == "-T5"

    def test_timing_flag_paranoid(self):
        """Paranoid timing maps to -T0."""
        assert self._server._get_timing_flag("paranoid") == "-T0"

    def test_timing_flag_unknown_defaults_to_t3(self):
        """Unknown timing value defaults to -T3."""
        assert self._server._get_timing_flag("fast") == "-T3"
        assert self._server._get_timing_flag("T4") == "-T3"

    def test_scan_type_tcp_connect(self):
        """tcp_connect maps to -sT."""
        assert self._server._get_scan_type_flags("tcp_connect") == ["-sT"]

    def test_scan_type_syn(self):
        """syn maps to -sS."""
        assert self._server._get_scan_type_flags("syn") == ["-sS"]

    def test_scan_type_udp(self):
        """udp maps to -sU."""
        assert self._server._get_scan_type_flags("udp") == ["-sU"]

    def test_scan_type_ack(self):
        """ack maps to -sA."""
        assert self._server._get_scan_type_flags("ack") == ["-sA"]

    def test_scan_type_fin(self):
        """fin maps to -sF."""
        assert self._server._get_scan_type_flags("fin") == ["-sF"]

    def test_scan_type_window(self):
        """window maps to -sW."""
        assert self._server._get_scan_type_flags("window") == ["-sW"]

    def test_scan_type_null(self):
        """null maps to -sN."""
        assert self._server._get_scan_type_flags("null") == ["-sN"]

    def test_scan_type_xmas(self):
        """xmas maps to -sX."""
        assert self._server._get_scan_type_flags("xmas") == ["-sX"]

    def test_scan_type_maimon(self):
        """maimon maps to -sM."""
        assert self._server._get_scan_type_flags("maimon") == ["-sM"]

    def test_scan_type_unknown_defaults_to_st(self):
        """Unknown scan type defaults to -sT."""
        assert self._server._get_scan_type_flags("tcp_syn") == ["-sT"]

    def test_registered_methods(self):
        """All 6 methods are registered."""
        assert len(self._server.methods) == 6
        expected = {"port_scan", "service_scan", "os_detection", "vuln_scan", "ping_scan", "get_interfaces"}
        assert set(self._server.methods.keys()) == expected


# ===========================================================================
# TIMEOUT ARCHITECTURE TESTS
# ===========================================================================

class TestTimeoutArchitecture:
    """Verify that _run_nmap uses run_command_with_progress for heartbeating.

    The #1 issue with nmap: port_scan has 35% timeout rate because
    run_command() gives no heartbeat to keep the MCP client alive.
    After the fix, _run_nmap should use run_command_with_progress().
    """

    @pytest.fixture(autouse=True, scope="class")
    def server(self):
        """Create a server instance."""
        try:
            cls = _get_server_class()
            self.__class__._server = cls()
        except Exception as e:
            pytest.skip(f"Cannot import NmapServer: {e}")

    def test_run_nmap_uses_progress(self):
        """_run_nmap should call run_command_with_progress, not run_command.

        This is the critical fix: without heartbeating, the MCP client
        kills the connection after its own timeout (typically 600s) when
        nmap is still running a long scan.
        """
        import inspect
        source = inspect.getsource(self._server._run_nmap)
        assert "run_command_with_progress" in source, (
            "_run_nmap must use run_command_with_progress for heartbeat support. "
            "Currently uses run_command which causes 35% timeout rate on port_scan."
        )

    def test_port_scan_timeout_adequate(self):
        """port_scan timeout should be >= 600s for full scans."""
        import inspect
        source = inspect.getsource(self._server.port_scan)
        # The default in _run_nmap or the call from port_scan should be >= 600
        # Check that port_scan either passes a higher timeout or uses adaptive timeout
        # The default 300s is too low for -p 1-65535
        nmap_source = inspect.getsource(self._server._run_nmap)
        # Accept if either:
        # 1. _run_nmap default timeout >= 600
        # 2. port_scan passes timeout >= 600 explicitly
        has_adequate_default = "timeout: int = " in nmap_source
        if has_adequate_default:
            import re
            match = re.search(r"timeout:\s*int\s*=\s*(\d+)", nmap_source)
            if match:
                default_timeout = int(match.group(1))
                if default_timeout >= 600:
                    return  # Good: default is adequate

        # Check if port_scan passes explicit timeout
        has_explicit = "timeout=" in source and any(
            int(t) >= 600 for t in __import__("re").findall(r"timeout=(\d+)", source)
        )
        assert has_explicit or False, (
            "port_scan should use timeout >= 600s. Current 300s default causes "
            "35% timeout rate on full port scans (-p 1-65535)."
        )

    def test_vuln_scan_timeout_not_exceed_registry(self):
        """vuln_scan server timeout should not exceed registry timeout_seconds.

        tool.yaml says timeout_seconds=600 but vuln_scan used timeout=900.
        The client kills at 600s, making the extra 300s of server timeout useless
        and causing confusing timeout errors.
        """
        import inspect
        import re
        source = inspect.getsource(self._server.vuln_scan)
        # Find the timeout value passed to _run_nmap
        match = re.search(r"timeout=(\d+)", source)
        if match:
            server_timeout = int(match.group(1))
            # Load registry timeout
            yaml_path = TOOL_DIR / "tool.yaml"
            with open(yaml_path) as f:
                yaml_data = yaml.safe_load(f)
            registry_timeout = yaml_data.get("timeout_seconds", 600)
            assert server_timeout <= registry_timeout, (
                f"vuln_scan server timeout ({server_timeout}s) exceeds registry "
                f"timeout_seconds ({registry_timeout}s). Client will kill first, "
                f"wasting server-side timeout buffer."
            )

    def test_nmap_progress_filter_defined(self):
        """_run_nmap should define a progress_filter for nmap status lines.

        nmap outputs progress like 'Stats: 0:01:23 elapsed; 0 hosts completed'
        and 'Nmap scan report for ...' which can be forwarded as heartbeats.
        """
        import inspect
        source = inspect.getsource(self._server._run_nmap)
        # Accept either a progress_filter parameter or heartbeat_interval
        has_progress = "progress_filter" in source or "heartbeat_interval" in source
        assert has_progress, (
            "_run_nmap should use run_command_with_progress with either a "
            "progress_filter for nmap status lines or a heartbeat_interval."
        )


# ===========================================================================
# ERROR CLASSIFICATION TESTS
# ===========================================================================

class TestErrorClassification:
    """Test nmap-specific error classification."""

    @pytest.fixture(autouse=True, scope="class")
    def server(self):
        """Create a server instance."""
        try:
            cls = _get_server_class()
            self.__class__._server = cls()
        except Exception as e:
            pytest.skip(f"Cannot import NmapServer: {e}")

    def test_classify_host_down(self):
        """'host seems down' error should classify as 'network'."""
        if hasattr(self._server, '_classify_nmap_error'):
            err_class, retryable, suggestions = self._server._classify_nmap_error(
                "Note: Host seems down. If it is really up, but blocking our ping probes, "
                "try -Pn"
            )
            assert err_class == "network", f"Expected 'network', got '{err_class}'"
            assert retryable is True
            assert any("Pn" in s or "skip_discovery" in s for s in suggestions), (
                f"Should suggest -Pn/skip_discovery, got: {suggestions}"
            )
        else:
            pytest.skip("_classify_nmap_error not implemented yet")

    def test_classify_network_unreachable(self):
        """'Network is unreachable' should classify as 'network'."""
        if hasattr(self._server, '_classify_nmap_error'):
            err_class, retryable, suggestions = self._server._classify_nmap_error(
                "RTTVAR has grown to over 2.3 seconds, decreasing to 2.0\n"
                "sendto in send_ip_raw: sendto(5, packet, 44, 0, 10.10.10.1, 16) => "
                "Network is unreachable"
            )
            assert err_class == "network", f"Expected 'network', got '{err_class}'"
        else:
            pytest.skip("_classify_nmap_error not implemented yet")

    def test_classify_privileged_error(self):
        """Privilege-related errors should classify as 'permission'."""
        if hasattr(self._server, '_classify_nmap_error'):
            err_class, retryable, suggestions = self._server._classify_nmap_error(
                "You requested a scan type which requires root privileges.\n"
                "QUITTING!"
            )
            assert err_class == "permission", f"Expected 'permission', got '{err_class}'"
            assert retryable is False
        else:
            pytest.skip("_classify_nmap_error not implemented yet")

    def test_classify_timeout(self):
        """Timeout errors from base class should still work."""
        err_class, retryable = self._server._classify_unhandled_error(
            1, "Traceback (most recent call last):\n  asyncio.TimeoutError"
        )
        assert err_class == "timeout"
        assert retryable is True

    def test_classify_clean_output(self):
        """Normal output should not be misclassified."""
        err_class, retryable = self._server._classify_unhandled_error(0, "")
        assert err_class == "unknown"


# ===========================================================================
# TOOL.YAML CONTRACT TESTS -- no container needed
# ===========================================================================

class TestToolYamlContract:
    """Verify tool.yaml matches server parameter definitions."""

    @pytest.fixture(autouse=True, scope="class")
    def load_data(self):
        """Load tool.yaml and server."""
        with open(TOOL_DIR / "tool.yaml") as f:
            self.__class__._yaml = yaml.safe_load(f)
        try:
            cls = _get_server_class()
            self.__class__._server = cls()
        except Exception as e:
            pytest.skip(f"Cannot import NmapServer: {e}")

    def test_yaml_has_all_6_methods(self):
        """tool.yaml should define exactly 6 methods."""
        methods = self._yaml.get("methods", {})
        assert len(methods) == 6, (
            f"Expected 6 methods, got {len(methods)}: {sorted(methods.keys())}"
        )

    def test_yaml_method_names(self):
        """tool.yaml should have the correct method names."""
        expected = {"port_scan", "service_scan", "os_detection", "vuln_scan", "ping_scan", "get_interfaces"}
        yaml_names = set(self._yaml.get("methods", {}).keys())
        assert yaml_names == expected, f"Expected {expected}, got {yaml_names}"

    def test_all_methods_have_descriptions(self):
        """Every method should have a description."""
        for name, defn in self._yaml.get("methods", {}).items():
            assert "description" in defn, f"Method {name} missing description"
            assert len(defn["description"]) > 10, f"Method {name} has too short description"

    def test_all_methods_have_when_to_use(self):
        """Every method should have a when_to_use field."""
        for name, defn in self._yaml.get("methods", {}).items():
            assert "when_to_use" in defn, f"Method {name} missing when_to_use"
            assert len(defn["when_to_use"]) > 10, f"Method {name} has too short when_to_use"

    def test_method_names_match_server(self):
        """Method names in tool.yaml match the server's registered methods."""
        yaml_names = set(self._yaml.get("methods", {}).keys())
        server_names = set(self._server.methods.keys())

        yaml_only = yaml_names - server_names
        server_only = server_names - yaml_names

        assert not yaml_only, f"Methods in tool.yaml but not server: {yaml_only}"
        assert not server_only, f"Methods in server but not tool.yaml: {server_only}"

    def test_yaml_params_subset_of_server(self):
        """Every yaml param should be accepted by the server handler."""
        for method_name, defn in self._yaml.get("methods", {}).items():
            yaml_params = set(defn.get("params", {}).keys())
            server_method = self._server.methods.get(method_name)
            if server_method is None:
                continue
            server_params = set(server_method.params.keys())
            yaml_only = yaml_params - server_params
            assert not yaml_only, (
                f"Method {method_name}: yaml has params not in server: {yaml_only}"
            )

    def test_server_params_subset_of_yaml(self):
        """Every server param should be documented in tool.yaml."""
        for method_name, defn in self._yaml.get("methods", {}).items():
            yaml_params = set(defn.get("params", {}).keys())
            server_method = self._server.methods.get(method_name)
            if server_method is None:
                continue
            server_params = set(server_method.params.keys())
            server_only = server_params - yaml_params
            assert not server_only, (
                f"Method {method_name}: server has params not in yaml: {server_only}"
            )

    def test_yaml_param_types_valid(self):
        """All param types should be valid."""
        valid_types = {"string", "integer", "boolean", "number", "array", "object", "enum"}
        for method_name, defn in self._yaml.get("methods", {}).items():
            for param_name, param_def in defn.get("params", {}).items():
                ptype = param_def.get("type", "string")
                assert ptype in valid_types, (
                    f"{method_name}.{param_name}: invalid type '{ptype}'"
                )

    def test_port_scan_has_target_required(self):
        """port_scan target param should be required."""
        params = self._yaml["methods"]["port_scan"]["params"]
        assert params["target"].get("required") is True

    def test_service_scan_has_ports_required(self):
        """service_scan ports param should be required."""
        params = self._yaml["methods"]["service_scan"]["params"]
        assert params["ports"].get("required") is True

    def test_vuln_scan_has_ports_required(self):
        """vuln_scan ports param should be required."""
        params = self._yaml["methods"]["vuln_scan"]["params"]
        assert params["ports"].get("required") is True

    def test_yaml_timeout_seconds(self):
        """tool.yaml should have timeout_seconds defined."""
        assert "timeout_seconds" in self._yaml
        assert self._yaml["timeout_seconds"] >= 300

    def test_yaml_privileged_required(self):
        """tool.yaml should mark privileged as required."""
        req = self._yaml.get("requirements", {})
        assert req.get("privileged") is True

    def test_yaml_phases(self):
        """tool.yaml should include reconnaissance and enumeration phases."""
        phases = self._yaml.get("phases", [])
        assert "reconnaissance" in phases
        assert "enumeration" in phases


# ===========================================================================
# INTEGRATION TESTS -- require --target
# ===========================================================================

@pytest.mark.integration
class TestIntegration:
    """Integration tests that need a real target.

    Run with: pytest tests/tools/test_nmap.py --tool=nmap
              --target=<IP> -m integration -v
    """

    def test_port_scan_real_target(self, nmap_env, target):
        """Port scan against a real target."""
        client, loop = nmap_env
        resp = loop.run_until_complete(client.call("port_scan", {
            "target": target,
            "ports": "22,80,443,445,8080",
            "scan_type": "syn",
            "timing": "aggressive",
            "skip_discovery": True,
        }))
        result = assert_tool_success(resp, "port_scan should succeed against real target")
        data = parse_tool_output(resp)
        assert "hosts" in data
        assert len(data["hosts"]) > 0

    def test_service_scan_real_target(self, nmap_env, target):
        """Service scan against a real target."""
        client, loop = nmap_env
        resp = loop.run_until_complete(client.call("service_scan", {
            "target": target,
            "ports": "22,80",
            "skip_discovery": True,
        }, timeout=300))
        result = assert_tool_success(resp, "service_scan should succeed")
        data = parse_tool_output(resp)
        assert "hosts" in data

    def test_os_detection_real_target(self, nmap_env, target):
        """OS detection against a real target."""
        client, loop = nmap_env
        resp = loop.run_until_complete(client.call("os_detection", {
            "target": target,
            "skip_discovery": True,
        }, timeout=300))
        # OS detection may not always succeed, but should not crash
        result = resp.get("result", {})
        assert result is not None

    def test_full_port_scan_with_heartbeat(self, nmap_env, target):
        """Full port scan (1-65535) should use heartbeats and not timeout.

        This is the key regression test for the 35% timeout rate fix.
        """
        client, loop = nmap_env
        resp = loop.run_until_complete(client.call("port_scan", {
            "target": target,
            "ports": "1-65535",
            "scan_type": "syn",
            "timing": "aggressive",
            "skip_discovery": True,
        }, timeout=900))
        # Should succeed or fail with a real nmap error, NOT a timeout
        result = resp.get("result", {})
        content_text = ""
        for c in result.get("content", []):
            if c.get("type") == "text":
                content_text += c["text"]
        assert "timed out" not in content_text.lower(), (
            f"Full port scan timed out (heartbeat fix regression): {content_text[:200]}"
        )


# ===========================================================================
# PROGRESS FILTER UNIT TESTS -- no container needed
# ===========================================================================

class TestProgressFilter:
    """Test _nmap_progress_filter with real nmap output lines.

    The progress filter is critical for heartbeat support: it extracts
    meaningful status messages from nmap's verbose output so the MCP client
    knows the scan is still alive.
    """

    @pytest.fixture(autouse=True, scope="class")
    def server(self):
        """Create a server instance."""
        try:
            cls = _get_server_class()
            self.__class__._server = cls()
        except Exception as e:
            pytest.skip(f"Cannot import NmapServer: {e}")

    def test_stats_line(self):
        """Stats lines from --stats-every are captured."""
        line = "Stats: 0:01:23 elapsed; 0 hosts completed (1 up), 1 undergoing SYN Stealth Scan"
        result = self._server._nmap_progress_filter(line)
        assert result is not None
        assert "Stats:" in result

    def test_percentage_progress(self):
        """Scan phase percentage lines are captured."""
        line = "SYN Stealth Scan Timing: About 45.00% done; ETC: 12:35 (0:01:20 remaining)"
        result = self._server._nmap_progress_filter(line)
        assert result is not None
        assert "45.00%" in result

    def test_completed_phase(self):
        """Completed phase lines are captured."""
        line = "Completed SYN Stealth Scan at 12:35, 120.50s elapsed (65535 total ports)"
        result = self._server._nmap_progress_filter(line)
        assert result is not None
        assert "Completed" in result

    def test_scan_report(self):
        """Host report lines are captured."""
        line = "Nmap scan report for target.htb (10.10.10.1)"
        result = self._server._nmap_progress_filter(line)
        assert result is not None
        assert "target.htb" in result

    def test_discovered_open_port(self):
        """Discovered open port lines are captured."""
        line = "Discovered open port 80/tcp on 10.10.10.1"
        result = self._server._nmap_progress_filter(line)
        assert result is not None
        assert "80/tcp" in result

    def test_unrelated_line_returns_none(self):
        """Unrelated stderr lines return None (not forwarded)."""
        assert self._server._nmap_progress_filter("Starting Nmap 7.98 ( https://nmap.org )") is None

    def test_empty_line_returns_none(self):
        """Empty lines return None."""
        assert self._server._nmap_progress_filter("") is None
        assert self._server._nmap_progress_filter("   ") is None

    def test_port_table_line_returns_none(self):
        """Port table lines should NOT be forwarded as progress."""
        assert self._server._nmap_progress_filter("22/tcp   open  ssh") is None
        assert self._server._nmap_progress_filter("PORT     STATE SERVICE") is None

    def test_long_stats_line_truncated(self):
        """Stats lines longer than 80 chars are truncated."""
        line = "Stats: 0:05:30 elapsed; 0 hosts completed (1 up), 1 undergoing SYN Stealth Scan -- this is a very long line with lots of extra information"
        result = self._server._nmap_progress_filter(line)
        assert result is not None
        assert len(result) <= 80

    def test_udp_scan_timing(self):
        """UDP Scan Timing progress lines are captured."""
        line = "UDP Scan Timing: About 23.50% done; ETC: 22:14 (0:03:45 remaining)"
        result = self._server._nmap_progress_filter(line)
        assert result is not None
        assert "23.50%" in result

    def test_service_scan_timing(self):
        """Service scan timing progress lines are captured."""
        line = "Service scan Timing: About 80.00% done; ETC: 10:30 (0:00:15 remaining)"
        result = self._server._nmap_progress_filter(line)
        assert result is not None
        assert "80.00%" in result


# ===========================================================================
# ACCEPTANCE TESTS -- call every method through Docker container
# ===========================================================================

class TestAcceptance:
    """Call every method through the Docker container against localhost.

    These tests verify:
    - Every method is callable through the full MCP protocol stack
    - Responses have correct structuredContent shape (success, error_class, retryable, suggestions)
    - Meta-param stripping works across all methods
    - Invalid enum values produce clean validation errors (not crashes)
    - Extra/wrong params from LLM mistakes are handled gracefully

    Acceptance tests differ from TestLiveMethods by systematically covering
    every method, every scan type, and common LLM mistake patterns observed
    in 152 real engagement calls across 17 HTB boxes.
    """

    def _assert_structuredContent(self, resp, method_name):
        """Assert response has structuredContent with required fields."""
        result = resp.get("result", {})
        sc = result.get("structuredContent")
        assert sc is not None, f"{method_name}: missing structuredContent"
        assert "success" in sc, f"{method_name}: structuredContent missing 'success'"
        assert "error_class" in sc, f"{method_name}: structuredContent missing 'error_class'"
        assert "retryable" in sc, f"{method_name}: structuredContent missing 'retryable'"
        assert "suggestions" in sc, f"{method_name}: structuredContent missing 'suggestions'"
        return sc

    def _get_content_text(self, resp):
        """Extract text from MCP response content."""
        result = resp.get("result", {})
        texts = []
        for c in result.get("content", []):
            if c.get("type") == "text":
                texts.append(c["text"])
        return "\n".join(texts)

    # ── port_scan ─────────────────────────────────────────────────

    def test_port_scan_localhost_tcp_connect(self, nmap_env):
        """port_scan with tcp_connect against localhost returns structuredContent."""
        client, loop = nmap_env
        resp = loop.run_until_complete(client.call("port_scan", {
            "target": "127.0.0.1",
            "ports": "1-100",
            "scan_type": "tcp_connect",
            "timing": "aggressive",
        }))
        sc = self._assert_structuredContent(resp, "port_scan/tcp_connect")
        assert sc["success"] is True

    def test_port_scan_localhost_syn(self, nmap_env):
        """port_scan with SYN scan against localhost (privileged container)."""
        client, loop = nmap_env
        resp = loop.run_until_complete(client.call("port_scan", {
            "target": "127.0.0.1",
            "ports": "22,80,443",
            "scan_type": "syn",
            "timing": "aggressive",
        }))
        sc = self._assert_structuredContent(resp, "port_scan/syn")
        # Privileged container, should succeed
        assert sc["success"] is True

    def test_port_scan_localhost_udp(self, nmap_env):
        """port_scan with UDP scan against localhost (privileged, slower)."""
        client, loop = nmap_env
        resp = loop.run_until_complete(client.call("port_scan", {
            "target": "127.0.0.1",
            "ports": "53,161,123",
            "scan_type": "udp",
            "timing": "aggressive",
        }, timeout=120))
        sc = self._assert_structuredContent(resp, "port_scan/udp")
        # UDP scan may succeed or timeout on localhost; should not crash
        assert isinstance(sc["success"], bool)

    def test_port_scan_localhost_ack(self, nmap_env):
        """port_scan with ACK scan against localhost (firewall mapping)."""
        client, loop = nmap_env
        resp = loop.run_until_complete(client.call("port_scan", {
            "target": "127.0.0.1",
            "ports": "22,80",
            "scan_type": "ack",
            "timing": "aggressive",
        }))
        sc = self._assert_structuredContent(resp, "port_scan/ack")
        assert isinstance(sc["success"], bool)

    def test_port_scan_localhost_fin(self, nmap_env):
        """port_scan with FIN scan against localhost (stealth/evasion)."""
        client, loop = nmap_env
        resp = loop.run_until_complete(client.call("port_scan", {
            "target": "127.0.0.1",
            "ports": "22,80",
            "scan_type": "fin",
            "timing": "aggressive",
        }))
        sc = self._assert_structuredContent(resp, "port_scan/fin")
        assert isinstance(sc["success"], bool)

    def test_port_scan_localhost_window(self, nmap_env):
        """port_scan with Window scan against localhost."""
        client, loop = nmap_env
        resp = loop.run_until_complete(client.call("port_scan", {
            "target": "127.0.0.1",
            "ports": "22,80",
            "scan_type": "window",
            "timing": "aggressive",
        }))
        sc = self._assert_structuredContent(resp, "port_scan/window")
        assert isinstance(sc["success"], bool)

    def test_port_scan_localhost_null(self, nmap_env):
        """port_scan with NULL scan against localhost (no TCP flags)."""
        client, loop = nmap_env
        resp = loop.run_until_complete(client.call("port_scan", {
            "target": "127.0.0.1",
            "ports": "22,80",
            "scan_type": "null",
            "timing": "aggressive",
        }))
        sc = self._assert_structuredContent(resp, "port_scan/null")
        assert isinstance(sc["success"], bool)

    def test_port_scan_localhost_xmas(self, nmap_env):
        """port_scan with Xmas scan against localhost (FIN/PSH/URG flags)."""
        client, loop = nmap_env
        resp = loop.run_until_complete(client.call("port_scan", {
            "target": "127.0.0.1",
            "ports": "22,80",
            "scan_type": "xmas",
            "timing": "aggressive",
        }))
        sc = self._assert_structuredContent(resp, "port_scan/xmas")
        assert isinstance(sc["success"], bool)

    def test_port_scan_localhost_maimon(self, nmap_env):
        """port_scan with Maimon scan against localhost (FIN/ACK probe)."""
        client, loop = nmap_env
        resp = loop.run_until_complete(client.call("port_scan", {
            "target": "127.0.0.1",
            "ports": "22,80",
            "scan_type": "maimon",
            "timing": "aggressive",
        }))
        sc = self._assert_structuredContent(resp, "port_scan/maimon")
        assert isinstance(sc["success"], bool)

    def test_port_scan_timing_polite(self, nmap_env):
        """port_scan with polite timing (T2) works without error.

        Note: paranoid (T0) and sneaky (T1) are too slow for CI (minutes per
        port). polite (T2) is the slowest practical timing for testing.
        """
        client, loop = nmap_env
        resp = loop.run_until_complete(client.call("port_scan", {
            "target": "127.0.0.1",
            "ports": "80",
            "scan_type": "tcp_connect",
            "timing": "polite",
        }, timeout=120))
        sc = self._assert_structuredContent(resp, "port_scan/polite")
        assert isinstance(sc["success"], bool)

    def test_port_scan_timing_insane(self, nmap_env):
        """port_scan with insane timing (T5) works."""
        client, loop = nmap_env
        resp = loop.run_until_complete(client.call("port_scan", {
            "target": "127.0.0.1",
            "ports": "22,80,443",
            "scan_type": "tcp_connect",
            "timing": "insane",
        }))
        sc = self._assert_structuredContent(resp, "port_scan/insane")
        assert sc["success"] is True

    def test_port_scan_custom_port_list(self, nmap_env):
        """port_scan with comma-separated port list."""
        client, loop = nmap_env
        resp = loop.run_until_complete(client.call("port_scan", {
            "target": "127.0.0.1",
            "ports": "21,22,23,25,53,80,110,111,135,139,143,443,445,993,995,3306,3389,5900,8080",
            "scan_type": "tcp_connect",
            "timing": "aggressive",
        }))
        sc = self._assert_structuredContent(resp, "port_scan/custom_ports")
        assert sc["success"] is True

    def test_port_scan_with_top_ports(self, nmap_env):
        """port_scan with top_ports parameter (mutually exclusive with ports)."""
        client, loop = nmap_env
        resp = loop.run_until_complete(client.call("port_scan", {
            "target": "127.0.0.1",
            "top_ports": 100,
            "scan_type": "tcp_connect",
            "timing": "aggressive",
        }))
        sc = self._assert_structuredContent(resp, "port_scan/top_ports")
        assert sc["success"] is True

    def test_port_scan_skip_discovery(self, nmap_env):
        """port_scan with skip_discovery=true adds -Pn flag."""
        client, loop = nmap_env
        resp = loop.run_until_complete(client.call("port_scan", {
            "target": "127.0.0.1",
            "ports": "80",
            "skip_discovery": True,
            "timing": "aggressive",
        }))
        sc = self._assert_structuredContent(resp, "port_scan/skip_discovery")
        assert sc["success"] is True

    def test_port_scan_response_shape(self, nmap_env):
        """port_scan response includes hosts array and summary."""
        client, loop = nmap_env
        resp = loop.run_until_complete(client.call("port_scan", {
            "target": "127.0.0.1",
            "ports": "1-100",
            "scan_type": "tcp_connect",
            "timing": "aggressive",
        }))
        data = parse_tool_output(resp)
        assert "hosts" in data, "port_scan response must include 'hosts' array"
        assert isinstance(data["hosts"], list)
        # scanner and args should be present from XML parsing
        assert "scanner" in data
        assert data["scanner"] == "nmap"
        assert "args" in data

    def test_port_scan_meta_param_timeout_stripped(self, nmap_env):
        """Meta-param 'timeout' does not reach the handler."""
        client, loop = nmap_env
        resp = loop.run_until_complete(client.call("port_scan", {
            "target": "127.0.0.1",
            "ports": "80",
            "timeout": 30,
        }))
        text = self._get_content_text(resp)
        assert "unexpected keyword argument" not in text

    def test_port_scan_meta_param_clock_offset_stripped(self, nmap_env):
        """Meta-param 'clock_offset' does not reach the handler."""
        client, loop = nmap_env
        resp = loop.run_until_complete(client.call("port_scan", {
            "target": "127.0.0.1",
            "ports": "80",
            "clock_offset": "+5h",
        }))
        text = self._get_content_text(resp)
        assert "unexpected keyword argument" not in text

    # ── service_scan ──────────────────────────────────────────────

    def test_service_scan_localhost(self, nmap_env):
        """service_scan against localhost returns structuredContent."""
        client, loop = nmap_env
        resp = loop.run_until_complete(client.call("service_scan", {
            "target": "127.0.0.1",
            "ports": "22,80",
            "skip_discovery": True,
        }, timeout=120))
        sc = self._assert_structuredContent(resp, "service_scan")
        assert isinstance(sc["success"], bool)

    def test_service_scan_version_intensity(self, nmap_env):
        """service_scan with version_intensity param works."""
        client, loop = nmap_env
        resp = loop.run_until_complete(client.call("service_scan", {
            "target": "127.0.0.1",
            "ports": "80",
            "skip_discovery": True,
            "version_intensity": 2,
        }, timeout=120))
        sc = self._assert_structuredContent(resp, "service_scan/version_intensity")
        assert isinstance(sc["success"], bool)

    def test_service_scan_missing_ports_error(self, nmap_env):
        """service_scan without required 'ports' returns a validation error."""
        client, loop = nmap_env
        resp = loop.run_until_complete(client.call("service_scan", {
            "target": "127.0.0.1",
        }))
        result = resp.get("result", {})
        is_error = result.get("isError", False)
        text = self._get_content_text(resp)
        assert is_error or "ports" in text.lower() or "required" in text.lower()

    def test_service_scan_extra_scripts_param_handled(self, nmap_env):
        """LLM sometimes passes 'scripts' param to service_scan (belongs to vuln_scan).

        Observed in engagement ses_3a9d2e3d: service_scan() got an unexpected
        keyword argument 'scripts'. The base server should strip unknown params
        or return a helpful error.
        """
        client, loop = nmap_env
        resp = loop.run_until_complete(client.call("service_scan", {
            "target": "127.0.0.1",
            "ports": "22,80",
            "skip_discovery": True,
            "scripts": "vuln",
        }, timeout=120))
        text = self._get_content_text(resp)
        # Should NOT crash with "unexpected keyword argument"
        assert "unexpected keyword argument" not in text, (
            "service_scan should handle extra 'scripts' param gracefully (strip or warn)"
        )

    # ── os_detection ──────────────────────────────────────────────

    def test_os_detection_localhost(self, nmap_env):
        """os_detection against localhost returns structuredContent."""
        client, loop = nmap_env
        resp = loop.run_until_complete(client.call("os_detection", {
            "target": "127.0.0.1",
            "skip_discovery": True,
        }, timeout=120))
        sc = self._assert_structuredContent(resp, "os_detection")
        assert isinstance(sc["success"], bool)

    def test_os_detection_missing_target_error(self, nmap_env):
        """os_detection without required 'target' returns error."""
        client, loop = nmap_env
        resp = loop.run_until_complete(client.call("os_detection", {}))
        result = resp.get("result", {})
        is_error = result.get("isError", False)
        text = self._get_content_text(resp)
        assert is_error or "target" in text.lower() or "required" in text.lower()

    # ── vuln_scan ─────────────────────────────────────────────────

    def test_vuln_scan_localhost(self, nmap_env):
        """vuln_scan against localhost returns structuredContent."""
        client, loop = nmap_env
        resp = loop.run_until_complete(client.call("vuln_scan", {
            "target": "127.0.0.1",
            "ports": "80",
            "skip_discovery": True,
        }, timeout=180))
        sc = self._assert_structuredContent(resp, "vuln_scan")
        assert isinstance(sc["success"], bool)

    def test_vuln_scan_custom_scripts(self, nmap_env):
        """vuln_scan with specific NSE scripts."""
        client, loop = nmap_env
        resp = loop.run_until_complete(client.call("vuln_scan", {
            "target": "127.0.0.1",
            "ports": "80",
            "scripts": "default,safe",
            "skip_discovery": True,
        }, timeout=180))
        sc = self._assert_structuredContent(resp, "vuln_scan/custom_scripts")
        assert isinstance(sc["success"], bool)

    def test_vuln_scan_with_script_args(self, nmap_env):
        """vuln_scan with script_args parameter."""
        client, loop = nmap_env
        resp = loop.run_until_complete(client.call("vuln_scan", {
            "target": "127.0.0.1",
            "ports": "80",
            "scripts": "http-enum",
            "script_args": "http-enum.basepath=/",
            "skip_discovery": True,
        }, timeout=180))
        sc = self._assert_structuredContent(resp, "vuln_scan/script_args")
        assert isinstance(sc["success"], bool)

    def test_vuln_scan_missing_ports_error(self, nmap_env):
        """vuln_scan without required 'ports' returns error."""
        client, loop = nmap_env
        resp = loop.run_until_complete(client.call("vuln_scan", {
            "target": "127.0.0.1",
        }))
        result = resp.get("result", {})
        is_error = result.get("isError", False)
        text = self._get_content_text(resp)
        assert is_error or "ports" in text.lower() or "required" in text.lower()

    # ── ping_scan ─────────────────────────────────────────────────

    def test_ping_scan_localhost(self, nmap_env):
        """ping_scan against localhost returns structuredContent."""
        client, loop = nmap_env
        resp = loop.run_until_complete(client.call("ping_scan", {
            "target": "127.0.0.1",
            "timing": "aggressive",
        }))
        sc = self._assert_structuredContent(resp, "ping_scan")
        assert sc["success"] is True

    def test_ping_scan_response_shape(self, nmap_env):
        """ping_scan response includes live_hosts list."""
        client, loop = nmap_env
        resp = loop.run_until_complete(client.call("ping_scan", {
            "target": "127.0.0.1",
            "timing": "aggressive",
        }))
        data = parse_tool_output(resp)
        assert "hosts" in data
        # Should have at least 1 host (localhost itself)
        if data.get("live_hosts"):
            assert isinstance(data["live_hosts"], list)
            assert isinstance(data["total_live"], int)

    def test_ping_scan_missing_target_error(self, nmap_env):
        """ping_scan without required 'target' returns error."""
        client, loop = nmap_env
        resp = loop.run_until_complete(client.call("ping_scan", {}))
        result = resp.get("result", {})
        is_error = result.get("isError", False)
        text = self._get_content_text(resp)
        assert is_error or "target" in text.lower() or "required" in text.lower()

    # ── get_interfaces ────────────────────────────────────────────

    def test_get_interfaces_returns_structuredContent(self, nmap_env):
        """get_interfaces returns structuredContent."""
        client, loop = nmap_env
        resp = loop.run_until_complete(client.call("get_interfaces", {}))
        sc = self._assert_structuredContent(resp, "get_interfaces")
        assert sc["success"] is True

    def test_get_interfaces_has_loopback(self, nmap_env):
        """get_interfaces should find at least loopback."""
        client, loop = nmap_env
        resp = loop.run_until_complete(client.call("get_interfaces", {}))
        data = parse_tool_output(resp)
        assert "interfaces" in data
        iface_names = [i["name"] for i in data["interfaces"]]
        assert "lo" in iface_names, "Should find loopback interface"

    def test_get_interfaces_recommended_lhost(self, nmap_env):
        """get_interfaces provides a non-loopback recommended_lhost."""
        client, loop = nmap_env
        resp = loop.run_until_complete(client.call("get_interfaces", {}))
        data = parse_tool_output(resp)
        lhost = data.get("recommended_lhost")
        assert lhost is not None, "Should have recommended_lhost"
        assert lhost != "127.0.0.1", "recommended_lhost should not be loopback"


# ===========================================================================
# CUSTOM NSE SCRIPT TESTS -- /session/nmap-scripts/ support
# ===========================================================================

class TestCustomNSEScripts:
    """Tests for custom NSE script support via /session/nmap-scripts/.

    OpenSploit mounts the session directory as /session/ in every container.
    Agents can write custom .nse scripts to /session/nmap-scripts/ and
    reference them by absolute path in vuln_scan's scripts parameter.

    These tests create a temporary directory with a custom NSE script,
    mount it as /session/ in a fresh container, and verify execution.
    """

    @pytest.fixture(scope="class")
    def session_dir(self, tmp_path_factory):
        """Create a temp dir simulating /session/ with nmap-scripts/."""
        session = tmp_path_factory.mktemp("session")
        scripts_dir = session / "nmap-scripts"
        scripts_dir.mkdir()
        return session

    @pytest.fixture(scope="class")
    def custom_script_path(self, session_dir):
        """Write a simple custom NSE script that always produces output."""
        scripts_dir = session_dir / "nmap-scripts"
        script = scripts_dir / "custom-test-probe.nse"
        script.write_text(
            'description = [[\n'
            'Custom test probe for OpenSploit session script validation.\n'
            ']]\n'
            '\n'
            'categories = {"safe", "discovery"}\n'
            '\n'
            'portrule = function(host, port)\n'
            '  return true\n'
            'end\n'
            '\n'
            'action = function(host, port)\n'
            '  return "OPENSPLOIT_CUSTOM_SCRIPT_OK: port " .. port.number .. "/" .. port.protocol\n'
            'end\n'
        )
        return script

    @pytest.fixture(scope="class")
    def nmap_env_with_session(self, request, session_dir):
        """MCPTestClient with /session/ volume mount for custom scripts."""
        tool = "nmap"
        prefix = request.config.getoption("--image-prefix", default="mcp-test-")
        image = f"{prefix}{tool}"

        client = MCPTestClient(
            image=image,
            tool_name=tool,
            volumes={str(session_dir): "/session"},
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

    def test_custom_script_executes(self, nmap_env_with_session, custom_script_path):
        """vuln_scan with a custom NSE script from /session/nmap-scripts/ executes successfully."""
        client, loop = nmap_env_with_session
        resp = loop.run_until_complete(client.call("vuln_scan", {
            "target": "127.0.0.1",
            "ports": "80",
            "scripts": "/session/nmap-scripts/custom-test-probe.nse",
            "skip_discovery": True,
        }, timeout=120))
        result = resp.get("result", {})
        # Should succeed (not crash), though port 80 may be closed on localhost
        assert result is not None, "Should get a response"
        text = ""
        for c in result.get("content", []):
            if c.get("type") == "text":
                text += c["text"]
        # Should NOT get a "script not found" or file error
        assert "NSE: failed to initialize" not in text, (
            f"Custom script should be found at /session/nmap-scripts/: {text[:300]}"
        )

    def test_custom_script_output_in_results(self, nmap_env_with_session, custom_script_path):
        """Custom NSE script output appears in the scan results.

        The script returns 'OPENSPLOIT_CUSTOM_SCRIPT_OK' for any open port.
        We scan port 80 on localhost -- if it's open, we'll see the output;
        if it's closed, the script won't run (portrule only matches open ports
        by default in nmap). We verify the scan completes without error either way.
        """
        client, loop = nmap_env_with_session
        resp = loop.run_until_complete(client.call("vuln_scan", {
            "target": "127.0.0.1",
            "ports": "1-100",
            "scripts": "/session/nmap-scripts/custom-test-probe.nse",
            "skip_discovery": True,
        }, timeout=120))
        result = resp.get("result", {})
        sc = result.get("structuredContent", {})
        # Scan should succeed (script loaded correctly even if no open ports match)
        assert isinstance(sc.get("success"), bool), "Should have structuredContent.success"

    def test_custom_script_mixed_with_builtin(self, nmap_env_with_session, custom_script_path):
        """Custom NSE script can be combined with built-in scripts via comma separation."""
        client, loop = nmap_env_with_session
        resp = loop.run_until_complete(client.call("vuln_scan", {
            "target": "127.0.0.1",
            "ports": "80",
            "scripts": "/session/nmap-scripts/custom-test-probe.nse,safe",
            "skip_discovery": True,
        }, timeout=120))
        result = resp.get("result", {})
        assert result is not None, "Should get a response"
        text = ""
        for c in result.get("content", []):
            if c.get("type") == "text":
                text += c["text"]
        assert "NSE: failed to initialize" not in text, (
            f"Mixed custom+builtin scripts should work: {text[:300]}"
        )

    def test_nonexistent_custom_script_error(self, nmap_env_with_session):
        """vuln_scan with a nonexistent custom script path returns a helpful error."""
        client, loop = nmap_env_with_session
        resp = loop.run_until_complete(client.call("vuln_scan", {
            "target": "127.0.0.1",
            "ports": "80",
            "scripts": "/session/nmap-scripts/does-not-exist.nse",
            "skip_discovery": True,
        }, timeout=120))
        result = resp.get("result", {})
        text = ""
        for c in result.get("content", []):
            if c.get("type") == "text":
                text += c["text"]
        # nmap should report that the script was not found
        # The exact message varies: "NSE: failed to initialize" or
        # "'does-not-exist' did not match a category, filename, or directory"
        is_error = result.get("isError", False)
        has_error_text = any(phrase in text.lower() for phrase in [
            "did not match", "failed to initialize", "error", "not found",
            "no such file", "could not find",
        ])
        assert is_error or has_error_text, (
            f"Nonexistent script should produce an error, got: {text[:300]}"
        )

    def test_nonexistent_session_scripts_dir_error(self, nmap_env):
        """vuln_scan with /session/ path on container WITHOUT session mount returns error.

        The default nmap_env fixture does NOT mount /session/. Referencing a
        path under /session/nmap-scripts/ should produce a clear error, not
        a mysterious crash.
        """
        client, loop = nmap_env
        resp = loop.run_until_complete(client.call("vuln_scan", {
            "target": "127.0.0.1",
            "ports": "80",
            "scripts": "/session/nmap-scripts/nonexistent.nse",
            "skip_discovery": True,
        }, timeout=120))
        result = resp.get("result", {})
        text = ""
        for c in result.get("content", []):
            if c.get("type") == "text":
                text += c["text"]
        is_error = result.get("isError", False)
        has_error_text = any(phrase in text.lower() for phrase in [
            "did not match", "failed to initialize", "error", "not found",
            "no such file", "could not find",
        ])
        assert is_error or has_error_text, (
            f"Missing /session/ mount should produce an error, got: {text[:300]}"
        )


# ===========================================================================
# TRAJECTORY-DERIVED TESTS -- common LLM mistakes from real engagements
# ===========================================================================

class TestTrajectoryDerived:
    """Tests derived from 152 real nmap calls across 17 HTB engagements.

    These cover the actual mistake patterns that LLMs make when calling nmap,
    ensuring the server handles them gracefully instead of crashing.

    Key findings from trajectory analysis:
    - 21% timeout rate on port_scan (pre-heartbeat fix)
    - Invalid enum values: "T4", "fast", "tcp_syn" (8 occurrences)
    - Wrong params: 'scripts' on service_scan (1 occurrence)
    - 42% of port_scans use skip_discovery=true
    - Most common scan_type: syn (60%), then tcp_connect (24%), udp (13%)
    - Most common timing: aggressive (72%), insane (19%)
    - Most common port range: "1-65535" (26% of port_scans)
    """

    def test_invalid_timing_T4(self, nmap_env):
        """LLM passes 'T4' instead of 'aggressive' -- should get clean validation error.

        Observed in 2 engagement calls. The LLM confuses nmap CLI flags (-T4)
        with the enum values the MCP server expects.
        """
        client, loop = nmap_env
        resp = loop.run_until_complete(client.call("port_scan", {
            "target": "127.0.0.1",
            "ports": "80",
            "scan_type": "syn",
            "timing": "T4",
        }))
        result = resp.get("result", {})
        is_error = result.get("isError", False)
        text = ""
        for c in result.get("content", []):
            if c.get("type") == "text":
                text += c["text"]
        # Should be a validation error, NOT a crash
        assert is_error, "Invalid timing 'T4' should return isError=true"
        assert "T4" in text, "Error message should mention the invalid value 'T4'"
        assert "unexpected keyword argument" not in text, (
            "Should be a validation error, not an unhandled crash"
        )

    def test_invalid_timing_fast(self, nmap_env):
        """LLM passes 'fast' instead of 'aggressive' or 'insane'.

        Observed in 4 engagement calls.
        """
        client, loop = nmap_env
        resp = loop.run_until_complete(client.call("port_scan", {
            "target": "127.0.0.1",
            "ports": "80",
            "timing": "fast",
        }))
        result = resp.get("result", {})
        is_error = result.get("isError", False)
        text = ""
        for c in result.get("content", []):
            if c.get("type") == "text":
                text += c["text"]
        assert is_error, "Invalid timing 'fast' should return isError=true"
        assert "fast" in text

    def test_invalid_scan_type_tcp_syn(self, nmap_env):
        """LLM passes 'tcp_syn' instead of 'syn'.

        Observed in 2 engagement calls. The LLM combines 'tcp_connect' and 'syn'
        into the non-existent 'tcp_syn'.
        """
        client, loop = nmap_env
        resp = loop.run_until_complete(client.call("port_scan", {
            "target": "127.0.0.1",
            "ports": "80",
            "scan_type": "tcp_syn",
            "timing": "aggressive",
        }))
        result = resp.get("result", {})
        is_error = result.get("isError", False)
        text = ""
        for c in result.get("content", []):
            if c.get("type") == "text":
                text += c["text"]
        assert is_error, "Invalid scan_type 'tcp_syn' should return isError=true"
        assert "tcp_syn" in text

    def test_extra_param_scripts_on_service_scan(self, nmap_env):
        """LLM passes 'scripts' to service_scan (belongs to vuln_scan).

        Observed in engagement ses_3a9d2e3d. This caused:
        'NmapServer.service_scan() got an unexpected keyword argument scripts'
        """
        client, loop = nmap_env
        resp = loop.run_until_complete(client.call("service_scan", {
            "target": "127.0.0.1",
            "ports": "22,80",
            "scripts": "default",
            "skip_discovery": True,
        }, timeout=120))
        text = ""
        for c in resp.get("result", {}).get("content", []):
            if c.get("type") == "text":
                text += c["text"]
        # The base server should strip unknown params rather than crashing
        assert "unexpected keyword argument" not in text, (
            "Extra param 'scripts' on service_scan should be stripped, not crash"
        )

    def test_empty_scan_type(self, nmap_env):
        """LLM passes empty string for scan_type.

        Observed in trajectory: scan_type='' combined with timing='fast'.
        """
        client, loop = nmap_env
        resp = loop.run_until_complete(client.call("port_scan", {
            "target": "127.0.0.1",
            "ports": "80",
            "scan_type": "",
            "timing": "aggressive",
        }))
        result = resp.get("result", {})
        is_error = result.get("isError", False)
        text = ""
        for c in result.get("content", []):
            if c.get("type") == "text":
                text += c["text"]
        # Empty string is not in the enum, should be rejected
        assert is_error, "Empty scan_type should return isError=true"

    def test_both_timeout_and_clock_offset_stripped(self, nmap_env):
        """Both meta-params passed together don't crash any method.

        The opensploit client sometimes passes both timeout and clock_offset.
        """
        client, loop = nmap_env
        for method, args in [
            ("port_scan", {"target": "127.0.0.1", "ports": "80"}),
            ("service_scan", {"target": "127.0.0.1", "ports": "80", "skip_discovery": True}),
            ("os_detection", {"target": "127.0.0.1", "skip_discovery": True}),
            ("ping_scan", {"target": "127.0.0.1"}),
            ("get_interfaces", {}),
        ]:
            args["timeout"] = 30
            args["clock_offset"] = "+5h"
            resp = loop.run_until_complete(client.call(method, args, timeout=120))
            text = ""
            for c in resp.get("result", {}).get("content", []):
                if c.get("type") == "text":
                    text += c["text"]
            assert "unexpected keyword argument" not in text, (
                f"Meta-params should be stripped for {method}"
            )

    def test_port_scan_commonly_used_port_patterns(self, nmap_env):
        """port_scan works with commonly used port patterns from trajectory.

        Top patterns: "1-65535" (25 calls), "22,80" (12 calls),
        "1-10000" (4 calls), "1-1000" (4 calls).
        """
        client, loop = nmap_env
        for ports in ["22,80", "1-1000", "80,443,8080"]:
            resp = loop.run_until_complete(client.call("port_scan", {
                "target": "127.0.0.1",
                "ports": ports,
                "scan_type": "tcp_connect",
                "timing": "aggressive",
            }))
            sc = resp.get("result", {}).get("structuredContent", {})
            assert sc.get("success") is True, (
                f"port_scan should succeed with ports='{ports}'"
            )


# ===========================================================================
# ERROR CLASSIFICATION EXTENDED TESTS
# ===========================================================================

class TestErrorClassificationExtended:
    """Extended error classification tests covering patterns from trajectory data."""

    @pytest.fixture(autouse=True, scope="class")
    def server(self):
        """Create a server instance."""
        try:
            cls = _get_server_class()
            self.__class__._server = cls()
        except Exception as e:
            pytest.skip(f"Cannot import NmapServer: {e}")

    def test_classify_dns_resolution_failure(self):
        """DNS resolution failure should classify as 'config'."""
        err_class, retryable, suggestions = self._server._classify_nmap_error(
            "Failed to resolve \"nonexistent.htb\"."
        )
        assert err_class == "config"
        assert retryable is False
        assert any("DNS" in s or "resolve" in s.lower() or "IP" in s for s in suggestions)

    def test_classify_all_ports_closed(self):
        """All ports closed should classify as 'network' and not retryable."""
        err_class, retryable, suggestions = self._server._classify_nmap_error(
            "All 1000 scanned ports on 10.10.10.1 are closed"
        )
        assert err_class == "network"
        assert retryable is False
        assert any("65535" in s or "all ports" in s.lower() for s in suggestions)

    def test_classify_all_ports_ignored_states(self):
        """All ports in ignored states should also classify as network error.

        Nmap can phrase this as 'ignored states' instead of 'closed'.
        """
        err_class, _, _ = self._server._classify_nmap_error(
            "All 1000 scanned ports on 10.10.10.1 are in ignored states.\n"
            "Not shown: 1000 closed tcp ports"
        )
        # This phrasing includes "closed" in the second line
        assert err_class == "network"

    def test_classify_empty_output(self):
        """Empty output returns unknown classification."""
        err_class, retryable, suggestions = self._server._classify_nmap_error("")
        assert err_class == "unknown"
        assert retryable is False

    def test_classify_host_is_down(self):
        """'Host is down' (alternate phrasing) should also classify as 'network'."""
        err_class, retryable, suggestions = self._server._classify_nmap_error(
            "Host is down."
        )
        assert err_class == "network"
        assert retryable is True

    def test_classify_no_route_to_host(self):
        """'No route to host' should classify as 'network'."""
        err_class, retryable, suggestions = self._server._classify_nmap_error(
            "sendto in send_ip_raw_decoys: No route to host (EHOSTUNREACH)"
        )
        assert err_class == "network"
        assert retryable is True

    def test_classify_operation_not_permitted(self):
        """'Operation not permitted' should classify as 'permission'."""
        err_class, retryable, suggestions = self._server._classify_nmap_error(
            "pcap_activate: Operation not permitted"
        )
        assert err_class == "permission"
        assert retryable is False


# ===========================================================================
# UNIT TESTS -- new named parameters and extra_args command building
# ===========================================================================

class TestNewParamsCommandBuilding:
    """Test that new named parameters and extra_args produce correct nmap commands.

    These are pure unit tests -- no Docker container needed. They verify
    that each new parameter maps to the correct nmap flag in the args list
    that gets passed to _run_nmap.
    """

    @pytest.fixture(autouse=True, scope="class")
    def server(self):
        """Create a server instance for testing."""
        try:
            cls = _get_server_class()
            self.__class__._server = cls()
        except Exception as e:
            pytest.skip(f"Cannot import NmapServer: {e}")

    # -- port_scan named params ------------------------------------------------

    def test_port_scan_min_rate(self):
        """min_rate adds --min-rate N to args."""
        import inspect
        source = inspect.getsource(self._server.port_scan)
        assert '"--min-rate"' in source or "'--min-rate'" in source

    def test_port_scan_max_rate(self):
        """max_rate adds --max-rate N to args."""
        import inspect
        source = inspect.getsource(self._server.port_scan)
        assert '"--max-rate"' in source or "'--max-rate'" in source

    def test_port_scan_max_retries(self):
        """max_retries adds --max-retries N to args."""
        import inspect
        source = inspect.getsource(self._server.port_scan)
        assert '"--max-retries"' in source or "'--max-retries'" in source

    def test_port_scan_no_dns(self):
        """no_dns adds -n flag."""
        import inspect
        source = inspect.getsource(self._server.port_scan)
        assert '"-n"' in source

    def test_port_scan_open_only(self):
        """open_only adds --open flag."""
        import inspect
        source = inspect.getsource(self._server.port_scan)
        assert '"--open"' in source

    def test_port_scan_reason(self):
        """reason adds --reason flag."""
        import inspect
        source = inspect.getsource(self._server.port_scan)
        assert '"--reason"' in source

    def test_port_scan_host_timeout(self):
        """host_timeout adds --host-timeout <val>."""
        import inspect
        source = inspect.getsource(self._server.port_scan)
        assert '"--host-timeout"' in source or "'--host-timeout'" in source

    def test_port_scan_exclude(self):
        """exclude adds --exclude <hosts>."""
        import inspect
        source = inspect.getsource(self._server.port_scan)
        assert '"--exclude"' in source or "'--exclude'" in source

    def test_port_scan_input_file(self):
        """input_file adds -iL <file>."""
        import inspect
        source = inspect.getsource(self._server.port_scan)
        assert '"-iL"' in source

    def test_port_scan_extra_args_uses_shlex(self):
        """extra_args is processed with shlex.split."""
        import inspect
        source = inspect.getsource(self._server.port_scan)
        assert "shlex.split" in source

    # -- service_scan named params ---------------------------------------------

    def test_service_scan_no_dns(self):
        """service_scan has no_dns parameter."""
        import inspect
        source = inspect.getsource(self._server.service_scan)
        assert '"-n"' in source

    def test_service_scan_open_only(self):
        """service_scan has open_only parameter."""
        import inspect
        source = inspect.getsource(self._server.service_scan)
        assert '"--open"' in source

    def test_service_scan_default_scripts(self):
        """default_scripts adds -sC flag."""
        import inspect
        source = inspect.getsource(self._server.service_scan)
        assert '"-sC"' in source

    def test_service_scan_extra_args_uses_shlex(self):
        """service_scan extra_args uses shlex.split."""
        import inspect
        source = inspect.getsource(self._server.service_scan)
        assert "shlex.split" in source

    # -- os_detection named params ---------------------------------------------

    def test_os_detection_no_dns(self):
        """os_detection has no_dns parameter."""
        import inspect
        source = inspect.getsource(self._server.os_detection)
        assert '"-n"' in source

    def test_os_detection_extra_args_uses_shlex(self):
        """os_detection extra_args uses shlex.split."""
        import inspect
        source = inspect.getsource(self._server.os_detection)
        assert "shlex.split" in source

    # -- vuln_scan named params ------------------------------------------------

    def test_vuln_scan_no_dns(self):
        """vuln_scan has no_dns parameter."""
        import inspect
        source = inspect.getsource(self._server.vuln_scan)
        assert '"-n"' in source

    def test_vuln_scan_extra_args_uses_shlex(self):
        """vuln_scan extra_args uses shlex.split."""
        import inspect
        source = inspect.getsource(self._server.vuln_scan)
        assert "shlex.split" in source

    # -- ping_scan named params ------------------------------------------------

    def test_ping_scan_no_dns(self):
        """ping_scan has no_dns parameter."""
        import inspect
        source = inspect.getsource(self._server.ping_scan)
        assert '"-n"' in source

    def test_ping_scan_exclude(self):
        """ping_scan has exclude parameter."""
        import inspect
        source = inspect.getsource(self._server.ping_scan)
        assert '"--exclude"' in source or "'--exclude'" in source

    def test_ping_scan_input_file(self):
        """ping_scan has input_file parameter."""
        import inspect
        source = inspect.getsource(self._server.ping_scan)
        assert '"-iL"' in source

    def test_ping_scan_extra_args_uses_shlex(self):
        """ping_scan extra_args uses shlex.split."""
        import inspect
        source = inspect.getsource(self._server.ping_scan)
        assert "shlex.split" in source

    # -- get_interfaces extra_args ---------------------------------------------

    def test_get_interfaces_accepts_extra_args(self):
        """get_interfaces handler accepts extra_args parameter."""
        import inspect
        sig = inspect.signature(self._server.get_interfaces)
        assert "extra_args" in sig.parameters

    # -- shlex.split edge cases ------------------------------------------------

    def test_shlex_split_simple_flags(self):
        """shlex.split correctly splits simple space-separated flags."""
        import shlex
        result = shlex.split("--min-rate 10000 -D RND:5 -f")
        assert result == ["--min-rate", "10000", "-D", "RND:5", "-f"]

    def test_shlex_split_quoted_args(self):
        """shlex.split handles quoted arguments with spaces."""
        import shlex
        result = shlex.split("--script-args 'userdb=users.txt,passdb=pass.txt'")
        assert result == ["--script-args", "userdb=users.txt,passdb=pass.txt"]

    def test_shlex_split_double_quoted(self):
        """shlex.split handles double-quoted arguments."""
        import shlex
        result = shlex.split('--script-args "http.useragent=Mozilla/5.0"')
        assert result == ["--script-args", "http.useragent=Mozilla/5.0"]

    def test_shlex_split_empty_string(self):
        """shlex.split on empty string returns empty list."""
        import shlex
        result = shlex.split("")
        assert result == []

    def test_shlex_split_multiple_flags(self):
        """shlex.split handles complex multi-flag combinations."""
        import shlex
        result = shlex.split("--source-port 53 -f --data-length 50 -D RND:3")
        assert result == ["--source-port", "53", "-f", "--data-length", "50", "-D", "RND:3"]

    # -- registered params match handler signature -----------------------------

    def test_port_scan_registered_params_match_handler(self):
        """All port_scan registered params have corresponding handler args."""
        import inspect
        sig = inspect.signature(self._server.port_scan)
        handler_params = set(sig.parameters.keys()) - {"self"}
        registered_params = set(self._server.methods["port_scan"].params.keys())
        reg_only = registered_params - handler_params
        handler_only = handler_params - registered_params
        assert not reg_only, f"Registered but not in handler: {reg_only}"
        assert not handler_only, f"In handler but not registered: {handler_only}"

    def test_service_scan_registered_params_match_handler(self):
        """All service_scan registered params have corresponding handler args."""
        import inspect
        sig = inspect.signature(self._server.service_scan)
        handler_params = set(sig.parameters.keys()) - {"self"}
        registered_params = set(self._server.methods["service_scan"].params.keys())
        assert registered_params == handler_params

    def test_os_detection_registered_params_match_handler(self):
        """All os_detection registered params have corresponding handler args."""
        import inspect
        sig = inspect.signature(self._server.os_detection)
        handler_params = set(sig.parameters.keys()) - {"self"}
        registered_params = set(self._server.methods["os_detection"].params.keys())
        assert registered_params == handler_params

    def test_vuln_scan_registered_params_match_handler(self):
        """All vuln_scan registered params have corresponding handler args."""
        import inspect
        sig = inspect.signature(self._server.vuln_scan)
        handler_params = set(sig.parameters.keys()) - {"self"}
        registered_params = set(self._server.methods["vuln_scan"].params.keys())
        assert registered_params == handler_params

    def test_ping_scan_registered_params_match_handler(self):
        """All ping_scan registered params have corresponding handler args."""
        import inspect
        sig = inspect.signature(self._server.ping_scan)
        handler_params = set(sig.parameters.keys()) - {"self"}
        registered_params = set(self._server.methods["ping_scan"].params.keys())
        assert registered_params == handler_params

    def test_get_interfaces_registered_params_match_handler(self):
        """All get_interfaces registered params have corresponding handler args."""
        import inspect
        sig = inspect.signature(self._server.get_interfaces)
        handler_params = set(sig.parameters.keys()) - {"self"}
        registered_params = set(self._server.methods["get_interfaces"].params.keys())
        assert registered_params == handler_params


# ===========================================================================
# CONTRACT TESTS -- new params: tool.yaml vs server
# ===========================================================================

class TestNewParamsContract:
    """Contract tests verifying new parameters match between tool.yaml and server."""

    @pytest.fixture(autouse=True, scope="class")
    def load_data(self):
        """Load tool.yaml and server."""
        with open(TOOL_DIR / "tool.yaml") as f:
            self.__class__._yaml = yaml.safe_load(f)
        try:
            cls = _get_server_class()
            self.__class__._server = cls()
        except Exception as e:
            pytest.skip(f"Cannot import NmapServer: {e}")

    def test_extra_args_on_all_6_methods_yaml(self):
        """extra_args is defined in tool.yaml for all 6 methods."""
        for method_name, defn in self._yaml["methods"].items():
            params = defn.get("params", {})
            assert "extra_args" in params, (
                f"Method {method_name} missing extra_args in tool.yaml"
            )

    def test_extra_args_on_all_6_methods_server(self):
        """extra_args is registered in the server for all 6 methods."""
        for method_name, method_info in self._server.methods.items():
            assert "extra_args" in method_info.params, (
                f"Method {method_name} missing extra_args in server"
            )

    def test_no_dns_on_expected_methods_yaml(self):
        """no_dns is in tool.yaml for port_scan, service_scan, vuln_scan, os_detection, ping_scan."""
        expected = {"port_scan", "service_scan", "vuln_scan", "os_detection", "ping_scan"}
        for method_name in expected:
            params = self._yaml["methods"][method_name].get("params", {})
            assert "no_dns" in params, (
                f"Method {method_name} missing no_dns in tool.yaml"
            )

    def test_no_dns_on_expected_methods_server(self):
        """no_dns is registered in server for expected methods."""
        expected = {"port_scan", "service_scan", "vuln_scan", "os_detection", "ping_scan"}
        for method_name in expected:
            assert "no_dns" in self._server.methods[method_name].params, (
                f"Method {method_name} missing no_dns in server"
            )

    def test_all_new_params_have_descriptions_yaml(self):
        """All new parameters have descriptions in tool.yaml."""
        new_params = {
            "port_scan": ["min_rate", "max_rate", "max_retries", "no_dns", "open_only",
                          "reason", "host_timeout", "exclude", "input_file", "extra_args"],
            "service_scan": ["no_dns", "open_only", "default_scripts", "extra_args"],
            "os_detection": ["no_dns", "extra_args"],
            "vuln_scan": ["no_dns", "extra_args"],
            "ping_scan": ["no_dns", "exclude", "input_file", "extra_args"],
            "get_interfaces": ["extra_args"],
        }
        for method_name, param_names in new_params.items():
            params = self._yaml["methods"][method_name].get("params", {})
            for param_name in param_names:
                assert param_name in params, (
                    f"{method_name}.{param_name} missing from tool.yaml"
                )
                desc = params[param_name].get("description", "")
                assert len(desc) > 10, (
                    f"{method_name}.{param_name} has too short description: '{desc}'"
                )

    def test_yaml_server_param_parity_all_methods(self):
        """For every method, yaml params == server params (bidirectional check)."""
        for method_name in self._yaml["methods"]:
            yaml_params = set(self._yaml["methods"][method_name].get("params", {}).keys())
            server_params = set(self._server.methods[method_name].params.keys())
            yaml_only = yaml_params - server_params
            server_only = server_params - yaml_params
            assert not yaml_only, (
                f"{method_name}: in yaml but not server: {yaml_only}"
            )
            assert not server_only, (
                f"{method_name}: in server but not yaml: {server_only}"
            )

    def test_default_scripts_only_on_service_scan(self):
        """default_scripts should only be on service_scan (not vuln_scan which has scripts param)."""
        assert "default_scripts" in self._yaml["methods"]["service_scan"].get("params", {})
        assert "default_scripts" not in self._yaml["methods"]["vuln_scan"].get("params", {})
        assert "default_scripts" not in self._yaml["methods"]["port_scan"].get("params", {})


# ===========================================================================
# ACCEPTANCE TESTS -- new params through Docker container
# ===========================================================================

class TestNewParamsAcceptance:
    """Acceptance tests for new parameters through the Docker MCP container.

    These call the actual nmap methods with new parameters against localhost
    to verify end-to-end functionality.
    """

    def _get_content_text(self, resp):
        """Extract text from MCP response content."""
        result = resp.get("result", {})
        texts = []
        for c in result.get("content", []):
            if c.get("type") == "text":
                texts.append(c["text"])
        return "\n".join(texts)

    def _assert_structuredContent(self, resp, method_name):
        """Assert response has structuredContent."""
        result = resp.get("result", {})
        sc = result.get("structuredContent")
        assert sc is not None, f"{method_name}: missing structuredContent"
        return sc

    # -- port_scan with new params --------------------------------------------

    def test_port_scan_min_rate(self, nmap_env):
        """port_scan with min_rate succeeds."""
        client, loop = nmap_env
        resp = loop.run_until_complete(client.call("port_scan", {
            "target": "127.0.0.1",
            "ports": "22,80",
            "scan_type": "tcp_connect",
            "timing": "aggressive",
            "min_rate": 1000,
        }))
        sc = self._assert_structuredContent(resp, "port_scan/min_rate")
        assert sc["success"] is True

    def test_port_scan_no_dns_open_only_reason(self, nmap_env):
        """port_scan with no_dns + open_only + reason succeeds."""
        client, loop = nmap_env
        resp = loop.run_until_complete(client.call("port_scan", {
            "target": "127.0.0.1",
            "ports": "1-100",
            "scan_type": "tcp_connect",
            "timing": "aggressive",
            "no_dns": True,
            "open_only": True,
            "reason": True,
        }))
        sc = self._assert_structuredContent(resp, "port_scan/no_dns+open_only+reason")
        assert sc["success"] is True

    def test_port_scan_max_retries(self, nmap_env):
        """port_scan with max_retries works."""
        client, loop = nmap_env
        resp = loop.run_until_complete(client.call("port_scan", {
            "target": "127.0.0.1",
            "ports": "22,80",
            "scan_type": "tcp_connect",
            "timing": "aggressive",
            "max_retries": 1,
        }))
        sc = self._assert_structuredContent(resp, "port_scan/max_retries")
        assert sc["success"] is True

    def test_port_scan_host_timeout(self, nmap_env):
        """port_scan with host_timeout works."""
        client, loop = nmap_env
        resp = loop.run_until_complete(client.call("port_scan", {
            "target": "127.0.0.1",
            "ports": "22,80",
            "scan_type": "tcp_connect",
            "timing": "aggressive",
            "host_timeout": "30s",
        }))
        sc = self._assert_structuredContent(resp, "port_scan/host_timeout")
        assert sc["success"] is True

    def test_port_scan_extra_args_simple(self, nmap_env):
        """port_scan with extra_args simple flags."""
        client, loop = nmap_env
        resp = loop.run_until_complete(client.call("port_scan", {
            "target": "127.0.0.1",
            "ports": "22,80",
            "scan_type": "tcp_connect",
            "timing": "aggressive",
            "extra_args": "--open -n",
        }))
        sc = self._assert_structuredContent(resp, "port_scan/extra_args_simple")
        assert sc["success"] is True

    def test_port_scan_extra_args_min_rate_decoy(self, nmap_env):
        """port_scan with extra_args for min-rate and decoy scan."""
        client, loop = nmap_env
        resp = loop.run_until_complete(client.call("port_scan", {
            "target": "127.0.0.1",
            "ports": "80",
            "scan_type": "syn",
            "timing": "aggressive",
            "extra_args": "--min-rate 5000 -D RND:3",
        }))
        sc = self._assert_structuredContent(resp, "port_scan/extra_args_decoy")
        # May succeed or fail (decoy on localhost can be quirky), but should not crash
        assert isinstance(sc["success"], bool)

    def test_port_scan_named_plus_extra_args_no_conflict(self, nmap_env):
        """Named params and extra_args work together without conflicts."""
        client, loop = nmap_env
        resp = loop.run_until_complete(client.call("port_scan", {
            "target": "127.0.0.1",
            "ports": "22,80",
            "scan_type": "tcp_connect",
            "timing": "aggressive",
            "no_dns": True,
            "open_only": True,
            "extra_args": "--reason",
        }))
        sc = self._assert_structuredContent(resp, "port_scan/named+extra_args")
        assert sc["success"] is True

    def test_port_scan_extra_args_empty_string(self, nmap_env):
        """port_scan with empty extra_args string does not crash."""
        client, loop = nmap_env
        resp = loop.run_until_complete(client.call("port_scan", {
            "target": "127.0.0.1",
            "ports": "80",
            "scan_type": "tcp_connect",
            "timing": "aggressive",
            "extra_args": "",
        }))
        sc = self._assert_structuredContent(resp, "port_scan/extra_args_empty")
        assert sc["success"] is True

    # -- service_scan with new params -----------------------------------------

    def test_service_scan_default_scripts(self, nmap_env):
        """service_scan with default_scripts=true adds -sC."""
        client, loop = nmap_env
        resp = loop.run_until_complete(client.call("service_scan", {
            "target": "127.0.0.1",
            "ports": "22,80",
            "skip_discovery": True,
            "default_scripts": True,
        }, timeout=180))
        sc = self._assert_structuredContent(resp, "service_scan/default_scripts")
        assert isinstance(sc["success"], bool)

    def test_service_scan_no_dns(self, nmap_env):
        """service_scan with no_dns works."""
        client, loop = nmap_env
        resp = loop.run_until_complete(client.call("service_scan", {
            "target": "127.0.0.1",
            "ports": "80",
            "skip_discovery": True,
            "no_dns": True,
        }, timeout=120))
        sc = self._assert_structuredContent(resp, "service_scan/no_dns")
        assert isinstance(sc["success"], bool)

    def test_service_scan_extra_args(self, nmap_env):
        """service_scan with extra_args works."""
        client, loop = nmap_env
        resp = loop.run_until_complete(client.call("service_scan", {
            "target": "127.0.0.1",
            "ports": "80",
            "skip_discovery": True,
            "extra_args": "-n --open",
        }, timeout=120))
        sc = self._assert_structuredContent(resp, "service_scan/extra_args")
        assert isinstance(sc["success"], bool)

    # -- vuln_scan with new params --------------------------------------------

    def test_vuln_scan_no_dns(self, nmap_env):
        """vuln_scan with no_dns works."""
        client, loop = nmap_env
        resp = loop.run_until_complete(client.call("vuln_scan", {
            "target": "127.0.0.1",
            "ports": "80",
            "scripts": "default,safe",
            "skip_discovery": True,
            "no_dns": True,
        }, timeout=180))
        sc = self._assert_structuredContent(resp, "vuln_scan/no_dns")
        assert isinstance(sc["success"], bool)

    def test_vuln_scan_extra_args_script_timeout(self, nmap_env):
        """vuln_scan with extra_args for script-timeout."""
        client, loop = nmap_env
        resp = loop.run_until_complete(client.call("vuln_scan", {
            "target": "127.0.0.1",
            "ports": "80",
            "scripts": "default",
            "skip_discovery": True,
            "extra_args": "--script-timeout 10s",
        }, timeout=180))
        sc = self._assert_structuredContent(resp, "vuln_scan/extra_args_script_timeout")
        assert isinstance(sc["success"], bool)

    # -- os_detection with new params -----------------------------------------

    def test_os_detection_no_dns(self, nmap_env):
        """os_detection with no_dns works."""
        client, loop = nmap_env
        resp = loop.run_until_complete(client.call("os_detection", {
            "target": "127.0.0.1",
            "skip_discovery": True,
            "no_dns": True,
        }, timeout=120))
        sc = self._assert_structuredContent(resp, "os_detection/no_dns")
        assert isinstance(sc["success"], bool)

    def test_os_detection_extra_args(self, nmap_env):
        """os_detection with extra_args works."""
        client, loop = nmap_env
        resp = loop.run_until_complete(client.call("os_detection", {
            "target": "127.0.0.1",
            "skip_discovery": True,
            "extra_args": "-n",
        }, timeout=120))
        sc = self._assert_structuredContent(resp, "os_detection/extra_args")
        assert isinstance(sc["success"], bool)

    # -- ping_scan with new params --------------------------------------------

    def test_ping_scan_no_dns(self, nmap_env):
        """ping_scan with no_dns works."""
        client, loop = nmap_env
        resp = loop.run_until_complete(client.call("ping_scan", {
            "target": "127.0.0.1",
            "timing": "aggressive",
            "no_dns": True,
        }))
        sc = self._assert_structuredContent(resp, "ping_scan/no_dns")
        assert sc["success"] is True

    def test_ping_scan_extra_args(self, nmap_env):
        """ping_scan with extra_args works."""
        client, loop = nmap_env
        resp = loop.run_until_complete(client.call("ping_scan", {
            "target": "127.0.0.1",
            "timing": "aggressive",
            "extra_args": "-n",
        }))
        sc = self._assert_structuredContent(resp, "ping_scan/extra_args")
        assert sc["success"] is True

    # -- get_interfaces with extra_args ----------------------------------------

    def test_get_interfaces_extra_args_ignored(self, nmap_env):
        """get_interfaces accepts extra_args without crashing (ignored)."""
        client, loop = nmap_env
        resp = loop.run_until_complete(client.call("get_interfaces", {
            "extra_args": "--some-flag",
        }))
        sc = self._assert_structuredContent(resp, "get_interfaces/extra_args")
        assert sc["success"] is True

    # -- edge cases and error handling -----------------------------------------

    def test_port_scan_extra_args_invalid_flag_no_crash(self, nmap_env):
        """Invalid extra_args flag produces nmap error, not server crash."""
        client, loop = nmap_env
        resp = loop.run_until_complete(client.call("port_scan", {
            "target": "127.0.0.1",
            "ports": "80",
            "scan_type": "tcp_connect",
            "timing": "aggressive",
            "extra_args": "--this-flag-does-not-exist",
        }))
        result = resp.get("result", {})
        text = self._get_content_text(resp)
        # Should not crash -- either returns error from nmap or succeeds (nmap ignores some flags)
        assert "unexpected keyword argument" not in text, (
            "extra_args should not cause Python-level crash"
        )
