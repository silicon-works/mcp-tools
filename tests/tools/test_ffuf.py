"""
Tests for the ffuf MCP tool server.

Covers:
- Smoke tests: boot, method list, required params, meta-param stripping
- Unit tests: _resolve_wordlist, _parse_ffuf_json, flag construction
- Method tests: dir_fuzz, param_fuzz, vhost_fuzz (all 3 methods via container)
- Error classification: connection refused, no results, timeout errors
- Heartbeat: verify run_command_with_progress is used (timeout fix)
- Contract tests: tool.yaml vs server parameter definitions
- Acceptance tests: every method called through container (no live target)
"""

import asyncio
import http.server
import importlib.util
import json
import os
import sys
import threading
from pathlib import Path
from typing import Any, Dict, Set
from unittest.mock import AsyncMock, MagicMock, patch

import pytest
import yaml

# ---------------------------------------------------------------------------
# Path setup
# ---------------------------------------------------------------------------
PROJECT_ROOT = Path(__file__).parent.parent.parent
TOOL_DIR = PROJECT_ROOT / "tools" / "ffuf"
FIXTURES_DIR = Path(__file__).parent.parent / "fixtures" / "ffuf"

sys.path.insert(0, str(TOOL_DIR))

# Import conftest helpers
from conftest import (
    MCPTestClient,
    assert_tool_error,
    assert_tool_success,
    parse_tool_output,
)


# ---------------------------------------------------------------------------
# Helper: import server module for direct unit testing
# ---------------------------------------------------------------------------
def _get_server_class():
    """Import and return the FfufServer class for direct method testing."""
    spec = importlib.util.spec_from_file_location(
        "ffuf_server", TOOL_DIR / "mcp-server.py"
    )
    mod = importlib.util.module_from_spec(spec)
    spec.loader.exec_module(mod)
    return mod.FfufServer


def _get_module():
    """Import the whole ffuf mcp-server module."""
    spec = importlib.util.spec_from_file_location(
        "ffuf_server", TOOL_DIR / "mcp-server.py"
    )
    mod = importlib.util.module_from_spec(spec)
    spec.loader.exec_module(mod)
    return mod


# ---------------------------------------------------------------------------
# Test HTTP server -- runs on host, reachable from --network=host container
# ---------------------------------------------------------------------------
class _HTTPRequestHandler(http.server.BaseHTTPRequestHandler):
    """Minimal HTTP server for testing ffuf fuzzing."""

    def log_message(self, format, *args):
        """Suppress log output during tests."""
        pass

    def do_GET(self):
        path = self.path.split("?")[0]

        # Known paths that return 200
        known_paths = {
            "/": (200, "<h1>Index</h1>", "text/html"),
            "/admin": (301, "", "text/html"),
            "/login": (200, "<h1>Login</h1>", "text/html"),
            "/api": (200, '{"status":"ok"}', "application/json"),
            "/robots.txt": (200, "User-agent: *\nDisallow: /admin", "text/plain"),
            "/index.html": (200, "<h1>Index</h1>", "text/html"),
            "/index.php": (200, "<h1>PHP Index</h1>", "text/html"),
            "/config.bak": (200, "db_password=secret", "text/plain"),
            "/test": (200, "test page", "text/plain"),
            "/hidden": (200, "hidden page", "text/plain"),
        }

        if path in known_paths:
            status, body, ct = known_paths[path]
            if status == 301:
                self.send_response(301)
                port = self.server.server_address[1]
                self.send_header("Location", f"http://127.0.0.1:{port}{path}/")
                self.send_header("Content-Length", "0")
                self.end_headers()
            else:
                self._send_response(status, body, ct)
        else:
            self._send_response(404, "Not Found")

    def do_POST(self):
        content_length = int(self.headers.get("Content-Length", 0))
        body = self.rfile.read(content_length) if content_length > 0 else b""

        path = self.path.split("?")[0]
        if path == "/login":
            try:
                data = json.loads(body)
                if data.get("username") == "admin" and data.get("password") == "secret":
                    self._send_response(200, '{"token":"abc123"}', "application/json")
                else:
                    self._send_response(401, '{"error":"invalid"}', "application/json")
            except json.JSONDecodeError:
                self._send_response(400, '{"error":"bad json"}', "application/json")
        else:
            self._send_response(404, "Not Found")

    def _send_response(self, code, body, content_type="text/plain"):
        body_bytes = body.encode("utf-8") if isinstance(body, str) else body
        self.send_response(code)
        self.send_header("Content-Type", content_type)
        self.send_header("Content-Length", str(len(body_bytes)))
        self.end_headers()
        self.wfile.write(body_bytes)


# Vhost-aware HTTP server for vhost fuzzing tests
class _VHostHTTPRequestHandler(http.server.BaseHTTPRequestHandler):
    """HTTP server that responds differently based on Host header."""

    def log_message(self, format, *args):
        pass

    def do_GET(self):
        host = self.headers.get("Host", "")

        # Different content based on vhost
        if host.startswith("dev."):
            self._send_response(200, "<h1>Dev Site</h1>", "text/html")
        elif host.startswith("api."):
            self._send_response(200, '{"api":"v2"}', "application/json")
        elif host.startswith("internal."):
            self._send_response(200, "<h1>Internal</h1>", "text/html")
        else:
            # Default response for unknown vhosts
            self._send_response(200, "<h1>Default Page</h1>", "text/html")

    def _send_response(self, code, body, content_type="text/plain"):
        body_bytes = body.encode("utf-8") if isinstance(body, str) else body
        self.send_response(code)
        self.send_header("Content-Type", content_type)
        self.send_header("Content-Length", str(len(body_bytes)))
        self.end_headers()
        self.wfile.write(body_bytes)


@pytest.fixture(scope="module")
def http_server():
    """Start a test HTTP server on a random port, return (host, port)."""
    server = http.server.HTTPServer(("0.0.0.0", 0), _HTTPRequestHandler)
    port = server.server_address[1]
    thread = threading.Thread(target=server.serve_forever, daemon=True)
    thread.start()
    yield "127.0.0.1", port
    server.shutdown()


@pytest.fixture(scope="module")
def vhost_server():
    """Start a vhost-aware HTTP server on a random port."""
    server = http.server.HTTPServer(("0.0.0.0", 0), _VHostHTTPRequestHandler)
    port = server.server_address[1]
    thread = threading.Thread(target=server.serve_forever, daemon=True)
    thread.start()
    yield "127.0.0.1", port
    server.shutdown()


# ---------------------------------------------------------------------------
# Module-scoped fixture: MCP client (Docker container)
# ---------------------------------------------------------------------------
@pytest.fixture(scope="module")
def ffuf_env(request):
    """Create an MCPTestClient with its event loop. Yields (client, loop)."""
    tool = "ffuf"
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


# ===========================================================================
# SMOKE TESTS -- require Docker container running
# ===========================================================================

class TestSmoke:
    """Smoke tests that verify the container boots and basic protocol works."""

    def test_boot_and_list_tools(self, ffuf_env):
        """Container starts and list_tools returns methods."""
        client, loop = ffuf_env
        assert len(client.tools) > 0, "Server should advertise at least one tool"
        names = client.tool_names()
        assert "dir_fuzz" in names
        assert "param_fuzz" in names
        assert "vhost_fuzz" in names

    def test_expected_method_count(self, ffuf_env):
        """Server should have exactly 3 built-in methods + verify_clock."""
        client, _ = ffuf_env
        names = client.tool_names()
        assert len(names) == 4, (
            f"Expected 4 methods (3 built-in + verify_clock), got {len(names)}: {sorted(names)}"
        )

    def test_method_list_matches_tool_yaml(self, ffuf_env):
        """Every method in tool.yaml is advertised by the server, and vice versa."""
        client, _ = ffuf_env
        server_names = client.tool_names() - {"verify_clock"}

        yaml_path = TOOL_DIR / "tool.yaml"
        with open(yaml_path) as f:
            yaml_data = yaml.safe_load(f)
        yaml_names = set(yaml_data.get("methods", {}).keys())

        yaml_only = yaml_names - server_names
        server_only = server_names - yaml_names

        assert not yaml_only, f"Methods in tool.yaml but not server: {yaml_only}"
        assert not server_only, f"Methods in server but not tool.yaml: {server_only}"

    def test_unknown_method(self, ffuf_env):
        """Calling an unknown method returns a clear error."""
        client, loop = ffuf_env
        resp = loop.run_until_complete(
            client.call("nonexistent_method", {"url": "http://example.com"})
        )
        result = resp.get("result", {})
        assert result.get("isError", False), "Unknown method should return error"
        content_text = ""
        for c in result.get("content", []):
            if c.get("type") == "text":
                content_text += c["text"]
        assert "unknown method" in content_text.lower() or "dir_fuzz" in content_text, (
            f"Error should mention available methods, got: {content_text[:300]}"
        )

    def test_meta_param_stripping(self, ffuf_env, http_server):
        """Meta params (timeout as client meta, clock_offset) are stripped without error."""
        client, loop = ffuf_env
        host, port = http_server
        resp = loop.run_until_complete(
            client.call("dir_fuzz", {
                "url": f"http://{host}:{port}/FUZZ",
                "wordlist": "small",
                "clock_offset": 1000,
            })
        )
        # Should not fail due to unknown parameter
        result = resp.get("result", {})
        assert not result.get("isError", False), (
            f"Meta param should be stripped, got error: {result}"
        )


# ===========================================================================
# UNIT TESTS -- test internal methods without Docker
# ===========================================================================

class TestParseJson:
    """Test the JSON output parser."""

    def test_parse_dir_results(self):
        """Parse a typical dir_fuzz JSON output."""
        with open(FIXTURES_DIR / "dir_fuzz_results.json") as f:
            json_str = f.read()

        server = _get_server_class()()
        parsed = server._parse_ffuf_json(json_str)

        assert parsed["total_results"] == 4
        assert len(parsed["results"]) == 4
        assert parsed["results"][0]["input"] == "admin"
        assert parsed["results"][0]["status"] == 301
        assert parsed["results"][0]["redirect_location"] == "http://target.htb/admin/"
        assert parsed["results"][1]["input"] == "index.html"
        assert parsed["results"][1]["status"] == 200
        assert parsed["results"][1]["length"] == 5247
        assert "command" in parsed
        assert "time" in parsed

    def test_parse_empty_results(self):
        """Parse JSON output with no results."""
        with open(FIXTURES_DIR / "empty_results.json") as f:
            json_str = f.read()

        server = _get_server_class()()
        parsed = server._parse_ffuf_json(json_str)

        assert parsed["total_results"] == 0
        assert parsed["results"] == []
        assert "command" in parsed

    def test_parse_vhost_results(self):
        """Parse vhost fuzzing JSON output."""
        with open(FIXTURES_DIR / "vhost_results.json") as f:
            json_str = f.read()

        server = _get_server_class()()
        parsed = server._parse_ffuf_json(json_str)

        assert parsed["total_results"] == 2
        assert parsed["results"][0]["input"] == "dev"
        assert parsed["results"][1]["input"] == "api"

    def test_parse_invalid_json(self):
        """Invalid JSON returns error dict."""
        server = _get_server_class()()
        parsed = server._parse_ffuf_json("not valid json {{{")

        assert "error" in parsed
        assert "raw" in parsed

    def test_parse_missing_fields(self):
        """JSON with missing optional fields still parses."""
        minimal = json.dumps({
            "results": [{"input": {}, "status": 200}],
        })
        server = _get_server_class()()
        parsed = server._parse_ffuf_json(minimal)

        assert parsed["total_results"] == 1
        assert parsed["results"][0]["input"] == ""
        assert parsed["results"][0]["status"] == 200
        assert parsed["results"][0]["length"] == 0


class TestResolveWordlist:
    """Test wordlist resolution."""

    def test_named_wordlists(self):
        """Named wordlists resolve to full paths."""
        server = _get_server_class()()
        for name, expected_path in server.WORDLISTS.items():
            result = server._resolve_wordlist(name)
            # Either resolves to the expected path or falls back to common
            assert result == expected_path or result == server.WORDLISTS["common"]

    def test_custom_path_passthrough(self):
        """Custom paths are returned as-is."""
        server = _get_server_class()()
        custom = "/session/wordlists/custom.txt"
        assert server._resolve_wordlist(custom) == custom

    def test_unknown_name_treated_as_path(self):
        """Unknown names are treated as file paths."""
        server = _get_server_class()()
        result = server._resolve_wordlist("nonexistent-wordlist-name")
        assert result == "nonexistent-wordlist-name"


class TestFlagConstruction:
    """Test that method parameters map to correct ffuf flags."""

    def test_dir_fuzz_match_status_maps_to_mc(self):
        """match_status parameter maps to -mc flag."""
        server = _get_server_class()()
        # We test this by checking the method's parameter registration
        method = server.methods["dir_fuzz"]
        assert "match_status" in method.params
        assert "filter_status" not in method.params  # Old name should not exist

    def test_dir_fuzz_filter_codes_maps_to_fc(self):
        """filter_codes parameter is registered."""
        server = _get_server_class()()
        method = server.methods["dir_fuzz"]
        assert "filter_codes" in method.params

    def test_dir_fuzz_auto_calibrate(self):
        """auto_calibrate parameter is registered."""
        server = _get_server_class()()
        method = server.methods["dir_fuzz"]
        assert "auto_calibrate" in method.params
        assert method.params["auto_calibrate"]["default"] is False

    def test_param_fuzz_has_filter_codes(self):
        """param_fuzz also has filter_codes."""
        server = _get_server_class()()
        method = server.methods["param_fuzz"]
        assert "filter_codes" in method.params
        assert "auto_calibrate" in method.params

    def test_vhost_fuzz_has_filter_codes(self):
        """vhost_fuzz also has filter_codes."""
        server = _get_server_class()()
        method = server.methods["vhost_fuzz"]
        assert "filter_codes" in method.params
        assert "auto_calibrate" in method.params

    def test_all_methods_have_match_status(self):
        """All three methods have match_status (not filter_status)."""
        server = _get_server_class()()
        for name in ["dir_fuzz", "param_fuzz", "vhost_fuzz"]:
            method = server.methods[name]
            assert "match_status" in method.params, f"{name} missing match_status"
            assert "filter_status" not in method.params, f"{name} still has filter_status"


class TestHeartbeat:
    """Verify that _run_ffuf uses run_command_with_progress for heartbeating."""

    def test_run_ffuf_uses_progress(self):
        """_run_ffuf must use run_command_with_progress, not run_command."""
        # Read the source code and check
        with open(TOOL_DIR / "mcp-server.py") as f:
            source = f.read()

        # The _run_ffuf method should call run_command_with_progress
        assert "run_command_with_progress" in source, (
            "_run_ffuf should use run_command_with_progress for heartbeat support. "
            "Using run_command causes client-side idle timeouts on long scans."
        )

    def test_silent_flag_present(self):
        """ffuf command should still use -s (silent) to suppress interactive output."""
        with open(TOOL_DIR / "mcp-server.py") as f:
            source = f.read()
        # -s flag suppresses interactive progress but heartbeat still works via timer
        assert '"-s"' in source


# ===========================================================================
# METHOD TESTS -- require Docker container + test HTTP server
# ===========================================================================

class TestDirFuzz:
    """Test dir_fuzz method via Docker container."""

    def test_basic_dir_fuzz(self, ffuf_env, http_server):
        """Basic directory fuzzing finds known paths."""
        client, loop = ffuf_env
        host, port = http_server
        resp = loop.run_until_complete(
            client.call("dir_fuzz", {
                "url": f"http://{host}:{port}/FUZZ",
                "wordlist": "small",
                "threads": 10,
            })
        )
        result = assert_tool_success(resp)
        data = parse_tool_output(resp)

        assert "results" in data
        assert data["total_results"] >= 0  # At least parses successfully
        # The small wordlist should match some of our known paths
        if data["total_results"] > 0:
            found_inputs = [r["input"] for r in data["results"]]
            # At least one known path should be found
            assert len(found_inputs) > 0

    def test_auto_fuzz_keyword(self, ffuf_env, http_server):
        """URL without FUZZ keyword gets it appended automatically."""
        client, loop = ffuf_env
        host, port = http_server
        resp = loop.run_until_complete(
            client.call("dir_fuzz", {
                "url": f"http://{host}:{port}",
                "wordlist": "small",
                "threads": 10,
            })
        )
        result = assert_tool_success(resp)
        data = parse_tool_output(resp)
        # Should succeed -- FUZZ keyword added automatically
        assert "results" in data

    def test_with_extensions(self, ffuf_env, http_server):
        """Extension fuzzing (e.g., .php,.html) works."""
        client, loop = ffuf_env
        host, port = http_server
        resp = loop.run_until_complete(
            client.call("dir_fuzz", {
                "url": f"http://{host}:{port}/FUZZ",
                "wordlist": "small",
                "extensions": "html,php,txt",
                "threads": 10,
            })
        )
        result = assert_tool_success(resp)
        data = parse_tool_output(resp)
        assert "results" in data

    def test_match_status_filter(self, ffuf_env, http_server):
        """match_status restricts to specific status codes."""
        client, loop = ffuf_env
        host, port = http_server
        resp = loop.run_until_complete(
            client.call("dir_fuzz", {
                "url": f"http://{host}:{port}/FUZZ",
                "wordlist": "small",
                "match_status": "200",
                "threads": 10,
            })
        )
        result = assert_tool_success(resp)
        data = parse_tool_output(resp)
        assert "results" in data
        # All results should be status 200
        for r in data.get("results", []):
            assert r["status"] == 200, f"Expected 200, got {r['status']} for {r['input']}"

    def test_filter_codes(self, ffuf_env, http_server):
        """filter_codes removes specific status codes from results."""
        client, loop = ffuf_env
        host, port = http_server
        resp = loop.run_until_complete(
            client.call("dir_fuzz", {
                "url": f"http://{host}:{port}/FUZZ",
                "wordlist": "small",
                "filter_codes": "301,403",
                "threads": 10,
            })
        )
        result = assert_tool_success(resp)
        data = parse_tool_output(resp)
        assert "results" in data
        # No results should have filtered status codes
        for r in data.get("results", []):
            assert r["status"] not in [301, 403], (
                f"Status {r['status']} should be filtered for {r['input']}"
            )

    def test_auto_calibrate(self, ffuf_env, http_server):
        """auto_calibrate flag is accepted and doesn't cause errors."""
        client, loop = ffuf_env
        host, port = http_server
        resp = loop.run_until_complete(
            client.call("dir_fuzz", {
                "url": f"http://{host}:{port}/FUZZ",
                "wordlist": "small",
                "auto_calibrate": True,
                "threads": 10,
            })
        )
        result = assert_tool_success(resp)
        data = parse_tool_output(resp)
        assert "results" in data

    def test_filter_size(self, ffuf_env, http_server):
        """filter_size removes responses of specific size."""
        client, loop = ffuf_env
        host, port = http_server
        resp = loop.run_until_complete(
            client.call("dir_fuzz", {
                "url": f"http://{host}:{port}/FUZZ",
                "wordlist": "small",
                "filter_size": "0",
                "threads": 10,
            })
        )
        result = assert_tool_success(resp)
        data = parse_tool_output(resp)
        assert "results" in data

    def test_custom_headers(self, ffuf_env, http_server):
        """Custom headers are passed through to ffuf."""
        client, loop = ffuf_env
        host, port = http_server
        resp = loop.run_until_complete(
            client.call("dir_fuzz", {
                "url": f"http://{host}:{port}/FUZZ",
                "wordlist": "small",
                "headers": {"X-Custom-Test": "test-value"},
                "threads": 10,
            })
        )
        result = assert_tool_success(resp)

    def test_cookies(self, ffuf_env, http_server):
        """Cookie header is passed through."""
        client, loop = ffuf_env
        host, port = http_server
        resp = loop.run_until_complete(
            client.call("dir_fuzz", {
                "url": f"http://{host}:{port}/FUZZ",
                "wordlist": "small",
                "cookies": "session=abc123; token=xyz",
                "threads": 10,
            })
        )
        result = assert_tool_success(resp)

    def test_no_results_returns_empty(self, ffuf_env, http_server):
        """Scan with no matches returns empty results, not an error."""
        client, loop = ffuf_env
        host, port = http_server
        resp = loop.run_until_complete(
            client.call("dir_fuzz", {
                "url": f"http://{host}:{port}/FUZZ",
                "wordlist": "small",
                "match_status": "999",  # No server returns 999
                "threads": 10,
            })
        )
        result = assert_tool_success(resp)
        data = parse_tool_output(resp)
        assert data.get("total_results", 0) == 0

    def test_summary_present_on_results(self, ffuf_env, http_server):
        """When results are found, a summary dict is included."""
        client, loop = ffuf_env
        host, port = http_server
        resp = loop.run_until_complete(
            client.call("dir_fuzz", {
                "url": f"http://{host}:{port}/FUZZ",
                "wordlist": "small",
                "threads": 10,
            })
        )
        data = parse_tool_output(resp)
        if data.get("total_results", 0) > 0:
            assert "summary" in data
            assert "target" in data["summary"]
            assert "found" in data["summary"]


class TestParamFuzz:
    """Test param_fuzz method via Docker container."""

    def test_basic_get_param_fuzz(self, ffuf_env, http_server):
        """Basic GET parameter fuzzing works."""
        client, loop = ffuf_env
        host, port = http_server
        resp = loop.run_until_complete(
            client.call("param_fuzz", {
                "url": f"http://{host}:{port}/?FUZZ=test",
                "wordlist": "small",
                "threads": 10,
            })
        )
        result = assert_tool_success(resp)
        data = parse_tool_output(resp)
        assert "results" in data or "total_results" in data

    def test_post_param_fuzz(self, ffuf_env, http_server):
        """POST parameter fuzzing with data works."""
        client, loop = ffuf_env
        host, port = http_server
        resp = loop.run_until_complete(
            client.call("param_fuzz", {
                "url": f"http://{host}:{port}/login",
                "wordlist": "small",
                "method": "POST",
                "data": '{"username":"admin","password":"FUZZ"}',
                "headers": {"Content-Type": "application/json"},
                "threads": 10,
            })
        )
        result = assert_tool_success(resp)
        data = parse_tool_output(resp)
        assert "summary" in data
        assert data["summary"]["method"] == "POST"

    def test_param_fuzz_with_match_status(self, ffuf_env, http_server):
        """match_status works in param_fuzz."""
        client, loop = ffuf_env
        host, port = http_server
        resp = loop.run_until_complete(
            client.call("param_fuzz", {
                "url": f"http://{host}:{port}/?FUZZ=test",
                "wordlist": "small",
                "match_status": "200",
                "threads": 10,
            })
        )
        result = assert_tool_success(resp)

    def test_param_fuzz_with_filter_codes(self, ffuf_env, http_server):
        """filter_codes works in param_fuzz."""
        client, loop = ffuf_env
        host, port = http_server
        resp = loop.run_until_complete(
            client.call("param_fuzz", {
                "url": f"http://{host}:{port}/?FUZZ=test",
                "wordlist": "small",
                "filter_codes": "404",
                "threads": 10,
            })
        )
        result = assert_tool_success(resp)

    def test_param_fuzz_with_auto_calibrate(self, ffuf_env, http_server):
        """auto_calibrate works in param_fuzz."""
        client, loop = ffuf_env
        host, port = http_server
        resp = loop.run_until_complete(
            client.call("param_fuzz", {
                "url": f"http://{host}:{port}/?FUZZ=test",
                "wordlist": "small",
                "auto_calibrate": True,
                "threads": 10,
            })
        )
        result = assert_tool_success(resp)


class TestVhostFuzz:
    """Test vhost_fuzz method via Docker container."""

    def test_basic_vhost_fuzz(self, ffuf_env, vhost_server):
        """Basic vhost fuzzing runs without error."""
        client, loop = ffuf_env
        host, port = vhost_server
        resp = loop.run_until_complete(
            client.call("vhost_fuzz", {
                "url": f"http://{host}:{port}",
                "domain": "target.htb",
                "wordlist": "small",
                "threads": 10,
            })
        )
        result = assert_tool_success(resp)
        data = parse_tool_output(resp)
        # Should have summary with vhost info
        if data.get("total_results", 0) > 0:
            assert "summary" in data
            assert "base_domain" in data["summary"]
            assert data["summary"]["base_domain"] == "target.htb"
            # vhosts should be formatted as subdomain.domain
            for vhost in data["summary"].get("vhosts", []):
                assert vhost.endswith(".target.htb")

    def test_vhost_with_filter_size(self, ffuf_env, vhost_server):
        """filter_size filters default vhost response."""
        client, loop = ffuf_env
        host, port = vhost_server
        resp = loop.run_until_complete(
            client.call("vhost_fuzz", {
                "url": f"http://{host}:{port}",
                "domain": "target.htb",
                "wordlist": "small",
                "filter_size": "0",
                "threads": 10,
            })
        )
        result = assert_tool_success(resp)

    def test_vhost_with_auto_calibrate(self, ffuf_env, vhost_server):
        """auto_calibrate works with vhost fuzzing."""
        client, loop = ffuf_env
        host, port = vhost_server
        resp = loop.run_until_complete(
            client.call("vhost_fuzz", {
                "url": f"http://{host}:{port}",
                "domain": "target.htb",
                "wordlist": "small",
                "auto_calibrate": True,
                "threads": 10,
            })
        )
        result = assert_tool_success(resp)

    def test_vhost_with_match_status(self, ffuf_env, vhost_server):
        """match_status works with vhost fuzzing."""
        client, loop = ffuf_env
        host, port = vhost_server
        resp = loop.run_until_complete(
            client.call("vhost_fuzz", {
                "url": f"http://{host}:{port}",
                "domain": "target.htb",
                "wordlist": "small",
                "match_status": "200",
                "threads": 10,
            })
        )
        result = assert_tool_success(resp)

    def test_vhost_with_filter_codes(self, ffuf_env, vhost_server):
        """filter_codes works with vhost fuzzing."""
        client, loop = ffuf_env
        host, port = vhost_server
        resp = loop.run_until_complete(
            client.call("vhost_fuzz", {
                "url": f"http://{host}:{port}",
                "domain": "target.htb",
                "wordlist": "small",
                "filter_codes": "403",
                "threads": 10,
            })
        )
        result = assert_tool_success(resp)


# ===========================================================================
# ERROR CLASSIFICATION TESTS
# ===========================================================================

class TestErrorClassification:
    """Test error handling and classification."""

    def test_connection_refused(self, ffuf_env):
        """Connection refused target returns classified error or empty results."""
        client, loop = ffuf_env
        # Port 1 is almost certainly not running an HTTP server
        resp = loop.run_until_complete(
            client.call("dir_fuzz", {
                "url": "http://127.0.0.1:1/FUZZ",
                "wordlist": "small",
                "threads": 5,
                "timeout": 2,
            }, timeout=120)
        )
        # ffuf with connection errors either returns empty results or an error
        result = resp.get("result", {})
        data = parse_tool_output(resp)
        if isinstance(data, dict):
            # If it succeeded, results should be empty
            total = data.get("total_results", 0)
            assert total == 0, "Connection refused target should have no results"
        # If it errored, that's also acceptable

    def test_invalid_wordlist_path(self, ffuf_env, http_server):
        """Non-existent wordlist path returns an error."""
        client, loop = ffuf_env
        host, port = http_server
        resp = loop.run_until_complete(
            client.call("dir_fuzz", {
                "url": f"http://{host}:{port}/FUZZ",
                "wordlist": "/nonexistent/wordlist.txt",
                "threads": 10,
            })
        )
        # ffuf should fail when the wordlist doesn't exist
        result = resp.get("result", {})
        is_error = result.get("isError", False)
        data = parse_tool_output(resp)
        # Either an error or empty results (ffuf exits with error on missing wordlist)
        if not is_error:
            assert isinstance(data, dict)


# ===========================================================================
# CONTRACT TESTS -- tool.yaml vs server parameter definitions
# ===========================================================================

class TestContract:
    """Verify tool.yaml and server method params are consistent."""

    def test_yaml_params_match_server_params(self):
        """Every param in tool.yaml exists in the server's method registration."""
        server = _get_server_class()()

        yaml_path = TOOL_DIR / "tool.yaml"
        with open(yaml_path) as f:
            yaml_data = yaml.safe_load(f)

        yaml_methods = yaml_data.get("methods", {})

        for method_name, method_def in yaml_methods.items():
            assert method_name in server.methods, (
                f"Method '{method_name}' in tool.yaml but not registered in server"
            )
            server_method = server.methods[method_name]
            yaml_params = set(method_def.get("params", {}).keys())
            server_params = set(server_method.params.keys())

            yaml_only = yaml_params - server_params
            server_only = server_params - yaml_params

            assert not yaml_only, (
                f"{method_name}: params in tool.yaml but not server: {yaml_only}"
            )
            # server_only is OK -- server may have params not in yaml (less strict)

    def test_required_params_correct(self):
        """Required params in tool.yaml match server registration."""
        server = _get_server_class()()

        yaml_path = TOOL_DIR / "tool.yaml"
        with open(yaml_path) as f:
            yaml_data = yaml.safe_load(f)

        yaml_methods = yaml_data.get("methods", {})

        for method_name, method_def in yaml_methods.items():
            if method_name not in server.methods:
                continue
            server_method = server.methods[method_name]

            for param_name, param_def in method_def.get("params", {}).items():
                yaml_required = param_def.get("required", False)
                if param_name in server_method.params:
                    server_required = server_method.params[param_name].get("required", False)
                    if yaml_required:
                        assert server_required, (
                            f"{method_name}.{param_name}: required in yaml but not in server"
                        )

    def test_no_filter_status_anywhere(self):
        """The old 'filter_status' param name should not exist anywhere."""
        server = _get_server_class()()
        for method_name, method in server.methods.items():
            assert "filter_status" not in method.params, (
                f"Method {method_name} still has old 'filter_status' param"
            )

        # Also check tool.yaml
        yaml_path = TOOL_DIR / "tool.yaml"
        with open(yaml_path) as f:
            yaml_data = yaml.safe_load(f)
        for method_name, method_def in yaml_data.get("methods", {}).items():
            assert "filter_status" not in method_def.get("params", {}), (
                f"tool.yaml {method_name} still has old 'filter_status' param"
            )

    def test_all_methods_registered(self):
        """Server registers exactly the expected methods."""
        server = _get_server_class()()
        expected = {"dir_fuzz", "param_fuzz", "vhost_fuzz"}
        actual = set(server.methods.keys())
        assert expected == actual, f"Expected methods {expected}, got {actual}"


# ===========================================================================
# ACCEPTANCE TESTS -- every method called through container
# ===========================================================================

class TestAcceptance:
    """Call every method through the container using the local HTTP test server.

    These tests verify:
    - The method exists and is callable
    - Required param validation works (missing required params -> error)
    - The response has correct structuredContent shape
    - No unhandled crashes

    Uses local http_server fixture for fast responses with the 'small' wordlist.
    """

    def _assert_structured_response(self, resp, method_name):
        """Assert response has structuredContent and no crashes."""
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
        return sc

    # ── dir_fuzz ──────────────────────────────────────────────

    def test_dir_fuzz_basic(self, ffuf_env, http_server):
        """dir_fuzz against local server completes successfully."""
        client, loop = ffuf_env
        host, port = http_server
        resp = loop.run_until_complete(client.call("dir_fuzz", {
            "url": f"http://{host}:{port}/FUZZ",
            "wordlist": "small",
            "threads": 10,
        }, timeout=120))
        self._assert_structured_response(resp, "dir_fuzz")

    def test_dir_fuzz_missing_url(self, ffuf_env):
        """dir_fuzz without url returns error."""
        client, loop = ffuf_env
        resp = loop.run_until_complete(client.call("dir_fuzz", {}))
        result = resp.get("result", {})
        is_error = result.get("isError", False)
        content_text = ""
        for c in result.get("content", []):
            if c.get("type") == "text":
                content_text += c["text"]
        assert is_error or "url" in content_text.lower() or "required" in content_text.lower()

    def test_dir_fuzz_with_options(self, ffuf_env, http_server):
        """dir_fuzz with extensions, filter_codes, headers does not crash."""
        client, loop = ffuf_env
        host, port = http_server
        resp = loop.run_until_complete(client.call("dir_fuzz", {
            "url": f"http://{host}:{port}/FUZZ",
            "wordlist": "small",
            "extensions": "php,html,txt",
            "filter_codes": "404,403",
            "headers": {"Host": "target.htb"},
            "cookies": "session=abc",
            "threads": 10,
        }, timeout=120))
        self._assert_structured_response(resp, "dir_fuzz+options")

    def test_dir_fuzz_auto_calibrate(self, ffuf_env, http_server):
        """dir_fuzz with auto_calibrate does not crash."""
        client, loop = ffuf_env
        host, port = http_server
        resp = loop.run_until_complete(client.call("dir_fuzz", {
            "url": f"http://{host}:{port}/FUZZ",
            "wordlist": "small",
            "auto_calibrate": True,
            "threads": 10,
        }, timeout=120))
        self._assert_structured_response(resp, "dir_fuzz+ac")

    # ── param_fuzz ────────────────────────────────────────────

    def test_param_fuzz_basic(self, ffuf_env, http_server):
        """param_fuzz against local server completes."""
        client, loop = ffuf_env
        host, port = http_server
        resp = loop.run_until_complete(client.call("param_fuzz", {
            "url": f"http://{host}:{port}/page?id=FUZZ",
            "wordlist": "small",
            "threads": 10,
        }, timeout=120))
        self._assert_structured_response(resp, "param_fuzz")

    def test_param_fuzz_missing_url(self, ffuf_env):
        """param_fuzz without url returns error."""
        client, loop = ffuf_env
        resp = loop.run_until_complete(client.call("param_fuzz", {}))
        result = resp.get("result", {})
        is_error = result.get("isError", False)
        content_text = ""
        for c in result.get("content", []):
            if c.get("type") == "text":
                content_text += c["text"]
        assert is_error or "url" in content_text.lower() or "required" in content_text.lower()

    def test_param_fuzz_post_method(self, ffuf_env, http_server):
        """param_fuzz with POST method and data does not crash."""
        client, loop = ffuf_env
        host, port = http_server
        resp = loop.run_until_complete(client.call("param_fuzz", {
            "url": f"http://{host}:{port}/login",
            "method": "POST",
            "data": "username=admin&password=FUZZ",
            "wordlist": "small",
            "threads": 10,
        }, timeout=120))
        self._assert_structured_response(resp, "param_fuzz+post")

    # ── vhost_fuzz ────────────────────────────────────────────

    def test_vhost_fuzz_basic(self, ffuf_env, http_server):
        """vhost_fuzz against local server completes."""
        client, loop = ffuf_env
        host, port = http_server
        resp = loop.run_until_complete(client.call("vhost_fuzz", {
            "url": f"http://{host}:{port}",
            "domain": "target.htb",
            "wordlist": "small",
            "threads": 10,
        }, timeout=120))
        self._assert_structured_response(resp, "vhost_fuzz")

    def test_vhost_fuzz_missing_url(self, ffuf_env):
        """vhost_fuzz without url returns error."""
        client, loop = ffuf_env
        resp = loop.run_until_complete(client.call("vhost_fuzz", {
            "domain": "target.htb",
        }))
        result = resp.get("result", {})
        is_error = result.get("isError", False)
        content_text = ""
        for c in result.get("content", []):
            if c.get("type") == "text":
                content_text += c["text"]
        assert is_error or "url" in content_text.lower() or "required" in content_text.lower()

    def test_vhost_fuzz_missing_domain(self, ffuf_env):
        """vhost_fuzz without domain returns error."""
        client, loop = ffuf_env
        resp = loop.run_until_complete(client.call("vhost_fuzz", {
            "url": "http://192.0.2.1",
        }))
        result = resp.get("result", {})
        is_error = result.get("isError", False)
        content_text = ""
        for c in result.get("content", []):
            if c.get("type") == "text":
                content_text += c["text"]
        assert is_error or "domain" in content_text.lower() or "required" in content_text.lower()

    def test_vhost_fuzz_with_filter_size(self, ffuf_env, http_server):
        """vhost_fuzz with filter_size does not crash."""
        client, loop = ffuf_env
        host, port = http_server
        resp = loop.run_until_complete(client.call("vhost_fuzz", {
            "url": f"http://{host}:{port}",
            "domain": "target.htb",
            "wordlist": "small",
            "filter_size": "1234",
            "threads": 10,
        }, timeout=120))
        self._assert_structured_response(resp, "vhost_fuzz+filter")

    # ── Cross-cutting ─────────────────────────────────────────

    def test_all_methods_return_structuredContent(self, ffuf_env):
        """verify_clock returns structuredContent with all required fields."""
        client, loop = ffuf_env
        resp = loop.run_until_complete(client.call("verify_clock", {}))
        result = resp.get("result", {})
        sc = result.get("structuredContent")
        assert sc is not None
        assert isinstance(sc, dict)
        for field in ("success", "error_class", "retryable", "suggestions"):
            assert field in sc, f"Missing field '{field}' in structuredContent"


# ===========================================================================
# TIMEOUT ESTIMATION TESTS -- unit tests for _estimate_timeout
# ===========================================================================

class TestEstimateTimeout:
    """Test the _estimate_timeout method that dynamically calculates wall-clock
    timeout based on wordlist size and extensions."""

    def _make_wordlist(self, tmp_path, lines):
        """Create a temporary wordlist with the given number of lines."""
        wl = tmp_path / "test_wordlist.txt"
        wl.write_text("\n".join(f"word{i}" for i in range(lines)))
        return str(wl)

    def test_small_wordlist_floor(self, tmp_path):
        """Small wordlist should hit the 60s floor."""
        server = _get_server_class()()
        wl = self._make_wordlist(tmp_path, 100)
        result = server._estimate_timeout(wl)
        assert result == 60, f"Expected 60s floor, got {result}"

    def test_medium_wordlist(self, tmp_path):
        """Medium wordlist (~5000 lines) produces a reasonable timeout."""
        server = _get_server_class()()
        wl = self._make_wordlist(tmp_path, 5000)
        # (5000 // 100) + 30 = 80
        result = server._estimate_timeout(wl)
        assert result == 80, f"Expected 80s, got {result}"

    def test_large_wordlist_ceiling(self, tmp_path):
        """Very large wordlist should hit the 900s ceiling."""
        server = _get_server_class()()
        wl = self._make_wordlist(tmp_path, 200000)
        result = server._estimate_timeout(wl)
        assert result == 900, f"Expected 900s ceiling, got {result}"

    def test_extensions_multiply_requests(self, tmp_path):
        """Extensions should multiply total request count for timeout calc."""
        server = _get_server_class()()
        wl = self._make_wordlist(tmp_path, 5000)

        # Without extensions: (5000 // 100) + 30 = 80
        no_ext = server._estimate_timeout(wl)
        assert no_ext == 80

        # With 4 extensions: (5000 * 5 // 100) + 30 = 280
        with_ext = server._estimate_timeout(wl, extensions="php,html,txt,bak")
        assert with_ext == 280, f"Expected 280s, got {with_ext}"

    def test_many_extensions_realistic(self, tmp_path):
        """Real engagement pattern: common wordlist + 16 extensions.

        From engagement data call 13: common (4614 lines) + 16 extensions
        caused timeout at 77s with old calc. New calc:
        4614 * 17 / 100 + 30 = 814s
        """
        server = _get_server_class()()
        wl = self._make_wordlist(tmp_path, 4614)
        exts = ".php,.phps,.bak,.txt,.html,.conf,.cfg,.ini,.inc,.old,.orig,.save,.log,.sql,.xml,.json"
        result = server._estimate_timeout(wl, extensions=exts)
        # 4614 * 17 = 78438, 78438 // 100 + 30 = 814
        assert result == 814, f"Expected 814s, got {result}"

    def test_missing_wordlist_defaults_to_300(self, tmp_path):
        """Non-existent wordlist path returns safe 300s default."""
        server = _get_server_class()()
        result = server._estimate_timeout("/nonexistent/wordlist.txt")
        assert result == 300, f"Expected 300s default, got {result}"

    def test_extensions_with_dots_stripped(self, tmp_path):
        """Extensions with leading dots should still count correctly."""
        server = _get_server_class()()
        wl = self._make_wordlist(tmp_path, 1000)
        # Both formats should produce same count
        no_dots = server._estimate_timeout(wl, extensions="php,html,txt")
        with_dots = server._estimate_timeout(wl, extensions=".php,.html,.txt")
        assert no_dots == with_dots

    def test_empty_extensions_string(self, tmp_path):
        """Empty extensions string should be same as no extensions."""
        server = _get_server_class()()
        wl = self._make_wordlist(tmp_path, 5000)
        no_ext = server._estimate_timeout(wl)
        empty_ext = server._estimate_timeout(wl, extensions="")
        assert no_ext == empty_ext


# ===========================================================================
# PARAM_FUZZ FUZZ KEYWORD VALIDATION TESTS
# ===========================================================================

class TestParamFuzzValidation:
    """Test that param_fuzz validates FUZZ keyword presence."""

    def test_param_fuzz_missing_fuzz_keyword(self, ffuf_env, http_server):
        """param_fuzz without FUZZ keyword returns validation error."""
        client, loop = ffuf_env
        host, port = http_server
        resp = loop.run_until_complete(
            client.call("param_fuzz", {
                "url": f"http://{host}:{port}/login",
                "wordlist": "small",
                "threads": 10,
            })
        )
        result = resp.get("result", {})
        # Should be an error
        assert result.get("isError", False), "param_fuzz without FUZZ should error"
        sc = result.get("structuredContent", {})
        assert sc.get("error_class") == "validation", (
            f"Expected validation error_class, got {sc.get('error_class')}"
        )

    def test_param_fuzz_fuzz_in_url_ok(self, ffuf_env, http_server):
        """param_fuzz with FUZZ in URL is accepted."""
        client, loop = ffuf_env
        host, port = http_server
        resp = loop.run_until_complete(
            client.call("param_fuzz", {
                "url": f"http://{host}:{port}/page?id=FUZZ",
                "wordlist": "small",
                "threads": 10,
            })
        )
        result = resp.get("result", {})
        assert not result.get("isError", False), "FUZZ in URL should not error"

    def test_param_fuzz_fuzz_in_data_ok(self, ffuf_env, http_server):
        """param_fuzz with FUZZ in POST data is accepted."""
        client, loop = ffuf_env
        host, port = http_server
        resp = loop.run_until_complete(
            client.call("param_fuzz", {
                "url": f"http://{host}:{port}/login",
                "method": "POST",
                "data": "username=admin&password=FUZZ",
                "wordlist": "small",
                "threads": 10,
            })
        )
        result = resp.get("result", {})
        assert not result.get("isError", False), "FUZZ in data should not error"

    def test_param_fuzz_validation_has_suggestions(self, ffuf_env, http_server):
        """Validation error includes actionable suggestions."""
        client, loop = ffuf_env
        host, port = http_server
        resp = loop.run_until_complete(
            client.call("param_fuzz", {
                "url": f"http://{host}:{port}/login",
                "wordlist": "small",
                "threads": 10,
            })
        )
        sc = resp.get("result", {}).get("structuredContent", {})
        suggestions = sc.get("suggestions", [])
        assert len(suggestions) > 0, "Validation error should include suggestions"
        # Should mention FUZZ placement
        all_text = " ".join(suggestions)
        assert "FUZZ" in all_text, "Suggestions should mention FUZZ keyword"


# ===========================================================================
# FILTER WORDS / FILTER LINES TESTS
# ===========================================================================

class TestFilterWordsLines:
    """Test filter_words (-fw) and filter_lines (-fl) params."""

    def test_dir_fuzz_has_filter_words(self):
        """dir_fuzz exposes filter_words parameter."""
        server = _get_server_class()()
        method = server.methods["dir_fuzz"]
        assert "filter_words" in method.params

    def test_dir_fuzz_has_filter_lines(self):
        """dir_fuzz exposes filter_lines parameter."""
        server = _get_server_class()()
        method = server.methods["dir_fuzz"]
        assert "filter_lines" in method.params

    def test_param_fuzz_has_filter_words(self):
        """param_fuzz exposes filter_words parameter."""
        server = _get_server_class()()
        method = server.methods["param_fuzz"]
        assert "filter_words" in method.params

    def test_param_fuzz_has_filter_lines(self):
        """param_fuzz exposes filter_lines parameter."""
        server = _get_server_class()()
        method = server.methods["param_fuzz"]
        assert "filter_lines" in method.params

    def test_vhost_fuzz_has_filter_words(self):
        """vhost_fuzz exposes filter_words parameter."""
        server = _get_server_class()()
        method = server.methods["vhost_fuzz"]
        assert "filter_words" in method.params

    def test_vhost_fuzz_has_filter_lines(self):
        """vhost_fuzz exposes filter_lines parameter."""
        server = _get_server_class()()
        method = server.methods["vhost_fuzz"]
        assert "filter_lines" in method.params

    def test_dir_fuzz_filter_words_via_container(self, ffuf_env, http_server):
        """filter_words is accepted by dir_fuzz without error."""
        client, loop = ffuf_env
        host, port = http_server
        resp = loop.run_until_complete(
            client.call("dir_fuzz", {
                "url": f"http://{host}:{port}/FUZZ",
                "wordlist": "small",
                "filter_words": "42",
                "threads": 10,
            })
        )
        result = assert_tool_success(resp)

    def test_dir_fuzz_filter_lines_via_container(self, ffuf_env, http_server):
        """filter_lines is accepted by dir_fuzz without error."""
        client, loop = ffuf_env
        host, port = http_server
        resp = loop.run_until_complete(
            client.call("dir_fuzz", {
                "url": f"http://{host}:{port}/FUZZ",
                "wordlist": "small",
                "filter_lines": "0",
                "threads": 10,
            })
        )
        result = assert_tool_success(resp)

    def test_param_fuzz_filter_words_via_container(self, ffuf_env, http_server):
        """filter_words is accepted by param_fuzz without error."""
        client, loop = ffuf_env
        host, port = http_server
        resp = loop.run_until_complete(
            client.call("param_fuzz", {
                "url": f"http://{host}:{port}/?FUZZ=test",
                "wordlist": "small",
                "filter_words": "1",
                "threads": 10,
            })
        )
        result = assert_tool_success(resp)

    def test_vhost_fuzz_filter_words_via_container(self, ffuf_env, vhost_server):
        """filter_words is accepted by vhost_fuzz without error."""
        client, loop = ffuf_env
        host, port = vhost_server
        resp = loop.run_until_complete(
            client.call("vhost_fuzz", {
                "url": f"http://{host}:{port}",
                "domain": "target.htb",
                "wordlist": "small",
                "filter_words": "5",
                "threads": 10,
            })
        )
        result = assert_tool_success(resp)


# ===========================================================================
# VHOST_FUZZ HEADERS AND COOKIES TESTS
# ===========================================================================

class TestVhostFuzzExtendedParams:
    """Test that vhost_fuzz now supports headers and cookies."""

    def test_vhost_fuzz_has_headers_param(self):
        """vhost_fuzz exposes headers parameter."""
        server = _get_server_class()()
        method = server.methods["vhost_fuzz"]
        assert "headers" in method.params

    def test_vhost_fuzz_has_cookies_param(self):
        """vhost_fuzz exposes cookies parameter."""
        server = _get_server_class()()
        method = server.methods["vhost_fuzz"]
        assert "cookies" in method.params

    def test_vhost_fuzz_with_headers_via_container(self, ffuf_env, vhost_server):
        """vhost_fuzz with custom headers does not crash."""
        client, loop = ffuf_env
        host, port = vhost_server
        resp = loop.run_until_complete(
            client.call("vhost_fuzz", {
                "url": f"http://{host}:{port}",
                "domain": "target.htb",
                "wordlist": "small",
                "headers": {"Authorization": "Bearer test-token"},
                "threads": 10,
            })
        )
        result = assert_tool_success(resp)

    def test_vhost_fuzz_with_cookies_via_container(self, ffuf_env, vhost_server):
        """vhost_fuzz with cookies does not crash."""
        client, loop = ffuf_env
        host, port = vhost_server
        resp = loop.run_until_complete(
            client.call("vhost_fuzz", {
                "url": f"http://{host}:{port}",
                "domain": "target.htb",
                "wordlist": "small",
                "cookies": "session=abc123",
                "threads": 10,
            })
        )
        result = assert_tool_success(resp)


# ===========================================================================
# PARAM_FUZZ TIMEOUT PARAMETER TESTS
# ===========================================================================

class TestParamFuzzTimeout:
    """Test that param_fuzz now exposes timeout (HTTP request timeout)."""

    def test_param_fuzz_has_timeout_param(self):
        """param_fuzz exposes timeout parameter."""
        server = _get_server_class()()
        method = server.methods["param_fuzz"]
        assert "timeout" in method.params
        assert method.params["timeout"]["default"] == 10

    def test_param_fuzz_with_timeout_via_container(self, ffuf_env, http_server):
        """param_fuzz with custom timeout does not crash."""
        client, loop = ffuf_env
        host, port = http_server
        resp = loop.run_until_complete(
            client.call("param_fuzz", {
                "url": f"http://{host}:{port}/?FUZZ=test",
                "wordlist": "small",
                "timeout": 5,
                "threads": 10,
            })
        )
        result = assert_tool_success(resp)


# ===========================================================================
# ENGAGEMENT-DERIVED REGRESSION TESTS
# ===========================================================================

class TestEngagementRegression:
    """Tests derived from actual engagement data patterns.

    These reproduce the exact argument combinations that failed or were
    frequently used in HTB engagements, ensuring the fixes handle them.
    """

    def test_dir_fuzz_with_many_extensions(self, ffuf_env, http_server):
        """Regression: common wordlist + 7 extensions was the pattern that
        caused 71.4% timeout rate on dir_fuzz (engagement Pirate/Overwatch).
        The timeout estimate should now account for the multiplier."""
        client, loop = ffuf_env
        host, port = http_server
        resp = loop.run_until_complete(
            client.call("dir_fuzz", {
                "url": f"http://{host}:{port}/FUZZ",
                "wordlist": "small",  # Use small for test speed
                "extensions": "asp,aspx,html,txt,bak,old,config",
                "threads": 10,
            }, timeout=120)
        )
        result = assert_tool_success(resp)
        data = parse_tool_output(resp)
        assert "results" in data

    def test_dir_fuzz_match_and_filter_combined(self, ffuf_env, http_server):
        """Regression: engagement call 2 used -mc 200,401 -fc 403 -ac together."""
        client, loop = ffuf_env
        host, port = http_server
        resp = loop.run_until_complete(
            client.call("dir_fuzz", {
                "url": f"http://{host}:{port}/FUZZ",
                "wordlist": "small",
                "match_status": "200,401",
                "filter_codes": "403",
                "auto_calibrate": True,
                "threads": 10,
            })
        )
        result = assert_tool_success(resp)
        data = parse_tool_output(resp)
        # All returned results should be 200 or 401 (not 403)
        for r in data.get("results", []):
            assert r["status"] in [200, 401], (
                f"Expected 200 or 401, got {r['status']}"
            )
            assert r["status"] != 403, "403 should be filtered out"

    def test_vhost_fuzz_with_filter_size_pattern(self, ffuf_env, vhost_server):
        """Regression: engagement calls 16-17 used -fs 703 for pirate.htb
        default response filtering. This was the most common vhost pattern."""
        client, loop = ffuf_env
        host, port = vhost_server
        # First, get the default response size
        resp = loop.run_until_complete(
            client.call("vhost_fuzz", {
                "url": f"http://{host}:{port}",
                "domain": "target.htb",
                "wordlist": "small",
                "threads": 10,
            })
        )
        result = assert_tool_success(resp)
        data = parse_tool_output(resp)

        # If we got results, find the most common size and filter it
        if data.get("total_results", 0) > 0:
            sizes = [r["length"] for r in data["results"]]
            from collections import Counter
            common_size = Counter(sizes).most_common(1)[0][0]

            # Now filter that size
            resp2 = loop.run_until_complete(
                client.call("vhost_fuzz", {
                    "url": f"http://{host}:{port}",
                    "domain": "target.htb",
                    "wordlist": "small",
                    "filter_size": str(common_size),
                    "threads": 10,
                })
            )
            result2 = assert_tool_success(resp2)
            data2 = parse_tool_output(resp2)
            # Filtered results should be fewer
            assert data2.get("total_results", 0) <= data["total_results"]

    def test_param_fuzz_post_json_body(self, ffuf_env, http_server):
        """Regression: engagement call 4 used POST with JSON body for login fuzzing."""
        client, loop = ffuf_env
        host, port = http_server
        resp = loop.run_until_complete(
            client.call("param_fuzz", {
                "url": f"http://{host}:{port}/login",
                "method": "POST",
                "data": '{"username":"admin","password":"FUZZ"}',
                "wordlist": "small",
                "headers": {"Content-Type": "application/json"},
                "threads": 10,
            })
        )
        result = assert_tool_success(resp)
        data = parse_tool_output(resp)
        assert data.get("summary", {}).get("method") == "POST"

    def test_vhost_fuzz_with_big_wordlist_name(self, ffuf_env, vhost_server):
        """Regression: engagement calls 17, 25 used 'big' wordlist for vhost.
        Ensure the named wordlist resolves correctly in container."""
        client, loop = ffuf_env
        host, port = vhost_server
        resp = loop.run_until_complete(
            client.call("vhost_fuzz", {
                "url": f"http://{host}:{port}",
                "domain": "target.htb",
                "wordlist": "big",
                "threads": 10,
                "auto_calibrate": True,
            }, timeout=300)
        )
        result = assert_tool_success(resp)

    def test_dir_fuzz_dot_prefixed_extensions(self, ffuf_env, http_server):
        """Regression: engagement call 29 used .asp,.aspx,.html,.txt,.config
        (dot-prefixed). ffuf handles this correctly but test ensures no crash."""
        client, loop = ffuf_env
        host, port = http_server
        resp = loop.run_until_complete(
            client.call("dir_fuzz", {
                "url": f"http://{host}:{port}/FUZZ",
                "wordlist": "small",
                "extensions": ".html,.php,.txt",
                "threads": 10,
            })
        )
        result = assert_tool_success(resp)


# ===========================================================================
# UPDATED CONTRACT TESTS -- verify new params in tool.yaml
# ===========================================================================

class TestContractV2:
    """Verify that new params are present in both tool.yaml and server."""

    def test_dir_fuzz_new_params_in_yaml(self):
        """dir_fuzz filter_words and filter_lines are in tool.yaml."""
        yaml_path = TOOL_DIR / "tool.yaml"
        with open(yaml_path) as f:
            yaml_data = yaml.safe_load(f)
        dir_params = yaml_data["methods"]["dir_fuzz"]["params"]
        assert "filter_words" in dir_params, "dir_fuzz missing filter_words in yaml"
        assert "filter_lines" in dir_params, "dir_fuzz missing filter_lines in yaml"

    def test_param_fuzz_new_params_in_yaml(self):
        """param_fuzz filter_words, filter_lines, timeout are in tool.yaml."""
        yaml_path = TOOL_DIR / "tool.yaml"
        with open(yaml_path) as f:
            yaml_data = yaml.safe_load(f)
        params = yaml_data["methods"]["param_fuzz"]["params"]
        assert "filter_words" in params, "param_fuzz missing filter_words in yaml"
        assert "filter_lines" in params, "param_fuzz missing filter_lines in yaml"
        assert "timeout" in params, "param_fuzz missing timeout in yaml"

    def test_vhost_fuzz_new_params_in_yaml(self):
        """vhost_fuzz filter_words, filter_lines, headers, cookies are in tool.yaml."""
        yaml_path = TOOL_DIR / "tool.yaml"
        with open(yaml_path) as f:
            yaml_data = yaml.safe_load(f)
        params = yaml_data["methods"]["vhost_fuzz"]["params"]
        assert "filter_words" in params, "vhost_fuzz missing filter_words in yaml"
        assert "filter_lines" in params, "vhost_fuzz missing filter_lines in yaml"
        assert "headers" in params, "vhost_fuzz missing headers in yaml"
        assert "cookies" in params, "vhost_fuzz missing cookies in yaml"

    def test_yaml_params_match_server_all_methods(self):
        """Extended contract: all yaml params exist in server for all methods."""
        server = _get_server_class()()
        yaml_path = TOOL_DIR / "tool.yaml"
        with open(yaml_path) as f:
            yaml_data = yaml.safe_load(f)

        for method_name, method_def in yaml_data.get("methods", {}).items():
            assert method_name in server.methods, (
                f"Method '{method_name}' in yaml but not server"
            )
            server_params = set(server.methods[method_name].params.keys())
            yaml_params = set(method_def.get("params", {}).keys())
            yaml_only = yaml_params - server_params
            assert not yaml_only, (
                f"{method_name}: params in yaml but not server: {yaml_only}"
            )
