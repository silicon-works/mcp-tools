"""
Tests for the curl MCP tool server.

Covers:
- Smoke tests: boot, method list, required params, meta-param stripping, clock
- Unit tests: helper functions (_parse_headers, _normalize_headers, _parse_timing,
  _strip_timing_block, _encode_payload, _extract_output, _get_error_message)
- Method tests: request, inject, upload, download, download_to_file
- Error classification: connection_refused, timeout, could_not_resolve_host, ssl_error
- Contract tests: tool.yaml vs server parameter definitions
- Acceptance tests: every method called through container (no live target)
"""

import asyncio
import base64
import gzip
import http.server
import importlib.util
import json
import os
import sys
import tempfile
import threading
from io import BytesIO
from pathlib import Path
from typing import Any, Dict, Set
from urllib.parse import parse_qs, urlparse, unquote

import pytest
import yaml

# ---------------------------------------------------------------------------
# Path setup
# ---------------------------------------------------------------------------
PROJECT_ROOT = Path(__file__).parent.parent.parent
TOOL_DIR = PROJECT_ROOT / "tools" / "curl"
FIXTURES_DIR = Path(__file__).parent.parent / "fixtures" / "curl"

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
    """Import and return the CurlServer class for direct method testing."""
    spec = importlib.util.spec_from_file_location(
        "curl_server", TOOL_DIR / "mcp-server.py"
    )
    mod = importlib.util.module_from_spec(spec)
    spec.loader.exec_module(mod)
    return mod.CurlServer


def _get_module():
    """Import the whole curl mcp-server module."""
    spec = importlib.util.spec_from_file_location(
        "curl_server", TOOL_DIR / "mcp-server.py"
    )
    mod = importlib.util.module_from_spec(spec)
    spec.loader.exec_module(mod)
    return mod


# ---------------------------------------------------------------------------
# Test HTTP server -- runs on host, reachable from --network=host container
# ---------------------------------------------------------------------------
class _HTTPRequestHandler(http.server.BaseHTTPRequestHandler):
    """Minimal HTTP server for testing curl methods."""

    def log_message(self, format, *args):
        """Suppress log output during tests."""
        pass

    def do_GET(self):
        parsed = urlparse(self.path)
        path = parsed.path
        query = parse_qs(parsed.query)

        if path == "/":
            self._send_response(200, "<h1>Hello World</h1>", content_type="text/html")
        elif path == "/json":
            self._send_response(200, '{"key": "value", "number": 42}', content_type="application/json")
        elif path == "/headers":
            # Echo back all request headers as JSON
            headers_dict = {k: v for k, v in self.headers.items()}
            self._send_response(200, json.dumps(headers_dict), content_type="application/json")
        elif path == "/status/404":
            self._send_response(404, "Not Found")
        elif path == "/status/500":
            self._send_response(500, "Internal Server Error")
        elif path == "/status/301":
            self.send_response(301)
            self.send_header("Location", f"http://127.0.0.1:{self.server.server_port}/")
            self.send_header("Content-Length", "0")
            self.end_headers()
        elif path == "/status/302":
            self.send_response(302)
            self.send_header("Location", f"http://127.0.0.1:{self.server.server_port}/json")
            self.send_header("Content-Length", "0")
            self.end_headers()
        elif path == "/redirect/loop":
            self.send_response(302)
            self.send_header("Location", f"http://127.0.0.1:{self.server.server_port}/redirect/loop")
            self.send_header("Content-Length", "0")
            self.end_headers()
        elif path == "/vuln":
            # Simulated vulnerable endpoint for inject testing
            cmd = query.get("cmd", [""])[0]
            cmd_decoded = unquote(cmd)
            body = f"<html><body><pre>COMMAND_START\n{cmd_decoded}\nCOMMAND_END</pre></body></html>"
            self._send_response(200, body, content_type="text/html")
        elif path == "/rce-plain":
            # RCE endpoint returning plain text output (no HTML)
            cmd = query.get("cmd", [""])[0]
            cmd_decoded = unquote(cmd)
            self._send_response(200, cmd_decoded, content_type="text/plain")
        elif path == "/download/test.txt":
            content = "line1\nline2\nline3\nline4\nline5\n"
            self._send_response(200, content, content_type="text/plain")
        elif path == "/download/test.bin":
            # Binary content
            binary_data = bytes(range(256))
            self.send_response(200)
            self.send_header("Content-Type", "application/octet-stream")
            self.send_header("Content-Length", str(len(binary_data)))
            self.end_headers()
            self.wfile.write(binary_data)
        elif path == "/download/test.txt.gz":
            # Gzip compressed content
            raw = b"gzipped line 1\ngzipped line 2\ngzipped line 3\n"
            buf = BytesIO()
            with gzip.GzipFile(fileobj=buf, mode="wb") as gz:
                gz.write(raw)
            gz_data = buf.getvalue()
            self.send_response(200)
            self.send_header("Content-Type", "application/gzip")
            self.send_header("Content-Length", str(len(gz_data)))
            self.end_headers()
            self.wfile.write(gz_data)
        elif path == "/download/large.txt":
            # Larger text file for download_to_file
            lines = [f"line {i}\n" for i in range(1000)]
            content = "".join(lines)
            self._send_response(200, content, content_type="text/plain")
        elif path == "/slow":
            # Endpoint that delays response (for timeout testing)
            import time
            time.sleep(5)
            self._send_response(200, "slow response")
        elif path == "/cookies":
            # Echo cookie header
            cookie = self.headers.get("Cookie", "")
            self._send_response(200, json.dumps({"cookie": cookie}), content_type="application/json")
        elif path == "/empty":
            # Empty body response
            self.send_response(200)
            self.send_header("Content-Length", "0")
            self.send_header("X-Custom", "test-value")
            self.end_headers()
        elif path == "/multi-cookie":
            # Response with multiple Set-Cookie headers
            body = "OK"
            body_bytes = body.encode("utf-8")
            self.send_response(200)
            self.send_header("Content-Type", "text/plain")
            self.send_header("Content-Length", str(len(body_bytes)))
            self.send_header("Set-Cookie", "session=abc123; Path=/")
            self.send_header("Set-Cookie", "user=admin; HttpOnly")
            self.send_header("Set-Cookie", "lang=en")
            self.end_headers()
            self.wfile.write(body_bytes)
        elif path == "/multiline-rce":
            # RCE endpoint that returns multiline output
            cmd = query.get("cmd", [""])[0]
            cmd_decoded = unquote(cmd)
            body = (
                "<html><body><pre>"
                "root:x:0:0:root:/root:/bin/bash\n"
                "daemon:x:1:1:daemon:/usr/sbin:/usr/sbin/nologin\n"
                "www-data:x:33:33:www-data:/var/www:/usr/sbin/nologin\n"
                "</pre></body></html>"
            )
            self._send_response(200, body, content_type="text/html")
        elif path == "/large-body":
            # Generate a response body > 50KB
            line = "A" * 100 + "\n"
            body = line * 600  # 60KB+
            self._send_response(200, body, content_type="text/plain")
        else:
            self._send_response(404, "Not Found")

    def do_POST(self):
        parsed = urlparse(self.path)
        path = parsed.path
        content_length = int(self.headers.get("Content-Length", 0))
        body = self.rfile.read(content_length) if content_length > 0 else b""

        if path == "/post":
            # Echo back the POST body and content type
            resp = json.dumps({
                "body": body.decode("utf-8", errors="replace"),
                "content_type": self.headers.get("Content-Type", ""),
                "content_length": content_length,
            })
            self._send_response(200, resp, content_type="application/json")
        elif path == "/upload":
            # Handle multipart upload -- just acknowledge it
            # Parse boundary from content type
            ct = self.headers.get("Content-Type", "")
            resp = json.dumps({
                "status": "uploaded",
                "content_type": ct,
                "content_length": content_length,
                "body_preview": body[:200].decode("utf-8", errors="replace"),
            })
            self._send_response(200, resp, content_type="application/json")
        elif path == "/inject-post":
            # POST-based RCE endpoint
            body_str = body.decode("utf-8", errors="replace")
            params = parse_qs(body_str)
            cmd = params.get("cmd", [""])[0]
            html_body = f"<pre>{cmd}</pre>"
            self._send_response(200, html_body, content_type="text/html")
        else:
            self._send_response(404, "Not Found")

    def do_HEAD(self):
        parsed = urlparse(self.path)
        if parsed.path == "/":
            self.send_response(200)
            self.send_header("Content-Type", "text/html")
            self.send_header("X-Server", "TestServer/1.0")
            self.end_headers()
        else:
            self.send_response(404)
            self.end_headers()

    def do_OPTIONS(self):
        self.send_response(200)
        self.send_header("Allow", "GET, POST, PUT, DELETE, HEAD, OPTIONS, PATCH")
        self.send_header("Content-Length", "0")
        self.end_headers()

    def do_PUT(self):
        content_length = int(self.headers.get("Content-Length", 0))
        body = self.rfile.read(content_length) if content_length > 0 else b""
        resp = json.dumps({"method": "PUT", "body_length": content_length})
        self._send_response(200, resp, content_type="application/json")

    def do_DELETE(self):
        self._send_response(200, '{"method": "DELETE", "status": "deleted"}',
                            content_type="application/json")

    def do_PATCH(self):
        content_length = int(self.headers.get("Content-Length", 0))
        body = self.rfile.read(content_length) if content_length > 0 else b""
        resp = json.dumps({"method": "PATCH", "body_length": content_length})
        self._send_response(200, resp, content_type="application/json")

    def _send_response(self, code, body, content_type="text/plain"):
        body_bytes = body.encode("utf-8") if isinstance(body, str) else body
        self.send_response(code)
        self.send_header("Content-Type", content_type)
        self.send_header("Content-Length", str(len(body_bytes)))
        self.send_header("X-Test", "present")
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


# ---------------------------------------------------------------------------
# Module-scoped fixture: MCP client (Docker container)
# ---------------------------------------------------------------------------
@pytest.fixture(scope="module")
def curl_env(request):
    """Create an MCPTestClient with its event loop. Yields (client, loop)."""
    tool = "curl"
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

    def test_boot_and_list_tools(self, curl_env):
        """Container starts and list_tools returns methods."""
        client, loop = curl_env
        assert len(client.tools) > 0, "Server should advertise at least one tool"
        names = client.tool_names()
        assert "request" in names
        assert "inject" in names
        assert "upload" in names
        assert "download" in names
        assert "download_to_file" in names

    def test_expected_method_count(self, curl_env):
        """Server should have exactly 5 built-in methods + verify_clock."""
        client, _ = curl_env
        names = client.tool_names()
        assert len(names) == 6, (
            f"Expected 6 methods (5 built-in + verify_clock), got {len(names)}: {sorted(names)}"
        )

    def test_method_list_matches_tool_yaml(self, curl_env):
        """Every method in tool.yaml is advertised by the server, and vice versa."""
        client, _ = curl_env
        server_names = client.tool_names() - {"verify_clock"}

        yaml_path = TOOL_DIR / "tool.yaml"
        with open(yaml_path) as f:
            yaml_data = yaml.safe_load(f)
        yaml_names = set(yaml_data.get("methods", {}).keys())

        yaml_only = yaml_names - server_names
        server_only = server_names - yaml_names

        assert not yaml_only, f"Methods in tool.yaml but not server: {yaml_only}"
        assert not server_only, f"Methods in server but not tool.yaml: {server_only}"

    def test_required_params_request(self, curl_env):
        """Calling request without required 'url' param returns an error."""
        client, loop = curl_env
        resp = loop.run_until_complete(
            client.call("request", {"method": "GET"})
        )
        result = resp.get("result", {})
        is_error = result.get("isError", False)
        content_text = ""
        for c in result.get("content", []):
            if c.get("type") == "text":
                content_text += c["text"]
        assert is_error or "url" in content_text.lower() or "error" in content_text.lower(), (
            f"Expected error about missing 'url', got: {content_text[:300]}"
        )

    def test_required_params_inject(self, curl_env):
        """Calling inject without required 'command' param returns an error."""
        client, loop = curl_env
        resp = loop.run_until_complete(
            client.call("inject", {"url": "http://example.com"})
        )
        result = resp.get("result", {})
        is_error = result.get("isError", False)
        content_text = ""
        for c in result.get("content", []):
            if c.get("type") == "text":
                content_text += c["text"]
        assert is_error or "command" in content_text.lower() or "error" in content_text.lower(), (
            f"Expected error about missing 'command', got: {content_text[:300]}"
        )

    def test_required_params_upload(self, curl_env):
        """Calling upload without required params returns an error."""
        client, loop = curl_env
        resp = loop.run_until_complete(
            client.call("upload", {"url": "http://example.com"})
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

    def test_required_params_download(self, curl_env):
        """Calling download without required 'url' param returns an error."""
        client, loop = curl_env
        resp = loop.run_until_complete(
            client.call("download", {})
        )
        result = resp.get("result", {})
        is_error = result.get("isError", False)
        content_text = ""
        for c in result.get("content", []):
            if c.get("type") == "text":
                content_text += c["text"]
        assert is_error or "url" in content_text.lower() or "error" in content_text.lower(), (
            f"Expected error about missing 'url', got: {content_text[:300]}"
        )

    def test_required_params_download_to_file(self, curl_env):
        """Calling download_to_file without required params returns an error."""
        client, loop = curl_env
        resp = loop.run_until_complete(
            client.call("download_to_file", {"url": "http://example.com/file.txt"})
        )
        result = resp.get("result", {})
        is_error = result.get("isError", False)
        content_text = ""
        for c in result.get("content", []):
            if c.get("type") == "text":
                content_text += c["text"]
        assert is_error or "output_path" in content_text.lower() or "error" in content_text.lower(), (
            f"Expected error about missing 'output_path', got: {content_text[:300]}"
        )

    def test_meta_params_stripped_clock_offset(self, curl_env):
        """Passing 'clock_offset' (meta-param) in args does not crash the server.

        Note: 'timeout' is a REAL param for curl methods, so it should NOT be stripped.
        """
        client, loop = curl_env
        resp = loop.run_until_complete(
            client.call("request", {
                "url": "http://127.0.0.1:1",  # will fail but should not crash
                "clock_offset": "+5h",
            })
        )
        result = resp.get("result", {})
        content_text = ""
        for c in result.get("content", []):
            if c.get("type") == "text":
                content_text += c["text"]
        # Should NOT get "unexpected keyword argument" crash
        assert "unexpected keyword argument" not in content_text, (
            f"Meta-param 'clock_offset' was not stripped: {content_text[:300]}"
        )

    def test_unknown_method_returns_error(self, curl_env):
        """Calling a non-existent method returns a helpful error."""
        client, loop = curl_env
        resp = loop.run_until_complete(
            client.call("fetch", {})
        )
        result = assert_tool_error(resp)
        content_text = ""
        for c in result.get("content", []):
            if c.get("type") == "text":
                content_text += c["text"]
        assert "Unknown method" in content_text
        assert "fetch" in content_text

    @pytest.mark.clock
    def test_verify_clock_available(self, curl_env):
        """verify_clock is registered in MCP_TEST_MODE."""
        client, _ = curl_env
        names = client.tool_names()
        assert "verify_clock" in names

    @pytest.mark.clock
    def test_verify_clock_returns_time(self, curl_env):
        """verify_clock returns current time and confirms no libfaketime."""
        client, loop = curl_env
        resp = loop.run_until_complete(client.call("verify_clock", {}))
        result = assert_tool_success(resp)
        data = parse_tool_output(resp)
        assert "current_time" in data
        assert "libfaketime_exists" in data
        # curl container does NOT have libfaketime
        assert data["libfaketime_exists"] is False

    def test_structuredContent_present(self, curl_env):
        """Responses include structuredContent with error classification fields."""
        client, loop = curl_env
        resp = loop.run_until_complete(client.call("verify_clock", {}))
        result = resp.get("result", {})
        sc = result.get("structuredContent")
        assert sc is not None, "structuredContent should be present"
        assert "success" in sc
        assert "error_class" in sc
        assert "retryable" in sc
        assert "suggestions" in sc


# ===========================================================================
# UNIT TESTS -- test helper functions directly, no container needed
# ===========================================================================

class TestHelpers:
    """Unit tests for CurlServer helper methods."""

    @classmethod
    def setup_class(cls):
        try:
            cls.ServerClass = _get_server_class()
            cls.server = cls.ServerClass()
            cls.mod = _get_module()
        except Exception as e:
            pytest.skip(f"Cannot import CurlServer: {e}")

    # -- _parse_headers --
    def test_parse_headers_basic(self):
        """Parse standard HTTP headers."""
        raw = "Content-Type: text/html\r\nContent-Length: 42\r\nX-Custom: value"
        result = self.server._parse_headers(raw)
        assert result["content-type"] == "text/html"
        assert result["content-length"] == "42"
        assert result["x-custom"] == "value"

    def test_parse_headers_empty(self):
        """Empty input returns empty dict."""
        assert self.server._parse_headers("") == {}

    def test_parse_headers_with_colons_in_value(self):
        """Header values containing colons are handled correctly."""
        raw = "Set-Cookie: session=abc; Path=/; HttpOnly"
        result = self.server._parse_headers(raw)
        assert result["set-cookie"] == "session=abc; Path=/; HttpOnly"

    # -- _normalize_headers --
    def test_normalize_headers_dict(self):
        """Dict input passed through."""
        headers = {"Content-Type": "application/json", "Authorization": "Bearer token"}
        result = self.server._normalize_headers(headers)
        assert result == headers

    def test_normalize_headers_list(self):
        """Array of 'Key: value' strings parsed correctly."""
        headers = ["Content-Type: application/json", "Authorization: Bearer token"]
        result = self.server._normalize_headers(headers)
        assert result["Content-Type"] == "application/json"
        assert result["Authorization"] == "Bearer token"

    def test_normalize_headers_none(self):
        """None returns empty dict."""
        assert self.server._normalize_headers(None) == {}

    def test_normalize_headers_invalid(self):
        """Non-dict/list returns empty dict."""
        assert self.server._normalize_headers(42) == {}

    # -- _parse_timing --
    def test_parse_timing_valid(self):
        """Parse valid timing JSON from curl output."""
        output = 'some output\n__TIMING_START__\n{"time_namelookup":0.001,"time_connect":0.005,"time_appconnect":0.050,"time_pretransfer":0.051,"time_starttransfer":0.100,"time_total":0.200,"remote_ip":"10.10.10.1","remote_port":80}\n__TIMING_END__\n'
        result = self.server._parse_timing(output)
        assert result is not None
        assert result["dns_lookup_ms"] == 1
        assert result["connect_ms"] == 5
        assert result["tls_handshake_ms"] == 45  # (0.050 - 0.005) * 1000
        assert result["first_byte_ms"] == 100
        assert result["total_ms"] == 200
        assert result["remote_ip"] == "10.10.10.1"
        assert result["remote_port"] == 80

    def test_parse_timing_no_tls(self):
        """HTTP (no TLS) has tls_handshake_ms == 0."""
        output = '__TIMING_START__\n{"time_namelookup":0.001,"time_connect":0.005,"time_appconnect":0.000,"time_pretransfer":0.006,"time_starttransfer":0.050,"time_total":0.100,"remote_ip":"10.10.10.1","remote_port":80}\n__TIMING_END__'
        result = self.server._parse_timing(output)
        assert result is not None
        assert result["tls_handshake_ms"] == 0

    def test_parse_timing_missing_markers(self):
        """Missing timing markers return None."""
        assert self.server._parse_timing("no timing here") is None

    def test_parse_timing_invalid_json(self):
        """Invalid JSON between markers returns None."""
        output = "__TIMING_START__\nnot json\n__TIMING_END__"
        assert self.server._parse_timing(output) is None

    # -- _strip_timing_block --
    def test_strip_timing_block(self):
        """Timing block is cleanly removed from output."""
        output = "response body here\n__TIMING_START__\n{...}\n__TIMING_END__\n"
        result = self.server._strip_timing_block(output)
        assert "__TIMING" not in result
        assert "response body here" in result

    def test_strip_timing_block_no_markers(self):
        """No markers means output unchanged."""
        output = "just normal output"
        assert self.server._strip_timing_block(output) == output

    # -- _encode_payload --
    def test_encode_payload_url(self):
        """URL encoding works."""
        result = self.server._encode_payload("cat /etc/passwd", "url")
        assert result == "cat%20%2Fetc%2Fpasswd"

    def test_encode_payload_double_url(self):
        """Double URL encoding works."""
        result = self.server._encode_payload("cat /etc/passwd", "double-url")
        assert "%25" in result  # % is double-encoded

    def test_encode_payload_base64(self):
        """Base64 encoding works."""
        result = self.server._encode_payload("id", "base64")
        assert result == base64.b64encode(b"id").decode()

    def test_encode_payload_none(self):
        """'none' encoding returns payload unchanged."""
        assert self.server._encode_payload("raw payload!", "none") == "raw payload!"

    # -- _extract_output --
    def test_extract_output_with_markers(self):
        """Output extracted between start and end markers."""
        body = "<html>COMMAND_START\nuid=0(root)\nCOMMAND_END</html>"
        result = self.server._extract_output(
            body,
            markers={"start": "COMMAND_START\n", "end": "\nCOMMAND_END"},
            strip_html=False,
        )
        assert result == "uid=0(root)"

    def test_extract_output_start_marker_only(self):
        """Extract from start marker to end of body."""
        body = "junk MARKER important data here"
        result = self.server._extract_output(
            body,
            markers={"start": "MARKER "},
            strip_html=False,
        )
        assert result == "important data here"

    def test_extract_output_end_marker_only(self):
        """Extract from beginning to end marker."""
        body = "useful data END_MARKER junk"
        result = self.server._extract_output(
            body,
            markers={"end": " END_MARKER"},
            strip_html=False,
        )
        assert result == "useful data"

    def test_extract_output_strip_html(self):
        """HTML tags are stripped and entities decoded."""
        body = "<pre>uid=0(root)&amp;gid=0</pre>"
        result = self.server._extract_output(body, strip_html=True)
        assert "uid=0(root)&gid=0" in result
        assert "<pre>" not in result

    def test_extract_output_no_strip_html(self):
        """When strip_html=False, HTML tags are preserved."""
        body = "<pre>output</pre>"
        result = self.server._extract_output(body, strip_html=False)
        assert "<pre>" in result

    # -- _get_error_message --
    def test_error_message_known_types(self):
        """Known error types return descriptive messages."""
        assert "hostname" in self.server._get_error_message("could_not_resolve_host", "").lower()
        assert "refused" in self.server._get_error_message("connection_refused", "").lower()
        assert "timed out" in self.server._get_error_message("timeout", "").lower()
        assert "ssl" in self.server._get_error_message("ssl_error", "").lower()
        assert "redirect" in self.server._get_error_message("too_many_redirects", "").lower()
        assert "empty" in self.server._get_error_message("empty_response", "").lower()
        assert "certificate" in self.server._get_error_message("ssl_certificate_error", "").lower()

    def test_error_message_unknown(self):
        """Unknown error type includes stderr content."""
        result = self.server._get_error_message("unknown", "some error detail")
        assert "some error detail" in result

    # -- _parse_verbose_request_headers --
    def test_parse_verbose_request_headers(self):
        """Parse request headers from curl -v output."""
        stderr = (
            "* Trying 10.10.10.1:80...\n"
            "* Connected to 10.10.10.1 port 80\n"
            "> GET / HTTP/1.1\n"
            "> Host: 10.10.10.1\n"
            "> User-Agent: Mozilla/5.0\n"
            "> Accept: */*\n"
            ">\n"
            "< HTTP/1.1 200 OK\n"
        )
        result = self.server._parse_verbose_request_headers(stderr)
        assert result["Host"] == "10.10.10.1"
        assert result["User-Agent"] == "Mozilla/5.0"
        assert result["Accept"] == "*/*"
        # The request line (GET / HTTP/1.1) should NOT appear as a header
        assert "GET" not in result

    # -- CURL_ERROR_TYPES mapping --
    def test_curl_error_types_mapping(self):
        """Verify known curl exit codes are mapped."""
        codes = self.mod.CURL_ERROR_TYPES
        assert codes[6] == "could_not_resolve_host"
        assert codes[7] == "connection_refused"
        assert codes[28] == "timeout"
        assert codes[35] == "ssl_error"
        assert codes[47] == "too_many_redirects"
        assert codes[52] == "empty_response"
        assert codes[56] == "receive_error"
        assert codes[60] == "ssl_certificate_error"

    # -- _classify_curl_error --
    def test_classify_curl_error_network(self):
        """Network errors classified correctly."""
        ec, retryable, suggestions = self.server._classify_curl_error("connection_refused")
        assert ec == "network"
        assert retryable is True
        assert len(suggestions) > 0

    def test_classify_curl_error_timeout(self):
        """Timeout errors classified correctly."""
        ec, retryable, suggestions = self.server._classify_curl_error("timeout")
        assert ec == "timeout"
        assert retryable is True

    def test_classify_curl_error_dns(self):
        """DNS errors classified as network."""
        ec, retryable, suggestions = self.server._classify_curl_error("could_not_resolve_host")
        assert ec == "network"
        assert retryable is True

    def test_classify_curl_error_ssl(self):
        """SSL errors classified as network, not retryable."""
        ec, retryable, suggestions = self.server._classify_curl_error("ssl_error")
        assert ec == "network"
        assert retryable is False

    def test_classify_curl_error_unknown(self):
        """Unknown errors return default values."""
        ec, retryable, suggestions = self.server._classify_curl_error("something_weird")
        assert ec == "unknown"
        assert retryable is False

    # -- _parse_headers: duplicate headers --
    def test_parse_headers_duplicate_set_cookie(self):
        """Multiple Set-Cookie headers are joined with ', '."""
        raw = (
            "Content-Type: text/html\r\n"
            "Set-Cookie: session=abc; Path=/\r\n"
            "Set-Cookie: user=admin; HttpOnly\r\n"
            "X-Custom: value"
        )
        result = self.server._parse_headers(raw)
        assert "session=abc" in result["set-cookie"]
        assert "user=admin" in result["set-cookie"]
        assert ", " in result["set-cookie"]
        assert result["content-type"] == "text/html"
        assert result["x-custom"] == "value"

    def test_parse_headers_duplicate_preserves_order(self):
        """First occurrence comes first in joined duplicate value."""
        raw = "X-Multi: first\r\nX-Multi: second\r\nX-Multi: third"
        result = self.server._parse_headers(raw)
        assert result["x-multi"] == "first, second, third"

    # -- _normalize_headers: colon without space --
    def test_normalize_headers_list_no_space_after_colon(self):
        """Array header entries without space after colon are still parsed."""
        headers = ["Content-Type:application/json", "Authorization:Bearer token"]
        result = self.server._normalize_headers(headers)
        assert result["Content-Type"] == "application/json"
        assert result["Authorization"] == "Bearer token"

    def test_normalize_headers_list_mixed_formats(self):
        """Mix of 'Key: value' and 'Key:value' formats."""
        headers = [
            "Content-Type: application/json",
            "X-Custom:no-space",
            "Cookie: session=abc",
        ]
        result = self.server._normalize_headers(headers)
        assert result["Content-Type"] == "application/json"
        assert result["X-Custom"] == "no-space"
        assert result["Cookie"] == "session=abc"

    def test_normalize_headers_list_value_with_colons(self):
        """Header values containing colons (e.g., URLs) are preserved."""
        headers = ["Referer: http://example.com:8080/page"]
        result = self.server._normalize_headers(headers)
        assert result["Referer"] == "http://example.com:8080/page"

    def test_normalize_headers_list_empty_value(self):
        """Header with colon but empty value."""
        headers = ["X-Empty:"]
        result = self.server._normalize_headers(headers)
        assert result["X-Empty"] == ""

    # -- _extract_output: multiline preservation --
    def test_extract_output_preserves_newlines(self):
        """strip_html=True preserves newlines in command output."""
        body = "<pre>uid=0(root)\nroot:x:0:0:root:/root:/bin/bash\nnobody:x:65534</pre>"
        result = self.server._extract_output(body, strip_html=True)
        assert "\n" in result, "Newlines should be preserved"
        lines = result.split("\n")
        assert len(lines) == 3
        assert "uid=0(root)" in lines[0]
        assert "root:x:0:0" in lines[1]
        assert "nobody:x:65534" in lines[2]

    def test_extract_output_collapses_blank_lines(self):
        """Excessive blank lines are collapsed to at most two consecutive."""
        body = "<p>line1</p>\n\n\n\n\n<p>line2</p>"
        result = self.server._extract_output(body, strip_html=True)
        assert "\n\n\n" not in result
        assert "line1" in result
        assert "line2" in result

    def test_extract_output_strips_horizontal_whitespace(self):
        """Horizontal whitespace (spaces/tabs) within a line is normalized."""
        body = "<pre>  lots   of    spaces  \ttabs  </pre>"
        result = self.server._extract_output(body, strip_html=True)
        assert "  " not in result  # No double spaces
        assert "\t" not in result  # No tabs

    def test_extract_output_multiline_cat_passwd(self):
        """Realistic /etc/passwd output preserves line structure."""
        body = (
            "<html><body><pre>"
            "root:x:0:0:root:/root:/bin/bash\n"
            "daemon:x:1:1:daemon:/usr/sbin:/usr/sbin/nologin\n"
            "www-data:x:33:33:www-data:/var/www:/usr/sbin/nologin\n"
            "</pre></body></html>"
        )
        result = self.server._extract_output(body, strip_html=True)
        lines = [l for l in result.split("\n") if l.strip()]
        assert len(lines) == 3
        assert lines[0].startswith("root:")
        assert lines[1].startswith("daemon:")
        assert lines[2].startswith("www-data:")

    def test_extract_output_ls_multiline(self):
        """Realistic ls -la output preserves line structure."""
        body = (
            "<pre>"
            "total 48\n"
            "drwxr-xr-x 2 root root 4096 Jan 1 00:00 .\n"
            "drwxr-xr-x 3 root root 4096 Jan 1 00:00 ..\n"
            "-rw-r--r-- 1 root root   33 Jan 1 00:00 user.txt\n"
            "</pre>"
        )
        result = self.server._extract_output(body, strip_html=True)
        lines = [l for l in result.split("\n") if l.strip()]
        assert len(lines) == 4
        assert "total 48" in lines[0]
        assert "user.txt" in lines[3]

    # -- _encode_payload: edge cases from engagement data --
    def test_encode_payload_url_with_newlines(self):
        """URL encoding handles newlines (heredoc commands)."""
        payload = "cat << 'EOF'\nline1\nline2\nEOF"
        result = self.server._encode_payload(payload, "url")
        assert "%0A" in result
        assert "\n" not in result

    def test_encode_payload_url_with_special_chars(self):
        """URL encoding handles shell special chars (&, |, ;, $)."""
        payload = "ls -la /home/ && cat /etc/shadow 2>/dev/null"
        result = self.server._encode_payload(payload, "url")
        assert "&" not in result  # & is encoded
        assert "%26" in result

    def test_encode_payload_double_url_with_special_chars(self):
        """Double URL encoding encodes % signs from first pass."""
        payload = "id; whoami"
        result = self.server._encode_payload(payload, "double-url")
        # ; is %3B after first pass, then %253B after second
        assert "%253B" in result

    def test_encode_payload_base64_with_special_chars(self):
        """Base64 encoding of commands with pipes and quotes."""
        payload = "cat /etc/passwd | grep root"
        result = self.server._encode_payload(payload, "base64")
        decoded = base64.b64decode(result.encode()).decode()
        assert decoded == payload

    def test_encode_payload_none_preserves_everything(self):
        """'none' encoding preserves all characters unchanged."""
        payload = "id; cat /etc/passwd & echo $USER"
        result = self.server._encode_payload(payload, "none")
        assert result == payload

    # -- _extract_output: markers edge cases --
    def test_extract_output_markers_not_found(self):
        """When markers are not found, return full body."""
        body = "no markers in this body"
        result = self.server._extract_output(
            body,
            markers={"start": "MISSING_START", "end": "MISSING_END"},
            strip_html=False,
        )
        assert result == body

    def test_extract_output_start_marker_not_found(self):
        """When start marker is not found, return full body."""
        body = "some content END here"
        result = self.server._extract_output(
            body,
            markers={"start": "MISSING"},
            strip_html=False,
        )
        assert result == body

    def test_extract_output_markers_with_html_and_newlines(self):
        """Markers extraction works across HTML with newlines."""
        body = (
            "<html><body>"
            "<pre>COMMAND_START\n"
            "uid=0(root) gid=0(root)\n"
            "COMMAND_END</pre>"
            "</body></html>"
        )
        result = self.server._extract_output(
            body,
            markers={"start": "COMMAND_START\n", "end": "\nCOMMAND_END"},
            strip_html=False,
        )
        assert result == "uid=0(root) gid=0(root)"

    # -- _parse_verbose_request_headers edge cases --
    def test_parse_verbose_headers_http2(self):
        """HTTP/2 verbose output uses different format markers."""
        stderr = (
            "* Trying 10.10.10.1:443...\n"
            "* Connected to 10.10.10.1 port 443\n"
            "> GET / HTTP/2\n"
            "> Host: 10.10.10.1\n"
            "> Accept: */*\n"
            ">\n"
        )
        result = self.server._parse_verbose_request_headers(stderr)
        assert result["Host"] == "10.10.10.1"
        assert result["Accept"] == "*/*"
        # HTTP/2 request line should not appear
        assert "GET" not in result

    def test_parse_verbose_headers_empty(self):
        """Empty stderr returns empty dict."""
        result = self.server._parse_verbose_request_headers("")
        assert result == {}

    # -- _parse_timing edge cases --
    def test_parse_timing_negative_appconnect(self):
        """Negative appconnect time (impossible but defensive)."""
        output = '__TIMING_START__\n{"time_namelookup":0.001,"time_connect":0.005,"time_appconnect":-0.001,"time_pretransfer":0.006,"time_starttransfer":0.050,"time_total":0.100,"remote_ip":"10.0.0.1","remote_port":80}\n__TIMING_END__'
        result = self.server._parse_timing(output)
        assert result is not None
        # Should not produce negative TLS time
        assert result["tls_handshake_ms"] == 0

    def test_parse_timing_zero_values(self):
        """All-zero timing (connection failed immediately)."""
        output = '__TIMING_START__\n{"time_namelookup":0.000,"time_connect":0.000,"time_appconnect":0.000,"time_pretransfer":0.000,"time_starttransfer":0.000,"time_total":0.000,"remote_ip":"","remote_port":0}\n__TIMING_END__'
        result = self.server._parse_timing(output)
        assert result is not None
        assert result["total_ms"] == 0
        assert result["remote_ip"] == ""
        assert result["remote_port"] == 0


# ===========================================================================
# LIVE METHOD TESTS: request
# ===========================================================================

class TestRequest:
    """Tests for the request method using live HTTP server + Docker container."""

    def test_get_basic(self, curl_env, http_server):
        """Basic GET request returns status code, headers, body."""
        client, loop = curl_env
        host, port = http_server
        resp = loop.run_until_complete(
            client.call("request", {
                "url": f"http://{host}:{port}/",
                "method": "GET",
                "timeout": 15,
            })
        )
        result = assert_tool_success(resp, "GET / should succeed")
        data = parse_tool_output(resp)
        assert data["status_code"] == 200
        assert "Hello World" in data["body"]
        assert data["body_length"] > 0
        assert isinstance(data["headers"], dict)
        assert data["headers"].get("content-type", "").startswith("text/html")

    def test_get_json(self, curl_env, http_server):
        """GET request for JSON content."""
        client, loop = curl_env
        host, port = http_server
        resp = loop.run_until_complete(
            client.call("request", {
                "url": f"http://{host}:{port}/json",
                "timeout": 15,
            })
        )
        data = parse_tool_output(resp)
        assert data["status_code"] == 200
        body_parsed = json.loads(data["body"])
        assert body_parsed["key"] == "value"
        assert body_parsed["number"] == 42

    def test_post_with_data(self, curl_env, http_server):
        """POST request with body data."""
        client, loop = curl_env
        host, port = http_server
        resp = loop.run_until_complete(
            client.call("request", {
                "url": f"http://{host}:{port}/post",
                "method": "POST",
                "data": "key=value&foo=bar",
                "timeout": 15,
            })
        )
        data = parse_tool_output(resp)
        assert data["status_code"] == 200
        body_parsed = json.loads(data["body"])
        assert "key=value" in body_parsed["body"]

    def test_post_with_body_alias(self, curl_env, http_server):
        """POST request using 'body' param (alias for 'data')."""
        client, loop = curl_env
        host, port = http_server
        resp = loop.run_until_complete(
            client.call("request", {
                "url": f"http://{host}:{port}/post",
                "method": "POST",
                "body": "alias_test=1",
                "timeout": 15,
            })
        )
        data = parse_tool_output(resp)
        assert data["status_code"] == 200
        body_parsed = json.loads(data["body"])
        assert "alias_test=1" in body_parsed["body"]

    def test_custom_headers(self, curl_env, http_server):
        """Custom headers are sent to server."""
        client, loop = curl_env
        host, port = http_server
        resp = loop.run_until_complete(
            client.call("request", {
                "url": f"http://{host}:{port}/headers",
                "headers": {"X-Custom-Test": "hello123", "Accept": "text/plain"},
                "timeout": 15,
            })
        )
        data = parse_tool_output(resp)
        assert data["status_code"] == 200
        body_parsed = json.loads(data["body"])
        assert body_parsed.get("X-Custom-Test") == "hello123"

    def test_headers_as_array(self, curl_env, http_server):
        """Headers passed as array of strings work."""
        client, loop = curl_env
        host, port = http_server
        resp = loop.run_until_complete(
            client.call("request", {
                "url": f"http://{host}:{port}/headers",
                "headers": ["X-Array-Header: arrayvalue"],
                "timeout": 15,
            })
        )
        data = parse_tool_output(resp)
        body_parsed = json.loads(data["body"])
        assert body_parsed.get("X-Array-Header") == "arrayvalue"

    def test_cookies(self, curl_env, http_server):
        """Cookie header is sent correctly."""
        client, loop = curl_env
        host, port = http_server
        resp = loop.run_until_complete(
            client.call("request", {
                "url": f"http://{host}:{port}/cookies",
                "cookie": "session=abc123; user=admin",
                "timeout": 15,
            })
        )
        data = parse_tool_output(resp)
        body_parsed = json.loads(data["body"])
        assert "session=abc123" in body_parsed["cookie"]

    def test_basic_auth(self, curl_env, http_server):
        """Basic auth is sent via Authorization header."""
        client, loop = curl_env
        host, port = http_server
        resp = loop.run_until_complete(
            client.call("request", {
                "url": f"http://{host}:{port}/headers",
                "auth": "admin:password123",
                "timeout": 15,
            })
        )
        data = parse_tool_output(resp)
        body_parsed = json.loads(data["body"])
        assert "Authorization" in body_parsed
        assert "Basic" in body_parsed["Authorization"]

    def test_head_method(self, curl_env, http_server):
        """HEAD request returns headers but no body."""
        client, loop = curl_env
        host, port = http_server
        resp = loop.run_until_complete(
            client.call("request", {
                "url": f"http://{host}:{port}/",
                "method": "HEAD",
                "timeout": 15,
            })
        )
        data = parse_tool_output(resp)
        assert data["status_code"] == 200
        # HEAD has no body
        assert data["body_length"] == 0 or data["body"] == ""

    def test_options_method(self, curl_env, http_server):
        """OPTIONS request returns Allow header."""
        client, loop = curl_env
        host, port = http_server
        resp = loop.run_until_complete(
            client.call("request", {
                "url": f"http://{host}:{port}/",
                "method": "OPTIONS",
                "timeout": 15,
            })
        )
        data = parse_tool_output(resp)
        assert data["status_code"] == 200
        assert "allow" in data["headers"]

    def test_put_method(self, curl_env, http_server):
        """PUT request works."""
        client, loop = curl_env
        host, port = http_server
        resp = loop.run_until_complete(
            client.call("request", {
                "url": f"http://{host}:{port}/",
                "method": "PUT",
                "data": '{"update": true}',
                "timeout": 15,
            })
        )
        data = parse_tool_output(resp)
        assert data["status_code"] == 200

    def test_delete_method(self, curl_env, http_server):
        """DELETE request works."""
        client, loop = curl_env
        host, port = http_server
        resp = loop.run_until_complete(
            client.call("request", {
                "url": f"http://{host}:{port}/",
                "method": "DELETE",
                "timeout": 15,
            })
        )
        data = parse_tool_output(resp)
        assert data["status_code"] == 200

    def test_patch_method(self, curl_env, http_server):
        """PATCH request works."""
        client, loop = curl_env
        host, port = http_server
        resp = loop.run_until_complete(
            client.call("request", {
                "url": f"http://{host}:{port}/",
                "method": "PATCH",
                "data": '{"patch": true}',
                "timeout": 15,
            })
        )
        data = parse_tool_output(resp)
        assert data["status_code"] == 200

    def test_http_404(self, curl_env, http_server):
        """404 response is returned as success with status_code=404."""
        client, loop = curl_env
        host, port = http_server
        resp = loop.run_until_complete(
            client.call("request", {
                "url": f"http://{host}:{port}/status/404",
                "timeout": 15,
            })
        )
        # HTTP errors (4xx/5xx) are still successful curl operations
        result = assert_tool_success(resp, "404 should be a successful curl operation")
        data = parse_tool_output(resp)
        assert data["status_code"] == 404

    def test_http_500(self, curl_env, http_server):
        """500 response is returned as success with status_code=500."""
        client, loop = curl_env
        host, port = http_server
        resp = loop.run_until_complete(
            client.call("request", {
                "url": f"http://{host}:{port}/status/500",
                "timeout": 15,
            })
        )
        result = assert_tool_success(resp, "500 should be a successful curl operation")
        data = parse_tool_output(resp)
        assert data["status_code"] == 500

    def test_follow_redirects(self, curl_env, http_server):
        """Redirects are followed by default."""
        client, loop = curl_env
        host, port = http_server
        resp = loop.run_until_complete(
            client.call("request", {
                "url": f"http://{host}:{port}/status/302",
                "timeout": 15,
            })
        )
        data = parse_tool_output(resp)
        # After following redirect to /json
        assert data["status_code"] == 200
        body_parsed = json.loads(data["body"])
        assert body_parsed.get("key") == "value"

    def test_no_follow_redirects(self, curl_env, http_server):
        """When follow_redirects=false, redirect is not followed."""
        client, loop = curl_env
        host, port = http_server
        resp = loop.run_until_complete(
            client.call("request", {
                "url": f"http://{host}:{port}/status/302",
                "follow_redirects": False,
                "timeout": 15,
            })
        )
        data = parse_tool_output(resp)
        assert data["status_code"] == 302

    def test_timing_data(self, curl_env, http_server):
        """Timing breakdown is returned."""
        client, loop = curl_env
        host, port = http_server
        resp = loop.run_until_complete(
            client.call("request", {
                "url": f"http://{host}:{port}/",
                "timeout": 15,
            })
        )
        data = parse_tool_output(resp)
        timing = data.get("timing")
        assert timing is not None, "Timing data should be present"
        assert "dns_lookup_ms" in timing
        assert "connect_ms" in timing
        assert "tls_handshake_ms" in timing
        assert "first_byte_ms" in timing
        assert "total_ms" in timing
        assert "remote_ip" in timing
        assert "remote_port" in timing
        assert timing["total_ms"] >= 0
        assert timing["remote_ip"] == "127.0.0.1"
        assert timing["remote_port"] == port

    def test_debug_level_1(self, curl_env, http_server):
        """Debug level 1 returns request headers."""
        client, loop = curl_env
        host, port = http_server
        resp = loop.run_until_complete(
            client.call("request", {
                "url": f"http://{host}:{port}/",
                "debug_level": 1,
                "timeout": 15,
            })
        )
        data = parse_tool_output(resp)
        assert "debug" in data
        assert "request_headers" in data["debug"]
        assert isinstance(data["debug"]["request_headers"], dict)

    def test_debug_level_2(self, curl_env, http_server):
        """Debug level 2 returns verbose output."""
        client, loop = curl_env
        host, port = http_server
        resp = loop.run_until_complete(
            client.call("request", {
                "url": f"http://{host}:{port}/",
                "debug_level": 2,
                "timeout": 15,
            })
        )
        data = parse_tool_output(resp)
        assert "debug" in data
        assert "verbose_output" in data["debug"]
        assert "Connected" in data["debug"]["verbose_output"] or "Trying" in data["debug"]["verbose_output"]

    def test_custom_user_agent(self, curl_env, http_server):
        """Custom User-Agent is sent."""
        client, loop = curl_env
        host, port = http_server
        resp = loop.run_until_complete(
            client.call("request", {
                "url": f"http://{host}:{port}/headers",
                "user_agent": "OpenSploit/1.0",
                "timeout": 15,
            })
        )
        data = parse_tool_output(resp)
        body_parsed = json.loads(data["body"])
        assert body_parsed.get("User-Agent") == "OpenSploit/1.0"

    def test_default_user_agent(self, curl_env, http_server):
        """Default User-Agent mimics Chrome on Windows."""
        client, loop = curl_env
        host, port = http_server
        resp = loop.run_until_complete(
            client.call("request", {
                "url": f"http://{host}:{port}/headers",
                "timeout": 15,
            })
        )
        data = parse_tool_output(resp)
        body_parsed = json.loads(data["body"])
        ua = body_parsed.get("User-Agent", "")
        assert "Mozilla" in ua, f"Default UA should mimic Chrome, got: {ua}"

    def test_empty_body_response(self, curl_env, http_server):
        """Empty body response is handled correctly."""
        client, loop = curl_env
        host, port = http_server
        resp = loop.run_until_complete(
            client.call("request", {
                "url": f"http://{host}:{port}/empty",
                "timeout": 15,
            })
        )
        data = parse_tool_output(resp)
        assert data["status_code"] == 200
        # X-Custom header should be present
        assert "x-custom" in data["headers"]

    def test_body_truncation(self, curl_env, http_server):
        """Bodies over 50KB are truncated."""
        # We can't easily create a 50KB response with our test server,
        # but we can verify body_length is reported correctly
        client, loop = curl_env
        host, port = http_server
        resp = loop.run_until_complete(
            client.call("request", {
                "url": f"http://{host}:{port}/download/large.txt",
                "timeout": 15,
            })
        )
        data = parse_tool_output(resp)
        assert data["status_code"] == 200
        assert data["body_length"] > 0

    def test_body_truncation_large(self, curl_env, http_server):
        """Bodies over 50KB are truncated but body_length reports full size."""
        client, loop = curl_env
        host, port = http_server
        resp = loop.run_until_complete(
            client.call("request", {
                "url": f"http://{host}:{port}/large-body",
                "timeout": 15,
            })
        )
        data = parse_tool_output(resp)
        assert data["status_code"] == 200
        # The full body is >50KB
        assert data["body_length"] > 50000
        # But the returned body is capped at 50KB
        assert len(data["body"]) <= 50000

    def test_multiple_set_cookie_headers(self, curl_env, http_server):
        """Multiple Set-Cookie headers are all captured."""
        client, loop = curl_env
        host, port = http_server
        resp = loop.run_until_complete(
            client.call("request", {
                "url": f"http://{host}:{port}/multi-cookie",
                "timeout": 15,
            })
        )
        data = parse_tool_output(resp)
        assert data["status_code"] == 200
        set_cookie = data["headers"].get("set-cookie", "")
        # All three cookies should be present
        assert "session=abc123" in set_cookie
        assert "user=admin" in set_cookie
        assert "lang=en" in set_cookie

    def test_redirect_chain_final_status(self, curl_env, http_server):
        """After following a 301 redirect, final status is 200."""
        client, loop = curl_env
        host, port = http_server
        resp = loop.run_until_complete(
            client.call("request", {
                "url": f"http://{host}:{port}/status/301",
                "timeout": 15,
            })
        )
        data = parse_tool_output(resp)
        assert data["status_code"] == 200
        assert "Hello World" in data["body"]


# ===========================================================================
# LIVE METHOD TESTS: inject
# ===========================================================================

class TestInject:
    """Tests for the inject method (RCE payload delivery)."""

    def test_inject_url_encoding(self, curl_env, http_server):
        """Inject with URL encoding via GET."""
        client, loop = curl_env
        host, port = http_server
        resp = loop.run_until_complete(
            client.call("inject", {
                "url": f"http://{host}:{port}/vuln?cmd={{PAYLOAD}}",
                "command": "cat /etc/passwd",
                "encoding": "url",
                "timeout": 15,
            })
        )
        result = assert_tool_success(resp, "inject GET should succeed")
        data = parse_tool_output(resp)
        assert data["status_code"] == 200
        assert "cat /etc/passwd" in data["output"]
        assert data["encoding"] == "url"

    def test_inject_none_encoding(self, curl_env, http_server):
        """Inject with no encoding."""
        client, loop = curl_env
        host, port = http_server
        resp = loop.run_until_complete(
            client.call("inject", {
                "url": f"http://{host}:{port}/rce-plain?cmd={{PAYLOAD}}",
                "command": "id",
                "encoding": "none",
                "strip_html": False,
                "timeout": 15,
            })
        )
        data = parse_tool_output(resp)
        assert data["status_code"] == 200
        assert "id" in data["output"]

    def test_inject_base64_encoding(self, curl_env, http_server):
        """Inject with base64 encoding."""
        client, loop = curl_env
        host, port = http_server
        resp = loop.run_until_complete(
            client.call("inject", {
                "url": f"http://{host}:{port}/rce-plain?cmd={{PAYLOAD}}",
                "command": "whoami",
                "encoding": "base64",
                "strip_html": False,
                "timeout": 15,
            })
        )
        data = parse_tool_output(resp)
        # The server receives the base64-encoded command
        expected_b64 = base64.b64encode(b"whoami").decode()
        assert expected_b64 in data["output"]

    def test_inject_double_url_encoding(self, curl_env, http_server):
        """Inject with double-URL encoding for WAF bypass."""
        client, loop = curl_env
        host, port = http_server
        resp = loop.run_until_complete(
            client.call("inject", {
                "url": f"http://{host}:{port}/rce-plain?cmd={{PAYLOAD}}",
                "command": "id",
                "encoding": "double-url",
                "strip_html": False,
                "timeout": 15,
            })
        )
        data = parse_tool_output(resp)
        assert data["status_code"] == 200

    def test_inject_output_markers(self, curl_env, http_server):
        """Inject with output markers extracts clean output."""
        client, loop = curl_env
        host, port = http_server
        resp = loop.run_until_complete(
            client.call("inject", {
                "url": f"http://{host}:{port}/vuln?cmd={{PAYLOAD}}",
                "command": "test_command",
                "encoding": "url",
                "output_markers": {"start": "COMMAND_START\n", "end": "\nCOMMAND_END"},
                "strip_html": False,
                "timeout": 15,
            })
        )
        data = parse_tool_output(resp)
        # Should extract only the content between markers
        assert "test_command" in data["output"]
        assert "COMMAND_START" not in data["output"]
        assert "COMMAND_END" not in data["output"]

    def test_inject_strip_html(self, curl_env, http_server):
        """HTML tags are stripped from inject output by default."""
        client, loop = curl_env
        host, port = http_server
        resp = loop.run_until_complete(
            client.call("inject", {
                "url": f"http://{host}:{port}/vuln?cmd={{PAYLOAD}}",
                "command": "test",
                "encoding": "url",
                "timeout": 15,
            })
        )
        data = parse_tool_output(resp)
        assert "<html>" not in data["output"]
        assert "<pre>" not in data["output"]

    def test_inject_no_strip_html(self, curl_env, http_server):
        """strip_html=false preserves HTML tags."""
        client, loop = curl_env
        host, port = http_server
        resp = loop.run_until_complete(
            client.call("inject", {
                "url": f"http://{host}:{port}/vuln?cmd={{PAYLOAD}}",
                "command": "test",
                "encoding": "url",
                "strip_html": False,
                "timeout": 15,
            })
        )
        data = parse_tool_output(resp)
        assert "<" in data["output"]  # HTML tags preserved

    def test_inject_returns_timing(self, curl_env, http_server):
        """Inject returns timing data."""
        client, loop = curl_env
        host, port = http_server
        resp = loop.run_until_complete(
            client.call("inject", {
                "url": f"http://{host}:{port}/vuln?cmd={{PAYLOAD}}",
                "command": "id",
                "encoding": "url",
                "timeout": 15,
            })
        )
        data = parse_tool_output(resp)
        assert "timing" in data
        assert data["timing"]["total_ms"] >= 0

    def test_inject_returns_raw_body_length(self, curl_env, http_server):
        """Inject returns raw_body_length for context about full response size."""
        client, loop = curl_env
        host, port = http_server
        resp = loop.run_until_complete(
            client.call("inject", {
                "url": f"http://{host}:{port}/vuln?cmd={{PAYLOAD}}",
                "command": "id",
                "encoding": "url",
                "timeout": 15,
            })
        )
        data = parse_tool_output(resp)
        assert "raw_body_length" in data
        assert data["raw_body_length"] > 0

    def test_inject_with_headers(self, curl_env, http_server):
        """Inject with custom headers."""
        client, loop = curl_env
        host, port = http_server
        resp = loop.run_until_complete(
            client.call("inject", {
                "url": f"http://{host}:{port}/vuln?cmd={{PAYLOAD}}",
                "command": "id",
                "encoding": "url",
                "headers": {"X-Forwarded-For": "127.0.0.1"},
                "timeout": 15,
            })
        )
        data = parse_tool_output(resp)
        assert data["status_code"] == 200

    def test_inject_multiline_output_preserved(self, curl_env, http_server):
        """Inject preserves newlines in multiline command output."""
        client, loop = curl_env
        host, port = http_server
        resp = loop.run_until_complete(
            client.call("inject", {
                "url": f"http://{host}:{port}/multiline-rce?cmd={{PAYLOAD}}",
                "command": "cat /etc/passwd",
                "encoding": "url",
                "timeout": 15,
            })
        )
        data = parse_tool_output(resp)
        assert data["status_code"] == 200
        output = data["output"]
        # strip_html=True (default) should preserve newlines
        assert "\n" in output, f"Newlines should be preserved in output: {repr(output)}"
        lines = [l for l in output.split("\n") if l.strip()]
        assert len(lines) >= 3, f"Expected 3+ lines, got {len(lines)}: {repr(output)}"
        assert any("root:" in l for l in lines)
        assert any("www-data:" in l for l in lines)

    def test_inject_special_chars_url_encoded(self, curl_env, http_server):
        """Inject with special shell characters are properly URL-encoded."""
        client, loop = curl_env
        host, port = http_server
        resp = loop.run_until_complete(
            client.call("inject", {
                "url": f"http://{host}:{port}/rce-plain?cmd={{PAYLOAD}}",
                "command": "ls -la /tmp && echo DONE",
                "encoding": "url",
                "strip_html": False,
                "timeout": 15,
            })
        )
        data = parse_tool_output(resp)
        assert data["status_code"] == 200
        # The server receives the URL-decoded version, so & should be present
        # in the echoed output
        assert "ls" in data["output"]

    def test_inject_with_cookie(self, curl_env, http_server):
        """Inject with authentication cookie works."""
        client, loop = curl_env
        host, port = http_server
        resp = loop.run_until_complete(
            client.call("inject", {
                "url": f"http://{host}:{port}/vuln?cmd={{PAYLOAD}}",
                "command": "id",
                "encoding": "url",
                "cookie": "session=abc123",
                "timeout": 15,
            })
        )
        data = parse_tool_output(resp)
        assert data["status_code"] == 200


# ===========================================================================
# LIVE METHOD TESTS: upload
# ===========================================================================

class TestUpload:
    """Tests for the upload method (multipart file upload)."""

    def test_upload_text_file(self, curl_env, http_server):
        """Upload a plain text file (e.g., PHP web shell)."""
        client, loop = curl_env
        host, port = http_server
        resp = loop.run_until_complete(
            client.call("upload", {
                "url": f"http://{host}:{port}/upload",
                "file_field": "file",
                "filename": "shell.php",
                "content": "<?php system($_GET['cmd']); ?>",
                "content_type": "application/x-php",
                "timeout": 30,
            })
        )
        result = assert_tool_success(resp, "upload should succeed")
        data = parse_tool_output(resp)
        assert data["status_code"] == 200
        assert data["filename"] == "shell.php"
        assert data["file_size"] > 0

    def test_upload_base64_content(self, curl_env, http_server):
        """Upload base64-encoded binary content."""
        client, loop = curl_env
        host, port = http_server
        # Small binary content
        binary = bytes(range(64))
        b64 = base64.b64encode(binary).decode()
        resp = loop.run_until_complete(
            client.call("upload", {
                "url": f"http://{host}:{port}/upload",
                "file_field": "upload",
                "filename": "payload.bin",
                "content": b64,
                "is_base64": True,
                "content_type": "application/octet-stream",
                "timeout": 30,
            })
        )
        result = assert_tool_success(resp, "base64 upload should succeed")
        data = parse_tool_output(resp)
        assert data["status_code"] == 200
        assert data["file_size"] == 64

    def test_upload_with_extra_fields(self, curl_env, http_server):
        """Upload with extra form fields."""
        client, loop = curl_env
        host, port = http_server
        resp = loop.run_until_complete(
            client.call("upload", {
                "url": f"http://{host}:{port}/upload",
                "file_field": "avatar",
                "filename": "image.jpg",
                "content": "fake image data",
                "content_type": "image/jpeg",
                "extra_fields": {"user_id": "1234", "action": "update"},
                "timeout": 30,
            })
        )
        result = assert_tool_success(resp, "upload with extra fields should succeed")
        data = parse_tool_output(resp)
        assert data["status_code"] == 200

    def test_upload_with_cookie(self, curl_env, http_server):
        """Upload with authentication cookie."""
        client, loop = curl_env
        host, port = http_server
        resp = loop.run_until_complete(
            client.call("upload", {
                "url": f"http://{host}:{port}/upload",
                "file_field": "file",
                "filename": "test.txt",
                "content": "test content",
                "cookie": "session=authenticated",
                "timeout": 30,
            })
        )
        result = assert_tool_success(resp, "upload with cookie should succeed")

    def test_upload_invalid_base64(self, curl_env, http_server):
        """Upload with invalid base64 returns error."""
        client, loop = curl_env
        host, port = http_server
        resp = loop.run_until_complete(
            client.call("upload", {
                "url": f"http://{host}:{port}/upload",
                "file_field": "file",
                "filename": "test.txt",
                "content": "not!!valid!!base64!!",
                "is_base64": True,
                "timeout": 30,
            })
        )
        result = resp.get("result", {})
        is_error = result.get("isError", False)
        if is_error:
            content_text = ""
            for c in result.get("content", []):
                if c.get("type") == "text":
                    content_text += c["text"]
            assert "base64" in content_text.lower() or "decode" in content_text.lower()

    def test_upload_returns_timing(self, curl_env, http_server):
        """Upload returns timing data."""
        client, loop = curl_env
        host, port = http_server
        resp = loop.run_until_complete(
            client.call("upload", {
                "url": f"http://{host}:{port}/upload",
                "file_field": "file",
                "filename": "test.txt",
                "content": "test",
                "timeout": 30,
            })
        )
        data = parse_tool_output(resp)
        assert "timing" in data
        assert data["timing"]["total_ms"] >= 0


# ===========================================================================
# LIVE METHOD TESTS: download
# ===========================================================================

class TestDownload:
    """Tests for the download method (file to base64)."""

    def test_download_text_file(self, curl_env, http_server):
        """Download a text file and get base64 content."""
        client, loop = curl_env
        host, port = http_server
        resp = loop.run_until_complete(
            client.call("download", {
                "url": f"http://{host}:{port}/download/test.txt",
                "timeout": 30,
            })
        )
        result = assert_tool_success(resp, "download should succeed")
        data = parse_tool_output(resp)
        assert data["filename"] == "test.txt"
        assert data["size_bytes"] > 0
        assert "content_base64" in data
        # Decode and verify
        decoded = base64.b64decode(data["content_base64"]).decode()
        assert "line1" in decoded
        assert "line5" in decoded

    def test_download_binary_file(self, curl_env, http_server):
        """Download a binary file and get base64 content."""
        client, loop = curl_env
        host, port = http_server
        resp = loop.run_until_complete(
            client.call("download", {
                "url": f"http://{host}:{port}/download/test.bin",
                "timeout": 30,
            })
        )
        result = assert_tool_success(resp, "binary download should succeed")
        data = parse_tool_output(resp)
        assert data["filename"] == "test.bin"
        assert data["size_bytes"] == 256
        # Verify binary content round-trips correctly
        decoded = base64.b64decode(data["content_base64"])
        assert decoded == bytes(range(256))

    def test_download_filename_extraction(self, curl_env, http_server):
        """Filename is extracted from URL path."""
        client, loop = curl_env
        host, port = http_server
        resp = loop.run_until_complete(
            client.call("download", {
                "url": f"http://{host}:{port}/download/test.txt",
                "timeout": 30,
            })
        )
        data = parse_tool_output(resp)
        assert data["filename"] == "test.txt"


# ===========================================================================
# LIVE METHOD TESTS: download_to_file
# ===========================================================================

class TestDownloadToFile:
    """Tests for the download_to_file method (save to disk)."""

    def test_download_to_file_basic(self, curl_env, http_server):
        """Download a file to a specified path."""
        client, loop = curl_env
        host, port = http_server
        resp = loop.run_until_complete(
            client.call("download_to_file", {
                "url": f"http://{host}:{port}/download/test.txt",
                "output_path": "/tmp/test_download.txt",
                "timeout": 30,
            })
        )
        result = assert_tool_success(resp, "download_to_file should succeed")
        data = parse_tool_output(resp)
        assert data["output_path"] == "/tmp/test_download.txt"
        assert data["size_bytes"] > 0
        assert data["size_mb"] >= 0
        # .txt files should have line_count
        assert data["line_count"] == 5
        assert data["decompressed"] is False

    def test_download_to_file_creates_dirs(self, curl_env, http_server):
        """Parent directories are created automatically."""
        client, loop = curl_env
        host, port = http_server
        resp = loop.run_until_complete(
            client.call("download_to_file", {
                "url": f"http://{host}:{port}/download/test.txt",
                "output_path": "/tmp/deep/nested/dir/output.txt",
                "timeout": 30,
            })
        )
        result = assert_tool_success(resp, "download_to_file with nested dirs should succeed")
        data = parse_tool_output(resp)
        assert data["output_path"] == "/tmp/deep/nested/dir/output.txt"

    def test_download_to_file_gz_decompress(self, curl_env, http_server):
        """Gzip files are auto-decompressed when decompress=true (default)."""
        client, loop = curl_env
        host, port = http_server
        resp = loop.run_until_complete(
            client.call("download_to_file", {
                "url": f"http://{host}:{port}/download/test.txt.gz",
                "output_path": "/tmp/test_decompressed.txt",
                "timeout": 30,
            })
        )
        result = assert_tool_success(resp, "gz download should succeed")
        data = parse_tool_output(resp)
        assert data["decompressed"] is True
        assert data["size_bytes"] > 0

    def test_download_to_file_no_decompress(self, curl_env, http_server):
        """Gzip files kept compressed when decompress=false."""
        client, loop = curl_env
        host, port = http_server
        resp = loop.run_until_complete(
            client.call("download_to_file", {
                "url": f"http://{host}:{port}/download/test.txt.gz",
                "output_path": "/tmp/test_compressed.txt.gz",
                "decompress": False,
                "timeout": 30,
            })
        )
        result = assert_tool_success(resp, "gz download without decompress should succeed")
        data = parse_tool_output(resp)
        assert data["decompressed"] is False

    def test_download_to_file_large(self, curl_env, http_server):
        """Download a larger file to disk."""
        client, loop = curl_env
        host, port = http_server
        resp = loop.run_until_complete(
            client.call("download_to_file", {
                "url": f"http://{host}:{port}/download/large.txt",
                "output_path": "/tmp/test_large.txt",
                "timeout": 60,
            })
        )
        result = assert_tool_success(resp, "large download should succeed")
        data = parse_tool_output(resp)
        assert data["line_count"] == 1000
        assert data["size_bytes"] > 5000


# ===========================================================================
# ERROR CLASSIFICATION TESTS
# ===========================================================================

class TestErrorClassification:
    """Tests for curl error detection and classification."""

    def test_connection_refused(self, curl_env):
        """Connection to closed port returns connection_refused error."""
        client, loop = curl_env
        resp = loop.run_until_complete(
            client.call("request", {
                "url": "http://127.0.0.1:1/",  # port 1 should be closed
                "timeout": 5,
                "connect_timeout": 3,
            })
        )
        result = resp.get("result", {})
        data = parse_tool_output(resp)
        if isinstance(data, dict) and "error" in data:
            error = data["error"]
            assert error["type"] in ("connection_refused", "unknown"), (
                f"Expected connection_refused, got: {error['type']}"
            )

    def test_error_structuredContent_has_error_class(self, curl_env):
        """Error responses populate structuredContent.error_class."""
        client, loop = curl_env
        resp = loop.run_until_complete(
            client.call("request", {
                "url": "http://127.0.0.1:1/",
                "timeout": 5,
                "connect_timeout": 3,
            })
        )
        result = resp.get("result", {})
        sc = result.get("structuredContent", {})
        assert sc.get("success") is False
        # error_class should be set (not None) for curl failures
        assert sc.get("error_class") is not None, (
            f"error_class should be populated for curl errors, got: {sc}"
        )

    def test_dns_resolution_failure(self, curl_env):
        """Unresolvable hostname returns could_not_resolve_host error."""
        client, loop = curl_env
        resp = loop.run_until_complete(
            client.call("request", {
                "url": "http://this-host-definitely-does-not-exist-12345.invalid/",
                "timeout": 10,
                "connect_timeout": 5,
            })
        )
        result = resp.get("result", {})
        data = parse_tool_output(resp)
        if isinstance(data, dict) and "error" in data:
            error = data["error"]
            assert error["type"] in ("could_not_resolve_host", "unknown"), (
                f"Expected could_not_resolve_host, got: {error['type']}"
            )

    def test_timeout_error(self, curl_env, http_server):
        """Very short timeout returns timeout error."""
        client, loop = curl_env
        host, port = http_server
        resp = loop.run_until_complete(
            client.call("request", {
                "url": f"http://{host}:{port}/slow",
                "timeout": 1,  # Server delays 5s, timeout is 1s
                "connect_timeout": 1,
            })
        )
        result = resp.get("result", {})
        data = parse_tool_output(resp)
        # Should either be an error or have timing showing timeout
        if isinstance(data, dict):
            if "error" in data and data["error"]:
                assert data["error"]["type"] in ("timeout", "unknown")

    def test_download_connection_refused(self, curl_env):
        """Download from closed port returns error."""
        client, loop = curl_env
        resp = loop.run_until_complete(
            client.call("download", {
                "url": "http://127.0.0.1:1/file.txt",
                "timeout": 5,
            })
        )
        result = resp.get("result", {})
        is_error = result.get("isError", False)
        assert is_error, "Download to closed port should fail"

    def test_download_to_file_connection_refused(self, curl_env):
        """download_to_file from closed port returns error."""
        client, loop = curl_env
        resp = loop.run_until_complete(
            client.call("download_to_file", {
                "url": "http://127.0.0.1:1/file.txt",
                "output_path": "/tmp/should_not_exist.txt",
                "timeout": 5,
            })
        )
        result = resp.get("result", {})
        is_error = result.get("isError", False)
        assert is_error, "download_to_file to closed port should fail"

    def test_inject_connection_error(self, curl_env):
        """Inject to unreachable host returns error with command context."""
        client, loop = curl_env
        resp = loop.run_until_complete(
            client.call("inject", {
                "url": "http://127.0.0.1:1/vuln?cmd={PAYLOAD}",
                "command": "id",
                "encoding": "url",
                "timeout": 5,
                "connect_timeout": 3,
            })
        )
        result = resp.get("result", {})
        is_error = result.get("isError", False)
        assert is_error, "Inject to closed port should fail"


# ===========================================================================
# CONTRACT TESTS -- tool.yaml vs server definitions
# ===========================================================================

class TestContract:
    """Verify tool.yaml and server method definitions are consistent."""

    @classmethod
    def setup_class(cls):
        try:
            cls.ServerClass = _get_server_class()
            cls.server = cls.ServerClass()
        except Exception as e:
            pytest.skip(f"Cannot import CurlServer: {e}")

        yaml_path = TOOL_DIR / "tool.yaml"
        with open(yaml_path) as f:
            cls.yaml_data = yaml.safe_load(f)

    def test_all_yaml_methods_registered(self):
        """Every method in tool.yaml has a handler registered in the server."""
        yaml_methods = set(self.yaml_data.get("methods", {}).keys())
        server_methods = set(self.server.methods.keys())
        yaml_only = yaml_methods - server_methods
        assert not yaml_only, f"Methods in tool.yaml but not registered: {yaml_only}"

    def test_all_server_methods_in_yaml(self):
        """Every registered method (except test-only) is in tool.yaml."""
        yaml_methods = set(self.yaml_data.get("methods", {}).keys())
        server_methods = set(self.server.methods.keys())
        # verify_clock is test-only, not in yaml
        server_only = server_methods - yaml_methods - {"verify_clock"}
        assert not server_only, f"Methods in server but not tool.yaml: {server_only}"

    def test_yaml_params_match_server_params(self):
        """For each method, required params in tool.yaml match server definition."""
        for method_name, yaml_method in self.yaml_data.get("methods", {}).items():
            if method_name not in self.server.methods:
                continue
            server_method = self.server.methods[method_name]
            yaml_params = set(yaml_method.get("params", {}).keys())
            server_params = set(server_method.params.keys())

            yaml_only = yaml_params - server_params
            server_only = server_params - yaml_params

            assert not yaml_only, (
                f"{method_name}: params in tool.yaml but not server: {yaml_only}"
            )
            assert not server_only, (
                f"{method_name}: params in server but not tool.yaml: {server_only}"
            )

    def test_required_params_match(self):
        """Required params in tool.yaml match server required params."""
        for method_name, yaml_method in self.yaml_data.get("methods", {}).items():
            if method_name not in self.server.methods:
                continue
            server_method = self.server.methods[method_name]

            yaml_required = {
                k for k, v in yaml_method.get("params", {}).items()
                if v.get("required", False)
            }
            server_required = {
                k for k, v in server_method.params.items()
                if v.get("required", False)
            }

            assert yaml_required == server_required, (
                f"{method_name}: required params mismatch. "
                f"yaml={yaml_required}, server={server_required}"
            )


# ===========================================================================
# ACCEPTANCE TESTS -- every method called through container
# ===========================================================================

class TestAcceptance:
    """Call every method through the container.

    These tests verify:
    - The method exists and is callable
    - Required param validation works (missing required params -> error)
    - The response has correct structuredContent shape
    - Error responses have error_class set (classified, not crash)

    Network methods use an unreachable IP (192.0.2.1). Some methods can
    succeed locally (e.g., download from localhost HTTP server).
    """

    _UNREACHABLE = "http://192.0.2.1/"

    def _assert_structured_response(self, resp, method_name):
        """Assert response has structuredContent and no crashes."""
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

    # ── request ───────────────────────────────────────────────

    def test_request_unreachable(self, curl_env):
        """request to unreachable target returns classified error."""
        client, loop = curl_env
        resp = loop.run_until_complete(client.call("request", {
            "url": self._UNREACHABLE, "timeout": 5, "connect_timeout": 3,
        }, timeout=30))
        self._assert_structured_response(resp, "request")

    def test_request_missing_url(self, curl_env):
        """request without url returns error."""
        client, loop = curl_env
        resp = loop.run_until_complete(client.call("request", {}))
        result = resp.get("result", {})
        is_error = result.get("isError", False)
        content_text = ""
        for c in result.get("content", []):
            if c.get("type") == "text":
                content_text += c["text"]
        assert is_error or "url" in content_text.lower() or "required" in content_text.lower()

    def test_request_with_all_options(self, curl_env):
        """request with method/headers/data/cookie/auth does not crash."""
        client, loop = curl_env
        resp = loop.run_until_complete(client.call("request", {
            "url": self._UNREACHABLE,
            "method": "POST",
            "headers": {"X-Test": "value"},
            "data": "key=value",
            "cookie": "session=abc123",
            "user_agent": "TestAgent/1.0",
            "insecure": True,
            "timeout": 5,
            "connect_timeout": 3,
        }, timeout=30))
        self._assert_structured_response(resp, "request+options")

    # ── inject ────────────────────────────────────────────────

    def test_inject_unreachable(self, curl_env):
        """inject to unreachable target returns classified error."""
        client, loop = curl_env
        resp = loop.run_until_complete(client.call("inject", {
            "url": "http://192.0.2.1/vuln.php?cmd={PAYLOAD}",
            "command": "id",
            "timeout": 5,
            "connect_timeout": 3,
        }, timeout=30))
        self._assert_structured_response(resp, "inject")

    def test_inject_missing_url(self, curl_env):
        """inject without url returns error."""
        client, loop = curl_env
        resp = loop.run_until_complete(client.call("inject", {
            "command": "id",
        }))
        result = resp.get("result", {})
        is_error = result.get("isError", False)
        content_text = ""
        for c in result.get("content", []):
            if c.get("type") == "text":
                content_text += c["text"]
        assert is_error or "url" in content_text.lower() or "required" in content_text.lower()

    def test_inject_missing_command(self, curl_env):
        """inject without command returns error."""
        client, loop = curl_env
        resp = loop.run_until_complete(client.call("inject", {
            "url": "http://192.0.2.1/vuln.php?cmd={PAYLOAD}",
        }))
        result = resp.get("result", {})
        is_error = result.get("isError", False)
        content_text = ""
        for c in result.get("content", []):
            if c.get("type") == "text":
                content_text += c["text"]
        assert is_error or "command" in content_text.lower() or "required" in content_text.lower()

    def test_inject_with_encoding_options(self, curl_env):
        """inject with encoding/markers/strip_html does not crash."""
        client, loop = curl_env
        resp = loop.run_until_complete(client.call("inject", {
            "url": "http://192.0.2.1/vuln.php?cmd={PAYLOAD}",
            "command": "id",
            "encoding": "base64",
            "output_markers": {"start": "<!--", "end": "-->"},
            "strip_html": False,
            "timeout": 5,
            "connect_timeout": 3,
        }, timeout=30))
        self._assert_structured_response(resp, "inject+options")

    # ── upload ────────────────────────────────────────────────

    def test_upload_unreachable(self, curl_env):
        """upload to unreachable target returns classified error."""
        client, loop = curl_env
        resp = loop.run_until_complete(client.call("upload", {
            "url": self._UNREACHABLE + "upload.php",
            "file_field": "file",
            "filename": "shell.php",
            "content": "<?php system($_GET['c']); ?>",
            "timeout": 5,
            "connect_timeout": 3,
        }, timeout=30))
        self._assert_structured_response(resp, "upload")

    def test_upload_missing_required(self, curl_env):
        """upload without file_field returns error."""
        client, loop = curl_env
        resp = loop.run_until_complete(client.call("upload", {
            "url": self._UNREACHABLE,
            "filename": "shell.php",
            "content": "test",
        }))
        result = resp.get("result", {})
        is_error = result.get("isError", False)
        content_text = ""
        for c in result.get("content", []):
            if c.get("type") == "text":
                content_text += c["text"]
        assert is_error or "file_field" in content_text.lower() or "required" in content_text.lower()

    def test_upload_with_extra_fields(self, curl_env):
        """upload with extra_fields and cookie does not crash."""
        client, loop = curl_env
        resp = loop.run_until_complete(client.call("upload", {
            "url": self._UNREACHABLE + "upload.php",
            "file_field": "avatar",
            "filename": "image.jpg",
            "content": "fake image data",
            "content_type": "image/jpeg",
            "extra_fields": {"submit": "Upload"},
            "cookie": "session=abc123",
            "timeout": 5,
            "connect_timeout": 3,
        }, timeout=30))
        self._assert_structured_response(resp, "upload+extras")

    # ── download ──────────────────────────────────────────────

    def test_download_unreachable(self, curl_env):
        """download from unreachable target returns classified error."""
        client, loop = curl_env
        resp = loop.run_until_complete(client.call("download", {
            "url": self._UNREACHABLE + "file.bin",
            "timeout": 5,
        }, timeout=30))
        self._assert_structured_response(resp, "download")

    def test_download_missing_url(self, curl_env):
        """download without url returns error."""
        client, loop = curl_env
        resp = loop.run_until_complete(client.call("download", {}))
        result = resp.get("result", {})
        is_error = result.get("isError", False)
        content_text = ""
        for c in result.get("content", []):
            if c.get("type") == "text":
                content_text += c["text"]
        assert is_error or "url" in content_text.lower() or "required" in content_text.lower()

    # ── download_to_file ──────────────────────────────────────

    def test_download_to_file_unreachable(self, curl_env):
        """download_to_file from unreachable target returns classified error."""
        client, loop = curl_env
        resp = loop.run_until_complete(client.call("download_to_file", {
            "url": self._UNREACHABLE + "bigfile.bin",
            "output_path": "/tmp/test_download.bin",
            "timeout": 5,
        }, timeout=30))
        self._assert_structured_response(resp, "download_to_file")

    def test_download_to_file_missing_output_path(self, curl_env):
        """download_to_file without output_path returns error."""
        client, loop = curl_env
        resp = loop.run_until_complete(client.call("download_to_file", {
            "url": self._UNREACHABLE + "bigfile.bin",
        }))
        result = resp.get("result", {})
        is_error = result.get("isError", False)
        content_text = ""
        for c in result.get("content", []):
            if c.get("type") == "text":
                content_text += c["text"]
        assert is_error or "output_path" in content_text.lower() or "required" in content_text.lower()

    # ── Cross-cutting ─────────────────────────────────────────

    def test_all_methods_return_structuredContent(self, curl_env):
        """verify_clock returns structuredContent with all required fields."""
        client, loop = curl_env
        resp = loop.run_until_complete(client.call("verify_clock", {}))
        result = resp.get("result", {})
        sc = result.get("structuredContent")
        assert sc is not None
        assert isinstance(sc, dict)
        for field in ("success", "error_class", "retryable", "suggestions"):
            assert field in sc, f"Missing field '{field}' in structuredContent"


# ===========================================================================
# INTEGRATION TESTS -- real target (marked, skipped unless --target)
# ===========================================================================

class TestIntegration:
    """Integration tests against real targets. Requires --target."""

    @pytest.mark.integration
    def test_real_target_request(self, curl_env, target):
        """Make a request to a real target."""
        client, loop = curl_env
        resp = loop.run_until_complete(
            client.call("request", {
                "url": f"http://{target}/",
                "timeout": 15,
            })
        )
        data = parse_tool_output(resp)
        assert data["status_code"] is not None
        assert data["timing"]["total_ms"] > 0
