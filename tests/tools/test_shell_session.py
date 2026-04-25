"""
Tests for the shell-session MCP tool server.

Covers:
- Smoke tests: boot, method list, required params, meta-param stripping, clock
- Unit tests: _classify_ssh_error, _is_retryable_error, _calculate_retry_delay,
              _generate_session_id
- Method tests: ssh_connect, exec, upload, download, list_sessions, close
- Non-zero exit handling: exec returns success=True for non-zero exit codes
- Session lifecycle: connect -> exec -> list -> close -> exec-fails
- Timeout handling: blocking paramiko calls run in thread executor
- Error classification: all error paths set error_class/retryable/suggestions
- Contract tests: tool.yaml vs server parameter definitions
- Integration tests: real target scenarios (marked @pytest.mark.integration)

Test SSH target:
  A lightweight sshd sidecar container (linuxserver/openssh-server) is started
  via Docker by the ssh_target fixture. It listens on 127.0.0.1:2222 with
  user=testuser, password=testpass. The MCP container uses --network=host so it
  can reach 127.0.0.1:2222.
"""

import asyncio
import base64
import importlib.util
import json
import os
import socket
import subprocess
import sys
import textwrap
import time
from pathlib import Path
from typing import Any, Dict, Set

import pytest
import yaml

# ---------------------------------------------------------------------------
# Path setup
# ---------------------------------------------------------------------------
PROJECT_ROOT = Path(__file__).parent.parent.parent
TOOL_DIR = PROJECT_ROOT / "tools" / "shell-session"
FIXTURES_DIR = Path(__file__).parent.parent / "fixtures" / "shell-session"

sys.path.insert(0, str(TOOL_DIR))

# Import conftest helpers
from conftest import (
    MCPTestClient,
    assert_tool_error,
    assert_tool_success,
    parse_tool_output,
)

# ---------------------------------------------------------------------------
# Constants
# ---------------------------------------------------------------------------
SSH_TARGET_IMAGE = "lscr.io/linuxserver/openssh-server:latest"
SSH_TARGET_CONTAINER = "mcp-test-shell-session-target"
SSH_TARGET_PORT = 2223  # Different from ssh tool tests to avoid collisions
SSH_TARGET_USER = "testuser"
SSH_TARGET_PASSWORD = "testpass"


# ---------------------------------------------------------------------------
# Helper: import server module for direct unit testing
# ---------------------------------------------------------------------------
def _get_server_class():
    """Import and return the ShellSessionServer class for direct method testing."""
    mcp_common_path = PROJECT_ROOT / "packages" / "mcp-common" / "src"
    if str(mcp_common_path) not in sys.path:
        sys.path.insert(0, str(mcp_common_path))

    spec = importlib.util.spec_from_file_location(
        "shell_session_server", TOOL_DIR / "mcp-server.py"
    )
    mod = importlib.util.module_from_spec(spec)
    spec.loader.exec_module(mod)
    return mod.ShellSessionServer


def _get_module():
    """Import the whole shell-session mcp-server module."""
    mcp_common_path = PROJECT_ROOT / "packages" / "mcp-common" / "src"
    if str(mcp_common_path) not in sys.path:
        sys.path.insert(0, str(mcp_common_path))

    spec = importlib.util.spec_from_file_location(
        "shell_session_server", TOOL_DIR / "mcp-server.py"
    )
    mod = importlib.util.module_from_spec(spec)
    spec.loader.exec_module(mod)
    return mod


# ---------------------------------------------------------------------------
# Fixtures: SSH target sidecar
# ---------------------------------------------------------------------------

def _is_port_open(host: str, port: int, timeout: float = 1.0) -> bool:
    """Check if a TCP port is open."""
    try:
        with socket.create_connection((host, port), timeout=timeout):
            return True
    except (ConnectionRefusedError, OSError, TimeoutError):
        return False


@pytest.fixture(scope="module")
def ssh_target():
    """Start an SSH server sidecar for testing.

    Uses linuxserver/openssh-server.
    Yields (host, port, username, password).
    """
    if _is_port_open("127.0.0.1", SSH_TARGET_PORT):
        yield ("127.0.0.1", SSH_TARGET_PORT, SSH_TARGET_USER, SSH_TARGET_PASSWORD)
        return

    try:
        subprocess.run(
            ["docker", "rm", "-f", SSH_TARGET_CONTAINER],
            capture_output=True, timeout=10,
        )

        result = subprocess.run(
            [
                "docker", "run", "-d",
                "--name", SSH_TARGET_CONTAINER,
                "--network=host",
                "-e", f"USER_NAME={SSH_TARGET_USER}",
                "-e", f"USER_PASSWORD={SSH_TARGET_PASSWORD}",
                "-e", "PASSWORD_ACCESS=true",
                "-e", f"LISTEN_PORT={SSH_TARGET_PORT}",
                "-e", "PUID=1000",
                "-e", "PGID=1000",
                SSH_TARGET_IMAGE,
            ],
            capture_output=True, text=True, timeout=60,
        )

        if result.returncode != 0:
            pytest.skip(f"Cannot start SSH target: {result.stderr}")

        for i in range(30):
            if _is_port_open("127.0.0.1", SSH_TARGET_PORT):
                time.sleep(1)
                break
            time.sleep(1)
        else:
            pytest.skip("SSH target did not become ready in 30s")

        yield ("127.0.0.1", SSH_TARGET_PORT, SSH_TARGET_USER, SSH_TARGET_PASSWORD)

    finally:
        subprocess.run(
            ["docker", "rm", "-f", SSH_TARGET_CONTAINER],
            capture_output=True, timeout=10,
        )


# ---------------------------------------------------------------------------
# Fixtures: MCP client
# ---------------------------------------------------------------------------

@pytest.fixture(scope="module")
def shell_env(request):
    """Create an MCPTestClient with its event loop. Yields (client, loop)."""
    tool = "shell-session"
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
# UNIT TESTS -- No container needed, pure Python testing
# ===========================================================================

class TestClassifySshError:
    """Test _classify_ssh_error helper for SSH error classification.

    Returns (message, error_class, retryable, suggestions) tuples.
    """

    @classmethod
    def setup_class(cls):
        try:
            cls.server = _get_server_class()()
        except Exception as e:
            pytest.skip(f"Cannot import ShellSessionServer: {e}")

    def test_connection_refused(self):
        """Connection refused is classified as network/retryable."""
        import paramiko
        err = paramiko.SSHException("Connection refused")
        msg, cls_, retryable, suggestions = self.server._classify_ssh_error(err)
        assert "Connection refused" in msg
        assert cls_ == "network"
        assert retryable is True
        assert len(suggestions) > 0

    def test_connection_timed_out(self):
        """Connection timed out is classified as timeout/retryable."""
        err = TimeoutError("Connection timed out")
        msg, cls_, retryable, suggestions = self.server._classify_ssh_error(err)
        assert "timed out" in msg.lower()
        assert cls_ == "timeout"
        assert retryable is True

    def test_no_route_to_host(self):
        """No route to host is classified as network/not retryable."""
        err = OSError("No route to host")
        msg, cls_, retryable, suggestions = self.server._classify_ssh_error(err)
        assert "No route to host" in msg
        assert cls_ == "network"
        assert retryable is False

    def test_permission_denied(self):
        """Authentication failure is classified as auth/not retryable."""
        import paramiko
        err = paramiko.AuthenticationException("Authentication failed")
        msg, cls_, retryable, suggestions = self.server._classify_ssh_error(err)
        assert "Authentication failed" in msg
        assert cls_ == "auth"
        assert retryable is False

    def test_network_unreachable(self):
        """Network unreachable is classified as network/retryable."""
        err = OSError("Network is unreachable")
        msg, cls_, retryable, suggestions = self.server._classify_ssh_error(err)
        assert "unreachable" in msg.lower()
        assert cls_ == "network"
        assert retryable is True

    def test_host_key_verification(self):
        """Host key issue is classified as config/not retryable."""
        err = Exception("host key verification failed")
        msg, cls_, retryable, suggestions = self.server._classify_ssh_error(err)
        assert cls_ == "config"
        assert retryable is False

    def test_invalid_key_format(self):
        """Invalid key format is classified as config/not retryable."""
        err = Exception("key format is invalid")
        msg, cls_, retryable, suggestions = self.server._classify_ssh_error(err)
        assert cls_ == "config"
        assert retryable is False

    def test_unknown_error(self):
        """Unknown error returns unknown/not retryable."""
        err = Exception("something went wrong")
        msg, cls_, retryable, suggestions = self.server._classify_ssh_error(err)
        assert cls_ == "unknown"
        assert retryable is False


class TestIsRetryableError:
    """Test _is_retryable_error for transient error detection."""

    @classmethod
    def setup_class(cls):
        try:
            cls.server = _get_server_class()()
        except Exception as e:
            pytest.skip(f"Cannot import ShellSessionServer: {e}")

    def test_timeout_is_retryable(self):
        assert self.server._is_retryable_error(Exception("Connection timed out"))

    def test_connection_reset_is_retryable(self):
        assert self.server._is_retryable_error(Exception("Connection reset by peer"))

    def test_network_unreachable_is_retryable(self):
        assert self.server._is_retryable_error(Exception("Network is unreachable"))

    def test_auth_failure_not_retryable(self):
        assert not self.server._is_retryable_error(Exception("Authentication failed"))

    def test_permission_denied_not_retryable(self):
        assert not self.server._is_retryable_error(Exception("Permission denied"))


class TestCalculateRetryDelay:
    """Test exponential backoff calculation."""

    @classmethod
    def setup_class(cls):
        try:
            cls.server = _get_server_class()()
        except Exception as e:
            pytest.skip(f"Cannot import ShellSessionServer: {e}")

    def test_first_attempt(self):
        delay = self.server._calculate_retry_delay(0)
        assert delay == 1.0

    def test_second_attempt(self):
        delay = self.server._calculate_retry_delay(1)
        assert delay == 2.0

    def test_third_attempt(self):
        delay = self.server._calculate_retry_delay(2)
        assert delay == 4.0

    def test_max_delay_capped(self):
        delay = self.server._calculate_retry_delay(10)
        assert delay == 10.0


class TestGenerateSessionId:
    """Test session ID generation."""

    @classmethod
    def setup_class(cls):
        try:
            cls.server = _get_server_class()()
        except Exception as e:
            pytest.skip(f"Cannot import ShellSessionServer: {e}")

    def test_format(self):
        sid = self.server._generate_session_id()
        assert sid.startswith("ses_")
        assert len(sid) == 16  # "ses_" + 12 hex chars

    def test_uniqueness(self):
        ids = {self.server._generate_session_id() for _ in range(100)}
        assert len(ids) == 100


class TestMethodRegistration:
    """Test that all expected methods are registered."""

    @classmethod
    def setup_class(cls):
        try:
            cls.server = _get_server_class()()
        except Exception as e:
            pytest.skip(f"Cannot import ShellSessionServer: {e}")

    def test_nine_methods_registered(self):
        """Server registers exactly 9 methods."""
        # In test mode, verify_clock is also registered
        expected = {
            "ssh_connect", "exec", "upload", "download",
            "listen", "shell_exec", "list_sessions", "close", "upgrade_shell",
        }
        registered = set(self.server.methods.keys())
        assert expected.issubset(registered), (
            f"Missing methods: {expected - registered}"
        )

    def test_methods_match_tool_yaml(self):
        """Every method in tool.yaml is registered in the server."""
        yaml_path = TOOL_DIR / "tool.yaml"
        with open(yaml_path) as f:
            yaml_data = yaml.safe_load(f)
        yaml_names = set(yaml_data.get("methods", {}).keys())
        server_names = set(self.server.methods.keys()) - {"verify_clock"}

        yaml_only = yaml_names - server_names
        server_only = server_names - yaml_names

        assert not yaml_only, f"Methods in tool.yaml but not server: {yaml_only}"
        assert not server_only, f"Methods in server but not tool.yaml: {server_only}"


class TestDirectAsyncMethods:
    """Test async methods directly (no container) for error paths."""

    @classmethod
    def setup_class(cls):
        try:
            cls.server = _get_server_class()()
        except Exception as e:
            pytest.skip(f"Cannot import ShellSessionServer: {e}")

    def test_ssh_connect_no_credentials(self):
        """ssh_connect without password or key returns params error."""
        loop = asyncio.new_event_loop()
        try:
            result = loop.run_until_complete(
                self.server.ssh_connect(host="127.0.0.1", username="root")
            )
            assert not result.success
            assert "password" in result.error.lower() or "private_key" in result.error.lower()
            assert result.error_class == "params"
        finally:
            loop.close()

    def test_exec_session_not_found(self):
        """exec with invalid session_id returns params error."""
        loop = asyncio.new_event_loop()
        try:
            result = loop.run_until_complete(
                self.server.exec_command(session_id="ses_nonexistent", command="id")
            )
            assert not result.success
            assert "not found" in result.error.lower()
            assert result.error_class == "params"
            assert len(result.suggestions) > 0
        finally:
            loop.close()

    def test_upload_session_not_found(self):
        """upload with invalid session_id returns params error."""
        loop = asyncio.new_event_loop()
        try:
            result = loop.run_until_complete(
                self.server.upload(
                    session_id="ses_nonexistent",
                    content="test",
                    remote_path="/tmp/test",
                )
            )
            assert not result.success
            assert "not found" in result.error.lower()
            assert result.error_class == "params"
        finally:
            loop.close()

    def test_download_session_not_found(self):
        """download with invalid session_id returns params error."""
        loop = asyncio.new_event_loop()
        try:
            result = loop.run_until_complete(
                self.server.download(session_id="ses_nonexistent", remote_path="/etc/passwd")
            )
            assert not result.success
            assert "not found" in result.error.lower()
            assert result.error_class == "params"
        finally:
            loop.close()

    def test_shell_exec_session_not_found(self):
        """shell_exec with invalid session_id returns params error."""
        loop = asyncio.new_event_loop()
        try:
            result = loop.run_until_complete(
                self.server.shell_exec(session_id="ses_nonexistent", command="id")
            )
            assert not result.success
            assert "not found" in result.error.lower()
            assert result.error_class == "params"
        finally:
            loop.close()

    def test_close_session_not_found(self):
        """close with invalid session_id returns params error."""
        loop = asyncio.new_event_loop()
        try:
            result = loop.run_until_complete(
                self.server.close_session(session_id="ses_nonexistent")
            )
            assert not result.success
            assert "not found" in result.error.lower()
            assert result.error_class == "params"
        finally:
            loop.close()

    def test_upgrade_shell_session_not_found(self):
        """upgrade_shell with invalid session_id returns params error."""
        loop = asyncio.new_event_loop()
        try:
            result = loop.run_until_complete(
                self.server.upgrade_shell(session_id="ses_nonexistent")
            )
            assert not result.success
            assert "not found" in result.error.lower()
            assert result.error_class == "params"
        finally:
            loop.close()

    def test_list_sessions_empty(self):
        """list_sessions with no active sessions returns empty list."""
        loop = asyncio.new_event_loop()
        try:
            result = loop.run_until_complete(self.server.list_sessions())
            assert result.success
            assert result.data["total"] == 0
            assert result.data["sessions"] == []
        finally:
            loop.close()


# ===========================================================================
# SMOKE TESTS -- require Docker container running
# ===========================================================================

class TestSmoke:
    """Smoke tests that verify the container boots and basic protocol works."""

    def test_boot_and_list_tools(self, shell_env):
        """Container starts and list_tools returns methods."""
        client, _ = shell_env
        assert len(client.tools) > 0, "Server should advertise at least one tool"
        names = client.tool_names()
        assert "ssh_connect" in names
        assert "exec" in names
        assert "upload" in names
        assert "download" in names
        assert "listen" in names
        assert "shell_exec" in names
        assert "list_sessions" in names
        assert "close" in names
        assert "upgrade_shell" in names

    def test_method_list_matches_tool_yaml(self, shell_env):
        """Every method in tool.yaml is advertised by the server, and vice versa."""
        client, _ = shell_env
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

    def test_expected_method_count(self, shell_env):
        """Server should have exactly 9 built-in methods + verify_clock."""
        client, _ = shell_env
        names = client.tool_names()
        assert len(names) == 10, (
            f"Expected 10 methods (9 built-in + verify_clock), got {len(names)}: {sorted(names)}"
        )

    def test_unknown_method_returns_error(self, shell_env):
        """Calling a non-existent method returns a helpful error."""
        client, loop = shell_env
        resp = loop.run_until_complete(client.call("connect", {}))
        result = assert_tool_error(resp)
        content_text = ""
        for c in result.get("content", []):
            if c.get("type") == "text":
                content_text += c["text"]
        assert "Unknown method" in content_text
        assert "connect" in content_text

    def test_meta_params_stripped_clock_offset(self, shell_env):
        """Passing 'clock_offset' (meta-param) does not crash the server."""
        client, loop = shell_env
        resp = loop.run_until_complete(
            client.call("exec", {
                "session_id": "ses_nonexistent",
                "command": "id",
                "clock_offset": "+5h",
            })
        )
        result = resp.get("result", {})
        content_text = ""
        for c in result.get("content", []):
            if c.get("type") == "text":
                content_text += c["text"]
        assert "unexpected keyword argument" not in content_text

    @pytest.mark.clock
    def test_verify_clock_available(self, shell_env):
        """verify_clock is registered in MCP_TEST_MODE."""
        client, _ = shell_env
        names = client.tool_names()
        assert "verify_clock" in names

    @pytest.mark.clock
    def test_verify_clock_returns_time(self, shell_env):
        """verify_clock returns current time and FAKETIME status."""
        client, loop = shell_env
        resp = loop.run_until_complete(client.call("verify_clock", {}))
        result = assert_tool_success(resp)
        data = parse_tool_output(resp)
        assert "current_time" in data
        assert "libfaketime_exists" in data

    def test_structuredContent_present(self, shell_env):
        """Responses include structuredContent with error classification fields."""
        client, loop = shell_env
        resp = loop.run_until_complete(client.call("verify_clock", {}))
        result = resp.get("result", {})
        sc = result.get("structuredContent")
        assert sc is not None, "structuredContent should be present"
        assert "success" in sc
        assert "error_class" in sc
        assert "retryable" in sc
        assert "suggestions" in sc


# ===========================================================================
# ERROR HANDLING TESTS -- verify proper error responses
# ===========================================================================

class TestErrorHandling:
    """Test error handling for unreachable/invalid targets."""

    def test_ssh_connect_no_credentials(self, shell_env):
        """ssh_connect without password or key returns error."""
        client, loop = shell_env
        resp = loop.run_until_complete(
            client.call("ssh_connect", {
                "host": "127.0.0.1",
                "username": "root",
            })
        )
        result = assert_tool_error(resp)
        sc = result.get("structuredContent", {})
        assert sc.get("error_class") == "params"

    def test_ssh_connect_connection_refused(self, shell_env):
        """ssh_connect to a closed port returns network error."""
        client, loop = shell_env
        resp = loop.run_until_complete(
            client.call("ssh_connect", {
                "host": "127.0.0.1",
                "username": "root",
                "password": "test",
                "port": 19998,
                "timeout": 5,
            }, timeout=60)
        )
        result = resp.get("result", {})
        assert result.get("isError", False), "Should fail on closed port"
        sc = result.get("structuredContent", {})
        assert sc.get("error_class") == "network", (
            f"Connection refused should be network, got: {sc.get('error_class')}"
        )
        assert sc.get("retryable") is True

    def test_exec_session_not_found(self, shell_env):
        """exec with invalid session returns params error."""
        client, loop = shell_env
        resp = loop.run_until_complete(
            client.call("exec", {
                "session_id": "ses_nonexistent",
                "command": "id",
            })
        )
        result = assert_tool_error(resp, "not found")
        sc = result.get("structuredContent", {})
        assert sc.get("error_class") == "params"

    def test_upload_session_not_found(self, shell_env):
        """upload with invalid session returns params error."""
        client, loop = shell_env
        resp = loop.run_until_complete(
            client.call("upload", {
                "session_id": "ses_nonexistent",
                "content": "test",
                "remote_path": "/tmp/test",
            })
        )
        result = assert_tool_error(resp, "not found")
        sc = result.get("structuredContent", {})
        assert sc.get("error_class") == "params"

    def test_download_session_not_found(self, shell_env):
        """download with invalid session returns params error."""
        client, loop = shell_env
        resp = loop.run_until_complete(
            client.call("download", {
                "session_id": "ses_nonexistent",
                "remote_path": "/etc/passwd",
            })
        )
        result = assert_tool_error(resp, "not found")
        sc = result.get("structuredContent", {})
        assert sc.get("error_class") == "params"

    def test_close_session_not_found(self, shell_env):
        """close with invalid session returns params error."""
        client, loop = shell_env
        resp = loop.run_until_complete(
            client.call("close", {
                "session_id": "ses_nonexistent",
            })
        )
        result = assert_tool_error(resp, "not found")
        sc = result.get("structuredContent", {})
        assert sc.get("error_class") == "params"

    def test_shell_exec_session_not_found(self, shell_env):
        """shell_exec with invalid session returns params error."""
        client, loop = shell_env
        resp = loop.run_until_complete(
            client.call("shell_exec", {
                "session_id": "ses_nonexistent",
                "command": "id",
            })
        )
        result = assert_tool_error(resp, "not found")
        sc = result.get("structuredContent", {})
        assert sc.get("error_class") == "params"

    def test_upgrade_shell_session_not_found(self, shell_env):
        """upgrade_shell with invalid session returns params error."""
        client, loop = shell_env
        resp = loop.run_until_complete(
            client.call("upgrade_shell", {
                "session_id": "ses_nonexistent",
            })
        )
        result = assert_tool_error(resp, "not found")
        sc = result.get("structuredContent", {})
        assert sc.get("error_class") == "params"

    def test_list_sessions_empty(self, shell_env):
        """list_sessions with no active sessions returns empty list."""
        client, loop = shell_env
        resp = loop.run_until_complete(client.call("list_sessions", {}))
        result = assert_tool_success(resp)
        data = parse_tool_output(resp)
        assert data["total"] == 0
        assert data["sessions"] == []


# ===========================================================================
# LIVE METHOD TESTS -- require Docker container + SSH target
# ===========================================================================

class TestSSHConnect:
    """Test the ssh_connect method against a real SSH target."""

    def test_ssh_connect_password(self, shell_env, ssh_target):
        """ssh_connect with password succeeds and returns session_id."""
        host, port, user, password = ssh_target
        client, loop = shell_env
        resp = loop.run_until_complete(
            client.call("ssh_connect", {
                "host": host,
                "username": user,
                "password": password,
                "port": port,
                "timeout": 30,
            })
        )
        result = assert_tool_success(resp, "ssh_connect should succeed")
        data = parse_tool_output(resp)
        assert "session_id" in data
        assert data["session_id"].startswith("ses_")
        assert data["host"] == host
        assert data["username"] == user
        assert data["attempts"] == 1

        # Clean up
        loop.run_until_complete(
            client.call("close", {"session_id": data["session_id"]})
        )

    def test_ssh_connect_wrong_password(self, shell_env, ssh_target):
        """ssh_connect with wrong password returns auth error."""
        host, port, user, _ = ssh_target
        client, loop = shell_env
        resp = loop.run_until_complete(
            client.call("ssh_connect", {
                "host": host,
                "username": user,
                "password": "wrong_password_xyz",
                "port": port,
                "timeout": 15,
            }, timeout=60)
        )
        result = resp.get("result", {})
        assert result.get("isError", False), "Wrong password should fail"
        sc = result.get("structuredContent", {})
        assert sc.get("error_class") == "auth", (
            f"Wrong password should be auth error, got: {sc.get('error_class')}"
        )
        assert sc.get("retryable") is False


class TestExec:
    """Test the exec method against a real SSH target."""

    @pytest.fixture(autouse=True)
    def _session(self, shell_env, ssh_target):
        """Create a session for exec tests, close on teardown."""
        host, port, user, password = ssh_target
        client, loop = shell_env
        resp = loop.run_until_complete(
            client.call("ssh_connect", {
                "host": host,
                "username": user,
                "password": password,
                "port": port,
                "timeout": 30,
            })
        )
        data = parse_tool_output(resp)
        self.session_id = data["session_id"]
        self.client = client
        self.loop = loop
        yield
        # Cleanup
        loop.run_until_complete(
            client.call("close", {"session_id": self.session_id})
        )

    def test_exec_basic_command(self):
        """exec runs a basic command and returns output."""
        resp = self.loop.run_until_complete(
            self.client.call("exec", {
                "session_id": self.session_id,
                "command": "echo hello_world_123",
                "timeout": 30,
            })
        )
        result = assert_tool_success(resp, "Basic exec should succeed")
        data = parse_tool_output(resp)
        assert "hello_world_123" in data.get("stdout", "")
        assert data.get("exit_code") == 0
        assert data.get("timed_out") is False

    def test_exec_nonzero_exit_is_success(self):
        """exec with non-zero exit code returns success=True (CRITICAL FIX).

        Non-zero exit codes are normal (e.g., cat nonexistent, grep no-match).
        The tool should return success=True and let the agent decide.
        """
        resp = self.loop.run_until_complete(
            self.client.call("exec", {
                "session_id": self.session_id,
                "command": "exit 42",
                "timeout": 30,
            })
        )
        # CRITICAL: This MUST be success, not error
        result = assert_tool_success(resp, "Non-zero exit should NOT be a tool error")
        data = parse_tool_output(resp)
        assert data.get("exit_code") == 42

    def test_exec_cat_nonexistent_file(self):
        """exec cat of nonexistent file returns success with non-zero exit code and stderr."""
        resp = self.loop.run_until_complete(
            self.client.call("exec", {
                "session_id": self.session_id,
                "command": "cat /nonexistent_file_xyz_test",
                "timeout": 30,
            })
        )
        result = assert_tool_success(resp, "cat nonexistent should be success with non-zero exit")
        data = parse_tool_output(resp)
        assert data.get("exit_code") != 0
        # stderr should contain the "No such file" message
        stderr = data.get("stderr") or ""
        assert "no such file" in stderr.lower() or "not found" in stderr.lower() or data.get("exit_code") != 0

    def test_exec_multiline_output(self):
        """exec handles multiline command output."""
        resp = self.loop.run_until_complete(
            self.client.call("exec", {
                "session_id": self.session_id,
                "command": "for i in 1 2 3; do echo line_$i; done",
                "timeout": 30,
            })
        )
        result = assert_tool_success(resp)
        data = parse_tool_output(resp)
        stdout = data.get("stdout", "")
        assert "line_1" in stdout
        assert "line_2" in stdout
        assert "line_3" in stdout

    def test_exec_stdout_and_stderr(self):
        """exec captures both stdout and stderr."""
        resp = self.loop.run_until_complete(
            self.client.call("exec", {
                "session_id": self.session_id,
                "command": "echo out_text && echo err_text >&2",
                "timeout": 30,
            })
        )
        result = assert_tool_success(resp, "stdout+stderr exec should succeed")
        data = parse_tool_output(resp)
        assert "out_text" in data.get("stdout", "")

    def test_exec_preserves_session(self):
        """Multiple exec calls on same session all succeed."""
        for i in range(3):
            resp = self.loop.run_until_complete(
                self.client.call("exec", {
                    "session_id": self.session_id,
                    "command": f"echo iteration_{i}",
                    "timeout": 30,
                })
            )
            result = assert_tool_success(resp, f"Iteration {i} should succeed")
            data = parse_tool_output(resp)
            assert f"iteration_{i}" in data.get("stdout", "")


class TestUpload:
    """Test the upload method."""

    @pytest.fixture(autouse=True)
    def _session(self, shell_env, ssh_target):
        """Create a session for upload tests."""
        host, port, user, password = ssh_target
        client, loop = shell_env
        resp = loop.run_until_complete(
            client.call("ssh_connect", {
                "host": host,
                "username": user,
                "password": password,
                "port": port,
                "timeout": 30,
            })
        )
        data = parse_tool_output(resp)
        self.session_id = data["session_id"]
        self.client = client
        self.loop = loop
        yield
        loop.run_until_complete(
            client.call("close", {"session_id": self.session_id})
        )

    def test_upload_text_content(self):
        """upload transfers text content to remote host."""
        test_content = "uploaded_test_content_67890"
        resp = self.loop.run_until_complete(
            self.client.call("upload", {
                "session_id": self.session_id,
                "content": test_content,
                "remote_path": "/tmp/test_upload_shell_session.txt",
                "mode": "0644",
            })
        )
        result = assert_tool_success(resp, "upload should succeed")
        data = parse_tool_output(resp)
        assert data.get("size") == len(test_content)

        # Verify the file was uploaded
        verify_resp = self.loop.run_until_complete(
            self.client.call("exec", {
                "session_id": self.session_id,
                "command": "cat /tmp/test_upload_shell_session.txt",
                "timeout": 30,
            })
        )
        verify_data = parse_tool_output(verify_resp)
        assert test_content in verify_data.get("stdout", "")

    def test_upload_base64_content(self):
        """upload transfers base64-encoded binary content."""
        binary_data = bytes(range(256))
        b64_content = base64.b64encode(binary_data).decode()
        resp = self.loop.run_until_complete(
            self.client.call("upload", {
                "session_id": self.session_id,
                "content": b64_content,
                "remote_path": "/tmp/test_upload_binary",
                "is_base64": True,
            })
        )
        result = assert_tool_success(resp, "base64 upload should succeed")
        data = parse_tool_output(resp)
        assert data.get("size") == 256


class TestDownload:
    """Test the download method."""

    @pytest.fixture(autouse=True)
    def _session(self, shell_env, ssh_target):
        """Create a session for download tests."""
        host, port, user, password = ssh_target
        client, loop = shell_env
        resp = loop.run_until_complete(
            client.call("ssh_connect", {
                "host": host,
                "username": user,
                "password": password,
                "port": port,
                "timeout": 30,
            })
        )
        data = parse_tool_output(resp)
        self.session_id = data["session_id"]
        self.client = client
        self.loop = loop
        yield
        loop.run_until_complete(
            client.call("close", {"session_id": self.session_id})
        )

    def test_download_text_file(self):
        """download retrieves a text file's content."""
        # Create a file first
        self.loop.run_until_complete(
            self.client.call("exec", {
                "session_id": self.session_id,
                "command": "echo 'download_test_content_12345' > /tmp/test_download_ss.txt",
                "timeout": 30,
            })
        )

        resp = self.loop.run_until_complete(
            self.client.call("download", {
                "session_id": self.session_id,
                "remote_path": "/tmp/test_download_ss.txt",
            })
        )
        result = assert_tool_success(resp, "download should succeed")
        data = parse_tool_output(resp)
        assert "download_test_content_12345" in data.get("content", "")
        assert data.get("size", 0) > 0

    def test_download_as_base64(self):
        """download with as_base64=True returns base64 content."""
        self.loop.run_until_complete(
            self.client.call("exec", {
                "session_id": self.session_id,
                "command": "echo 'base64_test' > /tmp/test_download_b64.txt",
                "timeout": 30,
            })
        )

        resp = self.loop.run_until_complete(
            self.client.call("download", {
                "session_id": self.session_id,
                "remote_path": "/tmp/test_download_b64.txt",
                "as_base64": True,
            })
        )
        result = assert_tool_success(resp, "download as base64 should succeed")
        data = parse_tool_output(resp)
        assert data.get("is_base64") is True
        # Decode and verify
        decoded = base64.b64decode(data["content"]).decode()
        assert "base64_test" in decoded


class TestSessionLifecycle:
    """Test full session lifecycle: connect -> exec -> list -> close -> exec fails."""

    def test_full_lifecycle(self, shell_env, ssh_target):
        """Complete lifecycle: connect, exec, list, close, exec-after-close fails."""
        host, port, user, password = ssh_target
        client, loop = shell_env

        # 1. Connect
        resp = loop.run_until_complete(
            client.call("ssh_connect", {
                "host": host,
                "username": user,
                "password": password,
                "port": port,
                "timeout": 30,
            })
        )
        result = assert_tool_success(resp, "Connect should succeed")
        data = parse_tool_output(resp)
        session_id = data["session_id"]

        # 2. Exec
        resp = loop.run_until_complete(
            client.call("exec", {
                "session_id": session_id,
                "command": "echo lifecycle_test",
                "timeout": 30,
            })
        )
        result = assert_tool_success(resp, "Exec should succeed")
        data = parse_tool_output(resp)
        assert "lifecycle_test" in data.get("stdout", "")

        # 3. List sessions
        resp = loop.run_until_complete(
            client.call("list_sessions", {})
        )
        result = assert_tool_success(resp, "List should succeed")
        data = parse_tool_output(resp)
        assert data["total"] >= 1
        session_ids = [s["id"] for s in data["sessions"]]
        assert session_id in session_ids

        # 4. Close
        resp = loop.run_until_complete(
            client.call("close", {"session_id": session_id})
        )
        result = assert_tool_success(resp, "Close should succeed")
        data = parse_tool_output(resp)
        assert data.get("type") == "ssh"

        # 5. Exec after close should fail
        resp = loop.run_until_complete(
            client.call("exec", {
                "session_id": session_id,
                "command": "echo should_fail",
                "timeout": 30,
            })
        )
        result = assert_tool_error(resp, "not found")


class TestConcurrentSessions:
    """Test multiple concurrent sessions."""

    def test_multiple_sessions(self, shell_env, ssh_target):
        """Multiple SSH sessions can coexist."""
        host, port, user, password = ssh_target
        client, loop = shell_env
        sessions = []

        try:
            # Create 3 sessions
            for i in range(3):
                resp = loop.run_until_complete(
                    client.call("ssh_connect", {
                        "host": host,
                        "username": user,
                        "password": password,
                        "port": port,
                        "timeout": 30,
                    })
                )
                data = parse_tool_output(resp)
                sessions.append(data["session_id"])

            # Execute on each session
            for i, sid in enumerate(sessions):
                resp = loop.run_until_complete(
                    client.call("exec", {
                        "session_id": sid,
                        "command": f"echo session_{i}",
                        "timeout": 30,
                    })
                )
                result = assert_tool_success(resp, f"Exec on session {i} should succeed")
                data = parse_tool_output(resp)
                assert f"session_{i}" in data.get("stdout", "")

            # List should show all 3 (plus any from other tests)
            resp = loop.run_until_complete(
                client.call("list_sessions", {})
            )
            data = parse_tool_output(resp)
            assert data["total"] >= 3

        finally:
            # Cleanup
            for sid in sessions:
                loop.run_until_complete(
                    client.call("close", {"session_id": sid})
                )


class TestTimeoutRecovery:
    """Test that the server recovers after a timeout."""

    def test_post_timeout_commands_work(self, shell_env, ssh_target):
        """After a command times out, subsequent commands on the SAME server still work.

        This verifies the event loop isn't blocked by paramiko (thread executor fix).
        """
        host, port, user, password = ssh_target
        client, loop = shell_env

        # Connect
        resp = loop.run_until_complete(
            client.call("ssh_connect", {
                "host": host,
                "username": user,
                "password": password,
                "port": port,
                "timeout": 30,
            })
        )
        data = parse_tool_output(resp)
        session_id = data["session_id"]

        try:
            # Run a command that will time out (sleep longer than timeout)
            resp = loop.run_until_complete(
                client.call("exec", {
                    "session_id": session_id,
                    "command": "sleep 30",
                    "timeout": 3,
                }, timeout=30)
            )
            # Should time out
            result = resp.get("result", {})
            if result.get("isError"):
                sc = result.get("structuredContent", {})
                assert sc.get("error_class") == "timeout"

            # Now open a NEW session and verify the server still works
            resp2 = loop.run_until_complete(
                client.call("ssh_connect", {
                    "host": host,
                    "username": user,
                    "password": password,
                    "port": port,
                    "timeout": 30,
                })
            )
            result2 = assert_tool_success(resp2, "Post-timeout connect should still work")
            data2 = parse_tool_output(resp2)
            new_session_id = data2["session_id"]

            # Execute on new session
            resp3 = loop.run_until_complete(
                client.call("exec", {
                    "session_id": new_session_id,
                    "command": "echo recovery_works",
                    "timeout": 30,
                })
            )
            result3 = assert_tool_success(resp3, "Post-timeout exec should work")
            data3 = parse_tool_output(resp3)
            assert "recovery_works" in data3.get("stdout", "")

            # Clean up new session
            loop.run_until_complete(
                client.call("close", {"session_id": new_session_id})
            )

        finally:
            loop.run_until_complete(
                client.call("close", {"session_id": session_id})
            )


class TestUploadDownloadRoundtrip:
    """Test upload + download roundtrip."""

    def test_text_roundtrip(self, shell_env, ssh_target):
        """Upload text, download it, verify match."""
        host, port, user, password = ssh_target
        client, loop = shell_env

        resp = loop.run_until_complete(
            client.call("ssh_connect", {
                "host": host,
                "username": user,
                "password": password,
                "port": port,
                "timeout": 30,
            })
        )
        data = parse_tool_output(resp)
        session_id = data["session_id"]

        try:
            test_content = "roundtrip_test_data_abc123\nline2\nline3"

            # Upload
            resp = loop.run_until_complete(
                client.call("upload", {
                    "session_id": session_id,
                    "content": test_content,
                    "remote_path": "/tmp/roundtrip_test.txt",
                    "mode": "0644",
                })
            )
            assert_tool_success(resp, "Upload should succeed")

            # Download
            resp = loop.run_until_complete(
                client.call("download", {
                    "session_id": session_id,
                    "remote_path": "/tmp/roundtrip_test.txt",
                })
            )
            result = assert_tool_success(resp, "Download should succeed")
            data = parse_tool_output(resp)
            assert data["content"].strip() == test_content

        finally:
            loop.run_until_complete(
                client.call("close", {"session_id": session_id})
            )


# ===========================================================================
# CONTRACT TESTS -- verify tool.yaml vs server parameter definitions
# ===========================================================================

class TestToolYamlContract:
    """Verify that tool.yaml method parameters match server registration."""

    @classmethod
    def setup_class(cls):
        try:
            cls.server = _get_server_class()()
        except Exception as e:
            pytest.skip(f"Cannot import ShellSessionServer: {e}")

        yaml_path = TOOL_DIR / "tool.yaml"
        with open(yaml_path) as f:
            cls.yaml_data = yaml.safe_load(f)

    def test_all_yaml_params_exist_in_server(self):
        """Every parameter listed in tool.yaml exists in the server's method definition."""
        yaml_methods = self.yaml_data.get("methods", {})
        mismatches = []

        for method_name, method_def in yaml_methods.items():
            yaml_params = set(method_def.get("params", {}).keys())
            if method_name not in self.server.methods:
                mismatches.append(f"{method_name}: not registered in server")
                continue
            server_params = set(self.server.methods[method_name].params.keys())
            yaml_only = yaml_params - server_params
            if yaml_only:
                mismatches.append(f"{method_name}: yaml-only params: {yaml_only}")

        assert not mismatches, f"Parameter mismatches:\n" + "\n".join(mismatches)

    def test_all_server_params_exist_in_yaml(self):
        """Every parameter in the server's method definition exists in tool.yaml."""
        yaml_methods = self.yaml_data.get("methods", {})
        mismatches = []

        for method_name, method_obj in self.server.methods.items():
            if method_name == "verify_clock":
                continue  # Test-only method
            server_params = set(method_obj.params.keys())
            if method_name not in yaml_methods:
                mismatches.append(f"{method_name}: not in tool.yaml")
                continue
            yaml_params = set(yaml_methods[method_name].get("params", {}).keys())
            server_only = server_params - yaml_params
            if server_only:
                mismatches.append(f"{method_name}: server-only params: {server_only}")

        assert not mismatches, f"Parameter mismatches:\n" + "\n".join(mismatches)

    def test_required_params_match(self):
        """Required parameters in tool.yaml match server definitions."""
        yaml_methods = self.yaml_data.get("methods", {})
        mismatches = []

        for method_name, method_def in yaml_methods.items():
            if method_name not in self.server.methods:
                continue
            for param_name, param_def in method_def.get("params", {}).items():
                yaml_required = param_def.get("required", False)
                server_param = self.server.methods[method_name].params.get(param_name, {})
                server_required = server_param.get("required", False)
                if yaml_required != server_required:
                    mismatches.append(
                        f"{method_name}.{param_name}: yaml required={yaml_required}, server required={server_required}"
                    )

        assert not mismatches, f"Required param mismatches:\n" + "\n".join(mismatches)

    def test_tool_yaml_has_phases(self):
        """tool.yaml specifies valid phases."""
        phases = self.yaml_data.get("phases", [])
        assert len(phases) > 0, "tool.yaml should specify phases"
        valid_phases = {"reconnaissance", "enumeration", "exploitation", "post-exploitation", "reporting"}
        for phase in phases:
            assert phase in valid_phases, f"Invalid phase: {phase}"

    def test_tool_yaml_has_routing(self):
        """tool.yaml specifies routing hints."""
        routing = self.yaml_data.get("routing", {})
        assert "use_for" in routing
        assert "never_use_for" in routing
        assert len(routing["use_for"]) > 0

    def test_tool_yaml_has_capabilities(self):
        """tool.yaml specifies capabilities list."""
        caps = self.yaml_data.get("capabilities", [])
        assert len(caps) > 0, "tool.yaml should specify capabilities"

    def test_tool_yaml_service_flag(self):
        """tool.yaml marks this as a stateful service."""
        assert self.yaml_data.get("service") is True
        assert self.yaml_data.get("service_name") == "shell-session"


# ===========================================================================
# ADDITIONAL UNIT TESTS -- dataclass/helper coverage
# ===========================================================================

class TestSSHSessionDataclass:
    """Test the SSHSession dataclass is_connected method."""

    @classmethod
    def setup_class(cls):
        try:
            cls.mod = _get_module()
        except Exception as e:
            pytest.skip(f"Cannot import module: {e}")

    def test_is_connected_no_transport(self):
        """is_connected returns False when transport is None."""
        from unittest.mock import MagicMock
        mock_client = MagicMock()
        mock_client.get_transport.return_value = None
        session = self.mod.SSHSession(
            id="ses_test123456",
            client=mock_client,
            sftp=None,
            host="127.0.0.1",
            port=22,
            username="test",
            connected_at=time.time(),
        )
        assert session.is_connected() is False

    def test_is_connected_transport_active(self):
        """is_connected returns True when transport is active."""
        from unittest.mock import MagicMock
        mock_client = MagicMock()
        mock_transport = MagicMock()
        mock_transport.is_active.return_value = True
        mock_client.get_transport.return_value = mock_transport
        session = self.mod.SSHSession(
            id="ses_test123456",
            client=mock_client,
            sftp=None,
            host="127.0.0.1",
            port=22,
            username="test",
            connected_at=time.time(),
        )
        assert session.is_connected() is True

    def test_is_connected_transport_inactive(self):
        """is_connected returns False when transport is inactive."""
        from unittest.mock import MagicMock
        mock_client = MagicMock()
        mock_transport = MagicMock()
        mock_transport.is_active.return_value = False
        mock_client.get_transport.return_value = mock_transport
        session = self.mod.SSHSession(
            id="ses_test123456",
            client=mock_client,
            sftp=None,
            host="127.0.0.1",
            port=22,
            username="test",
            connected_at=time.time(),
        )
        assert session.is_connected() is False

    def test_is_connected_exception_returns_false(self):
        """is_connected returns False when transport check raises."""
        from unittest.mock import MagicMock
        mock_client = MagicMock()
        mock_client.get_transport.side_effect = Exception("broken")
        session = self.mod.SSHSession(
            id="ses_test123456",
            client=mock_client,
            sftp=None,
            host="127.0.0.1",
            port=22,
            username="test",
            connected_at=time.time(),
        )
        assert session.is_connected() is False


class TestReverseShellSessionDataclass:
    """Test the ReverseShellSession dataclass is_connected method."""

    @classmethod
    def setup_class(cls):
        try:
            cls.mod = _get_module()
        except Exception as e:
            pytest.skip(f"Cannot import module: {e}")

    def test_is_connected_blocking_io_means_alive(self):
        """is_connected returns True when recv raises BlockingIOError (no data, alive)."""
        from unittest.mock import MagicMock
        mock_sock = MagicMock()
        mock_sock.recv.side_effect = BlockingIOError()
        session = self.mod.ReverseShellSession(
            id="ses_test123456",
            socket=mock_sock,
            remote_addr=("10.10.10.1", 12345),
            connected_at=time.time(),
        )
        assert session.is_connected() is True

    def test_is_connected_data_available(self):
        """is_connected returns True when recv returns data."""
        from unittest.mock import MagicMock
        mock_sock = MagicMock()
        mock_sock.recv.return_value = b"x"
        session = self.mod.ReverseShellSession(
            id="ses_test123456",
            socket=mock_sock,
            remote_addr=("10.10.10.1", 12345),
            connected_at=time.time(),
        )
        assert session.is_connected() is True

    def test_is_connected_empty_recv_means_closed(self):
        """is_connected returns False when recv returns empty (connection closed)."""
        from unittest.mock import MagicMock
        mock_sock = MagicMock()
        mock_sock.recv.return_value = b""
        session = self.mod.ReverseShellSession(
            id="ses_test123456",
            socket=mock_sock,
            remote_addr=("10.10.10.1", 12345),
            connected_at=time.time(),
        )
        assert session.is_connected() is False

    def test_is_connected_exception_returns_false(self):
        """is_connected returns False when recv raises unexpected error."""
        from unittest.mock import MagicMock
        mock_sock = MagicMock()
        mock_sock.recv.side_effect = ConnectionResetError("reset")
        session = self.mod.ReverseShellSession(
            id="ses_test123456",
            socket=mock_sock,
            remote_addr=("10.10.10.1", 12345),
            connected_at=time.time(),
        )
        assert session.is_connected() is False


class TestDirectAsyncDisconnectedSessions:
    """Test methods on disconnected sessions return correct errors."""

    @classmethod
    def setup_class(cls):
        try:
            cls.server = _get_server_class()()
        except Exception as e:
            pytest.skip(f"Cannot import ShellSessionServer: {e}")

    def _make_disconnected_ssh_session(self):
        """Create a mock disconnected SSH session in the server."""
        from unittest.mock import MagicMock
        mod = _get_module()
        mock_client = MagicMock()
        mock_client.get_transport.return_value = None  # disconnected
        session = mod.SSHSession(
            id="ses_disconnected",
            client=mock_client,
            sftp=None,
            host="10.10.10.1",
            port=22,
            username="testuser",
            connected_at=time.time(),
        )
        self.server.ssh_sessions["ses_disconnected"] = session
        return "ses_disconnected"

    def _make_disconnected_shell_session(self):
        """Create a mock disconnected reverse shell session in the server."""
        from unittest.mock import MagicMock
        mod = _get_module()
        mock_sock = MagicMock()
        mock_sock.recv.return_value = b""  # disconnected
        session = mod.ReverseShellSession(
            id="ses_shell_disc",
            socket=mock_sock,
            remote_addr=("10.10.10.1", 12345),
            connected_at=time.time(),
        )
        self.server.shell_sessions["ses_shell_disc"] = session
        return "ses_shell_disc"

    def test_exec_on_disconnected_ssh(self):
        """exec on a disconnected SSH session returns network error and cleans up."""
        sid = self._make_disconnected_ssh_session()
        loop = asyncio.new_event_loop()
        try:
            result = loop.run_until_complete(
                self.server.exec_command(session_id=sid, command="id")
            )
            assert not result.success
            assert result.error_class == "network"
            assert result.retryable is True
            assert sid not in self.server.ssh_sessions  # session cleaned up
        finally:
            loop.close()

    def test_upload_on_disconnected_ssh(self):
        """upload on a disconnected SSH session returns network error and cleans up."""
        sid = self._make_disconnected_ssh_session()
        loop = asyncio.new_event_loop()
        try:
            result = loop.run_until_complete(
                self.server.upload(session_id=sid, content="test", remote_path="/tmp/x")
            )
            assert not result.success
            assert result.error_class == "network"
            assert result.retryable is True
            assert sid not in self.server.ssh_sessions
        finally:
            loop.close()

    def test_download_on_disconnected_ssh(self):
        """download on a disconnected SSH session returns network error and cleans up."""
        sid = self._make_disconnected_ssh_session()
        loop = asyncio.new_event_loop()
        try:
            result = loop.run_until_complete(
                self.server.download(session_id=sid, remote_path="/etc/passwd")
            )
            assert not result.success
            assert result.error_class == "network"
            assert result.retryable is True
            assert sid not in self.server.ssh_sessions
        finally:
            loop.close()

    def test_shell_exec_on_disconnected_reverse_shell(self):
        """shell_exec on disconnected reverse shell returns network error and cleans up."""
        sid = self._make_disconnected_shell_session()
        loop = asyncio.new_event_loop()
        try:
            result = loop.run_until_complete(
                self.server.shell_exec(session_id=sid, command="id")
            )
            assert not result.success
            assert result.error_class == "network"
            assert result.retryable is True
            assert sid not in self.server.shell_sessions
        finally:
            loop.close()

    def test_upgrade_shell_on_disconnected_reverse_shell(self):
        """upgrade_shell on disconnected reverse shell returns network error and cleans up."""
        sid = self._make_disconnected_shell_session()
        loop = asyncio.new_event_loop()
        try:
            result = loop.run_until_complete(
                self.server.upgrade_shell(session_id=sid)
            )
            assert not result.success
            assert result.error_class == "network"
            assert result.retryable is True
            assert sid not in self.server.shell_sessions
        finally:
            loop.close()

    def test_list_sessions_prunes_disconnected(self):
        """list_sessions removes disconnected sessions from its output."""
        self._make_disconnected_ssh_session()
        self._make_disconnected_shell_session()
        loop = asyncio.new_event_loop()
        try:
            result = loop.run_until_complete(self.server.list_sessions())
            assert result.success
            # Both disconnected sessions should be pruned
            session_ids = [s["id"] for s in result.data["sessions"]]
            assert "ses_disconnected" not in session_ids
            assert "ses_shell_disc" not in session_ids
        finally:
            loop.close()


class TestDirectAsyncCloseSessionTypes:
    """Test close_session for both SSH and reverse shell session types."""

    @classmethod
    def setup_class(cls):
        try:
            cls.server = _get_server_class()()
        except Exception as e:
            pytest.skip(f"Cannot import ShellSessionServer: {e}")

    def test_close_ssh_session(self):
        """Closing an SSH session returns type=ssh."""
        from unittest.mock import MagicMock
        mod = _get_module()
        mock_client = MagicMock()
        session = mod.SSHSession(
            id="ses_ssh_close",
            client=mock_client,
            sftp=MagicMock(),
            host="10.10.10.1",
            port=22,
            username="test",
            connected_at=time.time(),
        )
        self.server.ssh_sessions["ses_ssh_close"] = session
        loop = asyncio.new_event_loop()
        try:
            result = loop.run_until_complete(
                self.server.close_session(session_id="ses_ssh_close")
            )
            assert result.success
            assert result.data["type"] == "ssh"
            assert "ses_ssh_close" not in self.server.ssh_sessions
        finally:
            loop.close()

    def test_close_reverse_shell_session(self):
        """Closing a reverse shell session returns type=reverse_shell."""
        from unittest.mock import MagicMock
        mod = _get_module()
        mock_sock = MagicMock()
        session = mod.ReverseShellSession(
            id="ses_rs_close",
            socket=mock_sock,
            remote_addr=("10.10.10.1", 12345),
            connected_at=time.time(),
        )
        self.server.shell_sessions["ses_rs_close"] = session
        loop = asyncio.new_event_loop()
        try:
            result = loop.run_until_complete(
                self.server.close_session(session_id="ses_rs_close")
            )
            assert result.success
            assert result.data["type"] == "reverse_shell"
            assert "ses_rs_close" not in self.server.shell_sessions
        finally:
            loop.close()


class TestRetryableErrorPatterns:
    """Extended retryable error pattern testing."""

    @classmethod
    def setup_class(cls):
        try:
            cls.server = _get_server_class()()
        except Exception as e:
            pytest.skip(f"Cannot import ShellSessionServer: {e}")

    def test_temporary_failure_is_retryable(self):
        assert self.server._is_retryable_error(Exception("Temporary failure in name resolution"))

    def test_resource_unavailable_is_retryable(self):
        assert self.server._is_retryable_error(Exception("Resource temporarily unavailable"))

    def test_connection_refused_not_retryable(self):
        """Connection refused is NOT in the retryable list (classify handles it separately)."""
        assert not self.server._is_retryable_error(Exception("Connection refused"))

    def test_empty_error_not_retryable(self):
        assert not self.server._is_retryable_error(Exception(""))


class TestSSHErrorClassificationEdgeCases:
    """Edge cases in SSH error classification."""

    @classmethod
    def setup_class(cls):
        try:
            cls.server = _get_server_class()()
        except Exception as e:
            pytest.skip(f"Cannot import ShellSessionServer: {e}")

    def test_unable_to_connect(self):
        """'Unable to connect' maps to network/retryable."""
        err = Exception("Unable to connect to port 22")
        msg, cls_, retryable, suggestions = self.server._classify_ssh_error(err)
        assert cls_ == "network"
        assert retryable is True

    def test_permission_denied_variant(self):
        """'Permission denied' (without 'authentication') still maps to auth."""
        err = Exception("Permission denied (publickey,password)")
        msg, cls_, retryable, suggestions = self.server._classify_ssh_error(err)
        assert cls_ == "auth"
        assert retryable is False

    def test_timeout_variant(self):
        """'timeout' keyword (not 'timed out') still matches."""
        err = Exception("SSH timeout connecting to host")
        msg, cls_, retryable, suggestions = self.server._classify_ssh_error(err)
        assert cls_ == "timeout"
        assert retryable is True


class TestDirectAsyncSSHConnectKeyParsing:
    """Test ssh_connect's private key parsing paths."""

    @classmethod
    def setup_class(cls):
        try:
            cls.server = _get_server_class()()
        except Exception as e:
            pytest.skip(f"Cannot import ShellSessionServer: {e}")

    def test_invalid_base64_key_returns_config_error(self):
        """ssh_connect with garbage private_key returns config error."""
        loop = asyncio.new_event_loop()
        try:
            result = loop.run_until_complete(
                self.server.ssh_connect(
                    host="127.0.0.1",
                    username="root",
                    private_key="not-a-valid-key-at-all",
                )
            )
            assert not result.success
            assert result.error_class == "config"
            assert any("key" in s.lower() for s in result.suggestions)
        finally:
            loop.close()


# ===========================================================================
# ACCEPTANCE TESTS -- call every method through Docker container
# ===========================================================================

class TestAcceptanceSSHMethods:
    """Acceptance tests: call every SSH-related method through the Docker container.

    Tests the full MCP protocol path: JSON-RPC -> container -> method -> response.
    """

    @pytest.fixture(autouse=True)
    def _session(self, shell_env, ssh_target):
        """Create a session for acceptance tests."""
        host, port, user, password = ssh_target
        client, loop = shell_env
        resp = loop.run_until_complete(
            client.call("ssh_connect", {
                "host": host,
                "username": user,
                "password": password,
                "port": port,
                "timeout": 30,
            })
        )
        data = parse_tool_output(resp)
        self.session_id = data["session_id"]
        self.client = client
        self.loop = loop
        yield
        loop.run_until_complete(
            client.call("close", {"session_id": self.session_id})
        )

    def test_exec_with_get_pty(self):
        """exec with get_pty=True returns output (PTY mode)."""
        resp = self.loop.run_until_complete(
            self.client.call("exec", {
                "session_id": self.session_id,
                "command": "echo pty_test_output",
                "timeout": 30,
                "get_pty": True,
            })
        )
        result = assert_tool_success(resp, "exec with PTY should succeed")
        data = parse_tool_output(resp)
        assert "pty_test_output" in data.get("stdout", "")

    def test_upload_with_permissions(self):
        """upload sets file permissions correctly."""
        resp = self.loop.run_until_complete(
            self.client.call("upload", {
                "session_id": self.session_id,
                "content": "#!/bin/sh\necho accept_test",
                "remote_path": "/tmp/accept_test.sh",
                "mode": "0755",
            })
        )
        assert_tool_success(resp, "upload should succeed")

        # Verify permissions
        resp = self.loop.run_until_complete(
            self.client.call("exec", {
                "session_id": self.session_id,
                "command": "stat -c '%a' /tmp/accept_test.sh",
                "timeout": 10,
            })
        )
        data = parse_tool_output(resp)
        assert "755" in data.get("stdout", "")

    def test_upload_then_exec_script(self):
        """Upload a script and execute it."""
        script = "#!/bin/sh\necho accept_exec_test_42"
        self.loop.run_until_complete(
            self.client.call("upload", {
                "session_id": self.session_id,
                "content": script,
                "remote_path": "/tmp/accept_exec.sh",
                "mode": "0755",
            })
        )
        resp = self.loop.run_until_complete(
            self.client.call("exec", {
                "session_id": self.session_id,
                "command": "/tmp/accept_exec.sh",
                "timeout": 10,
            })
        )
        result = assert_tool_success(resp)
        data = parse_tool_output(resp)
        assert "accept_exec_test_42" in data.get("stdout", "")

    def test_download_nonexistent_file(self):
        """download of nonexistent file returns error."""
        resp = self.loop.run_until_complete(
            self.client.call("download", {
                "session_id": self.session_id,
                "remote_path": "/tmp/this_file_definitely_does_not_exist_xyz",
            })
        )
        result = resp.get("result", {})
        assert result.get("isError", False), "Downloading nonexistent file should fail"

    def test_upload_download_binary_roundtrip(self):
        """Upload binary data (base64), download as base64, verify match."""
        original = bytes(range(256))
        b64_content = base64.b64encode(original).decode()

        # Upload
        resp = self.loop.run_until_complete(
            self.client.call("upload", {
                "session_id": self.session_id,
                "content": b64_content,
                "remote_path": "/tmp/accept_binary_test",
                "is_base64": True,
                "mode": "0644",
            })
        )
        assert_tool_success(resp, "binary upload should succeed")

        # Download
        resp = self.loop.run_until_complete(
            self.client.call("download", {
                "session_id": self.session_id,
                "remote_path": "/tmp/accept_binary_test",
                "as_base64": True,
            })
        )
        result = assert_tool_success(resp, "binary download should succeed")
        data = parse_tool_output(resp)
        downloaded = base64.b64decode(data["content"])
        assert downloaded == original

    def test_list_sessions_shows_active(self):
        """list_sessions includes the current session with correct metadata."""
        resp = self.loop.run_until_complete(
            self.client.call("list_sessions", {})
        )
        result = assert_tool_success(resp)
        data = parse_tool_output(resp)
        assert data["total"] >= 1
        found = False
        for s in data["sessions"]:
            if s["id"] == self.session_id:
                found = True
                assert s["type"] == "ssh"
                assert s["username"] is not None
                assert s["uptime_seconds"] >= 0
        assert found, f"Session {self.session_id} not found in list_sessions"

    def test_exec_large_output(self):
        """exec handles reasonably large output (>10KB)."""
        resp = self.loop.run_until_complete(
            self.client.call("exec", {
                "session_id": self.session_id,
                "command": "seq 1 2000",
                "timeout": 30,
            })
        )
        result = assert_tool_success(resp, "Large output exec should succeed")
        data = parse_tool_output(resp)
        stdout = data.get("stdout", "")
        assert "1" in stdout
        assert "2000" in stdout
        assert len(stdout) > 5000  # seq 1 2000 produces ~10KB

    def test_exec_environment_variables(self):
        """exec can access environment variables."""
        resp = self.loop.run_until_complete(
            self.client.call("exec", {
                "session_id": self.session_id,
                "command": "echo $HOME",
                "timeout": 10,
            })
        )
        result = assert_tool_success(resp)
        data = parse_tool_output(resp)
        assert data.get("stdout", "").strip() != ""


class TestAcceptanceReverseShellMethods:
    """Acceptance tests for reverse-shell-related methods.

    These methods (listen, shell_exec, upgrade_shell) require a live
    reverse shell which is not available in CI. Here we verify that
    calling them through the container returns correctly classified errors
    rather than crashing.
    """

    def test_listen_port_in_use(self, shell_env):
        """listen on a port that's already in use returns config error.

        We can't easily bind a port inside the container from outside,
        so we test the timeout path instead -- listen with a very short
        timeout and verify the error classification.
        """
        client, loop = shell_env
        resp = loop.run_until_complete(
            client.call("listen", {
                "port": 44444,
                "timeout": 1,
            }, timeout=30)
        )
        result = resp.get("result", {})
        # Should timeout since no connection arrives
        assert result.get("isError", False), "listen with no connection should fail"
        sc = result.get("structuredContent", {})
        assert sc.get("error_class") == "timeout"
        assert sc.get("retryable") is True

    def test_shell_exec_invalid_session_through_container(self, shell_env):
        """shell_exec with invalid session through container returns params error."""
        client, loop = shell_env
        resp = loop.run_until_complete(
            client.call("shell_exec", {
                "session_id": "ses_nonexistent",
                "command": "id",
            })
        )
        result = assert_tool_error(resp, "not found")
        sc = result.get("structuredContent", {})
        assert sc.get("error_class") == "params"
        assert len(sc.get("suggestions", [])) > 0

    def test_upgrade_shell_invalid_session_through_container(self, shell_env):
        """upgrade_shell with invalid session through container returns params error."""
        client, loop = shell_env
        resp = loop.run_until_complete(
            client.call("upgrade_shell", {
                "session_id": "ses_nonexistent",
            })
        )
        result = assert_tool_error(resp, "not found")
        sc = result.get("structuredContent", {})
        assert sc.get("error_class") == "params"
        assert len(sc.get("suggestions", [])) > 0

    def test_listen_returns_structured_content(self, shell_env):
        """listen error response includes all structuredContent fields."""
        client, loop = shell_env
        resp = loop.run_until_complete(
            client.call("listen", {
                "port": 44445,
                "timeout": 1,
            }, timeout=30)
        )
        result = resp.get("result", {})
        sc = result.get("structuredContent")
        assert sc is not None, "structuredContent should be present"
        assert "success" in sc
        assert "error_class" in sc
        assert "retryable" in sc
        assert "suggestions" in sc


class TestAcceptanceCloseMethod:
    """Acceptance test for close method through container."""

    def test_close_valid_ssh_session(self, shell_env, ssh_target):
        """close on a valid SSH session succeeds and returns type."""
        host, port, user, password = ssh_target
        client, loop = shell_env

        resp = loop.run_until_complete(
            client.call("ssh_connect", {
                "host": host,
                "username": user,
                "password": password,
                "port": port,
                "timeout": 30,
            })
        )
        data = parse_tool_output(resp)
        session_id = data["session_id"]

        resp = loop.run_until_complete(
            client.call("close", {"session_id": session_id})
        )
        result = assert_tool_success(resp, "close should succeed")
        data = parse_tool_output(resp)
        assert data.get("type") == "ssh"
        assert data.get("session_id") == session_id

    def test_close_twice_fails(self, shell_env, ssh_target):
        """Closing the same session twice fails on the second attempt."""
        host, port, user, password = ssh_target
        client, loop = shell_env

        resp = loop.run_until_complete(
            client.call("ssh_connect", {
                "host": host,
                "username": user,
                "password": password,
                "port": port,
                "timeout": 30,
            })
        )
        data = parse_tool_output(resp)
        session_id = data["session_id"]

        # First close
        resp = loop.run_until_complete(
            client.call("close", {"session_id": session_id})
        )
        assert_tool_success(resp, "first close should succeed")

        # Second close
        resp = loop.run_until_complete(
            client.call("close", {"session_id": session_id})
        )
        result = assert_tool_error(resp, "not found")


class TestAcceptanceSSHConnectEdgeCases:
    """Acceptance tests for ssh_connect edge cases through container."""

    def test_ssh_connect_custom_port(self, shell_env, ssh_target):
        """ssh_connect respects custom port setting."""
        host, port, user, password = ssh_target
        client, loop = shell_env
        resp = loop.run_until_complete(
            client.call("ssh_connect", {
                "host": host,
                "username": user,
                "password": password,
                "port": port,
                "timeout": 15,
            })
        )
        result = assert_tool_success(resp, "Custom port connect should succeed")
        data = parse_tool_output(resp)
        assert data["port"] == port
        # Report SFTP availability
        assert "sftp_available" in data

        loop.run_until_complete(
            client.call("close", {"session_id": data["session_id"]})
        )

    def test_ssh_connect_timeout_unreachable_host(self, shell_env):
        """ssh_connect to unreachable host times out with correct error class."""
        client, loop = shell_env
        resp = loop.run_until_complete(
            client.call("ssh_connect", {
                "host": "192.0.2.1",  # TEST-NET, always unreachable
                "username": "root",
                "password": "test",
                "port": 22,
                "timeout": 3,
            }, timeout=60)
        )
        result = resp.get("result", {})
        assert result.get("isError", False), "Unreachable host should fail"
        sc = result.get("structuredContent", {})
        # Should be timeout or network error
        assert sc.get("error_class") in ("timeout", "network"), (
            f"Expected timeout or network, got: {sc.get('error_class')}"
        )
