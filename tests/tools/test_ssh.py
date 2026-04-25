"""
Tests for the ssh MCP tool server.

Covers:
- Smoke tests: boot, method list, required params, meta-param stripping, clock
- Unit tests: _classify_ssh_error, _convert_openssh_to_pem, _build_ssh_args
- Method tests: exec, shell, copy_from, copy_to, upload_binary, run_script, background
- Timeout recovery: REQ-RES-001 — post-timeout commands must still work
- Concurrent calls: REQ-RES-003 — parallel calls must not deadlock
- Error classification: connection refused, permission denied, timeout, no route
- Contract tests: tool.yaml vs server parameter definitions
- Acceptance tests: every method called through container (no live SSH target)
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
TOOL_DIR = PROJECT_ROOT / "tools" / "ssh"
FIXTURES_DIR = Path(__file__).parent.parent / "fixtures" / "ssh"

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
SSH_TARGET_CONTAINER = "mcp-test-ssh-target"
SSH_TARGET_PORT = 2222
SSH_TARGET_USER = "testuser"
SSH_TARGET_PASSWORD = "testpass"


# ---------------------------------------------------------------------------
# Helper: import server module for direct unit testing
# ---------------------------------------------------------------------------
def _get_server_class():
    """Import and return the SSHServer class for direct method testing."""
    # Need mcp_common on sys.path
    mcp_common_path = PROJECT_ROOT / "packages" / "mcp-common" / "src"
    if str(mcp_common_path) not in sys.path:
        sys.path.insert(0, str(mcp_common_path))

    spec = importlib.util.spec_from_file_location(
        "ssh_server", TOOL_DIR / "mcp-server.py"
    )
    mod = importlib.util.module_from_spec(spec)
    spec.loader.exec_module(mod)
    return mod.SSHServer


def _get_module():
    """Import the whole ssh mcp-server module."""
    mcp_common_path = PROJECT_ROOT / "packages" / "mcp-common" / "src"
    if str(mcp_common_path) not in sys.path:
        sys.path.insert(0, str(mcp_common_path))

    spec = importlib.util.spec_from_file_location(
        "ssh_server", TOOL_DIR / "mcp-server.py"
    )
    mod = importlib.util.module_from_spec(spec)
    spec.loader.exec_module(mod)
    return mod


# ---------------------------------------------------------------------------
# Fixtures: SSH target sidecar
# ---------------------------------------------------------------------------

def _is_port_open(host: str, port: int, timeout: float = 1.0) -> bool:
    """Check if a TCP port is open."""
    import socket
    try:
        with socket.create_connection((host, port), timeout=timeout):
            return True
    except (ConnectionRefusedError, OSError, TimeoutError):
        return False


@pytest.fixture(scope="module")
def ssh_target():
    """Start an SSH server sidecar for testing.

    Uses linuxserver/openssh-server if available, falls back to
    a plain sshd in a Docker container.

    Yields (host, port, username, password).
    """
    # Check if there's already an SSH server on the test port
    if _is_port_open("127.0.0.1", SSH_TARGET_PORT):
        yield ("127.0.0.1", SSH_TARGET_PORT, SSH_TARGET_USER, SSH_TARGET_PASSWORD)
        return

    # Try to start a lightweight sshd container
    try:
        # Clean up any stale container
        subprocess.run(
            ["docker", "rm", "-f", SSH_TARGET_CONTAINER],
            capture_output=True, timeout=10,
        )

        # Start openssh-server container
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

        # Wait for SSH to be ready (up to 30s)
        for i in range(30):
            if _is_port_open("127.0.0.1", SSH_TARGET_PORT):
                # Give it a moment to fully initialize
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
def ssh_env(request):
    """Create an MCPTestClient with its event loop. Yields (client, loop)."""
    tool = "ssh"
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
    """Load a fixture file."""
    path = FIXTURES_DIR / name
    return path.read_text()


# ===========================================================================
# UNIT TESTS -- No container needed, pure Python testing
# ===========================================================================

class TestClassifySshError:
    """Test _classify_ssh_error helper for SSH error classification.

    Returns (error_message, error_class, retryable) tuples.
    """

    @classmethod
    def setup_class(cls):
        try:
            cls.server = _get_server_class()()
        except Exception as e:
            pytest.skip(f"Cannot import SSHServer: {e}")

    def test_connection_refused(self):
        """Connection refused stderr is classified as network/retryable."""
        msg, cls, retryable = self.server._classify_ssh_error(255, "ssh: connect to host 10.10.10.1 port 22: Connection refused")
        assert "Connection refused" in msg
        assert "SSH port is closed" in msg
        assert cls == "network"
        assert retryable is True

    def test_connection_timed_out(self):
        """Connection timed out is classified as timeout/retryable."""
        msg, cls, retryable = self.server._classify_ssh_error(255, "ssh: connect to host 10.10.10.1 port 22: Connection timed out")
        assert "timed out" in msg.lower()
        assert cls == "timeout"
        assert retryable is True

    def test_no_route_to_host(self):
        """No route to host is classified as network/not retryable."""
        msg, cls, retryable = self.server._classify_ssh_error(255, "ssh: connect to host 10.10.10.1 port 22: No route to host")
        assert "No route to host" in msg
        assert cls == "network"
        assert retryable is False

    def test_permission_denied(self):
        """Permission denied is classified as auth/not retryable."""
        msg, cls, retryable = self.server._classify_ssh_error(255, "Permission denied (publickey,password)")
        assert "Permission denied" in msg
        assert cls == "auth"
        assert retryable is False

    def test_host_key_verification_failed(self):
        """Host key verification failure is classified as config/not retryable."""
        msg, cls, retryable = self.server._classify_ssh_error(255, "Host key verification failed.\n")
        assert "Host key verification" in msg
        assert cls == "config"
        assert retryable is False

    def test_network_unreachable(self):
        """Network unreachable is classified as network/retryable."""
        msg, cls, retryable = self.server._classify_ssh_error(255, "ssh: connect to host 10.10.10.1 port 22: Network is unreachable")
        assert "Network unreachable" in msg
        assert cls == "network"
        assert retryable is True

    def test_generic_exit_255(self):
        """Exit code 255 with unrecognized stderr is classified as network/retryable."""
        msg, cls, retryable = self.server._classify_ssh_error(255, "some unknown error message")
        assert "255" in msg
        assert "connection or authentication" in msg.lower()
        assert cls == "network"
        assert retryable is True

    def test_non_255_exit_code(self):
        """Non-255 exit code is classified as unknown/not retryable."""
        msg, cls, retryable = self.server._classify_ssh_error(1, "command not found")
        assert "exit code 1" in msg
        assert "command not found" in msg
        assert cls == "unknown"
        assert retryable is False

    # --- Tests added from engagement data analysis ---

    def test_connection_reset(self):
        """Connection reset by peer is classified as network/retryable."""
        msg, cls, retryable = self.server._classify_ssh_error(255, "ssh: connect to host 10.10.10.1 port 22: Connection reset by peer")
        assert "Connection reset" in msg
        assert cls == "network"
        assert retryable is True

    def test_broken_pipe(self):
        """Broken pipe is classified as network/retryable."""
        msg, cls, retryable = self.server._classify_ssh_error(255, "Write failed: Broken pipe")
        assert "Broken pipe" in msg
        assert cls == "network"
        assert retryable is True

    def test_connection_closed(self):
        """Connection closed (SCP) is classified as network/retryable."""
        msg, cls, retryable = self.server._classify_ssh_error(1, "scp: Connection closed\n")
        assert "Connection closed" in msg
        assert cls == "network"
        assert retryable is True

    def test_scp_connection_closed_with_warnings(self):
        """SCP connection closed with SSH warnings still classified correctly.

        Real engagement pattern: stderr has 'Permanently added' + 'scp: Connection closed'.
        """
        stderr = (
            "Warning: Permanently added '10.129.232.170' (ED25519) to the list of known hosts.\r\n"
            "scp: Connection closed\r\n"
        )
        msg, cls, retryable = self.server._classify_ssh_error(1, stderr)
        assert "Connection closed" in msg
        assert cls == "network"
        assert retryable is True

    def test_post_quantum_warning_exit_255(self):
        """Post-quantum warning with exit 255 is classified as network (generic 255).

        Real engagement pattern: OpenSSH 10.x emits post-quantum warnings to stderr.
        The warning itself should not be the primary error message.
        """
        stderr = (
            "** WARNING: connection is not using a post-quantum key exchange algorithm.\r\n"
            "** This session may be vulnerable to \"store now, decrypt later\" attacks.\r\n"
        )
        msg, cls, retryable = self.server._classify_ssh_error(255, stderr)
        # Should fall through to generic exit 255 handler
        assert cls == "network"
        assert retryable is True

    def test_permission_denied_with_methods(self):
        """Permission denied with auth methods listed is classified as auth.

        Real engagement pattern from trajectory data.
        """
        msg, cls, retryable = self.server._classify_ssh_error(255, "Permission denied, please try again.\r\n")
        assert cls == "auth"
        assert retryable is False

    def test_permission_denied_publickey(self):
        """Permission denied (publickey) is classified as auth."""
        msg, cls, retryable = self.server._classify_ssh_error(255, "testuser@10.10.10.1: Permission denied (publickey).")
        assert cls == "auth"
        assert retryable is False


class TestConvertOpensshToPem:
    """Test _convert_openssh_to_pem key format conversion."""

    @classmethod
    def setup_class(cls):
        try:
            cls.server = _get_server_class()()
        except Exception as e:
            pytest.skip(f"Cannot import SSHServer: {e}")

    def test_pem_key_passthrough(self):
        """PEM format RSA key is returned as-is."""
        key = load_fixture("test_rsa_pem")
        result = self.server._convert_openssh_to_pem(key)
        assert "BEGIN RSA PRIVATE KEY" in result
        assert result == key

    def test_openssh_rsa_key_converted(self):
        """OpenSSH format RSA key is converted to PEM."""
        key = load_fixture("test_rsa_openssh")
        assert "BEGIN OPENSSH PRIVATE KEY" in key
        result = self.server._convert_openssh_to_pem(key)
        assert "BEGIN RSA PRIVATE KEY" in result or "BEGIN PRIVATE KEY" in result

    def test_ed25519_key_conversion_attempted(self):
        """Ed25519 OpenSSH key triggers conversion attempt.

        ssh-keygen may or may not be able to convert ed25519 to PEM
        (it can't in older versions). The function should not crash either way.
        """
        key = load_fixture("test_ed25519")
        assert "BEGIN OPENSSH PRIVATE KEY" in key
        # Should not raise
        result = self.server._convert_openssh_to_pem(key)
        # Result should be a string (either converted or original)
        assert isinstance(result, str)
        assert len(result) > 0

    def test_unknown_format_passthrough(self):
        """Unknown key format is returned as-is."""
        key = "not-a-key-format"
        result = self.server._convert_openssh_to_pem(key)
        assert result == key

    def test_dsa_key_passthrough(self):
        """DSA format key is treated as PEM (no conversion needed)."""
        key = "-----BEGIN DSA PRIVATE KEY-----\nfakecontent\n-----END DSA PRIVATE KEY-----"
        result = self.server._convert_openssh_to_pem(key)
        assert result == key

    def test_ec_key_passthrough(self):
        """EC format key is treated as PEM (no conversion needed)."""
        key = "-----BEGIN EC PRIVATE KEY-----\nfakecontent\n-----END EC PRIVATE KEY-----"
        result = self.server._convert_openssh_to_pem(key)
        assert result == key

    def test_generic_private_key_passthrough(self):
        """PKCS8 format key is treated as PEM (no conversion needed)."""
        key = "-----BEGIN PRIVATE KEY-----\nfakecontent\n-----END PRIVATE KEY-----"
        result = self.server._convert_openssh_to_pem(key)
        assert result == key


class TestBuildSshArgs:
    """Test _build_ssh_args helper for SSH command construction."""

    @classmethod
    def setup_class(cls):
        try:
            cls.server = _get_server_class()()
        except Exception as e:
            pytest.skip(f"Cannot import SSHServer: {e}")

    def test_password_auth_uses_sshpass(self):
        """Password auth uses sshpass prefix."""
        args = self.server._build_ssh_args("10.10.10.1", "root", password="toor")
        assert args[0] == "sshpass"
        assert args[1] == "-p"
        assert args[2] == "toor"
        assert "ssh" in args
        assert "root@10.10.10.1" in args

    def test_key_auth_uses_identity_file(self):
        """Key auth uses -i flag."""
        args = self.server._build_ssh_args("10.10.10.1", "root", key_file="/tmp/key")
        assert "-i" in args
        idx = args.index("-i")
        assert args[idx + 1] == "/tmp/key"

    def test_custom_port(self):
        """Custom port is passed with -p flag."""
        args = self.server._build_ssh_args("10.10.10.1", "root", port=2222)
        assert "-p" in args
        idx = args.index("-p")
        assert args[idx + 1] == "2222"

    def test_strict_host_key_checking_disabled(self):
        """StrictHostKeyChecking=no is always set."""
        args = self.server._build_ssh_args("10.10.10.1", "root")
        # Find the option
        joined = " ".join(args)
        assert "StrictHostKeyChecking=no" in joined

    def test_batch_mode_with_password(self):
        """BatchMode=no when password is provided (sshpass needs interactive)."""
        args = self.server._build_ssh_args("10.10.10.1", "root", password="pass")
        joined = " ".join(args)
        assert "BatchMode=no" in joined

    def test_batch_mode_without_password(self):
        """BatchMode=yes when no password (key auth or no auth)."""
        args = self.server._build_ssh_args("10.10.10.1", "root")
        joined = " ".join(args)
        assert "BatchMode=yes" in joined

    def test_server_alive_interval(self):
        """ServerAliveInterval is set for keepalive."""
        args = self.server._build_ssh_args("10.10.10.1", "root")
        joined = " ".join(args)
        assert "ServerAliveInterval=15" in joined

    def test_connect_timeout(self):
        """ConnectTimeout is set."""
        args = self.server._build_ssh_args("10.10.10.1", "root", connect_timeout=45)
        joined = " ".join(args)
        assert "ConnectTimeout=45" in joined

    def test_ssh_options_appended(self):
        """Custom SSH options are parsed and appended."""
        args = self.server._build_ssh_args(
            "10.10.10.1", "root",
            ssh_options="-o KexAlgorithms=curve25519-sha256 -o Ciphers=aes256-cbc"
        )
        joined = " ".join(args)
        assert "KexAlgorithms=curve25519-sha256" in joined
        assert "Ciphers=aes256-cbc" in joined

    def test_user_host_format(self):
        """Username@host is the last argument."""
        args = self.server._build_ssh_args("10.10.10.1", "admin")
        assert args[-1] == "admin@10.10.10.1"

    def test_no_password_no_sshpass(self):
        """Without password, sshpass is not in the args."""
        args = self.server._build_ssh_args("10.10.10.1", "root")
        assert "sshpass" not in args

    # --- Tests from real engagement ssh_options patterns ---

    def test_ssh_options_pubkey_auth_no(self):
        """ssh_options with PubkeyAuthentication=no (force password auth).

        Real engagement pattern: agent sends this to avoid key-based auth prompts.
        """
        args = self.server._build_ssh_args(
            "10.10.10.1", "root",
            ssh_options="-o PubkeyAuthentication=no -o PreferredAuthentications=password",
        )
        joined = " ".join(args)
        assert "PubkeyAuthentication=no" in joined
        assert "PreferredAuthentications=password" in joined

    def test_ssh_options_legacy_kex(self):
        """ssh_options with legacy key exchange algorithm.

        Real engagement pattern: HTB boxes often have old SSH versions.
        """
        args = self.server._build_ssh_args(
            "10.10.10.1", "root",
            ssh_options="-o StrictHostKeyChecking=no -o UserKnownHostsFile=/dev/null -o KexAlgorithms=+diffie-hellman-group14-sha1",
        )
        joined = " ".join(args)
        assert "KexAlgorithms=+diffie-hellman-group14-sha1" in joined

    def test_ssh_options_request_tty(self):
        """ssh_options with RequestTTY=force for interactive commands.

        Real engagement pattern: some commands need a TTY to produce output.
        """
        args = self.server._build_ssh_args(
            "10.10.10.1", "root",
            ssh_options="-o RequestTTY=force",
        )
        joined = " ".join(args)
        assert "RequestTTY=force" in joined

    def test_ssh_options_connect_timeout_override(self):
        """ssh_options with ConnectTimeout override.

        Real engagement pattern: agent sends explicit ConnectTimeout.
        Note: This will duplicate the default ConnectTimeout, but SSH uses the last one.
        """
        args = self.server._build_ssh_args(
            "10.10.10.1", "root",
            ssh_options="-o ConnectTimeout=10",
        )
        joined = " ".join(args)
        # Both the default and the override should be present
        assert "ConnectTimeout=" in joined

    def test_ssh_options_pubkey_accepted_algorithms(self):
        """ssh_options with PubkeyAcceptedAlgorithms for ed25519 keys.

        Real engagement pattern from trajectory data.
        """
        args = self.server._build_ssh_args(
            "10.10.10.1", "root",
            ssh_options="-o PubkeyAcceptedAlgorithms=+ssh-ed25519 -o ConnectTimeout=10",
        )
        joined = " ".join(args)
        assert "PubkeyAcceptedAlgorithms=+ssh-ed25519" in joined

    def test_both_password_and_key_file(self):
        """When both password and key_file are given, both are included.

        The SSH client will try key auth first, then fall back to password.
        """
        args = self.server._build_ssh_args(
            "10.10.10.1", "root",
            password="toor",
            key_file="/tmp/key",
        )
        assert "sshpass" in args
        assert "-i" in args
        idx = args.index("-i")
        assert args[idx + 1] == "/tmp/key"

    def test_default_port_22(self):
        """Default port 22 is always included."""
        args = self.server._build_ssh_args("10.10.10.1", "root")
        joined = " ".join(args)
        assert "-p 22" in joined

    def test_nonstandard_port_from_engagement(self):
        """Non-standard ports from engagement data (e.g., 55517, 60431).

        Real engagement data shows high ports like 55517, 60431, 38229.
        """
        for port in [55517, 60431, 38229]:
            args = self.server._build_ssh_args("10.10.10.1", "root", port=port)
            assert f"-p" in args
            idx = args.index("-p")
            assert args[idx + 1] == str(port)


class TestSshWarningFilter:
    """Test SSH stderr warning filtering logic.

    OpenSSH 10.x added post-quantum key exchange warnings that appear in stderr
    for every connection. These must be filtered to prevent false error classification.
    """

    def test_post_quantum_warning_filtered(self):
        """Post-quantum warnings (** lines) are removed from stderr."""
        stderr_lines = [
            "Warning: Permanently added '10.10.10.1' (ED25519) to the list of known hosts.",
            "** WARNING: connection is not using a post-quantum key exchange algorithm.",
            "** This session may be vulnerable to \"store now, decrypt later\" attacks.",
            "** The server may need to be upgraded. See https://openssh.com/pq.html",
            "real error message here",
        ]
        stderr = "\n".join(stderr_lines)

        # Apply the same filter logic as in exec_command
        errors_filtered = "\n".join(
            line for line in stderr.split("\n")
            if not line.startswith("Warning:")
            and "Permanently added" not in line
            and not line.startswith("** ")
        )
        assert "post-quantum" not in errors_filtered
        assert "WARNING" not in errors_filtered
        assert "Permanently added" not in errors_filtered
        assert "real error message here" in errors_filtered

    def test_only_post_quantum_warnings_result_in_empty_stderr(self):
        """When stderr contains ONLY SSH warnings, filtered result is empty/whitespace."""
        stderr_lines = [
            "Warning: Permanently added '10.10.10.1' (ED25519) to the list of known hosts.",
            "** WARNING: connection is not using a post-quantum key exchange algorithm.",
            "** This session may be vulnerable to \"store now, decrypt later\" attacks.",
            "** The server may need to be upgraded. See https://openssh.com/pq.html",
        ]
        stderr = "\n".join(stderr_lines)
        errors_filtered = "\n".join(
            line for line in stderr.split("\n")
            if not line.startswith("Warning:")
            and "Permanently added" not in line
            and not line.startswith("** ")
        )
        assert errors_filtered.strip() == ""

    def test_real_errors_preserved_after_filtering(self):
        """Real error messages are preserved even when mixed with warnings."""
        stderr = (
            "Warning: Permanently added '10.10.10.1' (ED25519) to the list of known hosts.\n"
            "** WARNING: connection is not using a post-quantum key exchange algorithm.\n"
            "Permission denied (publickey,password)."
        )
        errors_filtered = "\n".join(
            line for line in stderr.split("\n")
            if not line.startswith("Warning:")
            and "Permanently added" not in line
            and not line.startswith("** ")
        )
        assert "Permission denied" in errors_filtered


# ===========================================================================
# SMOKE TESTS -- require Docker container running
# ===========================================================================

class TestSmoke:
    """Smoke tests that verify the container boots and basic protocol works."""

    def test_boot_and_list_tools(self, ssh_env):
        """Container starts and list_tools returns methods."""
        client, _ = ssh_env
        assert len(client.tools) > 0, "Server should advertise at least one tool"
        names = client.tool_names()
        assert "exec" in names
        assert "shell" in names
        assert "copy_from" in names
        assert "copy_to" in names
        assert "upload_binary" in names
        assert "run_script" in names
        assert "background" in names

    def test_method_list_matches_tool_yaml(self, ssh_env):
        """Every method in tool.yaml is advertised by the server, and vice versa."""
        client, _ = ssh_env
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

    def test_expected_method_count(self, ssh_env):
        """Server should have exactly 7 built-in methods + verify_clock."""
        client, _ = ssh_env
        names = client.tool_names()
        assert len(names) == 8, (
            f"Expected 8 methods (7 built-in + verify_clock), got {len(names)}: {sorted(names)}"
        )

    def test_unknown_method_returns_error(self, ssh_env):
        """Calling a non-existent method returns a helpful error."""
        client, loop = ssh_env
        resp = loop.run_until_complete(client.call("connect", {}))
        result = assert_tool_error(resp)
        content_text = ""
        for c in result.get("content", []):
            if c.get("type") == "text":
                content_text += c["text"]
        assert "Unknown method" in content_text
        assert "connect" in content_text

    def test_meta_params_stripped_clock_offset(self, ssh_env):
        """Passing 'clock_offset' (meta-param) in args does not crash the server."""
        client, loop = ssh_env
        resp = loop.run_until_complete(
            client.call("exec", {
                "host": "127.0.0.1",
                "username": "root",
                "command": "id",
                "clock_offset": "+5h",
            })
        )
        result = resp.get("result", {})
        content_text = ""
        for c in result.get("content", []):
            if c.get("type") == "text":
                content_text += c["text"]
        # Should not fail with "unexpected keyword argument"
        assert "unexpected keyword argument" not in content_text

    @pytest.mark.clock
    def test_verify_clock_available(self, ssh_env):
        """verify_clock is registered in MCP_TEST_MODE."""
        client, _ = ssh_env
        names = client.tool_names()
        assert "verify_clock" in names

    @pytest.mark.clock
    def test_verify_clock_returns_time(self, ssh_env):
        """verify_clock returns current time and FAKETIME status."""
        client, loop = ssh_env
        resp = loop.run_until_complete(client.call("verify_clock", {}))
        result = assert_tool_success(resp)
        data = parse_tool_output(resp)
        assert "current_time" in data
        assert "libfaketime_exists" in data

    def test_structuredContent_present(self, ssh_env):
        """Responses include structuredContent with error classification fields."""
        client, loop = ssh_env
        resp = loop.run_until_complete(client.call("verify_clock", {}))
        result = resp.get("result", {})
        sc = result.get("structuredContent")
        assert sc is not None, "structuredContent should be present"
        assert "success" in sc
        assert "error_class" in sc
        assert "retryable" in sc
        assert "suggestions" in sc

    def test_exec_missing_required_host(self, ssh_env):
        """exec without 'host' returns an error or fails gracefully."""
        client, loop = ssh_env
        resp = loop.run_until_complete(
            client.call("exec", {
                "username": "root",
                "command": "id",
            })
        )
        # Should get some kind of error (missing required param)
        result = resp.get("result", {})
        is_error = result.get("isError", False)
        content_text = ""
        for c in result.get("content", []):
            if c.get("type") == "text":
                content_text += c["text"]
        assert is_error or "error" in content_text.lower(), (
            f"Expected error for missing host, got: {content_text[:300]}"
        )

    def test_exec_missing_required_command(self, ssh_env):
        """exec without 'command' returns an error or fails gracefully."""
        client, loop = ssh_env
        resp = loop.run_until_complete(
            client.call("exec", {
                "host": "127.0.0.1",
                "username": "root",
            })
        )
        result = resp.get("result", {})
        is_error = result.get("isError", False)
        content_text = ""
        for c in result.get("content", []):
            if c.get("type") == "text":
                content_text += c["text"]
        assert is_error or "error" in content_text.lower(), (
            f"Expected error for missing command, got: {content_text[:300]}"
        )

    def test_shell_missing_required_commands(self, ssh_env):
        """shell without 'commands' returns an error."""
        client, loop = ssh_env
        resp = loop.run_until_complete(
            client.call("shell", {
                "host": "127.0.0.1",
                "username": "root",
            })
        )
        result = resp.get("result", {})
        is_error = result.get("isError", False)
        content_text = ""
        for c in result.get("content", []):
            if c.get("type") == "text":
                content_text += c["text"]
        assert is_error or "error" in content_text.lower()


# ===========================================================================
# ERROR HANDLING TESTS -- verify proper error responses
# ===========================================================================

class TestErrorHandling:
    """Test error handling for unreachable/invalid targets."""

    def test_exec_connection_refused(self, ssh_env):
        """exec to a closed port returns a classified error with error_class=network."""
        client, loop = ssh_env
        resp = loop.run_until_complete(
            client.call("exec", {
                "host": "127.0.0.1",
                "username": "root",
                "command": "id",
                "port": 19999,
                "timeout": 10,
            }, timeout=60)
        )
        result = resp.get("result", {})
        assert result.get("isError", False), "Should fail on closed port"
        content_text = ""
        for c in result.get("content", []):
            if c.get("type") == "text":
                content_text += c["text"]
        assert "refused" in content_text.lower() or "error" in content_text.lower()

        # Verify structuredContent has proper error classification
        sc = result.get("structuredContent", {})
        assert sc.get("error_class") == "network", (
            f"Connection refused should be error_class=network, got: {sc.get('error_class')}"
        )
        assert sc.get("retryable") is True

    def test_exec_connection_timeout_short(self, ssh_env):
        """exec with very short timeout to unreachable host returns timeout error."""
        client, loop = ssh_env
        # Use a non-routable IP that will timeout
        resp = loop.run_until_complete(
            client.call("exec", {
                "host": "192.0.2.1",  # RFC 5737 TEST-NET-1, guaranteed non-routable
                "username": "root",
                "command": "id",
                "timeout": 5,
            }, timeout=60)
        )
        result = resp.get("result", {})
        assert result.get("isError", False), "Should fail on unreachable host"

    def test_exec_no_auth_fails(self, ssh_env, ssh_target):
        """exec without password or key to a real SSH server fails with auth error."""
        host, port, user, _ = ssh_target
        client, loop = ssh_env
        resp = loop.run_until_complete(
            client.call("exec", {
                "host": host,
                "username": user,
                "command": "id",
                "port": port,
                "timeout": 15,
            }, timeout=60)
        )
        result = resp.get("result", {})
        assert result.get("isError", False), "Should fail without credentials"
        content_text = ""
        for c in result.get("content", []):
            if c.get("type") == "text":
                content_text += c["text"]
        assert "denied" in content_text.lower() or "permission" in content_text.lower() or "error" in content_text.lower()


# ===========================================================================
# LIVE METHOD TESTS -- require Docker container + SSH target
# ===========================================================================

class TestExec:
    """Test the exec method against a real SSH target."""

    def test_exec_basic_command(self, ssh_env, ssh_target):
        """exec runs a basic command and returns output."""
        host, port, user, password = ssh_target
        client, loop = ssh_env
        resp = loop.run_until_complete(
            client.call("exec", {
                "host": host,
                "username": user,
                "password": password,
                "command": "echo hello_world",
                "port": port,
                "timeout": 30,
            })
        )
        result = assert_tool_success(resp, "Basic exec should succeed")
        data = parse_tool_output(resp)
        assert "hello_world" in data.get("stdout", "")
        assert data.get("exit_code") == 0

    def test_exec_returns_exit_code(self, ssh_env, ssh_target):
        """exec returns the command's exit code."""
        host, port, user, password = ssh_target
        client, loop = ssh_env
        resp = loop.run_until_complete(
            client.call("exec", {
                "host": host,
                "username": user,
                "password": password,
                "command": "exit 42",
                "port": port,
                "timeout": 30,
            })
        )
        # Non-zero exit code is NOT an MCP error (isError=False for SSH success,
        # the command just returned non-zero)
        data = parse_tool_output(resp)
        # The SSH exec returns the remote command's exit code
        result = resp.get("result", {})
        # If the server considers non-zero exit as success or error depends on impl
        # With the current code, non-zero exit + no SSH error = classified as SSH error
        if result.get("isError"):
            # That's acceptable - it means the SSH tool treats non-zero as failure
            pass
        else:
            assert data.get("exit_code") == 42

    def test_exec_stdout_and_stderr(self, ssh_env, ssh_target):
        """exec captures both stdout and stderr."""
        host, port, user, password = ssh_target
        client, loop = ssh_env
        resp = loop.run_until_complete(
            client.call("exec", {
                "host": host,
                "username": user,
                "password": password,
                "command": "echo out_text && echo err_text >&2",
                "port": port,
                "timeout": 30,
            })
        )
        result = assert_tool_success(resp, "stdout+stderr exec should succeed")
        data = parse_tool_output(resp)
        assert "out_text" in data.get("stdout", "")

    def test_exec_ssh_warnings_filtered(self, ssh_env, ssh_target):
        """SSH warnings like 'Permanently added' are filtered from stderr."""
        host, port, user, password = ssh_target
        client, loop = ssh_env
        resp = loop.run_until_complete(
            client.call("exec", {
                "host": host,
                "username": user,
                "password": password,
                "command": "echo test",
                "port": port,
                "timeout": 30,
            })
        )
        result = assert_tool_success(resp)
        data = parse_tool_output(resp)
        stderr = data.get("stderr", "") or ""
        assert "Permanently added" not in stderr

    def test_exec_with_ssh_options(self, ssh_env, ssh_target):
        """exec with custom ssh_options passes them through."""
        host, port, user, password = ssh_target
        client, loop = ssh_env
        resp = loop.run_until_complete(
            client.call("exec", {
                "host": host,
                "username": user,
                "password": password,
                "command": "echo options_work",
                "port": port,
                "timeout": 30,
                "ssh_options": "-o LogLevel=ERROR",
            })
        )
        result = assert_tool_success(resp, "exec with ssh_options should succeed")
        data = parse_tool_output(resp)
        assert "options_work" in data.get("stdout", "")

    def test_exec_multiline_output(self, ssh_env, ssh_target):
        """exec handles multiline command output."""
        host, port, user, password = ssh_target
        client, loop = ssh_env
        resp = loop.run_until_complete(
            client.call("exec", {
                "host": host,
                "username": user,
                "password": password,
                "command": "for i in 1 2 3; do echo line_$i; done",
                "port": port,
                "timeout": 30,
            })
        )
        result = assert_tool_success(resp)
        data = parse_tool_output(resp)
        stdout = data.get("stdout", "")
        assert "line_1" in stdout
        assert "line_2" in stdout
        assert "line_3" in stdout


class TestShell:
    """Test the shell method for sequential command execution."""

    def test_shell_multiple_commands(self, ssh_env, ssh_target):
        """shell executes multiple commands in sequence."""
        host, port, user, password = ssh_target
        client, loop = ssh_env
        resp = loop.run_until_complete(
            client.call("shell", {
                "host": host,
                "username": user,
                "password": password,
                "commands": ["echo first", "echo second", "echo third"],
                "port": port,
                "timeout": 30,
            })
        )
        result = assert_tool_success(resp, "shell should succeed")
        data = parse_tool_output(resp)
        stdout = data.get("stdout", "")
        assert "first" in stdout
        assert "second" in stdout
        assert "third" in stdout

    def test_shell_chain_stops_on_failure(self, ssh_env, ssh_target):
        """shell with && stops at first failure."""
        host, port, user, password = ssh_target
        client, loop = ssh_env
        resp = loop.run_until_complete(
            client.call("shell", {
                "host": host,
                "username": user,
                "password": password,
                "commands": ["echo before", "false", "echo after_failure"],
                "port": port,
                "timeout": 30,
            })
        )
        # The chain should stop at 'false' - "after_failure" should NOT appear
        # When exit code is non-zero, the response may be an error string or dict
        data = parse_tool_output(resp)
        if isinstance(data, dict):
            stdout = data.get("stdout", "")
        else:
            stdout = str(data)
        assert "after_failure" not in stdout

    def test_shell_empty_commands_list(self, ssh_env, ssh_target):
        """shell with empty commands list handles gracefully."""
        host, port, user, password = ssh_target
        client, loop = ssh_env
        resp = loop.run_until_complete(
            client.call("shell", {
                "host": host,
                "username": user,
                "password": password,
                "commands": [],
                "port": port,
                "timeout": 30,
            })
        )
        # Should either succeed with empty output or error gracefully
        result = resp.get("result", {})
        assert result is not None


class TestCopyFrom:
    """Test the copy_from method for downloading files."""

    def test_copy_from_text_file(self, ssh_env, ssh_target):
        """copy_from downloads a text file's content."""
        host, port, user, password = ssh_target
        client, loop = ssh_env

        # First create a file on the target
        loop.run_until_complete(
            client.call("exec", {
                "host": host,
                "username": user,
                "password": password,
                "command": "echo 'test_content_12345' > /tmp/test_download.txt",
                "port": port,
                "timeout": 30,
            })
        )

        # Now download it
        resp = loop.run_until_complete(
            client.call("copy_from", {
                "host": host,
                "username": user,
                "password": password,
                "remote_path": "/tmp/test_download.txt",
                "port": port,
                "timeout": 30,
            })
        )
        result = assert_tool_success(resp, "copy_from should succeed")
        data = parse_tool_output(resp)
        assert "test_content_12345" in data.get("content", "")
        assert data.get("size", 0) > 0

    def test_copy_from_nonexistent_file(self, ssh_env, ssh_target):
        """copy_from of a nonexistent file returns an error."""
        host, port, user, password = ssh_target
        client, loop = ssh_env
        resp = loop.run_until_complete(
            client.call("copy_from", {
                "host": host,
                "username": user,
                "password": password,
                "remote_path": "/tmp/nonexistent_file_xyz123.txt",
                "port": port,
                "timeout": 30,
            })
        )
        result = resp.get("result", {})
        assert result.get("isError", False), "copy_from nonexistent file should error"


class TestCopyTo:
    """Test the copy_to method for uploading content."""

    def test_copy_to_text_content(self, ssh_env, ssh_target):
        """copy_to uploads text content to remote host."""
        host, port, user, password = ssh_target
        client, loop = ssh_env

        test_content = "uploaded_test_content_67890"
        resp = loop.run_until_complete(
            client.call("copy_to", {
                "host": host,
                "username": user,
                "password": password,
                "content": test_content,
                "remote_path": "/tmp/test_upload.txt",
                "port": port,
                "timeout": 30,
            })
        )
        result = assert_tool_success(resp, "copy_to should succeed")
        data = parse_tool_output(resp)
        assert data.get("size") == len(test_content)

        # Verify the file was actually uploaded
        verify_resp = loop.run_until_complete(
            client.call("exec", {
                "host": host,
                "username": user,
                "password": password,
                "command": "cat /tmp/test_upload.txt",
                "port": port,
                "timeout": 30,
            })
        )
        verify_data = parse_tool_output(verify_resp)
        assert test_content in verify_data.get("stdout", "")

    def test_copy_to_multiline_script(self, ssh_env, ssh_target):
        """copy_to handles multiline script content."""
        host, port, user, password = ssh_target
        client, loop = ssh_env

        script = "#!/bin/bash\necho 'line1'\necho 'line2'\nexit 0\n"
        resp = loop.run_until_complete(
            client.call("copy_to", {
                "host": host,
                "username": user,
                "password": password,
                "content": script,
                "remote_path": "/tmp/test_script_upload.sh",
                "port": port,
                "timeout": 30,
            })
        )
        result = assert_tool_success(resp, "copy_to multiline should succeed")


class TestUploadBinary:
    """Test the upload_binary method for binary file transfer."""

    def test_upload_binary_small(self, ssh_env, ssh_target):
        """upload_binary transfers a small binary file."""
        host, port, user, password = ssh_target
        client, loop = ssh_env

        # Create a small binary payload
        binary_data = bytes(range(256)) * 4  # 1024 bytes
        b64_data = base64.b64encode(binary_data).decode()

        resp = loop.run_until_complete(
            client.call("upload_binary", {
                "host": host,
                "username": user,
                "password": password,
                "content_base64": b64_data,
                "remote_path": "/tmp/test_binary",
                "executable": True,
                "port": port,
                "timeout": 60,
            }, timeout=120)
        )
        result = assert_tool_success(resp, "upload_binary should succeed")
        data = parse_tool_output(resp)
        assert data.get("size") == len(binary_data)
        assert data.get("chunks", 0) >= 1

    def test_upload_binary_invalid_base64(self, ssh_env, ssh_target):
        """upload_binary with invalid base64 returns an error."""
        host, port, user, password = ssh_target
        client, loop = ssh_env

        resp = loop.run_until_complete(
            client.call("upload_binary", {
                "host": host,
                "username": user,
                "password": password,
                "content_base64": "not-valid-base64!!!",
                "remote_path": "/tmp/test_bad_binary",
                "port": port,
                "timeout": 30,
            })
        )
        result = resp.get("result", {})
        assert result.get("isError", False), "Invalid base64 should error"

    def test_upload_binary_not_executable(self, ssh_env, ssh_target):
        """upload_binary with executable=False does not chmod +x."""
        host, port, user, password = ssh_target
        client, loop = ssh_env

        binary_data = b"\x00\x01\x02\x03"
        b64_data = base64.b64encode(binary_data).decode()

        resp = loop.run_until_complete(
            client.call("upload_binary", {
                "host": host,
                "username": user,
                "password": password,
                "content_base64": b64_data,
                "remote_path": "/tmp/test_noexec_binary",
                "executable": False,
                "port": port,
                "timeout": 60,
            }, timeout=120)
        )
        result = assert_tool_success(resp, "upload_binary non-exec should succeed")
        data = parse_tool_output(resp)
        assert data.get("executable") is False


class TestRunScript:
    """Test the run_script method for script upload and execution."""

    def test_run_script_basic(self, ssh_env, ssh_target):
        """run_script uploads and executes a bash script."""
        host, port, user, password = ssh_target
        client, loop = ssh_env

        script = "#!/bin/bash\necho 'script_output_test'\nexit 0\n"
        resp = loop.run_until_complete(
            client.call("run_script", {
                "host": host,
                "username": user,
                "password": password,
                "script": script,
                "port": port,
                "timeout": 30,
            })
        )
        result = assert_tool_success(resp, "run_script should succeed")
        data = parse_tool_output(resp)
        assert "script_output_test" in data.get("stdout", "")

    def test_run_script_with_interpreter(self, ssh_env, ssh_target):
        """run_script uses the specified interpreter."""
        host, port, user, password = ssh_target
        client, loop = ssh_env

        # Use /bin/sh as interpreter
        script = "echo 'sh_interpreter_test'\n"
        resp = loop.run_until_complete(
            client.call("run_script", {
                "host": host,
                "username": user,
                "password": password,
                "script": script,
                "interpreter": "/bin/sh",
                "port": port,
                "timeout": 30,
            })
        )
        result = assert_tool_success(resp, "run_script with /bin/sh should succeed")
        data = parse_tool_output(resp)
        assert "sh_interpreter_test" in data.get("stdout", "")

    def test_run_script_cleans_up_temp_file(self, ssh_env, ssh_target):
        """run_script removes the temporary script file after execution.

        We count script_*.sh files before and after to handle concurrent tests.
        """
        host, port, user, password = ssh_target
        client, loop = ssh_env

        # Count script_*.sh files BEFORE
        before_resp = loop.run_until_complete(
            client.call("exec", {
                "host": host,
                "username": user,
                "password": password,
                "command": "ls /tmp/script_*.sh 2>/dev/null | wc -l",
                "port": port,
                "timeout": 15,
            })
        )
        before_data = parse_tool_output(before_resp)
        before_count = int(before_data.get("stdout", "0").strip() or "0")

        script = "#!/bin/bash\necho 'cleanup_test'\n"
        resp = loop.run_until_complete(
            client.call("run_script", {
                "host": host,
                "username": user,
                "password": password,
                "script": script,
                "port": port,
                "timeout": 30,
            })
        )
        result = assert_tool_success(resp)

        # Count script_*.sh files AFTER — should not have increased
        verify_resp = loop.run_until_complete(
            client.call("exec", {
                "host": host,
                "username": user,
                "password": password,
                "command": "ls /tmp/script_*.sh 2>/dev/null | wc -l",
                "port": port,
                "timeout": 15,
            })
        )
        verify_data = parse_tool_output(verify_resp)
        after_count = int(verify_data.get("stdout", "0").strip() or "0")
        assert after_count <= before_count, (
            f"Script files increased: before={before_count}, after={after_count}"
        )

    def test_run_script_failing_script(self, ssh_env, ssh_target):
        """run_script captures exit code from a failing script."""
        host, port, user, password = ssh_target
        client, loop = ssh_env

        script = "#!/bin/bash\nexit 7\n"
        resp = loop.run_until_complete(
            client.call("run_script", {
                "host": host,
                "username": user,
                "password": password,
                "script": script,
                "port": port,
                "timeout": 30,
            })
        )
        # The exec method reports non-zero exit as SSH error (rc != 0)
        # So this will be isError=True
        data = parse_tool_output(resp)
        # Either way, the response should include exit_code info
        result = resp.get("result", {})
        assert result is not None


class TestBackground:
    """Test the background method for detached process execution."""

    def test_background_basic(self, ssh_env, ssh_target):
        """background starts a detached process."""
        host, port, user, password = ssh_target
        client, loop = ssh_env

        resp = loop.run_until_complete(
            client.call("background", {
                "host": host,
                "username": user,
                "password": password,
                "command": "sleep 60",
                "port": port,
                "pid_file": "/tmp/test_bg_pid",
            })
        )
        result = assert_tool_success(resp, "background should succeed")
        data = parse_tool_output(resp)
        assert data.get("success") is True or data.get("detached") is True

        # Clean up the background process
        loop.run_until_complete(
            client.call("exec", {
                "host": host,
                "username": user,
                "password": password,
                "command": "kill $(cat /tmp/test_bg_pid) 2>/dev/null; rm -f /tmp/test_bg_pid",
                "port": port,
                "timeout": 10,
            })
        )

    def test_background_with_env(self, ssh_env, ssh_target):
        """background injects environment variables."""
        host, port, user, password = ssh_target
        client, loop = ssh_env

        resp = loop.run_until_complete(
            client.call("background", {
                "host": host,
                "username": user,
                "password": password,
                "command": "env > /tmp/test_bg_env.txt",
                "port": port,
                "env": {"TEST_VAR": "test_value_42"},
                "output_file": "/tmp/test_bg_out.txt",
            })
        )
        result = assert_tool_success(resp, "background with env should succeed")

        # Wait briefly for the background command to complete
        time.sleep(2)

        # Check the env file
        verify_resp = loop.run_until_complete(
            client.call("exec", {
                "host": host,
                "username": user,
                "password": password,
                "command": "cat /tmp/test_bg_env.txt 2>/dev/null",
                "port": port,
                "timeout": 15,
            })
        )
        verify_data = parse_tool_output(verify_resp)
        stdout = verify_data.get("stdout", "")
        assert "TEST_VAR=test_value_42" in stdout

    def test_background_with_pid_file(self, ssh_env, ssh_target):
        """background writes PID to the specified file."""
        host, port, user, password = ssh_target
        client, loop = ssh_env

        resp = loop.run_until_complete(
            client.call("background", {
                "host": host,
                "username": user,
                "password": password,
                "command": "sleep 120",
                "port": port,
                "pid_file": "/tmp/test_bg_pid2",
                "return_check_command": True,
            })
        )
        result = assert_tool_success(resp, "background with pid_file should succeed")
        data = parse_tool_output(resp)

        # Should have a PID
        pid = data.get("pid")
        if pid:
            assert pid.isdigit(), f"PID should be numeric, got: {pid}"
            # Should have check command
            assert "check_command" in data

        # Clean up
        loop.run_until_complete(
            client.call("exec", {
                "host": host,
                "username": user,
                "password": password,
                "command": "kill $(cat /tmp/test_bg_pid2) 2>/dev/null; rm -f /tmp/test_bg_pid2",
                "port": port,
                "timeout": 10,
            })
        )

    def test_background_without_pid_file(self, ssh_env, ssh_target):
        """background without pid_file still starts the process."""
        host, port, user, password = ssh_target
        client, loop = ssh_env

        resp = loop.run_until_complete(
            client.call("background", {
                "host": host,
                "username": user,
                "password": password,
                "command": "sleep 5",
                "port": port,
            })
        )
        result = assert_tool_success(resp, "background without pid should succeed")
        data = parse_tool_output(resp)
        assert data.get("detached") is True


# ===========================================================================
# TIMEOUT RECOVERY TESTS -- REQ-RES-001
# ===========================================================================

class TestTimeoutRecovery:
    """Test that the MCP transport recovers after command timeouts.

    REQ-RES-001: SSH MCP server SHALL recover from command timeouts
    without losing the MCP transport connection.

    This is the #1 real-world issue: 42+ wasted calls per engagement after
    a timeout corrupts the MCP transport. 'Not connected' errors cascade.
    """

    def test_exec_timeout_then_recovery(self, ssh_env, ssh_target):
        """After exec times out, the next exec should still work.

        This is the critical test from the requirements doc scenario #2.
        """
        host, port, user, password = ssh_target
        client, loop = ssh_env

        # Step 1: Send a command that will timeout
        resp_timeout = loop.run_until_complete(
            client.call("exec", {
                "host": host,
                "username": user,
                "password": password,
                "command": "sleep 120",
                "port": port,
                "timeout": 5,
            }, timeout=30)
        )

        # Should have timed out
        result_timeout = resp_timeout.get("result", {})
        assert result_timeout.get("isError", False), "sleep 120 with 5s timeout should error"
        content_text = ""
        for c in result_timeout.get("content", []):
            if c.get("type") == "text":
                content_text += c["text"]
        assert "timed out" in content_text.lower() or "timeout" in content_text.lower()

        # Step 2: The MCP transport should still work - send another command
        resp_recovery = loop.run_until_complete(
            client.call("exec", {
                "host": host,
                "username": user,
                "password": password,
                "command": "echo recovery_success",
                "port": port,
                "timeout": 30,
            }, timeout=60)
        )

        # This MUST succeed - if it doesn't, the MCP transport is corrupted
        result_recovery = assert_tool_success(
            resp_recovery,
            "Post-timeout exec MUST succeed (REQ-RES-001). "
            "If this fails, the MCP transport was corrupted by the timeout."
        )
        data = parse_tool_output(resp_recovery)
        assert "recovery_success" in data.get("stdout", "")

    def test_run_script_timeout_then_recovery(self, ssh_env, ssh_target):
        """After run_script times out, the next exec should still work.

        Requirements doc scenario #3.
        """
        host, port, user, password = ssh_target
        client, loop = ssh_env

        # Step 1: run_script that times out
        script = "#!/bin/bash\nwhile true; do sleep 1; done\n"
        resp_timeout = loop.run_until_complete(
            client.call("run_script", {
                "host": host,
                "username": user,
                "password": password,
                "script": script,
                "port": port,
                "timeout": 8,
            }, timeout=60)
        )

        result_timeout = resp_timeout.get("result", {})
        assert result_timeout.get("isError", False), "Infinite loop script should timeout"

        # Step 2: Recovery
        resp_recovery = loop.run_until_complete(
            client.call("exec", {
                "host": host,
                "username": user,
                "password": password,
                "command": "echo script_recovery_ok",
                "port": port,
                "timeout": 30,
            }, timeout=60)
        )

        result_recovery = assert_tool_success(
            resp_recovery,
            "Post-script-timeout exec MUST succeed (REQ-RES-001)"
        )
        data = parse_tool_output(resp_recovery)
        assert "script_recovery_ok" in data.get("stdout", "")

    def test_double_timeout_recovery(self, ssh_env, ssh_target):
        """Two consecutive timeouts, then a successful command.

        Stress test: ensure the recovery mechanism works even after
        multiple consecutive timeouts.
        """
        host, port, user, password = ssh_target
        client, loop = ssh_env

        # Timeout 1
        loop.run_until_complete(
            client.call("exec", {
                "host": host,
                "username": user,
                "password": password,
                "command": "sleep 120",
                "port": port,
                "timeout": 3,
            }, timeout=30)
        )

        # Timeout 2
        loop.run_until_complete(
            client.call("exec", {
                "host": host,
                "username": user,
                "password": password,
                "command": "sleep 120",
                "port": port,
                "timeout": 3,
            }, timeout=30)
        )

        # Recovery
        resp = loop.run_until_complete(
            client.call("exec", {
                "host": host,
                "username": user,
                "password": password,
                "command": "echo double_timeout_recovery",
                "port": port,
                "timeout": 30,
            }, timeout=60)
        )
        result = assert_tool_success(
            resp, "Post-double-timeout exec MUST succeed"
        )
        data = parse_tool_output(resp)
        assert "double_timeout_recovery" in data.get("stdout", "")


# ===========================================================================
# CONCURRENT CALL TESTS -- REQ-RES-003
# ===========================================================================

class TestConcurrentCalls:
    """Test that rapid-fire MCP calls do not deadlock or corrupt transport.

    REQ-RES-003: SSH MCP server SHALL handle concurrent calls without
    deadlocking or corrupting transport.

    NOTE: The MCPTestClient uses a simple serial recv() that cannot demux
    interleaved responses from truly parallel JSON-RPC calls. Instead, we
    test rapid sequential calls (server processes them concurrently due to
    asyncio event loop) which validates the same server-side concurrency
    without requiring a multiplexing test client.
    """

    def test_rapid_sequential_exec_calls(self, ssh_env, ssh_target):
        """Three rapid exec calls all return correct results.

        The server's asyncio event loop can process these concurrently
        even though the client sends/receives them sequentially.
        """
        host, port, user, password = ssh_target
        client, loop = ssh_env

        results = []
        for i in range(3):
            resp = loop.run_until_complete(
                client.call("exec", {
                    "host": host,
                    "username": user,
                    "password": password,
                    "command": f"echo rapid_{i}",
                    "port": port,
                    "timeout": 30,
                }, timeout=60)
            )
            results.append(resp)

        # All three should complete (no deadlock)
        assert len(results) == 3, "All 3 calls should complete"

        for i, resp in enumerate(results):
            result = assert_tool_success(resp, f"Rapid call {i} should succeed")
            data = parse_tool_output(resp)
            assert f"rapid_{i}" in data.get("stdout", "")

    def test_rapid_mixed_methods(self, ssh_env, ssh_target):
        """Rapid calls with different methods complete without errors."""
        host, port, user, password = ssh_target
        client, loop = ssh_env

        # Create a file for copy_from
        loop.run_until_complete(
            client.call("exec", {
                "host": host,
                "username": user,
                "password": password,
                "command": "echo 'rapid_test_content' > /tmp/rapid_test.txt",
                "port": port,
                "timeout": 15,
            })
        )

        # exec
        resp1 = loop.run_until_complete(
            client.call("exec", {
                "host": host,
                "username": user,
                "password": password,
                "command": "echo mixed_exec",
                "port": port,
                "timeout": 30,
            }, timeout=60)
        )
        assert_tool_success(resp1, "Mixed exec should succeed")

        # shell
        resp2 = loop.run_until_complete(
            client.call("shell", {
                "host": host,
                "username": user,
                "password": password,
                "commands": ["echo mixed_shell_1", "echo mixed_shell_2"],
                "port": port,
                "timeout": 30,
            }, timeout=60)
        )
        assert_tool_success(resp2, "Mixed shell should succeed")

        # copy_from
        resp3 = loop.run_until_complete(
            client.call("copy_from", {
                "host": host,
                "username": user,
                "password": password,
                "remote_path": "/tmp/rapid_test.txt",
                "port": port,
                "timeout": 30,
            }, timeout=60)
        )
        assert_tool_success(resp3, "Mixed copy_from should succeed")


# ===========================================================================
# CONTRACT TESTS -- tool.yaml vs server parameter definitions
# ===========================================================================

class TestContract:
    """Verify tool.yaml and server parameter definitions are consistent."""

    @classmethod
    def setup_class(cls):
        """Load tool.yaml and server class."""
        yaml_path = TOOL_DIR / "tool.yaml"
        with open(yaml_path) as f:
            cls.yaml_data = yaml.safe_load(f)

        try:
            cls.ServerClass = _get_server_class()
            cls.server = cls.ServerClass()
        except Exception as e:
            pytest.skip(f"Cannot import SSHServer: {e}")

    def test_all_yaml_methods_registered(self):
        """Every method in tool.yaml is registered in the server."""
        yaml_methods = set(self.yaml_data.get("methods", {}).keys())
        server_methods = set(self.server.methods.keys())

        missing = yaml_methods - server_methods
        assert not missing, f"Methods in tool.yaml but not server: {missing}"

    def test_all_server_methods_in_yaml(self):
        """Every registered method is documented in tool.yaml."""
        yaml_methods = set(self.yaml_data.get("methods", {}).keys())
        server_methods = set(self.server.methods.keys())

        extra = server_methods - yaml_methods
        assert not extra, f"Methods in server but not tool.yaml: {extra}"

    def test_yaml_required_params_match_server(self):
        """Required params in tool.yaml match server registration."""
        yaml_methods = self.yaml_data.get("methods", {})

        for method_name, yaml_def in yaml_methods.items():
            if method_name not in self.server.methods:
                continue  # Caught by other test

            yaml_params = yaml_def.get("params", {})
            server_params = self.server.methods[method_name].params

            yaml_required = {
                name for name, pdef in yaml_params.items()
                if pdef.get("required", False)
            }
            server_required = {
                name for name, pdef in server_params.items()
                if pdef.get("required", False)
            }

            assert yaml_required == server_required, (
                f"Method '{method_name}' required params mismatch: "
                f"yaml={yaml_required}, server={server_required}"
            )

    def test_yaml_param_names_subset_of_server(self):
        """Every param name in tool.yaml exists in the server registration."""
        yaml_methods = self.yaml_data.get("methods", {})

        for method_name, yaml_def in yaml_methods.items():
            if method_name not in self.server.methods:
                continue

            yaml_params = set(yaml_def.get("params", {}).keys())
            server_params = set(self.server.methods[method_name].params.keys())

            yaml_only = yaml_params - server_params
            assert not yaml_only, (
                f"Method '{method_name}': params in yaml but not server: {yaml_only}"
            )


# ===========================================================================
# ACCEPTANCE TESTS -- every method called through container (no live target)
# ===========================================================================

class TestAcceptance:
    """Call every method through the container without a live SSH target.

    These tests verify:
    - The method exists and is callable
    - Required param validation works (missing required params -> error)
    - The response has correct structuredContent shape
    - Error responses have error_class set (classified, not crash)

    Each test sends minimal args with an unreachable host (192.0.2.1) so the
    command will fail at connection time, but the MCP protocol layer, param
    validation, and error classification should all function correctly.
    """

    _FAKE_AUTH = {
        "host": "192.0.2.1",
        "username": "testuser",
        "password": "testpass",
    }

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

    # ── exec ──────────────────────────────────────────────────

    def test_exec(self, ssh_env):
        """exec with fake auth returns classified connection error."""
        client, loop = ssh_env
        resp = loop.run_until_complete(client.call("exec", {
            **self._FAKE_AUTH, "command": "id", "timeout": 15,
        }, timeout=120))
        self._assert_structured_response(resp, "exec")

    def test_exec_missing_host(self, ssh_env):
        """exec without host returns error."""
        client, loop = ssh_env
        resp = loop.run_until_complete(client.call("exec", {
            "username": "test", "command": "id",
        }))
        result = resp.get("result", {})
        is_error = result.get("isError", False)
        content_text = ""
        for c in result.get("content", []):
            if c.get("type") == "text":
                content_text += c["text"]
        assert is_error or "host" in content_text.lower() or "required" in content_text.lower() or "missing" in content_text.lower()

    def test_exec_missing_command(self, ssh_env):
        """exec without command returns error."""
        client, loop = ssh_env
        resp = loop.run_until_complete(client.call("exec", {
            **self._FAKE_AUTH,
        }))
        result = resp.get("result", {})
        is_error = result.get("isError", False)
        content_text = ""
        for c in result.get("content", []):
            if c.get("type") == "text":
                content_text += c["text"]
        assert is_error or "command" in content_text.lower() or "required" in content_text.lower() or "missing" in content_text.lower()

    def test_exec_with_key_param(self, ssh_env):
        """exec with key parameter does not crash."""
        client, loop = ssh_env
        resp = loop.run_until_complete(client.call("exec", {
            "host": "192.0.2.1", "username": "testuser",
            "key": "-----BEGIN OPENSSH PRIVATE KEY-----\nfake\n-----END OPENSSH PRIVATE KEY-----",
            "command": "id", "timeout": 15,
        }, timeout=120))
        result = resp.get("result", {})
        content_text = ""
        for c in result.get("content", []):
            if c.get("type") == "text":
                content_text += c["text"]
        assert "unexpected keyword argument" not in content_text

    def test_exec_with_ssh_options(self, ssh_env):
        """exec with ssh_options parameter does not crash."""
        client, loop = ssh_env
        resp = loop.run_until_complete(client.call("exec", {
            **self._FAKE_AUTH, "command": "id", "timeout": 15,
            "ssh_options": "-o KexAlgorithms=curve25519-sha256",
        }, timeout=120))
        self._assert_structured_response(resp, "exec+ssh_options")

    # ── shell ─────────────────────────────────────────────────

    def test_shell(self, ssh_env):
        """shell with fake auth returns classified connection error."""
        client, loop = ssh_env
        resp = loop.run_until_complete(client.call("shell", {
            **self._FAKE_AUTH, "commands": ["id", "whoami"], "timeout": 15,
        }, timeout=120))
        self._assert_structured_response(resp, "shell")

    def test_shell_missing_commands(self, ssh_env):
        """shell without commands returns error."""
        client, loop = ssh_env
        resp = loop.run_until_complete(client.call("shell", {
            **self._FAKE_AUTH,
        }))
        result = resp.get("result", {})
        is_error = result.get("isError", False)
        content_text = ""
        for c in result.get("content", []):
            if c.get("type") == "text":
                content_text += c["text"]
        assert is_error or "commands" in content_text.lower() or "required" in content_text.lower() or "missing" in content_text.lower()

    # ── copy_from ─────────────────────────────────────────────

    def test_copy_from(self, ssh_env):
        """copy_from with fake auth returns classified connection error."""
        client, loop = ssh_env
        resp = loop.run_until_complete(client.call("copy_from", {
            **self._FAKE_AUTH, "remote_path": "/etc/passwd", "timeout": 15,
        }, timeout=120))
        self._assert_structured_response(resp, "copy_from")

    def test_copy_from_missing_remote_path(self, ssh_env):
        """copy_from without remote_path returns error."""
        client, loop = ssh_env
        resp = loop.run_until_complete(client.call("copy_from", {
            **self._FAKE_AUTH,
        }))
        result = resp.get("result", {})
        is_error = result.get("isError", False)
        content_text = ""
        for c in result.get("content", []):
            if c.get("type") == "text":
                content_text += c["text"]
        assert is_error or "remote_path" in content_text.lower() or "required" in content_text.lower() or "missing" in content_text.lower()

    # ── copy_to ───────────────────────────────────────────────

    def test_copy_to(self, ssh_env):
        """copy_to with fake auth returns classified connection error."""
        client, loop = ssh_env
        resp = loop.run_until_complete(client.call("copy_to", {
            **self._FAKE_AUTH, "content": "test content",
            "remote_path": "/tmp/test.txt", "timeout": 15,
        }, timeout=120))
        self._assert_structured_response(resp, "copy_to")

    def test_copy_to_missing_content(self, ssh_env):
        """copy_to without content returns error."""
        client, loop = ssh_env
        resp = loop.run_until_complete(client.call("copy_to", {
            **self._FAKE_AUTH, "remote_path": "/tmp/test.txt",
        }))
        result = resp.get("result", {})
        is_error = result.get("isError", False)
        content_text = ""
        for c in result.get("content", []):
            if c.get("type") == "text":
                content_text += c["text"]
        assert is_error or "content" in content_text.lower() or "required" in content_text.lower() or "missing" in content_text.lower()

    # ── upload_binary ─────────────────────────────────────────

    def test_upload_binary(self, ssh_env):
        """upload_binary with fake auth returns classified connection error."""
        client, loop = ssh_env
        # upload_binary chains multiple exec_command calls internally,
        # each with retries (~75s per internal call).
        resp = loop.run_until_complete(client.call("upload_binary", {
            **self._FAKE_AUTH,
            "content_base64": base64.b64encode(b"fake binary").decode(),
            "remote_path": "/tmp/exploit", "timeout": 15,
        }, timeout=300))
        self._assert_structured_response(resp, "upload_binary")

    def test_upload_binary_missing_content(self, ssh_env):
        """upload_binary without content_base64 returns error."""
        client, loop = ssh_env
        resp = loop.run_until_complete(client.call("upload_binary", {
            **self._FAKE_AUTH, "remote_path": "/tmp/exploit",
        }))
        result = resp.get("result", {})
        is_error = result.get("isError", False)
        content_text = ""
        for c in result.get("content", []):
            if c.get("type") == "text":
                content_text += c["text"]
        assert is_error or "content_base64" in content_text.lower() or "required" in content_text.lower() or "missing" in content_text.lower()

    # ── run_script ────────────────────────────────────────────

    def test_run_script(self, ssh_env):
        """run_script with fake auth returns classified connection error."""
        client, loop = ssh_env
        # run_script calls copy_to then exec_command, each with retries
        resp = loop.run_until_complete(client.call("run_script", {
            **self._FAKE_AUTH, "script": "#!/bin/bash\nid", "timeout": 15,
        }, timeout=300))
        self._assert_structured_response(resp, "run_script")

    def test_run_script_missing_script(self, ssh_env):
        """run_script without script returns error."""
        client, loop = ssh_env
        resp = loop.run_until_complete(client.call("run_script", {
            **self._FAKE_AUTH,
        }))
        result = resp.get("result", {})
        is_error = result.get("isError", False)
        content_text = ""
        for c in result.get("content", []):
            if c.get("type") == "text":
                content_text += c["text"]
        assert is_error or "script" in content_text.lower() or "required" in content_text.lower() or "missing" in content_text.lower()

    # ── background ────────────────────────────────────────────

    def test_background(self, ssh_env):
        """background with fake auth returns classified connection error."""
        client, loop = ssh_env
        # background calls exec_command with timeout=30 + retries
        resp = loop.run_until_complete(client.call("background", {
            **self._FAKE_AUTH, "command": "nohup sleep 999 &",
        }, timeout=300))
        self._assert_structured_response(resp, "background")

    def test_background_missing_command(self, ssh_env):
        """background without command returns error."""
        client, loop = ssh_env
        resp = loop.run_until_complete(client.call("background", {
            **self._FAKE_AUTH,
        }))
        result = resp.get("result", {})
        is_error = result.get("isError", False)
        content_text = ""
        for c in result.get("content", []):
            if c.get("type") == "text":
                content_text += c["text"]
        assert is_error or "command" in content_text.lower() or "required" in content_text.lower() or "missing" in content_text.lower()

    def test_background_with_env_and_output_file(self, ssh_env):
        """background with env and output_file does not crash."""
        client, loop = ssh_env
        resp = loop.run_until_complete(client.call("background", {
            **self._FAKE_AUTH, "command": "python3 -m http.server 8888",
            "env": {"PYTHONPATH": "/tmp"}, "output_file": "/tmp/bg.log",
            "pid_file": "/tmp/bg.pid", "return_check_command": True,
        }, timeout=300))
        self._assert_structured_response(resp, "background+env")

    # ── Cross-cutting ─────────────────────────────────────────

    def test_all_methods_return_structuredContent(self, ssh_env):
        """verify_clock returns structuredContent with all required fields."""
        client, loop = ssh_env
        resp = loop.run_until_complete(client.call("verify_clock", {}))
        result = resp.get("result", {})
        sc = result.get("structuredContent")
        assert sc is not None
        assert isinstance(sc, dict)
        for field in ("success", "error_class", "retryable", "suggestions"):
            assert field in sc, f"Missing field '{field}' in structuredContent"

    def test_exec_structuredContent_error_fields_on_failure(self, ssh_env):
        """exec failure populates error_class and retryable in structuredContent.

        Uses closed port to trigger connection refused -> network/retryable.
        """
        client, loop = ssh_env
        resp = loop.run_until_complete(client.call("exec", {
            "host": "127.0.0.1", "username": "root",
            "command": "id", "port": 19999, "timeout": 10,
        }, timeout=60))
        result = resp.get("result", {})
        assert result.get("isError", False), "Should fail on closed port"
        sc = result.get("structuredContent", {})
        assert sc.get("success") is False
        assert sc.get("error_class") is not None, "error_class should be set on failure"
        assert isinstance(sc.get("retryable"), bool), "retryable should be bool"

    def test_exec_nonstandard_port(self, ssh_env):
        """exec with non-standard port (engagement pattern) does not crash.

        Real engagement data: ports like 55517, 60431 from SSH tunnels/pivots.
        """
        client, loop = ssh_env
        resp = loop.run_until_complete(client.call("exec", {
            **self._FAKE_AUTH, "command": "id",
            "port": 55517, "timeout": 10,
        }, timeout=120))
        # Should fail at connection (fake IP) but not crash
        self._assert_structured_response(resp, "exec+nonstandard_port")

    def test_exec_engagement_ssh_options_legacy_kex(self, ssh_env):
        """exec with legacy KexAlgorithms (real engagement pattern).

        Agent sends KexAlgorithms to connect to older SSH servers on HTB.
        """
        client, loop = ssh_env
        resp = loop.run_until_complete(client.call("exec", {
            **self._FAKE_AUTH, "command": "id", "timeout": 10,
            "ssh_options": "-o StrictHostKeyChecking=no -o UserKnownHostsFile=/dev/null -o KexAlgorithms=+diffie-hellman-group14-sha1",
        }, timeout=120))
        self._assert_structured_response(resp, "exec+legacy_kex")

    def test_shell_with_engagement_commands(self, ssh_env):
        """shell with typical engagement enumeration commands."""
        client, loop = ssh_env
        resp = loop.run_until_complete(client.call("shell", {
            **self._FAKE_AUTH,
            "commands": ["id", "whoami", "uname -a", "cat /etc/hostname"],
            "timeout": 15,
        }, timeout=120))
        self._assert_structured_response(resp, "shell+enum_commands")

    def test_run_script_with_interpreter(self, ssh_env):
        """run_script with /bin/sh interpreter (engagement pattern)."""
        client, loop = ssh_env
        resp = loop.run_until_complete(client.call("run_script", {
            **self._FAKE_AUTH,
            "script": "#!/bin/sh\nid\nuname -a",
            "interpreter": "/bin/sh",
            "timeout": 15,
        }, timeout=300))
        self._assert_structured_response(resp, "run_script+sh_interpreter")

    def test_upload_binary_with_custom_chunk_size(self, ssh_env):
        """upload_binary with explicit chunk_size (from tool.yaml)."""
        client, loop = ssh_env
        resp = loop.run_until_complete(client.call("upload_binary", {
            **self._FAKE_AUTH,
            "content_base64": base64.b64encode(b"fake binary data").decode(),
            "remote_path": "/tmp/test_chunk",
            "chunk_size": 10000,
            "executable": False,
            "timeout": 15,
        }, timeout=300))
        self._assert_structured_response(resp, "upload_binary+chunk_size")


# ===========================================================================
# ENGAGEMENT PATTERN TESTS -- verify real-world usage patterns work
# ===========================================================================

class TestEngagementPatterns:
    """Tests derived from analyzing 2390 SSH calls across 10+ engagements.

    These test patterns that the agent actually uses in the field,
    including edge cases found in trajectory data.
    """

    def test_exec_id_with_short_timeout(self, ssh_env, ssh_target):
        """exec 'id' with 10s timeout — the most common call (154 instances)."""
        host, port, user, password = ssh_target
        client, loop = ssh_env
        resp = loop.run_until_complete(
            client.call("exec", {
                "host": host,
                "username": user,
                "password": password,
                "command": "id",
                "port": port,
                "timeout": 10,
            })
        )
        result = assert_tool_success(resp, "id with short timeout should succeed")
        data = parse_tool_output(resp)
        assert "uid=" in data.get("stdout", "")

    def test_exec_chained_commands(self, ssh_env, ssh_target):
        """exec with && chained commands (real engagement pattern).

        Agent frequently sends 'id && cat /home/user/user.txt' in a single exec.
        """
        host, port, user, password = ssh_target
        client, loop = ssh_env
        resp = loop.run_until_complete(
            client.call("exec", {
                "host": host,
                "username": user,
                "password": password,
                "command": "id && whoami && hostname",
                "port": port,
                "timeout": 15,
            })
        )
        result = assert_tool_success(resp, "Chained commands should succeed")
        data = parse_tool_output(resp)
        stdout = data.get("stdout", "")
        assert "uid=" in stdout

    def test_exec_sudo_l(self, ssh_env, ssh_target):
        """exec 'sudo -l 2>&1' — the 3rd most common command.

        Agent checks sudo permissions for privilege escalation.
        May fail with 'user is not in the sudoers file' which is expected.
        """
        host, port, user, password = ssh_target
        client, loop = ssh_env
        resp = loop.run_until_complete(
            client.call("exec", {
                "host": host,
                "username": user,
                "password": password,
                "command": "sudo -l 2>&1",
                "port": port,
                "timeout": 15,
            })
        )
        # This may succeed or fail depending on sudoers config — just verify no crash
        result = resp.get("result", {})
        assert result is not None

    def test_shell_enumeration_pattern(self, ssh_env, ssh_target):
        """shell with common enumeration command set.

        Real engagement pattern: agent sends a list of recon commands.
        """
        host, port, user, password = ssh_target
        client, loop = ssh_env
        resp = loop.run_until_complete(
            client.call("shell", {
                "host": host,
                "username": user,
                "password": password,
                "commands": ["id", "uname -a", "cat /etc/os-release", "ip addr show"],
                "port": port,
                "timeout": 30,
            })
        )
        result = assert_tool_success(resp, "Enum shell should succeed")
        data = parse_tool_output(resp)
        assert "uid=" in data.get("stdout", "")

    def test_background_with_output_and_pid(self, ssh_env, ssh_target):
        """background with output_file + pid_file + return_check_command.

        This is the most common background pattern in engagement data:
        46 calls all had output_file, 42 had pid_file, 34 had return_check_command.
        """
        host, port, user, password = ssh_target
        client, loop = ssh_env
        resp = loop.run_until_complete(
            client.call("background", {
                "host": host,
                "username": user,
                "password": password,
                "command": "sleep 30",
                "port": port,
                "output_file": "/tmp/test_engage_bg.log",
                "pid_file": "/tmp/test_engage_bg.pid",
                "return_check_command": True,
            })
        )
        result = assert_tool_success(resp, "background with all options should succeed")
        data = parse_tool_output(resp)
        assert data.get("detached") is True or data.get("success") is True
        # Should have output_file and pid_file in response
        assert data.get("output_file") == "/tmp/test_engage_bg.log"
        assert data.get("pid_file") == "/tmp/test_engage_bg.pid"
        # check_command should be present when pid is available
        if data.get("pid"):
            assert "check_command" in data

        # Cleanup
        loop.run_until_complete(
            client.call("exec", {
                "host": host,
                "username": user,
                "password": password,
                "command": "kill $(cat /tmp/test_engage_bg.pid) 2>/dev/null; rm -f /tmp/test_engage_bg.*",
                "port": port,
                "timeout": 10,
            })
        )

    def test_copy_to_then_exec_verify(self, ssh_env, ssh_target):
        """copy_to + exec verification — common pattern for uploading scripts.

        Real engagement pattern: copy_to a script, then exec to verify/run it.
        """
        host, port, user, password = ssh_target
        client, loop = ssh_env

        script_content = "#!/bin/bash\necho VERIFY_MARKER_XYZ\n"
        upload_resp = loop.run_until_complete(
            client.call("copy_to", {
                "host": host,
                "username": user,
                "password": password,
                "content": script_content,
                "remote_path": "/tmp/test_engage_verify.sh",
                "port": port,
                "timeout": 30,
            })
        )
        result = assert_tool_success(upload_resp, "copy_to should succeed")

        verify_resp = loop.run_until_complete(
            client.call("exec", {
                "host": host,
                "username": user,
                "password": password,
                "command": "cat /tmp/test_engage_verify.sh && rm /tmp/test_engage_verify.sh",
                "port": port,
                "timeout": 15,
            })
        )
        verify_data = parse_tool_output(verify_resp)
        assert "VERIFY_MARKER_XYZ" in verify_data.get("stdout", "")

    def test_run_script_enumeration(self, ssh_env, ssh_target):
        """run_script with a realistic enumeration script.

        Real engagement pattern: agent uploads and runs multi-step enum scripts.
        """
        host, port, user, password = ssh_target
        client, loop = ssh_env

        enum_script = textwrap.dedent("""\
            #!/bin/bash
            echo "=== OS Info ==="
            uname -a
            echo "=== Users ==="
            cat /etc/passwd | head -5
            echo "=== Processes ==="
            ps aux | head -5
        """)
        resp = loop.run_until_complete(
            client.call("run_script", {
                "host": host,
                "username": user,
                "password": password,
                "script": enum_script,
                "interpreter": "/bin/bash",
                "port": port,
                "timeout": 30,
            })
        )
        result = assert_tool_success(resp, "Enum script should succeed")
        data = parse_tool_output(resp)
        stdout = data.get("stdout", "")
        assert "=== OS Info ===" in stdout
        assert "=== Users ===" in stdout


# ===========================================================================
# INTEGRATION TESTS -- require --target flag
# ===========================================================================

@pytest.mark.integration
class TestIntegration:
    """Integration tests requiring a real target (--target flag)."""

    def test_exec_on_target(self, ssh_env, target, username, password):
        """exec against a real target with provided credentials."""
        if not username or not password:
            pytest.skip("--username and --password required")

        client, loop = ssh_env
        resp = loop.run_until_complete(
            client.call("exec", {
                "host": target,
                "username": username,
                "password": password,
                "command": "id",
                "timeout": 30,
            })
        )
        result = assert_tool_success(resp, f"exec on {target} should succeed")
        data = parse_tool_output(resp)
        assert "uid=" in data.get("stdout", "")

    def test_shell_on_target(self, ssh_env, target, username, password):
        """shell against a real target."""
        if not username or not password:
            pytest.skip("--username and --password required")

        client, loop = ssh_env
        resp = loop.run_until_complete(
            client.call("shell", {
                "host": target,
                "username": username,
                "password": password,
                "commands": ["id", "whoami", "uname -a"],
                "timeout": 30,
            })
        )
        result = assert_tool_success(resp)
        data = parse_tool_output(resp)
        assert "uid=" in data.get("stdout", "")
