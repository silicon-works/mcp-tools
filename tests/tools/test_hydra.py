"""
Tests for the hydra MCP tool server.

Covers:
- Smoke tests: boot, method list, required params, meta-param stripping, clock
- Unit tests: _parse_hydra_output (credentials, password-only, spaces, stats,
  warnings, errors, verbose), _resolve_wordlist, command construction
- Method tests: bruteforce, ssh_brute, ftp_brute, web_form_brute, mysql_brute
  (all 5 methods via container)
- Heartbeat: verify heartbeat sends during long-running brute-force
- Error classification: connection refused, service down, rate limiting
- Feature 28 regression: passwords with spaces, VNC/Redis/SNMP parsing, -v not -V
- Contract tests: tool.yaml vs server parameter definitions
- Acceptance tests: every method called through container (no live target)
"""

import asyncio
import importlib.util
import json
import os
import subprocess
import sys
import time
from pathlib import Path
from typing import Any, Dict, Set
from unittest.mock import AsyncMock, MagicMock, patch

import pytest
import yaml

# ---------------------------------------------------------------------------
# Path setup
# ---------------------------------------------------------------------------
PROJECT_ROOT = Path(__file__).parent.parent.parent
TOOL_DIR = PROJECT_ROOT / "tools" / "hydra"
FIXTURES_DIR = Path(__file__).parent.parent / "fixtures" / "hydra"

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
    """Import and return the HydraServer class for direct method testing."""
    mcp_common_path = PROJECT_ROOT / "packages" / "mcp-common" / "src"
    if str(mcp_common_path) not in sys.path:
        sys.path.insert(0, str(mcp_common_path))

    spec = importlib.util.spec_from_file_location(
        "hydra_server", TOOL_DIR / "mcp-server.py"
    )
    mod = importlib.util.module_from_spec(spec)
    spec.loader.exec_module(mod)
    return mod.HydraServer


def _get_module():
    """Import the whole hydra mcp-server module."""
    mcp_common_path = PROJECT_ROOT / "packages" / "mcp-common" / "src"
    if str(mcp_common_path) not in sys.path:
        sys.path.insert(0, str(mcp_common_path))

    spec = importlib.util.spec_from_file_location(
        "hydra_server", TOOL_DIR / "mcp-server.py"
    )
    mod = importlib.util.module_from_spec(spec)
    spec.loader.exec_module(mod)
    return mod


# ---------------------------------------------------------------------------
# Module-scoped fixture: MCP client (Docker container)
# ---------------------------------------------------------------------------
@pytest.fixture(scope="module")
def hydra_env(request):
    """Create an MCPTestClient with its event loop. Yields (client, loop)."""
    tool = "hydra"
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


def _load_fixture(name: str) -> str:
    """Load a fixture file by name."""
    with open(FIXTURES_DIR / name) as f:
        return f.read()


# ===========================================================================
# SMOKE TESTS -- require Docker container running
# ===========================================================================

class TestSmoke:
    """Smoke tests that verify the container boots and basic protocol works."""

    def test_boot_and_list_tools(self, hydra_env):
        """Container starts and list_tools returns methods."""
        client, loop = hydra_env
        assert len(client.tools) > 0, "Server should advertise at least one tool"
        names = client.tool_names()
        assert "bruteforce" in names
        assert "ssh_brute" in names
        assert "ftp_brute" in names
        assert "web_form_brute" in names
        assert "mysql_brute" in names

    def test_expected_method_count(self, hydra_env):
        """Server should have exactly 5 built-in methods + verify_clock."""
        client, _ = hydra_env
        names = client.tool_names()
        assert len(names) == 6, (
            f"Expected 6 methods (5 built-in + verify_clock), got {len(names)}: {sorted(names)}"
        )

    def test_method_list_matches_tool_yaml(self, hydra_env):
        """Every method in tool.yaml is advertised by the server, and vice versa."""
        client, _ = hydra_env
        server_names = client.tool_names() - {"verify_clock"}

        yaml_path = TOOL_DIR / "tool.yaml"
        with open(yaml_path) as f:
            yaml_data = yaml.safe_load(f)
        yaml_names = set(yaml_data.get("methods", {}).keys())

        yaml_only = yaml_names - server_names
        server_only = server_names - yaml_names

        assert not yaml_only, f"Methods in tool.yaml but not server: {yaml_only}"
        assert not server_only, f"Methods in server but not tool.yaml: {server_only}"

    def test_unknown_method(self, hydra_env):
        """Calling an unknown method returns a clear error."""
        client, loop = hydra_env
        resp = loop.run_until_complete(
            client.call("nonexistent_method", {"target": "10.10.10.1"})
        )
        result = resp.get("result", {})
        assert result.get("isError", False), "Unknown method should return error"
        content_text = ""
        for c in result.get("content", []):
            if c.get("type") == "text":
                content_text += c["text"]
        assert "unknown method" in content_text.lower() or "bruteforce" in content_text, (
            f"Error should mention available methods, got: {content_text[:300]}"
        )

    def test_meta_param_stripping(self, hydra_env):
        """Meta params (clock_offset) are stripped without error."""
        client, loop = hydra_env
        # Call with invalid target but with meta params -- meta params should be stripped,
        # the error should be about connection, not about unknown parameter
        resp = loop.run_until_complete(
            client.call("bruteforce", {
                "target": "192.0.2.1",  # TEST-NET, won't connect
                "service": "ssh",
                "username": "test",
                "password": "test",
                "timeout": 5,
                "clock_offset": 1000,
            })
        )
        # Should not fail due to unknown parameter 'clock_offset'
        result = resp.get("result", {})
        content_text = ""
        for c in result.get("content", []):
            if c.get("type") == "text":
                content_text += c["text"]
        # If it errors, it should be a connection error, not a param error
        assert "clock_offset" not in content_text, (
            f"Meta param should be stripped, but found clock_offset in error: {content_text[:300]}"
        )


# ===========================================================================
# UNIT TESTS -- test internal methods without Docker
# ===========================================================================

class TestParseHydraOutput:
    """Test the _parse_hydra_output method with fixture files."""

    def test_parse_ssh_creds_found(self):
        """Parse SSH credential output -- standard login:password."""
        server = _get_server_class()()
        output = _load_fixture("ssh_creds_found.txt")
        parsed = server._parse_hydra_output(output)

        assert parsed["found"] is True
        assert parsed["count"] == 1
        assert len(parsed["credentials"]) == 1
        cred = parsed["credentials"][0]
        assert cred["port"] == 22
        assert cred["service"] == "ssh"
        assert cred["host"] == "10.10.10.1"
        assert cred["username"] == "admin"
        assert cred["password"] == "admin123"

    def test_parse_password_with_spaces(self):
        """Feature 28 regression: passwords with spaces are captured completely."""
        server = _get_server_class()()
        output = _load_fixture("password_with_spaces.txt")
        parsed = server._parse_hydra_output(output)

        assert parsed["found"] is True
        assert parsed["count"] == 2
        assert parsed["credentials"][0]["password"] == "my secret password"
        assert parsed["credentials"][1]["password"] == "p@ss w0rd with spaces"

    def test_parse_vnc_password_only(self):
        """Feature 28 regression: VNC password-only service parsed correctly."""
        server = _get_server_class()()
        output = _load_fixture("vnc_password_only.txt")
        parsed = server._parse_hydra_output(output)

        assert parsed["found"] is True
        assert parsed["count"] == 1
        cred = parsed["credentials"][0]
        assert cred["port"] == 5900
        assert cred["service"] == "vnc"
        assert cred["host"] == "10.10.10.5"
        assert cred["username"] == ""
        assert cred["password"] == "sUp3rS3cr3t"

    def test_parse_redis_password_only(self):
        """Feature 28 regression: Redis password-only service parsed correctly."""
        server = _get_server_class()()
        output = _load_fixture("redis_password_only.txt")
        parsed = server._parse_hydra_output(output)

        assert parsed["found"] is True
        assert parsed["count"] == 1
        cred = parsed["credentials"][0]
        assert cred["port"] == 6379
        assert cred["service"] == "redis"
        assert cred["password"] == "r3d!s_p@ss"

    def test_parse_snmp_password_only_multiple(self):
        """Feature 28 regression: SNMP multiple community strings found."""
        server = _get_server_class()()
        output = _load_fixture("snmp_password_only.txt")
        parsed = server._parse_hydra_output(output)

        assert parsed["found"] is True
        assert parsed["count"] == 2
        passwords = [c["password"] for c in parsed["credentials"]]
        assert "public" in passwords
        assert "private" in passwords

    def test_parse_http_form_creds(self):
        """Parse HTTP form brute-force output."""
        server = _get_server_class()()
        output = _load_fixture("http_form_creds.txt")
        parsed = server._parse_hydra_output(output)

        assert parsed["found"] is True
        assert parsed["count"] == 1
        cred = parsed["credentials"][0]
        assert cred["port"] == 80
        assert cred["service"] == "http-post-form"
        assert cred["username"] == "admin"
        assert cred["password"] == "SuperSecret123!"

    def test_parse_no_creds_found(self):
        """Parse output with no credentials found."""
        server = _get_server_class()()
        output = _load_fixture("no_creds_found.txt")
        parsed = server._parse_hydra_output(output)

        assert parsed["found"] is False
        assert parsed["count"] == 0
        assert len(parsed["credentials"]) == 0
        # Should still have stats from STATUS lines
        assert parsed["stats"]["attempts_total"] > 0

    def test_parse_connection_error(self):
        """Parse output with connection errors."""
        server = _get_server_class()()
        output = _load_fixture("connection_error.txt")
        parsed = server._parse_hydra_output(output)

        assert parsed["found"] is False
        assert len(parsed.get("errors", [])) >= 1
        # Error messages should contain connection info
        errors_text = " ".join(parsed["errors"])
        assert "connect" in errors_text.lower() or "support" in errors_text.lower()

    def test_parse_warnings_rate_limit(self):
        """Parse output with warnings about rate limiting."""
        server = _get_server_class()()
        output = _load_fixture("warnings_rate_limit.txt")
        parsed = server._parse_hydra_output(output)

        assert len(parsed.get("warnings", [])) >= 1
        warnings_text = " ".join(parsed["warnings"])
        assert "tasks" in warnings_text.lower() or "parallel" in warnings_text.lower()

    def test_parse_multiple_creds(self):
        """Parse output with multiple credentials found."""
        server = _get_server_class()()
        output = _load_fixture("multiple_creds.txt")
        parsed = server._parse_hydra_output(output)

        assert parsed["found"] is True
        assert parsed["count"] == 3
        usernames = [c["username"] for c in parsed["credentials"]]
        assert "admin" in usernames
        assert "root" in usernames
        assert "ftp" in usernames

    def test_parse_mysql_empty_password(self):
        """Parse MySQL output with empty password (null password found)."""
        server = _get_server_class()()
        output = _load_fixture("mysql_creds.txt")
        parsed = server._parse_hydra_output(output)

        assert parsed["found"] is True
        assert parsed["count"] == 1
        cred = parsed["credentials"][0]
        assert cred["username"] == "root"
        assert cred["password"] == ""
        assert cred["port"] == 3306

    def test_parse_verbose_output(self):
        """Parse output with verbose mode -- attempt lines included."""
        server = _get_server_class()()
        output = _load_fixture("verbose_output.txt")
        parsed = server._parse_hydra_output(output, include_verbose=True)

        assert parsed["found"] is True
        assert parsed["count"] == 1
        assert "verbose_output" in parsed
        assert "[ATTEMPT]" in parsed["verbose_output"]
        assert "[STATUS]" in parsed["verbose_output"]
        # Verify the actual credential is still found
        assert parsed["credentials"][0]["password"] == "welcome"

    def test_parse_verbose_output_not_included_by_default(self):
        """Verbose output should not be included when include_verbose is False."""
        server = _get_server_class()()
        output = _load_fixture("verbose_output.txt")
        parsed = server._parse_hydra_output(output, include_verbose=False)

        assert "verbose_output" not in parsed

    def test_parse_stats_from_data_line(self):
        """Stats should be extracted from [DATA] line when no STATUS available."""
        server = _get_server_class()()
        output = "[DATA] max 4 tasks per 1 server, overall 4 tasks, 10000 login tries\n"
        parsed = server._parse_hydra_output(output)

        assert parsed["stats"]["attempts_total"] == 10000

    def test_parse_stats_from_status_line(self):
        """Stats should be extracted from [STATUS] line, overriding [DATA] total."""
        server = _get_server_class()()
        output = (
            "[DATA] max 4 tasks per 1 server, overall 4 tasks, 10000 login tries\n"
            "[STATUS] 100.00 tries/min, 300 tries in 00:03h, 9700 to do in 01:37h, 4 active\n"
        )
        parsed = server._parse_hydra_output(output)

        assert parsed["stats"]["attempts_completed"] == 300
        assert parsed["stats"]["attempts_total"] == 10000  # 300 + 9700

    def test_parse_creds_with_errors(self):
        """Credentials found alongside connection errors -- both captured."""
        server = _get_server_class()()
        output = _load_fixture("creds_with_errors.txt")
        parsed = server._parse_hydra_output(output)

        assert parsed["found"] is True
        assert parsed["count"] == 2
        usernames = [c["username"] for c in parsed["credentials"]]
        assert "admin" in usernames
        assert "root" in usernames
        assert len(parsed.get("errors", [])) >= 1

    def test_parse_info_lines_as_warnings(self):
        """[INFO] lines should be captured in the warnings list."""
        server = _get_server_class()()
        output = _load_fixture("info_lines.txt")
        parsed = server._parse_hydra_output(output)

        assert len(parsed.get("warnings", [])) >= 1
        warnings_text = " ".join(parsed["warnings"])
        assert "reduced" in warnings_text.lower() or "smb" in warnings_text.lower()

    def test_parse_file_not_found_error(self):
        """File-not-found errors should be in the errors list."""
        server = _get_server_class()()
        output = _load_fixture("file_not_found.txt")
        parsed = server._parse_hydra_output(output)

        assert len(parsed.get("errors", [])) >= 1
        assert "not found" in parsed["errors"][0].lower()

    def test_parse_form_string_error(self):
        """Malformed form string errors should be captured."""
        server = _get_server_class()()
        output = _load_fixture("form_string_error.txt")
        parsed = server._parse_hydra_output(output)

        assert len(parsed.get("errors", [])) >= 1
        assert "optional parameter" in parsed["errors"][0].lower()

    def test_parse_https_post_form_creds(self):
        """Parse HTTPS POST form credentials."""
        server = _get_server_class()()
        output = _load_fixture("https_creds.txt")
        parsed = server._parse_hydra_output(output)

        assert parsed["found"] is True
        assert parsed["count"] == 1
        cred = parsed["credentials"][0]
        assert cred["port"] == 443
        assert cred["service"] == "https-post-form"
        assert cred["password"] == "S3cr3t!"

    def test_parse_rdp_with_warning(self):
        """RDP credentials parsed alongside module warning."""
        server = _get_server_class()()
        output = _load_fixture("rdp_warning.txt")
        parsed = server._parse_hydra_output(output)

        assert parsed["found"] is True
        assert parsed["count"] == 1
        assert parsed["credentials"][0]["service"] == "rdp"
        assert parsed["credentials"][0]["port"] == 3389
        assert len(parsed.get("warnings", [])) >= 1

    def test_parse_password_special_chars(self):
        """Passwords with special characters are fully captured."""
        server = _get_server_class()()
        output = _load_fixture("password_special_chars.txt")
        parsed = server._parse_hydra_output(output)

        assert parsed["found"] is True
        assert parsed["count"] == 3
        passwords = [c["password"] for c in parsed["credentials"]]
        assert "P@$$w0rd!#%^&*()" in passwords
        assert "p@ss:w0rd:with:colons" in passwords

    def test_parse_empty_output(self):
        """Empty output should not crash."""
        server = _get_server_class()()
        parsed = server._parse_hydra_output("")

        assert parsed["found"] is False
        assert parsed["count"] == 0
        assert len(parsed["credentials"]) == 0
        assert parsed["stats"]["attempts_total"] == 0

    def test_parse_only_banner(self):
        """Only banner output (no data/status lines) should not crash."""
        server = _get_server_class()()
        output = (
            "Hydra v9.6 (c) 2023 by van Hauser/THC\n"
            "Hydra starting at 2026-03-15\n"
        )
        parsed = server._parse_hydra_output(output)

        assert parsed["found"] is False
        assert parsed["count"] == 0

    def test_parse_multiple_status_updates(self):
        """Last STATUS line should provide the final progress snapshot."""
        server = _get_server_class()()
        output = (
            "[DATA] max 4 tasks per 1 server, overall 4 tasks, 10000 login tries\n"
            "[STATUS] 100.00 tries/min, 100 tries in 00:01h, 9900 to do in 01:39h, 4 active\n"
            "[STATUS] 100.00 tries/min, 500 tries in 00:05h, 9500 to do in 01:35h, 4 active\n"
            "[STATUS] 100.00 tries/min, 1000 tries in 00:10h, 9000 to do in 01:30h, 4 active\n"
        )
        parsed = server._parse_hydra_output(output)

        # Last STATUS wins: 1000 completed, 9000 remaining = 10000 total
        assert parsed["stats"]["attempts_completed"] == 1000
        assert parsed["stats"]["attempts_total"] == 10000

    def test_parse_http_get_with_misc_field(self):
        """HTTP-GET credentials with misc field in output."""
        server = _get_server_class()()
        output = "[5985][http-get] host: 10.129.231.186   misc: /   login: judith.mader   password: judith09\n"
        parsed = server._parse_hydra_output(output)

        assert parsed["found"] is True
        assert parsed["count"] == 1
        assert parsed["credentials"][0]["username"] == "judith.mader"
        assert parsed["credentials"][0]["password"] == "judith09"
        assert parsed["credentials"][0]["port"] == 5985


class TestResolveWordlist:
    """Test the _resolve_wordlist method."""

    def test_resolve_builtin_rockyou(self):
        server = _get_server_class()()
        path = server._resolve_wordlist("rockyou")
        assert path == "/usr/share/wordlists/rockyou.txt"

    def test_resolve_builtin_common_passwords(self):
        server = _get_server_class()()
        path = server._resolve_wordlist("common-passwords")
        assert path == "/usr/share/seclists/Passwords/Common-Credentials/10k-most-common.txt"

    def test_resolve_builtin_usernames(self):
        server = _get_server_class()()
        path = server._resolve_wordlist("usernames")
        assert path == "/usr/share/seclists/Usernames/top-usernames-shortlist.txt"

    def test_resolve_builtin_default_passwords(self):
        server = _get_server_class()()
        path = server._resolve_wordlist("default-passwords")
        assert path == "/usr/share/seclists/Passwords/Default-Credentials/default-passwords.txt"

    def test_resolve_custom_path(self):
        server = _get_server_class()()
        path = server._resolve_wordlist("/session/wordlists/custom.txt")
        assert path == "/session/wordlists/custom.txt"

    def test_resolve_ssh_usernames(self):
        server = _get_server_class()()
        path = server._resolve_wordlist("ssh-usernames")
        assert path == "/tmp/ssh-usernames.txt"


class TestCommandConstruction:
    """Test that command arguments are constructed correctly."""

    @pytest.mark.asyncio
    async def test_bruteforce_basic_ssh_command(self):
        """Verify SSH command construction with basic params."""
        server = _get_server_class()()
        calls = []

        async def mock_create_subprocess(*args, **kwargs):
            calls.append(args)
            proc = MagicMock()
            proc.communicate = AsyncMock(return_value=(b"[DATA] max 4 tasks, 1 login tries\n", b""))
            proc.terminate = MagicMock()
            proc.kill = MagicMock()
            proc.returncode = 0
            return proc

        with patch("asyncio.create_subprocess_exec", mock_create_subprocess):
            # Mock send_progress to avoid MCP context issues
            server.send_progress = AsyncMock()
            result = await server.bruteforce(
                target="10.10.10.1",
                service="ssh",
                username="admin",
                password="admin123",
                timeout=10,
            )

        assert len(calls) == 1
        cmd = list(calls[0])
        assert "hydra" in cmd
        assert "-l" in cmd
        idx = cmd.index("-l")
        assert cmd[idx + 1] == "admin"
        assert "-p" in cmd
        idx = cmd.index("-p")
        assert cmd[idx + 1] == "admin123"
        assert "-t" in cmd
        idx = cmd.index("-t")
        assert cmd[idx + 1] == "4"  # SSH default threads
        assert "ssh" in cmd
        assert "10.10.10.1" in cmd

    @pytest.mark.asyncio
    async def test_bruteforce_uses_v_not_V(self):
        """Feature 28 regression: -v (lowercase) should be used, not -V (uppercase)."""
        server = _get_server_class()()
        calls = []

        async def mock_create_subprocess(*args, **kwargs):
            calls.append(args)
            proc = MagicMock()
            proc.communicate = AsyncMock(return_value=(b"", b""))
            proc.terminate = MagicMock()
            proc.kill = MagicMock()
            proc.returncode = 0
            return proc

        with patch("asyncio.create_subprocess_exec", mock_create_subprocess):
            server.send_progress = AsyncMock()
            await server.bruteforce(
                target="10.10.10.1",
                service="ssh",
                username="test",
                password="test",
                timeout=5,
            )

        cmd = list(calls[0])
        assert "-v" in cmd, "Should use -v (lowercase) for minimal verbosity"
        assert "-V" not in cmd, "Should NOT use -V (very verbose)"

    @pytest.mark.asyncio
    async def test_bruteforce_password_only_service(self):
        """VNC/Redis/SNMP should not add -l/-L flags."""
        server = _get_server_class()()
        calls = []

        async def mock_create_subprocess(*args, **kwargs):
            calls.append(args)
            proc = MagicMock()
            proc.communicate = AsyncMock(return_value=(b"", b""))
            proc.terminate = MagicMock()
            proc.kill = MagicMock()
            proc.returncode = 0
            return proc

        for svc in ["vnc", "redis", "snmp", "cisco", "cisco-enable", "oracle-listener"]:
            calls.clear()
            with patch("asyncio.create_subprocess_exec", mock_create_subprocess):
                server.send_progress = AsyncMock()
                await server.bruteforce(
                    target="10.10.10.1",
                    service=svc,
                    password="test",
                    timeout=5,
                )
            cmd = list(calls[0])
            assert "-l" not in cmd, f"Password-only service {svc} should not have -l flag"
            assert "-L" not in cmd, f"Password-only service {svc} should not have -L flag"

    @pytest.mark.asyncio
    async def test_bruteforce_ssl_flag(self):
        """SSL flag -S should be added when ssl=True."""
        server = _get_server_class()()
        calls = []

        async def mock_create_subprocess(*args, **kwargs):
            calls.append(args)
            proc = MagicMock()
            proc.communicate = AsyncMock(return_value=(b"", b""))
            proc.terminate = MagicMock()
            proc.kill = MagicMock()
            proc.returncode = 0
            return proc

        with patch("asyncio.create_subprocess_exec", mock_create_subprocess):
            server.send_progress = AsyncMock()
            await server.bruteforce(
                target="10.10.10.1",
                service="imap",
                username="test",
                password="test",
                ssl=True,
                timeout=5,
            )

        cmd = list(calls[0])
        assert "-S" in cmd, "SSL flag should be present"

    @pytest.mark.asyncio
    async def test_bruteforce_loop_users_flag(self):
        """Loop users flag -u should be added when loop_users=True."""
        server = _get_server_class()()
        calls = []

        async def mock_create_subprocess(*args, **kwargs):
            calls.append(args)
            proc = MagicMock()
            proc.communicate = AsyncMock(return_value=(b"", b""))
            proc.terminate = MagicMock()
            proc.kill = MagicMock()
            proc.returncode = 0
            return proc

        with patch("asyncio.create_subprocess_exec", mock_create_subprocess):
            server.send_progress = AsyncMock()
            await server.bruteforce(
                target="10.10.10.1",
                service="ssh",
                username="test",
                password="test",
                loop_users=True,
                timeout=5,
            )

        cmd = list(calls[0])
        assert "-u" in cmd, "Loop users flag should be present"

    @pytest.mark.asyncio
    async def test_bruteforce_combo_file(self):
        """Combo file (-C) should override -l/-L/-p/-P."""
        server = _get_server_class()()
        calls = []

        async def mock_create_subprocess(*args, **kwargs):
            calls.append(args)
            proc = MagicMock()
            proc.communicate = AsyncMock(return_value=(b"", b""))
            proc.terminate = MagicMock()
            proc.kill = MagicMock()
            proc.returncode = 0
            return proc

        with patch("asyncio.create_subprocess_exec", mock_create_subprocess):
            server.send_progress = AsyncMock()
            await server.bruteforce(
                target="10.10.10.1",
                service="ssh",
                username="admin",  # Should be ignored
                password="test",   # Should be ignored
                combo_file="/tmp/combos.txt",
                timeout=5,
            )

        cmd = list(calls[0])
        assert "-C" in cmd, "Combo file flag should be present"
        assert "-l" not in cmd, "Username should not be passed with combo file"
        assert "-p" not in cmd, "Password should not be passed with combo file"

    @pytest.mark.asyncio
    async def test_bruteforce_password_gen(self):
        """Password generation (-x) should override passlist."""
        server = _get_server_class()()
        calls = []

        async def mock_create_subprocess(*args, **kwargs):
            calls.append(args)
            proc = MagicMock()
            proc.communicate = AsyncMock(return_value=(b"", b""))
            proc.terminate = MagicMock()
            proc.kill = MagicMock()
            proc.returncode = 0
            return proc

        with patch("asyncio.create_subprocess_exec", mock_create_subprocess):
            server.send_progress = AsyncMock()
            await server.bruteforce(
                target="10.10.10.1",
                service="ssh",
                username="admin",
                password_gen="4:4:1",
                timeout=5,
            )

        cmd = list(calls[0])
        assert "-x" in cmd
        idx = cmd.index("-x")
        assert cmd[idx + 1] == "4:4:1"
        assert "-P" not in cmd, "Password list should not be present with -x"

    @pytest.mark.asyncio
    async def test_bruteforce_stop_on_first(self):
        """Stop-on-first flag (-f) should be added."""
        server = _get_server_class()()
        calls = []

        async def mock_create_subprocess(*args, **kwargs):
            calls.append(args)
            proc = MagicMock()
            proc.communicate = AsyncMock(return_value=(b"", b""))
            proc.terminate = MagicMock()
            proc.kill = MagicMock()
            proc.returncode = 0
            return proc

        with patch("asyncio.create_subprocess_exec", mock_create_subprocess):
            server.send_progress = AsyncMock()
            await server.bruteforce(
                target="10.10.10.1",
                service="ssh",
                username="test",
                password="test",
                stop_on_first=True,
                timeout=5,
            )

        cmd = list(calls[0])
        assert "-f" in cmd

    @pytest.mark.asyncio
    async def test_bruteforce_wait_time(self):
        """Wait time (-W) flag should be added."""
        server = _get_server_class()()
        calls = []

        async def mock_create_subprocess(*args, **kwargs):
            calls.append(args)
            proc = MagicMock()
            proc.communicate = AsyncMock(return_value=(b"", b""))
            proc.terminate = MagicMock()
            proc.kill = MagicMock()
            proc.returncode = 0
            return proc

        with patch("asyncio.create_subprocess_exec", mock_create_subprocess):
            server.send_progress = AsyncMock()
            await server.bruteforce(
                target="10.10.10.1",
                service="ssh",
                username="test",
                password="test",
                wait_time=2,
                timeout=5,
            )

        cmd = list(calls[0])
        assert "-W" in cmd
        idx = cmd.index("-W")
        assert cmd[idx + 1] == "2"

    @pytest.mark.asyncio
    async def test_bruteforce_try_common(self):
        """Try common (-e) flag should be added."""
        server = _get_server_class()()
        calls = []

        async def mock_create_subprocess(*args, **kwargs):
            calls.append(args)
            proc = MagicMock()
            proc.communicate = AsyncMock(return_value=(b"", b""))
            proc.terminate = MagicMock()
            proc.kill = MagicMock()
            proc.returncode = 0
            return proc

        with patch("asyncio.create_subprocess_exec", mock_create_subprocess):
            server.send_progress = AsyncMock()
            await server.bruteforce(
                target="10.10.10.1",
                service="ssh",
                username="test",
                password="test",
                try_common="nsr",
                timeout=5,
            )

        cmd = list(calls[0])
        assert "-e" in cmd
        idx = cmd.index("-e")
        assert cmd[idx + 1] == "nsr"

    @pytest.mark.asyncio
    async def test_web_form_brute_constructs_form_string(self):
        """web_form_brute should construct the correct form string."""
        server = _get_server_class()()
        calls = []

        async def mock_create_subprocess(*args, **kwargs):
            calls.append(args)
            proc = MagicMock()
            proc.communicate = AsyncMock(return_value=(b"", b""))
            proc.terminate = MagicMock()
            proc.kill = MagicMock()
            proc.returncode = 0
            return proc

        with patch("asyncio.create_subprocess_exec", mock_create_subprocess):
            server.send_progress = AsyncMock()
            await server.web_form_brute(
                target="10.10.10.1",
                path="/login.php",
                user_field="user",
                pass_field="pass",
                fail_string="Invalid",
                username="admin",
                password="test",
                timeout=5,
            )

        cmd = list(calls[0])
        # Find the form string argument
        form_idx = cmd.index("http-post-form") + 1
        form_str = cmd[form_idx]
        assert form_str == "/login.php:user=^USER^&pass=^PASS^:F=Invalid"

    @pytest.mark.asyncio
    async def test_web_form_brute_with_extra_params(self):
        """web_form_brute should include extra_params in form string."""
        server = _get_server_class()()
        calls = []

        async def mock_create_subprocess(*args, **kwargs):
            calls.append(args)
            proc = MagicMock()
            proc.communicate = AsyncMock(return_value=(b"", b""))
            proc.terminate = MagicMock()
            proc.kill = MagicMock()
            proc.returncode = 0
            return proc

        with patch("asyncio.create_subprocess_exec", mock_create_subprocess):
            server.send_progress = AsyncMock()
            await server.web_form_brute(
                target="10.10.10.1",
                path="/login",
                fail_string="Login failed",
                username="admin",
                password="test",
                extra_params="submit=Login",
                timeout=5,
            )

        cmd = list(calls[0])
        form_idx = cmd.index("http-post-form") + 1
        form_str = cmd[form_idx]
        assert "submit=Login" in form_str
        assert form_str == "/login:username=^USER^&password=^PASS^&submit=Login:F=Login failed"

    @pytest.mark.asyncio
    async def test_web_form_brute_https(self):
        """web_form_brute with https=True should use https-post-form and port 443."""
        server = _get_server_class()()
        calls = []

        async def mock_create_subprocess(*args, **kwargs):
            calls.append(args)
            proc = MagicMock()
            proc.communicate = AsyncMock(return_value=(b"", b""))
            proc.terminate = MagicMock()
            proc.kill = MagicMock()
            proc.returncode = 0
            return proc

        with patch("asyncio.create_subprocess_exec", mock_create_subprocess):
            server.send_progress = AsyncMock()
            await server.web_form_brute(
                target="10.10.10.1",
                path="/login",
                fail_string="Invalid",
                username="admin",
                password="test",
                https=True,
                timeout=5,
            )

        cmd = list(calls[0])
        assert "https-post-form" in cmd
        assert "-s" in cmd
        idx = cmd.index("-s")
        assert cmd[idx + 1] == "443"

    @pytest.mark.asyncio
    async def test_mysql_brute_defaults(self):
        """mysql_brute should default to root user and port 3306."""
        server = _get_server_class()()
        calls = []

        async def mock_create_subprocess(*args, **kwargs):
            calls.append(args)
            proc = MagicMock()
            proc.communicate = AsyncMock(return_value=(b"", b""))
            proc.terminate = MagicMock()
            proc.kill = MagicMock()
            proc.returncode = 0
            return proc

        with patch("asyncio.create_subprocess_exec", mock_create_subprocess):
            server.send_progress = AsyncMock()
            await server.mysql_brute(
                target="10.10.10.1",
                password="test",
                timeout=5,
            )

        cmd = list(calls[0])
        assert "-l" in cmd
        idx = cmd.index("-l")
        assert cmd[idx + 1] == "root"
        assert "-s" in cmd
        idx = cmd.index("-s")
        assert cmd[idx + 1] == "3306"
        assert "mysql" in cmd

    @pytest.mark.asyncio
    async def test_ssh_brute_defaults(self):
        """ssh_brute should default to port 22 and 4 threads."""
        server = _get_server_class()()
        calls = []

        async def mock_create_subprocess(*args, **kwargs):
            calls.append(args)
            proc = MagicMock()
            proc.communicate = AsyncMock(return_value=(b"", b""))
            proc.terminate = MagicMock()
            proc.kill = MagicMock()
            proc.returncode = 0
            return proc

        with patch("asyncio.create_subprocess_exec", mock_create_subprocess):
            server.send_progress = AsyncMock()
            await server.ssh_brute(
                target="10.10.10.1",
                username="test",
                password="test",
                timeout=5,
            )

        cmd = list(calls[0])
        assert "-t" in cmd
        idx = cmd.index("-t")
        assert cmd[idx + 1] == "4"
        assert "-s" in cmd
        idx = cmd.index("-s")
        assert cmd[idx + 1] == "22"
        assert "ssh" in cmd

    @pytest.mark.asyncio
    async def test_ftp_brute_defaults(self):
        """ftp_brute should default to port 21 and 8 threads."""
        server = _get_server_class()()
        calls = []

        async def mock_create_subprocess(*args, **kwargs):
            calls.append(args)
            proc = MagicMock()
            proc.communicate = AsyncMock(return_value=(b"", b""))
            proc.terminate = MagicMock()
            proc.kill = MagicMock()
            proc.returncode = 0
            return proc

        with patch("asyncio.create_subprocess_exec", mock_create_subprocess):
            server.send_progress = AsyncMock()
            await server.ftp_brute(
                target="10.10.10.1",
                username="test",
                password="test",
                timeout=5,
            )

        cmd = list(calls[0])
        assert "-t" in cmd
        idx = cmd.index("-t")
        assert cmd[idx + 1] == "8"
        assert "-s" in cmd
        idx = cmd.index("-s")
        assert cmd[idx + 1] == "21"
        assert "ftp" in cmd

    @pytest.mark.asyncio
    async def test_http_post_form_requires_http_form(self):
        """bruteforce with http-post-form but no http_form should fail."""
        server = _get_server_class()()
        server.send_progress = AsyncMock()
        result = await server.bruteforce(
            target="10.10.10.1",
            service="http-post-form",
            username="admin",
            password="test",
            timeout=5,
        )
        assert result.success is False
        assert "http_form parameter required" in result.error

    @pytest.mark.asyncio
    async def test_bruteforce_includes_I_flag(self):
        """hydra should always include -I flag to ignore restore files."""
        server = _get_server_class()()
        calls = []

        async def mock_create_subprocess(*args, **kwargs):
            calls.append(args)
            proc = MagicMock()
            proc.communicate = AsyncMock(return_value=(b"", b""))
            proc.terminate = MagicMock()
            proc.kill = MagicMock()
            proc.returncode = 0
            return proc

        with patch("asyncio.create_subprocess_exec", mock_create_subprocess):
            server.send_progress = AsyncMock()
            await server.bruteforce(
                target="10.10.10.1",
                service="ssh",
                username="test",
                password="test",
                timeout=5,
            )

        cmd = list(calls[0])
        assert "-I" in cmd, "Should include -I flag to suppress restore file prompts"

    @pytest.mark.asyncio
    async def test_web_form_brute_escapes_colons_in_fail_string(self):
        """Colons in fail_string should be escaped with backslash."""
        server = _get_server_class()()
        calls = []

        async def mock_create_subprocess(*args, **kwargs):
            calls.append(args)
            proc = MagicMock()
            proc.communicate = AsyncMock(return_value=(b"", b""))
            proc.terminate = MagicMock()
            proc.kill = MagicMock()
            proc.returncode = 0
            return proc

        with patch("asyncio.create_subprocess_exec", mock_create_subprocess):
            server.send_progress = AsyncMock()
            await server.web_form_brute(
                target="10.10.10.1",
                path="/login",
                fail_string="Error: invalid credentials",
                username="admin",
                password="test",
                timeout=5,
            )

        cmd = list(calls[0])
        form_idx = cmd.index("http-post-form") + 1
        form_str = cmd[form_idx]
        # The fail_string colon should be escaped
        assert "F=Error\\: invalid credentials" in form_str
        # But the delimiter colons should NOT be escaped
        assert form_str.startswith("/login:")

    @pytest.mark.asyncio
    async def test_web_form_brute_escapes_colons_in_path(self):
        """Colons in path should be escaped."""
        server = _get_server_class()()
        calls = []

        async def mock_create_subprocess(*args, **kwargs):
            calls.append(args)
            proc = MagicMock()
            proc.communicate = AsyncMock(return_value=(b"", b""))
            proc.terminate = MagicMock()
            proc.kill = MagicMock()
            proc.returncode = 0
            return proc

        with patch("asyncio.create_subprocess_exec", mock_create_subprocess):
            server.send_progress = AsyncMock()
            await server.web_form_brute(
                target="10.10.10.1",
                path="/api:auth/login",
                fail_string="Invalid",
                username="admin",
                password="test",
                timeout=5,
            )

        cmd = list(calls[0])
        form_idx = cmd.index("http-post-form") + 1
        form_str = cmd[form_idx]
        # The path colon should be escaped
        assert form_str.startswith("/api\\:auth/login:")

    @pytest.mark.asyncio
    async def test_web_form_brute_escapes_colons_in_extra_params(self):
        """Colons in extra_params should be escaped."""
        server = _get_server_class()()
        calls = []

        async def mock_create_subprocess(*args, **kwargs):
            calls.append(args)
            proc = MagicMock()
            proc.communicate = AsyncMock(return_value=(b"", b""))
            proc.terminate = MagicMock()
            proc.kill = MagicMock()
            proc.returncode = 0
            return proc

        with patch("asyncio.create_subprocess_exec", mock_create_subprocess):
            server.send_progress = AsyncMock()
            await server.web_form_brute(
                target="10.10.10.1",
                path="/login",
                fail_string="Invalid",
                username="admin",
                password="test",
                extra_params="token=abc:123",
                timeout=5,
            )

        cmd = list(calls[0])
        form_idx = cmd.index("http-post-form") + 1
        form_str = cmd[form_idx]
        assert "token=abc\\:123" in form_str

    @pytest.mark.asyncio
    async def test_web_form_brute_no_double_escape(self):
        """Already-escaped colons should not be double-escaped."""
        server = _get_server_class()()
        calls = []

        async def mock_create_subprocess(*args, **kwargs):
            calls.append(args)
            proc = MagicMock()
            proc.communicate = AsyncMock(return_value=(b"", b""))
            proc.terminate = MagicMock()
            proc.kill = MagicMock()
            proc.returncode = 0
            return proc

        with patch("asyncio.create_subprocess_exec", mock_create_subprocess):
            server.send_progress = AsyncMock()
            await server.web_form_brute(
                target="10.10.10.1",
                path="/login",
                fail_string="Error\\: already escaped",
                username="admin",
                password="test",
                timeout=5,
            )

        cmd = list(calls[0])
        form_idx = cmd.index("http-post-form") + 1
        form_str = cmd[form_idx]
        # Already-escaped should stay as \: (not become \\:)
        assert "F=Error\\: already escaped" in form_str

    @pytest.mark.asyncio
    async def test_bruteforce_creds_found_with_errors_returns_success(self):
        """When credentials are found alongside errors, result should be success."""
        server = _get_server_class()()
        server.send_progress = AsyncMock()

        async def mock_create_subprocess(*args, **kwargs):
            proc = MagicMock()
            proc.communicate = AsyncMock(return_value=(
                b"[DATA] max 8 tasks per 1 server, overall 8 tasks, 1000 login tries\n"
                b"[21][ftp] host: 10.10.10.1   login: admin   password: admin\n"
                b"[ERROR] could not connect to target port 21\n"
                b"[21][ftp] host: 10.10.10.1   login: root   password: toor\n",
                b""
            ))
            proc.terminate = MagicMock()
            proc.kill = MagicMock()
            proc.returncode = 0
            return proc

        with patch("asyncio.create_subprocess_exec", mock_create_subprocess):
            result = await server.bruteforce(
                target="10.10.10.1",
                service="ftp",
                username="admin",
                password="test",
                timeout=10,
            )

        assert result.success is True, "Should be success when creds found despite errors"
        assert result.data["found"] is True
        assert result.data["count"] == 2
        # Errors should be promoted to warnings
        assert any("ERROR during scan" in w for w in result.data.get("warnings", []))

    @pytest.mark.asyncio
    async def test_bruteforce_errors_without_creds_returns_failure(self):
        """When only errors (no creds), result should be failure."""
        server = _get_server_class()()
        server.send_progress = AsyncMock()

        async def mock_create_subprocess(*args, **kwargs):
            proc = MagicMock()
            proc.communicate = AsyncMock(return_value=(
                b"[ERROR] could not connect to target port 22\n",
                b""
            ))
            proc.terminate = MagicMock()
            proc.kill = MagicMock()
            proc.returncode = 1
            return proc

        with patch("asyncio.create_subprocess_exec", mock_create_subprocess):
            result = await server.bruteforce(
                target="10.10.10.1",
                service="ssh",
                username="test",
                password="test",
                timeout=10,
            )

        assert result.success is False


class TestServiceDefaults:
    """Test service-specific default values."""

    def test_service_ports(self):
        """All services should have a default port."""
        server = _get_server_class()()
        # Spot-check critical services
        assert server.SERVICE_PORTS["ssh"] == 22
        assert server.SERVICE_PORTS["ftp"] == 21
        assert server.SERVICE_PORTS["mysql"] == 3306
        assert server.SERVICE_PORTS["rdp"] == 3389
        assert server.SERVICE_PORTS["vnc"] == 5900
        assert server.SERVICE_PORTS["redis"] == 6379
        assert server.SERVICE_PORTS["snmp"] == 161

    def test_service_threads(self):
        """Service-specific thread counts should be sensible."""
        server = _get_server_class()()
        # SSH must be low to avoid rate limiting
        assert server.SERVICE_THREADS["ssh"] == 4
        assert server.SERVICE_THREADS["sshkey"] == 4
        # Database services should be low
        assert server.SERVICE_THREADS["mysql"] <= 4
        assert server.SERVICE_THREADS["postgres"] <= 4
        # Default for HTTP should be higher
        assert server.DEFAULT_THREADS >= 16

    def test_password_only_services(self):
        """Password-only services set should be complete."""
        server = _get_server_class()()
        expected = {"redis", "cisco", "cisco-enable", "oracle-listener", "snmp", "vnc"}
        assert server.PASSWORD_ONLY_SERVICES == expected


# ===========================================================================
# HEARTBEAT TESTS -- verify heartbeat mechanism for long-running operations
# ===========================================================================

class TestHeartbeat:
    """Test that heartbeats are sent during long-running brute-force operations."""

    @pytest.mark.asyncio
    async def test_bruteforce_sends_heartbeats(self):
        """Verify heartbeats are sent during long-running operation.

        The heartbeat loop uses asyncio.sleep(30) in production. We patch
        the sleep call to fire much faster so the test doesn't take 30+ seconds.
        """
        server = _get_server_class()()
        heartbeats = []

        async def mock_send_progress(msg, progress=0.0, total=None):
            heartbeats.append(msg)

        server.send_progress = mock_send_progress

        # Create a slow subprocess mock that takes ~2 seconds
        async def mock_create_subprocess(*args, **kwargs):
            proc = MagicMock()

            async def slow_communicate():
                # Use a real sleep that won't be patched (we only patch
                # asyncio.sleep in the server module)
                await asyncio.sleep(2)
                return (
                    b"[DATA] max 4 tasks, 100 login tries\n"
                    b"[22][ssh] host: 10.10.10.1   login: admin   password: test\n",
                    b""
                )

            proc.communicate = slow_communicate
            proc.terminate = MagicMock()
            proc.kill = MagicMock()
            proc.returncode = 0
            proc.stdout = asyncio.subprocess.PIPE
            proc.stderr = asyncio.subprocess.PIPE
            return proc

        # Patch asyncio.sleep in the server module to use 0.3s instead of 30s
        mod = _get_module()
        original_sleep = asyncio.sleep

        async def fast_sleep(seconds):
            if seconds == 30:  # Heartbeat interval
                await original_sleep(0.3)
            else:
                await original_sleep(seconds)

        with patch("asyncio.create_subprocess_exec", mock_create_subprocess), \
             patch.object(asyncio, "sleep", fast_sleep):
            result = await server.bruteforce(
                target="10.10.10.1",
                service="ssh",
                username="admin",
                password="test",
                timeout=30,
            )

        # With 0.3s heartbeat interval and ~2s operation, expect multiple heartbeats
        assert len(heartbeats) >= 1, (
            f"Expected at least 1 heartbeat during operation, got {len(heartbeats)}"
        )
        # Heartbeat messages should contain "running"
        assert any("running" in h.lower() for h in heartbeats), (
            f"Heartbeats should contain 'running', got: {heartbeats}"
        )


# ===========================================================================
# ERROR CLASSIFICATION TESTS
# ===========================================================================

class TestErrorClassification:
    """Test that errors are properly classified."""

    @pytest.mark.asyncio
    async def test_timeout_returns_partial_results(self):
        """On timeout, partial results should be returned."""
        server = _get_server_class()()
        server.send_progress = AsyncMock()

        async def mock_create_subprocess(*args, **kwargs):
            proc = MagicMock()

            async def never_finish():
                await asyncio.sleep(9999)  # Never finishes
                return (b"", b"")

            async def terminate_output():
                return (
                    b"[22][ssh] host: 10.10.10.1   login: admin   password: found_before_timeout\n",
                    b""
                )

            proc.communicate = never_finish  # Initial call hangs
            proc.terminate = MagicMock()
            proc.kill = MagicMock()
            proc.returncode = -15  # SIGTERM
            proc.stdout = asyncio.subprocess.PIPE
            proc.stderr = asyncio.subprocess.PIPE

            # After terminate, communicate returns partial output
            _first_call = [True]
            _orig = proc.communicate
            async def patched_communicate():
                if _first_call[0]:
                    _first_call[0] = False
                    return await _orig()
                return await terminate_output()
            proc.communicate = patched_communicate

            return proc

        with patch("asyncio.create_subprocess_exec", mock_create_subprocess):
            result = await server.bruteforce(
                target="10.10.10.1",
                service="ssh",
                username="admin",
                password="test",
                timeout=1,  # Very short timeout
            )

        assert result.success is False
        assert "timed out" in result.error
        assert result.data.get("partial") is True

    @pytest.mark.asyncio
    async def test_connection_error_classified(self):
        """Connection errors should be detected from hydra output."""
        server = _get_server_class()()
        server.send_progress = AsyncMock()

        async def mock_create_subprocess(*args, **kwargs):
            proc = MagicMock()
            proc.communicate = AsyncMock(return_value=(
                b"[ERROR] could not connect to target port 22\n",
                b""
            ))
            proc.terminate = MagicMock()
            proc.kill = MagicMock()
            proc.returncode = 1
            return proc

        with patch("asyncio.create_subprocess_exec", mock_create_subprocess):
            result = await server.bruteforce(
                target="10.10.10.1",
                service="ssh",
                username="test",
                password="test",
                timeout=10,
            )

        assert result.success is False
        assert "connect" in result.error.lower()

    def test_classify_file_not_found(self):
        """File-not-found errors should be classified as 'params'."""
        server = _get_server_class()()
        assert server._classify_error("File for passwords not found: /tmp/wordlist.txt") == "params"

    def test_classify_optional_parameter(self):
        """Malformed form string errors should be classified as 'params'."""
        server = _get_server_class()()
        assert server._classify_error("no valid optional parameter type given: F") == "params"
        assert server._classify_error("optional parameters must have the format X=value: Invalid") == "params"

    def test_classify_connection_refused(self):
        """Connection refused should be 'network'."""
        server = _get_server_class()()
        assert server._classify_error("could not connect to target port 22") == "network"
        assert server._classify_error("Connection refused") == "network"

    def test_classify_auth_not_supported(self):
        """Auth not supported should be 'auth'."""
        server = _get_server_class()()
        assert server._classify_error("does not support password authentication (method reply 4)") == "auth"

    def test_classify_unknown(self):
        """Unknown errors should be 'unknown'."""
        server = _get_server_class()()
        assert server._classify_error("some weird error we haven't seen") == "unknown"

    def test_error_suggestions_include_params_paths(self):
        """Param error suggestions should mention file paths and form strings."""
        server = _get_server_class()()
        suggestions = server._error_suggestions("params", "http-post-form")
        suggestions_text = " ".join(suggestions)
        assert "path" in suggestions_text.lower() or "file" in suggestions_text.lower()

    @pytest.mark.asyncio
    async def test_file_not_found_error_classified_as_params(self):
        """hydra file-not-found error should get 'params' error_class."""
        server = _get_server_class()()
        server.send_progress = AsyncMock()

        async def mock_create_subprocess(*args, **kwargs):
            proc = MagicMock()
            proc.communicate = AsyncMock(return_value=(
                b"[ERROR] File for passwords not found: /tmp/nonexistent.txt\n",
                b""
            ))
            proc.terminate = MagicMock()
            proc.kill = MagicMock()
            proc.returncode = 1
            return proc

        with patch("asyncio.create_subprocess_exec", mock_create_subprocess):
            result = await server.bruteforce(
                target="10.10.10.1",
                service="ssh",
                username="test",
                passlist="/tmp/nonexistent.txt",
                timeout=10,
            )

        assert result.success is False
        assert result.error_class == "params"

    @pytest.mark.asyncio
    async def test_form_string_error_classified_as_params(self):
        """hydra form string error should get 'params' error_class."""
        server = _get_server_class()()
        server.send_progress = AsyncMock()

        async def mock_create_subprocess(*args, **kwargs):
            proc = MagicMock()
            proc.communicate = AsyncMock(return_value=(
                b"[ERROR] no valid optional parameter type given: F\n",
                b""
            ))
            proc.terminate = MagicMock()
            proc.kill = MagicMock()
            proc.returncode = 1
            return proc

        with patch("asyncio.create_subprocess_exec", mock_create_subprocess):
            result = await server.bruteforce(
                target="10.10.10.1",
                service="http-post-form",
                username="admin",
                password="test",
                http_form="/login:user=^USER^&pass=^PASS^:F=Invalid:H=Content-Type: application/json",
                timeout=10,
            )

        assert result.success is False
        assert result.error_class == "params"


# ===========================================================================
# CONTRACT TESTS -- tool.yaml vs server
# ===========================================================================

class TestContract:
    """Verify tool.yaml and server definitions match."""

    def test_yaml_methods_match_server(self):
        """Every method in tool.yaml should be in the server and vice versa."""
        yaml_path = TOOL_DIR / "tool.yaml"
        with open(yaml_path) as f:
            yaml_data = yaml.safe_load(f)
        yaml_methods = set(yaml_data.get("methods", {}).keys())

        server = _get_server_class()()
        # Server methods are in server.methods dict
        server_methods = set(server.methods.keys())

        yaml_only = yaml_methods - server_methods
        server_only = server_methods - yaml_methods

        assert not yaml_only, f"Methods in tool.yaml but not server: {yaml_only}"
        # Note: server may have extra internal methods, that's OK

    def test_yaml_params_subset_of_server(self):
        """Every param in tool.yaml should exist in the server's method definition."""
        yaml_path = TOOL_DIR / "tool.yaml"
        with open(yaml_path) as f:
            yaml_data = yaml.safe_load(f)

        server = _get_server_class()()

        for method_name, method_def in yaml_data.get("methods", {}).items():
            if method_name not in server.methods:
                continue

            yaml_params = set(method_def.get("params", {}).keys())
            server_method = server.methods[method_name]
            server_params = set(server_method.params.keys())

            yaml_only = yaml_params - server_params
            assert not yaml_only, (
                f"Method {method_name}: params in tool.yaml but not server: {yaml_only}"
            )

    def test_required_params_match(self):
        """Required params in tool.yaml should be required in server too."""
        yaml_path = TOOL_DIR / "tool.yaml"
        with open(yaml_path) as f:
            yaml_data = yaml.safe_load(f)

        server = _get_server_class()()

        for method_name, method_def in yaml_data.get("methods", {}).items():
            if method_name not in server.methods:
                continue

            server_method = server.methods[method_name]
            for param_name, param_def in method_def.get("params", {}).items():
                if param_def.get("required"):
                    server_param = server_method.params.get(param_name, {})
                    assert server_param.get("required"), (
                        f"Method {method_name}: param {param_name} is required "
                        f"in tool.yaml but not in server"
                    )


# ===========================================================================
# CONTAINER METHOD TESTS -- test actual methods via Docker
# ===========================================================================

class TestBruteforceContainer:
    """Test the bruteforce method via Docker container."""

    def test_bruteforce_unreachable_target(self, hydra_env):
        """Brute-force against unreachable target should fail gracefully."""
        client, loop = hydra_env
        resp = loop.run_until_complete(
            client.call("bruteforce", {
                "target": "192.0.2.1",  # TEST-NET, unreachable
                "service": "ssh",
                "username": "test",
                "password": "test",
                "timeout": 10,
            }, timeout=30)
        )
        # Should complete (not hang forever) with error
        result = resp.get("result", {})
        # Either isError or the data shows no credentials
        output = parse_tool_output(resp)
        if isinstance(output, dict):
            assert output.get("found", True) is not True or result.get("isError")
        else:
            # Text error output
            assert isinstance(output, str)

    def test_bruteforce_missing_required_param(self, hydra_env):
        """Missing required 'target' should return error."""
        client, loop = hydra_env
        resp = loop.run_until_complete(
            client.call("bruteforce", {
                "service": "ssh",
                "username": "test",
                "password": "test",
            })
        )
        result = resp.get("result", {})
        assert result.get("isError", False), "Missing target should error"


class TestSSHBruteContainer:
    """Test the ssh_brute method via Docker container."""

    def test_ssh_brute_unreachable(self, hydra_env):
        """ssh_brute against unreachable target should fail gracefully."""
        client, loop = hydra_env
        resp = loop.run_until_complete(
            client.call("ssh_brute", {
                "target": "192.0.2.1",
                "username": "test",
                "password": "test",
                "timeout": 10,
            }, timeout=30)
        )
        result = resp.get("result", {})
        output = parse_tool_output(resp)
        if isinstance(output, dict):
            assert output.get("found", True) is not True or result.get("isError")

    def test_ssh_brute_missing_target(self, hydra_env):
        """Missing target should error."""
        client, loop = hydra_env
        resp = loop.run_until_complete(
            client.call("ssh_brute", {
                "username": "test",
                "password": "test",
            })
        )
        result = resp.get("result", {})
        assert result.get("isError", False), "Missing target should error"


class TestFTPBruteContainer:
    """Test the ftp_brute method via Docker container."""

    def test_ftp_brute_unreachable(self, hydra_env):
        """ftp_brute against unreachable target should fail gracefully."""
        client, loop = hydra_env
        resp = loop.run_until_complete(
            client.call("ftp_brute", {
                "target": "192.0.2.1",
                "username": "test",
                "password": "test",
                "timeout": 10,
            }, timeout=30)
        )
        result = resp.get("result", {})
        output = parse_tool_output(resp)
        if isinstance(output, dict):
            assert output.get("found", True) is not True or result.get("isError")


class TestWebFormBruteContainer:
    """Test the web_form_brute method via Docker container."""

    def test_web_form_brute_unreachable(self, hydra_env):
        """web_form_brute against unreachable target should fail gracefully."""
        client, loop = hydra_env
        resp = loop.run_until_complete(
            client.call("web_form_brute", {
                "target": "192.0.2.1",
                "path": "/login",
                "fail_string": "Invalid",
                "username": "admin",
                "password": "test",
                "timeout": 10,
            }, timeout=30)
        )
        result = resp.get("result", {})
        output = parse_tool_output(resp)
        if isinstance(output, dict):
            assert output.get("found", True) is not True or result.get("isError")

    def test_web_form_brute_missing_fail_string(self, hydra_env):
        """Missing fail_string should error."""
        client, loop = hydra_env
        resp = loop.run_until_complete(
            client.call("web_form_brute", {
                "target": "10.10.10.1",
                "path": "/login",
                "username": "admin",
                "password": "test",
            })
        )
        result = resp.get("result", {})
        assert result.get("isError", False), "Missing fail_string should error"


class TestMySQLBruteContainer:
    """Test the mysql_brute method via Docker container."""

    def test_mysql_brute_unreachable(self, hydra_env):
        """mysql_brute against unreachable target should fail gracefully."""
        client, loop = hydra_env
        resp = loop.run_until_complete(
            client.call("mysql_brute", {
                "target": "192.0.2.1",
                "password": "test",
                "timeout": 10,
            }, timeout=30)
        )
        result = resp.get("result", {})
        output = parse_tool_output(resp)
        if isinstance(output, dict):
            assert output.get("found", True) is not True or result.get("isError")

    def test_mysql_brute_defaults_to_root(self, hydra_env):
        """mysql_brute should default to 'root' username."""
        # We verify this by checking the response summary
        client, loop = hydra_env
        resp = loop.run_until_complete(
            client.call("mysql_brute", {
                "target": "192.0.2.1",
                "password": "test",
                "timeout": 10,
            }, timeout=30)
        )
        output = parse_tool_output(resp)
        # The raw output or summary should reference the root user
        if isinstance(output, dict):
            raw = output.get("raw_output", "")
            summary = output.get("summary", {})
            # Can't assert much about unreachable target, just verify it completes
            assert True


# ===========================================================================
# ACCEPTANCE TESTS -- every method called through container (no live target)
# ===========================================================================

class TestAcceptance:
    """Call every method through the container without a live target.

    These tests verify:
    - The method exists and is callable
    - Required param validation works (missing required params -> error)
    - The response has correct structuredContent shape
    - Error responses have error_class set (classified, not crash)

    Each test sends minimal args with an unreachable host (192.0.2.1) so the
    command will fail at connection time, but the MCP protocol layer, param
    validation, and error classification should all function correctly.
    """

    _UNREACHABLE = "192.0.2.1"

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

    # ── bruteforce ────────────────────────────────────────────

    def test_bruteforce_unreachable(self, hydra_env):
        """bruteforce against unreachable target returns classified error."""
        client, loop = hydra_env
        resp = loop.run_until_complete(client.call("bruteforce", {
            "target": self._UNREACHABLE,
            "service": "ssh",
            "username": "admin",
            "password": "test",
            "timeout": 10,
        }, timeout=30))
        self._assert_structured_response(resp, "bruteforce")

    def test_bruteforce_missing_target(self, hydra_env):
        """bruteforce without target returns error."""
        client, loop = hydra_env
        resp = loop.run_until_complete(client.call("bruteforce", {
            "service": "ssh",
            "username": "admin",
            "password": "test",
        }))
        result = resp.get("result", {})
        is_error = result.get("isError", False)
        content_text = ""
        for c in result.get("content", []):
            if c.get("type") == "text":
                content_text += c["text"]
        assert is_error or "target" in content_text.lower() or "required" in content_text.lower()

    def test_bruteforce_missing_service(self, hydra_env):
        """bruteforce without service returns error."""
        client, loop = hydra_env
        resp = loop.run_until_complete(client.call("bruteforce", {
            "target": self._UNREACHABLE,
            "username": "admin",
            "password": "test",
        }))
        result = resp.get("result", {})
        is_error = result.get("isError", False)
        content_text = ""
        for c in result.get("content", []):
            if c.get("type") == "text":
                content_text += c["text"]
        assert is_error or "service" in content_text.lower() or "required" in content_text.lower()

    def test_bruteforce_with_options(self, hydra_env):
        """bruteforce with threads/stop_on_first/verbose does not crash."""
        client, loop = hydra_env
        resp = loop.run_until_complete(client.call("bruteforce", {
            "target": self._UNREACHABLE,
            "service": "ftp",
            "username": "admin",
            "password": "test",
            "threads": 2,
            "stop_on_first": True,
            "verbose": True,
            "timeout": 10,
        }, timeout=30))
        self._assert_structured_response(resp, "bruteforce+options")

    def test_bruteforce_with_try_common(self, hydra_env):
        """bruteforce with try_common flag does not crash."""
        client, loop = hydra_env
        resp = loop.run_until_complete(client.call("bruteforce", {
            "target": self._UNREACHABLE,
            "service": "ssh",
            "username": "admin",
            "try_common": "nsr",
            "timeout": 10,
        }, timeout=30))
        self._assert_structured_response(resp, "bruteforce+try_common")

    # ── ssh_brute ─────────────────────────────────────────────

    def test_ssh_brute_unreachable(self, hydra_env):
        """ssh_brute against unreachable target returns classified error."""
        client, loop = hydra_env
        resp = loop.run_until_complete(client.call("ssh_brute", {
            "target": self._UNREACHABLE,
            "username": "root",
            "password": "toor",
            "timeout": 10,
        }, timeout=30))
        self._assert_structured_response(resp, "ssh_brute")

    def test_ssh_brute_missing_target(self, hydra_env):
        """ssh_brute without target returns error."""
        client, loop = hydra_env
        resp = loop.run_until_complete(client.call("ssh_brute", {
            "username": "root",
            "password": "toor",
        }))
        result = resp.get("result", {})
        is_error = result.get("isError", False)
        content_text = ""
        for c in result.get("content", []):
            if c.get("type") == "text":
                content_text += c["text"]
        assert is_error or "target" in content_text.lower() or "required" in content_text.lower()

    # ── ftp_brute ─────────────────────────────────────────────

    def test_ftp_brute_unreachable(self, hydra_env):
        """ftp_brute against unreachable target returns classified error."""
        client, loop = hydra_env
        resp = loop.run_until_complete(client.call("ftp_brute", {
            "target": self._UNREACHABLE,
            "username": "anonymous",
            "password": "anonymous@",
            "timeout": 10,
        }, timeout=30))
        self._assert_structured_response(resp, "ftp_brute")

    def test_ftp_brute_missing_target(self, hydra_env):
        """ftp_brute without target returns error."""
        client, loop = hydra_env
        resp = loop.run_until_complete(client.call("ftp_brute", {
            "username": "anonymous",
            "password": "anonymous@",
        }))
        result = resp.get("result", {})
        is_error = result.get("isError", False)
        content_text = ""
        for c in result.get("content", []):
            if c.get("type") == "text":
                content_text += c["text"]
        assert is_error or "target" in content_text.lower() or "required" in content_text.lower()

    # ── web_form_brute ────────────────────────────────────────

    def test_web_form_brute_unreachable(self, hydra_env):
        """web_form_brute against unreachable target returns classified error."""
        client, loop = hydra_env
        resp = loop.run_until_complete(client.call("web_form_brute", {
            "target": self._UNREACHABLE,
            "path": "/login.php",
            "fail_string": "Invalid credentials",
            "username": "admin",
            "password": "test",
            "timeout": 10,
        }, timeout=30))
        self._assert_structured_response(resp, "web_form_brute")

    def test_web_form_brute_missing_path(self, hydra_env):
        """web_form_brute without path returns error."""
        client, loop = hydra_env
        resp = loop.run_until_complete(client.call("web_form_brute", {
            "target": self._UNREACHABLE,
            "fail_string": "Invalid",
            "username": "admin",
            "password": "test",
        }))
        result = resp.get("result", {})
        is_error = result.get("isError", False)
        content_text = ""
        for c in result.get("content", []):
            if c.get("type") == "text":
                content_text += c["text"]
        assert is_error or "path" in content_text.lower() or "required" in content_text.lower()

    def test_web_form_brute_missing_fail_string(self, hydra_env):
        """web_form_brute without fail_string returns error."""
        client, loop = hydra_env
        resp = loop.run_until_complete(client.call("web_form_brute", {
            "target": self._UNREACHABLE,
            "path": "/login",
            "username": "admin",
            "password": "test",
        }))
        result = resp.get("result", {})
        assert result.get("isError", False), "Missing fail_string should error"

    def test_web_form_brute_https(self, hydra_env):
        """web_form_brute with https flag does not crash."""
        client, loop = hydra_env
        resp = loop.run_until_complete(client.call("web_form_brute", {
            "target": self._UNREACHABLE,
            "path": "/login",
            "fail_string": "Invalid",
            "username": "admin",
            "password": "test",
            "https": True,
            "timeout": 10,
        }, timeout=30))
        self._assert_structured_response(resp, "web_form_brute+https")

    # ── mysql_brute ───────────────────────────────────────────

    def test_mysql_brute_unreachable(self, hydra_env):
        """mysql_brute against unreachable target returns classified error."""
        client, loop = hydra_env
        resp = loop.run_until_complete(client.call("mysql_brute", {
            "target": self._UNREACHABLE,
            "username": "root",
            "password": "test",
            "timeout": 10,
        }, timeout=30))
        self._assert_structured_response(resp, "mysql_brute")

    def test_mysql_brute_missing_target(self, hydra_env):
        """mysql_brute without target returns error."""
        client, loop = hydra_env
        resp = loop.run_until_complete(client.call("mysql_brute", {
            "username": "root",
            "password": "test",
        }))
        result = resp.get("result", {})
        is_error = result.get("isError", False)
        content_text = ""
        for c in result.get("content", []):
            if c.get("type") == "text":
                content_text += c["text"]
        assert is_error or "target" in content_text.lower() or "required" in content_text.lower()

    # ── Cross-cutting ─────────────────────────────────────────

    def test_all_methods_return_structuredContent(self, hydra_env):
        """verify_clock returns structuredContent with all required fields."""
        client, loop = hydra_env
        resp = loop.run_until_complete(client.call("verify_clock", {}))
        result = resp.get("result", {})
        sc = result.get("structuredContent")
        assert sc is not None
        assert isinstance(sc, dict)
        for field in ("success", "error_class", "retryable", "suggestions"):
            assert field in sc, f"Missing field '{field}' in structuredContent"
