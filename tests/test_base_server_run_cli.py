"""Unit tests for BaseMCPServer.run_cli and the dual-clock model.

These tests run as pure Python (no Docker), exercising:
  * run_cli arg validation (binary required, args must be list[str])
  * run_cli routing through run_command_with_progress
  * stdin_data feeding to subprocess
  * Hard-cap timeout via run_command_with_progress
  * Heartbeat task lifecycle (cancelled cleanly)
  * Auto-registration of run_cli in BaseMCPServer.__init__

This is the unit layer of the testing pyramid for Feature 35's transport
architecture. Integration-layer tests against real containers live in
tests/tools/ and require Docker.
"""

import asyncio
import sys
import os

# Ensure the local mcp-common src is importable when running pytest from the
# tests/ dir without installing the package.
sys.path.insert(
    0,
    os.path.join(os.path.dirname(__file__), "..", "packages", "mcp-common", "src"),
)

import pytest

from mcp_common.base_server import BaseMCPServer, ToolError, ToolResult


class _MinimalServer(BaseMCPServer):
    """Minimal concrete BaseMCPServer subclass — does nothing custom.

    BaseMCPServer is abstract-ish (uses ABC) but doesn't actually have any
    abstract methods, so we can instantiate a bare subclass for testing.
    """

    pass


# ─────────────────────────────────────────────────────────────────────
# Auto-registration
# ─────────────────────────────────────────────────────────────────────


def test_run_cli_auto_registered_in_init() -> None:
    """Every BaseMCPServer subclass exposes run_cli without doing anything."""
    server = _MinimalServer("test", "test server")
    assert "run_cli" in server.methods
    method = server.methods["run_cli"]
    assert "binary" in method.params
    assert method.params["binary"]["required"] is True
    assert "args" in method.params
    assert "stdin_data" in method.params
    assert method.params["stdin_data"]["required"] is False
    assert "env" in method.params
    assert method.params["env"]["required"] is False
    assert method.params["env"]["type"] == "object"
    assert "max_runtime" in method.params
    assert method.params["max_runtime"]["default"] == 86400


# ─────────────────────────────────────────────────────────────────────
# Arg validation
# ─────────────────────────────────────────────────────────────────────


@pytest.mark.asyncio
async def test_run_cli_rejects_empty_binary() -> None:
    server = _MinimalServer("test", "test")
    result = await server.run_cli(binary="", args=["foo"])
    assert isinstance(result, ToolResult)
    assert result.success is False
    assert result.error_class == "params"
    assert "binary" in result.error.lower()


@pytest.mark.asyncio
async def test_run_cli_rejects_non_string_binary() -> None:
    server = _MinimalServer("test", "test")
    result = await server.run_cli(binary=None, args=[])  # type: ignore[arg-type]
    assert result.success is False
    assert result.error_class == "params"


@pytest.mark.asyncio
async def test_run_cli_rejects_non_list_args() -> None:
    server = _MinimalServer("test", "test")
    result = await server.run_cli(binary="echo", args="hello")  # type: ignore[arg-type]
    assert result.success is False
    assert result.error_class == "params"
    assert "list of strings" in result.error.lower()


@pytest.mark.asyncio
async def test_run_cli_rejects_args_with_non_string_elements() -> None:
    server = _MinimalServer("test", "test")
    result = await server.run_cli(binary="echo", args=["a", 1, "b"])  # type: ignore[list-item]
    assert result.success is False
    assert result.error_class == "params"


# ─────────────────────────────────────────────────────────────────────
# Happy path — actually exec a binary
# ─────────────────────────────────────────────────────────────────────


@pytest.mark.asyncio
async def test_run_cli_executes_echo_and_captures_stdout() -> None:
    server = _MinimalServer("test", "test")
    result = await server.run_cli(binary="echo", args=["hello", "world"])
    assert result.success is True
    assert result.data["exit_code"] == 0
    assert "hello world" in result.data["stdout"]
    assert result.data["binary"] == "echo"
    assert result.data["args"] == ["hello", "world"]
    assert result.error is None


@pytest.mark.asyncio
async def test_run_cli_captures_stderr_separately() -> None:
    server = _MinimalServer("test", "test")
    # `sh -c 'echo to-err >&2'` writes only to stderr
    result = await server.run_cli(
        binary="sh",
        args=["-c", "echo to-err 1>&2"],
    )
    assert result.success is True
    assert result.data["stdout"] == ""
    assert "to-err" in result.data["stderr"]


@pytest.mark.asyncio
async def test_run_cli_preserves_non_zero_exit_in_data() -> None:
    """Non-zero exit is information, not transport failure — success=True so
    data is preserved on the wire and the plugin/LLM can interpret exit_code."""
    server = _MinimalServer("test", "test")
    result = await server.run_cli(
        binary="sh",
        args=["-c", "exit 42"],
    )
    assert result.success is True
    assert result.data["exit_code"] == 42
    assert result.data["completed"] is True
    assert result.error is None


# ─────────────────────────────────────────────────────────────────────
# stdin_data
# ─────────────────────────────────────────────────────────────────────


@pytest.mark.asyncio
async def test_run_cli_stdin_data_reaches_subprocess() -> None:
    """stdin_data should be piped to the subprocess, then closed (EOF)."""
    server = _MinimalServer("test", "test")
    # `cat` echoes whatever it reads from stdin to stdout. If stdin is
    # DEVNULL (no stdin_data), cat exits immediately with empty stdout.
    # If stdin_data="ping\n", cat writes "ping\n" to stdout.
    result = await server.run_cli(
        binary="cat",
        args=[],
        stdin_data="ping\n",
    )
    assert result.success is True
    assert result.data["stdout"] == "ping\n"


@pytest.mark.asyncio
async def test_run_cli_default_stdin_is_closed() -> None:
    """Without stdin_data, subprocess should see EOF immediately."""
    server = _MinimalServer("test", "test")
    result = await server.run_cli(binary="cat", args=[])
    assert result.success is True
    assert result.data["stdout"] == ""


@pytest.mark.asyncio
async def test_run_cli_stdin_data_accepts_bytes() -> None:
    """run_command_with_progress accepts bytes too — verify pass-through."""
    server = _MinimalServer("test", "test")
    # We test the underlying run_command_with_progress directly to verify
    # bytes acceptance — run_cli's signature is str only, but the lower-level
    # path supports both.
    proc = await server.run_command_with_progress(
        cmd=["cat"],
        timeout=10,
        stdin_data=b"\x00\x01\x02hello\n",
    )
    assert proc.returncode == 0
    assert "hello" in proc.stdout


# ─────────────────────────────────────────────────────────────────────
# env passthrough (sanctioned channel for KRB5CCNAME / FAKETIME / etc.)
# ─────────────────────────────────────────────────────────────────────


@pytest.mark.asyncio
async def test_run_cli_env_default_none_runs_cleanly() -> None:
    """env=None (default) forwards cleanly — pre-env-feature contract preserved."""
    server = _MinimalServer("test", "test")
    result = await server.run_cli(binary="echo", args=["ok"])
    assert result.success is True
    assert "ok" in result.data["stdout"]


@pytest.mark.asyncio
async def test_run_cli_env_dict_reaches_subprocess() -> None:
    """Sentinel test: env={"FOO":"bar"} → printenv FOO writes "bar" to stdout.

    This is the end-to-end forwarding path: run_cli → run_command_with_progress
    (line 548 merge with os.environ) → asyncio.create_subprocess_exec(env=).
    """
    server = _MinimalServer("test", "test")
    result = await server.run_cli(
        binary="printenv",
        args=["OS_RUN_CLI_ENV_TEST"],
        env={"OS_RUN_CLI_ENV_TEST": "sentinel-value"},
    )
    assert result.success is True
    assert result.data["exit_code"] == 0
    assert "sentinel-value" in result.data["stdout"]


@pytest.mark.asyncio
async def test_run_cli_env_merges_with_os_environ() -> None:
    """Agent env overlays on os.environ — PATH and friends remain inherited.

    Without merge, subprocess would only see {"FOO":"bar"} and `printenv PATH`
    would exit non-zero with empty stdout.
    """
    server = _MinimalServer("test", "test")
    result = await server.run_cli(
        binary="printenv",
        args=["PATH"],
        env={"OS_RUN_CLI_ENV_TEST": "ignored"},
    )
    assert result.success is True
    assert result.data["exit_code"] == 0
    # PATH must still be set — proves os.environ wasn't replaced
    assert len(result.data["stdout"].strip()) > 0


@pytest.mark.asyncio
async def test_run_cli_rejects_non_dict_env() -> None:
    """env must be a dict — list/str/int rejected with params error."""
    server = _MinimalServer("test", "test")
    result = await server.run_cli(
        binary="echo",
        args=["x"],
        env=["not", "a", "dict"],  # type: ignore[arg-type]
    )
    assert result.success is False
    assert result.error_class == "params"
    assert "dict" in result.error.lower()


@pytest.mark.asyncio
async def test_run_cli_rejects_env_with_non_string_value() -> None:
    """env values must be strings — int/None/dict-as-value rejected."""
    server = _MinimalServer("test", "test")
    result = await server.run_cli(
        binary="echo",
        args=["x"],
        env={"FOO": 42},  # type: ignore[dict-item]
    )
    assert result.success is False
    assert result.error_class == "params"


@pytest.mark.asyncio
async def test_run_cli_rejects_env_with_non_string_key() -> None:
    """env keys must be strings — protects direct Python callers (JSON-RPC
    dispatch coerces JSON object keys to str, but defence-in-depth)."""
    server = _MinimalServer("test", "test")
    result = await server.run_cli(
        binary="echo",
        args=["x"],
        env={123: "bar"},  # type: ignore[dict-item]
    )
    assert result.success is False
    assert result.error_class == "params"


# ─────────────────────────────────────────────────────────────────────
# Dual clock — hard cap
# ─────────────────────────────────────────────────────────────────────


@pytest.mark.asyncio
async def test_run_cli_hard_cap_kills_runaway_subprocess() -> None:
    """Hard cap fires after max_runtime, kills subprocess, surfaces timeout."""
    server = _MinimalServer("test", "test")
    # `sleep 30` would take 30s; cap at 1s.
    result = await server.run_cli(
        binary="sleep",
        args=["30"],
        max_runtime=1,
    )
    assert result.success is False
    assert result.error_class == "timeout"
    assert result.retryable is True
    assert "1 seconds" in result.error or "1s" in result.error


@pytest.mark.asyncio
async def test_run_cli_completes_under_hard_cap() -> None:
    """A binary that exits well under max_runtime should complete normally."""
    server = _MinimalServer("test", "test")
    result = await server.run_cli(
        binary="sh",
        args=["-c", "echo done; sleep 0.1"],
        max_runtime=10,
    )
    assert result.success is True
    assert "done" in result.data["stdout"]


@pytest.mark.asyncio
async def test_run_command_with_progress_no_timeout_means_unlimited() -> None:
    """timeout=None preserves the existing 'unlimited' contract."""
    server = _MinimalServer("test", "test")
    proc = await server.run_command_with_progress(
        cmd=["sh", "-c", "echo quick && exit 0"],
        timeout=None,
    )
    assert proc.returncode == 0
    assert "quick" in proc.stdout


# ─────────────────────────────────────────────────────────────────────
# Heartbeat task lifecycle
# ─────────────────────────────────────────────────────────────────────


@pytest.mark.asyncio
async def test_heartbeat_task_cancelled_after_normal_completion() -> None:
    """The heartbeat task must be cancelled cleanly when subprocess exits."""
    server = _MinimalServer("test", "test")
    # Capture all currently-pending tasks before, then verify nothing leaks.
    before = {t for t in asyncio.all_tasks() if not t.done()}
    proc = await server.run_command_with_progress(
        cmd=["echo", "x"],
        timeout=5,
        heartbeat_interval=0.05,
    )
    # Yield once for any cancellation cleanup.
    await asyncio.sleep(0.05)
    after = {t for t in asyncio.all_tasks() if not t.done()}
    leaked = after - before
    assert proc.returncode == 0
    # No heartbeat task should still be pending after run_command_with_progress
    # returns. (Implementation cancels in finally:; this asserts it.)
    assert all("heartbeat" not in (t.get_name() or "").lower() for t in leaked)


@pytest.mark.asyncio
async def test_heartbeat_task_cancelled_after_hard_cap() -> None:
    """Heartbeat task is also cancelled cleanly when hard cap fires."""
    server = _MinimalServer("test", "test")
    before = {t for t in asyncio.all_tasks() if not t.done()}
    with pytest.raises(ToolError):
        await server.run_command_with_progress(
            cmd=["sleep", "10"],
            timeout=1,
            heartbeat_interval=0.05,
        )
    await asyncio.sleep(0.05)
    after = {t for t in asyncio.all_tasks() if not t.done()}
    leaked = after - before
    assert all("heartbeat" not in (t.get_name() or "").lower() for t in leaked)
