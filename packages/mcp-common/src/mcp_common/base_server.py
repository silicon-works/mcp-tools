"""
Base MCP Server implementation for OpenSploit tool servers.

Provides a foundation for building MCP servers that wrap security tools.
"""

import asyncio
import datetime
import json
import logging
import os
import re
import signal as _signal
import subprocess
import sys
import time
from abc import ABC, abstractmethod
from contextlib import ExitStack
from dataclasses import dataclass, field
from typing import Any, Callable, Dict, List, Optional

from mcp.server import Server
from mcp.server.lowlevel.server import request_ctx
from mcp.server.stdio import stdio_server
from mcp.types import (
    TextContent,
    Tool,
    CallToolResult,
)

logging.basicConfig(level=logging.INFO, format="%(asctime)s - %(name)s - %(levelname)s - %(message)s")


@dataclass
class ToolResult:
    """Result from a tool execution."""
    success: bool
    data: Dict[str, Any] = field(default_factory=dict)
    raw_output: str = ""
    error: Optional[str] = None
    error_class: Optional[str] = None  # "timeout" | "auth" | "network" | "permission" | "config" | "params" | "unknown"
    retryable: bool = False
    suggestions: List[str] = field(default_factory=list)

    def to_content(self) -> List[TextContent]:
        """Convert result to MCP TextContent.

        When suggestions is non-empty, they are appended after the error line.
        When suggestions is empty, the format is identical to the original
        (preserves backward compatibility for existing tools).
        """
        if self.success:
            # Include raw_output in successful results when present
            result_data = dict(self.data)
            if self.raw_output:
                result_data["raw_output"] = self.raw_output
            return [TextContent(type="text", text=json.dumps(result_data, indent=2))]
        else:
            parts = [f"Error: {self.error}"]
            if self.suggestions:
                parts.append("Suggestions: " + "; ".join(self.suggestions))
            if self.raw_output:
                parts.append(f"\nRaw output:\n{self.raw_output}")
            return [TextContent(type="text", text="\n".join(parts))]


@dataclass
class ToolError(Exception):
    """Error during tool execution."""
    message: str
    details: Optional[str] = None

    def __str__(self) -> str:
        if self.details:
            return f"{self.message}: {self.details}"
        return self.message


@dataclass
class MethodDefinition:
    """Definition of a tool method."""
    name: str
    description: str
    params: Dict[str, Dict[str, Any]]
    handler: Callable


class BaseMCPServer(ABC):
    """
    Base class for MCP tool servers.

    Subclass this to create MCP servers for specific security tools.

    Example:
        class NmapServer(BaseMCPServer):
            def __init__(self):
                super().__init__("nmap", "Network scanner")
                self.register_method(
                    name="port_scan",
                    description="Scan for open ports",
                    params={...},
                    handler=self.port_scan
                )

            async def port_scan(self, target: str, ports: str = "1-1000") -> ToolResult:
                ...
    """

    # Meta-parameters injected by the opensploit client that should be stripped
    # before calling the handler — UNLESS the method's registered params include them
    # (e.g., nmap and hydra have 'timeout' as a real param).
    META_PARAMS = {"timeout", "clock_offset"}

    def __init__(self, name: str, description: str, version: str = "1.0.0"):
        self.name = name
        self.description = description
        self.version = version
        self.methods: Dict[str, MethodDefinition] = {}
        self.logger = logging.getLogger(f"mcp.{name}")
        self._server: Optional[Server] = None

        # Detached process registry: PID → metadata. Populated by
        # run_cli_detached, queried by status_detached, drained by
        # _cleanup_detached on server shutdown. In-memory because
        # detached children die with the container anyway; persistent
        # disk tracking would just record dead PIDs.
        self._detached: Dict[int, Dict[str, Any]] = {}

        # Register test-only methods when MCP_TEST_MODE is set
        if os.environ.get("MCP_TEST_MODE"):
            self.register_method(
                name="verify_clock",
                description="Return container's current time and FAKETIME status (test-only)",
                params={},
                handler=self._verify_clock,
            )

        # Auto-register the generic CLI runner. Every tool server inherits this
        # by virtue of subclassing BaseMCPServer — kind:cli tools rely on it
        # exclusively, kind:mcp tools use it as an escape hatch for ad-hoc
        # invocations the curated methods don't cover.
        self.register_method(
            name="run_cli",
            description=(
                "Execute the tool's binary with the given argv. Generic CLI "
                "runner for tools that take raw command-line arguments rather "
                "than structured method parameters. Returns stdout/stderr/exit "
                "code. Heartbeats every 30s; hard cap defaults to 24h."
            ),
            params={
                "binary": {
                    "type": "string",
                    "description": "Binary to execute (e.g. 'curl', 'sqlmap', 'impacket-secretsdump'). Must be on PATH inside the container.",
                    "required": True,
                },
                "args": {
                    "type": "array",
                    "items": {"type": "string"},
                    "description": "Argv list, already tokenized by the client. Each element is a single argv slot.",
                    "required": True,
                },
                "stdin_data": {
                    "type": "string",
                    "description": "Optional bytes/text fed to the binary's stdin (e.g. for john --stdin or hashcat).",
                    "required": False,
                },
                "env": {
                    "type": "object",
                    "description": "Optional env vars (Dict[str, str]) merged into the subprocess environment. Used by the plugin to forward agent-supplied values (KRB5CCNAME for Kerberos ccache, FAKETIME for libfaketime offset, etc.). The plugin enforces an allowlist before forwarding; here we just pipe to run_command_with_progress.",
                    "required": False,
                    "additionalProperties": {"type": "string"},
                },
                "max_runtime": {
                    "type": "integer",
                    "description": "Hard wall-clock cap in seconds. Defaults to 86400 (24h). Never resets — set generously.",
                    "required": False,
                    "default": 86400,
                },
            },
            handler=self.run_cli,
        )

        # Auto-register the detach trio. These let a tool spawn a long-lived
        # child that survives the cli call returning — the proper mechanism
        # for held listeners, ControlMaster sockets, time-bounded daemons,
        # etc. Replaces the bash `& disown && echo PID=$!` gymnastics that
        # tool.yaml usage_patterns previously had to encode by hand.
        self.register_method(
            name="run_cli_detached",
            description=(
                "Spawn a detached child process and return immediately. "
                "The child runs in a new session (survives the cli call). "
                "Stdout/stderr go to caller-specified files on /session/; "
                "optional stdin_from path is opened and piped to the child. "
                "Returns {pid, stdout_to, stdin_from, stderr_to} so the "
                "caller can resume / poll / kill later."
            ),
            params={
                "binary": {
                    "type": "string",
                    "description": "Binary to execute; same semantics as run_cli.",
                    "required": True,
                },
                "args": {
                    "type": "array",
                    "items": {"type": "string"},
                    "description": "Argv list.",
                    "required": True,
                },
                "stdout_to": {
                    "type": "string",
                    "description": (
                        "Absolute path under /session/ to capture stdout. "
                        "Opened in truncate mode; parent dirs created if missing."
                    ),
                    "required": True,
                },
                "stdin_from": {
                    "type": "string",
                    "description": (
                        "Optional absolute path; opened with O_RDONLY and piped to the "
                        "child's stdin. Use this for feeding a regular file into stdin "
                        "(child reads to EOF and stdin closes). Do NOT pass a FIFO/named "
                        "pipe here — open() on a FIFO blocks until a writer opens the "
                        "other end, which would deadlock this method. For bidirectional "
                        "shells where the agent needs to push commands into a held "
                        "process's stdin, use a bash wrapper: binary='bash', args=['-c', "
                        "'tail -f $DIR/cmd | <held-binary> ... > $DIR/out 2>&1'] (the "
                        "bash pipeline expresses the stdin-streaming shape internally)."
                    ),
                    "required": False,
                },
                "stderr_to": {
                    "type": "string",
                    "description": "Absolute path for stderr. Defaults to stdout_to (merged).",
                    "required": False,
                },
                "env": {
                    "type": "object",
                    "description": "Env vars merged with os.environ. Same allowlist semantics as run_cli.",
                    "required": False,
                    "additionalProperties": {"type": "string"},
                },
            },
            handler=self.run_cli_detached,
        )
        self.register_method(
            name="status_detached",
            description=(
                "Check whether a previously-detached PID is still alive. "
                "Returns {alive, since, stdout_to, stdout_bytes, tracked}. "
                "Caller's normal way to verify a held resource handle on resume."
            ),
            params={
                "pid": {
                    "type": "integer",
                    "description": "PID returned by run_cli_detached.",
                    "required": True,
                },
            },
            handler=self.status_detached,
        )
        self.register_method(
            name="kill_detached",
            description=(
                "Terminate a detached child. TERM with 2s grace then KILL; "
                "pass signal='KILL' to skip grace. Returns {killed, signal, pid}."
            ),
            params={
                "pid": {
                    "type": "integer",
                    "description": "PID returned by run_cli_detached.",
                    "required": True,
                },
                "signal": {
                    "type": "string",
                    "description": "TERM (graceful, 2s grace then KILL) or KILL (immediate).",
                    "required": False,
                    "default": "TERM",
                    "enum": ["TERM", "KILL"],
                },
            },
            handler=self.kill_detached,
        )

    async def run_cli(
        self,
        binary: str,
        args: List[str],
        stdin_data: Optional[str] = None,
        env: Optional[Dict[str, str]] = None,
        max_runtime: int = 86400,
    ) -> "ToolResult":
        """Generic CLI runner — execute ``binary args...`` and return raw output.

        This is the keystone of the kind:cli architecture. The client supplies
        a fully-tokenized argv (no shell, no quoting surprises). We just exec
        and return the result. Target validation, scope checks, reject_flags
        all happened in the plugin before we ever got the call.

        Heartbeat-driven progress notifications keep the client's idle clock
        alive. ``max_runtime`` is the hard cap that catches genuinely wedged
        binaries.

        ``env`` is the plugin's sanctioned channel for per-call env vars
        (KRB5CCNAME for Kerberos ccache, FAKETIME for libfaketime offset,
        etc.). The plugin allowlists keys before forwarding; here we just
        merge into the subprocess env via run_command_with_progress.
        """
        if not binary or not isinstance(binary, str):
            return ToolResult(
                success=False,
                error="run_cli requires non-empty 'binary'",
                error_class="params",
            )
        if not isinstance(args, list) or not all(isinstance(a, str) for a in args):
            return ToolResult(
                success=False,
                error="run_cli requires 'args' to be a list of strings",
                error_class="params",
            )
        if env is not None and (
            not isinstance(env, dict)
            or not all(isinstance(k, str) and isinstance(v, str) for k, v in env.items())
        ):
            return ToolResult(
                success=False,
                error="run_cli 'env' must be a Dict[str, str] when supplied",
                error_class="params",
            )

        cmd = [binary, *args]

        try:
            result = await self.run_command_with_progress(
                cmd,
                timeout=max_runtime,
                stdin_data=stdin_data,
                env=env,
            )
        except ToolError as e:
            # ToolError from run_command_with_progress is the hard-cap path —
            # subprocess was killed and we need to surface it as a timeout.
            return ToolResult(
                success=False,
                error=str(e),
                error_class="timeout",
                retryable=True,
            )

        # MCP-level "success" means "the run completed and we have output for
        # the caller". A non-zero exit is information, not a transport
        # failure — let tool_runner / the LLM interpret exit codes. Only true
        # failures (param errors, hard-cap timeout) return success=False.
        return ToolResult(
            success=True,
            data={
                "exit_code": result.returncode,
                "stdout": result.stdout,
                "stderr": result.stderr,
                "binary": binary,
                "args": args,
                "completed": True,
            },
        )

    async def run_cli_detached(
        self,
        binary: str,
        args: List[str],
        stdout_to: str,
        stdin_from: Optional[str] = None,
        stderr_to: Optional[str] = None,
        env: Optional[Dict[str, str]] = None,
    ) -> "ToolResult":
        """Spawn a detached child process and return immediately.

        See ``run_cli`` for the synchronous foreground equivalent. Where
        ``run_cli`` blocks until the child exits, this method:

          * Opens ``stdout_to`` / ``stderr_to`` for writing (truncate mode).
          * Opens ``stdin_from`` for reading if provided; else stdin = DEVNULL.
          * Spawns the child with ``start_new_session=True`` so it gets its
            own process session — it survives this MCP call's lifecycle and
            is reaped by the OS at container teardown (or by kill_detached).
          * Records the PID in ``self._detached`` so status/kill can find it.
          * Returns immediately with the PID and file paths.

        The child runs as a sibling of the MCP server. The container's idle
        reaper still applies; callers should touch the container (via any
        subsequent cli call) within the idle window or bump the per-tool
        idle config.

        For bidirectional shells where the agent needs to push commands
        into the held process's stdin (e.g., ``tail -f cmd | ncat -lvnp P``),
        the caller passes the bash pipeline as the command:
            binary="bash", args=["-c", "tail -f $DIR/cmd | ncat -lvnp $P > $DIR/out 2>&1"]
        with ``detach: true``. The pipeline expresses the stdin-streaming
        shape; ``stdin_from`` is for the simpler case of feeding a static
        file's contents to the child once.
        """
        # --- param validation (same shape as run_cli) ---
        if not binary or not isinstance(binary, str):
            return ToolResult(
                success=False,
                error="run_cli_detached requires non-empty 'binary'",
                error_class="params",
            )
        if not isinstance(args, list) or not all(isinstance(a, str) for a in args):
            return ToolResult(
                success=False,
                error="run_cli_detached requires 'args' as List[str]",
                error_class="params",
            )
        # Path validation: absolute-only. The /session/ convention is a
        # client-side concern (cli_in_container enforces it before sending);
        # we just require absolute paths so file ops don't surprise us.
        if not stdout_to or not isinstance(stdout_to, str) or not os.path.isabs(stdout_to):
            return ToolResult(
                success=False,
                error="run_cli_detached requires 'stdout_to' as an absolute path",
                error_class="params",
            )
        if stdin_from is not None and (
            not isinstance(stdin_from, str) or not os.path.isabs(stdin_from)
        ):
            return ToolResult(
                success=False,
                error="'stdin_from' must be an absolute path",
                error_class="params",
            )
        if stderr_to is not None and (
            not isinstance(stderr_to, str) or not os.path.isabs(stderr_to)
        ):
            return ToolResult(
                success=False,
                error="'stderr_to' must be an absolute path",
                error_class="params",
            )
        if env is not None and (
            not isinstance(env, dict)
            or not all(isinstance(k, str) and isinstance(v, str) for k, v in env.items())
        ):
            return ToolResult(
                success=False,
                error="'env' must be a Dict[str, str]",
                error_class="params",
            )

        # --- ensure dirs exist; open files for stdio redirection ---
        # Truncate mode — each detach run starts with a fresh capture file.
        # ExitStack closes everything we open on exit, regardless of which
        # step fails (file open / subprocess spawn). After successful spawn
        # the child has dup'd the fds and is unaffected by our close.
        stderr_path = stderr_to or stdout_to
        merged_env = {**os.environ, **env} if env else None
        cmd = [binary, *args]

        with ExitStack() as stack:
            try:
                os.makedirs(os.path.dirname(stdout_to), exist_ok=True)
                if stderr_path != stdout_to:
                    os.makedirs(os.path.dirname(stderr_path), exist_ok=True)
                stdout_fp = stack.enter_context(open(stdout_to, "wb", buffering=0))
                stderr_fp = (
                    stdout_fp if stderr_path == stdout_to
                    else stack.enter_context(open(stderr_path, "wb", buffering=0))
                )
                stdin_fp: Any = (
                    stack.enter_context(open(stdin_from, "rb"))
                    if stdin_from else asyncio.subprocess.DEVNULL
                )
            except OSError as e:
                return ToolResult(
                    success=False,
                    error=f"file open failed: {e}",
                    error_class="config",
                )

            try:
                proc = await asyncio.create_subprocess_exec(
                    *cmd,
                    stdin=stdin_fp,
                    stdout=stdout_fp,
                    stderr=stderr_fp,
                    env=merged_env,
                    start_new_session=True,  # detach from MCP server's session
                )
            except FileNotFoundError:
                return ToolResult(
                    success=False,
                    error=f"binary not found: {binary}",
                    error_class="config",
                )
            except OSError as e:
                # PermissionError (non-executable binary), resource exhaustion, etc.
                return ToolResult(
                    success=False,
                    error=f"spawn failed: {e}",
                    error_class="config",
                )
        # ExitStack closed our parent-side fds here. Child holds its dup'd copies.

        self._detached[proc.pid] = {
            "binary": binary,
            "args": args,
            "stdout_to": stdout_to,
            "stdin_from": stdin_from,
            "stderr_to": stderr_path,
            "started_at": time.time(),
            "proc": proc,  # asyncio Process handle; used for returncode checks
        }

        self.logger.info(
            f"run_cli_detached: spawned pid={proc.pid} cmd={' '.join(cmd)[:120]} "
            f"stdout_to={stdout_to}"
        )

        return ToolResult(
            success=True,
            data={
                "pid": proc.pid,
                "stdout_to": stdout_to,
                "stdin_from": stdin_from,
                "stderr_to": stderr_path,
                "binary": binary,
                "args": args,
            },
        )

    def _is_alive(self, pid: int) -> bool:
        """Untracked-PID liveness fallback via os.kill(pid, 0).

        For tracked PIDs use proc.returncode directly (SIGCHLD-driven,
        race-free); this helper is for the rare case where the caller
        holds a PID we don't have a Process handle for. Caveat: cannot
        distinguish zombies or PID-reuse — best effort only.
        """
        try:
            os.kill(pid, 0)
            return True
        except ProcessLookupError:
            return False
        except PermissionError:
            # exists but not ours — treat as alive
            return True

    async def status_detached(self, pid: int) -> "ToolResult":
        """Check whether a previously-detached PID is still alive.

        For tracked PIDs uses proc.returncode (SIGCHLD-driven, race-free).
        For untracked PIDs (e.g. a PID from a previous server lifetime)
        falls back to os.kill(pid, 0) — best-effort with the known caveat
        that it can't distinguish zombies or PID reuse.
        """
        if not isinstance(pid, int):
            return ToolResult(success=False, error="'pid' must be int", error_class="params")

        meta = self._detached.get(pid)
        if meta is not None:
            proc = meta["proc"]
            alive = proc.returncode is None
            exit_code = proc.returncode
            stdout_path = meta["stdout_to"]
            since = meta["started_at"]
        else:
            alive = self._is_alive(pid)
            exit_code = None
            stdout_path = None
            since = None

        stdout_bytes: Optional[int] = None
        if stdout_path:
            try:
                stdout_bytes = os.path.getsize(stdout_path)
            except OSError:
                stdout_bytes = None

        return ToolResult(
            success=True,
            data={
                "pid": pid,
                "alive": alive,
                "since": since,
                "stdout_to": stdout_path,
                "stdout_bytes": stdout_bytes,
                "exit_code": exit_code,
                "tracked": meta is not None,
            },
        )

    async def kill_detached(self, pid: int, signal: str = "TERM") -> "ToolResult":
        """Terminate a detached child AND its entire process group.

        TERM = graceful (2s grace then KILL); KILL = immediate.

        IMPORTANT: signals the PROCESS GROUP (via os.killpg / os.kill(-pid)),
        not just the single PID. This matters for bash-pipeline detached
        spawns where the spawned process has children (e.g.,
        `bash -c 'tail -f cmd | ncat -lvnp PORT'` spawns bash which forks
        tail and ncat as children in the same process group). Signaling
        only the leader would orphan tail and ncat to init, leaving the
        port bound after the "kill" — verified failure mode on the
        Helix-pathology smoke 2026-05-20. The `start_new_session=True`
        flag at spawn time makes the leader a process-group leader of
        a fresh group containing all descendants, so killpg reaches them
        all in one signal.

        For tracked PIDs (the common case — pid came from run_cli_detached),
        we still use proc.wait() to await termination — that's SIGCHLD-driven
        on the leader and tells us when the group leader has exited. The
        children's deaths trigger SIGCHLD on the leader's parent too, but
        we only care that the leader (the one we have a Process handle for)
        is reaped.

        For untracked PIDs (rare — e.g. caller has a PID from a previous
        server lifetime), falls back to os.killpg + a brief polling window
        since we have no Process handle to await on.
        """
        if not isinstance(pid, int):
            return ToolResult(success=False, error="'pid' must be int", error_class="params")
        if signal not in ("TERM", "KILL"):
            return ToolResult(
                success=False, error="'signal' must be 'TERM' or 'KILL'", error_class="params"
            )

        meta = self._detached.get(pid)
        proc = meta.get("proc") if meta else None

        if proc is not None:
            # --- Tracked path: signal the process group, await the leader ---
            if proc.returncode is not None:
                self._detached.pop(pid, None)
                return ToolResult(
                    success=True,
                    data={
                        "killed": False, "reason": "already exited",
                        "pid": pid, "exit_code": proc.returncode,
                    },
                )

            try:
                if signal == "TERM":
                    os.killpg(proc.pid, _signal.SIGTERM)  # whole group, not just leader
                    try:
                        await asyncio.wait_for(proc.wait(), timeout=2.0)
                        self._detached.pop(pid, None)
                        return ToolResult(
                            success=True,
                            data={
                                "killed": True, "signal": "TERM",
                                "pid": pid, "exit_code": proc.returncode,
                            },
                        )
                    except asyncio.TimeoutError:
                        # grace expired — escalate the whole group to KILL
                        os.killpg(proc.pid, _signal.SIGKILL)
                        actual_signal = "KILL (after TERM grace)"
                else:
                    os.killpg(proc.pid, _signal.SIGKILL)
                    actual_signal = "KILL"
            except ProcessLookupError:
                self._detached.pop(pid, None)
                return ToolResult(
                    success=True,
                    data={"killed": False, "reason": "already exited", "pid": pid},
                )

            try:
                await asyncio.wait_for(proc.wait(), timeout=1.0)
                self._detached.pop(pid, None)
                return ToolResult(
                    success=True,
                    data={
                        "killed": True, "signal": actual_signal,
                        "pid": pid, "exit_code": proc.returncode,
                    },
                )
            except asyncio.TimeoutError:
                return ToolResult(
                    success=False,
                    error=f"pid {pid} still alive 1s after KILL (zombie or escaped?)",
                    error_class="config",
                )

        # --- Untracked path: fall back to os.killpg + polling ---
        # No proc handle to await on; can't use asyncio idioms cleanly.
        # This case is rare — caller has a PID from a previous server.
        # We still target the process group (assumes the original spawn used
        # start_new_session=True, which it did under run_cli_detached); if
        # the caller's PID isn't a group leader, killpg returns EPERM and
        # we fall back to os.kill on the bare PID as a best-effort.
        sig = _signal.SIGTERM if signal == "TERM" else _signal.SIGKILL
        try:
            os.killpg(pid, sig)
        except ProcessLookupError:
            return ToolResult(
                success=True, data={"killed": False, "reason": "already exited", "pid": pid}
            )
        except PermissionError:
            # killpg failed because pid isn't a process group leader.
            # Fall back to single-PID signal — won't cascade to children
            # but is better than nothing for untracked PIDs.
            try:
                os.kill(pid, sig)
            except ProcessLookupError:
                return ToolResult(
                    success=True, data={"killed": False, "reason": "already exited", "pid": pid}
                )
            except PermissionError as e:
                return ToolResult(
                    success=False, error=f"cannot signal pid {pid}: {e}", error_class="permission"
                )
        if signal == "TERM":
            for _ in range(20):  # 2s grace
                if not self._is_alive(pid):
                    return ToolResult(
                        success=True, data={"killed": True, "signal": "TERM", "pid": pid}
                    )
                await asyncio.sleep(0.1)
            try: os.killpg(pid, _signal.SIGKILL)
            except (ProcessLookupError, PermissionError):
                try: os.kill(pid, _signal.SIGKILL)
                except ProcessLookupError: pass
        for _ in range(10):  # 1s confirmation
            if not self._is_alive(pid):
                return ToolResult(
                    success=True, data={"killed": True, "signal": signal, "pid": pid}
                )
            await asyncio.sleep(0.1)
        return ToolResult(
            success=False,
            error=f"pid {pid} still alive after KILL (zombie or escaped?)",
            error_class="config",
        )

    async def _cleanup_detached(self) -> None:
        """Reap all tracked detached children AND their process groups.

        Called from run()'s finally block. Sends SIGTERM to every still-alive
        child's process group concurrently (same group-signaling logic as
        kill_detached — see that method's docstring for the why; bash-pipeline
        spawns have child processes that would orphan if we only signaled the
        leader). Waits up to 1s for graceful exits (shorter than kill_detached's
        2s — cleanup is a fire-drill), then SIGKILLs any holdouts' groups.
        Returns when all are reaped or kill has been issued.
        """
        if not self._detached:
            return
        procs = [
            m["proc"] for m in self._detached.values()
            if m.get("proc") is not None and m["proc"].returncode is None
        ]
        self.logger.info(
            f"cleanup_detached: reaping {len(procs)} tracked children "
            f"(of {len(self._detached)} tracked entries)"
        )

        # Send TERM to all process groups simultaneously
        for proc in procs:
            try: os.killpg(proc.pid, _signal.SIGTERM)
            except ProcessLookupError: pass

        # Wait up to 1s for graceful exits (in parallel)
        if procs:
            await asyncio.gather(
                *[asyncio.wait_for(p.wait(), timeout=1.0) for p in procs],
                return_exceptions=True,  # swallow TimeoutError; KILL holdouts next
            )

        # KILL any group whose leader is still alive
        for proc in procs:
            if proc.returncode is None:
                try: os.killpg(proc.pid, _signal.SIGKILL)
                except ProcessLookupError: pass

        self._detached.clear()

    async def _verify_clock(self) -> "ToolResult":
        """Return the container's current time and FAKETIME configuration.

        Only registered when MCP_TEST_MODE=1 is set.  Returns enough detail
        to verify that libfaketime is working (or not installed).
        """
        faketime_val = os.environ.get("FAKETIME", "")
        ld_preload_val = os.environ.get("LD_PRELOAD", "")

        # Check if the libfaketime .so actually exists on disk
        libfaketime_exists = False
        if ld_preload_val:
            libfaketime_exists = os.path.isfile(ld_preload_val)
        else:
            # Search common locations
            import glob as _glob
            hits = _glob.glob("/usr/lib/**/libfaketime.so.1", recursive=True)
            libfaketime_exists = len(hits) > 0

        return ToolResult(
            success=True,
            data={
                "current_time": datetime.datetime.now().isoformat(),
                "utc_time": datetime.datetime.utcnow().isoformat(),
                "faketime": faketime_val,
                "ld_preload": ld_preload_val,
                "libfaketime_exists": libfaketime_exists,
            },
        )

    def _classify_unhandled_error(self, returncode: int, output: str) -> tuple:
        """Fallback classifier for universal CLI error patterns.

        Checks the LAST line of output for Python exception class names.
        In a Python traceback, the exception is always on the very last
        line at column 0 (e.g., ``PermissionError: [Errno 13] ...``).
        Checking only the last line avoids false positives from scan
        output that mentions error class names in the middle.

        Returns (error_class, retryable).  Defaults to ("unknown", False).
        """
        if not output:
            return ("unknown", False)

        # Get the last non-empty line — where Python puts the exception class
        lines = output.strip().splitlines()
        last_line = (lines[-1].strip()) if lines else ""

        # Python tracebacks: exception class on the last line.
        # Use 'in' to handle module-prefixed forms like asyncio.TimeoutError,
        # OSError subclasses, etc. Safe because we only check the last line.
        if "PermissionError" in last_line:
            return ("permission", False)
        if "TimeoutError" in last_line:
            return ("timeout", True)
        if "ConnectionRefusedError" in last_line:
            return ("network", True)
        if "FileNotFoundError" in last_line:
            return ("config", False)

        # "Connection refused" at start of any line (system-level, not in scan output)
        if re.search(r"^Connection refused", output, re.MULTILINE):
            return ("network", True)

        return ("unknown", False)

    def register_method(
        self,
        name: str,
        description: str,
        params: Dict[str, Dict[str, Any]],
        handler: Callable,
    ) -> None:
        """
        Register a tool method.

        Args:
            name: Method name (e.g., "port_scan")
            description: Human-readable description
            params: Parameter definitions with types and descriptions
            handler: Async function to handle the method call
        """
        self.methods[name] = MethodDefinition(
            name=name,
            description=description,
            params=params,
            handler=handler,
        )
        self.logger.info(f"Registered method: {name}")

    def _build_input_schema(self, params: Dict[str, Dict[str, Any]]) -> Dict[str, Any]:
        """Build JSON schema from parameter definitions."""
        properties = {}
        required = []

        for param_name, param_def in params.items():
            param_type = param_def.get("type", "string")

            # Handle enum type - JSON Schema uses type: "string" with enum array
            if param_type == "enum":
                prop = {
                    "type": "string",
                    "description": param_def.get("description", ""),
                }
                # Support both "values" (our convention) and "enum" keys
                if "values" in param_def:
                    prop["enum"] = param_def["values"]
                elif "enum" in param_def:
                    prop["enum"] = param_def["enum"]
            else:
                prop = {
                    "type": param_type,
                    "description": param_def.get("description", ""),
                }
                if "enum" in param_def:
                    prop["enum"] = param_def["enum"]

            if "default" in param_def:
                prop["default"] = param_def["default"]
            if "items" in param_def:
                prop["items"] = param_def["items"]

            properties[param_name] = prop

            if param_def.get("required", False):
                required.append(param_name)

        return {
            "type": "object",
            "properties": properties,
            "required": required,
        }

    async def run_command(
        self,
        cmd: List[str],
        timeout: int = 300,
        check: bool = False,
        env: Optional[Dict[str, str]] = None,
    ) -> subprocess.CompletedProcess:
        """
        Run a shell command asynchronously.

        .. deprecated::
            Use :meth:`run_command_with_progress` instead.  It sends MCP
            heartbeat notifications that prevent client-side idle timeouts
            and supports ``timeout=None`` for unlimited duration.

        Args:
            cmd: Command and arguments as list
            timeout: Timeout in seconds
            check: Raise exception on non-zero exit
            env: Optional env vars to merge with os.environ for the subprocess

        Returns:
            CompletedProcess with stdout and stderr
        """
        self.logger.info(f"Running command: {' '.join(cmd)}")

        merged_env = {**os.environ, **env} if env else None

        try:
            proc = await asyncio.create_subprocess_exec(
                *cmd,
                env=merged_env,
                stdin=asyncio.subprocess.DEVNULL,
                stdout=asyncio.subprocess.PIPE,
                stderr=asyncio.subprocess.PIPE,
            )

            stdout, stderr = await asyncio.wait_for(
                proc.communicate(),
                timeout=timeout,
            )

            result = subprocess.CompletedProcess(
                args=cmd,
                returncode=proc.returncode or 0,
                stdout=stdout.decode("utf-8", errors="replace"),
                stderr=stderr.decode("utf-8", errors="replace"),
            )

            if check and result.returncode != 0:
                raise ToolError(
                    message=f"Command failed with exit code {result.returncode}",
                    details=result.stderr,
                )

            return result

        except asyncio.TimeoutError:
            try:
                proc.kill()
                await proc.wait()
            except ProcessLookupError:
                pass
            raise ToolError(
                message=f"Command timed out after {timeout} seconds",
                details=" ".join(cmd),
            )
        except asyncio.CancelledError:
            self.logger.info("Request cancelled, killing subprocess")
            try:
                proc.kill()
                await proc.wait()
            except ProcessLookupError:
                pass
            raise

    async def _read_remaining(self, proc, timeout: float = 3.0) -> str:
        """Drain stdout+stderr from a terminated process with a timeout.

        Use after proc.terminate()/kill() + wait() to safely collect any
        remaining output without risking an indefinite hang on broken pipes.
        """
        output = ""
        for stream in [proc.stdout, proc.stderr]:
            if stream is None:
                continue
            try:
                data = await asyncio.wait_for(stream.read(), timeout=timeout)
                output += data.decode("utf-8", errors="replace")
            except (asyncio.TimeoutError, Exception):
                pass
        return output

    async def send_progress(self, message: str, progress: float = 0.0, total: float | None = None) -> None:
        """Send an MCP progress notification if a progress token exists on the current request.

        Safe to call unconditionally — silently no-ops when there is no active
        request context or no progress token was provided by the client.
        """
        try:
            ctx = request_ctx.get()
        except LookupError:
            return
        if ctx.meta is None or ctx.meta.progressToken is None:
            return
        try:
            await ctx.session.send_progress_notification(
                progress_token=ctx.meta.progressToken,
                progress=progress,
                total=total,
                message=message,
            )
        except Exception:
            self.logger.debug("Failed to send progress notification", exc_info=True)

    async def run_command_with_progress(
        self,
        cmd: List[str],
        timeout: int | None = None,
        check: bool = False,
        progress_filter: Callable[[str], str | None] | None = None,
        heartbeat_interval: float = 30.0,
        env: Optional[Dict[str, str]] = None,
        stdin_data: str | bytes | None = None,
    ) -> subprocess.CompletedProcess:
        """Run a command while streaming progress notifications from its output.

        Dual-clock contract:
          * **Hard cap** (this method) — ``timeout`` seconds wall-clock from
            start to finish. Never resets. Catches a hung subprocess that fools
            the heartbeat.
          * **Idle clock** (client-side) — driven by the heartbeat notifications
            this method emits every *heartbeat_interval* seconds. The MCP client
            resets its own idle timer on each heartbeat. Catches a dead server.

        Both work together. If the subprocess wedges but the asyncio event loop
        is healthy, heartbeats keep flowing and the client's idle clock won't
        fire — but the server-side ``timeout`` will, and we kill the subprocess.

        Args:
            cmd: Command and arguments as list.
            timeout: Hard wall-clock cap in seconds, or ``None`` for unlimited.
                For untrusted/long-running tools, set this generously (3600+);
                the heartbeat-driven idle clock is the first line of defense.
            check: Raise ``ToolError`` on non-zero exit code.
            progress_filter: ``(line) -> message | None``.  Return a short
                string to emit as a progress notification, or ``None`` to skip.
            heartbeat_interval: Seconds between automatic "Still running…"
                heartbeat notifications. Drives the client's idle clock; must be
                less than the client's idle_timeout (typically idle/2 or less).
            env: Optional env vars to merge with os.environ for the subprocess.
            stdin_data: Optional bytes/str to feed to the subprocess via stdin.
                When ``None``, stdin is closed (DEVNULL). Tools like ``john
                --stdin`` and ``hashcat`` need this.

        Returns:
            ``subprocess.CompletedProcess`` with full accumulated stdout/stderr
            (same interface as ``run_command``).
        """
        self.logger.info(f"Running (with progress): {' '.join(cmd)}")

        merged_env = {**os.environ, **env} if env else None

        # If caller provided stdin_data we open a pipe; otherwise close stdin.
        stdin_mode = (
            asyncio.subprocess.PIPE
            if stdin_data is not None
            else asyncio.subprocess.DEVNULL
        )

        proc = await asyncio.create_subprocess_exec(
            *cmd,
            env=merged_env,
            stdin=stdin_mode,
            stdout=asyncio.subprocess.PIPE,
            stderr=asyncio.subprocess.PIPE,
        )

        # Feed stdin (if any) and close so the subprocess sees EOF.
        if stdin_data is not None and proc.stdin is not None:
            payload = (
                stdin_data.encode("utf-8")
                if isinstance(stdin_data, str)
                else stdin_data
            )
            try:
                proc.stdin.write(payload)
                await proc.stdin.drain()
            finally:
                try:
                    proc.stdin.close()
                except Exception:
                    pass

        stdout_buf: list[str] = []
        stderr_buf: list[str] = []
        progress_count = 0

        async def _read_stream(stream: asyncio.StreamReader, buf: list[str]) -> None:
            """Read lines from a stream, sending progress_filter matches as status."""
            nonlocal progress_count
            while True:
                line_bytes = await stream.readline()
                if not line_bytes:
                    break
                line = line_bytes.decode("utf-8", errors="replace")
                buf.append(line)

                # progress_filter is for meaningful status messages, NOT heartbeating
                if progress_filter is not None:
                    msg = progress_filter(line)
                    if msg is not None:
                        progress_count += 1
                        await self.send_progress(msg, progress=float(progress_count))

        async def _heartbeat_loop() -> None:
            """Send heartbeats on a timer, independent of tool output."""
            nonlocal progress_count
            while True:
                await asyncio.sleep(heartbeat_interval)
                progress_count += 1
                await self.send_progress("Still running\u2026", progress=float(progress_count))

        heartbeat_task = asyncio.create_task(_heartbeat_loop())
        try:
            gather_coro = asyncio.gather(
                _read_stream(proc.stdout, stdout_buf),
                _read_stream(proc.stderr, stderr_buf),
            )
            if timeout is not None:
                await asyncio.wait_for(gather_coro, timeout=timeout)
            else:
                await gather_coro
            await proc.wait()
        except asyncio.TimeoutError:
            try:
                proc.kill()
                await proc.wait()
            except ProcessLookupError:
                pass
            raise ToolError(
                message=f"Command timed out after {timeout} seconds",
                details=" ".join(cmd),
            )
        except asyncio.CancelledError:
            self.logger.info("Request cancelled, killing subprocess")
            try:
                proc.kill()
                await proc.wait()
            except ProcessLookupError:
                pass
            raise
        finally:
            heartbeat_task.cancel()
            try:
                await heartbeat_task
            except asyncio.CancelledError:
                pass

        result = subprocess.CompletedProcess(
            args=cmd,
            returncode=proc.returncode or 0,
            stdout="".join(stdout_buf),
            stderr="".join(stderr_buf),
        )

        if check and result.returncode != 0:
            raise ToolError(
                message=f"Command failed with exit code {result.returncode}",
                details=result.stderr,
            )

        return result

    async def _handle_tool_call(self, name: str, arguments: Dict[str, Any]) -> CallToolResult:
        """Handle an incoming tool call."""
        if name not in self.methods:
            available_methods = list(self.methods.keys())
            error_msg = f"Unknown method: '{name}'\n\nAvailable methods for {self.name}:\n"
            for method_name in available_methods:
                method = self.methods[method_name]
                error_msg += f"  - {method_name}: {method.description}\n"
            error_msg += f"\nUse tool_registry_search to find the correct method name."
            return CallToolResult(
                content=[TextContent(type="text", text=error_msg)],
                isError=True,
            )

        method = self.methods[name]

        # --- Meta-parameter stripping ---
        # Strip known meta-params that the client sometimes passes inside args
        # by mistake, but ONLY if the method doesn't declare them as real params.
        arguments = dict(arguments)  # shallow copy to avoid mutating caller's dict
        for meta in self.META_PARAMS:
            if meta in arguments and meta not in method.params:
                self.logger.debug(f"Stripped meta-param '{meta}' from {name} call")
                del arguments[meta]

        # --- Unknown parameter stripping ---
        # Strip params not declared by the method to prevent **kwargs crashes.
        # LLMs sometimes pass params meant for other methods (e.g., 'scripts'
        # on service_scan when it belongs to vuln_scan). Log a warning so the
        # issue is visible, but don't crash.
        unknown = set(arguments.keys()) - set(method.params.keys())
        if unknown:
            self.logger.warning(
                f"Stripped unknown params for {name}: {unknown}. "
                f"Valid: {list(method.params.keys())}"
            )
            for key in unknown:
                del arguments[key]

        self.logger.info(f"Handling call to {name} with args: {arguments}")

        try:
            result = await method.handler(**arguments)

            if isinstance(result, ToolResult):
                # --- Fallback error classification ---
                if not result.success and result.error_class is None:
                    error_class, retryable = self._classify_unhandled_error(
                        0, result.raw_output
                    )
                    result.error_class = error_class
                    result.retryable = retryable

                return CallToolResult(
                    content=result.to_content(),
                    isError=not result.success,
                    structuredContent={
                        "success": result.success,
                        "error": result.error,
                        "error_class": result.error_class,
                        "retryable": result.retryable,
                        "suggestions": result.suggestions,
                        "data": result.data,
                    },
                )
            else:
                # Assume raw dict/string response
                return CallToolResult(
                    content=[TextContent(type="text", text=json.dumps(result, indent=2) if isinstance(result, dict) else str(result))],
                    isError=False,
                    structuredContent={
                        "success": True,
                        "error_class": None,
                        "retryable": False,
                        "suggestions": [],
                        "data": result if isinstance(result, dict) else {"raw": str(result)},
                    },
                )

        except ToolError as e:
            self.logger.error(f"Tool error in {name}: {e}")
            error_class, retryable = self._classify_unhandled_error(
                0, e.details or ""
            )
            return CallToolResult(
                content=[TextContent(type="text", text=str(e))],
                isError=True,
                structuredContent={
                    "success": False,
                    "error_class": error_class,
                    "retryable": retryable,
                    "suggestions": [],
                    "data": {},
                },
            )
        except Exception as e:
            self.logger.exception(f"Unexpected error in {name}")
            return CallToolResult(
                content=[TextContent(type="text", text=f"Internal error: {str(e)}")],
                isError=True,
                structuredContent={
                    "success": False,
                    "error_class": "unknown",
                    "retryable": False,
                    "suggestions": [],
                    "data": {},
                },
            )

    def _get_tools(self) -> List[Tool]:
        """Get list of available tools for MCP."""
        tools = []
        for method in self.methods.values():
            tools.append(Tool(
                name=method.name,
                description=method.description,
                inputSchema=self._build_input_schema(method.params),
            ))
        return tools

    async def run(self) -> None:
        """Start the MCP server."""
        self._server = Server(self.name, version=self.version)

        @self._server.list_tools()
        async def list_tools() -> List[Tool]:
            return self._get_tools()

        @self._server.call_tool()
        async def call_tool(name: str, arguments: Dict[str, Any]) -> CallToolResult:
            return await self._handle_tool_call(name, arguments)

        self.logger.info(f"Starting {self.name} MCP server v{self.version}")

        try:
            async with stdio_server() as (read_stream, write_stream):
                await self._server.run(
                    read_stream,
                    write_stream,
                    self._server.create_initialization_options(),
                )
        finally:
            # Reap tracked detached children on clean exits (stdio closed
            # by client; programmatic stop). On the docker-stop path,
            # SIGTERM kills this Python process before finally can run
            # without a signal handler — but the container teardown that
            # follows reaps detached children as siblings under PID 1
            # directly, so they don't leak. This hook is therefore the
            # narrower case of "the server stopped but the container
            # survives." Adding a SIGTERM handler to extend coverage is
            # possible but not needed given the docker teardown path.
            await self._cleanup_detached()

    @classmethod
    def main(cls) -> None:
        """Entry point for running the server."""
        server = cls()
        asyncio.run(server.run())
