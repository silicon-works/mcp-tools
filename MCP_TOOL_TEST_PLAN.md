# MCP Tool Test Plan

## Purpose

The MCP tool servers are not battle-tested. Real engagements consistently surface failures: wrong parameter names, missing methods in tool.yaml, silent clock offset failures, unhelpful error messages, and output parsing that misses critical data. This plan defines a systematic process to test every tool, one at a time, thoroughly.

## Opensploit-Side Tests (NOTED, NOT IN SCOPE)

These are opensploit bugs, not mcp-tools bugs. They should be fixed separately in the opensploit repo:

1. **OOM orphaned container cleanup** — `packages/opencode/src/container/manager.ts` needs startup cleanup of containers from crashed sessions. Add `--label opensploit=true` at container creation, `docker rm -f $(docker ps -q --filter label=opensploit)` on init.
2. **SIGTERM/SIGINT signal handlers** — `packages/opencode/src/index.ts` lines 40-50 have error handlers but no signal handlers. Add `process.on('SIGTERM', ...)` calling `ContainerManager.stopAll()`.
3. **Log rotation** — `packages/opencode/src/util/log.ts` line 68 truncates `dev.log` on startup. Should rotate to `dev.log.1` instead.
4. **Hardcoded libfaketime path** — `packages/opencode/src/container/manager.ts` lines 313-317 hardcode `/usr/lib/x86_64-linux-gnu/faketime/libfaketime.so.1`. Should only pass `FAKETIME` env var; containers discover their own path via entrypoint.sh.
5. **MCP Tasks for async tool execution** — MCP spec 2025-11-25 adds Tasks (experimental): call-now, fetch-later pattern. Server returns immediately with taskId, client polls for results, LLM isn't blocked. Both SDKs support it (TS v1.25.2 `client.experimental.tasks.*`, Python v1.26.0). Requires `manager.ts` to use `requestStream()` instead of `callTool()`. Eliminates the two-timeout problem entirely. This is the correct long-term architecture for tools >60s.

---

## Shared Infrastructure (Build First)

Before any per-tool testing, these shared pieces must exist:

### 1. conftest.py — Shared Test Fixtures

Location: `tests/conftest.py`

Provides:
- `MCPTestClient` — wraps `mcp-client.py` logic as a pytest fixture. Starts a container, connects via MCP stdio, provides `call(method, args)` and `list_tools()`.
- `@pytest.fixture(scope="module")` for container lifecycle — each test FILE gets its own container. Not session-scoped (one bad test would kill all subsequent tests). Not function-scoped (too slow, container startup per test).
- `--tool` CLI arg for targeting a specific tool.
- `--target`, `--domain`, `--username`, `--password` CLI args for integration tests.
- Timeout configuration per test.
- Helpers: `assert_tool_result_success(result)`, `assert_error_has_category(result, category)`, `parse_tool_output(result)`.

### 2. entrypoint.sh — Dynamic Faketime Discovery

Single source file at `packages/mcp-common/entrypoint.sh`. Dockerfiles reference it via the repo-root build context.

```bash
#!/bin/sh
if [ -n "$FAKETIME" ]; then
  FAKETIME_LIB=$(find /usr/lib -name "libfaketime.so.1" 2>/dev/null | head -1)
  if [ -n "$FAKETIME_LIB" ]; then
    export LD_PRELOAD="$FAKETIME_LIB"
    export FAKETIME_DONT_FAKE_MONOTONIC=1
  else
    # CRITICAL: unset LD_PRELOAD to clear any stale value the container manager may have set
    # via docker run -e. Without this, a wrong hardcoded path silently fails.
    unset LD_PRELOAD
    echo "FAKETIME_ERROR: FAKETIME=$FAKETIME but libfaketime.so.1 not found" >&2
  fi
fi
exec python3 mcp-server.py
```

Only add entrypoint.sh to Dockerfiles that install libfaketime. Tools without it keep `CMD ["python3", "mcp-server.py"]`.
Currently need entrypoint.sh: impacket, certipy, bloodyad, evil-winrm, netexec, enum4linux-ng, bloodhound.
Currently missing libfaketime (must add): kerbrute (Kerberos tool, needs it).

Every Dockerfile that installs libfaketime gets:
```dockerfile
COPY packages/mcp-common/entrypoint.sh /app/entrypoint.sh
RUN chmod +x /app/entrypoint.sh
CMD ["/app/entrypoint.sh"]
```

Note: build context is repo root (not tool dir), so the COPY path is `packages/mcp-common/entrypoint.sh`.

### 3. BaseMCPServer Changes

#### a. Unknown parameter warning + meta-parameter stripping

In `_handle_tool_call`, before calling the handler:

1. **Strip known meta-parameters** that the opensploit client should have extracted but the agent sometimes puts inside `args` by mistake. These cause `got an unexpected keyword argument` crashes (confirmed in 48 engagements: nmap, evil-winrm, netexec all affected).

**Only strip if the method doesn't expect the parameter.** Some tools have `timeout` as a legitimate registered param (nmap, hydra, etc.). Stripping unconditionally would break them.
```python
META_PARAMS = {"timeout", "clock_offset"}
for meta in META_PARAMS:
    if meta in arguments and meta not in method.params:
        del arguments[meta]
```

2. **Warn about remaining unknown params** but do NOT reject the call:
```python
unknown = set(cleaned.keys()) - set(method.params.keys())
if unknown:
    self.logger.warning(f"Unknown params for {name}: {unknown}. Valid: {list(method.params.keys())}")
    # Still call the handler — let it decide whether to fail
```

Why warn not reject: dynamic recipes may have incomplete param definitions, and some handlers accept **kwargs for forward-compatibility.

#### b. Fix run_command_with_progress() heartbeat to be output-independent

The current `run_command_with_progress()` only sends heartbeats when the tool produces output (the heartbeat check is inside the `_read_stream` loop, which blocks on `stream.readline()`). If a tool goes silent during a long operation (nmap during host discovery, sqlmap testing blind injection), no heartbeats are sent, and the client timeout fires anyway.

Fix: add an independent heartbeat asyncio task that runs concurrently:
```python
async def _heartbeat_task():
    """Send heartbeats on a timer, independent of tool output."""
    nonlocal progress_count
    while True:
        await asyncio.sleep(heartbeat_interval)
        progress_count += 1
        await self.send_progress("Still running...", progress=float(progress_count))

heartbeat = asyncio.create_task(_heartbeat_task())
try:
    await asyncio.wait_for(asyncio.gather(...), timeout=timeout)
finally:
    heartbeat.cancel()
```

This ensures the client timeout resets every 30s regardless of tool output. The server-side timeout becomes the single source of truth.

Remove the existing output-based heartbeat logic from `_read_stream`. The independent timer is the only heartbeat. The `progress_filter` callback still fires on output lines to send meaningful progress messages (e.g., "Found port 22 open"), but that's status reporting, not heartbeating. One timer, one job.

#### c. verify_clock method (test-only, NOT in tool list)

Add `_verify_clock()` as a method on BaseMCPServer but do NOT register it via `register_method()`. It should not appear in `list_tools` or the tool registry — 72 copies of verify_clock would pollute RAG search results and confuse the agent.

Instead, register it only when an environment variable is set (e.g., `MCP_TEST_MODE=1`):
```python
if os.environ.get("MCP_TEST_MODE"):
    self.register_method(
        name="verify_clock",
        description="Return container's current time and FAKETIME status",
        params={},
        handler=self._verify_clock,
    )
```

The test harness sets `MCP_TEST_MODE=1` when starting containers. Production containers don't have it.

Returns: current datetime, FAKETIME env var value, LD_PRELOAD value, whether libfaketime .so exists.

#### d. Error classification via ToolResult + structuredContent

**Verified**: MCP SDK 1.26.0 supports `structuredContent` on `CallToolResult` (confirmed in signature). This is the spec-compliant way to return machine-readable error data alongside LLM-readable text.

**No YAML config files. No regex pattern tables. No central error catalog.**

**How it works:**

1. Add fields to `ToolResult` dataclass:
```python
@dataclass
class ToolResult:
    success: bool
    data: Dict[str, Any] = field(default_factory=dict)
    raw_output: str = ""
    error: Optional[str] = None
    error_class: Optional[str] = None      # "timeout" | "auth" | "network" | "permission" | "config" | "params" | "unknown"
    retryable: bool = False
    suggestions: List[str] = field(default_factory=list)
```

2. Tool handlers set these fields explicitly when returning errors. The tool author knows what the error means — they wrote the wrapper:
```python
# In impacket server, get_tgt handler:
if "KRB_AP_ERR_SKEW" in stderr:
    return ToolResult(
        success=False,
        error="Clock skew too great for Kerberos authentication",
        error_class="config",
        retryable=True,
        suggestions=["Set clock_offset parameter to match target DC time"],
        raw_output=stderr,
    )
```

3. Update `ToolResult.to_content()` to include classification in the LLM-readable text:
```python
def to_content(self) -> List[TextContent]:
    if self.success:
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
```

4. BaseMCPServer._handle_tool_call() maps ToolResult to CallToolResult with structuredContent on BOTH success and error:
```python
return CallToolResult(
    content=result.to_content(),       # LLM reads this text (includes suggestions)
    structuredContent={                  # Client reads this programmatically
        "success": result.success,
        "error_class": result.error_class,
        "retryable": result.retryable,
        "suggestions": result.suggestions,
        **result.data,
    },
    isError=not result.success,
)
```

This way: the LLM gets suggestions in the text immediately. The opensploit client gets structured data for Feature 31 (loop detection, circuit breakers) when mcp-tool.ts is updated later.

5. BaseMCPServer has a thin fallback for unclassified errors (tools that haven't been updated yet):
```python
def _classify_unhandled_error(self, returncode, stderr):
    """Fallback for universal CLI error patterns. NOT per-tool regex.
    ONLY checks stderr (not stdout) to avoid misclassifying scan output.
    ONLY matches unambiguous system-level patterns, not strings that
    could appear in target scan results."""
    # Very conservative — ~5 patterns max:
    # Python traceback with specific exception types (PermissionError, TimeoutError)
    # "Connection refused" at start of line (system-level, not in scan output)
    # asyncio.TimeoutError (our own timeout)
    return error_class, retryable
```

**Risk mitigation:** The fallback only checks stderr, never stdout. It only matches patterns that are unambiguously system-level (Python tracebacks, connection-level errors). It does NOT match substrings like "permission denied" or "access denied" that could appear in scan results describing the TARGET's state. Better to return "unknown" than to misclassify.

**Why this approach:**
- Tool author classifies at the source — they have the context (which method, which flags, what exit code means)
- No fragile regex config files that drift from tool versions
- The tool handler IS coupled to the tool binary (same Docker image) — so classification stays in sync
- structuredContent is MCP-spec-compliant, read by opensploit client for circuit breakers / loop detection (Feature 31)
- Backward compatible — existing tools return error_class="unknown" via fallback
- Sub-agents update handlers during the per-tool testing pass

### 4. Test Runner Script

Location: `scripts/test-tool.sh`

Simple wrapper that:
1. Builds the tool's Docker image locally
2. Runs pytest for that specific tool
3. Reports results

```bash
#!/bin/sh
# Run from repo root — Dockerfiles COPY packages/mcp-common/ which requires repo root as build context
TOOL=$1
REBUILD=${2:-""}
if [ -z "$TOOL" ]; then echo "Usage: $0 <tool-name> [--rebuild]"; exit 1; fi
cd "$(dirname "$0")/.."

# Only build if image doesn't exist or --rebuild flag passed
IMAGE="mcp-test-$TOOL"
if [ "$REBUILD" = "--rebuild" ] || ! docker image inspect "$IMAGE" >/dev/null 2>&1; then
  echo "Building $TOOL..."
  docker build -t "$IMAGE" -f "tools/$TOOL/Dockerfile" . || exit 1
else
  echo "Image $IMAGE exists, skipping build (use --rebuild to force)"
fi

pytest tests/ -k "$TOOL or smoke" --tool="$TOOL" -v
```

---

## Per-Tool Test Process

Each tool gets its own sub-agent. The sub-agent follows this process in order, taking its time at each step.

### Step 1: Research (Read, Don't Write)

**Read the tool's implementation:**
- `tools/<tool>/mcp-server.py` — every line. Understand all methods, parameters, error handling, output parsing, state management.
- `tools/<tool>/tool.yaml` — every method definition. Compare parameter names, types, required flags against server.py.
- `tools/<tool>/Dockerfile` — what's installed, what version, whether libfaketime is present.
- `tools/<tool>/requirements.txt` — Python dependencies.

**Read the tool's help output:**
- Run `docker run --rm <image> <tool-binary> --help` (or `-h`, `man`)
- Compare exposed flags against what the MCP server wraps
- Note any flags the server doesn't expose that seem important
- Note any flags the server exposes that don't exist in the tool

**Read historical engagement data:**
- Search trajectory files in BOTH locations for MCP tool calls:
  - `../opensploit-vault/raw/ses_*/trajectory.jsonl` (17 vault sessions)
  - `~/.opensploit/sessions/ses_*/trajectory.jsonl` (31+ local sessions — has more recent data including Garfield)
- Trajectory event format for tool calls:
  ```json
  {
    "type": "tool",
    "tool": "mcp_tool",
    "toolInput": {"tool": "<tool-name>", "method": "<method>", "args": {...}},
    "toolOutput": "<string — the raw result>",
    "toolSuccess": true/false,
    "toolDuration": 12345,
    "agentName": "master|recon|enum|...",
    "timestamp": "2026-03-16T01:05:35Z"
  }
  ```
- Filter: `e["type"] == "tool" and e["tool"] == "mcp_tool" and e["toolInput"]["tool"] == "<this-tool>"`
- Extract: every method called, every set of arguments used, every output received, every error hit
- Look for patterns: what methods are used most, what errors come up, what parameter values are common
- Save extracted examples as test fixtures in `tests/fixtures/<tool>/`

**Read requirements docs:**
- Check `../opensploit-vault/requirements/` for any docs mentioning this tool
- Note any bug fixes, known issues, or test scenarios already specified

### Step 2: Identify Issues

Based on research, document:

1. **Contract mismatches** — methods in server.py but not tool.yaml (or vice versa)
2. **Parameter mismatches** — param names in tool.yaml that differ from server.py, or from the tool's actual `--help` flags
3. **Missing error handling** — methods that just check `returncode == 0` without parsing stderr
4. **Output parsing gaps** — output formats the parser doesn't handle
5. **Missing parameters** — important tool flags not exposed as MCP parameters
6. **Clock offset** — whether the tool needs it (Kerberos), whether libfaketime is installed
7. **Progress heartbeat gaps** — check whether any method typically runs >60s. If yes, it MUST use `run_command_with_progress()` instead of `run_command()`. The client already has `resetTimeoutOnProgress: true` — heartbeats reset the client timer every 30s, making the server timeout the single source of truth. No need to manually align client/server timeouts — just send heartbeats.
   - Data from 48 engagements: 11.5% overall timeout rate (1,407/12,198 calls). Top offenders: ffuf.dir_fuzz 71.4%, nmap.port_scan 31.4%, hydra.ssh_brute 47.4%.
   - `run_command_with_progress()` already exists in BaseMCPServer (line 277). It sends "Still running..." heartbeats every 30s by default. Almost no tools use it.
   - Optionally add a `progress_filter` function to extract meaningful status (e.g., nmap completion %, hydra attempts count) instead of generic heartbeats.
   - **Long-term (out of scope for this plan):** MCP Tasks (spec 2025-11-25, experimental) is the correct architecture for async tool execution. Both SDKs support it (TS v1.25.2, Python v1.26.0). Requires opensploit client changes (manager.ts → requestStream()). Log as future opensploit feature.

### Step 3: Write Smoke Tests

Tests that don't need a target. Goes in `tests/tools/test_<tool>.py`.

- **Boot test** — container starts, `list_tools` returns expected methods
- **Method list matches tool.yaml** — every method in tool.yaml exists, every method in server has a tool.yaml entry
- **Required params enforced** — call a method missing a required param, expect clear error
- **Meta-params stripped** — call a method that does NOT have `timeout` in its registered params, pass `timeout` in args anyway, expect no crash (stripped silently)
- **Clock verification** (if libfaketime installed) — start with `FAKETIME=+5h`, call `verify_clock`, confirm shift

### Step 4: Write Unit Tests

Tests for output parsing and error classification. Still no target needed.

- **Output parser tests** — feed recorded output from step 1 fixtures through the parser, verify structured data extraction
- **Error classification tests** — feed recorded error output, verify `error_info` has correct category
- **Edge cases** — empty output, malformed output, partial output (timeout mid-stream)

### Step 5: Write Integration Scenarios

Scenarios that need a target. Goes in `tests/tools/test_<tool>.py` or `tests/tools/scenarios/<tool>.yaml`, marked with `@pytest.mark.integration`.

These are parameterized by `--target`, `--domain`, etc. They can run against:
- A mock environment (Samba DC, test web app) in CI
- A real HTB box manually

Scenarios come from:
- Historical engagement data (step 1)
- Requirements doc test tables (Features 24, 27, 28, 30)
- The tool's own capabilities that haven't been tested

### Step 6: Fix Issues

Based on findings from steps 2-5:
- Fix tool.yaml mismatches (missing methods, wrong param names/types)
- Add error classification to tool handlers (error_class, retryable, suggestions on ToolResult returns)
- Fix output parsing gaps
- Add entrypoint.sh if libfaketime is needed but not wired up (Dockerfile change)
- **Switch long-running methods to `run_command_with_progress()`** — any method where typical execution exceeds 60s. Heartbeats reset the client timer, eliminating the two-timeout problem. Key targets: nmap.port_scan, nmap.vuln_scan, ffuf.dir_fuzz, hydra.*, john.crack, sqlmap.test_injection. Optionally add `progress_filter` for meaningful status messages.
- Fix any other bugs found

### Step 7: Run Tests and Verify

- Run all tests for this tool
- Fix any failures
- Confirm all tests pass

---

## Tool Priority Order

Based on engagement usage data (17 HTB engagements), complexity, and known failure frequency.

### Tier 1: High-Usage + Known Failures (AD/Kerberos Tools)

These failed on Garfield and other AD engagements. Fix first.

| # | Tool | Calls | Engagements | Server Lines | Known Issues |
|---|------|-------|-------------|-------------|--------------|
| 1 | impacket | 116 | 5 | 2563 | Clock offset, 1 method missing from tool.yaml, parameter mismatches, Garfield blocker |
| 2 | certipy | 52 | 3 | 1524 | Clock offset, 1 method missing from tool.yaml, ESC detection |
| 3 | bloodyad | 96 | 3 (local) | 1184 | 21.9% error rate in Garfield sessions. ACL error handling, 25 methods with minimal error parsing |
| 4 | kerbrute | 28 | 2 | 468 | No libfaketime in Dockerfile, parameter name mismatch (passwords vs passlist) |
| 5 | netexec | 759 | 7 | 1207 | 1 method missing from tool.yaml, heavy AD usage |
| 6 | evil-winrm | 539 | 6 | 248 | Session lifecycle issues, "Not connected" errors (28 failures in raw data) |
| 7 | impacket-relay | 25 | 1 | 457 | Stuck state, process death handling, Pirate engagement had 1 recorded failure |
| 8 | responder | 2 | 2 | 659 | tool.yaml had 3 methods (fixed?), SMB capture reliability |
| 9 | bloodhound | 1 | 1 | 460 | Barely used, needs validation |
| 10 | enum4linux-ng | 5 | 3 | 509 | Light usage, basic validation |

### Tier 2: High-Usage General Tools

These are used in almost every engagement. They mostly work but haven't been systematically tested.

| # | Tool | Calls | Engagements | Server Lines |
|---|------|-------|-------------|-------------|
| 11 | nmap | **done** 78 tests, 3 fixtures. Fixed: no heartbeat (root cause 35% timeout), timeout too low, vuln_scan mismatch, no error classification, no -v. 74 pass, 4 skip. |
| 12 | curl | **done** 104 tests, 2 fixtures. All 5 methods covered. Error classification added. 103 pass, 1 skip. No regressions. |
| 13 | ssh | **done** 75 tests, 3 fixtures. All 7 methods. Error classification, proc.wait() zombie fix, timeout recovery verified. "Not connected" cascade is client-side. 73 pass, 2 skip. |
| 14 | exploit-runner | **done** 108 tests, 1 fixture. CRITICAL: process group kill (child processes survived timeout), no heartbeat, no stdin=DEVNULL. Template success detection broken. All fixed. 108 pass. |
| 15 | shell-session | **done** 67 tests. CRITICAL: paramiko blocking asyncio event loop (root cause 62% timeout). "Error: None" bug on 80% of exec errors. Thread executor fix + 8 issues resolved. 67 pass. |
| 16 | netcat | **done** 87 tests. All 16 methods. 100% engagement success rate. datetime deprecation fix. 87 pass. |
| 17 | metasploit | **migrated May 2026** — Python wrapper retired in favor of Rapid7's official `msfmcpd` (kind:mcp). 8-test smoke suite covers the upstream-canonical tool surface (msf_search_modules, msf_module_info, msf_host_info, msf_service_info, msf_vulnerability_info, msf_note_info, msf_credential_info, msf_loot_info). Wrapper preserved at commit ad330f9 in case migration reverses. |
| 18 | ffuf | **done** 48 tests, 3 fixtures. CRITICAL: silent mode + no heartbeat = 71.4% timeout (fixed). Error classification added. Feature 28 params already correct. 48 pass. |
| 19 | hydra | **done** 61 tests, 12 fixtures. HTTPS→HTTP downgrade bug, empty password regex, heartbeat fix for 47.4% timeout. All 5 methods. 61 pass. |
| 20 | sqlmap | **done** 127 tests, 20 fixtures. P0: false positive vuln detection. P1: os_shell drops all output. Error classifier added. Heartbeat was already correct. 126 pass, 1 skip. |

### Tier 3: Medium-Usage Specialist Tools

| # | Tool | Calls | Engagements | Server Lines |
|---|------|-------|-------------|-------------|
| 21 | john | 55 | 8 | 420 |
| 22 | hashcat | 39 | 3 | 682 |
| 23 | web-fingerprint | 52 | 11 | 676 |
| 24 | scapy | 45 | 10 | 829 |
| 26 | tunnel | 60 | 5 | 420 |
| 27 | searchsploit | 35 | 12 | 291 |
| 28 | cve-lookup | 25 | 9 | 496 |
| 29 | hash-lookup | 11 | 5 | 427 |

### Tier 4: Low/No-Usage Tools

29 tools that have never been used in a real engagement. These still need smoke tests but lower priority.

amass, aws, cloudfox, dns, embedding, forensics, git-dumper, ike-scan, ilspy, mongodb, mssql, mysql, nikto, pacu, phpggc, prowler, pygpoabuse, s3scanner, smtp, snmp, sqlite, ssrfmap, ssti, theharvester, trivy, trufflehog, volatility, wpscan, ysoserial

Note: chisel (5 calls, Pirate), ftp (1 call, WingData), nuclei (2 calls, Cobblestone+Facts), zap (3 calls, Facts) have minimal real usage — they belong in Tier 3.

### Cross-Tool Integration Tests

Some scenarios span multiple tools (Feature 27 verified these):
- impacket.get_tgt → bloodyad (ccache sharing via /session/credentials/)
- impacket.get_tgt → bloodhound (ccache sharing)
- impacket.get_tgt → netexec (ccache sharing)
- certipy.authenticate → impacket (PFX → ccache → further attacks)

These tests are written during the SECOND tool's sub-agent run (e.g., bloodyad sub-agent writes the impacket→bloodyad ccache test). The first tool just needs to produce the artifact.

---

## Orchestration: How Sub-Agents Are Managed

### One Tool, One Agent, Sequential

The orchestrating agent (me) spawns **one sub-agent at a time**. Each sub-agent:
- Uses **opus** model (mandatory — no lighter models for real work)
- Works in the `../mcp-tools` working directory
- Receives a self-contained prompt with everything it needs
- Handles exactly one tool, steps 1-7
- Returns a structured report when done
- **Minimum time: 20 minutes per tool.** This is a thoroughness exercise, not a speed exercise. Complex tools (impacket, certipy, netexec) should take 30-60 minutes. If a sub-agent finishes in under 20 minutes, it didn't do the work properly.

### What happens if Docker build fails

Some tools pull external binaries (kerbrute downloads from GitHub, aws forks awslabs). If the Docker build fails due to network issues, missing repos, or version changes:
1. Document the failure in the report
2. Note what broke and why
3. Skip steps that require a running container (smoke tests, clock tests)
4. Still do steps that don't (contract validation, tool.yaml audit, trajectory analysis, fixture extraction)
5. Move on to the next tool — don't get stuck

### Sub-Agent Prompt Template

Each sub-agent receives:
1. The tool name and which tier it belongs to
2. Paths to: mcp-server.py, tool.yaml, Dockerfile, any existing tests
3. Paths to: raw engagement trajectories that used this tool (specific session IDs)
4. Paths to: relevant requirements docs
5. The shared infrastructure that's already in place (conftest.py, BaseMCPServer changes)
6. Explicit instructions: follow steps 1-7 in order, take your time, read everything first
7. The trajectory JSON format (documented above in step 1) so it can extract fixtures without guessing

### Sub-Agent Report Format

Each sub-agent returns a structured report:
```
## Tool: <name>
### Research Summary
- Server lines read: X
- Methods found: [list]
- Engagement data: X calls across Y engagements
- Issues identified: [list]

### Tests Created
- tests/tools/test_<tool>.py — X smoke, Y unit, Z integration tests
- tests/fixtures/<tool>/ — N fixture files extracted from trajectories

### Issues Found
1. [description] — severity, fixed/unfixed

### Issues Fixed
1. [description] — what was changed, in which file

### Test Results
- X passed, Y failed, Z skipped
- Failures: [details]

### Open Items
- [anything that couldn't be resolved]

### Time Spent
- Research: Xm, Tests: Ym, Fixes: Zm, Total: Nm
```

### Orchestrator Tracking

After each sub-agent completes, the orchestrator:
1. Reviews the report
2. Records: tests created, issues found, issues fixed, tests passing/failing
3. Updates this plan with status
4. Spawns the next tool's sub-agent

### Progress Table

| # | Tool | Status | Tests Created | Issues Found | Issues Fixed |
|---|------|--------|--------------|--------------|-------------|
| 0 | shared-infra | **done** | conftest.py, entrypoint.sh, pytest.ini, test-tool.sh | BaseMCPServer: heartbeat, meta-param strip, error classification, verify_clock | All 5 verification checks passed |
| 1 | impacket | **done** | 70 tests (all 20 methods covered), 34 fixtures | 8+10 issues. Parser bugs, entrypoint, error classification, heartbeats, all coverage gaps filled | 54 pass, 16 skip (integration). No regressions. |
| 2 | certipy | **done** | 55 tests (11 smoke, 15 parser, 9 error, 7 contract, 6 integration), 14 fixtures | 9 issues (2 parser bugs, no entrypoint, missing pyyaml, 14 missing error patterns, no classification, find no heartbeat, shadow false success) | All fixed. 50 pass, 5 skip (integration) |
| 3 | bloodyad | **done** | 39 tests (10 smoke, 11 error, 5 success, 8 contract, 4+1 integration), 14 fixtures | 3 issues (no error classification, no entrypoint, tool.yaml missing params) | Error classification on all 25 handlers, shadow ACL detection, entrypoint.sh. 34 pass, 5 skip. No regressions. |
| 4 | kerbrute | **done** | 43 tests (12 smoke, 13 parser, 6 error, 8 contract, 4 integration), 12 fixtures | 6 issues (no libfaketime, ANSI leak in passwords, no error classification, no heartbeat, param name confusion=agent-side) | libfaketime+entrypoint added, ANSI stripping fixed, error classification on all 4 handlers, switched to progress. 39 pass, 4 skip. No regressions. |
| 5 | netexec | **done** | 57 tests (11 smoke, 16 parser, 11 cmd builder, 6 error, 8 contract, 6 integration), 15 fixtures | 5 issues (no entrypoint, no error classification, no heartbeat on SMB/WinRM/LDAP, agent method name confusion, agent type confusion) | entrypoint.sh, error classification on all 7 handlers, heartbeat on 3 long-running methods. 51 pass, 6 skip. No regressions. |
| 6 | evil-winrm | **done** | 101 tests (14 smoke, 20 error, 11 client, 5 domain, 3 kwargs, 13 contract, 28 acceptance, 7 integration), 18 fixtures | Access denied regex too narrow, 4 missing error classifications, engagement-derived patterns | 94 pass, 7 skip. Full pyramid: unit + acceptance + scenarios (40 scenarios). |
| 7 | impacket-relay | **done** | 51 tests (+12 error classification), 7 fixtures | 7+1 issues: stdin theft, timeouts, stale cleanup, force_restart, parser, entrypoint, error classification | Process rewrite + error classification on all handlers. 51 pass, 1 skip. No regressions. |
| 8 | responder | **done** | 83 tests (17 smoke, 12 hash parse, 5 config, 10 duration, 6 error, 5 port bind, 3 ANSI, 3 copy, 16 contract, 5 interface, 1 integration), 9 fixtures | 5 issues: false success on port bind failure, config not restored, no max duration, SQLite lock, no error classification | All fixed. 83 pass. 410 total across 8 tools, zero regressions. |
| 9 | bloodhound | **done** | 68 tests (12 smoke, 22 cmd build, 5 output parse, 12 error, 9 contract, 6+2 integration), 11 fixtures | 4 issues: no error classification, no entrypoint, code duplication, no error_class on cred validation | All fixed. Refactored duplicate code. 60 pass, 8 skip. No regressions. |
| 10 | enum4linux-ng | **done** | 61 tests (11 smoke, 5 parse, 11 cmd build, 6 error, 11 result, 3 regression, 2 dockerfile, 7 contract, 6 integration), 7 fixtures | 6 issues: CRITICAL double .json extension (output always empty), CRITICAL wrong -R flag, no entrypoint, no error classification, no abort detection, temp file leak | All fixed. 55 pass, 6 skip. Zero regressions across all 10 tools. |
| 11+ | ... | pending | | | |

---

## File Structure After Completion

```
mcp-tools/
├── packages/mcp-common/
│   ├── src/mcp_common/
│   │   ├── base_server.py          # Updated: param validation, verify_clock, classify_error
│   │   └── entrypoint.sh           # NEW: dynamic faketime discovery
│   └── pyproject.toml
├── tests/
│   ├── conftest.py                 # NEW: shared fixtures, MCPTestClient
│   ├── test_tool_contracts.py      # EXISTING: enhanced
│   ├── test_smoke.py               # NEW: boot + list_tools for all tools
│   ├── tools/
│   │   ├── test_impacket.py        # Per-tool: smoke + unit + integration
│   │   ├── test_certipy.py
│   │   ├── test_bloodyad.py
│   │   ├── ...
│   │   └── scenarios/              # YAML scenario definitions
│   │       ├── impacket.yaml
│   │       ├── certipy.yaml
│   │       └── ...
│   └── fixtures/                   # Recorded outputs from real engagements
│       ├── impacket/
│       ├── certipy/
│       └── ...
├── tools/
│   ├── impacket/
│   │   ├── mcp-server.py           # Fixed: error classification in handlers, output parsing gaps
│   │   ├── tool.yaml               # Fixed: all methods documented, params match server
│   │   └── Dockerfile              # Updated: use entrypoint.sh (only if libfaketime installed)
│   └── .../
└── scripts/
    └── test-tool.sh                # NEW: per-tool test runner
```

---

## Manual HTB Validation (Final Phase)

After all per-tool sub-agents complete, integration scenarios exist for each tool but haven't been run against real targets. This is the manual validation phase.

**Constraint:** Only one HTB machine can be spawned at a time.

**Process:**
1. Pick an HTB box that exercises the most tools (Pirate used 22 tools, Fries used 19, DarkZero used 14)
2. Spawn the box
3. Run integration scenarios: `pytest tests/ -m integration --target=<IP> --domain=<domain> -v`
4. This runs ALL tools' integration scenarios against the live target
5. Record results, fix failures, re-run
6. Tear down box, pick next one

**Box selection strategy:** Pick boxes that cover different tool sets:
- **AD/Kerberos heavy:** Pirate or Fries (impacket, certipy, kerbrute, bloodyad, evil-winrm, netexec)
- **Web/Linux heavy:** Facts or Soulmate (curl, ffuf, sqlmap, playwright, ssh, exploit-runner)
- **Mixed:** DarkZero or Eighteen (both AD and general tools)

This phase happens AFTER all sub-agent work is done — the scenarios already exist, we're just running them.

---

## Degradation Risk Register

Changes that could make tools WORSE if implemented incorrectly:

| Change | Risk | Mitigation |
|--------|------|------------|
| entrypoint.sh replaces CMD | Container fails to start if sh missing | Use `#!/bin/sh` (POSIX), not bash. Only apply to libfaketime tools. |
| Unknown param warning | Could emit confusing warnings for valid dynamic recipe calls | Warn only, never reject. Handler still receives all params. |
| verify_clock method | 72 copies pollute RAG search | Only register when MCP_TEST_MODE=1 env is set. Production tools don't have it. |
| Fallback error classifier | Could misclassify scan output as tool errors | Only check stderr. Only match unambiguous system-level patterns. Default to "unknown". |
| to_content() format change | Subtle output differences could break agent parsing | Keep format identical when suggestions is empty (all existing tools). |
| structuredContent added | Client might forward it to LLM doubling context | opensploit client currently ignores it — no change until mcp-tool.ts is updated. |
| Switching to run_command_with_progress() | Could change output format if progress filter alters buffering | run_command_with_progress() returns identical CompletedProcess — same stdout/stderr. Only difference is progress notifications sent to client. |
| Switching to run_command_with_progress() changes timing | Heartbeat overhead could slow extremely fast methods | Only switch methods that typically run >60s. Fast methods keep run_command(). |
