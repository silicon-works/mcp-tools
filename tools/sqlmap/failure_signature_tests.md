# sqlmap failure_signatures live test set

Per Feature 35 spec: ≥3 deliberate-failure tests verifying the
`failure_signatures` entries in `tool.yaml` actually match sqlmap's stderr/stdout
behaviour. **All five tests below were run live in the kind:cli image
(`mcp-test-sqlmap`, sqlmap 1.7.2 from Debian bookworm) on 2026-04-25.**

## Critical finding (worth flagging in the spec)

**sqlmap exits 0 on hard failures** — DNS resolution, connection refused, and
connection timeout all return exit code 0 with the error written to stdout as
`[CRITICAL]` / `[ERROR]` lines. tool_runner's "non-zero exit = failure" heuristic
will MISS these. Match `failure_signatures.signal` on stdout/stderr substrings,
not on exit code.

This contrasts with curl (which exits 6/7/28 for DNS/refused/timeout). Across
Tier A migration, the assumption "exit code reflects success" needs per-tool
verification. Suggest documenting "exit code semantics" in the registry schema
as an optional field, or have tool_runner always pattern-match
failure_signatures regardless of exit code.

## Live verification log

### Test 1: DNS resolution failure
- **Command**: `sqlmap -u 'http://nonexistent-host.invalid.localdomain/?id=1' --batch --random-agent --timeout=5 --retries=1 --disable-coloring`
- **Actual exit**: **0** (NOT non-zero)
- **stdout/stderr substrings observed**:
  - `[ERROR] host 'nonexistent-host.invalid.localdomain' does not exist, skipping to the next target`
- **Matched signals**:
  - `host '` ✓
  - `does not exist, skipping to the next target` ✓
- **Result**: PASS (after broadening signal from "Could not resolve host" to sqlmap's actual phrasing)

### Test 2: Connection refused (port 1 on localhost)
- **Command**: `sqlmap -u 'http://127.0.0.1:1/?id=1' --batch --random-agent --timeout=5 --retries=1 --disable-coloring`
- **Actual exit**: **0**
- **stdout substrings observed**:
  - `[CRITICAL] unable to connect to the target URL ('Connection refused'). sqlmap is going to retry the request(s)`
  - `[ERROR] unable to connect to the target URL ('Connection refused'), skipping to the next target`
- **Matched signals**:
  - `unable to connect to the target URL` ✓
  - `Connection refused` ✓
- **Result**: PASS

### Test 3: Connection timeout (non-routable IP)
- **Command**: `sqlmap -u 'http://10.255.255.254/?id=1' --batch --random-agent --timeout=3 --retries=1 --disable-coloring`
- **Actual exit**: **0**
- **stdout substrings observed**:
  - `[CRITICAL] connection timed out to the target URL. sqlmap is going to retry the request(s)`
  - `[ERROR] connection timed out to the target URL, skipping to the next target`
- **Matched signals**:
  - `connection timed out to the target URL` ✓ (added — original `Operation timed out` did NOT match)
- **Result**: PASS (after adding the new signal)

### Test 4: Invalid URL (no scheme, no params)
- **Command**: `sqlmap -u 'not-a-url' --batch --random-agent --disable-coloring`
- **Actual exit**: **0**
- **stdout observed**:
  - `[INFO] testing URL 'http://not-a-url'` — sqlmap auto-prepends `http://`
  - `[ERROR] host 'not-a-url' does not exist, skipping to the next target`
- **Matched signals**: same as Test 1 (DNS path)
- **Result**: PASS — but note: sqlmap is FORGIVING about scheme. The `invalid target URL` signal in failure_signatures requires a more obviously-bad URL than "not-a-url" to fire. We KEEP the signal because sqlmap may emit it on truly malformed input.

### Test 5: Live happy-path probe against HTB Validation
- **Command**: `sqlmap -u 'http://10.129.95.235/account.php' --data='username=test&country=Brazil' --batch --random-agent --output-dir /session/sqlmap --level=2 --threads=4 -p country --disable-coloring`
- **Actual exit**: **0**
- **Wall time**: ~10 minutes
- **stdout (final lines)**:
  - `[WARNING] POST parameter 'country' does not seem to be injectable`
  - `[ERROR] all tested parameters do not appear to be injectable. Try to increase values for '--level'/'--risk' options ...`
- **Matched signal**: `all tested parameters do not appear to be injectable` ✓
- **`/session/sqlmap/` contents after run**: results-04252026_1219pm.csv + per-target session.sqlite + log
- **Result**: PASS for failure-signature matching. Note: Validation's vulnerability is **second-order** (POST to `/`, result on `/account.php`), so a single-step sqlmap scan won't find it; a full validation requires `--second-url`. That's beyond Phase 1 smoke scope but documented as a "gotcha" in tool.yaml.

## Pilot-gate sign-off

- ≥3 deliberate failure tests authored: ✓ (3 core failure modes + 2 supplementary including a real HTB target)
- All produced documented exit code 0: ✓ (CRITICAL FINDING — different from curl)
- All matched a `failure_signatures.signal` after the live verification: ✓
- `failure_signatures` updated and re-verified: ✓
  - "host '" added (DNS variant — sqlmap's actual wording)
  - "does not exist, skipping to the next target" added
  - "connection timed out to the target URL" added (replaces "Operation timed out")
  - "your sqlmap version is outdated" added as informational/ignore
- Container `/session` mount verified writable by sqlmap (CSV + SQLite session land there)

## Lessons for the migration spec

1. **Per-tool exit-code semantics matter.** sqlmap returns 0 on DNS/refused/timeout. tool_runner cannot rely on `result.exit_code === 0` to infer success. Either:
   - Document per-tool exit-code conventions in the YAML (e.g., a `success_indicators: { exit_code: "non_zero_means_error" | "always_zero" }` field), or
   - tool_runner always pattern-matches failure_signatures regardless of exit code (current implicit behaviour — make explicit in the prompt).

2. **--batch is non-negotiable.** Without it sqlmap blocks on stdin. The container has no stdin; the tool would hang forever. Strongly suggest the registry build step REJECT any usage_pattern for sqlmap that omits `--batch`.

3. **--output-dir /session/sqlmap should be canonical.** Without it, sqlmap writes to `/root/.local/share/sqlmap/output/` inside the container — invisible to tool_runner and lost when the container exits. Pin it.

4. **`--disable-coloring` recommended.** ANSI escape codes pollute stdout; tool_runner's prose parsing is more reliable without them.

5. **`your sqlmap version is outdated` is unconditional.** Every run will warn. Not a real failure — flagged as informational in failure_signatures.
