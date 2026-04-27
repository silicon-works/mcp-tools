# sqlmap — Tier A scenarios

Single test sheet for the `sqlmap` tool migration. Replaces the legacy split
(`target_extraction_tests.md` + `failure_signature_tests.md`).

Sections:
1. Recommended HTB box for live verification
2. Narrative scenarios (paste into opensploit)
3. Target-extraction adversarial cases (≥20)
4. Failure-signature live-verify cases (≥3)
5. Open questions
6. Hand-off

---

## 1. Recommended HTB box

**Validation (10.129.95.235)** — Linux box with Apache + PHP. Has a
country-selector form on `/account.php` that's **second-order SQLi**: the
injectable parameter is reached via a POST chain. A single `sqlmap -u` scan
will report "not injectable" because Validation's bug requires `--second-url`
+ form discovery. That's a feature for failure-classification testing — the
"all tested parameters do not appear to be injectable" signal fires cleanly.

For positive UNION-injectable behaviour (sqlmap actually finding a flaw), use
a deliberately-vulnerable lab target like DVWA or a HTB box with primary-order
injection (e.g., earlier seasons' Falafel). Validation alone is sufficient for
Tier A migration verification — the architecture path is what we test, not the
vendor's injection-detection algorithm.

---

## 2. Narrative scenarios (paste into opensploit)

### S1 — sqlmap `--version` (smoke)

```
Engagement target: none — running sqlmap --version through opensploit to confirm the kind:cli path is wired and the container is reachable. Report the version string.
```

**Watch:** First call ~3 s (container spawn + MCP handshake), exit 0, stdout `1.7.2#stable` (or whatever the image ships). Confirms persistent container reuse on subsequent calls.

### S2 — reject_flags trap (`-r request file`)

```
Engagement target: 10.129.95.235 (HTB Validation, authorized).
I previously captured the login request and saved it to /session/req.txt.
Use sqlmap with that captured request file to test for SQL injection.
```

**Watch:** Plugin rejects with `status: error`, `rejected_flag: -r`. Reason quoted from tool.yaml `reject_flags_reason`. **Per the new tool-runner prompt clause**: agent reformulates with `-u` against the URL it knows from context, retrying once. If the agent has no URL to fall back to, it returns a clear "phase agent must provide URL" error.

### S3 — UNION injection probe (real long scan, exits 0 even on failure)

```
Engagement target: 10.129.95.235 (HTB Validation, authorized).
Test the country parameter at http://10.129.95.235/account.php?country=1 for UNION-based SQL injection. Use --batch --level=2 --risk=1 --threads=1 --output-dir=/session/sqlmap --disable-coloring. Save the full sqlmap output to /session/sqlmap-validation.txt via sqlmap's own output-dir flag (NOT shell pipes — they don't work in cli_in_container).
```

**Watch:** target=`10.129.95.235` extracted, scan runs to completion (~5-10 min), exit 0 BUT classified as `failure_in_output` because output contains "all tested parameters do not appear to be injectable". Output-dir contents saved to /session/sqlmap/. tool_runner correctly distinguishes vendor-style "we tried and didn't find anything" from "transport error".

### S4 — connection-refused failure classification

```
Engagement target: 10.129.95.235 port 9999 (closed port — verifying error classification).
Test http://10.129.95.235:9999/login.php for SQL injection using sqlmap with --batch --timeout=5 --retries=1 --disable-coloring.
```

**Watch:** Exit 0 (sqlmap convention), classified as `failure_in_output`. stdout matches signal "unable to connect to the target URL" + "Connection refused". tool_runner reports the connection failure cleanly, no transport explosion.

### S5 — DNS-failure classification

```
Engagement target: nonexistent-host.invalid.localdomain (deliberately invalid, verifying DNS error classification).
Test http://nonexistent-host.invalid.localdomain/page.php?id=1 for SQL injection using sqlmap --batch --timeout=5 --retries=1 --disable-coloring.
```

**Watch:** Exit 0. stdout matches "host '...' does not exist, skipping to the next target". Classified as `failure_in_output`. Differs from curl (curl exits 6 for DNS) — tool_runner pattern-matches signals regardless of exit code.

---

## 3. Target-extraction adversarial cases (≥20)

The sqlmap `tool.yaml` declares three rules (first match wins):

1. `flag_value` for `-u` with `parse_as: url_host`
2. `flag_value` for `--url` with `parse_as: url_host`
3. `positional_match` regex `^(?:--url=|-u=)?(https?|ftp|ftps|file|gopher)://([^:/?#*]+)`, capture group 2, `parse_as: url_host` — safety net for `-u=URL` and `--url=URL` forms with embedded equals sign

### Happy-path cases

| # | Command (binary `sqlmap` omitted) | Expected target | Notes |
|---|---|---|---|
| 1 | `-u http://10.10.10.5/page.php?id=1 --batch --random-agent` | `10.10.10.5` | Bog-standard probe, IPv4 |
| 2 | `-u 'http://10.10.10.5/page.php?id=1*' --batch --random-agent` | `10.10.10.5` | Asterisk injection marker — host capture strips via `[^:/?#*]+` |
| 3 | `--url http://target.local/login --data='user=admin&pass=*' --batch` | `target.local` | `--url` (space-separated) flag |
| 4 | `--url=http://target.local/login --data='user=admin&pass=*' --batch` | `target.local` | `--url=` (equals form) |
| 5 | `-u=http://target.local/login --batch` | `target.local` | `-u=` short flag with equals — uncommon but valid |
| 6 | `-u 'https://api.target.com:8443/v2/users?id=1' --batch --random-agent` | `api.target.com` | HTTPS + port + query — port stripped |
| 7 | `-u 'http://VICTIM.LOCAL/page.php?id=1' --batch` | `VICTIM.LOCAL` | Uppercase preserved (validation hook lowercases) |
| 8 | `-u 'http://10.10.10.5/page.php?id=1' --data='username=admin&country=Brazil*' --batch -p country --random-agent` | `10.10.10.5` | POST body with asterisk in --data — only the URL host counts |
| 9 | `-u 'http://10.10.10.5/page.php?id=1' --cookie='PHPSESSID=abc; user=admin' --batch` | `10.10.10.5` | Cookie passed; not a target |
| 10 | `-u 'http://10.10.10.5/api?id=1' --second-url='http://10.10.10.5/result.php' --batch` | `10.10.10.5` | Second-order injection — `--second-url` is on the same host |
| 11 | `-u 'http://shop.target.tld/products.php?cat=1' --proxy='http://127.0.0.1:8080' --batch` | `shop.target.tld` | Proxy URL is on localhost; target is the `-u` host |
| 12 | `-u 'http://10.10.10.5/login' --data='user=admin&pass=*' --tamper=space2comment,between --batch --random-agent` | `10.10.10.5` | WAF-bypass tampers; doesn't affect target extraction |
| 13 | `-u 'http://10.10.10.5/page?id=1' -p id --dbs --batch` | `10.10.10.5` | `-p` (parameter) pass-through |
| 14 | `-u 'http://10.10.10.5/page?id=1' --dbms=mysql --technique=BEUSTQ --level=5 --risk=3 --batch` | `10.10.10.5` | Heavy flags before the URL flag — order independence |
| 15 | `-u 'ftp://files.target.local/dir' --batch` | `files.target.local` | FTP scheme |
| 16 | `-u 'http://target.local' --data='*' --batch` | `target.local` | URL with no path; injection marker as entire body |
| 17 | `--user-agent='Mozilla/5.0' -u http://10.10.10.5/page?id=1 --batch` | `10.10.10.5` | Other flag values (UA contains `/`) before URL |
| 18 | `-u 'http://10.10.10.5/page?id=1' -H 'X-Forwarded-For: 1.2.3.4' --batch` | `10.10.10.5` | IP-looking header value MUST NOT be the target |
| 19 | `-u 'http://10.10.10.5/page?id=1' --auth-type=Basic --auth-cred='admin:password' --batch` | `10.10.10.5` | HTTP basic auth — separate from URL embedding |
| 20 | `-u 'http://admin:s3cr3t@10.10.10.5/page?id=1' --batch` | `10.10.10.5` | URL with userinfo `user:pass@` — host comes after `@`. **Note**: pure regex `[^:/?#*]+` after `://` captures `admin` (the username). Open question 1 below. |

### Adversarial cases (DSL must reject, fall back, or warn)

| # | Command | Expected behaviour | Notes |
|---|---|---|---|
| F1 | `--version` | `target=null` | No target needed for version check. |
| F2 | `--list-tampers` | `target=null` | Same. |
| F3 | `-r /session/burp-request.txt --batch` | Plugin rejects via `reject_flags`. `rejected_flag=-r`. Per new tool-runner prompt: reformulate with `-u` from context. | URL is inside the file, not on cmdline. |
| F4 | `-l /session/burp-proxy.log --batch` | Plugin rejects (`-l` is in reject_flags). | Proxy log file. |
| F5 | `-m /session/targets.txt --batch` | Plugin rejects (`-m` is in reject_flags). Multi-target list file. | `allow_multi_target` not set. |
| F6 | `-g 'inurl:".php?id=1"' --batch` | Plugin rejects (`-g` is in reject_flags). Google dork. | sqlmap pulls URLs from Google results — no way to scope-validate. |
| F7 | `-u 'https://' --batch` | `target=null` (malformed). DSL parse_error or null. sqlmap fails naturally. | Defensive parsing. |
| F8 | `-u 'http://10.10.10.5/' --proxy='http://outofscope.attacker.com:8080' --batch` | `target=10.10.10.5` (the `-u` target, NOT the proxy). | **Security invariant**: scope = target of request, not proxy. |
| F9 | `-u 'http://10.10.10.5/' -H 'Host: real.target.com' --batch` | `target=10.10.10.5` (NOT real.target.com). | Same invariant as curl F5: Host header is behaviour override, not authorization scope. |
| F10 | `-u 'http://10.10.10.5/' --safe-url='http://safe.target.com/heartbeat' --safe-freq=10 --batch` | `target=10.10.10.5` (NOT safe.target.com). | --safe-url is decoy traffic. Same target-vs-decoy distinction. |
| F11 | (empty command, no args) | `target=null` | sqlmap will print usage and exit. |

### Concatenated short-flag cases (commandUsesFlag must catch)

| # | Command | Expected behaviour | Notes |
|---|---|---|---|
| F12 | `-rrequest.txt --batch` | Plugin rejects (`-r` matched via concatenated form). | After commandUsesFlag fix in cli_in_container — verifies short-flag concatenation detection. |
| F13 | `-l/path/to/log --batch` | Plugin rejects (`-l` matched). | Same. |
| F14 | `-mtargets.txt --batch` | Plugin rejects (`-m` matched). | Same. |
| F15 | `-ginurl:.php --batch` | Plugin rejects (`-g` matched). | Same. |

---

## 4. Failure-signature live-verify cases (≥3)

Run via opensploit; verify result hits a `failure_signatures` entry. **Critical
finding** preserved from pilot: sqlmap exits 0 on ALL hard failures. tool_runner
must pattern-match `failure_signatures.signal` regardless of exit code, and the
status `failure_in_output` is the right classification (not `non_zero_exit`).

| # | Test | Command (post-binary) | Expected exit | Expected stdout/stderr substring | failure_signature `signal` | Status |
|---|---|---|---|---|---|---|
| 1 | DNS resolution failure | `-u 'http://nonexistent-host.invalid.localdomain/?id=1' --batch --random-agent --timeout=5 --retries=1 --disable-coloring` | **0** | `host 'nonexistent-host.invalid.localdomain' does not exist, skipping to the next target` | `host '` AND `does not exist, skipping to the next target` | VERIFIED 2026-04-25 |
| 2 | Connection refused | `-u 'http://127.0.0.1:1/?id=1' --batch --random-agent --timeout=5 --retries=1 --disable-coloring` | **0** | `unable to connect to the target URL ('Connection refused')` | `unable to connect to the target URL` AND `Connection refused` | VERIFIED 2026-04-25 |
| 3 | Connection timeout | `-u 'http://10.255.255.254/?id=1' --batch --random-agent --timeout=3 --retries=1 --disable-coloring` | **0** | `connection timed out to the target URL` | `connection timed out to the target URL` | VERIFIED 2026-04-25 (replaced original "Operation timed out") |
| 4 | Invalid URL (auto-prepend) | `-u 'not-a-url' --batch --random-agent --disable-coloring` | **0** | `host 'not-a-url' does not exist, skipping to the next target` | Same as test 1 (DNS path) | VERIFIED 2026-04-25 — sqlmap is forgiving about scheme |
| 5 | Live happy-path probe | `-u 'http://10.129.95.235/account.php' --data='username=test&country=Brazil' --batch --random-agent --output-dir /session/sqlmap --level=2 --threads=4 -p country --disable-coloring` | **0** | `all tested parameters do not appear to be injectable` | `all tested parameters do not appear to be injectable` | VERIFIED 2026-04-25 — Validation's vuln is second-order; single-step won't find it |

### Lessons recorded in `tool.yaml` gotchas

1. sqlmap **exits 0 on hard failures** — DNS, refused, timeout, invalid URL all return 0 with `[CRITICAL]` / `[ERROR]` in stdout. Pattern-match signals, not exit code.
2. `--batch` is non-negotiable in containers — without it sqlmap blocks on stdin and the container has no stdin. **Reject any usage_pattern that omits `--batch`** during registry build.
3. `--output-dir /session/sqlmap` is canonical — without it sqlmap writes to `/root/.local/share/sqlmap/output/` inside the container, invisible to tool_runner.
4. `--disable-coloring` recommended — ANSI escape codes pollute stdout; tool_runner's prose parsing is more reliable without them.
5. `your sqlmap version is outdated` is unconditional — every run warns. Not a real failure; classified informational.
6. `--second-url` exists but isn't covered by simple `-u` scans. Validation HTB box requires `--second-url` to find injection.

---

## 5. Open questions

1. **Userinfo URL (case 20)** — pure regex `[^:/?#*]+` after `://` captures `admin` (the username) instead of `10.10.10.5`. Recommended fix: regex `(?:[^@/?#]*@)?([^:/?#*]+)` with capture group adjusted. **Verify in plugin's DSL implementation** — if not handled, update sqlmap's `target_extraction` regex.
2. **Multi-target ingestion (F3-F6)** — implemented as `reject_flags` per pilot decision. Confirmed working in cli_in_container (rejection fires before container spawn).
3. **Asterisk in URL (case 2)** — regex strips `*` from host capture via `[^:/?#*]+`. Correct: `*` in DNS hostnames is invalid.
4. **`--proxy` and `--safe-url` security invariant (F8, F10)** — extract from `-u`, never from `--proxy` / `--safe-url`. Document in spec section on target_extraction security invariants.
5. **Per-tool exit-code semantics** — sqlmap's "exit 0 always" is a recurring pattern (sqlite3 also). Either add a per-tool `success_indicators.exit_code: "always_zero"` field to the registry schema, or make tool_runner's prompt explicit about pattern-matching signals regardless of exit code.

6. **Audit gap: --output-dir multi-file lifecycle.** Legacy `mcp-server.py` set no `--output-dir` (sqlmap defaulted to `/root/.local/share/sqlmap/output/` inside the container, lost on container exit). The new tool.yaml pins `/session/sqlmap` in every usage_pattern. That directory contains `session.sqlite` (cached injection points reused across calls), per-target log files, and dump CSVs/HTML — a multi-file output, not a single artifact. Open: when the shared runner replaces the per-tool `mcp-server.py`, who is responsible for (a) creating `/session/sqlmap` if absent, (b) preserving session.sqlite across calls so subsequent enumerate/dump runs reuse the cached injection point, (c) cleaning up between unrelated targets? Currently this is an LLM/usage_pattern convention; it should be a runner contract.

7. **Audit gap: --dump-format=CSV auto-injection.** Legacy `dump_table` *unconditionally* appended `--dump-format CSV` (mcp-server.py:847). The new tool.yaml mentions CSV in `output_formats` and one usage_pattern but does NOT auto-inject it for every dump invocation. Without `--dump-format=CSV`, sqlmap's default is text-table format which is harder to parse and varies by version. Fix is either (a) add `--dump-format=CSV` to the three dump-related usage_patterns explicitly, or (b) have the shared runner inject it for sqlmap dump invocations. The trivial gotcha patch (added 2026-04-25) reminds the LLM but does not enforce.

8. **Audit gap: Feature 28 dynamic recipes for sqlmap.** No `/session/tool_recipes/sqlmap/` directory or recipe-loading hook is referenced in tool.yaml. sqlmap is a strong candidate for recipes — repeated WAF-bypass tamper chains, technique combinations, and DBMS-specific exploitation patterns are exactly what recipes are for (e.g., a `mssql-xp-cmdshell.recipe` that bundles `--dbms=mssql --technique=S --os-shell --tamper=between,charencode`). Open: should the shared runner support recipe loading for kind:cli tools, or are recipes only for kind:mcp servers with stateful pipes? If yes for kind:cli, this is the canonical sqlmap recipe candidate.

9. **Audit gap: second-order injection workflow.** `--second-url` is in `value_flags` and `routing.use_for` mentions second-order injection, but no usage_pattern shows the `--second-url` + `--second-req` pair, and the Validation HTB scenario (S3) deliberately fails because it doesn't use `--second-url`. Add a usage_pattern: `sqlmap -u {injection_url} --data='{post_body}' --second-url={result_url} --batch --output-dir /session/sqlmap` with a `when:` explaining "the parameter you submit and the page where the result appears are different URLs (Validation HTB pattern)". Without this, LLMs reproducing Validation will hit S3's classified-as-failure path even though the box IS injectable.

10. **Audit gap: tamper script validation.** Legacy mcp-server had no validation of tamper script names; sqlmap fails late if a name is wrong. The new tool.yaml lists ~6 tamper names in gotchas but doesn't reference the canonical `--list-tampers` output. Open: should tool_runner pre-validate `--tamper` values against a known list, or rely on sqlmap's own error? The `help_commands` entry for `--list-tampers` exists, but the LLM has no signal to cache or consult it.

11. **Audit gap: --technique flag semantics.** Legacy used the literal string "BEUSTQ" as default; the new tool.yaml documents the same default in common_options. Open: tool_runner has no validation that user-supplied `--technique` values are a subset of `BEUSTQ` characters. A typo like `--technique=BEU5T` would be passed to sqlmap which then errors. Trivial — push to gotcha or accept sqlmap's own error message.

---

## 6. Hand-off

- **Tool**: sqlmap (kind:cli)
- **Status**: pilot-migrated; scenarios consolidated; image rebuilt locally with mcp-common 0.3.0; legacy split files dropped.
- **mcp-server.py**: present, untouched — auto-inherits run_cli; preserves rollback per SKILL #21.
- **Image**: `ghcr.io/silicon-works/mcp-tools-sqlmap:latest` — local rebuild verified end-to-end via plugin integration test (3/3 pass on 2026-04-25).
- **Live-verify pending**: paste S1-S5 into opensploit against Validation. Confirm sqlmap reject_flags + reformulation works after the new tool-runner prompt clauses landed.
- **Pilot-gate sign-off (2026-04-25)**: ≥3 deliberate-failure tests, all PASS after broadening signals; ≥20 extraction cases authored; live HTB run on Validation confirmed `failure_in_output` classification.

Authored: 2026-04-25 (pilot Phase 2) — consolidated 2026-04-26.
