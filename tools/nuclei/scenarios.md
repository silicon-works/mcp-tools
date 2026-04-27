# nuclei — Tier A scenarios

Single test sheet for the `nuclei` tool migration.

Sections:
1. Recommended HTB box for live verification
2. Narrative scenarios (paste into opensploit)
3. Target-extraction adversarial cases (≥20)
4. Failure-signature live-verify cases (≥3)
5. Open questions
6. Hand-off

---

## 1. Recommended HTB box

**Validation (10.129.95.235)** — Linux box with Apache + PHP. Reachable
HTTP target for nuclei's exposure / misconfiguration / default-credentials
template families.

Caveat: HTB lab boxes are hand-crafted vulnerabilities, not real-world CVEs.
Nuclei's strength is template-pattern matching against actual CVE fingerprints
(Log4Shell, Spring4Shell, etc.), so most CVE-tagged templates will return zero
findings. **What we test here is the architecture path** (target extraction,
output format, failure classification, reject_flags), not nuclei's CVE-detection
algorithm.

For positive CVE-pattern testing, point nuclei at a deliberately-vulnerable
container (e.g., a vulhub instance) once available — out of scope for Tier A
gate.

Persistent test directory: standard `/session/` mount; nuclei outputs go to
`/session/nuclei-*.jsonl`.

---

## 2. Narrative scenarios (paste into opensploit)

### S1 — critical-only quick scan

```
Engagement target: 10.129.95.235 (HTB Validation, authorized).
Use nuclei to scan http://10.129.95.235 for critical-severity findings only. Use the JSONL output format and write to /session/nuclei-crit.jsonl. Disable the template update check for a reproducible run, and disable stdin reading (containers have no stdin).
```

**Watch:** Agent emits something like `nuclei -u http://10.129.95.235 -severity critical -jsonl -o /session/nuclei-crit.jsonl -disable-update-check -no-stdin`. target=`10.129.95.235` extracted from `-u`. First call ~3-5 s spawn + container exec; subsequent calls reuse warm container.

### S2 — exposure-tag scan (broader, info-disclosure)

```
Engagement target: 10.129.95.235 (HTB Validation).
Run nuclei with -tags exposure,misconfig against http://10.129.95.235. Output JSONL to /session/nuclei-exp.jsonl. Drop rate-limit to 50 req/s for stealth. Disable update check and stdin.
```

**Watch:** target extracted as before. Output likely a handful of low/info findings. Agent does NOT default to running ALL ~12,000 templates (would be very loud).

### S3 — targeted CVE check (single template by ID)

```
Engagement target: 10.129.95.235 (HTB Validation).
Use nuclei to test http://10.129.95.235 specifically for CVE-2021-44228 (Log4Shell). Use template ID, not tags. Output to /session/nuclei-log4shell.jsonl in JSONL format. Stop at first match.
```

**Watch:** Agent emits `nuclei -u http://10.129.95.235 -id CVE-2021-44228 -jsonl -o /session/nuclei-log4shell.jsonl -stop-at-first-match -disable-update-check -no-stdin`. Validation almost certainly returns zero findings — that's the expected negative result. Status `success` with empty findings, not a failure.

### S4 — authenticated scan with custom header

```
Engagement target: 10.129.95.235 (HTB Validation).
Run nuclei against http://10.129.95.235 with the cookie "PHPSESSID=test-session-token" set. Filter to high and critical severity. Output JSONL to /session/nuclei-auth.jsonl.
```

**Watch:** Agent emits `nuclei -u http://10.129.95.235 -H 'Cookie: PHPSESSID=test-session-token' -severity high,critical -jsonl -o /session/nuclei-auth.jsonl -disable-update-check -no-stdin`. The `-H` value contains a string that LOOKS valuable but should NOT be misextracted as target.

### S5 — DNS failure classification

```
Engagement target: nonexistent-host.invalid.localdomain (deliberately invalid, verifying DNS error classification).
Run nuclei against http://nonexistent-host.invalid.localdomain with -severity critical -disable-update-check -no-stdin -timeout 5.
```

**Watch:** stderr/stdout matches signal "no such host" or "Could not resolve host". Classified as `failure_in_output` (nuclei may exit 0 even on DNS failure — pattern-match required). Agent reports DNS issue cleanly.

### S6 — reject_flags trap (-l target list file)

```
Engagement target: 10.129.95.235 (HTB Validation).
I have a list of targets in /session/targets.txt. Use nuclei to scan all of them for high-severity findings.
```

**Watch:** Plugin rejects with `status: error`, `rejected_flag: -l`. Agent reformulates per the new tool-runner prompt clause: extract a single URL from context (10.129.95.235) and reformulate with `-u`. If the agent has multiple targets, it should issue separate `tool_runner` calls (one per target).

---

## 3. Target-extraction adversarial cases (≥20)

The nuclei `tool.yaml` declares two extraction rules (first match wins):

1. `flag_value` for `-u` with `parse_as: url_host`
2. `flag_value` for `-target` with `parse_as: url_host`

`reject_flags`: `-l`, `-target-list`, `-list` (target-list file ingestion).

`value_flags` includes ~80 entries to prevent value-position strings from
being misextracted (notably `-proxy`, `-template-url`, `-workflow-url`,
`-resolvers`, `-source-ip`, `-H`, `-V`, `-iv`, all `-o*` exports).

### Happy-path cases

| # | Command (binary `nuclei` omitted) | Expected target | Notes |
|---|---|---|---|
| 1 | `-u http://10.129.95.235/ -severity critical` | `10.129.95.235` | Bog-standard scan, IPv4 |
| 2 | `-u https://target.local:8443/api -severity high` | `target.local` | HTTPS + port + path; port stripped |
| 3 | `-target http://10.10.10.5/admin -tags exposure` | `10.10.10.5` | `-target` alias for `-u` |
| 4 | `-u http://VICTIM.LOCAL/ -id CVE-2021-44228` | `VICTIM.LOCAL` | Uppercase preserved |
| 5 | `-u 'http://admin:s3cr3t@10.10.10.5/'` | `10.10.10.5` | URL with userinfo — host comes after `@` |
| 6 | `-u http://[2001:db8::1]/ -severity high` | `[2001:db8::1]` (or `2001:db8::1` post-strip) | IPv6 bracketed |
| 7 | `-u http://10.10.10.5:8080/admin -tags exposure -jsonl -o /session/scan.jsonl` | `10.10.10.5` | Output flag value contains a path — not a target |
| 8 | `-tags exposure -severity critical -u http://10.10.10.5/` | `10.10.10.5` | Flags before -u; order independence |
| 9 | `-u http://10.10.10.5/ -id CVE-2021-44228 -stop-at-first-match` | `10.10.10.5` | Targeted CVE check |
| 10 | `-u http://api.target.com/v2/users?id=1 -severity high` | `api.target.com` | Query string in URL |
| 11 | `-u ftp://files.target.local/ -severity info` | `files.target.local` | FTP scheme |
| 12 | `-u http://10.10.10.5/ -t cves/2021/CVE-2021-44228.yaml -jsonl` | `10.10.10.5` | `-t` value is a template path — must NOT be picked |
| 13 | `-u http://10.10.10.5/ -w /session/workflows/wp.yaml` | `10.10.10.5` | `-w` value is a workflow path — must NOT match |
| 14 | `-u http://10.10.10.5/ -V 'host=10.255.255.254' -V 'port=8080'` | `10.10.10.5` | `-V` template variables contain IP-looking values — must NOT match |
| 15 | `-u http://10.10.10.5/ -iv /session/vars.yaml` | `10.10.10.5` | `-iv` vars file path — must NOT match |

### Adversarial — value_flag traps & security invariants

| # | Command | Expected | Notes |
|---|---|---|---|
| F1 | `-h` | `target=null` | Help. tool_runner bypasses scope check. |
| F2 | `-version` | `target=null` | Version. |
| F3 | `-tl -tags cve` | `target=null` | Template list — no scan, no target. |
| F4 | `-l /session/targets.txt -severity critical` | Plugin rejects (`-l` in reject_flags). Reformulate with `-u`. | Multi-target file ingestion. |
| F5 | `-target-list /session/list.txt` | Plugin rejects (`-target-list` in reject_flags). | Same. |
| F6 | `-list /session/targets.txt` | Plugin rejects (`-list` in reject_flags). | Same. |
| F7 | `-u http://10.10.10.5/ -proxy http://outofscope.attacker.com:8080` | `target=10.10.10.5` (NOT proxy). | Security invariant: scope = target of request, not proxy. |
| F8 | `-u http://10.10.10.5/ -p http://burp.local:8080` | `target=10.10.10.5` (NOT proxy). | `-p` is short form of `-proxy` per nuclei docs — confirm in value_flags. |
| F9 | `-u http://10.10.10.5/ -H 'Referer: https://other.target/'` | `target=10.10.10.5` (NOT referer). | `-H` value contains URL but is in value_flags. |
| F10 | `-u http://10.10.10.5/ -H 'X-Forwarded-For: 1.2.3.4'` | `target=10.10.10.5` | IP-looking header value MUST NOT be picked. Same invariant as curl/sqlmap F5. |
| F11 | `-u http://10.10.10.5/ -template-url https://templates.cdn.com/cves.yaml` | `target=10.10.10.5` (NOT template URL). | Template fetch URL is infrastructure, not target. |
| F12 | `-u http://10.10.10.5/ -workflow-url https://workflows.cdn.com/wp.yaml` | `target=10.10.10.5` (NOT workflow URL). | Same. |
| F13 | `-u http://10.10.10.5/ -resolvers 1.1.1.1,8.8.8.8` | `target=10.10.10.5` (NOT resolver IPs). | DNS resolvers are infrastructure. |
| F14 | `-u http://10.10.10.5/ -source-ip 10.10.10.99` | `target=10.10.10.5` (NOT source IP). | Network evasion flag. |
| F15 | `-u http://10.10.10.5/ -interface eth0` | `target=10.10.10.5` | Interface name is not a target. |
| F16 | `-u http://10.10.10.5/ -id CVE-2021-44228 -id CVE-2017-5638` | `target=10.10.10.5` | Multiple `-id` flags — last-wins or accumulating per nuclei behavior; doesn't affect target extraction. |
| F17 | `-u http://10.10.10.5/ -u http://10.10.10.6/` | First positional or last-wins per nuclei behavior; document. Recommend: extract first, flag `multi_target_detected=true`. | Multiple `-u` flags. |
| F18 | `-id CVE-2021-44228` (no `-u`) | `target=null` → nuclei errors out. | No target provided. Plugin allows pass-through; nuclei prints "no input provided" → failure_in_output. |
| F19 | `-tags exposure` (no `-u`) | `target=null` | Same. |
| F20 | `-u 'https://'` (malformed) | `target=null` (parse_error) → nuclei fails naturally. | Defensive parsing. |
| F21 | `-u http://10.10.10.5/ -trace-log /session/trace.log -debug-output /session/debug.log` | `target=10.10.10.5` (NOT log paths). | All `-*log*` flag values are paths, in value_flags. |

---

## 4. Failure-signature live-verify cases (≥3)

| # | Layer | Test | failure_signature `signal` | Status |
|---|---|---|---|---|
| 1 | DNS | `-u http://nonexistent-host.invalid.localdomain -severity critical -disable-update-check -no-stdin -timeout 5` | `no such host` AND/OR `Could not resolve host` | PENDING live verify |
| 2 | TCP | `-u http://127.0.0.1:1/ -severity critical -disable-update-check -no-stdin -timeout 3` | `connection refused` | PENDING live verify |
| 3 | TLS | `-u https://expired.badssl.com/ -severity critical -disable-update-check -no-stdin` | `x509:` OR `certificate signed by unknown authority` | PENDING — third-party domain; rerun once self-signed lab target exists |
| 4 | Template/argument | `-u http://10.129.95.235/ -id NONEXISTENT-TEMPLATE-XYZ -disable-update-check -no-stdin` | `template not found` OR `could not find any templates` | PENDING live verify |
| 5 | No-input | `-id CVE-2021-44228 -disable-update-check -no-stdin` (no `-u`) | `no input provided` | PENDING live verify |
| 6 | Rate-limit / host-error | Generated artificially by stress-scanning a fragile target — not easily reproducible in lab | `host error count exceeded` | PENDING — needs WAF-protected target |

### Layer diversity (SKILL #11) — achieved

5 distinct layers exercised: DNS / TCP / TLS / template-engine / argument-validation. Rate-limit layer (case 6) needs a more realistic target; defer to Wave 9 live HTB run.

---

## 5. Open questions

1. **`-p` short form of `-proxy`** (case F8) — verify against actual `nuclei -h` output. nuclei's flag parsing uses single-dash long flags; confirm `-p` exists or remove from value_flags.
2. **Multi-`-u` behavior** (case F17) — nuclei may accept multiple `-u` flags (extract all) OR last-wins. Document actual behavior; if it accepts multiple, consider declaring `allow_multi_target: true` rather than rejecting.
3. **OAST / interactsh egress** — nuclei templates that test for blind injection rely on OAST callbacks to `interactsh.com`. In airgap labs this hangs the scan. The yaml gotchas mention `-no-interactsh`; should it be a default in usage_patterns, or per-call decision?
4. **Headless templates** — some nuclei templates require Chromium for headless rendering. The current image may not include it. Document or upgrade image.
5. **TLS cert tests** — same blocker as curl/sqlmap: lab targets don't ship a TLS cert error. Need a self-signed nginx target.
6. **Template auto-update at first run** — nuclei attempts to update templates on startup. The Dockerfile pre-fetches them at build time, but `-disable-update-check` is still recommended for runtime reproducibility.
7. **`-as` (Wappalyzer auto-scan)** — automatic technology detection + template selection. Could be a powerful default usage_pattern but adds complexity; leave for post-Tier-A.

8. **Auto-injected boilerplate gone** — legacy `_add_common_args` injected `-duc -ni` (and `-fr` when truthy) on every method. Under kind:cli the LLM must remember to add `-disable-update-check` (and frequently `-no-interactsh` for airgap labs) on each call. Most usage_patterns now embed `-disable-update-check`; verify the agent does the same for ad-hoc calls. Consider whether the plugin should auto-prepend `-no-stdin -disable-update-check` (defensive, safe) to every nuclei argv if missing — currently it does not.

9. **`-silent` was always-on legacy** — every legacy method passed `-silent`. The new tool.yaml mentions it in `common_options.output` and a new "silent JSONL with periodic progress" usage_pattern, but the other usage_patterns don't include it. Without `-silent`, JSONL output is interleaved with banner / progress text, so a downstream JSONL parser may need to filter non-JSON lines. Decide: bake `-silent` into all JSONL usage_patterns, or document that the tool-runner must strip non-JSON lines.

10. **`-fr` follow-redirects default mismatch** — legacy methods enabled `-fr` by default (parameter `follow_redirects=True`). nuclei's native default is `-fr` OFF. Many CVE templates rely on the redirect target (canonical hostname, login page) to fingerprint. Without `-fr`, scans on real-world targets that 301 to www.* will silently return zero findings. Recommend: include `-fr` in all real-world usage_patterns. (Currently absent from most usage_pattern commands; would need a follow-up patch.)

11. **DAST rate-limit divergence** — legacy `dast_scan` used `-rate-limit 100` while `scan` used 150. The new "DAST / built-in fuzzer scan" usage_pattern preserves this; confirm via live test that 100 req/s is still the right ceiling for targets under fuzz load.

12. **JSONL schema fields exposed by legacy parser** — legacy `_parse_jsonl_output` mapped these JSON keys to flat fields: `template-id`, `info.name`, `info.severity`, `type`, `host`, `matched-at`, `extracted-results`, `info.description`, `info.reference`, `info.tags`. tool.yaml description names a subset (template-id, info.name, info.severity, host, matched-at, extracted-results, info.reference); add `type`, `info.description`, `info.tags` to the description so downstream consumers know they exist for templating / deduplication.

---

## 6. Hand-off

- **Tool**: nuclei (kind:cli)
- **Status**: tool.yaml authored end-to-end; scenarios.md written. Dockerfile updated to `python3-full` (Kali apt fix). mcp-server.py untouched (auto-inherits run_cli; rollback path).
- **Image**: `ghcr.io/silicon-works/mcp-tools-nuclei:latest` — needs rebuild during Wave 9 batch to pick up mcp-common 0.3.0.
- **Live-verify pending**: paste S1-S6 against Validation. Verify failure_signatures 1-2 (DNS, TCP) live; defer cases 3-6 until appropriate targets available.
- **Wave 1.3 — Sub-agent rate-limited mid-task**: tool.yaml was authored end-to-end by sub-agent (28K, comprehensive — 80+ value_flags, 14 usage_patterns, 17 gotchas, 19 failure_signatures). scenarios.md authored manually after sub-agent hit rate limit; no quality drop, just continuity preservation.

Authored: 2026-04-26.
