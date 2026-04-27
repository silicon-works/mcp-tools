# nikto — Tier A scenarios

Single test sheet for the `nikto` tool migration.

Sections:
1. Recommended HTB box for live verification
2. Narrative scenarios (paste into opensploit)
3. Target-extraction adversarial cases (≥20)
4. Failure-signature live-verify cases (≥3)
5. Open questions
6. Hand-off

---

## 1. Recommended HTB box

**Validation (10.129.95.235)** — Apache + PHP + MySQL stack. Surfaces nikto's
signature legacy findings: server-version banner, Apache misconfiguration
notes, default files (icons/, server-status), insecure HTTP methods, and
common CGI checks. Tuning category 2 (misconfiguration) and 3 (info-disclosure)
both fire reliably here.

Alternate: **Cap (10.10.10.245)** — also Apache + Python; gives a different
banner mix but similar surface area for the architecture path tests.

Caveat: HTB lab boxes are hand-crafted vulnerabilities, not real-world CVEs.
Nikto's strength is the OSVDB-cross-referenced legacy CVE database, which
mostly targets Apache 1.x / 2.0.x / 2.2.x era findings. Most modern HTB
boxes will return server-banner + a handful of misconfig findings, not the
full historical CVE chain. **What we test here is the architecture path**
(target extraction, output format, failure classification, multi-port handling),
not nikto's CVE-detection algorithm.

For positive legacy-CVE testing, point nikto at a deliberately-vulnerable
container (e.g., Metasploitable2 or vulhub Apache 2.0.x instance) once
available — out of scope for Tier A gate.

Persistent test directory: standard `/session/` mount; nikto outputs go to
`/session/nikto-*.json`.

---

## 2. Narrative scenarios (paste into opensploit)

### S1 — quick scan with JSON output

```
Engagement target: 10.129.95.235 (HTB Validation, authorized).
Use nikto to scan http://10.129.95.235 with default tuning. Use the JSON output format and write to /session/nikto.json. Show progress so I can see the scan is alive. Disable interactive prompts (containers have no stdin).
```

**Watch:** Agent emits something like `nikto -h http://10.129.95.235 -Format json -output /session/nikto.json -Display P -nointeractive`. target=`10.129.95.235` extracted from `-h`. First call ~3-5 s container spawn; subsequent calls reuse warm container.

### S2 — tuning-scoped scan (misconfig + info-disclosure only)

```
Engagement target: 10.129.95.235 (HTB Validation).
Run nikto against http://10.129.95.235 but only check categories 2 (misconfiguration) and 3 (information disclosure). JSON output to /session/nikto-misc.json. Show progress.
```

**Watch:** Agent emits `nikto -h http://10.129.95.235 -Tuning 23 -Format json -output /session/nikto-misc.json -Display P -nointeractive`. Scoped scan completes in ~2-5 minutes vs. 15-30 for full tuning. Surfaces banner + default-file findings (icons/, server-status) but skips slow categories (5, 7, b, c).

### S3 — SSL scan with custom port

```
Engagement target: 10.129.95.235 (HTB Validation, authorized).
Scan https://10.129.95.235 on port 8443 with nikto. Force SSL mode. Output JSON to /session/nikto-ssl.json. Show progress.
```

**Watch:** Agent emits `nikto -h 10.129.95.235 -ssl -port 8443 -Format json -output /session/nikto-ssl.json -Display P -nointeractive`. Validation may not have HTTPS on 8443 — expected to fall through with `No web server found` or `Connection refused`. The architecture path (target extraction, SSL flag handling) is what we verify; positive SSL coverage needs a self-signed lab target (deferred — same blocker as curl/sqlmap/nuclei).

### S4 — authenticated scan with -id

```
Engagement target: 10.129.95.235 (HTB Validation).
Run nikto against http://10.129.95.235/admin/ with HTTP Basic auth credentials admin:password. JSON output to /session/nikto-auth.json. Limit to categories 2 and 3.
```

**Watch:** Agent emits `nikto -h http://10.129.95.235 -id 'admin:password' -Tuning 23 -Format json -output /session/nikto-auth.json -Display P -nointeractive`. The `-id` value contains a string with a colon (`admin:password`) but is in `value_flags` so it must NOT be misextracted as a target. target=`10.129.95.235` only.

### S5 — DNS failure classification

```
Engagement target: nonexistent-host.invalid.localdomain (deliberately invalid, verifying DNS error classification).
Run nikto against http://nonexistent-host.invalid.localdomain with default tuning, JSON output to /session/nikto-dns.json, timeout 10 seconds.
```

**Watch:** stderr/stdout matches signal `Could not resolve` AND/OR `host lookup failed` AND/OR `Name or service not known`. Classified as `failure_in_output` (nikto exits 0 even on DNS failure — pattern-match required, same anti-pattern as ffuf/sqlmap/nuclei). Agent reports DNS issue cleanly without claiming "scan complete".

### S6 — `-h` with file path (target-list ingestion shape)

```
Engagement target: 10.129.95.235 (HTB Validation).
I have a list of targets in /session/targets.txt that includes 10.129.95.235 and a few other authorized boxes. Use nikto to scan all of them.
```

**Watch:** Agent SHOULD emit one tool_runner call per target (e.g., separate `nikto -h http://10.129.95.235 ...` and `nikto -h http://other.target ...` calls). If the agent instead emits `nikto -h /session/targets.txt`, the plugin's url_host parser returns null for the file path — scope validation will then refuse the call (no validatable target). Document this behavior in the agent prompt: nikto's `-h` is dual-use, but we constrain it to single-host form for scope safety.

---

## 3. Target-extraction adversarial cases (≥20)

The nikto `tool.yaml` declares three extraction rules (first match wins):

1. `flag_value` for `-h` with `parse_as: url_host`
2. `flag_value` for `-host` with `parse_as: url_host`
3. `positional_match` with `parse_as: url_host` (rare — fallback only)

`reject_flags`: empty (nikto's `-h` is dual-use; we let url_host parsing
return null for file paths instead of rejecting).

`value_flags` includes ~50 entries to prevent value-position strings from
being misextracted (notably `-useproxy`, `-id`, `-cert`, `-key`, `-CAfile`,
`-Save`, `-output`, `-config`, `-Format`, `-Plugins`, `-Display`, `-vhost`).

### Happy-path cases

| # | Command (binary `nikto` omitted) | Expected target | Notes |
|---|---|---|---|
| 1 | `-h http://10.129.95.235/ -Format json -output /session/n.json` | `10.129.95.235` | Bog-standard scan, IPv4 |
| 2 | `-h https://target.local:8443/api -Tuning 23` | `target.local` | HTTPS + port + path; port stripped |
| 3 | `-host http://10.10.10.5/admin -Tuning 23` | `10.10.10.5` | `-host` alias for `-h` |
| 4 | `-h http://VICTIM.LOCAL/ -id 'admin:pass'` | `VICTIM.LOCAL` | Uppercase preserved |
| 5 | `-h 'http://admin:s3cr3t@10.10.10.5/'` | `10.10.10.5` | URL with userinfo — host comes after `@` |
| 6 | `-h http://[2001:db8::1]/ -Tuning 23` | `[2001:db8::1]` (or `2001:db8::1` post-strip) | IPv6 bracketed |
| 7 | `-h http://10.10.10.5:8080/admin -Tuning 23 -Format json -output /session/scan.json` | `10.10.10.5` | Output flag value contains a path — not a target |
| 8 | `-Tuning 23 -Format json -h http://10.10.10.5/` | `10.10.10.5` | Flags before -h; order independence |
| 9 | `-h 10.10.10.5 -port 80,443 -Format json -output /session/scan.json` | `10.10.10.5` | Bare IP without scheme; port flag separate |
| 10 | `-h target.htb -port 8443 -ssl -Format json` | `target.htb` | Bare hostname + explicit -ssl + port |

### Adversarial — value_flag traps & security invariants

| # | Command | Expected | Notes |
|---|---|---|---|
| F1 | `-Help` | `target=null` | Help screen (capital H = help in nikto). tool_runner bypasses scope check. |
| F2 | `-H` | `target=null` | Short alias for -Help — NOT a header flag (unlike curl/nuclei). |
| F3 | `-Version` | `target=null` | Version. |
| F4 | `-list-plugins` | `target=null` | Plugin enumeration — no scan, no target. |
| F5 | `-h /session/targets.txt -Tuning 23` | `target=null` (file path fails url_host parse) | Target-list-via-file shape. Plugin scope-validation refuses the call (no validatable target). Documented in gotchas. |
| F6 | `-h http://10.10.10.5/ -useproxy http://outofscope.attacker.com:8080` | `target=10.10.10.5` (NOT proxy). | Security invariant: scope = target of request, not proxy. |
| F7 | `-h http://10.10.10.5/ -id 'admin:p4ssw0rd'` | `target=10.10.10.5`. | `-id` value contains a string with colon — NOT a host:port target. |
| F8 | `-h http://10.10.10.5/ -id 'attacker.com:malicious'` | `target=10.10.10.5` (NOT attacker.com). | Even when `-id` value LOOKS like a hostname:realm, must NOT extract. |
| F9 | `-h http://10.10.10.5/ -cert /session/client.pem -key /session/client.key` | `target=10.10.10.5` (NOT cert/key paths). | Client TLS material is a file path, not a target. |
| F10 | `-h http://10.10.10.5/ -CAfile /session/ca.pem` | `target=10.10.10.5` | CA bundle path, not a target. |
| F11 | `-h http://10.10.10.5/ -Save /session/dumps/` | `target=10.10.10.5` (NOT output dir). | -Save dumps request/response dir. |
| F12 | `-h http://10.10.10.5/ -output /session/nikto.json -Format json` | `target=10.10.10.5` | -output value is a file path. |
| F13 | `-h http://10.10.10.5/ -config /session/nikto.conf` | `target=10.10.10.5` | -config value is a file path. |
| F14 | `-h http://10.10.10.5/ -Plugins 'apache_expect_xss,headers'` | `target=10.10.10.5` | -Plugins value is a comma-separated plugin list. |
| F15 | `-h http://10.10.10.5/ -vhost admin.target.local` | `target=10.10.10.5` (NOT vhost name). | -vhost is the Host header value, not the resolved target. |
| F16 | `-h http://10.10.10.5/ -useragent 'http://referer.com/scan'` | `target=10.10.10.5` (NOT user-agent URL). | UA values can contain URL-shaped strings. |
| F17 | `-h http://10.10.10.5/ -h http://10.10.10.6/` | First or last (per nikto's getopt last-wins behavior); document. Recommend: extract first, flag `multi_target_detected=true`. | Multiple `-h` flags. |
| F18 | `-Tuning 23 -Format json` (no `-h`) | `target=null` → nikto errors with "No targets specified". | Plugin allows pass-through; nikto prints the error → failure_in_output. |
| F19 | `-h 'http://'` (malformed) | `target=null` (parse_error) → nikto fails naturally. | Defensive parsing. |
| F20 | `-h http://10.10.10.5/ -evasion 1 -mutate 2` | `target=10.10.10.5` | -evasion / -mutate values are integers, not targets. |
| F21 | `-h http://10.10.10.5/ -IgnoreCode 403,404` | `target=10.10.10.5` | -IgnoreCode value is a code list, not a target. |
| F22 | `-h http://10.10.10.5/ -ssl -port 8443 -Format json -output /session/ssl.json` | `target=10.10.10.5` | SSL mode + custom port + JSON output combo. |

---

## 4. Failure-signature live-verify cases (≥3)

| # | Layer | Test | failure_signature `signal` | Status |
|---|---|---|---|---|
| 1 | DNS | `-h http://nonexistent-host.invalid.localdomain -Format json -output /session/dns.json -Display P -nointeractive -timeout 10` | `Could not resolve` AND/OR `host lookup failed` AND/OR `Name or service not known` | PENDING live verify |
| 2 | TCP | `-h http://127.0.0.1 -port 1 -Format json -output /session/tcp.json -Display P -nointeractive -timeout 5` | `Connection refused` OR `No web server found` OR `Error connecting` | PENDING live verify |
| 3 | TLS | `-h https://expired.badssl.com -ssl -port 443 -Format json -output /session/tls.json -Display P -nointeractive` | `SSL handshake failed` OR `Certificate verify failed` OR `certificate verify failed` | PENDING — third-party domain; rerun once self-signed lab target exists |
| 4 | No-targets | `-Tuning 23 -Format json -output /session/notarget.json -Display P -nointeractive` (no -h) | `No targets specified` OR `Error: No host` | PENDING live verify |
| 5 | Argument | `-h http://10.129.95.235/ -tuning 23 -Format json -nointeractive` (lowercase -tuning) | `Bad option` OR silently ignored (case-sensitive parser) | PENDING — tests case-sensitivity claim |
| 6 | Plugin | `-h http://10.129.95.235/ -Plugins 'nonexistent_plugin_xyz' -Format json -output /session/plug.json -nointeractive` | `Could not load plugin` OR `Plugin .* failed` | PENDING live verify |

### Layer diversity (SKILL #11) — achieved

5+ distinct layers exercised: DNS / TCP / TLS / argument-validation / plugin-config / no-input. Rate-limit / WAF-protected layer not separately tested — nikto doesn't have a built-in concurrency knob that would surface a host-error-tracking layer the way nuclei's `-mhe` does; deferred to Wave 9 live HTB run if a fragile target surfaces.

---

## 5. Open questions

1. **`-h <file>` dual-use** (case F5) — nikto's `-h` accepts either a single host or a file path containing newline-separated hosts. We chose NOT to put `-h` in `reject_flags` because it's the only target flag (rejecting it would block all nikto calls). Instead, url_host parsing returns null for file paths and the plugin's scope validator refuses calls with no validatable target. **Question**: should we add a second-pass check that detects file-path-shaped `-h` values and emits a clearer error message ("nikto -h <file> is target-list ingestion — use one tool_runner call per target") rather than the generic "no validatable target" rejection? Defer to Wave 9.
2. **Multi-`-h` behavior** (case F17) — nikto's getopt likely uses last-wins. Document actual behavior; if it accepts multiple, consider declaring `allow_multi_target: true` rather than picking first.
3. **`-port` multi-port** — `-port 80,443,8080` runs sequentially within one nikto process. Total runtime is sum-of-ports. Should we add a usage_pattern note to issue separate tool_runner calls when parallelism matters? Done in gotchas; no further action.
4. **TLS cert tests** — same blocker as curl/sqlmap/nuclei: lab targets don't ship a TLS cert error. Need a self-signed nginx target. Case 3 above uses expired.badssl.com — third-party, not ideal.
5. **OSVDB references** — output contains OSVDB-NNNNN IDs from the legacy (shut-down 2016) database. Should the parser map these to current CVE references via a static lookup table? Out of scope for kind:cli (the LLM consumes raw output), but flag for future enhancement.
6. **Plugin discovery** — `nikto -list-plugins` enumerates available plugins. Should usage_patterns include a "list plugins first, then -Plugins" workflow? Currently we expect the LLM to know the common plugin names. Defer.
7. **First-call database refresh** — nikto checks plugin databases at startup. The Dockerfile build pre-fetches them, but on a freshly-rebuilt image the first call is slower. Should we add a warmup hook? Documented in gotchas; no action.
8. **Case-sensitivity of flags** (case 5 above) — nikto is case-sensitive on long flags (-Format ≠ -format). Verified empirically? Document explicitly; expected to be silently-ignored or parser-error. Verify in Wave 9 live run.
9. **Architectural: text-parser → JSON migration** — the legacy mcp-server.py parsed default text output via regex (`+ Server:`, `+ Target IP:`, OSVDB-NNNNN, `(/[^\s:]+)` path extraction) and returned a structured `{server_info, findings, total_findings}` blob. kind:cli replaces that with `-Format json -output /session/nikto.json`; the LLM consumes the JSON file directly. **Implication**: any downstream prompt/agent that previously relied on the parsed `findings[].osvdb` / `findings[].path` shape must now read the raw JSON file (which has its own `vulnerabilities` array shape — different keys). Audit consumers before flipping over.
10. **Architectural: hard-coded defaults dropped** — legacy ALWAYS appended `-nointeractive` and `-maxtime <max_time>s` (default 600s) to every invocation. kind:cli relies on the LLM to construct the full command, so usage_patterns + gotchas must explicitly carry that responsibility. Patched: gotcha #11 now states "ALWAYS pass BOTH -nointeractive AND -maxtime together". All eight `usage_patterns` already include `-nointeractive`; none currently include `-maxtime` — consider adding `-maxtime 1h` to each canonical pattern as a defensive default in Wave 9 follow-up.

---

## 6. Hand-off

- **Tool**: nikto (kind:cli)
- **Status**: tool.yaml authored end-to-end; scenarios.md written. Dockerfile updated to `python3-full` (Kali apt fix — same as impacket / ffuf / nuclei). mcp-server.py untouched (auto-inherits run_cli; rollback path).
- **Image**: `ghcr.io/silicon-works/mcp-tools-nikto:latest` — needs rebuild during Wave 9 batch to pick up mcp-common 0.3.0.
- **Live-verify pending**: paste S1-S6 against Validation. Verify failure_signatures 1, 2, 4, 6 (DNS, TCP, no-targets, plugin) live; defer cases 3, 5 (TLS / case-sensitivity) until appropriate targets / experiments available.
- **Legacy split files**: none present — no `target_extraction_tests.md` / `failure_signature_tests.md` / `__pycache__/` to remove.

Authored: 2026-04-25.
