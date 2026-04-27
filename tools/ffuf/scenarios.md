# ffuf — Tier A scenarios

Single test sheet for the `ffuf` tool migration (Wave 1.2, Feature 35 Tier A).
Replaces any legacy split (`target_extraction_tests.md` +
`failure_signature_tests.md` if they had been created).

Sections:
1. Recommended HTB box for live verification
2. Narrative scenarios (paste into opensploit)
3. Target-extraction adversarial cases (≥20)
4. Failure-signature live-verify cases (≥3)
5. Open questions
6. Hand-off

---

## 1. Recommended HTB box

**Primary: Validation (10.129.95.235)** — Linux box with Apache + PHP serving
real paths (`/account.php`, asset folders, etc.). Provides clean targets for
both happy-path discovery (S1, S2) and failure classification (S5, S6).
Already in the curl/sqlmap/nmap pilot rotation, so VPN + container network +
/session mount are already exercised.

**Alternate: Cap (10.10.10.245)** — also Linux + HTTP, has known-discoverable
paths for directory enumeration. Good fallback if Validation is offline.

### Tuning notes (ffuf-specific)

ffuf is **noisy by default**: every status code in the default `-mc` list
(200, 204, 301, 302, 307, 401, 403) is a "match". Without filters, scanning a
typical lab target produces dozens of false positives from soft-404 / catch-all
handlers. Two essential approaches:

1. **Baseline-then-filter**: curl the target root first to learn the default
   response size, then pass `-fs <size>` to filter that exact size out. Used
   for vhost / parameter discovery.
2. **Auto-calibrate**: pass `-ac` and ffuf probes a few random paths to
   baseline the noise itself. Faster, less surgical. Good first attempt.

The narrative scenarios below assume the agent makes a baseline call (S1.b
sub-step) before running the noisy enum.

### Wordlists available in the image

Image installs `dirb`, `seclists`, plus its own wordlist directory. Realistic
paths the agent should know:

- `/usr/share/dirb/wordlists/common.txt` (4,614 entries)
- `/usr/share/dirb/wordlists/big.txt` (20,469)
- `/usr/share/dirb/wordlists/small.txt` (959)
- `/usr/share/seclists/Discovery/Web-Content/common.txt`
- `/usr/share/seclists/Discovery/Web-Content/directory-list-2.3-small.txt` (87,650)
- `/usr/share/seclists/Discovery/Web-Content/directory-list-2.3-medium.txt` (220,546)
- `/usr/share/seclists/Discovery/Web-Content/raft-small-words.txt`
- `/usr/share/seclists/Discovery/Web-Content/raft-medium-words.txt`
- `/usr/share/seclists/Discovery/Web-Content/burp-parameter-names.txt`
- `/usr/share/seclists/Discovery/DNS/subdomains-top1million-5000.txt`

---

## 2. Narrative scenarios (paste into opensploit)

### S1 — Directory enumeration on Validation root

```
Engagement target: 10.129.95.235 (HTB Validation, authorized).
Run ffuf to discover hidden files/directories under http://10.129.95.235/.
Use /usr/share/seclists/Discovery/Web-Content/common.txt as the wordlist.
Filter out 404 responses. Save the JSON report to /session/ffuf-dir.json.
Use 40 threads. Report the discovered paths with status codes.
```

**Watch:** Agent emits clean argv:
`ffuf -u http://10.129.95.235/FUZZ -w /usr/share/seclists/Discovery/Web-Content/common.txt -fc 404 -t 40 -of json -o /session/ffuf-dir.json`.
First call ~5–10 s container spawn + scan-start; full run 30–90 s on
common.txt against Validation. /session/ffuf-dir.json materializes.
JSON has `commandline`, `time`, `results[]` with `status`, `length`, `input.FUZZ`.

### S2 — GET parameter discovery (baseline + ffuf)

```
Engagement target: 10.129.95.235 (HTB Validation, authorized).
First, curl http://10.129.95.235/account.php and report the response size in bytes — I need a baseline before fuzzing.
Then run ffuf to discover hidden GET parameter NAMES on that endpoint. Use the URL http://10.129.95.235/account.php?FUZZ=test, with the wordlist /usr/share/seclists/Discovery/Web-Content/burp-parameter-names.txt. Filter out responses matching the baseline size (use -fs <size> with the baseline size from the curl call). Save JSON to /session/ffuf-params.json.
```

**Watch:** Agent makes TWO tool calls: first curl (one-shot probe to get
Content-Length), second ffuf with `-fs <baseline>`. The chain demonstrates
that the LLM understands ffuf's filter-tuning workflow. Discovered params
return DIFFERENT response sizes from the baseline.

### S3 — VHost discovery via Host header fuzzing

```
Engagement target: 10.129.95.235 (HTB Validation, authorized).
First, curl http://10.129.95.235/ with no Host header override and report the response size. This is the default-vhost baseline.
Then run ffuf to discover virtual hosts by fuzzing the Host header. URL is http://10.129.95.235, wordlist is /usr/share/seclists/Discovery/DNS/subdomains-top1million-5000.txt. Filter responses matching the baseline size. Save JSON to /session/ffuf-vhost.json. Use the URL itself unchanged (FUZZ goes into the Host header, not the URL).
```

**Watch:** Agent emits
`ffuf -u http://10.129.95.235 -H 'Host: FUZZ.htb' -w .../subdomains... -fs <baseline> -of json -o /session/ffuf-vhost.json`.
**Critical**: target must be extracted from `-u`, NOT from the `-H 'Host: FUZZ.htb'`.
Host header is an override, not a connection target — see extraction case 7.

### S4 — POST body fuzz with rate-limiting

```
Engagement target: 10.129.95.235 (HTB Validation, authorized).
Test the login endpoint http://10.129.95.235/login.php for credential stuffing.
Use ffuf to fuzz the password field of a POST body username=admin&password=FUZZ.
Wordlist is /usr/share/seclists/Passwords/Common-Credentials/10-million-password-list-top-100.txt
(top-100 to keep it short). Throttle to 10 threads with rate cap 50 req/sec
to avoid lockouts. Filter 401 responses (expected failures). Save JSON to /session/ffuf-post.json.
Set Content-Type: application/x-www-form-urlencoded.
```

**Watch:** Agent emits POST with Content-Type, body with FUZZ, throttled
threads + rate. `ffuf -u http://10.129.95.235/login.php -X POST -d 'username=admin&password=FUZZ' -H 'Content-Type: application/x-www-form-urlencoded' -w /usr/share/seclists/Passwords/Common-Credentials/10-million-password-list-top-100.txt -t 10 -rate 50 -fc 401 -of json -o /session/ffuf-post.json`.
Confirms POST + body fuzzing pipeline works end-to-end.

### S5 — Failure classification: missing wordlist

```
Engagement target: 10.129.95.235 (HTB Validation, authorized).
Run ffuf with -u http://10.129.95.235/FUZZ and wordlist /tmp/nonexistent-wordlist.txt
(this file deliberately does not exist — verifying error classification).
Report the failure mode.
```

**Watch:** ffuf exits nonzero with stderr containing `Could not open` or
`wordlist file not found`. tool_runner classifier matches `failure_signatures`
entry for the wordlist layer. Agent reports cleanly without retrying with
the same path.

### S6 — `-request` reject_flags trap

```
Engagement target: 10.129.95.235 (HTB Validation, authorized).
I previously captured an HTTP request to /session/captured-req.txt.
Use ffuf with -request /session/captured-req.txt and -request-proto http
to fuzz the captured request — it has FUZZ markers in it.
```

**Watch:** Plugin rejects the call before container spawn with
`status: error`, `rejected_flag: -request`, reason quoted from
`reject_flags_reason`. **Per the new tool-runner prompt clause**: agent
reformulates with `-u <url>` after reading the captured file via the
read tool to extract the URL. If the agent has no fallback URL, it
returns a clear "phase agent must provide URL" error.

---

## 3. Target-extraction adversarial cases (≥20)

The ffuf `tool.yaml` declares one extraction rule:

1. `flag_value` with `flag: -u`, `parse_as: url_host` — extract host from the
   URL passed to `-u`.

The DSL relies on the `value_flags` list to know which flags consume the
next argv token. Misses there cause the DSL to misidentify proxy URLs,
wordlist paths, replay-proxy URLs, etc., as targets. The `-request` flag
is rejected before extraction even runs.

### Happy-path cases

| # | Command (binary `ffuf` omitted) | Expected target | Notes |
|---|---|---|---|
| 1 | `-u http://10.10.10.5/FUZZ -w /usr/share/dirb/wordlists/common.txt` | `10.10.10.5` | Bog-standard FUZZ-in-path |
| 2 | `-u https://target.htb/FUZZ -w /tmp/wl.txt -fc 404 -of json -o /session/r.json` | `target.htb` | Standard with filtering and output flags |
| 3 | `-u http://10.10.10.5:8080/api/FUZZ -w /tmp/wl.txt` | `10.10.10.5` | host:port — port stripped |
| 4 | `-u 'http://10.10.10.5/page?id=FUZZ' -w /tmp/values.txt` | `10.10.10.5` | FUZZ in query string |
| 5 | `-u 'http://10.10.10.5/page?FUZZ=test' -w /tmp/params.txt -fs 1234` | `10.10.10.5` | FUZZ as parameter NAME |
| 6 | `-u https://FUZZ.target.htb/ -w /tmp/subs.txt -fc 404` | `FUZZ.target.htb` | Subdomain fuzz: FUZZ literally appears in host. **Open question**: should DSL pre-strip FUZZ before scope check? See section 5. |
| 7 | `-u http://10.10.10.5 -H 'Host: FUZZ.target.htb' -w /tmp/subs.txt -fs 1234` | `10.10.10.5`, NOT `FUZZ.target.htb` | **Critical security invariant**: target is the connection destination (URL host), NOT the Host-header override. Same shape as curl F5. |
| 8 | `-u https://target.htb/ -H 'Authorization: Bearer abc' -H 'X-Test: 1' -w /tmp/wl.txt` | `target.htb` | Multiple custom headers — none should be picked as target |
| 9 | `-u https://VICTIM.LOCAL/FUZZ -w /tmp/wl.txt` | `VICTIM.LOCAL` | Uppercase host preserved (TargetValidation lowercases) |
| 10 | `-u https://admin:s3cr3t@10.10.10.5/dav/FUZZ -w /tmp/wl.txt` | `10.10.10.5` | URL with embedded userinfo — host comes after `@` |
| 11 | `-u 'http://[2001:db8::1]/FUZZ' -w /tmp/wl.txt` | `[2001:db8::1]` (or `2001:db8::1` after brackets stripped by TargetValidation) | IPv6 literal bracketed |
| 12 | `-u http://10.10.10.5/FUZZ -X POST -d 'username=admin&password=test' -H 'Content-Type: application/x-www-form-urlencoded' -w /tmp/wl.txt` | `10.10.10.5` | POST with body — body params not confused for target |
| 13 | `-u http://10.10.10.5/login -X POST -d 'username=admin&password=FUZZ' -w /tmp/passwd.txt -t 10 -rate 100` | `10.10.10.5` | POST body fuzzing (FUZZ in -d, NOT in URL) — target is still URL host |
| 14 | `-u http://10.10.10.5/FUZZ -w /usr/share/seclists/Discovery/Web-Content/raft-medium-words.txt:WORD -mode pitchfork` | `10.10.10.5` | Custom keyword on wordlist (`:WORD`) |
| 15 | `-u 'http://10.10.10.5/api?PARAM=VAL' -w /tmp/params.txt:PARAM -w /tmp/values.txt:VAL -mode clusterbomb` | `10.10.10.5` | Multi-FUZZ with two wordlists + custom keywords |
| 16 | `-u http://10.10.10.5/FUZZ -w /tmp/wl.txt -recursion -recursion-depth 2` | `10.10.10.5` | Recursion flags don't shift target |
| 17 | `-u https://target.htb/FUZZ -w /tmp/wl.txt -timeout 30 -maxtime 600 -maxtime-job 60` | `target.htb` | Multiple integer-value flags |
| 18 | `-u http://10.10.10.5/FUZZ -w /tmp/wl.txt -mc 200,301 -fc 404 -fs 0 -fw 10 -fl 5 -ft 100` | `10.10.10.5` | Full filter/matcher set |
| 19 | `-u http://10.10.10.5/FUZZ -w /tmp/wl.txt -ac -acc 'admin' -ach -ack FUZZ` | `10.10.10.5` | Auto-calibration flags |
| 20 | `-u http://10.10.10.5/FUZZ -w /tmp/wl.txt -input-cmd 'seq 1 100' -input-num 100 -mode pitchfork` | `10.10.10.5` | input-cmd value is a shell command, not a host |
| 21 | `-u https://target.htb/FUZZ -E /tmp/cert.pem -w /tmp/wl.txt -cc /tmp/client.crt -ck /tmp/client.key` | `target.htb` | Client cert/key — paths, not hosts |

### Adversarial cases (DSL must NOT pick the wrong token)

| # | Command | Expected behaviour | Notes |
|---|---|---|---|
| F1 | `-u http://10.10.10.5/FUZZ -x http://proxy.local:8080 -w /tmp/wl.txt` | target=`10.10.10.5`, NOT `proxy.local` | **Critical**: -x value is a proxy URL. value_flags must list `-x`. |
| F2 | `-u http://10.10.10.5/FUZZ -replay-proxy http://burp.local:8080 -w /tmp/wl.txt` | target=`10.10.10.5`, NOT `burp.local` | -replay-proxy value is a URL. value_flags must list `-replay-proxy`. |
| F3 | `-u http://10.10.10.5/FUZZ -b 'redirect=https://other.target/path; sess=abc' -w /tmp/wl.txt` | target=`10.10.10.5`, NOT `other.target` | Cookie value contains URL-shaped substring — but -b is a value_flag, not extractable. |
| F4 | `-u http://10.10.10.5/FUZZ -H 'Referer: https://referer.evil/' -w /tmp/wl.txt` | target=`10.10.10.5`, NOT `referer.evil` | -H value contains a URL — -H is a value_flag. |
| F5 | `-u http://10.10.10.5/FUZZ -H 'X-Forwarded-For: 10.10.10.99' -w /tmp/wl.txt` | target=`10.10.10.5`, NOT `10.10.10.99` | XFF header IP — header value, not connection target. |
| F6 | `-u http://10.10.10.5 -H 'Host: real.target.com' -w /tmp/wl.txt` | target=`10.10.10.5`, NOT `real.target.com`. **Critical**: scope is by network destination, not Host-header override. Otherwise an LLM could SSRF an in-scope IP and pretend to target an out-of-scope domain. | Same as case 7 above — duplicated for emphasis. |
| F7 | `-u http://10.10.10.5/FUZZ -w https://wordlist.host/words.txt` | target=`10.10.10.5`, NOT `wordlist.host`. ffuf doesn't actually fetch URLs as wordlists; this would fail at file-open. But the DSL must NOT extract the wordlist path either way. | -w is a value_flag, never an extraction source. |
| F8 | `-u http://10.10.10.5/FUZZ -w /tmp/wl.txt -d 'callback=https://decoy.com/cb' -X POST` | target=`10.10.10.5`, NOT `decoy.com` | URL inside POST body — body is data, not target. |
| F9 | `-u http://10.10.10.5/FUZZ -d '{"webhook":"https://hook.evil/r"}' -X POST -H 'Content-Type: application/json'` | target=`10.10.10.5`, NOT `hook.evil` | JSON body with URL field — same shape, different encoding. |
| F10 | `-u http://10.10.10.5/FUZZ -w /tmp/wl.txt -o /session/results-https-target.json -of json` | target=`10.10.10.5`, NOT anything in the output filename | Output filename contains `https` substring — must NOT match URL regex. |
| F11 | `-u http://10.10.10.5/FUZZ -w /tmp/wl.txt -of json -o /session/r.json -od /session/responses/` | target=`10.10.10.5` | -od (response dump dir) value is a path, not a host. |
| F12 | `-u http://10.10.10.5/FUZZ -w /tmp/wl.txt -debug-log /session/debug.log -config /tmp/ffuf.conf` | target=`10.10.10.5` | -debug-log and -config values are paths. |
| F13 | `-u http://10.10.10.5/FUZZ -w /tmp/wl.txt -t 40 -rate 200 -p 0.1-2.0 -timeout 30` | target=`10.10.10.5` | All numeric / range value flags — none look URL-shaped. |
| F14 | `-u http://10.10.10.5/FUZZ -w /tmp/wl.txt -mr 'error\\|denied' -fr 'forbidden'` | target=`10.10.10.5` | Regex value flags — text patterns, not hosts. |
| F15 | `-u http://10.10.10.5/FUZZ -w /tmp/wl.txt -mode clusterbomb -fmode and` | target=`10.10.10.5` | -mode / -fmode take enum values, not hosts. |
| F16 | `-u http://10.10.10.5/FUZZ -w /tmp/wl.txt -recursion-strategy greedy -recursion-depth 3` | target=`10.10.10.5` | -recursion-strategy and -recursion-depth take enum/int values. |
| F17 | `-V` | target=null → tool.execute.before allows (no target → no scope check) | Pure version check. |
| F18 | `-h` | target=null | Help dump. |
| F19 | (empty argv) | target=null → ffuf will error with "no FUZZ keyword" / "no -u flag" | Same shape as F17/F18. |
| F20 | `-w /tmp/wl.txt -fc 404` | target=null → ffuf will error "Encountered error(s): no -u" | Missing -u — DSL has nothing to extract from. |
| F21 | `-request /session/captured.txt -request-proto http -w /tmp/wl.txt` | Plugin rejects via `reject_flags`. `rejected_flag=-request`. Per new tool-runner prompt: agent reads the file, extracts URL, and reformulates with `-u <url>`. | -request is rejected. |
| F22 | `-u https://` | target=null → DSL parse_error → ffuf fails naturally | Defensive parsing. |
| F23 | `-u http://10.10.10.5/FUZZ -w /tmp/wl1.txt:HOST -w /tmp/wl2.txt:DOMAIN -u https://HOST.DOMAIN/` | LAST -u wins (Go flag parsing semantics) — target=`HOST.DOMAIN`. **Open question**: should DSL flag the duplicate -u or take last? See section 5. | Multiple -u flags. |
| F24 | `-u http://10.10.10.5/FUZZ -w /tmp/wl.txt -mc all -ms 1024 -mw 50 -ml 20` | target=`10.10.10.5` | -mc value `all` is a literal string, not a code — must not confuse parser. |
| F25 | `-u http://10.10.10.5/FUZZ -w /tmp/wl.txt -X PUT -d @/session/payload.bin` | target=`10.10.10.5` | -X enum value, -d with `@file` shorthand. |

---

## 4. Failure-signature live-verify cases (≥3)

Run via opensploit; verify the result hits a `failure_signatures` entry.
Live-verification status will be filled in once these are run on Validation
(2026-04-26+). Until then, they're authored from documentation + ffuf v2.x
help; SKILL #5 requires re-checking against the actual container image.

| # | Test | Command (post-binary) | Expected exit | Expected stderr/stdout substring | failure_signature `signal` | Status |
|---|---|---|---|---|---|---|
| 1 | DNS resolution failure | `-u http://nonexistent.invalid.localdomain/FUZZ -w /usr/share/dirb/wordlists/common.txt -timeout 5` | nonzero | `lookup nonexistent.invalid.localdomain: no such host` | `lookup` AND `no such host` | AUTHORED — verify on container |
| 2 | Connection refused | `-u http://10.129.95.235:1/FUZZ -w /usr/share/dirb/wordlists/common.txt -timeout 3` | nonzero (or 0 with errors logged) | `connect: connection refused` | `connection refused` | AUTHORED — verify; ffuf may aggregate errors and exit 0 if any matches were found |
| 3 | Connection timeout | `-u http://10.255.255.254/FUZZ -w /usr/share/dirb/wordlists/common.txt -timeout 2 -maxtime 10` | nonzero on -maxtime | `i/o timeout` AND `Maximum running time` | `i/o timeout` and `Maximum running time` | AUTHORED — verify |
| 4 | TLS cert error | `-u https://10.129.95.235/FUZZ -w /usr/share/dirb/wordlists/common.txt -timeout 5` (assumes self-signed or no TLS on Validation) | nonzero | `x509:` OR `certificate signed by unknown authority` | `x509:` | AUTHORED — depends on Validation having HTTPS endpoint with self-signed cert |
| 5 | Wordlist not found | `-u http://10.129.95.235/FUZZ -w /tmp/nonexistent-wordlist.txt` | nonzero | `Could not open file` OR `wordlist file not found` | `Could not open file` | AUTHORED — high-priority verify (file-layer signal) |
| 6 | Empty wordlist | `-u http://10.129.95.235/FUZZ -w /tmp/empty.txt` (after `: > /tmp/empty.txt`) | nonzero | `Wordlist is empty` | `Wordlist is empty` | AUTHORED — verify |
| 7 | URL missing FUZZ keyword | `-u http://10.129.95.235/ -w /usr/share/dirb/wordlists/common.txt` | nonzero | `No FUZZ keyword` OR `URL contains no FUZZ keyword` | `No FUZZ keyword` | AUTHORED — verify (param-validation layer) |
| 8 | Filter/matcher conflict | `-u http://10.129.95.235/FUZZ -w /tmp/wl.txt -mc 200 -fc 200` | nonzero | `matcher and filter configuration is in conflict` | `matcher and filter configuration is in conflict` | AUTHORED — verify; depends on whether v2.x detects this at parse time |
| 9 | Missing keyword in multi-wordlist | `-u http://10.129.95.235/FUZZ -w /tmp/wl1.txt:WORD1 -w /tmp/wl2.txt:WORD2` (URL has FUZZ, wordlists have WORD1/WORD2) | nonzero | `missing keyword from` | `missing keyword from` | AUTHORED — verify |

### Lessons to encode after live verification

1. **ffuf may exit 0 even on hard errors per-request** — if at least one
   request succeeded out of the wordlist, ffuf can still exit 0 with errors
   for the failed requests in stderr. tool_runner classifier MUST pattern-match
   the signals against output regardless of exit code (same shape as sqlmap
   and nmap). Encode as a `gotcha` in tool.yaml.
2. **Go's net.Lookup error format drift** — `lookup HOSTNAME: no such host`
   is the modern phrasing. Older Go versions used `lookup HOSTNAME on RESOLVER:
   no such host` (with resolver IP in the middle). Both signals listed.
3. **Connection-refused phrasing** — Go uses `connect: connection refused`
   while curl uses `Connection refused`. Listed both forms.
4. **TLS cert phrasing** — `x509:` is the prefix; specific suffixes vary
   (`x509: certificate signed by unknown authority`, `x509: certificate has
   expired`, `x509: certificate is valid for ..., not ...`). Match on the
   prefix.

---

## 5. Open questions

1. **FUZZ in target host (case 6)** — when the agent emits
   `-u https://FUZZ.target.htb/`, the DSL extracts host as
   `FUZZ.target.htb`. Should the plugin's TargetValidation pre-strip the
   `FUZZ.` prefix before scope check, or treat `*.target.htb` as a wildcard
   match? Current behaviour is unclear. Recommendation: TargetValidation
   should special-case the literal `FUZZ.` prefix on subdomain fuzzing.
2. **Multiple -u flags (case F23)** — Go's flag parser uses last-wins
   semantics. If the agent emits two `-u` flags, the DSL's `flag_value`
   rule needs a defined precedence. Recommendation: take last-wins (matches
   ffuf's actual parse). Document explicitly.
3. **Wordlist scope** — wordlists are local files; `-w` is a value_flag,
   not extracted. But what if the agent emits `-w https://attacker/wl.txt`?
   ffuf doesn't fetch URLs as wordlists, so the request fails at file-open.
   But should the plugin pre-validate that `-w` values look like local paths?
   Probably overkill — let ffuf fail naturally.
4. **TLS cert tests (failure case 4)** — Validation may not serve HTTPS,
   making the TLS test inert. Need a self-signed lab target before we can
   live-verify. Same blocker as curl Wave 1 (Open Questions 4).
5. **ffuf exit-code semantics** — does ffuf exit 0 when ALL requests fail
   (e.g., TCP refused on every URL)? Or only when at least one matched?
   Need to live-verify; affects tool_runner's classifier strategy.
6. **Recursion + reject_flags interaction** — when `-recursion` is set,
   ffuf spawns sub-jobs that issue more requests with paths discovered.
   Does the plugin's tool-runner re-validate the spawned URLs, or trust
   the original `-u` extraction? Recommendation: trust original; recursion
   is bounded to the same authority by ffuf design.
7. **Header value containing FUZZ as the placeholder vs. as data** — when
   `-H 'X-Forwarded-For: FUZZ'` is the fuzzing position, `FUZZ` is the
   placeholder. When `-H 'X-Real-IP: 10.10.10.99'` is data, the value is
   literal. The DSL doesn't need to distinguish — it ignores -H values.
   But document that scope validation is `-u`-driven only.

---

## 6. Hand-off

- **Tool**: ffuf (kind:cli)
- **Status**: Tier-A migrated; scenarios consolidated; tool.yaml rewritten
  from kind:mcp methods to kind:cli with target_extraction / value_flags /
  reject_flags / output_formats / failure_signatures sections. No image
  rebuild yet (deferred to Wave 9 batch). mcp-server.py untouched.
- **mcp-server.py**: present, untouched — auto-inherits run_cli from
  BaseMCPServer (mcp-common 0.3.0); preserves rollback path per SKILL #21.
  Legacy methods (dir_fuzz, param_fuzz, vhost_fuzz) remain available for
  kind:mcp callers that prefer structured params.
- **Dockerfile**: verified — Kali base + ffuf + dirb + seclists + Python
  venv + mcp-common install + CMD `python3 mcp-server.py`. No changes
  needed; Kali base is acceptable for ffuf because it ships seclists out
  of the box (saves a custom layer).
- **Image**: `ghcr.io/silicon-works/mcp-tools-ffuf:latest` — rebuild
  deferred to Wave 9 (batch rebuild).
- **Removed**: `__pycache__/` (build artifact; not committed in clean
  source tree). No legacy `target_extraction_tests.md` /
  `failure_signature_tests.md` files existed to remove.
- **Live-verify pending**: paste S1–S6 against Validation (10.129.95.235);
  verify failure_signature entries 1–9 still match (esp. layer-diverse
  signals — ffuf v2.x phrasing may have drifted from v1.x); confirm the
  -request reject_flags trap fires correctly through the plugin.
- **Pilot-gate sign-off**: ≥9 deliberate-failure tests authored (covering
  DNS, TCP, TLS, file, param-validation, output-validation layers — SKILL
  #11 layer-diversity); ≥25 extraction cases authored covering the proxy
  / replay-proxy / cookie / header / wordlist URL traps (SKILL #12);
  gotchas updated for default-noisy behaviour and v2.x flag-spelling.
- **Open questions surfaced**: see section 5 — FUZZ-in-host scope handling,
  multiple-u precedence, wordlist URL guard, HTTPS lab target for TLS
  failure verify, ffuf exit-code semantics, recursion scope re-validation,
  -H value scoping.

Authored: 2026-04-25 (Wave 1.2 Tier A migration).
