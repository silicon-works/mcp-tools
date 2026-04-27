# curl — Tier A scenarios

Single test sheet for the `curl` tool migration. Replaces the legacy split
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

**Primary: Validation (10.129.95.235)** — Linux box with Apache + PHP. Exposes a
country-selector form that we've already confirmed reachable. Surfaces clean
HTTP behaviour (200, 4xx, exit-7 on closed ports) for failure-classification tests.

**Alternate: Cap (10.10.10.245)** — also Linux + HTTP, exercises the same
behaviour. Pick whichever you can spawn.

Note: TLS-cert tests are NOT covered here because lab targets don't ship a
public-cert-error endpoint. Re-run those once a self-signed nginx target is
available (see Open Questions).

---

## 2. Narrative scenarios (paste into opensploit)

### S1 — basic GET probe + persistence

```
Engagement target: 10.129.95.235 (HTB Validation, authorized).
Use curl to fetch http://10.129.95.235/ and save the response body to /session/validation-root.html. Report the HTTP status code, content length, and Server header.

Then do a second curl call: HEAD-only probe of the same URL, save headers to /session/validation-head.txt.
```

**Watch:** First call ~3-5 s (container spawn + MCP handshake). Second call near-instant — warm container reuse.

### S2 — POST with form body

```
Engagement target: 10.129.95.235 (HTB Validation, authorized).
POST to http://10.129.95.235/account.php with form data "username=admin&password=test" and Content-Type application/x-www-form-urlencoded. Save full response (status line + headers + body) to /session/validation-login.txt. Use --max-time 30.
```

**Watch:** Agent emits clean argv: `curl -sS -i -X POST -H 'Content-Type: ...' -d 'username=...&password=...' --max-time 30 -o /session/validation-login.txt http://10.129.95.235/account.php`. No structured-method schema artifacts.

### S3 — JSON POST with custom headers

```
Engagement target: 10.129.95.235.
POST a JSON body {"id":1, "action":"probe"} to http://10.129.95.235/api/data with header "X-Test: 1" and Authorization "Bearer test". Save full response (status + headers + body) to /session/validation-api.txt. Use --max-time 30.
```

**Watch:** Multi-header composition works. JSON is shell-quoted correctly. No literal `2>&1 | tee` since shell metacharacters do not work in cli_in_container args.

### S4 — DNS failure classification

```
Engagement target: nonexistent-host.invalid.localdomain (deliberately invalid, verifying error classification).
Use curl to GET the URL with --max-time 5. Report what failure mode you classify this as.
```

**Watch:** `failure_in_output` or `non_zero_exit=6` with stderr containing "Could not resolve host". failure_signature matches.

### S5 — Connection refused classification

```
Engagement target: 10.129.95.235 port 1 (closed port — verifying error classification).
Use curl with --max-time 5 --connect-timeout 3 to GET http://10.129.95.235:1/. Report the failure classification.
```

**Watch:** exit 7. stderr matches `Couldn't connect to server` / `Failed to connect to`. Agent retries once if remediation hint applies, then accepts.

---

## 3. Target-extraction adversarial cases (≥20)

The curl `tool.yaml` declares two extraction rules:

1. `positional_match` with regex `^(https?|ftp|ftps|file|gopher|telnet|dict|ldap|ldaps|scp|sftp|smb|smbs|imap|imaps|pop3|pop3s|smtp|smtps|tftp|rtsp|rtmp|wss?)://([^:/?#]+)`, capture group 2
2. `flag_value` with `flag: --url`, `parse_as: url_host`

**First match wins.** Rule 1 inspects every positional in order; rule 2 fires only if no positional matches.

| # | Command (binary `curl` omitted) | Expected target | Notes |
|---|---|---|---|
| 1 | `-sS -o /session/out https://example.com/path` | `example.com` | Bog standard, trailing path |
| 2 | `-sSI http://10.10.10.5/` | `10.10.10.5` | IPv4 literal |
| 3 | `-sS http://10.129.206.176:8080/admin` | `10.129.206.176` | host:port — must drop port |
| 4 | `-sS -L https://target.local:443/api/v1/users?id=1&name=foo` | `target.local` | port + query string |
| 5 | `-sS -o /tmp/r.html http://[2001:db8::1]/` | `[2001:db8::1]` (or `2001:db8::1` after stripping) | IPv6 literal — see Open Questions |
| 6 | `-sS -X POST -d 'cmd=id' http://VICTIM.LOCAL/cmd.php` | `VICTIM.LOCAL` | Uppercase host preserved (validation hook lowercases) |
| 7 | `-sS -u admin:s3cr3t https://10.10.10.5/dav/` | `10.10.10.5` | URL with no userinfo (creds via -u) |
| 8 | `-sS https://admin:s3cr3t@10.10.10.5/dav/` | `10.10.10.5` | URL with userinfo embedded — host comes after @ |
| 9 | `-sS -k --tlsv1.2 https://expired.cert.target/` | `expired.cert.target` | Multiple flags before URL |
| 10 | `-sS --url https://flag-form.target/api -H 'X: y'` | `flag-form.target` | URL via --url flag (rule 2 fires) |
| 11 | `-sS -d 'a=1' --data-binary @/session/payload.bin https://api.target/upload` | `api.target` | Mixed -d and --data-binary; URL last |
| 12 | `-sS -F 'file=@/session/shell.php' http://10.10.10.5/upload.php` | `10.10.10.5` | Multipart upload |
| 13 | `-sS -b /session/cookies.txt -c /session/cookies.txt -L https://app.target/redirect` | `app.target` | Cookie jar paths must be filtered as flag args |
| 14 | `-sS -A 'Mozilla/5.0' -e 'https://referer.evil/' https://victim.target/` | `victim.target` | Referer (a URL) as flag value — final positional wins |
| 15 | `-sS --proxy http://proxy.local:8080 -o /session/r https://final.target/api` | `final.target` | Proxy URL as flag value — final positional is target |
| 16 | `-vv -o /session/page http://10.10.10.5/users/?q=' OR 1=1 --` | `10.10.10.5` | SQLi payload in query — host extraction not confused |
| 17 | `-sS -X PUT --data-binary @/etc/passwd https://target.htb/wp-content/uploads/x` | `target.htb` | Path with /uploads (no host confusion) |
| 18 | `-sS --negotiate -u : https://exchange.corp.local/EWS/Exchange.asmx` | `exchange.corp.local` | Kerberos auth; long FQDN |
| 19 | `-sS --socks5 127.0.0.1:1080 -o /session/r http://internal-only.target/admin` | `internal-only.target` | Pivot via SOCKS — final URL is the real target |
| 20 | `-sS -X POST -H 'Content-Type: application/json' -d '{"url":"http://decoy/"}' https://api.victim.com/v2/scan` | `api.victim.com` | Decoy URL inside JSON body — must NOT match; positional URL wins |
| 21 | `-sS http://10.10.10.5/foo http://10.10.10.6/bar` | `10.10.10.5` (first), `multi_target_detected=true` | Multi-URL — DSL flags multi_target; cli_in_container rejects unless allow_multi_target |
| 22 | `-sS -d 'name=value' http://10.10.10.5/login.php?next=/admin` | `10.10.10.5` | POST with query string in URL |
| 23 | `-sS http://target.local` | `target.local` | URL with no path or trailing slash |
| 24 | `-sS ftp://files.target.local/pub/` | `files.target.local` | FTP scheme |
| 25 | `-sS smbs://10.10.10.5/share/file.txt` | `10.10.10.5` | smbs scheme (curl supports SMB) |

### Adversarial / failure cases (DSL must reject or fall back)

| # | Command | Expected behaviour | Notes |
|---|---|---|---|
| F1 | `--version` | target=null → tool.execute.before allows (no target → no validation) | Pure version check |
| F2 | `-sS -o /session/r file:///etc/passwd` | target=null (file:// has empty authority) | Local file read, no network egress |
| F3 | `-sS https://` | target=null → DSL parse_error → curl fails naturally with clear error | Defensive parsing |
| F4 | `-sS  ` (no URL) | target=null → curl fails with "no URL specified" → exit nonzero | Same shape as F1 |
| F5 | `-sS -H 'Host: real.target.com' http://10.10.10.5/` | target=`10.10.10.5`, NOT `real.target.com`. **Critical security invariant**: scope is by network destination, not Host-header override. Otherwise an LLM could SSRF an in-scope IP and pretend to target an out-of-scope domain. | DSL must extract from URL, never from `-H Host:` |

---

## 4. Failure-signature live-verify cases (≥3)

Run each via opensploit (paste the prompt) and verify the result hits the
`failure_signatures` entry in `tool.yaml`. Each test produces an exit code,
a stderr message, and a `signal` substring the tool.yaml MUST contain.

| # | Test | Command (post-binary) | Expected exit | Expected stderr substring | failure_signature `signal` field | Status |
|---|---|---|---|---|---|---|
| 1 | DNS resolution failure | `-sS --max-time 5 https://nonexistent-host.invalid.localdomain/` | 6 | `Could not resolve host` | `Could not resolve host` | VERIFIED (2026-04-23) |
| 2 | Connection refused | `-sS --max-time 5 --connect-timeout 3 http://127.0.0.1:1/` | 7 | `Couldn't connect to server` / `Failed to connect to` | `Couldn't connect to server` AND `Failed to connect to` | VERIFIED — original signal `Connection refused` was broadened after live test |
| 3 | Connection timeout | `-sS --max-time 3 --connect-timeout 2 http://10.255.255.254:80/` | 28 | `Timeout was reached` / `Connection timed out` | `Timeout was reached` AND `Connection timed out` | VERIFIED — original signal `Operation timed out` was broadened after live test |
| 4 | TLS cert error | `-sS https://expired.badssl.com/` | 60 | `SSL certificate problem` | `SSL certificate problem` | NOT RUN — third-party domain; rerun once self-signed lab target exists |
| 5 | 401 Unauthorized (with `-f`) | `-sSf https://10.129.95.235/admin` | 22 | `error: 401` | `error: 401` | TENTATIVE — depends on Validation having a 401 endpoint |

### Lesson recorded (encode in `tool.yaml` gotchas)

curl's stderr text drifts between versions. Live signature authoring requires
running against the actual container image. Failure signatures derived from
docs alone will miss "Couldn't connect to server" vs "Connection refused" and
"Timeout was reached" vs "Operation timed out".

---

## 5. Open questions

1. **Multi-URL handling (case 21)** — current decision: cli_in_container rejects multi-URL invocations unless tool.yaml declares `allow_multi_target: true`. Phase agent splits into separate tool_runner calls. ✅ Implemented in plugin.
2. **IPv6 brackets (case 5)** — DSL currently captures `[2001:db8::1]` *with* brackets. The plugin's TargetValidation strips brackets before passing to scope check. Document explicitly in `target-extraction.ts`.
3. **Host-header override (case F5)** — security invariant: extract target from URL authority, never from `-H 'Host: ...'`. Encoded in `target-extraction.ts` documentation.
4. **TLS cert tests** — need a self-signed nginx in another container (lab target) before we can live-verify failure signature 4.

### Audit gaps (kind:cli migration, 2026-04-25)

5. **Audit gap: exit-code → error_class/retryable taxonomy lives only in legacy `_classify_curl_error`.**
   The legacy server returned a `(error_class, retryable, suggestions)` tuple per curl exit code, used by the orchestrator for retry decisions and remediation hinting. The new tool.yaml encodes the *signal text* in `failure_signatures` and added an exit-code summary gotcha, but the structured retryable/non-retryable split is not machine-readable.
   - `6, 7, 28, 52, 56` → retryable=true, class=`network`/`timeout`
   - `35, 60` → retryable=false, class=`network` (SSL config — change flags first)
   - `47` → retryable=false, class=`config` (redirect loop — change flags first)
   Decision needed: should the shared runner consume `failure_signatures[*].retryable: bool` or a separate `exit_code_classes` block? Either way, this is a runner-schema question shared across all 40 Tier A tools, not curl-specific. Defer until cross-tool taxonomy is decided; legacy `mcp-server.py` retains the canonical mapping until then.

6. **Audit gap: `inject` method's payload-encoding helper has no kind:cli equivalent.**
   The legacy `inject` method offered `encoding: url | double-url | base64 | none` and a `{PAYLOAD}` placeholder. In kind:cli, the LLM constructs the curl invocation and inlines the encoded payload directly. This is a deliberate simplification (LLM has more flexibility), but it removes a guardrail: junior agents previously asked for `encoding: double-url` and got it right. A new gotcha was added covering the encoding rule of thumb; if regressions appear in live HTB runs (e.g., commands with `&` or `=` getting mis-parsed by the target), upgrade this to a recipe-driven helper rather than re-introducing structured `inject`.

7. **Audit gap: redirect-chain response parsing was non-trivial in legacy.**
   Legacy `_execute_curl_request` (lines 568-645) walked all sections of `\r\n\r\n`-split output to find the LAST `HTTP/x` status line — needed for `-i -L` chains. Under kind:cli, the LLM reads the saved file/stdout directly; the new gotcha warns about concatenated header blocks but does not provide a parser. If LLM accuracy drops on redirect chains, consider a `usage_pattern` that uses `-D /session/headers.txt -o /session/body.bin` to separate them at the curl layer (`-D` writes only the FINAL response headers when combined with `-L`).

---

## 6. Hand-off

- **Tool**: curl (kind:cli)
- **Status**: pilot-migrated; scenarios consolidated; image rebuilt locally with mcp-common 0.3.0 (after foundation bump); legacy split files dropped.
- **mcp-server.py**: present, untouched — auto-inherits run_cli; preserves rollback path per SKILL #21.
- **Image**: `ghcr.io/silicon-works/mcp-tools-curl:latest` — local rebuild verified end-to-end via plugin integration test (3/3 pass).
- **Live-verify pending**: paste scenarios S1-S5 against Validation (10.129.95.235); verify failure_signatures entries 1-3 still match.
- **Pilot-gate sign-off (2026-04-23)**: ≥3 deliberate-failure tests, all matched after broadening; ≥20 extraction cases authored; 0% hallucination on the 5 narrative scenarios re-run on 2026-04-25.

Authored: 2026-04-23 (pilot Phase 1) — consolidated 2026-04-26.
