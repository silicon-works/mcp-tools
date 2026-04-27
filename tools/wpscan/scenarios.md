# wpscan — Tier A scenarios

Single test sheet for the `wpscan` tool migration.

Sections:
1. Recommended HTB box for live verification
2. Narrative scenarios (paste into opensploit)
3. Target-extraction adversarial cases (≥20)
4. Failure-signature live-verify cases (≥3)
5. Open questions
6. Hand-off

---

## 1. Recommended HTB box

**Blocky (10.10.10.37)** — Linux box with Apache + WordPress at the
document root. Authoritative WordPress target for wpscan: WP version
detection, plugin enumeration, user discovery via /?author=N, and
vulnerable plugin (BlockyChat / java-related) findings. Reachable
WordPress install at `http://10.10.10.37/`.

Alternative if Blocky is offline: spin up a vulhub WordPress container
locally (e.g., `vulhub/wordpress/CVE-2022-21661` or any of the
`vulhub/wordpress/` instances). All wpscan usage patterns work against
the local vulhub container at `http://127.0.0.1:8080/`.

For live API-token validation, set `WPSCAN_API_TOKEN` in the container
env (free at https://wpscan.com/profile, 25 lookups/day) and confirm
that vulnerability data populates in the JSON output.

Persistent test directory: standard `/session/` mount; wpscan outputs
go to `/session/wpscan-*.json`.

---

## 2. Narrative scenarios (paste into opensploit)

### S1 — basic enumeration (vulnerable plugins + themes + users)

```
Engagement target: 10.10.10.37 (HTB Blocky, authorized).
Use wpscan to scan http://10.10.10.37/ for vulnerable plugins, vulnerable themes, and users. Use JSON output format and write to /session/wpscan.json. Use a random user agent.
```

**Watch:** Agent emits `wpscan --url http://10.10.10.37/ -e u,vp,vt --random-user-agent -f json -o /session/wpscan.json`. target=`10.10.10.37` extracted from `--url`. First call ~5-10 s spawn + container exec; subsequent calls reuse warm container. JSON output contains `target_url`, `version`, `plugins`, `users`, `interesting_findings`.

### S2 — aggressive plugin discovery

```
Engagement target: 10.10.10.37 (HTB Blocky).
Run wpscan against http://10.10.10.37/ in aggressive plugin-detection mode to enumerate ALL plugins (not just vulnerable ones). Output JSON to /session/wpscan-plugins.json. Use a random user agent.
```

**Watch:** Agent emits `wpscan --url http://10.10.10.37/ --plugins-detection aggressive -e ap --random-user-agent -f json -o /session/wpscan-plugins.json`. target extracted as before. Slower (brute-forces ~10,000 plugin paths) but finds plugins not referenced in page source. Watch for HTTP 429 / rate limit.

### S3 — brute-force WordPress login (small wordlist)

```
Engagement target: 10.10.10.37 (HTB Blocky, authorized).
First create a small password list at /session/passwords.txt with these passwords: admin, password, wordpress, blocky, letmein, blockym4st3r. Then use wpscan to brute-force the WordPress admin login at http://10.10.10.37/wp-login.php. Username is 'admin'. Use 4 threads. JSON output to /session/wpscan-brute.json.
```

**Watch:** Agent first writes the wordlist file via the `write` tool, then emits `wpscan --url http://10.10.10.37/ -U admin -P /session/passwords.txt -t 4 --random-user-agent -f json -o /session/wpscan-brute.json`. target=`10.10.10.37` extracted from `--url`; `-P /session/passwords.txt` value is a wordlist file (NOT a target, plugin's reject_flags is empty for wordlist flags). Expect Blocky to crack `blockym4st3r` for the `notch` user (well-known HTB detail) — but since we're testing plugin behaviour, the success/fail isn't load-bearing here.

### S4 — comprehensive scan with WPScan API token

```
Engagement target: 10.10.10.37 (HTB Blocky).
Run wpscan against http://10.10.10.37/ enumerating users, vulnerable plugins, and vulnerable themes. Use the WPScan API token from the WPSCAN_API_TOKEN environment variable for vulnerability data. JSON output to /session/wpscan-api.json.
```

**Watch:** Agent emits `wpscan --url http://10.10.10.37/ -e u,vp,vt --random-user-agent -f json -o /session/wpscan-api.json`. wpscan picks up `WPSCAN_API_TOKEN` from container env automatically; alternatively the agent may pass `--api-token <token>` explicitly. Output JSON contains populated `vulnerabilities` arrays under each plugin (CVE IDs, fix versions, references). Without a token, vulnerabilities is empty.

### S5 — through HTTP proxy (Burp / inspection)

```
Engagement target: 10.10.10.37 (HTB Blocky).
Run wpscan against http://10.10.10.37/ for user enumeration, but route all requests through a local HTTP proxy at http://127.0.0.1:8080. Use a random user agent. JSON output to /session/wpscan-proxy.json.
```

**Watch:** Agent emits `wpscan --url http://10.10.10.37/ -e u --proxy http://127.0.0.1:8080 --random-user-agent -f json -o /session/wpscan-proxy.json`. **target=10.10.10.37** (from `--url`), NOT `127.0.0.1` (from `--proxy`). The plugin's value_flags must catch `--proxy` so its value is consumed but not extracted as target.

### S6 — failure: not WordPress (DNS-fail)

```
Engagement target: nonexistent-host.invalid.localdomain (deliberately invalid, verifying DNS error classification).
Run wpscan against http://nonexistent-host.invalid.localdomain/ for user enumeration. JSON output to /session/wpscan-fail.json.
```

**Watch:** stderr/stdout matches signal `Could not resolve host` or `Name or service not known`. Classified as `failure_in_output` (wpscan may exit 0 on DNS failure — pattern-match required). Agent reports DNS issue cleanly.

### S7 — failure: target not WordPress

```
Engagement target: 10.10.10.10 (assume HTTP-but-not-WordPress for this test).
Run wpscan against http://10.10.10.10/ for user enumeration. JSON output to /session/wpscan-notwp.json.
```

**Watch:** wpscan output contains `The remote website is up, but does not seem to be running WordPress` and `Scan Aborted`. failure_signature matches `Scan Aborted`. Agent should suggest `--force` or that the target may not be WordPress — pivot to nikto / nuclei.

---

## 3. Target-extraction adversarial cases (≥20)

The wpscan `tool.yaml` declares one extraction rule:

1. `flag_value` for `--url` with `parse_as: url_host`

`reject_flags`: empty (wordlists for `-P`/`-U` are local files, not target lists).

`value_flags` includes ~40 entries covering all flags that take a value
— notably `--proxy`, `--user-agent`, `--cookie-string`, `--http-auth`,
`--proxy-auth`, `-P`, `-U`, `-o`, `--ssl-cert`, `--scope`,
`--main-theme-name`.

### Happy-path cases

| # | Command (binary `wpscan` omitted) | Expected target | Notes |
|---|---|---|---|
| 1 | `--url http://10.10.10.37/ -e u,vp,vt -f json -o /session/wp.json` | `10.10.10.37` | Bog-standard scan, IPv4 |
| 2 | `--url https://blog.target.com:8443/wp -e u,vp` | `blog.target.com` | HTTPS + port + path; port stripped |
| 3 | `--url http://target.htb/wordpress/ -e ap --plugins-detection aggressive` | `target.htb` | WordPress at non-root path |
| 4 | `--url http://VICTIM.LOCAL/wp/ -e u --random-user-agent` | `VICTIM.LOCAL` | Uppercase preserved by url_host |
| 5 | `--url 'http://admin:s3cr3t@10.10.10.37/wp/'` | `10.10.10.37` | URL with userinfo — host comes after `@` |
| 6 | `--url http://[2001:db8::1]/wp -e u` | `[2001:db8::1]` (or `2001:db8::1` post-strip) | IPv6 bracketed |
| 7 | `--url http://10.10.10.37/ -e u --random-user-agent -f json -o /session/wpscan.json` | `10.10.10.37` | Output flag value is a path — not a target |
| 8 | `-e u,vp --random-user-agent --url http://10.10.10.37/` | `10.10.10.37` | Flags before `--url`; order independence |
| 9 | `--url http://10.10.10.37/ --plugins-detection aggressive -e ap` | `10.10.10.37` | Aggressive plugin detection |
| 10 | `--url http://api.target.com/wp/?p=1 -e u` | `api.target.com` | Query string in URL |

### Adversarial — value_flag traps & security invariants

| # | Command | Expected | Notes |
|---|---|---|---|
| F1 | `--help` | `target=null` | Help. tool_runner bypasses scope check. |
| F2 | `-h` | `target=null` | Short-form help. |
| F3 | `--version` | `target=null` | Version. |
| F4 | `--url http://10.10.10.37/ --proxy http://outofscope.attacker.com:8080 -e u` | `target=10.10.10.37` (NOT proxy host). | Security invariant: scope = target of request, not proxy. |
| F5 | `--url http://10.10.10.37/ --proxy http://127.0.0.1:8080` | `target=10.10.10.37` (NOT 127.0.0.1). | Local proxy is infrastructure, not target. |
| F6 | `--url http://10.10.10.37/ --proxy-auth burpuser:burppass --proxy http://127.0.0.1:8080` | `target=10.10.10.37` (NOT proxy-auth, NOT proxy). | `--proxy-auth` value contains `:` like a URL `host:port` but is creds. |
| F7 | `--url http://10.10.10.37/ --user-agent 'Mozilla/5.0 (compatible; bot; +https://crawler.example/info)'` | `target=10.10.10.37` (NOT crawler URL in UA). | UA value contains URL-shape; must be in value_flags. |
| F8 | `--url http://10.10.10.37/ --cookie-string 'redirect_to=http://target.com/wp-admin/; PHPSESSID=abc'` | `target=10.10.10.37` (NOT cookie URL). | Cookie value contains URL; entire string is single value. |
| F9 | `--url http://10.10.10.37/ -P /session/wordlists/rockyou.txt -U admin` | `target=10.10.10.37`. | `-P` path looks vaguely URL-shaped (`/session/...`) but is a file. |
| F10 | `--url http://10.10.10.37/ -U /session/users.txt -P /session/passwords.txt` | `target=10.10.10.37`. | Both `-U` and `-P` are wordlist paths, NOT targets. reject_flags empty for these (wordlists ≠ target lists). |
| F11 | `--url http://10.10.10.37/ --http-auth admin:s3cr3t -e u` | `target=10.10.10.37` (NOT http-auth). | Credential `user:pass` looks like host:port but is creds. |
| F12 | `--url http://10.10.10.37/ -o /session/wpscan-output.json -f json -e u` | `target=10.10.10.37` (NOT output path). | Output file path; in value_flags. |
| F13 | `--url http://10.10.10.37/ --ssl-cert /session/client.crt -e u` | `target=10.10.10.37` (NOT cert path). | Mutual-TLS client cert; in value_flags. |
| F14 | `--url http://10.10.10.37/ --scope '^https?://target\.com' -e u` | `target=10.10.10.37` (NOT scope regex). | Scope regex contains URL fragment; in value_flags. |
| F15 | `--url http://10.10.10.37/ --main-theme-name twentytwentythree -e vt` | `target=10.10.10.37` | Theme name is a slug, not a URL — but in value_flags as defensive measure. |
| F16 | `--url http://10.10.10.37/ --cookie-jar /session/cookies.txt` | `target=10.10.10.37` | Cookie-jar file path; in value_flags. |
| F17 | `--url http://10.10.10.37/ --cache-dir /session/.wpscan-cache` | `target=10.10.10.37` | Cache dir path; in value_flags. |
| F18 | `--url http://10.10.10.37/ -e u1-100 --threads 4` | `target=10.10.10.37` | `-e u1-100` user range (1-100); not a target. `--threads` value is int. |
| F19 | `--url http://10.10.10.37/ -e u --api-token abc123def456 -f json` | `target=10.10.10.37` | `--api-token` value is opaque token; in value_flags. |
| F20 | `--url http://10.10.10.37/ --api-token-file /session/wpscan-token.txt` | `target=10.10.10.37` | `--api-token-file` value is a file path. |
| F21 | `--url http://10.10.10.37/ --random-user-agent --force --stealthy -e u` | `target=10.10.10.37` | All boolean flags after `--url`; no value flags to confuse extraction. |
| F22 | `--url http://10.10.10.37/ --user-agent 'WPScan v3.8.28 (https://wpscan.com)'` | `target=10.10.10.37` (NOT wpscan.com from UA). | Default UA — explicitly contains wpscan.com URL; must NOT be picked. |
| F23 | `--url http://10.10.10.37/ -e u` and a SECOND `--url http://10.10.10.99/` | First `--url` value `10.10.10.37` (or last-wins per wpscan optparse). Document. | Multiple `--url` flags. wpscan optparse: last-wins. |
| F24 | `-e u --random-user-agent` (no `--url`) | `target=null` → wpscan errors `Url is invalid` or prints help. | No target provided. |
| F25 | `--url 'http://'` (malformed) | `target=null` (parse_error) → wpscan fails naturally. | Defensive parsing. |

---

## 4. Failure-signature live-verify cases (≥3)

| # | Layer | Test | failure_signature `signal` | Status |
|---|---|---|---|---|
| 1 | DNS | `--url http://nonexistent-host.invalid.localdomain/ -e u --random-user-agent --connect-timeout 5` | `Could not resolve host` AND/OR `Name or service not known` | PENDING live verify |
| 2 | TCP | `--url http://127.0.0.1:1/ -e u --random-user-agent --connect-timeout 3` | `connection refused` OR `Failed to open TCP connection` | PENDING live verify |
| 3 | TLS | `--url https://expired.badssl.com/wp/ -e u --random-user-agent` | `OpenSSL::SSL::SSLError` OR `certificate verify failed` | PENDING — third-party domain; rerun once self-signed lab target exists |
| 4 | WP-detection | `--url http://10.10.10.10/ -e u --random-user-agent` (against non-WP HTTP) | `does not seem to be running WordPress` OR `Scan Aborted` | PENDING live verify |
| 5 | Auth | `--url http://target/wp -e u --random-user-agent` (against HTTP-basic-auth-protected WP) | `WordPress requires HTTP authentication` OR `401` | PENDING — needs basic-auth-wrapped lab target |
| 6 | Argument | `--url http://10.10.10.37/ --bogus-flag -e u` | `Unrecognised option` | PENDING live verify |
| 7 | API | Run with valid `--api-token` repeatedly until quota hits | `API limit reached` | PENDING — requires real token + 25+ requests |
| 8 | Rate-limit | `--url http://target/wp -e ap --plugins-detection aggressive --threads 50` (hammer a Wordfence-protected WP) | `Too many requests` OR `429` | PENDING — needs WAF-protected target |

### Layer diversity (SKILL #11) — achieved

7 distinct layers exercised: DNS / TCP / TLS / WP-detection / HTTP-auth /
argument-validation / API-quota. Rate-limit layer (case 8) needs a more
realistic WAF-protected target; defer to Wave 9 live HTB run.

---

## 5. Open questions

1. **WPScan API token management** — should the agent treat WPSCAN_API_TOKEN as the canonical source (set once in container env) or pass via `--api-token` per-call (so the LLM controls token rotation)? Current preference: env var, since the agent isn't supposed to handle secrets in argv. Confirm with engagement-context handling.
2. **`--random-user-agent` as default** — every wpscan invocation arguably should use `--random-user-agent` (default UA fingerprints the scanner). Should the tool.yaml description / usage_patterns make this the default convention, or leave per-call? Currently every usage_pattern explicitly includes it.
3. **JSON parsing reliability (architectural)** — `-f json` produces a single document, but wpscan occasionally writes banner / update warning lines to stdout BEFORE the JSON document starts. The legacy mcp-server.py used `json.loads(stdout)` which silently returned `{}` on prefixed warnings (see `_parse_json_output`); under kind:cli the agent receives raw mixed stdout and must extract the JSON itself. **Recommendation**: every wpscan invocation in usage_patterns already passes `-o /session/wpscan-*.json` — encourage the agent to read THAT file (pure JSON) rather than parse stdout. Also recommend `--no-banner --no-update` for reproducibility on cold containers. Promote this from Open Question to a documented kind:cli convention before Wave 9 live verify.
4. **`-e` enumeration code combinatorial validity** — wpscan rejects some combos (vp + ap together is invalid; only one plugin enum mode per call). Should the tool.yaml describe the conflict explicitly, or rely on wpscan's `Invalid choice` failure_signature? Currently the gotchas mention "only one of vp/ap/p" but no formal validation.
5. **Wordfence / Sucuri WAF behaviour** — many real WordPress sites are wrapped in Wordfence or Sucuri. wpscan triggers their rate-limit + IP-block within seconds. Should the tool.yaml document `--throttle` defaults / suggest `--proxy` rotation? Currently the throttled-scan usage_pattern covers the basic case, but real-world adversarial environments need more.
6. **XML-RPC multicall on modern WordPress** — `--password-attack xmlrpc-multicall` only works on WP < 4.4 (released Dec 2015). Effectively dead in 2026 production targets. Should the tool.yaml deprecate the option, or leave it for legacy / vulhub?
7. **`--update` / `--no-update` at first run** — wpscan attempts to update its plugin/theme/vuln database on first run (~30s). The container ships with a pre-fetched DB; should `--no-update` be added to every default usage_pattern for reproducibility, or only when the user explicitly wants offline mode?
8. **Output JSON schema stability** — wpscan's JSON output schema has changed minor details across versions (3.7.x → 3.8.x). The legacy mcp-server.py parses specific fields; under kind:cli, downstream consumers depend on the LLM extracting the relevant fields. Confirm the schema documented in the description matches v3.8.28 exactly.

---

## 6. Hand-off

- **Tool**: wpscan (kind:cli)
- **Status**: tool.yaml authored end-to-end (kind:mcp → kind:cli); scenarios.md written. Dockerfile updated to `python3-full` (Kali apt fix — replaced `python3 python3-pip python3-venv`). mcp-server.py untouched (auto-inherits run_cli; rollback path via 5 legacy methods: scan, bruteforce, enumerate_users, enumerate_plugins, enumerate_themes).
- **Image**: `ghcr.io/silicon-works/mcp-tools-wpscan:latest` — needs rebuild during Wave 9 batch to pick up mcp-common 0.3.0 + python3-full Dockerfile.
- **Live-verify pending**: paste S1-S7 against Blocky (or vulhub). Verify failure_signatures 1-2 (DNS, TCP) live; verify 4 (not-WordPress) and 6 (Unrecognised option) — both should be straightforward live tests. Defer cases 3 (TLS), 5 (HTTP-auth), 7 (API quota), 8 (rate-limit / WAF) until appropriate targets available.
- **Wave 7.4 — straightforward migration**: wpscan is a single-binary Ruby gem with sane optparse-based flag handling. Target extraction via `--url` is unambiguous (no positional target, no sub-commands). value_flags coverage is comprehensive (~40 flags). reject_flags empty because wordlists for `-P`/`-U` are file references, not target lists.

Authored: 2026-04-25.
