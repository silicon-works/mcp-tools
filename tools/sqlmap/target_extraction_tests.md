# sqlmap target-extraction test set (Workstream A → B handshake)

Per Feature 35 spec: ≥20 adversarial commands, each with the expected target host
that the plugin's `target_extraction` DSL should pull from the sqlmap invocation.

The sqlmap `tool.yaml` declares three rules (first match wins):

1. `flag_value` for `-u` with `parse_as: url_host`
2. `flag_value` for `--url` with `parse_as: url_host`
3. `positional_match` regex `^(?:--url=|-u=)?(https?|ftp|ftps|file|gopher)://([^:/?#*]+)`, capture group 2, `parse_as: url_host` — safety net for `-u=URL` and `--url=URL` forms with embedded equals sign

Lessons applied from curl pilot:
- Explicit `parse_as: url_host` on every rule (Stage 1 finding)
- Multi-target ingestion (`-r FILE`, `-l FILE`, `-m FILE`, `-g DORK`) is NOT covered by these rules — the URL isn't on the command line. Such commands will extract `target=null` and the validation hook will warn but not block. Phase agent / tool_runner is expected to pre-resolve the target host out of band before such ingestion.

## Happy-path cases

| # | Command (binary `sqlmap` omitted) | Expected target | Notes |
|---|------------------------------------|-----------------|-------|
| 1  | `-u http://10.10.10.5/page.php?id=1 --batch --random-agent` | `10.10.10.5` | Bog-standard probe, IPv4 |
| 2  | `-u 'http://10.10.10.5/page.php?id=1*' --batch --random-agent` | `10.10.10.5` | Asterisk injection marker — tokenized through the `*`-stripping group `[^:/?#*]+` |
| 3  | `--url http://target.local/login --data='user=admin&pass=*' --batch` | `target.local` | `--url` (space-separated) flag |
| 4  | `--url=http://target.local/login --data='user=admin&pass=*' --batch` | `target.local` | `--url=` (equals form) |
| 5  | `-u=http://target.local/login --batch` | `target.local` | `-u=` short flag with equals — uncommon but valid |
| 6  | `-u 'https://api.target.com:8443/v2/users?id=1' --batch --random-agent` | `api.target.com` | HTTPS + port + query — port stripped |
| 7  | `-u 'http://VICTIM.LOCAL/page.php?id=1' --batch` | `VICTIM.LOCAL` | Uppercase preserved (validation hook lowercases) |
| 8  | `-u 'http://10.10.10.5/page.php?id=1' --data='username=admin&country=Brazil*' --batch -p country --random-agent` | `10.10.10.5` | POST body with asterisk in --data — only the URL host counts |
| 9  | `-u 'http://10.10.10.5/page.php?id=1' --cookie='PHPSESSID=abc; user=admin' --batch` | `10.10.10.5` | Cookie passed; not a target |
| 10 | `-u 'http://10.10.10.5/api?id=1' --second-url='http://10.10.10.5/result.php' --batch` | `10.10.10.5` | Second-order injection — `--second-url` is on the same host (still extract the `-u` host) |
| 11 | `-u 'http://shop.target.tld/products.php?cat=1' --proxy='http://127.0.0.1:8080' --batch` | `shop.target.tld` | Proxy URL is on localhost; target is the `-u` host |
| 12 | `-u 'http://10.10.10.5/login' --data='user=admin&pass=*' --tamper=space2comment,between --batch --random-agent` | `10.10.10.5` | WAF-bypass tampers; doesn't affect target extraction |
| 13 | `-u 'http://10.10.10.5/page?id=1' -p id --dbs --batch` | `10.10.10.5` | `-p` (parameter) pass-through |
| 14 | `-u 'http://10.10.10.5/page?id=1' --dbms=mysql --technique=BEUSTQ --level=5 --risk=3 --batch` | `10.10.10.5` | Heavy flags before the URL flag — order independence |
| 15 | `-u 'ftp://files.target.local/dir' --batch` | `files.target.local` | FTP scheme (sqlmap supports the prefix even if the test doesn't help) |
| 16 | `-u 'http://target.local' --data='*' --batch` | `target.local` | URL with no path; injection marker as entire body |
| 17 | `--user-agent='Mozilla/5.0' -u http://10.10.10.5/page?id=1 --batch` | `10.10.10.5` | Other flag values (UA contains `/`) before URL |
| 18 | `-u 'http://10.10.10.5/page?id=1' -H 'X-Forwarded-For: 1.2.3.4' --batch` | `10.10.10.5` | IP-looking header value MUST NOT be the target — only the URL counts (security invariant) |
| 19 | `-u 'http://10.10.10.5/page?id=1' --auth-type=Basic --auth-cred='admin:password' --batch` | `10.10.10.5` | HTTP basic auth — separate from URL embedding |
| 20 | `-u 'http://admin:s3cr3t@10.10.10.5/page?id=1' --batch` | `10.10.10.5` | URL with userinfo `user:pass@` — host comes after `@`. Regex `[^:/?#*]+` after `://` would catch `admin` (the username) — **BUG suspected**. Worth verifying the DSL handles this. |

## Adversarial cases (target extraction must REJECT, FALL BACK, or warn)

| # | Command | Expected behaviour | Notes |
|---|---------|--------------------|-------|
| F1 | `--version` | `target=null` | No target needed for version check. Validation hook should let it pass. |
| F2 | `--list-tampers` | `target=null` | Same. |
| F3 | `-r /session/burp-request.txt --batch` | `target=null` (URL is inside the file, not on cmdline) | tool_runner should warn or pre-resolve from the file. The current rules will return `target=null` — validation hook should accept (or fail open with warning). |
| F4 | `-l /session/burp-proxy.log --batch` | `target=null` | Same as F3 — proxy log file. |
| F5 | `-m /session/targets.txt --batch` | `target=null` | Multi-target list file. `allow_multi_target` is NOT set on sqlmap, so this is the right path: tool_runner should refuse multi-target sqlmap calls and ask the phase agent to split into per-target invocations OR pre-validate every URL in the file out of band. |
| F6 | `-g 'inurl:".php?id=1"' --batch` | `target=null` (Google dork) | Validation should warn — sqlmap will pull URLs from Google results and we have no way to scope-validate them. Suggest tool_runner refuse `-g` outright unless an explicit override. |
| F7 | `-u 'https://' --batch` | `target=null` (malformed) | Defensive parsing — DSL returns null, sqlmap fails naturally |
| F8 | `-u 'http://10.10.10.5/' --proxy='http://outofscope.attacker.com:8080' --batch` | `target=10.10.10.5` (the -u target, NOT the proxy) | SECURITY INVARIANT: scope = target of the request, not the proxy used to send it. Proxy is infrastructure, not target. |
| F9 | `-u 'http://10.10.10.5/' -H 'Host: real.target.com' --batch` | `target=10.10.10.5` (NOT real.target.com) | Same security invariant as curl Stage 1 F5: Host header is a behaviour override, not authorization scope. |
| F10 | `-u 'http://10.10.10.5/' --safe-url='http://safe.target.com/heartbeat' --safe-freq=10 --batch` | `target=10.10.10.5` (NOT safe.target.com) | --safe-url is decoy traffic to keep session alive. Same target-vs-decoy distinction. |
| F11 | (empty command, no args) | `target=null` | sqlmap will print usage and exit; no target validation needed. |

## Open questions for Workstream B

1. **Userinfo URL (case 20)**: regex `^(?:--url=|-u=)?(https?|...)://([^:/?#*]+)` after `://` matches `admin` (the username). It would extract `target=admin` instead of `10.10.10.5`. **Fix**: regex should explicitly skip `userinfo@` — change to `(?:[^@/?#]*@)?([^:/?#*]+)` and capture group 2. Worth verifying the DSL implementation handles this; if not, update sqlmap's `target_extraction` regex.
2. **Multi-target ingestion (F3, F4, F5, F6)**: should the plugin REJECT these forms outright (refuse to run sqlmap with `-r`/`-l`/`-m`/`-g` because target validation can't apply)? My read of the spec is yes for F5/F6 (multi-target = scope creep risk), maybe for F3/F4 (single target inside the file — pre-resolve and inject `-u` instead).
3. **Asterisk in URL (case 2)**: my regex strips `*` from the host capture via `[^:/?#*]+`. Is this correct, or should `*` be allowed (some weird hostname use cases)? Recommend keeping the strip — `*` in DNS hostnames is invalid.
4. **`--proxy` and `--safe-url` security invariant (F8, F10)**: spec doesn't explicitly call these out as "behaviour overrides, not target". Worth adding a sqlmap-specific note to the spec section on target_extraction security invariants.

## Status

These are the **expected** results. Workstream B's DSL parser implementation
already passed all 27 curl cases on the first try, so the same parser should
handle most of these. The userinfo case (case 20) and multi-target ingestion
cases (F3-F6) are the genuinely new ground vs curl.

Authored: 2026-04-25 (sqlmap pilot Phase 1, Step 4).
