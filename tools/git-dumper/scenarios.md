# git-dumper — Tier A scenarios

Single test sheet for the `git-dumper` tool migration (Wave 3.5 — fifth and
final tool of Wave 3, web-app injection / extraction cluster).

git-dumper wraps `arthaud/git-dumper` (a Python tool, installed via
`pip install git-dumper`). It extracts an exposed `.git/` directory tree
from a web server and reconstructs the full repository: objects, packs,
refs, and the working tree (via `git checkout`). Single-target tool — one
URL per invocation, no batch / list / stdin ingest. Native CLI; the LLM
constructs the full git-dumper invocation. Two positional arguments:
`<URL>` then `<output-directory>`.

Sections:
1. Recommended HTB box for live verification (and the unfortunate truth)
2. Narrative scenarios (paste into opensploit)
3. Target-extraction adversarial cases (≥20 — total 22)
4. Failure-signature live-verify cases (≥3 — total 5)
5. Open questions
6. Hand-off

---

## 1. Recommended HTB box

**Honest answer**: there is no canonical, currently-rotated HTB lab box that
exposes a vulnerable `.git/` surface in the same way that Validation is
canonical for sqlmap. Exposed-.git/ bugs on HTB tend to come and go with
retired seasons.

The closest historical candidates:

| Box | Surface | Verdict |
|---|---|---|
| **HTB Cap (10.10.10.245)** | Reportedly exposed .git/ on the dashboard endpoint in some season lineups; verify before relying on it | Verify with curl http://10.10.10.245/.git/HEAD before launching git-dumper |
| **HTB Forge** | Exposed .git/ behind the SSRF stage (post-foothold) | Auth-gated; .git/ is reachable via the SSRF primitive after the bypass — not directly via -u from the engagement IP |
| **HTB Curling** | /admin/ exposes .git/ with credentials in commit history | RECOMMENDED historical fit. Box is retired but has been re-spun in some lineups. Classic single-URL dump → secrets-in-history → privesc chain |
| **vulhub git-dumper / nginx-misconfig labs** | Local docker-compose lab with deliberately-exposed /.git/ | RECOMMENDED for migration verification. Reproducible, no HTB credit burn, no rotation risk |
| **Self-hosted nginx with /.git/ exposed** | Tiny nginx config that misses the standard `location ~ /\.git { deny all; }` block | EASIEST repeatable lab. Spin up nginx, drop a small repo's .git/ under /var/www/, expose port 80 |

**Recommendation for Wave 3.5 live verification**:

1. Smoke-test path-handling against `git-dumper --help` and `git-dumper -h`
   (safe in a stdio container; non-interactive).
2. Run a default dump (`git-dumper http://target/.git/ /session/git-dump`)
   against a deliberately-vulnerable docker-compose stack (e.g., a small
   nginx serving `.git/` from a checked-in test repo). Validates the
   positional-argument path end-to-end without HTB lab availability.
3. Smoke-test failure signatures (cases F1-F5 below) against a deliberately
   wrong target — no need for the target to be vulnerable.
4. Cross-check `git -C /session/git-dump log --all` after the dump to
   confirm content recovery.

**Persistent test directory**: mount `/tmp/git-dumper-test:/session` (per
SKILL #14). The dumped repo lives there for tool_runner pickup and
follow-up `git log` / `git checkout` calls.

Suggested smoke-test target setup:

```
mkdir -p /tmp/dumper-lab/www
git init /tmp/dumper-lab/www
echo "secret = 'OPENSPLOIT_CANARY_2026'" > /tmp/dumper-lab/www/config.py
git -C /tmp/dumper-lab/www add . && git -C /tmp/dumper-lab/www commit -m 'init'
docker run --rm -p 8080:80 -v /tmp/dumper-lab/www:/usr/share/nginx/html:ro nginx
```

Then `curl http://localhost:8080/.git/HEAD` should return a `ref:` line.

---

## 2. Narrative scenarios (paste into opensploit)

### S1 — `git-dumper --help` (smoke)

```
Engagement target: none — running git-dumper --help through opensploit to confirm the kind:cli path is wired and the binary resolves on PATH. Report the help text.
```

**Watch:** First call ~3 s (container spawn + MCP handshake), exit 0,
stdout contains usage text starting with `usage: git-dumper [-h]`.
Confirms persistent container reuse on subsequent calls. target=null
(no positional URL).

### S2 — Default dump (canonical path)

```
Engagement target: 10.10.10.245 (HTB Cap or self-hosted nginx misconfig lab, authorized).
Dump the exposed .git/ at http://10.10.10.245/.git/ to /session/git-dump-cap.
```

**Watch:** target=`10.10.10.245` extracted from positional URL via
`positional_match` regex (group 2). The LLM emits
`git-dumper http://10.10.10.245/.git/ /session/git-dump-cap`. git-dumper
fetches /.git/HEAD, refs, then walks the object graph parallel via -j 10.
Exit 0; classified success when /session/git-dump-cap/.git/ is populated.
Follow-up: `git -C /session/git-dump-cap log --all` to enumerate commits.

### S3 — Dump behind an auth header (bearer token)

```
Engagement target: 10.10.10.5 (self-hosted nginx + .git behind an auth wall, authorized).
The /admin/ endpoint requires Authorization: Bearer abc123. Dump http://10.10.10.5/admin/.git/ to /session/git-dump-admin.
```

**Watch:** Agent emits
`git-dumper http://10.10.10.5/admin/.git/ /session/git-dump-admin -H 'Authorization: Bearer abc123'`.
target=`10.10.10.5`. -H is a value_flag — the `'Authorization: Bearer abc123'`
string is consumed by the flag-walker, NOT treated as a positional. Dump
succeeds with the token; without it would 401 on every object.

### S4 — Slow / fragile target — throttle workers

```
Engagement target: 10.10.10.7 (HTB box with rate-limited /.git/, authorized).
Default -j 10 keeps tripping rate limits. Drop to -j 2, raise -t to 60, and allow 3 retries. Dump http://10.10.10.7/.git/ to /session/git-dump-slow.
```

**Watch:** Agent emits
`git-dumper http://10.10.10.7/.git/ /session/git-dump-slow -j 2 -t 60 -r 3`.
target=`10.10.10.7`. value_flags consume the integer values for -j/-t/-r.
Dump completes more slowly but with fewer 5xx / 'Connection reset' errors.

### S5 — Through a Burp proxy

```
Engagement target: 10.10.10.5 (lab, authorized).
Run the dump through Burp at 127.0.0.1:8080 for live HTTP inspection. Dump http://10.10.10.5/.git/ to /session/git-dump-burp.
```

**Watch:** Agent emits
`git-dumper http://10.10.10.5/.git/ /session/git-dump-burp --proxy http://127.0.0.1:8080`.
target=`10.10.10.5` (the URL host, NOT the proxy). Critical scope-validation
test: even though `--proxy` value contains `127.0.0.1`, the target stays as
the URL host. Burp captures every request for review.

### S6 — TLS-skip on self-signed cert (HTTPS lab)

```
Engagement target: 10.10.10.9 (HTB lab with self-signed HTTPS cert, authorized).
Dump https://10.10.10.9/.git/ to /session/git-dump-tls. The cert is self-signed — bypass verification.
```

**Watch:** Agent emits
`git-dumper https://10.10.10.9/.git/ /session/git-dump-tls --insecure`.
target=`10.10.10.9` (HTTPS scheme, regex still captures host group 2).
Without --insecure, git-dumper aborts with `SSL: CERTIFICATE_VERIFY_FAILED`.

### S7 — Custom User-Agent (avoid WAF fingerprint)

```
Engagement target: 10.10.10.5 (lab, authorized).
Default UA gets blocked by the WAF. Dump http://10.10.10.5/.git/ to /session/git-dump-ua, with a Firefox UA.
```

**Watch:** Agent emits
`git-dumper http://10.10.10.5/.git/ /session/git-dump-ua -u 'Mozilla/5.0 (X11; Linux x86_64; rv:128.0) Gecko/20100101 Firefox/128.0'`.
target=`10.10.10.5`. -u is User-Agent (NOT a target URL flag — the URL is
already in the first positional). value_flag consumes the UA string.

### S8 — Cookie via -c (compact)

```
Engagement target: 10.10.10.5 (lab, authorized).
Dump http://10.10.10.5/admin/.git/ to /session/git-dump-cookie. The session cookie is 'PHPSESSID=abc123; user=admin'.
```

**Watch:** Agent emits
`git-dumper http://10.10.10.5/admin/.git/ /session/git-dump-cookie -c 'PHPSESSID=abc123; user=admin'`.
target=`10.10.10.5`. -c value contains `;` and `=` — value_flag consumes
the cookie string atomically. The agent could equivalently use
`-H 'Cookie: PHPSESSID=...; user=admin'` — both work.

### S9 — Ignore noisy paths (skip media)

```
Engagement target: 10.10.10.5 (lab, authorized).
Dump http://10.10.10.5/.git/ to /session/git-dump-clean. Skip *.png and *.jpg — we don't need media blobs.
```

**Watch:** Agent emits
`git-dumper http://10.10.10.5/.git/ /session/git-dump-clean -i '*.png' -i '*.jpg'`.
target=`10.10.10.5`. -i is stackable; value_flag consumes each glob.

### S10 — Failure: connection refused (TCP layer)

```
Engagement target: 127.0.0.1 (intentionally wrong target for TCP-layer error classification).
Dump http://127.0.0.1:1/.git/ to /session/dump-fail-tcp — port 1 is unbound.
```

**Watch:** target=`127.0.0.1` extracted. git-dumper's underlying requests
library raises `Connection refused` / `Failed to establish a new connection`.
Failure classified via signature.

### S11 — Failure: DNS resolution (DNS layer)

```
Engagement target: nonexistent-host.invalid.localdomain (deliberately invalid).
Dump http://nonexistent-host.invalid.localdomain/.git/ to /session/dump-fail-dns.
```

**Watch:** target=`nonexistent-host.invalid.localdomain` extracted. DNS
lookup fails; output contains `Could not resolve` or `Name or service not
known`. Failure classified.

### S12 — Failure: 404 (URL missing /.git/)

```
Engagement target: example.com (real host but no /.git/ exposed).
Dump http://example.com/ to /session/dump-fail-404 — note the missing /.git/ suffix to verify the failure mode.
```

**Watch:** target=`example.com`. git-dumper hits /HEAD and gets 404.
Failure classified via `404` or `not found` signature. Fix prompt:
re-run with `http://example.com/.git/` (and confirm /.git/HEAD via curl
first).

---

## 3. Target-extraction adversarial cases (22 total, ≥20 spec)

The git-dumper `tool.yaml` declares TWO target_extraction rules (first
match wins):

1. `positional_match` regex `^(https?)://([^:/?#]+)`, capture group 2,
   `parse_as: url_host` — anchors on the URL form
2. `first_non_flag_positional` fallback for unusual schemes (none currently
   supported by git-dumper, but defensive)

`reject_flags` is empty (single-target tool, no bulk-list ingest, no
interactive shell). `value_flags` lists 13 entries covering ignore, jobs,
retry, timeout, user-agent, header, cookie, and proxy — every flag whose
value could leak as a positional URL.

### Happy-path cases — first-positional URL form

| #  | Command (binary `git-dumper` omitted) | Expected target | Notes |
|----|---|---|---|
| 1  | `http://10.10.10.245/.git/ /session/git-dump-cap` | `10.10.10.245` | Bog-standard HTTP IPv4 |
| 2  | `https://10.10.10.245/.git/ /session/git-dump-tls` | `10.10.10.245` | HTTPS scheme — regex's `https?` matches |
| 3  | `http://target.htb/.git/ /session/git-dump-htb` | `target.htb` | Hostname form |
| 4  | `http://target.htb:8080/.git/ /session/git-dump-port` | `target.htb` | Non-default port — `[^:/?#]+` stops at `:` so port stripped |
| 5  | `https://api.target.com:8443/admin/.git/ /session/git-dump-api` | `api.target.com` | HTTPS + port + path — host capture clean |
| 6  | `http://VICTIM.HTB/.git/ /session/git-dump-uc` | `VICTIM.HTB` | Uppercase preserved (TargetValidation lowercases downstream) |
| 7  | `http://10.10.10.5/.git/ /session/git-dump-flags -j 2` | `10.10.10.5` | Trailing flags after positionals — extraction unaffected |
| 8  | `http://10.10.10.5/.git/ /session/dump -H 'Authorization: Bearer xxx'` | `10.10.10.5` | -H value contains `:` and spaces — value_flag consumes |
| 9  | `http://10.10.10.5/.git/ /session/dump -c 'session=abc; user=admin'` | `10.10.10.5` | Cookie value contains `;` and `=` — value_flag consumes |
| 10 | `http://10.10.10.5/.git/ /session/dump -u 'Mozilla/5.0 ...'` | `10.10.10.5` | UA value contains `/` and spaces — value_flag consumes |
| 11 | `http://10.10.10.5/.git/ /session/dump --proxy http://127.0.0.1:8080` | `10.10.10.5` | Proxy URL is on localhost; target is the FIRST POSITIONAL, NOT the proxy |
| 12 | `http://10.10.10.5/.git/ /session/dump --insecure` | `10.10.10.5` | Boolean flag, no value — extraction unaffected |
| 13 | `http://10.10.10.5/.git/ /session/dump -i '*.png' -i '*.jpg'` | `10.10.10.5` | -i stackable; both globs consumed by value_flag |
| 14 | `-j 2 http://10.10.10.5/.git/ /session/dump` | `10.10.10.5` | Flags BEFORE positionals — value_flag consumes `2`, then URL is first non-flag positional |
| 15 | `-t 60 -r 3 http://10.10.10.5/.git/ /session/dump` | `10.10.10.5` | Multiple value_flags before positional — all consumed |
| 16 | `http://10.10.10.5:80/.git/ /session/dump` | `10.10.10.5` | Explicit port 80 — stripped from host |
| 17 | `http://shop.target.tld/.git/ /session/dump-shop` | `shop.target.tld` | Multi-label hostname |
| 18 | `http://[2001:db8::1]/.git/ /session/dump-v6` | `[2001` | **Open Question 2** — IPv6 in URL: regex `[^:/?#]+` stops at `:` so capture is `[2001` (broken). Worst case fallback to `first_non_flag_positional` returns the full URL. Document as known gap |
| 19 | `http://admin:s3cr3t@10.10.10.5/.git/ /session/dump-userinfo` | `admin` | **Open Question 1** — pure regex `[^:/?#]+` after `://` captures the userinfo `admin` (not the host). Same issue as sqlmap case 20 / ssti case 20. Recommended fix: regex `^(https?)://(?:[^@/?#]*@)?([^:/?#]+)` |
| 20 | `http://10.10.10.5/.git/index/file%20with%20spaces /session/dump` | `10.10.10.5` | URL-encoded spaces in path — host capture unaffected |

### Adversarial cases (DSL must reject, fall back, or warn)

| # | Command | Expected behaviour | Notes |
|---|---|---|---|
| F1 | `--help` | `target=null` | Top-level help — safe in container |
| F2 | `-h` | `target=null` | Short alias |
| F3 | (empty command, no args) | `target=null` | argparse exits with 'arguments required' |
| F4 | `http://10.10.10.5/.git/ /session/dump --proxy http://outofscope.attacker.com:8080` | `target=10.10.10.5` (the URL, NOT the proxy) | **Security invariant**: scope = URL of target, not proxy. Same as sqlmap F8 / ssti F10 |
| F5 | `http://10.10.10.5/.git/ /session/dump -H 'Host: real.target.com'` | `target=10.10.10.5` (NOT real.target.com) | Same invariant as curl F5 / sqlmap F9 / ssti F11: Host header is behaviour override, not authorization scope |
| F6 | `http://10.10.10.5/.git/ /session/dump -u 'http://attacker.com/'` | `target=10.10.10.5` | -u is User-Agent (NOT URL — git-dumper takes URL as positional). value_flag consumes the UA, even though it looks like a URL |
| F7 | `https:// /session/dump` | `target=null` | Malformed URL — regex match fails, fallback first_non_flag_positional returns `https://` (parse_as url_host fails cleanly) |
| F8 | `ftp://files.target.local/.git/ /session/dump` | Regex fails (no `https?` match); fallback returns `ftp://files.target.local/.git/` | git-dumper does NOT support ftp — runtime error from the tool. Documented in routing.never_use_for |

### Concatenated short-flag cases

git-dumper has no reject_flags, so concatenated short flags don't trigger
plugin-level rejection. They DO collide with positional parsing, however:

| # | Command | Expected behaviour | Notes |
|---|---|---|---|
| F9 | `-j2 http://10.10.10.5/.git/ /session/dump` | `target=10.10.10.5` | Concatenated `-j2` — argparse handles natively. Plugin's value_flag matches `-j` prefix; the `2` is glued |
| F10 | `-t60http://10.10.10.5/.git/ /session/dump` | undefined behaviour | Pathological — argparse will likely reject or treat the entire token as the timeout value. Don't generate; documented for defensive testing |

### Help / introspection (target=null)

| # | Command | Expected | Notes |
|---|---|---|---|
| H1 | `--help` | `target=null` | Top-level help |
| H2 | `-h` | `target=null` | Short alias |

---

## 4. Failure-signature live-verify cases (5 total, ≥3 spec)

Verify against the git-dumper container (rebuild during Wave 9 batch with
mcp-common 0.3.0 and python3-full base).

Layer diversity (SKILL #11) — 6 distinct verifiable layers represented in
`tool.yaml`'s `failure_signatures`. Live-verify the most common 5 below.

| # | Layer | Test | failure_signature `signal` | Status |
|---|---|---|---|---|
| 1 | DNS | `git-dumper http://nonexistent-host.invalid.localdomain/.git/ /session/dump-dns-fail` | `Could not resolve` OR `Name or service not known` | PENDING live verify |
| 2 | TCP | `git-dumper http://127.0.0.1:1/.git/ /session/dump-tcp-fail` | `Failed to establish a new connection` AND/OR `Connection refused` | PENDING live verify |
| 3 | HTTP (404) | `git-dumper http://example.com/ /session/dump-404-fail` (URL missing /.git/) | `404` OR `not found` | PENDING live verify |
| 4 | TLS | `git-dumper https://expired.badssl.com/.git/ /session/dump-tls-fail` (no --insecure) | `SSL: CERTIFICATE_VERIFY_FAILED` OR `certificate verify failed` | PENDING live verify |
| 5 | Filesystem | `git-dumper http://target/.git/ /readonly/dump` (output dir not writable) | `Permission denied` | PENDING live verify |

Plus encoded-but-not-yet-live: `Empty repository` and `0 files downloaded`
when /.git/objects/ is blocked but /.git/HEAD is reachable; `fatal: bad
object` post-dump when packs are incomplete.

### Layer diversity (SKILL #11) — achieved

6 distinct verifiable layers documented in `failure_signatures`:
1. **DNS** (case 1)
2. **TCP** (case 2)
3. **HTTP** (case 3 — 404 / app-layer)
4. **TLS** (case 4 — protocol-specific, post-handshake)
5. **Filesystem** (case 5 — local-side I/O failure)
6. **Application** (Empty repository / 0 files / fatal: bad object — post-dump validation; encoded but not testable without a partially-broken target)

### Lessons recorded in `tool.yaml` gotchas

1. **URL trailing slash matters** — http://target/.git/ works,
   http://target/.git does NOT. git-dumper expects to find /.git/HEAD
   relative to the URL path.
2. **Output dir positional must be writable** — /session/<dirname>/ is
   canonical and survives container recycle; /tmp/<dirname>/ is wiped on
   container restart.
3. **Smoke-test /.git/HEAD with curl FIRST** — if curl returns `ref:`,
   .git/ is genuinely exposed. If 404, the URL is wrong (or .git/ truly
   isn't there). Saves a 5-min container spawn + dump cycle on a doomed
   target.
4. **Default -j 10 is aggressive** — drop to -j 2 for slow / rate-limited
   / lab targets. Watch for `Connection reset by peer` and 5xx in stdout.
5. **Auth via -H or -c** — there is no --basic-auth or --bearer flag.
   Construct headers manually.
6. **No structured output** — git-dumper writes a directory tree on disk.
   Success = `{output_dir}/.git/` exists and `git log` works inside.
7. **Partial / blocked dumps** — some servers expose /.git/HEAD but block
   /.git/objects/. Dump appears to succeed but `git log` fails with
   `fatal: bad object`. Recovery: re-dump with -j 1, or seek alternative
   leaks (.git.zip, .git.tar.gz).

---

## 5. Open questions

1. **Userinfo URL (case 19)** — pure regex `[^:/?#]+` after `://` captures
   `admin` (the username) instead of `10.10.10.5`. Same issue as sqlmap
   case 20 / ssti case 20. Recommended fix: regex
   `^(https?)://(?:[^@/?#]*@)?([^:/?#]+)` with capture group still 2.
   **Verify in plugin's DSL implementation** — if not handled, update
   sqlmap, ssti, and git-dumper's `target_extraction` regex consistently.

2. **IPv6 URL (case 18)** — `http://[2001:db8::1]/.git/`: regex
   `[^:/?#]+` after `://` stops at the first `:` and captures `[2001`.
   Plugin behaviour: TargetValidation will likely reject the malformed
   host string. Real users running IPv6 targets are rare on HTB; document
   as known gap. Fix would be a more elaborate regex with bracket-aware
   capture: `^(https?)://(\[[0-9a-fA-F:]+\]|[^:/?#]+)`.

3. **Output dir name choice** — the legacy `dump` method (kind:mcp)
   auto-generated `/session/git-dump-<sanitized_host>`. With kind:cli,
   the LLM picks the directory explicitly. Recommend the agent include
   the directory name in the prompt context (e.g., "dump to
   /session/git-dump-doctor") to keep names descriptive. If the agent
   forgets, suggest `/session/git-dump` as a fallback default.

4. **Empty / partial dump detection** — git-dumper reports success
   (exit 0) even when /.git/objects/ is blocked and only HEAD/refs came
   through. Post-dump validation is the agent's responsibility:
   `git -C {output_dir} log --all` must return at least one commit, OR
   `ls {output_dir}/.git/objects/pack/` must show pack files. If neither
   holds, treat as INCOMPLETE. Failure signatures `Empty repository` /
   `0 files downloaded` are documented, but git-dumper's prose may not
   always emit these — pure exit-code check is unreliable.

5. **`.git/` trailing-slash sensitivity** — git-dumper requires the URL
   to end in `/.git/` (with the trailing slash). The legacy mcp-server.py
   normalized this by stripping `/.git` and re-appending. With kind:cli,
   the LLM is responsible for the URL form. Document in gotchas; live-
   verify whether git-dumper accepts `/.git` (no trailing slash) — it
   may or may not depending on the build.

6. **Default -j 10 vs lab box rate limits** — HTB boxes commonly have
   per-IP connection caps in the 5-10 concurrent range. -j 10 sometimes
   triggers `Connection reset by peer` on every other request. Document
   recommendation: drop to -j 2 for HTB by default; raise to -j 10 only
   for known-fast labs.

7. **Auth flow** — there's no --basic-auth / --bearer flag. The agent
   must construct `-H 'Authorization: Bearer xxx'` or
   `-H 'Authorization: Basic <base64>'` manually. Document a pattern
   for the LLM to follow. Capture tokens via a curl or playwright login
   for non-trivial auth flows.

8. **Recovery commands post-dump** — after a successful dump, the agent
   typically wants to run `git log --all`, `git checkout <branch>`,
   `git stash list`, and `git reflog`. These are NOT part of git-dumper —
   they're plain git commands against the dumped tree. The agent should
   know to follow up with these via the bash tool (or future
   git-recovery method). Document in gotchas.

9. **No HTB lab box for canonical live verification** — Validation is
   canonical for sqlmap; HTB Curling was the closest historical fit for
   git-dumper but is retired. Recommendation: build a small `vulhub`-style
   docker-compose lab (nginx + intentional /.git/ exposure) and ship it as
   `lab/git-dumper-test/` for repeatable Wave 9 verification. Same pattern
   as the ssti recommendation.

10. **Legacy mcp-server.py auto-extraction features** — the kind:mcp
    `dump` method also ran post-dump analysis: file count, branch list,
    commit count, secret-pattern grep, interesting-file glob. With
    kind:cli, the agent must invoke these manually (via bash + git
    commands, or via trufflehog scan_git for secret detection). The
    legacy `analyze` method is preserved as the rollback path per
    SKILL #21 — agents can still call git_dumper:analyze on a previously
    dumped repo if needed.

---

## 6. Hand-off

- **Tool**: git-dumper (kind:cli, arthaud/git-dumper — Python 3 — installed
  via `pip install git-dumper`). Binary `git-dumper` resolves on PATH after
  `pip install` in the venv.
- **Status**: tool.yaml authored end-to-end (kind:mcp → kind:cli);
  scenarios.md written. **Dockerfile EDITED** — `python3 / python3-pip /
  python3-venv` replaced with `python3-full` (Kali-rolling-friendly per
  nikto / impacket / ffuf / nuclei / ssti convention).
- **mcp-server.py UNTOUCHED** — auto-inherits `run_cli` from BaseMCPServer
  (mcp-common 0.3.0); existing per-method handlers (`dump`, `analyze`)
  preserved as the legacy / rollback path per SKILL #21. Especially
  valuable for git-dumper because the `analyze` method does post-dump
  enrichment (commit log, secret grep, interesting files) that's
  non-trivial to reconstruct from kind:cli alone. The `dump` legacy
  method also handles URL normalization (trailing slash, /.git suffix).
- **Image**: `ghcr.io/silicon-works/mcp-tools-git-dumper:latest` — needs
  rebuild during Wave 9 batch to pick up mcp-common 0.3.0 AND the new
  python3-full base. Image size unchanged (~250 MB).
- **target_extraction = TWO rules**: `positional_match` regex on the FIRST
  POSITIONAL URL (capture group 2 = host), with `first_non_flag_positional`
  fallback. Different shape from sqlmap / ssti (which use -u flag).
- **value_flags**: 13 entries — `-i/--ignore`, `-j/--jobs`, `-r/--retry`,
  `-t/--timeout`, `-u/--user-agent`, `-H/--header`, `-c/--cookie`,
  `--proxy`. Every flag whose value could leak as a positional URL is
  enumerated.
- **reject_flags**: EMPTY — git-dumper has no bulk-target ingest (no
  --load-urls / --input-file / stdin) and no interactive shell. Every
  flag is safe to forward.
- **Wave 3.5**: fifth and final tool of Wave 3 (web-app injection /
  extraction cluster). Tier A migration progress: 14 tools done after
  this (curl, sqlmap, impacket, nmap, ffuf, nuclei, nikto, john,
  hashcat, kerbrute, hydra, ssti, git-dumper). Wave 3 closes
  with this tool.
- **Live-verify pending**: paste S1-S12 against a self-hosted nginx
  /.git/ lab during Wave 9 batch rebuild + e2e run. Verify failure
  signatures 1-5 live; verify target-extraction cases 1-20 + F1-F10
  with plugin unit tests.
- **Files removed**: NONE — the directory was already on the simpler
  layout (no `target_extraction_tests.md`, no `failure_signature_tests.md`,
  no `__pycache__/`).

Authored: 2026-04-25.
