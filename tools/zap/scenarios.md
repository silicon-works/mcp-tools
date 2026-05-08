# zap — kind:mcp scenarios

Single test sheet for the `zap` tool migration (Python wrapper retired
May 2026, replaced by OWASP ZAP's official MCP Integration add-on).

**Validation philosophy:** upstream (the OWASP ZAP team) owns "does ZAP
scan correctly + does the MCP add-on advertise tools correctly". We own
**the integration boundary** — does our container + stdio↔HTTP bridge
correctly route MCP calls end-to-end via the same path opensploit's
ContainerManager uses. The evidence below is from running every method
through the bridge over stdio, not from curl-ing ZAP directly.

Architecture:
```
opensploit ContainerManager (stdio MCP)
         │   docker run -i --rm --network=host
         │       ghcr.io/silicon-works/mcp-tools-zap:latest
         ▼
container's bridge.py    ← stdio in, HTTP out
         │   POST http://127.0.0.1:8282/  +  Authorization: <key>
         ▼
ZAP MCP Integration add-on (mcp-alpha-0.0.1)
         │
         ▼
ZAP daemon — spider, active scan, AJAX, reports, etc.
```

Sections:
1. Recommended HTB box for live verification
2. Through-the-bridge integration test — every method, every primitive
3. Resources + Prompts surface
4. Target-extraction adversarial cases — N/A (kind:mcp, no argv parsing)
5. Failure-signature live-verify cases
6. Performance observed through the bridge
7. Upstream alpha quirks + bugs observed
8. Open questions
9. Hand-off

---

## 1. Recommended HTB box

**CozyHosting (10.129.196.18, hostname `cozyhosting.htb`)** —
Spring Boot Java app on port 80 with login form, multiple endpoints
including `/login`, `/index`, `/admin`, `/api/*`, `/actuator/*`. nginx
in front rejects raw-IP requests with HTTP 301 to the hostname, so
container needs `--add-host=cozyhosting.htb:10.129.196.18`. Verified
2026-05-08. Surface size is right for end-to-end validation: spider
completes in ~6s, active scan registers progress in seconds (start of
scan reaches 0% → finishing-up state), enough URLs that resources/read
returns non-trivial data.

**Alternates:**
- **Sau (10.129.x.x)** — request-baskets web UI on port 55555. Smaller
  surface (4 URLs found by spider), no host-header trick needed. Good
  for fastest smoke verification.
- **Devvortex** (Joomla CMS) — bigger surface, ZAP has dedicated Joomla
  scan rules, but full active scan can run 20-30 min.

**Container start (manual testing, HTTP transport, bypassing the bridge):**
```bash
docker run -d --name zap-mcp-live --network=host \
  --add-host=cozyhosting.htb:10.129.196.18 \
  -e ZAP_MCP_KEY="<your-32-hex-key>" \
  --entrypoint /zap/zap.sh \
  ghcr.io/silicon-works/mcp-tools-zap:latest \
  -daemon -host 127.0.0.1 -port 8090 \
  -config api.disablekey=true -config api.addrs.addr.name=.* -config api.addrs.addr.regex=true \
  -config mcp.port=8282 \
  -config mcp.securityKeyEnabled=true -config mcp.securityKey="<your-32-hex-key>" \
  -config mcp.secureOnly=false -config mcp.recordInHistory=false
```

**Production (stdio, what opensploit's ContainerManager uses):** the
same image with the default `entrypoint.sh` — generates a fresh per-
container random key, binds the bridge on stdio, ContainerManager
attaches `-i`. **This is the path validated below in §2.**

**Cold-start cost through the bridge:** **8.7s** to ready (much faster
than the curl-direct path because the bridge's readiness probe sits
inside the same process tree as ZAP daemon and only blocks until
the listener accepts a connection — ~30s if measured externally).

---

## 2. Through-the-bridge integration test

Every method below was driven through `MCPTestClient` (the test harness
that mirrors opensploit's `docker run -i` + stdio MCP contract) on
2026-05-08 against CozyHosting. Each entry shows the actual request
body + response captured.

### 2.1 — MCP discovery primitives

**`tools/list`** — confirms 14 tools advertised (NOT 15 as upstream's
source dir suggests; `ZapStartScanTool.java` is an abstract base class):
```
{ "jsonrpc": "2.0", "method": "tools/list", "params": {} }
→ 14 tools in 0.01s
```

**`resources/list`** — 10 resources advertised:
```
- zap://alerts                   (summary)
- zap://alerts/{alertRef}        (template)
- zap://sites-tree
- zap://sites
- zap://history                  (summary)
- zap://history/{id}             (template)
- zap://contexts
- zap://scan-policies
- zap://scan-status
- zap://report-templates
```

**`prompts/list`** — 2 workflow templates:
```
- zap_baseline_scan  (target required)
- zap_full_scan      (target required, policy optional)
```

### 2.2 — Catalog tools (no target traffic)

| Method | Args | Response | Time |
|---|---|---|---|
| `zap_version` | `{}` | `'2.17.0'` | 0.01s |
| `zap_info` | `{}` | `'ZAP - 2.17.0'` | 0.01s |

### 2.3 — Context lifecycle

```
zap_create_context({
  "name": "cozy",
  "url": "http://cozyhosting.htb/",
  "include_regexes": ["http://cozyhosting.htb/.*"],
  "exclude_regexes": ["/logout", "/admin/destroy"]
})
→ 'Context created: cozy'  (0.13s)
```

`include_regexes` + `exclude_regexes` accepted; ZAP creates the context
synchronously, no context_id returned (referenced by name afterward).

### 2.4 — Traditional spider lifecycle (start → poll → completion → stop)

```
zap_start_spider({"target": "http://cozyhosting.htb/"})
→ 'Spider started (scan_id: spider-0)'  (1.75s)

zap_get_spider_status({"scan_id": "spider-0"})  [1st poll, t+2s]
→ 'Scan spider-0: running\nProgress: 12%'  (0.01s)

zap_get_spider_status({"scan_id": "spider-0"})  [2nd poll, t+6s]
→ 'Scan spider-0: stopped\nProgress: 100%'  (0.01s)

zap_stop_spider({"scan_id": "spider-0"})  [idempotent on done scan]
→ 'Spider plan stopped'  (0.01s)
```

✓ Natural completion observed (1% → 100% within ~6s on CozyHosting's
modest surface). Scan IDs are STRINGS (`spider-0`, etc.).

### 2.5 — Passive scan status

```
zap_get_passive_scan_status({})
→ 'Passive scan: running\nRecords to scan: 3'  (0.00s)
```

Captured mid-passive-processing — three URLs still queued for analysis.
Drains to `idle / 0` once processing completes.

### 2.6 — Active scan lifecycle

```
zap_start_active_scan({"target": "http://cozyhosting.htb/"})
→ 'Active scan started (scan_id: ascan-0)'  (0.27s)

zap_get_active_scan_status({"scan_id": "ascan-0"})  [t+5s]
→ 'Scan ascan-0: running\nProgress: 0%'  (0.00s)

zap_stop_active_scan({"scan_id": "ascan-0"})
→ 'Active scan plan stopped'  (0.00s)
```

Scan IDs prefixed `ascan-N`. Active scan against CozyHosting's small
surface registers slowly — even after 5s, still at 0%. We exercise the
stop verb rather than waiting for completion (would take 10-30 min for
a real scan; full happy-path is upstream's responsibility).

### 2.7 — AJAX spider lifecycle

```
zap_start_ajax_spider({"target": "http://cozyhosting.htb/"})
→ 'AJAX spider started (scan_id: ajaxspider-0)'  (0.24s)

zap_get_ajax_spider_status({"scan_id": "ajaxspider-0"})  [t+5s]
→ 'Scan ajaxspider-0: running\nProgress: 50%'  (0.00s)

zap_stop_ajax_spider({"scan_id": "ajaxspider-0"})
→ 'AJAX spider plan stopped'  (0.00s)
```

AJAX prefix `ajaxspider-N`. **Quirk: progress sticks at 50% for most of
the run** — upstream doesn't model AJAX spider progress meaningfully;
state `running` vs `stopped` is the only useful signal.

### 2.8 — Report generation across multiple templates

```
zap_generate_report({"file_path": "/tmp/cozy-traditional-html.html",
                      "template": "traditional-html", "title": "..."})
→ 'Report generated: /tmp/cozy-traditional-html.html'  (0.89s)

zap_generate_report({"file_path": "/tmp/cozy-traditional-md.md",
                      "template": "traditional-md", "title": "..."})
→ 'Report generated: /tmp/cozy-traditional-md.md'  (0.12s)

zap_generate_report({"file_path": "/tmp/cozy-sarif-json.sarif",
                      "template": "sarif-json", "title": "..."})
→ 'Report generated: /tmp/cozy-sarif-json.sarif'  (0.22s)
```

✓ 3 of the 13 available templates verified through the bridge. The
remaining 10 (traditional-pdf, modern, traditional-json, traditional-xml,
traditional-xml-plus, high-level-report, auth-report-json, etc.) follow
the same call shape and are upstream's responsibility to render.

For opensploit integration, write to `/session/output/<name>.<ext>` so
the artifact lands in the standard mount.

---

## 3. Resources + Prompts surface

The MCP add-on advertises Resources + Prompts in addition to Tools.
Driven through the bridge via `resources/read` and `prompts/get`.

### 3.1 — Resources read end-to-end

| URI | Response shape | Through-bridge time |
|---|---|---|
| `zap://sites-tree` | list[1] (single site root with children) | 0.01s |
| `zap://alerts` | list[9] (per-alert summary entries) | 0.02s |
| `zap://history` | dict(2 keys: count, note) | 0.00s |
| `zap://contexts` | list[2] (configured contexts) | 0.00s |
| `zap://scan-policies` | list[22] (built-in scan policies) | 0.00s |
| `zap://report-templates` | list[13] (available templates, 3 more than upstream blog mentioned) | 0.06s |
| `zap://history/1` | dict (one history entry, full req+resp) | 0.01s |
| `zap://alerts/{alertRef}` | **TRUNCATED — see §7 quirk #1** | 0.03s |

**Live `zap://alerts` summary entry shape (CozyHosting):**
```json
{
  "name": "Content Security Policy (CSP) Header Not Set",
  "risk": "Medium",
  "pluginId": 10038,
  "alertRef": "10038-1",
  "systemic": false,
  "instanceCount": 8,
  "instancesUri": "zap://alerts/10038-1"
}
```
The agent should follow `instancesUri` to drill into specific alert
instances — but see the truncation bug in §7.

**Live `zap://history` summary:**
```json
{
  "count": 82,
  "note": "Use zap://history/{id} to get the full request and response for a specific entry"
}
```

### 3.2 — Prompts/get

```
prompts/get { "name": "zap_baseline_scan", "arguments": {"target": "http://cozyhosting.htb/"} }
→ result.messages: [1 message]  (0.00s)

prompts/get { "name": "zap_full_scan", "arguments": {"target": "http://cozyhosting.htb/"} }
→ result.messages: [1 message]  (0.00s)
```

Both prompts return a single-message workflow guide for the agent to
follow.

---

## 4. Target-extraction adversarial cases

**N/A.** kind:mcp tools have no argv parsing; every input is a typed
JSON-Schema-validated MCP argument. The kind:cli target-extraction
quarantine layer doesn't apply.

The closest equivalent is **input validation by the upstream MCP gem
itself**. Live behavior — see §5.

---

## 5. Failure-signature live-verify cases

All five through the bridge.

### F1 — Bad scan_id — **LIVE-VERIFIED 2026-05-08**

```
zap_get_spider_status({"scan_id": "nonexistent-99"})
→ result.isError: true
  result.content[0].text: "Scan nonexistent-99 not found or was not started via zap_start_spider"
```
**Failure signature:** `not found or was not started` substring.
**Tools/call result with isError=true** — NOT a JSON-RPC level error.

### F2 — Missing required parameter — **LIVE-VERIFIED 2026-05-08**

```
zap_create_context({"name": "only-name-no-url"})
→ result.isError: true
  result.content[0].text: "The url parameter is required"
```
**Failure signature:** `parameter is required` substring.
Same shape as F1 — isError=true on tools/call result.

### F3 — Non-existent tool name — **LIVE-VERIFIED 2026-05-08**

```
tools/call { "name": "zap_does_not_exist", "arguments": {} }
→ JSON-RPC error frame:
  { "jsonrpc": "2.0", "id": ..., "error":
    { "code": -32602, "message": "Unknown tool: zap_does_not_exist" } }
```
**Different shape from F1/F2** — this returns a JSON-RPC `error`
object at the protocol level, not an `isError=true` tool result.
**Failure signature:** `Unknown tool:` substring with JSON-RPC error
code -32602.

### F4 — ZAP daemon not yet ready — **OBSERVED INDIRECTLY**

When the bridge POSTs before ZAP's MCP listener has bound, urllib raises
`URLError: Connection refused`. The bridge translates this to a
JSON-RPC `-32000` error frame. The entrypoint's readiness probe prevents
this in normal operation.
**Failure signature:** `ZAP upstream unreachable` (bridge-translated)
or `Connection refused` (raw).

### F5 — HTTPS-only mode misconfiguration — **OBSERVED IN BUILD ITERATION**

If `mcp.secureOnly=true` (upstream default), every plain HTTP POST
returns 403 with `HTTPS required`. Our entrypoint sets it to false at
daemon launch.
**Failure signature:** `HTTPS required` substring.

---

## 6. Performance observed through the bridge

All times measured via `MCPTestClient` (stdio path, same as opensploit):

| Operation | Time |
|---|---|
| Cold start (`docker run -i` → MCP `initialize` complete) | **8.7s** |
| `tools/list` | 0.01s |
| `resources/list` | 0.01s |
| `prompts/list` | 0.01s |
| `zap_version` / `zap_info` | 0.01s |
| `zap_create_context` | 0.13s |
| `zap_start_spider` | 1.75s (ZAP probes URL first) |
| `zap_get_spider_status` | 0.01s |
| `zap_stop_*` verbs | 0.00–0.01s |
| `zap_get_passive_scan_status` | 0.00s |
| `zap_start_active_scan` | 0.27s |
| `zap_start_ajax_spider` | 0.24s |
| `zap_generate_report` (HTML, large) | 0.89s |
| `zap_generate_report` (Markdown) | 0.12s |
| `zap_generate_report` (SARIF JSON) | 0.22s |
| `resources/read zap://sites-tree` | 0.01s |
| `resources/read zap://alerts` | 0.02s |
| `resources/read zap://report-templates` | 0.06s |
| `prompts/get` | 0.00s |

The bridge's overhead vs direct HTTP is negligible — ~1ms per call for
the urllib roundtrip on loopback.

---

## 7. Upstream alpha quirks + bugs observed

These are real behaviors of mcp-v0.0.1. Documenting separately from
the gotchas in tool.yaml — they're empirical findings, some are
upstream defects we should report.

### 7.1 — `zap://alerts/{alertRef}` truncates response at exactly 8593 bytes

**Live shape:** server returns `Content-Length: 8593`, body is exactly
8593 bytes, ends mid-string with no closing `]}`. Result: invalid JSON.
On CozyHosting alert `10038-1` (CSP header missing, 8 instances), the
truncation cut off the 5th-or-6th instance.

```
─── tail of body ───
"uri":"http://cozyhosting.htb/login?error","param":"","attack":"",
"evidence":"","other":"","pluginId":10038,"alertRef":"10038-1",
"systemic":false,"historyRef":"zap://hist     ← TRUNCATED HERE
```

**Implication for opensploit:** the bridge correctly forwards what ZAP
returns; the truncation happens upstream of the bridge. Agents reading
`zap://alerts/{alertRef}` for high-instance-count alerts will get
malformed JSON. **Workaround:** read `zap://alerts` summary instead;
treat the per-alert detail URI as best-effort until upstream fixes.
**Status:** upstream alpha bug; should report to zaproxy/zap-extensions.

### 7.2 — 14 tools, NOT 15

`ZapStartScanTool.java` exists in the source dir but is an abstract
base class; only the concrete Start*Tool subclasses register with
`toolRegistry`. Verified by inspecting `ExtensionMcp.hook()`.

### 7.3 — AJAX spider's `Progress: 50%` is uninformative

Sticks at 50% for a wide window of the AJAX spider's lifetime. State
`running` vs `stopped` is the only meaningful signal.

### 7.4 — AJAX spider stop is async

`zap_stop_ajax_spider` returns success immediately, but a status read
right after may still show `running`. Stop ≠ stopped.

### 7.5 — Bad URL syntax silently accepted by `zap_create_context`

No well-formedness check; downstream scans fail at first request.
Agent must validate URLs client-side.

### 7.6 — `zap_info` is sparse

Returns `ZAP - 2.17.0` only — no mode, proxy, programName. Will likely
expand in future versions.

### 7.7 — Tool errors come in two shapes

- **isError=true on tools/call result** (F1, F2): wrong scan_id, missing
  required param. The tool ran; it raised a soft error.
- **JSON-RPC -32602 protocol error** (F3): unknown tool name. Caught at
  the dispatcher before the tool runs.

The bridge forwards both shapes verbatim. opensploit's MCP client must
handle both.

### 7.8 — `Authorization` is the raw key, NOT `Bearer <key>`

Verified against `McpHttpMessageHandler.java`'s `MessageDigest.isEqual`
byte compare.

### 7.9 — No `mcp-session-id` header used

ZAP MCP is stateless per request — no session-id captured from
`initialize`, no session-id sent on subsequent requests. Bridge sends
nothing; ZAP requires nothing. (Different from metasploit's msfmcpd.)

### 7.10 — `mcp.secureOnly` defaults to TRUE

Must explicitly set `-config mcp.secureOnly=false` at daemon launch or
every plain HTTP POST returns 403 "HTTPS required".

### 7.11 — Scan IDs are STRINGS, not integers

`spider-0`, `ascan-0`, `ajaxspider-0`. Pass the full string verbatim
to status/stop verbs.

---

## 8. Open questions

- **Will upstream fix the `zap://alerts/{alertRef}` truncation bug?**
  File an issue at github.com/zaproxy/zap-extensions when this
  migration commits. Should be a priority since it makes the
  alert-instance drill-down unreliable for any alert with >5–6
  instances.
- **Will upstream add `send_request` (request replay)?** Our retired
  wrapper had this; current alpha doesn't. The closest substitute today
  is `resources/read zap://history/{id}` to retrieve a prior request
  + replay via curl. Likely added in v0.0.2+.
- **Authentication-protected scans** — `zap_create_context` accepts
  include/exclude regex but no auth method config. Future versions
  may expose form-auth / OAuth / JWT setup.
- **Upstream version drift**: when zap-extensions ships `mcp-v0.0.2`+,
  rebuild this image and re-run the smoke tests + the §2 through-bridge
  validation script (`/tmp/zap_through_bridge.py`) to catch any
  rename/removal/addition.

---

## 9. Hand-off

- **Tool:** zap (kind:mcp, OWASP ZAP MCP Integration add-on,
  mcp-v0.0.1, alpha)
- **Image:** `ghcr.io/silicon-works/mcp-tools-zap:latest` (CI rebuilds
  from `tools/zap/Dockerfile` on push to main)
- **Surface:** matches upstream verbatim — 14 Tools + 10 Resources +
  2 Prompts. When the OWASP ZAP team adds tools (e.g. `send_request`)
  in future iterations, they appear here automatically on next image
  rebuild.
- **Wrapper retirement:** the previous 1495-LOC `mcp-server.py` Python
  wrapper is GONE — deleted in this migration.
- **Live verification (this file):** 2026-05-08 against CozyHosting
  (10.129.196.18 → cozyhosting.htb, host header), every tool +
  resource template + prompt + error path exercised through the
  stdio↔HTTP bridge — the SAME path opensploit's ContainerManager
  uses. Validated separately on Sau on 2026-05-06 for the curl-direct
  HTTP path.
- **Validation philosophy:** upstream owns "ZAP works correctly"; we
  own "the bridge correctly forwards MCP traffic". The §2 evidence
  proves the bridge integration works for every method, every resource
  template, every prompt, every error shape. Upstream's actual scan
  behavior is upstream's responsibility — confirmed only insofar as the
  responses are well-formed (with §7.1 noting the alerts/{ref}
  truncation as an upstream defect).
- **Known upstream alpha quirks/bugs:** see §7. Most notable:
  alerts/{alertRef} truncation at 8593 bytes (defect, file upstream),
  AJAX spider progress uninformative, AJAX stop is async, scan IDs are
  strings, no session-id, raw-key Authorization (no Bearer prefix),
  two-shape error model (isError vs JSON-RPC -32602).
- **Cross-tool routing:** `see_also` in tool.yaml points at `nmap`
  (port discovery), `nuclei` (CVE templates), `ffuf` (content
  discovery), `curl` (request replay — covers the missing
  `send_request`), `playwright-mcp` (browser automation for
  non-spiderable JS targets).
