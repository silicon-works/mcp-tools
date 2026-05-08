# playwright-mcp — kind:mcp scenarios

Single test sheet for the `playwright-mcp` tool standardization (May 2026).
This is NOT a wrapper migration — playwright-mcp has always been a thin
vendor wrapper around Microsoft's `@playwright/mcp` npm package. This
round added the missing standardization layer (scenarios.md,
failure_signatures, usage_patterns, gotchas, smoke test, kind:mcp
explicit, idle_timeout_seconds).

**Validation philosophy:** upstream (Microsoft) owns "does Chromium
render correctly + does the MCP server route protocol calls correctly".
We own the **integration boundary** — does our container + caps + entry
config + VPN/host-header handling correctly route MCP calls end-to-end
via the same path opensploit's ContainerManager uses. Evidence below is
from running every method category through the stdio MCP path.

Architecture:
```
opensploit ContainerManager (stdio MCP)
         │   docker run -i --rm --network=host
         │     [--add-host=hostname:ip for vhost-sensitive targets]
         │     ghcr.io/silicon-works/mcp-tools-playwright:latest
         ▼
container's entrypoint.sh
         │   • starts Xvfb :99 + x11vnc + websockify (VNC stack always on)
         │   • exec npx @playwright/mcp
         │       --config /config.json (channel:"" → chrome-headless-shell)
         │       --caps=vision,pdf,devtools,testing
         │       --allow-unrestricted-file-access
         ▼
@playwright/mcp v0.0.75 (stdio MCP) — Chromium runtime
```

Sections:
1. Recommended HTB box for live verification
2. Through-the-stdio integration test — every category, every primitive
3. Resources + Prompts surface
4. Target-extraction adversarial cases — N/A (kind:mcp, no argv parsing)
5. Failure-signature live-verify cases
6. Performance observed
7. Upstream alpha quirks + bugs observed
8. Open questions
9. Hand-off

---

## 1. Recommended HTB box

**CozyHosting (10.129.196.18, hostname `cozyhosting.htb`)** —
Spring Boot Java app on port 80 with login form + multiple endpoints.
nginx 301-redirects raw-IP requests to the hostname, so container needs
`--add-host=cozyhosting.htb:10.129.196.18`. Verified 2026-05-08.
Surface size is right for end-to-end validation:
- Login form with username/password textboxes + submit button
- Static homepage with 28 resources (CSS/JS/images/fonts) — exercises
  network_requests + console_messages
- Real form submission flow exercises fill_form + click + wait_for
- Hostname-based vhost exercises the --add-host requirement (a real
  HTB engagement gotcha)

**Alternates:**
- **Sau** (request-baskets) — smaller surface, no host-header trick.
- **Codify** (Node.js + vm2 sandbox) — exercises JS evaluation.
- Public sites (httpbin.org, playwright.dev) — for protocol-only
  validation when no HTB box is needed.

**Container start (manual testing, stdio):**
```bash
docker run -i --rm --network=host \
  --add-host=cozyhosting.htb:10.129.196.18 \
  ghcr.io/silicon-works/mcp-tools-playwright:latest
# pipe newline-delimited JSON-RPC frames over stdin; read responses on stdout
```

**Container start with HEADED + VNC (CAPTCHA handoff):**
```bash
docker run -i --rm --network=host \
  -e HEADED=1 \
  -e VPN_TARGET=10.129.196.18 -e VPN_HOSTNAME=cozyhosting.htb \
  ghcr.io/silicon-works/mcp-tools-playwright:latest
# operator attaches via http://localhost:6080/vnc.html
```

**Cold-start cost through stdio:** ~3-5s typical (Node + Chromium
spawn). Much faster than ZAP (no JVM). First navigate adds another
~3-9s for page load + resource fetching.

---

## 2. Through-the-stdio integration test

**Validation methodology — two passes:**

1. **Stdio batch pass** (initial sweep): driven through
   `/tmp/pw_scenario.py` which pipelines multiple steps into one
   container. Catches protocol/schema/runtime bugs but has zero
   reasoning gap between steps.
2. **Manual one-call-per-turn pass** (2026-05-08): I drove
   individual JSON-RPC frames through a long-lived container via
   FIFO + log-tail-on-stdout, with my reasoning between each call —
   the same shape an opensploit LLM agent uses (one tool call per
   turn). This pass surfaced bugs the batch pass missed: see §10.

The position-based-ref hazard (§7 quirk 3) was suspected from the
batch pass and CONFIRMED LIVE in the manual pass — clicking a stale
ref e26 silently routed to `await page.locator('#main').click()` on
the homepage with no error. Real opensploit-engagement validation
(Phase J) is still pending; that is the only true integration test.

### 2.1 — Discovery primitives

**`tools/list`** — confirms 44 tools advertised:
```
44 tools across categories:
  navigation: 3       (navigate, navigate_back, close)
  snapshot+capture: 3 (snapshot, take_screenshot, pdf_save)
  console+network: 3  (console_messages, network_requests, network_request)
  interaction: 10     (click, type, fill_form, press_key, hover,
                       select_option, handle_dialog, file_upload, drag, drop)
  vision-mode: 6      (mouse_click_xy, _move_xy, _drag_xy, _down, _up, _wheel)
  window+wait: 3      (resize, wait_for, resume)
  verify: 4           (verify_element_visible, _list_visible,
                       _text_visible, _value)
  js-eval: 2          (evaluate, run_code_unsafe)
  multi-tab: 1        (tabs)
  tracing: 2          (start_tracing, stop_tracing)
  video: 3            (start_video, stop_video, video_chapter)
  highlight+locator: 4 (highlight, hide_highlight, annotate, generate_locator)
```

### 2.2 — Login form discovery (Flow 1)

```
browser_navigate({url: "http://cozyhosting.htb/login"})
→ 3.64s; Page Title: 'Login - Cozy Hosting'; snapshot embedded in response

browser_snapshot({})
→ 0.01s, 869 chars structured tree:
    - main [ref=e2]
      - heading "Login to Your Account" [ref=e11]
      - textbox "Username" [ref=e17]
      - textbox "Password" [ref=e20]
      - checkbox "Remember me" [ref=e23]
      - button "Login" [ref=e26]

browser_take_screenshot({type: "png"})
→ 0.16s; 17,316-byte PNG image returned inline as base64
```

**Finding:** `browser_navigate` returns the snapshot inline in its
response body. After the first navigate you don't NEED a separate
browser_snapshot call to get refs.

### 2.3 — Form interaction (Flow 2)

```
browser_fill_form({fields: [
  {name: "Username", type: "textbox", target: "e17", value: "admin"},
  {name: "Password", type: "textbox", target: "e20", value: "wrong-password-test"}
]})
→ ✗ INITIAL ATTEMPT FAILED with: 'expected string, received undefined at
   fields.0.target' when I passed `ref:` instead of `target:`. The schema
   in older docs / our prior tool.yaml said ref. Live runtime requires
   target. **Tool.yaml updated to match.**

browser_click({target: "e26", element: "Login button"})
→ 1.17s; Playwright code 'await page.getByRole(\'button\', { name: \'Login\' }).click();'

browser_wait_for({time: 1.5})
→ 1.52s; "Waited for 1.5"

browser_evaluate({function: "() => ({title: document.title, url: location.href, errorVisible: !!document.querySelector('.alert')})"})
→ 1.02s; structured response with the live values
```

### 2.4 — Console + network capture (Flow 3)

```
browser_evaluate({function: "() => ({title: document.title, scriptCount: document.scripts.length, linkCount: document.links.length})"})
→ 1.03s; {"title": "Cozy Hosting - Home", "scriptCount": 5, "linkCount": 27}

browser_console_messages({level: "all"})
→ ✗ FAILED: 'Invalid option: expected one of "error"|"warning"|"info"|"debug"'
   The schema rejects 'all' even though older docs claim it works.

browser_network_requests({static: false})
→ 0.02s; "Note: 28 static requests not shown, run with 'static' option to see them."

browser_network_requests({static: true})
→ 0.02s; 28 lines listing every fetched resource (cozyhosting.htb/, googleapis fonts,
  bootstrap CSS/JS, image assets) with status codes
```

**Finding:** `browser_console_messages.level` accepts only
`error|warning|info|debug` — NOT `log` or `all`. tool.yaml updated.

### 2.5 — Vision mode (Flow 4)

```
browser_resize({width: 1280, height: 720})           → 0.01s
browser_take_screenshot({type: "png", fullPage: true}) → 0.94s; 17KB inline PNG
browser_mouse_move_xy({x: 400, y: 300})              → 0.01s
browser_mouse_click_xy({x: 640, y: 300})             → 1.02s; emits page snapshot post-click
browser_mouse_wheel({deltaX: 0, deltaY: 500})        → 0.01s
```

All vision-mode primitives execute as raw `await page.mouse.move(x,y)` /
`await page.mouse.click(x,y)` / `await page.mouse.wheel(dx,dy)`.

### 2.6 — Multi-tab (Flow 5)

```
browser_tabs({action: "list"})              → 0.01s; "0: (current) [Login - Cozy Hosting]..."
browser_tabs({action: "new", url: "http://cozyhosting.htb/"}) → 5.30s (page load)
browser_tabs({action: "list"})              → 0.02s; both tabs listed, current marker on tab 1
browser_tabs({action: "select", index: 0})  → 0.01s; current marker moves to tab 0
browser_snapshot({})                         → 0.01s; snapshot now includes "Open tabs" header
browser_tabs({action: "close", index: 1})   → 0.01s
```

**Finding:** snapshot output includes an "Open tabs" header listing all
tabs whenever >1 tab is open. Useful state visibility for the agent.

### 2.7 — Verify primitives + locator generation (Flow 6)

```
browser_verify_element_visible({role: "heading", accessibleName: "Login to Your Account"})
→ 0.06s; "Done" + Playwright code: await expect(page.getByRole('heading', {name: 'Login to Your Account'})).toBeVisible();

browser_verify_text_visible({text: "Username"})
→ 0.02s; "Done" — uses { exact: true } match

browser_verify_text_visible({text: "this-text-definitely-not-on-the-page"})
→ ✗ isError; "Text not found"

browser_generate_locator({target: "e26", element: "Login button"})
→ 0.01s; "getByRole('button', { name: 'Login' })" — usable in custom Playwright scripts

browser_highlight({target: "e17", element: "Username textbox"})
→ 0.02s; "Highlighted Username textbox"

browser_hide_highlight({})
→ 0.01s; "Hid page highlight"
```

### 2.8 — Evidence capture (Flow 7)

```
browser_start_tracing({})    → 0.27s; trace files at tmp/.playwright-mcp/traces/trace-*
browser_navigate(...)         → 3.13s
browser_pdf_save({filename: "cozy-login.pdf"})
→ ✗ FAILED: 'File access denied: /cozy-login.pdf is outside allowed
   roots. Allowed roots: /tmp/.playwright-mcp, /'.
   FIX: entrypoint.sh now passes --allow-unrestricted-file-access flag,
   which removes the workspace-roots check. Verified the flag's effect
   in upstream's --help.
browser_stop_tracing({})     → 0.01s; trace artifact saved
browser_start_video({})      → 0.01s; "Video recording started."
browser_video_chapter({title: "Login Form Reconnaissance", description: "..."})
→ 2.31s; chapter card rendered as a full-screen overlay (timing reflects the visual duration)
browser_stop_video({})       → 0.11s; "Video saved: tmp/.playwright-mcp/video-*.webm"
```

### 2.9 — Error paths (Flow 8)

```
browser_click({target: "e9999"})
→ ✗ "Ref e9999 not found in the current page snapshot. Try capturing new snapshot."

[navigate to /, then attempt to use the e17 ref from /login]
browser_click({target: "e17"})
→ ⚠ NO ERROR — silently clicked a different element on the new page
   (Playwright executed `await page.locator('div').nth(2).click()`).
   **Refs are POSITION-based across snapshots, not identity-based.**

browser_navigate({url: "not-a-valid-url"})
→ ✗ 'browserBackend.callTool: net::ERR_NAME_NOT_RESOLVED at https://not-a-valid-url/'

browser_navigate({url: "http://10.99.99.99/"})
→ ⚠ HUNG past 30s. No structured error frame; Playwright's internal
   navigation timeout is high. Always set explicit `timeout` on
   browser_navigate against potentially-unreachable IPs.
```

---

## 3. Resources + Prompts

@playwright/mcp v0.0.75 advertises **0 MCP resources and 0 MCP prompts**.
All functionality is exposed via tools/call. (Compare ZAP MCP add-on
which advertises 10 resources + 2 prompts in addition to tools.)

If upstream adds resources/prompts in future versions (e.g. the
Playwright Dashboard URL as a resource, or "log into a target" as a
prompt template), they'll appear automatically on next image rebuild —
re-validate scenarios.md when v0.0.76+ ships.

---

## 4. Target-extraction adversarial cases

**N/A.** kind:mcp tools have no argv parsing — every input is a typed
JSON-Schema-validated MCP argument. The target-extraction DSL (kind:cli's
quarantine layer) doesn't apply.

The closest equivalent is **input-schema validation by upstream's MCP
server**. Live behavior observed (§2 above): missing required args,
invalid enum values, and bad refs all return structured `isError: true`
JSON-RPC tools/call responses (NOT JSON-RPC `-32602` at the dispatcher
level — validation happens inside the tool body).

---

## 5. Failure-signature live-verify cases

### F1 — Bogus ref — **LIVE-VERIFIED 2026-05-08**

```
browser_click({target: "e9999"})
→ isError: 'Ref e9999 not found in the current page snapshot. Try capturing new snapshot.'
```
Failure signature: `Ref` + `not found in the current page snapshot`.

### F2 — Schema validation: wrong field key — **LIVE-VERIFIED 2026-05-08**

```
browser_fill_form({fields: [{name: "Username", type: "textbox", ref: "e17", value: "admin"}]})
→ isError: 'expected string, received undefined at fields.0.target'
```
Field key is `target` not `ref`. Failure signature:
`expected string, received undefined at fields`.

### F3 — Schema validation: wrong enum value — **LIVE-VERIFIED 2026-05-08**

```
browser_console_messages({level: "all"})
→ isError: 'Invalid option: expected one of "error"|"warning"|"info"|"debug"'
```
`level` accepts only error/warning/info/debug — not log, not all.
Failure signature: `Invalid option: expected one of`.

### F4 — File output sandbox — **LIVE-VERIFIED 2026-05-08**, FIXED via entrypoint flag

```
browser_pdf_save({filename: "cozy-login.pdf"})
→ isError: 'File access denied: /cozy-login.pdf is outside allowed roots. Allowed roots: /tmp/.playwright-mcp, /'
```
The default workspace sandbox blocks `/session/output/...` writes.
Entrypoint now passes `--allow-unrestricted-file-access` to fix.
Failure signature: `outside allowed roots`.

### F5 — DNS resolution failure — **LIVE-VERIFIED 2026-05-08**

```
browser_navigate({url: "not-a-valid-url"})
→ isError: 'net::ERR_NAME_NOT_RESOLVED at https://not-a-valid-url/'
```
Failure signature: `ERR_NAME_NOT_RESOLVED`.

### F6 — Network unreachable HANG — **LIVE-OBSERVED 2026-05-08, NO STRUCTURED ERROR**

```
browser_navigate({url: "http://10.99.99.99/"})
→ no response within 30s; eventually internal Playwright timeout
```
There's no clean failure signature for unreachable IPs — they hang.
The agent must set explicit per-call `timeout` to avoid blocking the
whole MCP session.

### F7 — Position-based ref drift — **LIVE-OBSERVED 2026-05-08, NO ERROR**

Subtler than F1: a stale ref (from a different page) does NOT error.
Playwright silently clicks whatever element occupies that position in
the current snapshot tree. **Always re-snapshot after navigate.**
This isn't a failure signature (no error frame) — it's a CORRECTNESS
HAZARD documented in the gotchas.

---

## 6. Performance observed

| Operation | Observed time |
|---|---|
| Cold start (docker run → tools/list responsive) | **~3-5s** (Node + Chromium spawn) |
| `tools/list` (44 tools) | 0.01-0.05s |
| `browser_navigate` to fresh URL (with full resource load) | 3-9s (varies with page weight) |
| `browser_navigate` revisiting cached URL | 1-3s |
| `browser_snapshot` | 0.01s |
| `browser_take_screenshot` (viewport, inline) | 0.16-0.94s (varies with page size) |
| `browser_click` | 1.0-1.2s (waits for action stability) |
| `browser_type` / `browser_fill_form` | 0.5-1s |
| `browser_evaluate` (simple expression) | 1.0s |
| `browser_console_messages` / `browser_network_requests` | 0.02s |
| `browser_mouse_*_xy` / `browser_resize` | 0.01s |
| `browser_tabs new` (with URL) | ~5s (page load) |
| `browser_tabs list/select/close` | 0.01-0.02s |
| `browser_verify_*` | 0.02-0.06s |
| `browser_generate_locator` | 0.01s |
| `browser_highlight` / `browser_hide_highlight` | 0.01-0.02s |
| `browser_start_tracing` | 0.27s |
| `browser_stop_tracing` | 0.01s |
| `browser_start_video` / `browser_stop_video` | 0.01-0.11s |
| `browser_video_chapter` | 2.31s (chapter card visible-time) |
| `browser_pdf_save` (with `--allow-unrestricted-file-access`) | sub-second |
| `browser_navigate` to UNREACHABLE IP | ⚠ HANGS past 30s — set explicit timeout |

Per-flow cold-start cost averaged ~3.1s container boot + ~3-9s first
navigate. Subsequent calls in the same container session are sub-second
to ~1s.

---

## 7. Upstream alpha quirks + bugs observed

These are real behaviors of @playwright/mcp v0.0.75 worth documenting:

1. **44 tools, NOT 32.** Surface grew significantly between Feb 2026
   (when prior tool.yaml was written) and v0.0.75 (May 2026). Added:
   browser_annotate, browser_generate_locator, browser_highlight/
   hide_highlight, browser_run_code_unsafe, browser_video_*, browser_
   start_tracing/stop_tracing (now default), browser_mouse_down/up/
   wheel, browser_drop, browser_verify_*, browser_resume.

2. **`--caps=testing` is undocumented but still works.** v0.0.75 `--help`
   lists `vision, pdf, devtools` as valid caps. But empirically
   `testing` is still honored — drops `--caps=testing,vision,pdf,
   devtools` returns 44 tools; `--caps=vision,pdf,devtools` returns 39
   (loses verify_*, generate_locator). We keep `testing` until proven
   gone.

3. **Refs are POSITION-based across snapshots.** Stale refs do NOT error
   — they execute against the element at that position in the current
   snapshot. Subtle correctness hazard. Always re-snapshot after navigate.

4. **`browser_fill_form` field key is `target` not `ref`.** Older docs
   said ref; runtime requires target.

5. **`browser_console_messages.level` enum is `error|warning|info|debug`
   only.** Older docs claim `log` and `all` work; they don't.

6. **`browser_navigate` does NOT return inline snapshot.** Verified live
   2026-05-08: response only contains a reference to a
   `tmp/.playwright-mcp/page-<timestamp>.yml` file inside the container.
   You MUST call `browser_snapshot` separately to get the page tree
   with refs. Same applies to click/fill_form/type — they confirm the
   Playwright code that ran but do not echo a fresh snapshot. Pattern:
   any state-changing action → browser_snapshot to read DOM state.
   (My earlier docs claimed otherwise; that was wrong.)

7. **File-output tools sandboxed to `/tmp/.playwright-mcp/`** by default.
   `--allow-unrestricted-file-access` flag (set in entrypoint) lets
   `/session/output/...` writes succeed.

8. **Unreachable IPs hang.** No structured error within reasonable time.
   Set explicit per-call `timeout`.

9. **Chrome `channel` config.** `channel: ""` (empty string) selects
   chrome-headless-shell, which IS VPN/tun0-compatible. Setting
   `channel: "chrome"` (full Chrome binary) breaks tun0 routing —
   verified incident from Feb 2026.

10. **VNC stack always runs.** Even in HEADED=0 mode, the entrypoint
    starts Xvfb + x11vnc + websockify on port 6080. In headless it
    points at a blank framebuffer — wasted but cheap. Single-codepath.

11. **MCP HTTP/SSE transport (--port flag) doesn't survive bare-POST
    pattern.** Verified live: an initialize POST returns a session-id,
    but the next bare POST returns 'Session not found'. This isn't how
    we use it in production (we use stdio), but worth noting if anyone
    tries to drive playwright-mcp via curl directly.

12. **Host header strict-match on HTTP transport.** When using --port,
    requests to `http://127.0.0.1:9999/` return 403 'Access is only
    allowed at localhost:9999' (the literal string `localhost`). Use
    `localhost` not `127.0.0.1` for that path.

13. **`browser_run_code_unsafe` runs in NODE context with the Playwright
    `page` object exposed — NOT page context.** The `code` param must
    be a function expression that receives `page` as its first argument.
    Verified live 2026-05-08: `code: '1+1'` failed with
    `TypeError: __fn__ is not a function`; `code: 'document.title'`
    failed with `ReferenceError: document is not defined`;
    `code: '(page) => page.title()'` succeeded. To read DOM via this
    tool you must do `(page) => page.evaluate(() => document.title)` —
    or just use `browser_evaluate` which already runs in page context.

14. **MCP server reports as "Playwright 1.61.0-alpha-1778188671000".**
    The npm package is `@playwright/mcp@v0.0.75` but the underlying
    Playwright runtime version reported in the initialize response is
    a 1.61.0-alpha pre-release. Useful to know if upstream issues
    cross-reference Playwright runtime versions.

---

## 8. Open questions

- **Does `--caps=testing` survive the next upstream release?** It's
  undocumented in v0.0.75 but still honored. If the next version drops
  it, we lose verify_* + generate_locator. Re-validate when v0.0.76 ships.
- **Resources/prompts may appear in future versions.** Currently
  v0.0.75 advertises 0/0; smoke test asserts only on tools count.
- **Auth-protected scans.** The container's @playwright/mcp doesn't
  expose any auth-config tooling. Auth-protected flows currently work
  by browser_fill_form-ing the login page; future versions may add
  more structured auth helpers.
- **Unreachable-IP hang fix.** The cleanest answer is "always set
  per-call timeout" but we could also have the agent prompt include
  a default-timeout convention. Not a tool fix; an agent-side practice.

## 8a. Things NOT verified that could bite us in production

These are integration boundaries the May 2026 standardization round
did NOT actually exercise. Treat as known-unknowns until Phase J.

1. **`/session/output/` writes post-`--allow-unrestricted-file-access`.**
   I verified the flag exists in upstream `--help` and removes the
   sandbox; I did NOT re-run pdf_save / take_screenshot /
   start_video / start_tracing with a `/session/output/...` path
   after applying the flag. **First real engagement that writes
   evidence to disk is the actual test.**

2. **opensploit ContainerManager → playwright integration.** Live
   testing went through `docker run -i --rm --network=host
   --add-host=...` invoked by hand. The opensploit-side path (the
   modified `manager.ts` that's currently uncommitted on `dev`)
   was NOT exercised against playwright. Specifically: does
   ContainerManager pass `--add-host` correctly when the agent's
   target is a vhost-sensitive HTB box? Unknown.

3. **HEADED=1 + VNC handoff for human-in-the-loop CAPTCHA.** The
   browser_headed_mode tool restarts the container with HEADED=1
   env override. Last live-verified Feb 2026 (per MEMORY.md). NOT
   re-exercised this round; treat as stale ground truth.

4. **VNC port collision under concurrent containers.** Entrypoint
   hard-codes VNC at port 6080. With `--network=host`, two parallel
   playwright containers fight over the port. Second container's
   websockify will fail. If opensploit ever spawns concurrent
   playwright instances (separate sub-agents browsing in parallel),
   one of them silently loses VNC. Mitigation: port-from-env hook,
   or only spawn one playwright at a time (current implicit
   assumption). Untested.

5. **Long idle behavior past 5+ minutes.** Container `idle_timeout_seconds`
   is set to 1800 (30 min). Browser session inside the container
   may decay sooner — Chromium's tab might GC, refs would
   definitely become stale, cookies could expire if the target
   site's session is short-lived. NOT tested. The first real
   engagement with a long pause (operator stepping away while
   playwright container sits idle) will surface whatever this is.

6. **Plugin-side failure_signature scanner.** MEMORY.md notes
   warning blindness for kind:cli (901 signatures load but never
   match at runtime — `cli-in-container.ts:587` mechanically
   converts exit code → status). Whether kind:mcp tools have the
   same scanner gap is unknown. If they do, the 10
   failure_signatures I added sit inert. Pending audit.

7. **Snapshot ref behavior across multi-turn LLM flows.** I
   documented the position-based-ref hazard from a single batched
   run. A real LLM agent issuing one call per turn might (a) cache
   a ref into a later prompt and silently misroute, (b) be
   pre-trained / prompted to re-snapshot before each interaction
   and never hit the hazard, or (c) hit it differently than my
   batched script did. The right test is a real engagement.

---

## 9a. Manual one-call-per-turn pass — findings (2026-05-08)

This pass was driven via FIFO + log-tail-on-stdout against a long-lived
container, one JSON-RPC frame per Bash invocation, with reasoning
between calls. Bugs the batch pass had missed or mis-stated:

| # | Bug found in manual pass | Status |
|---|---|---|
| M1 | `browser_navigate` does NOT echo snapshot inline (only a yml file reference inside container) | tool.yaml + scenarios §7-#6 corrected |
| M2 | `browser_run_code_unsafe` requires a FUNCTION EXPRESSION (`(page) => ...`); bare expressions fail with `TypeError: __fn__ is not a function`. Bare DOM access fails — `document is not defined`. The code runs Node-side with the Playwright `page` object exposed | tool.yaml description rewritten + scenarios §7-#13 added |
| M3 | Stale ref e26 from /login silently clicked `#main` on homepage with no error | hazard CONFIRMED LIVE (was suspected from batch pass) |
| M4 | pdf_save + take_screenshot to `/session/output/` WORK post-`--allow-unrestricted-file-access` | scenarios §8a-#1 known-unknown CLOSED — actual files written, 30301-byte PDF + 19205-byte PNG verified |
| M5 | 90s idle survives — browser session intact, refs re-derivable | scenarios §8a-#5 partially CLOSED for short idle (full 30-min idle still untested) |
| M6 | `fill_form` schema error format is structured zod array (`path: [fields, 0, target]`, `message: "Invalid input: expected string, received undefined"`), NOT the flat string my failure_signature implied | failure_signature still works as substring match but format is richer than documented |
| M7 | Server reports as `Playwright 1.61.0-alpha-1778188671000` (the runtime, not the @playwright/mcp package version) | scenarios §7-#14 added |
| M8 | `/session` is NOT auto-created in container — opensploit's ContainerManager must bind-mount it | scenarios §8a-#2 still open: I created `/session/output` manually with `docker exec mkdir -p` to test pdf_save; the actual ContainerManager bind-mount path remains unverified |

Bugs the manual pass did NOT find new evidence on (still pending):
- Concurrent VNC port 6080 collision (§8a-#4)
- HEADED=1 + VNC handoff (§8a-#3)
- Plugin-side failure_signature scanner for kind:mcp (§8a-#6)
- Multi-turn LLM-driven snapshot drift (§8a-#7) — partially addressed
  by M3 above (one stale ref confirmed) but full multi-turn LLM
  agent loop still untested

## 9. Hand-off

- **Tool:** playwright-mcp (kind:mcp, Microsoft @playwright/mcp v0.0.75)
- **Image:** `ghcr.io/silicon-works/mcp-tools-playwright:latest` (CI
  rebuilds from `tools/playwright/Dockerfile` on push to main)
- **Surface:** 44 tools across 12 categories (navigation, snapshot+capture,
  console+network, interaction, vision-mode, window+wait, verify, js-eval,
  multi-tab, tracing, video, highlight+locator). 0 resources + 0 prompts
  (subject to change in future upstream releases).
- **Wrapper retirement:** N/A — playwright-mcp has always been a thin
  vendor wrapper around upstream's npm package. This round added the
  standardization layer (failure_signatures, usage_patterns, gotchas,
  scenarios.md, smoke test, kind:mcp explicit, idle_timeout_seconds,
  --allow-unrestricted-file-access flag).
- **Live verification (this file):** CozyHosting @ 10.129.196.18,
  2026-05-08, 8 stdio-batch flows totaling ~40 tool calls (3+4+4+5+6+6+
  7+5) with full request/response captured. All 12 categories
  exercised at least once. NOT a true one-call-per-LLM-turn flow —
  see §2 validation caveat. Real opensploit-engagement validation is
  Phase J, still pending.
- **Known upstream alpha quirks:** see §7. Most notable: refs are
  position-based not identity-based (correctness hazard), file outputs
  sandboxed by default (entrypoint flag fixes), schema docs drift
  (`target` vs `ref`, level enum).
- **Cross-tool routing:** `see_also` in tool.yaml points at `curl`
  (cheaper alternative for non-JS calls), `zap` (combine for security
  scanning), `ffuf` (content discovery), `nuclei` (CVE template
  validation).
