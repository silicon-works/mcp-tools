# nmap — Tier A scenarios

Single test sheet for the `nmap` tool migration (Wave 1.1, Feature 35 Tier A).
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

**Primary: Validation (10.129.95.235)** — Linux box with a small open port set
(22, 80, others). User has been spawning this for the curl/sqlmap pilots, so
infrastructure (VPN, container network, /session mount) is already exercised.

**Alternate: any HTB box** — nmap is the universal first step. Pick whichever
machine is up. Cap (10.10.10.245), Knife, Pilgrimage, etc. all work.

### Privileged-mode requirement

The nmap container ships with `requirements.privileged: true` and the runtime
must spawn it with `--privileged` (or NET_RAW + NET_ADMIN capabilities).
Without privileged:
- `-sS` (SYN scan) silently degrades to `-sT` (TCP connect, slower, logged).
- `-sU` (UDP scan) errors out with "requires root privileges".
- `-O` (OS detection) errors out with "requires root privileges".
- Raw-packet evasion (`-f`, `-D`, `-S`, `--spoof-mac`) errors out.

Verify privileged mode is plumbed by running scenario S3 (UDP scan) — if it
errors with "requires root", the container manager isn't passing `--privileged`
even though `tool.yaml` declares it. That's an opensploit-app bug, not an nmap
tool.yaml bug.

---

## 2. Narrative scenarios (paste into opensploit)

### S1 — Quick TCP probe (top 1000 ports)

```
Engagement target: 10.129.95.235 (HTB Validation, authorized).
Use nmap to find open TCP ports on the host. Use a SYN scan with -T4 timing
and skip host discovery (-Pn). Save the XML output to /session/nmap-quick.xml
and report the open ports. Do not waste time scanning all 65535 ports — just
the default top 1000.
```

**Watch:** First call ~5-10 s container spawn + scan. Agent emits clean argv
like `nmap -sS -T4 -Pn -oX /session/nmap-quick.xml 10.129.95.235`. Container
runs privileged (SYN works). XML lands under /session/. Open ports parsed
from output.

### S2 — Service / version + default scripts (-sV -sC -p-)

```
Engagement target: 10.129.95.235 (HTB Validation, authorized).
Run a thorough nmap with full-port (-p-) service version detection (-sV) and
default safe scripts (-sC), with timing -T4 and --min-rate 1000. Skip host
discovery. Save XML to /session/nmap-thorough.xml. This will take several
minutes — do not cancel.
```

**Watch:** Long runtime (5-15 min). Container persists across the duration;
heartbeats keep it alive even when nmap is silent between hosts. Agent does
NOT cancel. When complete, services parsed: ssh OpenSSH version, http Apache
version, etc. XML dumped to /session/.

### S3 — UDP top-100 scan (privileged-mode test)

```
Engagement target: 10.129.95.235.
Run an nmap UDP scan against the top 100 UDP ports. Use -T4 timing and
skip host discovery. Save XML to /session/nmap-udp.xml.
```

**Watch:** Container MUST be privileged for `-sU` to work. If the call
returns "requires root privileges", the privileged plumbing is broken.
Otherwise: scan completes (UDP is slow — expect 5-10 min for top 100), open
UDP ports listed (usually just none on Validation, that's fine).

### S4 — Structured output capture (-oX to /session/)

```
Engagement target: 10.129.95.235.
Run a quick nmap scan (top 100 ports, SYN, -Pn, -T4) with output saved
to /session/scan.xml AND /session/scan.nmap (use -oA /session/scan to write
both formats from a single basename). Then read /session/scan.xml back and
report the file size.
```

**Watch:** Verifies -oA writes .nmap + .xml + .gnmap to /session/. Agent uses
the read tool to confirm file presence. /session/ persists across nmap and
read-tool calls.

### S5 — Failure classification: DNS resolution

```
Engagement target: nonexistent.invalid.localdomain (deliberately invalid,
verifying DNS-failure classification).
Run a quick nmap scan against this target and report what failure mode you
classify it as.
```

**Watch:** stderr/stdout matches `Failed to resolve` (matches `failure_signatures`
entry 1). tool_runner classifies as failure_in_output. Agent reports DNS
failure cleanly without retry.

### S6 — `-iL` reject_flags trap

```
Engagement target: contents of /session/targets.txt (which contains
10.129.95.235 on one line).
Use nmap with -iL /session/targets.txt to scan all targets in that file.
Save XML to /session/nmap-iL.xml.
```

**Watch:** Plugin rejects the call before container spawn with
`status: error`, `rejected_flag: -iL`, reason quoted from
`reject_flags_reason`. **Per the new tool-runner prompt clause**: agent
reformulates with positional argv (`nmap -sS -Pn -oX ... 10.129.95.235`),
having read the file via the read tool first. If the agent has no fallback
target, it returns a clear "phase agent must enumerate targets" error.

---

## 3. Target-extraction adversarial cases (≥20)

The nmap `tool.yaml` declares one extraction rule:

1. `first_non_flag_positional` — walks argv left-to-right, skipping every flag
   and every value-flag's argument (per `value_flags`). Returns the first
   positional that isn't a flag value.

The rule relies on the `value_flags` list to know which flags consume the
next token. Misses there (e.g., forgetting `-D` for decoys) cause the
DSL to misidentify the decoy IP as the target.

### Happy-path cases

| # | Command (binary `nmap` omitted) | Expected target | Notes |
|---|---|---|---|
| 1 | `-sS -p 22,80,443 10.10.10.5` | `10.10.10.5` | Bog-standard IPv4 |
| 2 | `-sV -sC -p- --min-rate 1000 -Pn -oX /session/scan.xml target.htb` | `target.htb` | FQDN after many flags |
| 3 | `-sU --top-ports 100 192.168.1.5` | `192.168.1.5` | UDP scan |
| 4 | `-sn 192.168.1.0/24` | `192.168.1.0/24` | CIDR (full block kept; plugin's TargetValidation expands) |
| 5 | `-sS 10.10.10.1-50` | `10.10.10.1-50` | Range expression (plugin expands) |
| 6 | `-sS 10.10.10.1,10.10.10.5,10.10.10.10` | `10.10.10.1,10.10.10.5,10.10.10.10` | Comma list (plugin splits) |
| 7 | `-sS host.target.com` | `host.target.com` | FQDN, no flags |
| 8 | `-sS 2001:db8::1` | `2001:db8::1` | Bare IPv6 |
| 9 | `-sS [2001:db8::1]` | `[2001:db8::1]` | Bracketed IPv6 (TargetValidation strips brackets) |
| 10 | `-sS -A -T4 -Pn -oX /session/scan.xml 10.10.10.5` | `10.10.10.5` | Aggressive scan with output flag |
| 11 | `-sV --script vuln -p 80,443 10.10.10.5` | `10.10.10.5` | NSE scripts; --script value is "vuln" not a target |
| 12 | `-sV --script smb-vuln-ms17-010 -p 445 10.10.10.5` | `10.10.10.5` | Specific script name |
| 13 | `-sS --script /session/nmap-scripts/custom.nse -p 80 10.10.10.5` | `10.10.10.5` | Custom NSE script path |
| 14 | `-sS -T4 --min-rate 1000 --max-rate 5000 --max-retries 2 10.10.10.5` | `10.10.10.5` | Timing flags with values |
| 15 | `-sS -p- --host-timeout 30s 10.10.10.5` | `10.10.10.5` | --host-timeout takes a value |
| 16 | `-sS -p- --exclude 10.0.0.1,10.0.0.254 10.0.0.0/24` | `10.0.0.0/24` | --exclude consumes its IP-list value, target is the CIDR |
| 17 | `-sS -PS22,80 10.10.10.5` | `10.10.10.5` | -PS with attached port list (no space) — DSL must handle attached value |
| 18 | `-sS -PA80,443 10.10.10.5` | `10.10.10.5` | -PA same shape |
| 19 | `-A -T4 10.129.95.235` | `10.129.95.235` | Aggressive shorthand |
| 20 | `-sS -p 80 VICTIM.LOCAL` | `VICTIM.LOCAL` | Uppercase FQDN preserved (TargetValidation lowercases) |
| 21 | `-sS -p 80 -e tun0 10.10.10.5` | `10.10.10.5` | -e (interface) value-flag — value is "tun0" |
| 22 | `-sS --datadir /opt/nmap-custom 10.10.10.5` | `10.10.10.5` | --datadir consumes a path |

### Adversarial cases (DSL must NOT pick the wrong token)

| # | Command | Expected behaviour | Notes |
|---|---|---|---|
| F1 | `-sS -D 10.10.10.99 10.10.10.5` | target=`10.10.10.5`, NOT `10.10.10.99` | **Critical**: -D (decoy IPs) value looks IP-shaped. value_flags must list `-D`. |
| F2 | `-sS -D RND:5,10.10.10.99,ME 10.10.10.5` | target=`10.10.10.5`, NOT the decoy list | Decoy list has random + IP + ME tokens. |
| F3 | `-sS -S 10.10.10.250 -e tun0 -Pn 10.10.10.5` | target=`10.10.10.5`, NOT `10.10.10.250` | -S (source IP spoofing) value is IP-shaped. |
| F4 | `-sS --proxies http://proxy.local:8080 10.10.10.5` | target=`10.10.10.5`, NOT the proxy URL | --proxies value is URL-shaped. |
| F5 | `-sS -g 53 10.10.10.5` | target=`10.10.10.5` | -g takes source-port number (not target). |
| F6 | `-sS --source-port 53 10.10.10.5` | target=`10.10.10.5` | Same as F5, long form. |
| F7 | `-sS --spoof-mac 00:11:22:33:44:55 10.10.10.5` | target=`10.10.10.5` | --spoof-mac value looks MAC-shaped, not target-shaped, but value_flags catches it. |
| F8 | `-sS -oX /session/scan.xml 10.10.10.5` | target=`10.10.10.5`, NOT `/session/scan.xml` | Output file path could be mistaken for hostname. |
| F9 | `-sS -oA /session/baseline 10.10.10.5` | target=`10.10.10.5`, NOT `/session/baseline` | Same for -oA basename. |
| F10 | `-sS --script-args 'userdb=users.txt,passdb=pass.txt' 10.10.10.5` | target=`10.10.10.5`, NOT the script-args string | Value contains text that could regex-match as a hostname. |
| F11 | `-sS --script-args-file /session/args.txt 10.10.10.5` | target=`10.10.10.5`, NOT the file path | Same. |
| F12 | `-sS --data-string 'GET / HTTP/1.0' 10.10.10.5` | target=`10.10.10.5`, NOT the payload string | --data-string consumes arbitrary text. |
| F13 | `-sS -iL /session/targets.txt` | Plugin rejects via `reject_flags`. `rejected_flag=-iL`. Per new tool-runner prompt: reformulate with positional argv after reading the file. | -iL is rejected. |
| F14 | `-sS -iR 10` | Plugin rejects via `reject_flags`. `rejected_flag=-iR`. | Random target generation — by definition out of scope. |
| F15 | `--version` | target=null → tool.execute.before allows (no target → no scope check) | Pure version check. |
| F16 | `--help` | target=null | Same, help dump. |
| F17 | (empty argv) | target=null → nmap will error with "No targets were specified" | Same shape as F15. |
| F18 | `-sS` (flags only, no target) | target=null → nmap errors "No targets were specified" | Same. |
| F19 | `-sS --script-help all` | target=null | --script-help consumes "all" as its value. |
| F20 | `-sS -p 80 -oX /session/r.xml -D 1.1.1.1,2.2.2.2 -S 3.3.3.3 -e tun0 -Pn 10.129.95.235` | target=`10.129.95.235`, NOT any decoy / source / interface value | The boss-fight: every value_flag in one command. Verifies the full value_flags list is honoured. |
| F21 | `-sS -p 80 10.10.10.5 10.10.10.6` | target=`10.10.10.5` (first), `multi_target_detected=true` | nmap natively accepts multi-target argv. Plugin should flag multi-target unless `allow_multi_target: true`. **Open question 2**. |
| F22 | `-sS --host-timeout 30s 10.10.10.5` | target=`10.10.10.5`, NOT `30s` | --host-timeout takes a duration value. |
| F23 | `-sS -PS22,80,443 10.10.10.5` | target=`10.10.10.5` | -PS with attached port-list value. |
| F24 | `-sS -p 80 [::1]` | target=`[::1]` | IPv6 loopback bracketed. |
| F25 | `-sS -p 80 ::1` | target=`::1` | IPv6 loopback bare. |

---

## 4. Failure-signature live-verify cases (≥3)

Run via opensploit; verify the result hits a `failure_signatures` entry.
Live-verification status will be filled in once these are run on Validation
(2026-04-26+). Until then, they're authored from documentation; SKILL #5
requires re-checking against the actual container image.

| # | Test | Command (post-binary) | Expected exit | Expected stderr/stdout substring | failure_signature `signal` | Status |
|---|---|---|---|---|---|---|
| 1 | DNS resolution failure | `-sS -Pn -T4 nonexistent.invalid.localdomain` | nonzero | `Failed to resolve "nonexistent.invalid.localdomain"` | `Failed to resolve` | AUTHORED — verify on container |
| 2 | Host down (ICMP filtered, no -Pn) | `-sS 10.255.255.254` (note: NO -Pn) | 0 (nmap exits 0 even when host is down — gotcha) | `Note: Host seems down` AND `0 hosts up` | `Note: Host seems down` AND `0 hosts up` | AUTHORED — verify; classifier MUST treat as failure_in_output despite exit 0 |
| 3 | Privilege denied (SYN without privileged) | `-sS -p 22 10.129.95.235` (run with container NOT privileged) | nonzero | `requires root privileges` OR `dnet: Failed to open device` OR `You requested a scan type which requires` | `requires root privileges` | AUTHORED — verify; depends on container manager bypassing privileged for the test |
| 4 | Invalid script | `-sS --script doesnotexist-script -p 80 10.129.95.235` | nonzero | `did not match any category, filename, or directory` | `did not match any category, filename, or directory` | AUTHORED — verify on container |
| 5 | No targets specified | `-sS -p 80` (no target) | nonzero | `No targets were specified` | `No targets were specified` | AUTHORED — verify |
| 6 | Network unreachable | `-sS 192.0.2.1` (TEST-NET, expected unroutable) | varies (depends on routing) | `Failed to determine route to` OR `Network is unreachable` | `Failed to determine route to` | AUTHORED — depends on VPN / routing state |

### Lessons to encode after live verification

1. **nmap exits 0 even when all hosts are down** — same shape as sqlmap.
   tool_runner classifier MUST pattern-match `0 hosts up` / `Note: Host seems down`
   against output regardless of exit code. Encode as a `gotcha` in tool.yaml
   (already done).
2. **Privilege errors are layer-dependent** — at unprivileged-Linux it's
   `Operation not permitted` from raw socket open; at the nmap layer it's
   `You requested a scan type which requires root privileges`. Both signals
   listed.
3. **NSE script errors precede QUITTING!** — when --script-args-file is
   missing, nmap prints `Read script-args file failed` then `QUITTING!`.
   Both signals listed; classifier should match the more specific one first.

---

## 5. Open questions

1. **Privileged-mode plumbing** — does opensploit-app's ContainerManager
   honour `requirements.privileged: true` from tool.yaml and pass `--privileged`
   to docker? S3 (UDP scan) is the live test; if it errors with "requires root",
   the plumbing is broken. Document the actual behaviour after running S3.
2. **Multi-target argv (case F21)** — nmap natively supports
   `nmap -sS host1 host2 host3`. Should the plugin reject as multi-target
   (current default) or allow with `allow_multi_target: true` since nmap
   was designed for it? Recommendation: add `allow_multi_target: true` to
   nmap's tool.yaml so subnet enumeration with explicit host lists works.
   **Decision deferred** to Wave 1.1 implementation review.
3. **IPv6 bracket handling (cases 9, F24)** — confirm plugin's
   TargetValidation strips brackets before scope check, same as curl. If not,
   a bracketed IPv6 in argv won't match the engagement scope (which stores
   bare addresses).
4. **CIDR / range expansion** — when target is `192.168.1.0/24`, does the
   plugin expand and validate every host against scope, or just check the
   network address? Same question for `10.0.0.1-50`. Document the actual
   behaviour.
5. **Output file safety** — gotcha: `-oX /session/scan.xml` is mandatory for
   /session/ persistence. Should the plugin warn / inject `-oX /session/{auto}.xml`
   if no `-o*` flag is present? Phase agent prompt may already cover this;
   verify.
6. **JSON output (-oJ)** — some nmap forks support `-oJ` for JSON; mainline
   nmap does not as of 7.98. Listed in `output_formats` for completeness but
   marked `preferred: false` because availability is image-dependent.
7. **Concatenated short-flag forms** — does the plugin's commandUsesFlag
   handle `-sSp80` vs `-sS -p 80`? nmap does parse the former, but value
   detection gets tricky. Recommendation: agent should prefer separated form;
   plugin should handle both.

### Audit gaps from legacy mcp-server.py (Wave 1.1 audit, 2026-04-25)

8. **Audit gap: XML parsing & summary extraction is now the LLM's job.**
   Legacy mcp-server.py used `parse_nmap_xml()` (from mcp-common) and produced
   structured summary objects per method:
   - `port_scan` → `summary: {target, open_ports[], total_open}`
   - `service_scan` → `services_summary[]` with `{port, protocol, service,
     product, version, extrainfo}`
   - `os_detection` → `os_summary: {best_match, confidence, all_matches[]}`
   - `vuln_scan` → `vulnerabilities[]` (filtered by keyword match against
     script output: `vulnerable | cve- | exploit | critical | high`) +
     `vuln_count`
   - `ping_scan` → `live_hosts[]`, `total_live`
   In kind:cli, the LLM gets raw nmap stdout/stderr (or the XML file at the
   path it specified with `-oX`). It must (a) request `-oX /session/...xml`,
   (b) read the XML back with the `read` tool or a follow-up bash, and (c)
   extract the summary fields itself. The vuln-finding keyword filter
   (`vulnerable|cve-|exploit|critical|high`) is now an agent-side heuristic;
   the gotcha line in tool.yaml documents it but enforcement moves to the LLM.
   **No code change required** — flagging that this stops being free.

9. **Audit gap: `get_interfaces` was never an nmap call.**
   Legacy mcp-server.py's `get_interfaces` method (line 755) ran `ip -j addr`
   and returned `{interfaces[], recommended_lhost}` (first non-loopback IPv4).
   It was bundled with nmap because LHOST discovery is recon-adjacent. In
   kind:cli this method does not exist on the nmap tool. Agents needing LHOST
   should call bash with `ip -j addr` directly (or `ip route get 1.1.1.1`,
   or read `/proc/net/route`). The new `routing.use_for` line "identify local
   network interfaces and LHOST IP (use bash + ip addr; nmap is overkill for
   this)" already redirects callers; but a routing-recipe entry on a future
   `bash` tool.yaml — or a stand-alone `network-info` mini-tool — would close
   the loop.

10. **Audit gap: `_nmap_progress_filter` regex was driving heartbeats.**
    Legacy mcp-server.py extracted progress lines (`Stats:`, `Scan Timing:
    About X% done`, `Completed ... Scan`, `Nmap scan report for`, `Discovered
    open port`) from stderr and pushed them as MCP progress notifications via
    `run_command_with_progress(..., heartbeat_interval=30.0)`. This kept the
    MCP transport alive during multi-minute silent stretches. In kind:cli the
    container runner has its own idle/heartbeat machinery (idle_timeout_seconds
    600 + max_runtime_seconds 86400), but it operates on raw stdio activity —
    not on the semantic distinction "nmap is between hosts" vs "nmap hung".
    The `gotchas` entry "Always pass -v" addresses the visibility half. The
    semantic-progress half — surfacing "About 45% done" to the user — is
    DROPPED on purpose for kind:cli (LLM can choose to tail the stdout stream
    if it cares; the runner doesn't synthesize progress events).

11. **Audit gap: per-method timeout differentiation.**
    Legacy mcp-server.py used 600s for port/service/vuln, 300s for OS
    detection, 120s for ping_scan. New tool.yaml has a single
    `timeout_seconds: 86400` (24h hard wall) and `idle_timeout_seconds: 600`
    (10 min silence). The 24h cap is intentional (covers /24 + UDP + vuln
    sweeps) but the LLM no longer gets implicit "OS detection should take
    ~5 min" guardrails. Agents should pass `--host-timeout 5m` for OS scans
    and `--host-timeout 30s` for ping sweeps. Recommendation for Wave 9:
    consider adding a `usage_pattern_timeouts` advisory section that maps
    common patterns → suggested `--host-timeout` so the LLM doesn't burn the
    full 24h on a misconfigured scan.

12. **Audit gap: error classification with `retryable` and `suggestions`
    fields.** Legacy `_classify_nmap_error` (line 331) returned a tuple
    `(error_class, retryable, suggestions[])`. Examples:
    - host-down → `("network", True, ["Retry with skip_discovery=true (-Pn)."])`
    - all-ports-closed → `("network", False, ["Try ports='1-65535'."])`
    - privilege-required → `("permission", False, ["Requires privileged mode."])`
    - DNS-failure → `("config", False, ["Use IP or check /etc/hosts."])`
    The new tool.yaml `failure_signatures` block carries the human-facing
    `remediation` text but does NOT classify by retryable / class / category.
    The runtime tool-runner classifier consumes `failure_signatures` and
    decides retry vs no-retry from the signal alone. This is a kind:cli-wide
    architectural choice (per Tier A migration), not an nmap-specific gap;
    flagging here so it's not lost. If retryability metadata becomes useful
    later, it would attach to each `failure_signatures` entry as a
    `retryable: true|false` field.

13. **Audit gap: param-level ergonomics dropped on purpose.**
    Legacy mcp-server.py exposed named parameters `top_ports`, `min_rate`,
    `max_rate`, `max_retries`, `no_dns`, `open_only`, `reason`,
    `host_timeout`, `exclude`, `version_intensity`, `default_scripts`,
    `script_args`, `scripts`, `scan_type` (enum mapped to flags),
    `timing` (enum mapped to -T0..T5), `skip_discovery` (mapped to -Pn).
    In kind:cli the LLM constructs raw argv directly. `common_options` in
    tool.yaml documents every flag; `usage_patterns` shows canonical command
    shapes. **DROPPED on purpose** — kind:cli supersedes the named-param
    surface. The audit confirms that every flag covered by a legacy
    parameter is documented in `common_options` (verified: -Pn under
    discovery; --top-ports under port_spec; --min-rate / --max-rate /
    --max-retries / --host-timeout under timing; -n under discovery; --open
    / --reason under output; --exclude under target_extraction reject_flags
    + value_flags; --version-intensity under service_detection; -sC under
    scan_type; --script-args under scripts; --script under scripts; -T0..T5
    under timing).

---

## 6. Hand-off

- **Tool**: nmap (kind:cli)
- **Status**: tier-A migrated; scenarios consolidated; tool.yaml rewritten.
  No image rebuild yet (deferred to Wave 9 batch). mcp-server.py untouched.
- **mcp-server.py**: present, untouched — auto-inherits run_cli from
  BaseMCPServer (mcp-common 0.3.0); preserves rollback path per SKILL #21.
  Legacy methods (port_scan, service_scan, os_detection, vuln_scan, ping_scan,
  get_interfaces) remain available for kind:mcp callers.
- **Dockerfile**: verified — Python + venv + mcp-common install + CMD
  `python3 mcp-server.py`. No changes needed.
- **Image**: `ghcr.io/silicon-works/mcp-tools-nmap:latest` — rebuild deferred
  to Wave 9 (batch rebuild).
- **Live-verify pending**: paste S1-S6 against Validation (10.129.95.235);
  verify failure_signature entries 1-5 still match (esp. layer-diverse signals
  that may have drifted across nmap versions); confirm privileged-mode
  plumbing works for S3 (UDP).
- **Pilot-gate sign-off**: ≥6 deliberate-failure tests authored (need live run);
  ≥25 extraction cases authored covering IP/FQDN/CIDR/range/list/IPv6/decoy/
  source/proxy/output/script-args boss-fights; gotchas updated for exit-0-on-
  host-down and privileged-mode requirements.
- **Open questions surfaced**: see section 5 — privileged-mode plumbing
  verification, multi-target argv decision, IPv6 bracket handling, CIDR scope
  validation, output-file safety, JSON output availability, concatenated short
  flags.

Authored: 2026-04-25 (Wave 1.1 Tier A migration).
