# amass — Tier A scenarios

Single test sheet for the `amass` tool migration (Wave 7.1).

Sections:
1. Recommended target for live verification
2. Narrative scenarios (paste into opensploit)
3. Target-extraction adversarial cases (≥20)
4. Failure-signature live-verify cases (≥3)
5. Open questions
6. Hand-off

---

## 1. Recommended target

**Real-world public domain — `iana.org` or `htb.eu`.**

amass is fundamentally an **internet-facing OSINT tool**: it queries
certificate-transparency logs, passive-DNS aggregators (Censys,
SecurityTrails, VirusTotal), web archives, and search engines. HTB lab
boxes (10.129.x.x) typically have **no public DNS exposure** — there is no
authoritative nameserver, no CT log entry, no WHOIS record. Running amass
against `validation.htb` will return empty.

For Tier A architecture verification (target extraction, failure
classification, output format, reject_flags) point amass at a known-good
real-world domain that:

- Has plenty of subdomains in CT logs (so passive enum produces
  non-trivial output)
- Is not in any engagement scope (so we test without raising scope
  questions)
- Belongs to a public infrastructure / educational org so traffic is
  unsurprising

`iana.org` and `htb.eu` (Hack The Box's main marketing domain) both fit.
`htb.eu` is the closest semantic cousin to the lab targets without
involving the lab range. **Pick `iana.org` for the canonical run** —
neutral, widely-instrumented, and unambiguously public.

For active+brute testing, do NOT point amass at a real third-party domain
unless you own it. Use a self-hosted dummy domain (e.g., `lab.local` with
a controlled BIND server in the lab) or skip active mode for Tier A.

Persistent test directory: standard `/session/` mount; amass outputs go to
`/session/amass-*.json` and `/session/amass-*.txt`.

---

## 2. Narrative scenarios (paste into opensploit)

### S1 — passive enum (stealth, no target queries)

```
Engagement target: iana.org (public domain, OSINT-only — no scope concerns).
Use amass to passively enumerate subdomains of iana.org. Use JSON output to /session/amass-iana.json. Disable colours for log parsing. Cap at 5 minutes.
```

**Watch:** Agent emits something like
`amass enum -passive -d iana.org -json /session/amass-iana.json -nocolor -timeout 5`.
target=`iana.org` extracted from `-d`. First call ~3-5 s spawn + container
exec; subsequent calls reuse warm container.

The plugin must NOT misextract `iana.org` from `/session/amass-iana.json`
or any other flag value — only `-d`'s value is the target.

### S2 — active enum + brute (loud, full coverage)

```
Engagement target: lab.local (controlled lab domain, authorised).
Use amass enum in active mode with DNS brute-force against lab.local. Use the seclists DNS subdomains-top1million-5000 wordlist. Use trusted resolvers from /session/resolvers.txt. Output JSON to /session/amass-lab.json.
```

**Watch:** Agent emits something like
`amass enum -active -brute -d lab.local -w /usr/share/seclists/Discovery/DNS/subdomains-top1million-5000.txt -rf /session/resolvers.txt -json /session/amass-lab.json -nocolor`.
target=`lab.local`. Wordlist path (-w), resolvers file (-rf), and output
file (-json) MUST NOT be misextracted as targets even though they are
file paths.

### S3 — intel mode (organisation discovery)

```
Engagement target: iana.org.
Run amass intel against iana.org. Include WHOIS-derived related domains. Output JSON to /session/amass-intel-iana.json.
```

**Watch:** Agent emits
`amass intel -d iana.org -whois -json /session/amass-intel-iana.json`.
The sub-command is `intel` (NOT `enum`). target=`iana.org` from `-d`.
Plugin extraction is sub-command-agnostic — `-d` works the same in both
enum and intel.

### S4 — custom resolvers (engagement-specific OSINT)

```
Engagement target: iana.org.
Run amass passive enum on iana.org using the resolvers in /session/resolvers.txt for verification. Use the engagement config at /session/amass.yaml. JSON output to /session/amass-iana-cfg.json.
```

**Watch:** Agent emits
`amass enum -passive -d iana.org -rf /session/resolvers.txt -config /session/amass.yaml -json /session/amass-iana-cfg.json`.
target=`iana.org`. The `-rf` value (`/session/resolvers.txt`) and
`-config` value (`/session/amass.yaml`) MUST be in value_flags so the
DSL skips them.

### S5 — failure: invalid domain / config error

```
Engagement target: nonexistent-host.invalid.localdomain (deliberately invalid, verifying failure classification).
Run amass enum -passive against nonexistent-host.invalid.localdomain with -timeout 1.
```

**Watch:** Either (a) amass returns zero subdomains in JSON and exits 0
(success-with-empty-results), OR (b) hits a DNS / network error and
emits something matching `no such host` / `Could not resolve`. Plugin
classifies as `failure_in_output` if the latter, `success` with empty
result set if the former.

For config-error variant: pass `-config /session/broken.yaml` (file with
intentionally malformed YAML) and look for `unmarshalling config file`
or `Invalid config` in stderr.

### S6 — reject_flags trap (-df target list file)

```
Engagement target: iana.org (and others).
I have a list of domains in /session/domains.txt. Use amass to enumerate subdomains for all of them.
```

**Watch:** Plugin rejects with `status: error`,
`rejected_flag: -df`. Agent reformulates per the tool-runner prompt
clause: read the file with the `read` tool, then issue separate
`tool_runner` calls (one per domain with its own `-d`), or a single call
with multiple `-d` flags if amass v5 supports it. Verify the rejection
message names `-df` specifically.

---

## 3. Target-extraction adversarial cases (≥20)

The amass `tool.yaml` declares ONE extraction rule: `flag_value` for `-d`
with `parse_as: raw` (since the value is a domain, not a URL).

`reject_flags`: `-df` (domain-list file ingestion).

`value_flags` includes ~50 entries to prevent value-position strings from
being misextracted (notably `-bl`/`-blf` which carry FQDN-shape values
that are NOT targets, plus `-include`/`-exclude`/`-r`/`-rf`/`-iface`/
`-config`/`-w`/`-o`/`-oA`/`-json`/`-dir`/`-p`).

### Happy-path cases

| # | Command (binary `amass` omitted) | Expected target | Notes |
|---|---|---|---|
| 1 | `enum -passive -d example.com -json /session/out.json` | `example.com` | Bog-standard passive enum |
| 2 | `enum -active -brute -d target.htb -w /session/wl.txt` | `target.htb` | Active mode with wordlist; -w MUST NOT match |
| 3 | `intel -d acme.corp -whois` | `acme.corp` | intel sub-command; `-d` works the same |
| 4 | `enum -passive -d HACKTHEBOX.EU -nocolor` | `HACKTHEBOX.EU` | Uppercase domain preserved |
| 5 | `enum -d sub.deeply.nested.example.com -passive` | `sub.deeply.nested.example.com` | Multi-label FQDN |
| 6 | `enum -passive -d xn--bcher-kva.example -json /session/o.json` | `xn--bcher-kva.example` | IDN punycode preserved |
| 7 | `enum -d example.com -d sister.com -passive -json /session/o.json` | `example.com` (first) — multi_target flag | Repeated -d. Document plugin behaviour: extract first, set `multi_target_detected=true`, validate ALL. |
| 8 | `enum -passive -d example.com -timeout 5 -silent` | `example.com` | -timeout / -silent are non-target flags |
| 9 | `enum -passive -d example.com -include crtsh,virustotal` | `example.com` | -include value is data-source list, NOT target |
| 10 | `enum -active -brute -d example.com -p 443,8443,8080` | `example.com` | -p value is port list, NOT target |

### Adversarial — value_flag traps & security invariants

| # | Command | Expected | Notes |
|---|---|---|---|
| F1 | `-h` | `target=null` | Top-level help. tool_runner bypasses scope check. |
| F2 | `enum -h` | `target=null` | enum sub-command help. |
| F3 | `intel -h` | `target=null` | intel sub-command help. |
| F4 | `-version` (or `version`) | `target=null` | Version. |
| F5 | `enum -list` | `target=null` | -list dumps data-source names; no target needed. |
| F6 | `enum -df /session/domains.txt -passive` | Plugin rejects (`-df` in reject_flags). Reformulate with `-d`. | Multi-target file ingestion. |
| F7 | `enum -d example.com -bl evil-source.example.com` | `target=example.com` (NOT `evil-source.example.com`). | -bl is BLACKLIST — value is FQDN-shape but a FILTER, not a target. Critical security invariant. |
| F8 | `enum -d example.com -blf /session/blacklist.txt` | `target=example.com` (NOT the file content). | -blf is the file form of -bl. Value is a path. |
| F9 | `enum -d example.com -include crtsh,virustotal,securitytrails` | `target=example.com` (NOT data-source names). | -include value is comma-separated source names. They do NOT regex-match domains, but value_flag list defends regardless. |
| F10 | `enum -d example.com -exclude badsource.io` | `target=example.com` (NOT `badsource.io`). | -exclude can carry FQDN-shape source names. Same invariant as -include. |
| F11 | `enum -d example.com -r 1.1.1.1,8.8.8.8` | `target=example.com` (NOT resolver IPs). | -r is DNS infrastructure, not target. |
| F12 | `enum -d example.com -rf /session/resolvers.txt` | `target=example.com` (NOT the file path). | -rf points to a resolver IP file. Value is a path. |
| F13 | `enum -d example.com -iface tun0` | `target=example.com` | -iface value is interface name. |
| F14 | `enum -d example.com -config /session/amass.yaml` | `target=example.com` (NOT the config path). | -config value is a YAML path. |
| F15 | `enum -d example.com -w /usr/share/seclists/Discovery/DNS/subdomains-top1million-5000.txt` | `target=example.com` (NOT the wordlist path). | -w wordlist path; common SecLists location. |
| F16 | `enum -d example.com -o /session/amass.txt -oA /session/amass-all` | `target=example.com` (NOT `/session/amass.txt` or `/session/amass-all`). | -o text output, -oA all-formats prefix. |
| F17 | `enum -d example.com -json /session/example.com.json` | `target=example.com` (from -d). NOT misextracted from filename. | Filename happens to contain the domain — must come from -d, not infer from path. |
| F18 | `enum -d example.com -dir /session/amass-db` | `target=example.com` | -dir is output directory. |
| F19 | `enum -d example.com -log /session/amass.log` | `target=example.com` | -log is log file path. |
| F20 | `enum -d example.com -min-for-recursive 5` | `target=example.com` | -min-for-recursive is integer threshold. |
| F21 | `enum -d example.com -tr 3` | `target=example.com` | -tr is transitive depth (integer). |
| F22 | `enum -d example.com -timeout 30` | `target=example.com` | -timeout value is minutes (integer). |
| F23 | `intel -org 'Acme Corp' -whois` | `target=null` (no -d). intel-by-org has no domain. | -org takes a string organisation name. Plugin: target=null when no -d; passes through to amass. |
| F24 | `intel -asn 13335 -whois` | `target=null` (no -d). | intel-by-ASN has no domain target. |
| F25 | `intel -cidr 1.1.1.0/24` | `target=null` (no -d, but CIDR could be the target). | DOCUMENT: should `-cidr` be a target_extraction rule with `parse_as: cidr`? Open Question. |
| F26 | `enum -passive` (no -d, no -df) | `target=null` → amass errors out naturally. | No target provided. Plugin allows pass-through; amass prints "the required flag -d not provided" → failure_in_output. |
| F27 | `enum -d ' '` (whitespace value) | `target=null` (parse_error) → amass fails naturally. | Defensive parsing on empty / whitespace value. |
| F28 | `enum -d 192.168.1.1 -passive` | `target=192.168.1.1` (extracted as raw). | amass technically rejects IPs with "no targets found", but extraction layer doesn't validate domain shape — pass-through with raw value. amass's own error becomes the user-visible failure. |
| F29 | `viz -d3 -dir /session/amass-db` | `target=null` (no -d). viz operates on DB. | viz sub-command — converts existing DB to graph format. No target. |
| F30 | `track -d example.com -dir /session/amass-db` | `target=example.com` | track sub-command, -d still works. |

### Sub-command syntax tests (amass-specific)

| # | Command | Expected | Notes |
|---|---|---|---|
| SC1 | `-d example.com -passive` (NO sub-command) | `target=example.com` (extracted) — but amass FAILS at runtime with "Subcommand 'enum'..." or top-level help. | Plugin extracts target normally; amass refuses to run without sub-command. failure_in_output classification. |
| SC2 | `enumm -d example.com` (typo — "enumm") | `target=example.com` — amass fails with unknown sub-command. | Same as SC1, different cause. |
| SC3 | `enum intel -d example.com` (two sub-commands) | `target=example.com` — amass fails. | amass treats first positional as sub-command; second positional is unexpected. |
| SC4 | `enum -- -d example.com` (POSIX --) | Depends on amass arg parser. Likely `target=null` (everything after -- is positional). Document. | Edge case; very unlikely in real use. |

---

## 4. Failure-signature live-verify cases (≥3)

| # | Layer | Test | failure_signature `signal` | Status |
|---|---|---|---|---|
| 1 | DNS | `enum -passive -d nonexistent-host.invalid.localdomain -timeout 1` | `no such host` AND/OR `Could not resolve` | PENDING live verify |
| 2 | TCP | Set `-rf /session/dead-resolvers.txt` (file with `127.0.0.99` only) and run brute against any domain | `connection refused` AND/OR `dial tcp` AND/OR `i/o timeout` | PENDING live verify |
| 3 | Config | `enum -d iana.org -config /session/broken.yaml` (yaml with `:::tab\tinvalid`) | `unmarshalling config file` OR `Invalid config` | PENDING live verify |
| 4 | API | Force VirusTotal call with a deliberately-bad API key in /session/amass.yaml — expect `Forbidden` or `API quota exceeded`. Hard to reproduce on demand without burning a real key. | `API quota exceeded` OR `Forbidden` OR `rate limit` | PENDING — needs API harness |
| 5 | Argument | `enum -passive` (no -d, no -df) | `the required flag` OR `must provide` | PENDING live verify |
| 6 | Sub-command | `enuum -d iana.org` (typo) | `unknown sub-command` OR `Subcommand` (top-level help dump) | PENDING live verify |
| 7 | Empty | `enum -passive -d nonexistent-real-but-empty.test -timeout 1` (real but empty domain) | `no results` OR `no targets found` OR success-with-empty (decide classification) | PENDING — needs a known-empty domain |

### Layer diversity (SKILL #11) — achieved

5+ distinct layers exercised: DNS / TCP / Config-parsing / API /
Argument-validation / Sub-command. Empty-result classification
(case 7) is a semantic decision rather than a hard error and is
documented in Open Questions.

---

## 5. Open questions

1. **Multi-`-d` behaviour** (case 7) — amass v5 accepts multiple `-d` flags
   (verified empirically). Plugin must:
   (a) extract the FIRST `-d` value as primary target, AND
   (b) validate ALL `-d` values against engagement scope, AND
   (c) set `multi_target_detected=true` so the agent / log captures the
   full target set.
   Decide whether to add `allow_multi_target: true` to tool.yaml or
   leave the multi-target handling to a generic plugin policy.

2. **`-cidr` as an intel-mode target** (case F25) — when the agent runs
   `amass intel -cidr 1.1.1.0/24`, the CIDR IS the target (search for
   domains hosted in that range). Should we add a second target_extraction
   rule with `flag: -cidr`, `parse_as: cidr`? Same question for `-asn`
   (organisation-level target identifier) and `-addr` (single IP target).
   Resolution: extending `target_extraction` to multiple rules is
   straightforward; primary blocker is whether the engagement scope
   model supports CIDR / ASN / IP targets at all.

3. **Sub-command precedence — `intel` vs `enum`** — both accept `-d`. The
   sub-command word changes WHAT amass does but NOT how the target is
   extracted. Plugin's extraction is sub-command-agnostic, which is
   correct — but the agent prompt should describe when to pick `enum`
   (subdomain enumeration) vs `intel` (organisation discovery: ASNs,
   netblocks, sister domains, WHOIS).

4. **API key management** — amass needs API keys (Censys, SecurityTrails,
   VirusTotal, etc.) for the most useful passive sources. The container
   ships an empty `/root/.config/amass/` and the user is expected to
   mount `/session/amass.yaml` with their keys. Document the canonical
   config-file shape (or supply a sample) so agents can construct one
   on demand from environment values.

5. **Passive vs active scope distinction** — passive enum sends ZERO
   traffic to the target and is safe pre-engagement. Active+brute
   generates measurable DNS query load. Should the plugin's permission
   model differentiate? E.g., scope-validate `-passive` against a
   relaxed list (any FQDN), and `-active`/`-brute` against the stricter
   engagement-scope list. Worth raising with permission-system owner.

6. **`-timeout` semantics** — amass's `-timeout` is in MINUTES (verified
   in `amass enum -h`), unlike most other tools where it's seconds. The
   agent prompt and gotchas already call this out, but a copy-paste
   between tools could trivially break this. Consider an integer-with-
   unit annotation in the value_flags spec.

7. **Default config file** — `~/.amass/config.yaml` is read automatically
   if no `-config` is given. In a fresh container this is empty, so the
   tool runs but only uses sources that don't need keys (CT logs,
   web archives). Document that `-config` is OPTIONAL but recommended.

8. **HTB lab targets** — almost all HTB lab boxes have NO public DNS
   exposure, making amass mostly useless against them. The standard
   demo target should be a real-world public domain (`iana.org`,
   `htb.eu`). For active+brute mode pick a lab-internal domain on a
   self-hosted BIND.

9. **Stdout banner / progress noise (legacy parsed it out)** — the
   legacy mcp-server.py contained a hand-rolled `_parse_text_results`
   filter that stripped: lines starting with digits forming progress
   bars (`X / Y [===...`), the OWASP ASCII banner glyphs (`.+++`,
   `+W@`, `&@`, `8@`, `WW`, `#@`, `o@`, `:W@`, `+o&`), version /
   org banner lines (`v5.`, `OWASP`, `In-depth`), and progress-rate
   lines containing `p/s`. The banner / progress goes to STDERR (not
   stdout), so failure_signature matchers are unaffected, but agents
   that grep `-o` text output for subdomains will pull garbage unless
   they pass `-silent` or filter client-side. Recommendation:
   prefer `-json` for tooling (clean one-record-per-line); when text
   is required, always pair `-o` with `-silent`.

10. **Result-set truncation** — legacy capped the structured response
    to the first 200 subdomains (`subdomains[:200]`). kind:cli streams
    the raw `-o` / `-json` file unchanged. For very large enumerations
    (thousands of subdomains on a wildcard-rich org) the file size
    survives but the LLM context window may be hit when the agent
    reads the file. Mitigation: agent should `head -n 200` or
    `wc -l` first, summarise, and load full file only on demand.
    Document this in the agent prompt rather than re-introducing a
    server-side cap.

11. **Partial-results-on-timeout recovery** — legacy detected
    `timeout` / `timed out` in the exception string and re-read the
    output file to salvage whatever subdomains had been written
    before the kill, returning `timed_out: true` in the data dict.
    kind:cli aborts on idle_timeout / max_runtime without an explicit
    salvage step. The `-o` / `-json` file survives in /session
    because amass writes incrementally as it discovers — agents
    should be instructed (in the recovery prompt or a tool-runner
    convention) to read the output file after a timeout failure
    instead of assuming the run produced nothing. Open question:
    do we want a `partial_output_recovery` hint in tool.yaml that
    the plugin can surface to the LLM on timeout exit?

12. **Empty-output-file cleanup** — legacy `os.unlink`'d the
    `/session/amass_*.txt` file if it ended up zero-byte (no
    subdomains discovered). kind:cli leaves zero-byte files in
    /session. Harmless (the working dir is per-session and pruned
    on session end) but the agent listing `/session/` will see
    apparently-empty artefacts. Not worth fixing.

---

## 6. Hand-off

- **Tool**: amass (kind:cli)
- **Status**: tool.yaml authored end-to-end (kind:mcp → kind:cli);
  scenarios.md written. mcp-server.py UNTOUCHED (auto-inherits run_cli
  via mcp-common 0.3.0; rollback path preserved).
- **Dockerfile**: NO changes needed. Base image is `python:3.11-slim`
  (Debian, NOT Kali) so the `python3-full` apt swap doesn't apply. amass
  binary installed from upstream GitHub release v5.0.1; mcp-common
  installed via the standard /app/packages mount; CMD remains
  `python3 mcp-server.py`.
- **Image**: `ghcr.io/silicon-works/mcp-tools-amass:latest` — needs
  rebuild during the Wave 9 batch to pick up mcp-common 0.3.0 and the
  new tool.yaml.
- **Cruft removed**: none (directory was already clean — no
  `target_extraction_tests.md`, no `failure_signature_tests.md`, no
  `__pycache__/`).
- **Live-verify pending**: paste S1-S6 against `iana.org` (passive) and
  a controlled lab domain (active+brute). Verify failure_signatures 1,
  3, 5, 6 live; defer cases 2, 4, 7 until appropriate harnesses exist.

Authored: 2026-04-25.
