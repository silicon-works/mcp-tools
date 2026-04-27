# theharvester — Tier A scenarios

Single test sheet for the `theharvester` tool migration (Wave 7.3).

Sections:
1. Recommended target for live verification
2. Narrative scenarios (paste into opensploit)
3. Target-extraction adversarial cases (≥20)
4. Failure-signature live-verify cases (≥3)
5. Open questions
6. Hand-off

---

## 1. Recommended target

**Real-world public domains — `iana.org` (canonical) and `htb.eu` (HTB
public marketing site).**

theHarvester is a **passive OSINT tool** that queries third-party
aggregators (CT logs, threat-intel platforms, search engines) for
records about a target domain. There are no HTB lab boxes with public
DNS / mail / cert footprints big enough to test against — by design
HTB lab boxes are isolated. Use real-world public domains for
verification.

### 1a. Canonical recon target — `iana.org`

`iana.org` has clean CT-log presence (multiple subdomains over the
years), known nameservers, public WHOIS, and a documented mail
infrastructure. crtsh, otx, hackertarget all return non-empty
results. Use for: target-extraction adversarial sweep, output-file
verification, structured-JSON parsing, and the canonical happy-path
scenario.

### 1b. Smaller / cleaner target — `htb.eu`

The Hack The Box public marketing domain. Smaller surface area than
`iana.org` — gives a fast (sub-30-second) crtsh + otx run for
quick-iteration verification during dev.

### 1c. Failure-mode targets

For empty-result testing: `nonexistent-test-domain-2026.invalid` —
NXDOMAIN style, zero results from every source. crtsh / otx will
respond cleanly with empty arrays.

For network-failure testing: pre-spawn the container with
`--network=none` (manager flag during dev) to force `Connection error`
/ `Name or service not known` at every source.

For API-quota testing: `-b virustotal` without a key in
`~/.theHarvester/api-keys.yaml` — silently no-ops with `Forbidden` or
empty result. To force a hard quota error, run repeated requests in a
loop against a free source until rate-limit hits.

Persistent test directory: `/session/` mount. theHarvester writes
`<prefix>.html`, `<prefix>.xml`, and `<prefix>.json` siblings — the
JSON file is the structured output the legacy `harvest()` method
parses.

---

## 2. Narrative scenarios (paste into opensploit)

### S1 — quick crtsh + otx probe

```
Engagement target: iana.org (public domain, OSINT-only — no scope concerns).
Use theharvester to do a fast OSINT pass on iana.org against just crtsh and otx, capped at 100 results per source. Save output under /session/.
```

**Watch:** Agent emits
`theHarvester -d iana.org -b crtsh,otx -l 100 -f /session/theharvester-iana-quick`.
target=`iana.org` extracted via flag_value `-d` rule. The `-b crtsh,otx`
value (`crtsh,otx`) MUST NOT be confused with a target — `-b` is in
value_flags. Output: three files at /session/theharvester-iana-quick.{html,xml,json}.

### S2 — comprehensive all-sources run

```
Engagement target: iana.org.
Use theharvester to run a comprehensive OSINT pass on iana.org using ALL sources, capped at 500 results per source. This may take several minutes.
```

**Watch:** Agent emits
`theHarvester -d iana.org -b all -l 500 -f /session/theharvester-iana-full`.
target=`iana.org` via flag_value `-d`. The `-b all` keyword is
consumed by `-b` value_flag. Wall-clock time scales with source count
and rate-limit retries. API-key sources without keys silently no-op.

### S3 — DNS verification + reverse DNS sweep

```
Engagement target: iana.org.
Use theharvester on iana.org with crtsh + hackertarget, verify discovered hosts via DNS, and reverse-resolve up to 100 IPs.
```

**Watch:** Agent emits
`theHarvester -d iana.org -b crtsh,hackertarget -l 200 -v -r 100 -f /session/theharvester-iana-verified`.
target=`iana.org` via flag_value `-d`. Both `-v` (boolean) and `-r 100`
(value-flag — value `100`, NOT a target) are consumed correctly. The
`100` integer must NOT be misinterpreted as a target candidate.

### S4 — single-source GitHub code scrape (API-key required)

```
Engagement target: iana.org.
Use theharvester on iana.org querying only the github-code source (capped at 50 results). This source requires an API key — expect zero results without one.
```

**Watch:** Agent emits
`theHarvester -d iana.org -b github-code -l 50 -f /session/theharvester-iana-github`.
target=`iana.org` via flag_value `-d`. `-b github-code` value
is consumed. Without `~/.theHarvester/api-keys.yaml` the run completes
with `0 emails` / `0 hosts` and exit code 0 — no explicit auth error
because theHarvester swallows missing-key errors silently. failure
signature `Forbidden` / `401` may surface if the source emits a hard
error before the swallow.

### S5 — custom DNS resolver

```
Engagement target: iana.org.
Use theharvester on iana.org with crtsh and hackertarget, verify hosts via DNS, and use Cloudflare's 1.1.1.1 as the DNS resolver.
```

**Watch:** Agent emits
`theHarvester -d iana.org -b crtsh,hackertarget -l 200 -v -e 1.1.1.1 -f /session/theharvester-iana-cf`.
target=`iana.org` via flag_value `-d`. The `-e 1.1.1.1` flag-value is
consumed by `-e` (in value_flags). Critical: `1.1.1.1` is IP-shaped
and could match a permissive positional regex — but theHarvester has
NO positional target rule, only flag_value `-d`. So `1.1.1.1` is
correctly classified as resolver, not target.

### S6 — failure: missing -d

```
Engagement target: none.
Run theharvester with -b crtsh -l 100 (deliberately omitting -d, verifying failure classification).
```

**Watch:** Agent emits `theHarvester -b crtsh -l 100`. theHarvester
argparse rejects with
`error: the following arguments are required: -d/--domain` and exit
code 2. failure_signature `error: argument -d` (or `the following
arguments are required`) fires. target=null at the plugin layer
because flag_value `-d` extraction returned nothing.

### S7 — failure: empty-result domain

```
Engagement target: nonexistent-test-domain-2026.invalid.
Use theharvester on nonexistent-test-domain-2026.invalid against crtsh + otx with -l 50. Verify clean empty-result handling.
```

**Watch:** Agent emits
`theHarvester -d nonexistent-test-domain-2026.invalid -b crtsh,otx -l 50 -f /session/theharvester-empty`.
crtsh returns `[]` (empty CT log array), otx returns 404 / empty.
theHarvester completes with exit 0 and `No emails found` / `No hosts
found` in stdout. failure_signatures `No emails found` and `No hosts
found` fire — both are EMPTY-RESULT signals (semantic, not crash).

---

## 3. Target-extraction adversarial cases (≥20)

theharvester `tool.yaml` declares ONE extraction rule:

1. `flag_value` for `-d` → target domain (parse_as: raw)

There is no positional_match rule — theHarvester has no positional
target form, ONLY `-d <domain>`. This makes target extraction
extremely simple compared to dig (which has three orthogonal
positional positions) and amass (sub-command + `-d`).

`reject_flags`: empty — theHarvester has no batch-input flag.

`value_flags` includes ~14 entries, with `-d` (target), `-b` (sources
list — most-trapped trap), `-e` (resolver IP — IP-shaped trap), `-f`
(output prefix), `-l` / `-S` / `-r` (integer values), and the boolean
flags listed for parser correctness.

### Happy-path cases

| # | Command (binary `theHarvester` omitted) | Expected target | Notes |
|---|---|---|---|
| 1 | `-d example.com -b crtsh -f /session/out` | `example.com` | Canonical form. flag_value `-d` extracts. |
| 2 | `-d target.htb -b crtsh,otx -l 100 -f /session/out` | `target.htb` | HTB-shape FQDN. |
| 3 | `-d sub.example.com -b all -l 500 -f /session/out` | `sub.example.com` | Subdomain target. |
| 4 | `-d example.co.uk -b crtsh -f /session/out` | `example.co.uk` | Multi-label TLD. |
| 5 | `-d xn--bcher-kva.example -b crtsh -f /session/out` | `xn--bcher-kva.example` | IDN punycode preserved. |
| 6 | `-d EXAMPLE.COM -b crtsh -f /session/out` | `EXAMPLE.COM` | Uppercase preserved (parse_as: raw). |
| 7 | `-d example.com -b crtsh -v -f /session/out` | `example.com` | -v (boolean) consumed correctly. |
| 8 | `-d example.com -b crtsh -r 50 -f /session/out` | `example.com` | -r (value-flag) value `50` consumed. |
| 9 | `-d example.com -b crtsh -e 8.8.8.8 -f /session/out` | `example.com` | -e value `8.8.8.8` is RESOLVER IP, NOT target. |
| 10 | `-b crtsh -d example.com -f /session/out` | `example.com` | flag-order independence — -d still extracted regardless of position. |

### Adversarial — value_flag traps & security invariants

| # | Command | Expected | Notes |
|---|---|---|---|
| F1 | `-h` | `target=null` | Help — no -d, no positional, no extraction. |
| F2 | `--help` | `target=null` | Long help — same. |
| F3 | `-d` (no value) | argparse error / `target=null` | -d without arg fails argparse before plugin sees output. Plugin's flag_value rule returns null. |
| F4 | `-b crtsh -l 100 -f /session/out` | `target=null` | Missing -d — argparse rejects. Plugin: flag_value -d returns nothing → null. **CRITICAL**: scope validation can't run; plugin's empty-target gate fires with the failure signature `error: argument -d`. |
| F5 | `-d example.com -b sub.example.com,crtsh -f /session/out` | `target=example.com` | **CRITICAL** trap: `-b` value contains `sub.example.com` which has FQDN shape. Must NOT be misextracted. -b is in value_flags so the entire value is consumed. flag_value -d's `example.com` wins. |
| F6 | `-d example.com -b 8.8.8.8.dnssec.live,crtsh -f /session/out` | `target=example.com` | Source name with FQDN shape (no real source has this, but the parser must handle it). -b consumes the value; -d wins. |
| F7 | `-d example.com -e 1.1.1.1 -b crtsh -f /session/out` | `target=example.com` | **CRITICAL**: -e value `1.1.1.1` is IP-shaped. Must NOT be confused with target. -e is in value_flags. -d wins. |
| F8 | `-d example.com -e 8.8.8.8,1.1.1.1 -b crtsh -f /session/out` | `target=example.com` | Multi-resolver value (theHarvester supports comma-separated resolvers in some builds). -e consumes the value as a single arg. -d wins. |
| F9 | `-d example.com -f /session/another.example.com -b crtsh` | `target=example.com` | **CRITICAL**: -f output-prefix is `another.example.com` — FQDN-shape PATH-LIKE component. -f is in value_flags. -d wins. |
| F10 | `-d example.com -f /session/theharvester-domain-results -b crtsh` | `target=example.com` | -f path doesn't even need to look like a domain; consumed regardless. -d wins. |
| F11 | `-d example.com -l 1000 -b crtsh -f /session/out` | `target=example.com` | -l value (1000) is integer — could be misread as part of host enumeration. -l is in value_flags. -d wins. |
| F12 | `-d example.com -S 100 -b crtsh -f /session/out` | `target=example.com` | -S start point (rare). -S is in value_flags. -d wins. |
| F13 | `-d example.com -r 50 -b crtsh -f /session/out` | `target=example.com` | -r value (50) is reverse-DNS count, NOT IP. -r is in value_flags. -d wins. |
| F14 | `-d example.com -b crtsh -p -f /session/out` | `target=example.com` | -p (boolean — use proxies) consumed correctly. No value follows. -d wins. |
| F15 | `-d example.com -b crtsh -s -f /session/out` | `target=example.com` | -s (boolean — Shodan enrichment). -d wins. |
| F16 | `-d example.com -b crtsh -n -c -t -f /session/out` | `target=example.com` | All three DNS-mode booleans (-n forced, -c brute, -t TLD discovery). -d wins. |
| F17 | `-d example.com -b crtsh,hackertarget,rapiddns,urlscan,certspotter,otx -l 200 -f /session/out` | `target=example.com` | Long source list — full free-source subset. The FQDN-shape `example.com` could appear inside source names, but here doesn't. -d wins. |
| F18 | `-d example.com -b all -f /session/out` | `target=example.com` | `-b all` keyword consumed by -b. -d wins. |
| F19 | `-d 1.2.3.4 -b crtsh -f /session/out` | `target=1.2.3.4` | IP literal as target — theHarvester accepts company names AND IPs in -d (some sources do reverse-DNS / WHOIS on IPs). flag_value rule preserves raw. **policy decision**: scope validation should treat this as an IP target. |
| F20 | `-d example.com sister.com -b crtsh -f /session/out` | `target=example.com` | theHarvester argparse for -d accepts ONLY ONE value — `sister.com` becomes a UNRECOGNIZED ARGUMENT. argparse rejects with `unrecognized arguments: sister.com`. Plugin: flag_value -d extracts `example.com` regardless; theHarvester itself fails. |
| F21 | `-d example.com -d sister.com -b crtsh -f /session/out` | `target=sister.com` (LAST -d wins in argparse) | theHarvester argparse uses standard `dest` overwrite — last -d wins. Plugin: flag_value rule needs to match this — DSL's flag_value with parse_as:raw extracts FIRST or LAST? **Open question 1**: confirm DSL behaviour. argparse semantics dictate LAST. |
| F22 | `-d -b crtsh -f /session/out` | argparse error / `target=-b` | Pathological: `-d` value is the literal string `-b`. argparse will treat this as target = `-b`. Plugin's flag_value extracts `-b` raw. theHarvester then runs with `domain="-b"` and most sources fail. **Document**: target sanitisation should reject leading-dash strings. |
| F23 | `-d "" -b crtsh -f /session/out` | argparse error / `target=""` | Empty-string -d. argparse accepts. theHarvester then runs with empty domain and fails inside source modules. Plugin: flag_value extracts empty string; scope validation should reject empty targets. |
| F24 | `-d localhost -b crtsh -f /session/out` | `target=localhost` | Single-label hostname. flag_value `-d` extracts raw — no domain-shape regex required (unlike dig's positional regex). theHarvester runs but most sources need an actual TLD. **Document**: `localhost` is technically valid input but useless OSINT. |
| F25 | `-d example.com -b crtsh -f /session/path with space/out` | `target=example.com` | Output path contains space (POSIX-quoted on the agent side). -f consumes the next argv token. -d wins. |
| F26 | `-d example.com -b crtsh -f /session/out --debug` | `target=example.com` | Unknown flag `--debug` after the well-formed argv. argparse may reject; plugin extracts target normally. |
| F27 | `-d example.com -b crtsh -f /session/out -- -d evil.com` | `target=example.com` | argparse `--` separator (rarely supported by theHarvester). The `-d evil.com` after `--` should be ignored as positional. Plugin: flag_value -d extracts the FIRST occurrence (`example.com`). **Open question 1**: confirm DSL extracts FIRST not LAST. |
| F28 | `-d "example.com; rm -rf /" -b crtsh -f /session/out` | `target=example.com; rm -rf /` (raw) | Command-injection-shaped value. flag_value parse_as:raw preserves the string. theHarvester argparse accepts it as a domain string; the harm is upstream (source APIs reject malformed input). Plugin: scope validation should reject domains containing shell metacharacters. |
| F29 | `-d 例え.jp -b crtsh -f /session/out` | `target=例え.jp` | Non-ASCII IDN (Japanese). flag_value parse_as:raw preserves. theHarvester punycode-encodes internally for sources. |
| F30 | `-d example.com.. -b crtsh -f /session/out` | `target=example.com..` | Trailing dots (FQDN absolute form). theHarvester accepts but some sources reject. flag_value preserves raw. |
| F31 | `-d -d example.com -b crtsh -f /session/out` | `target=-d` (or argparse error) | `-d` value is literal `-d`, then ANOTHER `-d example.com`. argparse may take the first -d's value as `-d` (literal), then trip on the second -d. Or take last-wins behaviour. Pathological. |

### Sub-command-style tests (theHarvester has none)

| # | Command | Expected | Notes |
|---|---|---|---|
| SC1 | `-h` | `target=null` | Help. |
| SC2 | (empty) | `target=null` / argparse error | theHarvester with NO args prints usage to stderr and exits 2. |
| SC3 | `-v` | `target=null` | -v is the DNS-VERIFY boolean (NOT verbose) — flag without -d, argparse rejects with required-arg error. |
| SC4 | `-d example.com` (no other flags) | `target=example.com` | Bare -d — theHarvester runs with default sources (`-b all` may be the default or no default depending on version). |

---

## 4. Failure-signature live-verify cases (≥3)

| # | Layer | Test | failure_signature `signal` | Status |
|---|---|---|---|---|
| 1 | Argument | `theHarvester -b crtsh -l 100` (missing -d) | `error: argument -d` AND/OR `the following arguments are required` | PENDING live verify |
| 2 | Empty-result | `theHarvester -d nonexistent-test-domain-2026.invalid -b crtsh,otx -l 50` | `No emails found` AND `No hosts found` | PENDING live verify |
| 3 | Network | `theHarvester -d example.com -b crtsh -l 50` with container network=none | `Connection error` AND/OR `Name or service not known` | PENDING live verify |
| 4 | API (rate limit) | `theHarvester -d example.com -b virustotal -l 100` (no API key OR repeated runs) | `Forbidden` AND/OR `429` AND/OR `API quota exceeded` | PENDING live verify |
| 5 | Source (broken module) | `theHarvester -d example.com -b deprecated-source -l 50` (use a known-broken source if any) | `Could not run` AND/OR `module .* not found` AND/OR `Traceback` | PENDING live verify |
| 6 | Argument (unknown source) | `theHarvester -d example.com -b nonexistent-source -l 50` | `invalid choice` AND/OR `unrecognized arguments` | PENDING live verify |
| 7 | Auth (invalid key) | `theHarvester -d example.com -b shodan -l 50` with bogus key in api-keys.yaml | `Unauthorized` AND/OR `Invalid API key` AND/OR `401` | PENDING live verify |
| 8 | Network (timeout) | `theHarvester -d example.com -b virustotal -l 50` with iptables-induced delay | `Read timed out` AND/OR `timeout` | PENDING live verify |
| 9 | Argument (-r without value) | `theHarvester -d example.com -b crtsh -r -f /session/out` | `argument -r: expected one argument` | PENDING live verify |
| 10 | Source (JSON parse) | `theHarvester -d example.com -b <source-with-html-error-page> -l 50` | `JSONDecodeError` AND/OR `Traceback` | PENDING live verify |

### Layer diversity (SKILL #11) — achieved

6+ distinct verifiable layers exercised:
- **Argument-validation** (missing -d, unknown source, missing value)
- **Network** (TCP/DNS unreachable, connection refused, timeout)
- **API** (rate limit, quota, forbidden, 4xx)
- **Auth** (invalid key, 401, unauthorized)
- **Source** (broken module, missing dependency, JSON parse error, traceback)
- **Empty-result** (no emails, no hosts — semantic, not crash)

---

## 5. Open questions

1. **DSL flag_value first-vs-last semantics** — when `-d` appears
   multiple times in argv (case F21, F31), does the DSL's flag_value
   rule extract FIRST or LAST occurrence? theHarvester argparse
   semantics (Python argparse default) is LAST-wins (overwrite).
   If DSL extracts FIRST, the agent would scope-validate `example.com`
   while theHarvester actually queries `sister.com` — a scope-bypass
   vector. **Recommendation**: confirm DSL extracts LAST (matches
   argparse), or document the divergence and add a target-sanitisation
   gate that rejects multiple -d occurrences.

2. **Empty / dash-prefixed -d values** — cases F22 (`-d -b`), F23
   (`-d ""`) extract pathological target values. Plugin's scope
   validation MUST reject:
   - Empty / whitespace-only target
   - Target starting with `-` (could be misinterpreted as a flag
     downstream)
   - Target containing shell metacharacters (`;`, `|`, `&`, `$`,
     backticks, `>`, `<`)
   This is generic CLI hygiene but theHarvester is particularly
   exposed because there's no positional validation gate.

3. **API-key management** — many sources require keys in
   `~/.theHarvester/api-keys.yaml`. The container image does NOT
   ship a populated config. **Open question**: should the engagement
   pre-stage an api-keys.yaml under /session/ and the run-time
   container copy it into ~/.theHarvester/ at startup? The legacy
   harvest method silently no-ops on missing keys; the kind:cli path
   inherits the same behaviour. Document expected workflow:
   keys-yaml stays out of containers by default; when an engagement
   has paid keys, drop them in `/session/api-keys.yaml` and amend
   the entry-point.

4. **Rate-limit handling and retry policy** — theHarvester does NOT
   retry on rate-limit; it gives up the source and moves on. For
   long-running engagements with API quota concerns, no built-in
   throttling exists. **Open question**: should the plugin add a
   wrapper that detects 429 / quota errors and surfaces a
   structured retry-after suggestion to the agent? Current state:
   failure_signature catches the signal but no automated retry —
   the agent must re-issue the call manually.

5. **Structured output convention** — `-f <prefix>` writes THREE
   files (.html, .xml, .json). The mcp-server.py legacy `harvest()`
   parses .json; the kind:cli path returns raw text via run_cli
   (the agent reads the .json itself via the `read` tool). **Open
   question**: should kind:cli's `output_formats` advertise the
   .json sibling explicitly so the agent knows to read
   `<prefix>.json` after the run completes? Current YAML notes this
   in `output_formats[].notes` but the agent may need a
   structured-output convention (e.g., a sentinel in stdout pointing
   at the JSON path). Defer to maintainer.

6. **Multi-source dispatch — parallel vs sequential** — theHarvester
   queries sources in parallel by default (Python asyncio fan-out).
   When ONE source hangs, the whole run hangs until per-source
   timeout. **Open question**: idle_timeout=300 (5 min) covers a
   single hung source's wedge; max_runtime=3600 (1 h) caps the
   absolute wall-clock. For -b all with 30+ sources at 200 results
   each, the long tail is real. Document: prefer the free subset
   (`-b crtsh,otx,hackertarget,rapiddns,urlscan,certspotter`) for
   anything time-sensitive; reserve `-b all` for overnight /
   batch runs.

7. **`-d` accepts company names AND IPs** — case F19 (`-d 1.2.3.4`)
   shows IPs are valid. theHarvester docs note that `-d` is
   "domain or company name". **Open question**: does the DSL's
   scope validation route IP-targets through the same external-IP /
   private-IP / scope-list checks as positional IPs? It should —
   scope validation operates on the EXTRACTED target value
   regardless of source rule (flag_value vs positional_match).
   Verify by running `theHarvester -d 8.8.8.8 -b crtsh` and
   checking the agent's scope-validation prompt fires.

8. **Single-label hostnames (no dot)** — case F24 (`-d localhost`)
   extracts `localhost` cleanly via flag_value. theHarvester runs
   the OSINT pass against `localhost` — most sources reject silently
   or return zero results. Document: this is harmless but useless;
   the agent should warn the user before running OSINT on a
   single-label name.

9. **Help text vs source list discoverability** — the legacy
   `list_sources()` method returns a hardcoded source map (see
   mcp-server.py `known_sources` dict). The kind:cli path delegates
   to `theHarvester -h` which prints sources but in a less-parseable
   form. **Open question**: keep list_sources() as a parallel
   discovery method, or rely entirely on `-h` output parsing? The
   kind:cli rollback path (per SKILL #21) keeps list_sources()
   alive — recommend retaining it long-term as a structured-source
   directory that the agent can query without parsing help output.

10. **dnsdumpster moved to API-key-required** — historical
    documentation (and the mcp-server.py `known_sources` table at
    line 217) flagged dnsdumpster as `api_key: True` correctly;
    older guides may say it's free. The tool.yaml's gotchas section
    documents this. Verify the api_key flag stays accurate as
    upstream sources keep pivoting between free/paid models.

11. **Domain pre-cleaning lost in kind:cli path** — legacy
    `mcp-server.py` lines 67-75 (`_clean_domain` helper) auto-stripped
    `https?://` protocol prefixes and trailing `/path/?query#frag`
    components before passing to `-d`. kind:cli passes user argv
    through verbatim. If the LLM emits
    `-d https://example.com/foo`, theHarvester argparse accepts it
    but most sources silently zero-result (they expect a bare DNS
    label). **Mitigation**: gotcha entry added to tool.yaml warning
    the LLM to emit bare hostnames only. **Open question**: should
    the plugin add an argv-rewrite rule (regex strip on -d value)
    that mirrors the legacy `_clean_domain` behaviour, or rely
    entirely on prompt-side discipline? The legacy path was
    defence-in-depth; kind:cli currently has only one layer
    (prompting).

12. **Structured `list_sources` directory vs `-h` parsing** — legacy
    `mcp-server.py` lines 210-239 returned a hardcoded 28-source
    table with `{name, type, api_key: bool}` per source plus a
    `recommended_free` shortcut. kind:cli `help_commands` only
    points at `theHarvester -h` whose output is not reliably
    parseable across versions. The legacy `methods.list_sources`
    block IS preserved in tool.yaml (lines 417-431) per SKILL #21
    rollback. **Open question**: should the structured source map
    be re-exported as a YAML data block under `tool.yaml`
    (e.g., `sources:` top-level list) so the agent can query it
    without spawning the legacy method? Currently the legacy
    method is the only path to the structured data. Recommend
    keeping list_sources alive long-term, OR mirror the source
    table into tool.yaml as data the agent can consult directly.

---

## 6. Hand-off

- **Tool**: theharvester (kind:cli), single-binary (`theHarvester`,
  capital H — case-sensitive on Linux).
- **Multi-binary**: NO — confirmed by reading mcp-server.py (line 17
  `HARVESTER_BIN = "theHarvester"` is the only binary invoked; no
  parallel CLI / no helper scripts).
- **Status**: tool.yaml authored end-to-end (kind:mcp → kind:cli);
  scenarios.md written. mcp-server.py UNTOUCHED (auto-inherits
  run_cli via mcp-common 0.3.0; rollback path preserved). The legacy
  method handlers (harvest, list_sources) remain as the rollback
  path per SKILL #21.
- **Dockerfile**: NOT changed — uses `python:3.12-slim` base
  (Debian-slim, NOT Kali). No `python3 python3-pip python3-venv`
  trio to swap. The `python3-full` substitution rule applies only
  to Kali bases; this image installs theHarvester via pip from
  `git+https://github.com/laramies/theHarvester.git@4.10.1` and
  uses a venv for mcp-common — already correct shape.
- **Image**: `ghcr.io/silicon-works/mcp-tools-theharvester:latest`
  — needs rebuild during the Wave 9 batch to pick up mcp-common
  0.3.0 and the new tool.yaml.
- **Cruft removed**: NONE — directory was already clean (only
  Dockerfile, mcp-server.py, requirements.txt, tool.yaml — no
  target_extraction_tests.md, no failure_signature_tests.md, no
  __pycache__/).
- **Live-verify pending**: paste S1-S7 against `iana.org`,
  `htb.eu`, and `nonexistent-test-domain-2026.invalid`. Verify
  failure_signatures 1, 2, 6 immediately (argparse, empty-result,
  unknown source); defer 3 (network), 4 (rate limit), 5 (broken
  source), 7 (invalid auth), 8 (timeout), 9 (-r without value),
  10 (JSON parse) until paired with infra controls or known-broken
  sources.

Authored: 2026-04-25.
