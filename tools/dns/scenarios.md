# dns — Tier A scenarios

Single test sheet for the `dns` tool migration (Wave 7.2).

Sections:
1. Recommended target for live verification
2. Narrative scenarios (paste into opensploit)
3. Target-extraction adversarial cases (≥20)
4. Failure-signature live-verify cases (≥3)
5. Open questions
6. Hand-off

---

## 1. Recommended target

**Real-world public domain — `iana.org` (canonical) plus an HTB box with
DNS exposure for AXFR testing.**

dig is fundamentally a **DNS query tool** that works against ANY DNS
server reachable from the container. There are two distinct test paths:

### 1a. Public, well-formed DNS (extraction + record-type variety)

`iana.org` — the canonical DNS test target. Has A, AAAA, MX, NS, SOA,
TXT, DNSKEY records. Authoritative servers respond cleanly to all
sensible queries. Use for: target-extraction adversarial sweep, record
type matrix (A, MX, NS, SOA, TXT, ANY), DNSSEC (`+dnssec`), trace
(`+trace`), reverse (`-x` against a known IP).

iana.org responds to AXFR with REFUSED — useful for testing the
**failure_signature** classification of the AXFR-denied path.

### 1b. AXFR-vulnerable target

For a known-vulnerable AXFR target (the headline DNS misconfig hit), use:

- HTB box: **FluxCapacitor**, **Cronos**, **Sunday**, **Bashed**'s
  internal DNS — when the lab box runs an internal NS that allows AXFR,
  `dig @<box> <domain> AXFR` dumps the zone. Verify per-engagement.
- Lab/local: a self-hosted BIND with `allow-transfer { any; };` in the
  zone config — the canonical AXFR-vulnerable setup.
- Public test domains: **`zonetransfer.me`** is a deliberately-vulnerable
  public DNS test target maintained by Robin Wood (DigiNinja) — runs at
  `nsztm1.digi.ninja` / `nsztm2.digi.ninja` and accepts AXFR from any
  IP. The de-facto standard public testbed for AXFR demos.

For Wave 7.2 architecture verification (target extraction, failure
classification, kind:cli wiring, run_cli auto-inheritance) point dig at
**`iana.org`** for the canonical record-type sweep and **`zonetransfer.me`
@ nsztm1.digi.ninja**` for the AXFR success path.

Persistent test directory: standard `/session/` mount; dig has no native
file-output mode (unlike amass), so test output is in stdout only and
parser runs on the `text_full` / `text_short` blob returned by run_cli.

---

## 2. Narrative scenarios (paste into opensploit)

### S1 — basic A record query

```
Engagement target: iana.org (public domain, OSINT-only — no scope concerns).
Use dig to get the A record for iana.org. Use +short for compact output.
```

**Watch:** Agent emits `dig iana.org A +short` (or just `dig iana.org`).
target=`iana.org` extracted via positional_match (domain shape).
Record type `A` is a positional but has no dots — the regex requires a
dot, so `A` is NOT misextracted. `+short` is a positional with `+`
prefix, skipped by the `(?![@+])` regex prefix.

### S2 — reverse PTR lookup

```
Engagement target: 8.8.8.8 (public DNS, OSINT-only).
Use dig to do a reverse DNS lookup on 8.8.8.8.
```

**Watch:** Agent emits `dig -x 8.8.8.8 +short`.
target=`8.8.8.8` extracted via flag_value `-x` rule. The IP literal
matches scope-validation as a public IP. The DSL's flag_value rule
fires BEFORE positional_match (rule precedence), so even if the IP
also appears as a positional somewhere, `-x`'s value wins.

### S3 — AXFR zone transfer attempt against a known-vulnerable target

```
Engagement target: zonetransfer.me (deliberately-vulnerable public AXFR test domain).
Use dig to attempt a zone transfer of zonetransfer.me via nsztm1.digi.ninja.
```

**Watch:** Agent emits
`dig @nsztm1.digi.ninja zonetransfer.me AXFR`.
target=`zonetransfer.me` extracted via positional_match. The
`@nsztm1.digi.ninja` positional starts with `@` and is skipped by
the regex. `AXFR` has no dot — also skipped. Output should contain
`; XFR size: <N> records` (success marker) and a list of A / MX /
TXT records from the leaked zone.

### S4 — info-gathering: MX, TXT, NS in sequence

```
Engagement target: iana.org.
Use dig to enumerate iana.org: get the MX records (mail servers), TXT records (SPF/DKIM), and NS records (nameservers). Use +short for each.
```

**Watch:** Agent emits THREE separate dig calls (or a chained one if
the agent constructs one):
- `dig iana.org MX +short`
- `dig iana.org TXT +short +nocomments`
- `dig iana.org NS +short`

Each extracts `iana.org` correctly. The record types (`MX`, `TXT`, `NS`)
are all positionals without dots — DSL doesn't misextract. The
+short / +nocomments tokens have `+` prefix — skipped by the regex.

### S5 — query a specific server (split-horizon detection)

```
Engagement target: iana.org.
Use dig to query the A record for iana.org against Google's public DNS (8.8.8.8) and compare to Cloudflare's (1.1.1.1).
```

**Watch:** Agent emits two calls:
- `dig @8.8.8.8 iana.org A +short`
- `dig @1.1.1.1 iana.org A +short`

target=`iana.org` in both. The `@8.8.8.8` and `@1.1.1.1` positionals
are skipped by the regex (start with `@`). The IPs themselves do
match the IPv4 regex, BUT the `(?![@+])` negative lookahead prevents
positionals starting with `@` from matching at all.

### S6 — failure: NXDOMAIN

```
Engagement target: nonexistent-host.invalid.localdomain (deliberately invalid, verifying failure classification).
Use dig to query the A record for nonexistent-host.invalid.localdomain.
```

**Watch:** dig succeeds (exit code 0!) and emits `;; ->>HEADER<<- ...
status: NXDOMAIN, ...`. Plugin classifies via failure_signature `NXDOMAIN`
in stdout. Important: dig's exit code is 0 even on NXDOMAIN — pattern
match, not exit code, drives classification. The `gotchas[]` document
this.

For `connection timed out / no servers could be reached`: pass
`@127.0.0.99` (an unreachable resolver). dig will retry then fail with
`; communications error` and `; no servers could be reached`.

For `REFUSED` (AXFR-denied): pass `dig @8.8.8.8 iana.org AXFR` — Google's
public resolver refuses AXFR.

---

## 3. Target-extraction adversarial cases (≥20)

The dns `tool.yaml` declares THREE extraction rules, in precedence order:

1. `flag_value` for `-x` → reverse-lookup IP
2. `flag_value` for `-q` → explicit query-name flag
3. `positional_match` with regex `^(?![@+])(\[[0-9a-fA-F:]*:[0-9a-fA-F:]*\]|[0-9a-fA-F]*:[0-9a-fA-F:]*:[0-9a-fA-F:]*|[0-9]{1,3}(?:\.[0-9]{1,3}){3}|[a-zA-Z0-9][a-zA-Z0-9.-]*\.[a-zA-Z]{2,})$`

The IPv6 alternative requires at least TWO colons in the token — this
prevents bare DNS record types `A` and `AAAA` (pure-hex letter strings
with NO colons) from accidentally matching the IPv6 alternative. Other
record types (`MX`, `NS`, `TXT`, `ANY`, etc.) contain non-hex letters and
naturally fail the IPv6 alternative.

`reject_flags`: `-f` (batch file — multi-query off-argv).

`value_flags` includes ~15 entries — most importantly `-x`, `-q`,
`-t`, `-c`, `-p`, `-b`, `-k`, `-y`, `-m`, `-f` (rejected but listed).

### Happy-path cases

| # | Command (binary `dig` omitted) | Expected target | Notes |
|---|---|---|---|
| 1 | `example.com` | `example.com` | Bare A query. Single positional, has dot — matches regex. |
| 2 | `example.com A` | `example.com` | A is a second positional but has NO dot, doesn't match regex. example.com matches first. |
| 3 | `example.com MX +short` | `example.com` | `MX` no dot, `+short` has `+` prefix — both skipped. |
| 4 | `@8.8.8.8 example.com` | `example.com` | `@8.8.8.8` skipped by `(?![@+])`. |
| 5 | `@8.8.8.8 example.com NS +short` | `example.com` | Same; NS no dot, +short has `+`. |
| 6 | `-x 8.8.8.8` | `8.8.8.8` | flag_value `-x` rule fires first. |
| 7 | `@1.1.1.1 -x 8.8.8.8 +short` | `8.8.8.8` | flag_value `-x` wins over positional_match. `@1.1.1.1` skipped anyway. |
| 8 | `-q example.com -t MX` | `example.com` | flag_value `-q` rule fires first. |
| 9 | `example.com AXFR @ns.example.com` | `example.com` | First non-skipped positional with dot. `@ns.example.com` skipped (starts with `@`). `AXFR` no dot. |
| 10 | `example.co.uk` | `example.co.uk` | Multi-label TLD. |

### Adversarial — value_flag traps & security invariants

| # | Command | Expected | Notes |
|---|---|---|---|
| F1 | `-h` | `target=null` | Help — no positional, no -x, no -q. |
| F2 | `-v` | `target=null` | Version. |
| F3 | `+short` | `target=null` | Bare +option, no domain. dig prints help. |
| F4 | `@8.8.8.8` | `target=null` | Only `@server` positional — skipped by regex. dig defaults to `. NS` query. |
| F5 | `MX` | `target=null` | Bare type — no dot, doesn't match regex. dig errors. |
| F6 | `-f /session/queries.txt` | Plugin rejects (`-f` in reject_flags). | Batch file ingestion. |
| F7 | `@8.8.8.8 example.com` | `target=example.com` (NOT `8.8.8.8`). | Critical: resolver IP must NOT be confused with query target. The `@` prefix exclusion is the security invariant. |
| F8 | `@nsztm1.digi.ninja zonetransfer.me AXFR` | `target=zonetransfer.me` (NOT `nsztm1.digi.ninja`). | Same invariant with hostname-shape NS. The `@` prefix exclusion catches it. |
| F9 | `+timeout=10 example.com` | `target=example.com` (NOT `+timeout=10`). | `+` prefix exclusion catches the +option even though it has digits. |
| F10 | `+subnet=1.2.3.0/24 example.com A` | `target=example.com` (NOT `1.2.3.0` from +subnet value). | Critical: `+subnet=1.2.3.0/24` is one positional token. The `+` prefix exclusion catches it. The `/24` would also break the regex anyway. |
| F11 | `example.com -t AXFR` | `target=example.com` | -t value is record type (`AXFR`); -t is in value_flags so AXFR is consumed. example.com matches positionally. |
| F12 | `example.com -c CH version.bind TXT` | `target=example.com` | Tricky: `version.bind` HAS a dot and looks like a domain. BUT example.com is the FIRST positional that matches the regex. positional_match's `evaluatePositionalMatch` returns the FIRST match in iteration order. Document: with multi-domain positionals dig also accepts (it queries both names sequentially), the first wins for scope. |
| F13 | `version.bind -c CH TXT @ns.example.com` | `target=version.bind` | When NO `example.com`-style domain comes first, `version.bind` is the canonical query name. CH-class `version.bind` queries are a real recon pattern (BIND server fingerprinting). |
| F14 | `-x 8.8.8.8 @1.1.1.1` | `target=8.8.8.8` | flag_value `-x` rule fires; @1.1.1.1 is positional but skipped. |
| F15 | `-x ::1 @localhost` | `target=::1` | IPv6 reverse — flag_value `-x` captures the IPv6 literal raw. |
| F16 | `-q example.com -t MX @ns.example.com` | `target=example.com` | flag_value `-q` rule fires before positional_match. The `@ns.example.com` positional is skipped anyway. |
| F17 | `-p 5353 example.com` | `target=example.com` | `-p` value is port (5353); -p is in value_flags. |
| F18 | `-b 10.0.0.5 example.com` | `target=example.com` | `-b` value is bind address (10.0.0.5); -b is in value_flags. The bind IP must NOT be confused with target. |
| F19 | `-k /session/keyfile example.com` | `target=example.com` | `-k` value is TSIG key path; -k is in value_flags. |
| F20 | `-y hmac-sha256:keyname:secret example.com` | `target=example.com` | `-y` value is inline TSIG key spec; -y is in value_flags. |
| F21 | `-m trace,record example.com` | `target=example.com` | `-m` value is memory debug spec (rare). -m is in value_flags. |
| F22 | `192.168.1.1` | `target=192.168.1.1` | Pure IPv4 positional — matches IPv4 alternative in regex. |
| F23 | `[2001:db8::1]` | `target=2001:db8::1` | Bracketed IPv6 positional. Bracket-stripping in postProcess. |
| F24 | `2001:db8::1` | `target=2001:db8::1` | Bare IPv6 — matches `[0-9a-fA-F:]+` alternative. |
| F25 | `example.com sister.com` | `target=example.com`, multi_target_detected=true (both match) | dig accepts MULTIPLE query names — runs each. positional_match returns BOTH; uniq dedup keeps both; first wins, multi_target=true. **Decide policy**: should `allow_multi_target: true` be set? See open question 1. |
| F26 | `EXAMPLE.COM` | `EXAMPLE.COM` | Uppercase preserved (parse_as: raw, no case folding). |
| F27 | `xn--bcher-kva.example` | `xn--bcher-kva.example` | IDN punycode preserved. |
| F28 | `localhost` | `target=null` | NO dot — fails the domain-shape regex. dig still runs and queries `localhost`; scope validation can't fire. Document. |
| F29 | `@8.8.8.8 localhost A` | `target=null` | Same as F28 — `localhost` has no dot. Document. |
| F30 | `_443._tcp.example.com TLSA +short` | `target=_443._tcp.example.com` | DANE-style underscore-prefixed name. The regex `[a-zA-Z0-9][a-zA-Z0-9.-]*\.[a-zA-Z]{2,}` requires the FIRST char to be `[a-zA-Z0-9]` — `_443` starts with `_`, FAILS the regex. **Edge case** — document as Open Question 4. Alternative: relax regex to `[a-zA-Z0-9_]` first-char. |
| F31 | `+trace example.com` | `target=example.com` | `+trace` skipped by regex; example.com matches. |
| F32 | `example.com IN A` | `target=example.com` | `IN` is the class (no dot); `A` no dot. example.com matches first. |
| F33 | `-c IN example.com` | `target=example.com` | `-c` value is class (`IN`); -c is in value_flags. |

### Sub-command-style tests (dig has none, but variant invocations)

| # | Command | Expected | Notes |
|---|---|---|---|
| SC1 | `-h` | `target=null` | Help. |
| SC2 | (empty) | `target=null` | dig with NO args prints usage to stderr and exits 0 — odd but harmless. |
| SC3 | `example.com extra.example.com` | `target=example.com` (first match), multi_target=true | dig accepts multiple names; we extract first, flag multi-target. |
| SC4 | `-- example.com` | Depends on tokeniser — `--` is unusual for dig. Most likely: `--` is treated as an unknown short flag, example.com matches positionally. Document. | Edge case. |

---

## 4. Failure-signature live-verify cases (≥3)

| # | Layer | Test | failure_signature `signal` | Status |
|---|---|---|---|---|
| 1 | DNS-protocol (NXDOMAIN) | `dig nonexistent-host.invalid.localdomain A` | `NXDOMAIN` | PENDING live verify |
| 2 | DNS-protocol (REFUSED) | `dig @8.8.8.8 iana.org AXFR` (Google refuses AXFR) | `REFUSED` AND/OR `; Transfer failed.` | PENDING live verify |
| 3 | Network (timeout) | `dig @127.0.0.99 example.com +timeout=2 +tries=1` (unreachable resolver) | `connection timed out; no servers could be reached` AND/OR `no servers could be reached` | PENDING live verify |
| 4 | Argument | `dig +retries=3 example.com` (wrong: should be +retry, not +retries) | `Invalid option` | PENDING live verify |
| 5 | Argument (unknown type) | `dig example.com FOOBAR` | `unknown query type` AND/OR `Invalid option` | PENDING live verify |
| 6 | DNS-protocol (NOTAUTH) | `dig @8.8.8.8 example.org SOA` against domain google's resolver isn't authoritative for | usually returns answer (recursive), but with `+norecurse` returns NOTAUTH | PENDING live verify |
| 7 | TSIG (BADKEY) | `dig -y hmac-md5:bogus:c2VjcmV0 @<server> example.com` | `BADKEY` AND/OR `tsig verify failure` | PENDING — needs TSIG-configured server |
| 8 | AXFR success (positive marker) | `dig @nsztm1.digi.ninja zonetransfer.me AXFR` | `; XFR size:` (success — documented in failure_signatures) | PENDING live verify |
| 9 | DNS-protocol (SERVFAIL) | `dig @8.8.8.8 dnssec-failed.org A +dnssec` (deliberately broken DNSSEC test domain) | `SERVFAIL` | PENDING live verify |

### Layer diversity (SKILL #11) — achieved

5+ distinct verifiable layers exercised: DNS-protocol (NXDOMAIN /
REFUSED / SERVFAIL / NOTAUTH) / Network (timeout) / AXFR-specific /
Argument / TSIG-auth. The AXFR success marker is the inverse pole
(captured in failure_signatures for completeness).

---

## 5. Open questions

1. **Multi-domain positional behaviour** (case F25) — dig accepts
   multiple query names on argv (queries each in sequence). Plugin's
   positional_match returns BOTH, sets multi_target_detected=true.
   Decide whether to add `allow_multi_target: true` so this works
   pass-through. Recommendation: set `allow_multi_target: true` —
   matches dig's natural multi-query behaviour. (NOT set in the
   current tool.yaml — defer to maintainer.)

2. **dig's positional target rule precision** — the
   `^(?![@+])(<ipv6>|<ipv4>|<domain>)$` regex must capture every
   real-world domain shape while excluding `@server` / `+option` /
   bare-type tokens. The chosen regex requires:
   - First char `[a-zA-Z0-9]` for hostnames (excludes underscore-prefix
     like `_443._tcp.example.com` — see Open Question 4)
   - At least one dot in the domain alternative
   - Or pure IPv4 (`[0-9]{1,3}(?:\.[0-9]{1,3}){3}`)
   - Or IPv6 with at least TWO colons in the token (with or without
     brackets) — IMPORTANT: the two-colon requirement is what stops
     bare DNS record types `A` and `AAAA` (pure-hex letter strings
     with NO colons) from accidentally matching the IPv6 alternative.
     `MX`, `NS`, `TXT`, etc. fail naturally because they contain
     non-hex letters.
   - `(?![@+])` negative lookahead to skip `@` / `+` prefixes.

   Cases passing: `example.com`, `1.2.3.4`, `[::1]`, `2001:db8::1`,
   `xn--bcher-kva.example`. Cases failing on purpose: `+short`,
   `@8.8.8.8`, `MX`, `A`, `AAAA`, `localhost` (no dot — see Open
   Question 3), `_443._tcp.example.com` (underscore prefix — see
   Open Question 4).

3. **Single-label hostnames (no dot)** — `dig localhost` queries the
   local-name without a dot. The current regex requires a dot, so
   `localhost` is NOT extracted (target=null). Plugin still runs the
   command pass-through — dig succeeds against system resolver — but
   scope validation can't fire. For HTB / lab work this is mostly
   harmless (lab boxes use FQDNs); for paranoid scope policy, an
   alternative regex `^(?![@+])([a-zA-Z0-9][a-zA-Z0-9.-]*)$`
   (allow no-dot single-label) would catch `localhost` and any other
   hostname. Trade-off: would also catch `MX`, `AXFR`, `+short` (if
   the `+` exclusion fails). Defer until a real engagement needs
   single-label scope.

4. **Underscore-prefixed names (DANE / SRV / DKIM)** — names like
   `_443._tcp.example.com`, `_dmarc.example.com`, `_acme-challenge.example.com`
   start with `_` which the current regex rejects (first char must
   be `[a-zA-Z0-9]`). Plugin sets target=null and falls through. dig
   still runs the query — just no scope validation. Recommendation:
   relax first-char to `[a-zA-Z0-9_]` to capture these. The `_`
   character is RFC-valid in DNS labels (RFC 2782 SRV records, RFC
   6698 TLSA records) and seeing it in operational pentest workflows
   is common. Defer to maintainer review.

5. **Reverse lookup target type** — `dig -x 8.8.8.8` extracts
   `8.8.8.8` as the target via flag_value. Scope validation classifies
   it as a public IP. For `dig -x <internal-IP>` the target is the
   internal IP — correctly scope-validated. Question: does the
   in-addr.arpa zone count as the actual "destination" for scope
   purposes? Probably no — the QUERY is for the in-addr.arpa zone but
   the SCOPE concern is the IP we're investigating. Document: the
   extracted target is the IP being reverse-looked-up, not the
   in-addr.arpa pseudo-domain.

6. **+option with embedded values** — `+timeout=10`, `+tries=2`,
   `+subnet=1.2.3.0/24` are single argv tokens with `=value`. The
   tokeniser treats them as positionals (no `-` prefix). The DSL's
   regex's `(?![@+])` prefix excludes them all. No issue, but
   document: any future +option with a domain-shape value (none today)
   would need a value_flag entry.

7. **AXFR success classification** — `; XFR size: <N> records` is the
   success marker. Listed in failure_signatures for completeness, but
   really it's a SUCCESS signal — the plugin's classification needs
   to know that `; XFR size:` => success regardless of accompanying
   `Transfer failed` (which CAN appear in stderr alongside if the
   transfer partial-failed). Plugin policy: success markers OVERRIDE
   failure markers for the same call.

8. **dig's exit code behaviour** — dig exits 0 even on NXDOMAIN /
   REFUSED / SERVFAIL. Plugin must rely on stdout pattern-matching,
   NOT exit code, for failure detection. This is documented in
   gotchas and is consistent with amass / other DNS tools.

9. **+trace ignores @<server>** — when `+trace` is set, dig walks
   from the root regardless of `@<server>`. Combining them is
   misleading but harmless. Document.

10. **HTB AXFR target — confirm a working public testbed** —
    `zonetransfer.me` via `nsztm1.digi.ninja` (DigiNinja) is the
    de-facto AXFR demo. Verify still serving as of 2026-04 in the
    Wave 9 build.

11. **Architectural drop: legacy result post-processing** — the legacy
    handlers (`lookup`, `zone_transfer`, `enum`) parsed dig text into
    structured JSON: `_parse_dig_answer` produced `[{name, ttl, class,
    type, value}, ...]`; `zone_transfer` additionally extracted
    `hostnames = sorted(set(r.name for r in records if r.type in
    ('A', 'AAAA', 'CNAME')))` and emitted `record_count` /
    `hostname_count` aggregates. Under kind:cli the LLM consumes raw
    dig text and does its own structuring. **No automatic hostname
    extraction post-AXFR.** When the agent wants the legacy aggregate
    shape, either (a) emit `+short` and parse line-oriented output, or
    (b) call the legacy `zone_transfer` method via the rollback path.
    Document if a downstream tool / pattern depends on the structured
    JSON shape.

12. **Architectural drop: PTR record-type label remap** — the legacy
    `lookup()` handler returns `record_type: "PTR" if reverse else
    record_type` in its JSON response — i.e., `dig -x 8.8.8.8` is
    labeled as a PTR query in the data shape, even though argv-wise
    `-x` is the trigger. Under kind:cli the LLM sees raw text only,
    where dig itself emits `;; QUESTION SECTION:\n;<reversed-ip>.in-addr.arpa.\tIN\tPTR`
    — the PTR labelling is implicit. No action needed; flagged for
    awareness if any downstream JSON-shape consumer depends on the
    explicit "PTR" tag.

13. **Architectural drop: `enum()` was a fan-out helper** — the legacy
    `enum()` handler iterated 9 record types (A, AAAA, CNAME, MX, NS,
    SOA, TXT, SRV, PTR) with `+short +tries=1`, accumulated results
    into a dict `{type: [values...]}`, and returned a single
    aggregated response. Under kind:cli the LLM emits one dig per
    record type (see narrative scenario S4). Slightly more agent
    tokens; preserves transparency. Total wall-clock is similar
    (sequential queries either way). The legacy method remains as a
    rollback path.

---

## 6. Hand-off

- **Tool**: dns (kind:cli), single-binary (`dig`)
- **Multi-binary**: NO — confirmed by reading mcp-server.py (line 207
  `cmd = ["dig"]` is the only binary invoked; no dnsrecon, no dnsenum,
  no massdns).
- **Status**: tool.yaml authored end-to-end (kind:mcp → kind:cli);
  scenarios.md written. mcp-server.py UNTOUCHED (auto-inherits run_cli
  via mcp-common 0.3.0; rollback path preserved). The legacy method
  handlers (lookup, zone_transfer, enum) remain as the rollback path
  per SKILL #21.
- **Dockerfile**: CHANGED — replaced `python3 python3-pip python3-venv`
  trio with `python3-full` per the Kali-base swap convention. dnsutils
  + ca-certificates retained.
- **Image**: `ghcr.io/silicon-works/mcp-tools-dns:latest` — needs
  rebuild during the Wave 9 batch to pick up mcp-common 0.3.0 and the
  new tool.yaml.
- **Cruft removed**: NONE — directory was already clean (only
  Dockerfile, mcp-server.py, requirements.txt, tool.yaml — no
  target_extraction_tests.md, no failure_signature_tests.md, no
  __pycache__/).
- **Live-verify pending**: paste S1-S6 against `iana.org`, `8.8.8.8`,
  and `zonetransfer.me`. Verify failure_signatures 1-3 and 5
  immediately; defer 4 (Argument), 6 (NOTAUTH), 7 (TSIG), 8 (AXFR
  success), 9 (SERVFAIL) until paired with failing/specialised
  targets.

Authored: 2026-04-25.
