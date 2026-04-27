# searchsploit — Tier A scenarios

Single test sheet for the `searchsploit` (ExploitDB CLI search,
binary `searchsploit`) tool migration.

Sections:
1. Recommended sample for live verification
2. Narrative scenarios (paste into opensploit)
3. Target-extraction adversarial cases (≥20)
4. Failure-signature live-verify cases (≥3)
5. Open questions
6. Hand-off

---

## 1. Recommended sample for live verification

**N/A — searchsploit has no network target.** searchsploit operates
entirely on the local ExploitDB mirror (45,000+ public exploits,
shellcodes, papers) bundled at `/usr/share/exploitdb/` inside the
container; there is no remote host to scan, attack, or authenticate
against. The "target" of a searchsploit call is a SET OF SEARCH TERMS
(positional, e.g., `apache 2.4`), or a CVE ID (`--cve CVE-2021-44228`),
or an EDB-ID (`--id 50383`), or a local nmap-XML path
(`--nmap /session/scan.xml`), or an EDB-ID-to-mirror
(`--mirror 50383`).

For LIVE VERIFICATION of the architecture path, four options:

**(a) Known-CVE lookup (recommended for CI / Tier A gate).** Use a
high-profile CVE that is guaranteed to have multiple public exploits
in the bundled mirror:

- **CVE-2021-44228 (Log4Shell)** — Java RCE; many PoCs and weaponised
  exploits in EDB. Smoke test for `--cve` lookup.
- **CVE-2017-5638 (Struts2 RCE)** — Apache Struts2 OGNL injection;
  numerous EDB entries.
- **CVE-2014-6271 (Shellshock)** — bash function parsing bug;
  classic PoCs.
- **CVE-2017-0144 (EternalBlue)** — SMB RCE; multiple EDB IDs.
- **CVE-2019-0708 (BlueKeep)** — RDP RCE; PoC entries.

CVE-based lookup exercises the most precise search path and is the
most stable smoke test (free-text search has fuzzy version matching
that can return surprising results).

**(b) EDB-ID lookup.** A specific known-good EDB-ID:

- **50383** — Apache HTTP Server 2.4.49 path-traversal RCE
  (CVE-2021-41773); a Python script.
- **39446** — Linux kernel DCCP IPv6 use-after-free
  (CVE-2017-6074); C code.
- **42315** — Microsoft SMBv1 EternalBlue (MS17-010); Python.

Exercises `--id` mode and the path-resolution flow.

**(c) nmap-XML import.** Stage a small nmap XML scan in `/session/`:

```
nmap -sV -oX /session/scan.xml scanme.nmap.org
searchsploit --nmap /session/scan.xml -j
```

Exercises the most powerful integration path — XML parsing + per-service
search. The fixture nmap XML doesn't need to be a real engagement;
`scanme.nmap.org` (Nmap project's public test target) is fine, OR a
saved XML from an HTB box, OR a hand-crafted minimal XML with a known
service banner like `<service name="http" product="Apache" version="2.4.49"/>`.

**(d) Mirror an exploit.** End-to-end flow:

```
cd /session && searchsploit --mirror 50383
ls /session/50383.py
cat /session/50383.py | head -20
```

Exercises file-copy + path-resolution. After mirroring, the exploit can
be edited and run via exploit-runner (out of scope for this scenarios
sheet).

For all four options, the search/lookup is purely local — no network
egress is needed. The only command that needs network is `searchsploit -u`
(database update), which is a maintenance op, not a query.

Persistent test directory: standard `/session/` mount; searchsploit
reads from `/usr/share/exploitdb/` inside the image (not /session/) and
writes (when `--mirror` is invoked) to CWD — pre-cd into /session/ via
the wrapper so artifacts land in the persistent mount.

---

## 2. Narrative scenarios (paste into opensploit)

### S1 — smoke test: confirm searchsploit is functional

```
Run searchsploit --help against the container so I can confirm the binary is on PATH and the local DB is initialized.
```

**Watch:** Agent emits `searchsploit --help` (or `-h`). target=`null`
(no network target). stdout is the usage / flags listing; exits 0
(or non-zero with usage on some versions — consistent regardless).
If the binary isn't on PATH the run fails with `command not found`
(container build issue).

### S2 — basic free-text search with JSON output

```
Find public exploits for Apache HTTP Server 2.4. Use JSON output so I can parse the result.
```

**Watch:** Agent emits `searchsploit apache 2.4 -j`. target=`null`.
stdout is a JSON object with keys `SEARCH`, `DB_PATH`,
`RESULTS_EXPLOIT`, `RESULTS_SHELLCODE`, `RESULTS_PAPER`. The
`RESULTS_EXPLOIT` array contains many entries (Apache 2.x has decades
of exploits). Each entry has EDB-ID, Title, Path, Date. Fuzzy version
matching means '2.4' matches '2.0 < 2.5', '2.4.0', '2.4.49', etc. —
expect adjacent-version results. To narrow, agent may follow up with
`-s` (strict) or `-e` (exact title).

### S3 — CVE lookup for a known vulnerability

```
Look up exploits for CVE-2021-44228 (Log4Shell). I want JSON output.
```

**Watch:** Agent emits `searchsploit --cve CVE-2021-44228 -j`.
target=`null`. stdout is JSON with multiple Log4Shell entries
(weaponised PoCs, scanners, demo exploits). `--cve` searches the CVE
field directly — more precise than free-text search on 'log4j' which
would also match log4j 1.x entries unrelated to Log4Shell. Agent may
also accept the CVE without the prefix (`--cve 2021-44228`).

### S4 — EDB-ID lookup for a specific exploit

```
I have EDB-ID 50383 from a write-up. Confirm it's in the local mirror and tell me the path.
```

**Watch:** Agent emits `searchsploit --id 50383 -j` (or with `-p` to
print the absolute path). target=`null`. stdout is a JSON object with
the single matching record: Title (Apache HTTP Server 2.4.49 RCE),
Path (linux/remote/50383.py), Date. To get the absolute filesystem
path use `-p` instead of `-j`. To READ the file content the agent
follows up with a `cat /usr/share/exploitdb/exploits/linux/remote/50383.py`
via run_cli (separate call).

### S5 — nmap XML import (service-driven exploit discovery)

```
I have an nmap scan at /session/scan.xml. Find all exploits matching the detected services. JSON output.
```

**Watch:** Agent emits `searchsploit --nmap /session/scan.xml -j`.
target=`null` (the nmap XML contains scan-result IPs, but those are
already-scanned hosts, NOT new targets being attacked — searchsploit
is parsing the file to extract service banners, not pivoting to new
hosts). stdout is JSON grouped per host:port with exploit candidates
per service. The nmap XML must be `-oX` output (true XML); `-oN`
(normal) or `-oG` (grepable) WILL fail with `not a valid XML` /
`Cannot read`.

### S6 — mirror exploit to /session/ for modification

```
Copy EDB-ID 50383 to /session/ so I can edit it. Confirm the file lands there.
```

**Watch:** Agent emits `cd /session && searchsploit --mirror 50383`
(the `cd` is critical — searchsploit copies to CWD, not /session/ by
default). target=`null`. The exploit file (e.g., 50383.py) is written
to /session/. Agent follows up with `ls /session/50383.py` (or
similar) to confirm the file exists. If the agent forgets the `cd`,
the file lands in the wrapper's default CWD (likely /app or wherever
the cli runs), not /session/ — inaccessible to subsequent calls.

### S7 — exclude PoCs and DoS

```
Find WordPress exploits but exclude proof-of-concepts and DoS entries.
```

**Watch:** Agent emits `searchsploit wordpress -j --exclude='(PoC)|/dos/'`.
target=`null`. The `--exclude` argument is pipe-separated regex; the
quotes are necessary because `(`, `)`, and `|` are shell metacharacters
(though wrapper runs without a shell so quoting is mostly cosmetic
for argv parsing). Output is JSON with PoCs and DoS-path entries
filtered out — typically reduces the result count by 30-50% on common
queries.

### S8 — title-only search (filter out path-match noise)

```
Search for exploits titled with 'eternalblue' — title field only, ignore matches that just happen to have 'eternalblue' in the file path.
```

**Watch:** Agent emits `searchsploit -t eternalblue -j` (or
`searchsploit --title eternalblue -j`). target=`null`. `-t` restricts
matching to the Title field, ignoring the Path. Useful when path-based
matches pull in unrelated files (e.g., a security paper that mentions
eternalblue in passing). stdout is JSON with stricter-matched entries.

### S9 — strict version match

```
Find exploits for Apache 2.4.49 SPECIFICALLY — not 2.4.0, not 2.4.50, only 2.4.49.
```

**Watch:** Agent emits `searchsploit apache 2.4.49 -s -j`. target=`null`.
`-s` disables fuzzy version matching. Without -s, '2.4.49' matches
adjacent versions (2.4.x, version-range strings like '2.0 < 2.5'). With
-s, only entries with the exact string '2.4.49' in title/path match.
Useful for narrow targeting; risky for false negatives (some entries
say 'Apache 2.4.x' generically and won't match strict '2.4.49').

### S10 — failure: empty result

```
Search for exploits matching 'thisproductdoesnotexist xyz123'.
```

**Watch:** Agent emits `searchsploit thisproductdoesnotexist xyz123 -j`.
target=`null`. searchsploit exits 0 (success) but the JSON arrays are
empty: `{"RESULTS_EXPLOIT": [], "RESULTS_SHELLCODE": [], "RESULTS_PAPER": []}`.
In default table mode the output is `Exploits: No Result` /
`Shellcodes: No Result`. Failure classified via signal `Exploits: No Result`
or `No Result`. Status: `informational` — not a true failure;
remediation is to broaden the query.

### S11 — failure: nmap XML file not found

```
Search exploits using /session/missing-scan.xml.
```

**Watch:** Agent emits `searchsploit --nmap /session/missing-scan.xml -j`.
target=`null`. searchsploit exits non-zero with stderr/stdout
containing `Cannot read` or `nmap XML file not found` or `No such file
or directory`. Failure classified via signal `Cannot read` or
`No such file or directory`. Remediation: verify with `ls /session/`
and confirm the nmap was run with `-oX` (not `-oN`).

### S12 — failure: malformed CVE format

```
Look up CVE 'not-a-cve'.
```

**Watch:** Agent emits `searchsploit --cve not-a-cve -j`. target=`null`.
Behaviour varies: (a) some versions return empty results (treated as a
free-text search in the CVE field), (b) some versions reject with
`invalid argument` or similar. Either way, target=`null` and the
result is unhelpful. Agent should use a real CVE format (`CVE-YYYY-NNNN`).

---

## 3. Target-extraction adversarial cases (≥20)

The searchsploit `tool.yaml` declares NO target_extraction rules.
Every call should return `target=null` because searchsploit has no
network target — it operates on the local ExploitDB mirror only. The
"operands" of a searchsploit call are (a) search TERMS (positional),
(b) optional `--cve`/`--id`/`--mirror`/`--examine` ID values,
(c) optional `--nmap` XML file path, (d) optional `--exclude` filter
regex, (e) boolean output / search flags. None are network targets.

`reject_flags`: empty (no target-list ingestion concept). The only
file-path input (`--nmap`) is a CONSUMER of nmap output — the IPs
inside the XML are scan-result metadata being looked up against the
local DB, not new targets being attacked.

`value_flags` includes ~30 entries to ensure the DSL parses
searchsploit's argv correctly without misinterpreting flag values
or search terms as positional targets. Search terms LOOK like
arbitrary strings (because they ARE) and may include version numbers,
CVE-shaped strings, IP-shaped strings, hostname-shaped strings — none
are network targets in the OpenSploit sense.

### Happy-path cases (every one returns target=null)

| # | Command (binary `searchsploit` omitted) | Expected target | Notes |
|---|---|---|---|
| 1 | `apache 2.4 -j` | `null` | Bare positional terms — basic free-text search. |
| 2 | `--cve CVE-2021-44228 -j` | `null` | CVE lookup. |
| 3 | `--id 50383 -j` | `null` | EDB-ID lookup. |
| 4 | `--nmap /session/scan.xml -j` | `null` | nmap-XML import. The XML file is local input, NOT a target. |
| 5 | `--mirror 50383` | `null` | Mirror exploit to CWD. |
| 6 | `wordpress -j --exclude='(PoC)|/dos/'` | `null` | Free-text + exclusion filter. |
| 7 | `-t eternalblue -j` | `null` | Title-only search. |
| 8 | `apache 2.4.49 -s -j` | `null` | Strict version match. |
| 9 | `-u` | `null` | Update DB (network maintenance op). |
| 10 | `linux kernel 5.4 privilege -j` | `null` | Multi-term search. |

### Help / introspection (target=null by definition)

| # | Command | Expected | Notes |
|---|---|---|---|
| H1 | `-h` | `target=null` | Help. |
| H2 | `--help` | `target=null` | Long form of -h. |
| H3 | (no args) | `target=null` | Bare invocation prints usage; non-zero exit. |

### Adversarial — value_flag traps & "looks like a target" invariants

| # | Command | Expected | Notes |
|---|---|---|---|
| F1 | `10.10.10.5 rce` | `target=null` | First positional term LOOKS like an IPv4 address. NOT a target — it's a search term being looked up against the local DB. (No real exploit titles contain raw IPs but the search will simply return zero results.) |
| F2 | `--cve CVE-2021-44228` | `target=null` | CVE ID is a value of --cve, NOT a target. |
| F3 | `--id 50383` | `target=null` | EDB-ID is a value of --id, NOT a target. |
| F4 | `--nmap /session/scan-of-10.10.10.5.xml -j` | `null` | nmap XML filename embeds the scanned IP. NOT a target — it's a local file path. The IPs INSIDE the XML are also not searchsploit targets (they're scan results). |
| F5 | `--mirror 50383` | `target=null` | EDB-ID is a value of --mirror, NOT a target. |
| F6 | `--exclude='/windows/' apache` | `target=null` | --exclude regex looks like a path; positional `apache` is search term. NOT a target. |
| F7 | `cisco-asa-ssl-vpn 9.6.4.42 -j` | `target=null` | Search terms include hostname-shaped string AND version-shaped string. NOT a target. |
| F8 | `vmware esxi 7.0 --cve CVE-2024-37085 -j` | `target=null` | Mix of free-text and CVE — though searchsploit may not honor both at once, target=null regardless. |
| F9 | `apache --exclude='(PoC)|/dos/|/windows/' -j -e -s` | `target=null` | Many flags + complex exclude. None are targets. |
| F10 | `192.168.1.1 firewall` | `target=null` | Search term IPv4 + product. The IP-shaped string is a SEARCH KEYWORD, not a host. |
| F11 | `--cve 2021-44228` | `target=null` | CVE without prefix. NOT a target. |
| F12 | `apache.example.com 2.4 -j` | `target=null` | First term is a hostname-shaped string. NOT a target — searchsploit treats it as a literal search keyword. |
| F13 | `https://example.com/exploit -j` | `target=null` | URL-shaped search term. NOT a target. |
| F14 | `-c -e -s -t apache 2.4.49 -j` | `target=null` | All four search-modifier booleans + terms. None are targets. |
| F15 | `--examine 50383` | `target=null` | --examine takes EDB-ID; pager opens the file (no-op inside container). NOT a target. |
| F16 | `-x 50383` | `target=null` | Short form of --examine. EDB-ID, NOT a target. |
| F17 | `--nmap /session/scan.xml --exclude='/dos/' -j` | `target=null` | nmap-XML import + exclude. Path values not targets. |
| F18 | `-w wordpress` | `target=null` | -w adds URL column; `wordpress` is search term. NOT a target. |
| F19 | `--colour apache 2.4` | `target=null` | --colour is boolean; positionals are search terms. |
| F20 | `apache 2.4 -j --no-colour` | `target=null` | --no-colour is boolean. NOT a target. |
| F21 | `MS17-010 -j` | `target=null` | MS bulletin search. NOT a target (the colon-separated form `MS17-010` looks like a tag, not a host). |
| F22 | `cve-2017-0144 -j` | `target=null` | Lowercase CVE-shape as free-text term (NOT --cve). NOT a target. |
| F23 | `linux kernel 5.4.0-generic privilege` | `target=null` | Long multi-term search with version. NOT a target. |
| F24 | `phpmyadmin 4.8.1 sql injection` | `target=null` | Multi-word search across product + version + vuln class. NOT a target. |

### Multi-positional & ambiguous-positional cases

| # | Command | Expected | Notes |
|---|---|---|---|
| M1 | `apache && searchsploit nginx` | `target=null` (per call) | Shell `&&` won't run inside cli_in_container (no shell). Per-call: each parses to target=null. |
| M2 | `-j apache 2.4` | `target=null` | -j first, then positionals. argparse permissive. NOT a target. |
| M3 | `apache --cve CVE-2021-41773 -j` | `target=null` | CVE flag mixed with free-text terms; searchsploit may ignore the free-text or merge — target=null regardless. |
| M4 | (no args) | `target=null` | Argparse error / help printed; still target=null. |

### Stdin trap (searchsploit doesn't read stdin in normal flow)

| # | Command (LLM might naively try) | What happens | Correct shape |
|---|---|---|---|
| P1 | `cat /session/scan.xml \| searchsploit --nmap -` | cli_in_container HAS NO SHELL. The `\|` would be passed as a literal arg or rejected. searchsploit does NOT read XML from stdin (--nmap requires a file path). | Use `searchsploit --nmap /session/scan.xml -j`. The path positional is the only XML input transport. |

---

## 4. Failure-signature live-verify cases (≥3)

| # | Layer | Test | failure_signature `signal` | Status |
|---|---|---|---|---|
| 1 | Empty result (informational) | `searchsploit thisproductdoesnotexist xyz123 -j` | `Exploits: No Result` AND/OR `No Result` (or empty arrays in JSON) | PENDING live verify |
| 2 | File / I/O | `searchsploit --nmap /session/nonexistent.xml -j` | `Cannot read` OR `No such file or directory` OR `nmap XML file not found` | PENDING live verify |
| 3 | XML format | `searchsploit --nmap /session/scan.txt -j` (a text file, not XML) | `not a valid XML` OR `Cannot read` | PENDING live verify |
| 4 | Argparse / argument | `searchsploit --notaflag value` | `unrecognized option` OR `invalid argument` | PENDING live verify |
| 5 | Argparse / required | `searchsploit --cve` (no CVE value) | `requires an argument` OR `expected one argument` | PENDING live verify |
| 6 | DB / data | (force-corrupt /usr/share/exploitdb/files_exploits.csv) `searchsploit apache -j` | `searchsploit-db not found` OR `Database not initialized` | PENDING live verify (manual fixture) |
| 7 | Network (--update) | `searchsploit -u` in air-gapped container | `git fetch failed` OR `Could not resolve host` | PENDING live verify (network-isolation fixture) |
| 8 | Mirror / write | `cd / && searchsploit --mirror 50383` (CWD not writable) | `Failed to copy` OR `Permission denied` | PENDING live verify |

### Layer diversity (SKILL #11) — achieved

8 distinct layers exercised: empty-result (informational), file/IO,
XML format, argparse argument, argparse required, DB/data, network,
mirror/write. Resource layer (out-of-memory on huge nmap XML) is hard
to provoke deliberately in a small lab; defer to Wave 9 live HTB run
with a real engagement nmap XML.

---

## 5. Open questions

1. **target_extraction = empty list — confirmed correct?** searchsploit
   has no network target. The plugin's TargetValidation framework
   expects hostnames/IPs. We're declaring zero rules; the plugin
   extracts target=null and the gotcha note documents that scope-
   validation is N/A. Verify the plugin handles `target=null`
   gracefully (doesn't reject the call; doesn't try to validate "null"
   against the engagement scope). Same shape as john / hashcat /
   volatility / ilspy — those have already been migrated. Cross-check
   that IP-shaped search-term cases (F1, F10, F12) and hostname-shaped
   cases (F12) do NOT accidentally extract via some default URL/IP-
   extraction fallback. The `--nmap` XML case (F4) is particularly
   interesting — the XML contains real scanned IPs as scan results;
   we explicitly do NOT treat those as new targets, but if the plugin
   has a default "any IP-shaped value extracts as target" rule, the
   filename embedded with an IP could trip it.

2. **Empty-result classification.** searchsploit exits 0 with
   `Exploits: No Result` when zero matches are found — this is
   INFORMATIONAL, not a failure. The current failure_signatures list
   includes 'Exploits: No Result' / 'No Result' as signals with
   "informational, not a failure" remediation. Should this be a
   distinct status (`empty_result`) rather than mixed in with true
   failures? The downstream pipeline currently treats any matched
   failure_signature as `failure_in_output`; we'd need a separate
   `info_in_output` classification for empty-result. Defer to plugin
   design; for now the remediation text makes the distinction clear.

3. **DB update workflow (`-u`).** `searchsploit -u` requires network
   access to fetch from the upstream ExploitDB git mirror. The tool
   is otherwise marked `network: false`. Should the `requirements.network`
   flag be context-dependent (`false` for queries, `true` for updates)?
   Currently we declare `false` and document `-u` as a maintenance op
   that requires network in the gotchas. The container runtime should
   allow egress for `-u` regardless of the `network: false` setting
   (it's a one-off update, not a per-call requirement). Verify the
   container's network policy doesn't block `-u` in air-gapped mode —
   if it does, document the workaround (skip -u, use bundled mirror).

4. **--mirror destination semantics.** `searchsploit --mirror <id>`
   copies to CWD, not /session/. The wrapper runs each command in its
   own shell, so `cd /session && searchsploit --mirror 50383` is the
   safe pattern. If the agent forgets the `cd`, the file lands in the
   wrapper's default CWD (likely /app or wherever the cli runs), not
   /session/ — inaccessible to subsequent calls. Should we (a) document
   a wrapper convention that always pre-cds to /session/ before
   --mirror, (b) ship a wrapper flag like `--mirror-to /session/` that
   does the cd transparently, or (c) accept that the agent must
   construct the cd-and-mirror chain itself? Current approach is (c)
   with a gotcha; (a) would be cleaner but adds wrapper complexity.

5. **--nmap XML format compatibility.** searchsploit's --nmap mode
   parses nmap XML output (-oX). Variations matter:
   (a) nmap XML schema versions — newer nmap versions emit slightly
       different structure (script outputs, CPE strings). searchsploit
       should handle this gracefully but bit-rot is possible.
   (b) NSE-script-augmented XML — XML with `--script vuln` or
       `--script vulners` includes additional elements. searchsploit
       parses the basic service banners; NSE script output is ignored.
   (c) Truncated XML (interrupted nmap run) — the XML is malformed.
       searchsploit should report `not a valid XML`; verify it doesn't
       silently produce partial results.
   (d) Empty-services XML (host-up but no port banners) — searchsploit
       should report no exploits and exit 0; verify it doesn't crash.
   Defer to live verification with a corpus of real nmap XML files
   (HTB engagements + common test targets like scanme.nmap.org).

6. **Stale exploits.** Many entries in the bundled mirror are old PoCs
   that no longer work against modern targets due to bit-rot, missing
   dependencies, or environmental drift. searchsploit can't classify
   reliability — every match is presented uniformly. Should we (a) add
   a `--exclude='(PoC)'` default to filter PoCs out, (b) document the
   reliability problem in gotchas (current approach), or (c) ship a
   curated reliability metadata layer? Current is (b); (a) is risky
   because some PoCs are genuinely useful starting points; (c) is
   out-of-scope for kind:cli migration.

7. **--examine / -x behavior in container.** `searchsploit --examine 50383`
   opens the exploit in $PAGER (typically less or more). Inside the
   container, $PAGER may be unset (no interactive terminal); the call
   may hang waiting for input or fail with `pager not found`. Recommend
   --mirror + cat instead. Should the gotchas explicitly call out
   --examine as not-recommended in container? Currently mentioned in
   common_options but not as a top-level gotcha. Defer to live verify;
   if --examine hangs, add a hard gotcha.

8. **Legacy `type` filter parameter is GONE in kind:cli.** The legacy
   MCP wrapper's `search` method accepted a `type` parameter
   (`all|exploit|shellcode|paper`) and applied client-side filtering
   over the unioned `RESULTS_EXPLOIT` + `RESULTS_SHELLCODE` +
   `RESULTS_PAPER` arrays. searchsploit itself has NO server-side
   `--type=` flag — the wrapper synthesized this filter. In kind:cli,
   the agent receives the raw JSON with all three arrays and must
   filter itself. Documented as a gotcha. Decision: do not re-add a
   wrapper-side filter; agents are LLMs and can trivially ignore arrays
   they don't want. The semantic loss is a single boolean parameter,
   which the agent can reproduce in one line of post-processing.

9. **`searchsploit -p` depends on `rev`.** The legacy MCP wrapper had a
   `_resolve_exploit_path` helper that explicitly avoided
   `searchsploit -p` because the `rev` command (used internally by the
   `-p` codepath) may not be installed in the container. Instead, it
   resolved EDB-ID → path via JSON parsing of the search result. In
   kind:cli the agent constructs `searchsploit -p` directly per the
   usage pattern; if `rev` is missing this fails. Verified Dockerfile
   uses `kalilinux/kali-rolling` base which DOES include `bsdmainutils`
   (provides `rev`) by default — so `-p` should work. But if the image
   is ever rebuilt on a slimmer base (debian-slim, alpine), `-p` will
   silently break. Documented as a gotcha with a JSON-path-extraction
   fallback. Defer adding `bsdmainutils` to the explicit Dockerfile
   apt-install list to next image-rebuild cycle (Wave 9 batch).

10. **Lookup-mode operands documented but `--id` flag not in legacy.**
    The legacy `_resolve_exploit_path` accepts an `exploit_id` and
    runs `searchsploit --json <id>` (positional, no `--id` flag).
    The new tool.yaml documents `--id 50383 -j` as the canonical
    EDB-ID lookup form. Both work — searchsploit accepts an EDB-ID as
    a positional and matches it against the EDB-ID column — but the
    tool.yaml's preference for `--id` is a deliberate clarification,
    not a regression. Agents should use `--id <num>` for clarity;
    bare-positional `searchsploit 50383` also resolves but is less
    self-documenting.

---

## 6. Hand-off

- **Tool**: searchsploit (kind:cli)
- **Status**: tool.yaml authored end-to-end (kind:cli, binary:searchsploit, 10min max_runtime, no target_extraction); scenarios.md written. Dockerfile reviewed — base image is `kalilinux/kali-rolling`, so the python3-pip / python3-venv → python3-full swap was required and applied. mcp-server.py UNTOUCHED (auto-inherits run_cli; rollback path).
- **Image**: `ghcr.io/silicon-works/mcp-tools-searchsploit:latest` — needs rebuild during Wave 9 batch to pick up mcp-common 0.3.0 and the python3-full swap.
- **target_extraction = empty list**: explicit design choice. searchsploit has no network target; the plugin should treat target=null as "no scope validation needed" for this tool. Same shape as john / hashcat / volatility / ilspy. See Open Question #1.
- **Wave 7.11**: of Feature 35 / Tier A migration.
- **Live-verify pending**: paste S1-S12 against the container for end-to-end verification. Failure signatures 1-2 (empty result, file-not-found) verifiable against any container; 3 (XML format) needs a non-XML fixture; 6 (DB corruption) requires a manual fixture; 7 (network failure on -u) requires network-isolation fixture.
- **Cleanup**: no legacy `target_extraction_tests.md`, `failure_signature_tests.md`, or `__pycache__/` files were present in the searchsploit/ directory (verified via initial Read phase — directory contained only Dockerfile, mcp-server.py, requirements.txt, tool.yaml) — nothing to remove.
- **Dockerfile**: ONE change applied — replaced `python3 python3-pip python3-venv` with `python3-full` (Kali rolling repos no longer ship the split packages). exploitdb apt package retained (provides the bundled mirror at /usr/share/exploitdb/). venv setup, mcp-common install, mcp-server.py copy, CMD all unchanged.

Authored: 2026-04-25.
