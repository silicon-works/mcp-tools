# john — Tier A scenarios

Single test sheet for the `john` (John the Ripper) tool migration.

Sections:
1. Recommended HTB box for live verification
2. Narrative scenarios (paste into opensploit)
3. Target-extraction adversarial cases (≥20)
4. Failure-signature live-verify cases (≥3)
5. Open questions
6. Hand-off

---

## 1. Recommended HTB box

**N/A — john has no network target.** john operates entirely on local hash
files; there is no remote host to scan, attack, or authenticate against.
The "target" of a john call is a file path inside the container (e.g.,
`/session/hashes.txt`), not a hostname or IP.

For LIVE VERIFICATION of the architecture path, two options:

**(a) Static synthetic hash file (recommended for CI / Tier A gate).**
A small handcrafted hash file at `/session/hashes-test.txt` with a few
known-crackable hashes (e.g., the rockyou top 10 in raw-md5 form). Lets
us verify target extraction (target=null), output handling, failure
classification, and successful-crack flow without requiring an HTB box.

Example test-fixture content (paste into `/session/hashes-test.txt`):

```
5f4dcc3b5aa765d61d8327deb882cf99
e10adc3949ba59abbe56e057f20f883e
25d55ad283aa400af464c76d713c07ad
```

These are MD5 hashes of `password`, `123456`, and `12345678` respectively
— rockyou top 3, all crack in <1 second.

**(b) End-to-end engagement.** Any HTB box that has produced hashes in
prior engagement steps. The typical workflow:

1. nmap → identify Active Directory / SMB / web services
2. impacket-secretsdump → write /session/<box>-ntds.txt
3. john --format=nt --wordlist=rockyou.txt /session/<box>-ntds.txt
4. → cracked NTLM hashes for credential reuse

Recent example: **Hercules (or any HTB AD box)** where secretsdump produces
NTDS hashes; john's output feeds into netexec for lateral movement. The
hashes are STATIC FILES in /session/, NOT a network target — john's
behaviour is independent of which box generated them.

Persistent test directory: standard `/session/` mount; john reads input
from `/session/*.txt` and writes pot file to `/session/john.pot` (when
`--pot=/session/john.pot` is specified).

---

## 2. Narrative scenarios (paste into opensploit)

### S1 — wordlist + rules attack (most common)

```
I have NTLM hashes from secretsdump in /session/ntds-hashes.txt. Use john to crack them with rockyou.txt and the default mangling rules. Specify the format explicitly so john doesn't waste time auto-detecting. Pin the pot file to /session/john.pot so cracks survive container restart.
```

**Watch:** Agent emits something like `john --wordlist=/usr/share/wordlists/rockyou.txt --rules --format=nt --pot=/session/john.pot /session/ntds-hashes.txt`. target=`null` (no network target). First call ~3-5 s container spawn; subsequent calls reuse warm container. Cracked passwords appear in stdout (`password (administrator)`) AND in /session/john.pot.

### S2 — mask attack against NTLM

```
I have NTLM hashes in /session/ntlm-corp.txt. Corporate password policy is "Capitalized + 4 digits" (e.g., "Welcome2024", "Summer2025"). Run john with a mask pattern matching 6-12 characters of mixed-case + 4 trailing digits. NTLM format.
```

**Watch:** Agent emits `john --mask='?u?l?l?l?l?l?l?l?d?d?d?d' --min-length=8 --max-length=12 --format=nt /session/ntlm-corp.txt`. target=`null`. Mask pattern is the operand; min/max-length bounds the keyspace. john prints status updates (candidates tried, c/s rate) every few minutes.

### S3 — show already-cracked passwords

```
I cracked some hashes in /session/old-hashes.txt yesterday with john --pot=/session/john.pot. Show me the cracked results without re-running the attack.
```

**Watch:** Agent emits `john --show --pot=/session/john.pot --format=nt /session/old-hashes.txt`. target=`null`. john reads the pot file and prints `user:password` pairs for any hash that's already cracked. Returns instantly (no cracking, just pot lookup).

### S4 — stdin candidate input via run_cli stdin_data

```
I want to feed a custom candidate stream to john (not a wordlist file — a generator that produces candidates on the fly). The candidates are: 'apple', 'banana', 'cherry'. Hash file is /session/test.txt with one raw-md5 hash. Use john's stdin mode and pass the candidates via tool_runner's stdin_data field.
```

**Watch:** Agent calls tool_runner with command=`john --stdin --format=raw-md5 /session/test.txt` and stdin_data=`apple\nbanana\ncherry\n`. Plugin pipes stdin_data to john's subprocess stdin. target=`null`. CRITICAL: agent must NOT try a shell-pipe form (`echo apple banana cherry | john --stdin ...`) because cli_in_container has no shell — that would fail. The right shape is the explicit stdin_data field.

### S5 — failure: hash file not found

```
Crack the hashes in /session/nonexistent-file.txt with john using rockyou.txt and --format=raw-md5.
```

**Watch:** Agent emits `john --wordlist=/usr/share/wordlists/rockyou.txt --format=raw-md5 /session/nonexistent-file.txt`. target=`null`. john exits with stderr/stdout containing `fopen: /session/nonexistent-file.txt: No such file or directory`. Failure classified via signal `No such file or directory` AND/OR `fopen:`. Status: `failure_in_output`.

### S6 — failure: format mismatch (No password hashes loaded)

```
I have a file with bcrypt hashes in /session/bcrypt-hashes.txt but I'm not sure of the format. Try cracking it with --format=raw-md5 first to see what happens.
```

**Watch:** Agent emits `john --format=raw-md5 --wordlist=/usr/share/wordlists/rockyou.txt /session/bcrypt-hashes.txt`. target=`null`. john loads the hash file but rejects it because bcrypt hashes don't match raw-md5 structure. Output: `No password hashes loaded`. Failure classified via signal `No password hashes loaded`. Agent should reformulate with `--format=bcrypt` based on the failure remediation.

### S7 — kerberoast TGS hash crack

```
I have kerberoasted TGS-REP hashes in /session/spns.txt from impacket-GetUserSPNs. Crack them with rockyou.txt and the default ruleset. Format is krb5tgs.
```

**Watch:** Agent emits `john --format=krb5tgs --wordlist=/usr/share/wordlists/rockyou.txt --rules --pot=/session/john.pot /session/spns.txt`. target=`null`. Slow per-attempt (Kerberos crypto is expensive); agent should mention `--fork=2` for parallelism on multi-CPU containers.

---

## 3. Target-extraction adversarial cases (≥20)

The john `tool.yaml` declares NO target_extraction rules. Every call should
return `target=null` because john has no network target — it operates on
local hash files only. The "operand" (positional argument) is a file path,
not a hostname/IP/URL.

`reject_flags`: empty (no target-list ingestion concept).

`value_flags` includes ~80 entries to ensure the DSL parses john's argv
correctly without misinterpreting flag values as positional targets. Values
may LOOK like file paths (because they often are), but none of them are
network targets.

### Happy-path cases (every one returns target=null)

| # | Command (binary `john` omitted) | Expected target | Notes |
|---|---|---|---|
| 1 | `/session/hashes.txt` | `null` | Bare positional hash file. No flags. |
| 2 | `--wordlist=/usr/share/wordlists/rockyou.txt --rules --format=nt /session/ntlm.txt` | `null` | Standard NTLM crack. Wordlist value is a path, NOT a target. |
| 3 | `--mask='?l?l?l?l?d?d?d?d' --format=raw-md5 /session/md5.txt` | `null` | Mask attack. Mask value is a pattern, not a target. |
| 4 | `--show --pot=/session/john.pot --format=nt /session/ntlm.txt` | `null` | Pot file lookup. --pot= value is a path. |
| 5 | `--incremental=Digits --max-length=8 --format=raw-md5 /session/hashes.txt` | `null` | Incremental brute. No target. |
| 6 | `--single --format=sha512crypt /session/shadow.txt` | `null` | Single mode. No target. |
| 7 | `--session=engagement-1 --restore` | `null` | Resume previous session. No file argument. |
| 8 | `--restore=engagement-1` | `null` | Same. |
| 9 | `--status=engagement-1` | `null` | Status check on running session. |
| 10 | `--fork=4 --wordlist=rockyou.txt --rules --format=bcrypt /session/bc.txt` | `null` | Parallel crack with --fork. |

### Help / introspection (target=null by definition)

| # | Command | Expected | Notes |
|---|---|---|---|
| H1 | `--help` | `target=null` | Help. tool_runner bypasses scope check. |
| H2 | `--list=help` | `target=null` | Full --list menu. |
| H3 | `--list=formats` | `target=null` | List supported formats. |
| H4 | `--list=hidden-options` | `target=null` | Advanced flags. |
| H5 | `--list=build-info` | `target=null` | Build info. |
| H6 | `--test` | `target=null` | Benchmark mode. No hashes, no target. |
| H7 | `--test=10` | `target=null` | 10-second benchmark. |

### Adversarial — value_flag traps & "looks like a target" invariants

| # | Command | Expected | Notes |
|---|---|---|---|
| F1 | `--external=ip-validator /session/hashes.txt` | `target=null` | --external value is an external-mode filter NAME, not a network target — even if the name looks IP-related. |
| F2 | `--wordlist=10.10.10.5.txt /session/hashes.txt` | `target=null` | Wordlist filename happens to match an IPv4-looking string. NOT a target. Wordlist is in value_flags. |
| F3 | `--pot=/session/192.168.1.1.pot /session/hashes.txt` | `target=null` | Pot path with IP-looking name. NOT a target. |
| F4 | `--logfile=/session/admin@target.com.log /session/hashes.txt` | `target=null` | Log path contains email-shape that LOOKS like a target. NOT a target. |
| F5 | `--rules=KoreLogic --wordlist=rockyou.txt /session/hashes.txt` | `target=null` | Rule set NAME, not a path. No target ambiguity. |
| F6 | `--mask='https://?l?l?l?l.com' --format=raw-md5 /session/hashes.txt` | `target=null` | Mask pattern contains a URL-shape. The MASK VALUE is the operand; it's not extracted as target. |
| F7 | `--config=/session/john-corp.conf --wordlist=rockyou.txt /session/hashes.txt` | `target=null` | --config path, not a target. |
| F8 | `--stdin --format=raw-md5 /session/hashes.txt` | `target=null` | Stdin mode. File argument is the hash file, not a target. |
| F9 | `--devices=0,1 --format=bcrypt --wordlist=rockyou.txt /session/hashes.txt` | `target=null` | Device list (GPU IDs). NOT targets. |
| F10 | `--node=2/4 --wordlist=rockyou.txt /session/hashes.txt` | `target=null` | Cluster node spec. NOT a target. |
| F11 | `--users=root,admin --format=sha512crypt /session/shadow.txt` | `target=null` | User filter. NOT targets. |
| F12 | `--shells=/bin/bash --format=sha512crypt /session/shadow.txt` | `target=null` | Shell filter. Path-shape but NOT a target. |
| F13 | `--format=raw-md5 /session/hashes.txt` | `target=null` | Format with dash in name. john uses double-dash long flags + dashed format names — must parse correctly. |
| F14 | `--format=netntlmv2 /session/responder-hashes.txt` | `target=null` | Format name is a single token (no dashes). |
| F15 | `--format=krb5tgs /session/spns.txt` | `target=null` | Kerberos TGS format. No target. |
| F16 | `--max-length=12 --min-length=8 --incremental=Alpha /session/hashes.txt` | `target=null` | Length bounds + incremental. No target. |
| F17 | `--rules-stack=Single,Wordlist,KoreLogic --wordlist=rockyou.txt /session/hashes.txt` | `target=null` | Comma-separated rule chain. NOT a target list. |
| F18 | `--salts=2 --format=md5crypt /session/hashes.txt` | `target=null` | Salt-count filter. Numeric value, not a target. |

### Multi-positional & no-positional cases

| # | Command | Expected | Notes |
|---|---|---|---|
| M1 | `/session/file1.txt /session/file2.txt` | `target=null` | Multiple hash files. john loads all of them; still no network target. |
| M2 | `--wordlist=rockyou.txt --rules` (no positional) | `target=null` | No file argument — john prints help and exits with non-zero. Plugin should still parse cleanly with target=null. |
| M3 | `--format=raw-md5 /session/h1.txt /session/h2.txt /session/h3.txt` | `target=null` | Three hash files. All operands; no targets. |

### Stdin-pipe trap (the SHELL-PIPE that doesn't work)

| # | Command (as the LLM might naively emit it) | What happens | Correct shape |
|---|---|---|---|
| P1 | `crunch 6 6 abc \| john --stdin --format=raw-md5 /session/hashes.txt` | cli_in_container HAS NO SHELL. The `\|` is treated as a literal arg or rejected. Either way it FAILS. | Use tool_runner's `stdin_data` field with the candidate text; john reads from subprocess stdin. |
| P2 | `echo password \| john --stdin --format=raw-md5 /session/hashes.txt` | Same — no shell, no pipe. | Same. |

---

## 4. Failure-signature live-verify cases (≥3)

| # | Layer | Test | failure_signature `signal` | Status |
|---|---|---|---|---|
| 1 | File / I/O | `--wordlist=/usr/share/wordlists/rockyou.txt --format=raw-md5 /session/nonexistent.txt` | `No such file or directory` AND/OR `fopen:` | PENDING live verify |
| 2 | Hash format / loader | Write a bcrypt hash to /session/wrong.txt, then `--format=raw-md5 /session/wrong.txt` | `No password hashes loaded` | PENDING live verify |
| 3 | Mask / argument | `--mask='?l?l?z?z' --format=raw-md5 /session/hashes.txt` (?z is invalid) | `Mask error` OR `Invalid character class` | PENDING live verify |
| 4 | Wordlist | `--wordlist=/session/missing-wordlist.txt --format=raw-md5 /session/hashes.txt` | `Cannot read wordlist` OR `No such file or directory` | PENDING live verify |
| 5 | Format-name validation | `--format=NOTAFORMAT /session/hashes.txt` | `Unknown ciphertext format name` | PENDING live verify |
| 6 | Empty input | Touch an empty /session/empty.txt, then `--format=raw-md5 /session/empty.txt` | `No password hashes loaded` (same family as case 2) | PENDING live verify |

### Layer diversity (SKILL #11) — achieved

5+ distinct layers exercised: file/IO, hash-loader, mask-parser, wordlist,
format-validation, empty-input. Resource layer (out-of-memory, fork
failure) is hard to provoke deliberately in a small lab; defer to Wave 9
live HTB run with a real engagement workflow.

---

## 5. Open questions

1. **target_extraction = empty list — confirmed correct?** john has no network
   target. The plugin's TargetValidation framework expects hostnames/IPs.
   We're declaring zero rules; the plugin extracts target=null and the
   gotcha note documents that scope-validation is N/A. Verify the plugin
   handles `target=null` gracefully (doesn't reject the call; doesn't try
   to validate "null" against the engagement scope). If the plugin currently
   REJECTS target=null calls, we need a `target_optional: true` flag or
   similar. Check `opensploit-plugin/src/cli_in_container.ts` (or wherever
   target validation lives) for the null-target code path.

2. **Stdin pipe handling**. The new run_cli signature accepts `stdin_data`.
   Verify (a) the plugin pipes stdin_data to subprocess stdin correctly,
   (b) john's --stdin flag reads from stdin not from the file argument,
   (c) whether multi-line stdin_data needs explicit `\n` separators or
   the plugin handles them transparently. Live-test with S4.

3. **--fork=N count**. resources.cpu = 2.0 in tool.yaml. Should usage_patterns
   default to --fork=2 in the bcrypt example, or leave it to the LLM to
   decide based on engagement context? Current pattern says "Set N to the
   container's CPU allocation" — adequate, but worth a dedicated sub-doc.

4. **Pot-file persistence across engagements**. Default ~/.john/john.pot
   lives in the container's home dir; container restart wipes it. Always
   recommending --pot=/session/john.pot is correct — but is /session/
   shared across engagements or per-engagement? If per-engagement, pot
   files don't pool cracked passwords across different engagements (which
   is desirable for compartmentalization). Verify with engagement-state docs.

5. **GPU acceleration**. john-jumbo on Kali ships with CPU-only build (no
   --devices= support). hashcat handles GPU. Should john's tool.yaml
   explicitly say "use hashcat for GPU" or just rely on the see_also
   pointer? Currently both — see_also AND a gotcha note.

6. **Hash file format detection**. john's `--format=?` lists all formats but
   doesn't AUTO-IDENTIFY a hash. The old MCP layer had an `identify`
   method; in kind:cli the LLM has to ask explicitly. Document the
   workflow: run hashid (separate tool, see_also) OR experiment with
   `--show --format=<guess>` to test format guesses.

7. **Wordlist auto-decompress**. /usr/share/wordlists/rockyou.txt may be
   .gz on fresh Kali rebuilds. The Dockerfile currently has a one-shot
   `if [ -f rockyou.txt.gz ]; then gunzip ...; fi`. Verify this still
   works on the latest kalilinux/kali-rolling image. If not, switch to
   --wordlist= a pre-decompressed path or build a custom wordlist.

8. **Legacy MCP convenience methods removed (`crack` auto-show, `show`/`identify`
   accepting hash STRINGS, `convert` wrapping *2john)**. The legacy server
   exposed four high-level methods: `crack` (which ran the wordlist/mask/
   incremental attack THEN automatically called `john --show` and merged
   the parsed cracked-passwords list into the result data), `show` (took a
   hash STRING, wrote to a tempfile, called `john --show`), `identify`
   (regex-based hash-format detector with john-probing fallback), and
   `convert` (mapped 28 file types to *2john script paths and ran them).
   In kind:cli all four are gone — the LLM constructs the raw john invocation.
   Documented the replacement workflows in tool.yaml gotchas: full wordlist
   paths (no shortnames), explicit two-step crack-then-show, write hashes
   to a file first, *2john script-by-script invocation, hash-id via prefix
   patterns or hashid. Verify in Wave 9 live runs that the LLM correctly
   chains crack → --show without coaching, and that *2john usage flows
   from the gotcha list rather than requiring hardcoded knowledge.

9. **Resume across container restarts**. --session=NAME writes
   ~/.john/NAME.rec. Container restart wipes ~/.john/. To survive restarts,
   point the session file to /session/<name>.rec — but john doesn't expose
   a `--session-file=PATH` flag, only `--session=NAME` (writes to ~/.john/).
   Possible workaround: bind-mount ~/.john/ to /session/.john/. Out of
   scope for tool.yaml; document as a runtime concern.

---

## 6. Hand-off

- **Tool**: john (kind:cli)
- **Status**: tool.yaml authored end-to-end; scenarios.md written. Dockerfile reviewed — already uses python3-pip + python3-venv pattern; works fine on current Kali rolling. Did NOT change to python3-full because the existing pattern is functional and the Kali image hasn't shown the impacket-style stale-repo regression for john's package set. (If a future build fails on python3-pip / python3-venv, swap to python3-full per the impacket / nuclei pattern.) mcp-server.py untouched (auto-inherits run_cli; rollback path).
- **Image**: `ghcr.io/silicon-works/mcp-tools-john:latest` — needs rebuild during Wave 9 batch to pick up mcp-common 0.3.0.
- **target_extraction = empty list**: explicit design choice. john has no network target; the plugin should treat target=null as "no scope validation needed" for this tool. See Open Question #1.
- **Wave 1.5**: final tool of Wave 1 (curl, sqlmap, impacket, nmap, ffuf, nuclei, nikto, john all migrated). Tier A gate complete — Wave 2 can start (hashcat, kerbrute, hydra).
- **Live-verify pending**: paste S1-S7 against a synthetic hash file (/session/hashes-test.txt with rockyou top 3 raw-md5 hashes) for end-to-end. Verify failure_signatures 1-2 (file-not-found, format mismatch) live; defer cases 3-6 once synthetic fixture is in place.

Authored: 2026-04-25.
