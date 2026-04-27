# hashcat — Tier A scenarios

Single test sheet for the `hashcat` tool migration (Wave 2.1).

Sections:
1. Recommended HTB box for live verification
2. Narrative scenarios (paste into opensploit)
3. Target-extraction adversarial cases (≥20)
4. Failure-signature live-verify cases (≥3)
5. Open questions
6. Hand-off

---

## 1. Recommended HTB box

**N/A — hashcat has no network target.** Like its sister tool `john`,
hashcat operates entirely on local hash files; there is no remote host
to scan, attack, or authenticate against. The "target" of a hashcat call
is a file path inside the container (e.g., `/session/hashes.txt`) plus a
wordlist or mask, not a hostname or IP.

For LIVE VERIFICATION of the architecture path, two options:

**(a) Static synthetic hash file (recommended for CI / Tier A gate).**
A small handcrafted hash file at `/session/hashes-test.txt` with a few
known-crackable hashes (NTLM hashes whose plaintexts are in rockyou top
100). Lets us verify target extraction (target=null), output handling,
failure classification, and successful-crack flow without requiring an
HTB box.

Example test-fixture content (paste into `/session/hashes-test.txt` —
NTLM hashes of `password`, `123456`, `admin`, `letmein`, `qwerty` — all
rockyou top 50):

```
8846f7eaee8fb117ad06bdd830b7586c
32ed87bdb5fdc5e9cba88547376818d4
209c6174da490caeb422f3fa5a7ae634
0d757ad173d2fc249ce19364fd64c8ec
8578edf66d2003c98c1a08b015ce1ab9
```

These are NTLM (-m 1000) hashes — all crack in <1 second with rockyou
because the plaintexts are in the top 50. First entry verifies a known
positive; remaining four verify multi-hash output handling.

**(b) End-to-end engagement.** Any HTB box that has produced hashes in
prior engagement steps. The typical workflow:

1. nmap → identify Active Directory / SMB / web services
2. impacket-secretsdump → write /session/<box>-ntds.txt
3. hashcat -a 0 -m 1000 /session/<box>-ntds.txt /session/rockyou.txt
   --potfile-path /session/hashcat.pot --force --status --status-timer=30
4. → cracked NTLM hashes for credential reuse

Recent example: **Hercules (or any HTB AD box)** where secretsdump
produces NTDS hashes; hashcat's output feeds into netexec for lateral
movement. Hashes are STATIC FILES in /session/, NOT a network target —
hashcat's behaviour is independent of which box generated them.

Persistent test directory: standard `/session/` mount; hashcat reads
input from `/session/*.txt`, writes potfile to `/session/hashcat.pot`
(when `--potfile-path /session/hashcat.pot` is specified), and writes
optional outfile to `/session/cracked.txt`.

---

## 2. Narrative scenarios (paste into opensploit)

### S1 — wordlist attack vs NTLM (most common)

```
I have NTLM hashes from secretsdump in /session/ntds-hashes.txt. Use hashcat with rockyou.txt to crack them. Mode 1000. Pin the potfile to /session/hashcat.pot so cracks survive container restart, and emit status updates every 30 seconds. We're in a Docker container with no GPU, so include --force.
```

**Watch:** Agent emits something like `hashcat -a 0 -m 1000 /session/ntds-hashes.txt /session/rockyou.txt --potfile-path /session/hashcat.pot --status --status-timer=30 --force`. target=`null` (no network target). First call ~5-15s container spawn + kernel compile; subsequent calls reuse warm container. Cracked passwords appear in stdout (`hash:plaintext`) AND in /session/hashcat.pot.

### S2 — mask attack vs MD5 (8-char alphanumeric)

```
I have MD5 hashes in /session/md5-hashes.txt. Try a mask attack assuming 4 lowercase letters followed by 4 digits (Name1234 shape). Mode 0.
```

**Watch:** Agent emits `hashcat -a 3 -m 0 /session/md5-hashes.txt '?l?l?l?l?d?d?d?d' --potfile-path /session/hashcat.pot --force`. target=`null`. Mask string is the operand; -a 3 = mask mode. ~30 seconds on CPU for the full 26^4 × 10^4 ≈ 4.5 billion candidate keyspace at typical NTLM-equivalent c/s rate (MD5 is even faster).

### S3 — wordlist + best64 rules vs SHA1

```
Crack SHA1 hashes in /session/sha1-hashes.txt with rockyou.txt and the best64 rules from /usr/share/hashcat/rules/best64.rule. Mode 100.
```

**Watch:** Agent emits `hashcat -a 0 -m 100 -r /usr/share/hashcat/rules/best64.rule /session/sha1-hashes.txt /session/rockyou.txt --potfile-path /session/hashcat.pot --force`. target=`null`. Rules multiply the wordlist by ~64 mangling rules. Effective candidates: ~14M × 64 ≈ 900M. SHA1 c/s rate is similar to MD5 — full pass in ~1-2 minutes on CPU.

### S4 — show already-cracked passwords from potfile

```
I cracked some NTLM hashes in /session/old-ntds.txt yesterday with hashcat --potfile-path /session/hashcat.pot. Show me the cracked results without re-running the attack.
```

**Watch:** Agent emits `hashcat -m 1000 --show /session/old-ntds.txt --potfile-path /session/hashcat.pot --force`. target=`null`. hashcat reads the potfile and prints `hash:plaintext` for any hash that's already cracked. Returns instantly (no cracking). -m must match the original crack mode.

### S5 — failure: invalid hash mode

```
Crack the hashes in /session/hashes.txt with hashcat. Use mode 99999 (just to see what happens) and rockyou.txt.
```

**Watch:** Agent emits `hashcat -a 0 -m 99999 /session/hashes.txt /session/rockyou.txt --potfile-path /session/hashcat.pot --force`. target=`null`. hashcat aborts with `Mode 'X' is not supported` or `Invalid -m specified`. Failure classified via signal `Mode '.*' is not supported` OR `Invalid -m specified`. Agent should reformulate with a valid mode based on the failure remediation (recommend running `hashcat --identify /session/hashes.txt`).

### S6 — failure: wordlist not found

```
Crack /session/hashes.txt with the wordlist /session/missing-wordlist.txt. Mode 1000.
```

**Watch:** Agent emits `hashcat -a 0 -m 1000 /session/hashes.txt /session/missing-wordlist.txt --potfile-path /session/hashcat.pot --force`. target=`null`. hashcat exits with `No such file or directory` or `Could not open hashfile` style error pointing to the wordlist (since the wordlist is also opened as a file). Failure classified via signal `No such file or directory`.

### S7 — GPU-not-available (--force required)

```
Run a quick benchmark of NTLM (mode 1000) in this container.
```

**Watch:** Agent emits `hashcat -b -m 1000 --force`. target=`null`. Without `--force` hashcat would abort with `No devices found` because the Docker container has no GPU passthrough (`--gpus all` not set). With `--force`, hashcat falls back to OpenCL CPU runtime (mesa-opencl-icd / pocl) and benches at the CPU c/s rate (typically 100s of MH/s for NTLM). Document: --force is REQUIRED for every hashcat run inside the current container build because the plugin doesn't pass --gpus.

### S8 — kerberoast TGS-REP crack

```
I have kerberoasted TGS-REP hashes in /session/tgs.txt from impacket-GetUserSPNs. Crack them with rockyou.txt and best64 rules. Mode 13100 for RC4.
```

**Watch:** Agent emits `hashcat -a 0 -m 13100 /session/tgs.txt /session/rockyou.txt -r /usr/share/hashcat/rules/best64.rule --potfile-path /session/hashcat.pot --force --status --status-timer=60`. target=`null`. Slow per-attempt (RC4-HMAC + Kerberos crypto); --status-timer=60 keeps idle_timeout heartbeats flowing.

---

## 3. Target-extraction adversarial cases (≥20)

The hashcat `tool.yaml` declares NO target_extraction rules. Every call
should return `target=null` because hashcat has no network target — it
operates on local hash files only. The "operands" (positional arguments)
are file paths and/or mask strings, not hostnames/IPs/URLs.

`reject_flags`: empty (no target-list ingestion concept).

`value_flags` includes ~80 entries to ensure the DSL parses hashcat's
argv correctly without misinterpreting flag values as positional
targets. Values may LOOK like file paths, hostnames, or IPs (because
they often are), but none of them are network pentest targets.

### Happy-path cases (every one returns target=null)

| #  | Command (binary `hashcat` omitted) | Expected target | Notes |
|----|---|---|---|
| 1  | `-a 0 -m 1000 /session/hashes.txt /session/rockyou.txt --force` | `null` | Wordlist NTLM. Two file paths; neither is a target. |
| 2  | `-a 3 -m 0 /session/hashes.txt '?l?l?l?l?d?d?d?d' --force` | `null` | Mask MD5. Mask string is an operand, not a target. |
| 3  | `-a 0 -m 100 -r /usr/share/hashcat/rules/best64.rule /session/h.txt /session/rockyou.txt --force` | `null` | SHA1 + rules. -r value is a rule file path. |
| 4  | `-a 6 -m 1800 /session/h.txt /session/rockyou.txt '?d?d?d' --force` | `null` | Hybrid wordlist+mask. Wordlist + mask string operands. |
| 5  | `-a 7 -m 0 /session/h.txt '?d?d?d' /session/rockyou.txt --force` | `null` | Hybrid mask+wordlist. Order reversed; still no target. |
| 6  | `-a 1 -m 0 /session/h.txt /session/wl1.txt /session/wl2.txt --force` | `null` | Combination attack. Two wordlists; no target. |
| 7  | `-m 1000 --show /session/h.txt --potfile-path /session/hashcat.pot --force` | `null` | Potfile lookup. --potfile-path value is a path. |
| 8  | `-m 1000 --left /session/h.txt --potfile-path /session/hashcat.pot --force` | `null` | List uncracked. Same shape. |
| 9  | `-a 0 -m 13100 /session/tgs.txt /session/rockyou.txt --force` | `null` | Kerberoast crack. No target. |
| 10 | `-a 9 -m 1000 /session/h.txt /session/rockyou.txt --force` | `null` | Association attack. No target. |

### Help / introspection (target=null by definition)

| #  | Command | Expected | Notes |
|----|---|---|---|
| H1 | `--help` | `target=null` | Help. tool_runner bypasses scope check. |
| H2 | `-V` | `target=null` | Version short form. |
| H3 | `--version` | `target=null` | Version long form. |
| H4 | `-b -m 1000 --force` | `target=null` | Benchmark mode 1000. |
| H5 | `--benchmark-all --force` | `target=null` | Benchmark every mode. |
| H6 | `-m 1000 --example-hashes` | `target=null` | Print example NTLM hashes. |
| H7 | `--identify /session/h.txt --force` | `target=null` | Auto-identify. |
| H8 | `--opencl-info` | `target=null` | Enumerate OpenCL devices. |

### Adversarial — value_flag traps & "looks like a target" invariants

| #   | Command | Expected | Notes |
|-----|---|---|---|
| F1  | `--brain-host brain.internal -a 0 -m 1000 /session/h.txt /session/rockyou.txt --force` | `target=null` | --brain-host is hashcat's DISTRIBUTED COORDINATION server (infrastructure for splitting work across cracking nodes), NOT a pentest target. The hostname value is internal-network only. |
| F2  | `--brain-host 10.10.10.5 --brain-port 6379 -a 0 -m 1000 /session/h.txt /session/rockyou.txt --force` | `target=null` | brain-host with an IP-shape value. STILL hashcat infrastructure, not a target. |
| F3  | `-a 0 -m 1000 /session/192.168.1.1.txt /session/rockyou.txt --force` | `target=null` | Hash file path happens to match an IPv4-looking string. Path is the operand, NOT a target. |
| F4  | `-a 0 -m 1000 /session/some@thing/hashes.txt /session/rockyou.txt --force` | `target=null` | Hash file path contains '@' (email-shape). Still a file path. |
| F5  | `-a 0 -m 1000 /session/h.txt /session/admin@target.com.wordlist --force` | `target=null` | Wordlist filename has email-shape. NOT a target. |
| F6  | `-a 3 -m 0 /session/h.txt 'https://?l?l?l.com' --force` | `target=null` | Mask string looks like a URL pattern. The MASK is the operand; not a target. |
| F7  | `-a 3 -m 0 /session/h.txt 'evil.com?d?d?d' --force` | `target=null` | Mask with literal hostname-shape prefix. Still a mask string. |
| F8  | `-a 0 -m 1000 /session/h.txt /session/rockyou.txt --outfile /session/cracked.txt --force` | `target=null` | --outfile path. Not a target. |
| F9  | `-a 0 -m 1000 /session/h.txt /session/rockyou.txt --potfile-path /session/192.168.1.1.pot --force` | `target=null` | Potfile path with IP-shape. Not a target. |
| F10 | `-a 0 -m 1000 /session/h.txt /session/rockyou.txt --debug-file /session/admin@target.com.log --force` | `target=null` | Debug file path with email-shape. Not a target. |
| F11 | `-a 0 -m 1000 /session/h.txt /session/rockyou.txt --induct-dir /session/incoming --force` | `target=null` | --induct-dir is a directory path for new-wordlist induction. Not a target. |
| F12 | `-a 0 -m 1000 -r /session/rules/192.168.1.1.rule /session/h.txt /session/rockyou.txt --force` | `target=null` | Rules path with IP-shape filename. Not a target. |
| F13 | `-a 0 -m 1000 -d 1,2,3 /session/h.txt /session/rockyou.txt --force` | `target=null` | --devices list (GPU/CPU IDs). Not targets. |
| F14 | `-a 0 -m 1000 -D 1,2 /session/h.txt /session/rockyou.txt --force` | `target=null` | --device-types list (1=CPU, 2=GPU). Not targets. |
| F15 | `-a 0 -m 1000 --cpu-affinity 0,1 /session/h.txt /session/rockyou.txt --force` | `target=null` | CPU affinity list (CPU IDs). Not targets. |
| F16 | `-a 3 -m 1000 /session/h.txt '?1?1?1?1' -1 '?l?d' --force` | `target=null` | Custom charset definition. -1 value is a charset string. Not a target. |
| F17 | `-a 3 -m 1000 /session/h.txt '?1?1?1?1' -1 '?l?d' -2 'abc123' -3 '!@#' -4 '?u?d' --force` | `target=null` | All 4 custom charsets. None is a target. |
| F18 | `-a 0 -m 1000 --session=client-engagement-1 /session/h.txt /session/rockyou.txt --force` | `target=null` | Session name. Not a target. |
| F19 | `-a 0 -m 1000 --session=engagement.htb /session/h.txt /session/rockyou.txt --force` | `target=null` | Session name happens to look like an HTB hostname. Still just a session name. |
| F20 | `--restore --session=engagement-1` | `target=null` | Resume previous session. No file argument. |
| F21 | `-a 0 -m 22000 /session/handshake.hccapx /session/rockyou.txt --force` | `target=null` | WPA crack — hash file is a binary capture (.hccapx). Not a target. |
| F22 | `-a 0 -m 1000 --keyfile /session/keyfile.bin /session/h.txt /session/rockyou.txt --force` | `target=null` | --keyfile path (TrueCrypt-style). Not a target. |
| F23 | `-a 0 -m 1000 --keyboard-layout-mapping /session/german.hckmap /session/h.txt /session/rockyou.txt --force` | `target=null` | Layout mapping path. Not a target. |
| F24 | `-a 0 -m 1000 --markov-hcstat2 /session/custom.hcstat2 /session/h.txt /session/rockyou.txt --force` | `target=null` | Markov stats file. Not a target. |
| F25 | `-a 3 -m 0 --runtime 3600 /session/h.txt '?d?d?d?d?d?d' --force` | `target=null` | --runtime soft cap (seconds). Not a target. |
| F26 | `-a 3 -m 0 -i --increment-min=4 --increment-max=8 /session/h.txt '?a?a?a?a?a?a?a?a' --force` | `target=null` | Increment mode bounds. Numeric values, not targets. |

### Multi-positional & no-positional cases

| #  | Command | Expected | Notes |
|----|---|---|---|
| M1 | `-a 0 -m 1000 /session/h1.txt /session/rockyou.txt --force` (then) `-a 0 -m 1000 /session/h2.txt /session/rockyou.txt --force` | `target=null` (both) | Two separate calls; each operand is a file path. |
| M2 | `-a 1 -m 0 /session/h.txt /session/wl1.txt /session/wl2.txt --force` | `target=null` | Combinator: hash file + 2 wordlists = 3 positionals. None is a target. |
| M3 | `-a 0 -m 1000 --force` (no positional) | `target=null` | No file argument — hashcat prints help/error, exits non-zero. Plugin should still parse cleanly with target=null. |
| M4 | `-a 6 -m 1800 /session/h.txt /session/rockyou.txt '?d?d?d?d' --force` | `target=null` | Hybrid: hash + wordlist + mask = 3 positionals (mask is the 3rd). None is a target. |

### Stdin / pipe trap (the SHELL-PIPE that doesn't work)

| # | Command (as the LLM might naively emit it) | What happens | Correct shape |
|---|---|---|---|
| P1 | `crunch 8 8 abcdef \| hashcat --stdout --stdin -m 0 -a 0 /session/h.txt --force` | cli_in_container HAS NO SHELL. The `\|` is treated as a literal arg or rejected. Either way it FAILS. | hashcat doesn't have a true `--stdin` flag for cracking input the way john does; for piped candidates, generate the wordlist to a file first, then `-a 0 hash.txt wordlist.txt`. Or use `--stdout` + tool_runner stdin_data ↔ stdout. |

---

## 4. Failure-signature live-verify cases (≥3)

| # | Layer | Test | failure_signature `signal` | Status |
|---|---|---|---|---|
| 1 | File / I/O | `-a 0 -m 1000 /session/nonexistent.txt /session/rockyou.txt --force` | `No such file or directory` AND/OR `Could not open hashfile` | PENDING live verify |
| 2 | Hash format / loader | Write a bcrypt hash to /session/wrong.txt, then `-a 0 -m 0 /session/wrong.txt /session/rockyou.txt --force` (mode 0 = MD5) | `No hashes loaded` AND/OR `Token length exception` | PENDING live verify |
| 3 | Hash mode | `-a 0 -m 99999 /session/h.txt /session/rockyou.txt --force` | `Mode '.*' is not supported` OR `Invalid -m specified` | PENDING live verify |
| 4 | Hash mode (missing) | `-a 0 /session/h.txt /session/rockyou.txt --force` (no -m) | `No hash-mode specified` | PENDING live verify |
| 5 | Mask / argument | `-a 3 -m 0 /session/h.txt '?l?l?z?z' --force` (?z is invalid) | `Mask error` OR `Invalid mask` | PENDING live verify |
| 6 | Wordlist | `-a 0 -m 1000 /session/h.txt /session/missing-wordlist.txt --force` | `No such file or directory` | PENDING live verify |
| 7 | Device / OpenCL | `-a 0 -m 1000 /session/h.txt /session/rockyou.txt` (no --force in container without --gpus) | `No devices found/left` | PENDING live verify |
| 8 | Custom charset undefined | `-a 3 -m 0 /session/h.txt '?1?1?1?1' --force` (no -1 definition) | `Custom-charset.*not specified` | PENDING live verify |

### Layer diversity (SKILL #11) — achieved

≥5 distinct layers exercised: file/IO, hash-loader, mask-parser, hash-mode-validator, wordlist, device/OpenCL, custom-charset-validator. Resource layer (out-of-memory) is hard to provoke deliberately in a small lab; defer to a Wave 9 live HTB run with a real engagement workflow that uses dive.rule on a large wordlist.

---

## 5. Open questions

1. **target_extraction = empty list — confirmed correct?** Same design as john. hashcat has no network target; the plugin's TargetValidation framework expects hostnames/IPs. We declare zero rules; the plugin extracts target=null and the gotcha note documents that scope-validation is N/A. Verify the plugin handles `target=null` gracefully (doesn't reject the call; doesn't try to validate "null" against the engagement scope). If the plugin currently REJECTS target=null calls, we need a `target_optional: true` flag or similar. Check `opensploit-plugin/src/cli_in_container.ts` for the null-target code path. (Note: john already exercised this path — if john works, hashcat will too.)

2. **`--brain-host` semantics**. Hashcat's brain server is distributed-cracking infrastructure, NOT a pentest target. The `--brain-host` flag value LOOKS like a network target (hostname/IP). Decision: declared in `value_flags` so the DSL captures it but does NOT extract it as a target. This is the right call because the brain server is internal cracking-cluster infra; running scope-validation against it would block legitimate uses. Document: if a future feature adds "internal-infrastructure scope" (e.g., "is this brain server inside the engagement network?"), revisit.

3. **GPU passthrough in containers**. Current opensploit-plugin Docker invocations do NOT pass `--gpus all`. Therefore every hashcat run REQUIRES `--force` to fall back to OpenCL CPU runtime. CPU performance is much slower (e.g., NTLM ~100 MH/s vs ~10 GH/s on a midrange GPU). For Wave 9 / production, consider: (a) plugin flag to optionally pass `--gpus all` per tool, (b) container build switch for GPU-enabled image variant. Out of scope for this migration; document in usage_patterns.

4. **`--restore` session compatibility across image versions**. .restore files from different hashcat MAJOR versions are incompatible. If the GHCR image is rebuilt with a new hashcat version (v7.1.2 → v7.2.x), in-flight long-running sessions cannot resume. Mitigation: pin hashcat version in the image build; document the resume-on-rebuild risk in tool.yaml gotchas (already done).

5. **Potfile path differences between hashcat versions**. v6/v7 use `~/.local/share/hashcat/hashcat.potfile`; older builds use `~/.hashcat/hashcat.potfile`. Always pin `--potfile-path /session/hashcat.pot` to avoid version-dependent location guessing. Documented in gotchas.

6. **Slow-hash modes and idle_timeout heartbeats**. Slow modes (bcrypt -m 3200, scrypt -m 8900, Argon2 -m 34000) can run for HOURS without a status update unless `--status` is enabled. idle_timeout_seconds=600 (10 min) means a slow-hash run without `--status --status-timer=N` could be killed prematurely. RECOMMENDATION (already in usage_patterns): always include `--status --status-timer=30` (or 60 for very slow modes) on long crack runs. Verify plugin treats stdout status lines as heartbeats (pretty sure john tests confirmed this; hashcat output format is similar but check live).

7. **Custom charset count**. Hashcat documentation traditionally describes 4 custom charsets (-1/-2/-3/-4). Some recent builds support up to 8 (-5/-6/-7/-8). value_flags currently lists 1-4. If a future build needs 5-8, add them. Out of scope here.

8. **OpenCL CPU runtime in image**. Image ships with `mesa-opencl-icd` and `ocl-icd-libopencl1`. Verify on next rebuild that pocl (Portable OpenCL) is also available — pocl is more portable than mesa for pure CPU and avoids GPU-driver-related crashes. Document: if `hashcat --opencl-info` shows zero platforms, install pocl into the image.

9. **Hash file format for mode 22000 (WPA)**. WPA uses .hccapx binary captures, not text hashes. The positional argument is still a file path, just binary instead of text. Verify the DSL parser treats binary-content paths the same as text-content paths (it should — the DSL only sees the path string, not the file contents).

10. **Loss of bundled hash-id heuristic from legacy server**. The legacy `mcp-server.py` `identify` method ran `hashcat --identify` AND a regex heuristic over ~13 well-known prefix / length patterns (md5crypt $1$, sha256crypt $5$, sha512crypt $6$, bcrypt $2[aby]$, phpass $P$/$H$, apr1, argon2, MD5/NTLM 32-hex collision returning both modes, SHA1 40-hex, SHA256 64-hex, SHA512 128-hex, MD5+salt `[a-f]{32}:[a-f]+`, MySQL 4.1+ `*[A-F]{40}`, LM 16-hex). The kind:cli surface delegates entirely to `hashcat --identify`, which only inspects the first line and does not return ambiguity-aware multi-mode candidates the same way (e.g. for a 32-hex string it will not always emit both 0 and 1000 with the right framing). Mitigations documented in tool.yaml gotchas: agent should also call `hashid` (separate tool) for cross-validation and visually inspect prefixes for $-tagged crypt strings. If post-migration HTB runs show agents struggling to disambiguate 32-hex (MD5 vs NTLM) from context, consider re-introducing a small `hashcat-identify-heuristic` shim — but probably not worth the extra MCP server; the LLM should infer mode from context (Windows dump → 1000 NTLM, web app dump → 0 MD5).

11. **Cold-start kernel compile margin**. Legacy server added 120 s head-room above `--runtime` (`run_command(timeout=timeout + 120)`) to absorb the CPU-only kernel compile that precedes any cracking. With kind:cli the outer `max_runtime_seconds` and any LLM-set `--runtime` must include this slack — otherwise short crack budgets (e.g. `--runtime 60`) will be killed by the wrapper before hashcat even starts trying candidates. Documented in gotchas; verify in live HTB run that 30 s `--runtime` doesn't cause spurious failures on cold containers.

12. **Default workload profile in this image**. Legacy `_base_args` pinned `-w 2` (medium) specifically because the 1024 MB container OOMs on `-w 3`/`-w 4` runs with heavy rulesets (dive, OneRuleToRuleThemAll). Documented in gotchas; if a future image bumps `resources.memory_mb` ≥ 2048, `-w 3` becomes safe and recommendations should follow.

13. **Outfile suppression vs duplicate writes**. Legacy `_base_args` set `-o /dev/null` so cracked results lived only in the pinned potfile (recoverable via `--show`). The kind:cli usage_patterns don't pass `-o /dev/null`, which means hashcat will write a default outfile in cwd on each crack — harmless but produces stray files in the container working directory. Either accept that side-effect, or have the LLM emit `-o /dev/null` (or `--outfile /session/cracked.txt --outfile-format=3` for explicit hash:password capture) on every run. Documented in gotchas; not blocking.

---

## 6. Hand-off

- **Tool**: hashcat (kind:cli)
- **Status**: tool.yaml authored end-to-end; scenarios.md written. Dockerfile updated — replaced `python3 python3-pip python3-venv` with `python3-full` to match the impacket / nuclei / nikto / john pattern (Kali rolling occasionally has stale repo indexes that 404 on the discrete packages but resolve `python3-full` cleanly). Also added `apt-get clean` and `DEBIAN_FRONTEND=noninteractive` (already present) for consistency. Image still ships hashcat + mesa-opencl-icd + ocl-icd-libopencl1 + wordlists + rockyou.txt decompression. mcp-server.py untouched — auto-inherits run_cli from BaseMCPServer (mcp-common 0.3.0); existing crack_dictionary / crack_mask / crack_hybrid / crack_combinator / show / identify methods kept as the rollback path.
- **Image**: `ghcr.io/silicon-works/mcp-tools-hashcat:latest` — needs rebuild during Wave 9 batch to pick up mcp-common 0.3.0. Image is large (~1 GB) due to rockyou.txt + hashcat rules + OpenCL ICDs.
- **target_extraction = empty list**: explicit design choice, identical to john. hashcat has no network target; plugin should treat target=null as "no scope validation needed" for this tool. See Open Question #1.
- **--force is REQUIRED in all crack and benchmark scenarios**: because Docker containers don't currently get --gpus passthrough. Documented in gotchas, every usage_pattern, and Open Question #3.
- **Wave 2.1**: first tool of Wave 2 (hashcat done; kerbrute and hydra are Wave 2.2 and 2.3 still pending). Tier A migration progress: 9 tools done (curl, sqlmap, impacket, nmap, ffuf, nuclei, nikto, john, hashcat).
- **Live-verify pending**: paste S1-S8 against the synthetic NTLM hash fixture (/session/hashes-test.txt with the 5 rockyou top-50 NTLM hashes shown in section 1) for end-to-end. Verify failure_signatures 1-3 (file-not-found, format mismatch, invalid mode) live; defer cases 4-8 once synthetic fixture is in place.
- **Files removed**: none — no `target_extraction_tests.md`, `failure_signature_tests.md`, or `__pycache__/` were present in the hashcat directory.

Authored: 2026-04-25.
