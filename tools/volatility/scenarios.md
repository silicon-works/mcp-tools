# volatility — Tier A scenarios

Single test sheet for the `volatility` (Volatility 3, binary `vol`) tool migration.

Sections:
1. Recommended HTB box for live verification
2. Narrative scenarios (paste into opensploit)
3. Target-extraction adversarial cases (≥20)
4. Failure-signature live-verify cases (≥3)
5. Open questions
6. Hand-off

---

## 1. Recommended HTB box

**N/A — volatility has no network target.** Volatility 3 operates entirely
on local memory dump files inside the container; there is no remote host
to scan, attack, or authenticate against. The "target" of a vol call is
a file path (e.g., `/session/dump.raw`) supplied via `-f`, plus a
namespaced plugin name as a positional (e.g., `windows.pslist.PsList`).

For LIVE VERIFICATION of the architecture path, three options:

**(a) Public sample dump (recommended for CI / Tier A gate).**
Stage a small, known-good memory dump in `/session/`. Recommended
options:

- **Honeynet Project's "BluePill" challenge dump** — small Windows 10
  dump with a known process tree and a hidden malicious process; well-
  documented walkthroughs exist for cross-checking plugin output.
- **The "Stuxnet" sample dump** (~256 MB Windows XP) — classic teaching
  dump with malfind hits and registry artifacts.
- **A handcrafted small dump** generated with `dd if=/dev/mem`-style
  capture against a disposable VM, or via volatility's own test fixtures.
- **The Volatility Foundation's "demo.bin"** sample (publicly available
  with the framework's documentation).

The dump file path is what matters for the architecture test — any
parseable dump exercises layer detection, plugin resolution, renderer
output, and failure paths.

**(b) Generated dump.** Capture memory from a disposable Linux VM with
LiME (Linux Memory Extractor, https://github.com/504ensicslabs/lime)
producing a `.lime` dump, copy to `/session/dump.lime`, and run
`linux.bash.Bash`, `linux.pslist.PsList`, `linux.banners.Banners`. This
is the most reproducible CI fixture if no public dump is bundled.

**(c) End-to-end engagement.** Any HTB box where a memory dump was
produced during post-exploitation (rare on standard HTB; more common
in Forensics-tagged challenges and CTF-style boxes). Workflow:

1. Initial access → compromise host
2. Capture memory (LiME for Linux, DumpIt/winpmem for Windows)
3. Exfil dump to attacker box → /session/<box>-dump.raw
4. `vol -f /session/<box>-dump.raw windows.info.Info` → confirm
5. Run pslist / netscan / hashdump / malfind → extract artifacts
6. Feed extracted hashes to hashcat (-m 1000) for cracking

The dump is a STATIC FILE in /session/; vol's behaviour is independent
of where it came from.

Persistent test directory: standard `/session/` mount; vol reads dump
via `-f /session/<name>` and the cache directory should be pinned via
`--cache-path /session/vol-cache` to persist layer-detection caches
across container restarts.

---

## 2. Narrative scenarios (paste into opensploit)

### S1 — identify the dump (always do this first)

```
I have a memory dump at /session/dump.raw. Run volatility's windows.info plugin to confirm the OS, kernel version, and that the dump is parseable. JSON output. Pin the cache to /session/vol-cache so this and subsequent calls are fast.
```

**Watch:** Agent emits something like `vol -f /session/dump.raw -r json --cache-path /session/vol-cache windows.info.Info`. target=`null` (no network target). First call is slow (~30-60 s) building the cache; subsequent calls reuse it. JSON object includes `Kernel Base`, `DTB`, `Symbols`, `Is64Bit`, `IsPAE`, `MajorVersion`, `MinorVersion`, `MachineType`, `KdVersionBlock`, `NTBuildLab`, `NtSystemRoot`, `ProductType`, `SystemTime`. If output instead has `Could not determine layer`, the dump is corrupt or wrong-OS — try `linux.banners.Banners`.

### S2 — process listing (Windows)

```
List running processes from /session/dump.raw using volatility windows.pslist. JSON output for downstream parsing.
```

**Watch:** Agent emits `vol -f /session/dump.raw -r json windows.pslist.PsList`. target=`null`. Returns array of process objects with PID, PPID, ImageFileName, Offset, Threads, Handles, SessionId, Wow64, CreateTime, ExitTime. ~50-200 entries on a typical desktop dump. Cache hit makes this near-instant after S1.

### S3 — process tree (parent-child relationships)

```
Show me the process tree from /session/dump.raw. I want to spot suspicious parent-child relationships like winword.exe spawning powershell. Use the pstree plugin with JSON output.
```

**Watch:** Agent emits `vol -f /session/dump.raw -r json windows.pstree.PsTree`. target=`null`. JSON output is nested (children array per process). Look for: explorer.exe → winword.exe → cmd.exe → powershell.exe (phishing chain), services.exe → suspicious_legit_looking_name.exe, etc.

### S4 — network connections

```
Extract TCP/UDP connections from /session/dump.raw using volatility's netscan plugin. JSON output. I want to map connections to owning PIDs.
```

**Watch:** Agent emits `vol -f /session/dump.raw -r json windows.netscan.NetScan`. target=`null`. Returns array with Offset, Proto, LocalAddr, LocalPort, ForeignAddr, ForeignPort, State, PID, Owner, Created. Cross-reference PIDs against the pslist output from S2 to identify which process owned each connection.

### S5 — extract NTLM hashes from SAM hive

```
Run volatility hashdump against the Windows memory dump at /session/dump.raw. I want NTLM hashes I can crack with hashcat -m 1000. JSON output.
```

**Watch:** Agent emits `vol -f /session/dump.raw -r json windows.registry.hashdump.Hashdump`. target=`null`. Returns array of {User, rid, lmhash, nthash}. Format the output as `user:rid:lmhash:nthash` (or `user:nthash` for hashcat -m 1000) by piping through a small jq/awk filter (separate run_cli call) or asking hashcat to ingest the structured form.

### S6 — Linux bash command history

```
Extract bash command history from /session/dump.lime — this is a Linux memory dump captured with LiME. Use volatility's linux.bash plugin.
```

**Watch:** Agent emits `vol -f /session/dump.lime linux.bash.Bash`. target=`null`. Returns rows with PID, Process (bash), CommandTime, Command. Recovers in-memory history even if `.bash_history` was deleted on disk. Cross-reference timestamps against the engagement timeline to spot attacker commands.

### S7 — MFT extraction with output dir

```
Extract NTFS MFT entries from /session/dump.raw using volatility windows.mftscan. Write extracted artifacts to /session/mft/. Use the cache at /session/vol-cache.
```

**Watch:** Agent emits `mkdir -p /session/mft` first (separate run_cli), then `vol -f /session/dump.raw windows.mftscan.MFTScan -o /session/mft/ --cache-path /session/vol-cache`. target=`null` for both calls. CRITICAL: agent must NOT pass `-o /session/mft/` if the directory doesn't exist — `mkdir -p` first OR rely on the plugin's output directory create logic (varies per plugin).

### S8 — malfind injection scan

```
Scan /session/dump.raw for injected code using volatility windows.malfind. Scope to PID 1234 only (a process we suspect is compromised). JSON output.
```

**Watch:** Agent emits `vol -f /session/dump.raw -r json windows.malfind.Malfind --pid 1234`. target=`null`. Returns rows with PID, Process, Start VPN, End VPN, Tag, Protection, CommitCharge, PrivateMemory, File output, Notes, Hexdump, Disasm. Anonymous RWX regions = high-confidence shellcode injection. Pair with windows.dumpfiles.DumpFiles --pid 1234 to extract suspicious regions.

### S9 — failure: dump file not found

```
Run volatility windows.pslist against /session/nonexistent-dump.raw.
```

**Watch:** Agent emits `vol -f /session/nonexistent-dump.raw windows.pslist.PsList`. target=`null`. vol exits non-zero with stderr/stdout containing `No such file or directory` AND/OR `Could not open`. Failure classified via signal `No such file or directory` (or `Could not open`). Status: `failure_in_output`.

### S10 — failure: wrong-OS plugin against a Linux dump

```
I have a Linux memory dump at /session/linux-dump.lime but the analyst ran windows.pslist against it by mistake. Reproduce the failure and show how to fix it.
```

**Watch:** Agent emits `vol -f /session/linux-dump.lime windows.pslist.PsList`. target=`null`. vol fails with `Unsatisfied requirement` AND/OR `unable to validate plugin requirements`. Remediation: switch plugin to `linux.pslist.PsList` (matching OS namespace).

### S11 — failure: typo in plugin name

```
Run volatility's pslist plugin against /session/dump.raw — but use the vol2-style name 'pslist' (no namespace).
```

**Watch:** Agent emits `vol -f /session/dump.raw pslist`. target=`null`. vol fails with `plugin .* not found` (or argparse rejection). Remediation: use the namespaced form `windows.pslist.PsList`.

---

## 3. Target-extraction adversarial cases (≥20)

The volatility `tool.yaml` declares NO target_extraction rules. Every call
should return `target=null` because volatility has no network target — it
operates on local memory dump files only. The "operands" of a vol call are
(a) the dump file path via -f, (b) the namespaced plugin name as a
positional, (c) plugin-specific options. None are network targets.

`reject_flags`: empty (no target-list ingestion concept).

`value_flags` includes ~40 entries to ensure the DSL parses vol's argv
correctly without misinterpreting flag values as positional targets.
Values may LOOK like file paths or URLs (because they often are), but
none are network targets in the OpenSploit sense.

### Happy-path cases (every one returns target=null)

| # | Command (binary `vol` omitted) | Expected target | Notes |
|---|---|---|---|
| 1 | `-f /session/dump.raw windows.pslist.PsList` | `null` | Standard windows process list. Plugin name is the positional. |
| 2 | `-f /session/dump.raw windows.info.Info` | `null` | OS detection. |
| 3 | `-f /session/dump.raw windows.netscan.NetScan -r json` | `null` | Network connections, JSON output. |
| 4 | `-f /session/dump.raw windows.registry.hashdump.Hashdump -r json` | `null` | NTLM hash extraction. |
| 5 | `-f /session/dump.lime linux.bash.Bash` | `null` | Linux bash history. |
| 6 | `-f /session/dump.raw windows.malfind.Malfind --pid 1234 -r json` | `null` | Injection scan, scoped to PID 1234. |
| 7 | `-f /session/dump.raw windows.mftscan.MFTScan -o /session/mft/` | `null` | MFT extraction with output dir. |
| 8 | `-f /session/dump.raw windows.pstree.PsTree -r csv` | `null` | Process tree, CSV renderer. |
| 9 | `-f /session/dump.raw timeliner.Timeliner -r csv --cache-path /session/vol-cache` | `null` | Timeliner with cache. |
| 10 | `-f /session/dump.raw windows.registry.printkey.PrintKey --key 'Software\\Microsoft\\Windows\\CurrentVersion\\Run'` | `null` | Registry printkey. Backslashes in --key value MUST NOT be parsed as flags. |

### Help / introspection (target=null by definition)

| # | Command | Expected | Notes |
|---|---|---|---|
| H1 | `-h` | `target=null` | Help. |
| H2 | `--help` | `target=null` | Long form of -h. |
| H3 | `-V` | `target=null` | Version. |
| H4 | `--version` | `target=null` | Long form of -V. |
| H5 | `--info` | `target=null` | Framework info. No -f required. |
| H6 | `windows.pslist.PsList -h` | `target=null` | Plugin-specific help. |
| H7 | `frameworkinfo.FrameworkInfo` | `target=null` | Framework introspection plugin. No -f required. |
| H8 | `-f /session/dump.raw isfinfo.IsfInfo` | `target=null` | Symbol-table enumeration. |

### Adversarial — value_flag traps & "looks like a target" invariants

| # | Command | Expected | Notes |
|---|---|---|---|
| F1 | `--single-location http://10.10.10.5/dump.raw windows.pslist.PsList` | `target=null` | --single-location URL is an alternate dump SOURCE, NOT a pentest target. Even with an http:// URL containing an IP, this is fetch-input not target-of-attack. CRITICAL to NOT match. |
| F2 | `--single-location file:///mnt/dumps/192.168.1.1.raw windows.info.Info` | `target=null` | file:// URL with IP-shape filename. NOT a target. |
| F3 | `--single-location smb://server/share/dump.raw windows.info.Info` | `target=null` | SMB URL. The server hostname is a fetch source, NOT a pentest target. |
| F4 | `-f /session/10.10.10.5.dump windows.pslist.PsList` | `target=null` | Dump filename happens to match an IPv4-looking string. NOT a target. |
| F5 | `-f /session/dump.raw windows.netscan.NetScan` | `null` | Plugin name contains "netscan" but is NOT a network operation — it scans memory for network artifacts. Plugin name MUST NOT be parsed as target. |
| F6 | `-f /session/dump.raw windows.registry.printkey.PrintKey --key 'HKLM\\SYSTEM\\CurrentControlSet\\Services\\Tcpip\\Parameters\\Interfaces'` | `null` | Registry key path looks complex and contains words like "Tcpip" — NOT a target. --key is a value_flag. |
| F7 | `-f /session/dump.raw windows.filescan.FileScan --regex '\.exe$'` | `null` | Regex pattern. NOT a target. |
| F8 | `-f /session/dump.raw windows.dumpfiles.DumpFiles --virtaddr 0x7ffe0000 -o /session/extract/` | `null` | Hex offset value. NOT a target. |
| F9 | `-f /session/dump.raw -p /custom/plugins:/session/plugins windows.pslist.PsList` | `null` | Colon-separated plugin-dirs list. Looks like host:port shape — must NOT be parsed as targets. |
| F10 | `-f /session/dump.raw -s LinuxUbuntu_5_15_0-50-generic_x64 linux.pslist.PsList` | `null` | Symbol-table override. Name shape is unique; not a target. |
| F11 | `-f /session/dump.raw --cache-path /session/vol-cache windows.pslist.PsList` | `null` | Cache path. NOT a target. |
| F12 | `-f /session/dump.raw -l /session/vol.log windows.pslist.PsList` | `null` | Log path. NOT a target. |
| F13 | `-f /session/dump.raw --config /session/custom.json windows.pslist.PsList` | `null` | Config file path. NOT a target. |
| F14 | `-f /session/dump.raw windows.netstat.NetStat` | `null` | Plugin name "netstat" — NOT a target. |
| F15 | `-f /session/dump.raw windows.svcscan.SvcScan` | `null` | "svcscan" plugin name — NOT a target. |
| F16 | `-f /session/dump.raw windows.handles.Handles --pid 4 --object-type Key` | `null` | --object-type value with class name. NOT a target. |
| F17 | `-f /session/dump.raw -r json --columns 'PID,PPID,ImageFileName,CreateTime' windows.pslist.PsList` | `null` | Comma-separated column list. NOT a target list. |
| F18 | `-f /session/dump.raw windows.modules.Modules` | `null` | Plugin name only. NOT a target. |
| F19 | `-f /session/dump.raw windows.driverscan.DriverScan` | `null` | Plugin "driverscan". NOT a target. |
| F20 | `-f /session/dump.raw -vvv windows.pslist.PsList` | `null` | Verbose flag. NOT a target. |

### Multi-positional & ambiguous-positional cases

| # | Command | Expected | Notes |
|---|---|---|---|
| M1 | `-f /session/d1.raw windows.pslist.PsList && vol -f /session/d2.raw windows.pslist.PsList` | `target=null` (per call) | Shell `&&` won't run inside cli_in_container (no shell). Per-call: each parses to target=null. |
| M2 | `windows.pslist.PsList -f /session/dump.raw` | `target=null` | argparse permissive — plugin-name first, then -f. Still no target. |
| M3 | `-f /session/dump.raw windows.dumpfiles.DumpFiles --pid 1234 --virtaddr 0x10000 --dump -o /session/dumped/` | `target=null` | Many flags + plugin name. No target. |
| M4 | `-f /session/dump.raw --info` | `target=null` | --info short-circuits before plugin run. |
| M5 | (no positional, just flags) `-f /session/dump.raw -h` | `target=null` | Help with -f set but no plugin. argparse may error or print help; still target=null. |

### Stdin trap (volatility doesn't read stdin in normal flow)

| # | Command (LLM might naively try) | What happens | Correct shape |
|---|---|---|---|
| P1 | `cat /session/dump.raw \| vol windows.pslist.PsList` | cli_in_container HAS NO SHELL. The `\|` would be passed as a literal arg or rejected. vol does NOT read dumps from stdin. | Use `-f /session/dump.raw windows.pslist.PsList`. The `--single-location` URL is the only alternate input transport, and it takes a URL not stdin. |

---

## 4. Failure-signature live-verify cases (≥3)

| # | Layer | Test | failure_signature `signal` | Status |
|---|---|---|---|---|
| 1 | File / I/O | `-f /session/nonexistent-dump.raw windows.pslist.PsList` | `No such file or directory` AND/OR `Could not open` | PENDING live verify |
| 2 | Plugin-resolution | `-f /session/dump.raw pslist` (vol2-style name, no namespace) | `plugin .* not found` OR `unrecognized arguments` | PENDING live verify |
| 3 | Layer-detection | `-f /session/empty.raw windows.pslist.PsList` (touch an empty file) | `Could not determine layer` | PENDING live verify |
| 4 | Symbol-table | `-f /session/<obscure-build>.raw windows.info.Info` (a dump whose kernel build isn't in the bundled symbol pack) | `No symbols available` OR `Failed to find symbols` | PENDING live verify |
| 5 | Plugin-runtime | `-f /session/linux-dump.lime windows.pslist.PsList` (wrong OS plugin) | `Unsatisfied requirement` OR `unable to validate plugin requirements` | PENDING live verify |
| 6 | Argument | `-f /session/dump.raw windows.pslist.PsList --notaflag value` | `unrecognized arguments` OR `error: argument` | PENDING live verify |
| 7 | Required-arg | `windows.pslist.PsList` (no -f) | `the following arguments are required` | PENDING live verify |

### Layer diversity (SKILL #11) — achieved

7 distinct layers exercised: file/IO, plugin-resolution, layer-detection,
symbol-table, plugin-runtime, argparse argument, argparse required.
Resource layer (out-of-memory on huge dumps) is hard to provoke
deliberately in a small lab; defer to Wave 9 live HTB run with a real
multi-GB engagement dump.

---

## 5. Open questions

1. **target_extraction = empty list — confirmed correct?** volatility has
   no network target. The plugin's TargetValidation framework expects
   hostnames/IPs. We're declaring zero rules; the plugin extracts
   target=null and the gotcha note documents that scope-validation is
   N/A. Verify the plugin handles `target=null` gracefully (doesn't
   reject the call; doesn't try to validate "null" against the engagement
   scope). Same shape as john / hashcat — those have already been
   migrated; if they work, volatility should work. Cross-check that
   `--single-location http://...` or `smb://...` URL forms ALSO produce
   target=null (not parsed as a target via some default URL-extraction
   fallback). If the plugin currently REJECTS target=null calls or
   accidentally extracts a URL from --single-location, we need either a
   `target_optional: true` flag or an explicit reject-list entry for
   --single-location.

2. **First-run profile auto-detection cost.** vol3 builds a layer-
   detection cache on first run. On large dumps (4-16 GB) this can be
   30-120 seconds — the second clock (idle_timeout_seconds=600) is
   designed to absorb this, but we should confirm via a real large-dump
   run that vol3 emits SOMETHING to stdout/stderr during the cache build
   (heartbeat-like progress) rather than going silent. If silent, the
   wrapper's idle-timeout could mistakenly kill the run on a truly cold
   cache. Worth a `-vvv` test against a 4 GB+ dump.

3. **Output-dir mounting / pre-create semantics.** Plugins that write
   artifacts (windows.dumpfiles.DumpFiles, windows.mftscan.MFTScan with
   --dump, windows.memmap.Memmap with --dump) require `-o /session/<dir>/`
   AND the directory must EXIST. The plugin does NOT auto-create. The
   correct workflow is two run_cli calls: first `mkdir -p /session/<dir>`
   then `vol ... -o /session/<dir>/`. Should the workflow be documented
   more prominently (e.g., a dedicated gotcha about mkdir-first), or
   should we add a wrapper convention that creates the -o dir if missing?
   Current scenarios.md S7 documents the mkdir-first pattern but it's
   easy to miss.

4. **Plugin discovery cost.** `vol -h` lists 100+ plugins. We list a
   curated subset in `common_options.plugin`, but the list is not
   exhaustive — there are community plugins, and the bundled set varies
   slightly between vol3 minor versions. Should we (a) maintain a fully-
   exhaustive plugin list in tool.yaml (high maintenance), (b) just
   point the LLM at `vol -h` for discovery (current approach), or (c)
   ship a separate `plugin-list.md` reference doc? Current approach is
   (b); (c) is plausible if the LLM struggles to navigate `vol -h`
   output.

5. **Symbol-pack distribution.** Bundled symbol tables cover common
   Windows builds (NT 10.0, 6.x) and recent Linux/Mac kernels, but
   "Failed to find symbols" against unusual builds (Windows Server
   variants, custom Linux kernel builds, jailbroken iOS/Mac) is the
   single most common live-verify failure. The fix is to ship the
   community symbol pack from
   https://github.com/Abyss-W4tcher/volatility3-symbols at image build
   time — but that's ~2 GB. Trade-off: image_size_mb bloats from 214
   to ~2200, but cold-start success rate jumps. Defer to engagement-
   pattern data: how often do real HTB / engagement dumps fail symbol
   resolution against the bundled pack?

6. **`--write` flag risk surface.** Passing --write allows plugins to
   modify the dump file (typically slack-space writeback). This is
   destructive and can corrupt the dump for further analysis. Should
   --write be added to a per-tool reject-list (or wrapped with a
   permission prompt) to prevent accidental corruption? Currently
   value_flags lists --write as a boolean-shape entry but doesn't
   reject it.

7. **`yarascan` plugin gap.** windows.yarascan.YaraScan is built into
   volatility 3 but requires yara-python at runtime, which is NOT
   installed in this image. Two options: (a) add yara-python to
   requirements.txt and rebuild (image grows ~30 MB; gains in-memory
   yara scanning), (b) document the gap and route to dump-and-yara-
   externally workflow (current approach). If the LLM frequently asks
   for in-memory yarascan, swap to (a) in a follow-up wave.

---

## 6. Hand-off

- **Tool**: volatility (kind:cli)
- **Status**: tool.yaml authored end-to-end (kind:cli, binary:vol, 4h max_runtime, no target_extraction); scenarios.md written. Dockerfile reviewed — base image is `python:3.11-slim` (NOT Kali), so the python3-pip / python3-venv → python3-full swap doesn't apply (the swap is a Kali-rolling-specific fix for stale-repo regressions). Volatility 3 is installed via pip (`pip install volatility3 pycryptodome`); pycryptodome is required for the registry hashdump / lsadump plugins. mcp-server.py UNTOUCHED (auto-inherits run_cli; rollback path).
- **Image**: `ghcr.io/silicon-works/mcp-tools-volatility:latest` — needs rebuild during Wave 9 batch to pick up mcp-common 0.3.0.
- **target_extraction = empty list**: explicit design choice. volatility has no network target; the plugin should treat target=null as "no scope validation needed" for this tool. Same shape as john / hashcat. See Open Question #1.
- **Wave 7.6**: of Feature 35 / Tier A migration.
- **Live-verify pending**: paste S1-S11 against a public sample dump in /session/ for end-to-end verification. Failure signatures 1-3 (file-not-found, plugin-not-found, empty-file layer-detection) verifiable on any system; cases 4-7 require specific dump fixtures.
- **Cleanup**: no legacy `target_extraction_tests.md`, `failure_signature_tests.md`, or `__pycache__/` files were present in the volatility/ directory (verified via initial Read phase) — nothing to remove.
- **Dockerfile**: NO changes required. Base is `python:3.11-slim` (Debian-based, not Kali). Python tooling, pip install of volatility3 + pycryptodome, mcp-common copy, /session mkdir, mcp-server.py copy, CMD — all present and correct.

Authored: 2026-04-25.
