# ilspy — Tier A scenarios

Single test sheet for the `ilspy` (ILSpy CLI, binary `ilspycmd`) tool migration.

Sections:
1. Recommended sample for live verification
2. Narrative scenarios (paste into opensploit)
3. Target-extraction adversarial cases (≥20)
4. Failure-signature live-verify cases (≥3)
5. Open questions
6. Hand-off

---

## 1. Recommended sample for live verification

**N/A — ilspy has no network target.** ilspycmd operates entirely on
local .NET assemblies (.dll / .exe / .winmd / .netmodule) inside the
container; there is no remote host to scan, attack, or authenticate
against. The "target" of an ilspycmd call is a FILE PATH (e.g.,
`/session/sample.dll`) supplied as the first positional argument, plus
optional flags (`-o`, `-t`, `-r`, `--project`, `--ilcode`, `-l`,
`-genpdb`).

For LIVE VERIFICATION of the architecture path, three options:

**(a) Public sample assembly (recommended for CI / Tier A gate).**
Stage a small, known-good .NET DLL or EXE in `/session/`. Recommended
options:

- **A C# `Hello, World!`** — compile a single-file `Program.cs` with
  `dotnet build`, copy the resulting `bin/Debug/net8.0/Program.dll` to
  `/session/sample.dll`. Smallest possible reproducible fixture.
- **A bundled .NET reference assembly** — copy
  `/usr/share/dotnet/shared/Microsoft.NETCore.App/8.0.*/System.dll` (or
  similar) into `/session/`. Always present in this image (the dotnet
  SDK ships them). Useful for testing reference-resolution.
- **A standard tool DLL** — e.g., `Newtonsoft.Json.dll` from a NuGet
  cache. Common, well-documented, exercises non-trivial type / generic
  / lambda decompilation.
- **An MSSQL CLR-extracted assembly** — from an HTB box where MSSQL
  CLR is enabled and `mssql extract_assembly` has retrieved the .NET
  DLL. Real-world post-exploitation flow.

The assembly file path is what matters for the architecture test —
any parseable .NET binary exercises type enumeration, decompilation
output, reference resolution, and failure paths.

**(b) Generated assembly.** In-container build with the bundled SDK:
```
echo 'class Program { static void Main(){ System.Console.WriteLine("hi"); } }' > /tmp/p.cs
dotnet new console -o /tmp/p
dotnet build /tmp/p -c Release
cp /tmp/p/bin/Release/net8.0/p.dll /session/sample.dll
```
This is the most reproducible CI fixture if no public assembly is
bundled.

**(c) End-to-end engagement.** Any HTB box where a .NET binary surfaces
during enumeration or post-exploitation. Common workflow:

1. SQL injection → MSSQL CLR enabled
2. `mssql extract_assembly` → .NET DLL retrieved to /session/
3. `ilspycmd /session/<dll> -t Namespace.SuspectedClass`
   → recover the C# source for the class containing credentials
4. Find hardcoded password / key / connection string
5. Use the recovered creds for further lateral movement

The assembly is a STATIC FILE in /session/; ilspy's behaviour is
independent of where it came from.

Persistent test directory: standard `/session/` mount; ilspycmd reads
the assembly via the positional path and writes (when `-o` is set) to
a directory under `/session/<name>/` that MUST be pre-created by a
separate `mkdir -p` run_cli call.

---

## 2. Narrative scenarios (paste into opensploit)

### S1 — smoke test: confirm ilspycmd is functional

```
Run ilspy with --version against the container so I can confirm the dotnet tool is on PATH and the runtime starts cleanly.
```

**Watch:** Agent emits `ilspycmd --version`. target=`null` (no network target). stdout is the version string (e.g., `9.1.0`); exits 0 in <1s. If the binary isn't on PATH the run fails with `command not found` (container build issue).

### S2 — decompile entire assembly to a directory (--dump)

```
I have a .NET DLL at /session/sample.dll. Decompile the entire assembly to readable C# and write the output to /session/decompiled/. Pre-create the output dir first.
```

**Watch:** Agent emits TWO calls. First a `mkdir -p /session/decompiled` (separate run_cli, target=`null`), then `ilspycmd /session/sample.dll -o /session/decompiled --dump` (target=`null`). The second call decompiles every type in the assembly to a single concatenated `.cs` file (or many files with `--project`). EXPENSIVE on large assemblies; for focused analysis prefer S3.

### S3 — decompile a single type (-t)

```
From /session/sample.dll, decompile only the class BackupService.BackupClients. Stream to stdout — I want to read it inline.
```

**Watch:** Agent emits `ilspycmd /session/sample.dll -t BackupService.BackupClients`. target=`null`. stdout is the C# source for that single type. FAST — runs in seconds even on large assemblies. The fully qualified name is CASE-SENSITIVE; if it's spelled wrong the call fails with `Type .* not found` — agent should suggest re-running without `-t` (or with a broader filter) to enumerate types.

### S4 — decompile as a navigable project (--project)

```
Decompile /session/sample.dll into a compilable .csproj layout under /session/csproj/. One file per type, with a generated .csproj. Pre-create the output dir.
```

**Watch:** Agent emits `mkdir -p /session/csproj` first, then `ilspycmd /session/sample.dll --project -o /session/csproj/`. target=`null` for both. Output is multiple `.cs` files under `/session/csproj/` plus a `.csproj` manifest listing them. Easier to navigate than `--dump`'s single-file output; useful for IDE-loading or re-compiling a modified version.

### S5 — raw IL output (--ilcode)

```
The C# decompile of /session/obfuscated.dll looks suspicious — methods are full of goto labels and the control flow is broken. Give me the raw IL instead so I can spot what the obfuscator did.
```

**Watch:** Agent emits `ilspycmd /session/obfuscated.dll --ilcode`. target=`null`. stdout is raw IL (intermediate language) instead of C#. Useful for obfuscation analysis, reflection-emit detection, and cases where the C# decompiler can't reconstruct the original logic. Pair with `-il-sequence-points` for source-line annotations (only meaningful with `--ilcode`).

### S6 — reference resolution (-r)

```
/session/sample.dll references custom assemblies that aren't standard .NET. The resolver fails with 'Could not resolve assembly' for ClientsBackup.Common. I have the missing references in /session/refs/. Re-run with the references staged.
```

**Watch:** Agent emits `ilspycmd /session/sample.dll -r /session/refs/ -o /session/out/` (after `mkdir -p /session/out` first). target=`null` for both. The `-r` flag is REPEATABLE for multiple search paths (`-r /a/ -r /b/`). Without it the decompiler emits `Could not resolve assembly` per missing reference and may produce incomplete output.

### S7 — generate PDB alongside decompile (-genpdb)

```
Decompile /session/sample.dll AND emit a PDB symbol file alongside the source so I can do symbolic debugging on a re-compiled version. Output to /session/symbolic/.
```

**Watch:** Agent emits `mkdir -p /session/symbolic` then `ilspycmd /session/sample.dll -genpdb -o /session/symbolic/`. target=`null` for both. Output dir contains the decompiled source + `.pdb` files keyed to it. The PDB lets you set breakpoints in a re-compiled version that maps back to the decompiled lines.

### S8 — failure: file not found

```
Decompile /session/nonexistent.dll.
```

**Watch:** Agent emits `ilspycmd /session/nonexistent.dll`. target=`null`. ilspycmd exits non-zero with stderr/stdout containing `Could not find file` or `not found`. Failure classified via signal `Could not find file` (or `not found`). Status: `failure_in_output`.

### S9 — failure: not a valid PE file

```
I copied a JPEG to /session/notreal.dll by mistake. Try decompiling it.
```

**Watch:** Agent emits `ilspycmd /session/notreal.dll`. target=`null`. ilspycmd exits non-zero with stderr/stdout containing `not a valid PE file` or `BadImageFormatException`. Remediation: confirm the file type with `file <path>`. For Java use jadx; for native binaries use objdump/strings/radare2 via exploit-runner.

### S10 — failure: type not found

```
Decompile only the class MyApp.NonExistentClass from /session/sample.dll.
```

**Watch:** Agent emits `ilspycmd /session/sample.dll -t MyApp.NonExistentClass`. target=`null`. Exit non-zero with stderr/stdout containing `Type .* not found`. Remediation: re-run without `-t` (or with `--dump`) to enumerate types, then retry with the correct fully qualified name.

### S11 — failure: missing positional

```
Run ilspycmd without an assembly path.
```

**Watch:** Agent emits `ilspycmd` (no args). target=`null`. Argparse fails with `Required argument` or prints help and exits non-zero. Remediation: supply the assembly path positional (`ilspycmd /session/<path>`).

---

## 3. Target-extraction adversarial cases (≥20)

The ilspy `tool.yaml` declares NO target_extraction rules. Every call
should return `target=null` because ilspycmd has no network target —
it operates on local .NET assemblies only. The "operands" of an
ilspycmd call are (a) the assembly file path positional, (b) optional
`-o` output dir, (c) optional `-t` type-name filter, (d) optional
`-r` reference path, (e) optional `-l` language selector, (f) project
/ IL / PDB / dump booleans. None are network targets.

`reject_flags`: empty (no target-list ingestion concept).

`value_flags` includes ~25 entries to ensure the DSL parses ilspycmd's
argv correctly without misinterpreting flag values as positional
targets. Values may LOOK like file paths or type names (because they
often are), but none are network targets in the OpenSploit sense.

### Happy-path cases (every one returns target=null)

| # | Command (binary `ilspycmd` omitted) | Expected target | Notes |
|---|---|---|---|
| 1 | `/session/sample.dll` | `null` | Bare positional — default decompile to stdout. |
| 2 | `/session/sample.dll -o /session/out/ --dump` | `null` | Dump entire assembly to dir. |
| 3 | `/session/sample.dll -t BackupService.BackupClients` | `null` | Single-type decompile. Type name is a value of -t, NOT a target. |
| 4 | `/session/sample.dll --project -o /session/csproj/` | `null` | Project format with output dir. |
| 5 | `/session/sample.dll --ilcode` | `null` | Raw IL output. |
| 6 | `/session/sample.dll -r /session/refs/ -o /session/out/` | `null` | Reference path + output. |
| 7 | `/session/sample.dll -genpdb -o /session/symbolic/` | `null` | PDB generation. |
| 8 | `/session/sample.dll -l csharp -o /session/out/ --project` | `null` | Explicit language + project. |
| 9 | `/session/sample.dll -il -il-sequence-points` | `null` | IL with sequence points. |
| 10 | `/session/sample.dll --no-symbols -o /session/out/ --dump` | `null` | Suppress debug symbols. |

### Help / introspection (target=null by definition)

| # | Command | Expected | Notes |
|---|---|---|---|
| H1 | `-h` | `target=null` | Help. |
| H2 | `--help` | `target=null` | Long form of -h. |
| H3 | `-V` | `target=null` | Version. |
| H4 | `--version` | `target=null` | Long form of -V. |

### Adversarial — value_flag traps & "looks like a target" invariants

| # | Command | Expected | Notes |
|---|---|---|---|
| F1 | `/session/10.10.10.5.dll` | `target=null` | Filename happens to match an IPv4-looking string. NOT a target. |
| F2 | `/session/sample.dll -t Microsoft.Win32.Registry` | `target=null` | Type name contains "Win32" / "Registry" / dotted-namespace shape — looks complex; NOT a target. -t is a value_flag. |
| F3 | `/session/sample.dll -o /session/decompiled-192.168.1.1/ --dump` | `target=null` | Output dir name contains an IP-shaped string. NOT a target. -o is a value_flag. |
| F4 | `/session/sample.dll -r /session/refs/192.168.1.1/ -o /session/out/` | `target=null` | Reference path contains IP-shaped subdir. NOT a target. -r is a value_flag. |
| F5 | `/session/sample.dll -t System.Net.Sockets.TcpClient` | `target=null` | Type name is a network class — but it's a TYPE NAME, not a target. -t is a value_flag. |
| F6 | `/session/sample.dll -l csharp-2010` | `target=null` | Language value contains a year-like string. NOT a target. -l is a value_flag. |
| F7 | `/session/MSSQL-CLR-from-10.0.0.5.dll --dump -o /session/out/` | `target=null` | Filename embeds the source IP from extraction context. NOT a target. |
| F8 | `/session/sample.dll -r /session/refs1/ -r /session/refs2/ -r /session/refs3/` | `target=null` | -r is REPEATABLE; multiple value-flag instances. None are targets. |
| F9 | `/session/sample.dll -t MyApp.Auth.LoginService.Authenticate` | `target=null` | Method-like dotted name (deep namespace). NOT a target. |
| F10 | `/session/sample.dll -o /session/output_for_192.168.0.0_24/ --project` | `target=null` | Output dir embeds CIDR-looking string. NOT a target. |
| F11 | `/session/sample.dll --ilcode -il-sequence-points` | `target=null` | Multiple boolean flags — none take values. NOT a target. |
| F12 | `--help` | `target=null` | Help, no positional. |
| F13 | `/session/sample.dll -l il -o /session/raw_il/` | `target=null` | Language=il (alternate IL request) + output dir. |
| F14 | `/session/sample.dll --outputdir /session/long-form-out/ --dump` | `target=null` | Long-form -o flag (--outputdir). |
| F15 | `/session/sample.dll --type BackupService.Backup --project -o /session/proj/` | `target=null` | Long-form -t (--type) combined with --project. |
| F16 | `/session/sample.dll --referencepath /session/refs/ -o /session/out/` | `target=null` | Long-form -r (--referencepath). |
| F17 | `/session/sample.dll --language csharp-2010 -o /session/legacy/ --dump` | `target=null` | Long-form -l (--language) with legacy dialect. |
| F18 | `/session/sample.dll --lzma --project -o /session/out/` | `target=null` | --lzma compresses output. NOT a target. |
| F19 | `/session/sample.dll -t SomeClass` | `target=null` | Bare unqualified type name (will fail at runtime as not-fully-qualified, but parser still extracts target=null). |
| F20 | `/session/sample.dll -t global::System.Console` | `target=null` | Type name with global:: prefix. NOT a target. |

### Multi-positional & ambiguous-positional cases

| # | Command | Expected | Notes |
|---|---|---|---|
| M1 | `/session/d1.dll -o /session/out1/ --dump && ilspycmd /session/d2.dll -o /session/out2/ --dump` | `target=null` (per call) | Shell `&&` won't run inside cli_in_container (no shell). Per-call: each parses to target=null. |
| M2 | `-o /session/out/ /session/sample.dll --dump` | `target=null` | argparse permissive — flag-first, then positional. Still no target. |
| M3 | `/session/sample.dll -t MyApp.Auth.LoginService --project -o /session/auth/` | `target=null` | Many flags + positional. No target. |
| M4 | `--version` | `target=null` | --version short-circuits before any decompile. |
| M5 | (no args, just `ilspycmd`) | `target=null` | Argparse error / help; still target=null. |

### Stdin trap (ilspycmd doesn't read stdin in normal flow)

| # | Command (LLM might naively try) | What happens | Correct shape |
|---|---|---|---|
| P1 | `cat /session/sample.dll \| ilspycmd` | cli_in_container HAS NO SHELL. The `\|` would be passed as a literal arg or rejected. ilspycmd does NOT read assemblies from stdin. | Use `ilspycmd /session/sample.dll`. The positional path is the only input transport. |

---

## 4. Failure-signature live-verify cases (≥3)

| # | Layer | Test | failure_signature `signal` | Status |
|---|---|---|---|---|
| 1 | File / I/O | `/session/nonexistent.dll` | `Could not find file` AND/OR `not found` | PENDING live verify |
| 2 | PE / format | `/session/notreal.dll` (a JPEG renamed to .dll) | `not a valid PE file` OR `BadImageFormatException` | PENDING live verify |
| 3 | Reference-resolution | `/session/sample.dll` (assembly that depends on a missing custom DLL, with no `-r` passed) | `Could not resolve assembly` | PENDING live verify |
| 4 | Type-resolution | `/session/sample.dll -t MyApp.NonExistentClass` | `Type .* not found` OR `No such type` | PENDING live verify |
| 5 | Argparse / argument | `/session/sample.dll --notaflag value` | `Unrecognized command or argument` | PENDING live verify |
| 6 | Argparse / required | `ilspycmd` (no positional) | `Required argument` (or help printed with non-zero exit) | PENDING live verify |
| 7 | Output / I/O | `/session/sample.dll -o /session/missing-dir/ --dump` (no mkdir first) | `directory does not exist` OR `Cannot create file` | PENDING live verify |

### Layer diversity (SKILL #11) — achieved

7 distinct layers exercised: file/IO, PE format, reference-resolution,
type-resolution, argparse argument, argparse required, output I/O.
Resource layer (out-of-memory on huge assemblies) is hard to provoke
deliberately in a small lab; defer to Wave 9 live HTB run with a real
multi-MB engagement assembly (e.g., a full .NET application bundle).

---

## 5. Open questions

1. **target_extraction = empty list — confirmed correct?** ilspy has
   no network target. The plugin's TargetValidation framework expects
   hostnames/IPs. We're declaring zero rules; the plugin extracts
   target=null and the gotcha note documents that scope-validation is
   N/A. Verify the plugin handles `target=null` gracefully (doesn't
   reject the call; doesn't try to validate "null" against the
   engagement scope). Same shape as volatility / john / hashcat —
   those have already been migrated; if they work, ilspy should work.
   Cross-check that filename-as-IP cases (F1, F4, F7, F10) do NOT
   accidentally extract via some default URL/IP-extraction fallback.

2. **.NET runtime version assumptions.** This image bundles
   `mcr.microsoft.com/dotnet/sdk:8.0` → ilspycmd runs on .NET 8. The
   bundled reference assemblies are .NET 8 and earlier (the SDK ships
   reference packs for older targets). Decompiling assemblies built
   for newer .NET (e.g., .NET 9 / 10 future) MAY succeed (the
   decompiler is largely format-version-agnostic) but reference
   resolution against newer BCL types will fail. Document the
   .NET-version trade-off when ilspy ships in containers built against
   newer SDKs.

3. **Reference-path conventions for HTB engagements.** When extracting
   a CLR assembly from MSSQL, the assembly's references typically
   include both standard BCL DLLs (resolved automatically) AND custom
   in-house DLLs that aren't on the box. Should we (a) document a
   convention that the agent always extracts ALL referenced
   assemblies before decompiling (via mssql extract_assembly), (b)
   ship a fallback heuristic that scans /session/ for any .dll and
   passes them all via `-r` automatically, or (c) accept that
   incomplete decompilation with `Could not resolve assembly` warnings
   is the norm and just decompile what we can? Current approach is
   (c); (a) would yield cleaner output but adds engagement workflow
   steps.

4. **Output-dir mounting / pre-create semantics.** Modes that write
   artifacts (`--dump`, `--project`, `-genpdb`) require `-o /session/<dir>/`
   AND the directory must EXIST. The tool does NOT auto-create. The
   correct workflow is two run_cli calls: first `mkdir -p /session/<dir>`
   then `ilspycmd ... -o /session/<dir>/`. Should the workflow be
   documented more prominently (a dedicated gotcha exists, but it's
   easy to miss), or should we add a wrapper convention that creates
   the -o dir if missing? Current scenarios.md S2/S4/S6/S7 all
   document mkdir-first.

5. **Obfuscated assembly handling.** Many real-world .NET binaries
   are obfuscated (string encryption, control-flow flattening,
   identifier renaming). ilspycmd's C# pass produces syntactically
   valid but semantically broken output on heavy obfuscation —
   methods full of `goto`, mangled names like `\u200B`, dead-code
   junk. Should we (a) document a "fall back to --ilcode" workflow
   in gotchas, (b) ship a separate de-obfuscation tool (de4dot is
   the standard), or (c) leave it to the LLM to recognize the
   pattern? Current gotcha mentions (a); (b) is the right answer
   for serious obfuscation but adds a tool. Defer to engagement-
   pattern data: how often do we see heavily obfuscated assemblies
   in HTB / real engagements?

6. **`--dump` runtime on framework DLLs.** Decompiling a full .NET
   framework DLL (e.g., `mscorlib.dll`, `System.dll` ~5-10 MB with
   thousands of types) with `--dump` can take many minutes and
   produce hundreds of MB of C# source. The 1h max_runtime should
   handle the worst case, but the wrapper's idle-timeout (10 min)
   could mistakenly kill a slow-but-progressing run if ilspycmd
   stays silent. Worth a `-vvv`-equivalent test (ilspycmd doesn't
   have a verbose flag, but check if it emits progress on stderr
   during long runs). If silent, add a documentation note: prefer
   `-t <type>` over `--dump` for framework DLLs.

7. **Resource extraction gap.** RESOLVED in audit (2026-04-25). The
   previous mcp-server.py exposed a `list_resources` method that
   grep'd `--ilcode` output for `.mresource` declarations to
   enumerate embedded resources. tool.yaml now documents the
   two-step recipe in `gotchas` AND `usage_patterns` ("Enumerate
   embedded resources (--ilcode + grep recipe)"). Agent assembles:
   (a) `ilspycmd /session/sample.dll --ilcode`, then (b) grep for
   `.mresource` lines using regex
   `\.mresource\s+(?:public|private)?\s*'?([^']+)'?`.

8. **Type enumeration via `-l <kinds>` (parity with legacy
   `list_types`).** RESOLVED in audit (2026-04-25). The legacy
   mcp-server.py exposed `list_types` which invoked
   `ilspycmd -l <kinds> <path>` where `<kinds>` is a single
   concatenated string (`cisde` = class+interface+struct+delegate+enum,
   no commas). This usage of `-l` is OVERLOADED with the language
   selector role (`-l csharp` / `-l il`) and was not previously
   documented. tool.yaml now describes the type-enumeration overload
   in `gotchas` AND adds a dedicated usage_pattern. Agents should
   use `ilspycmd <path> -l cisde` to discover available type names
   before issuing a `-t` decompile, especially after a
   `Type .* not found` error.

9. **`-l` overload disambiguation hazard.** The fact that `-l`
   accepts both LANGUAGE values (`csharp`, `il`, `csharp-2010`) AND
   ENTITY-KIND strings (`c`, `i`, `s`, `d`, `e`, `cisde`) is a
   subtle parser ambiguity in ilspycmd. There is no way an agent
   could discover this without reading mcp-server.py or running
   experiments — the `--help` output describes only the language
   role. value_flags lists `-l` once; both meanings are covered.
   Long-term: consider whether the LLM might confuse the two and
   pass an invalid combo (e.g., `-l csharp-il`). Defer until
   engagement-data shows a real misfire.

---

## 6. Hand-off

- **Tool**: ilspy (kind:cli)
- **Status**: tool.yaml authored end-to-end (kind:cli, binary:ilspycmd, 1h max_runtime, no target_extraction); scenarios.md written. Dockerfile reviewed — base image is `mcr.microsoft.com/dotnet/sdk:8.0` (Microsoft .NET SDK Debian-based; NOT Kali), so the python3-pip / python3-venv → python3-full swap doesn't apply (the swap is a Kali-rolling-specific fix for stale-repo regressions). ilspycmd is installed via `dotnet tool install -g ilspycmd` and added to PATH via `/root/.dotnet/tools`. Python tooling (python3 + venv) is layered on top to host mcp-common + mcp-server.py. mcp-server.py UNTOUCHED (auto-inherits run_cli; rollback path).
- **Image**: `ghcr.io/silicon-works/mcp-tools-ilspy:latest` — needs rebuild during Wave 9 batch to pick up mcp-common 0.3.0.
- **target_extraction = empty list**: explicit design choice. ilspy has no network target; the plugin should treat target=null as "no scope validation needed" for this tool. Same shape as volatility / john / hashcat. See Open Question #1.
- **Wave 7.10**: of Feature 35 / Tier A migration.
- **Live-verify pending**: paste S1-S11 against a sample assembly in /session/ for end-to-end verification. Failure signatures 1-2 (file-not-found, bad-PE) verifiable on any system with a small fixture; cases 3-7 require specific assembly fixtures.
- **Cleanup**: no legacy `target_extraction_tests.md`, `failure_signature_tests.md`, or `__pycache__/` files were present in the ilspy/ directory (verified via initial Read phase — directory contains only Dockerfile, mcp-server.py, requirements.txt, tool.yaml) — nothing to remove.
- **Dockerfile**: NO changes required. Base is `mcr.microsoft.com/dotnet/sdk:8.0` (Debian-based, not Kali). dotnet-tool install of ilspycmd, python3 + venv layered for mcp-common, /app workdir, mcp-server.py copy, CMD — all present and correct. The `python3-pip` / `python3-venv` packages remain (this is a Microsoft Debian image, not Kali; the package-rename fix doesn't apply).

Authored: 2026-04-25.
