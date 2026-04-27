# ike-scan — Tier A scenarios

Single test sheet for the `ike-scan` tool migration (kind:cli, multi-binary
— ike-scan 1.9 + psk-crack 1.9).

Sections:
1. Recommended HTB box / lab for live verification
2. Narrative scenarios (paste into opensploit)
3. Target-extraction adversarial cases (≥20)
4. Failure-signature live-verify cases (≥3)
5. Open questions
6. Hand-off

---

## 1. Recommended HTB box / lab

IKE/IPsec is **rare in HTB's lab rotation** — UDP/500 is almost never
exposed on standard HTB boxes. The few candidates:

**Primary: Conceal (10.10.10.116)** — Windows box where IPsec is part of
the intended path. UDP/500 is filtered externally but enumerable after
SNMP recovers an IPsec policy hint. Useful for the Aggressive-Mode group
name brute path. Retired box; image readily spawnable on HTB premium.

**Alternate: Reel (10.10.10.77)** — Windows AD box; not strictly an IKE
target but the engagement narrative hints at VPN connectivity for
internal pivoting. NOT a direct ike-scan target.

**Lab availability is the bottleneck for this tool.** HTB's design
intentionally avoids IPsec (nat-t / firewall complications), so most
ike-scan validation needs a **self-hosted lab**:

**Standalone fallback (no HTB)**: spin up `strongswan/strongswan` or
`solita/strongswan` Docker container with Aggressive Mode enabled and a
known-weak PSK ("test123"). Configuration:

```
config setup
  charondebug="all"
conn aggressive
  authby=psk
  aggressive=yes
  ike=3des-sha1-modp1024
  esp=3des-sha1
  left=%defaultroute
  leftid=@server
  right=%any
  rightid=@client
  auto=add
```

Walks return one Aggressive-Mode handshake per call. The PSK is set in
`/etc/ipsec.secrets` as `: PSK "test123"`. Used for repeatable CI-style
verification.

**Cisco IOSv lab (most realistic)**: GNS3 / EVE-NG with a Cisco IOSv
router configured for `crypto isakmp policy` + Aggressive Mode + a
shared key. Most realistic backoff-fingerprint test bed because the
backoff curve matches a real Cisco device. Requires Cisco IOSv image
(licensed).

Note: ike-scan UDP filtering is RAMPANT — `nmap -sU --top-ports 200`
against random Internet hosts almost never returns IKE hits because
firewalls reflexively drop UDP/500 from external. Document the box's
IPsec exposure in the engagement report; never assume IKE is reachable
just because port 500 was scanned.

---

## 2. Narrative scenarios (paste into opensploit)

### S1 — basic IKE Main-Mode probe (lowest-noise first contact)

```
Engagement target: 10.10.10.20 (lab strongSwan, authorized).
Use the ike-scan tool to send a basic IKE Main-Mode probe to the target
on the default UDP port 500. Use multi-line output (-M) for parseable
results. Save the output to /session/lab-ike-main.txt. Report: whether
the responder is alive, the SA= line (transform accepted), and any
Vendor-ID payload.
```

**Watch:** Agent picks the `ike-scan` binary. Argv shape: `ike-scan -M
10.10.10.20`. First call ~3-5 s (container spawn + MCP handshake).
Note: target is the LAST positional, the SOLE positional. The DSL
extracts target=`10.10.10.20`.

### S2 — Aggressive-Mode PSK extraction (the hash-capture move)

```
Engagement target: 10.10.10.20 (lab strongSwan with Aggressive Mode
enabled, authorized).
Use ike-scan to test Aggressive Mode with the group name "test", saving
the captured PSK hash to /session/lab-ike-hash.txt. Use multi-line
output. Confirm the file is non-empty after the call.
```

**Watch:** Argv: `ike-scan -M -A -d test -P /session/lab-ike-hash.txt
10.10.10.20`. CRITICAL: target is LAST positional, `-P
/session/lab-ike-hash.txt` is a flag value (NOT a target), `-d test`
is also a flag value (NOT a target). DSL extracts target=`10.10.10.20`.

### S3 — backoff-pattern vendor fingerprint (slow but precise)

```
Engagement target: 10.10.10.20 (lab strongSwan, authorized).
Use ike-scan with --showbackoff to fingerprint the responder vendor via
backoff timing patterns. Use multi-line output. Budget ~120 seconds.
Save to /session/lab-backoff.txt. Report the implementation guess at
the bottom of the output.
```

**Watch:** Argv: `ike-scan -M --showbackoff 10.10.10.20`. The
`--showbackoff` flag is in value_flags (accepts optional seconds value)
but here used as a boolean — the DSL must accept either form. Output
contains a backoff table and a final `Implementation guess: <vendor>`
line.

### S4 — custom transform spec (when default 8 transforms don't elicit response)

```
Engagement target: 10.10.10.20 (lab strongSwan, authorized).
Use ike-scan to test the host with the explicit transform set
3DES/SHA1/PSK/MODP1024 (numeric: 5,2,1,2). Use multi-line output and
save to /session/lab-trans.txt. Report whether the transform was
accepted.
```

**Watch:** Argv: `ike-scan -M --trans=5,2,1,2 10.10.10.20`. The
`--trans=5,2,1,2` value contains commas and looks numeric — it's
captured by `--trans=` long-form syntax (so the value is one argv
token). DSL doesn't confuse `5,2,1,2` with a target despite the
numeric appearance.

### S5 — NAT-T probe on UDP/4500

```
Engagement target: 10.10.10.20 (lab strongSwan with NAT-T, authorized).
Use ike-scan to probe UDP/4500 (NAT-T port) instead of the default 500.
Use multi-line output. Save to /session/lab-natt.txt. Report whether
the host responds on 4500.
```

**Watch:** Argv: `ike-scan -M -p 4500 10.10.10.20`. The `-p 4500` flag
overrides the default 500. DSL captures `-p` as a value_flag (consumes
4500), then target=`10.10.10.20`.

### S6 — IKEv2 probe (modern protocol)

```
Engagement target: 10.10.10.20 (lab strongSwan with IKEv2, authorized).
Use ike-scan with the IKEv2 flag (-2) to probe the responder. Use
multi-line output. Save to /session/lab-ikev2.txt. Report whether
IKEv2 is accepted and any version info.
```

**Watch:** Argv: `ike-scan -2 -M 10.10.10.20`. The `-2` is a boolean
flag (no value); DSL doesn't accidentally capture `10.10.10.20` as a
value to `-2`. Many IKEv1 flags don't apply to IKEv2 — agent should
not combine `-A` with `-2`.

### S7 — DNS failure classification

```
Engagement target: nonexistent-ipsec.invalid.localdomain (deliberately
invalid, verifying error classification).
Use ike-scan with -M -r 1 -t 250 (fail fast) on this hostname. Report
what failure mode you classify this as.
```

**Watch:** stderr / stdout contains `Could not resolve` or
`getaddrinfo` or `Name or service not known`. failure_signature
matches.

### S8 — wrong port / no IKE responder

```
Engagement target: 10.10.10.20 (lab Apache web server on 80, NOT IKE,
authorized).
Use ike-scan with -M -r 1 -t 250 on this host. The host has no IKE
responder. Report the failure mode.
```

**Watch:** Output contains `0 returned handshake` (no IKE response).
The agent correctly classifies this as "host alive but not IKE OR
filtered". Distinguishing requires nmap UDP scan first.

### S9 — psk-crack against captured hash with rockyou

```
Engagement context: PSK hash captured in S2 at
/session/lab-ike-hash.txt. The lab PSK is "test123" (deliberately
weak).
Use the ike-scan tool with the psk-crack binary, dictionary attack
against the rockyou wordlist
(/usr/share/wordlists/rockyou.txt). Save output to
/session/lab-crack.txt. Report whether the password was found.
```

**Watch:** Argv: `psk-crack -d /usr/share/wordlists/rockyou.txt
/session/lab-ike-hash.txt`. CRITICAL: psk-crack is OFFLINE — no
network target. The "target" for scope validation purposes is the
hashfile path (LAST positional). cli_in_container forwards `psk-crack`
as the binary. Output contains `Key found "test123"` on success.

### S10 — psk-crack with custom wordlist

```
Engagement context: PSK hash at /session/lab-ike-hash.txt. Engagement
suggests PSK candidates: "vpn-prod-2024", "lab123", "ipsec-test".
Use the `write` tool to create /session/candidates.txt with these
three lines. Then use psk-crack via the ike-scan tool with `-d
/session/candidates.txt` to crack the hash. Report which candidate
matched (if any).
```

**Watch:** Argv: `psk-crack -d /session/candidates.txt
/session/lab-ike-hash.txt`. Two positional-shaped arguments — the FIRST
is consumed by `-d` (flag value), the SECOND (last) is the hashfile.
DSL extracts the LAST positional as the target.

---

## 3. Target-extraction adversarial cases (≥20)

The ike-scan `tool.yaml` declares two extraction rules:

1. `last_non_flag_positional` — target is the LAST non-flag positional
2. `positional_match` — strip optional `:port` suffix, handle bracketed v6

**Critical invariant:** the convention here is **last positional**
(not first as for snmp/nmap), because ike-scan's command form is
"flags first, host(s) last": `ike-scan -M -A -d test -P
/session/file.txt 10.10.10.5`. With a flag value like `-P
/session/file.txt`, the file path is consumed by `-P` and is NOT a
positional. Same for `-d <id>` (Aggressive-Mode group name) and `-n
<id>` (initiator ID).

| # | Command (binary as shown) | Expected target | Notes |
|---|---|---|---|
| 1 | `ike-scan -M 10.10.10.5` | `10.10.10.5` | Bog-standard probe; sole positional |
| 2 | `ike-scan -M router.target.local` | `router.target.local` | FQDN target; sole positional |
| 3 | `ike-scan -M 10.10.10.5:1500` | `10.10.10.5` | host:port shorthand — strip the :port. NB: ike-scan natively uses `-p` for port; this case is for safety |
| 4 | `ike-scan -M -A -d test -P /session/hash.txt 10.10.10.5` | `10.10.10.5` | Aggressive Mode with -P flag value — file path NOT a target |
| 5 | `ike-scan -M -A -d test 10.10.10.5` | `10.10.10.5` | Aggressive Mode without -P; -d value is group ID |
| 6 | `ike-scan -M --trans=5,2,1,2 10.10.10.5` | `10.10.10.5` | Custom transform; --trans= long-form has the value attached |
| 7 | `ike-scan -M --showbackoff 10.10.10.5` | `10.10.10.5` | Backoff fingerprint (boolean form) |
| 8 | `ike-scan -M --showbackoff=60 10.10.10.5` | `10.10.10.5` | Backoff fingerprint with optional seconds value (long-form attached) |
| 9 | `ike-scan -M -p 4500 10.10.10.5` | `10.10.10.5` | NAT-T port 4500 — `-p` is value_flag, target stays last |
| 10 | `ike-scan -2 -M 10.10.10.5` | `10.10.10.5` | IKEv2 (`-2` boolean) |
| 11 | `ike-scan -M -A -d test -n initiator-fqdn -P /session/hash.txt 10.10.10.5` | `10.10.10.5` | Both -d and -n value flags consumed before positional |
| 12 | `ike-scan -M --vendor=4048b7d56ebce88525e7de7f00d6c2d3 10.10.10.5` | `10.10.10.5` | Custom Vendor-ID hex; --vendor= consumes hex value |
| 13 | `ike-scan -M 10.10.10.5 10.10.10.6 10.10.10.7` | `10.10.10.7` | **Multi-host probe** — DSL takes LAST positional as scope target. allow_multi_target=true |
| 14 | `ike-scan -M --id=test --pskcrack=/session/hash.txt 10.10.10.5` | `10.10.10.5` | Long-form --id= and --pskcrack= attached; target last |
| 15 | `ike-scan -M -r 1 -t 250 10.10.10.5` | `10.10.10.5` | Tight-budget timing flags before target |
| 16 | `ike-scan -M -v -v 10.10.10.5` | `10.10.10.5` | Repeated -v boolean flags (verbose); doesn't consume positionals |
| 17 | `ike-scan -M --id-type=2 -A -d test 10.10.10.5` | `10.10.10.5` | --id-type= long-form attached value |
| 18 | `ike-scan -M [2001:db8::1]:500 1.3.6.1.2.1.1` | `[2001:db8::1]` (or `2001:db8::1`) — see Open Questions | IPv6 bracketed; trailing token here is intentional adversarial — see edge case below |
| 19 | `ike-scan -M TARGET.LOCAL` | `TARGET.LOCAL` | Uppercase host preserved |
| 20 | `ike-scan -M --bandwidth 10000 10.10.10.5` | `10.10.10.5` | --bandwidth value flag (legacy) |
| 21 | `ike-scan -M --lifetime 28800 10.10.10.5` | `10.10.10.5` | SA lifetime value flag |
| 22 | `ike-scan -M -A -d 10.10.10.99 10.10.10.5` | `10.10.10.5` | -d value LOOKS like an IP (group name happens to be IP-shaped) — value_flag traps; target stays last |
| 23 | `ike-scan -M -A -d test -P /session/10.10.10.99.hash 10.10.10.5` | `10.10.10.5` | -P value contains an IP-shaped filename — value_flag traps |
| 24 | `psk-crack -d /usr/share/wordlists/rockyou.txt /session/hash.txt` | `/session/hash.txt` | psk-crack: hashfile is LAST positional (offline tool — "target" is local file) |
| 25 | `psk-crack -B 0123456789 -l 8 /session/hash.txt` | `/session/hash.txt` | psk-crack brute mode; -B/-l value flags before hashfile |
| 26 | `psk-crack /session/hash.txt` | `/session/hash.txt` | psk-crack with no flags; hashfile sole positional |
| 27 | `psk-crack -d /session/words.txt /session/hash.txt` | `/session/hash.txt` | psk-crack with custom wordlist; hashfile last |
| 28 | `ike-scan -M -A --id=cisco-vpn-group -P /session/hash.txt --trans=5,2,1,2 -p 500 10.10.10.5` | `10.10.10.5` | Many flags, target last — stress test |

### Adversarial / failure cases (DSL must reject or fall back)

| # | Command | Expected behaviour | Notes |
|---|---|---|---|
| F1 | `ike-scan -V` | target=null → tool.execute.before allows (no target → no validation) | ike-scan version flag |
| F2 | `ike-scan --version` | target=null | Same as F1, long form |
| F3 | `ike-scan -h` | target=null → no validation | Help banner |
| F4 | `ike-scan --help` | target=null | Help, long form |
| F5 | `psk-crack -h` | target=null | psk-crack help |
| F6 | `psk-crack --help` | target=null | psk-crack help, long form |
| F7 | `ike-scan -M --inputfile /session/hosts.txt` | reject — `--inputfile` is in reject_flags | Multi-host file ingestion blocked at plugin layer |
| F8 | `ike-scan -M -f /session/hosts.txt` | reject — `-f` (short form) is also in reject_flags | Same as F7 (some builds accept -f as input file alias) |
| F9 | `ike-scan -M` (no host) | target=null → ike-scan fails naturally with `No targets to process` usage error | Missing required positional → ike-scan exits nonzero |
| F10 | `ike-scan -M -P` (missing -P value, then no host) | target=null → ike-scan fails with usage error (`-P requires a value`) | Argv parse error at the binary |
| F11 | `ike-scan -M -A -d 10.10.10.99 10.10.10.5` | target=`10.10.10.5`, NOT `10.10.10.99`. **Critical security invariant**: target is the LAST POSITIONAL host, NEVER a flag-value group ID even if it's IP-shaped. | -d value LOOKS like an IP (group name is IP-shaped) — but value_flags traps it; last positional wins. |
| F12 | `ike-scan -M -A -d test -P 10.10.10.99 10.10.10.5` | target=`10.10.10.5`, NOT `10.10.10.99`. -P value (PSK hash file path) is consumed even when IP-shaped. | -P value is FILE PATH that happens to look like an IP. value_flag traps. |
| F13 | `ike-scan -M --inputfile=/session/hosts.txt 10.10.10.5` | reject — long-form `--inputfile=…` also matches reject_flags | reject_flags must match long-form attached-value syntax too |
| F14 | `ike-scan -M --trans=5,2,1,2,EVIL 10.10.10.5` | target=`10.10.10.5`. Malformed trans value is binary's problem; DSL still extracts. | --trans= long-form value isn't validated by DSL; ike-scan emits `Bad value` at runtime |
| F15 | `psk-crack -d /session/words.txt` (no hashfile) | target=null → psk-crack fails with usage error | Missing required hashfile positional |
| F16 | `psk-crack -d /etc/passwd /session/hash.txt` | target=`/session/hash.txt`. -d value consumed; last positional is hashfile. | Even if -d points to an unusual file, DSL extracts the LAST positional |

---

## 4. Failure-signature live-verify cases (≥3)

Run each via opensploit (paste the prompt) and verify the result hits
the `failure_signatures` entry in `tool.yaml`. Each test produces an
exit code, a stderr/stdout message, and a `signal` substring the
tool.yaml MUST contain.

| # | Test | Command (post-binary) | Expected exit | Expected stderr/stdout substring | failure_signature `signal` field | Status |
|---|---|---|---|---|---|---|
| 1 | DNS resolution failure | `ike-scan -M -r 1 -t 250 nonexistent.invalid.localdomain` | nonzero | `Could not resolve` / `getaddrinfo` / `Name or service not known` | `Could not resolve` AND `getaddrinfo` AND `Name or service not known` | NEEDS LIVE VERIFY |
| 2 | UDP no-response (filtered or non-IKE host) | `ike-scan -M -r 1 -t 250 10.10.10.5` (host alive but not IKE) | 0 | `0 returned handshake` | `0 returned handshake` | NEEDS LIVE VERIFY |
| 3 | NO-PROPOSAL-CHOSEN (responder rejects all default transforms) | `ike-scan -M --trans=99,99,99,99 10.10.10.5` | 0 | `0 returned notify` or `NO-PROPOSAL-CHOSEN` | `NO-PROPOSAL-CHOSEN` AND `0 returned notify` | NEEDS LIVE VERIFY |
| 4 | INVALID-EXCHANGE (Main Mode rejected) | `ike-scan -M 10.10.10.5` (against Aggressive-only host) | 0 | `INVALID-EXCHANGE` | `INVALID-EXCHANGE` | NEEDS LIVE VERIFY |
| 5 | Operation not permitted (raw socket without privilege) | `ike-scan -M --sport=500 10.10.10.5` (in non-privileged container) | nonzero | `Operation not permitted` / `Could not bind` | `Operation not permitted` AND `Could not bind to source port` | NEEDS LIVE VERIFY |
| 6 | Invalid argument | `ike-scan --not-a-real-flag 10.10.10.5` | nonzero | `unknown option` / `Invalid` | `unknown option` AND `Invalid` | NEEDS LIVE VERIFY |
| 7 | Bad transform value | `ike-scan -M --trans=NOTVALID 10.10.10.5` | nonzero | `Bad value` / `Invalid` | `Bad value` AND `Invalid` | NEEDS LIVE VERIFY |
| 8 | psk-crack hash file not found | `psk-crack -d /usr/share/wordlists/rockyou.txt /session/nonexistent.hash` | nonzero | `Cannot open` | `Cannot open` | NEEDS LIVE VERIFY |
| 9 | psk-crack no hash data | `psk-crack -d /usr/share/wordlists/rockyou.txt /session/empty.txt` | nonzero | `no hash data found` | `no hash data found` | NEEDS LIVE VERIFY |
| 10 | psk-crack key not found | `psk-crack -d /session/wrong-words.txt /session/lab-ike-hash.txt` | 0 or nonzero | `Key not found` / `Running` finishes without `Key found` | `Key not found` | NEEDS LIVE VERIFY |
| 11 | Aggressive Mode handshake returned (success marker) | `ike-scan -M -A -d test -P /session/lab-ike-hash.txt 10.10.10.20` (against Aggressive-enabled lab) | 0 | `Aggressive Mode handshake returned` | `Aggressive Mode handshake returned` | NEEDS LIVE VERIFY |
| 12 | Main Mode handshake returned (success marker) | `ike-scan -M 10.10.10.20` (against Main Mode lab) | 0 | `Main Mode handshake returned` | `Main Mode handshake returned` | NEEDS LIVE VERIFY |

### Lesson recorded (encode in `tool.yaml` gotchas)

ike-scan's stderr text varies between distributions (Debian/Kali ship
the upstream 1.9.5 source; some forks patch wording, e.g., RHEL/CentOS
EPEL ships an older 1.9.4 with different timeout phrasing). Live
signature authoring requires running against the actual container
image. Failure signatures derived from docs alone will miss the exact
prefix (e.g., `0 returned handshake` vs `0 hosts returned handshake`).

ike-scan exits 0 even for `0 returned handshake` and `INVALID-EXCHANGE`
— the SNMP-like behaviour where the SNMP layer returns a valid response
that happens to indicate "no such thing" / "not allowed". Don't rely on
ike-scan exit code for "did the host respond" detection; parse stdout.
psk-crack's exit code is more meaningful (nonzero for hash-not-found,
0 for "exhausted dictionary, no key found" — the latter is "ran cleanly
but no result").

ike-scan PRINTS the result on success (e.g., `Aggressive Mode handshake
returned`) but does NOT explicitly distinguish vendor on the responder
side without `--showbackoff`. The Vendor-ID payload in the response is
advisory and can be missing or spoofed; backoff timing is the
high-confidence channel.

psk-crack OUTPUT FORMATS DIFFER BY BUILD — Debian's psk-crack 1.9.5
emits `Key found "<password>"` on success; older builds emit
`PSK = <password>` or `key found: <password>`. The legacy parser in
mcp-server.py handles all three, but the kind:cli path relies on
failure_signatures → `Key found` substring as the canonical marker.
Verify against the actual container build before relying on it.

---

## 5. Open questions

1. **IPv6 brackets (case 18)** — ike-scan accepts IPv6 literals but
   bracket syntax handling is build-dependent. Some 1.9.5 builds parse
   `[2001:db8::1]:500` as `[2001:db8::1]` host + `:500` port (matches
   `-p 500` semantics); others reject the brackets. Verify against
   `target-extraction.ts` once a v6-only lab IPsec endpoint is
   available. The DSL's positional_match regex captures the bracketed
   host *with* brackets; downstream TargetValidation strips brackets
   before scope check (same as curl).
2. **IPv6 -i6 flag (NOT in value_flags)** — ike-scan has `-6` /
   `--ipv6` flag (where supported) to force IPv6 socket. NOT listed as
   value_flag (boolean). Verify the build supports it; on older builds
   IPv6 may require recompile.
3. **Multi-binary dispatch verification** — every usage_pattern declares
   `binary:` explicitly. Does cli_in_container correctly forward the
   chosen binary to docker exec? Verified for impacket / smtp /
   forensics / snmp already; assume the same plumbing handles ike-scan.
   Confirm via S1 (S1 should invoke `ike-scan` not `mcp-server.py`)
   and S9 (S9 should invoke `psk-crack` not `ike-scan`).
4. **Raw socket privileges** — ike-scan with `--sport=500` requires
   CAP_NET_RAW (root). Default uses high source port. The Dockerfile
   does NOT enable privileged. The `--sport=500` flag should trigger a
   security warning (raw socket needed) before docker spawn — but the
   privileged-container approval flow is upstream of this tool.yaml.
   Document behavior.
5. **`--showbackoff` value optionality** — `--showbackoff` accepts an
   optional seconds value (e.g., `--showbackoff=120`). value_flags
   lists it as taking a value, which is the safest assumption (the DSL
   will consume the next token as the value if no `=` is present). For
   the boolean form (`--showbackoff` standalone), the next positional
   is treated as the value — which would be wrong. **Mitigation**: use
   ONLY the long-form `--showbackoff=<seconds>` syntax, OR treat
   `--showbackoff` as boolean (drop from value_flags). Verify against
   the actual build.
6. **`-A` aggressive mode + IKEv2 (`-2`) compatibility** — IKEv2 has
   no Aggressive Mode (the v1 concept doesn't apply). Combining `-A
   -2` returns a usage error. Document in gotchas; agent should not
   combine.
7. **psk-crack hashfile-as-target validation** — psk-crack's "target"
   for scope-validation purposes is a LOCAL FILE PATH, not a network
   host. The DSL's last_non_flag_positional rule extracts the file
   path; TargetValidation then has to handle "local file" vs "network
   target" disambiguation. **Mitigation**: psk-crack is offline-only;
   scope validation should bypass network checks for psk-crack
   invocations. Verify against the actual scope-validation hook.
8. **Multi-host probe scope (case 13)** — ike-scan's
   `allow_multi_target: true` means multiple hosts on argv. The DSL
   takes only the LAST as the scope target; this is wrong for
   multi-host scope validation. **Mitigation**: scope-validation hook
   should iterate ALL non-flag positionals and validate each against
   the engagement scope, not just the last. Verify behavior.
9. **Vendor-ID hex length** — `--vendor=<hex>` accepts 32+ hex chars
   (16+ bytes). Odd-length hex causes `Bad value` at runtime. DSL
   doesn't validate; agent must produce well-formed hex.
10. **NAT-T flag set varies by build** — `--natt`, `--nat-t`,
    `--natt-port`, `--natt-spi` are post-1.9.4 additions; older builds
    don't have them. value_flags lists all; binary will reject
    unknown flags with `unknown option`. Verify build version with
    `ike-scan --version` before using NAT-T-specific flags.
11. **psk-crack vs hashcat tradeoff** — psk-crack single-thread is
    ~100k-500k attempts/sec. hashcat -m 5300 (SHA1) on a modern GPU is
    100M+ attempts/sec — 200-1000x faster. For brute > length 6 OR
    rockyou+rules, switch to hashcat. The hash format produced by
    `ike-scan -P` is the right shape but the metadata header may need
    stripping for hashcat. Verify with a known-PSK lab.
12. **Live verification on a real IKE target** — HTB rarely exposes
    IKE; access requires a self-hosted lab (strongSwan / Cisco IOSv).
    Run S1-S12 against a `strongswan/strongswan` Docker container in a
    docker-compose harness as part of the kind:cli pilot validation.

13. **Audit gap: multi-binary chain workflow (ike-scan -P → psk-crack)
    is implicit, never a single scenario.** The legacy
    `get_psk_hash` + `crack_psk` methods composed two binaries with
    glue (write hash to temp file, hand the path to psk-crack, parse
    output, return cracked password). The kind:cli path scatters the
    chain across S2 (capture) and S9/S10 (crack), but never as a
    single integrated walkthrough. **Recommended chain (agent reads
    this verbatim):**
    - Step 1: `ike-scan -M -A -d <group> -P /session/ike-hash.txt
      <host>` — capture. Verify success via `Aggressive Mode
      handshake returned` substring in stdout AND non-empty
      /session/ike-hash.txt.
    - Step 2 (optional sanity): `read` /session/ike-hash.txt and
      confirm the line has 9 colon-separated fields with ≥3 hex
      blobs >20 chars. Empty file or fewer fields → Aggressive Mode
      wasn't actually accepted; go back to S2 with a different
      group_name.
    - Step 3: `psk-crack -d /usr/share/wordlists/rockyou.txt
      /session/ike-hash.txt` — crack. Search stdout for `Key found
      "<password>"` / `key found: <password>` / `PSK = <password>`
      (build-dependent). Empty result + clean exit == dictionary
      exhausted; switch to a custom wordlist (S10) or brute (S2-style
      `-B`-shorthand or `-B`-explicit).
    - Step 4 (escalation): if length 7+ brute is needed, switch to
      hashcat -m 5300 (SHA1) / -m 5400 (MD5). The on-disk hash file
      is the right shape but may need metadata-header stripping.
    The chain is NOT encoded as a single usage_pattern (kind:cli
    doesn't support multi-binary recipes); the LLM must orchestrate.
    See requirements doc §3.2 (Master Pentest Agent orchestrates
    binary chains).

14. **Audit gap: IKEv1 vs IKEv2 flag-set divergence is not formally
    listed; agent risks combining incompatible flags.** Open
    question #6 mentions `-A` + `-2` is a usage error, but the full
    divergence is broader. **Flag categories that DO NOT apply to
    IKEv2 (`-2`):**
    - `-A` / `--aggressive` — IKEv2 has no Aggressive Mode (RFC 7296
      removed it; IKE_SA_INIT does the equivalent without PSK leak).
    - `-d <id>` / `--id=<id>` — IKEv2 identity exchange happens in
      IKE_AUTH (post-DH), not the initial proposal. ike-scan's `-d`
      is IKEv1-only.
    - `-n <id>` / `--inititator-id=<id>` — same reason as `-d`.
    - `--trans=<enc>,<hash>,<auth>,<group>` — IKEv2 transforms use a
      different SA payload structure (SAi2 vs SAi1). ike-scan's
      `--trans` syntax is IKEv1-specific. IKEv2 transform negotiation
      is mostly automatic in ike-scan.
    - `-P` / `--pskcrack` — IKEv2 doesn't leak PSK in the same way;
      `-P` saves an Aggressive-Mode-shaped hash that's IKEv1-only.
      Combining `-2` with `-P` produces an empty file or warning.
    **Flag categories that DO apply to IKEv2:** `-M` / `--multiline`,
    `-p` / `--dport`, `-s` / `--sport`, `-r` / `--retry`, `-t` /
    `--timeout`, `-v` / `--verbose`, `-q` / `--quiet`, `-N` /
    `--nodns`, `--showbackoff`, `--vendor=<hex>` (sometimes — IKEv2
    has its own vendor mechanism). **Mitigation**: when `-2` /
    `--ikev2` is in argv, the agent should NOT include `-A`, `-d`,
    `-n`, `--trans=`, or `-P`. The DSL doesn't validate this; ike-scan
    will return a usage error or silently produce empty output.
    Encode this divergence in the agent's TVAR reasoning before argv
    construction.

15. **Audit gap: psk-crack offline scope-validation needs explicit
    bypass.** Open question #7 flags this; concretely, the
    `last_non_flag_positional` rule extracts `/session/<file>` as
    the "target" for psk-crack invocations. The scope-validation hook
    then has to recognise this as a LOCAL FILE PATH (matches
    `/session/...` prefix) and SKIP the IP / hostname / scope checks.
    Failing to bypass means every psk-crack call is blocked on
    "target /session/hash.txt is not in engagement scope" —
    NEEDS LIVE VERIFY against the cli_in_container hook.

16. **Audit gap: `--showbackoff` value optionality breaks
    `last_non_flag_positional` extraction.** Open question #5 flags
    the issue; concretely, when `--showbackoff` (no `=`) is used as a
    boolean, the DSL's value_flag entry consumes the NEXT token as
    the value — which is the host. Result: target=null, ike-scan
    runs without a host, exits with `No targets to process`.
    **Mitigation (currently undocumented in tool.yaml's
    value_flags):** the DSL should treat `--showbackoff` (and
    `--showbackofftime`) as accepting an OPTIONAL value, where the
    optional value is detected via the `=<seconds>` long-form syntax
    ONLY, and the bare `--showbackoff` form is a boolean. The
    cleanest agent rule is: ALWAYS use `--showbackoff=<seconds>` if a
    seconds value is needed, NEVER bare `--showbackoff <seconds>`.
    NEEDS LIVE VERIFY against the actual value_flags handling.

17. **Audit gap: legacy parser regex patterns are NOT exposed in
    failure_signatures or output_formats notes for read-tool
    post-processing.** mcp-server.py's `_parse_ike_output` parsed:
    - host line: `^(\d+\.\d+\.\d+\.\d+)\s+(.+)$` — IPv4 + response
      (won't match v6 — limitation of the legacy parser).
    - SA line: `^\s*SA=\((.+)\)$` — indented, parens-wrapped.
    - VID line: `^\s*VID=(.+)$` — indented, equals-prefixed.
    - Handshake marker: literal `Handshake returned` substring.
    - Aggressive Mode marker: literal `Aggressive Mode` substring
      (anywhere in line).
    These are useful for the agent's read-tool post-processing of
    `/session/<output>.txt` files — encoded into the gotchas (line
    "ike-scan -M OUTPUT LINE MARKERS"). The `_is_valid_psk_hash_line`
    validator's logic (skip metadata patterns, require 9+ colon
    fields, require 3+ hex fields >20 chars) is encoded in the
    gotcha "PSK HASH FILE FORMAT".

---

## 6. Hand-off

- **Tool**: ike-scan (kind:cli) — multi-binary toolkit
  - ike-scan 1.9 (network probing, Aggressive Mode PSK capture,
    transform enumeration, Vendor-ID + backoff fingerprinting, NAT-T)
  - psk-crack 1.9 (offline cracker for IKE Aggressive-Mode PSK
    hashes — dictionary or brute force)
- **Status**: migrated; scenarios consolidated; tool.yaml uses the
  impacket / snmp / smtp-style multi-sub-binary pattern (no top-level
  `binary:`, per-usage_pattern `binary:` field).
- **mcp-server.py**: present, untouched — auto-inherits run_cli;
  preserves the legacy method handlers (scan / aggressive_mode /
  enumerate_transforms / brute_group_names / get_psk_hash / crack_psk)
  as the rollback path per SKILL #21.
- **Image**: `ghcr.io/silicon-works/mcp-tools-ike-scan:latest` —
  Dockerfile is Kali rolling base + apt-installs `ike-scan` (provides
  both ike-scan AND psk-crack binaries) + `python3-full` + mcp-common
  0.3.0. Local rebuild required after this migration before
  end-to-end verification.
- **Dockerfile change**: `python3 python3-pip python3-venv` →
  `python3-full` (Kali-base externally-managed-environment fix). All
  other apt packages preserved.
- **Live-verify pending**: paste S1-S12 against a self-hosted
  strongSwan / Cisco IOSv lab once provisioned; verify
  failure_signatures entries 1-12 match the actual container output.
  HTB does not have a reliable IKE target.
- **Pilot-gate sign-off**: ≥12 deliberate-failure tests authored
  (live verify pending); ≥28 extraction cases authored (16
  adversarial F1-F16); ≥17 narrative-coverage usage_patterns
  authored; multi-binary pattern matches impacket / snmp precedent.

Authored: 2026-04-25 (Wave 6.3).
