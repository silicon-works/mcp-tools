# snmp — Tier A scenarios

Single test sheet for the `snmp` tool migration (kind:cli, multi-binary —
net-snmp 5.9 family + onesixtyone 0.3.3).

Sections:
1. Recommended HTB box for live verification
2. Narrative scenarios (paste into opensploit)
3. Target-extraction adversarial cases (≥20)
4. Failure-signature live-verify cases (≥3)
5. Open questions
6. Hand-off

---

## 1. Recommended HTB box

SNMP is unusually rare in HTB's lab rotation — UDP/161 is often filtered out
of "easy" boxes and most Active Directory boxes never expose SNMP. The few
candidates:

**Primary: Sneaky (10.10.10.20)** — Linux box with SNMP on UDP/161 and a
walk-able tree that leaks an internal IPv6 address (the intended path). The
SNMP community is `public`. Retired box; image readily spawnable on HTB
premium. Validates: snmpwalk system + interfaces, scope-extraction with the
positional target, MIB rendering.

**Alternate: SneakyMailer (10.10.10.197)** — name implies SMTP focus but
SNMP IS exposed on internal-facing interfaces inside the network namespace.
Useful for v3 testing if the engagement progresses to that level.

**Alternate: Postman (10.10.10.160)** — Linux with a Redis + Webmin path;
SNMP is NOT directly exposed to the attacker but a config file recovery
phase mentions a community string. Less useful for snmp tool exercise.

**Standalone fallback (no HTB)**: spin up `polinux/snmpd` Docker image
locally — clean snmpd 5.9 with `public` (read-only) and `private` (read-
write) communities. Walks return ~600 entries (system + interfaces + tcp/
udp + host-resources). Used for repeatable CI-style verification.

**Onesixtyone-specific testing**: the `polinux/snmpd` container responds
to ANY community string (returns a tiny banner), making it a poor brute-
force target. Use a hardened agent (e.g., `librenms/librenms` or a real
network device emulator) for realistic onesixtyone tests where only the
correct community string elicits a response.

Note: SNMP UDP filtering is RAMPANT — nmap's `-sU --top-ports 200` against
random HTB boxes returns 0 SNMP hits in ~80% of cases. Document the box's
SNMP exposure in the engagement report; don't assume SNMP is available
just because port 161 was scanned.

---

## 2. Narrative scenarios (paste into opensploit)

### S1 — system MIB walk (lowest-noise first contact)

```
Engagement target: 10.10.10.20 (HTB Sneaky, authorized).
Use the snmp tool to walk the system MIB (1.3.6.1.2.1.1) on the target
with community string "public" and SNMP version 2c. Save the output to
/session/sneaky-system.txt. Report: sysDescr (full OS string), sysName,
sysContact, sysLocation, sysUpTime.
```

**Watch:** Agent picks the `snmpwalk` binary. Argv shape: `snmpwalk -v 2c
-c public 10.10.10.20 1.3.6.1.2.1.1`. First call ~3-5 s (container spawn +
MCP handshake). Note: target is FIRST positional, OID is SECOND positional
— the DSL extracts target=`10.10.10.20`, NOT the OID `1.3.6.1.2.1.1`.

### S2 — running-processes walk (the credential-leak hit)

```
Engagement target: 10.10.10.20, authorized.
Use the snmp tool to walk the HOST-RESOURCES-MIB process table
(1.3.6.1.2.1.25.4.2) with community "public", v2c. Save to
/session/sneaky-procs.txt. Search the output for any process command-line
arguments that contain credentials (look for -p, -u, --password, mysql,
ssh patterns).
```

**Watch:** Argv: `snmpwalk -v 2c -c public 10.10.10.20 1.3.6.1.2.1.25.4.2`
or with `-m HOST-RESOURCES-MIB` for symbolic resolution. Agent recognises
the credential-leak vector via process-table.

### S3 — bulkwalk for full mib-2 tree (high-performance)

```
Engagement target: 10.10.10.20, authorized.
Use snmpbulkwalk to enumerate the full mib-2 subtree (1.3.6.1.2.1) with
community "public", v2c. Tune max-repetitions to 50 for faster transfer.
Save to /session/sneaky-mib2.txt. Report: total entry count and any
unusual MIB modules surfaced (e.g., vendor-specific OIDs).
```

**Watch:** Argv: `snmpbulkwalk -v 2c -c public -Cr 50 10.10.10.20
1.3.6.1.2.1`. Agent picks snmpbulkwalk over snmpwalk for speed. -Cr value
is not confused with the target.

### S4 — community brute via onesixtyone

```
Engagement target: 10.10.10.20, authorized.
The community string for this engagement is unknown (assume neither public
nor private works). Use onesixtyone via the snmp tool to brute-force
common community strings against the host. Use the seclists wordlist at
/usr/share/seclists/Discovery/SNMP/common-snmp-community-strings.txt.
Use -w 50 to be polite. Save to /session/sneaky-community-brute.txt.
Report any communities that responded.
```

**Watch:** Argv: `onesixtyone 10.10.10.20 -c /usr/share/seclists/Discovery/
SNMP/common-snmp-community-strings.txt -w 50`. CRITICAL: target is FIRST
positional, then `-c` is the COMMUNITY-WORDLIST FILE. Agent does NOT
confuse onesixtyone's `-c` with net-snmp's `-c <community-string>`.

### S5 — SNMPv3 authPriv walk (production credential test)

```
Engagement target: 10.10.10.50 (assumed v3-required SNMPv3 lab device,
authorized).
Recovered creds from a config dump: username `monitor`, auth passphrase
`MonitorAuth!2024`, priv passphrase `MonitorPriv!2024`. Auth protocol
SHA, priv protocol AES. Use the snmp tool to walk the system MIB with
v3 authPriv. Save to /session/v3-system.txt.
```

**Watch:** Argv: `snmpwalk -v 3 -l authPriv -u monitor -a SHA -A
'MonitorAuth!2024' -x AES -X 'MonitorPriv!2024' 10.10.10.50 1.3.6.1.2.1.1`.
Agent constructs ALL SIX v3 flags in canonical order. Passphrases QUOTED
because of `!` shell metacharacter.

### S6 — snmpset write (post-exploitation pivot)

```
Engagement target: 10.10.10.20, authorized — write community confirmed
as "private".
Use the snmp tool with snmpset to write a marker to sysContact.0 to
demonstrate write access. Set the value to "pwn@attacker.local" with
type 's' (string). Save the transaction to /session/sneaky-write.txt.
Verify the write by following up with snmpget on sysContact.0.
```

**Watch:** Argv: `snmpset -v 2c -c private 10.10.10.20 sysContact.0 s
'pwn@attacker.local'`. Agent constructs the triple form: oid type value.
Type letter `s` for string. Then a follow-up `snmpget -v 2c -c public
10.10.10.20 sysContact.0` confirms.

### S7 — DNS failure classification

```
Engagement target: nonexistent-snmp.invalid.localdomain (deliberately
invalid, verifying error classification).
Use snmpwalk via the snmp tool with -v 2c -c public and OID 1.3.6.1.2.1.1
on this hostname. -t 3 -r 0 to fail fast. Report what failure mode you
classify this as.
```

**Watch:** stderr / stdout contains `Cannot resolve` or `Name or service
not known` or `Unknown host`. failure_signature matches.

### S8 — wrong community / no response

```
Engagement target: 10.10.10.20, authorized.
Use snmpwalk with the obviously-wrong community "this-is-not-the-right-
community", v2c, OID 1.3.6.1.2.1.1, -t 2 -r 1 to fail fast. Report
the failure mode.
```

**Watch:** Output contains `Timeout: No Response from`. The agent
correctly maps this to "wrong community OR port closed OR target down" —
all three are indistinguishable from the SNMP layer (the agent silently
drops invalid-community packets). Distinguishing requires nmap UDP scan.

---

## 3. Target-extraction adversarial cases (≥20)

The snmp `tool.yaml` declares two extraction rules:

1. `first_non_flag_positional` — target is the FIRST non-flag positional
2. `positional_match` — strip optional `:port` suffix, handle bracketed v6

**Critical invariant:** subsequent positionals are OID(s) for net-snmp
binaries — they must NOT be confused with the target. An OID like
`1.3.6.1.2.1.1` looks like an IPv4 address to a naive regex match; the
DSL's first_non_flag_positional rule fires first and consumes the host.

| # | Command (binary as shown) | Expected target | Notes |
|---|---|---|---|
| 1 | `snmpwalk -v 2c -c public 10.10.10.5 1.3.6.1.2.1.1` | `10.10.10.5` | Bog-standard walk; target=first positional, OID=second |
| 2 | `snmpwalk -v 2c -c public router.target.local system` | `router.target.local` | Hostname FQDN target; symbolic OID |
| 3 | `snmpwalk -v 2c -c public 10.10.10.5:1161 1.3.6.1.2.1.1` | `10.10.10.5` | host:port shorthand — strip the :port |
| 4 | `snmpget -v 2c -c public 10.10.10.5 sysDescr.0` | `10.10.10.5` | Symbolic OID with .0 instance suffix |
| 5 | `snmpget -v 2c -c public 10.10.10.5 1.3.6.1.2.1.1.1.0` | `10.10.10.5` | Numeric OID — NOT confused with target despite IPv4-looking dots |
| 6 | `snmpset -v 2c -c private 10.10.10.5 sysContact.0 s 'admin@target'` | `10.10.10.5` | snmpset triple form: oid type value — value contains @ but not extracted |
| 7 | `snmpset -v 2c -c private 10.10.10.5 sysContact.0 s 'admin@target' sysLocation.0 s 'Datacenter A'` | `10.10.10.5` | Multi-triple set — many positionals after target |
| 8 | `snmpbulkwalk -v 2c -c public 10.10.10.5 1.3.6.1.2.1` | `10.10.10.5` | bulkwalk — same shape as walk |
| 9 | `snmpbulkwalk -v 2c -c public -Cr 50 10.10.10.5 1.3.6.1.2.1.25` | `10.10.10.5` | -Cr 50 is value_flag — DSL doesn't capture `50` as target |
| 10 | `snmpwalk -v 3 -l authPriv -u admin -a SHA -A 'AuthPass!' -x AES -X 'PrivPass!' 10.10.10.5 1.3.6.1.2.1.1` | `10.10.10.5` | v3 authPriv — six value_flags before positional target |
| 11 | `snmpwalk -v 2c -c public [2001:db8::1]:161 1.3.6.1.2.1.1` | `[2001:db8::1]` (or `2001:db8::1`) | IPv6 bracketed — see Open Questions |
| 12 | `snmpwalk -v 2c -c public TARGET.LOCAL 1.3.6.1.2.1.1` | `TARGET.LOCAL` | Uppercase host preserved (validation hook lowercases later) |
| 13 | `onesixtyone 10.10.10.5 -c /usr/share/seclists/Discovery/SNMP/common-snmp-community-strings.txt` | `10.10.10.5` | onesixtyone target FIRST positional, -c is wordlist FILE |
| 14 | `onesixtyone 10.10.10.5 -c /session/communities.txt -w 100` | `10.10.10.5` | onesixtyone with rate-limit; target stays first |
| 15 | `onesixtyone -p 1161 10.10.10.5 -c /session/communities.txt` | `10.10.10.5` | onesixtyone -p 1161 (port) — target after the value flag |
| 16 | `snmpwalk -v 2c -c 'community-with-spaces and-special-chars!' 10.10.10.5 1.3.6.1.2.1.1` | `10.10.10.5` | -c value contains spaces and ! — value_flag traps it |
| 17 | `snmpwalk -v 2c -c public -m ALL -OnvQ 10.10.10.5 1.3.6.1.2.1.25.4.2` | `10.10.10.5` | -m ALL + -OnvQ output bundle before target |
| 18 | `snmpwalk -v 2c -c 192.168.1.1 10.10.10.5 1.3.6.1.2.1.1` | `10.10.10.5` | -c value LOOKS like an IP but is a community string — value_flag traps |
| 19 | `snmpset -v 2c -c private 10.10.10.5 ipDefaultRouter.0 a 192.168.1.254` | `10.10.10.5` | snmpset value is an IP address with type `a` (IPAddress) — not a target |
| 20 | `snmpwalk -v 2c -c public 10.10.10.5 1.3.6.1.4.1.9.2.1` | `10.10.10.5` | OID is 5+ dots (vendor enterprise OID — Cisco) — still NOT extracted as target |
| 21 | `snmpwalk -v 2c -c public 10.10.10.5 1.3.6.1.2.1.4.20.1.1.10.10.10.5` | `10.10.10.5` | OID embeds an IP (ipAdEntAddr.10.10.10.5) — target is FIRST positional, NOT the embedded IP |
| 22 | `snmptable -v 2c -c public -Cb 10.10.10.5 1.3.6.1.2.1.2.2` | `10.10.10.5` | snmptable with -Cb (brief headers) — different binary, same target shape |
| 23 | `snmpdf -v 2c -c public 10.10.10.5` | `10.10.10.5` | snmpdf — no OID positional, just target |
| 24 | `snmpwalk -v 2c -c public -t 10 -r 3 10.10.10.5 system` | `10.10.10.5` | Timing flags before target |
| 25 | `snmpwalk -v 2c -c public 10.10.10.5` | `10.10.10.5` | NO OID — full-tree walk; target is sole positional |
| 26 | `snmpgetnext -v 2c -c public 10.10.10.5 1.3.6.1.2.1.1` | `10.10.10.5` | snmpgetnext — different binary, same shape |
| 27 | `snmpwalk -v 2c -c public -L o 10.10.10.5 1.3.6.1.2.1.1` | `10.10.10.5` | -L o (log to stdout) — value_flag |

### Adversarial / failure cases (DSL must reject or fall back)

| # | Command | Expected behaviour | Notes |
|---|---|---|---|
| F1 | `snmpwalk -V` | target=null → tool.execute.before allows (no target → no validation) | net-snmp version flag |
| F2 | `snmpwalk -h` | target=null → no validation | Help banner |
| F3 | `onesixtyone -h` | target=null → no validation | onesixtyone help |
| F4 | `snmptranslate -On sysDescr.0` | target=null (snmptranslate is OFFLINE — no host arg ever) | Pure offline OID translation |
| F5 | `snmptranslate -Of 1.3.6.1.2.1.1.1.0` | target=null | Inverse offline translation |
| F6 | `onesixtyone -i /session/hosts.txt -c /session/communities.txt` | reject — `-i` is in reject_flags | Multi-host file ingestion blocked at plugin layer |
| F7 | `snmpwalk -v 2c -c public` (no host) | target=null → snmpwalk fails naturally with `Need IP/host` usage error | Missing required positional → snmpwalk exits nonzero |
| F8 | `snmpwalk 1.3.6.1.2.1.1` (no flags, no host — OID looks like IP) | target=`1.3.6.1.2.1.1` (first_non_flag_positional captures it) — snmpwalk fails because no -c | **Edge case**: the parser ALWAYS takes the first positional. If the user mistakenly omits the host and only passes OID, the OID becomes the "target" and nmap-scope validation will fire on it. snmpwalk itself will then fail with a usage error because no -c was given. Document but don't try to fix at parse layer. |
| F9 | `snmpwalk -v 2c -c '10.10.10.5' 10.10.10.99 1.3.6.1.2.1.1` | target=`10.10.10.99`, NOT `10.10.10.5`. **Critical security invariant**: target is the FIRST POSITIONAL host, NEVER a community-string value. | -c value LOOKS like a target IP but value_flags traps it; first positional wins. |
| F10 | `snmpwalk -v 2c -c public -A 10.10.10.5 router.target 1.3.6.1.2.1.1` | target=`router.target`, NOT `10.10.10.5`. -A value (auth passphrase) traps the IP-shape. | -A value is auth passphrase, not target. Even though it looks like an IP. |
| F11 | `onesixtyone 10.10.10.5 -i /session/hosts.txt` | reject — `-i` rejected even with positional present | reject_flags fires before target_extraction |
| F12 | `snmpset -v 2c -c private 10.10.10.5 sysContact.0 s pwn@attacker.local` (unquoted) | target=`10.10.10.5`. Value `pwn@attacker.local` is the snmpset value (string). | Argv tokenisation: even unquoted, the value is one token because no shell expansion in DSL argv. |

---

## 4. Failure-signature live-verify cases (≥3)

Run each via opensploit (paste the prompt) and verify the result hits the
`failure_signatures` entry in `tool.yaml`. Each test produces an exit code,
a stderr/stdout message, and a `signal` substring the tool.yaml MUST contain.

| # | Test | Command (post-binary) | Expected exit | Expected stderr/stdout substring | failure_signature `signal` field | Status |
|---|---|---|---|---|---|---|
| 1 | DNS resolution failure | `snmpwalk -v 2c -c public -t 3 -r 0 nonexistent.invalid.localdomain 1.3.6.1.2.1.1` | nonzero | `Cannot resolve` / `Name or service not known` / `Unknown host` | `Cannot resolve` AND `Name or service not known` AND `Unknown host` | NEEDS LIVE VERIFY |
| 2 | UDP timeout / wrong community / port closed | `snmpwalk -v 2c -c definitely-wrong-string-12345 -t 2 -r 1 10.10.10.5 1.3.6.1.2.1.1` | nonzero | `Timeout: No Response from` | `Timeout: No Response from` | NEEDS LIVE VERIFY |
| 3 | v3 wrong digest (auth fail) | `snmpwalk -v 3 -l authPriv -u monitor -a SHA -A wrongpass1234 -x AES -X wrongprivpass 10.10.10.5 1.3.6.1.2.1.1` | nonzero | `Authentication failure` / `Wrong digest` / `usmStatsWrongDigests` | `Authentication failure (incorrect password, community or key)` AND `Wrong digest` | NEEDS LIVE VERIFY |
| 4 | v3 unknown user | `snmpwalk -v 3 -l authNoPriv -u nonexistentuser -a SHA -A somepass1234 10.10.10.5 1.3.6.1.2.1.1` | nonzero | `Unknown user name` / `usmStatsUnknownUserNames` | `Unknown user name` | NEEDS LIVE VERIFY |
| 5 | noSuchInstance (scalar without .0) | `snmpget -v 2c -c public 10.10.10.5 sysDescr` | 0 (snmpget prints `No Such Instance` and exits 0) | `noSuchInstance` / `No Such Instance` | `noSuchInstance` | NEEDS LIVE VERIFY |
| 6 | noSuchObject (unknown OID) | `snmpget -v 2c -c public 10.10.10.5 1.3.99.99.99.0` | 0 | `noSuchObject` / `No Such Object` | `noSuchObject` | NEEDS LIVE VERIFY |
| 7 | snmpset bad type letter | `snmpset -v 2c -c private 10.10.10.5 sysContact.0 INVALID-TYPE 'value'` | nonzero | `Bad operator` | `Bad operator` | NEEDS LIVE VERIFY |
| 8 | passphrase too short | `snmpwalk -v 3 -l authPriv -u admin -a SHA -A short -x AES -X alsoshort 10.10.10.5 1.3.6.1.2.1.1` | nonzero | `Error generating a key for authentication pass phrase` | `Error generating a key for authentication pass phrase` | NEEDS LIVE VERIFY |

### Lesson recorded (encode in `tool.yaml` gotchas)

net-snmp's stderr text varies between distributions (Debian/Kali ship the
upstream net-snmp 5.9 source; some forks patch wording). Live signature
authoring requires running against the actual container image. Failure
signatures derived from docs alone will miss `Couldn't connect` vs
`Connection refused` and may miss the protocol-stage prefix.

snmpget exits 0 for `noSuchObject` / `noSuchInstance` — the SNMP layer
returned a valid response that happened to indicate "no such thing". Don't
rely on snmpget exit code for "did the OID exist" detection; parse stdout.
Same for snmpwalk on a tree that doesn't exist (returns 0, prints one
`No Such Object` line).

snmpset PRINTS the resulting value on success, exits 0; on failure exits
nonzero AND prints the SNMP error reason. The PRINT-on-success behaviour
means a successful write looks confusingly similar to a successful read.
Distinguish by whether the agent's request was set (verify with a
follow-up snmpget).

---

## 5. Open questions

1. **IPv6 brackets (case 11)** — net-snmp accepts `[2001:db8::1]:161` as
   a host:port shorthand. The DSL's positional_match regex captures
   `[2001:db8::1]` *with* brackets. Expected behaviour: TargetValidation
   strips brackets before passing to scope check, same as curl. Verify
   against `target-extraction.ts` once a v6-only lab SNMP agent is
   available.
2. **Multi-binary dispatch verification** — every usage_pattern declares
   `binary:` explicitly. Does cli_in_container correctly forward the
   chosen binary to docker exec? Verified for impacket / smtp / forensics
   already; assume the same plumbing handles snmp. Confirm via S1 (S1
   should invoke `snmpwalk` not `snmp` or `mcp-server.py`).
3. **onesixtyone `-i` reject** — listed in reject_flags. Verify the
   plugin layer rejects with a clear error message ("multi-host file
   ingestion blocked") rather than silently passing through and failing
   at scope validation. This is the canonical reject_flag test case for
   the snmp tool.
4. **onesixtyone `-c` collision** — onesixtyone's `-c` is a wordlist
   FILE; net-snmp's `-c` is a community string. Same flag letter,
   different semantics. value_flags lists `-c` once (it's binary-
   independent at the value-flag level — both consume a value). The DSL
   only invokes one binary per call, so there's no actual collision.
   Verify in S4 that the agent doesn't accidentally pass a community
   STRING to onesixtyone's -c.
5. **v3 flag-count gotcha** — six flags for authPriv is easy to misorder
   or miss. Document in gotchas (canonical order: -v 3 -l authPriv -u
   USER -a PROTO -A PASS -x PROTO -X PASS). Verify in S5.
6. **Community-string visibility** — v1/v2c communities are on the
   cmdline (visible in `ps`/audit logs of the attacker container) AND
   on the wire as plaintext. Encoded in gotchas. For client engagements
   prefer v3.
7. **Snmpset write-community discovery** — `private` is the textbook
   write community but rotation is common. The brute_community usage
   pattern only finds READ-able communities (any response = match);
   write-able communities require attempting an actual snmpset which is
   destructive. Document but no automated solution yet.
8. **MIB loading state** — the Dockerfile uncomments `mibs :` in
   /etc/snmp/snmp.conf and installs snmp-mibs-downloader. Verify on the
   actual built image that `-m ALL` resolves vendor MIBs. Without this,
   walks return numeric OIDs only, which is correct but human-unfriendly.
9. **Live verification on a real SNMP target** — Sneaky was retired;
   access requires HTB premium. polinux/snmpd standalone is the no-HTB
   fallback for repeatable CI-style verification. Run S1-S8 against
   polinux/snmpd in a docker-compose harness as part of the kind:cli
   pilot validation.
10. **OID-as-second-positional adversarial** — case 5 (`snmpget -v 2c
    -c public 10.10.10.5 1.3.6.1.2.1.1.1.0`) is the canonical test for
    "OID looks like IPv4 but isn't the target". The DSL's
    first_non_flag_positional rule fires deterministically — but verify
    with a unit test against `target-extraction.ts` because regression
    here would silently bypass scope validation by treating the OID as
    a second target.
11. **COMMON_OIDS dict drift** — the legacy `mcp-server.py` shipped a
    Python dict of named-shortcut OIDs (`system`, `interfaces`,
    `ip_addresses`, `routes`, `tcp_connections`, `udp_listeners`,
    `processes`, `installed_software`, `storage`, `users`). Under
    kind:cli the LLM writes the OID directly — the named-shortcut layer
    is GONE for the run_cli path. The shortcut names persist in the
    legacy `methods.walk.params.oid_name` schema (preserved for the
    rollback path). New agent guidance: use the numeric OIDs documented
    in gotchas and routing.use_for. **Open**: should `system` /
    `processes` / etc. be allowed as symbolic OID arguments to net-snmp
    when MIBs are loaded? `snmpwalk -m ALL <host> system` works because
    SNMPv2-MIB defines `system` as a node alias, but
    `1.3.6.1.4.1.77.1.2.25` (`users`, Windows LanMan UserTable) is
    NOT a symbolic alias — only resolvable numerically. Document the
    asymmetry; don't restore the dict.
12. **`tcp_connections` (1.3.6.1.2.1.6.13) and `udp_listeners`
    (1.3.6.1.2.1.7.5)** — present in legacy COMMON_OIDS but absent from
    the new usage_patterns. They're moderate-value (mirror of
    `netstat -tn` / `netstat -unl`) and should be reachable via direct
    snmpwalk argv (the LLM doesn't NEED a usage_pattern for every OID),
    but no example currently demonstrates the pattern. Consider adding
    a "Walk TCP connections via tcpConnTable" usage_pattern in a
    follow-up wave; for now the LLM has to compose argv from gotchas.
13. **`users` OID (1.3.6.1.4.1.77.1.2.25 — Windows LanMan UserTable)**
    — legacy dict's most exotic entry. Vendor-specific (Microsoft
    private enterprise OID), works on legacy Windows SNMP agents and
    leaks local user accounts. Worth its own usage_pattern when a
    Windows SNMP target is in scope. NOT covered by `-m ALL` unless
    LANMANAGER-MIB is in /usr/share/snmp/mibs (it is not by default
    in the Kali image).
14. **`/app/community-strings.txt` BUILT-IN WORDLIST** — legacy
    onesixtyone path defaulted to a baked-in `/app/community-strings.txt`
    (~17 entries). Tool.yaml's usage_patterns only reference the
    seclists path. Both work; the built-in is faster to invoke (no
    seclists dependency) but narrower. Mentioned now in gotchas.
15. **Output truncation cap (50KB)** — legacy `sanitize_output` capped
    raw_output at 50000 chars. kind:cli inherits this via run_cli.
    Bulk walks of full mib-2 trees on busy routers EXCEED 50KB; for
    those cases the agent should redirect via wrapper or chunk the
    walk by subtree. Documented now in gotchas; no automated split.
16. **snmpwalk vs snmpget exit-code semantics** — snmpwalk exits 0 even
    when the tree is empty / OID doesn't exist (prints one
    `No Such Object` line). snmpget likewise exits 0 for
    `noSuchInstance`. The legacy handler classified these via STDOUT
    string match; failure_signatures now lists BOTH the lowercase
    camelCase form (`noSuchObject`, `noSuchInstance`) and the
    human-readable capital-case form (`No Such Object`,
    `No Such Instance`) for parity with what net-snmp actually emits.
17. **Stderr `No SNMP response` distinct from stdout `Timeout`** —
    legacy handler had two separate branches: stdout `Timeout` /
    `No Response` (line 346) and stderr `No SNMP response` (line 353).
    Both indicate the same root cause cluster (community wrong, port
    closed, target down) but appear in different streams depending on
    net-snmp build. failure_signatures now has all three signals
    (`Timeout: No Response from`, `No Response from`, `No SNMP
    response`).
18. **Per-request timeout multiplier (`timeout * 10 + 30`)** — legacy
    walks budgeted (per-request timeout) × 10 + 30s for the entire
    container call. kind:cli has a flat `timeout_seconds: 3600` cap.
    For aggressive `-t 30 -r 5` defaults on a thousand-OID tree, the
    legacy budget would have been ~330s; the new flat 3600s ceiling
    accommodates worst-case but doesn't auto-tune. The LLM should
    prefer scoped walks with explicit `-t 1 -r 0` for fast probes.

---

## 6. Hand-off

- **Tool**: snmp (kind:cli) — multi-binary toolkit
  - net-snmp 5.9: snmpwalk, snmpget, snmpgetnext, snmpset,
    snmpbulkget, snmpbulkwalk, snmptable, snmpdf, snmpnetstat,
    snmptranslate
  - onesixtyone 0.3.3 (community brute)
- **Status**: migrated; scenarios consolidated; tool.yaml uses the
  impacket/smtp-style multi-sub-binary pattern (no top-level `binary:`,
  per-usage_pattern `binary:` field).
- **mcp-server.py**: present, untouched — auto-inherits run_cli;
  preserves the legacy method handlers (walk / get / bulk_walk /
  brute_community) as the rollback path per SKILL #21.
- **Image**: `ghcr.io/silicon-works/mcp-tools-snmp:latest` — Dockerfile
  is Kali rolling base + apt-installs `snmp` + `snmp-mibs-downloader` +
  `onesixtyone` + `python3-full` + mcp-common 0.3.0. Local rebuild
  required after this migration before end-to-end verification.
- **Dockerfile change**: `python3 python3-pip python3-venv` →
  `python3-full` (Kali-base externally-managed-environment fix). All
  other apt packages preserved.
- **Live-verify pending**: paste S1-S8 against Sneaky (HTB) /
  polinux/snmpd (standalone) once access is provisioned; verify
  failure_signatures entries 1-8 match the actual container output.
- **Pilot-gate sign-off**: ≥8 deliberate-failure tests authored (live
  verify pending); ≥27 extraction cases authored (12 adversarial F1-F12);
  ≥20 narrative-coverage usage_patterns authored; multi-binary pattern
  matches impacket / smtp precedent.

Authored: 2026-04-25 (Wave 6.2).
