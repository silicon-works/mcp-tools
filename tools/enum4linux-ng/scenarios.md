# enum4linux-ng — Tier A scenarios

Single test sheet for the `enum4linux-ng` tool migration (Wave 6.4 — final
tool of Wave 6, AD enumeration cluster).

enum4linux-ng v1.3.4 is the modern Python rewrite of Mark Lowe's
`enum4linux.pl` — a **single binary** (`enum4linux-ng`) that wraps the
Samba client tools (`nmblookup`, `net`, `rpcclient`, `smbclient`) for
SMB / Windows / Samba enumeration. The TARGET is a SINGLE positional
`<host>` that comes LAST after all flag values. There is NO list / CIDR /
file form (`allow_multi_target: false`).

This is structurally similar to ike-scan (single binary, target as last
positional, multiple flag-value flags whose values would shape-match a
target) but DIFFERENT in shape — ike-scan accepts MULTIPLE positionals
(host list); enum4linux-ng accepts EXACTLY ONE host per call.

Sections:
1. Recommended HTB box for live verification
2. Narrative scenarios (paste into opensploit)
3. Target-extraction adversarial cases (≥20 — total 24)
4. Failure-signature live-verify cases (≥3 — total 6)
5. Open questions
6. Hand-off

---

## 1. Recommended HTB box

**Hercules (10.129.242.196)** — same Linux DC for `hercules.htb` used for
impacket / netexec / kerbrute testing. Why Hercules is right for
enum4linux-ng testing:

- **NTLM disabled domain-wide** — surfaces `Server doesn't allow
  connection` and `STATUS_ACCESS_DENIED` failure paths. Forces the
  Kerberos (`-K /session/<user>.ccache`) path to be exercised.
- **LDAP open on the DC** — `-L` (LDAP domain info) returns rootDSE +
  default naming context. Confirms the DC role and feeds follow-up
  impacket-ldapsearch. Anonymous LDAP often allowed on Win2008+ DCs.
- **Real AD environment with rich RPC** — `-U` / `-G` / `-Gm` / `-R`
  / `-P` / `-I` all exercise different RPC pipes (samr, lsarpc,
  netlogon, srvsvc, spoolss).
- **Default share set** — IPC$, ADMIN$, C$, NETLOGON, SYSVOL — exercises
  `-S` access-check matrix (READ/WRITE).
- **Test-data RID range 500-2000** — covers Administrator (500), Guest
  (501), krbtgt (502), and the natalie.a / mason.j / tom.h test users
  in the 1000+ range.

Test credential pair: `hercules.htb/natalie.a:Prettyprincess123!` (per
the HTB writeup; valid as of the 2026-04-25 verification run for
impacket / netexec).

**Persistent test directory**: mount `/tmp/enum4linux-test:/session` (per
SKILL #14). Multi-step flows like getTGT (writes /session/natalie.a.ccache)
+ enum4linux-ng `-K` (reads /session/natalie.a.ccache) need the same dir
across calls.

**Alternate HTB boxes for diversity**:
- **Active (10.10.10.100)** — classic SMB null-session leakage; exercises
  the `-A` happy path with anonymous access.
- **Forest (10.10.10.161)** — AS-REP roastable users via `-U`; pair with
  impacket-GetNPUsers downstream.
- **Sauna (10.10.10.175)** — `-R` RID brute on a Windows DC that allows
  null-session lookupsids.

---

## 2. Narrative scenarios (paste into opensploit)

### S1 — Null-session full enum on Active (the happy path)

```
Engagement target: 10.10.10.100 (HTB Active, authorized).
Use enum4linux-ng -A -oY /session/active-null 10.10.10.100 to do a full null-session enumeration. Active leaves SMB open with anonymous SAMR access — expect users, groups, and the Replication share visible without credentials.
```

**Watch:** target=`10.10.10.100` extracted via `last_non_flag_positional`
(rule 1). The flag value `/session/active-null` is consumed by `-oY`
(value_flag) and must NOT be confused with the host. `-A` runs the
simple-enum bundle (-U -G -S -P -O -N -I -L). YAML output at
`/session/active-null.yaml` — extension auto-appended. Expected: SAMR
returns the user list; the Replication share is anonymous-readable
(contains the Groups.xml GPP password — out of scope here, but the share
visibility is the canonical Active SMB leak).

### S2 — Authenticated full enum on Hercules with valid creds

```
Engagement target: 10.129.242.196 (HTB Hercules, authorized).
Use enum4linux-ng -A -u natalie.a -p 'Prettyprincess123!' -w hercules.htb -oY /session/hercules-auth 10.129.242.196 to do an authenticated enumeration with NTLM. Hercules has NTLM disabled domain-wide, so this WILL fail at the auth layer — verify the failure mode is Server doesn't allow connection.
```

**Watch:** target=`10.129.242.196`. `-u natalie.a` and `-p 'Pretty...'`
and `-w hercules.htb` all in value_flags; `-w hercules.htb` is FQDN-shape
and would otherwise extract as a target — value_flag defends. NTLM
disabled → `Server doesn't allow connection` in output. Failure
classification: switch to Kerberos (S3).

### S3 — Kerberos enum on Hercules (the NTLM-disabled workaround)

```
Engagement target: 10.129.242.196 (HTB Hercules).
First, use impacket-getTGT with hercules.htb/natalie.a:Prettyprincess123! to write a ccache to /session/natalie.a.ccache. Then run enum4linux-ng -A -u natalie.a -K /session/natalie.a.ccache -oY /session/hercules-krb 10.129.242.196.
```

**Watch:** Two-step flow — getTGT from impacket writes ccache;
enum4linux-ng reads it via `-K`. target=`10.129.242.196`. `-K
/session/natalie.a.ccache` value is a file path — NOT a target shape, but
value_flag defends. With Kerberos, NTLM disablement is bypassed; expect
the full -A bundle to succeed (users, groups, shares, policy). Compare
output to S2's failure to confirm the workaround.

### S4 — RID brute when SAMR user enum is blocked

```
Engagement target: 10.129.242.196 (HTB Hercules).
Use enum4linux-ng -R -r 500-2000 -u natalie.a -K /session/natalie.a.ccache -oY /session/hercules-rid 10.129.242.196 to do RID cycling over the 500-2000 range. RID brute uses lookupsids RPC (different from SAMR-OPEN-USER) — often works when -U returns empty.
```

**Watch:** target=`10.129.242.196`. `-r 500-2000` value contains a hyphen
— would not match the target regex but value_flag defends. `-R` is
TREATED AS BOOLEAN (no optional BULK_SIZE), so the next token after `-R`
(in this command, `-r`) is recognized as a flag, not as `-R`'s value.
Output: `users` array with username + RID for each successful lookup.
Skips the RIDs returning STATUS_NONE_MAPPED (no user at that RID).

### S5 — Specific operations only (-S -G -P, skip RID overhead)

```
Engagement target: 10.10.10.161 (HTB Forest).
Use enum4linux-ng -S -G -P -u guest -p '' -oY /session/forest-sgp 10.10.10.161 to enumerate JUST shares, groups, and password policy without the slow RID cycle. Forest allows null-session SAMR and has the standard share set.
```

**Watch:** target=`10.10.10.161`. Multiple boolean flags (-S -G -P) are
listed in value_flags as boolean for parser safety. Selective enum is
faster than -A on slow targets. Output has `shares` + `groups` +
`password_policy` populated; `users` empty (we skipped -U).

### S6 — Failure: STATUS_ACCESS_DENIED on Hercules (NTLM disabled — surface protocol-level signal)

```
Engagement target: 10.129.242.196 (HTB Hercules, NTLM disabled domain-wide).
Use enum4linux-ng -U -u natalie.a -p 'Prettyprincess123!' 10.129.242.196 to attempt SAMR user enum with valid creds. Verify the failure mode is NTLM disablement (Server doesn't allow connection) or STATUS_ACCESS_DENIED, not wrong-password.
```

**Watch:** Output contains `Server doesn't allow connection` (transport
layer — NTLM rejected at session-setup) OR `STATUS_ACCESS_DENIED` (auth
succeeded null but SAMR-OPEN-USER blocked). Failure classified via either
signal. Distinct from STATUS_LOGON_FAILURE (wrong password). Agent
remediation: switch to Kerberos (S3) or switch to RID brute via
lookupsids (S4).

### S7 — Group members deep-dive (-Gm — not in -A)

```
Engagement target: 10.10.10.100 (HTB Active).
Use enum4linux-ng -Gm -u SVC_TGS -p GPPstillStandingStrong2k18 -oY /session/active-groupmembers 10.10.10.100 to enumerate groups WITH member lists. Active's SVC_TGS account is in the standard groups; the interesting one is whether it's in any privileged group.
```

**Watch:** `-Gm` is groups + members (slower than `-G` because one RPC
call per group). target=`10.10.10.100`. `-Gm` is in value_flags as
boolean. Output `groups` array now includes a `members` field per group.
Look for: 'Domain Admins', 'Enterprise Admins', 'Backup Operators' member
lists.

### S8 — LDAP DC info probe (-L)

```
Engagement target: 10.129.242.196 (HTB Hercules DC).
Use enum4linux-ng -L -u '' -p '' -oY /session/hercules-ldap 10.129.242.196 to probe LDAP. Hercules is a DC with anonymous LDAP allowed (Win2008+ default). Expect rootDSE attributes and the default naming context.
```

**Watch:** target=`10.129.242.196`. `-L` is the LDAP probe — only
meaningful on DCs. On non-DCs returns 'LDAP not running' / 'Could not
connect to LDAP'. Captures the domain DN for follow-up
impacket-ldapsearch / netexec ldap.

---

## 3. Target-extraction adversarial cases (24 total, ≥20 spec)

The enum4linux-ng `tool.yaml` declares TWO `target_extraction` rules
(first match wins):

1. `last_non_flag_positional`, `parse_as: raw` — captures the host even
   when flag values are interleaved with the positional. Mirror of
   ike-scan's pattern.
2. `positional_match` regex `^\[?([^\]:/?#\s]+|[0-9a-fA-F:]+)\]?(?::\d+)?$`,
   `parse_as: raw` — fallback shape-match for IPv4 / FQDN / bracketed
   IPv6, in case the LLM places host first (rare; per the help text,
   host comes last).

`value_flags` declares ~25 entries to prevent value-position strings
(passwords, usernames, workgroups, RID ranges, output prefixes, ccache
paths, NTLM hashes) from being mistaken for targets — every flag whose
value could shape-match the target regex is enumerated. Most boolean
flags (-A, -As, -U, -G, -Gm, -S, -C, -P, -O, -L, -I, -N, --local-auth,
--keep, -v) are also listed for parser safety.

### Happy-path cases — last positional shape match

| #  | Command (binary `enum4linux-ng` omitted) | Expected target | Notes |
|----|---|---|---|
| 1  | `-A -oY /session/out 10.10.10.5` | `10.10.10.5` | Vanilla -A null-session |
| 2  | `-A -u admin -p 'pass' -oY /session/out 10.10.10.5` | `10.10.10.5` | Authenticated -A |
| 3  | `-U -u guest -p '' 10.10.10.5` | `10.10.10.5` | Single-module probe |
| 4  | `-S -u admin -p 'p' -oY /session/shares 10.10.10.5` | `10.10.10.5` | Shares only |
| 5  | `-R -r 500-2000 -u guest -p '' 10.10.10.5` | `10.10.10.5` | RID brute — `-r 500-2000` value with hyphen |
| 6  | `-A -u admin -p 'p' -w corp.local -oY /session/out 10.10.10.5` | `10.10.10.5` | -w workgroup is FQDN-shape; value_flag defends |
| 7  | `-A -u admin@corp.local -p 'p' -oY /session/out 10.10.10.5` | `10.10.10.5` | -u value is UPN form (FQDN-shape); value_flag defends |
| 8  | `-A -K /session/admin.ccache -u admin -oY /session/out 10.10.10.5` | `10.10.10.5` | -K ccache path; not target-shape |
| 9  | `-A -H 31d6cfe0d16ae931b73c59d7e0c089c0 -u admin -oY /session/out 10.10.10.5` | `10.10.10.5` | -H NTLM hash; 32-hex doesn't shape-match |
| 10 | `-A -oY /session/out dc01.corp.local` | `dc01.corp.local` | FQDN target — dotted shape |
| 11 | `-A -oY /session/out dc.hercules.htb` | `dc.hercules.htb` | FQDN with .htb TLD |
| 12 | `-A -oY /session/out [fe80::1]` | `[fe80::1]` | Bracketed IPv6 (rule 2 fallback) |
| 13 | `-Gm -u admin -p 'p' -oY /session/gm 10.10.10.5` | `10.10.10.5` | -Gm groups+members |
| 14 | `-L -u '' -p '' 10.10.10.5` | `10.10.10.5` | LDAP DC probe |

### Adversarial — value-flag traps (passwords / usernames / workgroups that LOOK like targets)

| #  | Command | Expected | Notes |
|----|---|---|---|
| 15 | `-A -u admin -p '10.10.10.99' 10.10.10.5` | `10.10.10.5` | Password is IP-shape! -p in value_flags consumes it atomically. |
| 16 | `-A -u admin -p 'ftp://other.target/' 10.10.10.5` | `10.10.10.5` | Password contains URL with hostname; -p value_flag consumes whole quoted string. |
| 17 | `-A -u 'admin@dc01.corp.local' -p 'p' 10.10.10.5` | `10.10.10.5` | -u UPN form (admin@dc01.corp.local); FQDN-shape value MUST NOT be picked. -u in value_flags. |
| 18 | `-A -w other.corp.local -u admin -p 'p' 10.10.10.5` | `10.10.10.5` | -w workgroup `other.corp.local` looks FQDN-shape; -w in value_flags. |
| 19 | `-R -r 500-1100,5000-5100 -u guest -p '' 10.10.10.5` | `10.10.10.5` | -r value contains digits-and-hyphens-and-commas; doesn't shape-match target regex AND -r in value_flags. |
| 20 | `-R -r 500-1100 -u guest -p '' -oY /session/rid 10.10.10.5` | `10.10.10.5` | Same as 19 with output flag interleaved. |
| 21 | `-A -k 'administrator,guest,krbtgt' -u admin -p 'p' 10.10.10.5` | `10.10.10.5` | -k CSV user list; not target-shape but value_flag defends. |
| 22 | `-A -t 30 -u admin -p 'p' 10.10.10.5` | `10.10.10.5` | -t timeout is integer; -t in value_flags. |
| 23 | `-A -u admin -p 'p' -oA /session/full-out 10.10.10.5` | `10.10.10.5` | -oA output prefix path; -oA in value_flags. |
| 24 | `-A -u admin -p 'p' -oJ /session/json-out 10.10.10.5` | `10.10.10.5` | -oJ JSON prefix path; -oJ in value_flags. |

### Adversarial — security invariants & ambiguity

| #  | Command | Expected | Notes |
|----|---|---|---|
| F1 | `--help` | `target=null` | Help — no positional; tool runner bypasses scope check. |
| F2 | `-h` | `target=null` | Short alias. |
| F3 | (no args) | `target=null` | argparse exits with required-positional error. |
| F4 | `-A` | `target=null` | -A only, no host — argparse error. |
| F5 | `-A 10.10.10.0/24` | `10.10.10.0/24` | CIDR-shape — passes regex but enum4linux-ng will REJECT at runtime (not a valid host). `allow_multi_target: false` permits this through scope but the binary will fail. **Known DSL gap** (Open Question 2). |
| F6 | `-A 10.10.10.5,10.10.10.6` | `target=null` | Comma-list — fails the target shape regex (commas inside positional). enum4linux-ng has no list form. |
| F7 | `-A localhost` | `target=null` | `localhost` has NO dots — fails the FQDN regex. **Known DSL gap** (Open Question 1) — same issue as netexec / ike-scan. |
| F8 | `-R 1000 10.10.10.5` | `10.10.10.5` | `-R` with explicit BULK_SIZE 1000. `-R` is BOOLEAN in our value_flags; `1000` is a separate argv token but doesn't shape-match the target regex (digits only). Last positional is `10.10.10.5`. **Edge case** — see Open Question 4. |
| F9 | `-R 10.10.10.5` | `10.10.10.5` | `-R` with NO BULK_SIZE — host directly after. `-R` boolean → `10.10.10.5` is last positional, parses correctly. |
| F10| `-A -u admin -p '' --local-auth 10.10.10.5` | `10.10.10.5` | --local-auth is boolean; in value_flags as boolean for parser safety. |

---

## 4. Failure-signature live-verify cases (6 total, ≥3 spec)

Verify against the enum4linux-ng container (rebuild during Wave 9 batch
with mcp-common 0.3.0 and python3-full base — Dockerfile fix landed
today).

Layer diversity (SKILL #11) — 6 distinct verifiable layers represented in
`tool.yaml`'s `failure_signatures`. Live-verify the most common 6 below.

| # | Layer | Test | failure_signature `signal` | Status |
|---|---|---|---|---|
| 1 | DNS | `enum4linux-ng -A nonexistent.invalid` | `Could not resolve` OR `Name or service not known` | PENDING live verify (Wave 9) |
| 2 | TCP | `enum4linux-ng -A 127.0.0.1` (no SMB on loopback) | `Connection refused` OR `do_connect: Connection` | PENDING live verify |
| 3 | SMB / NTLM disabled | `enum4linux-ng -A -u natalie.a -p 'Prettyprincess123!' 10.129.242.196` (Hercules NTLM disabled) | `Server doesn't allow connection` | PENDING live verify — UNIQUE to AD targets and worth surfacing |
| 4 | SMB / wrong creds | `enum4linux-ng -A -u nonexistent -p 'wrong' <smb-target>` (any reachable SMB host with NTLM enabled) | `STATUS_LOGON_FAILURE` OR `Could not establish session` | PENDING live verify |
| 5 | RPC / access denied | `enum4linux-ng -U -u guest -p '' <hardened-DC>` (DC blocking SAMR-OPEN-USER but allowing null connect) | `STATUS_ACCESS_DENIED` OR `RPC_S_ACCESS_DENIED` | PENDING live verify |
| 6 | argparse | `enum4linux-ng --no-such-flag 10.10.10.5` | `error: unrecognized arguments` OR `error: argument` | PENDING live verify |

### Layer diversity (SKILL #11) — achieved

6 distinct verifiable layers documented in `failure_signatures`:
1. **DNS** (case 1)
2. **TCP** (case 2)
3. **SMB / NTLM** (case 3 — NTLM disablement; case 4 — wrong creds)
4. **RPC** (case 5 — STATUS_ACCESS_DENIED, RPC_S_ACCESS_DENIED, RPC_NT_ACCESS_DENIED, RPC_NT_LOGON_FAILURE, RPC_S_NO_INTERFACES_REGISTERED, BIND request rejected)
5. **argparse** (case 6 — argument validation, mutually-exclusive auth-flag error)
6. **Kerberos** (KDC_ERR_PREAUTH_FAILED / KRB_AP_ERR_SKEW / KDC_ERR_S_PRINCIPAL_UNKNOWN — encoded; live-verifiable when -K is used with a stale ccache or wrong realm)

### Signals encoded but not yet live-verified

`STATUS_BAD_NETWORK_NAME` (only fires with -s SHARES_FILE which is
REJECTED), `STATUS_NOT_SUPPORTED`, `Connection error`, `Aborting
remainder of tests` (catch-all — read line above for actual cause),
`error: the following arguments are required`, `not allowed with
argument` (mutually-exclusive auth — `-p` and `-K` both passed),
KDC_ERR_*, KRB_AP_ERR_SKEW.

These exercise post-pilot when corresponding misconfigurations /
scenarios are reproducible.

---

## 5. Open questions

1. **`localhost` and bare-token hostnames (case F7)** — the FQDN regex
   in fallback rule 2 requires at least one dot, and
   `last_non_flag_positional` extracts whatever comes last regardless of
   shape. So `enum4linux-ng -A localhost` extracts `localhost` via rule 1
   correctly — actually NOT a gap for enum4linux-ng (it IS a gap for
   netexec because netexec's positional_match-only chain requires
   shape-match). **Verify in Wave 9** that `last_non_flag_positional`
   captures `localhost` cleanly (it should — no shape filter on rule 1).

2. **CIDR / list rejection (case F5, F6)** — enum4linux-ng has no list
   or CIDR support. The DSL's `last_non_flag_positional` will happily
   capture `10.10.10.0/24` (regex permits the slash) but the binary
   will fail at runtime with a Samba-tool error. `allow_multi_target:
   false` is set, but multi_target_detected only fires on MULTIPLE
   positionals — a single CIDR token doesn't trigger it. **Recommendation**:
   add a downstream binary-validity check in cli_in_container that
   short-circuits known-invalid host shapes (CIDR for tools without
   `allow_multi_target`). Plugin Phase 2.

3. **`-R [BULK_SIZE]` optional-value ambiguity (case F8)** — `-R`'s
   argparse signature is `-R [BULK_SIZE]`, where BULK_SIZE is OPTIONAL.
   We chose to treat `-R` as BOOLEAN in value_flags (NOT value-taking).
   This means:
     - `enum4linux-ng -R 10.10.10.5` (no BULK_SIZE) → host is last
       positional → CORRECT.
     - `enum4linux-ng -R 1000 10.10.10.5` (with BULK_SIZE) → `1000` is
       loose positional, `10.10.10.5` is last positional → CORRECT
       (1000 doesn't shape-match the target regex).
     - `enum4linux-ng -R 10.10.10.5` (no BULK_SIZE) but the LLM intended
       BULK_SIZE=10.10.10.5 → IMPOSSIBLE: enum4linux-ng would parse
       BULK_SIZE as `int`, not IP. So no real ambiguity at the binary
       level; only at the DSL parsing layer.

   **Recommendation**: keep `-R` as boolean in value_flags. **Open**: if
   future versions of enum4linux-ng make `-R` value-mandatory, revisit.

4. **`-d` is BOOLEAN but listed in value_flags defensively** —
   enum4linux-ng v1.3.4 has `-d` as a pure boolean (detailed enum,
   applies to -U/-G/-R). We listed it in `value_flags` as a defensive
   measure in case future versions add a value form. The DSL skips
   `-d` harmlessly when no value follows; if a future version makes it
   value-taking, the spec is correct already. **Recommendation**: revisit
   if upstream changes `-d`.

5. **Output prefix vs file extension** — `-oJ <PREFIX>` writes to
   `<PREFIX>.json` (extension auto-appended); same for `-oY` (.yaml)
   and `-oA` (both). The LLM might accidentally pass
   `-oY /session/out.yaml`, which would write `/session/out.yaml.yaml`
   (double extension). **Recommendation**: document in gotchas (done) and
   in usage_patterns commands (done — all examples pass extensionless
   prefixes).

6. **`-K TICKET_FILE` Kerberos ccache flow** — when `-K` is used,
   enum4linux-ng inherits Samba's behavior of checking `KRB5CCNAME` env
   first. The kind:cli image's entrypoint.sh wires KRB5CCNAME if the
   client sets it. For multi-step flows (impacket-getTGT writes ccache,
   then enum4linux-ng `-K`), the SAME /session/ mount is required.
   **Recommendation**: document as gotcha (done — see usage_patterns
   "Kerberos ticket auth").

7. **Mutually-exclusive auth flags** — `-p`, `-K`, `-H` form a Python
   argparse `mutually_exclusive_group`. Passing two produces `argument
   -K: not allowed with argument -p`. Encoded in failure_signatures as
   `not allowed with argument`. Live-verify in Wave 9.

8. **`-s SHARES_FILE` rejection** — share-name brute-force wordlist file
   is REJECTED via reject_flags. `-S` (RPC share enum) is the
   replacement — queries server's share list directly. **Verify in Wave
   9**: confirm cli_in_container.ts honors reject_flags for `-s`.

9. **No `--smb-port` flag** — original enum4linux.pl had `--smb-port`;
   v1.3.4 does NOT. The Samba sub-tools auto-discover (try 445, fall
   back to 139). For non-standard SMB ports, the agent must use
   impacket-smbclient or netexec --port. Documented in gotchas.

10. **`-A` does NOT include `-R` or `-Gm`** — common user
    misunderstanding. `-A` is the SAFE simple-enum bundle: `-U -G -S -P
    -O -N -I -L`. To include RID brute, add `-R`. To include group
    members, add `-Gm`. Documented in gotchas + usage_patterns.

11. **Recipe system retirement** — the original mcp-server.py (preserved
    for legacy method calls) loads dynamic recipes from
    `/session/tool_recipes/enum4linux-ng/` (Feature 28). With kind:cli,
    the LLM writes argv directly and recipes are dead code under the
    run_cli path. Recipes still load for legacy method calls if the
    directory exists. Per REQ-TR-016, this is RETIRED for kind:cli.
    Documented in gotchas — done.

12. **Error classification gradient lost in kind:cli** — the legacy
    `_classify_enum_error()` produced a structured `(error_class,
    retryable, suggestions)` tuple distinguishing auth (STATUS_LOGON_FAILURE
    / LOGON_FAILURE / Could not establish session) from network (Aborting
    + connection refused / timed out) from auth-perm (Aborting +
    STATUS_ACCESS_DENIED) from params (usage error). Crucially the legacy
    code checks AUTH signals BEFORE the `Aborting remainder of tests`
    keyword, because partial port-level connection refusals during a
    failed auth produce both signals — auth-first-precedence avoids
    misclassifying credential failures as transport failures. Under
    kind:cli the agent reads raw stdout/stderr and must apply this same
    precedence manually. Encoded as a gotcha; the agent prompt should
    surface this when triaging enum failures.

13. **ANSI escape codes in default text output** — enum4linux-ng emits
    colourful section banners with `\x1b[...m` codes. Regex grep on raw
    stdout for `STATUS_*` / `Aborting...` / `Server doesn't allow
    connection` works ONLY after stripping ANSI (the legacy code does
    `re.sub(r"\x1b\[[0-9;]*m", "", output)`). Easier: always pass
    `-oY <prefix>` and parse the YAML — the structured output is ANSI-free.
    Encoded as a gotcha.

14. **`enum_policy` legacy uses `-P -I` not `-P`** — the legacy
    `enum_policy` method invokes `-P -I` together (policy + printer
    info), NOT `-P` alone. The `-I` flag pulls additional `srvinfo` /
    domain attributes that the legacy method exposes as `domain_info`.
    Under kind:cli the agent should call `enum4linux-ng -P -I -oY ...`
    when matching the legacy semantic; usage_patterns documents `-P`
    alone (still valid, but narrower). Encoded as a gotcha.

15. **Success probe is `sessions_possible` in JSON/YAML output** — the
    legacy code returns success=False when output shows `Aborting
    remainder of tests` AND parsed JSON has `sessions_possible == false`
    (or missing). When consuming `-oJ`/`-oY` output under kind:cli, the
    agent should check this same key to determine whether enum4linux-ng
    actually established a session. Just checking exit code (0) is
    insufficient — exits 0 on transport failure too. Encoded as a gotcha.

16. **No automatic output cleanup under kind:cli** — legacy methods
    `_cleanup_json_files` removed both the temp prefix and the
    auto-suffixed `.json` file after every call. Under kind:cli the
    output file at `/session/<prefix>.yaml` persists indefinitely. The
    agent must pick distinct prefixes per call (e.g., timestamp or
    target IP suffix) to avoid silent overwrite. Encoded as a gotcha.

---

## 6. Hand-off

- **Tool**: enum4linux-ng (kind:cli, single binary `enum4linux-ng`,
  Python rewrite of enum4linux.pl). Argv form: `enum4linux-ng [flags]
  <host>`. Single positional, no list / CIDR / file form.
- **Status**: tool.yaml authored end-to-end (kind:mcp + kind:cli);
  scenarios.md written. **Dockerfile EDITED** — `python3 / python3-pip /
  python3-venv` replaced with `python3-full` (Kali-rolling-friendly per
  Wave 6 convention). libfaketime retained (Kerberos clock-skew defence
  — enum4linux-ng's `-K` path needs it on hardened DCs).
- **mcp-server.py UNTOUCHED** — auto-inherits `run_cli` from
  BaseMCPServer (mcp-common 0.3.0); existing per-method handlers
  (`enumerate`, `enum_users`, `enum_shares`, `enum_groups`,
  `enum_policy`) preserved as the legacy / rollback path per SKILL #21.
  The methods carry rich error classification (network vs auth vs perm)
  via `_classify_enum_error()` that's NOT reconstructible from raw
  stdout — agents that want classified errors still call `mcp_tool
  enum4linux-ng enumerate ...` rather than `cli_in_container
  enum4linux-ng -A ...`. Both paths coexist.
- **Image**: `ghcr.io/silicon-works/mcp-tools-enum4linux-ng:latest` —
  needs rebuild during Wave 9 batch to pick up mcp-common 0.3.0 AND the
  python3-full base. Image size unchanged (~150 MB — Kali enum4linux-ng
  + smbclient + libfaketime).
- **target_extraction = TWO rules**: `last_non_flag_positional` (rule 1
  — captures host even when flag values interleave) + `positional_match`
  shape-regex fallback (rule 2 — defensive for IPv4 / FQDN / bracketed
  IPv6 in host-first ordering). Mirror of ike-scan's pattern.
- **value_flags**: ~25 entries — every auth flag (-u/-p/-K/-H/--local-auth),
  every workgroup flag (-w), every RID-tuning flag (-R/-r/-k), every
  output flag (-oJ/-oY/-oA), every timeout flag (-t), and every boolean
  enum module flag (-A/-As/-U/-G/-Gm/-S/-C/-P/-O/-L/-I/-N/-d/--keep/-v)
  for parser safety.
- **reject_flags**: `-s` (share-name brute-force wordlist file). Use
  `-S` (RPC share enum) instead. `-iL` / `--target-file` /
  `--input-file` do NOT exist in enum4linux-ng — no host-list
  rejection needed.
- **allow_multi_target: false** — single host per call. CIDR / list /
  file forms unsupported by the binary.
- **Wave 6.4**: FINAL tool of Wave 6 (AD enumeration cluster — completed
  with smtp / snmp / ike-scan / enum4linux-ng). Tier A migration
  progress: 24 tools done after this (curl, sqlmap, impacket, nmap,
  ffuf, nuclei, nikto, john, hashcat, kerbrute, hydra, ssti,
  git-dumper, netexec, certipy, bloodyad, pygpoabuse, mysql, mssql,
  smtp, snmp, ike-scan, enum4linux-ng).
- **Live-verify pending**: paste S1-S8 against Active / Hercules /
  Forest during Wave 9 batch rebuild + e2e run. Verify failure
  signatures 1-6 live; verify target-extraction cases 1-24 + F1-F10
  with plugin unit tests. Confirm `last_non_flag_positional` captures
  `localhost` (Open Question 1). Confirm `-R [BULK_SIZE]` ambiguity
  cases F8/F9 parse correctly.
- **Files removed**: `__pycache__/` (build artefact, not in git but
  present on disk — removed). NO `target_extraction_tests.md` and NO
  `failure_signature_tests.md` ever existed for enum4linux-ng —
  directory was already on the simpler layout.

Authored: 2026-04-25 (Wave 6.4 — final tool of Wave 6).
