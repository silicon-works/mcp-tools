# bloodyad — Tier A scenarios

Single test sheet for the `bloodyad` tool migration (Wave 4.3 — third tool of
Wave 4, AD post-exploitation cluster after netexec and certipy).

bloodyAD is a single binary `bloodyAD` (CASE-SENSITIVE — capital `A` and `D`,
NOT `bloodyad`) with **action-based architecture**:

```
bloodyAD --host <DC> -d <DOMAIN> -u <USER> -p <PASS> <action> [sub-action] [args]
```

Five top-level actions (`add`, `get`, `set`, `remove`, `commit`). Each action
has a sub-action positional (e.g., `add user`, `get search`, `set password`,
`remove groupMember`). Many sub-actions take FURTHER positionals (e.g., `add
user <name> <pwd>` has 2 more; `set password <user> <new>` has 2 more; `set
rbcd <target> <delegate>` has 2 more). The legacy MCP server (mcp-server.py,
1649 LOC) exposes 27 methods covering 8 add / 7 get / 3 set / 9 remove
sub-actions.

Structurally similar to certipy (Wave 4.2) and netexec (Wave 4.1) — single
binary with sub-commands. **Critically different from certipy / netexec**:
bloodyAD has TWO levels of positional dispatch (action AND sub-action), and
some sub-actions take 2-4 further positional args (object name, value, etc.).
The DSL's `flag_value`-only target extraction must correctly skip ALL of these
positionals. **There is NO positional target — the DC is always `--host`.**

Sections:
1. Recommended HTB box for live verification
2. Narrative scenarios (paste into opensploit)
3. Target-extraction adversarial cases (≥20 — total 24)
4. Failure-signature live-verify cases (≥3 — total 6)
5. Open questions
6. Hand-off

---

## 1. Recommended HTB box

**Hercules (10.129.242.196)** — listed in registry as the canonical AD lab box
for ACL/RBCD/shadow-credentials operations. Verify availability for the wave
since HTB rotates retired boxes.

**Note**: bloodyAD requires WRITE access on AD objects to be useful for the
modify operations (`set password`, `add groupMember`, `add genericAll`, `set
rbcd`, `add shadowCredentials`, etc.). For READ-ONLY enumeration (`get
writable`, `get search`, `get object`, `get membership`, `get children`, `get
dnsDump`, `get trusts`), any authenticated user works — these run against any
AD lab.

**Boxes that historically had bloodyAD-friendly ACL paths:**
- **Hercules** — canonical (current registry entry).
- **Garfield** — Shadow Credentials path; closed engagement (Garfield in
  memory notes — `_check_shadow` was added specifically for this).
- **Pirate** — Windows DC per pirate-htb-insights.md; some ACL paths but
  bloodyAD wasn't the primary tool there (impacket-relay was).

**Documented gap (Open Question 6)**: bloodyAD live-verify on read-only ops
runs anywhere with valid creds; modify ops need a deliberately-misconfigured
ACL. For this migration, target_extraction and command-shape audits are done
via plugin unit tests; runtime behaviour is verified post-pilot against
Hercules during Wave 9 batch rebuild.

**Persistent test directory**: mount `/tmp/bloodyad-test:/session` (per
SKILL #14). Multi-step flows (add computer → set rbcd → impacket getST) need
the same working dir across calls so the machine credential and any captured
ccache are visible to the next bloodyAD invocation.

---

## 2. Narrative scenarios (paste into opensploit)

### S1 — get writable (find ACL escalation paths)

```
Engagement target: <DC IP> with valid AD credentials (authorized AD lab).
Use bloodyAD --host <DC IP> -d corp.local -u auditor -p 'P@ss123' get writable to enumerate every AD object the auditor account has WRITE access on. Report any USER, COMPUTER, or GROUP entries — these are direct privesc paths.
```

**Watch:** target=`<DC IP>` extracted via flag_value rule 1 (`--host`). The
action `get` is positional 1 and sub-action `writable` is positional 2 — both
correctly NOT extracted as targets. Output is plain text with `[+]` and `[-]`
prefixes, listing each writable object's DN, attribute, and right.

### S2 — get search with LDAP filter (DONT_REQ_PREAUTH enumeration)

```
Engagement target: <DC IP> with valid AD credentials (authorized AD lab).
Find all users with DONT_REQ_PREAUTH set (UF_DONT_REQUIRE_PREAUTH bit, value 4194304) — these are AS-REP roastable. Use bloodyAD --host <DC IP> -d corp.local -u auditor -p 'P@ss123' get search --filter '(&(objectClass=user)(userAccountControl:1.2.840.113556.1.4.803:=4194304))' --attr sAMAccountName.
```

**Watch:** target=`<DC IP>`. Action `get`, sub-action `search` — both
positionals correctly skipped. The `--filter` value contains parens, colons,
and dots (FQDN-shape numeric OID `1.2.840.113556.1.4.803`) but is consumed
atomically by the `--filter` value_flag. The output is a list of
sAMAccountNames suitable for impacket GetNPUsers.py.

### S3 — set password (ForceChangePassword privesc)

```
Engagement target: <DC IP> with valid AD credentials (authorized AD lab). Auditor has ForceChangePassword on victim user.
Reset the victim's password to a known value. Use bloodyAD --host <DC IP> -d corp.local -u auditor -p 'P@ss123' set password victim 'NewPass2026!'.
```

**Watch:** target=`<DC IP>`. Action `set`, sub-action `password`, then TWO
further positionals (`victim` is a sAMAccountName, `'NewPass2026!'` is the new
password). The DSL must NOT pick `victim` or the new password as a target.
After success, validate via `netexec ldap <DC> -u victim -p 'NewPass2026!'`.

### S4 — add groupMember (Domain Admins membership)

```
Engagement target: <DC IP> with valid AD credentials (authorized AD lab). Auditor has Write on 'Domain Admins' member list.
Add the auditor account to Domain Admins. Use bloodyAD --host <DC IP> -d corp.local -u auditor -p 'P@ss123' add groupMember 'Domain Admins' auditor.
```

**Watch:** target=`<DC IP>`. Action `add`, sub-action `groupMember`, then two
further positionals (`'Domain Admins'` and `auditor`). The single-quoted group
name is one argv token. After success, the new membership applies on next TGT
request — agent purges existing tickets and re-authenticates as auditor.

### S5 — add shadowCredentials (msDS-KeyCredentialLink abuse)

```
Engagement target: <DC IP> with valid AD credentials (authorized AD lab). Auditor has Write on victim's msDS-KeyCredentialLink.
Add a key credential to victim, dropping the PEM at /session/victim-shadow.pem. Use bloodyAD --host <DC IP> -d corp.local -u auditor -p 'P@ss123' add shadowCredentials --path /session/victim-shadow.pem victim.
```

**Watch:** target=`<DC IP>`. Action `add`, sub-action `shadowCredentials`,
flag `--path /session/victim-shadow.pem` (value_flag), positional `victim`.
The PEM contains the key+cert pair for PKINIT auth. NB: bloodyAD generates
the local key BEFORE the LDAP modify is attempted — `[+] KeyCredential
generated` followed by `insufficientAccessRights` is the partial-failure trap
(documented in `_check_shadow` in mcp-server.py line 1151). Treat as FAILED
unless the final line is the success marker.

### S6 — set rbcd (RBCD chain — set msDS-AllowedToActOnBehalfOfOtherIdentity)

```
Engagement target: <DC IP> with valid AD credentials (authorized AD lab). Attacker controls FAKEPC$ machine account (created via add computer); has Write on TARGETPC$'s msDS-AllowedToActOnBehalfOfOtherIdentity.
Configure RBCD: set bloodyAD --host <DC IP> -d corp.local -u attacker -p 'P@ss123' set rbcd 'TARGETPC$' 'FAKEPC$'.
```

**Watch:** target=`<DC IP>`. Action `set`, sub-action `rbcd`, then two
machine-account positionals with trailing `$`. The `$` must be inside the
single-quoted argv token. Followed by impacket's getST -impersonate
administrator to obtain a service ticket as administrator on TARGETPC.

### S7 — Kerberos pass-the-ticket (-k with KRB5CCNAME)

```
Engagement target: dc01.corp.local (DC FQDN — REQUIRED for Kerberos SPN resolution; authorized AD lab). KRB5CCNAME=/session/credentials/auditor.ccache pre-set in container env.
Use bloodyAD --host dc01.corp.local -d corp.local -u auditor -k get search --filter '(objectClass=user)' --attr sAMAccountName to bind via Kerberos pass-the-ticket and list all users.
```

**Watch:** target=`dc01.corp.local` extracted via `--host`. The `-k` is BARE
BOOLEAN — DO NOT pass a ccache path inline (bloodyAD's argparse nargs='*' on
-k would greedily consume the action token). The ccache is supplied via
`KRB5CCNAME` env var. The `-d corp.local` value is FQDN-shape but consumed by
the `-d` value_flag. NB: --host MUST be FQDN for Kerberos SPN resolution; with
IP, KDC_ERR_S_PRINCIPAL_UNKNOWN.

### S8 — PKINIT certificate auth (-c after certipy)

```
Engagement target: <DC IP> with valid PFX from certipy (authorized AD lab). PFX previously split into /session/admin.key and /session/admin.crt via certipy cert.
Use bloodyAD --host <DC IP> -d corp.local -u administrator -c '/session/admin.key:/session/admin.crt' get writable to authenticate via PKINIT and dump the writable set as administrator.
```

**Watch:** target=`<DC IP>`. The `-c` value `/session/admin.key:/session/admin.crt`
contains a colon SEPARATOR (not shell syntax — internal to the value_flag).
Single-quoted to keep the entire pair as one argv token. Plugin's `-c`
value_flag consumes atomically.

### S9 — failure: DNS unreachable

```
Engagement target: invalid-dc-name.invalid.localdomain (deliberately wrong).
Use bloodyAD --host invalid-dc-name.invalid.localdomain -d corp.local -u auditor -p 'P@ss123' get writable.
```

**Watch:** target=`invalid-dc-name.invalid.localdomain` extracted. DNS lookup
fails; output contains `Could not resolve` or `Name or service not known`.
Failure classified via signature.

### S10 — failure: connection refused (TCP layer)

```
Engagement target: 127.0.0.1 (intentionally wrong target — no LDAP on localhost).
Use bloodyAD --host 127.0.0.1 -d corp.local -u auditor -p 'P@ss123' get writable.
```

**Watch:** target=`127.0.0.1`. LDAP TCP connect to 389 fails with
`Connection refused`. Failure classified.

### S11 — failure: insufficient access rights (modify denied)

```
Engagement target: <DC IP> with low-privilege creds (authorized AD lab). Auditor does NOT have ForceChangePassword on victim.
Use bloodyAD --host <DC IP> -d corp.local -u auditor -p 'P@ss123' set password victim 'NewPass!' to attempt password reset that will be denied.
```

**Watch:** target=`<DC IP>`. Output contains `insufficientAccessRights` or
`INSUFF_ACCESS_RIGHTS`. The bind succeeds, but the LDAP modify fails for
permission. Failure classified; agent remediation: re-run `get writable
--otype USER` to discover what the auditor CAN modify.

---

## 3. Target-extraction adversarial cases (24 total, ≥20 spec)

The bloodyad `tool.yaml` declares TWO `target_extraction` rules (first match
wins, both `flag_value` — NO positional rules):

1. `flag_value` for `--host` (parse_as: raw) — REQUIRED for all DC-bound
   operations. Most explicit.
2. `flag_value` for `--dc-ip` (parse_as: raw) — IP override fallback when
   `--host` is an unresolvable hostname.

NO `positional_match` rule. The action positionals (`add`, `get`, `set`,
`remove`) are positional 1, sub-action positionals (`user`, `computer`,
`groupMember`, `password`, `rbcd`, `genericAll`, `shadowCredentials`,
`dnsRecord`, etc.) are positional 2, and operation arg positionals (target
sAMAccountName, group name, password value, attribute name) follow. NONE are
targets.

`value_flags` declares ~30 entries — every flag whose value could shape-match
a host (`--host`, `--dc-ip`, `--filter`, `--attr`, `--ou`, `--path`, etc.)
plus boolean flags listed defensively (`-k`, `-s`, `-v`, `--detail`,
`--direct`, `--no-recurse`, `--resolve-sd`, `--no-detail`, `--transitive`,
`--forest`).

### Happy-path cases — flag_value extraction

| #  | Command (binary `bloodyAD` omitted) | Expected target | Notes |
|----|---|---|---|
| 1  | `--host 10.10.10.5 -d corp.local -u auditor -p 'P@ss123' get writable` | `10.10.10.5` | basic --host (rule 1) |
| 2  | `--host dc01.corp.local -d corp.local -u auditor -p 'P@ss123' get writable` | `dc01.corp.local` | --host with FQDN |
| 3  | `--host DC01 -d corp.local -u auditor -p 'P@ss123' --dc-ip 10.10.10.5 get writable` | `DC01` | --host wins over --dc-ip (rule 1 before rule 2) |
| 4  | `--host dc01.corp.local --dc-ip 10.10.10.5 -d corp.local -u auditor -p 'P@ss123' -k get writable` | `dc01.corp.local` | --host + --dc-ip + -k Kerberos; --host wins |
| 5  | `--host 10.10.10.5 -d corp.local -u auditor -p 'P@ss123' set password victim 'NewPass!'` | `10.10.10.5` | set password 4-positional (action + sub + 2 args); only --host extracted |
| 6  | `--host 10.10.10.5 -d corp.local -u auditor -p 'P@ss123' add groupMember 'Domain Admins' auditor` | `10.10.10.5` | add groupMember 4-positional (action + sub + 2 args); 'Domain Admins' has space; only --host extracted |
| 7  | `--host 10.10.10.5 -d corp.local -u auditor -p 'P@ss123' set rbcd 'TARGETPC$' 'FAKEPC$'` | `10.10.10.5` | set rbcd; trailing-$ machine accounts NOT picked as targets |
| 8  | `--host 10.10.10.5 -d corp.local -u auditor -p 'P@ss123' add user newuser 'NewUserPass!' --ou 'OU=Users,DC=corp,DC=local'` | `10.10.10.5` | add user 4-positional + --ou flag with DN value |
| 9  | `--host 10.10.10.5 -d corp.local -u auditor -p 'P@ss123' get search --filter '(&(objectClass=user)(userAccountControl:1.2.840.113556.1.4.803:=4194304))' --attr sAMAccountName` | `10.10.10.5` | get search with complex filter (parens, colons, dots, OID) — value_flag consumes |
| 10 | `--host 10.10.10.5 -d corp.local -u admin -c '/session/admin.key:/session/admin.crt' get writable` | `10.10.10.5` | -c PKINIT cert with internal colon separator (value_flag consumes whole pair) |

### Adversarial — value-flag traps (FQDN/IP-shape values that could be picked)

| #  | Command | Expected | Notes |
|----|---|---|---|
| 11 | `--host 10.10.10.5 -d corp.local -u auditor@corp.local -p 'P@ss123' get writable` | `10.10.10.5` | UPN `auditor@corp.local` is FQDN-shape; -u value_flag consumes atomically |
| 12 | `--host 10.10.10.5 -d corp.local -u auditor -p ':31d6cfe0d16ae931b73c59d7e0c089c0' get writable` | `10.10.10.5` | -p with PtH `:NTHASH` (leading colon); -p value_flag consumes |
| 13 | `--host 10.10.10.5 -d corp.local -u auditor -p 'P@ss123' add dnsRecord pwned.corp.local 1.2.3.4` | `10.10.10.5` | add dnsRecord positionals: name `pwned.corp.local` is FQDN-shape, data `1.2.3.4` is IP-shape — NEITHER picked (no positional rule) |
| 14 | `--host 10.10.10.5 -d corp.local -u auditor -p 'P@ss123' get search --filter '(objectClass=user)' --base 'CN=Users,DC=corp,DC=local'` | `10.10.10.5` | --base value is DN with embedded commas; value_flag consumes |
| 15 | `--host 10.10.10.5 -d corp.local -u auditor -p 'P@ss123' get object 'CN=victim,CN=Users,DC=corp,DC=local' --attr memberOf` | `10.10.10.5` | get object with DN positional containing dots and commas — NOT picked (no positional rule) |
| 16 | `--host 10.10.10.5 -d corp.local -u auditor -p 'P@ss123' add shadowCredentials --path /session/victim-shadow.pem victim` | `10.10.10.5` | --path with file path containing dots; --path value_flag consumes; positional `victim` not picked |
| 17 | `--host 10.10.10.5 -d corp.local -u auditor -p 'P@ss123' set object 'CN=victim,CN=Users,DC=corp,DC=local' servicePrincipalName -v http/web.corp.local` | `10.10.10.5` | -v positional value `http/web.corp.local` (FQDN-shape with /) — NOT picked |
| 18 | `--host 10.10.10.5 -d corp.local -u auditor -p 'P@ss123' add uac victim -f DONT_REQ_PREAUTH` | `10.10.10.5` | -f UAC flag value `DONT_REQ_PREAUTH`; -f value_flag consumes |

### Adversarial — security invariants & ambiguity

| #  | Command | Expected | Notes |
|----|---|---|---|
| F1 | `--help` | `target=null` | Top-level help. Tool runner bypasses scope. |
| F2 | `-h` | `target=null` | Short alias. |
| F3 | `add --help` | `target=null` | Per-action help. |
| F4 | `get --help` | `target=null` | Per-action help. |
| F5 | `set --help` | `target=null` | Per-action help. |
| F6 | `remove --help` | `target=null` | Per-action help. |
| F7 | `get search --help` | `target=null` | Per-sub-action help. |
| F8 | `-d corp.local -u auditor -p 'P@ss123' get writable` | `target=null` | Missing --host — argparse rejects but extraction returns null which is correct (no flag_value match, no positional fallback). |
| F9 | `--host 10.10.10.5 --dc-ip 192.168.1.10 -d corp.local -u auditor -p 'P@ss123' get writable` | `10.10.10.5` | Both --host and --dc-ip present; --host wins (rule 1 before rule 2). **Security invariant**: --host is the operational target; --dc-ip is a DNS hint. |

(Total: 24 cases, ≥20 spec — 18 happy/adversarial value-flag cases + 6
help/security-invariant cases. Some help variants combined.)

---

## 4. Failure-signature live-verify cases (6 total, ≥3 spec)

Verify against the bloodyad container (rebuild during Wave 9 batch with
mcp-common 0.3.0 and python3-full base — Dockerfile fix landed today).

Layer diversity (SKILL #11) — 7 distinct verifiable layers represented in
`tool.yaml`'s `failure_signatures`. Live-verify the most common 6 below.

| # | Layer | Test | failure_signature `signal` | Status |
|---|---|---|---|---|
| 1 | DNS | `bloodyAD --host nonexistent.invalid -d corp.local -u u -p p get writable` | `Could not resolve` OR `Name or service not known` | PENDING live verify (Wave 9) |
| 2 | TCP | `bloodyAD --host 127.0.0.1 -d corp.local -u u -p p get writable` (no LDAP on localhost) | `Connection refused` | PENDING live verify |
| 3 | LDAP bind / NTLM | `bloodyAD --host <DC IP> -d corp.local -u nonexistent -p wrong get writable` | `invalidCredentials` OR `AcceptSecurityContext error` | PENDING live verify (needs DC) |
| 4 | LDAP modify (permission) | `bloodyAD --host <DC IP> -d corp.local -u low-priv -p p set password victim 'New!'` (low-priv lacks ForceChangePassword) | `insufficientAccessRights` | PENDING live verify |
| 5 | Kerberos preauth | `bloodyAD --host dc01.corp.local -d corp.local -u u -k get writable` (with stale ccache) | `KDC_ERR_PREAUTH_FAILED` OR `KRB_AP_ERR_SKEW` | PENDING live verify (needs DC + bad ccache) |
| 6 | argparse | `bloodyAD --host <DC IP> -d corp.local -u u -p p add GroupMember 'Domain Admins' auditor` (WRONG CASING — `GroupMember` instead of `groupMember`) | `error: argument` OR `invalid choice` | PENDING live verify |

### Layer diversity (SKILL #11) — achieved

7 distinct verifiable layers documented in `failure_signatures`:
1. **DNS** (case 1 — `Could not resolve`, `Name or service not known`)
2. **TCP** (case 2 — `Connection refused`, `ConnectionResetError`, `TimeoutError`)
3. **LDAP bind / NTLM** (case 3 — `invalidCredentials`, `AcceptSecurityContext error`,
   `STRONG_AUTH_REQUIRED`, `LDAP connection failed`)
4. **LDAP modify (permission)** (case 4 — `insufficientAccessRights`,
   `INSUFF_ACCESS_RIGHTS`, `unwillingToPerform`, `WILL_NOT_PERFORM`)
5. **Kerberos** (case 5 — `KRB_AP_ERR_SKEW`, `Clock skew too great`,
   `KDC_ERR_PREAUTH_FAILED`, `KDC_ERR_S_PRINCIPAL_UNKNOWN`, `KerberosError`,
   `minikerberos.protocol.errors`)
6. **AD object / policy** (`noSuchObject`, `NoResultError`,
   `constraintViolation`, `CONSTRAINT_ATT_TYPE`, `Password can't be changed`,
   `oldpass provided is not valid`, `invalidAttributeSyntax`)
7. **argparse** (case 6 — `error: argument`, `the following arguments are
   required`, `invalid choice`)

Plus shadow-credentials-specific: `KeyCredential generated` followed by
`insufficientAccessRights` is the Garfield false-positive trap (legacy
`_check_shadow` in mcp-server.py line 1151) — encoded so the LLM treats the
local key generation as NOT-success when the LDAP modify fails.

### Signals encoded but not yet live-verified

`STRONG_AUTH_REQUIRED` (LDAP signing required → switch to LDAPS via -s),
`unwillingToPerform`, `WILL_NOT_PERFORM`, `noSuchObject`, `NoResultError`,
`constraintViolation`, `CONSTRAINT_ATT_TYPE`, `Password can't be changed`,
`oldpass provided is not valid`, `invalidAttributeSyntax`,
`KDC_ERR_S_PRINCIPAL_UNKNOWN`, `KDC_ERR_PREAUTH_FAILED`, `Clock skew too
great`, `NoneType' object is not subscriptable` (msldap crash on bad creds),
`the following arguments are required`, `invalid choice`,
`ConnectionResetError`, `TimeoutError`.

These exercise post-pilot when a working AD lab is reachable.

---

## 5. Open questions

1. **KRB5CCNAME plumbing for `-k` Kerberos auth** — the legacy mcp-server.py
   (`_get_auth_env`, line 768) auto-injects `KRB5CCNAME` from `_active_ccache`
   (auto-discovered from `/session/credentials/*.ccache`). The kind:cli path
   has NO equivalent — the agent must set `KRB5CCNAME` explicitly via the
   tool runner's `env` parameter, OR pre-stage the ccache to `/etc/krb5.cc`
   (the default location). Document workaround: agent invokes via
   `cli_in_container` with `env: {"KRB5CCNAME": "/session/credentials/auditor.ccache"}`.
   Long-term: consider an `inherit_env` plugin DSL feature so tool.yaml can
   declare `kerberos_ccache_env: KRB5CCNAME` and the runner resolves the
   ccache path from session state.

2. **`--host` vs `--dc-ip` precedence** — both are flag_value rules; the DSL
   evaluates in declared order, first match wins. Verified that `--host`
   wins over `--dc-ip`. **Caveat**: when `--host` is an unresolvable hostname
   (typo, missing DNS), the operation fails with `Could not resolve` even
   though `--dc-ip` is set — this is bloodyAD's own behaviour, not an
   extraction bug. The agent should always prefer IP literals for `--host`
   when DNS reliability is uncertain.

3. **Action / sub-action parsing for adversarial cases** — bloodyAD argparse
   uses CASE-SENSITIVE sub-action names (`groupMember`, NOT `GroupMember` or
   `groupmember`). Wrong casing → argparse `invalid choice` error. The
   target-extraction DSL doesn't see this layer — it only extracts from
   flag values. But the agent's prompt should reinforce the camelCase
   convention. Documented in gotchas.

4. **No structured output format** — bloodyAD writes plain text only. Unlike
   certipy (`-output PREFIX_*.json`) or netexec (`--json`), there is NO
   JSON/CSV/XML option. The `output_formats` table declares text-only with a
   single carve-out for `add shadowCredentials --path` which produces a PEM
   file. Agents pattern-match `[+]`/`[-]`/`[!]` prefixed text or rely on the
   `failure_signatures` table for error classification. Long-term: consider
   a wrapper that JSON-ifies the text output post-hoc — but bloodyAD
   upstream has no plans to add native JSON support per the project README.

5. **Recipe system retirement** — the original mcp-server.py loads dynamic
   recipes from `/session/tool_recipes/bloodyad/` (Feature 28). With kind:cli,
   the LLM writes argv directly and recipes are dead code under the run_cli
   path. Recipes still load for legacy method calls if the directory exists.
   Per REQ-TR-016, this is RETIRED for kind:cli. Document in tool.yaml
   gotchas — done.

6. **HTB lab availability for live verify** — Hercules is the canonical
   bloodyAD lab in the registry but is rotation-dependent. Read-only `get
   writable` / `get search` runs against any AD lab; modify operations need
   a deliberately-misconfigured ACL path. For this migration,
   target_extraction and command-shape validation are done via plugin unit
   tests; runtime behaviour is verified post-pilot when a working AD
   environment is reachable. Documented as known gap.

7. **Output file capture for `add shadowCredentials`** — bloodyAD writes the
   PEM to CWD (which is `/app` inside the container WHEN kind:cli is invoked,
   or `/session/bloodyad/` WHEN the legacy mcp-server.py method is invoked
   via `_ensure_work_dir`). Agents using kind:cli MUST pin output paths
   with `--path /session/<name>.pem` for persistent capture. Documented in
   gotchas — done. Long-term: consider wrapping kind:cli runs in a `cd
   /session && bloodyAD ...` shell invocation so the default output
   location is /session/.

8. **Stateful ccache restore (mcp-server.py `_restore_state` line 753)** —
   the legacy MCP path auto-restores Kerberos state on container start
   (copies `/session/config/krb5.conf` → `/etc/krb5.conf`, picks the most
   recent `/session/credentials/*.ccache` for `_active_ccache`). The
   kind:cli path bypasses `__init__` entirely — these pre-flight steps DON'T
   run unless the agent invokes a legacy method first. Workaround: agent
   pre-stages krb5.conf and ccache via the `bash` tool, OR invokes a no-op
   legacy method (e.g., `mcp_tool bloodyad get_writable ...` once) to
   trigger the restore. Document in gotchas.

9. **Dash-convention error patterns** — `--u` (double dash single-letter) or
   `-host` (single dash multi-character) both produce argparse errors but
   the message is generic (`error: unrecognized arguments`). Documented in
   gotchas as a common LLM mistake pattern.

10. **Kerberos clock skew on kind:cli** — bloodyAD's Dockerfile retains
    `libfaketime` and the entrypoint.sh wires FAKETIME from
    `clock_offset`. Kerberos clock skew is a frequent failure on hardened
    AD targets (KRB_AP_ERR_SKEW). Verify libfaketime survives the
    Dockerfile fix (python3-pip / python3-venv → python3-full) — should,
    since libfaketime is a separate apt package. (Same as netexec /
    certipy Open Question 10.)

11. **Audit gap: per-method `success_check` overrides lost in kind:cli** —
    the legacy mcp-server.py wires two custom success predicates that the
    kind:cli path bypasses entirely:
    - `set_password` (line 1047): `success_check=lambda out, rc: rc == 0
      or "changed successfully" in out.lower()` — accepts non-zero exit
      codes when the success marker is present (false-negative defence
      against bloodyAD's inconsistent exit codes).
    - `add_shadow_credentials` (`_check_shadow`, line 1151): rejects
      `rc == 0` when the combined output contains `KeyCredential
      generated` together with `insufficientAccessRights` — this is the
      Garfield false-positive trap where the local key is generated
      BEFORE the LDAP modify is attempted, so the cert lands on disk
      even when the operation fails.
    Under kind:cli, success is defined by exit code alone — both subtle
    classifications are lost. The `failure_signatures` table encodes
    `KeyCredential generated` so the LLM can detect the false-positive
    trap by pattern-matching, but the false-negative case for
    `set_password` is now a tool.yaml gotcha (see "SET PASSWORD
    FALSE-NEGATIVE"). Long-term fix: extend the kind:cli plugin DSL with
    a `success_check` field (regex or text-contains) so tool.yaml can
    declare per-method success predicates without falling back to the
    legacy mcp-server.py method handler. Until the plugin gains this
    feature, agents should consult the failure_signatures table and the
    explicit gotcha for non-zero-exit-but-still-succeeded cases.

12. **Audit gap: `_classify_bloodyad_error` runs only for legacy methods**
    — the legacy mcp-server.py exposes `error_class`, `retryable`, and
    `suggestions` fields on the ToolResult by inspecting combined
    stdout+stderr against ~12 LDAP/Kerberos/network error patterns
    (mcp-server.py lines 779-892, ~115 LOC). kind:cli does NOT classify;
    it returns raw stdout/stderr and lets the LLM consult
    `failure_signatures` in tool.yaml. The signature table is rich
    enough that the LLM can usually replicate the legacy classification,
    BUT the legacy `retryable` boolean (used by client retry loops) is
    lost — agents under kind:cli must decide retryability themselves
    based on the signature's remediation text. Document if any client
    retry logic depended on the `retryable` flag during the kind:mcp
    era; otherwise this is a graceful degradation.

13. **Audit gap: `extra_args` shlex semantics differ** — every legacy
    method accepts `extra_args` (single string, `shlex.split` then
    appended to argv). kind:cli has no equivalent — agents append flags
    directly to the argv list. The semantic break: a legacy
    `extra_args="--ou 'OU=Users,DC=corp,DC=local'"` would be split by
    shlex into two argv tokens (handling the embedded space inside
    single quotes); under kind:cli the agent must already produce the
    correct argv tokens. Documented in the new gotcha; LLM must learn
    the difference. No plugin work required.

---

## 6. Hand-off

- **Tool**: bloodyad (kind:cli, single binary `bloodyAD` — CASE-SENSITIVE,
  capital A and D). Action-based architecture: `bloodyAD <auth flags>
  <action> [sub-action] [args]` over 5 actions (add / get / set / remove /
  commit) with 27 documented sub-action methods.
- **Status**: tool.yaml authored end-to-end (kind:mcp methods PRESERVED +
  kind:cli sections ADDED on top); scenarios.md written. **Dockerfile
  EDITED** — `python3 / python3-pip / python3-venv` replaced with
  `python3-full` (Kali-rolling-friendly per nikto / impacket / ffuf /
  nuclei / git-dumper / ssti / netexec / certipy convention). libfaketime
  retained (Kerberos clock-skew defence — bloodyAD goes through Kerberos
  on `-k` PtT and on PKINIT `-c` after certipy).
- **mcp-server.py UNTOUCHED** — auto-inherits `run_cli` from BaseMCPServer
  (mcp-common 0.3.0); existing 27 method handlers (set_password, set_owner,
  set_object, add_genericall, add_rbcd, add_shadow_credentials,
  add_group_member, add_computer, add_dcsync, add_uac, add_dns_record,
  add_user, get_object, get_children, get_search, get_writable,
  get_membership, get_dnsdump, get_trusts, remove_genericall, remove_rbcd,
  remove_group_member, remove_shadow_credentials, remove_dcsync, remove_uac,
  remove_dns_record, remove_object) preserved as the legacy / rollback path
  per SKILL #21. The methods carry rich error classification (auth vs
  permission vs config vs network — see `_classify_bloodyad_error`,
  ~115 LOC starting line 779) that's NOT reconstructible from raw stdout.
  Agents that want classified errors still call `mcp_tool bloodyad
  set_password ...` rather than `cli_in_container bloodyAD ... set password
  ...`. Both paths coexist. Also retained: stateful Kerberos restore
  (`_restore_state`, line 753) for legacy methods only — kind:cli path
  requires explicit KRB5CCNAME env (Open Question 1, 8).
- **Image**: `ghcr.io/silicon-works/mcp-tools-bloodyad:latest` — needs
  rebuild during Wave 9 batch to pick up mcp-common 0.3.0 AND the
  python3-full base. Image size unchanged (~650 MB).
- **target_extraction = TWO rules**: ALL `flag_value`. Rule 1 `--host`
  (REQUIRED for all DC-bound ops). Rule 2 `--dc-ip` (DNS resolver hint /
  fallback). NO `positional_match` — actions and sub-actions are
  positional 1 and 2 (never targets); operation arg positionals (target
  names, passwords, group names, attribute values) follow (also never
  targets). The action positionals are particularly DSL-test-worthy
  because bloodyAD has FIVE top-level actions and ~30 sub-actions, all of
  which must NEVER be picked.
- **value_flags**: ~30 entries — every auth flag (`--host`, `--dc-ip`,
  `-d`, `-u`, `-p`, `-c`, `-f`, plus boolean `-k`, `-s`, `-v` for safety),
  every action-level value flag (`--oldpass`, `--ou`, `--path`), every get
  sub-action flag (`--attr`, `--filter`, `--base`, `--otype`, `--right`,
  `--target`, `--detail`, `--direct`, `--resolve-sd`, `--no-recurse`,
  `--no-detail`, `--transitive`), every dnsRecord flag (`--dnstype`,
  `--zone`, `--ttl`, `--port`, `--priority`, `--weight`, `--preference`,
  `--forest`), and the remove-shadow flag (`--key`).
- **reject_flags**: EMPTY — bloodyAD has no bulk-target ingest flag. All
  positionals are action/sub-action tokens or operation arguments
  (sAMAccountName, DN, password value, attribute name, LDAP filter), NEVER
  targets. Single-target tool — one DC per call. Documented in
  reject_flags_reason.
- **allow_multi_target: false** — bloodyAD targets a single DC per call.
  No CIDR support. (Different from netexec where CIDR is idiomatic.)
- **Wave 4.3**: third tool of Wave 4 (AD post-exploitation cluster). Tier
  A migration progress: 17 tools done after this (curl, sqlmap, impacket,
  nmap, ffuf, nuclei, nikto, john, hashcat, kerbrute, hydra,
  ssti, git-dumper, netexec, certipy, bloodyad). Wave 4 continues with
  pygpoabuse.
- **CASE-SENSITIVE binary name (SKILL #5)** — verified against
  mcp-server.py's `_build_auth` (line 954): `cmd = ["bloodyAD", ...]`. The
  Kali apt package installs `/usr/bin/bloodyAD` (case-preserving). Wrong
  casing (`bloodyad`, `bloodyAd`, `BloodyAD`) → command not found. This
  is the #1 most important fact for agents to internalize — it's the only
  CamelCase binary in the kind:cli toolset.
- **CASE-SENSITIVE sub-actions (SKILL #5)** — argparse uses camelCase
  with lowercase first letter: `groupMember`, `shadowCredentials`,
  `dnsRecord`, `dnsDump`, `genericAll`, `userAccountControl`. Wrong
  casing → argparse `invalid choice`. Documented in gotchas.
- **Mixed dash convention (SKILL #5)** — short single-letter flags use
  SINGLE dash (`-u`, `-p`, `-d`, `-k`, `-c`, `-f`, `-v`, `-s`);
  multi-character long flags use DOUBLE dash (`--host`, `--dc-ip`,
  `--filter`, `--oldpass`, `--ou`, `--attr`, `--otype`, `--right`,
  `--detail`, `--direct`, `--no-recurse`, `--resolve-sd`, `--zone`,
  `--dnstype`, `--ttl`, `--port`, `--priority`, `--weight`,
  `--preference`, `--forest`, `--no-detail`, `--transitive`, `--key`,
  `--path`, `--target`, `--base`). Documented in gotchas.
- **Files removed**: `__pycache__/` (build artefact, not in git but
  present on disk — removed). NO `target_extraction_tests.md` and NO
  `failure_signature_tests.md` ever existed for bloodyad — directory was
  already on the simpler layout.
- **Live-verify pending**: paste S1-S11 against an AD lab (Hercules
  preferred — Open Question 6) during Wave 9 batch rebuild + e2e run.
  Verify failure signatures 1-6 live; verify target-extraction cases
  1-18 + F1-F9 with plugin unit tests (no DC needed for
  target_extraction unit tests — pure command-shape parsing).

Authored: 2026-04-25 (Wave 4.3).
