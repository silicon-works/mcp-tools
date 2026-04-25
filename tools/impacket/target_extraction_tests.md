# impacket target-extraction test set (Workstream A → B handshake)

Per Feature 35 spec: ≥20 adversarial commands, each with the expected target host
that the plugin's `target_extraction` DSL should pull from the impacket invocation.

The impacket `tool.yaml` declares four rules (first match wins):

1. `positional_match` regex `^(?:[^/@\s]+/)?[^@\s]+@([^:/?#\s]+)`, capture group 1, `parse_as: raw` — matches the standard `[domain/]user[:password]@host` form used by `secretsdump`, `psexec`, `wmiexec`, `smbexec`, `dcomexec`, `atexec`, `lookupsid`, `smbclient`, `mssqlclient`.
2. `flag_value` for `-target` (`parse_as: raw`) — used by `ntlmrelayx -t` (no — that's `-t`, see notes), and as an unfortunate name reuse by `dacledit -target <DN>` and `owneredit -target <DN>` (see F12 below — known wart).
3. `flag_value` for `-target-ip` (`parse_as: raw`) — used as override when the SPN host differs from the network host.
4. `flag_value` for `-dc-ip` (`parse_as: raw`) — fallback ONLY when no positional / `-target` / `-target-ip` is present. Catches `GetUserSPNs`, `GetNPUsers`, `changepasswd`, `findDelegation`, `getTGT`, `getST` (no positional `@host`).

Lessons applied from curl + sqlmap pilots:
- Explicit `parse_as: "raw"` on every rule (no URL parsing — these are bare hostnames / IPs).
- `value_flags` declares ~40 entries to prevent value-position strings from being mistaken for targets (notably `-spn`, `-impersonate`, `-hashes`, `-aesKey`, `-outputfile`, `-computer-name`, `-computer-pass`, `-delegate-to`, `-delegate-from`, `-principal`, `-action`, `-rights`, `-codec`, `-q`, ...).
- Per-pattern `binary:` field — the test command's first token is the binary name, but the `target_extraction` DSL operates on the args (binary excluded).

## Happy-path cases

| # | Command (binary shown for clarity, target_extraction sees args only) | Expected target | Notes |
|---|----------------------------------------------------------------------|-----------------|-------|
| 1  | `impacket-secretsdump CORP/administrator:Pass123@10.10.10.5 -just-dc-ntlm` | `10.10.10.5` | Bog-standard DCSync, IPv4 |
| 2  | `impacket-secretsdump CORP.LOCAL/da.user:p@dc01.corp.local -just-dc -outputfile /session/loot/dump` | `dc01.corp.local` | FQDN domain, FQDN host, password without special chars |
| 3  | `impacket-secretsdump 'corp/svc_admin:Pa$$w0rd!@10.10.10.5'` | `10.10.10.5` | Password contains `$`, `!`, single-quoted on shell — value reaches DSL clean |
| 4  | `impacket-secretsdump 'CORP/admin:abc123@10.10.10.5' -hashes :aad3b435b51404eeaad3b435b51404ee:31d6cfe0d16ae931b73c59d7e0c089c0` | `10.10.10.5` | Positional `@host` wins; `-hashes` value (LM:NT) must NOT be picked even with colon |
| 5  | `impacket-psexec CORP/admin@10.10.10.5 -k -no-pass` | `10.10.10.5` | Kerberos pass-the-ticket; positional still has `@host` |
| 6  | `impacket-wmiexec WORKGROUP/Administrator:LocalPass@192.168.50.10 'whoami /all'` | `192.168.50.10` | wmiexec single-shot with quoted command — extra positional must not confuse extractor |
| 7  | `impacket-smbclient CORP/da:p@10.10.10.5` | `10.10.10.5` | Interactive smbclient |
| 8  | `impacket-mssqlclient CORP/sql_user:Sql123@10.10.10.20 -windows-auth` | `10.10.10.20` | MSSQL with Windows auth — host extracted from positional |
| 9  | `impacket-secretsdump CORP/admin:p@dc01.corp.local -just-dc-ntlm -dc-ip 10.10.10.5` | `dc01.corp.local` | Both positional `@host` AND `-dc-ip` present — positional wins (DC FQDN is the network target, `-dc-ip` is just KDC routing) |
| 10 | `impacket-getTGT CORP/user:Pass123 -dc-ip 10.10.10.5` | `10.10.10.5` | No positional `@host` — `-dc-ip` fallback fires (rule 4) |
| 11 | `impacket-GetUserSPNs CORP/user:Pass123 -dc-ip 10.10.10.5 -request -outputfile /session/loot/k.txt` | `10.10.10.5` | Kerberoast — no positional `@host`. The DC IS the operational target. `-dc-ip` fallback. |
| 12 | `impacket-GetNPUsers 'CORP/' -no-pass -dc-ip 10.10.10.5 -usersfile /session/users.txt` | `10.10.10.5` | Unauth AS-REP roast. Bare `CORP/` doesn't match positional regex (no `@`). `-dc-ip` fallback fires. |
| 13 | `impacket-findDelegation CORP/user:p -dc-ip 10.10.10.5` | `10.10.10.5` | Delegation enum — same shape as kerberoast |
| 14 | `impacket-addcomputer CORP/user:p -computer-name 'PWNED$' -computer-pass 'MachinePass1!' -dc-host dc01.corp.local` | `dc01.corp.local` (via `-dc-host` value? **see Q4**) OR `null` (no positional, no `-target`, no `-target-ip`, no `-dc-ip`) | Edge case: `-dc-host` is functionally the DC target but isn't in the rules. Either add `-dc-host` as 5th flag_value rule, OR document that addcomputer requires `-dc-ip` instead. |
| 15 | `impacket-getST CORP/svc:p -spn cifs/dc01.corp.local -impersonate Administrator -dc-ip 10.10.10.5` | `10.10.10.5` | S4U2Self/Proxy. `-spn` value (`cifs/dc01.corp.local`) is the *target service*, not a network address — must NOT be picked. `-impersonate` value (`Administrator`) is a username — must NOT be picked. `-dc-ip` fallback fires. |

## Adversarial cases — value_flag traps & multi-binary forms

| # | Command | Expected | Notes |
|---|---------|----------|-------|
| 16 | `impacket-GetUserSPNs 'CORP/admin:p' -dc-ip 10.10.10.5 -request -outputfile /session/admin@10.255.255.254/k.txt` | `10.10.10.5` | `-outputfile` value contains a literal `@10.255.255.254` substring — must NOT be parsed as positional. `-outputfile` is in `value_flags`, so the DSL must skip it. The fallback `-dc-ip` rule then fires. |
| 17 | `impacket-secretsdump 'CORP/svc:p@10.10.10.5' -just-dc-user 'CORP/krbtgt'` | `10.10.10.5` | `-just-dc-user` value (`CORP/krbtgt`) contains a `/` and a `:`-free principal — must NOT be parsed as positional. positional rule 1 fires on the first arg. |
| 18 | `impacket-getST CORP/svc:p -spn cifs/victim.corp.local@RANDOMREALM -impersonate Administrator -dc-ip 10.10.10.5` | `10.10.10.5` | The SPN string (`cifs/victim.corp.local@RANDOMREALM`) syntactically looks like a `domain/user@host` form — but it's the value of `-spn`, which is a value_flag. DSL must NOT pull `RANDOMREALM` as the target. Positional rule never matches (first arg `CORP/svc:p` has no `@`). `-dc-ip` fallback wins. |
| 19 | `impacket-secretsdump CORP/admin:p@dc01 -system /session/SYSTEM.bak -security /session/SECURITY.bak -sam /session/SAM.bak` | `dc01` | Offline registry hive dump. Positional `@host` is still present (legacy), even though no network call is made. Extractor returns `dc01`. Validation hook should treat as in-scope iff `dc01` is in scope. |
| 20 | `impacket-rbcd -action write -delegate-to 'victim$' -delegate-from 'pwned$' CORP/user:Pass123 -dc-ip 10.10.10.5` | `10.10.10.5` | rbcd: positional appears AFTER flags. Positional rule must scan all args, not only `args[0]`. `-delegate-to` / `-delegate-from` values look like SAM names (`victim$`) but are in `value_flags`. `-dc-ip` fallback fires only because positional rule has no `@host`. |
| 21 | `impacket-dacledit -action write -rights FullControl -principal 'pwned' -target 'CN=Domain Admins,CN=Users,DC=corp,DC=local' CORP/user:p -dc-ip 10.10.10.5` | `10.10.10.5` (NOT the LDAP DN) | **Known DSL wart**: `-target` rule 2 would extract the DN (`CN=Domain Admins,...`) as the network target. Scope validator would reject (DN is not a valid hostname/IP). The CORRECT target is the DC via `-dc-ip` (rule 4 fallback). **Action**: either skip `-target` rule for the `dacledit`/`owneredit` binaries, OR add a per-binary `target_extraction_overrides` keyed on `binary`. For the pilot: document and live-validate that scope check fails closed (rejects DN-shaped value) when run via the DSL. |
| 22 | `impacket-ntlmrelayx -t smb://10.10.10.5/ADMIN$ -smb2support` | `smb://10.10.10.5/ADMIN$` (raw — note `-t` not `-target` — see Q1) | ntlmrelayx target flag is short `-t`, NOT `-target`. The current rules do NOT cover `-t`. Result: positional rule misses (no positional), `-target` rule misses (it's `-t`), fallback `-dc-ip` not present → `target=null`. **Action**: see Q1. ntlmrelayx is a Tier B candidate (stateful listener) — not in the kind:cli pilot — but worth flagging. |
| 23 | `impacket-ticketer -nthash deadbeef... -domain-sid S-1-5-21-... -domain corp.local Administrator` | `null` (offline ticket forge — no network call) | ticketer forges a ticket from already-stolen krbtgt material. No connection. positional rule misses (no `@host`). All flags are value_flags. No `-dc-ip`. Result: `target=null`. Validation hook should allow offline/no-target binaries to proceed. **Action**: tool_runner allow-list of `no_target_ok` binaries (ticketer, ticket_converter, raiseChild?). |
| 24 | `impacket-getTGT 'CORP/user' -hashes :31d6cfe0d16ae931b73c59d7e0c089c0 -dc-ip 10.10.10.5` | `10.10.10.5` | Overpass-the-hash — `-hashes` value is `:hex...`. Must NOT be parsed as positional. `-dc-ip` fallback. |
| 25 | `impacket-secretsdump 'corp/user:pa$$@10.10.10.5' -just-dc-ntlm` | `10.10.10.5` | Password contains `$` (allowed by regex, since `[^@\s]+` accepts `$`). |
| 26 | `impacket-secretsdump '/admin@10.10.10.5'` | `10.10.10.5` | NULL domain (just `/admin@host`) — regex `^(?:[^/@\s]+/)?` makes domain optional, but the bare leading `/` is unusual. Regex behaviour: `[^/@\s]+/` requires ≥1 non-slash char before `/`, so `/admin@host` does NOT match the optional prefix and falls to `[^@\s]+` which then captures `/admin` as the user. Group 1 captures `10.10.10.5`. **Confirm in DSL.** |
| 27 | `impacket-secretsdump 'admin@10.10.10.5'` | `10.10.10.5` | No domain prefix at all (allowed by impacket — uses host-only auth or assumes WORKGROUP). Regex `(?:[^/@\s]+/)?` is optional → fires the optional, then `[^@\s]+` matches `admin`, then `@`, then capture `10.10.10.5`. ✓ |

## Adversarial cases — security invariants & ambiguity

| # | Command | Expected | Notes |
|---|---------|----------|-------|
| F1 | `impacket-secretsdump --help` | `null` | Help/version flags. tool_runner should bypass scope check for `--help` / `-h` / no-args. |
| F2 | `impacket-secretsdump` (no args) | `null` | Same — print usage. |
| F3 | `impacket-getTGT 'CORP/user:p'` (no `-dc-ip`) | `null` | Pure auto-discovery: impacket tries DNS SRV `_kerberos._udp.corp.local`. We have no way to predict what host that resolves to from the cmdline alone. Validation hook should warn ("KDC will be auto-discovered; cannot pre-validate scope") and let it proceed OR refuse and demand explicit `-dc-ip`. **Action**: prefer the latter — refuse and ask for explicit `-dc-ip`. |
| F4 | `impacket-secretsdump 'CORP/admin:p@10.10.10.5' -dc-ip 10.255.255.254` | `10.10.10.5` (positional wins) | positional rule 1 fires. `-dc-ip` is ignored. **Security invariant**: `-dc-ip` is auth/KDC routing, NOT scope. The actual DCSync RPC traffic goes to the positional `@10.10.10.5`. Scope check applies to that, NOT to the (possibly arbitrary) `-dc-ip`. |
| F5 | `impacket-secretsdump 'CORP/admin:p@10.10.10.5' -target-ip 10.255.255.254 -dc-ip 10.0.0.1` | `10.10.10.5` (positional wins) | Same invariant. positional beats `-target-ip` beats `-dc-ip`. |
| F6 | `impacket-getST CORP/svc:p -spn cifs/scope-creep.attacker.com -impersonate Administrator -dc-ip 10.10.10.5` | `10.10.10.5` | The `-spn` value is the SPN of the service the ST will be valid for — but the network call is to the KDC (`-dc-ip`). Scope check applies to the DC, not the SPN host. (S4U doesn't connect to the SPN — that happens later when you USE the ST.) |
| F7 | `impacket-psexec '@10.10.10.5'` | `10.10.10.5` (regex: `^(?:[^/@\s]+/)?[^@\s]+@(...)` — the user part `[^@\s]+` requires ≥1 char, so `@10.10.10.5` alone does NOT match. **Result: target=null.**) | Empty-user edge case. impacket itself would reject the auth. Plugin returns null → validation may pass through or warn. |
| F8 | `impacket-secretsdump 'CORP/admin:p@10.10.10.5' 'CORP/admin:p@10.10.10.6'` | `10.10.10.5` (first positional only) | Multi-target forbidden in impacket binaries (each is single-target). Second positional is silently ignored by impacket itself. Plugin extracts the first match. tool_runner should warn if multiple positional-shaped args present (likely user error). |
| F9 | `impacket-secretsdump 'CORP/admin:p@10.10.10.5/SHARE'` | `10.10.10.5` (regex stops at `/` — `[^:/?#\s]+`) | Some users habitually paste `\\host\share`-style — `/SHARE` after host is ignored by extractor. |
| F10 | `impacket-secretsdump 'CORP/admin:p@10.10.10.5:445'` | `10.10.10.5` (regex stops at `:` — `[^:/?#\s]+`) | Explicit `:port` after host. Extractor strips port — scope check sees just the host. impacket itself accepts the port. |
| F11 | `impacket-secretsdump 'CORP/admin:p@[fe80::1]'` | `[fe80::1` (regex: `[^:/?#\s]+` stops at `:` inside the bracket → `[fe80` ❌) | **IPv6 broken in current regex.** The square-bracket form for IPv6 hosts (`@[ipv6]`) is not handled — the `:`-stop kicks in inside the bracket. **Action**: regex should special-case `\[([^\]]+)\]` for bracketed IPv6 OR document that IPv6 targets require explicit `-target-ip`. For the pilot: HTB / pentest engagements are IPv4-only — defer fix. |
| F12 | `impacket-dacledit -action read -principal admin -target 'CN=foo,DC=corp,DC=local' CORP/user:p` | `CN=foo,DC=corp,DC=local` (rule 2 fires) | Same DN trap as case 21 but without `-dc-ip`. Scope validator must reject — DN won't parse as host. Failure mode: closed (good) but error message will be confusing. **Action**: per-binary override or skip `-target` rule for dacledit/owneredit. |

## Coverage summary

- 15 happy-path cases (positional, Kerberos, multi-binary, value_flag traps, fallback)
- 12 adversarial / security-invariant cases
- **Total: 27 cases** (≥20 spec satisfied)
- Critical security invariants exercised: positional beats `-dc-ip` (F4, F5), `-spn`/`-impersonate` not extracted (15, 18, F6), `-hashes`/`-aesKey`/`-outputfile` not extracted (4, 16), proxy-style flags not extracted (none — impacket has no `--proxy` analogue)

## Open questions for Workstream B

1. **ntlmrelayx `-t` flag (case 22)**: ntlmrelayx uses short `-t TARGET`, not `-target`. Add `-t` to flag_value rules? Counter-argument: ntlmrelayx is Tier B (stateful listener) and excluded from kind:cli pilot. Defer until ntlmrelayx is migrated, OR add now as defensive cover.
2. **`-dc-host` (case 14)**: addcomputer prefers `-dc-host FQDN` over `-dc-ip`. Add a 5th flag_value rule for `-dc-host`? It's strictly equivalent (fallback when no positional). Recommend: yes, add it — single-line change, matches existing fallback semantics.
3. **Per-binary overrides for `-target` semantics (cases 21, F12)**: dacledit / owneredit / rbcd reuse `-target` for AD object identifier (DN or sAMAccountName), NOT for network target. Either:
   - (a) add `target_extraction_overrides` keyed on binary that REMOVE rule 2 for these binaries, OR
   - (b) make the `-target` rule conditional on `parse_as: "host_or_ip"` so DN strings get rejected at parse time (cleaner but DSL doesn't yet support that parse_as variant).
   For the pilot, (a) is the smaller change. Recommend (a).
4. **Auto-discovery cases without `-dc-ip` (F3)**: refuse outright (require explicit `-dc-ip`/`-dc-host`) OR allow with a "scope cannot be pre-validated" warning? Recommend refuse: in pentest engagements, the operator always knows the DC IP — making it explicit is good hygiene and removes a scope-bypass vector.
5. **No-target-ok binaries (case 23)**: ticketer / ticketConverter / raiseChild operate offline. Add `no_target_ok: true` field to their per-pattern entries? OR an allow-list in tool.yaml at the top-level keyed by binary? Recommend: per-pattern field (more local, easier to audit).
6. **IPv6 bracketed hosts (F11)**: defer (HTB is IPv4-only). Document in tool.yaml gotchas if not already.
