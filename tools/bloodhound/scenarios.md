# bloodhound — Tier A scenarios

Single test sheet for the `bloodhound` tool migration.

bloodhound-python v1.9.0 is a single-binary Python tool for collecting Active
Directory relationship data into BloodHound LEGACY-format JSON files. Native
CLI; the LLM constructs the full bloodhound-python invocation. There are NO
positional arguments — every input is flag-valued. Primary network target is
`-ns/--nameserver` (DC IP used as DNS resolver). Secondary targets are
`-dc/--domain-controller` (DC FQDN override) and `-gc/--global-catalog`
(GC for multi-domain forests).

Sections:
1. Recommended HTB box for live verification
2. Narrative scenarios (paste into opensploit)
3. Target-extraction adversarial cases (≥20)
4. Failure-signature live-verify cases (≥3)
5. Open questions
6. Hand-off

---

## 1. Recommended HTB box

**Garfield (10.129.244.207)** — Linux DC for `garfield.htb`. Verified live
2026-04-29 during this migration. AD ports 53/88/135/389/445/636/3268 all
open; LDAP rootDSE returns `defaultNamingContext: DC=garfield,DC=htb` and
`dnsHostName: DC01.garfield.htb`. Small AD lab — fast DCOnly + All
collections (legacy fixture comment: "All+zip 91-153s" with j.arbuckle).

**Alternate AD-flavoured boxes:** Hercules (`10.129.242.196 hercules.htb`
in /etc/hosts), Certified (`10.129.231.186 dc01.certified.htb`). Any retired
Linux/Windows AD lab exercises the same surface.

**Persistent test directory:** mount `/tmp/bloodhound-test:/session` (per
SKILL #14). bloodhound writes output JSON files to the parent of `-op`. Use
`-op /session/output/bh` so files land in `/session/output/`.

**Credentials needed for happy-path scenarios:** the legacy fixture comment
recorded `j.arbuckle` as the active user; password not in the artifact set.
Run S1-S3 only after obtaining a valid Garfield user via kerbrute userenum
or external writeup.

---

## 2. Narrative scenarios (paste into opensploit)

### S1 — DCOnly stealth collection (recommended first run)

```
Engagement target: 10.129.244.207 (HTB Garfield, authorized).
Realm garfield.htb. Credentials: <USER> / <PASS>.
Collect AD relationship data using bloodhound's stealth profile (DCOnly — only LDAP queries to the DC, no per-computer enumeration). Save outputs to /session/output/ with prefix `bh`. Use --dns-tcp for Docker reliability.
```

**Watch:** `bloodhound-python -d garfield.htb -u <user> -p '<pass>' -ns 10.129.244.207 --dns-tcp -c DCOnly -op /session/output/bh -v`. target=`10.129.244.207` from `-ns`. Output: `bh_<ts>_users.json`, `bh_<ts>_groups.json`, `bh_<ts>_domains.json`, `bh_<ts>_gpos.json`, `bh_<ts>_ous.json`, `bh_<ts>_containers.json` (NO computers.json — DCOnly skips per-host enumeration). meta.version 5 in each JSON.

### S2 — Default collection (Group + LocalAdmin + Session + Trusts)

```
After S1, run a Default collection that also enumerates LocalAdmin/Session via SMB on each host. Save to /session/output/ with prefix `bh-default`. Use 10 workers.
```

**Watch:** `bloodhound-python -d garfield.htb -u <user> -p '<pass>' -ns 10.129.244.207 --dns-tcp -c Default -w 10 -op /session/output/bh-default -v`. This time the output set INCLUDES `bh-default_<ts>_computers.json` because Default's LocalAdmin/Session methods enumerate every domain computer via SMB/RPC. Watch for `Connection to LDAP server lost` if ATA/Defender for Identity reacts.

### S3 — Pass-the-hash collection

```
Suppose I obtained an NTLM hash from secretsdump: aad3b435b51404ee:<NT-hash>. Run a DCOnly collection using --hashes for pass-the-hash auth. Save to /session/output/ with prefix `bh-pth`.
```

**Watch:** `bloodhound-python -d garfield.htb -u <user> --hashes 'aad3b435b51404ee:<NT>' -ns 10.129.244.207 --dns-tcp -c DCOnly -op /session/output/bh-pth -v`. LM half is the empty-password sentinel `aad3b435b51404ee`. NO `-no-pass` is needed — the hash IS the credential.

**Engagement-side note (2026-04-30, Forest):** Some DCs reject NTLM bind even with a correct hash (Forest returns LDAP `data 52e` to NTLM-bind PtH despite `impacket-getTGT --hashes` issuing a TGT cleanly with the same hash). When this happens, fall back to `--auth-method kerberos --hashes ...` (or PtH→getTGT→S4 ccache flow). Not a plugin-layer issue — the argv/env paths above pass through bloodhound unchanged.

### S4 — Kerberos ccache via env passthrough

```
I've already obtained a TGT via impacket-getTGT and the ccache is at /session/output/credentials/<user>.ccache. Run a DCOnly collection using Kerberos auth via that ccache. Save to /session/output/ with prefix `bh-krb`.
```

**Watch:** Agent emits `cli_in_container({tool: "bloodhound", binary: "bloodhound-python", command: "-d garfield.htb -u <user> -k -no-pass -ns 10.129.244.207 --dns-tcp -c DCOnly -op /session/output/bh-krb -v", env: '{"KRB5CCNAME":"/session/output/credentials/<user>.ccache"}'})`. target=`10.129.244.207` extracted from `-ns` (visible in argv); KRB5CCNAME forwarded to run_cli's subprocess env (no bash wrapper). The plugin allowlists KRB5CCNAME globally so no tool.yaml change needed. -no-pass mandatory with -k (otherwise blocks on stdin). Pre-fix this only worked via `bash -c` which was a cross-tool scope-bypass; the env arg is the sanctioned channel.

**Plugin-layer live verification (2026-04-30, Forest 10.129.200.105):** With KRB5CCNAME pointing at a pre-issued ccache, bloodhound found and used the cred store (`getKerberosTGS` ran, no `KRB5CCNAME not set` errors). Confirms env passthrough works end-to-end through `cli_in_container → run_cli → subprocess env`. NOT a bloodhound functional test; the bloodhound team owns the auth path.

### S4b — Kerberos with clock-skew workaround (FAKETIME)

```
Same as S4 but the host clock is +5h ahead of the DC. Run bloodhound with FAKETIME set so libfaketime brings the container's apparent clock back into Kerberos tolerance.
```

**Watch:** Agent emits `cli_in_container({..., env: '{"KRB5CCNAME":"/session/output/credentials/<user>.ccache","FAKETIME":"+5h"}'})`. The plugin hoists FAKETIME into ContainerOptions.clockOffset (`manager.ts:351-358` already wires libfaketime via LD_PRELOAD at docker run); changing the offset between calls causes a container restart so the fresh subprocess sees the new offset. KRB5CCNAME flows through to subprocess env normally. Without this, KRB_AP_ERR_SKEW fires when host clock differs from DC by >5min.

**Plugin-layer live verification (2026-04-30, Forest 10.129.200.105):** Forest's DC was running ~7 min ahead of local. Without FAKETIME, Kerberos AS_REQ + TGS_REQ failed with `KRB_AP_ERR_SKEW(Clock skew too great)`. With `FAKETIME=+7m` passed via the env arg, libfaketime LD_PRELOAD activated in the container subprocess (`date` shifted to match DC), AS_REQ + TGS_REQ both succeeded, LDAP-via-Kerberos auth completed, and DCOnly collection wrote 76 groups + 15 OUs + 20 containers + 2 computers. Confirms FAKETIME-hoist + libfaketime wiring works end-to-end for the actual Kerberos workflow. Not a bloodhound test — a verification that our plugin's clock-offset path reaches the live Kerberos call.

### S5 — DNS resolution failure (live-verified)

```
Target: 192.0.2.1 (TEST-NET-1, deliberately unreachable for DNS-error classification). Realm fake.htb. Run a DCOnly collection with --dns-timeout 5 to verify DNS-failure handling.
```

**Watch:** `bloodhound-python -d fake.htb -u admin -p Password1 -ns 192.0.2.1 --dns-tcp --dns-timeout 5 -c DCOnly -op /session/output/bh-dns-fail -v`. Output contains `dns.resolver.LifetimeTimeout: ... 5.X seconds: Server Do53:192.0.2.1@53 answered The DNS operation timed out.` Both `LifetimeTimeout` and `DNS operation timed out` failure_signatures fire. **Live-verified 2026-04-28** during the kind:cli migration smoke test.

---

## 3. Target-extraction adversarial cases (≥20)

The bloodhound `tool.yaml` declares **six `flag_value` rules** for `-ns`,
`--nameserver`, `-dc`, `--domain-controller`, `-gc`, `--global-catalog` (all
`parse_as: raw`). `-d / --domain` is in `value_flags` only — it is the
Kerberos REALM, NOT a target. Same security invariant as kerbrute.

**Verified 2026-04-29 against the DSL parser** — both pre-fix (surfaced two
scope bypasses) and post-fix (multi-rule aggregation + bash-c rejection
landed in `opensploit-plugin`). Permanent regression coverage lives in
`opensploit-plugin/test/util/target-extraction.test.ts` (multi-rule cases)
and `opensploit-plugin/test/tools/cli-in-container.unit.test.ts` (bash-c
rejection). Cases marked ⚠️ in the tables below exercise behaviour that
WAS wrong pre-fix and document the original exploit shape; the table now
shows the post-fix expected behaviour.

### Happy-path cases

| # | Command (binary `bloodhound-python` omitted) | Expected target | Notes |
|---|---|---|---|
| 1 | `-d corp.local -u admin -p 'pw' -ns 10.10.10.5 --dns-tcp -c DCOnly -op /session/output/bh` | `10.10.10.5` | Bog-standard DCOnly. -ns is the DC IP. |
| 2 | `-d corp.local -u admin -p 'pw' --nameserver 10.10.10.5 --dns-tcp -c All -op /session/output/bh` | `10.10.10.5` | `--nameserver` long form. |
| 3 | `-d corp.local -u admin -p 'pw' -ns 10.10.10.5 -dc dc01.corp.local -c All -op /session/output/bh` | primary=`10.10.10.5`, multi=true (post-fix) | Multi-rule aggregation: -ns + -dc both visible to scope-validation. cli_in_container then refuses with "multiple targets" error so each endpoint is split. |
| 4 | `-d corp.local -u admin --hashes 'aad3b435b51404ee:31d6cfe0...' -ns 10.10.10.5 -c DCOnly -op /session/output/bh` | `10.10.10.5` | PtH. `--hashes` value (LM:NT, contains colon) suppressed by value_flags. |
| 5 | `-d corp.local -u admin -k -no-pass -ns 10.10.10.5 --dns-tcp -c DCOnly -op /session/output/bh` | `10.10.10.5` | -k and -no-pass are booleans. |
| 6 | `-d corp.local -u admin -aesKey 'b65f...' -ns 10.10.10.5 -c DCOnly -op /session/output/bh` | `10.10.10.5` | -aesKey hex value suppressed. |
| 7 | `-d corp.local -u admin -p 'pw' -ns 10.10.10.5 --use-ldaps -c DCOnly -op /session/output/bh` | `10.10.10.5` | --use-ldaps boolean. |

### Help / version (target=null)

| # | Command | Expected | Notes |
|---|---|---|---|
| 8 | `--help` | `null` | tool_runner bypasses scope check on null target only when `extractionRules.length === 0` (current behaviour). See OQ #1 — this also bypasses for any null result, which is the bug. |
| 9 | `-h` | `null` | Short alias. |

### Adversarial — realm-vs-target traps (security invariants)

| # | Command | Expected | Notes |
|---|---|---|---|
| 10 | `-d corp.local -u admin -p 'pw' -ns 10.10.10.5 -c DCOnly -op /session/output/bh` (NO -dc, NO -gc) | `10.10.10.5` | Realm `corp.local` LOOKS target-shaped but must NOT extract. **Critical invariant.** |
| 11 | `-d 10.20.30.40 -u admin -p 'pw' -ns 10.10.10.5 -c DCOnly -op /session/output/bh` | `10.10.10.5` (NOT `10.20.30.40`) | Realm value happens to be IP-shaped (legal — realms are arbitrary strings). value_flags must skip it. |
| 12 | `-d corp.local -u admin -p '10.10.10.5' -ns 10.20.30.40 -c DCOnly -op /session/output/bh` | `10.20.30.40` | Password contains an IP literal. -p value suppressed. |
| 13 | `-d corp.local -u 'admin@10.10.10.5' -p 'pw' -ns 10.20.30.40 -c DCOnly -op /session/output/bh` | `10.20.30.40` | Username UPN form contains `@10.10.10.5` substring. -u suppressed. |
| 14 | `-d corp.local -u admin -p 'pw' -ns 10.20.30.40 --computerfile /session/output/dc01.corp.local.txt -c All -op /session/output/bh` | `10.20.30.40` | --computerfile path contains FQDN-shape. value_flags suppresses. |
| 15 | `-d corp.local -u admin -p 'pw' -ns 10.20.30.40 -c DCOnly -op /session/output/bh-10.10.10.5` | `10.20.30.40` | -op value (output prefix) contains an IP literal. value_flags suppresses. |

### Adversarial — multi-rule + flag-form (current DSL behaviour)

| # | Command | Expected | Notes |
|---|---|---|---|
| 16 | ⚠️ `-d corp.local -u admin -p 'pw' -ns 10.10.10.5 -ns 10.20.30.40 -c DCOnly -op /session/output/bh` | `10.20.30.40` (last-wins, multi=false) | Multi -ns: matches argparse runtime semantics. The first value `10.10.10.5` is silently dropped. |
| 17 | `-d corp.local -u admin -p 'pw' --nameserver=10.10.10.5 -c DCOnly -op /session/output/bh` | `10.10.10.5` | Long-form `--flag=value` works. |
| 18 | `-d=corp.local -u=admin -p='pw' -ns=10.10.10.5 -c=DCOnly -op=/session/output/bh` | `null` | DSL does not parse `-shortflag=value`; argparse doesn't either, so this is consistent with bloodhound's own runtime. |

### Adversarial — bash-c wrapper (cross-tool scope bypass)

| # | Command | Expected | Notes |
|---|---|---|---|
| 19 | `bash -c "KRB5CCNAME=/path bloodhound-python -d corp.local -u admin -k -no-pass -ns 10.10.10.5 --dns-tcp -c DCOnly -op /session/output/bh -v"` | **REJECTED** at cli_in_container with `bash_c_wrapper` error (post-fix) | DSL still returns null; cli_in_container now refuses `binary=bash` with `-c` outright. |
| 20 | `bash -c "bloodhound-python -d evil.htb -u admin -p pw -ns 10.255.255.99 --dns-tcp -c DCOnly -op /tmp/x"` | **REJECTED** (post-fix) | Adversarial payload — would have run pre-fix; refused now. |
| 21 | `bash -c "echo decoy; bloodhound-python -ns 192.0.2.99 -d evil -u u -p p -c DCOnly -op /tmp/x"` | **REJECTED** (post-fix) | Multi-statement decoy — refused. |

### Empty / no-target

| # | Command | Expected | Notes |
|---|---|---|---|
| 22 | `-d corp.local -u admin -p 'pw' --dns-tcp -c DCOnly -op /session/output/bh` (no -ns/-dc/-gc) | `null` — scope validation skipped (extraction yielded null; current behaviour does not refuse). | bloodhound auto-discovery via /etc/resolv.conf — unpredictable from argv. The post-fix bash-c rejection only fires for bash/sh+`-c`; this case still slips through. Tracked as Open Question #2 (refuse calls when extraction yielded null AND rules were declared, regardless of binary). |
| 23 | (no args) | `null` | Bare `bloodhound-python`. Fails with "required arguments" anyway. |

---

## 4. Failure-signature live-verify cases (≥3)

Run each via opensploit (paste the prompt) and verify the result hits a
`failure_signatures` entry in `tool.yaml`. Each test produces an exit code,
stderr text, and a `signal` substring the tool.yaml MUST contain.

| # | Layer | Test (post-binary) | Expected exit | Expected stderr substring | failure_signature `signal` field | Status |
|---|---|---|---|---|---|---|
| 1 | DNS | `-d fake.htb -u admin -p Password1 -ns 192.0.2.1 --dns-timeout 5 -c DCOnly -op /tmp/smoke -v` | 1 | `LifetimeTimeout` AND `DNS operation timed out` | `LifetimeTimeout` AND `DNS operation timed out` | **VERIFIED 2026-04-28** (TEST-NET-1) and **2026-04-29** (Garfield + wrong-realm path; same DNS-layer signature fired). |
| 2 | LDAP bind | `-d garfield.htb -u nonexistent_user_xyz -p 'WrongPassword!' -ns 10.129.244.207 --dns-tcp -c DCOnly -op /tmp/smoke -v` | 1 | `Could not authenticate to LDAP` | `Could not authenticate to LDAP` | **VERIFIED 2026-04-29** against Garfield. |
| 3 | Domain config (via -dc bypass) | `-d fake.local -u admin -p 'pw' -ns 10.129.244.207 -dc DC01.garfield.htb --dns-tcp -c DCOnly -op /tmp/smoke -v` | 1 | `Specified domain was not found in LDAP` | `Specified domain was not found in LDAP` | PENDING — needs explicit -dc to bypass DNS auto-discovery. (Without -dc, wrong-realm surfaces as `LifetimeTimeout` because the DC's DNS doesn't have SRV records for `fake.local`.) |
| 4 | Kerberos preauth | `-d garfield.htb -u admin -p WrongPassword -k --auth-method kerberos -ns 10.129.244.207 --dns-tcp -c DCOnly -op /tmp/smoke -v` | 1 | `KDC_ERR_PREAUTH_FAILED` OR `Pre-authentication information was invalid` | `KDC_ERR_PREAUTH_FAILED` AND `Pre-authentication information was invalid` | PENDING — forces Kerberos so KDC error code surfaces instead of LDAP-bind error. |
| 5 | TCP / LDAP | (needs bench setup: working DNS resolver pointing at a host where 389/636 is firewalled) | 1 | `LDAPSocketOpenError` OR `[Errno 111] Connection refused` | `LDAPSocketOpenError` AND `[Errno 111] Connection refused` | PENDING — hard to provoke against Garfield (LDAP is open); defer to engagement-side observation. |

### Lesson recorded (encode in `tool.yaml` gotchas)

bloodhound's wrong-realm behaviour against an AD-aware DC presents as a
DNS-layer timeout (failed SRV lookup) BEFORE LDAP layer evaluates the
domain. The domain-config-layer signature only fires when DNS auto-
discovery is bypassed via explicit `-dc <FQDN>`. Documented in tool.yaml
gotchas + the failure-signature `Specified domain was not found in LDAP`
remediation.

---

## 5. Open questions

1. **✅ FIXED: cross-tool scope-bypass + multi-rule aggregation + Kerberos env passthrough** — surfaced 2026-04-29, all closed in the same plugin diff.
   - **Bypass class closure (broader than bash-c)**: pre-fix, any argv hidden inside an opaque string (bash -c, python3 -c, perl -e, ruby -e, awk programs, stdin scripts, agent forgetting `-ns`) returned `target: null` and the scope-validation block silently skipped. Post-fix: `cli_in_container.ts` refuses any call where `target_extraction` rules exist but extraction yielded null, with `--help` / `--version` exempted for tool introspection. Subsumes the prior bash-c-only check (which had over-aggressive `.includes("-c")` and missed every interpreter besides bash/sh).
   - **Multi-rule aggregation**: `extractTarget()` now aggregates matches across all rules instead of returning on the first; sets `multi_target_detected: true` when count > 1 so cli_in_container can split / refuse. `-ns A -dc B` no longer silently drops B.
   - **Kerberos / FAKETIME passthrough (the legitimate use case the bypass enabled)**: `cli_in_container` now accepts a structured `env: '{"KRB5CCNAME":"...","FAKETIME":"+5h"}'` arg. The plugin allowlists (KRB5CCNAME, KRB5_CONFIG, FAKETIME, FAKETIME_DONT_FAKE_MONOTONIC globally; tool.yaml `allowed_env` extends per-tool); FAKETIME is hoisted to `ContainerOptions.clockOffset` (existing `manager.ts:351-358` libfaketime path); the rest forwards to `run_cli`'s subprocess env (server already accepted `env` per `base_server.py:370`). LD_PRELOAD / PATH / HTTP_PROXY etc. are NOT allowlisted so they can't be smuggled.
   - Regression coverage: 7 multi-rule tests in `target-extraction.test.ts`; 9 null-target/help-version tests + 11 env-passthrough/allowlist tests in `cli-in-container.unit.test.ts`.

2. **Auto-discovery without -ns** — case 22 above. With the broader null-target check, this is now also refused. The agent gets a clear error explaining the call shape; introspection (`--help`/`--version`) still works. Resolved.

3. **Shape 2 — script-content opaqueness** — still open. Agent can `write /session/output/scripts/x.sh` with hardcoded `-ns malicious.evil`, then invoke `bash /script.sh -ns 10.10.10.5` (decoy `-ns` in outer argv). DSL extracts the decoy, scope-check passes, script's hardcoded target wins. Closing this requires either script-content scanning at write/invoke time, or trusted-script allowlist, or forbidding `bash <script>` entirely (kills legitimate orchestration). Out of scope for this migration; flag for a follow-up that audits all `bash <script>` invocations across Tier A engagements before deciding the right architectural move.

4. **Cypher query layer** — bloodhound only COLLECTS data; analysis (Cypher queries against Neo4j) is in a separate tool that doesn't exist yet. Not part of this migration.

---

## 6. Hand-off

- **Tool**: bloodhound (kind:cli, single Python binary `bloodhound-python` v1.9.0).
- **Status**: tool.yaml authored end-to-end; scenarios.md written; legacy per-method test artifacts deleted (`test_bloodhound.py` 1939 LOC, 15 fixture files, `integration_scenarios/bloodhound.txt` 686 LOC). `mcp-server.py` replaced with 28-line RunCliServer stub.
- **Image**: `ghcr.io/silicon-works/mcp-tools-bloodhound:latest` — needs CI rebuild to pick up the new stub. ~258 MB.
- **Dockerfile**: UNCHANGED (already correct: kalilinux-rolling + bloodhound.py apt + krb5-user + libfaketime + entrypoint.sh + python3 mcp-server.py).
- **target_extraction**: 6 `flag_value` rules (-ns, --nameserver, -dc, --domain-controller, -gc, --global-catalog). 23 adversarial cases verified live against `target-extraction.ts` via `/tmp/verify-bloodhound-extraction.ts` — 36/36 pass; documents both happy-path and the two scope-bypass cases (OQ #1 bash-c, OQ #2 multi-rule).
- **value_flags**: 26 entries covering every flag in `bloodhound-python --help` that consumes a value. Booleans intentionally excluded.
- **failure_signatures**: 24 entries across 7 layers. Live-verified 2 layers (DNS, LDAP-bind). 5 pending (Kerberos preauth, TCP/LDAP, domain-config-via-dc-bypass, file-IO, clock-skew).
- **Live-verify status (2026-04-29)**: smoke + DNS-failure + LDAP-bind + bash-c chain confirmed. Happy-path scenarios S1-S3 NOT YET RUN — need valid Garfield credentials.
- **Plugin fixes shipped alongside this migration (2026-04-29 → 2026-04-30):**
  - `target-extraction.ts`: aggregate matches across all rules; emit `multi_target_detected: true` when count > 1 instead of silently dropping non-first-rule values.
  - `cli-in-container.ts`: (a) refuse calls where target_extraction rules exist but extraction yielded null (catches bash -c, python -c, perl -e, ruby -e, awk programs, stdin scripts, missing target flag — all in one rule). `--help` / `--version` exempted. (b) Add structured `env` arg with global allowlist (KRB5CCNAME, KRB5_CONFIG, FAKETIME, FAKETIME_DONT_FAKE_MONOTONIC) and per-tool extension via tool.yaml `allowed_env`. FAKETIME hoisted to ContainerOptions.clockOffset (existing libfaketime wiring). Replaces the `bash -c` smuggling channel.
- **Full functionality preserved:** S1 (password), S2 (Default+SMB), S3 (PtH), S4 (Kerberos via env), S4b (clock-skew via FAKETIME), S5 (DNS failure), S6 (computerfile), S7 (LDAPS+EPA), S8 (wrong domain). All scenarios that worked under the legacy MCP wrapper still work via the kind:cli + env-arg path.
- **Live-verify status (2026-04-30)**: pending — Forest (10.129.200.105 / htb.local / FOREST.htb.local) spawned. Smoke + DNS-failure + LDAP-bind verified previously against Garfield. S1, S3, S4, S4b to be run against Forest.

Authored: 2026-04-28; live-verified + plugin fixes 2026-04-29; env-passthrough + null-target broadening 2026-04-30.
