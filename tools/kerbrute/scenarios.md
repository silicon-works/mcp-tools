# kerbrute — Tier A scenarios

Single test sheet for the `kerbrute` tool migration (Wave 2.2).

kerbrute is a single-binary Go tool for AD username enumeration and password
spraying via Kerberos pre-authentication on port 88. Four sub-commands
(`userenum`, `passwordspray`, `bruteuser`, `bruteforce`) plus `version` /
`help`. Native CLI; the LLM constructs the full kerbrute invocation.

Sections:
1. Recommended HTB box for live verification
2. Narrative scenarios (paste into opensploit)
3. Target-extraction adversarial cases (≥20 — total 24)
4. Failure-signature live-verify cases (≥3 — total 6)
5. Open questions
6. Hand-off

---

## 1. Recommended HTB box

**Hercules (10.129.242.196)** — Linux DC for `hercules.htb`. Same AD lab used
for impacket testing; perfect for kerbrute because:

- **Kerberos available on port 88** — kerbrute's only protocol surface.
- **Real AD environment** — exercises both KDC_ERR_C_PRINCIPAL_UNKNOWN
  (invalid user) and KDC_ERR_PREAUTH_REQUIRED (valid user) responses.
- **Known-good user**: `natalie.a` with password `Prettyprincess123!` per
  HTB writeups (verified valid as of 2026-04-25). Lets us test S2/S3 with a
  guaranteed positive result.

**Persistent test directory**: mount `/tmp/kerb-test:/session` (per SKILL #14).
The agent must `write` users.txt / passwords.txt / combos.txt to /session/
BEFORE invoking kerbrute — kerbrute reads them as positional file paths
inside the container. The legacy mcp-server.py wrote tempfiles
automatically; the kind:cli path requires explicit `write` calls first.

Suggested test fixture content for `/session/users.txt` (mix of definitely-
valid + definitely-invalid + a real Hercules user):

```
administrator
guest
krbtgt
admin
natalie.a
backup_svc
sql_svc
nonexistent_user_xyz123
fake.account
helpdesk
```

Suggested `/session/passwords.txt` (small list including the real password
for natalie.a):

```
Welcome1
Password1
Spring2026!
Hercules!
Prettyprincess123!
ChangeMe!
Summer2025!
Admin@123
hercules2025
guest
```

---

## 2. Narrative scenarios (paste into opensploit)

### S1 — userenum against Hercules (happy path)

```
Engagement target: 10.129.242.196 (HTB Hercules, authorized).
Realm is hercules.htb. I've written /session/users.txt with 10 candidate usernames including natalie.a (known-good) and several invalid ones. Use kerbrute userenum to enumerate which usernames are valid in the hercules.htb realm. Save the log to /session/kerbrute-userenum.txt and use -v so failures land in stdout for parsing.
```

**Watch:** Agent emits `kerbrute userenum --dc 10.129.242.196 --domain hercules.htb -v /session/users.txt -o /session/kerbrute-userenum.txt` (possibly with `-t 10`). target=`10.129.242.196` extracted from `--dc`. Output contains `[+] VALID USERNAME: natalie.a@hercules.htb` (and any other valid users) plus `[!] <user>@hercules.htb - User does not exist` for invalid ones. Final summary line: `Done! Tested 10 usernames (N valid) in <time> seconds`.

### S2 — passwordspray against Hercules

```
Engagement target: 10.129.242.196 (HTB Hercules).
Realm hercules.htb. After S1 I have /session/users.txt with valid users. Spray the password 'Prettyprincess123!' against all of them. Use --safe so we abort on first lockout, --delay 250 to be polite. Log to /session/kerbrute-spray.txt.
```

**Watch:** Agent emits `kerbrute passwordspray --dc 10.129.242.196 --domain hercules.htb --safe --delay 250 -v /session/users.txt 'Prettyprincess123!' -o /session/kerbrute-spray.txt`. target=`10.129.242.196` from `--dc`. The password (`Prettyprincess123!`) is the LAST positional, NOT a target — it's the spray candidate. Expect `[+] VALID LOGIN: natalie.a@hercules.htb:Prettyprincess123!`. Other users return `[-] user@hercules.htb:Prettyprincess123! - KDC_ERR_PREAUTH_FAILED`.

### S3 — bruteuser against natalie.a

```
Engagement target: 10.129.242.196 (HTB Hercules).
Realm hercules.htb. /session/passwords.txt has 10 passwords including the real one for natalie.a. Use kerbrute bruteuser against natalie.a with that wordlist. Use --safe and --delay 500. WARNING about argument order — kerbrute bruteuser expects the password list FIRST then the username.
```

**Watch:** Agent emits `kerbrute bruteuser --dc 10.129.242.196 --domain hercules.htb --safe --delay 500 -v /session/passwords.txt natalie.a -o /session/kerbrute-brute.txt`. **Argument order trap:** the password file `/session/passwords.txt` comes BEFORE `natalie.a` (per `kerbrute bruteuser --help`: `<password_list> username`). target=`10.129.242.196`. Expect `[+] VALID LOGIN: natalie.a@hercules.htb:Prettyprincess123!` after up to 5 failed attempts (depending on password ordering).

### S4 — DNS resolution failure (negative test, layer-diverse)

```
Engagement target: nonexistent.invalid (deliberately invalid for DNS-error classification).
Realm doesn't matter for this test. Run kerbrute userenum --dc nonexistent.invalid against /session/users.txt to verify DNS-failure handling.
```

**Watch:** Agent emits `kerbrute userenum --dc nonexistent.invalid --domain hercules.htb -v /session/users.txt`. target=`nonexistent.invalid` extracted (scope check rejects it with helpful error, OR if scope check is bypassed for testing, kerbrute output matches `lookup nonexistent.invalid: no such host` (Go DNS error). Failure classified via `lookup .* no such host` signature. kerbrute exits 0 — do NOT trust the exit code.

### S5 — wrong realm (negative test)

```
Engagement target: 10.129.242.196 (HTB Hercules).
But this time set the domain to 'fake.local' (intentionally wrong realm) and run userenum against /session/users.txt. Verify kerbrute reports a wrong-realm error rather than silently returning all-invalid.
```

**Watch:** Agent emits `kerbrute userenum --dc 10.129.242.196 --domain fake.local -v /session/users.txt`. target=`10.129.242.196` (the `--domain` value `fake.local` is NOT extracted as target — that's the realm, not the host). Expect output containing `[!] KDC ERROR - Wrong Realm` or `KDC_ERR_WRONG_REALM`. Failure classified via `Wrong Realm` signature. Crucially, the agent should NOT mistake the all-invalid-users output for "no users exist" — it's a wrong-realm config error.

### S6 — file not found (negative test)

```
Engagement target: 10.129.242.196 (HTB Hercules).
Realm hercules.htb. Run kerbrute userenum but point it at /session/missing-users.txt (intentionally absent). Verify the file-not-found error is classified cleanly.
```

**Watch:** Agent emits `kerbrute userenum --dc 10.129.242.196 --domain hercules.htb -v /session/missing-users.txt`. target=`10.129.242.196`. Expect kerbrute output matching `open /session/missing-users.txt: no such file or directory` (Go os.Open error). Failure classified via `no such host` (NO — that's DNS) — actually `no such file or directory` / `open .* no such file`. Agent should suggest using the `write` tool to create the wordlist first.

### S7 — connection refused (negative test, TCP layer)

```
Engagement target: 127.0.0.1 (intentionally not a KDC, for TCP-layer error classification).
Realm hercules.htb. Run kerbrute userenum --dc 127.0.0.1 against /session/users.txt to verify TCP-layer connection-refused handling.
```

**Watch:** Agent emits `kerbrute userenum --dc 127.0.0.1 --domain hercules.htb -v /session/users.txt`. target=`127.0.0.1`. Expect output matching `connection refused` (Go net dial error) or `Can't talk to KDC`. Distinct from S4 (DNS layer) — this exercises TCP-layer signature.

### S8 — bruteforce combo file

```
Engagement target: 10.129.242.196 (HTB Hercules).
Realm hercules.htb. I've written /session/combos.txt with mixed user:pass pairs including natalie.a:Prettyprincess123! plus several decoys. Use kerbrute bruteforce to test them. Use --safe.
```

**Watch:** Agent emits `kerbrute bruteforce --dc 10.129.242.196 --domain hercules.htb --safe -v /session/combos.txt -o /session/kerbrute-combo.txt`. target=`10.129.242.196`. Combo file format is `username:password` per line (as documented in `kerbrute bruteforce --help`). Expect `[+] VALID LOGIN: natalie.a@hercules.htb:Prettyprincess123!` if that combo is in the file. Same lockout-risk profile as bruteuser — each user attempt counts toward THAT user's lockout.

---

## 3. Target-extraction adversarial cases (24 total, ≥20 spec)

The kerbrute `tool.yaml` declares ONE rule:

1. `flag_value` for `--dc` (`parse_as: raw`) — kerbrute's only network-target
   flag. The first positional is always a sub-command and subsequent
   positionals are LOCAL FILE paths or inline strings (password / username).

`value_flags` declares: `--dc`, `--domain`, `-d`, `--threads`, `-t`,
`--delay`, `--output`, `-o`. Critical: `--domain` / `-d` is the Kerberos
realm (e.g., `hercules.htb`), NOT a target — it MUST appear in value_flags
so the DSL skips its value, AND it MUST NOT be referenced in any
target_extraction rule.

### Happy-path cases

| #  | Command (binary `kerbrute` omitted) | Expected target | Notes |
|----|---|---|---|
| 1  | `userenum --dc 10.129.242.196 --domain hercules.htb /session/users.txt` | `10.129.242.196` | Bog-standard userenum; --dc is the IP. |
| 2  | `userenum --dc dc.hercules.htb -d hercules.htb /session/users.txt` | `dc.hercules.htb` | --dc as FQDN. -d is the realm (skipped). |
| 3  | `userenum --dc dc01 --domain corp.local /session/users.txt` | `dc01` | --dc as bare hostname. |
| 4  | `passwordspray --dc 10.10.10.5 --domain corp.local /session/users.txt 'Spring2025!'` | `10.10.10.5` | passwordspray: password is last positional, not a target. |
| 5  | `passwordspray --dc 10.10.10.5 --domain corp.local --safe /session/users.txt 'Welcome1'` | `10.10.10.5` | --safe is a boolean flag; doesn't consume a value. |
| 6  | `bruteuser --dc 10.10.10.5 --domain corp.local /session/passwords.txt natalie.a` | `10.10.10.5` | bruteuser: <password_list> THEN <username>. Username `natalie.a` is NOT a target (no `@host`). |
| 7  | `bruteforce --dc 10.10.10.5 --domain corp.local /session/combos.txt` | `10.10.10.5` | bruteforce takes a single combo-file positional. |
| 8  | `userenum --dc 10.10.10.5 -d hercules.htb -t 5 --delay 250 -v /session/users.txt` | `10.10.10.5` | Threading + delay + verbose flags around --dc; rule still extracts --dc. |
| 9  | `passwordspray --dc 10.10.10.5 --domain hercules.htb /session/users.txt --user-as-pass` | `10.10.10.5` | --user-as-pass is a boolean; password positional is omitted. |
| 10 | `userenum --dc 10.10.10.5 --domain corp.local /session/users.txt -o /session/run.log` | `10.10.10.5` | -o output path AFTER the wordlist; --dc still extracted. |

### Help / version (target=null)

| #  | Command | Expected | Notes |
|----|---|---|---|
| H1 | `--help` | `target=null` | Top-level help. tool_runner bypasses scope check. |
| H2 | `-h` | `target=null` | Short alias. |
| H3 | `userenum --help` | `target=null` | Sub-command help. |
| H4 | `passwordspray --help` | `target=null` | Sub-command help. |
| H5 | `version` | `target=null` | Version sub-command. |

### Adversarial — value_flag traps & realm-vs-target ambiguity

| #   | Command | Expected | Notes |
|-----|---|---|---|
| F1  | `userenum --domain hercules.htb /session/users.txt` (NO --dc) | `null` | Auto-discovery via DNS SRV. Plugin should refuse the call (Open Question 1) or extract null and fail closed. The realm `hercules.htb` LOOKS target-shaped but must NOT be extracted. |
| F2  | `userenum --dc 10.10.10.5 --domain corp.local /session/users.txt` | `10.10.10.5` (NOT `corp.local`) | Realm trap. `--domain corp.local` is the realm, NOT a host. Critical invariant — verifies value_flags suppresses it. |
| F3  | `userenum --dc 10.10.10.5 -d corp.local /session/users.txt` | `10.10.10.5` | Same as F2 but using `-d` short form. Also must NOT be extracted as target. |
| F4  | `userenum --dc 10.10.10.5 -d hercules.htb -o /session/dc.hercules.htb.log /session/users.txt` | `10.10.10.5` | -o value contains literal `dc.hercules.htb` substring. value_flags must skip. |
| F5  | `userenum --dc 10.10.10.5 -d hercules.htb /session/dc.hercules.htb.users.txt` | `10.10.10.5` | Wordlist filename contains `dc.hercules.htb` shape. NOT a target — it's a file path. |
| F6  | `passwordspray --dc 10.10.10.5 -d corp.local /session/users.txt 'admin@10.255.255.254'` | `10.10.10.5` | Spray PASSWORD literally contains `@10.255.255.254` (bizarre but legal). Last positional is the password operand, NOT a target. |
| F7  | `passwordspray --dc 10.10.10.5 -d corp.local /session/users.txt 'Welcome1'` | `10.10.10.5` | Two positionals after sub-command: wordlist path then password. Neither is a target. |
| F8  | `bruteuser --dc 10.10.10.5 -d corp.local /session/passwords.txt 'admin@evil.com'` | `10.10.10.5` | bruteuser <password_list> <username>. Username happens to LOOK like an email (`admin@evil.com`) — it's still a username string, not a target. |
| F9  | `userenum --dc 10.10.10.5:88 --domain corp.local /session/users.txt` | `10.10.10.5:88` (extracted as raw) | kerbrute does NOT accept ports on --dc (port 88 is hard-coded). The rule extracts the raw string `10.10.10.5:88`; downstream scope-validation should strip the port. kerbrute itself will probably fail to connect — see failure classification. |
| F10 | `userenum --dc 10.10.10.5 -d 10.20.30.40 /session/users.txt` | `10.10.10.5` (NOT `10.20.30.40`) | Realm value happens to be IP-shaped (unusual but legal — realms can be any string). Must NOT be extracted; only --dc. |
| F11 | `userenum --dc 10.10.10.5 --domain corp.local --threads 50 /session/users.txt` | `10.10.10.5` | --threads value `50` (numeric) — value_flags entry suppresses misinterpretation. |
| F12 | `userenum --dc 10.10.10.5 --domain corp.local -t 50 --delay 1000 /session/users.txt` | `10.10.10.5` | Both -t and --delay value-take. |
| F13 | `userenum --dc 10.10.10.5 --domain corp.local /session/users.txt /session/extra.txt` | `10.10.10.5` | Userenum takes only ONE wordlist; extra positional is bogus but kerbrute will error. Target extraction is unaffected — still --dc. |
| F14 | `userenum --dc 10.10.10.5 -d corp.local --safe -v /session/users.txt` | `10.10.10.5` | --safe and -v are booleans; no value consumed. |
| F15 | `bruteforce --dc 10.10.10.5 --domain corp.local /session/admin@10.10.10.5.combos.txt` | `10.10.10.5` | Combo file path contains literal `@10.10.10.5` substring. Path is operand, NOT target — but extraction here yields `10.10.10.5` from --dc anyway (same value, coincidence). The point is: `--dc` rule fires, NOT a positional/email regex. |
| F16 | `passwordspray --dc 10.10.10.5 -d corp.local /session/users.txt 'P@ssw0rd!'` | `10.10.10.5` | Password contains `@` — legal. Last positional is the spray candidate, not a target. |

### Adversarial — security invariants & sub-command ordering

| #   | Command | Expected | Notes |
|-----|---|---|---|
| F17 | `--dc 10.10.10.5 userenum --domain corp.local /session/users.txt` | `10.10.10.5` (DSL) but kerbrute REJECTS | DSL extracts --dc regardless of position, BUT kerbrute is Cobra-based and requires the sub-command FIRST. This call fails at runtime with "unknown command" — extraction was correct, runtime was wrong. |
| F18 | `userenum /session/users.txt --dc 10.10.10.5 --domain corp.local` | `10.10.10.5` | --dc appears AFTER the wordlist. Cobra is lenient about flag position; the DSL's flag_value rule walks all argv. |
| F19 | `userenum --dc 10.10.10.5 --dc 10.20.30.40 --domain corp.local /session/users.txt` | `10.20.30.40` (last-wins per Go's pflag library) | Multi --dc: per Cobra/pflag's standard behaviour, the LAST value wins. The DSL's flag_value rule should honour the last-wins semantics. |
| F20 | `userenum --dc=10.10.10.5 --domain=corp.local /session/users.txt` | `10.10.10.5` | `--flag=value` form (Cobra accepts both `--flag value` and `--flag=value`). DSL's flag_value rule must handle both. |

### Empty / no-target / special

| #  | Command | Expected | Notes |
|----|---|---|---|
| F21 | `userenum --domain corp.local /session/users.txt` | `null` | No --dc → target=null. Plugin should refuse (OQ 1). |
| F22 | `userenum --dc '' --domain corp.local /session/users.txt` | `''` (empty string) | Empty --dc value. Extraction yields empty string; downstream scope-validation should reject. |
| F23 | (no args) | `target=null` | Top-level kerbrute invocation. tool_runner bypasses scope check. |
| F24 | `help` | `target=null` | `kerbrute help` sub-command (NOT a flag — Cobra exposes both). |

---

## 4. Failure-signature live-verify cases (6 total, ≥3 spec)

Verify against the kerbrute container (rebuild during Wave 9 batch with mcp-common 0.3.0). All cases below need an Hercules-equivalent live KDC plus a couple of synthetic invalid configs.

| # | Layer | Test | failure_signature `signal` | Status |
|---|---|---|---|---|
| 1 | DNS | `userenum --dc nonexistent.invalid -d hercules.htb /session/users.txt` | `lookup .* no such host` AND/OR `no such host` | PENDING live verify (Wave 9 batch) |
| 2 | TCP | `userenum --dc 127.0.0.1 -d hercules.htb /session/users.txt` | `connection refused` AND/OR `Can't talk to KDC` | PENDING live verify |
| 3 | Realm | `userenum --dc 10.129.242.196 -d fake.local /session/users.txt` | `Wrong Realm` AND/OR `KDC_ERR_WRONG_REALM` | PENDING live verify |
| 4 | File I/O | `userenum --dc 10.129.242.196 -d hercules.htb /session/missing.txt` | `no such file or directory` AND/OR `open .* no such file` | PENDING live verify |
| 5 | Kerberos preauth | `passwordspray --dc 10.129.242.196 -d hercules.htb /session/users.txt 'WrongPassword!'` | `KDC_ERR_PREAUTH_FAILED` (in `[-]` lines) | PENDING live verify (expected behaviour, classified as `auth` not fatal) |
| 6 | Realm / KDC | `userenum --dc 10.129.242.196 -d corp.local /session/users.txt` (realm doesn't match Hercules) | `Wrong Realm` | PENDING live verify |

Additional layer signatures encoded but not yet live-verified (deferred to
Wave 9):
- `i/o timeout` — DC firewalled / unreachable
- `KRB_AP_ERR_SKEW` / `Clock skew too great` — clock skew (hard to provoke
  deliberately; document for future incident response)
- `KDC_ERR_C_PRINCIPAL_UNKNOWN` — invalid username (expected in userenum, not
  fatal; classified as informational)
- `KDC_ERR_CLIENT_REVOKED` / `USER LOCKED OUT` — locked account
- `Bad username: blank` — empty line in wordlist
- `unknown flag` / `unknown command` — syntax error
- `Failed: KDC has no support for encryption type` — hardened DC

### Layer diversity (SKILL #11) — achieved

5 distinct layers with verifiable signatures: **DNS** (case 1), **TCP** (case
2), **Realm/Kerberos config** (cases 3 + 6), **File I/O** (case 4), **Kerberos
preauth** (case 5). Plus the encoded-but-not-live: clock-skew (separate
Kerberos sub-layer), lockout (auth-policy), realm-encryption (KDC config).

---

## 5. Open questions

1. **Auto-discovery without --dc (case F1, F21)** — when --dc is omitted,
   kerbrute does a DNS SRV lookup for `_kerberos._tcp.<realm>` and the
   resolved host is unpredictable from argv alone. Recommendation: tool_runner
   should REFUSE calls without --dc and emit a clear error message
   ("kerbrute requires --dc to be set explicitly so the engagement scope can
   be validated"). Removes a scope-bypass vector. Single-line change in
   `cli_in_container.ts` — check for the rule's flag presence before
   extraction.

2. **Lockout-protection thresholds** — kerbrute's `--safe` aborts on the
   FIRST detected lockout, but doesn't expose a configurable threshold
   ("abort after N consecutive lockouts"). For aggressive lockout policies
   you may want to abort earlier; for permissive ones you may want to
   continue past 1-2 false-positive lockouts. Out of scope for the kind:cli
   migration; would require upstream patch to kerbrute or a wrapper layer.
   Document in usage_patterns: pair `--safe` with conservative `--delay`.

3. **Proxy / SOCKS support** — kerbrute v1.0.3 has NO `--proxy` flag (verified
   against `kerbrute --help`). For VPN-only routing this is fine; for chaining
   through a SOCKS proxy (e.g., `chisel`/`ligolo` from a compromised host)
   kerbrute can't be used directly. Workarounds: (a) run kerbrute on the
   compromised host directly, (b) port-forward the KDC to a local port and
   point --dc at localhost, (c) use `proxychains kerbrute` (which routes the
   Go binary's syscalls through libc DNS — works because Go DOES use libc
   `getaddrinfo` for DNS by default, but raw socket ops bypass libc). Not
   verified end-to-end; document as known limitation.

4. **Port override** — kerbrute always uses port 88 (hard-coded; no
   `--port` flag). For non-standard KDC ports (rare in production, common in
   CTFs) kerbrute cannot target them. Workaround: `socat TCP-LISTEN:88 TCP:<dc>:<weird-port>` on the kerbrute host to translate. Document as known
   limitation.

5. **Multi --dc handling (case F19)** — Cobra/pflag's default is "last-wins"
   for repeated flags. The DSL's flag_value rule should honour the same
   semantics; verify in plugin tests. If the plugin's flag_value rule returns
   the FIRST value instead, this is a divergence from kerbrute's runtime
   behaviour and should be aligned.

6. **--dc=value vs --dc value (case F20)** — both forms are valid Cobra
   syntax. Plugin's flag_value rule must handle BOTH. Verify in plugin
   tests; if only `--flag value` is supported, add `--flag=value` parsing.

7. **Empty --dc value (case F22)** — `--dc ''` should be rejected at the
   tool_runner level; an empty target string makes scope validation
   nonsensical. Verify the plugin's TargetValidation rejects empty strings;
   if not, add a non-empty assertion.

8. **Wordlist hygiene** — kerbrute errors on empty lines (`Bad username: blank`).
   The legacy mcp-server.py auto-filtered these. With kind:cli the LLM is
   responsible for clean input. Future enhancement: a server-side preflight
   that strips blank lines before invoking the binary. Out of scope here.

---

## 6. Hand-off

- **Tool**: kerbrute (kind:cli, single-binary Go tool)
- **Status**: tool.yaml authored end-to-end; scenarios.md written. Dockerfile
  unchanged — base image is `python:3.11-slim` (NOT Kali) so the
  `python3-full` swap doesn't apply. mcp-server.py UNTOUCHED — auto-inherits
  `run_cli` from BaseMCPServer (mcp-common 0.3.0); existing per-method
  handlers (`userenum`, `passwordspray`, `bruteuser`, `bruteforce`) preserved
  as the legacy / rollback path per SKILL #21.
- **Image**: `ghcr.io/silicon-works/mcp-tools-kerbrute:latest` — needs rebuild
  during Wave 9 batch to pick up mcp-common 0.3.0. Image is small (~194 MB).
- **target_extraction = single `flag_value` rule on `--dc`**: kerbrute's
  network target is always the value of --dc (or auto-discovery via DNS SRV
  if absent — recommended REFUSED at plugin layer per OQ 1). The
  realm-vs-target trap (`--domain hercules.htb` looks domain-shaped but is
  the Kerberos realm) is suppressed by listing `--domain`/`-d` in
  value_flags and NOT in target_extraction rules. 24 extraction cases
  authored covering happy paths, value-flag traps, sub-command ordering,
  multi-flag last-wins, `--flag=value` form, empty-target, and auto-discovery
  refusal.
- **value_flags scoped tight**: --dc, --domain, -d, --threads, -t, --delay,
  --output, -o. Booleans (--safe, --user-as-pass, -v, --verbose, -h, --help)
  are intentionally NOT listed (they don't consume a value, so the DSL's
  default token-walk handles them correctly).
- **Wave 2.2**: second tool of Wave 2 (hashcat done as 2.1; hydra is 2.3
  pending). Tier A migration progress: 10 tools done after kerbrute (curl,
  sqlmap, impacket, nmap, ffuf, nuclei, nikto, john, hashcat, kerbrute).
- **Live-verify pending**: paste S1-S8 against Hercules. Verify failure
  signatures 1-6 live during the Wave 9 batch rebuild + e2e run. Confirm
  realm-vs-target trap behaviour on F2/F3/F10 (security invariant).
- **Files removed**: `__pycache__/` directory (compiled Python cache from
  legacy testing). No `target_extraction_tests.md` or `failure_signature_tests.md`
  files were present — the kerbrute directory was already on the simpler
  layout used by recent migrations (Dockerfile, mcp-server.py, requirements.txt,
  tool.yaml).

Authored: 2026-04-25.
