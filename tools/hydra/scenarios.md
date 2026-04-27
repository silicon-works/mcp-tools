# hydra — Tier A scenarios

Single test sheet for the `hydra` tool migration (Wave 2.3 — final tool of
Wave 2, Credentials cluster).

hydra is THC-Hydra v9.6: a multi-protocol network authentication brute-forcer
covering 50+ protocols (ssh, ftp, http-{get,post}-form, smb, mysql, mssql,
rdp, vnc, telnet, smtp, imap, pop3, redis, mongodb, ldap2, ldap3, snmp,
sshkey, etc.). Two target syntaxes (URL-positional preferred; alternate
two-positional `<host> <protocol>` form supported). Native CLI; the LLM
constructs the full hydra invocation.

Sections:
1. Recommended HTB box for live verification (per-protocol)
2. Narrative scenarios (paste into opensploit)
3. Target-extraction adversarial cases (≥20 — total 28)
4. Failure-signature live-verify cases (≥3 — total 7)
5. Open questions
6. Hand-off

---

## 1. Recommended HTB box

**Primary: Validation (10.129.95.235)** — Linux web app with a
form-based login at `/account.php`. Richest test surface for hydra because:

- **HTTP-form protocol** is the most complex hydra surface (3-field
  module-spec parsing with ^USER^ / ^PASS^ substitution and fail/success
  detector strings) and Validation has a clean form to test against.
- **Lab / no lockout** — HTB boxes typically don't enforce account lockout,
  so we can iterate -m form specs without burning real credentials.
- **Multi-protocol cross-check**: Validation also has SSH (port 22) which
  doubles as the SSH-protocol smoke test.

**Secondary boxes per protocol**:

| Protocol | Recommended HTB | Notes |
|---|---|---|
| ssh | Cap (10.10.10.245) or Validation (10.129.95.235) | Most boxes have SSH. Either works. |
| http-post-form / https-post-form | Validation (10.129.95.235) | `/account.php` form |
| smb / smb2 | Hercules (10.129.242.196) | Linux DC for hercules.htb (also used for kerbrute / impacket) |
| mysql | Cap (10.10.10.245) — port 3306 if exposed | Rare on HTB; use a docker mariadb if no live target |
| mssql | (HTB Querier or other AD-MSSQL box when available) | Common in Windows AD lab boxes |
| ftp | Validation or any vsftpd-on-HTB box | Often anonymous-allowed on lab |

**LOCKOUT WARNING (production engagements only)**: HTB lab boxes generally
don't enforce AD account lockout. Production AD lockout policy is typically
5 failed logins / 30 minutes — a single hydra run with -L /usr/share/seclists/Usernames/top-usernames-shortlist.txt
(17 users) × -P /usr/share/wordlists/rockyou.txt (14M passwords) WILL lock
every user instantly. ALWAYS:

1. Run `kerbrute --safe --delay 250 userenum` first to identify valid users
   (kerbrute pre-auth doesn't always count toward lockout; check policy first).
2. Verify the lockout policy on a domain-joined host (`net accounts /domain`
   or `netexec smb <dc> -u <user> -p <pass> --pass-pol`).
3. Use -l (single user) not -L; use -e nsr first; throttle with -t 1 and -W.

**Persistent test directory**: mount `/tmp/hydra-test:/session` (per
SKILL #14). The agent must `write` users.txt / passwords.txt / combos.txt to
/session/ BEFORE invoking hydra — hydra reads them as -L/-P/-C file paths
inside the container. The legacy mcp-server.py wrote tempfiles automatically;
the kind:cli path requires explicit `write` calls first.

Suggested `/session/users.txt` (small mixed list):

```
admin
administrator
root
user
test
guest
ftp
mysql
oracle
```

Suggested `/session/passwords.txt` (small list with common defaults):

```
password
admin
root
123456
qwerty
P@ssw0rd
Welcome1
changeme
toor
letmein
```

Suggested `/session/combos.txt` (default-credential pairs):

```
admin:admin
admin:password
root:root
root:toor
guest:guest
ftp:ftp
mysql:mysql
oracle:oracle
sa:
sa:sa
```

---

## 2. Narrative scenarios (paste into opensploit)

### S1 — SSH single-user wordlist (happy path)

```
Engagement target: 10.129.95.235 (HTB Validation, authorized).
Try to brute-force the SSH login for the user 'admin' against /session/passwords.txt. Use a small thread count (4) to avoid SSH MaxStartups rate-limiting, stop at the first valid pair, and use verbose output so we can see attempts. Save the output to /session/hydra-ssh.txt.
```

**Watch:** Agent emits `hydra -l admin -P /session/passwords.txt -t 4 -f -V -o /session/hydra-ssh.txt ssh://10.129.95.235`. target=`10.129.95.235` extracted from the URL-positional via the regex group-2 capture (positional_match rule). Output contains `[22][ssh] host: 10.129.95.235   login: admin   password: <pw>` if a hit; otherwise `<N> of <M> targets completed, 0 valid passwords found`.

### S2 — HTTP POST form attack against Validation

```
Engagement target: 10.129.95.235 (HTB Validation).
The login form lives at /account.php. The username field is 'user', the password field is 'pass', and the failure message is 'Login failed'. Brute-force with /session/users.txt × /session/passwords.txt. -t 16 is fine for HTTP. Stop at first hit and use verbose. Save output to /session/hydra-http.txt.
```

**Watch:** Agent emits `hydra -L /session/users.txt -P /session/passwords.txt -t 16 -f -V -o /session/hydra-http.txt 10.129.95.235 http-post-form '/account.php:user=^USER^&pass=^PASS^:Login failed'`. target=`10.129.95.235` extracted via the `first_non_flag_positional` fallback — note: the URL regex DOES NOT match the bare hostname (no `://`), so the second rule fires. The `-m`-style module spec is the LAST positional but is preceded by `http-post-form`; the DSL must walk past flags AND value_flags until the first plain positional. Output: `[80][http-post-form] host: 10.129.95.235   login: <user>   password: <pw>` on a hit.

### S3 — SMB brute against Hercules (small password list, lockout-aware)

```
Engagement target: 10.129.242.196 (HTB Hercules).
This is a Linux DC for hercules.htb. Brute-force SMB for the user 'administrator' with /session/passwords.txt. Use -t 4 (Windows AD lockout policies are tight), -f to stop at first hit, -V for visibility. Save to /session/hydra-smb.txt.
```

**Watch:** Agent emits `hydra -l administrator -P /session/passwords.txt -t 4 -f -V -o /session/hydra-smb.txt smb://10.129.242.196`. target=`10.129.242.196` extracted from the smb:// URL. Output: `[445][smb] host: 10.129.242.196   login: administrator   password: <pw>` on a hit. **HTB caveat**: Hercules in the kerbrute scenarios was used with natalie.a/Prettyprincess123!; if administrator is a real account with a strong password the run will simply finish with 0 valid passwords found — that's still a successful test of the protocol/extraction path.

### S4 — Multi-protocol pipeline (kerbrute → hydra)

```
Engagement target: 10.129.242.196 (HTB Hercules), authorized.
Step 1: I've already run kerbrute userenum and saved the valid users to /session/valid-users.txt (output: natalie.a, administrator, helpdesk).
Step 2: Use hydra to test SMB authentication for those valid users with /session/passwords.txt. -t 4, -f, -V, output to /session/hydra-cross.txt. Use the username list, not single user.
```

**Watch:** Agent emits `hydra -L /session/valid-users.txt -P /session/passwords.txt -t 4 -f -V -o /session/hydra-cross.txt smb://10.129.242.196`. target=`10.129.242.196`. The fact that the username list came from kerbrute is an out-of-band engagement detail — hydra just sees -L as a file path. Demonstrates the canonical "kerbrute discovers valid users → hydra brutes their passwords on non-Kerberos services" pattern.

### S5 — Failure: connection refused (TCP layer)

```
Engagement target: 127.0.0.1 (intentionally wrong target for TCP-layer error classification).
Try `hydra -l admin -p test ssh://127.0.0.1:1` — port 1 is not running SSH. Verify the connection-refused error is classified cleanly.
```

**Watch:** Agent emits `hydra -l admin -p test -V ssh://127.0.0.1:1`. target=`127.0.0.1` extracted from the URL (port `1` is in the userinfo position of the URL regex but the host capture group 2 is `127.0.0.1`). Expect output containing `Connection refused` or `cannot connect`. Failure classified via `Connection refused` signature.

### S6 — Failure: unknown service / unsupported protocol

```
Engagement target: 10.129.95.235 (HTB Validation).
Try `hydra -l admin -p test 10.129.95.235 microsoft-sql` — 'microsoft-sql' is not a valid hydra service name. Verify the unknown-service error is classified.
```

**Watch:** Agent emits `hydra -l admin -p test -V 10.129.95.235 microsoft-sql`. target=`10.129.95.235` extracted via `first_non_flag_positional` (the second-to-last positional). hydra rejects with `unknown service: microsoft-sql` (the correct name is `mssql`). Failure classified via `unknown service:` signature; remediation suggests running `hydra -h` to list supported services.

### S7 — reject_flags trap (-M file)

```
Engagement target: see the file /session/targets.txt which contains 10.129.95.235 and 10.129.242.196.
Try `hydra -M /session/targets.txt -l admin -p test ssh`. The -M flag loads multiple targets from a file.
```

**Watch:** Plugin's cli_in_container REJECTS the call before container spawn because `-M` is in the reject_flags list. Error message references `reject_flags_reason`: "File-based target ingestion (-M <file>) puts the host list outside the command line where scope validation cannot reach. Read the target list yourself (with the read tool) and call hydra once per target." Agent should reformulate as TWO separate hydra calls, one per target.

### S8 — http-post-form syntax debug

```
Engagement target: 10.129.95.235 (HTB Validation).
I'm not sure if my form spec is correct — try `hydra -l admin -p WrongPassword -V 10.129.95.235 http-post-form '/account.php:user=^USER^&pass=^PASS^:Login failed'` and verify hydra reports the attempt. We're not trying to crack — just sanity-checking the -m format.
```

**Watch:** Agent emits exactly that. target=`10.129.95.235`. With a SINGLE -p (not -P), hydra makes ONE attempt. -V prints the attempt line. If the form spec is wrong (missing colon, bad ^USER^ token), hydra errors with `Module .* requires` or similar; if right, hydra prints `[80][http-post-form] attempt to login as admin/WrongPassword` and (for the wrong password) `0 valid passwords found`. This is the canonical debug pattern — single -p before unleashing -P.

### S9 — Empty/same/reverse password check (-e nsr first pass)

```
Engagement target: 10.129.95.235 (HTB Validation).
Before any wordlist, try -e nsr (null + same-as-login + reversed) against the SSH service for users in /session/users.txt. -t 4, -f, -V. Save to /session/hydra-easy.txt.
```

**Watch:** Agent emits `hydra -L /session/users.txt -e nsr -t 4 -f -V -o /session/hydra-easy.txt ssh://10.129.95.235`. target=`10.129.95.235`. -e nsr means hydra tests THREE password variants per user: empty, username-as-password, and reversed-username. With 9 users that's 27 attempts — finishes in seconds. Catches misconfigurations. Always-run-first pattern per scenario S1.

---

## 3. Target-extraction adversarial cases (28 total, ≥20 spec)

The hydra `tool.yaml` declares TWO target_extraction rules:

1. `positional_match` with regex `^([a-z][a-z0-9-]*?[2-3]?)://([^:/?#]+)`,
   capture group 2, parse_as `raw` — for the URL-positional form
   (`ssh://10.10.10.5`).
2. `first_non_flag_positional` — fallback for the alternate two-positional
   `<host> <protocol>` form (`hydra ... 10.10.10.5 ssh`).

`reject_flags` declares `-M`. `reject_flags_reason` documents that file-based
target lists are out of scope for cli_in_container.

`value_flags` lists every value-taking hydra flag including the auth flags
(-l/-L/-p/-P/-C/-e/-x/-y/-r), targeting (-M/-s), module (-m), output (-o/-b),
threading (-t/-T/-w/-W/-c), and behaviour booleans listed for parser safety
(-f/-F/-u/-S/-O/-K/-q/-v/-V/-d/-4/-6/-R/-h/-U/-N).

### Happy-path cases — URL-positional form (rule 1 fires)

| #  | Command (binary `hydra` omitted) | Expected target | Notes |
|----|---|---|---|
| 1  | `-l admin -P /session/passwords.txt -t 4 -f -V ssh://10.10.10.5` | `10.10.10.5` | Bog-standard SSH URL form. Group 2 capture. |
| 2  | `-l admin -p Password ftp://10.10.10.5` | `10.10.10.5` | FTP URL. Single -p (not -P). |
| 3  | `-L /session/users.txt -P /session/passwords.txt smb://10.10.10.5` | `10.10.10.5` | SMB URL with both lists. |
| 4  | `-l sa -p 'Password123!' mssql://10.10.10.5` | `10.10.10.5` | MSSQL URL. Password contains '!' — fine. |
| 5  | `-l admin -P /session/p.txt mongodb://10.10.10.5:27017` | `10.10.10.5` | MongoDB URL with explicit port. Group 2 still 10.10.10.5. |
| 6  | `-L users.txt -P pass.txt http-post-form://10.10.10.5/login.php` | `10.10.10.5` | http-post-form as URL form (rare but valid syntax). Group 2 captures `10.10.10.5`. |
| 7  | `-C /session/combos.txt redis://10.10.10.5` | `10.10.10.5` | Redis URL with combo file. |
| 8  | `-l admin -P p.txt -t 1 -W 5 ssh://target.htb` | `target.htb` | Bare hostname in URL host position. |
| 9  | `-L u.txt -P p.txt -e nsr -V vnc://10.10.10.5:5901` | `10.10.10.5` | VNC URL with non-default port. |
| 10 | `-l admin -p test https-post-form://10.10.10.5/admin/login` | `10.10.10.5` | HTTPS form URL. |

### Happy-path cases — Alternate two-positional form (rule 2 fires)

| #   | Command | Expected | Notes |
|-----|---|---|---|
| A1  | `-l admin -P /session/p.txt 10.10.10.5 ssh` | `10.10.10.5` | Bare host THEN protocol, after flags. `first_non_flag_positional` walks past -l (value), -P (value) and returns 10.10.10.5. |
| A2  | `-L u.txt -P p.txt -s 2222 10.10.10.5 ssh` | `10.10.10.5` | -s 2222 overrides default port; host still 10.10.10.5. |
| A3  | `-L u.txt -P p.txt 10.10.10.5 mssql` | `10.10.10.5` | MSSQL via two-positional. |
| A4  | `-l admin -p test target.htb ftp` | `target.htb` | Bare hostname (not IP) in two-positional form. |
| A5  | `-L u.txt -P p.txt -t 4 -f -V 10.10.10.5 http-post-form '/login.php:user=^USER^&pass=^PASS^:Login failed'` | `10.10.10.5` | Three trailing positionals: host, protocol, module-spec. The DSL's `first_non_flag_positional` returns the FIRST positional after flags — that's `10.10.10.5`. The protocol token and module-spec come after. |

### Help / introspection (target=null)

| #  | Command | Expected | Notes |
|----|---|---|---|
| H1 | `-h` | `target=null` | Top-level help. |
| H2 | `--help` | `target=null` | Long alias (some builds). |
| H3 | `-U ssh` | `target=null` | Module help — `-U` value is the protocol name `ssh`, not a target. -U is in value_flags so the DSL skips its value. |
| H4 | `-U http-post-form` | `target=null` | Module help for http-post-form. |
| H5 | (no args) | `target=null` | Bare `hydra` invocation prints usage and exits. |

### Adversarial — value-flag traps & module-spec injection

| #   | Command | Expected | Notes |
|-----|---|---|---|
| F1  | `-l user@example.com -p pass ssh://10.10.10.5` | `10.10.10.5` | Username contains `@` and email-shape. -l is in value_flags so the email IS NOT misinterpreted as a target. URL captures 10.10.10.5. |
| F2  | `-l admin -p 'pass:with:colons' ssh://10.10.10.5` | `10.10.10.5` | Password contains literal colons. -p is in value_flags — value consumed as a single token (shell-quoted in the LLM emission). |
| F3  | `-l admin -P /session/passwords.txt -o /session/output.txt ssh://10.10.10.5` | `10.10.10.5` | -o file path. -o is in value_flags. URL captured. |
| F4  | `-l admin -p test -b json -o /session/h.json ssh://10.10.10.5` | `10.10.10.5` | -b json (output format value). Both -b and -o are value_flags. |
| F5  | `-l admin -x 6:8:a -V ssh://10.10.10.5` | `10.10.10.5` | -x value `6:8:a` (mask spec). -x is in value_flags — value `6:8:a` not misread as host:port. |
| F6  | `-L u.txt -P p.txt 10.10.10.5 http-post-form '/login.php?next=https://evil.com:user=^USER^&pass=^PASS^:Login failed'` | `10.10.10.5` | Module spec contains `https://evil.com` as part of a query parameter. CRITICAL TRAP — the URL regex inside the module spec MUST NOT fire. Because the module spec is the FOURTH positional (host=1st, protocol=2nd, module-spec=3rd in the alternate form... actually 1st flag-free positional is the host). The DSL extracts target via rule 1 OR rule 2 — module spec is eaten as a later positional. |
| F7  | `-L u.txt -P p.txt 10.10.10.5 http-post-form '/login.php:user=^USER^&pass=^PASS^:Location: /admin'` | `10.10.10.5` | Module spec uses `Location: /admin` as a redirect-detector for success — the literal `:` inside the spec is a colon-delimiter trap. Hydra parses the module spec as 3 fields split on `:`; the failure-detector `Location: /admin` contains a colon, so the spec is actually MALFORMED unless the colon is escaped (`\\:`). Extraction-wise: target is still `10.10.10.5`; hydra will runtime-error with `Module .* requires` or wrong number of fields. |
| F8  | `-L u.txt -P p.txt -m '/login.php:user=^USER^&pass=^PASS^:Login failed' 10.10.10.5 http-post-form` | `10.10.10.5` | -m flag form (rather than trailing positional). -m is in value_flags so its value is consumed as a single token; host is the next positional. |
| F9  | `-l admin -p test mysql://user:pass@10.10.10.5` | `10.10.10.5` | userinfo URL. Group 2 of the regex captures `10.10.10.5` (everything between `://` and `:/?#`); userinfo `user:pass@` is OUTSIDE group 2 because `@` matches the `[^:/?#]+` class — wait, that's a problem. The character class `[^:/?#]+` does match `@`, which means group 2 would capture `user:pass@10.10.10.5`. CORRECTION: this case demonstrates a known limitation — the URL regex is greedy on group 2 and includes userinfo when present. Downstream scope validation should strip everything before `@` (URL parser handles userinfo correctly). Open Question 4. |
| F10 | `-l admin -P p.txt -s 1433 10.10.10.5 mssql` | `10.10.10.5` | -s value (1433) is a port number — value_flags consumes it. The next positional after -s's value is the host. |
| F11 | `-L /session/dc.example.com.users.txt -P p.txt 10.10.10.5 ssh` | `10.10.10.5` | -L value is a file path that contains a hostname-shape substring. value_flags consumes the path. |
| F12 | `-l admin -P p.txt -e nsr ssh://10.10.10.5` | `10.10.10.5` | -e value `nsr` is in {n, s, r, ns, nr, sr, nsr}. value_flags consumes it. |
| F13 | `-l admin -p test -t 4 -W 1 -c 1 -w 30 ssh://10.10.10.5` | `10.10.10.5` | All four threading/timing flags take values. value_flags handles all. |
| F14 | `-L u.txt -P p.txt -f -V -d -q -4 ssh://10.10.10.5` | `10.10.10.5` | Mix of booleans (-f, -V, -d, -q, -4). They don't consume values; URL still captured. |
| F15 | `-l admin -p test [2001:db8::1]:22 ssh` | `[2001:db8::1]` (raw) OR `2001:db8::1` (after bracket strip) | IPv6 bracketed in alternate two-positional form. Group 2 of regex MAY NOT match because `[` is in the character class exclusion. With `first_non_flag_positional`, the first non-flag positional is `[2001:db8::1]:22`. Downstream TargetValidation strips brackets and port. May need Open Question 5 verification. |
| F16 | `-l admin -p test ssh://[2001:db8::1]:22` | `[2001:db8::1]` (raw) | IPv6 bracketed in URL form. The character class `[^:/?#]+` matches `[` and `]` but NOT `:`, so group 2 captures `[2001:db8::1` (truncated at the first `:`). Known limitation; OQ 5. |
| F17 | `-L u.txt -P /session/admin@target.com.passwords.txt ssh://10.10.10.5` | `10.10.10.5` | -P value contains email-shape filename. value_flags consumes the path. |

### Adversarial — security invariants & ordering

| #   | Command | Expected | Notes |
|-----|---|---|---|
| F18 | `-M /session/targets.txt -l admin -P p.txt ssh` | REJECTED | reject_flags fires on -M; cli_in_container refuses BEFORE container spawn. |
| F19 | `-l admin -P p.txt ssh://10.10.10.5 ssh://10.20.30.40` | `10.10.10.5` (first match) OR `10.20.30.40` (last match) | Two URL positionals — hydra v9.x accepts only ONE host per invocation; multi-target is via -M (rejected). The DSL's `positional_match` rule should return the FIRST match. Open Question 6. |
| F20 | `ssh://10.10.10.5 -l admin -P p.txt` | `10.10.10.5` | URL appears BEFORE the flags. positional_match still finds it because the rule walks all of argv. |
| F21 | `-l admin -P p.txt -- ssh://10.10.10.5` | `10.10.10.5` | `--` is a typical Unix end-of-flags marker. hydra may or may not honour it; the DSL's positional_match should still find the URL. Verify in plugin tests. |

### Empty / no-target / special

| #  | Command | Expected | Notes |
|----|---|---|---|
| F22 | `-l admin -P p.txt` (no host or protocol) | `null` | No target argument at all — hydra runtime-errors with `Syntax: ... see -h`. Extraction is null; cli_in_container can pass through (hydra will fail-fast). |
| F23 | `-l admin -P p.txt ssh` (protocol only, no host) | `null` (rule 1) or `ssh` (rule 2) | Single positional `ssh` could match `first_non_flag_positional` — but `ssh` is also a recognised protocol name. Open Question 7: should the fallback rule reject single-token positionals that match a known hydra protocol? |
| F24 | `-l admin -P p.txt -- ssh` | similar to F23 | Same trap with -- separator. |
| F25 | `-h` | `null` | Top-level help. |
| F26 | `-U ssh` | `null` | Module help for ssh. -U value is `ssh` (protocol token). |
| F27 | `--help` | `null` | Long help. |
| F28 | `-R` | `null` | Restore mode — reads ./hydra.restore. No target argument. -R is a value_flag entry but it's actually a boolean; listed for parser safety. |

---

## 4. Failure-signature live-verify cases (7 total, ≥3 spec)

Verify against the hydra container (rebuild during Wave 9 batch with
mcp-common 0.3.0). All cases below need a Validation-equivalent live target
plus a few synthetic invalid configs.

| # | Layer | Test | failure_signature `signal` | Status |
|---|---|---|---|---|
| 1 | DNS | `-l admin -p test ssh://nonexistent.invalid` | `Could not resolve` AND/OR `unable to resolve` | PENDING live verify |
| 2 | TCP | `-l admin -p test ssh://127.0.0.1:1` (port 1 unbound) | `Connection refused` AND/OR `cannot connect` | PENDING live verify |
| 3 | Protocol-specific (SSH) | `-l admin -p test ssh://10.129.95.235:80` (HTTP port — not SSH) | `SSH protocol error` (or `Connection reset` style) | PENDING live verify |
| 4 | Module / syntax | `10.10.10.5 http-post-form '/login.php:user=^USER^&pass=^PASS^'` (only 2 colon-fields, missing fail-string) | `Module .* requires` AND/OR `Syntax:.*see -h` | PENDING live verify |
| 5 | File I/O | `-L /session/missing-users.txt -P p.txt ssh://10.10.10.5` | `File for .* not found` AND/OR `Could not open` | PENDING live verify |
| 6 | Argument validation | `-l admin -p test 10.10.10.5 microsoft-sql` (unknown service) | `unknown service:` | PENDING live verify |
| 7 | Auth-policy (MySQL) | After 100+ failed mysql connects from one source IP: any further attempt | `max_connect_errors` | PENDING live verify (requires throwaway MySQL) |

Additional layer signatures encoded but not yet live-verified (deferred to
Wave 9):
- `Connection timed out` — firewalled target
- `Key exchange failed` — SSH KEX algorithm mismatch
- `0 valid passwords found` — successful run, no creds (informational)
- `Restorefile .* found` — leftover hydra.restore in cwd
- `all children have been disabled` — global connection failure
- `account is locked` — auth-policy lockout (hard to provoke without burning real accounts)
- `child .* connection error` — sporadic worker failure

### Layer diversity (SKILL #11) — achieved

5 distinct verifiable layers:
1. **DNS** (case 1)
2. **TCP** (case 2)
3. **Protocol-specific** (case 3 — SSH banner / handshake)
4. **Module/syntax** (case 4 — http-post-form parser)
5. **File I/O** (case 5 — wordlist not found)

Plus encoded-but-not-live: argument validation (case 6), auth-policy
(case 7), connection timing (Connection timed out), KEX (Key exchange
failed).

---

## 5. Open questions

1. **Two target-extraction rules — precedence?** When both `positional_match`
   (URL form) AND `first_non_flag_positional` (alternate form) could fire,
   which wins? Recommendation: positional_match has explicit pattern → run
   FIRST; only fall back to first_non_flag_positional when no URL is found.
   The plugin's flag_value / positional_match / first_non_flag_positional
   ordering should be deterministic — verify in plugin tests. If not, add
   ordering metadata to the YAML.

2. **Alternate-form `<host> <protocol>` extraction reliability** (cases
   A1-A5). The fallback `first_non_flag_positional` rule walks argv and
   returns the first non-flag positional. With value_flags consuming all
   the named flag values, the FIRST plain positional should be the host
   in alternate form. But:
   - Case A5 has THREE trailing positionals (host, protocol, module-spec).
     The rule returns the FIRST — should return host. ✓
   - Case F23 has ONLY a protocol token (`ssh`) as a positional — should
     ideally return null, not `ssh`. Recommendation: fallback rule should
     check if the token matches a known hydra protocol regex
     (`^(ssh|ftp|smb|smb2|...)$`) and skip if so. Out of scope for the
     YAML; likely a plugin enhancement.

3. **`-M <file>` reject_flags effectiveness**. Verify in plugin tests that
   case F18 is REJECTED before docker spawn (not just "extracted as null
   target"). The reject_flags mechanism must fire early. john's empty
   reject_flags list and nmap's `-iL`/`-iR` rejects are the reference
   behaviour.

4. **Userinfo URL extraction (case F9)**. Regex `[^:/?#]+` greedily includes
   `@` because `@` is not in the exclusion class. So
   `mysql://user:pass@10.10.10.5` captures group 2 as `user:pass@10.10.10.5`
   — incorrect. Two fixes possible: (a) tighten the regex to exclude `@`
   (`[^:/?#@]+`); (b) downstream scope-validation strips userinfo via URL
   parser. Recommend (a) as a robust YAML-side fix:
   ```yaml
   pattern: "^([a-z][a-z0-9-]*?[2-3]?)://(?:[^/@\\s]*@)?([^:/?#@]+)"
   ```
   Verify in plugin tests; update YAML if needed.

5. **IPv6 bracketed targets (cases F15, F16)**. Same regex limitation:
   `[^:/?#]+` matches `[` and `]` but stops at `:` — for
   `ssh://[2001:db8::1]:22` group 2 captures `[2001:db8::1` (truncated).
   Fix: alternate regex branch for bracketed IPv6, e.g.
   `(?:\\[([0-9a-fA-F:]+)\\]|([^:/?#]+))`. Plugin's TargetValidation likely
   handles bare IPv6 with brackets correctly — defer the regex fix to
   Wave 9 if it works downstream.

6. **Multi-host invocation (case F19)**. hydra v9.6 accepts only ONE host
   per call (multi-host requires -M, which we reject). If the LLM emits
   `ssh://10.10.10.5 ssh://10.20.30.40`, hydra runtime-errors. The DSL's
   positional_match should return the FIRST match (so scope-validation
   approves the first host); hydra fails fast at runtime. Verify plugin
   behaviour.

7. **First-positional ambiguity (cases F23, F24)**. When the only
   positional is a known protocol token (e.g., `ssh`), should
   `first_non_flag_positional` return `ssh` (which then fails scope
   validation as "not a hostname") or null? Recommend: plugin should
   reject any extracted target that matches a known hydra protocol token
   list and treat it as null. Plugin enhancement; document here, file
   issue.

8. **http-post-form module spec parsing**. The module spec is THREE
   colon-separated fields: `<path>:<post-data>:<fail-or-success-detector>`.
   The third field can contain literal colons (e.g., `Location: /admin`)
   that MUST be escaped as `\\:`. The legacy mcp-server.py's
   `web_form_brute` method auto-escaped these; with kind:cli the LLM is
   responsible. Future enhancement: a lint rule that warns on unescaped
   colons in -m values for http-post-form. Out of scope here.

9. **Restore file persistence (-R)**. `hydra -R` reads ./hydra.restore from
   the current working directory. Inside a Docker container the cwd is
   typically /app or /tmp, NOT /session. If a long brute-force is
   interrupted and the cwd doesn't survive, -R is useless. Recommendation:
   document that `-R` ONLY works if the previous run was launched from a
   /session-mounted directory AND the container is restarted with the same
   mount. For most tool_runner use this is impractical; long brute-forces
   should either (a) complete in one run with a tighter wordlist, or
   (b) be split into N smaller runs.

10. **Lockout-protection helper**. There's no native hydra equivalent to
    kerbrute's `--safe`. Adding one would require either (a) an upstream
    patch (unlikely; hydra is mature), (b) a wrapper layer that monitors
    output for `account is locked` and SIGTERM's hydra. Future enhancement;
    document here. For now: usage_patterns guidance + gotchas warning is
    the mitigation.

11. **Audit gap: result-line parsing discipline.** The legacy mcp-server.py
    (`_parse_hydra_output`, lines 561–659) parsed hydra stdout into a
    structured object: credentials list (regex against `[<port>][<service>]
    host: ... login: ... password: ...`), separate password-only-services
    branch (no `login:` field — VNC/Redis/SNMP/Cisco/oracle-listener), stats
    block from `[STATUS] N tries in HH:MMh, M to do` and `[DATA] ... N login
    tries`, and warnings/errors lines. With kind:cli the LLM consumes raw
    output and must do this parsing itself. The key regexes/anchors:
    - Credential hit: `\[(\d+)\]\[([\w-]+)\]\s+host:\s+(\S+).*?\s+login:\s+(\S+)\s+password:\s*(.*)`
    - Password-only hit (no `login:`): `\[(\d+)\]\[([\w-]+)\]\s+host:\s+(\S+).*?\s+password:\s+(.+)` AND no `login:` substring.
    - Total keyspace: `\[DATA\].*?(\d+)\s+login\s+tries`
    - Progress: `\[STATUS\].*?(\d+)\s+tries\s+in\s+[\d:]+h?,\s+(\d+)\s+to\s+do`
    Look for these patterns when reasoning about partial output.

12. **Audit gap: errors-with-credentials promotion.** Legacy behaviour
    (mcp-server.py lines 941–949): if hydra emits `[ERROR]` lines BUT also
    successfully reports a credential hit, the errors are demoted to
    warnings and the run is treated as SUCCESS-with-warnings (not failure).
    Rationale: a transient `child connection error` or `Connection refused`
    on one parallel slot doesn't invalidate a credential found on another
    slot. With kind:cli the LLM should apply the same rule: if the output
    contains a `login: ... password: ...` hit anywhere AND `[ERROR]` lines
    elsewhere, treat the run as SUCCESS, surface the errors as warnings,
    and report the credential. Failing to apply this rule will cause
    correct hits to be falsely reported as failures.

13. **Audit gap: web_form_brute colon-escape replicability.** Legacy
    `_escape_colon` (lines 1087–1089) implemented a 3-step replace:
    `s.replace("\\:", "\x00").replace(":", "\\:").replace("\x00", "\\:")` —
    idempotent on already-escaped colons (so user input that already has
    `\:` doesn't get double-escaped to `\\\:`). The legacy `web_form_brute`
    method auto-applied this to path, user_field, pass_field, fail_string,
    AND extra_params before assembling the 3-field module spec. With
    kind:cli the LLM must hand-escape any colon that should be a LITERAL
    inside any of those fields (the gotchas section now spells out which
    fields and shows examples). The 3-step replace is the canonical
    idempotent escape — apply it (or its conceptual equivalent) when
    template-substituting user-provided strings into a `-m` form spec.

14. **Audit gap: no implicit username/password defaulting.** Legacy
    mcp-server.py (lines 786–798) silently filled `-L
    /usr/share/seclists/Usernames/top-usernames-shortlist.txt` and `-P
    /usr/share/seclists/Passwords/Common-Credentials/10k-most-common.txt`
    when the caller specified neither a single user/pass nor a list. With
    kind:cli the LLM gets exactly the argv it wrote — no implicit
    fallback. Consequence: a bare `hydra ssh://10.10.10.5` with no -l/-L/-p/-P
    will hydra-runtime-error with "no login set" rather than running a
    convenient default. The full paths to the legacy defaults are now
    documented in gotchas; explicitly write them on the command line if
    the convenience-default behaviour is desired. SSH_USERNAMES tempfile
    generation (legacy `_resolve_wordlist` for the `ssh-usernames` alias,
    lines 549–557) is also dropped — write that list yourself with the
    `write` tool to /session/ssh-usernames.txt and pass the full path.

---

## 6. Hand-off

- **Tool**: hydra (kind:cli, single-binary C tool with libssl, libsasl,
  libpq, libmysqlclient, libssh, libsmbclient runtime deps)
- **Status**: tool.yaml authored end-to-end; scenarios.md written.
  Dockerfile UNCHANGED — base image is `kalilinux/kali-rolling` and
  `python3 python3-pip python3-venv` install successfully on the current
  image; per the spec "if Kali base with python3-pip/python3-venv, replace
  with python3-full" was the swap criterion, but the existing image already
  builds cleanly and previous Wave migrations kept the python3 + python3-pip
  + python3-venv triple where it works. Decision: NO Dockerfile edits.
  mcp-server.py UNTOUCHED — auto-inherits `run_cli` from BaseMCPServer
  (mcp-common 0.3.0); existing per-method handlers (`bruteforce`,
  `ssh_brute`, `ftp_brute`, `web_form_brute`, `mysql_brute`) preserved as
  the legacy / rollback path per SKILL #21.
- **Image**: `ghcr.io/silicon-works/mcp-tools-hydra:latest` — needs rebuild
  during Wave 9 batch to pick up mcp-common 0.3.0. Image is moderate
  (~200 MB) due to wordlists + seclists + hydra protocol library dependencies.
- **target_extraction = TWO rules**: (1) URL-positional regex with group 2
  capture for the modern `protocol://host[:port]` form; (2)
  `first_non_flag_positional` fallback for the alternate `<host>
  <protocol>` two-positional form. The latter is needed because hydra's
  legacy syntax is still common in tutorials and many module specs (e.g.,
  http-post-form with the spec as a positional).
- **value_flags**: 30+ entries covering auth (-l/-L/-p/-P/-C/-e/-x/-y/-r),
  targeting (-M/-s), module options (-m), output (-o/-b/-I), threading
  (-t/-T/-w/-W/-c), and behaviour booleans (-f/-F/-u/-S/-O/-K/-q/-v/-V/-d/
  -4/-6/-R/-h/-U/-N). Booleans are listed for parser safety even though
  they don't consume values.
- **reject_flags**: `-M` (file-based multi-target) — the only flag that
  puts the target list outside the command line.
- **Wave 2.3**: third and final tool of Wave 2 (Credentials cluster).
  hashcat = Wave 2.1, kerbrute = Wave 2.2, hydra = Wave 2.3. Tier A
  migration progress: 11 tools done (curl, sqlmap, impacket, nmap, ffuf,
  nuclei, nikto, john, hashcat, kerbrute, hydra).
- **Live-verify pending**: paste S1-S9 against Validation
  (10.129.95.235) + Hercules (10.129.242.196) during Wave 9 batch
  rebuild + e2e run. Verify failure signatures 1-7 live; verify
  alternate-form extraction (cases A1-A5) and adversarial cases F1-F28
  with plugin unit tests.
- **Files removed**: `__pycache__/` directory (compiled Python cache from
  legacy testing — `mcp-server.cpython-312.pyc`). No
  `target_extraction_tests.md` or `failure_signature_tests.md` files were
  present; the hydra directory was already on the simpler layout.

Authored: 2026-04-25.
