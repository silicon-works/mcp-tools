# mysql — Tier A scenarios

Single test sheet for the `mysql` tool migration. Replaces the legacy split
(`target_extraction_tests.md` + `failure_signature_tests.md`) — neither file
existed in this directory; the consolidated form is the standard going forward.

Sections:
1. Recommended HTB box for live verification
2. Narrative scenarios (paste into opensploit)
3. Target-extraction adversarial cases (≥20)
4. Failure-signature live-verify cases (≥3)
5. Open questions
6. Hand-off

---

## 1. Recommended HTB box

**Falafel (10.10.10.73, retired Linux)** — runs MySQL 5.5.x with a deliberate
SQLi → file-read → SSH key extraction chain. After the SQLi gives you the
`moshe:` cleartext, port 3306 is firewalled but you can pivot via SSH and run
`mysql -h 127.0.0.1 -u moshe -pSecret -e 'SELECT VERSION()'` from inside the
box. The box exercises: (a) auth happy-path, (b) `LOAD_FILE` for SSH key
read, (c) `INTO OUTFILE` denied by `secure_file_priv`, (d) older
`password` column (5.5 is pre-5.7-rename).

**Alternative — Mirai (10.10.10.48, retired Linux)** — Pi-hole with a
default `pi:raspberry` SSH login; MySQL is bound to localhost only.
Useful for the SSH-then-mysql `127.0.0.1` pivot pattern.

**Standalone alternative — vulhub mysql/CVE-2012-2122**: ships with
deliberate auth bypass — useful for testing the `Access denied for user`
failure-signature path (cycling through random passwords until the bypass
fires). Run inside the test infra rather than HTB if unrelated boxes are
needed.

For Tier A migration verification, what matters is that the **architecture
path** is wired (kind:cli routes through cli_in_container, target extraction
catches `-h`, password no-space gotcha doesn't trip the parser). The vendor
behaviour is well-documented; Falafel-style tests confirm the integration.

---

## 2. Narrative scenarios (paste into opensploit)

### S1 — `mysql --version` (smoke)

```
Engagement target: none — running mysql --version through opensploit to confirm the kind:cli path is wired and the container is reachable. Report the version string and identify whether this is the Oracle MySQL or MariaDB client.
```

**Watch:** First call ~3 s (container spawn + MCP handshake), exit 0, stdout
matches either `mysql  Ver 8.0.x for Linux` (Oracle MySQL client) or
`mysql  Ver 15.1 Distrib 10.x-MariaDB` (MariaDB client — Kali default since
`default-mysql-client` resolves to `mariadb-client`). Confirms persistent
container reuse on subsequent calls.

### S2 — Version check + list databases (happy path)

```
Engagement target: 10.129.95.84 (HTB Falafel-equivalent, authorized).
The user moshe has the MySQL password 'falafel' from the SQLi. Use mysql to (1) confirm the credential works with SELECT VERSION(), then (2) list all databases via SHOW DATABASES. Use -B for TSV output.
```

**Watch:** target=`10.129.95.84` extracted from `-h`; first call returns the
mysql server version; second call returns 4-7 databases (mysql,
information_schema, performance_schema, sys + one or two app DBs). Both
calls exit 0 with parseable TSV stdout. `-pfalafel` (no space) parsed as a
single value-flag-with-value, NOT split into `-p` + `falafel` positional.

### S3 — Dump password hashes from mysql.user

```
Engagement target: 10.129.95.84 (authorized).
You have root@localhost MySQL access via the SQLi-derived creds. Dump the user, host, and authentication_string columns from mysql.user. Use -B -N -s for clean parseable output.
```

**Watch:** target=`10.129.95.84`; output has 3 columns separated by tabs, no
header row, no footer. Hash column shows `*40HEX` (mysql_native_password)
or empty (auth_socket) or `$A$005$...` (caching_sha2). Useful for handing
off to john / hashcat. tool_runner doesn't truncate the binary-looking hash
field.

### S4 — SSL-required connection (force REQUIRED)

```
Engagement target: 10.129.95.84 (authorized — this server is MySQL 8.0 with require_secure_transport=ON).
Connect with --ssl-mode=REQUIRED and run SELECT @@have_ssl, @@require_secure_transport.
```

**Watch:** TLS handshake completes; query returns `YES YES` (server confirms
SSL is on). If the server is MySQL 5.x with ssl off, this would fail with
`SSL connection error` — that case is in S6.

### S5 — LOAD_FILE for SQLi-derived file read

```
Engagement target: 10.129.95.84 (authorized).
The auth user has FILE privilege. Read /etc/passwd via SELECT LOAD_FILE('/etc/passwd'). Use a single -e query.
```

**Watch:** target=`10.129.95.84`; the LOAD_FILE returns the /etc/passwd
contents as a single column value with embedded newlines. tool_runner
preserves the multi-line output. NULL return would indicate either FILE
privilege missing or `secure_file_priv` blocking the path.

### S6 — Failure: wrong password (Access denied)

```
Engagement target: 10.129.95.84 (authorized — using deliberately wrong password to verify error classification).
Test mysql connection with -u root -pwrong-password and see how the error is classified.
```

**Watch:** Exit code 1; stderr contains `ERROR 1045 (28000): Access denied
for user 'root'@'<source-ip>' (using password: YES)`. Classified as
`failure_in_output` matching the `Access denied for user` /
`ERROR 1045` signals. tool_runner reports the auth failure cleanly with no
container-side timeout.

### S7 — Failure: wrong host (DNS resolution)

```
Engagement target: nonexistent-host.invalid.localdomain (deliberately invalid, verifying DNS error classification).
Test mysql -h nonexistent-host.invalid.localdomain -u root -pSecret -e 'SELECT 1'.
```

**Watch:** Exit code 1; stderr contains `Unknown MySQL server host
'nonexistent-host.invalid.localdomain'` or `Can't resolve hostname`.
Classified as `failure_in_output` matching the DNS signals.

---

## 3. Target-extraction adversarial cases (≥20)

The mysql `tool.yaml` declares two rules (first match wins):

1. `flag_value` for `-h` with `parse_as: raw`
2. `flag_value` for `--host` with `parse_as: raw`

The first positional is a DATABASE NAME (sets default DB), NOT a host —
this is the central anti-pattern this tool's extraction must avoid.

### Happy-path cases

| # | Command (binary `mysql` omitted) | Expected target | Notes |
|---|---|---|---|
| 1 | `-h 10.10.10.5 -u root -pSecret -e 'SELECT 1'` | `10.10.10.5` | Standard IPv4 host |
| 2 | `-h 10.10.10.73 -u moshe -pfalafel -e 'SELECT VERSION()'` | `10.10.10.73` | HTB Falafel pattern with -p<password> no space |
| 3 | `-h target.local -u admin -pPass123 -e 'SHOW DATABASES'` | `target.local` | Hostname (not IP) |
| 4 | `-h db.corp.target.com -u root -pSecret -e 'SHOW DATABASES'` | `db.corp.target.com` | FQDN |
| 5 | `-h 2001:db8::1 -u root -pSecret -e 'SELECT 1'` | `2001:db8::1` | IPv6 literal — `parse_as: raw` preserves it as-is |
| 6 | `-h 10.10.10.5 -P 3307 -u root -pSecret -e 'SELECT 1'` | `10.10.10.5` | Non-default port via -P (capital) |
| 7 | `--host=10.10.10.5 -u root -pSecret -e 'SELECT 1'` | `10.10.10.5` | Long-form --host=value |
| 8 | `--host 10.10.10.5 -u root -pSecret -e 'SELECT 1'` | `10.10.10.5` | Long-form --host space-separated |
| 9 | `-h 10.10.10.5 -u root --password=Secret -e 'SELECT 1'` | `10.10.10.5` | --password=value (long form, equals) |
| 10 | `-h 10.10.10.5 -u root -pSecret -D mysql -e 'SELECT * FROM user'` | `10.10.10.5` | -D database (must NOT match as target) |
| 11 | `-h 10.10.10.5 -u root -pSecret mysql -e 'SELECT * FROM user'` | `10.10.10.5` | Positional database `mysql` (must NOT match as target) |
| 12 | `-h 10.10.10.5 -u root -pSecret -D mysql --ssl-mode=REQUIRED -e 'SELECT 1'` | `10.10.10.5` | SSL flag + DB + query — only -h matters |
| 13 | `-h 10.10.10.5 -u root -pSecret --ssl-ca=/session/ca.pem --ssl-cert=/session/c.pem --ssl-key=/session/k.pem -e 'SELECT 1'` | `10.10.10.5` | SSL CA/cert/key paths must NOT be confused with target |
| 14 | `-h 10.10.10.5 -u root -pSecret -e \"SELECT LOAD_FILE('/etc/passwd')\"` | `10.10.10.5` | -e query containing a path that LOOKS hostlike |
| 15 | `-h 10.10.10.5 -u root -pSecret -e 'SELECT @@hostname, @@version'` | `10.10.10.5` | -e query containing the word `hostname` and `@@` |
| 16 | `-h 10.10.10.5 -u root -pSecret -e \"SELECT * FROM users WHERE email='admin@10.10.10.6'\"` | `10.10.10.5` | -e query containing a different IP in a string literal — must extract from -h not from the query |
| 17 | `-S /var/run/mysqld/mysqld.sock -u root -pSecret -e 'SELECT 1'` | `null` | Unix socket connection, NO -h — target_extraction returns null |
| 18 | `-h 10.10.10.5 -u root -pSecret -e 'SHOW DATABASES;SHOW TABLES'` | `10.10.10.5` | Multi-statement -e query |
| 19 | `--no-defaults -h 10.10.10.5 -u root -pSecret -e 'SELECT 1'` | `10.10.10.5` | --no-defaults before -h (other tool flags before host) |
| 20 | `-h 10.10.10.5 --port=3307 -u root --password=Secret --database=mysql --execute='SELECT VERSION()'` | `10.10.10.5` | All long-form flags |
| 21 | `--init-command='SET NAMES utf8mb4' -h 10.10.10.5 -u root -pSecret -e 'SELECT 1'` | `10.10.10.5` | --init-command value (a query) before -h |
| 22 | `-h 10.10.10.5 -u 'admin@dom.com' -pSecret -e 'SELECT 1'` | `10.10.10.5` | Username CONTAINS `@` and a TLD-looking string — must NOT be the target |
| 23 | `-h 10.10.10.5 -u root -pSecret --bind-address=192.168.1.10 -e 'SELECT 1'` | `10.10.10.5` | --bind-address (LOCAL bind, not target — must NOT win) |

### Adversarial cases (DSL must reject, fall back, or warn)

| # | Command | Expected behaviour | Notes |
|---|---|---|---|
| F1 | `--version` | `target=null` | No host needed for version check. |
| F2 | `--help` | `target=null` | Same. |
| F3 | `-u root -pSecret -e 'SELECT 1'` | `target=null` | No -h supplied — mysql defaults to localhost via socket. Target extraction returns null. |
| F4 | `-h 10.10.10.5 -u root -p Secret -e 'SELECT 1'` | `target=10.10.10.5` BUT command will hang | The -p has a SPACE before Secret — mysql parses Secret as the positional database, then prompts interactively for the password (which hangs in a no-stdin container). Target extraction is correct (-h still wins), but the command itself is broken. tool_runner should detect via idle timeout. |
| F5 | `-h 10.10.10.5 -u root -p test_db -e 'SELECT 1'` | `target=10.10.10.5` BUT command broken | Same pitfall as F4 — `test_db` looks like an intentional database name; mysql parses it as such and prompts for password. Target extraction correct. |
| F6 | `mydb -h 10.10.10.5 -u root -pSecret -e 'SELECT 1'` | `target=10.10.10.5` | First positional `mydb` is a DATABASE NAME, not the host. -h still wins. |
| F7 | `-h 10.10.10.5/mydb -u root -pSecret -e 'SELECT 1'` | `target=10.10.10.5/mydb` (raw — buggy host) | mysql doesn't support URI-form `host/db`. The slash is part of the value. mysql will fail with `Unknown MySQL server host '10.10.10.5/mydb'`. Target extraction is technically correct (-h flag-value as raw), but the value itself is malformed — surfaces via failure_signatures DNS path. |
| F8 | `-h '' -u root -pSecret -e 'SELECT 1'` | `target=` (empty) | Empty -h value — mysql treats empty as localhost. Extraction returns empty string; tool_runner should normalize empty to null. |
| F9 | `(empty command, no args)` | `target=null` | mysql with no args opens interactive client (hangs) — extraction null; the run will hit idle timeout. |
| F10 | `-h 10.10.10.5 -u root -pSecret < /session/queries.sql` | `target=10.10.10.5` BUT shell redirect doesn't work | cli_in_container does NOT have shell — `<` is a literal token. target extraction correct, but the run is broken. tool_runner should reject or warn. |
| F11 | `-h 10.10.10.5 -u root -pSecret \| grep ERROR` | `target=10.10.10.5` BUT pipe doesn't work | Same — no shell, pipe is literal. Target extraction correct, run broken. |
| F12 | `--protocol=TCP -h 10.10.10.5 -u root -pSecret -e 'SELECT 1'` | `target=10.10.10.5` | --protocol value `TCP` must NOT match as target. |
| F13 | `--prompt='mysql> ' -h 10.10.10.5 -u root -pSecret -e 'SELECT 1'` | `target=10.10.10.5` | --prompt has a value with spaces and a `>` char. |
| F14 | `--default-character-set=utf8mb4 -h 10.10.10.5 -u root -pSecret -e 'SELECT 1'` | `target=10.10.10.5` | Long flag with hyphens before -h. |

### Concatenated short-flag cases (commandUsesFlag must catch)

| # | Command | Expected behaviour | Notes |
|---|---|---|---|
| F15 | `-h10.10.10.5 -uroot -pSecret -e 'SELECT 1'` | `target=10.10.10.5` | Short flags with NO space between flag and value (mysql convention for -p but ALSO supported for -h, -u, -P, -D — all single-char short flags accept either form). |
| F16 | `-h 10.10.10.5 -uroot -pSecret -P3306 -Dmysql -e 'SELECT 1'` | `target=10.10.10.5` | Mix of spaced and concatenated short flags. |
| F17 | `-S/tmp/mysql.sock -uroot -pSecret -e 'SELECT 1'` | `target=null` | Concatenated -S socket path; no -h means null target. |

---

## 4. Failure-signature live-verify cases (≥3)

Run via opensploit; verify result hits a `failure_signatures` entry.

| # | Test | Command (post-binary) | Expected exit | Expected stdout/stderr substring | failure_signature `signal` | Status |
|---|---|---|---|---|---|---|
| 1 | DNS resolution failure | `-h nonexistent-host.invalid.localdomain -u root -pSecret -e 'SELECT 1'` | **1** | `Unknown MySQL server host 'nonexistent-host.invalid.localdomain'` | `Unknown MySQL server host` | PENDING (live-verify on rebuilt image) |
| 2 | Connection refused (closed port) | `-h 127.0.0.1 -P 1 -u root -pSecret -e 'SELECT 1' --connect-timeout=3` | **1** | `Can't connect to MySQL server on '127.0.0.1' (111)` | `Can't connect to MySQL server` AND `Connection refused` | PENDING |
| 3 | Wrong password (Access denied) | `-h 10.129.95.84 -u root -pwrong-password -e 'SELECT 1'` | **1** | `ERROR 1045 (28000): Access denied for user 'root'@'<ip>' (using password: YES)` | `Access denied for user` AND `ERROR 1045` | PENDING — requires reachable test mysql |
| 4 | Unknown database | `-h 10.129.95.84 -u root -pSecret -D nonexistent_db -e 'SELECT 1'` | **1** | `ERROR 1049 (42000): Unknown database 'nonexistent_db'` | `Unknown database` AND `ERROR 1049` | PENDING |
| 5 | SSL connection error | `-h 10.129.95.84 -u root -pSecret --ssl-mode=REQUIRED -e 'SELECT 1'` (against a 5.5 server with SSL off) | **1** | `SSL connection error` | `SSL connection error` | PENDING |
| 6 | Syntax error in -e | `-h 10.129.95.84 -u root -pSecret -e 'SLECT 1 FRMO mysql.user'` | **1** | `ERROR 1064 (42000): You have an error in your SQL syntax` | `syntax error` AND `You have an error in your SQL syntax` | PENDING |
| 7 | Privilege denied (LOAD_FILE without FILE priv) | `-h 10.129.95.84 -u low_priv_user -pSecret -e \"SELECT LOAD_FILE('/etc/passwd')\"` | **0** (returns NULL — query succeeds, but result is NULL) | `NULL` (literal in result) — NO error message | NOT a stderr signal — pattern-match the result. tool_runner classifies as success but agent must read the NULL. | DOCUMENTED — not a stderr-detectable failure |

### Lessons recorded in `tool.yaml` gotchas

1. mysql client exits **1** on most hard failures (DNS, refused, auth, syntax, unknown DB) — distinct from sqlmap's "always 0" pattern. Exit code IS reliable for hard failures, but pattern-match signals for the specific cause (DNS vs TCP vs auth vs syntax).
2. **`-p<password>` no-space** is the recurring failure mode. With a space, mysql silently re-parses the value as the positional database name and then waits for stdin for the password — which hangs. tool_runner's idle-timeout will catch this, but the operator should be steered toward `-pSecret` or `--password=Secret` form via gotchas.
3. **`secure_file_priv` blocks LOAD_FILE / INTO OUTFILE** for paths outside its directory. Default on Debian-style mysql packages: `/var/lib/mysql-files/`. Default on stock builds: empty (anywhere mysqld can write). Always check `SHOW VARIABLES LIKE 'secure_file_priv'` before assuming you can write to /var/www/.
4. **MariaDB vs MySQL client divergence** — `--xml` and a few other flags are mariadb-only. Default on Kali (`default-mysql-client` → `mariadb-client`) is the MariaDB client. Detect via `mysql --version` first call.
5. **System databases visible to all** — information_schema, mysql, performance_schema, sys all show up in `SHOW DATABASES` regardless of grants. Application DBs are scoped per-user. Don't assume "I can see N databases" means full access — most are visible to everyone.

---

## 5. Open questions

1. **`-p<password>` no-space convention** — cli_in_container's argv parser must treat `-pXXX` as a single concatenated short flag with value (NOT split on the boundary). Verify with case F15 / F16. If the parser splits `-pSecret` into `-p` + `Secret` positional, the rejection path must surface clearly, NOT silently reformulate to `-p Secret` (which would hang).
2. **Interactive shell handling** — without `-e`, mysql opens an interactive prompt that hangs the container. Should there be a synthetic `reject_pattern` in tool.yaml for "argv has no -e and no --execute" to fail-fast at the registry layer? Currently relies on idle_timeout, which is correct but slow (300 s).
3. **`INTO OUTFILE` server-side risk** — the destination path is from the SERVER's perspective, not the client's. Operators may write to `/etc/passwd` thinking it's a client-side path and accidentally clobber the server's. Should tool.yaml have a `dangerous_query_patterns` advisory list (INTO OUTFILE, INTO DUMPFILE, SET GLOBAL, DROP)? Out-of-scope for Tier A migration; note for future hardening.
4. **`MYSQL_PWD` env var** — the only non-cmdline password path is the `MYSQL_PWD` env var, but cli_in_container doesn't currently expose env-var injection. Could be a future enhancement to avoid password-in-ps. Not blocking for migration.
5. **MariaDB vs Oracle MySQL flag divergence** — `--xml` works only on MariaDB client. Kali default is MariaDB, but if the container ever switches to mysql-client-core (Oracle), --xml usage_pattern would break. Should the image-side variant be locked? Currently `default-mysql-client` floats — pin to `mariadb-client` explicitly?
6. **Hash format detection automation** — when dumping `mysql.user.authentication_string`, the format depends on auth_plugin. Should there be a wrapper recipe that joins user + plugin + authentication_string in one query for downstream john / hashcat hand-off? Out-of-scope for Tier A.
7. **`secure_file_priv` discovery** — should the image bundle a "fingerprint" sub-method that runs `SHOW VARIABLES LIKE 'secure_file_priv'; SHOW VARIABLES LIKE 'have_ssl'; SHOW GRANTS FOR CURRENT_USER()` in a single call to surface FILE / SSL / privilege capabilities? Useful but out-of-scope for migration; reference via usage_patterns.

---

## 6. Hand-off

- **Tool**: mysql (kind:cli)
- **Status**: migrated; scenarios consolidated; Dockerfile updated to `python3-full` (Kali).
- **mcp-server.py**: present, untouched — auto-inherits run_cli; preserves rollback per SKILL #21. Five legacy methods (query, list_databases, list_tables, dump_table, find_credentials) preserved.
- **Image**: `ghcr.io/silicon-works/mcp-tools-mysql:latest` — local rebuild required to pick up `python3-full` Dockerfile. CI rebuild on next push.
- **Live-verify pending**: paste S1–S7 into opensploit against an HTB box with MySQL exposed (Falafel for retired, or any Active machine running MariaDB/MySQL on 3306). Confirm `-p<password>` no-space parsing works end-to-end, target extraction picks `-h` not the positional database, failure signatures trip on Access denied and DNS.
- **Cleanup**: no legacy split files (`target_extraction_tests.md` / `failure_signature_tests.md`) existed; no `__pycache__/` present. Nothing to remove beyond the tool.yaml schema bump.
- **Wave 5.1 sign-off**: ≥7 narrative scenarios authored; ≥23 target-extraction cases; ≥6 failure-signature cases; ≥7 open questions. Layer-diverse failure_signatures (DNS / TCP / auth / SSL / database / privilege / argparse) — ≥7 distinct layers.

Authored: 2026-04-25 (Wave 5.1).
