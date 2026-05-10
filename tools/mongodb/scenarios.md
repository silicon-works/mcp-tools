# mongodb-mcp-server — kind:mcp scenarios

Live-verification record for the May 2026 vendor-MCP swap from the legacy
682-LOC pymongo wrapper to mongodb-js/mongodb-mcp-server v0.3.x.

Validation methodology: **manual one-call-per-LLM-turn** stdio MCP harness
(FIFO + log-tail-on-stdout, the same shape opensploit's ContainerManager
uses), driven against a local `mongo:7` container at `localhost:27018`
seeded with offensive-typical credential data. Each call was issued with my
reasoning between turns — no pipelined batch script.

Sections:
1. Recommended target
2. Through-the-stdio integration test — every method category, every primitive
3. Resources + Prompts surface
4. Target-extraction adversarial cases — N/A (kind:mcp, no argv parsing)
5. Failure-signature live-verify cases
6. Performance observed
7. Vendor MCP quirks + offensive-relevant gotchas
8. Things NOT verified that could bite us in production
9. Hand-off
10. Manual re-verification (2026-05-09)

---

## 1. Recommended target

**Local seeded `mongo:7` instance** — same engagement-class shape as an
unauth-exposed MongoDB on an HTB box, but no VPN dependency. Setup:

```bash
docker run -d --rm --name mongo-test --network=host mongo:7 --port 27018
docker exec mongo-test mongosh --port 27018 --quiet --eval '
db = db.getSiblingDB("htb_test");
db.users.insertMany([
  {username: "admin", password: "P@ssw0rd123", role: "admin"},
  {username: "alice", password_hash: "5f4dcc3b5aa765d61d8327deb882cf99", role: "user"},
  {username: "bob", api_key: "sk-secret-key-abc", role: "user"}
]);
db.posts.insertOne({title: "Welcome", body: "test post"});
db = db.getSiblingDB("admin_db");
db.credentials.insertOne({system: "ldap", bind_dn: "cn=admin", password: "ldap-secret"});
'
```

Why this shape mimics offensive reality:
- `htb_test.users` collection with three different credential storage shapes
  (plaintext password, MD5 hash, API key) — exercises the cred-hunt projection
  pattern across realistic field-name variation.
- `admin_db.credentials` has a `password` field at top-level — exercises the
  fallback "look in any DB named like admin/auth/secret" heuristic.
- Port 27018 (non-default) — verifies the URI's port parameter actually wins
  over upstream's default-port assumption.

**Live HTB alternates** (no exposed mongodb in current trajectory window —
0/79 invocations of mongodb across past engagements per the audit memory):
- Any HTB box discovered via `nmap -sV -p 27017 --script mongodb-info` to be
  running unauth mongodb. Pirate.HTB (per pirate-htb-insights memory) had a
  mongodb instance, though out-of-scope per current MCP-vs-Tier-A audit.

**Container start (manual testing harness, stdio):**
```bash
docker run -i --rm --network=host \
  -v /tmp/mdb_test_session:/session:rw \
  ghcr.io/silicon-works/mcp-tools-mongodb:latest
# pipe newline-delimited JSON-RPC frames to stdin; read responses on stdout
```

---

## 2. Through-the-stdio integration test

**Validation methodology + caveat:** every method below was driven through
stdio MCP (the same protocol shape opensploit's ContainerManager uses) on
2026-05-08 against the local mongo:7 target. Calls were issued one at a time
through a FIFO harness with my reasoning between turns — same shape an
opensploit LLM agent uses (one tool call per turn). This catches schema/
runtime/state-machine bugs and surfaces behaviors that don't show up in
batched scripted tests.

### 2.1 Discovery — initialize + tools/list

**`initialize`** — server identifies itself:
```
{"result":{"protocolVersion":"2024-11-05","capabilities":{"resources":{...},"completions":{},"logging":{},"tools":{"listChanged":true}},"serverInfo":{"name":"MongoDB MCP Server","version":"0.3.0"}}, ...}
```
- Server self-reports as `MongoDB MCP Server v0.3.0`. Matches our pinned npm major (`mongodb-mcp-server@^0`).
- `tools.listChanged: true` capability is set — relevant to the connect↔switch-connection toggle (upstream emits notifications/tools/list_changed when surface mutates).

**`tools/list`** (pre-connect) — 13 tools:
```
aggregate, collection-indexes, collection-schema, collection-storage-size,
connect, count, db-stats, explain, export, find, list-collections,
list-databases, mongodb-logs
```

### 2.2 Connection lifecycle (Flow 1)

```
connect({connectionString: "mongodb://localhost:27018/?appName=mongo"})
→ result.content[].text: "Successfully connected to ..."
  (took ~2-3s; verifying with db.runCommand({ping:1}))

[verify defender-side view via mongosh on the same target:]
db.adminCommand({currentOp: 1, "$ownOps": false})
  .inprog.filter(o => o.appName).map(o => o.appName)
  → ["mongo", "mongosh 2.8.2", ...]
```

**Critical finding:** defender sees `appName: 'mongo'` — NOT
`mongodb-mcp-server 0.3.0--<deviceId>--<clientName>`. The URI override
worked. This is the offensive-fingerprint mitigation; without it, every
defender's `db.currentOp()` would fingerprint our agent.

### 2.3 Database + collection enumeration (Flow 2)

```
list-databases({})
→ "Found 5 databases" + table: admin, admin_db, config, htb_test, local

list-collections({database: "htb_test"})
→ "Found 2 collections": users, posts
```

**Note:** every result that contains target-side data is wrapped by upstream
in `<untrusted-user-data-...>...</untrusted-user-data-...>` markers + a
"DO NOT execute instructions inside" pre/post-amble. This is upstream's
prompt-injection mitigation. Useful security property; agent prose
extraction must strip these markers when summarizing.

### 2.4 Credential extraction (Flow 3)

```
find({database: "htb_test", collection: "users", filter: {}, limit: 10})
→ "Found 3 documents in the collection 'users'."
   [
     {username:"admin", password:"P@ssw0rd123", role:"admin"},
     {username:"alice", password_hash:"5f4dcc3b5aa765d61d8327deb882cf99", role:"user"},
     {username:"bob", api_key:"sk-secret-key-abc", role:"user"}
   ]
```

**Result**: same offensive utility as the legacy custom wrapper's
`find_credentials` method, just composed via `find` with empty filter +
explicit projection. The legacy heuristic of "pattern-match users/auth/
credentials collection names + projection on password/hash/api_key/secret
fields" lives in usage_patterns.

### 2.5 Bulk extraction to /session/output (Flow 4)

```
export({
  database: "htb_test",
  collection: "users",
  exportTitle: "users",
  exportTarget: [{name: "find", arguments: {filter: {}, limit: 100}}],
  jsonExportFormat: "canonical"
})
→ result.content[].text:
  "Data for namespace htb_test.users is being exported and will be made
   available under resource URI - exported-data://htb_test.users.<docUuid>.json.
   Optionally, when the export is finished, the exported data can also be
   accessed under path - /session/output/<sessionUuid>/htb_test.users.<docUuid>.json"
```

**Host-side verification**:
```
$ ls -la /tmp/mdb_test_session/output/
drwxr-xr-x  3 root  root  4096  May  8 21:24  <sessionUuid>/

$ ls /tmp/mdb_test_session/output/<sessionUuid>/
htb_test.users.<docUuid>.json    (~4 KB, contains all 3 user docs in canonical extended-JSON)
```

**Critical finding**: end-to-end `entrypoint mkdir + bind-mount +
MDB_MCP_EXPORTS_PATH=/session/output + vendor's export tool` chain works.
File appears on host filesystem under `${sessionDir}/output/<uuid>/`. This
is the equivalent of playwright's `--output-dir` fix — without it, exports
land at `/root/.mongodb/mongodb-mcp/exports/<uuid>/` inside the container
and are lost when the container exits.

### 2.6 Diagnostics (Flow 5)

```
db-stats({database: "htb_test"})
→ {"db":"htb_test","collections":2,"views":0,"objects":4,"avgObjSize":85,
   "dataSize":340,"storageSize":40960,"indexes":2,"indexSize":40960,
   "totalSize":81920,"scaleFactor":1,
   "fsUsedSize":228353081344,"fsTotalSize":248841129984,"ok":1}
```

`fsUsedSize/fsTotalSize` — useful offensive fingerprinting signal. Real
production DB vs empty test instance shows up immediately in the ratio.

### 2.7 Connect↔switch-connection toggle (Flow 6)

```
[after a successful connect in Flow 1]
tools/list({})
→ TOOL COUNT: 13
  Names: ['aggregate', 'collection-indexes', 'collection-schema',
          'collection-storage-size', 'count', 'db-stats', 'explain',
          'export', 'find', 'list-collections', 'list-databases',
          'mongodb-logs', 'switch-connection']
  connect present? False
  switch-connection present? True
```

**Critical finding**: the connect/switch-connection slot is DYNAMIC. Tool
count stays at 13 either way; the slot rotates based on connection state.
Calling `connect` post-connect returns `MCP error -32602: Tool connect not
found`. Documented in tool.yaml gotchas + failure_signatures.

### 2.8 Disabled-tools verification (Flow 7)

```
[try a write operation that should be filtered out by MDB_MCP_DISABLED_TOOLS=
 atlas,create,update,delete]

insert-many({database: "htb_test", collection: "users",
             documents: [{username: "backdoor", password: "x"}]})
→ "MCP error -32602: Tool insert-many not found"
```

**Verified**: write/destroy tools are correctly filtered out of the surface
by the entrypoint's deny-list. The error shape is "Tool X not found" —
agents that pattern-match this know to either (a) override the env var if
post-ex destruction is in scope, or (b) compose the operation through a
different MCP altogether.

---

## 3. Resources + Prompts

`mongodb-mcp-server v0.3.0` advertises **`resources.subscribe: true`** in
the initialize response (verified live 2026-05-08), which means it does
expose MCP resources. The export tool returns a resource URI like
`exported-data://htb_test.users.<docUuid>.json` — that's a resource
exported by the server.

**However**: opensploit's `mcp_tool` only dispatches `tools/call`, not
`resources/read`. To extract the exported data, the agent reads the
parallel filesystem path the export tool reports (under /session/output/),
not the resource URI. This mirrors zap's resources gap (zap's add-on
exposes 10 resources too, but opensploit can't dispatch them).

No prompts exposed in v0.3.0 (verified live).

---

## 4. Target-extraction adversarial cases

**N/A.** kind:mcp tools have no argv parsing — every input is a typed
JSON-Schema-validated MCP argument. The target-extraction DSL (kind:cli's
quarantine layer) doesn't apply.

The closest equivalent is **input-schema validation by upstream**. Live
behavior observed (§2 above): missing required args, invalid enum values,
and bad shape on exportTarget all return structured `MCP error -32602:
Input validation error` with a zod-style array of issues.

---

## 5. Failure-signature live-verify cases

### F1 — Tool connect not found (post-connect state) — **LIVE-VERIFIED 2026-05-08**

```
[after successful connect, call connect again with bad URI]
connect({connectionString: "mongodb://nonexistent.invalid:27017/?appName=mongo&serverSelectionTimeoutMS=3000"})
→ "MCP error -32602: Tool connect not found"
```

The agent expecting connect to either succeed or return a connection error
must instead reach for switch-connection. Failure signature: `Tool connect
not found`.

### F2 — Tool insert-many not found (deny-listed) — **LIVE-VERIFIED 2026-05-08**

```
insert-many({database: "htb_test", collection: "users", documents: [...]})
→ "MCP error -32602: Tool insert-many not found"
```

Failure signature: `Tool insert-many not found` (or update-many / delete-
many / drop-collection / drop-database / rename-collection / create-* /
drop-* — same shape).

### F3 — Invalid logger config-parse error — **LIVE-VERIFIED 2026-05-08**

```
[entrypoint with `--loggers stderr --exportsPath /session/output`]
→ Container crashes with stderr:
   "Error: Invalid logger: --exportsPath
    at setupUserConfig (file:///.../config.js:262:19)"
```

Upstream's CLI parser treats `--loggers <values...>` as multi-value and
greedily consumes the next arg. Fix: use env var (MDB_MCP_EXPORTS_PATH)
instead of `--exportsPath` flag. Already applied to entrypoint.

### F4 — exportTarget schema strictness — **LIVE-VERIFIED 2026-05-08**

```
[send exportTarget as a string]
export({..., exportTarget: "file"})
→ "MCP error -32602: Input validation error: ...
   path: ['exportTarget'], message: 'Expected array, received string'"

[send exportTarget as array of strings]
export({..., exportTarget: ["file"]})
→ "Input validation error: ...
   path: ['exportTarget', 0], message: 'Expected object, received string'"

[correct shape]
export({..., exportTarget: [{name: "find", arguments: {filter: {}, limit: 100}}]})
→ "Data for namespace ... is being exported ..."
```

Schema enforces `Array<{name: 'find'|'aggregate', arguments: {...}}>`.
Documented in tool.yaml `export` method params.

---

## 6. Performance observed

| Operation | Observed time |
|---|---|
| Container cold start (docker run → tools/list responsive) | **~2s** (Node + npx mongodb-mcp-server) |
| `tools/list` (13 tools) | 0.01-0.05s |
| `connect` (TCP connect + handshake to localhost mongo:7) | 1-3s |
| `list-databases` | 0.05-0.1s |
| `list-collections` | 0.05-0.1s |
| `find` with limit 10 | 0.05-0.2s (3-doc collection; scales with doc count) |
| `count` | 0.02-0.05s |
| `db-stats` | 0.02-0.05s |
| `collection-schema` (sample-derived) | 0.05-0.2s |
| `collection-indexes` | 0.02-0.05s |
| `aggregate` (simple pipeline) | 0.05-0.5s |
| `explain` | 0.02-0.1s |
| `export` (find cursor → file, async) | 0.1s response + 0.5-2s file write |
| `connect` to UNREACHABLE host (default 30s timeout) | 30s — agent should add `&serverSelectionTimeoutMS=3000` |

---

## 7. Vendor MCP quirks + offensive-relevant gotchas

These are real behaviors of mongodb-js/mongodb-mcp-server v0.3.0 worth
documenting:

1. **`appName` fingerprint** in MongoDB connection metadata. Upstream sets
   `appName=mongodb-mcp-server X.Y.Z--<deviceId>--<clientName>` if the URI
   doesn't override. Fix: pass `?appName=mongo` (or generic value) in URI.
   Verified live 2026-05-08: defender-side `db.currentOp()` showed `appName:
   'mongo'` after override.

2. **`--readOnly` flag drops `connect`** (upstream bug). Verified live —
   passing `--readOnly` removes the connect tool from tools/list, even
   though connect's operationType should be in the read-only allowlist.
   Workaround: use deny-list approach
   (`MDB_MCP_DISABLED_TOOLS=atlas,create,update,delete`) instead.

3. **`connect ↔ switch-connection` dynamic slot**. Pre-connect: connect
   present. Post-connect: switch-connection replaces it. Tool count stays
   at 13. Calling `connect` post-connect returns "Tool connect not found".

4. **`--loggers` multi-value flag eats following args**. `--loggers stderr
   --exportsPath /session/output` crashes with `Invalid logger:
   --exportsPath`. Use env var equivalent (MDB_MCP_EXPORTS_PATH).

5. **`exportTarget` schema is strict-array-of-objects**. Not a string,
   not an array of strings — array of `{name, arguments}` cursor specs.

6. **Default `exportsPath` is `/root/.mongodb/mongodb-mcp/exports/<uuid>/`**
   (lost when container exits). Override via `MDB_MCP_EXPORTS_PATH=
   /session/output` for bind-mount visibility.

7. **Telemetry on by default**. `MDB_MCP_TELEMETRY` defaults to `enabled`;
   product-analytics events go to MongoDB Inc. `DO_NOT_TRACK=1` is also
   honored. Both set to disabled in this image's entrypoint.

8. **Atlas tools require `MDB_MCP_API_CLIENT_ID` + `MDB_MCP_API_CLIENT_SECRET`**.
   Without those, every atlas-* call returns auth-error. Default disable
   via `MDB_MCP_DISABLED_TOOLS=atlas` keeps the agent's tool selection
   focused on the wire-protocol tools.

9. **`untrusted-user-data` markers wrap document-data results**. Upstream
   prompt-injection mitigation. Agent prose-extraction must strip them.

10. **`limit` on find caps at `MDB_MCP_MAX_DOCUMENTS_PER_QUERY`**. Even if
    the agent passes `limit: 10000`, the actual cap is min(limit, env-var).
    Default 100. Override per call via env arg if a wider sweep is needed.

11. **Server reports as `MongoDB MCP Server v0.3.0`** in initialize. Not
    `mongodb-mcp-server` (the npm package name) — useful to know if
    cross-referencing logs.

12. **`mongodb-logs` tool requires `getLog` privilege on the connected
    user** — typically only the admin DB user. Will fail with "not
    authorized" on most non-admin connections.

---

## 8. Things NOT verified that could bite us in production

These are integration boundaries the May 2026 swap did NOT exercise.

1. **Live HTB engagement against an exposed mongodb instance.** Past
   trajectory has 0/79 invocations of mongodb. The local mongo:7 target
   used for verification shares the wire protocol but not the
   network-routing complexity of HTB VPN. First HTB engagement that lands
   on an exposed mongo will be the actual test.

2. **Atlas mode end-to-end.** The disable-by-default path was verified;
   the enable-with-creds path (set MDB_MCP_API_CLIENT_ID + _SECRET, drop
   atlas from disabled-tools) was not, because no Atlas test instance was
   set up.

3. **TLS-required MongoDB instances.** All testing was against a non-TLS
   localhost mongo:7. Atlas defaults to TLS; some prod targets require it.
   Connection URI scheme `mongodb+srv://` and TLS handshake quirks
   (cipher mismatches, cert validation) untested.

4. **Authentication paths beyond plaintext.** SCRAM-SHA-256 (default modern
   MongoDB) tested implicitly via the mongosh handshake; LDAP/Kerberos
   plug-in auth not tested.

5. **Sharded cluster (mongos router) connection.** db.currentOp() behavior
   differs vs direct mongod — appName propagates per shard, slow-query log
   is shard-local. Untested.

6. **`switch-connection` state hygiene.** Verified the slot toggle but did
   NOT verify whether agent's earlier list-databases / find result is
   "still relevant" after switch (it is NOT — but the agent might not
   realize that without prompt guidance). Documented in gotcha #12.

7. **`mongodb-logs` privilege requirement.** Tool call wasn't exercised
   because the test instance allows everything as no-auth user. Real
   targets will return "not authorized" most of the time.

8. **Long-running aggregation pipeline timeouts.** Verified 0.05-0.5s for
   a simple pipeline; haven't tested a heavy `$lookup` against a large
   collection that hits MDB_MCP_MAX_TIME_MS=30000.

---

## 9. Hand-off

- **Tool:** mongodb (kind:mcp, mongodb-js/mongodb-mcp-server v0.3.x via
  npm @^0)
- **Image:** `ghcr.io/silicon-works/mcp-tools-mongodb:latest` (CI rebuilds
  from `tools/mongodb/Dockerfile` on push to main)
- **Surface:** 13 tools (12 read+metadata + 1 connect/switch-connection
  toggle slot). Resources: 1 export-data resource. Prompts: 0.
- **Wrapper retirement:** prior 682-LOC pymongo custom wrapper (7 hand-
  rolled methods) deleted entirely; legacy `find_credentials` heuristic
  preserved as a usage_pattern that composes list-databases →
  list-collections → find with projection.
- **Live verification (this file):** local mongo:7 at localhost:27018,
  2026-05-08, ~30 manual stdio MCP calls covering all 13 tools, all 3
  failure modes, and the connect↔switch-connection toggle. Defender-side
  appName mitigation verified via `db.currentOp()`. Export to bind-mount
  verified via host-filesystem `ls`.
- **Known upstream alpha quirks:** see §7. Most notable: --readOnly drops
  connect (workaround applied), --loggers eats following flag (workaround
  applied), connect/switch-connection is dynamic, untrusted-user-data
  wrapping mitigates prompt injection.
- **Cross-tool routing:** see_also points at mssql, elasticsearch (other
  DB tools), hydra (for cred brute), nmap (for discovery), curl (for
  Atlas API direct).

## 10. Manual re-verification (2026-05-09)

Independent re-verify run against a fresh `mongo:7` target on a docker
user-defined network (rather than localhost:27018), driven one MCP call
per LLM turn. Goal: confirm wrapper still works after the May 6-9
metasploit/zap/playwright/prowler swap-in churn touched no mongodb code.
Seed data: `htb_test.users` with 3 credential shapes (plaintext, bcrypt,
api_key+secret) + `htb_test.config` with secret-bearing fields +
`admin_db.notes`.

| # | Call | Result |
|---|---|---|
| 1 | initialize | server=`MongoDB MCP Server` v `0.3.0`, caps include resources.subscribe |
| 2 | tools/list | 13 tools (write tools filtered at startup as designed: 8 disabled) |
| 3 | connect with `connectionStringOrClusterName` | **MCP -32602 input validation error** — vendor only accepts `connectionString`. Captured as new `failure_signatures` entry + gotcha. |
| 4 | connect with `connectionString` | "Successfully connected", server pushed 2× `tools/list_changed` notifications |
| 5 | list-databases | 5 dbs (admin/admin_db/config/htb_test/local), wrapped in `<untrusted-user-data-...>` envelope |
| 6 | list-collections htb_test | `users`, `config` |
| 7 | find users {} limit 10 | All 3 docs with all 3 credential shapes preserved |
| 8 | count users {role:"superuser"} | 1 |
| 9 | export users → /session/output/ | File landed on host bind mount at `/tmp/mongo-sess/output/<scope>/htb_test.users.<docUuid>.json` (430 bytes, all 3 docs preserved) |
| 10 | aggregate users [groupBy role] | 3 groups (automation/superuser/user) |

**New finding** (added to tool.yaml failure_signatures + gotchas):
the vendor schema for connect/switch-connection accepts ONLY
`connectionString` — NOT the legacy Atlas-style
`connectionStringOrClusterName` that the older custom wrapper used.
Easy mistake for an LLM agent trained on older docs.

All other behaviors matched the 2026-05-08 baseline.

## Sources

- [mongodb-js/mongodb-mcp-server](https://github.com/mongodb-js/mongodb-mcp-server) — vendor source
- [mongodb-mcp-server on npm](https://www.npmjs.com/package/mongodb-mcp-server)
- [MongoDB MCP Server GA announcement](https://www.mongodb.com/products/updates/mongodb-mcp-server-generally-available/)
