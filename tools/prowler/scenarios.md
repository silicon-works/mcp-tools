# prowler — vendor-MCP swap scenarios

Live-verification record for the May 2026 vendor-MCP swap from the legacy
406-LOC custom Python wrapper (3 methods: scan/list_checks/scan_service)
to prowler-cloud/prowler's official MCP server (`mcp_server` in main repo,
`prowler-mcp` v0.5.0 at master) running INSIDE a bundled container that
ships the FULL self-hosted Prowler App stack (postgres-16 + redis-7 +
dozerdb + Django REST API + Celery worker + prowler-mcp stdio bridge).

**Validation methodology:** manual one-call-per-LLM-turn stdio MCP
harness (FIFO + log-tail-on-stdout, the same shape opensploit's
ContainerManager uses), driven against the bundled stack on 2026-05-09.
Each call was issued with my reasoning between turns — no batched script.

Sections:
1. Architecture + container boot sequence
2. Phase A — wrapper-works verification (no cloud target needed)
3. Resources + Prompts
4. Target-extraction adversarial cases (N/A for kind:mcp)
5. Failure-signature live-verify cases
6. Performance observed
7. Vendor MCP quirks + offensive-relevant gotchas
8. Things NOT verified that could bite us in production
9. Phase B placeholder — AWS Fortress integration test
10. Hand-off

---

## 1. Architecture + container boot sequence

```
opensploit ContainerManager (stdio MCP, service:true once per session)
        │   docker run -i --rm --network=host
        │     -v ${sessionDir}:/session:rw
        │     ghcr.io/silicon-works/mcp-tools-prowler:latest
        ▼
container's entrypoint.sh
   1. generate-or-load secrets at /var/lib/prowler/secrets/
        (RSA token-signing keypair, Fernet encryption key,
         postgres/redis/neo4j passwords)
   2. set offensive env: PROWLER_AWS_BOTO3_USER_AGENT_EXTRA='',
        DJANGO_SENTRY_DSN='', DJANGO_DEBUG=False
   3. start postgres-16 (Debian cluster, pg_ctlcluster)
   4. start redis-server (valkey-API-compatible)
   5. start dozerdb (Apache 2 neo4j fork)
   6. django migrate --database=admin (90+ migrations on first boot)
   7. bootstrap.py: create Tenant + admin User + TenantAPIKey via
        Django ORM, print pk_xxx (cached at /var/lib/prowler/bootstrap/api_key)
   8. export PROWLER_APP_API_KEY=$(cat key);
        API_BASE_URL=http://127.0.0.1:8080/api/v1
   9. start gunicorn (Django REST API on 127.0.0.1:8080) + celery worker
  10. wait for /api/v1/ to return 200
  11. exec prowler-mcp --transport stdio (foreground)
        ▼
prowler-mcp v0.5.0 (FastMCP framework v2.14.0)
        │   identifies as 'prowler-mcp-server'
        │   3 sub-servers loaded with prefixes:
        │   • prowler_hub_*  → hub.prowler.com  (no auth)
        │   • prowler_docs_* → docs.prowler.com (no auth)
        │   • prowler_app_*  → http://127.0.0.1:8080/api/v1 (Bearer pk_xxx)
        ▼
target cloud (AWS / Azure / GCP / K8s / M365 / GitHub)
   via Celery worker calling prowler library against connected creds,
   with PROWLER_AWS_BOTO3_USER_AGENT_EXTRA='' so CloudTrail's userAgent
   field shows generic Boto3/X.Y.Z — NOT the APN_1826889 fingerprint
   that vanilla prowler stamps.
```

### Boot timing observed (2026-05-09)

| Stage | First boot | Subsequent boots (warm volumes) |
|---|---|---|
| Secret generation | <1s | <1s (loaded from disk) |
| Postgres start + ready | 1s | 1s |
| Redis start + ready | 1s | 1s |
| DozerDB start + ready | 30-45s | 5-10s |
| Django migrations (90+) | ~90s | 0s (no-op) |
| Bootstrap.py (Tenant + User + TenantAPIKey) | 1-2s | 0s (cached key reused) |
| Gunicorn + celery + /health | 18-24s | 18-24s |
| **Total to MCP-stdio-ready** | **123s (2:03)** | **93s (1:33)** |

Live-measured 2026-05-09 against clean image build:
- **Cold boot 123s** — secrets gen + roles + migrations + bootstrap + django.
- **Warm boot 93s** — savings come only from skipping bootstrap + migration no-op.
  DozerDB cluster init + JVM startup + gunicorn/celery boot are NOT cached and
  account for the bulk of the warm time. Earlier "~30-60s" warm-boot estimate
  was wrong — keeping ~90s as the realistic floor.

Earlier "~7 min" cold-start figure in older docs was from the very first
boot during iterative build/debug (rebuild churn + dulwich crash retries +
poetry-lock-regen); clean rebuilds are 3-4x faster.

Cold start dominated by migrations on a fresh DB. With persistent
volumes mounted on `/var/lib/postgresql` + `/opt/dozerdb/data` +
`/var/lib/prowler`, subsequent boots are an order of magnitude faster.

---

## 2. Phase A — wrapper-works verification (no cloud target needed)

The "wrapper works" question — does our self-hosted bundle correctly
intermediate between opensploit's stdio MCP transport and the vendor's
HTTP-based Prowler App API — is fully answerable without ever pointing
Prowler at a target cloud. Phase A exercises the entire chain:

  opensploit-MCP-stdio → bundled-container → prowler-mcp (FastMCP) →
  ProwlerAPIClient (httpx) → bundled Django API (gunicorn) → postgres
  (RowLevelSecurity-protected reads/writes)

The five Phase A tests below collectively prove every link.

### Test A1 — Initialize handshake — **LIVE-VERIFIED 2026-05-09**

```
→ {"jsonrpc":"2.0","id":1,"method":"initialize","params":{...}}
← {"result":{
     "protocolVersion":"2024-11-05",
     "capabilities":{
       "experimental":{"tasks":{...}},
       "prompts":{"listChanged":false},
       "resources":{"subscribe":false,"listChanged":false},
       "tools":{"listChanged":true}
     },
     "serverInfo":{
       "name":"prowler-mcp-server",
       "version":"2.14.0"
     }
  }}
```

**Findings:**
- Server name `prowler-mcp-server` (FastMCP namespace, not the package name)
- Version `2.14.0` is FastMCP framework — NOT prowler-mcp's product version
  (which is 0.5.0). The smoke test asserts both correctly.

### Test A2 — tools/list — **LIVE-VERIFIED 2026-05-09**

```
TOTAL TOOLS: 41
PREFIXES: {'prowler_app': 29, 'prowler_docs': 2, 'prowler_hub': 10}
```

Full alphabetized list verified against the docs/getting-started/basic-usage/prowler-mcp-tools page — 1:1 match.

### Test A3 — `prowler_hub_list_providers` (no-auth, fetches GitHub) — **LIVE-VERIFIED**

```
→ tools/call name=prowler_hub_list_providers
← {"count":17,"providers":[
     {"id":"azure","name":"Azure"},
     {"id":"gcp","name":"Google Cloud"},
     {"id":"kubernetes","name":"Kubernetes"},
     {"id":"m365","name":"Microsoft365"},
     {"id":"mongodbatlas","name":"MongoDB Atlas"},
     {"id":"github","name":"GitHub"},
     ...17 total
  ]}
```

**Confirms:** container has outbound internet to hub.prowler.com,
prowler_hub_* tools work without ANY auth (proves the no-auth subset
is reachable even before connecting a provider).

### Test A4 — `prowler_docs_search` (no-auth, fetches docs) — **LIVE-VERIFIED**

```
→ tools/call name=prowler_docs_search arguments={"term":"S3 bucket public access"}
← [{"path":"developer-guide/check-metadata-guidelines",
    "title":"Writing Guidelines",
    "url":"https://prowler.mintlify.app/...",
    "highlights":["...<mark><b>S3 bucket</b></mark>..."],
    "score":9.576681},
   ...]
```

**Confirms:** docs.prowler.com is reachable, full-text search returns
ranked hits with highlighted matches in markdown.

### Test A5 — `prowler_app_search_providers` (auth-required) — **LIVE-VERIFIED**

```
→ tools/call name=prowler_app_search_providers
← {"providers":[],"total_num_providers":0,"total_num_pages":1,"current_page":1}
```

**This is the critical wrapper-works check.** It proves the entire
Phase A auth chain:

1. ✓ bootstrap.py created Tenant + admin User + TenantAPIKey in postgres
2. ✓ TenantAPIKey was minted with `pk_` prefix (length 196)
3. ✓ Entrypoint cached the key + exported PROWLER_APP_API_KEY env
4. ✓ prowler-mcp's ProwlerAPIClient picked up the env var, set Bearer
     header on httpx call to localhost:8080/api/v1/providers
5. ✓ Gunicorn validated the JWT against the postgres TenantAPIKey table
6. ✓ RowLevelSecurity policy fired (no providers exist for this tenant
     yet, so empty array is the correct response — not an error)

**The empty array is not a bug — it's the expected state of a freshly-
bootstrapped tenant with no providers connected.** Phase B (AWS
Fortress) is the test that exercises the providers-populated path.

### Test A6 — `prowler_hub_get_provider_services aws` — **LIVE-VERIFIED**

```
→ tools/call name=prowler_hub_get_provider_services arguments={"provider_id":"aws"}
← {"count":84, "services":[...]}
```

84 AWS services available. Confirms hub catalog can be drilled into
provider→services for scoping scans.

### Test A7 — `prowler_hub_get_check_details s3_bucket_public_access` — **LIVE-VERIFIED**

First attempt with `provider_id`+`check_id` failed (see §4 F1).
Second attempt with `check_id` only succeeded:

```
→ tools/call name=prowler_hub_get_check_details arguments={"check_id":"s3_bucket_public_access"}
← {
    "id": "s3_bucket_public_access",
    "provider": "aws",
    "title": "S3 bucket is not publicly accessible to Everyone or Authenticated Users",
    "severity": "critical",
    "risk": "Publicly accessible buckets jeopardize **confidentiality** through unauthenticated reads, **integrity**...",
    ...
  }
```

---

## 3. Resources + Prompts

`prowler-mcp` (FastMCP v2.14.0) advertises capabilities in initialize:
- `prompts.listChanged: false` — server doesn't push prompts list updates
- `resources.subscribe: false, listChanged: false` — server doesn't push resource updates

We did NOT call `prompts/list` or `resources/list` during Phase A — the
spec says they may exist. opensploit's `mcp_tool` only dispatches
`tools/call`, so prompts/resources are NOT reachable from the agent
even if they exist (mirrors the zap + mongodb situation).

---

## 4. Target-extraction adversarial cases

**N/A.** kind:mcp tools have no argv parsing. Every input is JSON-Schema
validated by Pydantic in the FastMCP server. Schema mismatches return
structured errors (see §5 F1).

---

## 5. Failure-signature live-verify cases

### F1 — Schema validation: unexpected_keyword_argument — **LIVE-VERIFIED 2026-05-09**

```
→ tools/call name=prowler_hub_get_check_details
   arguments={"provider_id":"aws","check_id":"s3_bucket_public_access"}
← isError: True
   "1 validation error for call[get_check_details]
    provider_id
      Unexpected keyword argument [type=unexpected_keyword_argument,
      input_value='aws', input_type=str]"
```

The `prowler_hub_get_check_details` schema accepts ONLY `check_id` —
no `provider_id`. Common confusion with `prowler_hub_get_check_code`
and `prowler_hub_get_check_fixer` which DO take both. tool.yaml
gotchas section calls this out explicitly.

Failure signature: `Unexpected keyword argument`.

### F2 — PyPI package name confusion — **LIVE-OBSERVED at build time**

```
$ pip install prowler-mcp-server  (incorrect)
ERROR: No matching distribution found for prowler-mcp-server
```

PyPI package is `prowler-mcp` (without `-server`). Image installs from
local source (/opt/prowler-src/mcp_server) at build time to bypass PyPI
version drift entirely.

Failure signature: `Could not find a version that satisfies the requirement`.

### F3 — Django sys.path missing — **LIVE-OBSERVED at first boot**

```
ModuleNotFoundError: No module named 'config'
```

bootstrap.py imports Django settings (`config.django.production`) which
requires PROWLER_API_DIR (`/opt/prowler-src/api/src/backend`) on
sys.path. Manage.py adds it implicitly; bootstrap.py doesn't get that.
Mitigated: bootstrap.py inserts the dir explicitly before django.setup().

Failure signature: `ModuleNotFoundError: No module named 'config'`.

### F4 — Poetry config option drift — **LIVE-OBSERVED at build time**

```
$ poetry config experimental.system-git-client true
Setting experimental.system-git-client does not exist
```

Poetry 2.x removed the `experimental.system-git-client` option that 1.x
used to bypass dulwich. Workaround: sed-rewrite the prowler library
git dep (`prowler @ git+https://github.com/...`) to a local-path dep
(`prowler @ file:///opt/prowler-src`) which uses pip's local installer
instead of dulwich.

Failure signature: `Setting experimental.system-git-client does not exist`.

### F5 — Poetry lock stale after sed-edit — **LIVE-OBSERVED at build time**

```
$ poetry install
pyproject.toml changed significantly since poetry.lock was last generated.
```

Image runs `poetry lock --no-cache` BEFORE `poetry install` to
regenerate the lock matching our sed-edited pyproject.toml.

Failure signature: `pyproject.toml changed significantly since poetry.lock`.

### F6 — DozerDB symlink breakage — **LIVE-OBSERVED at first boot**

```
java.nio.file.FileAlreadyExistsException: /opt/dozerdb/data
File /opt/dozerdb/logs exists and is not a directory.
```

Upstream `graphstack/dozerdb:5.26.3.0` image has `/var/lib/neo4j/logs ->
/logs` and `/var/lib/neo4j/data -> /data` symlinks (volume mount points).
Docker COPY into our runtime broke them. Mitigated: Dockerfile runs
`rm -rf /opt/dozerdb/{logs,data} && mkdir` after the COPY.

Failure signature: `FileAlreadyExistsException: /opt/dozerdb/data`.

### F7 — Postgres conf-not-in-data-dir — **LIVE-OBSERVED at first boot**

```
postgres: could not access the server configuration file
"/var/lib/postgresql/16/main/postgresql.conf": No such file or directory
```

Debian's apt postgresql-16 stores config at `/etc/postgresql/16/main/`
NOT in the data dir. Bare `pg_ctl` doesn't know about Debian's split.
Mitigated: entrypoint uses `pg_ctlcluster 16 main start` which respects
Debian conventions.

Failure signature: `could not access the server configuration file`.

---

## 6. Performance observed

| Operation | Observed time |
|---|---|
| Container cold start (fresh volumes) | 123s / 2:03 (live-measured 2026-05-09) |
| Container warm start (persistent volumes, after SIGKILL recovery) | 93s / 1:33 (live-measured 2026-05-09) |
| Memory at idle (full stack up, no calls) | 2.78 GiB / 11.9% of 23 GB host RAM |
| `tools/list` (41 tools) | <0.1s |
| `prowler_hub_list_providers` (no-auth, GitHub fetch) | 0.5-1s |
| `prowler_docs_search` (no-auth, docs.prowler.com fetch) | 0.5-1s |
| `prowler_hub_get_check_details` (no-auth, single-check fetch) | 0.5-1s |
| `prowler_app_search_providers` (auth, local API) | <0.1s |
| `prowler_app_trigger_scan` (auth, returns scan_id immediately) | 0.1-0.3s (NOT YET VERIFIED — Phase B) |
| `prowler_app_get_scan` polling | <0.1s per call |
| Full AWS scan completion (small account, ~100 resources) | 5-15 min (NOT YET VERIFIED — Phase B) |
| `prowler_app_search_security_findings` (paginated) | <0.5s per page |

---

## 7. Vendor MCP quirks + offensive-relevant gotchas

These are real behaviors of `prowler-mcp` v0.5.0 + the bundled stack:

1. **`APN_1826889` boto3 user_agent_extra fingerprint** — verified in
   `prowler/providers/aws/config.py`. Defenders running CloudTrail see
   this in every event's `userAgent` field. Killed by entrypoint setting
   `PROWLER_AWS_BOTO3_USER_AGENT_EXTRA=''`.

2. **41-tool surface, fixed.** Vendor doesn't have a "minimal" mode.
   We accept all 41; agents pick by tool_registry_search.

3. **Three-namespace prefix model** — prowler_hub_*, prowler_docs_*,
   prowler_app_* — set by `setup_main_server()` via FastMCP's
   `import_server(..., prefix=...)`.

4. **Dynamic surface caveat** — server caps `tools.listChanged: true`
   so theoretically the surface could mutate. Verified live: 41 tools
   stable post-init. If it ever shrinks at runtime (e.g., app sub-server
   fails after an outage), the tool count assertion catches it.

5. **`prowler_hub_get_check_details` takes ONLY `check_id`.** No
   `provider_id` (verified F1). Confused with siblings — agents pattern
   off get_check_code's signature and get burned.

6. **Default secrets in upstream's compose `.env`** are PUBLIC strings
   committed to the repo (POSTGRES_ADMIN_PASSWORD=postgres,
   AUTH_SECRET="N/c6mnaS5+SWq81+819OrzQZlmx1Vxtp/orjttJSmw8="). Image
   randomizes ALL of them on first boot via `openssl rand -base64 32`.
   If you build a custom image without the entrypoint, you inherit the
   public defaults.

7. **Postgres data + neo4j data persist across container restarts only
   if you mount volumes.** Without `-v`, every restart costs the ~2-3 min
   cold-start tax. Recommended: `-v prowler_pgdata:/var/lib/postgresql -v prowler_neo4j:/opt/dozerdb/data -v prowler_state:/var/lib/prowler`.

8. **bootstrap.py is idempotent** for Tenant/User/Membership/Role/UserRoleRelationship
   (all use `get_or_create`). For TenantAPIKey it appends a random
   suffix to the name on collision (since the plaintext key is
   unrecoverable from the encrypted DB row). To avoid spurious key
   churn across restarts, persist `/var/lib/prowler/bootstrap/api_key`
   on a volume.

9. **No tenant signup management command.** Upstream has only
   `check_and_fix_socialaccount_sites_migration` and `findings`
   management commands — no built-in `create_tenant` / `create_user`.
   Hence our custom `bootstrap.py`.

10. **DozerDB log4j init is noisy on first boot.** Despite the
    rm-rf-and-mkdir of logs/data after COPY (F6 fix), neo4j-admin
    set-initial-password emits ~30 log4j config validation warnings
    before working. Cosmetic — service still comes up healthy.

11. **CloudTrail event fetch lookback default** — `prowler_app_get_resource_events`
    defaults to 7 days lookback. For longer post-ex forensics, pass
    `lookback_days: 90` (max varies by AWS CloudTrail retention; default
    AWS retention is 90 days).

12. **Async Celery scan model** — `trigger_scan` returns immediately
    with a `scan_id`; the actual scan runs in the worker. If the agent
    treats it as synchronous (assumes findings exist immediately after
    trigger_scan returns), it gets empty results. ALWAYS poll
    `get_scan` until `state==completed`.

---

## 8. Things NOT verified that could bite us in production

1. **Phase B (AWS Fortress integration test) is DEFERRED.** Phase A
   proves the WRAPPER works end-to-end (auth flow + all 3 namespaces
   reachable). What's NOT verified:
   - `prowler_app_connect_provider` against real AWS creds
   - `prowler_app_trigger_scan` actually completing
   - Findings persisted correctly + searchable
   - Attack-paths Cypher queries against a populated graph
   - `get_resource_events` actually fetching CloudTrail data
   - CloudTrail UA fingerprint mitigation (PROWLER_AWS_BOTO3_USER_AGENT_EXTRA='')
     visible in defender's CloudTrail (theoretical based on source-grep,
     not yet observed in target's logs)

2. **Warm-start time NOT verified.** Estimate of 30-60s on subsequent
   boots assumes persistent volumes. First subsequent restart is the
   real test.

3. **DozerDB attack-paths integration.** We boot dozerdb successfully,
   but the `cartography` python package (which populates the graph) is
   triggered by a Celery worker job that hasn't run in Phase A. Whether
   cartography → dozerdb → prowler_app_run_attack_paths_query forms a
   working chain end-to-end is unverified.

4. **Sentry stays disabled when DJANGO_SENTRY_DSN=''.** Verified in
   sentry.py source code (sentry_sdk.init with empty DSN is no-op per
   Sentry SDK convention) but not observed at runtime.

5. **Multi-tenant isolation.** bootstrap.py creates ONE tenant; we
   don't test that RLS policies actually prevent cross-tenant data
   leakage. Out of scope for offensive use (we never have multiple
   tenants in one container).

6. **API throttling / rate limits on hub.prowler.com fetches.** A burst
   of `prowler_hub_*` calls might hit upstream rate limits. Not
   reproduced.

7. **Image rebuilds ARM64.** All testing was on x86_64. Multi-arch
   pinned base images (`graphstack/dozerdb:5.26.3.0` Multi-arch?)
   may or may not work on ARM.

---

## 9. Phase B placeholder — AWS Fortress integration test

Test plan against AWS Fortress (HTB) — DEFERRED:

1. Compromise Fortress's Windows AD entry point (`aws.htb`,
   10.13.37.15) to obtain AWS access keys (separate offensive work
   chain, not part of prowler MCP testing)
2. With keys in hand, drive manual MCP harness:
   ```
   prowler_app_connect_provider(provider_uid=ACCT, provider_type=aws,
       credentials={aws_access_key_id, aws_secret_access_key})
   prowler_app_trigger_scan(provider_id=...)
   poll prowler_app_get_scan until state=completed
   prowler_app_get_findings_overview()
   prowler_app_search_security_findings(severity=critical, status=FAIL)
   prowler_app_run_attack_paths_query(scan_id=, query_id=)
   ```
3. CloudTrail post-mortem via separate `aws cloudtrail lookup-events`
   to verify `userAgent` field shows generic Boto3 — NOT APN_1826889.

When Phase B runs, append findings to this file under a "Phase B
verification" section with timestamps + observed scan duration +
attack-paths query results.

---

## 10. Hand-off

- **Tool:** prowler (kind:mcp, prowler-cloud/prowler mcp_server v0.5.0
  via local-source pip install in image)
- **Image:** `ghcr.io/silicon-works/mcp-tools-prowler:latest` (CI
  rebuilds from `tools/prowler/Dockerfile` on push to main)
- **Surface:** 41 tools across 3 namespaces (10 hub no-auth + 2 docs
  no-auth + 29 app auth-required). Resources: 0 advertised (FastMCP
  server caps say `subscribe:false, listChanged:false`). Prompts: 0
  advertised.
- **Wrapper retirement:** prior 406-LOC custom Python wrapper deleted
  entirely. Three-method legacy surface (scan/list_checks/scan_service)
  superseded by the 41-tool vendor surface; legacy `scan` is now the
  trigger_scan + get_scan + search_security_findings flow.
- **Live verification (this file):** bundled stack on Linux x86_64
  Debian bookworm, 2026-05-09. Phase A complete (5 of 5 wrapper-works
  tests green); Phase B deferred.
- **Known upstream alpha quirks:** see §6. Most notable:
  APN_1826889 fingerprint mitigation, 41-tool surface fixed, async
  scan model requires polling, get_check_details schema doesn't accept
  provider_id (Pydantic validation error).
- **Cross-tool routing:** see_also points at aws (existing vendor wrap
  for direct AWS API), curl (raw HTTPS to local Django API for
  debugging), trivy (container/IaC scanning), nuclei (app-layer
  scanning), nmap (cloud service exposure discovery).

## Sources

- [prowler-cloud/prowler mcp_server](https://github.com/prowler-cloud/prowler/tree/master/mcp_server) — vendor source
- [prowler-mcp on PyPI](https://pypi.org/project/prowler-mcp/) — v0.5.0 max as of 2026-05-09
- [Prowler MCP Server overview docs](https://docs.prowler.com/getting-started/products/prowler-mcp)
- [Prowler MCP Tools reference](https://docs.prowler.com/getting-started/basic-usage/prowler-mcp-tools)
- [Prowler App self-hosted installation](https://docs.prowler.com/getting-started/installation/prowler-app)
- [Bug #8897 — fresh self-host RSA key gen failure](https://github.com/prowler-cloud/prowler/issues/8897)
