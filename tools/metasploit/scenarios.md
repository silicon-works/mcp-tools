# metasploit — kind:mcp scenarios

Single test sheet for the `metasploit` tool migration (Python wrapper retired
May 2026, replaced by Rapid7's official `msfmcpd` running 8 read-only tools).

metasploit is a kind:mcp tool wrapping Rapid7's official `msfmcpd` Ruby
binary. The container hybrid-installs Kali's `metasploit-framework` apt
package + sparse-cloned `msfmcpd` / `lib/msf/core/mcp/` from upstream master
+ the `mcp` Ruby gem. msfmcpd auto-spawns `msfrpcd` internally on container
start with random credentials; the agent's MCP traffic flows over stdio
(production) or HTTP (dev/inspection only — set `MSF_MCP_TRANSPORT=http`).

Sections:
1. Recommended HTB box for live verification
2. Narrative scenarios — all 8 methods, individually verified
3. Target-extraction adversarial cases — N/A (kind:mcp, no argv parsing)
4. Failure-signature live-verify cases (≥3)
5. Workspace population — required because msfmcpd is read-only
6. Performance observed
7. Open questions
8. Hand-off

---

## 1. Recommended HTB box

**Forest (10.129.197.47)** — Windows Server 2016 DC for `htb.local`.
Live-verified 2026-05-06. AD ports 53/88/135/139/389/445/464/593/636/3268
/3269/5985/9389 all open. Small AD lab — fast db_nmap (~12s for the AD port
set, ~36s with `-sV` + version fingerprinting) + smb_version scanner adds
real records to the workspace. Ideal for exercising the catalog tools (DC
domain `htb.local` lights up plenty of Kerberos/LDAP modules) and the DB
tools (single host, populated services, smb_version-derived notes).

**Alternate boxes:** any HTB AD lab with reachable AD ports works. The
catalog tools (`msf_search_modules`, `msf_module_info`) don't actually
touch the target — they query the in-image module index — so the only
network requirement is for the populator step in §5.

**Container start command (dev/inspection, HTTP transport):**
```
docker run -d --name msf-mcp-live --network=host \
  -e MSF_MCP_TRANSPORT=http -e MSF_MCP_HOST=127.0.0.1 -e MSF_MCP_PORT=3001 \
  ghcr.io/silicon-works/mcp-tools-metasploit:latest
```
**Production (stdio, what opensploit's ContainerManager uses):** the same
image without the env overrides; ContainerManager attaches stdin/stdout
itself.

**Cold-start cost:** ~36s (postgres start + msfdb init + workspace
bootstrap + msfmcpd-spawned msfrpcd + module index load). Subsequent
tool calls are sub-second.

---

## 2. Narrative scenarios — all 8 methods

Every method below was exercised one-by-one against a live msfmcpd talking
to a real msfrpcd inside the container. `→` shows actual response data
from the 2026-05-06 verification run on Forest.

### S1 — `tools/list` (discovery) — **LIVE-VERIFIED 2026-05-06**

**Invoke:** standard MCP `tools/list`.

**Expected:** 8 tools advertised:
```
msf_search_modules, msf_module_info,
msf_host_info, msf_service_info, msf_vulnerability_info,
msf_note_info, msf_credential_info, msf_loot_info
```
Each carries an `inputSchema` (JSON Schema), `outputSchema`, and
`annotations: {readOnlyHint: true, idempotentHint: true, destructiveHint: false}`.

**Live verdict:** ✓ all 8 advertised, schemas match upstream's Ruby source.

### S2 — `msf_search_modules` (catalog query) — **LIVE-VERIFIED 2026-05-06**

```
msf_search_modules({"query": "asrep", "limit": 10})
```
→ 3 matches in 0.23s:
- `auxiliary/gather/asrep` (Find Users Without Pre-Auth Required)
- `auxiliary/gather/kerberos_enumusers`
- `auxiliary/gather/ldap_query`

`metadata`: `{query_time: 0.178, total_items: 3, returned_items: 3, limit: 10, offset: 0}`.

**Other queries verified live:** `"ms17_010"` → 4 matches; `"CVE-2020-1472"` → 1 match (zerologon); `"kerberos enum"` → 3 matches; `"ldap"` → 49 matches (covers `auxiliary/admin/ldap/bad_successor`, `ad_cs_cert_template`, etc.).

### S3 — `msf_module_info` (module metadata) — **LIVE-VERIFIED 2026-05-06**

```
msf_module_info({"type": "auxiliary", "name": "gather/asrep"})
```
→ structured payload in 0.18s:
```
type: 'auxiliary'
name: 'Find Users Without Pre-Auth Required (ASREP-roast)'
fullname: 'auxiliary/gather/asrep'
rank: 'normal'
stance: 'aggressive'
privileged: False
has_check_method: False
options: 24 entries (RHOSTS, RPORT=389, KrbClockSkew, USERNAME, USER_FILE, etc.)
references: 1 (ired.team AS-REP roasting writeup)
```
**Note:** the `name` argument does NOT include the type prefix. Pass
`type: "exploit", name: "windows/smb/ms17_010_eternalblue"` — NOT
`name: "exploit/windows/..."`. `msf_search_modules` returns `fullname`
WITH the prefix; the agent must strip it before calling `module_info`.

### S4 — `msf_host_info` (DB query, after populator) — **LIVE-VERIFIED 2026-05-06**

Pre-state: workspace populated by `db_nmap` against Forest (see §5).

```
msf_host_info({})
```
→ 1 record in 0.12s:
```json
{
  "address": "10.129.197.47",
  "mac_address": "",
  "hostname": "",
  "state": "alive",
  "os_name": "Unknown",
  "os_flavor": "",
  "os_service_pack": "",
  "os_language": "",
  "purpose": "device",
  "info": "",
  "created_at": "2026-05-06T21:21:45Z",
  "updated_at": "2026-05-06T21:21:45Z"
}
```
**Note:** `os_name=Unknown` because db_nmap with `-sV` doesn't run OS
detection. For OS info include `-O` in the populator scan or run a
separate scanner module.

### S5 — `msf_service_info` (DB query, all services) — **LIVE-VERIFIED 2026-05-06**

```
msf_service_info({"workspace": "default"})
```
→ 13 records in 0.09s. Sample (port 88, Kerberos):
```json
{
  "host_address": "10.129.197.47",
  "port": 88,
  "protocol": "tcp",
  "state": "open",
  "name": "kerberos-sec",
  "info": "Microsoft Windows Kerberos server time: 2026-05-06 21:28:05Z"
}
```
Full port set observed: 53, 88, 135, 139, 389, 445, 464, 593, 636, 3268,
3269, 5985, 9389. Banner-derived domain (`htb.local`) and Site
(`Default-First-Site-Name`) recorded under LDAP entries.

### S6 — `msf_service_info` with filters — **LIVE-VERIFIED 2026-05-06**

```
msf_service_info({"workspace": "default", "host": "10.129.197.47",
                  "ports": "445", "protocol": "tcp"})
```
→ 2 records in 0.06s — both port 445/tcp on Forest. One from `db_nmap`
(name=`microsoft-ds`, info=Server 2008 R2-2012 banner) and one from
`smb_version` scanner (name=`smb`, info=full SMB dialect + GUID +
domain=HTB + Win2016 build 14393). Different scanners record under
different `name`s on the same port; this is real upstream behavior.

### S7 — `msf_service_info` pagination — **LIVE-VERIFIED 2026-05-06**

```
page 1: msf_service_info({"workspace": "default", "limit": 2, "offset": 0})
page 2: msf_service_info({"workspace": "default", "limit": 2, "offset": 2})
```
→ both pages return 2 records, `total_items=14` (constant), offset
advances correctly. Page 1: ports 53, 88. Page 2: ports 135, 139.

### S8 — `msf_note_info` (DB query, after smb_version scanner) — **LIVE-VERIFIED 2026-05-06**

Pre-state: `smb_version` scanner run from msfconsole (see §5).

```
msf_note_info({"workspace": "default"})
```
→ 2 records in 0.07s:
```json
[
  {
    "host": "10.129.197.47", "service_name_or_port": "microsoft-ds",
    "note_type": "fingerprint.match",
    "data": "{\"os.edition\"=>\"Standard\", \"os.build\"=>\"14393\", \"host.domain\"=>\"HTB\", \"host.name\"=>\"FOREST\"}"
  },
  {
    "host": "10.129.197.47", "service_name_or_port": "microsoft-ds",
    "note_type": "smb.fingerprint",
    "data": "{:native_os=>\"Windows Server 2016 Standard 14393\", ...}"
  }
]
```
Useful intelligence: `host.name=FOREST`, `host.domain=HTB`,
`os.build=14393` (= Win Server 2016 Standard).

### S9 — `msf_credential_info` (DB query, with manual cred) — **LIVE-VERIFIED 2026-05-06**

Pre-state: `creds add user:guest password:'' realm:HTB.LOCAL` run from
msfconsole (see §5).

```
msf_credential_info({"workspace": "default"})
```
→ 2 records in 0.12s (one with realm, one without):
```json
{
  "host": "", "port": 0, "protocol": "", "service_name": "",
  "user": "guest", "secret": "",
  "type": "Metasploit::Credential::BlankPassword",
  "updated_at": "2026-05-05T07:39:03Z"
}
```
The `type` field is the canonical MSF private-credential class name —
agents can branch on `BlankPassword` vs `Password` vs `NTLMHash` vs
`KrbEncKey` to drive different attack paths. `host` and `port` are
empty when the credential is realm-scoped rather than service-bound.

### S10 — `msf_loot_info` (DB query, after manual loot insert) — **LIVE-VERIFIED 2026-05-06**

Pre-state: `loot -a -f /etc/hostname -i ... -t enum_test 10.129.197.47`
run from msfconsole (see §5).

```
msf_loot_info({"workspace": "default"})
```
→ 1 record in 0.06s:
```json
{
  "host": "10.129.197.47", "loot_type": "enum_test",
  "content_type": "text/plain", "name": "hostname",
  "info": "forest-enum-test-after-respawn",
  "data": "debian\n",
  "created_at": "2026-05-06T21:23:10Z",
  "updated_at": "2026-05-06T21:23:10Z"
}
```
The `data` field returns inline file contents — no separate fetch step
needed. For binary loot the field is base64-encoded by upstream.

### S11 — `msf_vulnerability_info` (DB query, after manual postgres insert) — **LIVE-VERIFIED 2026-05-06**

Pre-state: synthetic vuln inserted directly into postgres because no
read-only-friendly populator exists for vulns (no MCP method, and
msfconsole's `vulns` command can list but not insert; only scanner
modules write to the table during normal flow). See §5.

```
msf_vulnerability_info({"workspace": "default"})
```
→ 1 record in 0.08s:
```json
{
  "host": "10.129.197.47",
  "name": "TEST_VULN_FOR_VALIDATION",
  "created_at": "2026-05-06T21:24:13Z"
}
```
**Schema observation:** the published `outputSchema` lists
`host, port, protocol, name, references, created_at`. The manual insert
omitted `service_id` and `vulns_refs` rows, so `port`, `protocol`, and
`references` are absent. Real scanner-recorded vulns (e.g.,
`auxiliary/scanner/smb/smb_ms17_010` against an MS17-010-vulnerable
target) populate all six.

### S12 — error path: `msf_module_info` with bad path — **LIVE-VERIFIED 2026-05-06**

```
msf_module_info({"type": "exploit", "name": "no/such/module/exists/anywhere"})
```
→ `isError: true` in 0.05s with text `"Metasploit API error: Invalid Module"`.
Agent gets a clear, parseable failure signal — no crash, no hang.

---

## 3. Target-extraction adversarial cases

**N/A.** kind:mcp tools have no argv parsing — every input is a typed
JSON-Schema-validated MCP argument. The target-extraction DSL (used by
kind:cli to find/quarantine network targets in argv) does not apply.

The closest equivalent is **input-schema validation by the upstream
`mcp` gem itself**, which rejects unknown fields and missing required
fields with JSON-RPC `-32602 Invalid params`. See §4 for live evidence.

---

## 4. Failure-signature live-verify cases

### F1 — Missing required `workspace` arg — **LIVE-VERIFIED 2026-05-06**

```
msf_loot_info({})   # no workspace
```
→ JSON-RPC error frame:
```json
{"code": -32602, "message": "Invalid params",
 "data": "Missing required arguments: workspace"}
```
**Failure signature:** `Missing required arguments` substring.
**Affects:** all DB tools EXCEPT `msf_host_info` (host_info has no
required-args declaration in upstream's `host_info.rb`; the other 5 do
despite having a default value — a real upstream inconsistency, not ours).

### F2 — Bad module path — **LIVE-VERIFIED 2026-05-06** (S12 above)

`isError: true` + text `"Metasploit API error: Invalid Module"`.
**Failure signature:** `Invalid Module` substring.

### F3 — Empty workspace not-yet-bootstrapped — **WAS** a failure mode

When the container's entrypoint failed to pre-create the `default`
workspace, every DB tool returned
`Metasploit API error: Invalid workspace`. **Mitigated in entrypoint.sh**
by running `msfconsole -q -x "workspace -a default; exit"` after
`msfdb init`. Still possible if msfdb init silently fails (e.g.
postgres unavailable). Failure signature: `Invalid workspace` substring.

### F4 — Rate limit triggered — **LIVE-VERIFIED 2026-05-04**

msfmcpd token-bucket rate limit: 60 req/min, burst 10. The 11th call
in a tight loop (<10s gap) returns `Rate limit exceeded` until the
bucket refills. Pace tight loops with ≥1s gaps. This was the cause of
the spurious `msf_loot_info` failure in the original Phase H batch run
before pacing was added.

---

## 5. Workspace population — required because msfmcpd is read-only

The 6 DB-backed tools query an msf workspace populated by external
activity. msfmcpd has NO write methods — there is no MCP-level
`db_nmap`, `db_import`, or scanner-execute. Workspace state must be
populated **out of band**.

**Production flow (when other agent tools eventually feed msf):**
- Agent runs nmap (separate kind:cli `nmap` tool), gets XML output
- Agent runs (currently unimplemented) some bridge that calls
  `db_import` on the msf workspace, OR
- Upstream Rapid7 ships a write-MCP-layer in the next iteration

**Verification flow (what the test harness does):**

```bash
# 1. Populate hosts + services from a real scan
docker exec msf-mcp-live msfconsole -q -x \
  "db_nmap -Pn -sT -sV -p 53,88,135,139,389,445,464,593,636,3268,3269,5985,9389 10.129.197.47; exit"

# 2. Add notes via a scanner module (smb_version is fast, low-noise)
docker exec msf-mcp-live msfconsole -q -x \
  "use auxiliary/scanner/smb/smb_version; set RHOSTS 10.129.197.47; run; exit"

# 3. Add a credential record (msfconsole's `creds add` works)
docker exec msf-mcp-live msfconsole -q -x \
  "creds add user:guest password:'' realm:HTB.LOCAL; exit"

# 4. Add a loot record
docker exec msf-mcp-live msfconsole -q -x \
  "loot -a -f /etc/hostname -i 'enum-test' -t enum_test 10.129.197.47; exit"

# 5. Add a vuln record (postgres direct — no msfconsole equivalent for manual inserts)
docker exec --user postgres msf-mcp-live psql msf -c "
  INSERT INTO vulns (host_id, name, info, created_at, updated_at, resource)
  SELECT id, 'TEST_VULN_FOR_VALIDATION', 'manually inserted',
         NOW(), NOW(), '{}'::jsonb
  FROM hosts WHERE address = '10.129.197.47';"
```

After these 5 steps the workspace has: 1 host, 13 services (14 if
smb_version was run, which adds a second port-445 record),
2 notes, 1+ credentials, 1 loot record, 1 vuln record.

---

## 6. Performance observed

| Operation | Observed time |
|---|---|
| Cold start (docker run → 8 tools advertised) | **36.6s** |
| `msf_search_modules` (catalog hit) | 0.23s |
| `msf_module_info` (full metadata, 24 options) | 0.18s |
| Each DB-backed tool, populated | 0.06–0.12s |
| `db_nmap -sT -sV` on Forest (14 AD ports) | ~12–48s depending on filtering |
| `auxiliary/scanner/smb/smb_version` on Forest | ~19s |
| Total Phase H batch (16 calls) end-to-end | ~5 minutes (dominated by populator) |

---

## 7. Open questions

- **`msf_credential_info` returns hashes how?** Live verification used a
  blank-password cred (`Metasploit::Credential::BlankPassword`). The
  `secret` field for an `NTLMHash` or `Krb` private should contain the
  hash — not yet observed live; should verify with a real `hashdump` or
  `secretsdump` import once a write-path is available.
- **`msf_vulnerability_info`'s `references` field shape** — observed
  empty on a manually-inserted vuln. A scanner-recorded vuln (e.g., a
  positive `smb_ms17_010` finding) populates the join with module refs;
  not yet observed live.
- **HTTP transport session-id handling** — verified working with curl.
  opensploit's ContainerManager uses stdio (no session-id concept). If
  HTTP transport is ever used (multi-tenant deployment, agent fleet),
  validate that session expiry/cleanup is well-behaved.
- **Workspace persistence between container restarts** — postgres data
  lives inside the container. Per-engagement container = clean DB. If
  cross-engagement persistence ever matters, mount postgres data on a
  named volume.

---

## 8. Hand-off

- **Tool:** metasploit (kind:mcp, Rapid7 official msfmcpd, 8 read-only
  catalog + DB query tools)
- **Image:** `ghcr.io/silicon-works/mcp-tools-metasploit:latest` (CI
  rebuilds from `tools/metasploit/Dockerfile` on push to main)
- **Surface:** matches upstream verbatim — when Rapid7 adds execution
  / session tools in a future iteration, they appear here automatically
  on next image rebuild
- **Wrapper preserved:** mcp-tools commit `ad330f9` retains the legacy
  29-method Python wrapper if migration ever reverses
- **Live verification (this file):** Forest @ 10.129.197.47, 2026-05-06,
  every method exercised individually with real records observed
- **Known upstream quirks:** workspace required-arg inconsistency (5/6
  DB tools), rate-limit at 60 req/min burst 10, no MCP-level write path
  → workspace population requires out-of-band msfconsole or postgres
- **Cross-tool routing:** `see_also` in tool.yaml points at
  `exploit-runner` (execution path), `searchsploit` (broader catalog),
  `nmap` (workspace populator), `nuclei` (vuln validation)
