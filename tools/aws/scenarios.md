# aws — vendor MCP standardization scenarios

Live-verification record for the May 2026 standardization round of the
`aws` tool. **Not a vendor-MCP swap** — `tools/aws/` was always a thin
wrapper around AWS Labs' official `awslabs.aws-api-mcp-server` PyPI
package. Custom code is 33 lines: env vars + User-Agent fingerprint
patch + `from awslabs.aws_api_mcp_server.server import main; main()`.
This standardization round adds the `kind:mcp` explicit declaration,
`service:true` for credential persistence, full failure_signatures
+ gotchas + usage_patterns, smoke test, and this file — mirroring the
playwright May 8 standardization pattern.

**Validation methodology:** manual one-call-per-LLM-turn stdio MCP
harness (FIFO + log-tail, the same shape opensploit's ContainerManager
uses), driven against `ghcr.io/silicon-works/mcp-tools-aws:latest` on
2026-05-11. Each call was issued with reasoning between turns — no
batched scripts. Vendor source-verified at commit
`prowler-vendor/aws-mcp-vendor` (HEAD: latest awslabs/mcp main).

Sections:
1. Architecture + container boot sequence
2. Manual through-the-stdio integration test
3. Resources + Prompts
4. Target-extraction adversarial cases (N/A for kind:mcp)
5. Failure-signature live-verify cases
6. Performance observed
7. Vendor MCP quirks + offensive-relevant gotchas
8. Things NOT verified that could bite us in production
9. Hand-off

---

## 1. Architecture + container boot sequence

```
opensploit ContainerManager (stdio MCP, service:true once per session)
        │   docker run -i --rm
        │     -e AWS_ACCESS_KEY_ID=... -e AWS_SECRET_ACCESS_KEY=...
        │     -e AWS_SESSION_TOKEN=... -e AWS_REGION=us-east-1
        │     -v ${sessionDir}:/session:rw
        │     ghcr.io/silicon-works/mcp-tools-aws:latest
        ▼
container's CMD: python3 /app/mcp-server.py (~33 LOC)
   1. set AWS_API_MCP_TELEMETRY=false (kill awslabs telemetry)
   2. set AWS_API_MCP_TRANSPORT=stdio
   3. monkey-patch boto3 user-agent to strip md/awslabs#mcp#... fingerprint
   4. from awslabs.aws_api_mcp_server.server import main; main()
        ▼
awslabs.aws-api-mcp-server v1.3.x (FastMCP framework v3.2.x)
        │   serverInfo: {name: "AWS-API-MCP", version: "<framework v>"}
        │   2 default tools registered: call_aws, suggest_aws_commands
        │   (3rd tool get_execution_plan only if EXPERIMENTAL_AGENT_SCRIPTS=true)
        ▼
boto3 + bundled awscli==1.45.x
        │   reads creds from standard chain:
        │     env > ~/.aws/credentials > IMDSv2 > ECS task role
        ▼
target AWS account (any service)
```

### Boot timing observed (2026-05-11)

| Stage | Cold |
|---|---|
| Container start (image cached locally) | <1s |
| Python venv activate + boto3/awscli + FastMCP init | 3-5s |
| FastMCP "Starting MCP server 'AWS-API-MCP'" log | t+~5s |
| **Total to MCP-stdio-ready** | **~5s** |

Significantly faster than prowler/mongodb because there's no DB stack to
init — just Python imports.

---

## 2. Manual through-the-stdio integration test

### Test 1 — Initialize handshake — **LIVE-VERIFIED 2026-05-11**

```
→ {"jsonrpc":"2.0","id":1,"method":"initialize","params":{...}}
← {"result":{
     "protocolVersion":"2024-11-05",
     "capabilities":{
       "experimental":{},
       "logging":{},
       "prompts":{"listChanged":false},
       "resources":{"subscribe":false,"listChanged":false},
       "tools":{"listChanged":true},
       "extensions":{"io.modelcontextprotocol/ui":{}}
     },
     "serverInfo":{"name":"AWS-API-MCP","version":"3.2.4"}
  }}
```

**Findings:**
- Server name `AWS-API-MCP` (FastMCP namespace, NOT the package name `awslabs.aws-api-mcp-server`)
- Version `3.2.4` is FastMCP framework — NOT the underlying `awslabs.aws-api-mcp-server` package (which is 1.3.x). Same naming pattern as prowler's `prowler-mcp-server` v `2.14.0`.
- Vendor advertises an `extensions.io.modelcontextprotocol/ui` capability — UI extension, not used by opensploit's mcp_tool dispatcher.

### Test 2 — tools/list — **LIVE-VERIFIED 2026-05-11**

```
TOTAL TOOLS: 2 (default surface)
  • call_aws
      properties: ['cli_command', 'max_results']
      required: ['cli_command']
  • suggest_aws_commands
      properties: ['query']
      required: ['query']
```

Confirmed against vendor source (`awslabs/aws_api_mcp_server/server.py`):
- `call_aws` registered unconditionally at line 183
- `suggest_aws_commands` registered unconditionally at line 89
- `get_execution_plan` registered conditionally at line 380, gated by
  `if ENABLE_AGENT_SCRIPTS:` (which is `get_env_bool('EXPERIMENTAL_AGENT_SCRIPTS', False)`)

Our entrypoint does NOT set EXPERIMENTAL_AGENT_SCRIPTS → 2-tool surface.

### Test 3 — `call_aws aws sts get-caller-identity` (no creds) — **LIVE-VERIFIED**

```
→ tools/call name=call_aws arguments={"cli_command":"aws sts get-caller-identity"}
← isError: False
   content[0].text: [{"cli_command":"aws sts get-caller-identity",
                      "error":"Error while executing the command: No AWS credentials found.
                       Please configure your AWS credentials using 'aws configure' or
                       set appropriate environment variables."}]
```

**Confirms:**
- Container reaches the boto3 layer (no networking/initialization issues)
- No-creds error captured as `failure_signature: no_credentials`
- **Critical quirk: isError is FALSE on a failed command.** Vendor wraps every result
  (success or error) in result.content[0].text as a JSON list. Standard MCP isError flag
  is NOT used. Captured as a top-line gotcha.

### Test 4 — `call_aws aws --version` — **LIVE-VERIFIED**

```
→ tools/call name=call_aws arguments={"cli_command":"aws --version"}
← isError: False
   content[0].text: [{"cli_command":"aws --version",
                      "error":"argument --version: expected one argument"}]
```

**Surprise:** even `aws --version` (which works fine in a normal shell) errors
through the MCP wrapper because vendor's awscli parser expects a service
positional arg. Don't use this as a "container is alive" probe — use
`aws sts get-caller-identity` (which gives the no-creds signal cleanly).

### Test 5 — `call_aws ls /tmp` (non-aws command) — **LIVE-VERIFIED**

```
→ tools/call name=call_aws arguments={"cli_command":"ls /tmp"}
← isError: False
   content[0].text: [{"cli_command":"ls /tmp",
                      "error":"Error while validating the command:
                       {\"validation_failures\":[{\"reason\":\"The provided CLI command
                        is not an AWS command\",\"context\":null}],
                        \"missing_context_failures\":null}"}]
```

**Confirms:** vendor pre-validates the cli_command starts with `aws ` before any
boto3 call. Captured as `failure_signature: non_aws_command`.

### Tests NOT executed (deferred — would need real AWS account)

- `call_aws aws sts get-caller-identity` WITH valid creds → confirms identity
- `call_aws` with `--region *` cross-region scan → confirms vendor expansion works
- `call_aws` batch mode (list of 20 commands) → confirms MAX_BATCH_COMMANDS limit
- Any actual API call against a real account
- `suggest_aws_commands` — DELIBERATELY NOT tested (OPSEC: hits AWS Labs telemetry endpoint with query text)

---

## 3. Resources + Prompts

`awslabs.aws-api-mcp-server` (FastMCP v3.2.4) advertises capabilities in initialize:
- `prompts.listChanged: false` — server doesn't push prompts list updates
- `resources.subscribe: false, listChanged: false` — server doesn't push resource updates
- `extensions.io.modelcontextprotocol/ui` — UI extension surface (unused by opensploit)

We did NOT call `prompts/list` or `resources/list` during this verification —
the spec says they may exist. opensploit's `mcp_tool` only dispatches
`tools/call`, so prompts/resources are NOT reachable from the agent
even if vendor exposes any (mirrors prowler/mongodb/zap's situation).

---

## 4. Target-extraction adversarial cases

**N/A.** kind:mcp tools have no argv parsing. Every input is JSON-Schema
validated by Pydantic in the FastMCP server. The `cli_command` arg IS a
shell-like string but vendor's pre-validation rejects pipes, redirects,
shell substitution, env vars (per the `call_aws` description's "Command
restrictions" section). Schema mismatches return structured errors (see §5).

---

## 5. Failure-signature live-verify cases

### F1 — No AWS credentials — **LIVE-VERIFIED 2026-05-11**

Documented in §2 Test 3. Signature: `"No AWS credentials found"`.

### F2 — Non-AWS command — **LIVE-VERIFIED 2026-05-11**

Documented in §2 Test 5. Signature: `"The provided CLI command is not an AWS command"`.

### F3 — argv validation error — **LIVE-VERIFIED 2026-05-11**

Documented in §2 Test 4. Signature: `"argument .*: expected one argument"`.

### F4 — Batch limit exceeded — **NOT live-verified, vendor-source confirmed**

Vendor source: `awslabs/aws_api_mcp_server/core/common/config.py:189`:
```
MAX_BATCH_COMMANDS = 20
```
Server raises `AwsApiMcpError(f'Number of batch commands exceeds the maximum limit of {MAX_BATCH_COMMANDS}.')`.

### F5-F9 — Real AWS API errors

Documented in tool.yaml failure_signatures based on standard AWS API error
shapes (ExpiredToken, AccessDenied, ThrottlingException, etc.). NOT
live-verified during this round — would require a real AWS account.

---

## 6. Performance observed

| Operation | Observed time |
|---|---|
| Container cold start (image cached locally) | ~5s (live-measured) |
| `tools/list` (2 tools) | <0.1s |
| `call_aws` no-creds error (synchronous) | <0.5s (no boto3 network) |
| `call_aws` argv-validation error | <0.5s (rejected before boto3) |
| `call_aws` non-aws-command rejection | <0.5s (rejected before boto3) |
| `call_aws` against real AWS API | NOT MEASURED — depends on AWS endpoint latency |
| `call_aws --region *` cross-region scan | NOT MEASURED — N regions × per-region latency |
| `call_aws` batch mode (up to 20 commands) | NOT MEASURED — depends on AWS endpoint latency, all sequential per vendor source |

---

## 7. Vendor MCP quirks + offensive-relevant gotchas

These are real behaviors of `awslabs.aws-api-mcp-server` v1.3.x + the wrapper:

1. **`isError: false` on failure.** Vendor wraps EVERY result, success or error,
   in `result.content[0].text` as a JSON list of `{cli_command, response|error}`.
   Standard MCP isError is always false. Agent must parse the content JSON.

2. **Default 2-tool surface, conditional 3rd.** call_aws + suggest_aws_commands
   always present. get_execution_plan only appears if EXPERIMENTAL_AGENT_SCRIPTS=true.
   Our entrypoint does NOT enable it.

3. **`suggest_aws_commands` calls home.** Hits AWS Labs HTTPS endpoint with raw
   query text. NO vendor env to disable. Agent self-discipline required.

4. **Older `AWS_API_MCP_ALLOW_SUGGEST` env was a no-op.** Our wrapper used to set
   this thinking it disabled suggest_aws_commands — vendor source has no such env.
   Removed from Dockerfile in this standardization round.

5. **`--region *` is a vendor extension.** Standard awscli has no `*` region.
   Vendor expands `*` server-side into one call per enabled region.

6. **`MAX_BATCH_COMMANDS = 20`.** Vendor config.py:189. Larger fan-outs need
   client-side chunking.

7. **Default region us-east-1.** No AWS_REGION env + no --region in cli_command
   → defaults to us-east-1. Set AWS_REGION via envOverrides for engagements
   in other regions.

8. **Working dir defaults to `/tmp/aws-api-mcp/workdir`.** Vendor reads/writes
   files (e.g., for `aws s3 cp` to local paths) here. Set
   `AWS_API_MCP_WORKING_DIR=/session/aws-work` to direct outputs into the
   session dir for cross-tool access.

9. **No vendor "set credentials" tool.** Creds via standard boto3 chain only.
   With service:true container persistence, env vars at container start are
   the cleanest path.

10. **Boto3 user-agent still partially visible.** Our wrapper strips the awslabs
    MCP fingerprint, but boto3's own UA (`Boto3/1.41.x Python/3.13 Linux/...`)
    remains. Defenders can distinguish API-driven from console-clicked, just
    not Prowler/awslabs-MCP-specifically.

11. **READ_OPERATIONS_ONLY toggle.** Vendor env name is `READ_OPERATIONS_ONLY`
    (NOT prefixed with AWS_API_MCP_). Set true for read-only engagements.

---

## 8. Things NOT verified that could bite us in production

1. **No real AWS account integration test done.** All §2 tests exercised the
   wrapper transport + the no-creds / validation error paths. We did NOT verify:
   - any actual API call succeeds when creds are valid
   - cross-region `--region *` expansion works
   - batch mode with 20 commands actually parallelizes server-side
   - paginated results (max_results) truncate as expected
   - response-shape parsing for typical operations (S3 list, IAM list, EC2 describe)

2. **`suggest_aws_commands` not exercised.** Deliberately — would call home to
   AWS Labs telemetry endpoint with query text. Captured as gotcha, not test.

3. **`get_execution_plan` not enabled.** EXPERIMENTAL_AGENT_SCRIPTS=true would
   register a 3rd tool, vendor's pre-baked workflow scripts. Engagement-class
   fit unclear (the description suggests business-task automation, not offensive).

4. **User-Agent strip patch not verified at runtime.** Our `mcp-server.py`
   monkey-patches boto3's UA construction at import time. The patch should
   apply to all subsequent boto3 client constructions, but we haven't observed
   an actual CloudTrail event to confirm `awslabs` is absent from the UA field.

5. **Credential refresh on STS expiry.** Temporary STS creds expire (default 1hr).
   With service:true the container persists past that. Vendor's behavior on
   expired creds: returns `ExpiredToken` error to the agent, which must then
   re-acquire and update env via opensploit's envOverrides. Not yet observed.

6. **Rate-limit / throttle behavior under heavy fan-out.** Cross-region `*` +
   batch mode could trigger throttle. Vendor has no built-in retry/backoff
   surfaced in the wrapper output; agent must handle.

7. **Working-dir mount under /session.** Default workdir is /tmp/aws-api-mcp/workdir;
   we documented setting it to /session/aws-work via env, but didn't verify the
   permission/ownership story when /session is bind-mounted from host.

---

## 9. Hand-off

- **Tool:** aws (kind:mcp, awslabs.aws-api-mcp-server v1.3.x via PyPI)
- **Image:** `ghcr.io/silicon-works/mcp-tools-aws:latest` (~347MB)
- **Surface:** 2 default tools (call_aws + suggest_aws_commands). Resources: 0
  documented (FastMCP advertises `subscribe:false, listChanged:false`). Prompts:
  0 documented.
- **NOT a wrapper retirement** — was always vendor MCP wrap. Standardization
  round only: kind:mcp explicit, service:true added, scenarios.md (this file),
  failure_signatures (9), gotchas (10), usage_patterns (7), smoke test.
- **Live verification (this file):** local x86_64 Linux Debian bookworm,
  2026-05-11. 5 manual stdio MCP calls (initialize, tools/list, 3× call_aws
  no-creds/argv/non-aws). Real AWS account integration NOT performed.
- **Known upstream alpha quirks:** see §7. Most notable: isError-false-on-error
  (parse content JSON), default 2-tool surface, suggest_aws_commands OPSEC
  leak, --region * vendor extension, MAX_BATCH_COMMANDS=20.
- **Cross-tool routing:** see_also points at pacu (offensive AWS exploitation
  modules), cloudfox (read-only attack-path correlation), prowler (compliance
  audit), s3scanner (bucket discovery from outside), trufflehog (secret
  scanning in S3 contents).

## Sources

- [awslabs/mcp — aws-api-mcp-server subdir](https://github.com/awslabs/mcp/tree/main/src/aws-api-mcp-server) — vendor source
- [awslabs.aws-api-mcp-server on PyPI](https://pypi.org/project/awslabs.aws-api-mcp-server/) — package
- [AWS Labs MCP overview](https://github.com/awslabs/mcp) — meta-repo (40+ MCP servers)
