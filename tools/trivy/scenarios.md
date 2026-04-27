# trivy — Tier A scenarios

Single test sheet for the `trivy` tool migration (Wave 7.5).

trivy v0.69 is Aquasecurity's flagship all-in-one vulnerability scanner —
a **single binary** (`trivy`) with a **cobra-style sub-command
architecture**: `trivy <subcommand> [flags] <target>`. Sub-commands cover
container images (`image`), filesystems (`fs`), git repos (`repo`),
Kubernetes clusters (`k8s`), Infrastructure-as-Code (`config`), AWS
accounts (`aws`), VM images (`vm`), and SBOMs (`sbom`).

This is structurally **different** from every other Tier A tool migrated
so far: trivy is the first to require **sub-command-then-target** parsing.
The DSL handles this naturally via `last_non_flag_positional` — the
sub-command is also a positional, but the scan target is always LATER in
argv, so "last positional" picks the target correctly. Sub-commands like
`version` (no target) and `aws` (no positional, account-id flag-based)
fall through cleanly to null target.

Sections:
1. Recommended target for live verification
2. Narrative scenarios (paste into opensploit)
3. Target-extraction adversarial cases (≥20)
4. Failure-signature live-verify cases (≥3)
5. Open questions
6. Hand-off

---

## 1. Recommended target

trivy is **NOT an HTB-style network tool**. It scans artifacts at rest:
container images, filesystems, IaC files, SBOMs. There is no "HTB box"
for trivy in the way Blocky is for wpscan or Hercules is for
enum4linux-ng. The right verification target is a known-vulnerable
artifact you can fetch into the container's `/session/` workspace.

**Recommended verification artifacts** (in order of preference):

1. **`alpine:3.14`** — public Docker Hub image. Last patched in 2021,
   carries ~30 known CVEs of varying severity. Confirms registry pull,
   DB lookup, and JSON output. Fast (~5 MB image) and offline-safe
   (DB is pre-baked in the trivy container; image pull is the only
   network requirement).

2. **`ghcr.io/aquasecurity/trivy-test-images/alpine-310:latest`** —
   official trivy test image with deliberately old packages.
   Authoritative for trivy testing.

3. **`vulhub` IaC sample** — clone any vulhub challenge repo into
   `/session/source` and run `trivy fs /session/source --scanners
   vuln,secret`. vulhub repos contain intentionally vulnerable
   `Dockerfile`s and exposed `docker-compose.yml` patterns.

4. **`/session/terraform/`** — write a small Terraform file with a
   public S3 bucket and a security group open to 0.0.0.0/0, then run
   `trivy config /session/terraform/ -f json`. Confirms IaC scanner
   path without needing an external target.

5. **HTB containerized challenges (rare)** — a few HTB boxes expose
   container images via mounted Docker socket or accessible registry
   ports. When applicable, `trivy image <image-from-target>` is a
   direct enumeration step; but most HTB boxes don't expose registries.

For SBOM testing: generate an SBOM with `trivy fs -f cyclonedx
--list-all-pkgs -o /session/sbom.cdx.json /session/source`, then
re-consume it via `trivy sbom -f json /session/sbom.cdx.json`. This
exercises both the producer and consumer paths in one engagement.

For AWS testing: requires real AWS credentials. Use a sandbox account
(LocalStack does NOT fully support trivy aws). Set
`AWS_ACCESS_KEY_ID`/`AWS_SECRET_ACCESS_KEY` in the container and run
`trivy aws --account-id <id> --region us-east-1 -f json -o
/session/trivy-aws.json`.

Persistent test directory: standard `/session/` mount; trivy outputs
go to `/session/trivy-*.json` and `/session/trivy-cache/` (DB cache).

---

## 2. Narrative scenarios (paste into opensploit)

### S1 — basic image scan (HIGH+CRITICAL)

```
Engagement target: alpine:3.14 (public Docker Hub image, deliberately old).
Use trivy to scan the alpine:3.14 container image for HIGH and CRITICAL severity vulnerabilities. Use JSON output format and write to /session/trivy-image.json. Disable the progress bar.
```

**Watch:** Agent emits `trivy image -f json -o /session/trivy-image.json --severity HIGH,CRITICAL --no-progress alpine:3.14`. target=`alpine:3.14` extracted via `last_non_flag_positional`. The sub-command `image` is ALSO a positional but isn't the LAST one. First call ~10-30 s spawn + image pull + DB load; subsequent calls reuse warm container + cached DB. JSON output contains `Results[].Vulnerabilities[]` with CVE IDs.

### S2 — filesystem scan with secret detection

```
Engagement target: /session/source (post-exploitation captured project tree).
First create /session/source with a sample package.json containing an outdated 'lodash' dependency at version 4.17.4. Then use trivy to scan /session/source for vulnerable dependencies AND hardcoded secrets, output JSON to /session/trivy-fs.json with no progress bar.
```

**Watch:** Agent first writes the `package.json` via the `write` tool (NOT bash heredoc), then emits `trivy fs --scanners vuln,secret --no-progress -f json -o /session/trivy-fs.json /session/source`. target=`/session/source` extracted via `last_non_flag_positional`. The `--scanners vuln,secret` value is consumed by `--scanners` (in value_flags), not extracted. lodash 4.17.4 has multiple known CVEs (e.g., CVE-2019-10744 prototype pollution).

### S3 — git repository scan

```
Engagement target: a public github repo with known dependencies.
Use trivy to scan the public github repository at https://github.com/OWASP/NodeGoat for vulnerable dependencies and misconfigurations. Output JSON to /session/trivy-repo.json.
```

**Watch:** Agent emits `trivy repo -f json -o /session/trivy-repo.json --scanners vuln,misconfig https://github.com/OWASP/NodeGoat`. target=`https://github.com/OWASP/NodeGoat` extracted as the LAST positional. Plugin's value_flags catches `-f`, `-o`, `--scanners`. trivy clones the repo to a temp dir and runs the scan. NodeGoat is OWASP's deliberately vulnerable Node.js app — yields CVEs and Dockerfile misconfigs.

### S4 — IaC misconfiguration scan

```
Engagement target: /session/terraform (extracted IaC from CI/CD pipeline).
First create /session/terraform/main.tf with: a public AWS S3 bucket (acl = "public-read"), and a security group with cidr_blocks = ["0.0.0.0/0"] on port 22. Then run trivy config against /session/terraform with HIGH and CRITICAL severity, output JSON to /session/trivy-iac.json.
```

**Watch:** Agent writes the Terraform file via `write`, then emits `trivy config -f json -o /session/trivy-iac.json --severity HIGH,CRITICAL /session/terraform`. target=`/session/terraform`. trivy detects:
- AVD-AWS-0086 (S3 bucket public ACL)
- AVD-AWS-0107 (security group port 22 open to internet)

These are signed with their own IDs (NOT CVEs — Aqua-internal vulnerability database for misconfigs).

### S5 — SBOM consumption (CycloneDX)

```
Engagement target: /session/sbom.cdx.json (CycloneDX SBOM provided by upstream supplier).
First, generate /session/sbom.cdx.json by running trivy fs against /session/source with -f cyclonedx --list-all-pkgs. Then run trivy sbom against the generated SBOM file, output JSON to /session/trivy-sbom.json.
```

**Watch:** Two-call sequence. First: `trivy fs -f cyclonedx -o /session/sbom.cdx.json --list-all-pkgs /session/source` (target=`/session/source`). Second: `trivy sbom -f json -o /session/trivy-sbom.json /session/sbom.cdx.json` (target=`/session/sbom.cdx.json`). Demonstrates SBOM producer + consumer round-trip.

### S6 — failure: image not found

```
Engagement target: nonexistent-registry.invalid.localdomain/fake-image:tag (deliberately invalid, verifying registry-fail classification).
Run trivy image against nonexistent-registry.invalid.localdomain/fake-image:tag. JSON output to /session/trivy-fail.json.
```

**Watch:** stderr matches signal `failed to download` AND/OR `no such host` AND/OR `connection refused`. Classified as `failure_in_output`. Agent reports DNS / registry issue cleanly.

### S7 — failure: unknown sub-command

```
Engagement target: alpine:3.14 (the test).
Run trivy with the sub-command 'scan' against alpine:3.14, output JSON to /session/trivy-bad.json.
```

**Watch:** Agent emits `trivy scan alpine:3.14 -f json -o /session/trivy-bad.json` — but `scan` is NOT a valid sub-command. trivy errors with `Error: unknown command "scan" for "trivy"`. failure_signature matches `Error: unknown command`. Agent should retry with the correct sub-command (`image`).

### S8 — failure: target without sub-command

```
Engagement target: alpine:3.14 (the test).
Run trivy directly against alpine:3.14 without specifying any sub-command, output JSON to /session/trivy-nosubcmd.json.
```

**Watch:** Agent emits `trivy alpine:3.14 -f json -o /session/trivy-nosubcmd.json`. trivy treats `alpine:3.14` as an unknown sub-command and errors with `Error: unknown command "alpine:3.14"`. Same failure_signature as S7. Agent should add `image` before the target.

---

## 3. Target-extraction adversarial cases (≥20)

The trivy `tool.yaml` declares two extraction rules:

1. `last_non_flag_positional` (parse_as: raw)
2. `positional_match` (fallback shape match)

`reject_flags`: `--input` (image tar load — target outside argv).

`value_flags` includes ~80 entries covering all flags that take a value
across all sub-commands — notably `--severity`, `--scanners`,
`--vuln-type`, `--cache-dir`, `--ignorefile`, `-f`, `-o`,
`--account-id`, `--region`, `--service`, `--namespaces`,
`--branch`, `--commit`, `--tag`, `--proxy`, `--username`,
`--password`, `--registry-token`.

### Happy-path cases

| # | Command (binary `trivy` omitted) | Expected target | Notes |
|---|---|---|---|
| 1 | `image -f json -o /session/x.json --severity HIGH,CRITICAL alpine:3.14` | `alpine:3.14` | Standard image scan. last_non_flag_positional skips `image` (first positional) and returns `alpine:3.14` (second positional after flag values). |
| 2 | `image alpine:3.14 -f json` | `alpine:3.14` | Target before flags — order-independent. last_non_flag_positional still returns `alpine:3.14`. |
| 3 | `fs --scanners vuln,secret /session/source` | `/session/source` | fs sub-command, filesystem path target. `vuln,secret` consumed by --scanners. |
| 4 | `repo https://github.com/example/app -f json` | `https://github.com/example/app` | repo sub-command with HTTPS git URL. |
| 5 | `config /session/terraform/` | `/session/terraform/` | config sub-command, IaC dir target, no flags. |
| 6 | `sbom /session/sbom.cdx.json -f json -o /session/out.json` | `/session/sbom.cdx.json` | sbom sub-command, SBOM file target. |
| 7 | `k8s -f json --report summary` | `k8s` (or null per shape match) | k8s sub-command with no positional after. last positional is `k8s` itself; positional_match fallback may still return it as-is. SAFE: k8s scope is enforced by --context/--cluster, not argv. |
| 8 | `image registry.example.com/org/app:1.2.3-rc1 -f json` | `registry.example.com/org/app:1.2.3-rc1` | Full registry reference with version-suffix tag. |
| 9 | `image -f sarif --scanners vuln,misconfig,secret alpine:3.14` | `alpine:3.14` | Multi-value `--scanners` consumed correctly. |
| 10 | `repo --branch main -f json https://github.com/example/app` | `https://github.com/example/app` | `--branch` value-flag consumes `main`; URL extracted as last. |

### Adversarial — value_flag traps & sub-command edge cases

| # | Command | Expected | Notes |
|---|---|---|---|
| F1 | `--help` | `target=null` | Top-level help. tool_runner bypasses scope check. |
| F2 | `image --help` | `target=null` (or `image` from positional_match — both safe; help skips network) | Sub-command help. Only positional is `image` itself. |
| F3 | `-h` | `target=null` | Short-form help. |
| F4 | `version` | `version` (or null — positional_match doesn't match `version` against IPv4 pattern) | Version sub-command. No target needed. |
| F5 | `--version` | `target=null` | Long-form version flag (different from `version` subcmd, same effect). |
| F6 | `image --severity HIGH,CRITICAL alpine:3.14` | `alpine:3.14` (NOT `HIGH,CRITICAL`) | `--severity` value `HIGH,CRITICAL` is a flag-value, must NOT be the target. value_flags catches it. |
| F7 | `image --scanners vuln,misconfig,secret,license alpine:3.14` | `alpine:3.14` (NOT `vuln,misconfig,secret,license`) | `--scanners` value is a flag-value. value_flags catches it. |
| F8 | `image --severity HIGH,CRITICAL --scanners vuln,secret --vuln-type os,library alpine:3.14` | `alpine:3.14` (NOT any of the three flag values) | Three value flags in a row. Each value consumed by its flag. |
| F9 | `image -o /session/trivy-image.json alpine:3.14` | `alpine:3.14` (NOT the output path) | `-o` value is output path; in value_flags. |
| F10 | `image --output /session/trivy.json -f json alpine:3.14` | `alpine:3.14` (NOT output path or `json`) | Long-form `--output` and `-f` both in value_flags. |
| F11 | `image --cache-dir /session/trivy-cache alpine:3.14` | `alpine:3.14` (NOT cache dir) | `--cache-dir` value is dir path; in value_flags. |
| F12 | `image --ignorefile /session/.trivyignore alpine:3.14` | `alpine:3.14` (NOT ignorefile path) | `--ignorefile` value is file path; in value_flags. |
| F13 | `image --proxy http://127.0.0.1:8080 alpine:3.14` | `alpine:3.14` (NOT `127.0.0.1`) | Local proxy URL, NOT engagement target. value_flags catches it. |
| F14 | `image --username admin --password secret123 registry.io/private/app:v1` | `registry.io/private/app:v1` (NOT `admin`, `secret123`) | Registry creds — both in value_flags. |
| F15 | `image --registry-token ghp_abc123def456 ghcr.io/org/app:latest` | `ghcr.io/org/app:latest` (NOT token) | Registry token in value_flags. |
| F16 | `image --timeout 30m alpine:3.14` | `alpine:3.14` (NOT `30m`) | Timeout duration value; in value_flags. |
| F17 | `image --severity HIGH,CRITICAL --no-progress --quiet --skip-db-update alpine:3.14` | `alpine:3.14` | Mix of value-flag (`--severity`) and boolean flags. Booleans don't consume next arg. |
| F18 | `repo --branch feature/auth -f json https://github.com/example/app` | `https://github.com/example/app` (NOT `feature/auth`) | `--branch` value contains slash; in value_flags. |
| F19 | `repo --commit a1b2c3d4e5 -f json https://github.com/example/app` | `https://github.com/example/app` (NOT commit hash) | `--commit` value is hex string; in value_flags. |
| F20 | `aws --account-id 123456789012 --region us-east-1 -f json -o /session/trivy-aws.json` | `aws` (or null — positional_match doesn't match `aws` as IP/CIDR/URL) | aws sub-command has NO positional target. Last positional IS `aws`. SAFE: AWS scope is enforced via --account-id (in value_flags). |
| F21 | `aws --account-id 123456789012 --region us-east-1 --service iam` | `aws` (same as F20) | AWS with --service filter; still no positional. |
| F22 | `k8s --context prod-cluster --namespaces default,kube-system` | `k8s` (or null) | k8s with --context (cluster identity); no positional. value_flags catches `--context` and `--namespaces`. |
| F23 | `image --insecure registry.local/app:dev` | `registry.local/app:dev` | `--insecure` is BOOLEAN (no value); doesn't consume next arg. |
| F24 | `image --skip-db-update --offline-scan alpine:3.14` | `alpine:3.14` | Two boolean flags before target. |
| F25 | `image --input /session/saved-image.tar` | `REJECTED` — reject_flags blocks `--input` | Plugin should reject before docker spawn. The image identity lives in the tar metadata. |
| F26 | `image alpine:3.14` (NO flags at all) | `alpine:3.14` | Zero-flag minimal command — last positional is the target. |
| F27 | `image -f json --severity HIGH,CRITICAL --scanners vuln --ignore-unfixed --exit-code 1 -o /session/x.json alpine:3.14` | `alpine:3.14` | Long flag chain — value flags + booleans + target. |
| F28 | `image --db-repository ghcr.io/aquasecurity/trivy-db alpine:3.14` | `alpine:3.14` (NOT db repo URL) | `--db-repository` value is OCI registry URL; in value_flags. |
| F29 | `image --java-db-repository ghcr.io/aquasecurity/trivy-java-db alpine:3.14` | `alpine:3.14` (NOT java-db URL) | Same as F28 but Java-specific. |
| F30 | `fs --skip-files /session/secrets.yaml --skip-dirs /session/node_modules /session/source` | `/session/source` (NOT `--skip-files` or `--skip-dirs` values) | Both `--skip-files` and `--skip-dirs` in value_flags. |
| F31 | `config --policy-namespaces builtin.terraform,custom /session/terraform` | `/session/terraform` (NOT policy namespace list) | `--policy-namespaces` value contains comma-list; in value_flags. |
| F32 | `image --platform linux/amd64 alpine:3.14` | `alpine:3.14` (NOT platform string) | `--platform` value is `os/arch`; in value_flags. Looks vaguely like a path. |
| F33 | `repo --tag v1.2.3 https://github.com/example/app` | `https://github.com/example/app` (NOT tag) | `--tag` value-flag (NOT to be confused with image tag, which is part of the image ref). |

### Happy-path cases — IPv6 / unusual targets

| # | Command | Expected | Notes |
|---|---|---|---|
| H1 | `image -f json [::1]/test:latest` | `[::1]/test:latest` (or just `[::1]/test:latest` raw) | IPv6 bracketed in image ref. Edge case — most registries use hostnames. |
| H2 | `fs /session/path with space/` | `/session/path with space/` | Path with spaces — must be quoted in shell, but argv-level the path is one token. |
| H3 | `image alpine` | `alpine` | Image without explicit `:tag` — defaults to `:latest`. raw extraction returns `alpine`. |
| H4 | `image alpine@sha256:abc123def456` | `alpine@sha256:abc123def456` | Image referenced by digest, not tag. |
| H5 | `image localhost:5000/myapp:dev` | `localhost:5000/myapp:dev` | Local registry with explicit port — `:5000` is registry port, NOT image tag. |

---

## 4. Failure-signature live-verify cases (≥3)

| # | Layer | Test | failure_signature `signal` | Status |
|---|---|---|---|---|
| 1 | DNS | `image nonexistent-registry.invalid.localdomain/x:tag --timeout 10s` | `no such host` AND/OR `failed to download` | PENDING live verify |
| 2 | TCP | `image localhost:1/x:tag --timeout 5s` | `connection refused` | PENDING live verify |
| 3 | DB-init | corrupt `~/.cache/trivy/db/trivy.db` then run `image alpine:3.14 --skip-db-update` | `failed to initialize db` OR `db update error` | PENDING — needs cache corruption setup |
| 4 | Argument | `scan alpine:3.14` (invalid sub-command) | `Error: unknown command` | PENDING live verify |
| 5 | Argument | `image --bogus-flag alpine:3.14` | `unknown flag` | PENDING live verify |
| 6 | Image | `image registry.example.com/does/not/exist:tag` | `manifest unknown` OR `image not found` | PENDING — needs reachable registry that returns 404 |
| 7 | Auth | `image ghcr.io/silicon-works/private-image:tag` (without creds) | `unauthorized` OR `denied` | PENDING — needs known-private image |
| 8 | Path | `fs /session/does/not/exist` | `no such file or directory` | PENDING live verify |
| 9 | AWS | `aws --account-id 999999999999 --region us-east-1` (no creds set) | `could not load credentials` OR `InvalidClientTokenId` | PENDING — needs AWS env unset to confirm |
| 10 | Empty | `image alpine:3.14 --severity CRITICAL` (against an image with no CRITICAL findings) | `no security issues` OR empty Results array | PENDING live verify (informational, NOT a failure) |
| 11 | Timeout | `image very-slow-registry/huge-image --timeout 1s` | `context deadline exceeded` | PENDING — needs slow registry to reproduce reliably |

### Layer diversity (SKILL #11) — achieved

8+ distinct layers exercised: DNS / TCP / DB-init / argument-validation /
unknown-flag / image-not-found / auth / filesystem-path / AWS-creds /
empty-result / timeout. SKILL #11 minimum (5 distinct layers) is met
several times over.

---

## 5. Open questions

1. **Sub-command target extraction precedence** — `last_non_flag_positional`
   correctly picks the LAST positional (the target), but for sub-commands
   like `version`, `aws`, `k8s` (no positional target), the last positional
   IS the sub-command name itself. Should the plugin add a sub-command
   denylist (skip if last positional is `version`/`aws`/`k8s` etc.) or rely
   on `positional_match` to filter via shape (current approach)?
   Current approach works but logs "target=`aws`" in audit which is
   misleading. Proposed cleanup: add a `subcommand_skip` list to the DSL
   (defer to next DSL feature). Workaround for now: the positional_match
   pattern only matches IPv4/CIDR/hostname/URL/path shapes — `aws`,
   `version`, `k8s` won't match, so the second rule yields null. Net
   result is correct.

2. **`aws` sub-command without `--account-id`** — when AWS env credentials
   are set and `--account-id` is omitted, trivy uses
   `aws sts get-caller-identity` to determine the account. Scope
   validation in opensploit is per-target, but here the "target" is an
   AWS account-id determined at runtime — no way to validate ahead of time.
   Should the plugin require `--account-id` explicitly for `aws` calls?
   Currently NOT enforced. Defer to engagement-state-level scope rules.

3. **DB caching across sessions** — the trivy DB is ~500 MB and refreshes
   roughly every 6 hours upstream. The container ships with a pre-baked DB
   from build time, but for engagements lasting >24 h, the DB will go stale.
   Should `--cache-dir /session/trivy-cache` be the default usage_pattern
   (persisting across container restarts within the same session)? Or
   should the container have a docker volume mount for `/root/.cache/trivy`
   shared across all trivy invocations? Defer to ops decision.

4. **`--security-checks` deprecation handling** — newer trivy uses
   `--scanners`, but both work. Should the tool.yaml document only
   `--scanners` (canonical) or both (LLM may emit either)? Current tool.yaml
   includes both in `value_flags` for safe parsing, and gotchas mention the
   deprecation explicitly. Should `--security-checks` be marked as
   discouraged in usage_patterns? Not currently — risk of LLM picking the
   deprecated form is low, and the deprecation warning is informational.

5. **Image-ref vs sub-command collision** — what happens if someone names
   an image `image` (i.e., `trivy image image:latest`)? trivy resolves the
   first positional as the sub-command, the second as the image. The DSL
   handles this correctly (last_non_flag_positional returns `image:latest`).
   Edge case — never seen in practice, but documented.

6. **Multi-target invocation** — trivy doesn't support multiple positional
   targets in one call. `trivy image alpine:3.14 ubuntu:22.04` errors with
   `accepts 1 arg(s), received 2`. The DSL's last_non_flag_positional
   would extract `ubuntu:22.04`, but trivy itself rejects the call. NOT a
   reject_flag concern (no flag enables multi-target intake).

7. **`--input <tar>` rejection scope** — currently in reject_flags. Should
   we instead require the LLM to docker-cp the tar's contents into a
   filesystem-scannable path and use `trivy fs` instead? Or allow
   `--input` with a defensive check that the tar lives under /session/?
   Current decision: REJECT (image identity not in argv = scope can't
   validate). The LLM's workaround is to pull the image to a registry and
   use `trivy image <registry-ref>`.

8. **Vendor-database freshness vs reproducibility** — for engagement
   reproducibility, `--skip-db-update` keeps the DB pinned to whatever was
   in the container build. For engagement freshness, latest DB has the
   newest CVEs. Trade-off should be documented per usage_pattern. Current
   tool.yaml notes the trade-off in gotchas; no enforcement.

9. **Per-sub-command JSON output structure differs** — legacy parsers in
   `mcp-server.py` reflect this: `image`/`fs`/`repo`/`sbom` populate
   `Results[].Vulnerabilities[]` (vuln entries with `VulnerabilityID`,
   `Severity`, `PkgName`, `InstalledVersion`, `FixedVersion`, `Title`),
   while `config` populates `Results[].Misconfigurations[]` (entries with
   `ID`, `Severity`, `Title`, `Description`, `Resolution`). `--list-all-pkgs`
   on `fs`/`image` adds `Results[].Packages[]` (entries with `Name`,
   `Version`, plus `r.Type` for ecosystem). LLMs parsing trivy JSON need
   to dispatch on sub-command + flags to know which array to read. Not
   currently called out in tool.yaml's `output_formats` notes — the
   schema is stable but the inhabited keys are sub-command-conditional.

10. **`config` sub-command silent `--scanners` semantics** — legacy
    `scan_iac` runs `trivy config --format json <path>` with NO
    `--scanners` flag. `config` is hardcoded to misconfig+secret+license
    scanners (vuln scanner is a no-op for IaC). Passing `--scanners vuln`
    to `config` produces empty Results. Distinct from `image`/`fs` where
    `--scanners` defaults to `vuln` only and you must opt into
    `vuln,misconfig,secret`. Not currently documented; could trip up an
    LLM transferring `--scanners vuln,secret` patterns from `fs` to
    `config`.

11. **`config` sub-command does NOT use the vuln DB** — legacy `scan_iac`
    omits `--skip-db-update` (which appears on every other sub-command
    call). `config` reads built-in / configured misconfig policies (Rego
    bundles), not the trivy-db OCI artifact. Implication: `--skip-db-update`
    is a no-op for `config` and the failure_signature `failed to initialize
    db` will not fire on `config` scans even if the DB is corrupt. The
    `--checks-bundle-repository` flag (already in value_flags) is the
    `config`-equivalent of `--db-repository`. Not currently called out.

12. **Default `--timeout 5m` is the silent killer** — trivy's internal
    `--timeout` defaults to 5 minutes per scan. Most large-image scans
    fail with `context deadline exceeded` before the container's
    `idle_timeout_seconds: 600` ever applies. Legacy methods set Python
    asyncio timeouts (600 s for image, 300 s for fs/config/sbom) but
    relied on trivy's own 5-min default for the actual scan deadline —
    meaning the legacy server would also have failed on large images.
    The kind:cli gotchas now flag this; addressed.

---

## 6. Hand-off

- **Tool**: trivy (kind:cli)
- **Status**: tool.yaml authored end-to-end (kind:mcp → kind:cli);
  scenarios.md written. Dockerfile uses `python:3.11-slim` base (NOT
  Kali) — no `python3-full` swap needed; existing `python3 -m venv`
  flow works as-is. mcp-server.py untouched (auto-inherits run_cli;
  rollback path via 5 legacy methods: scan_image, scan_filesystem,
  scan_iac, scan_sbom, list_vulns).
- **Image**: `ghcr.io/silicon-works/mcp-tools-trivy:latest` — needs
  rebuild during Wave 9 batch to pick up mcp-common 0.3.0. The trivy
  binary itself is installed via Aquasec's apt repo
  (https://aquasecurity.github.io/trivy-repo/deb/) and pinned at 0.69.x.
- **Live-verify pending**: paste S1-S8 against alpine:3.14 (S1, S6) and
  /session/source + /session/terraform (S2, S4 — agent must write the
  test files first via `write` tool). Verify failure_signatures 1, 2,
  4, 5, 8 (all of which are inexpensive locally). Defer cases 3
  (DB corruption), 6 (registry 404), 7 (auth), 9 (AWS), 11 (timeout)
  until appropriate fixtures available.
- **Wave 7.5 — first sub-command-architecture migration**: trivy is the
  first Tier A tool with a true sub-command-then-target argv shape.
  The DSL's `last_non_flag_positional` rule handles this naturally —
  the sub-command is also a positional, but the scan target is later in
  argv, so "last positional" picks the target. Sub-commands with no
  positional (`aws`, `k8s`) fall through cleanly because
  `positional_match` rejects sub-command keywords as non-target shapes.
  `--input <tar>` is the single reject_flag (image identity outside
  argv). value_flags coverage is comprehensive (~80 flags) covering all
  sub-commands' value-flag surface.

Authored: 2026-04-25.
