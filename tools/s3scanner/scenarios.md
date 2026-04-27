# s3scanner — Tier A scenarios

Single test sheet for the `s3scanner` tool migration (Wave 7.8).

s3scanner is **sa7mon/S3Scanner v3** — the **Go port** of the original
Python sa7mon/S3Scanner. Confirmed via image inspection
(`docker run ... s3scanner --help`) on 2026-04-25. Single binary
(`s3scanner`) at `/usr/bin/s3scanner` in the Kali apt build.

The v3 Go rewrite has a **simpler flag set** than the v2 Python predecessor
(many v2 flags were dropped: `-output-file`, `-output-format`, `-quiet`,
`-region-list`, `-aws-id`, `-aws-secret`, `-write-test`, `-permission-test`,
`-include-empty` — none of those exist in v3). v3 uses **Go's flag package**
with **single-dash flags** (`-bucket=value` or `-bucket value`).

The full v3 flag set (10 flags total, verified live):

- INPUT (1 required): `-bucket`, `-bucket-file`, `-mq`
- OUTPUT: `-db`, `-json`
- OPTIONS: `-enumerate`, `-provider`, `-threads`
- DEBUG: `-verbose`, `-version`

Argv shape:

```
s3scanner [options] -bucket <name>
```

There is **NO positional target** — every invocation requires one of the
INPUT flags. The OpenSploit migration uses `-bucket` exclusively;
`-bucket-file` (multi-target file), `-mq` (multi-target via RabbitMQ), and
`-db` (Postgres results sink) are **reject_flags**.

The DSL handles target extraction via a single `flag_value` rule for
`-bucket` (parse_as: raw). No positional fallback needed (no positional
form exists).

Sections:
1. Recommended target for live verification
2. Narrative scenarios (paste into opensploit)
3. Target-extraction adversarial cases (≥20)
4. Failure-signature live-verify cases (≥3)
5. Open questions
6. Hand-off

---

## 1. Recommended target

s3scanner is **NOT an HTB-style network tool**. It probes AWS / GCP /
DigitalOcean / Dreamhost / Linode object-storage endpoints. There is no
"HTB box" for s3scanner the way Blocky is for wpscan — HTB rarely exposes
S3 buckets as part of the engagement scope. The right verification target
is a **public test bucket** or a **self-hosted MinIO instance** in
`/session/`.

**Recommended verification artifacts** (in order of preference):

1. **`flaws.cloud`** — well-known intentionally-public AWS S3 bucket
   from the FlAWS challenge by Scott Piper. Persists since ~2017 and is
   maintained by Summit Route as a S3-misconfig training resource.
   Authoritative for s3scanner testing. Run as:
   `s3scanner -bucket flaws.cloud -enumerate -json`. Expected output:
   `exists=1, perm_all_users_read=1, num_objects=7` (or whatever the
   challenge currently exposes — content evolves slightly over time).

2. **`commoncrawl-us-west-2`** — Common Crawl's public S3 bucket. Massive
   (petabyte-scale) but listable. Use WITHOUT `-enumerate` (the listing
   would never finish). Run as: `s3scanner -bucket commoncrawl-us-west-2
   -json`. Expected: `exists=1, perm_all_users_read=1` (public).

3. **`s3.amazonaws.com`** — the literal AWS S3 endpoint hostname is NOT a
   valid bucket name (it has a dot AND is reserved). Use as a
   sanity check that s3scanner correctly rejects invalid names —
   expected output: `level=info msg="invalid | s3.amazonaws.com"`.

4. **`nonexistent-bucket-xyz-9999999`** — random unlikely name. Verifies
   the `exists=0` path. No network/auth concerns.

5. **A self-hosted MinIO instance** — for offline testing without internet
   access. Mount a config.yml at `/session/.s3scanner/config.yml`
   defining `custom.endpoint: http://minio:9000` and run with
   `-provider custom`. More setup than the public buckets above; usually
   not worth it unless the engagement requires air-gapped operation.

For brute-force testing: build a small wordlist of known company-name
mutations (`acme-backup`, `acme-dev`, `acme-prod`, etc.) and emit one
`-bucket=<name>` call per name. Do NOT use `-bucket-file` (REJECTED by
the DSL because it shifts targets outside argv).

For authenticated AWS access (your own bucket): s3scanner v3 does NOT
support auth — use the `aws` tool for authenticated S3 operations. v3
only does anonymous probes.

Persistent test directory: standard `/session/` mount; s3scanner NDJSON
output should be redirected via shell to `/session/buckets.ndjson`
(no `-o` flag — see Gotchas).

---

## 2. Narrative scenarios (paste into opensploit)

### S1 — single bucket scan (verified-public, fast existence + ACL probe)

```
Engagement target: flaws.cloud (a public test S3 bucket from the FlAWS
challenge). Use s3scanner to confirm the bucket exists and probe its
anonymous ACL permissions. JSON output. Skip object enumeration on this
first pass — we only want existence + ACL.
```

**Watch:** Agent emits `s3scanner -bucket flaws.cloud -json`.
target=`flaws.cloud` extracted via `flag_value` rule for `-bucket`.
Expected output: one NDJSON line with `bucket.exists=1`,
`bucket.perm_all_users_read=1`, and other perm fields (likely 2=unknown
for write perms on an anonymous probe). ~1-2s runtime.

### S2 — single bucket with object enumeration

```
Engagement target: flaws.cloud (the FlAWS public bucket).
Now enumerate the bucket's objects (after S1 confirmed perm_all_users_read=1).
JSON output.
```

**Watch:** Agent emits `s3scanner -bucket flaws.cloud -enumerate -json`.
target=`flaws.cloud` extracted via `flag_value` rule for `-bucket`.
`-enumerate` triggers ListObjects API pagination. Output JSON includes
`bucket.objects: [{key, size}, ...]`. flaws.cloud has ~7 objects
(hint1.html, hint2.html, hint3.html, index.html, logo.png, robots.txt,
secret-dd02c7c.html or similar). ~3-5s runtime.

### S3 — non-AWS provider scan (DigitalOcean Spaces)

```
Engagement target: a DigitalOcean Spaces bucket named "test-do-public"
that we discovered via subdomain enumeration. Use s3scanner to probe its
existence and ACL. JSON output.
```

**Watch:** Agent emits `s3scanner -bucket test-do-public -provider digitalocean
-json`. target=`test-do-public` extracted via `flag_value` rule for `-bucket`.
`-provider digitalocean` routes to the DO Spaces endpoint. Output schema
is identical to AWS S3 (same JSON shape, different backend). DO rate-limits
harder than AWS — keep `-threads` low (default 4 is fine for single-bucket).

### S4 — quick existence check on a likely-nonexistent name

```
Engagement target: nonexistent-bucket-test-12345 (unlikely name, used
to verify the s3scanner exists=0 path). JSON output.
```

**Watch:** Agent emits `s3scanner -bucket nonexistent-bucket-test-12345 -json`.
target=`nonexistent-bucket-test-12345` extracted via `flag_value` rule.
Expected output: one NDJSON line with `bucket.exists=0`,
`bucket.region=""`, all perm fields = 2 (unknown — the bucket doesn't
exist so ACL is moot). Exit code 0 (NOT a tool error — informational).

### S5 — invalid bucket name (validation path)

```
Engagement target: Inv@l!d-Bucket (literally invalid per S3 naming rules).
Use s3scanner to demonstrate the validation path. JSON output.
```

**Watch:** Agent emits `s3scanner -bucket "Inv@l!d-Bucket" -json`. The name
violates S3 naming rules (uppercase + special chars). Expected output:
`{"level":"info","msg":"invalid | Inv@l!d-Bucket","time":"..."}`. NOT a
tool error — exit code 0. Confirms s3scanner skips invalid names without
crashing the run.

### S6 — failure: missing required input flag

```
Engagement target: any (the test).
Run s3scanner with NO input flag (no -bucket, no -bucket-file, no -mq).
JSON output.
```

**Watch:** Agent emits `s3scanner -json` (or `s3scanner` with no args).
s3scanner errors with `time="..." level=error msg="exactly one of: -bucket,
-bucket-file, -mq required"`. failure_signature matches `exactly one of:
-bucket, -bucket-file, -mq required`. Agent should add `-bucket=<name>`
and retry. Non-zero exit code.

### S7 — failure: unknown flag (LLM emits double-dash)

```
Engagement target: flaws.cloud (the FlAWS bucket).
Run s3scanner with the POSIX-style --bucket flag (LLM trained on POSIX
double-dash conventions might emit this). JSON output.
```

**Watch:** Agent emits `s3scanner --bucket=flaws.cloud -json`. Go's flag
package rejects it: `flag provided but not defined: --bucket=flaws.cloud`.
failure_signature matches `flag provided but not defined`. Agent should
correct to single-dash `-bucket=flaws.cloud` and retry. Non-zero exit.

### S8 — failure: unknown provider

```
Engagement target: flaws.cloud.
Run s3scanner with -provider invalidcloud (a typo / nonexistent provider
name). JSON output.
```

**Watch:** Agent emits `s3scanner -bucket flaws.cloud -provider invalidcloud
-json`. s3scanner errors with `level=error msg="unknown provider: invalidcloud"`.
failure_signature matches `unknown provider`. Agent should fix to
`-provider aws|gcp|digitalocean|dreamhost|linode|custom` and retry.

### S9 — failure: -bucket-file rejected by plugin (REJECT_FLAG)

```
Engagement target: a wordlist file at /session/buckets.txt with 100 bucket
name guesses. Use s3scanner -bucket-file to brute-force them.
```

**Watch:** Agent emits `s3scanner -bucket-file /session/buckets.txt -json`.
The plugin's reject_flags pipeline blocks `-bucket-file` BEFORE it reaches
the binary — rejection reason: "Multi-target file — bucket names live in
the file, scope validator can't reach them". Agent should iterate over
the wordlist at the orchestrator level and emit one `-bucket=<name>` call
per target. The audit log captures each target cleanly.

### S10 — failure: network unreachable (air-gapped container)

```
Engagement target: flaws.cloud (but the container is air-gapped — outbound
network is blocked). JSON output.
```

**Watch:** Agent emits `s3scanner -bucket flaws.cloud -json` from a
network-isolated container (`docker run --network none`). s3scanner errors
with a long message containing `dial tcp: lookup ... on ...:53: dial udp
...:53: connect: network is unreachable` AND `exceeded maximum number of
attempts`. failure_signature matches `network is unreachable` AND
`exceeded maximum number of attempts`. Agent should escalate to user
(network policy issue) — no retry will help.

---

## 3. Target-extraction adversarial cases (≥20)

The s3scanner `tool.yaml` declares 1 extraction rule:

1. `flag_value` for `-bucket` (parse_as: raw)

`reject_flags`: `-bucket-file`, `-mq`, `-db` (all shift target / output
outside argv).

`value_flags` includes 10 entries covering all v3 flags: `-bucket`,
`-bucket-file`, `-provider`, `-threads`, `-json`, `-enumerate`, `-mq`,
`-db`, `-verbose`, `-version`. Single-dash form (Go's flag package).

There is NO positional target (s3scanner v3 has no positional argv shape).

### Happy-path cases

| # | Command (binary `s3scanner` omitted) | Expected target | Notes |
|---|---|---|---|
| 1 | `-bucket flaws.cloud -json` | `flaws.cloud` | Standard scan. flag_value rule for `-bucket` fires. Space-form: `-bucket <value>`. |
| 2 | `-bucket=flaws.cloud -json` | `flaws.cloud` | Same as #1 but equals-form: `-bucket=<value>`. flag_value rule must handle both. |
| 3 | `-bucket flaws.cloud -enumerate -json` | `flaws.cloud` | With enumeration. The `-enumerate` boolean doesn't consume next arg. |
| 4 | `-bucket flaws.cloud -provider gcp -json` | `flaws.cloud` | With provider override. `-provider gcp` is a value_flag — `gcp` consumed, target unaffected. |
| 5 | `-bucket flaws.cloud -threads 16 -json` | `flaws.cloud` | With thread tuning. `-threads 16` value consumed. |
| 6 | `-bucket flaws.cloud -threads=16 -json` | `flaws.cloud` | Equals-form for value flag. Same precedence. |
| 7 | `-bucket=my-bucket-with-dots.example.com -json` | `my-bucket-with-dots.example.com` | Bucket name with dots (legacy AWS naming style). Raw extraction. |
| 8 | `-bucket=my-bucket -enumerate -threads 8 -provider digitalocean -verbose -json` | `my-bucket` | Long flag chain. All value_flags consume their values; flag_value for `-bucket` extracts the target. |
| 9 | `-json -bucket flaws.cloud -enumerate` | `flaws.cloud` | Flag order shuffled — booleans before `-bucket`. flag_value rule still finds it. |
| 10 | `-enumerate -provider aws -threads 4 -bucket=flaws.cloud -json` | `flaws.cloud` | `-bucket` appears AFTER many other flags. flag_value rule walks the whole argv. |

### Adversarial — value_flag traps & rejected-flag handling

| # | Command | Expected | Notes |
|---|---|---|---|
| F1 | `--help` | `target=null` | Top-level help. tool_runner bypasses scope check. NOTE: Go's flag package treats `--help` and `-h` and `-help` interchangeably for the help intent. |
| F2 | `-h` | `target=null` | Short-form help. |
| F3 | `--version` | `target=null` | Long-form version flag (note: actual flag is `-version`, but tool_runner bypasses). |
| F4 | `-version` | `target=null` | Single-dash version flag (the canonical form). |
| F5 | `-bucket flaws.cloud -provider aws -json` | `flaws.cloud` (NOT `aws`) | `-provider` value `aws` is a flag-value, must NOT be the target. value_flags catches it. |
| F6 | `-bucket flaws.cloud -threads 32 -json` | `flaws.cloud` (NOT `32`) | `-threads` value `32` is numeric; in value_flags. CRITICAL — `32` could otherwise be interpreted as a positional in some edge cases. |
| F7 | `-bucket flaws.cloud -provider digitalocean -threads 8 -enumerate -verbose -json` | `flaws.cloud` (NOT `digitalocean` / `8`) | All value flags (`-provider`, `-threads`) consume their values; booleans (`-enumerate`, `-verbose`, `-json`) don't consume args. |
| F8 | `-bucket-file /session/buckets.txt -json` | REJECT (no extraction; `-bucket-file` is a reject_flag) | The plugin's reject_flags pipeline blocks the call BEFORE extraction. Engagement audit captures the rejection reason. |
| F9 | `-mq -json` | REJECT (`-mq` is a reject_flag) | Multi-target via RabbitMQ — scope validator can't see the bucket names. Plugin blocks. |
| F10 | `-db -bucket flaws.cloud -json` | REJECT (`-db` is a reject_flag) | Side-channel results sink (Postgres) bypasses audit-logged stdout. Plugin blocks. NOTE: even though `-bucket` is set, `-db` triggers the rejection regardless. |
| F11 | `-bucket flaws.cloud -bucket-file /session/buckets.txt -json` | REJECT (mixed input modes — `-bucket-file` triggers reject) | Even when `-bucket` is also set, the presence of `-bucket-file` triggers the reject_flag pipeline. Defense in depth. |
| F12 | `-bucket=s3://flaws.cloud -json` | `s3://flaws.cloud` (literal) | `s3://` prefix is captured as-is by `parse_as: raw`. NOTE: this will fail at the s3scanner binary level (invalid bucket name) but extraction returns the literal. The shape is documented; LLMs may emit it. |
| F13 | `-bucket=flaws.cloud/some/path -json` | `flaws.cloud/some/path` (literal) | Path inside a bucket — captured as-is. Will fail at the s3scanner binary level. |
| F14 | `-bucket=Inv@l!d-Bucket -json` | `Inv@l!d-Bucket` (literal — invalid) | Invalid S3 name (uppercase + special chars). Extracted as-is; s3scanner emits `level=info msg="invalid"` at run time but extraction succeeds. |
| F15 | `-bucket "name with space" -json` | `name with space` | Bucket name with space (theoretically invalid for S3 but not for parse_as: raw). Quoted in shell, single token at argv level. |
| F16 | `-bucket flaws.cloud` (no other flags) | `flaws.cloud` | Zero-other-flag minimal command — flag_value rule fires. |
| F17 | `-bucket flaws.cloud -verbose` | `flaws.cloud` | `-verbose` is a boolean — doesn't consume next arg. |
| F18 | `-bucket=flaws.cloud -enumerate -json -verbose -threads=8 -provider=aws` | `flaws.cloud` | Equals-form throughout. flag_value rule must handle equals-form for `-bucket`. value_flags handles equals-form for `-threads` / `-provider`. |
| F19 | `-bucket flaws.cloud -threads=16 -provider digitalocean -json` | `flaws.cloud` | Mixed equals + space form across different flags. |
| F20 | `-bucket flaws.cloud -json -bucket second-bucket` | `second-bucket` (LAST -bucket wins) | Duplicate `-bucket` flag — Go's flag package keeps the LAST value. The DSL's flag_value rule should match Go's behavior (or document the divergence). RECOMMEND: flag_value rule returns the LAST occurrence's value to match Go binary semantics. |
| F21 | `-bucket flaws.cloud -enumerate -bucket=second -json` | `second` (LAST `-bucket` wins) | Same edge case as F20 with mixed equals/space forms. |
| F22 | `-bucket --json` | `--json` (literal!) | EDGE CASE: `-bucket` consumes the NEXT token as its value, even if that token starts with `-`. So `-bucket --json` extracts `--json` as the bucket name. This is Go's flag-package behavior (mostly POSIX-incompatible). LLMs may emit this if confused. The extracted name will fail at run time as an invalid bucket name. |
| F23 | `-enumerate -bucket flaws.cloud` | `flaws.cloud` | Boolean flag BEFORE `-bucket`. `-enumerate` doesn't consume next arg; `-bucket` consumes `flaws.cloud`. |
| F24 | `-threads 8 -bucket flaws.cloud -json` | `flaws.cloud` | Value flag with numeric value before `-bucket`. `-threads` consumes `8`; `-bucket` consumes `flaws.cloud`. |
| F25 | `-provider aws -bucket=flaws.cloud -json` | `flaws.cloud` | `-provider` value `aws` consumed; `-bucket=flaws.cloud` extracts the target. |
| F26 | `-bucket "" -json` | `""` (empty string) | Empty bucket name. Extraction returns empty; s3scanner binary will likely error. EDGE CASE: scope validator should reject empty target. |
| F27 | `-bucket=` (no value) | `` (empty — equals-form with no value) | Equals-form with empty RHS. Same as F26. |
| F28 | `-version -bucket flaws.cloud` | `flaws.cloud` (or null if `-version` short-circuits) | `-version` causes immediate exit, never running the scan. tool_runner can either extract `flaws.cloud` (per the rule) OR treat `-version` as a help-class flag and skip extraction. Document: extraction proceeds; the binary exits before the extracted target is used. |

### Happy-path cases — IPv6 / unusual targets

| # | Command | Expected | Notes |
|---|---|---|---|
| H1 | `-bucket=192.168.1.1 -json` | `192.168.1.1` | An IP-like name — bucket names CAN look like IPs but S3 forbids it (validation). Raw extraction; s3scanner will emit `level=info msg="invalid"`. |
| H2 | `-bucket=2001-db8-1234.example.com -json` | `2001-db8-1234.example.com` | An IPv6-shape-but-actually-a-domain name. Raw extraction. |
| H3 | `-bucket=mc.example.org -json` | `mc.example.org` | Subdomain-style bucket name. Raw extraction. |
| H4 | `-bucket=a-very-long-bucket-name-with-many-hyphens-up-to-63-chars-x -json` | `a-very-long-bucket-name-with-many-hyphens-up-to-63-chars-x` | Max-length valid S3 name. Raw extraction. |
| H5 | `-bucket=ab -json` | `ab` (too short — invalid) | 2-char name, below S3 minimum (3 chars). Extraction returns; binary emits `level=info msg="invalid"`. |

---

## 4. Failure-signature live-verify cases (≥3)

| # | Layer | Test | failure_signature `signal` | Status |
|---|---|---|---|---|
| 1 | Argument | `s3scanner -json` (no input flag) | `exactly one of: -bucket, -bucket-file, -mq required` | VERIFIED live (output exact match) |
| 2 | Argument | `s3scanner --bucket=flaws.cloud -json` (POSIX double-dash) | `flag provided but not defined` | VERIFIED live |
| 3 | Argument | `s3scanner -bogus-flag -bucket flaws.cloud` | `flag provided but not defined` | VERIFIED live |
| 4 | Provider | `s3scanner -bucket flaws.cloud -provider invalidcloud -json` | `unknown provider` | VERIFIED live |
| 5 | Config | `s3scanner -db -bucket flaws.cloud` | `config file not found` | VERIFIED live (`-db` requires config; `-mq` and `-provider custom` likewise) |
| 6 | File | `s3scanner -bucket-file /nonexistent/file.txt -json` | `open` AND `no such file or directory` | VERIFIED live (NOTE: `-bucket-file` is REJECTED by the plugin — this signature only fires if reject_flags pipeline is bypassed) |
| 7 | Network/DNS | `s3scanner -bucket test-bucket -json` (with `--network none` container) | `network is unreachable` AND `exceeded maximum number of attempts` | VERIFIED live (network-namespace isolation reproduces) |
| 8 | Validation | `s3scanner -bucket "Inv@l!d-Bucket" -json` | `invalid` (informational, level=info, NOT a tool error) | VERIFIED live |
| 9 | Existence | `s3scanner -bucket nonexistent-bucket-xyz-9999999 -json` | `exists=0` in JSON output (NOT a tool error — exit code 0) | VERIFIED live |
| 10 | Network/Throttle | High-`-threads` brute-force against AWS S3 | `Throttling` OR `503 Slow Down` | PENDING live verify (needs sustained burst) |

### Layer diversity (SKILL #11) — achieved

7 distinct layers exercised: argument (3 distinct sub-cases) / provider /
config / file / network-DNS / validation / existence / throttle. SKILL #11
minimum (5 distinct layers) is met.

---

## 5. Open questions

1. **AWS credential management** — s3scanner v3 has NO env-var or argv-form
   AWS auth (unlike v2 Python which had `-aws-id` / `-aws-secret`). For
   authenticated probing of YOUR OWN buckets, the LLM should be steered to
   the `aws` tool. Should the tool.yaml documentation more loudly state
   "v3 is anonymous-only — for auth use aws"? Currently in gotchas; could
   be promoted to a dedicated usage_pattern. Decision deferred — LLMs that
   try `-aws-id` will hit the `flag provided but not defined` failure
   signature and self-correct.

2. **`-bucket-file` reject_flag rationale** — multi-target file means the
   scope validator can't reach the actual bucket names being probed. The
   alternative would be: (a) plugin reads the file and validates each name
   against engagement scope, then strips the flag and emits one `-bucket`
   call per target. This is more work for the plugin (file IO + per-call
   audit log multiplication). Currently rejected outright — let the
   orchestrator iterate. Decision: reject_flag is correct for the audit
   model. Could revisit if engagement-scale bucket-list scanning becomes
   common.

3. **Multi-region defaults** — s3scanner v3 auto-detects bucket region via
   HEAD (no `-region` flag exists). For very specific regional probing
   (e.g., test a bucket only in `us-west-2`), there's no argv-level
   control — you'd have to use `-provider custom` with a config.yml
   defining the endpoint. Should usage_patterns mention this gap?
   Currently NOT mentioned. The use case is rare (most engagements don't
   need region-specific scoping); leaving out for now.

4. **`-bucket=` empty-value handling** — extraction returns empty string;
   s3scanner binary will emit `invalid` (info-level). Plugin scope
   validator should reject empty target before reaching the binary.
   Currently relies on s3scanner's invalid-name validation as the
   backstop — could be promoted to a plugin-level pre-check. Defer to
   plugin policy.

5. **Duplicate `-bucket` flag (F20/F21)** — Go's flag package keeps the
   LAST occurrence. The DSL's flag_value rule should match this (return
   last). Audit log should reflect the actual binary-target (last
   `-bucket` value), not the first. Currently UNCONFIRMED whether the DSL
   matches Go's last-wins semantics — defer to plugin-side test coverage.

6. **`-version` short-circuit interaction with target_extraction** —
   `-version` causes immediate exit before the scan. If `-version` is
   set AND `-bucket=<name>` is set, the binary prints version and exits
   without using the bucket. Should the DSL detect `-version` as a
   help-class flag and skip extraction? Currently: extraction proceeds.
   Document: the extracted target is captured in audit log even though
   the binary never used it. Consistency wins over pedantry — the LLM
   wouldn't emit `-version` and `-bucket` together intentionally.

7. **Validation-vs-error semantics** — `level=info msg="invalid | <name>"`
   is INFORMATIONAL (exit code 0), not an error. The plugin's
   failure_signatures pipeline includes `invalid` to surface it as
   actionable to the LLM (so it can filter the wordlist). But this signal
   could collide with `level=error` messages that contain the word
   `invalid` (e.g., a hypothetical future "invalid config syntax" error).
   Currently low-risk but worth monitoring as v3 evolves.

8. **HOME env var and config.yml resolution** — for `-provider custom`,
   `-mq`, `-db` the binary searches `.`, `/etc/s3scanner/`,
   `$HOME/.s3scanner/` for `config.yml`. The Dockerfile doesn't set HOME
   explicitly (defaults to `/root` for root user). Should the tool.yaml's
   environment section document HOME more loudly? Currently mentioned;
   could be elevated to a usage_pattern for the rare `-provider custom`
   case.

9. **Legacy stdout+stderr merge dropped** — the legacy `scan` / `test`
   handlers in `mcp-server.py` did `combined = f"{stdout}\n{stderr}".strip()`
   before NDJSON parsing, because s3scanner emits SOME records on stderr
   even with `-json` (info/error lines). Under run_cli the LLM sees both
   streams as the engagement transcript renders them, but if downstream
   tooling (e.g., a future structured-output extractor) keys off stdout
   only, it will miss `level=error` JSON lines. Architectural decision:
   the run_cli engagement transcript is the merge point; no plugin-level
   stream-merging needed. Document for any future post-processor.

10. **Legacy 20000-char output cap dropped** — the legacy handlers wrapped
    the raw output with `sanitize_output(combined, max_length=20000)`.
    run_cli does not auto-truncate. For `-enumerate` on very large buckets
    the NDJSON stream can grow into MB; the LLM should redirect to a
    session file rather than ingest the whole stream. Now documented in
    tool.yaml gotchas. No further action required.

---

## 6. Hand-off

- **Tool**: s3scanner (kind:cli)
- **Status**: tool.yaml authored end-to-end (kind:mcp → kind:cli);
  scenarios.md written. Dockerfile updated to use `python3-full` on Kali
  base (replacing `python3 python3-pip python3-venv`). mcp-server.py
  untouched (auto-inherits run_cli; rollback path via 2 legacy methods:
  scan, test).
- **Image**: `ghcr.io/silicon-works/mcp-tools-s3scanner:latest` — needs
  rebuild during Wave 9 batch to pick up mcp-common 0.3.0 and the
  Dockerfile python3-full change. The s3scanner binary itself is
  installed via Kali's apt repo (current Kali package version reports
  `dev` — sa7mon/S3Scanner v3 Go port).
- **Live-verify**: tool.yaml's failure_signatures 1-9 verified live during
  authoring (via direct `docker run` against the GHCR image). S1, S2, S4
  (single-bucket scans against flaws.cloud) ready to paste; S3 (DO
  Spaces) needs a known DO target — defer to engagement use. S6-S10
  (failure cases) ready. S11 (rate-limit) deferred until appropriate
  fixtures.
- **Wave 7.8 — Go-binary, single-flag-target migration**: s3scanner v3 is
  the SIMPLEST kind:cli migration so far — single target_extraction rule
  (flag_value for `-bucket`), no positional fallback, 10-flag total
  surface. The structural difference from trufflehog (Wave 7.7 Go
  sub-command tool): s3scanner has NO sub-command, just a flat flag set.
  3 reject_flags (`-bucket-file`, `-mq`, `-db`) cover the multi-target /
  side-channel-output cases. value_flags is small (10 entries). All
  flags use single-dash form (Go's flag package, NOT POSIX double-dash).
- **v2 → v3 flag drift**: the previous Python v2 had ~15 more flags
  (`-output-file`, `-output-format`, `-quiet`, `-region-list`, `-aws-id`,
  `-aws-secret`, `-write-test`, `-permission-test`, `-include-empty`,
  etc.). v3 dropped them all. LLMs trained on v2 docs may emit v2 flags
  and hit the `flag provided but not defined` failure signature — they
  should self-correct via `s3scanner --help`.
- **Auth model**: v3 is anonymous-only. For authenticated bucket probing
  (your own AWS account), the LLM should be steered to the `aws` tool.
  This is documented in the tool.yaml description, gotchas, and
  see_also.

Authored: 2026-04-25.
