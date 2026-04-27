# trufflehog — Tier A scenarios

Single test sheet for the `trufflehog` tool migration (Wave 7.7).

trufflehog v3 is Truffle Security's flagship secret/credential discovery
tool — a **single binary** (`trufflehog`) with a **cobra-style sub-command
architecture**: `trufflehog <subcommand> [flags] [target]`. Sub-commands
cover git history (`git`), filesystems (`filesystem` / `fs`), GitHub repos
and orgs (`github`), GitLab (`gitlab`), Docker images (`docker`), S3 / GCS
buckets (`s3` / `gcs`), Hugging Face models (`huggingface`), and CI/CD
platforms (`postman`, `circleci`, `jenkins`, `syslog`).

trufflehog is the **second sub-command-architecture migration after trivy**
(Wave 7.5). The structural difference from trivy is that trufflehog's
"target" lives in **multiple places** depending on sub-command:

- `git` / `filesystem` — target is the **last positional**.
- `github` — target is the value of `--repo` or `--org`.
- `s3` / `gcs` — target is the value of `--bucket`.
- `docker` — target is the value of `--image`.
- `huggingface` — target is the value of `--model` / `--space` / `--user`.
- `jenkins` — target is the value of `--url`.
- `postman` / `circleci` — NO target in argv (token-scoped).

The DSL handles this via a **sequence of `flag_value` rules** (one per
target-bearing flag) followed by **`last_non_flag_positional`** as
fallback. Precedence: flag_value rules first (most specific), positional
fallback after, shape-match positional last.

Sections:
1. Recommended target for live verification
2. Narrative scenarios (paste into opensploit)
3. Target-extraction adversarial cases (≥20)
4. Failure-signature live-verify cases (≥3)
5. Open questions
6. Hand-off

---

## 1. Recommended target

trufflehog is **NOT an HTB-style network tool**. It scans git repos,
filesystems, cloud buckets, container images, and CI/CD platforms for
leaked credentials. There is no "HTB box" for trufflehog in the way
Blocky is for wpscan or Hercules is for enum4linux-ng. The right
verification target is a **deliberately-leaky artifact** you can fetch
or construct in `/session/`.

**Recommended verification artifacts** (in order of preference):

1. **`https://github.com/Plazmaz/leaky-repo`** — well-known
   intentionally-leaky public repo seeded with example creds across
   many detector categories. Authoritative for trufflehog testing.
   Run as: `trufflehog git https://github.com/Plazmaz/leaky-repo
   --json --no-verification --no-update` (use `--no-verification`
   to avoid hammering the upstream services with seeded fake creds —
   they'd still produce hits but the verification calls are wasted).

2. **`/session/leaky-tree`** — write a small project tree containing
   seeded fake creds across detector categories (AWS access key
   pattern, GitHub PAT pattern, Slack webhook, generic bearer). Then
   run `trufflehog filesystem /session/leaky-tree --json --no-verification
   --no-update`. Confirms filesystem scanner path without network.
   Seed values MUST use Truffle's documented test patterns (e.g.,
   `AKIAIOSFODNN7EXAMPLE` for AWS) — these are recognized by
   detectors but explicitly blocked from verification.

3. **`alpine:3.14` Docker image** — public Docker Hub image. Has no
   real secrets but exercises the docker scanner path (image pull,
   layer walk, config inspection). Confirms `docker --image=` argv
   shape and the layer-iteration code path. Expect zero verified
   findings.

4. **A throwaway public S3 bucket** (no creds in path; standard public
   bucket like `s3://commoncrawl-us-west-2/cc-index/` for a tiny
   `--include-paths` regex). Confirms the `s3 --bucket=...` argv
   shape and the cloud-bucket-iteration code path. Expect zero
   verified findings unless someone left real creds in the bucket
   (unlikely for crawl indexes).

5. **HTB-style boxes (rare)** — a few HTB boxes expose `.git`
   directories or backup files containing credentials. When applicable,
   `git-dumper` followed by `trufflehog git file:///session/dumped`
   (note `file://` — see Gotchas) is a direct enumeration step. But
   most HTB boxes don't have git-dumpable contents.

For GitHub testing: requires a personal GITHUB_TOKEN. Use a token
scoped to public-repo + read:org against a deliberately-leaky test
org (set up your own under your personal account with seeded fake
creds, or use a published demo org if available).

For S3 testing: requires real AWS credentials with read on a target
bucket. LocalStack supports trufflehog's S3 client OK for offline
testing.

Persistent test directory: standard `/session/` mount; trufflehog
NDJSON output should be redirected via shell to
`/session/findings.ndjson` (no `-o` flag — see Gotchas).

---

## 2. Narrative scenarios (paste into opensploit)

### S1 — filesystem scan (verified-only, with seeded leaky tree)

```
Engagement target: /session/leaky-tree (post-exploitation captured project tree).
First create /session/leaky-tree with a sample config.yaml containing the test credential 'AKIAIOSFODNN7EXAMPLE' (a known AWS test access key) and a .env file with 'GITHUB_TOKEN=ghp_examplePATtokenForTesting'. Then use trufflehog to scan /session/leaky-tree with verified-only filtering, JSON output, and no auto-update.
```

**Watch:** Agent first writes the seeded files via the `write` tool (NOT bash heredoc), then emits `trufflehog filesystem /session/leaky-tree --json --only-verified --no-update`. target=`/session/leaky-tree` extracted via `last_non_flag_positional`. The sub-command `filesystem` is ALSO a positional but isn't the LAST one. Output is NDJSON to stdout — agent should redirect with `--shell-redirect` capability or `tee /session/findings.ndjson`. Note: with `--only-verified`, the test creds (AKIAIOSFODNN7EXAMPLE, ghp_example...) will NOT verify (they're documentation placeholders) — output may be empty. Drop `--only-verified` for unverified hits.

### S2 — git history scan (remote URL — clone + walk all commits)

```
Engagement target: a public github repo with known seeded credentials.
Use trufflehog to scan the public github repo at https://github.com/Plazmaz/leaky-repo for leaked secrets via git history. Use JSON output, skip live verification (the seeded creds are fake), and disable auto-update for reproducibility.
```

**Watch:** Agent emits `trufflehog git https://github.com/Plazmaz/leaky-repo --json --no-verification --no-update`. target=`https://github.com/Plazmaz/leaky-repo` extracted via `last_non_flag_positional`. trufflehog clones to a temp dir and walks every branch + every commit. NDJSON streams to stdout — many findings expected (this repo is intentionally leaky). Each NDJSON object has `SourceMetadata.Data.Git.{repository, file, commit, email, line}`.

### S3 — GitHub repo scan via API

```
Engagement target: https://github.com/Plazmaz/leaky-repo (the public test repo).
Use trufflehog to scan this repo via the GitHub API (NOT clone-and-walk). Use JSON output, skip live verification, and disable auto-update. Set the GITHUB_TOKEN environment variable from the engagement environment.
```

**Watch:** Agent emits `trufflehog github --repo=https://github.com/Plazmaz/leaky-repo --json --no-verification --no-update`. target=`https://github.com/Plazmaz/leaky-repo` extracted via the `flag_value` rule for `--repo`. NOTE: this is the FIRST adversarial test for the flag_value extraction logic — confirm the plugin's audit log shows the URL as the target, NOT some other token. With GITHUB_TOKEN set in env, the API rate-limit lifts to 5000/h.

### S4 — Docker image scan

```
Engagement target: alpine:3.14 (public Docker Hub image, used as a sanity check).
Use trufflehog to scan the alpine:3.14 container image's layers and config for leaked credentials. JSON output, skip verification (alpine has no real creds), no auto-update.
```

**Watch:** Agent emits `trufflehog docker --image=alpine:3.14 --json --no-verification --no-update`. target=`alpine:3.14` extracted via `flag_value` for `--image`. trufflehog pulls the image (or uses a cached copy), walks every layer's filesystem, and inspects config.env / config.labels. Expect zero findings (alpine is clean). First call ~10-30 s for image pull; subsequent calls reuse the cached image.

### S5 — S3 bucket scan (public bucket, no creds)

```
Engagement target: s3://commoncrawl-us-west-2 (a public AWS S3 bucket — Common Crawl).
Use trufflehog to scan the s3://commoncrawl-us-west-2 bucket's contents for leaked secrets. JSON output, skip verification, no auto-update. Filter to high-value file extensions only via --include-paths.
```

**Watch:** Agent emits `trufflehog s3 --bucket=commoncrawl-us-west-2 --json --no-verification --no-update --include-paths '\.(env|conf|ini|yaml|json|sh|sql|key|pem)$'`. target=`commoncrawl-us-west-2` extracted via `flag_value` for `--bucket`. NOTE: bucket name has NO `s3://` prefix — that's the trufflehog convention (matches AWS SDK). The `--include-paths` regex is consumed by `--include-paths` (in value_flags), NOT the target. Expect zero findings (Common Crawl is web crawl data, not secrets). Bucket is public — no AWS creds needed.

### S6 — failure: missing sub-command

```
Engagement target: /session/source (the test).
Run trufflehog without specifying any sub-command, against /session/source. JSON output.
```

**Watch:** Agent emits `trufflehog /session/source --json` — but `/session/source` isn't a valid sub-command. trufflehog errors with `Error: unknown command "/session/source" for "trufflehog"` or similar. failure_signature matches `Error: unknown command`. Agent should retry with `filesystem /session/source` (or `git file:///session/source` for history scan).

### S7 — failure: GitHub auth (private repo without token)

```
Engagement target: a known-private GitHub repo URL.
Use trufflehog to scan a private repo via GitHub API WITHOUT setting GITHUB_TOKEN. Expect a 404 / unauthorized failure.
```

**Watch:** Agent emits `trufflehog github --repo=https://github.com/silicon-works/some-private-repo --json --no-verification --no-update`. trufflehog returns either `404 Not Found` (GitHub returns 404 for private repos to anonymous viewers — repo enumeration protection) or `401 Unauthorized` if the path-of-failure surfaces it differently. failure_signature matches `repository not found` OR `401 Unauthorized`. Agent should set GITHUB_TOKEN and retry.

### S8 — failure: required flag missing (s3 without --bucket)

```
Engagement target: any S3 (the test).
Run trufflehog s3 with no --bucket flag. JSON output.
```

**Watch:** Agent emits `trufflehog s3 --json --no-update`. trufflehog errors with `Error: required flag(s) "bucket" not set`. failure_signature matches `Error: required flag`. Agent should add `--bucket=<name>` and retry.

---

## 3. Target-extraction adversarial cases (≥20)

The trufflehog `tool.yaml` declares 11 extraction rules, in order:

1. `flag_value` for `--repo` (parse_as: raw)
2. `flag_value` for `--org` (parse_as: raw)
3. `flag_value` for `--bucket` (parse_as: raw)
4. `flag_value` for `--image` (parse_as: raw)
5. `flag_value` for `--url` (parse_as: raw)
6. `flag_value` for `--model` (parse_as: raw)
7. `flag_value` for `--space` (parse_as: raw)
8. `flag_value` for `--user` (parse_as: raw)
9. `flag_value` for `--address` (parse_as: raw)
10. `last_non_flag_positional` (parse_as: raw)
11. `positional_match` (fallback shape match)

`reject_flags`: empty (no flag shifts target outside argv).

`value_flags` includes ~70 entries covering all flags that take a value
across all sub-commands — notably the target-bearing flags above plus
`--token`, `--username`, `--password`, `--key`, `--secret`,
`--role-arn`, `--branch`, `--since-commit`, `--max-depth`,
`--include-paths`, `--exclude-paths`, `--include-detectors`,
`--exclude-detectors`, `--filter-entropy`, `--archive-max-size`,
`--archive-max-depth`, `--concurrency`, `--config`, `--head`,
`--endpoint`.

### Happy-path cases

| # | Command (binary `trufflehog` omitted) | Expected target | Notes |
|---|---|---|---|
| 1 | `filesystem /session/source --json --only-verified` | `/session/source` | Standard fs scan. last_non_flag_positional skips `filesystem` (first positional) and returns `/session/source` (second positional, unconsumed). |
| 2 | `git https://github.com/example/repo.git --json --only-verified` | `https://github.com/example/repo.git` | git remote URL. Last positional after the sub-command. |
| 3 | `git file:///session/source --json` | `file:///session/source` | git LOCAL path via file:// to force history walk on a local dir. last_non_flag_positional captures the file:// URL. |
| 4 | `github --repo=https://github.com/example/repo --json` | `https://github.com/example/repo` | github repo via flag_value rule for `--repo`. Equals-form: `--repo=<value>`. |
| 5 | `github --repo https://github.com/example/repo --json` | `https://github.com/example/repo` | Same as #4 but space-form: `--repo <value>`. flag_value rule must handle both. |
| 6 | `github --org=example-org --json` | `example-org` | github org-wide scan. flag_value rule for `--org`. |
| 7 | `s3 --bucket=my-bucket --json` | `my-bucket` | S3 scan. flag_value rule for `--bucket`. NOTE: no `s3://` prefix — that's the convention. |
| 8 | `gcs --bucket=my-gcs-bucket --json` | `my-gcs-bucket` | GCS scan — same flag, different sub-command. flag_value rule fires the same way. |
| 9 | `docker --image=alpine:3.14 --json` | `alpine:3.14` | Docker image. flag_value rule for `--image`. |
| 10 | `docker --image=registry.example.com/org/app:1.2.3 --json` | `registry.example.com/org/app:1.2.3` | Full registry reference (with `:tag`). |
| 11 | `huggingface --model=user/model-name --json` | `user/model-name` | HF model. flag_value rule for `--model`. |
| 12 | `huggingface --space=user/space-name --json` | `user/space-name` | HF Space (different flag). |
| 13 | `huggingface --user=username --json` | `username` | HF user (scan all of user's models). |
| 14 | `jenkins --url=https://jenkins.example.com --json` | `https://jenkins.example.com` | Jenkins server. flag_value rule for `--url`. |
| 15 | `filesystem /session/path with space/ --json` | `/session/path with space/` | Path with spaces — must be quoted in shell, but argv-level the path is one token. |
| 16 | `git https://github.com/example/repo --branch main --max-depth 100 --json` | `https://github.com/example/repo` | URL is LAST positional; --branch consumes `main`, --max-depth consumes `100`. |
| 17 | `github --repo=https://github.example.com/org/repo --endpoint=https://github.example.com --token=ghp_xxx --json` | `https://github.example.com/org/repo` | GitHub Enterprise — flag_value for --repo wins; --endpoint and --token are consumed by their respective value_flags. |
| 18 | `s3 --bucket=my-bucket --key=AKIA... --secret=... --role-arn=arn:aws:iam::123:role/x --json` | `my-bucket` | S3 with full auth set. --bucket value is target; AWS creds consumed by value_flags. |
| 19 | `git --branch develop --since-commit a1b2c3d https://github.com/example/repo` | `https://github.com/example/repo` | Multiple value flags BEFORE the URL — last_non_flag_positional walks past them. |

### Adversarial — value_flag traps & sub-command edge cases

| # | Command | Expected | Notes |
|---|---|---|---|
| F1 | `--help` | `target=null` | Top-level help. tool_runner bypasses scope check. |
| F2 | `git --help` | `target=null` (or `git` from positional_match — both safe; help skips network) | Sub-command help. Only positional is `git` itself. |
| F3 | `-h` | `target=null` | Short-form help. |
| F4 | `--version` | `target=null` | Long-form version flag. |
| F5 | `git --branch main https://github.com/example/repo` | `https://github.com/example/repo` (NOT `main`) | `--branch` value `main` is a flag-value, must NOT be the target. value_flags catches it. |
| F6 | `git --include-paths '\.env$' --exclude-paths 'node_modules' https://github.com/example/repo` | `https://github.com/example/repo` (NOT either regex) | `--include-paths` and `--exclude-paths` values are regexes; in value_flags. Crucially, `'\.env$'` is a path-shape regex that COULD be mistaken for a target if value_flags didn't catch it. |
| F7 | `git --since-commit a1b2c3d4e5 --max-depth 1000 https://github.com/example/repo` | `https://github.com/example/repo` (NOT commit hash, NOT `1000`) | `--since-commit` and `--max-depth` values consumed; URL is the LAST positional. |
| F8 | `git --include-detectors aws,github,slack --exclude-detectors generic https://github.com/example/repo` | `https://github.com/example/repo` (NOT detector lists) | `--include-detectors` and `--exclude-detectors` values are comma-lists; in value_flags. |
| F9 | `git --filter-entropy 4.5 --concurrency 16 https://github.com/example/repo` | `https://github.com/example/repo` (NOT `4.5` or `16`) | Numeric value flags consumed correctly. |
| F10 | `github --repo=https://github.com/example/repo --token=ghp_abcDefGhiJklMnoPqr --json` | `https://github.com/example/repo` (NOT token) | `--token` is a value flag — token MUST NOT be extracted as target. value_flags catches it. CRITICAL for credential safety. |
| F11 | `github --org=example --token=ghp_secrettoken123 --include-members --json` | `example` (NOT token) | `--org` flag_value rule fires FIRST (declared earlier in target_extraction), capturing `example`. Token never considered. |
| F12 | `s3 --bucket=my-bucket --key=AKIAIOSFODNN7EXAMPLE --secret=wJalrXUtnFEMI/K7MDENG/bPxRfiCYEXAMPLEKEY --json` | `my-bucket` (NOT AWS keys) | AWS access key + secret key are values of `--key` and `--secret` (in value_flags). flag_value for `--bucket` wins. CRITICAL — the AWS access key has the same shape (length, charset) as some IAM resource ARNs and could be confused for a target without value_flags coverage. |
| F13 | `s3 --bucket=my-bucket --role-arn=arn:aws:iam::123456789012:role/scanner --json` | `my-bucket` (NOT role ARN) | `--role-arn` value is an AWS ARN; in value_flags. |
| F14 | `huggingface --model=meta-llama/Llama-3-70B --token=hf_secrettoken123 --json` | `meta-llama/Llama-3-70B` (NOT token) | flag_value for `--model` fires; `--token` consumed. |
| F15 | `git --config /session/custom-detectors.yaml https://github.com/example/repo` | `https://github.com/example/repo` (NOT config path) | `--config` value is a config file path; in value_flags. |
| F16 | `git --head HEAD~10 https://github.com/example/repo` | `https://github.com/example/repo` (NOT `HEAD~10`) | `--head` value is a git ref; in value_flags. |
| F17 | `filesystem --archive-max-size 100MB --archive-max-depth 5 /session/source` | `/session/source` (NOT `100MB` or `5`) | Archive flag values consumed; path is last positional. |
| F18 | `filesystem --no-verification --no-update --json --only-verified /session/source` | `/session/source` | Mix of boolean flags before path — booleans don't consume next arg; path captured. |
| F19 | `git https://github.com/example/repo` (NO flags at all) | `https://github.com/example/repo` | Zero-flag minimal command — last positional is the target. |
| F20 | `postman --token=PMAK-secrettoken123 --json` | `target=null` (or `postman` from positional_match — both safe; token-scoped scan) | postman has NO target in argv (token-scoped). flag_value rules don't match (no --repo/--bucket/etc.). last_non_flag_positional returns `postman` (the sub-command). positional_match fallback rejects `postman` (not URL/path/IP shape). Net target=null. SAFE: scope is the API token, not argv. |
| F21 | `circleci --token=ccitoken123 --json` | `target=null` (same reason as F20) | circleci is also token-scoped — no positional target. |
| F22 | `git --bare /session/bare-repo` | `/session/bare-repo` | `--bare` is BOOLEAN (no value); doesn't consume next arg. Path captured as last positional. |
| F23 | `github --repo=https://github.com/example/repo --include-issue-comments --include-pull-request-comments --json` | `https://github.com/example/repo` | flag_value for `--repo` wins; the boolean `--include-*-comments` flags don't consume args. |
| F24 | `git --json --only-verified https://github.com/example/repo --debug --trace --profile` | `https://github.com/example/repo` | URL is in the MIDDLE of argv with boolean flags after. last_non_flag_positional walks left-to-right; `--debug`/`--trace`/`--profile` are booleans (in value_flags as boolean-list); URL is the only positional. |
| F25 | `github --repo=https://github.com/example/repo --org=example` | `https://github.com/example/repo` (--repo wins) | BOTH `--repo` and `--org` set — flag_value for `--repo` is declared FIRST in target_extraction, so it wins by precedence. Documented edge case. |
| F26 | `s3 --bucket=my-bucket --cloud-environment=aws --json` | `my-bucket` | `--cloud-environment` value is consumed; `--bucket` flag_value wins. |
| F27 | `git https://github.com/example/repo --include-paths 'src/.*\.go$'` | `https://github.com/example/repo` | URL is BEFORE the value-flag — last_non_flag_positional still picks URL because `src/.*\.go$` is consumed by `--include-paths`. |
| F28 | `github --org=example --include-repos=foo,bar --exclude-repos=baz` | `example` | `--include-repos` and `--exclude-repos` values are repo-name lists; in value_flags. flag_value for `--org` wins. |
| F29 | `huggingface --user=username --token=hf_xyz` | `username` | flag_value for `--user` fires; token consumed. NOTE: `--user` is a generic-sounding flag name — common-flag risk. The flag_value rule is specifically declared so it picks up the HF subcommand intent. |
| F30 | `jenkins --url=https://jenkins.example.com --token=jenkinstoken --json` | `https://jenkins.example.com` | flag_value for `--url` fires; token consumed. |
| F31 | `git https://user:password@github.com/example/repo.git` | `https://user:password@github.com/example/repo.git` | URL with embedded basic-auth creds. Captured AS-IS. SECURITY NOTE: this leaks creds into the audit log. The plugin's audit redaction (if any) should mask the password segment. |
| F32 | `filesystem /session/source --include-paths 'AKIA[0-9A-Z]{16}' --json` | `/session/source` (NOT the AKIA regex) | The `--include-paths` regex LOOKS LIKE an AWS key prefix — pure regex, not a key. value_flags must catch it OR target_extraction would propose a string that matches the AWS-key shape. value_flags wins. |
| F33 | `git --no-update --json --no-verification --concurrency 32 --filter-entropy 3.5 --archive-max-size 500MB --archive-max-depth 8 https://github.com/example/repo` | `https://github.com/example/repo` | Long flag chain — value flags + booleans + target. The URL is the only positional after all value flags consume their values. |

### Happy-path cases — IPv6 / unusual targets

| # | Command | Expected | Notes |
|---|---|---|---|
| H1 | `git ssh://git@[::1]:22/repo.git` | `ssh://git@[::1]:22/repo.git` | IPv6 bracketed in SSH URL. Edge case — most repos use hostname URLs. |
| H2 | `filesystem /session/symlink-to-repo` | `/session/symlink-to-repo` | Path is a symlink — trufflehog follows it. extraction is path-as-given. |
| H3 | `docker --image=alpine` | `alpine` | Image without explicit `:tag` — defaults to `:latest` via Docker conventions. Raw extraction returns `alpine`. |
| H4 | `docker --image=alpine@sha256:abc123def456` | `alpine@sha256:abc123def456` | Image referenced by digest, not tag. |
| H5 | `s3 --bucket=my-bucket-with-dots.example.com` | `my-bucket-with-dots.example.com` | S3 bucket name with dots (legacy AWS naming style). Raw extraction. |

---

## 4. Failure-signature live-verify cases (≥3)

| # | Layer | Test | failure_signature `signal` | Status |
|---|---|---|---|---|
| 1 | DNS | `git https://nonexistent-registry.invalid.localdomain/repo.git --no-update --no-verification` | `no such host` AND/OR `dial tcp` | PENDING live verify |
| 2 | TCP | `github --repo=https://localhost:1/x/y --no-update --no-verification` | `connection refused` AND/OR `dial tcp` | PENDING live verify |
| 3 | Auth | `github --repo=https://github.com/silicon-works/private-repo --no-update --no-verification` (without GITHUB_TOKEN) | `repository not found` (GitHub returns 404 for private repos to anonymous viewers) OR `401 Unauthorized` | PENDING live verify (needs known-private repo) |
| 4 | Auth | `s3 --bucket=private-bucket-with-no-access --no-update --no-verification` (without IAM creds) | `AccessDenied` OR `403 Forbidden` | PENDING live verify (needs known-private bucket) |
| 5 | Argument | `scan /session/source` (invalid sub-command) | `Error: unknown command` | PENDING live verify |
| 6 | Argument | `s3 --json --no-update` (missing required --bucket flag) | `Error: required flag` | PENDING live verify |
| 7 | Argument | `git --bogus-flag https://github.com/example/repo` | `unknown flag` | PENDING live verify |
| 8 | Path | `filesystem /session/does/not/exist --no-update` | `no such file or directory` OR `path does not exist` | PENDING live verify |
| 9 | Repo | `git /session/not-a-git-repo --no-update` (path exists but isn't a git repo) | `not a git repository` | PENDING live verify |
| 10 | Rate-limit | `github --org=large-public-org --no-update --no-verification` (without GITHUB_TOKEN) | `rate limit` OR `API rate limit exceeded` | PENDING — needs unauthenticated burst to a large org |
| 11 | Empty | `filesystem /session/empty-dir --json --only-verified --no-update` | `0 verified secrets` OR empty NDJSON output | PENDING live verify (informational, NOT a failure) |
| 12 | Verification | `filesystem /session/leaky-tree --json --only-verified --no-update` (with EXAMPLE creds — won't verify) | output empty (no findings); stderr may show `verification failed` per cred (informational, NOT a tool error) | PENDING live verify |

### Layer diversity (SKILL #11) — achieved

7+ distinct layers exercised: DNS / TCP / auth-github / auth-s3 / argument
(unknown-cmd / required-flag / unknown-flag) / path-not-found /
not-a-repo / rate-limit / empty-result / verification. SKILL #11
minimum (5 distinct layers) is met several times over.

---

## 5. Open questions

1. **Multi-form target extraction precedence** — `--repo` and `--org` can
   BOTH appear in a single `github` invocation. The current
   `target_extraction` declares `--repo` BEFORE `--org`, so `--repo` wins
   when both are present. Is that the right precedence, or should we
   reject the call as ambiguous? trufflehog itself accepts both and uses
   `--repo` (org is ignored when repo is set). Current decision: match
   trufflehog's behavior — `--repo` wins. Could revisit if engagement-state
   audit prefers explicit ambiguity rejection.

2. **`--only-verified` detection risk** — every verified scan generates a
   LIVE call to the upstream service for each candidate cred. For a leaky
   org with hundreds of seeded test creds, this can mean hundreds of
   verification requests against AWS sts, GitHub /user, Slack auth.test,
   Stripe /v1/account, etc. This is detectable via target's logs / DLP.
   Should the tool.yaml flag this more loudly in usage_patterns? Currently
   in gotchas. Consider adding a "stealth-mode" usage_pattern that
   defaults to `--no-verification`.

3. **GitHub Enterprise `--endpoint` discovery** — when scanning a GHE
   instance, the agent must pass `--endpoint=https://<ghe-host>` AND
   `--repo=<full-url>`. There's no auto-detection from the URL — if the
   URL is `https://github.example.com/org/repo`, trufflehog still talks
   to `api.github.com` unless `--endpoint` is set. Should the tool.yaml
   gotchas section bold this? Currently mentioned. Might be worth a
   dedicated usage_pattern.

4. **`filesystem` vs `git` mode on local paths** — passing a local path
   to `git` requires `file://` prefix to force history walk; without
   prefix, trufflehog treats it as filesystem-mode (working tree only).
   Easy footgun. Should the tool.yaml's usage_patterns cover both forms
   prominently? Currently does (S2 uses URL, S3 uses file://). LLM may
   still mis-emit `git /session/source` (without file://) and get the
   filesystem-mode behavior silently. Consider a failure_signature for
   "expected git history scan but got working-tree scan" — but trufflehog
   doesn't actually produce a distinct error for this; it just runs
   filesystem-mode quietly.

5. **Token redaction in argv audit logs** — when `--token=<value>`
   appears in argv (rather than as env var), the engagement audit log
   captures the token. The plugin's audit redaction layer should mask
   `--token=...` values. Currently UNCONFIRMED whether
   audit redaction is applied here. Defer to plugin-side audit feature.
   Workaround: prefer env vars (GITHUB_TOKEN / GITLAB_TOKEN) over `--token`
   in usage_patterns (currently done).

6. **`postman` / `circleci` null-target permission model** — these
   sub-commands have no positional or target-bearing flag; scope is
   defined by the API token. The plugin treats null-target calls as
   informational / non-engagement-target, so scope validation skips. Is
   that correct, or should the engagement state explicitly authorize
   token-scoped scans (since they CAN find creds across many repos that
   weren't part of the engagement scope)? Defer to engagement-state-level
   policy.

7. **Multi-target `--repo` invocation** — trufflehog's `github --repo`
   accepts a comma-separated list (`--repo=url1,url2,url3`) per recent
   versions. The flag_value rule extracts the WHOLE comma-list as the
   target string. Is that acceptable for scope validation, or should it
   be split? Currently extracted as-is. Plugin-side scope validator could
   split on comma if needed.

8. **`huggingface` 3-flag dispatch** — `huggingface` accepts
   `--model=<m>` OR `--space=<s>` OR `--user=<u>` (mutually exclusive
   in practice). The DSL declares each as a `flag_value` rule. If two
   are passed simultaneously, the first one declared (`--model`) wins
   per precedence. trufflehog itself errors if multiple are passed.
   No conflict, but documented.

9. **Auto-update vs reproducibility** — without `--no-update`, two runs
   of trufflehog against the same target may produce DIFFERENT results
   because the detector set updated between runs. For engagement-grade
   reproducibility, ALWAYS pass `--no-update`. Currently in gotchas and
   in every default usage_pattern. Should `--no-update` be a hard requirement
   (auto-injected by the plugin)? Defer to plugin-side argv mutation
   policy.

---

## 6. Hand-off

- **Tool**: trufflehog (kind:cli)
- **Status**: tool.yaml authored end-to-end (kind:mcp → kind:cli);
  scenarios.md written. Dockerfile updated to use `python3-full` on
  Kali base (replacing `python3 python3-pip python3-venv`). mcp-server.py
  untouched (auto-inherits run_cli; rollback path via 3 legacy methods:
  scan_git, scan_filesystem, scan_s3).
- **Image**: `ghcr.io/silicon-works/mcp-tools-trufflehog:latest` — needs
  rebuild during Wave 9 batch to pick up mcp-common 0.3.0 and the
  Dockerfile python3-full change. The trufflehog binary itself is
  installed via Kali's apt repo (current Kali package version aligns
  with upstream v3.x).
- **Live-verify pending**: paste S1-S8 against
  https://github.com/Plazmaz/leaky-repo (S2, S3) and seeded
  /session/leaky-tree (S1 — agent must write the test files first via
  `write` tool). Verify failure_signatures 1, 2, 5, 6, 7, 8, 9 (all
  inexpensive locally). Defer cases 3 (private repo), 4 (private
  bucket), 10 (rate-limit), 11/12 (empty/verification informational)
  until appropriate fixtures available.
- **Wave 7.7 — second sub-command-architecture migration**: trufflehog
  is the second Tier A tool with sub-command argv shape (after trivy,
  Wave 7.5). The structural difference: trivy puts the target as a
  POSITIONAL after the sub-command for ALL sub-commands; trufflehog
  splits target location across **positional** (`git`, `filesystem`)
  and **flag value** (`github --repo`, `s3 --bucket`, `docker --image`,
  `huggingface --model`, `jenkins --url`, etc.). The DSL handles this
  cleanly via a stack of `flag_value` rules ahead of
  `last_non_flag_positional` — flag_value rules fire first when the
  matching flag is present, last_non_flag_positional handles the
  positional-target sub-commands. value_flags coverage is comprehensive
  (~70 flags). reject_flags is empty (no flag shifts target outside argv).
- **Token safety**: GitHub / GitLab / Postman / CircleCI / HuggingFace
  tokens MUST come via env vars (GITHUB_TOKEN etc.) rather than `--token`
  argv to keep tokens out of the audit log. usage_patterns prefer env
  vars; gotchas call this out.

Authored: 2026-04-25.
