# cloudfox — Tier A scenarios

Single test sheet for the `cloudfox` tool migration (Wave 7.9).

cloudfox is BishopFox's flagship cloud post-exploitation enumeration tool — a
**single binary** (`cloudfox`) with a **cobra-style provider + sub-command
architecture**: `cloudfox <provider> <subcmd> [flags]`. Providers are `aws`
(flagship — ~30+ sub-commands), `azure`, `gcp`, `k8s` (smaller surfaces,
5-6 sub-commands each).

cloudfox is the **third sub-command-architecture migration** after trivy
(Wave 7.5) and trufflehog (Wave 7.7). The structural difference vs.
trufflehog:

- trufflehog's target is a **mix of positionals** (`git`, `filesystem`)
  **and flag values** (`github --repo`, `s3 --bucket`, `docker --image`).
- cloudfox's target is **always a flag value** — `--profile <name>` (AWS),
  `--subscription <id>` (Azure), `--project <id>` (GCP), `--kubeconfig <path>`
  (k8s). When env-var auth is used (no `--profile`), target is null.

The DSL handles this via a **stack of `flag_value` rules** (one per
target-bearing flag). No `last_non_flag_positional` rule — cloudfox has no
positional target. The provider + sub-command positionals are consumed by
cobra dispatching, NOT extracted as targets.

Sections:
1. Recommended target for live verification
2. Narrative scenarios (paste into opensploit)
3. Target-extraction adversarial cases (≥20)
4. Failure-signature live-verify cases (≥3)
5. Open questions
6. Hand-off

---

## 1. Recommended target

cloudfox is **NOT a network tool** and there is no HTB-style box for it.
cloudfox's target is an **AWS / Azure / GCP / Kubernetes account** —
verification requires real cloud credentials with read-level access. There
is no offline mode (cloudfox calls live AWS APIs).

**Recommended verification targets** (in order of preference):

1. **A throwaway AWS lab account** — set up via the AWS Free Tier or a
   dedicated pentest-lab account. Seed it with a few resources:
   - 1-2 IAM users (one with admin policy, one with read-only)
   - 1-2 IAM roles with cross-account trust policies
   - 1-2 EC2 instances with attached IAM instance profiles (one with
     SSM-access role, one with no role) and seeded user-data scripts
     (e.g., `#!/bin/bash\necho "DB_PASSWORD=hunter2" >> /etc/env.d/app`)
   - 1-2 Lambda functions with env-vars containing fake secrets
     (`API_KEY=ak_test_examplefakekey123`)
   - 1-2 S3 buckets (one public, one private)
   - 1-2 Secrets Manager entries
   Run `aws configure --profile=lab-account` to write creds to
   `~/.aws/credentials`, then test with `cloudfox aws inventory
   --profile=lab-account`. This exercises the `flag_value` rule for
   `--profile` AND the actual AWS API path.

2. **STUB CREDENTIALS for offline argv-extraction testing** — write a
   `~/.aws/credentials` profile with bogus creds (`aws_access_key_id =
   AKIAIOSFODNN7EXAMPLE` — the documented AWS placeholder). cloudfox
   will fail at the auth layer (`InvalidClientTokenId`) but argv parsing
   still happens. This validates the target_extraction layer WITHOUT
   needing real AWS API access. Useful for the failure_signature
   verification cases below.

3. **AWS_ACCESS_KEY_ID env var with bogus values** — set
   `AWS_ACCESS_KEY_ID=AKIAIOSFODNN7EXAMPLE` and
   `AWS_SECRET_ACCESS_KEY=wJalrXUtnFEMI/K7MDENG/bPxRfiCYEXAMPLEKEY` in
   the container env, omit `--profile`. Validates the **null-target**
   path of target_extraction (no `--profile`, no `--subscription` etc. =
   target null).

4. **LocalStack** — runs AWS-API-compatible mock locally. Configure
   cloudfox with `AWS_ENDPOINT_URL=http://localstack:4566` (note: cloudfox
   itself doesn't expose `--endpoint`, but the underlying AWS SDK Go
   honors AWS_ENDPOINT_URL env var as of v2). Imperfect — many services
   are partial in LocalStack — but useful for offline integration.

5. **Azure / GCP / k8s testing** — Azure free trial subscription, GCP
   Free Tier project, or a local k3s cluster. Same pattern as AWS — set
   creds via env vars or session files, then run `cloudfox azure inventory
   --subscription=<id>`, etc.

For OpenSploit engagements: cloudfox runs ONLY after AWS credentials are
captured in earlier phases (e.g., from a leaked .aws/credentials file
exfiltrated via SSRF, an EC2 instance metadata theft, or a compromised
admin's local config). The engagement state must explicitly authorize the
cloud account (account ID + profile name) BEFORE cloudfox is invoked.

Persistent test directory: `/session/cloudfox/` — pass via
`--output-directory=/session/cloudfox/` so loot files land in the
engagement working dir, not the container's ephemeral
`~/.cloudfox/cloudfox-output/`.

---

## 2. Narrative scenarios (paste into opensploit)

### S1 — AWS account inventory (FIRST scan after creds obtained)

```
Engagement target: AWS account scoped via the 'lab-account' profile in /session/.aws/credentials.
Use cloudfox to run an inventory scan on this AWS account. Use JSON output and persist loot files under /session/cloudfox/. The HOME env var is set to /session so cloudfox finds the credentials file at /session/.aws/credentials.
```

**Watch:** Agent emits `cloudfox aws inventory --profile=lab-account
--output-format=json --output-directory=/session/cloudfox/`. target=`lab-account`
extracted via `flag_value` rule for `--profile`. cloudfox queries STS
`get-caller-identity`, then walks each AWS service to count resources +
detect preferred regions. Output: JSON to stdout AND loot files under
`/session/cloudfox/<account-id>/inventory/`. ~30s for a small account. The
sub-command `inventory` is a positional consumed by cobra (NOT a
target_extraction value). The provider `aws` is also a positional consumed
by cobra.

### S2 — AWS full sweep (all-checks across all regions)

```
Engagement target: AWS account scoped via 'prod-account' profile. The engagement is authorized for full enumeration across all enabled regions.
Use cloudfox aws all-checks to run every enumeration sub-command across every enabled AWS region. JSON output. Loot to /session/cloudfox/. Auto-confirm prompts.
```

**Watch:** Agent emits `cloudfox aws all-checks --profile=prod-account
--all-regions --output-format=json --output-directory=/session/cloudfox/
--verbosity=2 -y`. target=`prod-account` via `flag_value` for `--profile`.
`--all-regions` (boolean) iterates every enabled region; `-y` auto-answers
prompts. Long runtime — 5-30 min for moderate accounts. Idle stretches
during AWS pagination are NORMAL — `idle_timeout=600s` covers the longest
silent waits.

### S3 — AWS attack-path discovery (workloads with admin)

```
Engagement target: AWS account 'lab-account'. Goal: identify compute workloads (EC2/Lambda/ECS/CodeBuild) whose IAM role has admin or path-to-admin permissions.
Use cloudfox aws workloads with --admin-only filter. JSON output, loot to /session/cloudfox/.
```

**Watch:** Agent emits `cloudfox aws workloads --profile=lab-account
--admin-only --output-format=json --output-directory=/session/cloudfox/`.
target=`lab-account`. The `workloads` sub-command is the high-value
output — it identifies COMPUTE TARGETS where compromising the workload
yields admin AWS access. `--admin-only` filters to confirmed
admin-with-path. `--admin-only` is a BOOLEAN flag (not a value flag) —
must NOT consume the next arg as its value.

### S4 — AWS env-var secret discovery

```
Engagement target: AWS account 'lab-account'. Goal: discover secrets leaked into Lambda / ECS / CodeBuild environment variables across all regions.
Use cloudfox aws env-vars with --all-regions. JSON output, loot to /session/cloudfox/.
```

**Watch:** Agent emits `cloudfox aws env-vars --profile=lab-account
--all-regions --output-format=json --output-directory=/session/cloudfox/`.
target=`lab-account`. Output JSON has rows per (Service, Resource, Region,
EnvVarName, EnvVarValue). After scan, agent should grep for
`password|secret|key|token|api` to surface findings.

### S5 — AWS env-var auth (no --profile, env-var-only target=null)

```
Engagement target: an AWS account scoped via STS session credentials in environment (AWS_ACCESS_KEY_ID, AWS_SECRET_ACCESS_KEY, AWS_SESSION_TOKEN are set in the engagement environment).
Use cloudfox aws inventory without --profile (rely on env-var auth). JSON output, loot to /session/cloudfox/.
```

**Watch:** Agent emits `cloudfox aws inventory --output-format=json
--output-directory=/session/cloudfox/` (NO --profile). target_extraction
returns null — none of the `--profile`/`--subscription`/`--project`/
`--kubeconfig` flags are present. The plugin's null-target informational-call
path applies: scope validation skips, AND the orchestrator MUST
pre-validate that the env credentials are in-scope. This is a CRITICAL
boundary — without engagement-state-level validation of AWS_ACCESS_KEY_ID,
the call is unguarded.

### S6 — Azure inventory

```
Engagement target: Azure subscription <subscription-id>. Auth via az login cached session (mounted at /session/.azure/).
Use cloudfox azure inventory on the specified subscription. JSON output, loot to /session/cloudfox/.
```

**Watch:** Agent emits `cloudfox azure inventory --subscription=<sub-id>
--output-format=json --output-directory=/session/cloudfox/`.
target=`<sub-id>` via `flag_value` rule for `--subscription`. Note: cobra
positional `azure` (provider) and `inventory` (sub-command) are consumed
before flag parsing. Azure sub-command surface is small (~5 sub-commands).

### S7 — failure: unknown sub-command (cobra dispatch error)

```
Engagement target: AWS account 'lab-account'. (The test — the agent will mistype.)
Use cloudfox aws prinicpals (note typo) on the lab-account profile.
```

**Watch:** Agent emits `cloudfox aws prinicpals --profile=lab-account` (note
typo: "prinicpals" not "principals"). cloudfox errors with `Error: unknown
command "prinicpals" for "cloudfox aws"` and prints the AWS sub-command
list. failure_signature matches `Error: unknown command`. Agent should
correct to `principals` and retry.

### S8 — failure: profile not found

```
Engagement target: AWS account scoped via 'nonexistent-profile'. (The test — this profile won't exist in /session/.aws/credentials.)
Use cloudfox aws inventory with --profile=nonexistent-profile. JSON output.
```

**Watch:** Agent emits `cloudfox aws inventory --profile=nonexistent-profile
--output-format=json`. cloudfox (or the underlying AWS SDK Go) errors with
`could not load profile` or `failed to get shared config profile,
nonexistent-profile`. failure_signature matches `could not load profile`.
Agent should add the profile to `/session/.aws/credentials` and retry.

### S9 — failure: ExpiredToken (STS session expired)

```
Engagement target: AWS account scoped via STS session creds — but the session has expired since the creds were captured.
Use cloudfox aws inventory with the captured (now-stale) AWS_ACCESS_KEY_ID + AWS_SECRET_ACCESS_KEY + AWS_SESSION_TOKEN env vars.
```

**Watch:** Agent emits `cloudfox aws inventory --output-format=json` (env-var
auth path; target=null). cloudfox errors with `ExpiredToken: The security
token included in the request is expired`. failure_signature matches
`ExpiredToken`. Agent should re-mint creds via `aws sts get-session-token`
or assume-role re-attempt with refreshed credentials.

---

## 3. Target-extraction adversarial cases (≥20)

The cloudfox `tool.yaml` declares 5 extraction rules, in order:

1. `flag_value` for `--profile` (parse_as: raw)
2. `flag_value` for `-p` (parse_as: raw)
3. `flag_value` for `--subscription` (parse_as: raw)
4. `flag_value` for `--project` (parse_as: raw)
5. `flag_value` for `--kubeconfig` (parse_as: raw)

`reject_flags`: empty (no flag shifts target outside argv).

`value_flags` covers all flags that take a value across all providers + sub-
commands — notably the target-bearing flags above plus `--region`/`-r`,
`--output-format`/`-o`, `--output-directory`, `--verbosity`/`-v`,
`--principal`, `--action`, `--resource`, `--user-data-search-term`,
`--tenant-id`, `--namespace`. Boolean flags (`--all-regions`, `-y`,
`--yes`, `--admin-only`, `--skip-adminonly`, `--help`, `--version`) are
listed in value_flags for parser correctness (skipped harmlessly).

### Happy-path cases

| # | Command (binary `cloudfox` omitted) | Expected target | Notes |
|---|---|---|---|
| 1 | `aws inventory --profile=default --output-format=json` | `default` | Standard AWS inventory. `flag_value` for `--profile` fires; equals-form `--profile=<value>`. |
| 2 | `aws inventory --profile default --output-format=json` | `default` | Same as #1 but space-form: `--profile <value>`. flag_value rule must handle both. |
| 3 | `aws all-checks -p prod --all-regions --output-format=json -y` | `prod` | Short-form `-p` flag for profile; flag_value rule for `-p` fires. `--all-regions` and `-y` are booleans. |
| 4 | `aws workloads --profile=lab-account --admin-only --output-format=json` | `lab-account` | `--admin-only` is a BOOLEAN — must NOT consume `--output-format` as its value. |
| 5 | `aws principals --profile=staging --region=eu-west-2 --output-format=json --output-directory=/session/cf/` | `staging` | Multiple value flags; `--profile` extraction wins (declared first). |
| 6 | `aws env-vars --profile=admin --all-regions --verbosity=3` | `admin` | `--verbosity=3` value consumed; profile extracted. |
| 7 | `aws iam-simulator --profile=audit --principal=arn:aws:iam::123:user/alice --action=s3:GetObject --resource=arn:aws:s3:::bucket` | `audit` | Multiple value-flags with ARN values; `--profile` fires. NOTE: principal/resource ARNs are NOT engagement-scope identifiers — they're auth-context, correctly NOT extracted. |
| 8 | `azure inventory --subscription=12345678-1234-1234-1234-123456789012 --output-format=json` | `12345678-1234-1234-1234-123456789012` | `flag_value` for `--subscription` fires. Subscription ID is the Azure engagement scope. |
| 9 | `gcp inventory --project=my-gcp-project --output-format=json` | `my-gcp-project` | `flag_value` for `--project` fires. Project ID is the GCP engagement scope. |
| 10 | `k8s pods --kubeconfig=/session/.kube/config --namespace=default --output-format=json` | `/session/.kube/config` | `flag_value` for `--kubeconfig` fires. Kubeconfig path is the k8s engagement scope. |
| 11 | `aws inventory --profile=prod -o json -v 2 -y` | `prod` | Short-form everywhere: `-o`, `-v`, `-y`. `--profile` (long form) wins because declared. NOTE: long-form `--profile` matches even when other flags use short form. |
| 12 | `aws all-checks --profile=lab --all-regions --output-format=csv --output-directory=/session/cloudfox/ --verbosity=2 --skip-adminonly -y` | `lab` | Long mixed flag set — value flags + booleans. `--profile` extracted; all booleans (`--all-regions`, `--skip-adminonly`, `-y`) don't consume next args. |
| 13 | `aws --profile=default inventory --output-format=json` | `default` | Profile flag BEFORE the sub-command (cobra accepts both orderings). flag_value for `--profile` still fires. |
| 14 | `aws inventory --profile=name-with-dashes --output-format=json` | `name-with-dashes` | Profile names can contain hyphens. Raw extraction. |
| 15 | `aws inventory --profile=default --region=us-east-1 --output-format=json` | `default` | --region is a value flag — consumed; profile extracted. NOTE: `--region` value `us-east-1` LOOKS LIKE a target identifier but isn't. |

### Adversarial — value_flag traps & cobra edge cases

| # | Command | Expected | Notes |
|---|---|---|---|
| F1 | `--help` | `target=null` | Top-level help. tool_runner bypasses scope check. |
| F2 | `aws --help` | `target=null` | AWS provider help — only positional is `aws` (provider). No `--profile`, target=null. |
| F3 | `aws inventory --help` | `target=null` | Per-sub-command help. |
| F4 | `--version` | `target=null` | Version flag. |
| F5 | `aws inventory --profile=default --region=us-west-2` | `default` (NOT `us-west-2`) | `--region` value is consumed by value_flags; profile extracted. CRITICAL: regions LOOK LIKE engagement-scope strings. |
| F6 | `aws inventory --profile=default --output-directory=/session/cloudfox/` | `default` (NOT `/session/cloudfox/`) | `--output-directory` value is a path; consumed by value_flags. |
| F7 | `aws inventory --profile=default --output-format=json` | `default` (NOT `json`) | `--output-format` value is `json`; consumed. |
| F8 | `aws inventory --profile=default --verbosity=3` | `default` (NOT `3`) | Numeric value flag consumed. |
| F9 | `aws iam-simulator --profile=audit --principal=arn:aws:iam::123:user/alice --action=s3:GetObject` | `audit` (NOT principal ARN, NOT action) | Multiple value-flags; `--profile` declared first wins. Principal ARN COULD be confused for a target but value_flags catches `--principal`. |
| F10 | `aws iam-simulator --profile=audit --resource=arn:aws:s3:::very-sensitive-bucket` | `audit` (NOT resource ARN) | Resource ARN consumed by `--resource` value flag. |
| F11 | `aws instances --profile=lab --user-data-search-term=password` | `lab` (NOT `password`) | `--user-data-search-term` value is `password`; consumed. |
| F12 | `aws inventory -p default -o json -v 2` | `default` | All short-form; `-p` declared as `flag_value` rule wins. Short-form `-o` and `-v` consumed by value_flags. |
| F13 | `aws inventory -p=default -o=json` | `default` | Equals-form on short flags (cobra accepts). flag_value for `-p` must handle equals-form. |
| F14 | `aws inventory --all-regions --profile=default` | `default` | `--all-regions` is BOOLEAN — must NOT consume `--profile=default` as its value. value_flags lists it as boolean for parser correctness. |
| F15 | `aws workloads --admin-only --profile=lab` | `lab` | `--admin-only` is BOOLEAN. value_flags lists for correctness. |
| F16 | `aws inventory --skip-adminonly --profile=audit` | `audit` | `--skip-adminonly` is BOOLEAN. |
| F17 | `aws all-checks -y --profile=prod` | `prod` | `-y` (yes) is BOOLEAN. |
| F18 | `aws inventory` (NO flags) | `target=null` | Cobra runs `inventory` sub-command but no profile = no auth. cloudfox errors at runtime; target_extraction correctly returns null. |
| F19 | `aws inventory --output-format=json` | `target=null` | NO --profile = env-var auth path. target_extraction returns null because no flag_value matched. The plugin's null-target informational-call path applies. |
| F20 | `azure inventory --subscription=12345 --tenant-id=67890` | `12345` | Both `--subscription` and `--tenant-id` are value flags; `--subscription` declared first wins. `--tenant-id` value consumed by value_flags. |
| F21 | `gcp inventory --project=my-project --output-format=json` | `my-project` | `--project` is the GCP scope. |
| F22 | `k8s pods --kubeconfig=/session/.kube/config --namespace=production` | `/session/.kube/config` | `--namespace` is a value flag; consumed. |
| F23 | `aws inventory --profile=default --profile=other` | `default` (FIRST occurrence wins, per typical cobra/argparse semantics) | Duplicate `--profile` — flag_value rule extracts the FIRST occurrence. cobra itself takes the LAST (overwrites). DOCUMENTED EDGE CASE: target_extraction != cobra's effective profile. The plugin should warn or error on duplicate target-bearing flags. |
| F24 | `aws inventory --profile=default --subscription=fakesub` | `default` (--profile wins, declared first) | Both flags present — declaration order in target_extraction defines precedence. |
| F25 | `aws principals --profile=audit --include-detectors=foo` | `audit` | Spurious flag `--include-detectors` (which is a TRUFFLEHOG flag, not cloudfox) — cobra would error at parse time, but for argv extraction the LLM might emit it by mistake. value_flags doesn't list it; the trailing `=foo` is part of the same token, so no consumption issue. `--profile` extraction still works. |
| F26 | `aws inventory --region=us-east-1 --profile=default` | `default` | Region BEFORE profile in argv. Order doesn't matter for flag_value rule — scans whole argv. |
| F27 | `aws iam-simulator --profile=audit --principal=alice --action=ec2:DescribeInstances --resource='*'` | `audit` | Resource value is the literal `*` (all resources). Consumed by `--resource` value flag. |
| F28 | `aws inventory --profile=acct-with-equals=in-name` | `acct-with-equals=in-name` | Profile name with literal `=` character. Equals-form `--profile=value` parses everything after first `=` as value. NOTE: literal `=` in profile names is uncommon but valid in AWS profile naming rules. |
| F29 | `azure inventory --subscription "12345 with spaces"` | `12345 with spaces` | Subscription ID with spaces (uncommon but possible if user typed it wrong). Argv-level the value is one token. |
| F30 | `aws inventory --profile=default -p override` | `default` (FIRST flag_value rule wins — `--profile` declared before `-p`) | Both `--profile` and `-p` set with different values — `--profile` declared first in target_extraction wins. cobra would take whichever it parses last. DOCUMENTED EDGE CASE. |

### Happy-path cases — null-target (env-var auth)

| # | Command | Expected | Notes |
|---|---|---|---|
| H1 | `aws inventory --output-format=json` (with AWS_* env vars set) | `target=null` | env-var auth path; no flag_value matches. Plugin null-target informational-call path applies. SAFE — orchestrator pre-validates env creds. |
| H2 | `aws all-checks --all-regions -y` (env-var auth) | `target=null` | Same as H1; env-var auth, all-regions sweep. |
| H3 | `azure inventory` (with AZURE_* env vars set) | `target=null` | Azure env-var auth. NOTE: Azure has no env-var that maps to `--subscription` directly — typically you'd still pass `--subscription` flag. If omitted, cloudfox uses the default subscription from `az account show` (cached session). |
| H4 | `gcp inventory` (with GOOGLE_APPLICATION_CREDENTIALS set) | `target=null` | GCP service-account JSON auth. The SA key file's project_id field is used; no `--project` flag = target=null. |
| H5 | `k8s pods --namespace=default` (with KUBECONFIG env var set) | `target=null` | k8s env-var auth via KUBECONFIG. No `--kubeconfig` flag = target=null. NOTE: this does fire a flag_value rule MISS (correctly). |

---

## 4. Failure-signature live-verify cases (≥3)

| # | Layer | Test | failure_signature `signal` | Status |
|---|---|---|---|---|
| 1 | AWS API | `aws inventory --profile=lab` (where the profile's IAM principal lacks `iam:ListUsers`) | `AccessDenied` | PENDING live verify (needs lab account with limited principal) |
| 2 | Auth | `aws inventory` (NO --profile, NO AWS_* env vars set) | `no valid credential` OR `NoCredentialProviders` | PENDING live verify |
| 3 | Auth | `aws inventory --profile=lab` (where /session/.aws/credentials exists with `aws_access_key_id = AKIAIOSFODNN7EXAMPLE` and bogus secret) | `InvalidClientTokenId` OR `SignatureDoesNotMatch` | PENDING live verify (offline — no real AWS API needed for auth pre-check) |
| 4 | Auth | `aws inventory` (with AWS_SESSION_TOKEN that has expired) | `ExpiredToken` | PENDING live verify (mint short-TTL session, wait for expiry) |
| 5 | Profile | `aws inventory --profile=nonexistent-profile` | `could not load profile` OR `failed to get shared config profile` | PENDING live verify |
| 6 | Argument | `aws prinicpals --profile=lab` (typo: prinicpals) | `Error: unknown command` | PENDING live verify |
| 7 | Argument | `aws inventory --profile=lab --bogus-flag=value` | `unknown flag` | PENDING live verify |
| 8 | Argument | `cloudfox lab --profile=lab` (missing provider — `lab` isn't a provider) | `Error: unknown command` | PENDING live verify |
| 9 | Region | `aws principals --profile=lab --region=us-fake-99` | `InvalidRegion` OR `region us-fake-99 is not valid` | PENDING live verify |
| 10 | Region | `aws principals --profile=lab --all-regions` (where one region is opt-in-required and not enabled) | `OptInRequired` (per-region; cloudfox continues with other regions; logged not exit-error) | PENDING live verify |
| 11 | Quota | `aws all-checks --profile=lab --all-regions` against a HEAVILY-throttled account | `Throttling` OR `RequestLimitExceeded` (cloudfox backs off; eventually completes — don't kill) | PENDING — needs throttled-account fixture |
| 12 | Network | `aws inventory --profile=lab` in air-gapped container (no outbound 443) | `no such host` OR `connection refused` OR `context deadline exceeded` | PENDING live verify (air-gap container) |

### Layer diversity (SKILL #11) — achieved

7 distinct verifiable layers exercised:
1. **AWS API permissions** — AccessDenied
2. **Auth (creds)** — no valid credential / InvalidClientTokenId / ExpiredToken
3. **Profile resolution** — could not load profile
4. **Argument (sub-command)** — unknown command
5. **Argument (flag)** — unknown flag
6. **Region** — InvalidRegion / OptInRequired
7. **Network/DNS** — no such host / connection refused

SKILL #11 minimum (5 distinct layers) is met across the failure_signatures in
tool.yaml.

---

## 5. Open questions

1. **Credential management strategy for cloud tools** — cloudfox is the
   first OpenSploit tool that operates on cloud accounts via real
   credentials (not network targets). The credential lifecycle questions
   are NOT cloudfox-specific — they apply to all cloud tools (aws CLI,
   pacu, prowler, az, gcloud, kubectl):
   - WHERE do captured AWS creds live? Per-engagement
     `/session/.aws/credentials` with HOME=/session is one option;
     env-var injection from engagement state is another.
   - WHEN does scope validation happen for env-var auth? target_extraction
     returns null; null-target informational-call path skips scope
     validation. The orchestrator MUST validate AWS_ACCESS_KEY_ID is in-
     scope before invocation — but this is engagement-state policy, not
     tool-plugin policy.
   - HOW are STS session expirations handled? cloudfox returns
     `ExpiredToken` and bails; the orchestrator should detect this signal
     and either re-mint creds (if assume-role chain is configured) or
     prompt the user. Currently no automatic re-mint.

   Defer to the upcoming "cloud tool family" requirements doc. cloudfox's
   tool.yaml documents the auth surface; cross-tool policy is out of scope
   here.

2. **Multi-provider dispatch in a single call** — cloudfox uses a
   provider-then-sub-command cobra structure. There's no single call that
   spans aws + azure + gcp simultaneously. Each provider is a SEPARATE
   call. Should the agent be guided to chain calls (one cloudfox call per
   provider) or is sequential dispatch handled at the agent-prompt level?
   Currently no tool-yaml-level guidance — defer to agent-prompt
   "sequential cloud sweep" pattern.

3. **`--output-directory` persistence vs ephemeral** — cloudfox writes
   loot files to the directory. Without `--output-directory=/session/...`,
   loot lands in `~/.cloudfox/cloudfox-output/` INSIDE the container,
   which evaporates on container exit. The default is ephemeral. The
   tool.yaml gotchas section calls this out, but should `--output-directory`
   be auto-injected by the plugin? Defer to plugin-side argv mutation
   policy. Currently the LLM must remember to pass it (every usage_pattern
   includes it).

4. **Sub-command surface drift** — Bishop Fox adds new AWS sub-commands
   periodically (e.g., `sso`, `cloudformation` were added in recent
   releases). The list in this tool.yaml is verified for the current Kali
   apt build. When upstream adds new sub-commands, the LLM may emit them
   based on training data even if cloudfox doesn't recognize them yet
   (or vice versa). failure_signature `Error: unknown command` catches
   this. Question: should the tool.yaml include a "known sub-command set
   as of <date>" hint in usage_patterns? Currently only mentioned in the
   header comment. Could add a `aws_subcommands:` field.

5. **`pmapper` integration** — the AWS `pmapper` sub-command runs Bishop
   Fox's wrapper around the open-source PMapper tool (a separate AWS
   privesc-graph tool). cloudfox's `pmapper` requires PMapper to be
   installed in the container (it's a Python tool). The Dockerfile
   currently does NOT install PMapper — `cloudfox aws pmapper` will
   error with "pmapper not found in PATH" or similar. Question: should
   PMapper be added to the Dockerfile, OR should `pmapper` be excluded
   from the recommended sub-command list? Currently mentioned in the
   header comment but not flagged loudly. Defer to a Wave 9 follow-up
   (build-time Dockerfile decision).

6. **Output-format default mismatch** — the legacy mcp-server.py defaults
   to `output="wide"` (which maps to `--output-format=table`). But the new
   kind:cli usage_patterns ALL prefer `--output-format=json` for tooling.
   This is a HARD divergence: agents using the old method-call path
   (`run` method) get table; agents using the new run_cli path get json
   (when they remember to pass --output-format). Question: is this
   intentional? Yes — kind:cli is the new default, and the LLM writes
   argv directly with `--output-format=json` per usage_patterns. The
   legacy method handler is preserved as the rollback path (SKILL #21),
   not the recommended path.

7. **Token / cred redaction in argv audit logs** — cloudfox does NOT take
   `--access-key=AKIA...` or `--secret-key=...` flags (no creds in argv —
   confirmed in mcp-server.py and cloudfox --help). All cred flow is via
   env vars or ~/.aws/credentials. So the audit log is naturally
   cred-clean for cloudfox. UNLIKE trufflehog where `--token=ghp_...`
   could leak in argv. Confirmed safe.

8. **Legacy pre-flight allowlist regression** — the legacy
   mcp-server.py maintained a hardcoded `CLOUDFOX_COMMANDS` list of 32
   AWS sub-commands and rejected any `command` value not in that list
   BEFORE shelling out to cloudfox. The new kind:cli path has no such
   client-side gate — argv goes straight to cobra, and typos surface as
   `Error: unknown command` (caught by failure_signatures). This is an
   intentional architectural simplification with two consequences:
   (a) **Loss**: no fast-fail on typo; the agent burns one cloudfox
   spawn (~1-2s of container startup) before learning the sub-command
   is wrong.
   (b) **Gain**: new upstream sub-commands (e.g., `all-checks`, `sso`,
   `cloudformation`) work out-of-the-box without updating the wrapper.
   The legacy list missed `all-checks` and `sso` entirely — agents on
   the legacy path could not invoke them. The kind:cli path closes
   this drift gap.
   Defer to the Wave-9 sub-command-drift hint discussion (open
   question #4) — if drift becomes a recurring failure mode, an
   `aws_subcommands:` field could re-introduce a soft allowlist for
   the LLM-prompt builder (without enforcing rejection).

9. **Output-format default drift** — the legacy default was
   `output="wide"`, translated to `-o wide` in the cloudfox argv.
   Upstream cloudfox accepts only `table | csv | json | brief` — `wide`
   is NOT a documented value. On older cloudfox builds this silently
   fell back to table; on current builds it may error with `unknown
   output format`. The kind:cli usage_patterns ALL pass
   `--output-format=json` explicitly. The legacy method handlers (run,
   list_commands) preserved as rollback path inherit the broken
   `wide` default — if rollback is ever exercised, the run method
   should be patched to default to `table` (or just pass through
   without setting `-o`). Currently flagged in tool.yaml gotchas; no
   code change applied (additive-only constraint).

10. **AWS_DEFAULT_REGION env-var leakage from legacy run method** —
    the legacy mcp-server.py set `env["AWS_DEFAULT_REGION"] = region`
    AND emitted `-r <region>` on the argv. The two are redundant;
    `--region` on argv takes precedence over the env var. Under
    kind:cli, the LLM picks one mechanism (almost always `--region`
    on argv). The environment block in tool.yaml documents the env
    var for completeness but the kind:cli path should not rely on it.
    Note: when AWS_DEFAULT_REGION is set in the container baseline
    (e.g., from engagement-state credentials), it remains the fallback
    for argv calls that omit `--region`. This is correct behavior and
    matches the legacy run method's effective resolution order
    (argv > env > us-east-1 default). No change needed.

---

## 6. Hand-off

- **Tool**: cloudfox (kind:cli)
- **Status**: tool.yaml authored end-to-end (kind:mcp → kind:cli);
  scenarios.md written. Dockerfile updated to use `python3-full` on
  Kali base (replacing `python3 python3-pip python3-venv`). mcp-server.py
  untouched (auto-inherits run_cli; rollback path via 2 legacy methods:
  run, list_commands). No legacy/cruft files (no
  target_extraction_tests.md, failure_signature_tests.md, or __pycache__/).
- **Image**: `ghcr.io/silicon-works/mcp-tools-cloudfox:latest` — needs
  rebuild during Wave 9 batch to pick up mcp-common 0.3.0 and the
  Dockerfile python3-full change. The cloudfox binary is downloaded
  directly from BishopFox's GitHub release (current pin: latest); the
  Dockerfile fetches the linux-amd64.zip and installs to /usr/local/bin.
- **Live-verify pending**: paste S1-S9 against a real lab AWS account.
  S1 (inventory), S3 (workloads), S4 (env-vars) are the highest-value
  validation cases — they exercise the most-used sub-commands. S5
  (env-var auth, target=null) validates the null-target pathway. S7
  (typo) and S8 (missing profile) validate failure_signatures. S9
  (ExpiredToken) requires waiting for STS session expiry (15min-1h
  depending on token TTL).
- **Wave 7.9 — third sub-command-architecture migration**: cloudfox is
  the third Tier A tool with sub-command argv shape, after trivy
  (Wave 7.5) and trufflehog (Wave 7.7). The structural difference vs.
  trufflehog: cloudfox's target is ALWAYS a flag value (--profile /
  --subscription / --project / --kubeconfig); never a positional. The
  provider + sub-command positionals are consumed by cobra dispatching
  and NOT extracted as targets. This is cleaner than trufflehog (where
  target location varies between positional and flag value across
  sub-commands).
- **Cred safety**: cloudfox does NOT accept credentials in argv (verified
  via cloudfox --help and the legacy mcp-server.py). All auth flows via
  env vars or ~/.aws/credentials profile files. The audit log is
  naturally cred-clean — no token redaction needed (UNLIKE trufflehog).
- **Null-target scope**: when --profile is omitted (env-var auth),
  target_extraction returns null. Plugin's null-target informational-call
  path applies — orchestrator MUST pre-validate env credentials are
  in-engagement-scope BEFORE invocation. This is the most important
  policy boundary for cloudfox.
- **Wave 9 follow-ups**: (1) decide whether to bundle PMapper in the
  Dockerfile for `cloudfox aws pmapper` support; (2) verify the
  Dockerfile rebuild produces a binary that matches the help text in
  this tool.yaml (sub-command surface drift check).

Authored: 2026-04-25.
