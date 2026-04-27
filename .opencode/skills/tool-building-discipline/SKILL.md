---
name: tool-building-discipline
description: Principles for building OpenSploit tooling — kind:cli registry entries, Python MCP server rewrites, container plumbing. Covers read-first authoring, one-at-a-time gating, container surface as contract, the test pyramid, manual-first verification, layer-diverse failure coverage, adversarial parser tests, real-target ground truth with matched targets, deployment-integrity discipline (cache invalidation, image-namespace alignment, sentinel modes), and hand-off discipline. Apply to any tool authoring or rewrite.
---

# Tool Building Discipline

How to build OpenSploit tooling that survives contact with real targets.
Covers kind:cli migrations (curl, sqlmap, impacket) and MCP server rewrites
(Playwright/browser stack, container manager). The same discipline applies —
testing and deployment are integral to building.

---

## Authoring

### 1. Read before write

Before authoring a single line, read every existing artifact:

- The vendor binary's `--help` and a spot-read of CLI source
- The current `mcp-server.py` (its argv shaping, stderr parsing, env vars)
- The current `Dockerfile` (base image, runtime quirks, custom entrypoints)
- The current `tool.yaml` (existing routing, triggers, capabilities)
- One or two real HTB writeups using the tool — ground patterns in actual
  workflows, not vendor docs
- The container manager / plugin code that will invoke the new artifact

You are extracting **operational knowledge** the existing code encoded
implicitly. The wrapper is going away; its knowledge moves into the new
artifact. Authoring without reading produces hallucinated patterns.

### 2. One thing at a time, no pre-authoring

Each iteration teaches the next:

- curl taught `parse_as: url_host`
- sqlmap taught CLI tools exit 0 on hard failures and `value_flags` is the
  security-critical defensive layer
- impacket taught multi-binary single-entry, case-sensitive binary names,
  `STATUS_NOT_SUPPORTED` for NTLM-disabled targets
- Playwright taught the chrome-vs-headless-shell VPN routing trade-off
  and the env-override container pattern

None would have been caught had they been authored in parallel. Strict
gating: finish one, learn what it taught, apply to the next. When tempted
to bundle, ask "what does *this* iteration teach me?" — if you can't
answer, you'll find out, but only if you finish before starting the next.

### 3. Build minimally — every layer needs a one-line justification

Drop layers when you can. Keep them only with documented reason.

- kind:cli migration drops the Python MCP server layer entirely.
- impacket Dockerfile kept `kalilinux/kali-rolling` (~1GB) over
  `debian-slim` (~300MB) because Debian lacks `impacket-scripts`.
  Documented trade-off, not laziness.
- libfaketime was REMOVED from the kind:cli image because
  `cli_in_container` doesn't pipe FAKETIME yet — don't carry layers
  whose upstream consumer doesn't exist.
- Playwright kept Xvfb + x11vnc + websockify because headed-mode VNC
  human-in-the-loop requires it; documented why it's inert in headless.

Rule: every layer carries a one-line justification adjacent to it
(Dockerfile comment, yaml comment, code comment). If you can't write
one, drop it.

### 4. The container surface IS the tool contract

The mount points, network mode, env propagation, working directory, and
user identity define what the tool can and can't do as much as the binary
does. Document them at the boundary that sets them.

- `WORKDIR /session` — every kind:cli tool gets a writable session dir.
  Tools that write loot anywhere else are violating contract.
- `--network=host` — standard for VPN-routed pentest tooling. Without it,
  tun0 routes don't resolve from inside the container.
- Env propagation is NOT automatic. `KRB5CCNAME`, `FAKETIME`, headed-mode
  toggles all need explicit `-e` from the caller. Don't assume the host
  shell's env survives the boundary.
- User identity: most images run as root inside the container (file
  ownership in `/session` will reflect that on the host). Document if you
  break this.
- Multi-binary tools omit top-level `CMD`; the caller selects per call.

When a tool needs a non-default surface (privileged, raw-socket cap,
custom DNS), it goes in `tool.yaml` `requirements:` and gets explicit
operator approval. Surfaces should never be implicit.

### 5. Match vendor reality, don't normalize

Mirror vendor quirks. Papering over hides bugs.

- Binary names: impacket has `impacket-secretsdump` (lowercase) AND
  `impacket-GetUserSPNs` (camelCase). Don't normalize. Document
  camelCase ones in `gotchas`.
- Flag spellings: `-output-file` vs `-outputfile`. Match what `--help`
  actually shows.
- Error formats: impacket's actual stderr for timeout is the lowercase
  phrase `timed out`, not `TimeoutError`. Match what's emitted.
- Vendor surprises: Hercules HTB returns `STATUS_NOT_SUPPORTED` for
  NTLM-disabled domains. Add a signature for it; don't translate.

When the vendor changes their string in the next release, your
live-verified test catches it. When you "translate", you've added a
layer that has to be re-translated and the bug surface is yours forever.

### 6. Document trade-offs at the decision point

The trade-off comment lives in the file that makes the trade-off — not
in a README, not in commit history.

```dockerfile
# Base: kalilinux/kali-rolling — Debian's python3-impacket lacks the
# `impacket-scripts` shim package that puts the binaries on PATH with
# the `impacket-*` names this tool.yaml references. Image is ~1GB vs
# ~300MB for debian-slim, but correctness > size for the pilot.
FROM kalilinux/kali-rolling
```

The reader hits this comment when about to question the choice. They
either agree, or have new information that updates the trade-off — and
they update the comment in the same commit. Trade-off stays in sync
with the code making it.

### 7. Encode operational knowledge in artifacts, not heads

When you discover a quirk, it goes somewhere version-controlled and
discoverable from the work area:

- Tool quirks → `gotchas:` in tool.yaml
- Failure modes → `failure_signatures:` with remediation paragraphs
- Trade-offs → comment in the file making the trade-off
- Open questions → dedicated section in the relevant test doc
- Cross-tool architectural findings → memory entries

Slack messages, commit messages, your own memory, and linked Jira
tickets do NOT count. The next person (often you in a month) will not
remember. Write it down where they will trip over it.

---

## Testing — integral to building

Build and test in the same loop. A tool that builds clean but hasn't
been verified against a real target is not built — it's drafted.

### 8. The test pyramid

```
              /\
             /E2E\              <- 1: agent-driven realistic task
            /------\
           / Live   \           <- 3+: real-target verification (HTB / VPN)
          / verify   \
         /------------\
        / Container    \        <- ~5: docker run smoke tests
       /  smoke         \
      /------------------\
     / Build + parse +    \     <- many: docker build, yaml schema,
    /  static checks       \         schema conformance, lint
   /------------------------\
```

Wide cheap base, narrow expensive top. Build pressure to push tests
DOWN the pyramid: a bug catchable by a schema check should not first
appear at live-verify. When something slips up, write the lower-tier
check that would have caught it.

But don't skip the top. A green pyramid bottom means nothing if
live-verify is missing. Real vendors ship surprises that synthetic
fixtures don't reproduce.

What lives at each tier, for both CLI tools and MCP server rewrites:

- **Tier 1 (build + static)** — image builds, yaml parses, schema
  conforms, lint passes, no accidental deletions of rollback artifacts.
  Run on every change.
- **Tier 2 (container smoke)** — `--help` returns clean, `--version`
  matches expected vendor version, `/session` is writable, declared
  binaries exist on PATH, network reachable from inside container.
  Run when the image changes.
- **Tier 3 (live-verify)** — failure_signatures triggered against real
  targets, parser rules exercised against adversarial inputs, security
  invariants verified. Run when behavior changes.
- **Tier 4 (agent E2E)** — one realistic positive task with the agent
  driving, three hallucination traps, observe trajectory. Run once at
  the gate.

### 9. Manual first, automate second

For every NEW test category, run it manually one at a time before
automating.

- One `docker run` per shell command, full output inline
- One `opencode run` per invocation — no `> file 2>&1` (block-buffers
  on regular stdout, looks like a hang)
- Inspect raw stdout, stderr, exit code, and resulting filesystem state
- *Then* write the assertion / pattern / test

Scripts that batch and summarize hide diagnostic detail. You will write
passing tests against the wrong invariant. **The user has flagged this
rule across multiple sessions.** Respect it.

When something surprises you mid-build, drop back to interactive single
commands. Don't try to debug from a log file dumped by an outer harness.

### 10. Trust nothing — verify against reality

- **Exit codes lie.** sqlmap and impacket both exit 0 on hard failures.
  Always pattern-match stderr.
- **Vendor docs lie or are stale.** `--help` is more current than the
  man page; CLI source is more current than `--help`.
- **Synthetic fixtures lie.** Vendor stderr changes between releases.
  Use real targets at live-verify.
- **Cached environments lie.** Old GHCR Playwright image had no
  entrypoint.sh / VNC stack despite the registry pointing to it;
  symptoms looked like a code bug. Always check what's *actually*
  running: `docker image inspect`, `docker run ... id`, the image
  digest, the registry tag your splice script wrote.
- **Host network ≠ container network.** Even with `--network=host`,
  container behavior under tun0 differs from the host process — chrome
  vs chrome-headless-shell, for example, can route differently to VPN
  IPs. Test the actual path the tool will use, in the container.
- **Your own assumptions lie.** Run the smallest reproduction and
  inspect raw output before designing on top of it.

The cost of verification is always less than the cost of debugging
a wrong mental model.

### 11. Layer diversity > test count

Five tests at the TCP layer is one test repeated five times. Better:

- 1 TCP-layer (refused / timed out)
- 1 DNS-layer (name not known)
- 1 protocol-layer (NTLM disabled / TLS handshake failed)
- 1 app-auth (wrong password / preauth failed)
- 1 authz (access denied / insufficient rights)

Five tests across five layers tells you the failure surface. Five
tests in one layer tells you the same thing five times. When designing
`failure_signatures`, walk down the network stack and pick one signal
per layer the tool can fail at.

Same applies to MCP server rewrites: one test for image init failure,
one for transport handshake, one for tool listing, one for invocation
failure, one for cleanup — not five for invocation.

### 12. Adversarial coverage

Don't only test happy paths. Design inputs to break the parser.

For `target_extraction` rules (kind:cli):
- Every `value_flag` whose value could be mistaken for a target —
  confirm the parser doesn't pick it
- Multi-target / file-ingest forms (`-r FILE`, `-l FILE`, `-m FILE`,
  `-g DORK`) — expected `target=null`
- Help / version / no-arg — expected `target=null`
- Two flags both target-shaped — document which wins and *why*
  (the *why* is the security invariant)

For output parsing (MCP server rewrites):
- Empty output
- Output >5KB (truncation, store-externally threshold)
- Non-UTF-8 / mixed encodings
- Crash / timeout / partial output

For auth flows (any tool that authenticates):
- Wrong password
- Disabled / locked-out / expired account
- Insufficient privilege
- Token / ticket expired

These are the cases that produce confusing field reports. Catch them
at live-verify.

### 13. Real targets at the top tiers — and pick the right one

HTB boxes for AD work, real web servers for web work, the actual VPN
for routing-sensitive code. Synthetic targets lie.

**Match the target to the behavior surface you're testing.** A
"passing" sqlmap test against a target with no SQLi is meaningless.
Picking the right target IS part of test design:

- Hercules (NTLM-disabled AD) for impacket — surfaces protocol-layer
  signals (`STATUS_NOT_SUPPORTED`) that vanilla AD targets miss
- Cap (Linux web app) for curl — exercises bare HTTP behavior
- Validation (Linux web app with injection) for sqlmap — actually has
  SQLi to find
- A clean VPN-up target with known reachable services for network-layer
  failure modes

The user will name the box and provide creds. Sometimes `/etc/hosts`
updates are needed; ask once if uncertain. Wrong target wastes time and
produces misleading green results — worse than a red one because
nobody knows to investigate.

### 14. Persistent test state for multi-step flows

Some tests need chained state across multiple invocations:

- impacket: `getTGT` writes a ccache to `/session`; `secretsdump -k
  -no-pass` reads it via `KRB5CCNAME`
- web sessions: login writes a cookie jar; subsequent requests reuse it
- multi-step exploits: stage 1 produces a token, stage 2 consumes it

The test runner's per-tool session dir is auto-cleaned per run. Don't
fight it — bypass it. Mount a persistent dir directly:

```sh
mkdir -p /tmp/imp-test
docker run --rm --network=host -v /tmp/imp-test:/session ...
```

Document the persistence requirement in the test doc, and clean the
persistent dir explicitly when starting fresh. Never test multi-step
flows by interleaving cleanup-vs-no-cleanup runs in the same session.

### 15. Fast iteration cycle

```
[Build]  →  [Smoke against real target]  →  [Inspect output]  →  [Improve]
   ↑                                                                  │
   └──────────────────────────────────────────────────────────────────┘
```

Each cycle in minutes, not hours. If a cycle is taking an hour:

- Live target too slow → use a closer one or pre-cache state
- Image rebuild too slow → use docker layer caching deliberately
- Output too noisy → add `-debug` / `--verbose` to the inner tool,
  not to your harness
- Verifying too much per cycle → narrow to one signal at a time

Speed of iteration is a quality input. Slow cycles produce more
hallucinated patches because you stop running them.

---

## Deployment integrity

Tools live across boundaries: local build → registry → tarball → cache
→ agent invocation. Each transition can introduce bugs. "Works in dev"
does not mean "works in pilot" does not mean "works in production".

### 16. Cache invalidation is part of every change

When schema, `kind`, or image changes, downstream caches need explicit
clearing. Forgetting one produces "looks fixed but isn't" bugs that
take hours to diagnose.

Caches that exist in this stack:
- LanceDB tool registry cache (`~/.opensploit/opensploit.lance/`) —
  rebuilds from `registry.yaml` on next start IF cleared
- Registry tarball + hash sidecar
  (`~/.opensploit/registry.lance.tar.gz`, `registry.sha256`) —
  short-circuits the YAML re-import path
- Docker layer cache — can serve stale `apt-get install` layers when
  package versions change
- Container manager session containers — long-lived, may pin an old
  image until session ends
- Embeddings (BGE-M3) on tool methods — re-run when descriptions change

The pilot-enable script clears the first two automatically. Production
deployments need their own equivalents. When you change tool.yaml
schema or `kind`, audit which caches now point to a stale snapshot and
clear them.

### 17. Image namespace alignment

Local build names (`mcp-test-<tool>`) and registry pointer paths
(`ghcr.io/silicon-works/mcp-tools-<tool>:latest`) are different
namespaces. The registry YAML points to the registry path; local pilot
splicing rewrites to the local tag. Without alignment, you can run a
green local image while the agent silently invokes the stale registry
image.

The Playwright image-mismatch incident: registry pointed to the GHCR
image (which had no entrypoint.sh and no VNC stack); local builds had
the right tag but were never used because the agent resolved the
registry path. Symptom looked like missing code; root cause was image
resolution.

When local builds must satisfy a registry-pointer path:
```sh
docker tag mcp-test-<tool>:latest ghcr.io/silicon-works/mcp-tools-<tool>:latest
```

Or rewrite the image field in the local registry (the pilot script
does this — read it before inventing a new pattern).

Always verify with `docker image inspect <pulled-name> | jq .Id` that
the running image is the one you built.

### 18. The build pipeline has its own contract

Tool authoring is upstream of CI scripts that the registry depends on
(`mcp-tools/scripts/build-registry.py`,
`mcp-tools/scripts/build-registry-lance.py`). When you add a field to
`tool.yaml`:

- Does the YAML→JSON ingest preserve it?
- Does the LanceDB embedding pipeline include it in the embedded text?
- Does the schema validator accept it (or is the validator lazy and
  the failure shows up only at agent-load time)?
- Does the registry hash sidecar pick up the change?

Add the field, run the relevant CI script locally against your tool,
inspect the output. The schema is enforced lazily — your tool can
build green and still fail at ingest. Verify upstream consumers before
declaring done.

### 19. Sentinel-mode deployment pattern

For reversible runtime configuration that affects multiple processes,
prefer sentinel files over env vars. The pilot mode pattern:

- `~/.opensploit/.pilot-mode` exists → registry is locally-spliced,
  remote-fetch is skipped
- Paired `enable-pilot-mode.ts` / `disable-pilot-mode.ts` scripts that
  do all the work (cache clearing, sentinel writing, splicing)
- One-line check in the consumer code (`if (existsSync(SENTINEL))`)

Why this beats env vars for cross-process state:
- Env vars don't survive process restarts unless persisted somewhere
- Multiple processes (CLI, server, sub-agents) all see the same
  sentinel state without coordination
- Reversibility is one file delete; no "did I unset that env var in
  every shell?" confusion

Reusable for any reversible-runtime-config beyond pilot mode (debug
mode, training-data capture, observer enabled). Use this pattern when
you need a knob that affects multiple processes and wants to be
reversible cleanly.

---

## Hand-off

### 20. Capture open questions, don't fix in scope

When building one thing surfaces a problem in another (DSL doesn't
handle bracketed IPv6, container manager doesn't pipe FAKETIME, vendor
behavior differs from docs), write it down — don't fix it.

- Add explicit "Open questions" section in the relevant artifact
- Name the case, expected behavior, observed behavior, recommended fix
- Move on

Two reasons: (1) scope creep destroys gating discipline; (2) the next
person needs the issue findable without re-discovery.

### 21. Preserve rollback until the new path is proven

Don't delete the old artifact during a migration:

- `mcp-server.py` stays in place during kind:cli pilot — rollback path
- Old Dockerfiles get updated, not deleted-and-recreated, until
  verified
- Old registry entries get superseded, not removed, until the new
  entries pass live-verify + at least one real agent task

Removal is one line of diff. Lose that property and rollback becomes a
research project.

### 22. Explicit hand-off message

When you finish a piece of work, the hand-off names:

- What was done — concrete artifacts produced
- Next gate — who picks it up and what they verify
- Open questions surfaced for the next stage

Example: "<tool> Phase 1 done — Dockerfile + tool.yaml + ≥3
live-verified failure_signatures + ≥20 target_extraction cases +
spliced into pilot registry. Ready for full-stack: tool_runner gate
with shape test, hallucination traps, realistic positive task. Open
questions in target_extraction_tests.md §Open questions."

If you can't summarize all three in 2-3 sentences, the work isn't
actually done — say what's left.

---

## When to apply

- About to build a new MCP server, kind:cli entry, container plumbing
  change, or any tool-adjacent component
- About to rewrite or refactor an existing one
- Reviewing someone else's tool work and want to know what to push
  back on

If your task does not involve building or modifying tooling, this
skill is not the right reference.
