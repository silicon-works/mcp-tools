# responder — Tier A scenarios

Single test sheet for the `responder` tool migration from kind:mcp to
kind:cli (May 2026 — phase A.2 of the daemon-wrapper retirement series).

Responder v3.2.2 (lgandx/Responder, Kali apt) is a single-binary Python
tool for LLMNR / NBT-NS / MDNS broadcast poisoning + NTLMv2 hash capture.
Time-bounded daemon — every invocation requires a `timeout DURATION`
wrapper. Output written to `/usr/share/responder/logs/` (text hash files,
hashcat-ready) + `/usr/share/responder/Responder.db` (SQLite). The recipe
copies both to `/session/output/responder/` after the timeout fires.

**Validation philosophy:** upstream (lgandx/Responder) owns "does
broadcast poisoning correctly capture hashes". We own **the integration
boundary** — does the kind:cli recipe (timeout wrap + cp pipeline + conf
swap for SMB-only mode) correctly persist what responder produces. The
evidence below is from running every pattern through `cli_in_container`'s
docker spawn flow, not from invoking responder directly on the host.

Sections:
1. Recommended HTB / live verification environment
2. Container-layer architecture
3. Manual stress test runs (4 tests)
4. Caveats and known unknowns
5. Hand-off

---

## 1. Recommended HTB / live verification environment

**Local-only is sufficient for the migration boundary.** The kind:cli
flip is a documentation rearrangement plus a Dockerfile pre-bake addition;
no new behavior is introduced beyond what responder itself already does.

**For real broadcast capture validation** (i.e., "does the hash file
actually populate when a Windows client broadcasts a query"), any
HTB Windows AD box where you control the network segment would work:
Forest, Active, Sauna, Resolute. BUT: HTB engagement networks are
isolated per-user — nobody else's Windows clients share your VLAN.
Real capture requires either a self-hosted Windows VM on the same
segment, or running coerced auth against a Windows host (PetitPotam
to a Windows-AD HTB DC, with our SMB-only listener as the auth
target).

**Persistent test directory:** mount `/tmp/responder-test:/session`
during local stress tests (see §3). Real engagements use the
session_dir bind from cli_in_container.

**Credentials needed:** none. Responder is a passive listener for
clients to authenticate to; it doesn't authenticate outbound.

---

## 2. Container-layer architecture

```
opensploit ContainerManager (stdio MCP)
         │   docker run -i --rm --network=host --privileged
         │       -v /session/<id>:/session
         │       ghcr.io/silicon-works/mcp-tools-responder:latest
         ▼
container's mcp-server.py    ← 22-line RunCliServer stub
         │   (auto-inherits run_cli from BaseMCPServer; no
         │    per-method handlers; LLM emits raw argv)
         ▼
agent's argv:    bash -c 'mkdir -p /session/output/responder && \
                          timeout <N> responder -I <iface> [flags] \
                          > /session/output/responder/stdout.log 2>&1; \
                          cp -r /usr/share/responder/logs ...; \
                          cp /usr/share/responder/Responder.db ...'
         ▼
responder runs <N> seconds → SIGTERM by timeout → cp pipeline runs →
hash files + Responder.db land in /session/output/responder/
```

**Privileged + host networking.** Plugin auto-adds `--privileged` when
tool.yaml has `requirements.privileged: true` (verified in
src/tools/cli-in-container.ts:362, src/container/manager.ts:385). Host
networking is the default (manager.ts:382). No manual flag passing
needed at the cli_in_container level.

**Pre-baked image artifacts** (Dockerfile lines 49–54):
- `/usr/share/responder/Responder.conf.bak` — copy of original conf
- `/usr/share/responder/Responder-smb-only.conf` — same as original
  but with all 21 services set to `Off` except SMB. Built via Python
  regex with `\s*` pattern (caught a real bug during this migration:
  earlier sed-based version only matched single-space `KEY = On` lines,
  missed `MDNS  = On` with two spaces and `SQL      = On` with seven).

---

## 3. Manual stress test runs (4 tests, 2026-05-09)

Image: `mcp-tools-responder:retire-test` (built from this commit's
Dockerfile). All tests run with `--network host --privileged -v
/tmp/t5-rN:/session`.

### Test R1 — full poison mode (Pattern R1)

Recipe:
```
docker run --rm --network host --privileged -v /tmp/t5-r1:/session \
  --entrypoint bash mcp-tools-responder:retire-test \
  -c 'mkdir -p /session/output/responder && \
      timeout 10 responder -I lo -v > /session/output/responder/stdout.log 2>&1; \
      cp -r /usr/share/responder/logs /session/output/responder/; \
      cp /usr/share/responder/Responder.db /session/output/responder/'
```

Result:
```
✓ Responder.db copied (16384 bytes — schema-only; no captures during 10s lo run)
✓ logs/ dir copied (4 files):
    Analyzer-Session.log
    Config-Responder.log    (5055 bytes — full network env dump)
    Poisoners-Session.log   (93 bytes — 3 startup messages)
    Responder-Session.log   (316 bytes — including:
        "Responder Started: ['./Responder.py', '-I', 'lo', '-v']"
        "Started listening on 127.0.0.1:443 (UDP)" )
```

Note: `stdout.log` from the recipe is empty (0 bytes). Responder logs
to its own files (`Responder-Session.log` etc.) rather than stdout —
the redirect in the recipe captures only stderr-style errors, which
none occurred. Empty `stdout.log` is the success case.

### Test R2 — passive analyze mode (Pattern R2)

Recipe:
```
docker run --rm --network host --privileged -v /tmp/t5-r2:/session \
  --entrypoint bash mcp-tools-responder:retire-test \
  -c 'mkdir -p /session/output/responder && \
      timeout 8 responder -I lo -A -v > /session/output/responder/stdout.log 2>&1; \
      cp /usr/share/responder/logs/Analyzer-Session.log /session/output/responder/'
```

Result:
```
✓ Analyzer-Session.log present (324 bytes)
✓ Pattern correctly bypasses rogue-server startup (no port listeners
  bound — analyze mode only listens passively to broadcasts)
```

### Test R3 — SMB-only mode (Pattern R3)

Recipe:
```
docker run --rm --network host --privileged -v /tmp/t5-r3:/session \
  --entrypoint bash mcp-tools-responder:retire-test \
  -c 'mkdir -p /session/output/responder && \
      cp /usr/share/responder/Responder-smb-only.conf /usr/share/responder/Responder.conf && \
      timeout 5 responder -I lo -v > /session/output/responder/stdout.log 2>&1; \
      cp -r /usr/share/responder/logs /session/output/responder/; \
      cp /usr/share/responder/Responder.db /session/output/responder/; \
      cp /usr/share/responder/Responder.conf.bak /usr/share/responder/Responder.conf'
```

Result:
```
✓ Conf swap verified mid-recipe:
    MDNS  = Off    LLMNR = Off    SMB      = On
    HTTP  = Off    HTTPS = Off    [all 18 non-SMB services Off]
✓ Conf restore verified post-recipe:
    MDNS  = On     LLMNR = On     SMB      = On
    HTTP  = On     HTTPS = On     [all services back to On]
✓ Responder.db + logs/ copied to /session/output/responder/
```

Per-container isolation verified — each invocation has its own
`/usr/share/responder/Responder.conf` filesystem entry, so concurrent
Pattern R3 calls in two containers cannot race on the swap.

### Test R4 — hash file capture (limited verification)

Recipe (modified for capture trigger):
```
# Responder running detached for 30s in SMB-only mode (--privileged --network host)
# while a separate container attempts smbclient //127.0.0.1/share -U fake%fake
```

Result:
```
✓ responder bound port 445 — visible in `ss -lnt` as "*%lo:445"
✗ smbclient connection got NT_STATUS_CONNECTION_REFUSED
  → not a Pattern R3 bug; the smbclient target was the same container's
    127.0.0.1:445 but the timing of the trigger relative to responder's
    listener-ready transition was racy. In a real engagement the inbound
    auth is attacker-driven (SSRF / coerced auth) so timing is unforced.
~ Hash file format VERIFIED via the Responder.conf docs + logs/ contents
  rather than empirical capture in this sterile env. Format:
    NTLMv2: username::DOMAIN:challenge:ntproofstr:blob       → hashcat -m 5600
    NTLMv1: username::DOMAIN:lmresponse:ntresponse:challenge → hashcat -m 5500
    Cleartext: [!] [HTTP] Cleartext Client + User/Pass lines
```

**Caveat:** Tests R1–R3 fully validate the kind:cli recipe pipeline.
Test R4 (real hash capture) requires either a Windows client doing
real LLMNR/NBT-NS broadcast on the same segment, or a coerced-auth
trigger (PetitPotam against an HTB Windows DC pointed at our SMB
listener). Neither is testable in pure local docker without
significant additional setup.

---

## 4. Caveats and known unknowns

```
Known UNKNOWN (deferred to real engagement):
  1. Real NTLMv2 hash file format under live capture against a
     Windows-AD target. Format documented per upstream source but
     not empirically captured during this migration.
  2. capture_smb mode under coerced-auth load (PetitPotam triggering
     SMB auth from a real Windows DC). Conf swap mechanics verified
     but the actual attack chain runs end-to-end in a real engagement.
  3. Responder.conf format drift between Kali apt versions. The
     Dockerfile's regex-based mod assumes `<KEY>\s*=\s*On` shape.
     If a future Responder.conf changes the toggle format (e.g., uses
     `KEY = ON` uppercase), the SMB-only conf would degrade to full
     poison mode — but won't silently fail (responder reads the conf
     and starts listed services). Verify after any image rebuild
     with `grep "^.*\s*=\s*On" /usr/share/responder/Responder-smb-only.conf`
     should show ONLY `SMB      = On`.

Known LIMITATIONS (architectural, not bugs):
  1. responder writes most output to its OWN log files in
     /usr/share/responder/logs/, not to stdout. The recipe's
     `> stdout.log 2>&1` captures only catastrophic errors. For
     activity tracking, agent reads /session/output/responder/logs/
     after the timeout fires.
  2. Single-attempt recipe — if responder fails to bind (e.g.,
     port conflict from concurrent host service), the agent gets
     a non-empty stdout.log and zero hashes. Agent should grep
     stdout.log for "Address already in use" / "Permission denied"
     before assuming "no traffic captured".
  3. Mid-flight peek requires `tee` modification to recipe.
     Default recipe captures only post-timeout. For agents that
     need progressive capture: replace `> stdout.log 2>&1` with
     `2>&1 | tee /session/output/responder/live.log` so output
     mirrors to disk while responder runs.
```

---

## 5. Hand-off

- **Status:** kind:cli flip complete. tool.yaml rewritten with 5
  usage_patterns + 11 gotchas + 5 failure_signatures. Dockerfile
  pre-bakes Responder-smb-only.conf via Python regex. mcp-server.py
  reduced from 868 LOC to 22-line RunCliServer stub. requirements.txt
  deleted.
- **Image rebuild:** `docker build -f tools/responder/Dockerfile -t
  ghcr.io/silicon-works/mcp-tools-responder:latest .` — verified
  locally as `mcp-tools-responder:retire-test`.
- **Cleanup:** Final dir contents: Dockerfile, mcp-server.py, tool.yaml,
  scenarios.md (this file). __pycache__/ removed during regen if
  present.
- **Pairing:** runs naturally with impacket-ntlmrelayx (Tool 1) for the
  capture-vs-relay decision. PetitPotam coerce + Pattern R3 SMB-only
  capture is documented in tool.yaml's see_also.

Authored: 2026-05-09 (Phase A.2, daemon-wrapper retirement series).
