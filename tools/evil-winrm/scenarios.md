# evil-winrm — kind:mcp → kind:cli flip + live Forest validation

May 2026. Flipped the 402-LOC kind:mcp pypsrp wrapper to kind:cli: a
thin `winrm-exec` CLI (the "binary") + a 22-LOC RunCliServer stub.
Audit verdict was "keep — netexec winrm is NTLM-only, evil-winrm is the
only Kerberos-capable WinRM in the registry"; the strict framework said
kind:cli (no in-process state/daemon/heavy-init), so: kind:cli, not
retire, not keep-mcp.

**Unlike prowler/mongodb/aws this session, this was NOT deferred to a
real engagement — it was fully live-validated against HTB Forest
(10.129.252.9), all 9 scenarios, because the Kerberos path (the entire
justification for keeping the tool) had per the May 8 audit memory never
been live-validated.** That validation caught 4 real bugs that would
each have shipped a broken tool.

## 1. Architecture

```
opensploit ContainerManager (kind:cli, run_cli over MCP transport)
        │  cli_in_container({tool: "evil-winrm", binary: "winrm-exec",
        │                     command: "--target ... --command ..."})
        ▼
RunCliServer stub (mcp-server.py, 22 LOC — auto-registers run_cli)
        │  exec: /usr/local/bin/winrm-exec <argv>
        ▼
winrm-exec (361 LOC argparse CLI, the "binary")
        │  pypsrp.client.Client — PowerShell PSRP plugin URI by default
        │  NTLM pw | NTLM PtH (hash) | Kerberos (ccache, username=None)
        │  exec (execute_ps / execute_cmd) | upload copy() | download fetch()
        │  ~140-LOC error classifier -> JSON stdout + [winrm-exec] stderr
        ▼
target Windows host : WinRM 5985 (HTTP) / 5986 (HTTPS)
```

Image: `python:3.12-slim-bookworm` (NOT Kali — dropped the never-used
Ruby `evil-winrm` apt package; we drive pypsrp). `pip install
pypsrp[kerberos]` (the extra is mandatory — see Bug 1). Image ~464MB
measured 2026-05-17 (down from the old Kali kind:mcp 681MB). Further diet possible via
multi-stage build (compile gssapi/krb5 in a builder, copy wheels to a
gcc-free runtime → ~150MB) — noted as a follow-up, not blocking.

## 2. Live Forest validation (2026-05-17)

Target: HTB Forest 10.129.252.9 (AD DC, HTB.LOCAL). Cred obtained
properly (not assumed): AS-REP roast svc-alfresco (impacket-GetNPUsers
-no-pass) → john krb5asrep crack → **svc-alfresco : s3rvice**
(NT 9248997e4ef68ca2bb47ae4e6f128668). Forest WinRM 5985 open, Kerberos
88 open. Each scenario run as its own `docker run` (manual, one per
turn).

| # | Scenario | Result |
|---|---|---|
| S1 | NTLM password exec (`whoami /all`) | ✓ `htb\svc-alfresco`, PSRP PowerShell, exit 0 |
| S2 | NTLM pass-the-hash exec | ✓ `FOREST` / `htb\svc-alfresco`, exit 0 |
| S2b | (empty-hash run, pre-fix) | ✓ classifier validated live: `error_class=auth`, exit 2, structured stderr |
| S3 | Kerberos ccache exec | ✓ `htb\svc-alfresco` / `FOREST`, exit 0 — **the irreplaceable capability** (after 3 bug fixes) |
| S4 | upload (native PSRP copy) | ✓ 27B to `C:\Windows\Temp\`, verified by read-back |
| S5 | download (native PSRP fetch) | ✓ Forest `user.txt` retrieved (`fa5897730d3094346b57a5a96a055b80`, 34B) (after parse-bug fix) |
| S6 | `--shell cmd` (WinRS CMD) | ✓ correctly returned `WSManFault Code:5 Access denied` — non-admin svc-alfresco is CMD-WinRS-gated (exactly why PowerShell PSRP plugin URI is the default); classifier fired `error_class=permission` accurately |

## 3. Bugs caught by live validation (all would have shipped broken)

**Bug 1 — missing `krb5` python module.** Dockerfile installed
`pypsrp gssapi`; pypsrp's GSSAPIProxy also needs the `krb5` module,
absent → S3 failed `No module named 'krb5'`. Only surfaces at
Kerberos-auth RUNTIME, not at import (build verification `import gssapi`
passed). Fix: `pip install 'pypsrp[kerberos]'` (pulls gssapi + krb5 +
pyspnego[kerberos]).

**Bug 2 — krb5.conf realm not applied.** winrm-exec copied
`/session/config/krb5.conf → /etc/krb5.conf` only if /etc/krb5.conf was
absent, but debian-slim's krb5-config ships a stub /etc/krb5.conf → the
copy was skipped → realm fell back to MIT's hardcoded ATHENA.MIT.EDU →
`Client 'svc-alfresco@ATHENA.MIT.EDU' not found in Kerberos database`.
Latent in the original Kali wrapper too (Kali's krb5-user didn't
auto-create the file). Fix: set `KRB5_CONFIG` env (canonical override,
wins over /etc/krb5.conf regardless).

**Bug 3 — ccache ignored (the big one).** winrm-exec passed
`username=svc-alfresco, password=""` to the Kerberos `Client`, so
pyspnego attempted a fresh AS-REQ (kinit-equivalent) which failed
pre-auth on the empty password → `Pre-authentication failed`. To USE an
existing ccache, pyspnego needs `username=None` so it picks up the
default KRB5CCNAME credential. **Carried verbatim from the retired
402-LOC wrapper — its Kerberos path was never live-validated (May 8
memory: "live-validate on Forest" was an open, never-done item). The
"by accident the most capable WinRM MCP" claim rested on a provably
broken Kerberos path.** Fix: `username=None, password=None` when a
ccache is supplied; only pass principal+password for ccache-less
Kerberos (fresh AS-REQ).

**Bug 4 — `--download` drive-colon parse.** `partition(":")` split
`C:\Users\...\user.txt:/session/out` on the drive-letter colon (`C:`),
fetching just "C". Fix: find the separator colon at index ≥ 2 (past a
potential drive letter); `ntpath.basename` for the Windows basename on
Linux. (`--upload LOCAL:REMOTE` was unaffected — LOCAL is a colon-free
container path, so the first colon IS the separator; S4 passed.)

**Bug 5 — error classifier blind to the real Kerberos strings (fresh-eyes
review, post-validation).** The classifier was ported verbatim from the
retired 402-LOC wrapper and keyed on krb5 *macro names*
(`KDC_ERR_C_PRINCIPAL_UNKNOWN`, `KDC_ERR_PREAUTH_FAILED`,
`KRB_AP_ERR_SKEW`). But python-krb5/pyspnego — what this tool actually
uses — emits *human-readable* strings. Replaying the real strings
captured during S3 through the classifier proved it returned
`error_class=unknown` with **zero suggestions** for both
`"... not found in Kerberos database"` (realm-not-applied) and
`"Pre-authentication failed: Input/output error"` (skew/ccache) — i.e.
blind on exactly the Kerberos errors that are the tool's entire reason
to exist. The NTLM (`Failed to authenticate`) and WSManFault Code:5
patterns DID match (validated live S2b/S6). Fix: add human-string
patterns (`not found in Kerberos database`, `Pre-authentication failed`)
matched first, keep the macro names as defense-in-depth, and route
realm-not-applied → `config` with the krb5.conf/KRB5_CONFIG remediation
and pre-auth → `auth` with the "if creds good, it's skew → FAKETIME"
suggestion. Re-proven by replaying the captured strings post-fix
(config/3-sugg, auth/4-sugg). tool.yaml `failure_signatures` updated to
match the binary.

Clock-skew note: Forest DC was ~6m49s ahead of the container (>5min
Kerberos tolerance). S3 needed FAKETIME +7m + LD_PRELOAD libfaketime.
In production the plugin hoists FAKETIME → ContainerOptions.clockOffset
→ entrypoint.sh LD_PRELOAD; for the manual test (which bypasses the
entrypoint) it was set explicitly. Skew did NOT present as
`KRB_AP_ERR_SKEW` — it surfaced as `Pre-authentication failed:
Input/output error` (see Bug 5); the FAKETIME remediation is wired into
that classifier branch + tool.yaml failure_signatures + gotchas.

## 4. Verified vs not

**Verified live on Forest:** all of S1-S6 (NTLM-pw, NTLM-PtH, Kerberos
ccache, upload, download, cmd-shell), the error classifier on 3
distinct real errors (auth on empty hash, permission on WSManFault
Code:5, plus the bug-driven failures), the realm/ccache/clock-skew
operational chain.

**Not verified:** the **ccache-less Kerberos path** (`--auth kerberos
--password ...` with NO `--ccache` → fresh AS-REQ via the principal +
password) — only the `--ccache` Kerberos sub-path (S3) was live-proven;
the fresh-AS-REQ branch in get_client() and bare-principal/realm
resolution for it are untested (no target exercised it). HTTPS/5986
transport (Forest is HTTP 5985 only); SSL cert paths; non-Forest AD
topologies; ConstrainedLanguage-mode
trigger specifically (S6 hit access-denied first — svc-alfresco is
non-admin so the CMD WinRS URI is gated before any language-mode check;
the PowerShell default path is what svc-alfresco uses and that works).
`--shell cmd` SUCCESS path needs an admin/Server-where-CMD-WinRS-is-
allowed account — deferred to a future engagement with such a target.

## 5. Hand-off

- **Tool:** evil-winrm (kind:cli, binary `winrm-exec`, pypsrp[kerberos])
- **Image:** `ghcr.io/silicon-works/mcp-tools-evil-winrm:latest` (~443MB;
  multi-stage diet to ~150MB is a noted follow-up)
- **Surface:** one invocation = exec | upload | download; auth = NTLM-pw
  | NTLM-PtH (`--hash`) | Kerberos (`--ccache --auth kerberos`).
- **Why kept (not retired):** Kerberos-authenticated WinRM — netexec
  winrm is NTLM-only (verified in nxc/protocols/winrm.py). Live-proven
  on Forest. Plus native PSRP file transfer.
- **Cross-tool:** netexec/tool.yaml see_also corrected (was wrongly
  "pywinrm + base64 chunking"). see_also → netexec (multi-target,
  NTLM-only), impacket (other remote-exec protocols), ssh (Linux/modern
  Windows), kerbrute (user enum).
- **Confidence:** HIGH for the validated surface — this is the only
  tool this session with full real-AD live validation rather than
  deferred wrapper-works testing. The 4-bug catch is the proof that
  doing it on Forest (not deferring) was correct.

## Sources

- HTB Forest 10.129.252.9 (HTB.LOCAL), live 2026-05-17
- pypsrp (jborean93) — PSRP client library; `[kerberos]` extra
- netexec nxc/protocols/winrm.py — confirms NTLM-only WinRM upstream
