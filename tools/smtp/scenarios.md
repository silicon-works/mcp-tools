# smtp — Tier A scenarios

Single test sheet for the `smtp` tool migration (kind:cli, multi-binary —
`swaks` + `smtp-user-enum`). Replaces the legacy split (`target_extraction_tests.md`
+ `failure_signature_tests.md`).

Sections:
1. Recommended HTB box for live verification
2. Narrative scenarios (paste into opensploit)
3. Target-extraction adversarial cases (≥20)
4. Failure-signature live-verify cases (≥3)
5. Open questions
6. Hand-off

---

## 1. Recommended HTB box

**Primary: Solidstate (10.10.10.51)** — Linux box with James 2.3.2 SMTP/IMAP
on ports 25 / 110 / 4555. Surfaces VRFY-style user enumeration cleanly and
banners as `JAMES SMTP Server 2.3.2`. Open relay behaviour also exposed for
the relay-test scenario. Retired box, image readily spawnable on HTB premium.

**Alternate: Mailing (10.10.11.14)** — Linux + hMailServer + Roundcube.
Exposes 25 / 587 / 110 / 143 / 993 / 995 with proper STARTTLS. Useful for
exercising the auth + TLS flag combinations.

**Standalone fallback (no HTB)**: spin up `vulhub/postfix-cve-2014-3566`
locally — provides a postfix MTA with VRFY enabled and known weak relay
config. Used historically when HTB lab access is unavailable.

Note: TLS-cert-error tests are NOT covered here because lab MTAs ship valid
or self-signed certs that swaks ignores by default (--tls-verify off). Re-run
those once a strict-cert lab target is available (see Open Questions).

---

## 2. Narrative scenarios (paste into opensploit)

### S1 — banner / EHLO probe (HELO-only)

```
Engagement target: 10.10.10.51 (HTB Solidstate, authorized).
Use the smtp tool to probe the SMTP banner and EHLO capabilities on port 25
without sending any actual mail. Save the transaction log to /session/solidstate-banner.txt.
Report: banner string, supported AUTH mechanisms (if any), STARTTLS support,
PIPELINING, SIZE limits.
```

**Watch:** Agent picks the `swaks` binary path with `--quit-after HELO`.
Argv shape: `swaks --server 10.10.10.51 --port 25 --quit-after HELO --ehlo
attacker.local --to x@target --from y@attacker --timeout 15`. First call
~3-5 s (container spawn + MCP handshake).

### S2 — VRFY user enumeration

```
Engagement target: 10.10.10.51 (HTB Solidstate, authorized).
Write the following usernames to /session/users.txt then use smtp-user-enum
via the smtp tool with VRFY method on port 25:
root, admin, james, mindy, mailer, postmaster, ftp, daemon, www-data,
nobody, test, mail, list, sshd, john.

Save the result to /session/solidstate-vrfy.txt. Report which usernames
exist on the server.
```

**Watch:** Agent picks the `smtp-user-enum` binary. Argv shape: `smtp-user-enum
-M VRFY -t 10.10.10.51 -p 25 -U /session/users.txt -w 10`. Agent first uses
the `write` tool to create /session/users.txt — NOT bash heredoc / echo.

### S3 — RCPT TO enumeration with domain (fallback when VRFY fails)

```
Engagement target: 10.10.10.51, authorized.
The server may have VRFY disabled on a more locked-down install. Re-run
the user enumeration using the RCPT TO method with domain `solidstate.htb`,
same userlist at /session/users.txt. Save to /session/solidstate-rcpt.txt.
```

**Watch:** Argv: `smtp-user-enum -M RCPT -t 10.10.10.51 -p 25 -U /session/users.txt
-D solidstate.htb -w 10`. Agent recognises -D is required for RCPT.

### S4 — Open-relay test (--quit-after RCPT)

```
Engagement target: 10.10.10.51, authorized.
Test whether the SMTP server is an open relay. Use swaks with --quit-after
RCPT, send from probe@attacker.local to relay-test@example.com (an external
domain that is NOT @solidstate.htb). Save the transaction to
/session/solidstate-relay.txt. Report whether the server accepted the
relay.
```

**Watch:** Argv: `swaks --server 10.10.10.51 --port 25 --to
relay-test@example.com --from probe@attacker.local --quit-after RCPT
--ehlo attacker.local --timeout 30`. Agent does NOT send DATA. Result line
shows either `250 OK` (open relay = finding) or `550 5.7.1 Relay access
denied` (closed = expected).

### S5 — Authenticated send on submission port 587 with STARTTLS

```
Engagement target: 10.10.11.14 (HTB Mailing, authorized).
Send an email through the submission port (587) with STARTTLS using the
credentials maya:floral.pa$$word. To: tony@mailing.htb, From:
maya@mailing.htb, Subject: "test from maya", Body: "test message".
Save the transaction to /session/mailing-auth-send.txt. Report whether
auth and delivery succeeded.
```

**Watch:** Argv: `swaks --server 10.10.11.14 --port 587 -tls --auth PLAIN
--auth-user maya --auth-password 'floral.pa$$word' --to tony@mailing.htb
--from maya@mailing.htb --header 'Subject: test from maya' --body 'test
message' --timeout 30`. Critical: agent uses SINGLE-DASH `-tls` for STARTTLS,
not `--tls`. Password quoted because of `$`.

### S6 — DNS failure classification

```
Engagement target: nonexistent-mta.invalid.localdomain (deliberately invalid,
verifying error classification).
Use swaks via the smtp tool with --quit-after HELO and --timeout 5.
Report what failure mode you classify this as.
```

**Watch:** stderr contains `Could not resolve` or `Name or service not
known`. failure_signature matches.

---

## 3. Target-extraction adversarial cases (≥20)

The smtp `tool.yaml` declares three extraction rules:

1. `flag_value --server` (swaks long form, parse_as: host_port — strips `:port`)
2. `flag_value -s` (swaks short form for --server)
3. `flag_value -t` (smtp-user-enum target)

**First match wins.** Per binary: swaks calls hit rule 1 or 2; smtp-user-enum
calls hit rule 3. There is no positional target form for either binary.

| # | Command (binary as shown) | Expected target | Notes |
|---|---|---|---|
| 1 | `swaks --server 10.10.10.51 --port 25 --to a@b --from c@d --quit-after HELO` | `10.10.10.51` | Bog-standard swaks invocation |
| 2 | `swaks --server smtp.target.local --port 587 -tls --to a@b --from c@d` | `smtp.target.local` | Hostname FQDN |
| 3 | `swaks --server 10.10.10.51:2525 --to a@b --from c@d` | `10.10.10.51` | host:port — must STRIP the port |
| 4 | `swaks -s 10.10.10.51 --port 587 --to a@b --from c@d` | `10.10.10.51` | Short form -s |
| 5 | `swaks --to a@b --from c@d --server 10.10.10.51 --port 25` | `10.10.10.51` | --server in middle of argv |
| 6 | `swaks --server [2001:db8::1]:25 --to a@b --from c@d` | `[2001:db8::1]` (or `2001:db8::1`) | IPv6 literal — see Open Questions |
| 7 | `swaks --server VICTIM.LOCAL --port 25 --to a@b --from c@d` | `VICTIM.LOCAL` | Uppercase host preserved (validation hook lowercases) |
| 8 | `smtp-user-enum -M VRFY -t 10.10.10.51 -p 25 -U /session/users.txt` | `10.10.10.51` | smtp-user-enum target via -t |
| 9 | `smtp-user-enum -t 10.10.10.51 -M RCPT -D solidstate.htb -U /session/users.txt -p 25` | `10.10.10.51` | -t in different position |
| 10 | `smtp-user-enum -M VRFY -p 25 -t mail.target.local -U /session/users.txt` | `mail.target.local` | Hostname target |
| 11 | `swaks --server 10.10.10.51 --port 25 --to root@example.com --from probe@attacker.local --header 'X-Originating-IP: 192.168.1.1' --quit-after HELO` | `10.10.10.51` | Header value contains an IP — NOT extracted |
| 12 | `swaks --server 10.10.10.51 --port 25 --to a@malicious.com --from b@spoofed.local` | `10.10.10.51` | --to and --from values are addresses — not targets |
| 13 | `swaks --server 10.10.10.51 --port 587 -tls --auth PLAIN --auth-user user@10.0.0.1 --auth-password 'pw' --to a@b --from c@d` | `10.10.10.51` | --auth-user contains @-delimited string — must NOT be confused |
| 14 | `smtp-user-enum -M RCPT -t 10.10.10.51 -D evil.com -U /session/users.txt` | `10.10.10.51` | -D domain is NOT the target host |
| 15 | `swaks --server 10.10.10.51 -tls --auth-user 'admin' --auth-password 'pa$$:word' --to a@b --from c@d --port 587` | `10.10.10.51` | Password contains `:` — value_flag traps -auth-password value |
| 16 | `swaks --server 10.10.10.51 --port 25 --to a@b --from c@d --header 'To: real@10.10.10.99' --quit-after HELO` | `10.10.10.51` | Header value contains IP — DSL extracts ONLY from --server |
| 17 | `swaks --server 10.10.10.51 --port 25 --to a@b --from c@d --ehlo 192.168.1.1` | `10.10.10.51` | --ehlo value is an IP — but NOT the network target |
| 18 | `swaks --server 10.10.10.51 --data /session/body-with-host-10.0.0.5.txt --to a@b --from c@d --port 25` | `10.10.10.51` | Path contains "10.0.0.5" — value_flag --data traps it |
| 19 | `swaks --server 10.10.10.51 --port 465 -tlsc --to a@b --from c@d --header 'Subject: 10.10.10.99'` | `10.10.10.51` | Subject contains IP literal — header value, not target |
| 20 | `swaks --server smtp.relay.target -tls --port 587 --auth PLAIN --auth-user user --auth-password 'p' --to a@10.10.10.99 --from b@c` | `smtp.relay.target` | --to has IP in domain — but it's an email address, not a network target |
| 21 | `smtp-user-enum -M VRFY -t 10.10.10.51 -p 25 -u root` | `10.10.10.51` | Single-user form (-u not -U) |
| 22 | `swaks --server 10.10.10.51 --port 25 --to a@b --from c@d --copy 'cc1@example.com,cc2@example.com'` | `10.10.10.51` | --copy value is comma-separated emails — not targets |
| 23 | `smtp-user-enum -M VRFY -t 10.10.10.51 -p 25 -U /session/users.txt -w 30 -m 1 -r 5` | `10.10.10.51` | Many integer flags before/after -t |
| 24 | `swaks --server 10.10.10.51 --port 25 --to a@b --from c@d --attach @/session/payload.docm --attach-name 'invoice.pdf'` | `10.10.10.51` | --attach value starts with @ — value_flag handles it |
| 25 | `swaks --server 10.10.10.51 --port 25 --to a@b --from c@d --tls-sni real.host.local` | `10.10.10.51` | --tls-sni value looks like a hostname — but it's a TLS SNI override, not a target |

### Adversarial / failure cases (DSL must reject or fall back)

| # | Command | Expected behaviour | Notes |
|---|---|---|---|
| F1 | `swaks --version` | target=null → tool.execute.before allows (no target → no validation) | Pure version check |
| F2 | `swaks --help` | target=null → no validation | Help banner |
| F3 | `smtp-user-enum -h` | target=null → no validation | smtp-user-enum help |
| F4 | `swaks --dump-mail --to a@b --from c@d --header 'Subject: x' --body 'y'` | target=null (no --server / -s — dump-mail is offline) | No network activity |
| F5 | `smtp-user-enum -M VRFY -T /session/hosts.txt -U /session/users.txt` | reject — -T is in reject_flags | Multi-host file ingestion blocked at plugin layer |
| F6 | `swaks --to a@b --from c@d --port 25` (no --server) | target=null → swaks fails naturally with "swaks needs a server" | Missing required flag → swaks exits nonzero |
| F7 | `swaks --server '' --to a@b --from c@d` | target=null (empty value) → DSL parse_error → swaks fails | Empty --server value |
| F8 | `swaks --server 10.10.10.51 --header 'Host: real.target.com' --to a@b --from c@d --port 25` | target=`10.10.10.51`, NOT `real.target.com`. **Critical security invariant**: the SMTP target is the network destination (`--server` flag), not a Host: header value. | DSL must extract from --server, never from --header |
| F9 | `swaks --server 10.10.10.51 --port 25 --to a@b --from c@d --copy a@10.10.99.99` (with multi-target=false) | target=`10.10.10.51`, NOT 10.10.99.99. --copy values are email addresses. | Single network target enforced |
| F10 | `smtp-user-enum -M VRFY -U /session/users.txt -p 25` (no -t) | target=null → smtp-user-enum prints usage and exits | Required -t missing |

---

## 4. Failure-signature live-verify cases (≥3)

Run each via opensploit (paste the prompt) and verify the result hits the
`failure_signatures` entry in `tool.yaml`. Each test produces an exit code,
a stderr message, and a `signal` substring the tool.yaml MUST contain.

| # | Test | Command (post-binary) | Expected exit | Expected stderr substring | failure_signature `signal` field | Status |
|---|---|---|---|---|---|---|
| 1 | DNS resolution failure (swaks) | `--server nonexistent-mta.invalid.localdomain --port 25 --to a@b --from c@d --quit-after HELO --timeout 5` | nonzero | `Could not resolve` / `Name or service not known` | `Could not resolve` AND `Name or service not known` | NEEDS LIVE VERIFY |
| 2 | Connection refused (swaks port closed) | `--server 127.0.0.1 --port 1 --to a@b --from c@d --quit-after HELO --timeout 5` | nonzero | `Connection refused` | `Connection refused` | NEEDS LIVE VERIFY — swaks may emit `connect: Connection refused` |
| 3 | Connection timeout (filtered host) | `--server 10.255.255.254 --port 25 --to a@b --from c@d --quit-after HELO --timeout 3` | nonzero | `Connection timed out` / `Operation timed out` | `Connection timed out` AND `Operation timed out` | NEEDS LIVE VERIFY |
| 4 | SMTP 502 / VRFY disabled | `smtp-user-enum -M VRFY -t <postfix-host-with-disable_vrfy=yes> -p 25 -U /session/users.txt -w 10` | 0 (smtp-user-enum always 0) | `502` in transaction log | `502` | NEEDS LIVE VERIFY — postfix returns `502 5.5.1 VRFY command is disabled` |
| 5 | Auth failure 535 | `swaks --server <smtp> --port 587 -tls --auth PLAIN --auth-user wronguser --auth-password wrongpass --to a@b --from c@d --quit-after AUTH` | nonzero | `535` | `535` | NEEDS LIVE VERIFY |
| 6 | Open-relay denied 550 | `swaks --server <closed-relay> --port 25 --to relay@external.example --from probe@attacker.local --quit-after RCPT --timeout 30` | 0 (transaction completed; just rejected) | `Relay access denied` / `554` / `550` | `Relay access denied` AND `550` AND `554` | NEEDS LIVE VERIFY |
| 7 | RCPT method without -D (501) | `smtp-user-enum -M RCPT -t <smtp> -p 25 -u michael -w 10` (no -D) | 0 | `501` (syntax error) | `501` | NEEDS LIVE VERIFY |

### Lesson recorded (encode in `tool.yaml` gotchas)

swaks's stderr text varies between distributions (Kali's swaks is the
upstream Perl version; Debian swaks may patch wording). Live signature
authoring requires running against the actual container image. Failure
signatures derived from docs alone will miss `Couldn't connect` vs
`Connection refused` and may miss the protocol-stage prefix (e.g.,
`*** Trying server:port` precedes the failure).

smtp-user-enum exits 0 ALWAYS — its exit code is meaningless for failure
detection. Always parse stdout for `exists` / `does not exist` / numeric
code patterns.

---

## 5. Open questions

1. **IPv6 brackets (case 6)** — DSL captures `[2001:db8::1]` *with* brackets
   when --server uses bracket form. Expected behaviour: TargetValidation
   strips brackets before passing to scope check, same as curl. Verify
   against `target-extraction.ts` once a v6-only lab MTA is available.
2. **Host-header / EHLO override (case F8)** — security invariant: extract
   target from --server, never from --header `Host:` or --ehlo. Encoded in
   target_extraction (only --server / -s / -t are sources).
3. **TLS verification tests** — need a self-signed-cert MTA in another
   container before we can live-verify `certificate verify failed` /
   `SSL/TLS handshake failed` failure signatures. Most lab MTAs ship valid
   or self-signed certs that swaks ignores by default.
4. **swaks `-tls` vs `--tls`** — verified single-dash is correct via swaks
   docs. The double-dash form `--tls` does NOT exist in swaks (only
   --tls-protocol / --tls-cert / --tls-verify use double-dash). Encoded in
   gotchas.
5. **smtp-user-enum STARTTLS support** — does smtp-user-enum 1.2 actually
   STARTTLS before issuing VRFY/RCPT on port 587? The tool source is short
   Perl — verify by reading or running against a STARTTLS-required postfix.
   If it doesn't STARTTLS, the fallback (swaks loop or nmap NSE) is the
   recorded answer.
6. **AUTH mechanism enumeration** — `swaks --help --auth` lists supported
   mechanisms in the local build. Confirm the kind:cli image's swaks ships
   PLAIN, LOGIN, CRAM-MD5, DIGEST-MD5, NTLM (per Kali's smtp-meta package).
   NTLM specifically requires Authen::NTLM perl module — verify present.
7. **Multi-recipient handling (case 22)** — current decision: `--copy` /
   `--cc` / `--bcc` values are email-address comma lists, NOT network
   targets. allow_multi_target=false enforces single network target via
   --server. The DSL accepts the multi-recipient values without confusion
   because they're trapped by value_flags.
8. **Live verification on Solidstate** — the box was retired; access requires
   HTB premium. Mailing is in the active rotation but more expensive to
   spawn. Standalone vulhub postfix is the no-HTB fallback for repeatable
   CI-style verification.
9. **Relay-test classification PRECEDENCE** — the legacy `relay_test` handler
   (mcp-server.py lines 402-421) implements a deliberate two-pass parser:
   (a) FIRST scan combined stdout+stderr for `relay denied` / `not permitted`
   / any 5xx code (550/553/554/454/451) — match → `is_open_relay=false`;
   (b) ONLY if no negative signal seen, look for an `RCPT TO` line followed
   on the next line by a `<...250...` response → `is_open_relay=true`.
   Under kind:cli the LLM does this classification post-hoc from raw
   transcript. Encoded as a tool.yaml gotcha; risk is the LLM may naively
   count 250s and false-positive (EHLO and MAIL FROM both return 250
   regardless of relay posture). Verify by hand against an HTB box once a
   confirmed-closed-relay target is captured. The lesson belongs in
   gotchas, not as a usage_pattern (no argv difference between the open
   and closed cases — the difference is in the response interpretation).
10. **swaks legacy parser regex** — the legacy `_parse_swaks_output`
    (mcp-server.py lines 159-212) parses server responses with
    `<[*~\s]*\s*(\d{3})\s*(.*)`. Under kind:cli this regex is preserved
    in the tool.yaml gotchas as a reference for any agent that wants to
    reconstruct structured `smtp_codes` from raw transcripts. Not
    architectural — but worth recording for downstream observability /
    pattern-extraction work.
11. **Userfile domain-append divergence** — legacy `enum_users` (mcp-server.py
    lines 313-321) auto-appended `@<domain>` to each line of the temp
    userfile when method=RCPT and domain was set. Under kind:cli the LLM
    explicitly chooses one path (write bare usernames + `-D domain`, OR
    write `user@domain` lines + omit `-D`). Encoded in tool.yaml gotchas
    to prevent the double-append failure (`user@domain@domain` → 501).

---

## 6. Hand-off

- **Tool**: smtp (kind:cli) — multi-binary (swaks + smtp-user-enum)
- **Status**: migrated; scenarios consolidated; tool.yaml uses the
  impacket-style multi-sub-binary pattern (no top-level `binary:`,
  per-usage_pattern `binary:` field).
- **mcp-server.py**: present, untouched — auto-inherits run_cli; preserves
  the legacy method handlers (send / enum_users / relay_test) as the
  rollback path per SKILL #21.
- **Image**: `ghcr.io/silicon-works/mcp-tools-smtp:latest` — Dockerfile is
  Kali base + apt-installs swaks + smtp-user-enum + python3-full +
  mcp-common 0.3.0. Local rebuild required after this migration before
  end-to-end verification.
- **Live-verify pending**: paste S1-S6 against Solidstate / Mailing once
  HTB access is provisioned; verify failure_signatures entries 1-6 match
  the actual container output.
- **Pilot-gate sign-off**: ≥7 deliberate-failure tests authored (live verify
  pending); ≥25 extraction cases authored (10 adversarial F1-F10);
  ≥16 narrative-coverage usage_patterns authored; multi-binary pattern
  matches impacket precedent.

Authored: 2026-04-25 (Wave 6.1).
