# curl target-extraction test set (Workstream A → B handshake)

Per Feature 35 amendment 2: ≥20 adversarial commands, each with the expected target host
that the plugin's `target_extraction` DSL should pull from the curl invocation.

The curl `tool.yaml` declares two rules:

1. `positional_match` with regex `^(https?|ftp|ftps|file|gopher|telnet|dict|ldap|ldaps|scp|sftp|smb|smbs|imap|imaps|pop3|pop3s|smtp|smtps|tftp|rtsp|rtmp|wss?)://([^:/?#]+)`, capture group 2
2. `flag_value` with `flag: --url`, `parse_as: url_host`

**First match wins.** Rule 1 inspects every positional (in order); if no positional matches, fall back to `--url` flag value.

Table format:
- **Command** — what the LLM might generate (binary `curl` omitted; only flags + positionals)
- **Expected target** — what the DSL should extract
- **Notes** — what the test exercises

| # | Command | Expected target | Notes |
|---|---------|-----------------|-------|
| 1 | `-sS -o /session/out https://example.com/path` | `example.com` | Bog standard, trailing path |
| 2 | `-sSI http://10.10.10.5/` | `10.10.10.5` | IPv4 literal |
| 3 | `-sS http://10.129.206.176:8080/admin` | `10.129.206.176` | host:port — must drop port |
| 4 | `-sS -L https://target.local:443/api/v1/users?id=1&name=foo` | `target.local` | port + query string |
| 5 | `-sS -o /tmp/r.html http://[2001:db8::1]/` | `[2001:db8::1]` | IPv6 literal in brackets — depends on regex |
| 6 | `-sS -X POST -d 'cmd=id' http://VICTIM.LOCAL/cmd.php` | `VICTIM.LOCAL` | Uppercase host — DSL preserves case (validation hook can lowercase) |
| 7 | `-sS -u admin:s3cr3t https://10.10.10.5/dav/` | `10.10.10.5` | URL with no userinfo (creds via -u) |
| 8 | `-sS https://admin:s3cr3t@10.10.10.5/dav/` | `10.10.10.5` | URL with userinfo embedded — host comes after @ |
| 9 | `-sS -k --tlsv1.2 https://expired.cert.target/` | `expired.cert.target` | Multiple flags before URL |
| 10 | `-sS --url https://flag-form.target/api -H 'X: y'` | `flag-form.target` | URL via --url flag (rule 2 fires) |
| 11 | `-sS -d 'a=1' --data-binary @/session/payload.bin https://api.target/upload` | `api.target` | Mixed -d and --data-binary; URL last |
| 12 | `-sS -F 'file=@/session/shell.php' http://10.10.10.5/upload.php` | `10.10.10.5` | Multipart upload |
| 13 | `-sS -b /session/cookies.txt -c /session/cookies.txt -L https://app.target/redirect` | `app.target` | Cookie jar paths look like positionals — must be filtered as flag args |
| 14 | `-sS -A 'Mozilla/5.0' -e 'https://referer.evil/' https://victim.target/` | `victim.target` | Referer (a URL) as flag value — must NOT match as target; final positional wins |
| 15 | `-sS --proxy http://proxy.local:8080 -o /session/r https://final.target/api` | `final.target` | Proxy URL as flag value — final positional is target |
| 16 | `-vv -o /session/page http://10.10.10.5/users/?q=' OR 1=1 --` | `10.10.10.5` | SQLi payload in query — host extraction must not be confused |
| 17 | `-sS -X PUT --data-binary @/etc/passwd https://target.htb/wp-content/uploads/x` | `target.htb` | Path with /uploads (no host confusion) |
| 18 | `-sS --negotiate -u : https://exchange.corp.local/EWS/Exchange.asmx` | `exchange.corp.local` | Kerberos auth; long-ish FQDN |
| 19 | `-sS --socks5 127.0.0.1:1080 -o /session/r http://internal-only.target/admin` | `internal-only.target` | Pivot via SOCKS — final URL is the real target |
| 20 | `-sS -X POST -H 'Content-Type: application/json' -d '{"url":"http://decoy/"}' https://api.victim.com/v2/scan` | `api.victim.com` | Decoy URL inside JSON body — must NOT match; positional URL wins |
| 21 | `-sS http://10.10.10.5/foo http://10.10.10.6/bar` | `10.10.10.5` (or `10.10.10.6`?) | Multi-URL — curl actually fetches both. Documented edge case: rule should pick FIRST positional URL; phase agent should not generate multi-URL commands (split into two calls). Test verifies behaviour. |
| 22 | `-sS -d 'name=value' http://10.10.10.5/login.php?next=/admin` | `10.10.10.5` | POST with query string in URL |
| 23 | `-sS http://target.local` | `target.local` | URL with no path or trailing slash |
| 24 | `-sS ftp://files.target.local/pub/` | `files.target.local` | FTP scheme |
| 25 | `-sS smbs://10.10.10.5/share/file.txt` | `10.10.10.5` | smbs scheme (curl supports SMB) |

## Adversarial / failure cases (DSL must REJECT or FALL BACK)

| # | Command | Expected behaviour | Notes |
|---|---------|--------------------|-------|
| F1 | `--version` | No target → DSL returns null/empty → tool.execute.before SHOULD allow (no target → no validation needed) | Pure version check |
| F2 | `-sS -o /session/r file:///etc/passwd` | Target = `null` (file:// has empty authority) — should be treated as "no remote target" | Local file read, no network egress |
| F3 | `-sS https://` | Malformed URL → DSL returns null → should still allow curl to fail naturally with a clear error | Defensive parsing |
| F4 | `-sS  ` (no URL) | No target → curl will fail with "no URL specified" → exit nonzero, classifier picks up | Same as F1 |
| F5 | `-sS  -H 'Host: real.target.com'  http://10.10.10.5/` | Extracted target = `10.10.10.5` (the IP), NOT `real.target.com` (the Host header). Host header is a *behaviour* override, not authorization scope. Validation hook must scope-check the IP, not the Host header. | Critical: scope is by network destination, not requested host header. Otherwise an LLM could SSRF an in-scope IP and pretend it's targeting an out-of-scope domain |

## Open question for Workstream B

- **Multi-URL (case 21)**: Should the plugin's `cli_in_container` reject commands with multiple positional URLs, or accept and validate the first? Recommendation: **reject with a clear error**, since multi-URL curl invocations don't compose well with the `<tool_result>` shape (one exit code, mixed body file). Phase agent should split into separate `tool_runner` calls.
- **IPv6 brackets (case 5)**: My regex captures `[2001:db8::1]` *with* brackets. Workstream B should strip `[` and `]` before passing to the validation hook.
- **Host-header override (case F5)**: Plugin must extract from the URL, not the `-H 'Host: ...'` header. Worth documenting as a SECURITY invariant of the DSL.

## Status

These are the **expected** results. Workstream B implements the DSL parser; once it's online,
this file becomes a runnable test fixture. For now it is the contract.

Authored: 2026-04-23 (curl pilot, Phase 1).
