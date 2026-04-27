# ssh — Tier A scenarios

Single test sheet for the `ssh` tool migration (kind:cli, multi-binary
toolkit: ssh / scp / sshpass).

Sections:
1. Recommended HTB box for live verification
2. Narrative scenarios (paste into opensploit)
3. Target-extraction adversarial cases (≥20)
4. Failure-signature live-verify cases (≥3)
5. Open questions
6. Hand-off

---

## 1. Recommended HTB box for live verification

ssh is one of the most universally-present services on HTB. Almost every
Linux box has port 22 open with OpenSSH. Recommended targets (any one of
these will exercise the full toolkit):

- **Cap (10.10.10.245)**: easy, ssh available. After foothold the user has
  shell via web; use ssh as post-exploit pivot. Good first target.
- **Validation (10.129.95.235)**: medium, ssh available. Lets you exercise
  `scp` for `/etc/passwd` exfil and `ssh user@host 'sudo -l'` as part of
  privesc. Good multi-step target.
- **Hercules (10.129.242.196)**: medium, ssh available, has sshpass-friendly
  password auth path (no key by default). Good for exercising the
  sshpass code path.
- **Cap is the simplest** — start there for smoke tests.

For **password-auth specifically**, find any HTB box where a user is
discovered with a known password (web-app credential leak, /etc/shadow
crack, etc.). The credentials feed into sshpass directly:

```
sshpass -p 'discovered_password' ssh -o StrictHostKeyChecking=no user@10.10.10.5 'whoami'
```

For **key-auth**, any HTB box where you exfil `id_rsa` from a writable
home directory (Cap, Validation, etc.) — write the key to /session/id_rsa,
chmod 600, then:

```
chmod 600 /session/id_rsa  # via the write tool's chmod
ssh -i /session/id_rsa -o StrictHostKeyChecking=no -T user@10.10.10.5 'whoami; id'
```

Persistent test directory: standard /session/ mount inside the
cli_in_container container.

---

## 2. Narrative scenarios (paste into opensploit)

### S1 — smoke test: confirm all three binaries are functional

```
Run ssh -V, scp -h, and sshpass -h one at a time so I can confirm the three ssh-toolkit binaries are on PATH and working.
```

**Watch:** Agent emits three separate calls, each to a different
`binary:`. target=`null` for all three. ssh -V prints to stderr (e.g.,
"OpenSSH_10.2p1 Debian-1, OpenSSL 3.0.x"). scp -h prints usage banner.
sshpass -h prints its 5-line flag summary. If any binary isn't on PATH
the call fails with `command not found` (container build issue).

### S2 — key-based one-shot exec

```
I have an SSH private key at /session/id_rsa for user 'admin' on 10.10.10.5. Run a single command 'whoami; id; uname -a' to confirm the credentials work and capture identity info.
```

**Watch:** Agent emits `ssh -i /session/id_rsa -o StrictHostKeyChecking=no
-o UserKnownHostsFile=/dev/null -T admin@10.10.10.5 'whoami; id; uname -a'`.
binary=`ssh`. target=`10.10.10.5`. stdout is the remote command output —
typically ~3 lines (whoami + id + uname). Verifies the most common ssh use
pattern: key auth + post-exploit identity check.

### S3 — multi-command via && chain

```
SSH to admin@10.10.10.5 with /session/id_rsa and run a sequence: cd /tmp, list contents, find any 'flag.txt' files, and print uptime.
```

**Watch:** Agent emits `ssh -i /session/id_rsa -o StrictHostKeyChecking=no
-T admin@10.10.10.5 'cd /tmp && ls -la && find . -name flag.txt
2>/dev/null && uptime'`. binary=`ssh`. target=`10.10.10.5`. Single SSH
connection runs all four commands; output is the concatenation of their
stdout.

### S4 — SCP download (remote → local)

```
Download /etc/passwd from admin@10.10.10.5 to /session/loot/passwd using /session/id_rsa.
```

**Watch:** Agent emits `scp -i /session/id_rsa -o StrictHostKeyChecking=no
admin@10.10.10.5:/etc/passwd /session/loot/passwd`. binary=`scp`. target=
`10.10.10.5`. After completion /session/loot/passwd contains the file
content. stdout is brief progress; stderr typically empty under -q. The
agent then `read`s /session/loot/passwd to inspect the content.

### S5 — SCP upload (local → remote, payload delivery)

```
Upload /session/payload.sh to admin@10.10.10.5:/tmp/payload.sh using /session/id_rsa.
```

**Watch:** Agent emits `scp -i /session/id_rsa -o StrictHostKeyChecking=no
/session/payload.sh admin@10.10.10.5:/tmp/payload.sh`. binary=`scp`. target=
`10.10.10.5`. Followed up usually by an ssh exec to chmod +x and run the
script.

### S6 — sshpass password auth

```
SSH to user@10.10.10.5 with password 'Password123' and run 'sudo -l' to check for privesc.
```

**Watch:** Agent emits `sshpass -p 'Password123' ssh -o
StrictHostKeyChecking=no -o UserKnownHostsFile=/dev/null -T user@10.10.10.5
'sudo -l'`. binary=`sshpass`. target=`10.10.10.5` (extracted from the
embedded ssh argv's positional). stdout is sudo -l output. This is the
canonical sshpass + ssh wrapping pattern.

### S7 — reject_flags trap (port forward attempted)

```
Set up an SSH local port forward from localhost:8080 to 10.10.10.5's localhost:80 using /session/id_rsa.
```

**Watch:** Agent should NOT emit `ssh -L 8080:localhost:80 ...` — `-L` is
in reject_flags. Two acceptable behaviors: (a) the cli_in_container parser
REJECTS the call with a clear error pointing to the `tunnel` (kind:mcp)
tool, OR (b) the agent recognizes the request shape and routes to the
`tunnel` tool directly without trying ssh. Either way, no actual ssh
process with -L should be spawned (it can't survive cli_in_container's
one-shot model). Documents the tunnel-tool boundary.

### S8 — failure: auth fail with wrong key

```
Try to SSH to admin@10.10.10.5 with /session/wrong-key.pem.
```

**Watch:** Agent emits `ssh -i /session/wrong-key.pem -o
StrictHostKeyChecking=no -T admin@10.10.10.5 'whoami'`. binary=`ssh`.
target=`10.10.10.5`. Server rejects auth; stderr contains `Permission
denied (publickey)` or `Permission denied (publickey,password)`. exit_code
255 (the ssh-specific connection-failure code). Failure classified via
signal `Permission denied`.

### S9 — failure: connection refused (closed port)

```
Try to SSH to admin@10.10.10.5 on port 9999 (no service there).
```

**Watch:** Agent emits `ssh -p 9999 -i /session/id_rsa -o
StrictHostKeyChecking=no -T admin@10.10.10.5 'whoami'`. binary=`ssh`.
target=`10.10.10.5`. stderr: `ssh: connect to host 10.10.10.5 port 9999:
Connection refused`. exit_code 255. Failure classified via signal
`Connection refused`.

### S10 — failure: host key changed

```
Connect to admin@10.10.10.5 with strict host key checking enabled (deliberately, for safety): ssh -o StrictHostKeyChecking=yes -i /session/id_rsa admin@10.10.10.5 'whoami'.
```

**Watch:** First run on a fresh container: ssh prompts ('Are you sure you
want to continue connecting'); cli_in_container has no TTY → call hangs
until idle_timeout. Second run after manual /known_hosts pollution with a
DIFFERENT key: ssh fails with `Host key verification failed` /
`REMOTE HOST IDENTIFICATION HAS CHANGED`. exit_code 255. Failure
classified via signal `Host key verification failed`. Documents why
LAB-ONLY default `-o StrictHostKeyChecking=no` is essential.

### S11 — background process via nohup

```
Start /tmp/persistent-listener.sh on admin@10.10.10.5 in the background, redirecting output to /tmp/listener.log, and confirm it launched.
```

**Watch:** Agent emits `ssh -i /session/id_rsa -o StrictHostKeyChecking=no
-T admin@10.10.10.5 'nohup /tmp/persistent-listener.sh >/tmp/listener.log
2>&1 & disown && echo BACKGROUND_STARTED'`. binary=`ssh`. target=
`10.10.10.5`. stdout: 'BACKGROUND_STARTED' (sentinel). Process keeps
running on the target after ssh disconnects (verified by a follow-up
`ssh ... 'pgrep -f persistent-listener.sh'`).

### S12 — jump host (ProxyJump)

```
Connect to internal@192.168.50.10 via the bastion at admin@10.10.10.5, using /session/id_rsa for both.
```

**Watch:** Agent emits `ssh -i /session/id_rsa -J admin@10.10.10.5 -o
StrictHostKeyChecking=no -T internal@192.168.50.10 'whoami'`. binary=
`ssh`. target=`192.168.50.10` (the FINAL host, not the jump). The jump
connection is one-shot (set up + torn down within the single ssh
process); no persistent state is held. NB: target_extraction's regex
captures the last `[user@]host` positional, which is internal@192.168.50.10.

### S13 — legacy KEX fallback

```
SSH to admin@10.10.10.5 — the server is a Cisco IOS device that only speaks ssh-rsa host keys and diffie-hellman-group14-sha1.
```

**Watch:** Agent emits `ssh -o KexAlgorithms=+diffie-hellman-group14-sha1
-o HostKeyAlgorithms=+ssh-rsa -o PubkeyAcceptedKeyTypes=+ssh-rsa -i
/session/id_rsa -T admin@10.10.10.5 'show version'`. binary=`ssh`. target=
`10.10.10.5`. Without the +ALG additions, OpenSSH 10.x rejects the
connection with `no matching host key type found` or `no matching key
exchange method`.

### S14 — failure: unprotected key file

```
SSH to admin@10.10.10.5 with /session/id_rsa, but the key was created with permissions 0644 (group/world readable).
```

**Watch:** Agent emits the standard `ssh -i /session/id_rsa ...`. ssh
refuses with `WARNING: UNPROTECTED PRIVATE KEY FILE` followed by
`Permissions ... are too open`. exit_code 255. Remediation: chmod 600 the
key first OR pass `-o IdentitiesOnly=yes` (sometimes bypasses the check).
Failure classified via signal `WARNING: UNPROTECTED PRIVATE KEY FILE`.

---

## 3. Target-extraction adversarial cases (≥20)

The ssh `tool.yaml` declares ONE target_extraction rule:

```yaml
- rule: "positional_match"
  pattern: '^([^@\s]+@)?([^:/?#\s]+)'
  group: 2
  parse_as: "raw"
```

The rule walks argv looking for the first positional that matches
`[user@]host[:path]`. Group 1 is the optional `user@` prefix; group 2 is
the host. value_flags (-i, -o, -p, -F, etc.) ensure flag VALUES are not
misread as positionals.

reject_flags rejects -L, -R, -D, -N, -W, -M, -S, -O (stateful tunnel /
control-master flags).

### Happy-path cases

| # | Binary | Command | Expected target | Notes |
|---|---|---|---|---|
| 1 | ssh | `-i /session/id_rsa -T user@10.10.10.5 'whoami'` | `10.10.10.5` | Canonical key auth + user@host. |
| 2 | ssh | `-T 10.10.10.5 'uptime'` | `10.10.10.5` | Bare host (no user@). |
| 3 | ssh | `-i /session/id_rsa -o StrictHostKeyChecking=no -T root@target.htb 'id'` | `target.htb` | FQDN target. |
| 4 | ssh | `-i /session/key.pem -p 2222 -T ec2-user@bastion.example.com 'date'` | `bastion.example.com` | Custom port + FQDN. |
| 5 | ssh | `-l admin -i /session/id_rsa 10.10.10.5 'whoami'` | `10.10.10.5` | -l user form (alternate). |
| 6 | scp | `-i /session/id_rsa user@10.10.10.5:/etc/passwd /session/passwd` | `10.10.10.5` | Remote → local. |
| 7 | scp | `-i /session/id_rsa /session/x.sh user@10.10.10.5:/tmp/` | `10.10.10.5` | Local → remote. |
| 8 | scp | `-r -i /session/id_rsa /session/dir user@10.10.10.5:/tmp/` | `10.10.10.5` | Recursive upload. |
| 9 | scp | `-i /session/id_rsa -P 2222 user@10.10.10.5:/etc/passwd /session/passwd` | `10.10.10.5` | scp custom port (CAPITAL P). |
| 10 | sshpass | `-p 'pass' ssh -T user@10.10.10.5 'whoami'` | `10.10.10.5` | Password-auth wrapper. |
| 11 | sshpass | `-e ssh -T user@10.10.10.5 'id'` | `10.10.10.5` | Password from SSHPASS env. |
| 12 | sshpass | `-f /session/.pwd ssh -T user@10.10.10.5 'cat /etc/shadow'` | `10.10.10.5` | Password from file. |
| 13 | sshpass | `-p 'pass' scp -P 2222 /session/x.sh user@10.10.10.5:/tmp/` | `10.10.10.5` | sshpass + scp + custom port. |
| 14 | ssh | `-i /session/id_rsa -J admin@10.10.10.5 -T internal@192.168.50.10 'whoami'` | `192.168.50.10` | Jump host: target is the FINAL host, not -J. |
| 15 | ssh | `-i /session/id_rsa -T user@[2001:db8::1] 'whoami'` | `[2001:db8::1]` OR `2001:db8::1` | IPv6 in brackets. (Plugin should handle either form.) |

### Help / introspection (target=null)

| # | Binary | Command | Expected | Notes |
|---|---|---|---|---|
| H1 | ssh | `-h` | `target=null` | Help. |
| H2 | ssh | `-V` | `target=null` | Version (stderr). |
| H3 | ssh | `-G localhost` | `localhost` (or null — debatable; -G prints config for "localhost") | Edge: -G takes a positional that LOOKS like a target but is just a placeholder. |
| H4 | scp | `-h` | `target=null` | Help. |
| H5 | sshpass | `-h` | `target=null` | Help. |
| H6 | ssh | `-Q cipher` | `target=null` | Algorithm query. |

### Adversarial — value_flag traps & "looks like a target" invariants

| # | Binary | Command | Expected target | Notes |
|---|---|---|---|---|
| F1 | ssh | `-i /session/id_rsa -T user@10.10.10.5 'whoami'` | `10.10.10.5` | -i value is a path NOT a host (positional walk skips -i value). |
| F2 | ssh | `-o ProxyCommand='nc 10.99.99.99 80' -T user@10.10.10.5 'whoami'` | `10.10.10.5` | -o value is a config string with embedded IP — NOT the target. |
| F3 | ssh | `-o User=admin -o IdentityFile=/session/id_rsa -T 10.10.10.5 'whoami'` | `10.10.10.5` | -o values look like KEY=VALUE; the IP in -o would never be a target. |
| F4 | ssh | `-p 22022 -i /session/id_rsa -T user@10.10.10.5 'whoami'` | `10.10.10.5` | -p value is an integer port (NOT a target). |
| F5 | ssh | `-c aes256-ctr -i /session/id_rsa -T user@10.10.10.5 'whoami'` | `10.10.10.5` | -c value is a cipher name (with dashes). |
| F6 | ssh | `-F /session/ssh.conf -T user@10.10.10.5 'whoami'` | `10.10.10.5` | -F value is a config file path. |
| F7 | sshpass | `-p '10.10.10.99' ssh -T user@10.10.10.5 'whoami'` | `10.10.10.5` | Password value LOOKS like an IP — must NOT extract as target. -p value is consumed by sshpass; ssh's positional is user@10.10.10.5. |
| F8 | sshpass | `-p 'user@10.10.10.99:80' ssh -T user@10.10.10.5 'whoami'` | `10.10.10.5` | Password contains LITERAL user@host shape — must not match. |
| F9 | scp | `-P 22 -i /session/id_rsa user@10.10.10.5:/etc/passwd /session/p` | `10.10.10.5` | scp -P value (integer port). |
| F10 | scp | `-i /session/id_rsa /session/file-from-10.99.99.99.txt user@10.10.10.5:/tmp/` | `10.10.10.5` | Source file NAME embeds an IP — not a target. |
| F11 | ssh | `-i /session/id_rsa -T user@10.10.10.5 'curl http://10.99.99.99/x'` | `10.10.10.5` | Remote command embeds another IP — that's the REMOTE command, not a target. The third positional after host is the command (always quoted). |
| F12 | ssh | `-i /session/id_rsa -T user@10.10.10.5 'echo user@evil.com'` | `10.10.10.5` | Remote command contains a literal user@host string — must not match. |
| F13 | ssh | `-i /session/id_rsa -T -o ProxyJump=admin@10.99.99.99 user@10.10.10.5 'whoami'` | `10.10.10.5` | -o ProxyJump value contains user@host — but the target is the FINAL positional. |
| F14 | ssh | `-J admin@10.99.99.99 -i /session/id_rsa -T user@10.10.10.5 'whoami'` | `10.10.10.5` | -J value contains user@host (jump host, NOT the target). value_flags includes -J so its value is skipped. |
| F15 | ssh | `-b 10.0.0.5 -i /session/id_rsa -T user@10.10.10.5 'whoami'` | `10.10.10.5` | -b value is local source IP (bind address), NOT the target. |
| F16 | ssh | `-e none -i /session/id_rsa -T user@10.10.10.5 'whoami'` | `10.10.10.5` | -e value is escape char ('none' literal). |
| F17 | scp | `-3 -i /session/id_rsa user@10.10.10.5:/etc/p user@10.10.10.6:/tmp/p` | depends on parser — likely `10.10.10.6` (LAST positional) | scp's two-host form (transit via localhost). EDGE CASE: which host is "the" target? The PARSER picks the LAST positional. Document the choice. |
| F18 | ssh | `-i /session/id_rsa user@10.10.10.5 -T 'whoami'` | `10.10.10.5` | Flag AFTER positional (argparse permissive). target should still be 10.10.10.5. |
| F19 | ssh | `-i /session/id_rsa -T '10.10.10.5' 'whoami'` | `10.10.10.5` | Quoted host (shell-like quoting that the LLM sometimes emits). |
| F20 | ssh | `-i /session/id_rsa -T root@10.10.10.5/maybe 'whoami'` | `10.10.10.5` | Trailing /path — regex stops at /. (Unusual: ssh doesn't support paths after host, but the regex MUST cope if the LLM types it.) |
| F21 | ssh | `-i /session/id_rsa -T user@10.10.10.5:22 'whoami'` | `10.10.10.5` | Trailing :22 — regex stops at :. (ssh doesn't support host:port syntax — port is always -p — but the regex must handle the typo.) |
| F22 | ssh | `-T user@host-with-dash.lab 'whoami'` | `host-with-dash.lab` | Hostname with dashes. |
| F23 | scp | `-i /session/id_rsa user@10.10.10.5:'/path with spaces/file' /session/x` | `10.10.10.5` | Path with spaces (quoted). The colon-after-host part is not a target; regex stops at :. |
| F24 | ssh | `-i /session/id_rsa user@10.10.10.5` (no command — opens interactive shell, but kind:cli has no TTY → fails with PTY warning OR hangs) | `10.10.10.5` | target still extractable; the FAILURE is operational (hang/PTY warning), not target_extraction. |
| F25 | ssh | `-T user@10.10.10.5 'echo "user2@host2 is in this string"'` | `10.10.10.5` | Remote command literal contains user@host — must not match. |

### Reject_flags cases (these MUST be rejected at parse time)

| # | Binary | Command | Expected | Notes |
|---|---|---|---|---|
| R1 | ssh | `-L 8080:localhost:80 -i /session/id_rsa -N user@10.10.10.5` | REJECTED | -L is in reject_flags. Route to `tunnel` tool. |
| R2 | ssh | `-R 8080:localhost:80 -i /session/id_rsa -N user@10.10.10.5` | REJECTED | -R is in reject_flags. |
| R3 | ssh | `-D 1080 -i /session/id_rsa -N user@10.10.10.5` | REJECTED | -D (dynamic SOCKS) in reject_flags. |
| R4 | ssh | `-N -i /session/id_rsa user@10.10.10.5` | REJECTED | -N (no command) is meaningless without -L/-R/-D; rejected. |
| R5 | ssh | `-W 10.99.99.99:80 -i /session/id_rsa user@10.10.10.5` | REJECTED | -W (forward to host) — stateful. |
| R6 | ssh | `-M -S /tmp/ctl -i /session/id_rsa user@10.10.10.5` | REJECTED | -M (control master) + -S (control socket) — persistent multiplex. |
| R7 | ssh | `-O check -S /tmp/ctl user@10.10.10.5` | REJECTED | -O (control command) — meaningless without an existing -M. NB: scp -O has DIFFERENT meaning (legacy SCP); reject is binary-scoped. |
| R8 | scp | `-O -i /session/id_rsa user@10.10.10.5:/etc/passwd /session/p` | NOT REJECTED | scp -O = legacy SCP protocol (totally different from ssh -O). reject_flags is binary-scoped — scp -O is legitimate. target=`10.10.10.5`. |

### Multi-binary dispatch traps

| # | Setup | What COULD go wrong | What MUST happen |
|---|---|---|---|
| D1 | Agent emits `binary: ssh` but argv starts with `-p 'password' ssh user@host 'cmd'`. | -p is sshpass's password flag; ssh would reject as missing port value. | Use `binary: sshpass`. The DSL's `binary:` field IS THE BINARY — argv is appended. Mixing them is a recipe error. |
| D2 | Agent emits `binary: scp` with argv `-p 22 user@host:/x /y`. | scp -p is BOOLEAN preserve-perms; '22' is a positional file → fails. | Use `-P 22` (capital P) for scp port. The same letter has different meaning across the three binaries. |
| D3 | Agent emits `binary: ssh` with argv `user@host 'cmd'` but no -T. | Without -T, ssh emits "Pseudo-terminal will not be allocated" warning AND may produce ANSI / readline noise in stdout. | Always include -T for cli_in_container (no TTY available). |
| D4 | Agent uses `-i /session/id_rsa` but the file was written with permissions 0644. | ssh refuses with WARNING: UNPROTECTED PRIVATE KEY FILE. | chmod 600 the key first via the write tool's chmod, OR pass `-o IdentitiesOnly=yes`. |
| D5 | Agent uses sshpass -p 'PASS' but the password contains shell-special chars (single-quote, $, !). | Quoting breaks; sshpass reads the wrong password. | Use sshpass -f FILE (read from /session/.pwd) or -e (SSHPASS env). |
| D6 | Agent runs `ssh user@host 'echo data | base64 -d > /tmp/file' < /session/file.b64`. | argv > 128KB hits ARG_MAX. cli_in_container's stdin handling needed. | Use scp instead, OR confirm cli_in_container's stdin pipe support before relying on it. |

### Stdin trap (cli_in_container has no shell; pipes don't work as argv)

| # | Command (LLM might naively try) | What happens | Correct shape |
|---|---|---|---|
| P1 | `cat /session/file.b64 \| ssh user@host 'base64 -d > /tmp/x'` | cli_in_container HAS NO SHELL. The `\|` would be passed as a literal arg. | Stage the file via scp first, then ssh exec. |
| P2 | `ssh user@host 'cmd1' && ssh user@host 'cmd2'` (combine via shell &&) | No shell — && is a literal arg. | Combine via the REMOTE shell instead: `ssh user@host 'cmd1 && cmd2'`. |
| P3 | `for h in $hosts; do ssh user@$h ...; done` | No shell loop. | The agent must emit one ssh call per host. |

---

## 4. Failure-signature live-verify cases (≥3)

| # | Layer | Test | failure_signature `signal` | Status |
|---|---|---|---|---|
| 1 | DNS | `ssh -i /session/id_rsa -T admin@nonexistent-domain.invalid 'whoami'` | `Could not resolve hostname` OR `Name or service not known` | PENDING live verify |
| 2 | TCP | `ssh -p 9999 -i /session/id_rsa -T admin@10.10.10.5 'whoami'` (closed port) | `Connection refused` | PENDING live verify |
| 3 | TCP | `ssh -i /session/id_rsa -T admin@10.99.99.99 'whoami'` (unroutable) | `No route to host` OR `Connection timed out` | PENDING live verify |
| 4 | Host key | First connection without `-o StrictHostKeyChecking=no` | hangs (no TTY) → idle_timeout. With `-o StrictHostKeyChecking=yes`: `Host key verification failed` after known_hosts pollution | PENDING live verify |
| 5 | Host key | OpenSSH 10 on legacy server | `no matching host key type found` OR `no matching key exchange method` | PENDING live verify |
| 6 | Auth | Wrong key | `Permission denied (publickey)` OR `Permission denied (publickey,password)` | PENDING live verify |
| 7 | Auth | sshpass wrong password | `Permission denied, please try again` (with -o BatchMode=no) OR `Permission denied (publickey,password)` | PENDING live verify |
| 8 | Key file | Key chmod 0644 | `WARNING: UNPROTECTED PRIVATE KEY FILE` | PENDING live verify |
| 9 | Key file | Truncated / corrupt key | `Load key "/session/id_rsa": invalid format` | PENDING live verify |
| 10 | Argument | `ssh --notaflag user@host` | `unknown option` | PENDING live verify |
| 11 | Argument | `ssh -o StrictHostkeyChecking=no` (capital K wrong) | `Bad configuration option` | PENDING live verify |
| 12 | SCP / protocol | scp to legacy server (no SFTP subsystem) without `-O` | `subsystem request failed on channel 0` | PENDING live verify |
| 13 | Sshpass | `sshpass` (no command) | `sshpass: Not enough arguments` | PENDING live verify |

### Layer diversity (SKILL #11) — achieved

8 distinct verifiable layers exercised: DNS, TCP, host-key, auth, key-file,
argparse-spelling, scp-protocol, sshpass-specific.

---

## 5. Open questions

1. **Multi-binary dispatch — sshpass invocation form under run_cli.**
   sshpass's argv form is `sshpass [flags] COMMAND [args...]` where
   COMMAND is itself a binary (typically `ssh` or `scp`). Under run_cli,
   the usage_pattern declares `binary: sshpass`, so cli_in_container
   spawns `sshpass`. The `command:` field then includes `ssh user@host
   'cmd'` as the rest of argv. Verify that:
   - The argv parser treats `ssh` (after sshpass's flags) as a literal
     argument, NOT as a flag-resetting binary boundary.
   - target_extraction correctly walks past sshpass's own flags
     (-p/-f/-d/-e/-v) and the `ssh` literal, then matches the user@host
     positional from ssh's argv.
   - reject_flags scope: `-L` applies to ssh but NOT to sshpass's own
     flags. Under sshpass invocation, the embedded ssh argv would
     include -L if the LLM tried to tunnel — should this be rejected?
     (My take: YES — the ssh argv is still ssh, just wrapped. The
     parser should detect that `sshpass ... ssh -L ...` includes a
     forbidden ssh flag.) Verify implementation matches.

2. **reject_flags scope — binary-scoped vs argv-scoped.** scp -O has a
   DIFFERENT meaning (legacy SCP protocol) from ssh -O (control
   command). The reject_flags list includes -O for the ssh case but
   should NOT reject scp -O. Verify the cli_in_container parser is
   binary-scoped (only rejects -O when binary=ssh). The yaml comment
   on reject_flags documents this assumption.

3. **Key file permissions in containers.** ssh refuses keys with
   permissions broader than 0600 ('WARNING: UNPROTECTED PRIVATE KEY
   FILE'). The write tool that stages /session/id_rsa typically writes
   0644 by default. Two paths:
   - (a) Always pair key writes with a chmod 600 step (LLM-mediated).
   - (b) Pass `-o IdentitiesOnly=yes` (sometimes bypasses the check —
     UNRELIABLE).
   - (c) Wrapper-level: cli_in_container could chmod 600 any -i path
     under /session/ before invoking ssh.
   Currently relying on (a) — the agent should chmod after writing the
   key. If we see frequent UNPROTECTED-KEY failures in live runs,
   escalate to (c).

4. **Persistent-session boundary with `shell-session`.** This `ssh` tool
   is for ONE-SHOT operations (each call opens a fresh connection,
   exec's, exits). `shell-session` (kind:mcp) is for PERSISTENT
   multi-command shells where state matters. The boundary:
   - **Use ssh (this tool)**: ONE remote command per call; multiple
     commands joined via `&&` or `;` in a single quoted argv;
     fire-and-forget background processes via nohup + disown.
   - **Use shell-session**: cd + env + many follow-up commands sharing
     state; interactive tools that need readline; sustained
     multi-command exploit chains where each step builds on the last.
   Document this in the routing.never_use_for / see_also fields. Both
   tools coexist; the agent picks based on workload shape. If the LLM
   defaults to ssh for everything (because it's mentioned more
   frequently), we may need to bias the registry ranker toward
   shell-session for persistent-shell triggers.

5. **Tunnel-flag rejection vs. silent routing.** When the agent emits
   `ssh -L 8080:... user@host`, two behaviors are possible:
   - (a) cli_in_container parser hard-rejects with a clear error
     pointing to the `tunnel` tool.
   - (b) The agent's planner detects the tunnel intent BEFORE invoking
     ssh and routes to `tunnel` directly.
   Currently relying on (a) via reject_flags. Verify the rejection
   message is clear ('this flag requires a stateful ssh process; use
   the `tunnel` tool for SOCKS / port forwarding') so the LLM
   self-corrects on retry.

6. **Sshpass password exposure in audit logs.** sshpass -p 'PASS' puts
   the password in the cli_in_container audit log AND in `ps` output
   on the host. For HTB / labs the exposure is harmless; for real
   engagements with audit-trail concerns, the agent should prefer
   sshpass -e (SSHPASS env) or -f FILE. Should the gotchas RECOMMEND
   -e/-f over -p? Currently they describe all three; defer to live
   feedback.

7. **OpenSSH-format vs PEM key auto-conversion.** The legacy
   mcp-server.py auto-converted OpenSSH-format keys to PEM via
   `ssh-keygen -p -m PEM`. ssh ITSELF accepts both formats, so the
   conversion was likely unnecessary. Under run_cli the LLM doesn't
   convert; ssh handles whatever format the key is in. Verify in
   live runs that no OpenSSH-format key triggers an authentication
   failure that PEM wouldn't. If we see format-related failures,
   document in gotchas + add a usage_pattern for ssh-keygen
   conversion.

8. **Background process verification under run_cli.** The legacy
   `background` method returned a `check_command` (`ps -p PID`) that
   the agent could re-run later to verify the process. Under run_cli
   the LLM constructs the nohup chain inline and echoes a sentinel
   ('BACKGROUND_STARTED'). To verify the process is still running, the
   agent issues a follow-up `ssh user@host 'pgrep -f scriptname'` —
   one extra round-trip. If we see this pattern often, consider
   adding a usage_pattern that captures the PID via `nohup ... & echo
   $! > /tmp/pid.txt` so the agent can read the PID later.

9. **Stdin handling for binary uploads.** The legacy upload_binary
   method chunked binary data into 50KB pieces and base64-decoded
   per chunk via `echo CHUNK | base64 -d >> file`. Under run_cli, two
   alternatives:
   - (a) Use scp (preferred, simpler).
   - (b) Stream raw bytes via cli_in_container's stdin to `ssh user@host
     'cat > /tmp/file'` — needs cli_in_container to support stdin
     piping.
   Verify cli_in_container's stdin support for the (b) form. If not
   supported, document the chunk-base64 fallback as a usage_pattern.

10. **Connection multiplexing with `~/.ssh/config` ControlMaster.** ssh
    supports ControlMaster + ControlPath for connection reuse —
    multiple ssh invocations against the same host share one TCP+KEX+
    auth setup. Under cli_in_container's one-shot model, this CANNOT
    work (each call has its own container; sockets don't persist). If
    the agent issues many ssh calls in a row against the same host,
    each one pays the full TCP+KEX+auth cost (~1-3s on tun0). Pivot to
    `shell-session` (kind:mcp) for chatty workflows. Document this
    perf consideration in gotchas.

11. **Audit gap: transient-failure auto-retry has been DROPPED in the
    kind:cli migration.** Legacy mcp-server.py wrapped every `exec` in a
    `while attempt <= retries:` loop with 2-attempt-default and
    exponential backoff (`2 * attempt` seconds) on three specific
    transient signals: `connection timed out`, `connection reset by
    peer`, `network is unreachable`. The connect-timeout was even
    bumped on the second attempt (`min(45, timeout)` vs. first
    attempt's `min(30, timeout // 2)`). Under run_cli there is no
    retry harness — the call returns whatever ssh exited with. The
    LLM must now observe the failure_signature and re-emit the call
    manually. **Decision needed**: do we (a) document this as an LLM
    responsibility in gotchas (DONE — added to gotchas list) and rely
    on the agent's judgment, OR (b) push the retry into
    cli_in_container as a generic kind:cli feature so all 40 Tier A
    tools benefit? Option (b) is the better long-term play but is out
    of scope for this audit. Option (a) is in place now. Verify in
    live HTB runs that the LLM correctly retries on `Connection reset
    by peer` against rate-limited targets; if it doesn't, escalate
    to (b).

12. **Audit gap: stderr post-quantum warning filtering has been
    DROPPED.** Legacy mcp-server.py filtered out OpenSSH 10.x banner
    warnings (`Warning:`, `Permanently added`, `** `) from stderr
    before returning the error string. Under run_cli these now appear
    in raw stderr. Risk: a successful command could emit a `Warning:`
    line that an LLM-based downstream parser misreads as an error.
    Mitigation in place: a gotcha entry instructs the LLM to ignore
    these prefixes and trust the exit code. **Decision needed**:
    should cli_in_container's stderr pipeline auto-filter these
    well-known informational prefixes for ALL kind:cli tools (similar
    to legacy parity)? Same option (b) framing as the retry question.

13. **Audit gap: OpenSSH-format → PEM key auto-conversion has been
    DROPPED in the kind:cli path.** Legacy `_convert_openssh_to_pem`
    detected `-----BEGIN OPENSSH PRIVATE KEY-----` headers and
    transparently invoked `ssh-keygen -p -m PEM -f keyfile -N "" -P
    ""` to convert before writing the key for ssh's `-i` flag. Under
    run_cli, the LLM does NOT auto-convert; the key file is passed
    to `ssh -i` in whatever format it was written. **Status**:
    LIKELY HARMLESS. ssh ITSELF accepts both PEM and OPENSSH formats
    natively (the legacy conversion was defensive, originally added
    for now-historical paramiko / older library compatibility, not
    for OpenSSH client compatibility). The gotchas entry already
    flags this and instructs the LLM to do explicit `ssh-keygen -p
    -m PEM` if a format-related auth failure surfaces. **Verify in
    live runs**: if an OpenSSH-format key causes
    `Permission denied (publickey)` against a target that accepts a
    converted PEM equivalent, that's a regression and conversion
    must be re-introduced. So far no such case has been observed.

---

## 6. Hand-off

- **Tool**: ssh (kind:cli, multi-binary toolkit: ssh / scp / sshpass)
- **Status**: tool.yaml authored end-to-end (kind:cli, NO top-level
  binary, per-pattern `binary:` field; 1 h max_runtime; 5 min idle for
  one-shot exec / scp transfers; target_extraction with
  user@host positional regex; reject_flags for stateful tunnel /
  control-master flags; ~50 value_flags spanning all three binaries);
  scenarios.md written with 14 narrative scenarios, 25 happy/adversarial
  target-extraction cases, 6 help/introspection cases, 8 reject_flags
  cases, 6 multi-binary dispatch traps, 13 failure-signature cases
  across 8 layers.
- **Dockerfile**: ONE change applied — replaced
  `python3 python3-pip python3-venv` with `python3-full` (Kali rolling
  repos no longer ship the split packages reliably). openssh-client +
  sshpass packages retained. venv setup, mcp-common install,
  mcp-server.py copy, CMD all unchanged.
- **mcp-server.py**: UNTOUCHED (auto-inherits run_cli from
  BaseMCPServer 0.3.0; seven legacy methods preserved as rollback
  path: exec, shell, copy_from, copy_to, upload_binary, run_script,
  background).
- **Image**: `ghcr.io/silicon-works/mcp-tools-ssh:latest` — needs
  rebuild during Wave 9 batch to pick up mcp-common 0.3.0 and the
  python3-full swap.
- **Wave 8.1**: of Feature 35 / Tier A migration. Overlap case with
  `shell-session` (kind:mcp): this `ssh` tool handles ONE-SHOT
  operations (each call = fresh connection); `shell-session` handles
  PERSISTENT multi-command shells. The boundary is documented in
  routing.never_use_for, see_also, and gotchas. Both tools coexist.
- **Live-verify pending**: paste S1-S14 against Cap (10.10.10.245) or
  Validation (10.129.95.235) for end-to-end verification. Failure
  signatures 1-3 (DNS, TCP, no-route) verifiable against any
  unreachable host; 4 (host key) needs known_hosts pollution; 5 (legacy
  KEX) needs a Cisco IOS / Solaris fixture; 6-7 (auth fail) trivial
  with a wrong key/pass; 8-9 (key permissions / corruption) trivial
  with a chmod or truncated file; 12 (legacy SCP) needs an old SSH
  server fixture.
- **Cleanup**: `__pycache__/` directory removed (contained
  `mcp-server.cpython-312.pyc`). No legacy `target_extraction_tests.md`
  or `failure_signature_tests.md` were present in tools/ssh/ —
  nothing else to remove. Final dir contents: Dockerfile,
  mcp-server.py, requirements.txt, tool.yaml, scenarios.md.

Authored: 2026-04-25.
