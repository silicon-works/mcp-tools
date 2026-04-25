# impacket failure_signature live verification

Verified against the kind:cli image (`mcp-test-impacket`, built 2026-04-25) by
running the binary directly via `docker run --rm --network=host`. Each test
documents the exact command, observed stderr substring, exit code, and which
`failure_signatures` entry in `tool.yaml` it confirms.

Notes:
- Most impacket binaries exit **0 even on hard failure**, so we cannot trust
  the exit code alone — pattern-matching `failure_signatures` is mandatory.
- Targets used: 10.255.255.254 (unreachable for timeout test), 127.0.0.1
  (loopback for refused-connection test), Hercules HTB DC at 10.129.242.196
  (live AD environment for SMB/Kerberos tests). Hercules has NTLM disabled
  domain-wide, which surfaced the `STATUS_NOT_SUPPORTED` signal that the
  initial draft had missed.
- All commands run with `-v /tmp/imp-test:/session` mounted writable.

## Test 1 — Connection refused (closed port)

```
docker run --rm --network=host -v /tmp/imp-test:/session mcp-test-impacket \
  impacket-secretsdump 'CORP/admin:pass@127.0.0.1' -just-dc-ntlm
```

stderr (relevant line):
```
[-] RemoteOperations failed: [Errno Connection error (127.0.0.1:445)] [Errno 111] Connection refused
```

Exit code: 0
Confirms: `[Errno 111] Connection refused` → "TCP connect failed."
Also confirms: bare `Connection refused` substring.

## Test 2 — Network timeout (unreachable IP)

```
timeout 30 docker run --rm --network=host -v /tmp/imp-test:/session mcp-test-impacket \
  impacket-secretsdump 'CORP/admin:pass@10.255.255.254' -just-dc-ntlm
```

stderr (relevant line):
```
[-] RemoteOperations failed: [Errno Connection error (10.255.255.254:445)] timed out
```

Exit code: 124 (outer `timeout` killed it after impacket's own ~25s socket timeout fired)
Confirms: `timed out` → "TCP / RPC timeout."
Note: the initial draft used `TimeoutError` as the signal — impacket's actual
stderr is the lowercase phrase `timed out`, so the signal was changed.

## Test 3 — STATUS_NOT_SUPPORTED (NTLM disabled on target)

```
docker run --rm --network=host -v /tmp/imp-test:/session mcp-test-impacket \
  impacket-secretsdump 'hercules.htb/natalie.a:wrongpassword@10.129.242.196' -just-dc-ntlm
```

stderr (relevant lines):
```
[-] RemoteOperations failed: SMB SessionError: STATUS_NOT_SUPPORTED({Operation Failed} The requested operation was unsuccessful.)
```

Exit code: 0
Confirms: `STATUS_NOT_SUPPORTED` → "NTLM is disabled on the target. Switch to Kerberos auth..."
Important finding: the SMB layer rejects auth **before** any password check
runs, so a wrong password against an NTLM-disabled target masquerades as
this code rather than `STATUS_LOGON_FAILURE`. Without this signature the
agent would be misled into believing creds were valid.

## Test 4 — KDC_ERR_PREAUTH_FAILED (wrong Kerberos password)

```
docker run --rm --network=host -v /tmp/imp-test:/session mcp-test-impacket \
  impacket-getTGT 'hercules.htb/natalie.a:wrongpassword' -dc-ip 10.129.242.196
```

stderr (relevant line):
```
[-] Kerberos SessionError: KDC_ERR_PREAUTH_FAILED(Pre-authentication information was invalid)
```

Exit code: 0
Confirms: `KDC_ERR_PREAUTH_FAILED` → "Wrong password during Kerberos preauth."

## Test 5 — KDC_ERR_C_PRINCIPAL_UNKNOWN (nonexistent user)

```
echo "nonexistentuser" > /tmp/imp-test/users.txt
docker run --rm --network=host -v /tmp/imp-test:/session mcp-test-impacket \
  impacket-GetNPUsers 'hercules.htb/' -no-pass -dc-ip 10.129.242.196 \
  -usersfile /session/users.txt
```

stderr (relevant line):
```
[-] Kerberos SessionError: KDC_ERR_C_PRINCIPAL_UNKNOWN(Client not found in Kerberos database)
```

Exit code: 0
Confirms: `KDC_ERR_C_PRINCIPAL_UNKNOWN` → "User principal not found in the realm."

## Test 6 — KDC_ERR_S_PRINCIPAL_UNKNOWN (Kerberos service SPN missing)

```
docker run --rm --network=host -v /tmp/imp-test:/session \
  -e KRB5CCNAME=/session/natalie.a.ccache mcp-test-impacket \
  impacket-secretsdump 'hercules.htb/natalie.a@10.129.242.196' \
  -k -no-pass -just-dc-ntlm -dc-ip 10.129.242.196 -debug
```

stderr (relevant line):
```
[+] SMBConnection didn't work, hoping Kerberos will help (Kerberos SessionError: KDC_ERR_S_PRINCIPAL_UNKNOWN(Server not found in Kerberos database))
```

Exit code: 0
Confirms: `KDC_ERR_S_PRINCIPAL_UNKNOWN` → "Service principal not found."
Root cause for this run: Kerberos requires the host's FQDN (CIFS/dc.hercules.htb)
in the SPN — we passed the bare IP, so no matching SPN exists in the realm.
Remediation: pass the DC FQDN as the positional host (after adding it to
/etc/hosts) instead of an IP, or use NTLM auth where allowed.

## Test 7 — DNS resolution failure

```
docker run --rm --network=host -v /tmp/imp-test:/session \
  -e KRB5CCNAME=/session/natalie.a.ccache mcp-test-impacket \
  impacket-secretsdump 'hercules.htb/natalie.a@dc.hercules.htb' \
  -k -no-pass -just-dc-ntlm -dc-ip 10.129.242.196 -debug
```

stderr (relevant line):
```
[+] SMBConnection didn't work, hoping Kerberos will help ([Errno Connection error (dc.hercules.htb:445)] [Errno -2] Name or service not known)
```

Exit code: 0
Confirms: `[Errno -2] Name or service not known` → "DNS resolution failed."

## Test 8 — Positive control (getTGT happy path)

```
docker run --rm --network=host -v /tmp/imp-test:/session mcp-test-impacket \
  impacket-getTGT 'hercules.htb/natalie.a:Prettyprincess123!' -dc-ip 10.129.242.196
```

stdout:
```
[*] Saving ticket in natalie.a.ccache
```

Exit code: 0
File written: `/tmp/imp-test/natalie.a.ccache` (1435 bytes)
Confirms: no failure signature should match a successful run — sanity check
that we don't have a false-positive substring in `failure_signatures` that
would flag a working command.

## Coverage summary

Live-verified ≥ 3 (achieved 7 distinct signals):

| Signal | Test | Layer |
|---|---|---|
| `[Errno 111] Connection refused` | 1 | TCP |
| `timed out` | 2 | TCP |
| `STATUS_NOT_SUPPORTED` | 3 | SMB (newly added) |
| `KDC_ERR_PREAUTH_FAILED` | 4 | Kerberos preauth |
| `KDC_ERR_C_PRINCIPAL_UNKNOWN` | 5 | Kerberos client |
| `KDC_ERR_S_PRINCIPAL_UNKNOWN` | 6 | Kerberos service |
| `[Errno -2] Name or service not known` | 7 | DNS |

Signals in `tool.yaml` not yet live-verified (kept from authoritative impacket
source review, not yet exercised against a live target):
`STATUS_ACCESS_DENIED`, `STATUS_ACCOUNT_DISABLED`, `STATUS_ACCOUNT_LOCKED_OUT`,
`STATUS_PASSWORD_EXPIRED`, `KRB_AP_ERR_SKEW`, `KDC_ERR_PREAUTH_REQUIRED`,
`DCERPC Runtime Error: code: 0x5`, `DCERPC Runtime Error`, `rpc_s_access_denied`,
`ERROR_DS_DRA_BAD_DN`, `[Errno 113] No route to host`, `SessionError: code: 0x`,
`Errors connecting to MS-SAMR endpoint`, `raise NoMechanismFoundError`.
These should be exercised post-pilot when corresponding misconfigurations
are reproducible.
