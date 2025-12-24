# ffuf MCP Server

Fast web fuzzer for directory discovery, parameter fuzzing, and vhost enumeration.

## Overview

This MCP server wraps ffuf, providing a structured interface for web fuzzing tasks during enumeration phase.

## Methods

### `dir_fuzz`

Fuzz directories and files on a web server.

**Parameters:**
| Parameter | Type | Required | Default | Description |
|-----------|------|----------|---------|-------------|
| `url` | string | Yes | - | Target URL (FUZZ keyword added if missing) |
| `wordlist` | string | No | `common` | Wordlist name or path |
| `extensions` | string | No | - | File extensions (e.g., `php,html,txt`) |
| `threads` | integer | No | `40` | Concurrent threads |
| `filter_status` | string | No | `200,204,301,302,307,401,403,405` | Match these status codes |
| `filter_size` | string | No | - | Filter out responses of this size |
| `timeout` | integer | No | `10` | HTTP request timeout |

**Available Wordlists:**
- `common` - /usr/share/wordlists/dirb/common.txt
- `big` - /usr/share/wordlists/dirb/big.txt
- `dirbuster-small` - directory-list-2.3-small.txt
- `dirbuster-medium` - directory-list-2.3-medium.txt

**Example:**
```json
{
  "url": "http://10.10.10.1/FUZZ",
  "wordlist": "common",
  "extensions": "php,html",
  "threads": 50
}
```

### `param_fuzz`

Fuzz GET or POST parameters.

**Parameters:**
| Parameter | Type | Required | Default | Description |
|-----------|------|----------|---------|-------------|
| `url` | string | Yes | - | URL with FUZZ in parameter |
| `wordlist` | string | No | `common` | Wordlist name or path |
| `method` | string | No | `GET` | HTTP method (GET/POST) |
| `data` | string | No | - | POST data with FUZZ keyword |
| `threads` | integer | No | `40` | Concurrent threads |
| `filter_status` | string | No | - | Match these status codes |
| `filter_size` | string | No | - | Filter out responses of this size |

**Example (GET):**
```json
{
  "url": "http://10.10.10.1/page?id=FUZZ",
  "wordlist": "common"
}
```

**Example (POST):**
```json
{
  "url": "http://10.10.10.1/login",
  "method": "POST",
  "data": "username=admin&password=FUZZ",
  "wordlist": "common"
}
```

### `vhost_fuzz`

Fuzz virtual hosts on a web server.

**Parameters:**
| Parameter | Type | Required | Default | Description |
|-----------|------|----------|---------|-------------|
| `url` | string | Yes | - | Target URL (IP or hostname) |
| `domain` | string | Yes | - | Base domain (e.g., `target.htb`) |
| `wordlist` | string | No | `common` | Wordlist for subdomain prefixes |
| `threads` | integer | No | `40` | Concurrent threads |
| `filter_size` | string | No | - | Filter default response size |

**Example:**
```json
{
  "url": "http://10.10.10.1",
  "domain": "target.htb",
  "wordlist": "common",
  "filter_size": "1234"
}
```

## Building

```bash
# From repository root
docker build -t ghcr.io/silicon-works/mcp-tools-ffuf:latest -f tools/ffuf/Dockerfile .
```

## Running

```bash
docker run -i --network host ghcr.io/silicon-works/mcp-tools-ffuf:latest
```

## Tips

1. **Filter by size**: For vhost fuzzing, first check the default response size, then filter it out
2. **Extensions**: Common extensions to try: `php,html,txt,asp,aspx,jsp,js,bak,old`
3. **Threads**: Reduce threads if getting rate-limited or connection errors
