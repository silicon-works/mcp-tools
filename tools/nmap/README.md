# nmap MCP Server

Network scanner for port discovery, service detection, and OS fingerprinting.

## Overview

This MCP server wraps the nmap network scanner, providing a structured interface for the OpenSploit agent to perform reconnaissance and enumeration tasks.

## Methods

### `port_scan`

Scan for open ports on a target.

**Parameters:**
| Parameter | Type | Required | Default | Description |
|-----------|------|----------|---------|-------------|
| `target` | string | Yes | - | IP address, hostname, or CIDR range |
| `ports` | string | No | `1-1000` | Port range (e.g., `22,80,443` or `1-1000`) |
| `scan_type` | enum | No | `tcp_connect` | `tcp_connect`, `syn`, `udp`, `ack` |
| `timing` | enum | No | `normal` | `paranoid`, `sneaky`, `polite`, `normal`, `aggressive`, `insane` |

**Example:**
```json
{
  "target": "10.10.10.1",
  "ports": "1-65535",
  "scan_type": "syn",
  "timing": "aggressive"
}
```

### `service_scan`

Identify service versions on open ports.

**Parameters:**
| Parameter | Type | Required | Description |
|-----------|------|----------|-------------|
| `target` | string | Yes | IP address or hostname |
| `ports` | string | Yes | Ports to scan (from previous `port_scan` results) |

**Example:**
```json
{
  "target": "10.10.10.1",
  "ports": "22,80,443,8080"
}
```

### `os_detection`

Detect operating system of target.

**Parameters:**
| Parameter | Type | Required | Description |
|-----------|------|----------|-------------|
| `target` | string | Yes | IP address or hostname |

**Note:** OS detection may require privileged access.

### `vuln_scan`

Run NSE vulnerability scripts against target.

**Parameters:**
| Parameter | Type | Required | Default | Description |
|-----------|------|----------|---------|-------------|
| `target` | string | Yes | - | IP address or hostname |
| `ports` | string | Yes | - | Ports to scan |
| `scripts` | string | No | `vuln` | NSE script category or specific scripts |

**Example:**
```json
{
  "target": "10.10.10.1",
  "ports": "80,443",
  "scripts": "http-vuln*,ssl-heartbleed"
}
```

## Building

```bash
# From repository root
docker build -t ghcr.io/silicon-works/mcp-tools-nmap:latest -f tools/nmap/Dockerfile .
```

## Running

The server communicates via stdio (MCP protocol):

```bash
docker run -i ghcr.io/silicon-works/mcp-tools-nmap:latest
```

## Network Access

This container requires network access to scan targets. When running with Docker:

```bash
docker run -i --network host ghcr.io/silicon-works/mcp-tools-nmap:latest
```

Or specify the target network:

```bash
docker run -i --network target_network ghcr.io/silicon-works/mcp-tools-nmap:latest
```

## Security Considerations

- Always ensure you have authorization to scan the target
- SYN scans (`-sS`) require root/privileged access
- OS detection requires root/privileged access
- Consider timing settings to avoid network disruption
