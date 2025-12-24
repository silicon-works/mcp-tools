# mcp-tools

MCP tool servers + registry for [OpenSploit](https://opensploit.ai), the open source offensive cyber security agent.

## Overview

This repository contains:

- **`registry.yaml`** - Tool registry defining all available security tools, their capabilities, and MCP method signatures
- **`tools/`** - Individual MCP server implementations for each security tool
- **`packages/mcp-common/`** - Shared Python utilities for building MCP servers

Each tool runs in its own Docker container based on `kalilinux/kali-rolling`, providing isolated and consistent security tooling.

## Architecture

```
┌──────────────────────────────────────────────────────────────┐
│                    OpenSploit Agent                          │
│                                                              │
│  1. Queries Tool Registry Search (RAG)                       │
│  2. Gets tool info + MCP server + methods                    │
│  3. Pulls Docker image if not cached                         │
│  4. Starts container, connects via stdio (MCP)               │
│  5. Invokes methods, receives structured results             │
└──────────────────────────────────────────────────────────────┘
                              │
                              ▼
┌──────────────────────────────────────────────────────────────┐
│                    Tool Containers                           │
│                                                              │
│  ┌─────────┐  ┌─────────┐  ┌─────────┐  ┌─────────┐         │
│  │  nmap   │  │ gobuster│  │ sqlmap  │  │  etc... │         │
│  │   MCP   │  │   MCP   │  │   MCP   │  │         │         │
│  └─────────┘  └─────────┘  └─────────┘  └─────────┘         │
│                                                              │
│  Base: kalilinux/kali-rolling                               │
│  Registry: ghcr.io/silicon-works/mcp-tools-<name>           │
└──────────────────────────────────────────────────────────────┘
```

## Tools

| Tool | Version | Phase | Description | Status |
|------|---------|-------|-------------|--------|
| nmap | 7.94 | Reconnaissance | Port scanning, service detection, OS fingerprinting | ✅ Implemented |
| gobuster | 3.6 | Enumeration | Directory and DNS bruteforcing | 📋 Planned |
| ffuf | 2.1 | Enumeration | Fast web fuzzer | 📋 Planned |
| sqlmap | 1.8 | Exploitation | SQL injection testing | 📋 Planned |
| nikto | 2.5 | Enumeration | Web server vulnerability scanning | 📋 Planned |
| hydra | 9.5 | Exploitation | Password brute-forcing | 📋 Planned |
| whatweb | 0.5 | Reconnaissance | Web technology fingerprinting | 📋 Planned |
| linpeas | latest | Post-Exploitation | Linux privilege escalation enumeration | 📋 Planned |
| winpeas | latest | Post-Exploitation | Windows privilege escalation enumeration | 📋 Planned |

> **Note:** Before implementing new tools, check if an official MCP server already exists (e.g., Burp Suite, Playwright). Tools with complex session management (e.g., Metasploit) require special consideration.

## Registry

The `registry.yaml` file defines all available tools with their:

- **Capabilities** - What the tool can do (e.g., `port_scanning`, `sql_injection`)
- **Phases** - Which pentest phase(s) the tool belongs to
- **Methods** - Available MCP methods with parameters and return types
- **Requirements** - Network access, privileges, resources

OpenSploit fetches this registry from `https://opensploit.ai/registry.yaml` and caches it locally.

## Development

### Prerequisites

- Docker
- Python 3.10+
- Bun (for testing with OpenSploit)

### Building a Tool

```bash
# Build a specific tool
docker build -t ghcr.io/silicon-works/mcp-tools-nmap:latest -f tools/nmap/Dockerfile .

# Run the tool locally (for testing)
docker run -i --network host ghcr.io/silicon-works/mcp-tools-nmap:latest
```

### Creating a New Tool

1. Create directory structure:
   ```
   tools/<toolname>/
   ├── Dockerfile
   ├── mcp-server.py
   ├── requirements.txt
   └── README.md
   ```

2. Implement the MCP server using `mcp-common`:
   ```python
   from mcp_common import BaseMCPServer, ToolResult

   class MyToolServer(BaseMCPServer):
       def __init__(self):
           super().__init__("mytool", "Description")
           self.register_method(
               name="my_method",
               description="What it does",
               params={...},
               handler=self.my_method,
           )

       async def my_method(self, **params) -> ToolResult:
           # Run the tool and return structured results
           ...

   if __name__ == "__main__":
       MyToolServer.main()
   ```

3. Add tool to `registry.yaml`

4. Add tool to `.github/workflows/build-publish.yaml` path filters

### Testing

```bash
# Install dev dependencies
cd packages/mcp-common
pip install -e ".[dev]"

# Run tests
pytest
```

## CI/CD

### Build and Publish (`build-publish.yaml`)

- Triggers on changes to `tools/**` or `packages/mcp-common/**`
- Detects which tools changed using path filters
- Builds only changed tools
- Pushes to `ghcr.io/silicon-works/mcp-tools-<name>`
- Tags with `latest` and git SHA

### Registry Publish (`registry-publish.yaml`)

- Triggers on changes to `registry.yaml`
- Validates registry schema
- Uploads to `opensploit.ai/registry.yaml`

## Contributing

1. Fork the repository
2. Create a feature branch
3. Implement your tool following the patterns above
4. Add tests
5. Submit a PR

### Before Adding a New Tool

- Check if an official MCP server already exists
- Consider if the tool is stateless (preferred) or requires session management
- Discuss complex tools in an issue first

## License

MIT License - See [LICENSE](LICENSE)

## Links

- [OpenSploit](https://github.com/silicon-works/opensploit) - Main agent repository
- [OpenSploit.ai](https://opensploit.ai) - Website and documentation
- [MCP Specification](https://modelcontextprotocol.io) - Model Context Protocol
