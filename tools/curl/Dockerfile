# OpenSploit MCP Server: curl
# HTTP/HTTPS/FTP client for web requests, exploit testing, and file downloads.
#
# kind:cli at the SCHEMA layer (LLM emits raw argv, no per-tool methods needed
# for tool_runner) — but routed via MCP TRANSPORT for persistent containers,
# heartbeat-driven idle timeouts, hard-cap dual clock, and battle-tested
# infrastructure. Container exposes the auto-inherited `run_cli` method from
# BaseMCPServer; the tool-specific methods (request, inject, upload, etc.)
# remain available for kind:mcp callers that prefer structured params.

FROM debian:bookworm-slim

LABEL org.opencontainers.image.source="https://github.com/silicon-works/mcp-tools"
LABEL org.opencontainers.image.description="curl MCP server for OpenSploit"
LABEL org.opencontainers.image.licenses="MIT"

# curl + libraries (full feature surface) + Python for the MCP server.
# bookworm-slim is ~80 MB lighter than kali-rolling and has everything we need.
RUN apt-get update && \
    apt-get install -y --no-install-recommends \
        curl \
        ca-certificates \
        krb5-user \
        libgssapi-krb5-2 \
        libpsl5 \
        libidn2-0 \
        python3 \
        python3-pip \
        python3-venv && \
    rm -rf /var/lib/apt/lists/* && \
    apt-get clean

WORKDIR /app

# Virtualenv keeps Python deps off the system pip.
RUN python3 -m venv /app/venv
ENV PATH="/app/venv/bin:$PATH"

# Shared mcp-common (BaseMCPServer with auto-inherited run_cli).
COPY packages/mcp-common /app/packages/mcp-common
RUN pip install --no-cache-dir /app/packages/mcp-common

# MCP server (subclasses BaseMCPServer; auto-registers run_cli).
COPY tools/curl/mcp-server.py .

# Session directory for artifacts (mounted by ContainerManager).
WORKDIR /session

# stdio MCP transport — ContainerManager spawns this and connects.
CMD ["python3", "/app/mcp-server.py"]
