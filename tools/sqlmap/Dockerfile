# OpenSploit MCP Server: sqlmap
# Automatic SQL injection detection and exploitation.
#
# kind:cli at the SCHEMA layer (LLM emits raw argv via tool_runner) — routed
# via MCP TRANSPORT for persistent containers, heartbeat-driven idle timeouts,
# hard-cap dual clock. Container exposes the auto-inherited `run_cli` method
# from BaseMCPServer; the existing per-tool sqlmap methods remain available
# for kind:mcp callers that prefer structured params.

FROM debian:bookworm-slim

LABEL org.opencontainers.image.source="https://github.com/silicon-works/mcp-tools"
LABEL org.opencontainers.image.description="sqlmap MCP server for OpenSploit"
LABEL org.opencontainers.image.licenses="MIT"

# sqlmap is a Python tool. Debian's `sqlmap` package pulls a slightly older
# stable build but is reproducible and self-contained. python3 is already
# pulled in as a dependency.
#
# Optional libs we keep:
#   - krb5-user / libgssapi-krb5-2 — for sqlmap's --auth-type=NTLM/Kerberos
#   - libpsl5 / libidn2-0 — for IDN URL handling consistent with curl image
RUN apt-get update && \
    apt-get install -y --no-install-recommends \
        sqlmap \
        ca-certificates \
        krb5-user \
        libgssapi-krb5-2 \
        libpsl5 \
        libidn2-0 \
        python3-pip \
        python3-venv \
    && rm -rf /var/lib/apt/lists/* \
    && apt-get clean

WORKDIR /app

# Virtualenv keeps Python deps off the system pip and away from sqlmap's libs.
RUN python3 -m venv /app/venv
ENV PATH="/app/venv/bin:$PATH"

# Shared mcp-common (BaseMCPServer with auto-inherited run_cli).
COPY packages/mcp-common /app/packages/mcp-common
RUN pip install --no-cache-dir /app/packages/mcp-common

# MCP server (subclasses BaseMCPServer; auto-registers run_cli).
COPY tools/sqlmap/mcp-server.py .

# Session directory for artifacts (mounted by ContainerManager).
WORKDIR /session

# stdio MCP transport — ContainerManager spawns this and connects.
CMD ["python3", "/app/mcp-server.py"]
