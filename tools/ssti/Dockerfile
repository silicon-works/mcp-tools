# OpenSploit MCP Server: ssti
# Server-Side Template Injection detection and exploitation via SSTImap.
#
# kind:cli at the SCHEMA layer (LLM emits raw argv via tool_runner) — routed
# via MCP TRANSPORT for persistent containers. Container exposes the
# auto-inherited `run_cli` method from BaseMCPServer (mcp-common 0.3.0); the
# legacy per-method handlers (detect / exploit / list_engines) remain
# available as the rollback path for kind:mcp callers.

FROM kalilinux/kali-rolling

LABEL org.opencontainers.image.source="https://github.com/silicon-works/mcp-tools"
LABEL org.opencontainers.image.description="ssti MCP server for OpenSploit"
LABEL org.opencontainers.image.licenses="MIT"

# Install Python + git. Use python3-full not separate python3-pip/python3-venv —
# Kali rolling occasionally has stale repo indexes that 404 on the discrete
# packages but resolve python3-full cleanly. Same fix as impacket / ffuf /
# nuclei / nikto Dockerfiles.
RUN apt-get update && \
    apt-get install -y --no-install-recommends \
        git \
        ca-certificates \
        python3-full && \
    rm -rf /var/lib/apt/lists/* && \
    apt-get clean

# Clone SSTImap (vladko312 fork — actively maintained 1.3.x line; tplmap
# successor). The script self-bootstraps via `python3 sstimap.py`; we install
# a small wrapper on PATH so kind:cli's `binary: sstimap` resolves naturally.
RUN git clone --depth 1 https://github.com/vladko312/SSTImap.git /opt/sstimap && \
    chmod +x /opt/sstimap/sstimap.py && \
    printf '#!/bin/sh\ncd /opt/sstimap && exec /app/venv/bin/python3 sstimap.py "$@"\n' > /usr/local/bin/sstimap && \
    chmod +x /usr/local/bin/sstimap

# Create app directory
WORKDIR /app

# Create virtual environment
RUN python3 -m venv /app/venv
ENV PATH="/app/venv/bin:$PATH"

# Install SSTImap deps INTO the venv. The wrapper at /usr/local/bin/sstimap
# now invokes /app/venv/bin/python3 (rather than system python which Kali
# rolling ships without pip). PATH already prefers the venv so `pip` here
# is the venv pip.
RUN pip install --no-cache-dir -r /opt/sstimap/requirements.txt

# Copy and install shared mcp-common package (into the venv)
COPY packages/mcp-common /app/packages/mcp-common
RUN pip install --no-cache-dir /app/packages/mcp-common

# Copy MCP server code
COPY tools/ssti/mcp-server.py .

# MCP servers communicate via stdio
CMD ["python3", "mcp-server.py"]
