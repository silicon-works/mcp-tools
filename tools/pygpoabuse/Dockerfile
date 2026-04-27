# OpenSploit MCP Server: pygpoabuse
# Active Directory GPO exploitation via pyGPOAbuse (Hackndo/pyGPOAbuse).
#
# kind:cli at the SCHEMA layer (LLM emits raw argv via tool_runner) — routed
# via MCP TRANSPORT for persistent containers. Container exposes the
# auto-inherited `run_cli` method from BaseMCPServer (mcp-common 0.3.0); the
# legacy per-method handlers (scheduled_task, cleanup) remain available as
# the rollback path for kind:mcp callers.

FROM kalilinux/kali-rolling

LABEL org.opencontainers.image.source="https://github.com/silicon-works/mcp-tools"
LABEL org.opencontainers.image.description="pygpoabuse MCP server for OpenSploit"
LABEL org.opencontainers.image.licenses="MIT"

# Install Python + git. Use python3-full not separate python3-pip/python3-venv —
# Kali rolling occasionally has stale repo indexes that 404 on the discrete
# packages but resolve python3-full cleanly. Same fix as impacket / ffuf /
# nuclei / nikto / ssti / netexec / certipy / bloodyad Dockerfiles.
RUN apt-get update && \
    apt-get install -y --no-install-recommends \
        git \
        ca-certificates \
        python3-full && \
    rm -rf /var/lib/apt/lists/* && \
    apt-get clean

# Clone pyGPOAbuse. The script self-bootstraps via `python3 pygpoabuse.py`;
# we install a small wrapper on PATH so kind:cli's `binary: pygpoabuse`
# resolves naturally. Wrapper uses the venv (created below) — Kali's system
# python3 ships without pip, so upstream deps live in the venv.
RUN git clone --depth 1 https://github.com/Hackndo/pyGPOAbuse.git /opt/pygpoabuse && \
    chmod +x /opt/pygpoabuse/pygpoabuse.py && \
    printf '#!/bin/sh\nexec /app/venv/bin/python3 /opt/pygpoabuse/pygpoabuse.py "$@"\n' > /usr/local/bin/pygpoabuse && \
    chmod +x /usr/local/bin/pygpoabuse

# Create app directory
WORKDIR /app

# Create virtual environment. Both mcp-common AND the upstream pyGPOAbuse
# deps install here.
RUN python3 -m venv /app/venv
ENV PATH="/app/venv/bin:$PATH"

# Install pyGPOAbuse upstream deps (impacket / msldap / minikerberos / ...).
RUN pip install --no-cache-dir -r /opt/pygpoabuse/requirements.txt

# Copy and install shared mcp-common package (into the venv)
COPY packages/mcp-common /app/packages/mcp-common
RUN pip install --no-cache-dir /app/packages/mcp-common

# Copy MCP server code
COPY tools/pygpoabuse/mcp-server.py .

# MCP servers communicate via stdio
CMD ["python3", "mcp-server.py"]
