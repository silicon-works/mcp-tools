# OpenSploit MCP Server: netexec
# Multi-protocol credential validation and authenticated execution

FROM kalilinux/kali-rolling

LABEL org.opencontainers.image.source="https://github.com/silicon-works/mcp-tools"
LABEL org.opencontainers.image.description="netexec MCP server for OpenSploit"
LABEL org.opencontainers.image.licenses="MIT"

# Install netexec from Kali repos + Python. Use python3-full not separate
# python3-pip/python3-venv — Kali rolling occasionally has stale repo indexes
# that 404 on the discrete packages but resolve python3-full cleanly. Same fix
# as impacket / ffuf / nuclei / nikto Dockerfiles.
RUN apt-get update && \
    apt-get install -y --no-install-recommends \
        netexec \
        libfaketime \
        python3-full \
    && rm -rf /var/lib/apt/lists/* \
    && apt-get clean

# Create app directory
WORKDIR /app

# Create virtual environment
RUN python3 -m venv /app/venv
ENV PATH="/app/venv/bin:$PATH"

# Copy and install shared mcp-common package
COPY packages/mcp-common /app/packages/mcp-common
RUN pip install --no-cache-dir /app/packages/mcp-common

# Copy MCP server code
COPY tools/netexec/mcp-server.py .

# Copy entrypoint for dynamic faketime discovery
COPY packages/mcp-common/entrypoint.sh /app/entrypoint.sh
RUN chmod +x /app/entrypoint.sh

# MCP servers communicate via stdio
CMD ["/app/entrypoint.sh"]
