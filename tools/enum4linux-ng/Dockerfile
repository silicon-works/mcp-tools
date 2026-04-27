# OpenSploit MCP Server: enum4linux-ng
# SMB/Windows enumeration tool

FROM kalilinux/kali-rolling

LABEL org.opencontainers.image.source="https://github.com/silicon-works/mcp-tools"
LABEL org.opencontainers.image.description="enum4linux-ng MCP server for OpenSploit"
LABEL org.opencontainers.image.licenses="MIT"

# Install enum4linux-ng and dependencies
# python3-full bundles pip + venv on Kali rolling (replaces python3-pip / python3-venv
# which are gated on Kali rolling 2026+ per Wave 6 migration convention).
RUN apt-get update && \
    apt-get install -y --no-install-recommends \
        enum4linux-ng \
        smbclient \
        libfaketime \
        python3-full && \
    rm -rf /var/lib/apt/lists/* && \
    apt-get clean

# Create app directory
WORKDIR /app

# Create virtual environment
RUN python3 -m venv /app/venv
ENV PATH="/app/venv/bin:$PATH"

# Copy and install shared mcp-common package
COPY packages/mcp-common /app/packages/mcp-common
RUN pip install --no-cache-dir /app/packages/mcp-common

# Copy MCP server code
COPY tools/enum4linux-ng/mcp-server.py .

# Copy entrypoint (FAKETIME support)
COPY packages/mcp-common/entrypoint.sh /app/entrypoint.sh
RUN chmod +x /app/entrypoint.sh

# MCP servers communicate via stdio
CMD ["/app/entrypoint.sh"]
