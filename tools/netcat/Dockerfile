# OpenSploit MCP Server: netcat
# Network utility for reverse shells, HTTP capture, and port testing
# v2.0.0 - Added HTTP server, UDP support, non-blocking listeners

FROM kalilinux/kali-rolling

LABEL org.opencontainers.image.source="https://github.com/silicon-works/mcp-tools"
LABEL org.opencontainers.image.description="netcat MCP server for OpenSploit"
LABEL org.opencontainers.image.licenses="MIT"

# Install system dependencies
# - netcat/ncat/socat for fallback operations
# - iproute2 for interface discovery
# - Python for MCP server
RUN apt-get update && \
    apt-get install -y --no-install-recommends \
        netcat-traditional \
        ncat \
        socat \
        iproute2 \
        python3 \
        python3-pip \
        python3-venv && \
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

# Install tool-specific dependencies (aiohttp, cryptography)
COPY tools/netcat/requirements.txt .
RUN pip install --no-cache-dir -r requirements.txt

# Copy MCP server code
COPY tools/netcat/mcp-server.py .

# Create session directory mount point
RUN mkdir -p /session/netcat

# MCP servers communicate via stdio
CMD ["python3", "mcp-server.py"]
