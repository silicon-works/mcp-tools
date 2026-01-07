# OpenSploit MCP Server: scapy
# Packet crafting and protocol testing for UDP, custom protocols, and raw socket operations

FROM kalilinux/kali-rolling

LABEL org.opencontainers.image.source="https://github.com/silicon-works/mcp-tools"
LABEL org.opencontainers.image.description="scapy MCP server for OpenSploit"
LABEL org.opencontainers.image.licenses="MIT"

# Install Python and network tools
RUN apt-get update && \
    apt-get install -y --no-install-recommends \
        python3 \
        python3-pip \
        python3-venv \
        libpcap-dev \
        tcpdump && \
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

# Install tool-specific dependencies
COPY tools/scapy/requirements.txt .
RUN pip install --no-cache-dir -r requirements.txt

# Copy MCP server code
COPY tools/scapy/mcp-server.py .

# Security Note: Container needs NET_RAW and NET_ADMIN capabilities for packet crafting.
# OpenSploit prompts for user approval before running privileged containers.

# MCP servers communicate via stdio
CMD ["python3", "mcp-server.py"]
