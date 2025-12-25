# OpenSploit MCP Server: nmap
# Network scanner for port discovery, service detection, and OS fingerprinting

FROM kalilinux/kali-rolling

LABEL org.opencontainers.image.source="https://github.com/silicon-works/mcp-tools"
LABEL org.opencontainers.image.description="nmap MCP server for OpenSploit"
LABEL org.opencontainers.image.licenses="MIT"

# Install nmap, iproute2 (for ip command), and Python
RUN apt-get update && \
    apt-get install -y --no-install-recommends \
        nmap \
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

# Install tool-specific dependencies
COPY tools/nmap/requirements.txt .
RUN pip install --no-cache-dir -r requirements.txt

# Copy MCP server code
COPY tools/nmap/mcp-server.py .

# Security Note: Container runs as root because nmap requires elevated privileges
# for most scan types (SYN scans, OS detection, raw packets). Container isolation
# provides the security boundary. OpenSploit prompts for user approval before
# running privileged containers.

# MCP servers communicate via stdio
CMD ["python3", "mcp-server.py"]
