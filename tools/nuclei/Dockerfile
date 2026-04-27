# OpenSploit MCP Server: nuclei
# Template-based vulnerability scanner

FROM kalilinux/kali-rolling

LABEL org.opencontainers.image.source="https://github.com/silicon-works/mcp-tools"
LABEL org.opencontainers.image.description="nuclei MCP server for OpenSploit"
LABEL org.opencontainers.image.licenses="MIT"

# Install nuclei + Python. Use python3-full not separate python3-pip/python3-venv —
# Kali rolling occasionally has stale repo indexes that 404 on the discrete
# packages but resolve python3-full cleanly. Same fix as impacket Dockerfile.
RUN apt-get update && \
    apt-get install -y --no-install-recommends \
        nuclei \
        python3-full && \
    rm -rf /var/lib/apt/lists/* && \
    apt-get clean

# Download nuclei templates with retry and verification
RUN mkdir -p /root/nuclei-templates && \
    for i in 1 2 3; do \
        nuclei -update-templates && break || sleep 5; \
    done && \
    ls /root/nuclei-templates/ | head -5

# Create app directory
WORKDIR /app

# Create virtual environment
RUN python3 -m venv /app/venv
ENV PATH="/app/venv/bin:$PATH"

# Copy and install shared mcp-common package
COPY packages/mcp-common /app/packages/mcp-common
RUN pip install --no-cache-dir /app/packages/mcp-common

# Copy MCP server code
COPY tools/nuclei/mcp-server.py .

# MCP servers communicate via stdio
CMD ["python3", "mcp-server.py"]
