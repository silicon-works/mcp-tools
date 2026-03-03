# OpenSploit MCP Server: chisel
# HTTP-based tunneling via Chisel v1.11.4
# Requires: --network=host for tunnel accessibility

FROM python:3.11-slim

LABEL org.opencontainers.image.source="https://github.com/silicon-works/mcp-tools"
LABEL org.opencontainers.image.description="Chisel MCP server for OpenSploit"
LABEL org.opencontainers.image.licenses="MIT"

# Install chisel binary from GitHub releases
ARG CHISEL_VERSION=1.11.4
RUN apt-get update && \
    apt-get install -y --no-install-recommends wget gzip && \
    wget -q "https://github.com/jpillora/chisel/releases/download/v${CHISEL_VERSION}/chisel_${CHISEL_VERSION}_linux_amd64.gz" \
        -O /tmp/chisel.gz && \
    gunzip /tmp/chisel.gz && \
    mv /tmp/chisel /usr/local/bin/chisel && \
    chmod +x /usr/local/bin/chisel && \
    apt-get purge -y wget && \
    apt-get autoremove -y && \
    rm -rf /var/lib/apt/lists/*

WORKDIR /app

# Create venv
RUN python3 -m venv /app/venv
ENV PATH="/app/venv/bin:$PATH"

# Install shared mcp-common package
COPY packages/mcp-common /app/packages/mcp-common
RUN pip install --no-cache-dir /app/packages/mcp-common

# Create session directory
RUN mkdir -p /session

# Copy MCP server code
COPY tools/chisel/mcp-server.py .

CMD ["python3", "mcp-server.py"]
