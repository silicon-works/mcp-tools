# OpenSploit MCP Server: OWASP ZAP
# Web application security scanner with active vulnerability detection

FROM ghcr.io/zaproxy/zaproxy:stable

LABEL org.opencontainers.image.source="https://github.com/silicon-works/mcp-tools"
LABEL org.opencontainers.image.description="OWASP ZAP MCP server for OpenSploit"
LABEL org.opencontainers.image.licenses="Apache-2.0"

USER root

# Install Python dependencies for MCP server
RUN apt-get update && \
    apt-get install -y --no-install-recommends \
        python3-pip \
        python3-venv \
        && \
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
COPY tools/zap/requirements.txt .
RUN pip install --no-cache-dir -r requirements.txt

# Copy MCP server code and startup script
COPY tools/zap/mcp-server.py .
COPY tools/zap/start.sh .
RUN chmod +x start.sh

# ZAP API port (internal)
ENV ZAP_PORT=8080

# MCP servers communicate via stdio
CMD ["./start.sh"]
