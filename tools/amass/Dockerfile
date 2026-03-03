# OpenSploit MCP Server: amass
# Subdomain discovery via OWASP Amass v5.0

FROM python:3.11-slim

LABEL org.opencontainers.image.source="https://github.com/silicon-works/mcp-tools"
LABEL org.opencontainers.image.description="Amass MCP server for OpenSploit"
LABEL org.opencontainers.image.licenses="MIT"

# Install amass binary from GitHub release
RUN apt-get update && \
    apt-get install -y --no-install-recommends wget ca-certificates && \
    wget -qO /tmp/amass.tar.gz https://github.com/owasp-amass/amass/releases/download/v5.0.1/amass_linux_amd64.tar.gz && \
    tar -xzf /tmp/amass.tar.gz -C /tmp && \
    mv /tmp/amass_linux_amd64/amass /usr/local/bin/amass && \
    chmod +x /usr/local/bin/amass && \
    rm -rf /tmp/amass* && \
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

# Create session and config directories
RUN mkdir -p /session /root/.config/amass

# Copy MCP server code
COPY tools/amass/mcp-server.py .

CMD ["python3", "mcp-server.py"]
