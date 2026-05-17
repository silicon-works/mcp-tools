# OpenSploit MCP Server: ftp (kind:cli)
# FTP/FTPS client via curl for connect/list/download/upload/delete operations.

FROM python:3.11-slim

LABEL org.opencontainers.image.source="https://github.com/silicon-works/mcp-tools"
LABEL org.opencontainers.image.description="FTP MCP server for OpenSploit (kind:cli, May 2026 Tier A flip)"
LABEL org.opencontainers.image.licenses="MIT"

# Install curl CLI (kind:cli flip — May 2026, Tier A)
# Debian bookworm-slim's curl supports ftp://, ftps://, --ftp-ssl, -T, --quote, -X
RUN apt-get update && \
    apt-get install -y --no-install-recommends curl && \
    rm -rf /var/lib/apt/lists/*

WORKDIR /app

# Install shared mcp-common package
COPY packages/mcp-common /tmp/mcp-common
RUN pip install --no-cache-dir /tmp/mcp-common && rm -rf /tmp/mcp-common

# Create session directory
RUN mkdir -p /session

# Copy MCP server stub (22-LOC RunCliServer)
COPY tools/ftp/mcp-server.py .

CMD ["python", "mcp-server.py"]
