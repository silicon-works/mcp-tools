# OpenSploit MCP Server: sqlite (kind:cli)
# SQLite database client for post-exploitation extraction of .db / .sqlite files.

FROM python:3.11-slim

LABEL org.opencontainers.image.source="https://github.com/silicon-works/mcp-tools"
LABEL org.opencontainers.image.description="SQLite MCP server for OpenSploit (kind:cli, May 2026 flip)"
LABEL org.opencontainers.image.licenses="MIT"

# Install sqlite3 CLI binary (kind:cli flip — May 2026)
# Debian bookworm-slim ships sqlite3 3.40.1; JSON output mode (-json) needs 3.33+ so fine.
RUN apt-get update && \
    apt-get install -y --no-install-recommends sqlite3 && \
    rm -rf /var/lib/apt/lists/*

WORKDIR /app

# Install shared mcp-common package
COPY packages/mcp-common /tmp/mcp-common
RUN pip install --no-cache-dir /tmp/mcp-common && rm -rf /tmp/mcp-common

# Create session directory
RUN mkdir -p /session

# Copy MCP server stub (22-LOC RunCliServer)
COPY tools/sqlite/mcp-server.py .

CMD ["python", "mcp-server.py"]
