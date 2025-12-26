# OpenSploit MCP Server: web-session
# Web session state management for authenticated testing

FROM python:3.11-slim

LABEL org.opencontainers.image.source="https://github.com/silicon-works/mcp-tools"
LABEL org.opencontainers.image.description="Web session MCP server for OpenSploit"
LABEL org.opencontainers.image.licenses="MIT"

WORKDIR /app

# Copy and install shared mcp-common package
COPY packages/mcp-common /tmp/mcp-common
RUN pip install --no-cache-dir /tmp/mcp-common && rm -rf /tmp/mcp-common

# Copy MCP server code
COPY tools/web-session/mcp-server.py .

# MCP servers communicate via stdio
CMD ["python", "mcp-server.py"]
