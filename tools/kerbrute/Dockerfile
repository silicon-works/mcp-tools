# OpenSploit MCP Server: kerbrute
# Kerberos username enumeration and password spraying

FROM python:3.11-slim

LABEL org.opencontainers.image.source="https://github.com/silicon-works/mcp-tools"
LABEL org.opencontainers.image.description="Kerbrute MCP server for OpenSploit"
LABEL org.opencontainers.image.licenses="MIT"

# Install curl for downloading kerbrute binary
RUN apt-get update && \
    apt-get install -y --no-install-recommends curl && \
    rm -rf /var/lib/apt/lists/* && \
    apt-get clean

WORKDIR /app

# Download kerbrute Go binary (linux amd64)
RUN curl -fsSL https://github.com/ropnop/kerbrute/releases/download/v1.0.3/kerbrute_linux_amd64 \
    -o /app/kerbrute && \
    chmod +x /app/kerbrute

# Install mcp-common
COPY packages/mcp-common /tmp/mcp-common
RUN pip install --no-cache-dir /tmp/mcp-common && rm -rf /tmp/mcp-common

# Copy MCP server code
COPY tools/kerbrute/mcp-server.py .

CMD ["python3", "mcp-server.py"]
