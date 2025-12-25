FROM python:3.11-slim

LABEL maintainer="OpenSploit"
LABEL description="SSH tunnel and SOCKS proxy MCP server"

# Install SSH client and sshpass for password auth
RUN apt-get update && apt-get install -y --no-install-recommends \
    openssh-client \
    sshpass \
    && rm -rf /var/lib/apt/lists/*

WORKDIR /app

# Install mcp-common from local package
COPY packages/mcp-common /tmp/mcp-common
RUN pip install --no-cache-dir /tmp/mcp-common && rm -rf /tmp/mcp-common

# Copy server code
COPY tools/tunnel/mcp-server.py .

EXPOSE 8080

CMD ["python", "mcp-server.py"]
