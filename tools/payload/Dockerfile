FROM python:3.11-slim

LABEL maintainer="OpenSploit"
LABEL description="Payload compiler and generator MCP server"

# Install build tools and utilities
RUN apt-get update && apt-get install -y --no-install-recommends \
    gcc \
    gcc-multilib \
    libc6-dev \
    libc6-dev-i386 \
    nasm \
    mingw-w64 \
    && rm -rf /var/lib/apt/lists/*

WORKDIR /app

# Install mcp-common from local package
COPY packages/mcp-common /tmp/mcp-common
RUN pip install --no-cache-dir /tmp/mcp-common && rm -rf /tmp/mcp-common

# Copy server code and templates
COPY tools/payload/mcp-server.py .
COPY tools/payload/templates/ ./templates/

# Create workspace for compilation
RUN mkdir -p /workspace && chmod 777 /workspace

EXPOSE 8080

CMD ["python", "mcp-server.py"]
