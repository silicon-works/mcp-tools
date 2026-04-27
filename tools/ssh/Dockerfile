# OpenSploit MCP Server: ssh
# SSH client for remote shell access with credentials

FROM kalilinux/kali-rolling

LABEL org.opencontainers.image.source="https://github.com/silicon-works/mcp-tools"
LABEL org.opencontainers.image.description="SSH MCP server for OpenSploit"
LABEL org.opencontainers.image.licenses="MIT"

# Install SSH client and sshpass for password auth
# python3-full bundles python3 + venv + ensurepip on Kali rolling (the split
# python3-pip / python3-venv packages are no longer reliably available).
RUN apt-get update && \
    apt-get install -y --no-install-recommends \
        openssh-client \
        sshpass \
        python3-full && \
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

# Copy MCP server code
COPY tools/ssh/mcp-server.py .

# MCP servers communicate via stdio
CMD ["python3", "mcp-server.py"]
