# OpenSploit MCP Server: aws
# AWS CLI API proxy via awslabs aws-api-mcp-server (forked for offensive use)
# Strips User-Agent fingerprint, disables telemetry and suggest endpoint

FROM kalilinux/kali-rolling

LABEL org.opencontainers.image.source="https://github.com/silicon-works/mcp-tools"
LABEL org.opencontainers.image.description="aws MCP server for OpenSploit"
LABEL org.opencontainers.image.licenses="MIT"

# Install Python
RUN apt-get update && \
    apt-get install -y --no-install-recommends \
        ca-certificates \
        python3 \
        python3-pip \
        python3-venv && \
    rm -rf /var/lib/apt/lists/* && \
    apt-get clean

# Create app directory
WORKDIR /app

# Create virtual environment
RUN python3 -m venv /app/venv
ENV PATH="/app/venv/bin:$PATH"

# Install awslabs aws-api-mcp-server
RUN pip install --no-cache-dir "awslabs.aws-api-mcp-server"

# Disable telemetry and suggest endpoint
ENV AWS_API_MCP_TELEMETRY=false
ENV AWS_API_MCP_ALLOW_SUGGEST=false

# Copy our wrapper that strips User-Agent
COPY tools/aws/mcp-server.py .

# MCP servers communicate via stdio
CMD ["python3", "mcp-server.py"]
