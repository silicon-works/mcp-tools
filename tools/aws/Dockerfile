# OpenSploit MCP Server: aws
# Thin wrapper around awslabs.aws-api-mcp-server (PyPI, official AWS Labs).
# Strips User-Agent fingerprint (md/awslabs#mcp#aws-api-mcp-server#X.Y.Z) +
# kills telemetry. Vendor exposes 2 default tools (call_aws + suggest_aws_commands)
# via FastMCP framework v3.x.

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

# Disable telemetry. AWS_API_MCP_ALLOW_SUGGEST does NOT exist in vendor source
# (verified 2026-05-11 against awslabs.aws-api-mcp-server v1.3.36) — removed.
# OPSEC: suggest_aws_commands tool hits a remote AWS Labs HTTP endpoint with
# the agent's query text. Documented as gotcha; agent should prefer call_aws.
ENV AWS_API_MCP_TELEMETRY=false

# Copy our wrapper that strips User-Agent
COPY tools/aws/mcp-server.py .

# MCP servers communicate via stdio
CMD ["python3", "mcp-server.py"]
