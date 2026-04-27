# OpenSploit MCP Server: trufflehog
# Secret and credential discovery in git repos, filesystems, and S3 buckets

FROM kalilinux/kali-rolling

LABEL org.opencontainers.image.source="https://github.com/silicon-works/mcp-tools"
LABEL org.opencontainers.image.description="trufflehog MCP server for OpenSploit"
LABEL org.opencontainers.image.licenses="MIT"

# Install trufflehog (available in Kali repos) and Python
# Use python3-full on Kali to get python3 + pip + venv in one PEP 668-friendly package
RUN apt-get update && \
    apt-get install -y --no-install-recommends \
        trufflehog \
        git \
        ca-certificates \
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
COPY tools/trufflehog/mcp-server.py .

# MCP servers communicate via stdio
CMD ["python3", "mcp-server.py"]
