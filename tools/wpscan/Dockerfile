# OpenSploit MCP Server: wpscan
# WordPress vulnerability scanner

FROM kalilinux/kali-rolling

LABEL org.opencontainers.image.source="https://github.com/silicon-works/mcp-tools"
LABEL org.opencontainers.image.description="wpscan MCP server for OpenSploit"
LABEL org.opencontainers.image.licenses="MIT"

# Install wpscan and Python
RUN apt-get update && \
    apt-get install -y --no-install-recommends \
        wpscan \
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

# Copy and install shared mcp-common package
COPY packages/mcp-common /app/packages/mcp-common
RUN pip install --no-cache-dir /app/packages/mcp-common

# Install tool-specific dependencies
COPY tools/wpscan/requirements.txt .
RUN pip install --no-cache-dir -r requirements.txt

# Copy MCP server code
COPY tools/wpscan/mcp-server.py .

# MCP servers communicate via stdio
CMD ["python3", "mcp-server.py"]
