# OpenSploit MCP Server: searchsploit
# Exploit database search tool

FROM kalilinux/kali-rolling

LABEL org.opencontainers.image.source="https://github.com/silicon-works/mcp-tools"
LABEL org.opencontainers.image.description="searchsploit MCP server for OpenSploit"
LABEL org.opencontainers.image.licenses="MIT"

# Install exploitdb and Python
# Note: Kali rolling repos no longer ship python3-pip / python3-venv as
# separate packages — use python3-full which bundles them.
RUN apt-get update && \
    apt-get install -y --no-install-recommends \
        exploitdb \
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
COPY tools/searchsploit/mcp-server.py .

# MCP servers communicate via stdio
CMD ["python3", "mcp-server.py"]
