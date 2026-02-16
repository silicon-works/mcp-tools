# OpenSploit MCP Server: metasploit
# Exploitation framework with persistent sessions via msfrpcd

FROM kalilinux/kali-rolling

LABEL org.opencontainers.image.source="https://github.com/silicon-works/mcp-tools"
LABEL org.opencontainers.image.description="metasploit MCP server for OpenSploit"
LABEL org.opencontainers.image.licenses="MIT"

# Install metasploit-framework + curl for health check
RUN apt-get update && \
    apt-get install -y --no-install-recommends \
        metasploit-framework \
        curl \
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
COPY tools/metasploit/requirements.txt .
RUN pip install --no-cache-dir -r requirements.txt

# Copy MCP server code
COPY tools/metasploit/mcp-server.py .

# Copy and prepare entrypoint
COPY tools/metasploit/entrypoint.sh .
RUN chmod +x /app/entrypoint.sh

# msfrpcd + MCP server via entrypoint
ENTRYPOINT ["bash", "/app/entrypoint.sh"]
