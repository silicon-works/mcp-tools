# OpenSploit MCP Server: hydra
# Network authentication brute-forcing tool

FROM kalilinux/kali-rolling

LABEL org.opencontainers.image.source="https://github.com/silicon-works/mcp-tools"
LABEL org.opencontainers.image.description="hydra MCP server for OpenSploit"
LABEL org.opencontainers.image.licenses="MIT"

# Install hydra, wordlists, and Python
RUN apt-get update && \
    apt-get install -y --no-install-recommends \
        hydra \
        wordlists \
        seclists \
        python3 \
        python3-pip \
        python3-venv && \
    rm -rf /var/lib/apt/lists/* && \
    apt-get clean

# Decompress rockyou if needed
RUN if [ -f /usr/share/wordlists/rockyou.txt.gz ]; then \
        gunzip /usr/share/wordlists/rockyou.txt.gz || true; \
    fi

# Create app directory
WORKDIR /app

# Create virtual environment
RUN python3 -m venv /app/venv
ENV PATH="/app/venv/bin:$PATH"

# Copy and install shared mcp-common package
COPY packages/mcp-common /app/packages/mcp-common
RUN pip install --no-cache-dir /app/packages/mcp-common

# Install tool-specific dependencies
COPY tools/hydra/requirements.txt .
RUN pip install --no-cache-dir -r requirements.txt

# Copy MCP server code
COPY tools/hydra/mcp-server.py .

# MCP servers communicate via stdio
CMD ["python3", "mcp-server.py"]
