# OpenSploit MCP Server: ssti
# Server-Side Template Injection detection and exploitation via SSTImap

FROM kalilinux/kali-rolling

LABEL org.opencontainers.image.source="https://github.com/silicon-works/mcp-tools"
LABEL org.opencontainers.image.description="ssti MCP server for OpenSploit"
LABEL org.opencontainers.image.licenses="MIT"

# Install Python and git
RUN apt-get update && \
    apt-get install -y --no-install-recommends \
        git \
        ca-certificates \
        python3 \
        python3-pip \
        python3-venv && \
    rm -rf /var/lib/apt/lists/* && \
    apt-get clean

# Clone SSTImap
RUN git clone --depth 1 https://github.com/vladko312/SSTImap.git /opt/sstimap && \
    cd /opt/sstimap && \
    pip3 install --break-system-packages -r requirements.txt

# Create app directory
WORKDIR /app

# Create virtual environment
RUN python3 -m venv /app/venv
ENV PATH="/app/venv/bin:$PATH"

# Install SSTImap deps in venv too
RUN pip install --no-cache-dir urllib3 requests PyYAML beautifulsoup4

# Copy and install shared mcp-common package
COPY packages/mcp-common /app/packages/mcp-common
RUN pip install --no-cache-dir /app/packages/mcp-common

# Install tool-specific dependencies
COPY tools/ssti/requirements.txt .
RUN pip install --no-cache-dir -r requirements.txt

# Copy MCP server code
COPY tools/ssti/mcp-server.py .

# MCP servers communicate via stdio
CMD ["python3", "mcp-server.py"]
