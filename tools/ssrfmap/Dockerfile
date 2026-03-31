# OpenSploit MCP Server: ssrfmap
# SSRF exploitation framework via SSRFmap + gopher payload generation via Gopherus

FROM kalilinux/kali-rolling

LABEL org.opencontainers.image.source="https://github.com/silicon-works/mcp-tools"
LABEL org.opencontainers.image.description="ssrfmap MCP server for OpenSploit"
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

# Clone SSRFmap
RUN git clone --depth 1 https://github.com/swisskyrepo/SSRFmap.git /opt/ssrfmap && \
    cd /opt/ssrfmap && \
    pip3 install --break-system-packages -r requirements.txt

# Clone Gopherus (Python2 tool — we'll wrap it via Python3)
RUN git clone --depth 1 https://github.com/tarunkant/Gopherus.git /opt/gopherus 2>/dev/null || true

# Create app directory
WORKDIR /app

# Create virtual environment
RUN python3 -m venv /app/venv
ENV PATH="/app/venv/bin:$PATH"

# Install deps in venv
RUN pip install --no-cache-dir requests urllib3

# Copy and install shared mcp-common package
COPY packages/mcp-common /app/packages/mcp-common
RUN pip install --no-cache-dir /app/packages/mcp-common

# Install tool-specific dependencies
COPY tools/ssrfmap/requirements.txt .
RUN pip install --no-cache-dir -r requirements.txt

# Copy MCP server code
COPY tools/ssrfmap/mcp-server.py .

# MCP servers communicate via stdio
CMD ["python3", "mcp-server.py"]
