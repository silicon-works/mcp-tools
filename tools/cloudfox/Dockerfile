# OpenSploit MCP Server: cloudfox
# AWS attack path enumeration via Bishop Fox CloudFox

FROM kalilinux/kali-rolling

LABEL org.opencontainers.image.source="https://github.com/silicon-works/mcp-tools"
LABEL org.opencontainers.image.description="cloudfox MCP server for OpenSploit"
LABEL org.opencontainers.image.licenses="MIT"

# Install Python, wget, unzip
RUN apt-get update && \
    apt-get install -y --no-install-recommends \
        wget \
        unzip \
        ca-certificates \
        python3 \
        python3-pip \
        python3-venv && \
    rm -rf /var/lib/apt/lists/* && \
    apt-get clean

# Download CloudFox binary
RUN wget -q "https://github.com/BishopFox/cloudfox/releases/latest/download/cloudfox-linux-amd64.zip" -O /tmp/cf.zip && \
    cd /tmp && unzip -q cf.zip && \
    mv /tmp/cloudfox/cloudfox /usr/local/bin/cloudfox && \
    chmod +x /usr/local/bin/cloudfox && \
    rm -rf /tmp/cf.zip /tmp/cloudfox

# Create app directory
WORKDIR /app

# Create virtual environment
RUN python3 -m venv /app/venv
ENV PATH="/app/venv/bin:$PATH"

# Copy and install shared mcp-common package
COPY packages/mcp-common /app/packages/mcp-common
RUN pip install --no-cache-dir /app/packages/mcp-common

# Install tool-specific dependencies
COPY tools/cloudfox/requirements.txt .
RUN pip install --no-cache-dir -r requirements.txt

# Copy MCP server code
COPY tools/cloudfox/mcp-server.py .

# MCP servers communicate via stdio
CMD ["python3", "mcp-server.py"]
