# OpenSploit MCP Server: pygpoabuse
# Active Directory GPO exploitation via pyGPOAbuse

FROM kalilinux/kali-rolling

LABEL org.opencontainers.image.source="https://github.com/silicon-works/mcp-tools"
LABEL org.opencontainers.image.description="pygpoabuse MCP server for OpenSploit"
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

# Clone pyGPOAbuse and install deps
RUN git clone --depth 1 https://github.com/Hackndo/pyGPOAbuse.git /opt/pygpoabuse && \
    cd /opt/pygpoabuse && \
    pip3 install --break-system-packages -r requirements.txt

# Create app directory
WORKDIR /app

# Create virtual environment
RUN python3 -m venv /app/venv
ENV PATH="/app/venv/bin:$PATH"

# Install pygpoabuse dependencies in venv
RUN pip install --no-cache-dir impacket msldap

# Copy and install shared mcp-common package
COPY packages/mcp-common /app/packages/mcp-common
RUN pip install --no-cache-dir /app/packages/mcp-common

# Install tool-specific dependencies
COPY tools/pygpoabuse/requirements.txt .
RUN pip install --no-cache-dir -r requirements.txt

# Copy MCP server code
COPY tools/pygpoabuse/mcp-server.py .

# MCP servers communicate via stdio
CMD ["python3", "mcp-server.py"]
