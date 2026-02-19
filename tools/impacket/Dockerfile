# OpenSploit MCP Server: impacket
# Windows/AD exploitation toolkit (psexec, secretsdump, kerberoast, etc.)

FROM kalilinux/kali-rolling

LABEL org.opencontainers.image.source="https://github.com/silicon-works/mcp-tools"
LABEL org.opencontainers.image.description="Impacket MCP server for OpenSploit"
LABEL org.opencontainers.image.licenses="MIT"

# Install impacket (system package includes all scripts), Kerberos libs, Python
RUN apt-get update && \
    apt-get install -y --no-install-recommends \
        python3-impacket \
        impacket-scripts \
        krb5-user \
        libkrb5-dev \
        python3 \
        python3-pip \
        python3-venv && \
    rm -rf /var/lib/apt/lists/* && \
    apt-get clean

# Create app directory
WORKDIR /app

# Create virtual environment with system-site-packages so venv sees system impacket
RUN python3 -m venv --system-site-packages /app/venv
ENV PATH="/app/venv/bin:$PATH"

# Copy and install shared mcp-common package
COPY packages/mcp-common /app/packages/mcp-common
RUN pip install --no-cache-dir /app/packages/mcp-common

# Install tool-specific dependencies (empty - impacket comes from system)
COPY tools/impacket/requirements.txt .
RUN pip install --no-cache-dir -r requirements.txt

# Copy MCP server code
COPY tools/impacket/mcp-server.py .

# MCP servers communicate via stdio - no entrypoint needed (stateless tool)
CMD ["python3", "mcp-server.py"]
