# OpenSploit MCP Server: ysoserial
# .NET deserialization gadget chain generator via ysoserial.net

FROM kalilinux/kali-rolling

LABEL org.opencontainers.image.source="https://github.com/silicon-works/mcp-tools"
LABEL org.opencontainers.image.description="ysoserial MCP server for OpenSploit"
LABEL org.opencontainers.image.licenses="MIT"

# Install Mono runtime, wget, unzip, and Python
RUN apt-get update && \
    apt-get install -y --no-install-recommends \
        mono-complete \
        wget \
        unzip \
        ca-certificates \
        python3 \
        python3-pip \
        python3-venv && \
    rm -rf /var/lib/apt/lists/* && \
    apt-get clean

# Download ysoserial.net v1.36
RUN cd /tmp && \
    wget -q "https://github.com/pwntester/ysoserial.net/releases/download/v1.36/ysoserial-1dba9c4416ba6e79b6b262b758fa75e2ee9008e9.zip" -O ysoserial.zip && \
    unzip -q ysoserial.zip -d /opt/ysoserial && \
    rm ysoserial.zip

# Create app directory
WORKDIR /app

# Create virtual environment
RUN python3 -m venv /app/venv
ENV PATH="/app/venv/bin:$PATH"

# Copy and install shared mcp-common package
COPY packages/mcp-common /app/packages/mcp-common
RUN pip install --no-cache-dir /app/packages/mcp-common

# Install tool-specific dependencies
COPY tools/ysoserial/requirements.txt .
RUN pip install --no-cache-dir -r requirements.txt

# Copy MCP server code
COPY tools/ysoserial/mcp-server.py .

# MCP servers communicate via stdio
CMD ["python3", "mcp-server.py"]
