# OpenSploit MCP Server: responder
# LLMNR/NBT-NS/MDNS poisoning and NTLMv2 hash capture
# Requires: --privileged --network=host

FROM kalilinux/kali-rolling

LABEL org.opencontainers.image.source="https://github.com/silicon-works/mcp-tools"
LABEL org.opencontainers.image.description="Responder MCP server for OpenSploit"
LABEL org.opencontainers.image.licenses="MIT"

# Install Responder and networking tools
RUN apt-get update && \
    apt-get install -y --no-install-recommends \
        responder \
        python3-netifaces \
        iproute2 \
        python3 \
        python3-pip \
        python3-venv && \
    rm -rf /var/lib/apt/lists/* && \
    apt-get clean

WORKDIR /app

# Create venv with system-site-packages so venv Python sees netifaces
# (Responder.py uses #!/usr/bin/env python3 which resolves to venv Python via PATH)
RUN python3 -m venv --system-site-packages /app/venv
ENV PATH="/app/venv/bin:$PATH"

# Install shared mcp-common package
COPY packages/mcp-common /app/packages/mcp-common
RUN pip install --no-cache-dir /app/packages/mcp-common

# Create session output directory
RUN mkdir -p /session/responder

# Ensure Responder logs directory exists
RUN mkdir -p /usr/share/responder/logs

# Copy MCP server code
COPY tools/responder/mcp-server.py .

CMD ["python3", "mcp-server.py"]
