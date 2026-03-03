# OpenSploit MCP Server: hashcat
# Password cracking via hashcat v7.1.2
# CPU-only mode (no GPU in Docker containers)

FROM kalilinux/kali-rolling

LABEL org.opencontainers.image.source="https://github.com/silicon-works/mcp-tools"
LABEL org.opencontainers.image.description="Hashcat MCP server for OpenSploit"
LABEL org.opencontainers.image.licenses="MIT"

# Install hashcat and wordlists
RUN apt-get update && \
    DEBIAN_FRONTEND=noninteractive apt-get install -y --no-install-recommends \
        hashcat \
        pocl-opencl-icd \
        ocl-icd-libopencl1 \
        wordlists \
        python3 python3-pip python3-venv && \
    rm -rf /var/lib/apt/lists/*

# Decompress rockyou if needed
RUN if [ -f /usr/share/wordlists/rockyou.txt.gz ]; then \
        gunzip /usr/share/wordlists/rockyou.txt.gz; \
    fi

WORKDIR /app

# Create venv
RUN python3 -m venv /app/venv
ENV PATH="/app/venv/bin:$PATH"

# Install shared mcp-common package
COPY packages/mcp-common /app/packages/mcp-common
RUN pip install --no-cache-dir /app/packages/mcp-common

# Create session directory
RUN mkdir -p /session

# Copy MCP server code
COPY tools/hashcat/mcp-server.py .

CMD ["python3", "mcp-server.py"]
