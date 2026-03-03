# OpenSploit MCP Server: forensics
# File analysis bundle — binwalk v2.4.3, foremost v1.5.7,
# steghide v0.5.1, exiftool v13.50

FROM kalilinux/kali-rolling

LABEL org.opencontainers.image.source="https://github.com/silicon-works/mcp-tools"
LABEL org.opencontainers.image.description="Forensics MCP server for OpenSploit"
LABEL org.opencontainers.image.licenses="MIT"

# Install forensics tools
RUN apt-get update && \
    DEBIAN_FRONTEND=noninteractive apt-get install -y --no-install-recommends \
        binwalk \
        foremost \
        steghide \
        libimage-exiftool-perl \
        python3 python3-pip python3-venv && \
    rm -rf /var/lib/apt/lists/*

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
COPY tools/forensics/mcp-server.py .

CMD ["python3", "mcp-server.py"]
