# OpenSploit MCP Server: ffuf
# Fast web fuzzer for directory discovery, parameter fuzzing, and vhost enumeration

FROM kalilinux/kali-rolling

LABEL org.opencontainers.image.source="https://github.com/silicon-works/mcp-tools"
LABEL org.opencontainers.image.description="ffuf MCP server for OpenSploit"
LABEL org.opencontainers.image.licenses="MIT"

# Install ffuf and Python with wordlists
# python3-full is Kali/Debian's metapackage that bundles python3 + pip + venv
# in one shot — splitting them as `python3-pip python3-venv` causes
# "Unable to locate package" on stale Kali roots, but `python3-full` resolves
# cleanly (same fix used in tools/impacket/Dockerfile).
RUN apt-get update && \
    apt-get install -y --no-install-recommends \
        ffuf \
        dirb \
        seclists \
        python3-full && \
    rm -rf /var/lib/apt/lists/* && \
    apt-get clean

# Create app directory
WORKDIR /app

# Create virtual environment
RUN python3 -m venv /app/venv
ENV PATH="/app/venv/bin:$PATH"

# Copy and install shared mcp-common package
COPY packages/mcp-common /app/packages/mcp-common
RUN pip install --no-cache-dir /app/packages/mcp-common

# Copy MCP server code
COPY tools/ffuf/mcp-server.py .

# Security Note: ffuf doesn't require elevated privileges for HTTP requests.
# Container runs as root for consistency with other tools.

# MCP servers communicate via stdio
CMD ["python3", "mcp-server.py"]
