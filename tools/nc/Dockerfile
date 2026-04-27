# OpenSploit MCP Server: nc (kind:cli one-shot port operations)
# Sibling of the netcat (kind:mcp) tool. Same package set, different
# image — independent build keeps the two tools loosely coupled and
# makes registry hash management simple. Image size ~150 MB matches
# netcat.

FROM kalilinux/kali-rolling

LABEL org.opencontainers.image.source="https://github.com/silicon-works/mcp-tools"
LABEL org.opencontainers.image.description="nc MCP server (kind:cli one-shot port ops) for OpenSploit"
LABEL org.opencontainers.image.licenses="MIT"

# System dependencies:
#   netcat-traditional   — classic `nc` (limited flag set, no --send-only)
#   ncat                 — Nmap's modern netcat (richer flag set, used for
#                          banner grab via --send-only / --recv-only)
#   socat                — most flexible address-pair toolkit (TCP / UDP /
#                          UNIX sockets / OPENSSL / EXEC / SYSTEM)
#   iproute2             — kept for parity with the netcat image (operators
#                          may want `ip addr` style introspection on
#                          ad-hoc debugging)
#   python3-full         — bundles python3 + venv + ensurepip on Kali
#                          rolling (split python3-pip / python3-venv
#                          packages are no longer reliably available)
RUN apt-get update && \
    apt-get install -y --no-install-recommends \
        netcat-traditional \
        ncat \
        socat \
        iproute2 \
        python3-full && \
    rm -rf /var/lib/apt/lists/* && \
    apt-get clean

# Create app directory
WORKDIR /app

# Create virtual environment
RUN python3 -m venv /app/venv
ENV PATH="/app/venv/bin:$PATH"

# Copy and install shared mcp-common package (auto-inherits run_cli)
COPY packages/mcp-common /app/packages/mcp-common
RUN pip install --no-cache-dir /app/packages/mcp-common

# Copy MCP server code
COPY tools/nc/mcp-server.py .

# MCP servers communicate via stdio
CMD ["python3", "mcp-server.py"]
