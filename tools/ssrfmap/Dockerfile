# OpenSploit MCP Server: ssrfmap (kind:cli)
# SSRF exploitation framework via swisskyrepo/SSRFmap (24 modules) — May 2026 Tier A flip.

FROM kalilinux/kali-rolling

LABEL org.opencontainers.image.source="https://github.com/silicon-works/mcp-tools"
LABEL org.opencontainers.image.description="ssrfmap MCP server for OpenSploit (kind:cli, May 2026 Tier A flip)"
LABEL org.opencontainers.image.licenses="MIT"

# Install Python + git
RUN apt-get update && \
    apt-get install -y --no-install-recommends \
        git \
        ca-certificates \
        python3 \
        python3-pip && \
    rm -rf /var/lib/apt/lists/* && \
    apt-get clean

# Clone SSRFmap + install its deps system-wide (no venv — simpler for kind:cli flip)
RUN git clone --depth 1 https://github.com/swisskyrepo/SSRFmap.git /opt/ssrfmap && \
    cd /opt/ssrfmap && \
    pip3 install --break-system-packages --no-cache-dir -r requirements.txt

# NOTE: Gopherus dropped (May 2026, Tier A flip) — was Python2-only with no
# python2 in image; the legacy wrapper never invoked it. Gopher payload
# generation for binary protocols (Redis/MySQL/FastCGI/Postgres) is handled
# by SSRFmap's own per-module gopher logic (redis.py, mysql.py, fastcgi.py).

WORKDIR /app

# Install shared mcp-common package system-wide alongside SSRFmap's deps
COPY packages/mcp-common /app/packages/mcp-common
RUN pip3 install --break-system-packages --no-cache-dir /app/packages/mcp-common

# Create session directory
RUN mkdir -p /session

# Copy MCP server stub (22-LOC RunCliServer)
COPY tools/ssrfmap/mcp-server.py .

CMD ["python3", "mcp-server.py"]
