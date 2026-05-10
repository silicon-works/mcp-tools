# OpenSploit MCP Server: mongodb (vendor-MCP swap)
#
# Wraps mongodb-js/mongodb-mcp-server (the OFFICIAL MongoDB MCP server, GA per
# MongoDB Inc) with offensive-side tuning: telemetry off, fingerprint-aware,
# read-only default, Atlas tools disabled by default to drop ~21 always-failing
# entries from the surface when no Atlas service-account creds are configured.
#
# This replaces the prior 682-LOC pymongo-based custom wrapper. See
# scenarios.md "Migration history" + tool.yaml "notes" for the rationale.

FROM node:22-bookworm-slim

LABEL org.opencontainers.image.source="https://github.com/silicon-works/mcp-tools"
LABEL org.opencontainers.image.description="mongodb-mcp-server (offensive-tuned vendor wrapper) for OpenSploit"
LABEL org.opencontainers.image.licenses="MIT"

# Minimal base — node:22-bookworm-slim already has node + npm. We only add CA
# certs (TLS to MongoDB Atlas / TLS-enabled instances) and procps (ps/pgrep
# for entrypoint diagnostics during failure modes).
RUN apt-get update && apt-get install -y --no-install-recommends \
        ca-certificates \
        procps \
    && rm -rf /var/lib/apt/lists/* && apt-get clean

# Install mongodb-mcp-server (npm). Pinning a major lets us see schema drift
# at upgrade time instead of being silently surprised. Bump after running
# tests/tools/test_mongodb_mcp.py against the new version.
RUN npm install -g mongodb-mcp-server@^0

# Pre-create platform-convention output dir so vendor's `export` tool's
# default exportsPath resolves under the bind-mount. ContainerManager binds
# ${sessionDir}:/session:rw at run time, so this mkdir lands on the host
# filesystem.
RUN mkdir -p /session/output

WORKDIR /app

COPY tools/mongodb/entrypoint.sh /entrypoint.sh
RUN chmod +x /entrypoint.sh

ENTRYPOINT ["/entrypoint.sh"]
