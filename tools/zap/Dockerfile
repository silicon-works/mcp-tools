# OpenSploit MCP Server: OWASP ZAP (vendor MCP add-on)
#
# ZAP 2.17.0 + the upstream MCP add-on (mcp-alpha-0.0.1, April 2026). The
# add-on runs INSIDE ZAP's daemon process and exposes MCP-over-HTTP on port
# 8282; we wrap that with a stdio↔HTTP bridge so opensploit's stdio-based
# ContainerManager can talk to it transparently.
#
# Upstream registers 14 tools (NOT 15 — ZapStartScanTool is an abstract
# base class, not a tool):
#   zap_version, zap_info, zap_create_context,
#   zap_start_spider,  zap_stop_spider,  zap_get_spider_status,
#   zap_start_ajax_spider, zap_stop_ajax_spider, zap_get_ajax_spider_status,
#   zap_start_active_scan, zap_stop_active_scan, zap_get_active_scan_status,
#   zap_get_passive_scan_status, zap_generate_report

FROM ghcr.io/zaproxy/zaproxy:stable

LABEL org.opencontainers.image.source="https://github.com/silicon-works/mcp-tools"
LABEL org.opencontainers.image.description="OWASP ZAP MCP server (vendor add-on) for OpenSploit"
LABEL org.opencontainers.image.licenses="Apache-2.0"

USER root

# python3 is already in the base image; the bridge has zero pip deps (uses
# urllib from stdlib). We only need curl for the entrypoint readiness probe.
RUN apt-get update && \
    apt-get install -y --no-install-recommends curl && \
    rm -rf /var/lib/apt/lists/* && \
    apt-get clean

# Drop the official MCP add-on into ZAP's plugin dir. The base image already
# bundles the 5 add-on dependencies (automation, commonlib, network, pscan,
# reports) at versions ≥ what mcp-alpha-0.0.1 requires.
ARG MCP_ADDON_URL=https://github.com/zaproxy/zap-extensions/releases/download/mcp-v0.0.1/mcp-alpha-0.0.1.zap
RUN curl -fsSL "$MCP_ADDON_URL" -o /zap/plugin/mcp-alpha-0.0.1.zap && \
    chown zap:zap /zap/plugin/mcp-alpha-0.0.1.zap && \
    chmod 0644 /zap/plugin/mcp-alpha-0.0.1.zap

# Bridge + entrypoint live in /app, owned by zap so we can run unprivileged.
WORKDIR /app
COPY tools/zap/entrypoint.sh /app/entrypoint.sh
COPY tools/zap/bridge.py /app/bridge.py
RUN chmod +x /app/entrypoint.sh && \
    chown -R zap:zap /app

# Hand back to the unprivileged zap user (matches base-image default).
USER zap

# Internal ZAP MCP HTTP listener port. Not published — the bridge talks
# loopback. Override via env if you ever need to.
ENV ZAP_MCP_PORT=8282

ENTRYPOINT ["bash", "/app/entrypoint.sh"]
