# OpenSploit kind:cli image: curl
# HTTP/HTTPS/FTP client for web requests, exploit testing, and file downloads.
# Plain CLI — no Python wrapper, no MCP server. Plugin invokes `curl` directly
# via cli_in_container() with the full command constructed by the LLM.

FROM debian:bookworm-slim

LABEL org.opencontainers.image.source="https://github.com/silicon-works/mcp-tools"
LABEL org.opencontainers.image.description="curl (kind:cli) for OpenSploit"
LABEL org.opencontainers.image.licenses="MIT"

# Install curl + the libraries it needs for the full feature surface our YAML
# advertises (NTLM/Kerberos/HTTP2/HTTP3, libidn2 for IDN URLs, libpsl for cookies).
# libcurl4-gnutls-dev is dropped in favour of the openssl-backed package.
RUN apt-get update && \
    apt-get install -y --no-install-recommends \
        curl \
        ca-certificates \
        krb5-user \
        libgssapi-krb5-2 \
        libpsl5 \
        libidn2-0 \
    && rm -rf /var/lib/apt/lists/* \
    && apt-get clean

WORKDIR /session

# Plugin will pass the full curl invocation via `docker run <image> curl ...`.
# No CMD set on purpose — the cli_in_container primitive overrides it per call.
