# OpenSploit kind:cli image: sqlmap
# Automatic SQL injection detection and exploitation. Plain CLI — no Python
# wrapper, no MCP server. Plugin invokes `sqlmap` directly via cli_in_container()
# with the full command constructed by the LLM.

FROM debian:bookworm-slim

LABEL org.opencontainers.image.source="https://github.com/silicon-works/mcp-tools"
LABEL org.opencontainers.image.description="sqlmap (kind:cli) for OpenSploit"
LABEL org.opencontainers.image.licenses="MIT"

# sqlmap is a Python tool. Debian's `sqlmap` package pulls a slightly older
# stable build but is reproducible and self-contained. python3 is already
# pulled in as a dependency.
#
# Optional libs we keep:
#   - krb5-user / libgssapi-krb5-2 — for sqlmap's --auth-type=NTLM/Kerberos
#   - libpsl5 / libidn2-0 — for IDN URL handling consistent with curl image
RUN apt-get update && \
    apt-get install -y --no-install-recommends \
        sqlmap \
        ca-certificates \
        krb5-user \
        libgssapi-krb5-2 \
        libpsl5 \
        libidn2-0 \
    && rm -rf /var/lib/apt/lists/* \
    && apt-get clean

WORKDIR /session

# Plugin invokes via `docker run <image> sqlmap ...`. No CMD — cli_in_container
# overrides per call.
