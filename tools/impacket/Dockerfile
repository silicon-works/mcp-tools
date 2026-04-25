# OpenSploit kind:cli image: impacket
# Active Directory and SMB attack toolkit (47 sub-binaries: secretsdump,
# psexec, GetUserSPNs, GetNPUsers, smbclient, lookupsid, ...). Plain CLI —
# no Python wrapper, no MCP server. Plugin invokes the per-pattern binary
# directly via cli_in_container() with the full command constructed by the LLM.
#
# Base: kalilinux/kali-rolling — Debian's python3-impacket lacks the
# `impacket-scripts` shim package that puts the binaries on PATH with the
# `impacket-*` names this tool.yaml references. Kali ships `impacket-scripts`
# out of the box; switching to Debian + pip would get us only `secretsdump.py`
# etc. (no impacket- prefix), forcing us to maintain a layer of symlinks.
# Image is ~1GB vs ~300MB for debian-slim, but correctness > size for the
# pilot. Revisit during post-pilot polish.
#
# Note on clock skew: the original MCP-server image carried libfaketime so the
# server could splice FAKETIME via a meta-param. cli_in_container does not
# currently pipe a clock_offset env through, so we OMIT libfaketime here. If a
# Kerberos call hits KRB_AP_ERR_SKEW, the agent should sync the host clock or
# use a different attack path.

FROM kalilinux/kali-rolling

LABEL org.opencontainers.image.source="https://github.com/silicon-works/mcp-tools"
LABEL org.opencontainers.image.description="impacket (kind:cli) for OpenSploit"
LABEL org.opencontainers.image.licenses="MIT"

# python3-impacket ships the library; impacket-scripts ships impacket-* on PATH.
# Kerberos client libs needed for -k auth and -aesKey paths.
RUN apt-get update && \
    apt-get install -y --no-install-recommends \
        python3-impacket \
        impacket-scripts \
        krb5-user \
        libkrb5-dev \
        ca-certificates \
        python3 \
    && rm -rf /var/lib/apt/lists/* \
    && apt-get clean

# Bundle scripts that aren't in the apt package
COPY tools/impacket/scripts/rbcd.py tools/impacket/scripts/changepasswd.py /opt/impacket-scripts/
RUN chmod +x /opt/impacket-scripts/*.py 2>/dev/null || true

# krbrelayx (addspn.py) — community-maintained AD attack scripts using impacket
RUN apt-get update && apt-get install -y --no-install-recommends git ca-certificates && \
    git clone --depth 1 https://github.com/dirkjanm/krbrelayx.git /opt/krbrelayx && \
    chmod +x /opt/krbrelayx/*.py && \
    apt-get purge -y git && apt-get autoremove -y && \
    rm -rf /var/lib/apt/lists/*

WORKDIR /session

# No CMD — cli_in_container overrides per call (the per-pattern `binary:` field
# in tool.yaml selects which impacket-* binary to invoke).
