# OpenSploit MCP Server: impacket
# Active Directory and SMB attack toolkit (47 sub-binaries: secretsdump,
# psexec, GetUserSPNs, GetNPUsers, smbclient, lookupsid, ...).
#
# kind:cli at the SCHEMA layer (LLM emits raw argv per sub-binary via
# tool_runner) — routed via MCP TRANSPORT for persistent containers,
# heartbeat-driven idle timeouts, hard-cap dual clock. Container exposes the
# auto-inherited `run_cli` method from BaseMCPServer; the per-pattern
# `binary:` field in tool.yaml selects which impacket-* sub-binary to invoke
# and run_cli forwards it as argv[0].
#
# Base: kalilinux/kali-rolling — Debian's python3-impacket lacks the
# `impacket-scripts` shim package that puts the binaries on PATH with the
# `impacket-*` names this tool.yaml references. Kali ships `impacket-scripts`
# out of the box; switching to Debian + pip would get us only `secretsdump.py`
# etc. (no impacket- prefix), forcing us to maintain a layer of symlinks.
# Image is ~1GB vs ~300MB for debian-slim, but correctness > size.
#
# Clock skew: libfaketime is installed and the entrypoint discovers it
# dynamically. The plugin's cli_in_container `env` arg accepts FAKETIME as a
# container knob (hoisted to ContainerOptions.clockOffset → docker run env),
# so an agent hitting KRB_AP_ERR_SKEW can shift the container clock to match
# the DC without needing to sync the host clock.

FROM kalilinux/kali-rolling

LABEL org.opencontainers.image.source="https://github.com/silicon-works/mcp-tools"
LABEL org.opencontainers.image.description="impacket MCP server for OpenSploit"
LABEL org.opencontainers.image.licenses="MIT"

# python3-impacket ships the library; impacket-scripts ships impacket-* on PATH.
# Kerberos client libs needed for -k auth and -aesKey paths.
# python3-full is Kali/Debian's metapackage that bundles python3 + pip + venv
# in one shot — splitting them as `python3-pip python3-venv` causes
# "Unable to locate package" on stale Kali roots, but `python3-full` resolves
# cleanly. Source: kalilinux/kali-rolling consistently exposes python3-full
# whereas the discrete pip/venv packages depend on which day the rolling
# index was rolled.
RUN apt-get update && \
    apt-get install -y --no-install-recommends \
        python3-impacket \
        impacket-scripts \
        krb5-user \
        libkrb5-dev \
        libfaketime \
        ca-certificates \
        python3-full \
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

WORKDIR /app

# Virtualenv for the MCP server. We use --system-site-packages so the venv can
# import python3-impacket installed via apt (otherwise we'd need to pip-install
# impacket inside the venv, losing the kali-curated `impacket-*` PATH binaries).
RUN python3 -m venv --system-site-packages /app/venv
ENV PATH="/app/venv/bin:$PATH"

# Shared mcp-common (BaseMCPServer with auto-inherited run_cli).
COPY packages/mcp-common /app/packages/mcp-common
RUN pip install --no-cache-dir /app/packages/mcp-common

# MCP server (subclasses BaseMCPServer; auto-registers run_cli).
COPY tools/impacket/mcp-server.py .

# Dynamic faketime discovery entrypoint — activates LD_PRELOAD only when the
# plugin sets FAKETIME, otherwise leaves the container untouched. WORKDIR
# stays at /app so the entrypoint's `python3 mcp-server.py` resolves.
COPY packages/mcp-common/entrypoint.sh /app/entrypoint.sh
RUN chmod +x /app/entrypoint.sh

# stdio MCP transport — ContainerManager spawns this and connects.
CMD ["/app/entrypoint.sh"]
