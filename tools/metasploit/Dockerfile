# OpenSploit MCP Server: metasploit (Rapid7's official msfmcpd)
#
# Read-only catalog + DB-state queries. 8 tools, all upstream:
#   msf_search_modules, msf_module_info, msf_host_info, msf_service_info,
#   msf_vulnerability_info, msf_note_info, msf_credential_info, msf_loot_info
#
# For exploit execution / session interaction → use exploit-runner instead.
# Upstream plans to add execution tools later; we'll inherit them automatically.
#
# ─── Layout ────────────────────────────────────────────────────────────────
# Kali ships metasploit-framework but trails master, so msfmcpd (April 2026)
# isn't in the apt package yet. We hybrid-install: take Kali's framework gems
# + Postgres for the DB tier, then sparse-clone the upstream MCP layer
# (lib/msf/core/mcp{.rb,/}, msfmcpd, config example) and bundle-install the
# `mcp` gem into Kali's existing bundle. Once Kali catches up, this whole
# block collapses to a single `apt install metasploit-framework` line.

FROM kalilinux/kali-rolling

LABEL org.opencontainers.image.source="https://github.com/silicon-works/mcp-tools"
LABEL org.opencontainers.image.description="metasploit MCP server (Rapid7 msfmcpd) for OpenSploit"
LABEL org.opencontainers.image.licenses="BSD-3-Clause"

ARG KALI_MIRROR=http://kali.cs.nctu.edu.tw/kali
RUN echo "deb $KALI_MIRROR kali-rolling main contrib non-free non-free-firmware" \
        > /etc/apt/sources.list && \
    apt-get update && \
    apt-get install -y --no-install-recommends \
        metasploit-framework \
        postgresql \
        procps \
        git && \
    rm -rf /var/lib/apt/lists/* && \
    apt-get clean

# Sparse-clone upstream master to grab the MCP server code that hasn't
# landed in Kali's apt package yet. We don't need the full repo — just the
# 8-tool MCP layer plus the entrypoint script.
RUN git clone --depth=1 --filter=blob:none --sparse \
        https://github.com/rapid7/metasploit-framework.git /tmp/msf-upstream && \
    cd /tmp/msf-upstream && \
    git sparse-checkout set --skip-checks \
        lib/msf/core/mcp.rb \
        lib/msf/core/mcp \
        config/mcp_config.yaml.example \
        msfmcpd \
        msfrpcd && \
    cp lib/msf/core/mcp.rb /usr/share/metasploit-framework/lib/msf/core/ && \
    cp -r lib/msf/core/mcp /usr/share/metasploit-framework/lib/msf/core/ && \
    cp msfmcpd /usr/share/metasploit-framework/msfmcpd && \
    chmod +x /usr/share/metasploit-framework/msfmcpd && \
    # msfmcpd's RpcManager passes credentials via MSF_RPC_USER / MSF_RPC_PASS
    # env vars — that wiring landed AFTER Kali's 6.4.126 cut, so we replace
    # the framework's msfrpcd with the upstream one (env-var aware).
    cp msfrpcd /usr/share/metasploit-framework/msfrpcd && \
    chmod +x /usr/share/metasploit-framework/msfrpcd && \
    cp config/mcp_config.yaml.example \
        /usr/share/metasploit-framework/config/ && \
    rm -rf /tmp/msf-upstream

# Add the mcp gem (0.13.0) to Kali's bundle. We unfreeze the lockfile,
# install just the new dependencies, then re-freeze for runtime safety.
WORKDIR /usr/share/metasploit-framework
RUN echo "gem 'mcp', '0.13.0'" >> Gemfile && \
    bundle config set --local frozen false && \
    bundle install --jobs=4 && \
    bundle config set --local frozen true

# Convenience symlink so PATH discovery finds msfmcpd.
RUN ln -sf /usr/share/metasploit-framework/msfmcpd /usr/local/bin/msfmcpd

# Sanity check: the binary actually runs and prints its banner.
RUN /usr/share/metasploit-framework/msfmcpd --version 2>&1 | head -3

WORKDIR /app
COPY tools/metasploit/entrypoint.sh /app/entrypoint.sh
RUN chmod +x /app/entrypoint.sh

ENTRYPOINT ["bash", "/app/entrypoint.sh"]
