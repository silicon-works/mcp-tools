#!/bin/bash
set -e

# msfmcpd entrypoint
#
# Bring up Postgres + msfdb (required by 6 of the 8 upstream tools), then
# exec msfmcpd. msfmcpd auto-launches msfrpcd internally with its own
# random credentials — we don't manage that anymore.
#
# Stdout is reserved for MCP JSON-RPC traffic; everything diagnostic goes
# to stderr.

# ── PostgreSQL + msfdb initialization ─────────────────────────────────────
# msf_host_info / msf_service_info / msf_vulnerability_info / msf_note_info
# / msf_credential_info / msf_loot_info all require an active DB. Without
# it they error at runtime; msf_search_modules and msf_module_info still
# work (they don't touch the DB).
echo "Initializing PostgreSQL + msfdb..." >&2
if service postgresql start >&2 2>&1; then
    for i in $(seq 1 30); do
        if pg_isready -h /var/run/postgresql -q 2>/dev/null; then
            echo "Postgres ready (after ${i}s)" >&2
            break
        fi
        sleep 1
    done

    if [ -e /usr/share/metasploit-framework/config/database.yml ]; then
        echo "msfdb already configured" >&2
    elif msfdb init >&2 2>&1; then
        echo "msfdb initialized" >&2
    else
        echo "WARNING: msfdb init failed — DB-backed tools will return errors" >&2
    fi

    # msfdb init creates the schema but does NOT create any workspaces.
    # Without at least the 'default' workspace, every msf_*_info tool
    # returns "Invalid workspace". Bootstrap it via a one-shot msfconsole
    # command so the agent's first DB call succeeds.
    if [ -e /usr/share/metasploit-framework/config/database.yml ]; then
        echo "Bootstrapping default workspace..." >&2
        msfconsole -q -x "workspace -a default; exit" >&2 2>&1 || \
            echo "WARNING: workspace bootstrap failed — first DB call may need an explicit workspace=<name> parameter" >&2
    fi
else
    echo "WARNING: postgres failed to start — DB-backed tools will return errors" >&2
fi

# ── Credentials ───────────────────────────────────────────────────────────
# msfmcpd's auto_start_rpc spawns msfrpcd internally; if MSF_API_USER /
# MSF_API_PASSWORD are unset it generates random ones. We surface them via
# env so the caller can override for debugging.
if [ -z "${MSF_API_USER:-}" ]; then
    export MSF_API_USER="msf"
fi
if [ -z "${MSF_API_PASSWORD:-}" ]; then
    MSF_API_PASSWORD="$(python3 -c 'import secrets; print(secrets.token_hex(16))' 2>/dev/null \
                        || od -A n -t x1 /dev/urandom | tr -d ' \n' | head -c 32)"
    echo "MSF_API_PASSWORD: generated random per-session value" >&2
    export MSF_API_PASSWORD
else
    echo "MSF_API_PASSWORD: using caller-provided value" >&2
fi

# Default config: stdio transport, MessagePack RPC, auto-start msfrpcd.
export MSF_MCP_TRANSPORT="${MSF_MCP_TRANSPORT:-stdio}"
export MSF_API_TYPE="${MSF_API_TYPE:-messagepack}"
export MSF_API_HOST="${MSF_API_HOST:-127.0.0.1}"
export MSF_API_PORT="${MSF_API_PORT:-55553}"
export MSF_AUTO_START_RPC="${MSF_AUTO_START_RPC:-true}"

# ── Launch msfmcpd ────────────────────────────────────────────────────────
# msfmcpd handles its own startup polling for msfrpcd — no manual wait loop
# required. stdio is on fd 0/1; all msfmcpd diagnostics go to fd 2.
#
# We must chdir into the metasploit-framework tree so `bundler/setup` finds
# the framework's Gemfile (which has the mcp gem we added at build time).
# Running the symlink from /usr/local/bin makes bundler resolve a different
# Gemfile and fail with "cannot load such file -- msf/core/mcp".
export BUNDLE_GEMFILE=/usr/share/metasploit-framework/Gemfile
cd /usr/share/metasploit-framework
exec ./msfmcpd --user "$MSF_API_USER" --password "$MSF_API_PASSWORD"
