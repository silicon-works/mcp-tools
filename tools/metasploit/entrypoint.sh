#!/bin/bash
set -e

# MSF_PASSWORD: per-engagement random by default (defense in depth — only
# matters if the container is ever exposed beyond loopback). Override with
# MSF_PASSWORD env from caller for reproducibility / debugging.
#
# We EXPORT so both msfrpcd (started below with -P flag) and the MCP server
# (which reads os.environ.get("MSF_PASSWORD") at line 371 of mcp-server.py)
# see the same value. Without export, MCP server would fall back to default
# and fail to authenticate to the daemon.
if [ -z "${MSF_PASSWORD:-}" ]; then
    MSF_PASSWORD="$(python3 -c 'import secrets; print(secrets.token_hex(16))' 2>/dev/null \
                    || od -A n -t x1 /dev/urandom | tr -d ' \n' | head -c 32)"
    echo "MSF_PASSWORD: generated random per-session value" >&2
else
    echo "MSF_PASSWORD: using caller-provided value" >&2
fi
export MSF_PASSWORD

# ── PostgreSQL + msfdb initialization (May 2026) ──────────────────────────
# Without a database, msfconsole's hosts/services/creds/loot/notes/vulns/
# db_nmap/db_import commands all fail. Per-session container = clean DB
# state each engagement, which is the right semantics. Cost: ~30-60s cold
# start latency (postgres start + msfdb init on first run).
#
# This block was added May 2026 after the user pushed for ~80%+ msfconsole
# coverage. Without it, ~7 methods (list_hosts, list_services, list_creds,
# list_vulns, list_loot, list_notes, db_nmap, db_import) silently fail.
#
# If postgres/msfdb setup fails (e.g., environment missing the postgres
# package), we fall back to msfrpcd -n (no DB) so the rest of the tool
# still works. The agent gets clear errors when calling DB-dependent methods.
ENABLE_DB=1
if [ "$ENABLE_DB" = "1" ]; then
    echo "Initializing PostgreSQL + msfdb..." >&2
    if service postgresql start >&2 2>&1; then
        # Wait for postgres to accept connections
        for i in $(seq 1 30); do
            if pg_isready -h /var/run/postgresql -q 2>/dev/null; then
                echo "Postgres ready (after ~$((i))s)" >&2
                break
            fi
            sleep 1
        done

        # Initialize msfdb (creates msf user + database, writes
        # /usr/share/metasploit-framework/config/database.yml).
        #
        # NOTE: Kali's msfdb is strict — exactly one positional arg required.
        # Earlier versions of this entrypoint passed `init --use-defaults`,
        # which silently dropped through to the usage banner (exit 0) without
        # actually initializing anything. msfrpcd then started without
        # database.yml, and every console spawned through it inherited
        # "Database not connected" — breaking db_nmap, list_hosts/services,
        # list_creds/loot/notes. Plain `msfdb init` is non-interactive on
        # this image (no prompts), so no extra flags are needed.
        #
        # After this succeeds, msfrpcd reads database.yml on startup and ALL
        # consoles (shared and per-call) inherit the active DB connection —
        # we must NOT pass `-n` to msfrpcd in that case.
        if [ -e /usr/share/metasploit-framework/config/database.yml ]; then
            echo "msfdb already configured (database.yml present)" >&2
            DB_FLAGS=""
        elif msfdb init >&2 2>&1; then
            if [ -e /usr/share/metasploit-framework/config/database.yml ]; then
                echo "msfdb initialized" >&2
                DB_FLAGS=""
            else
                echo "WARNING: msfdb init exited 0 but database.yml missing — falling back to no-database mode" >&2
                DB_FLAGS="-n"
            fi
        else
            echo "WARNING: msfdb init failed, falling back to no-database mode" >&2
            DB_FLAGS="-n"
        fi
    else
        echo "WARNING: postgres failed to start, falling back to no-database mode" >&2
        DB_FLAGS="-n"
    fi
else
    DB_FLAGS="-n"
fi

# Start msfrpcd in background. -f = stay foreground (we background via &).
# -S = no SSL. $DB_FLAGS = "" if DB initialized, "-n" if we fell back.
# All output to stderr to keep stdout clean for MCP JSON-RPC.
msfrpcd -P "$MSF_PASSWORD" -U msf -f -S $DB_FLAGS -a 127.0.0.1 -p 55553 >&2 &
MSFRPCD_PID=$!

# Wait for msfrpcd to accept connections (up to 180s — DB-enabled boot is
# slower than -n boot. Pre-DB-fix this was 120s. Bumped May 2026.)
echo "Waiting for msfrpcd to start..." >&2
ready=false
for i in $(seq 1 90); do
    if (echo > /dev/tcp/127.0.0.1/55553) 2>/dev/null; then
        echo "msfrpcd is ready (after ~$((i * 2))s)" >&2
        ready=true
        break
    fi
    if ! kill -0 "$MSFRPCD_PID" 2>/dev/null; then
        echo "ERROR: msfrpcd exited unexpectedly" >&2
        exit 1
    fi
    sleep 2
done

if [ "$ready" = false ]; then
    echo "WARNING: msfrpcd not ready after 180s, MCP server will retry connection" >&2
fi

# Start MCP server (foreground — stdio to ContainerManager)
exec python3 /app/mcp-server.py
