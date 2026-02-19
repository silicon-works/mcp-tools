#!/bin/bash
set -e

# Start msfrpcd in background (-f = stay in foreground so bash owns the PID,
# -S = no SSL, -n = no database).  We background via '&' ourselves.
# All output goes to stderr to keep stdout clean for MCP JSON-RPC.
msfrpcd -P "${MSF_PASSWORD:-msfpassword}" -U msf -f -S -n -a 127.0.0.1 -p 55553 >&2 &
MSFRPCD_PID=$!

# Wait for msfrpcd to accept connections (up to 120s — first boot initializes modules)
echo "Waiting for msfrpcd to start..." >&2
ready=false
for i in $(seq 1 60); do
    if (echo > /dev/tcp/127.0.0.1/55553) 2>/dev/null; then
        echo "msfrpcd is ready (after ~$((i * 2))s)" >&2
        ready=true
        break
    fi
    # Check msfrpcd didn't crash
    if ! kill -0 "$MSFRPCD_PID" 2>/dev/null; then
        echo "ERROR: msfrpcd exited unexpectedly" >&2
        exit 1
    fi
    sleep 2
done

if [ "$ready" = false ]; then
    echo "WARNING: msfrpcd not ready after 120s, MCP server will retry connection" >&2
fi

# Start MCP server (foreground — stdio to ContainerManager)
exec python3 /app/mcp-server.py
