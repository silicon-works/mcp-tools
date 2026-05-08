#!/bin/bash
set -e

# zap (vendor MCP add-on) entrypoint
#
# Boot ZAP in daemon mode with the MCP HTTP listener enabled, wait for the
# listener to come up, then exec the stdio↔HTTP bridge.
#
# Stdout (fd 1) is reserved for MCP JSON-RPC traffic. ZAP's own stdout/stderr,
# our own logs, curl output — everything diagnostic — must go to fd 2.

ZAP_MCP_PORT="${ZAP_MCP_PORT:-8282}"

# ── Generate or accept a security key ────────────────────────────────────
# ZAP's MCP add-on enforces an Authorization header check (raw-key compare —
# no Bearer prefix). Default: mint a fresh 32-hex-char key per container
# start. Override with ZAP_MCP_KEY env from the caller for debugging /
# attaching a manual MCP client. We pass the resolved value to both ZAP
# (via -config) and the bridge (via env).
if [ -z "${ZAP_MCP_KEY:-}" ]; then
    ZAP_MCP_KEY="$(python3 -c 'import secrets; print(secrets.token_hex(16))')"
    echo "ZAP MCP: generated random per-session key (length=${#ZAP_MCP_KEY})" >&2
else
    echo "ZAP MCP: using caller-provided ZAP_MCP_KEY (length=${#ZAP_MCP_KEY})" >&2
fi
export ZAP_MCP_KEY

# ── Launch ZAP daemon ─────────────────────────────────────────────────────
# Key config flags:
#   mcp.securityKeyEnabled / mcp.securityKey — auth (per McpParam.java)
#   mcp.secureOnly         — defaults to TRUE (HTTPS-only); we MUST disable
#                            it to use plaintext HTTP on loopback
#   mcp.recordInHistory    — keep MCP traffic out of ZAP's history table
#   mcp.port               — default 8282 anyway, set explicitly for clarity
#
# Other settings:
#   api.disablekey=true               — don't gate ZAP's classic JSON API
#   api.addrs.addr.name=.* / regex    — accept API calls from any addr
#   network.localServers ... addOnUpdate=Disabled — silence first-run prompts
#
# All ZAP output redirected to stderr so MCP stdout stays clean. ZAP also
# closes stdin once daemonized — we redirect stdin from /dev/null so it
# doesn't fight with the bridge for the real fd 0.
echo "ZAP MCP: starting ZAP daemon on 127.0.0.1:${ZAP_MCP_PORT}..." >&2
/zap/zap.sh -daemon \
    -host 127.0.0.1 \
    -port 8090 \
    -config api.disablekey=true \
    -config api.addrs.addr.name=.* \
    -config api.addrs.addr.regex=true \
    -config mcp.port="${ZAP_MCP_PORT}" \
    -config mcp.securityKeyEnabled=true \
    -config mcp.securityKey="${ZAP_MCP_KEY}" \
    -config mcp.secureOnly=false \
    -config mcp.recordInHistory=false \
    </dev/null >&2 2>&1 &

ZAP_PID=$!
echo "ZAP MCP: daemon PID=${ZAP_PID}" >&2

# ── Wait for the MCP HTTP listener to accept connections ──────────────────
# ZAP cold start is slow (30-60s typically; allow up to 120s). The MCP
# server starts late in the boot sequence — after add-on options load —
# so polling the classic API on :8090 isn't sufficient. We poll the MCP
# port directly with an unauthenticated POST and look for HTTP 401 (which
# means the listener is up; without a valid key we get rejected at auth).
URL="http://127.0.0.1:${ZAP_MCP_PORT}/"
DEADLINE=$(( $(date +%s) + 120 ))
echo "ZAP MCP: waiting for listener at ${URL}..." >&2
while true; do
    if [ "$(date +%s)" -ge "$DEADLINE" ]; then
        echo "ERROR: ZAP MCP listener didn't come up within 120s" >&2
        kill "$ZAP_PID" 2>/dev/null || true
        exit 1
    fi
    if ! kill -0 "$ZAP_PID" 2>/dev/null; then
        echo "ERROR: ZAP daemon exited before MCP listener came up" >&2
        exit 1
    fi
    # Try a bare POST. We only care that the TCP+HTTP layer is reachable.
    # Any HTTP response (including 401 Unauthorized) means the listener is
    # alive; only connection refused / timeout means we keep waiting.
    #
    # `-4` forces IPv4 (avoids curl trying ::1 first and writing "000" for
    # the failed v6 attempt before the v4 success, which causes the
    # %{http_code} writer to emit a concatenated value like "000200").
    HTTP_CODE=$(curl -s -o /dev/null -w '%{http_code}' -4 \
        -X POST -H 'Content-Type: application/json' \
        --data '{"probe":1}' \
        --connect-timeout 2 --max-time 5 \
        "$URL" 2>/dev/null || echo "000")
    # A real HTTP response is always exactly 3 digits; "000" means curl
    # failed to connect (still booting). Anything else means the MCP
    # listener is up — even 400/401 is fine, we just need TCP/HTTP layer.
    if [ "${#HTTP_CODE}" = "3" ] && [ "$HTTP_CODE" != "000" ]; then
        echo "ZAP MCP: listener responding (HTTP ${HTTP_CODE})" >&2
        break
    fi
    sleep 1
done

# ── Hand off to the stdio↔HTTP bridge ────────────────────────────────────
# exec replaces this shell with python so signals propagate to the bridge
# directly. ZAP keeps running in the background as a subprocess; when the
# bridge exits (stdin EOF), the container exits and Docker reaps ZAP.
echo "ZAP MCP: handing stdio off to bridge.py" >&2
exec python3 /app/bridge.py
