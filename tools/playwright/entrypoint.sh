#!/bin/bash
set -e

export DISPLAY=:99

# Start virtual framebuffer (1920x1080, 24-bit color)
Xvfb :99 -screen 0 1920x1080x24 -ac >/dev/null 2>&1 &
sleep 1

# Start VNC server — no password, shared connections allowed
x11vnc -display :99 -forever -nopw -shared -rfbport 5900 >/dev/null 2>&1 &
sleep 0.5

# Start noVNC web proxy (accessible at http://localhost:6080/vnc.html)
websockify --web /usr/share/novnc 6080 localhost:5900 >/dev/null 2>&1 &

# Select config based on HEADED env var
# Default: headless (uses chrome-headless-shell, VPN-compatible)
# HEADED=1: headed mode (uses full chrome binary, needs socat proxy for VPN)
CONFIG="/config.json"

if [ "${HEADED}" = "1" ]; then
  echo "Running in headed mode (VNC visible at http://localhost:6080/vnc.html)" >&2

  # The full chrome binary cannot reach tun0/VPN IPs (ERR_ADDRESS_UNREACHABLE).
  # Workaround: socat proxies localhost:80 -> VPN target, and --host-resolver-rules
  # makes Chrome resolve the hostname to 127.0.0.1.
  # See: opensploit-training-data/CHROMIUM_HEADED_VPN_BUG.md

  if [ -n "${VPN_TARGET}" ] && [ -n "${VPN_HOSTNAME}" ]; then
    # Start socat proxy: localhost:80 -> VPN target:80
    socat TCP-LISTEN:80,fork,reuseaddr TCP:"${VPN_TARGET}":80 >/dev/null 2>&1 &

    # If target also has HTTPS, proxy port 443 too
    if [ -n "${VPN_TARGET_HTTPS}" ]; then
      socat TCP-LISTEN:443,fork,reuseaddr TCP:"${VPN_TARGET}":443 >/dev/null 2>&1 &
    fi

    sleep 1

    # Generate headed config with host-resolver-rules
    # Supports multiple hostnames: VPN_HOSTNAME="host1,host2"
    RESOLVER_RULES=""
    IFS=',' read -ra HOSTS <<< "${VPN_HOSTNAME}"
    for host in "${HOSTS[@]}"; do
      host=$(echo "$host" | xargs)  # trim whitespace
      if [ -n "${RESOLVER_RULES}" ]; then
        RESOLVER_RULES="${RESOLVER_RULES}, "
      fi
      RESOLVER_RULES="${RESOLVER_RULES}MAP ${host} 127.0.0.1"
    done

    echo "{\"browser\":{\"browserName\":\"chromium\",\"launchOptions\":{\"channel\":\"\",\"headless\":false,\"chromiumSandbox\":false,\"args\":[\"--host-resolver-rules=${RESOLVER_RULES}\",\"--window-size=1920,1080\",\"--window-position=0,0\"]}},\"imageResponses\":\"allow\"}" > /config-runtime.json
    CONFIG="/config-runtime.json"
    echo "VPN proxy active: ${VPN_HOSTNAME} -> 127.0.0.1 -> socat -> ${VPN_TARGET}" >&2
  else
    # Headed mode without VPN proxy (for non-VPN targets)
    CONFIG="/config-headed.json"
  fi
fi

# Playwright MCP server — communicates via stdio (stdin/stdout)
# All background processes redirect to /dev/null to keep stdio clean for MCP
exec npx @playwright/mcp --config "$CONFIG" --caps=testing,tracing,pdf,vision
