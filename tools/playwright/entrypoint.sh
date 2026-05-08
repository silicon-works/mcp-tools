#!/bin/bash
set -e

# Pre-create the platform-convention output dir so Playwright file-output tools
# (page.pdf, page.screenshot, page.video, tracing) can write directly to
# /session/output/<name>.<ext> without each agent having to mkdir first.
# This runs AFTER ContainerManager bind-mounts ${sessionDir}:/session:rw, so
# the mkdir lands on the host-mapped filesystem (visible to opensploit).
# page.pdf / page.screenshot do NOT auto-create parent dirs (verified live
# 2026-05-08); without this, agents writing to /session/output/x.pdf get
# ENOENT silently.
mkdir -p /session/output 2>/dev/null || true

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
#
# Caps in @playwright/mcp v0.0.75:
#   vision   — mouse_*_xy primitives (browser_mouse_click_xy, _move_xy, _drag_xy)
#   pdf      — browser_pdf_save
#   devtools — browser_run_code_unsafe (raw JS in the page)
#   testing  — browser_verify_* helpers (verify_element_visible / list_visible /
#              text_visible / value, plus browser_generate_locator). Not in
#              `--help` output (looks retired) but still honored by the runtime
#              and unlocks 5 tools we want for assertion flows. Keep until
#              proven gone.
#   tracing  — was a pre-v0.0.75 cap; tracing tools (browser_start_tracing /
#              stop_tracing) are now in the default surface, no flag needed.
# Video tools (browser_start_video / stop_video / video_chapter) are also
# default-enabled.
# --allow-unrestricted-file-access: required so file-output tools
# (browser_take_screenshot/pdf_save/start_video/start_tracing) can write
# under /session/output/<name>.<ext>. By default Playwright sandboxes
# output to its own workspace dir (/tmp/.playwright-mcp); without this
# flag agents trying to write to /session/output/ get
# 'File access denied: <path> is outside allowed roots' (verified live
# 2026-05-08).
# --timeout-navigation 30000: cap unreachable-URL hangs at 30s instead of upstream
#   default 60s. browser_navigate has NO per-call timeout arg, and per-page
#   page.setDefaultNavigationTimeout() set via run_code_unsafe is IGNORED — the
#   MCP wrapper enforces its own outer timeout. Verified live 2026-05-08:
#   navigate to http://10.99.99.99/ blocked exactly 60s with default; 30s caps
#   the wasted-call cost on unreachable HTB boxes / VPN dropouts. Legitimate
#   slow pages (heavy SPAs) load in <15s, so 30s leaves margin.
exec npx @playwright/mcp --config "$CONFIG" --caps=vision,pdf,devtools,testing --allow-unrestricted-file-access --output-dir /session/output --timeout-navigation 30000
