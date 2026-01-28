#!/bin/bash
# Start ZAP in daemon mode and then run MCP server

# Start ZAP daemon in background with Chrome configured for AJAX spider
# Chrome is more reliable than Firefox in Docker containers
# Chrome args: --no-sandbox (required for root), --disable-features=HttpsUpgrades (prevent HTTP->HTTPS)
/zap/zap.sh -daemon -host 127.0.0.1 -port ${ZAP_PORT:-8080} \
    -config api.addrs.addr.name=.* \
    -config api.addrs.addr.regex=true \
    -config api.disablekey=true \
    -config ajaxSpider.browserId=chrome-headless \
    -config "selenium.chromeArgs.arg(0).argument=--no-sandbox" \
    -config "selenium.chromeArgs.arg(1).argument=--disable-features=HttpsUpgrades" >&2 &

ZAP_PID=$!

# Wait for ZAP API to be ready
echo "Waiting for ZAP to start..." >&2
for i in {1..60}; do
    if curl -s "http://127.0.0.1:${ZAP_PORT:-8080}/JSON/core/view/version/" > /dev/null 2>&1; then
        echo "ZAP is ready" >&2
        break
    fi
    sleep 1
done

# Check if ZAP started successfully
if ! curl -s "http://127.0.0.1:${ZAP_PORT:-8080}/JSON/core/view/version/" > /dev/null 2>&1; then
    echo "ERROR: ZAP failed to start" >&2
    exit 1
fi

# Run MCP server (foreground, handles stdio)
exec python3 /app/mcp-server.py
