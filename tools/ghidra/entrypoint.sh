#!/bin/bash
# OpenSploit MCP Server: ghidra
# Starts Ghidra headless server (Java) in background, then runs
# bridge_mcp_ghidra.py (Python MCP stdio) in foreground.
# Same pattern as Playwright's entrypoint.sh.

set -e

GHIDRA_HOME="${GHIDRA_HOME:-/opt/ghidra}"
PORT="${GHIDRA_MCP_PORT:-8089}"
JAVA_OPTS="${JAVA_OPTS:--Xmx4g -XX:+UseG1GC}"

# Build classpath from Ghidra JARs (matches bethington's entrypoint pattern)
CLASSPATH="/app/GhidraMCP.jar"
for jar in "${GHIDRA_HOME}"/Ghidra/Framework/*/lib/*.jar \
           "${GHIDRA_HOME}"/Ghidra/Features/*/lib/*.jar \
           "${GHIDRA_HOME}"/Ghidra/Processors/*/lib/*.jar; do
    [ -f "$jar" ] && CLASSPATH="${CLASSPATH}:${jar}"
done

# Start Ghidra headless REST server in background
# Redirect to /dev/null to keep MCP stdio channel clean
java \
    ${JAVA_OPTS} \
    -Dghidra.home="${GHIDRA_HOME}" \
    -Dapplication.name=GhidraMCP \
    -classpath "${CLASSPATH}" \
    com.xebyte.headless.GhidraMCPHeadlessServer \
    --bind 127.0.0.1 --port "${PORT}" \
    >/dev/null 2>&1 &

# Wait for server to be ready
echo "Waiting for Ghidra headless server on port ${PORT}..." >&2
until curl -sf "http://127.0.0.1:${PORT}/check_connection" > /dev/null 2>&1; do
    sleep 1
done
echo "Ghidra headless server ready" >&2

# Run MCP bridge in foreground (stdio)
exec python3 /app/mcp-wrapper.py \
    --ghidra-server "http://127.0.0.1:${PORT}" \
    --transport stdio
