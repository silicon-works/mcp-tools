#!/bin/sh
# Container-level smoke test for kind:cli tools.
#
# Builds the tool's Docker image, then runs the binary inside with the supplied
# arguments. Mounts ./.test-session as /session so we can verify the writable
# session contract. Prints exit code and a hint on where output landed.
#
# Usage:
#   ./scripts/test-cli-tool.sh <tool-name> [<args>...]
#   ./scripts/test-cli-tool.sh <tool-name> --binary <impacket-secretsdump> [<args>...]
#
# When tool.yaml omits top-level `binary:` (multi-binary tools like impacket),
# pass --binary <name> as the first argument after the tool name. Otherwise
# the binary is read from tool.yaml.
#
# Examples:
#   ./scripts/test-cli-tool.sh curl --version
#   ./scripts/test-cli-tool.sh curl -sSI http://10.129.206.176/
#   ./scripts/test-cli-tool.sh impacket --binary impacket-secretsdump --help
#   ./scripts/test-cli-tool.sh impacket --binary impacket-GetUserSPNs CORP/u:p -dc-ip 10.10.10.5

set -eu

if [ $# -lt 1 ]; then
    echo "Usage: $0 <tool-name> [--binary <name>] [<args>...]" >&2
    exit 2
fi

TOOL="$1"
shift

# Optional --binary override (for multi-binary tools like impacket)
BINARY_OVERRIDE=""
if [ "${1:-}" = "--binary" ] && [ $# -ge 2 ]; then
    BINARY_OVERRIDE="$2"
    shift 2
fi

SCRIPT_DIR="$(cd "$(dirname "$0")" && pwd)"
REPO_ROOT="$(cd "$SCRIPT_DIR/.." && pwd)"
TOOL_DIR="$REPO_ROOT/tools/$TOOL"

if [ ! -d "$TOOL_DIR" ]; then
    echo "ERROR: tool dir not found: $TOOL_DIR" >&2
    exit 1
fi

if [ ! -f "$TOOL_DIR/tool.yaml" ]; then
    echo "ERROR: tool.yaml not found: $TOOL_DIR/tool.yaml" >&2
    exit 1
fi

if [ ! -f "$TOOL_DIR/Dockerfile" ]; then
    echo "ERROR: Dockerfile not found: $TOOL_DIR/Dockerfile" >&2
    exit 1
fi

# Resolve binary: --binary override wins; otherwise read from tool.yaml.
BINARY="$BINARY_OVERRIDE"
if [ -z "$BINARY" ]; then
    if command -v yq >/dev/null 2>&1; then
        BINARY="$(yq -r '.binary // empty' "$TOOL_DIR/tool.yaml" 2>/dev/null || true)"
    fi
    if [ -z "$BINARY" ]; then
        BINARY="$(awk '/^binary:[[:space:]]/{print $2; exit}' "$TOOL_DIR/tool.yaml")"
    fi
fi
if [ -z "$BINARY" ]; then
    echo "ERROR: could not resolve binary. Either set top-level 'binary:' in $TOOL_DIR/tool.yaml," >&2
    echo "       or pass --binary <name> as the first arg (multi-binary tools)." >&2
    exit 1
fi

# Per-tool session sandbox. Cleared each run so we can verify the mount writes.
SESSION_DIR="$REPO_ROOT/.test-session/$TOOL"
rm -rf "$SESSION_DIR"
mkdir -p "$SESSION_DIR"

IMAGE="mcp-test-$TOOL"

echo ">>> Building image $IMAGE from $TOOL_DIR/Dockerfile"
docker build -q -t "$IMAGE" -f "$TOOL_DIR/Dockerfile" "$REPO_ROOT" >/dev/null

echo ">>> Image size:"
docker image inspect "$IMAGE" --format '{{.Size}}' \
    | awk '{printf "    %.1f MB\n", $1/1024/1024}'

echo ">>> Running: $BINARY $*"
echo ">>> Session dir: $SESSION_DIR (mounted as /session, writable)"

set +e
docker run --rm --network=host -v "$SESSION_DIR:/session" "$IMAGE" "$BINARY" "$@"
RC=$?
set -e

echo ">>> Exit: $RC"

# Show what landed in /session, if anything.
if [ -n "$(ls -A "$SESSION_DIR" 2>/dev/null)" ]; then
    echo ">>> /session contents:"
    ls -la "$SESSION_DIR" | sed 's/^/    /'
else
    echo ">>> /session is empty (no output written by tool)"
fi

exit $RC
