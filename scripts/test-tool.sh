#!/bin/sh
# Run tests for a single MCP tool server.
#
# Usage:
#   ./scripts/test-tool.sh <tool-name> [--rebuild]
#
# Builds the Docker image if it doesn't exist (or if --rebuild is passed),
# then runs pytest with --tool=<tool-name>.
#
# Must be run from the repo root (or the script will cd there).

TOOL=$1
REBUILD=${2:-""}

if [ -z "$TOOL" ]; then
  echo "Usage: $0 <tool-name> [--rebuild]"
  exit 1
fi

cd "$(dirname "$0")/.."

# Verify the tool directory exists
if [ ! -d "tools/$TOOL" ]; then
  echo "Error: tools/$TOOL does not exist"
  exit 1
fi

# Build image if needed
IMAGE="mcp-test-$TOOL"
if [ "$REBUILD" = "--rebuild" ] || ! docker image inspect "$IMAGE" >/dev/null 2>&1; then
  echo "Building $TOOL..."
  docker build -t "$IMAGE" -f "tools/$TOOL/Dockerfile" . || exit 1
else
  echo "Image $IMAGE exists, skipping build (use --rebuild to force)"
fi

pytest tests/ -k "$TOOL or smoke" --tool="$TOOL" -v
