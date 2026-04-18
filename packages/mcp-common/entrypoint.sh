#!/bin/sh
if [ -n "$FAKETIME" ]; then
  FAKETIME_LIB=$(find /usr/lib -name "libfaketime.so.1" 2>/dev/null | head -1)
  if [ -n "$FAKETIME_LIB" ]; then
    export LD_PRELOAD="$FAKETIME_LIB"
    export FAKETIME_DONT_FAKE_MONOTONIC=1
  else
    unset LD_PRELOAD
    echo "FAKETIME_ERROR: FAKETIME=$FAKETIME but libfaketime.so.1 not found" >&2
  fi
fi
exec python3 mcp-server.py
