#!/usr/bin/env python3
"""
Thin wrapper around bethington/ghidra-mcp's bridge_mcp_ghidra.py.

Adds the load_binary MCP tool (missing from upstream) which loads
a binary from the filesystem into Ghidra's headless server.

All other 127 tools come from the bridge.
"""

import sys

sys.path.insert(0, "/app")

# Importing the bridge registers all @mcp.tool() functions
import bridge_mcp_ghidra
from bridge_mcp_ghidra import mcp, safe_post


@mcp.tool()
def load_binary(file: str) -> str:
    """
    Load a binary file from the filesystem into Ghidra for analysis.

    This is a headless-only endpoint. Call this first before using other
    analysis tools. Ghidra will auto-analyze the binary (5-30s depending
    on size).

    Args:
        file: Absolute path to the binary file (e.g., '/data/vuln', '/session/binary')

    Returns:
        JSON with program name, format, and analysis status
    """
    if not file:
        return '{"error": "File path is required"}'
    return safe_post("load_program", {"file": file})


if __name__ == "__main__":
    bridge_mcp_ghidra.main()
