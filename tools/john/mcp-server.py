#!/usr/bin/env python3
"""
OpenSploit MCP Server: john

kind:cli — exposes only the auto-registered run_cli method from
BaseMCPServer. The agent emits raw argv via cli_in_container; target
extraction, scope validation, and reject_flags are handled in the
plugin before this server ever sees the call.

Per-tool method handlers (request, scan, exploit, ...) lived in this
file before Feature 35 collapsed the schema layer to raw argv. Recover
them from git history if a structured method ever proves worth bringing
back as a recipe.
"""

from mcp_common import RunCliServer

if __name__ == "__main__":
    RunCliServer.serve(
        name="john",
        description="Password hash cracking tool — John the Ripper 1.9.0-jumbo-1 (community-enhanced version) with AVX2 acceleration.",
    )
