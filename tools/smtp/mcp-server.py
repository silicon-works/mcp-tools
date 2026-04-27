#!/usr/bin/env python3
"""
OpenSploit MCP Server: smtp

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
        name="smtp",
        description="SMTP testing toolkit wrapping two binaries: `swaks` (the Swiss Army Knife for SMTP — send crafted mail, test open relays, probe TLS/auth, inject headers, dry-run with --quit-after) and `smtp-user-enum` (Perl tool for VRFY/EXPN/RCPT TO us...",
    )
