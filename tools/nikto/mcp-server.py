#!/usr/bin/env python3
"""
OpenSploit MCP Server: nikto

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
        name="nikto",
        description="Perl-based legacy web-server vulnerability scanner that runs ~6,900 HTTP-server checks (plus 6,200 Drupal-specific and 1,800 dictionary checks) against a target.",
    )
