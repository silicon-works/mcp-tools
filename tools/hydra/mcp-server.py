#!/usr/bin/env python3
"""
OpenSploit MCP Server: hydra

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
        name="hydra",
        description="THC-Hydra v9.6 — network authentication brute-forcer supporting 50+ protocols including ssh, ftp, http-{get,post,get-form,post-form}, https-{get,post,get-form,post-form}, smb, smb2, rdp, mysql, mssql, postgres, vnc, telnet, smtp, pop3, i...",
    )
