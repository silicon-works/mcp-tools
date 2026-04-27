#!/usr/bin/env python3
"""
OpenSploit MCP Server: impacket

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
        name="impacket",
        description="Active Directory and SMB attack toolkit (47 Python sub-binaries: secretsdump, psexec, wmiexec, smbexec, GetUserSPNs, GetNPUsers, getTGT, getST, mssqlclient, addcomputer, findDelegation, rbcd, dacledit, ...).",
    )
