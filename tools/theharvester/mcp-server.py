#!/usr/bin/env python3
"""
OpenSploit MCP Server: theharvester

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
        name="theharvester",
        description="Email and subdomain OSINT via theHarvester v4.10.1 — passive reconnaissance for emails, subdomains, IPs, ASNs, and interesting URLs from 50+ data sources spanning certificate transparency logs, DNS aggregators, search engines, threat-int...",
    )
