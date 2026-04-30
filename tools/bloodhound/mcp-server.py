#!/usr/bin/env python3
"""
OpenSploit MCP Server: bloodhound

kind:cli — exposes only the auto-registered run_cli method from
BaseMCPServer. The agent emits raw argv via cli_in_container; target
extraction (-ns / -dc / -gc), scope validation, and reject_flags are
handled in the plugin before this server ever sees the call.

Per-tool method handlers (collect / collect_stealth) and the
~300-line Kerberos/LDAP error classifier lived in this file before
Feature 35 collapsed the schema layer to raw argv. Recover them from
git history if a structured method or server-side parser ever proves
worth bringing back as a recipe (e.g., for `meta.version` extraction
from output JSON post-run).

Operational knowledge migrated to tool.yaml as failure_signatures and
gotchas (output prefix shape, KRB5CCNAME wrapper pattern, ATA/ATP
detection avoidance, multi-domain forest GC override, etc.).
"""

from mcp_common import RunCliServer

if __name__ == "__main__":
    RunCliServer.serve(
        name="bloodhound",
        description="Active Directory relationship mapping and attack-path data collector via bloodhound-python v1.9.0 (dirkjanm/BloodHound.py, BloodHound LEGACY ingestor — NOT BloodHound CE).",
    )
