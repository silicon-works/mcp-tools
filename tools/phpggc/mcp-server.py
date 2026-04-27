#!/usr/bin/env python3
"""
OpenSploit MCP Server: phpggc

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
        name="phpggc",
        description="PHP Generic Gadget Chains — generates serialized PHP payloads for unserialize() / phar:// deserialization attacks across ~100+ gadget chains spanning 14+ frameworks (Symfony, Laravel, Monolog, Doctrine, Drupal, WordPress, Magento, Guzzle...",
    )
