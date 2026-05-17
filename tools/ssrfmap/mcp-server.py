#!/usr/bin/env python3
"""
OpenSploit MCP Server: ssrfmap

kind:cli — exposes only the auto-registered run_cli method from
BaseMCPServer. The agent emits raw argv via cli_in_container;
SSRFmap is invoked as `python3 /opt/ssrfmap/ssrfmap.py -r REQFILE
-p PARAM -m MODULE [...]`.

Operational knowledge (request-file format with \\r\\n line endings,
all 24 modules and their use cases, --level 1-5 WAF bypass,
-l PORT internal reverse-shell handler, diff-based response
extraction writing to /opt/ssrfmap/<host>_<port>/, the bash-wrapper
recipe pattern that cp's captured files to /session/output/ssrfmap/)
lives in tool.yaml as usage_patterns + gotchas. The 597-LOC
re-implementation wrapper (Python `requests` based, never invoked
the real SSRFmap binary that was sitting in the image) collapses
to this 22-LOC stub; agent now uses the REAL SSRFmap with all 24
modules instead of the wrapper's 2 effectively-implemented modules.
"""

from mcp_common import RunCliServer

if __name__ == "__main__":
    RunCliServer.serve(
        name="ssrfmap",
        description="SSRF exploitation framework via swisskyrepo/SSRFmap CLI (/opt/ssrfmap/ssrfmap.py, 24 modules). Stateless per-call: agent writes raw HTTP request file → ssrfmap fires payloads → captured response data (diff-based extraction) lands in /opt/ssrfmap/<host>_<port>/ which recipes auto-cp to /session/output/ssrfmap/. The 597-LOC kind:mcp wrapper (May 2026 retired) was a Python `requests` re-implementation that never invoked the real SSRFmap; this kind:cli flip exposes the full 24-module surface.",
    )
