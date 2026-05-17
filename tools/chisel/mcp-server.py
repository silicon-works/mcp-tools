#!/usr/bin/env python3
"""
OpenSploit MCP Server: chisel

kind:cli — exposes only the auto-registered run_cli method from
BaseMCPServer. The agent emits raw argv via cli_in_container; chisel
takes a `server` or `client` subcommand followed by mode-specific
flags + remote specs. Single Go binary at /usr/local/bin/chisel.

Operational knowledge (engagement-lifetime daemon semantics, fingerprint
extraction from stderr log, --keyfile persistence for stable fingerprint,
agent-side server vs target-side client division, --network=host port
reachability, TLS via --tls-cert/--tls-key, backend proxy for stealth,
SOCKS reachability for proxychains) lives in tool.yaml as usage_patterns
+ gotchas. The 582-LOC bespoke wrapper (asyncio subprocess + in-memory
process dict + fingerprint extraction loop + close-by-id) collapses to
this 22-LOC stub because all of that work now happens per-call via
cli_in_container + filesystem state at /session/output/chisel/.
"""

from mcp_common import RunCliServer

if __name__ == "__main__":
    RunCliServer.serve(
        name="chisel",
        description="HTTP-based tunneling and SOCKS5 proxy via Chisel v1.11.4 (jpillora/chisel). Single Go binary, server/client subcommands. Engagement-lifetime daemon — recipes use cli_in_container's max_runtime_seconds (24h default) as the kill switch; filesystem state at /session/output/chisel/ replaces the legacy in-memory process dict.",
    )
