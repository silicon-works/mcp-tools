#!/usr/bin/env python3
"""
OpenSploit MCP Server: responder

kind:cli — exposes only the auto-registered run_cli method from
BaseMCPServer. The agent emits raw argv via cli_in_container; responder
takes -I IFACE [flags] and runs as a privileged broadcast poisoner.

Operational knowledge (timeout wrapping, hash file locations, conf
modification for SMB-only mode, hashcat format mappings, interface
auto-detect via `ip -j addr | python3`) lives in tool.yaml as
usage_patterns + gotchas.

Pre-baked image artifacts (Responder.conf.bak + Responder-smb-only.conf)
are dropped into /usr/share/responder/ at image build time so capture_smb
mode just swaps and restores the conf file — no Python parsing needed.
"""

from mcp_common import RunCliServer

if __name__ == "__main__":
    RunCliServer.serve(
        name="responder",
        description="LLMNR/NBT-NS/MDNS broadcast poisoning + NTLMv2 hash capture via Responder v3.2.2 (lgandx/Responder, Kali apt). Privileged + host networking required.",
    )
