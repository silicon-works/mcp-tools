#!/usr/bin/env python3
"""
OpenSploit MCP Server: ftp

kind:cli — exposes only the auto-registered run_cli method from
BaseMCPServer. The agent emits raw argv via cli_in_container; curl
handles all FTP/FTPS operations via its built-in protocol support.
Single binary at /usr/bin/curl (Debian package, 8.14.1+).

Operational knowledge (anonymous-by-default behavior of curl
ftp:// without -u, passive-mode default vs --ftp-active, FTPS
implicit ftps:// vs explicit --ssl-reqd, raw FTP command
injection via --quote, base64 round-trip for binary up/download,
50KB text-truncation as agent-side concern via head -c) lives in
tool.yaml as usage_patterns + gotchas. The 564-LOC bespoke wrapper
(Python ftplib + temp-file management + LIST output parsing +
base64 encoding + welcome-banner extraction) collapses to this
22-LOC stub because all of that work now happens per-call via
curl + bash.
"""

from mcp_common import RunCliServer

if __name__ == "__main__":
    RunCliServer.serve(
        name="ftp",
        description="FTP/FTPS client via /usr/bin/curl for connect, list, download, upload, delete. Stateless per-call. The 564-LOC kind:mcp wrapper (May 2026 retired) collapses to raw curl argv via cli_in_container; usage_patterns + gotchas in tool.yaml carry the anonymous-default behavior, passive/active mode, FTPS modes, base64 path, and --quote FTP-command idiom.",
    )
