#!/usr/bin/env python3
"""
OpenSploit MCP Server: sqlite

kind:cli — exposes only the auto-registered run_cli method from
BaseMCPServer. The agent emits raw argv via cli_in_container; sqlite3
takes a database path + SQL query (or PRAGMA / dot-command).
Single binary at /usr/bin/sqlite3 (Debian package, version 3.46.1+).

Operational knowledge (JSON output mode for parsing, BLOB hex via
quote(), special-char column quoting, find_credentials heuristic
replaced by bash-grep recipe on PRAGMA table_info, base64 path via
Write + base64 -d for downloaded DBs, WAL-mode sidecar caveats for
browser databases, sqlite_master vs sqlite_schema alias, .recover
for damaged DBs) lives in tool.yaml as usage_patterns + gotchas.
The 621-LOC bespoke wrapper (Python sqlite3 stdlib + handcrafted
credential-pattern tables + base64 temp-file management + auto-LIMIT
injection) collapses to this 22-LOC stub because all of that work
now happens per-call via sqlite3 CLI's -json output + agent-supplied
SQL.
"""

from mcp_common import RunCliServer

if __name__ == "__main__":
    RunCliServer.serve(
        name="sqlite",
        description="SQLite database client (v3.46.1 with FTS5) via /usr/bin/sqlite3 CLI for post-exploitation extraction of .db / .sqlite files. Stateless per-call: open DB → run SQL → close. Use -json for parseable output, quote(col) for BLOB hex literals, PRAGMA table_info for schema. The 621-LOC kind:mcp wrapper (May 2026 retired) collapses to raw sqlite3 argv via cli_in_container; usage_patterns + gotchas in tool.yaml carry the credential-hunt heuristic + base64 path + WAL caveats.",
    )
