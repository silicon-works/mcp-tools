# Known Gaps and Future Improvements

## 1. Long-running tool calls block the LLM

When a tool call takes a long time (e.g., 30-min nmap scan), the LLM is paused waiting for the result. Opensploit receives heartbeat progress via `onprogress` callback but the LLM cannot monitor or cancel mid-execution.

**Current state**: Heartbeats keep the connection alive. The scan runs to completion.
**Future fix**: MCP Tasks (spec 2025-11-25, experimental). Both SDKs support it (TS v1.25.2, Python v1.26.0). Requires opensploit client changes (manager.ts → requestStream()). Would let the LLM continue working and check progress periodically.
**Interim option**: Opensploit could implement a cancel policy in the `onprogress` callback based on elapsed time or stalled progress.

## 2. Custom files via /session/ not documented for most tools

The `/session/` directory is mounted read-write in every container. Agents can write custom files there and tools can reference them by path. This is validated and documented for nmap (custom NSE scripts) but not for other tools that would benefit.

Tools that need tool.yaml updates to document `/session/` custom file support:
- **sqlmap**: Custom tamper scripts → `/session/sqlmap-tampers/custom.py` → `--tamper=` path
- **ffuf**: Custom wordlists → `/session/wordlists/custom.txt` → wordlist path param
- **hydra**: Custom wordlists/combo files → `/session/wordlists/` → password/combo file params
- **nuclei**: Custom YAML templates → `/session/nuclei-templates/` → template path
- **john/hashcat**: Custom rules files → `/session/rules/` → rules path param
<!-- metasploit: removed May 2026 — replaced with Rapid7's read-only msfmcpd. Resource-script + custom-module execution moved to exploit-runner. -->


No code changes needed — just tool.yaml documentation so the agent discovers the capability via RAG.

## 3. Seven tools still use deprecated run_command()

These tools use custom subprocess management instead of `self.run_command()`, so they weren't updated in the heartbeat migration: evil-winrm, impacket-relay, responder, ssh, exploit-runner, shell-session, hydra.

They need individual attention to add heartbeats to their custom subprocess code. Lower priority since their custom management was written for specific reasons (stdin theft fix, paramiko thread executor, etc.).

## 4. Remaining 52 tools not yet tested

Tiers 3 and 4 (32 specialist + 20 low-usage tools) have not been through the per-tool testing process. They still use the deprecated `run_command()` with server-side timeouts. They'll be updated as they're picked up for testing.
