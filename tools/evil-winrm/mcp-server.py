#!/usr/bin/env python3
"""
OpenSploit tool: evil-winrm

kind:cli — exposes only the auto-registered run_cli method from
BaseMCPServer. The agent emits raw argv via cli_in_container; the
"binary" is `winrm-exec` (our thin pypsrp CLI on PATH at
/usr/local/bin/winrm-exec).

Why a custom binary instead of wrapping an upstream one: no scriptable
WinRM binary exists — Ruby evil-winrm is REPL-only (no -c COMMAND),
pypsrp is a library, netexec winrm is NTLM-only (no Kerberos). winrm-exec
is the most capable scriptable WinRM client we can ship: NTLM password,
NTLM pass-the-hash, AND Kerberos-via-ccache, plus native PSRP copy()/
fetch() file transfer.

The 402-LOC kind:mcp wrapper (May 2026 retired) collapses to this stub
because the WinRM logic + the 100-LOC error classifier now live in
winrm-exec, and the engagement knowledge (NTLM/PtH/Kerberos recipes,
ConstrainedLanguage fallback, clock-skew→FAKETIME, KDC/logon-failure
classification) lives in tool.yaml usage_patterns + failure_signatures.
"""

from mcp_common import RunCliServer

if __name__ == "__main__":
    RunCliServer.serve(
        name="evil-winrm",
        description="WinRM/PSRP remote exec + file transfer via the `winrm-exec` CLI (pypsrp). NTLM password, NTLM pass-the-hash, AND Kerberos-via-ccache (netexec winrm is NTLM-only). Native PSRP copy()/fetch() file transfer. Uses the PowerShell plugin URI (works for non-admin WinRM on Win Server 2025 where the CMD WinRS URI is restricted). The 402-LOC kind:mcp wrapper (May 2026 retired) collapses to raw winrm-exec argv via cli_in_container; usage_patterns + failure_signatures in tool.yaml carry the NTLM/PtH/Kerberos recipes + the error classifier.",
    )
