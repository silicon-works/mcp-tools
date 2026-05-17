# OpenSploit tool: evil-winrm  (kind:cli — May 2026 flip from kind:mcp)
#
# WinRM/PSRP remote exec + file transfer via pypsrp. The "binary" is our
# own thin CLI `winrm-exec` (no scriptable WinRM binary exists upstream —
# Ruby evil-winrm is REPL-only, pypsrp is a library). The 402-LOC kind:mcp
# server collapsed to a ~22-LOC RunCliServer stub; the WinRM logic + the
# 100-LOC error classifier moved into winrm-exec; engagement knowledge is
# in tool.yaml usage_patterns + failure_signatures.
#
# Base: python:3.12-slim-bookworm — NOT Kali. The previous kind:mcp image
# apt-installed the Ruby `evil-winrm` package off Kali (never used — we
# drive pypsrp, not the Ruby REPL). Dropping Kali + Ruby diets the image
# from 681MB (old GHCR kind:mcp) to ~464MB (measured 2026-05-17). A
# multi-stage build (compile gssapi/krb5 in a builder, copy wheels into a
# gcc-free runtime) would reach ~150MB — noted follow-up, not blocking.
# Distinct from `netexec winrm` (NTLM-only): this supports NTLM password,
# NTLM pass-the-hash, AND Kerberos via ccache.

FROM python:3.12-slim-bookworm

LABEL org.opencontainers.image.source="https://github.com/silicon-works/mcp-tools"
LABEL org.opencontainers.image.description="evil-winrm (kind:cli, pypsrp WinRM/PSRP) for OpenSploit"
LABEL org.opencontainers.image.licenses="MIT"

# krb5 runtime + dev (gssapi pip build needs libkrb5-dev + krb5-config + gcc),
# krb5-user for kinit/klist debugging, libfaketime for Kerberos clock-skew
# (plugin hoists FAKETIME -> ContainerOptions.clockOffset -> LD_PRELOAD).
RUN apt-get update && \
    DEBIAN_FRONTEND=noninteractive apt-get install -y --no-install-recommends \
        gcc \
        krb5-user \
        krb5-config \
        libkrb5-dev \
        libfaketime \
        ca-certificates && \
    rm -rf /var/lib/apt/lists/* && \
    apt-get clean

WORKDIR /app

RUN python3 -m venv /app/venv
ENV PATH="/app/venv/bin:$PATH"

# Shared mcp-common: provides RunCliServer (auto-registers run_cli).
COPY packages/mcp-common /app/packages/mcp-common
RUN pip install --no-cache-dir /app/packages/mcp-common

# pypsrp: native PowerShell Remoting Protocol (PSRP plugin URI — works for
# non-admin WinRM users on Win Server 2025 where the CMD WinRS URI is
# restricted). The [kerberos] extra pulls the FULL Kerberos runtime stack
# (gssapi + krb5 + pyspnego[kerberos]) — `pip install pypsrp gssapi` alone
# is INSUFFICIENT: pypsrp's GSSAPIProxy also needs the `krb5` module, whose
# absence only surfaces at Kerberos-auth runtime, not at import (caught live
# on Forest 2026-05-17 — S3 Kerberos test failed with "No module named
# 'krb5'" until this was changed to the extra).
RUN pip install --no-cache-dir 'pypsrp[kerberos]'

# winrm-exec is the kind:cli "binary" — on PATH, invoked by run_cli.
COPY tools/evil-winrm/winrm-exec /usr/local/bin/winrm-exec
RUN chmod +x /usr/local/bin/winrm-exec

# Session dir for downloaded loot / shared krb5.conf.
RUN mkdir -p /session

# RunCliServer stub + entrypoint (libfaketime dynamic discovery).
COPY tools/evil-winrm/mcp-server.py /app/mcp-server.py
COPY packages/mcp-common/entrypoint.sh /app/entrypoint.sh
RUN chmod +x /app/entrypoint.sh

CMD ["/app/entrypoint.sh"]
