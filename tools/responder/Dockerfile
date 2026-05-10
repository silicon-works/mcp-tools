# OpenSploit MCP Server: responder
# LLMNR/NBT-NS/MDNS poisoning and NTLMv2 hash capture via Responder v3.2.2
# (lgandx/Responder, Kali apt). kind:cli at the SCHEMA layer (LLM emits raw
# argv via tool_runner) — routed via MCP TRANSPORT for persistent containers,
# heartbeat-driven idle timeouts, hard-cap dual clock. Container exposes the
# auto-inherited run_cli method from BaseMCPServer; the LLM constructs the
# full responder invocation including timeout-wrapping and post-execution
# log copy.
#
# Requires: --privileged --network=host (handled automatically by plugin
# when tool.yaml has requirements.privileged: true and host networking is
# the default).

FROM kalilinux/kali-rolling

LABEL org.opencontainers.image.source="https://github.com/silicon-works/mcp-tools"
LABEL org.opencontainers.image.description="Responder MCP server for OpenSploit (kind:cli, May 2026)"
LABEL org.opencontainers.image.licenses="MIT"

# Install Responder and networking tools.
# python3-netifaces is required by responder itself (not by our wrapper).
# sqlite3 CLI added so agents can query Responder.db structured fields.
RUN apt-get update && \
    apt-get install -y --no-install-recommends \
        responder \
        python3-netifaces \
        iproute2 \
        sqlite3 \
        python3 \
        python3-pip \
        python3-venv && \
    rm -rf /var/lib/apt/lists/* && \
    apt-get clean

WORKDIR /app

# venv with system-site-packages so venv Python sees netifaces.
RUN python3 -m venv --system-site-packages /app/venv
ENV PATH="/app/venv/bin:$PATH"

# mcp-common provides RunCliServer.
COPY packages/mcp-common /app/packages/mcp-common
RUN pip install --no-cache-dir /app/packages/mcp-common

# Session output dir.
RUN mkdir -p /session/output

# Ensure Responder logs dir exists (responder writes here on startup).
RUN mkdir -p /usr/share/responder/logs

# v3.0 (May 2026) — pre-bake Responder-smb-only.conf + Responder.conf.bak
# for the SMB-only capture pattern (replaces capture_smb method's
# configparser modification). Pattern R3 in tool.yaml uses these:
#   1. cp Responder-smb-only.conf → Responder.conf  (before responder run)
#   2. responder runs in SMB-only mode (only port 445 binds)
#   3. cp Responder.conf.bak → Responder.conf  (restore after run)
RUN cp /usr/share/responder/Responder.conf /usr/share/responder/Responder.conf.bak && \
    cp /usr/share/responder/Responder.conf /usr/share/responder/Responder-smb-only.conf && \
    python3 -c "\
import re, sys; \
p = '/usr/share/responder/Responder-smb-only.conf'; \
text = open(p).read(); \
text = re.sub(r'^(LLMNR|NBTNS|MDNS)(\s*)=(\s*)On(\s*)\$', r'\1\2=\3Off\4', text, flags=re.MULTILINE); \
text = re.sub(r'^(SQL|QUIC|RDP|Kerberos|FTP|POP|SMTP|IMAP|HTTP|HTTPS|DNS|LDAP|DCERPC|WINRM|SNMP|MQTT|MYSQL)(\s*)=(\s*)On(\s*)\$', r'\1\2=\3Off\4', text, flags=re.MULTILINE); \
open(p, 'w').write(text); \
print('SMB-only conf written')"

COPY tools/responder/mcp-server.py .

CMD ["python3", "mcp-server.py"]
