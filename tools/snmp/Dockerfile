# OpenSploit MCP Server: snmp
# SNMP enumeration via snmpwalk/snmpbulkwalk/snmpget and community string brute-force via onesixtyone

FROM kalilinux/kali-rolling

LABEL org.opencontainers.image.source="https://github.com/silicon-works/mcp-tools"
LABEL org.opencontainers.image.description="snmp MCP server for OpenSploit"
LABEL org.opencontainers.image.licenses="MIT"

# Install SNMP tools, onesixtyone, and Python
RUN apt-get update && \
    apt-get install -y --no-install-recommends \
        snmp \
        snmp-mibs-downloader \
        onesixtyone \
        ca-certificates \
        python3 \
        python3-pip \
        python3-venv && \
    rm -rf /var/lib/apt/lists/* && \
    apt-get clean

# Enable MIB loading (disabled by default in Debian/Kali)
RUN sed -i 's/^mibs :$/# mibs :/' /etc/snmp/snmp.conf 2>/dev/null || true

# Create app directory
WORKDIR /app

# Create virtual environment
RUN python3 -m venv /app/venv
ENV PATH="/app/venv/bin:$PATH"

# Copy and install shared mcp-common package
COPY packages/mcp-common /app/packages/mcp-common
RUN pip install --no-cache-dir /app/packages/mcp-common

# Install tool-specific dependencies
COPY tools/snmp/requirements.txt .
RUN pip install --no-cache-dir -r requirements.txt

# Copy MCP server code
COPY tools/snmp/mcp-server.py .

# Include a default community string wordlist
RUN echo -e "public\nprivate\ncommunity\nmanager\nadmin\ndefault\npassword\nsnmpd\nsnmp\nnetwork\nmonitor\nagent\ninternal\nsecret\ncisco\nrouter\nswitch" > /app/community-strings.txt

# MCP servers communicate via stdio
CMD ["python3", "mcp-server.py"]
