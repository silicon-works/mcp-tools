# OpenSploit MCP Server: certipy
# AD Certificate Services enumeration and exploitation
# Requires: network access to target domain (LDAP 389/636, Kerberos 88)

FROM kalilinux/kali-rolling

LABEL org.opencontainers.image.source="https://github.com/silicon-works/mcp-tools"
LABEL org.opencontainers.image.description="Certipy MCP server for OpenSploit"
LABEL org.opencontainers.image.licenses="MIT"

# Install certipy-ad and Kerberos dependencies
# DEBIAN_FRONTEND=noninteractive prevents krb5-user from prompting for realm
RUN apt-get update && \
    DEBIAN_FRONTEND=noninteractive apt-get install -y --no-install-recommends \
        python3 \
        python3-pip \
        python3-venv \
        python3-dev \
        build-essential \
        libssl-dev \
        libffi-dev \
        libkrb5-dev \
        krb5-user \
        libfaketime \
        iproute2 && \
    rm -rf /var/lib/apt/lists/* && \
    apt-get clean

WORKDIR /app

# Create venv
RUN python3 -m venv /app/venv
ENV PATH="/app/venv/bin:$PATH"

# Install shared mcp-common package
COPY packages/mcp-common /app/packages/mcp-common
RUN pip install --no-cache-dir /app/packages/mcp-common

# Install certipy-ad
RUN pip install --no-cache-dir certipy-ad

# Create session output directories
RUN mkdir -p /session/certipy

# Copy MCP server code
COPY tools/certipy/mcp-server.py .

CMD ["python3", "mcp-server.py"]
