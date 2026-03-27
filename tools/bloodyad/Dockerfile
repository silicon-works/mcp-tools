# OpenSploit MCP Server: bloodyad
# AD privilege escalation via LDAP — ACL abuse, RBCD, shadow credentials, password resets

FROM kalilinux/kali-rolling

LABEL org.opencontainers.image.source="https://github.com/silicon-works/mcp-tools"
LABEL org.opencontainers.image.description="bloodyAD MCP server for OpenSploit"
LABEL org.opencontainers.image.licenses="MIT"

# Install bloodyAD from Kali repos + Kerberos dependencies
RUN apt-get update && \
    DEBIAN_FRONTEND=noninteractive apt-get install -y --no-install-recommends \
        bloodyad \
        krb5-user \
        libkrb5-dev \
        libfaketime \
        python3 \
        python3-pip \
        python3-venv \
    && rm -rf /var/lib/apt/lists/* \
    && apt-get clean

WORKDIR /app

# Create virtual environment with system packages (bloodyAD installed via apt)
RUN python3 -m venv --system-site-packages /app/venv
ENV PATH="/app/venv/bin:$PATH"

# Copy and install shared mcp-common package
COPY packages/mcp-common /app/packages/mcp-common
RUN pip install --no-cache-dir /app/packages/mcp-common

# Create session directory
RUN mkdir -p /session

# Copy MCP server
COPY tools/bloodyad/mcp-server.py /app/mcp-server.py

CMD ["python3", "/app/mcp-server.py"]
