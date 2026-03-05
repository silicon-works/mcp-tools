# OpenSploit MCP Server: bloodhound
# Active Directory relationship mapping via bloodhound-python

FROM kalilinux/kali-rolling

LABEL org.opencontainers.image.source="https://github.com/silicon-works/mcp-tools"
LABEL org.opencontainers.image.description="BloodHound MCP server for OpenSploit"
LABEL org.opencontainers.image.licenses="MIT"

# Install bloodhound-python and Kerberos libs from Kali packages
RUN apt-get update && \
    apt-get install -y --no-install-recommends \
        bloodhound.py \
        krb5-user \
        libfaketime \
        python3 \
        python3-pip \
        python3-venv && \
    rm -rf /var/lib/apt/lists/* && \
    apt-get clean

WORKDIR /app

# Create venv with system-site-packages so venv sees system bloodhound
RUN python3 -m venv --system-site-packages /app/venv
ENV PATH="/app/venv/bin:$PATH"

# Install shared mcp-common package
COPY packages/mcp-common /app/packages/mcp-common
RUN pip install --no-cache-dir /app/packages/mcp-common

# Create session output directory
RUN mkdir -p /session

# Copy MCP server code
COPY tools/bloodhound/mcp-server.py .

CMD ["python3", "mcp-server.py"]
