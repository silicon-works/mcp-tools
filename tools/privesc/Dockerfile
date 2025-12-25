# OpenSploit MCP Server: privesc
# Privilege escalation enumeration and exploit suggestion

FROM kalilinux/kali-rolling

LABEL org.opencontainers.image.source="https://github.com/silicon-works/mcp-tools"
LABEL org.opencontainers.image.description="Privilege escalation enumeration MCP server for OpenSploit"
LABEL org.opencontainers.image.licenses="MIT"

# Install dependencies
RUN apt-get update && \
    apt-get install -y --no-install-recommends \
        curl \
        wget \
        ca-certificates \
        python3 \
        python3-pip \
        python3-venv && \
    rm -rf /var/lib/apt/lists/* && \
    apt-get clean

# Create app directory
WORKDIR /app

# Download enumeration scripts
RUN mkdir -p /app/scripts && \
    curl -sL https://github.com/peass-ng/PEASS-ng/releases/latest/download/linpeas.sh -o /app/scripts/linpeas.sh && \
    curl -sL https://raw.githubusercontent.com/diego-treitos/linux-smart-enumeration/master/lse.sh -o /app/scripts/lse.sh && \
    chmod +x /app/scripts/*.sh

# Create virtual environment
RUN python3 -m venv /app/venv
ENV PATH="/app/venv/bin:$PATH"

# Copy and install shared mcp-common package
COPY packages/mcp-common /app/packages/mcp-common
RUN pip install --no-cache-dir /app/packages/mcp-common

# Install tool-specific dependencies
COPY tools/privesc/requirements.txt .
RUN pip install --no-cache-dir -r requirements.txt

# Copy MCP server code and CVE database
COPY tools/privesc/mcp-server.py .
COPY tools/privesc/cve_database.json .

# MCP servers communicate via stdio
CMD ["python3", "mcp-server.py"]
