# OpenSploit MCP Server: evil-winrm
# WinRM shell access, command execution, and file transfer

FROM kalilinux/kali-rolling

LABEL org.opencontainers.image.source="https://github.com/silicon-works/mcp-tools"
LABEL org.opencontainers.image.description="evil-winrm MCP server for OpenSploit"
LABEL org.opencontainers.image.licenses="MIT"

# Install evil-winrm from Kali repos + Python
RUN apt-get update && \
    apt-get install -y --no-install-recommends \
        evil-winrm \
        python3 \
        python3-pip \
        python3-venv \
    && rm -rf /var/lib/apt/lists/* \
    && apt-get clean

WORKDIR /app

# Create virtual environment
RUN python3 -m venv /app/venv
ENV PATH="/app/venv/bin:$PATH"

# Copy and install shared mcp-common package
COPY packages/mcp-common /app/packages/mcp-common
RUN pip install --no-cache-dir /app/packages/mcp-common

# Install pypsrp for native PowerShell Remoting Protocol support
# (pywinrm hardcodes CMD shell URI, blocked on Win Server 2025 for non-admins)
RUN pip install --no-cache-dir pypsrp

# Copy MCP server
COPY tools/evil-winrm/mcp-server.py /app/mcp-server.py

CMD ["python3", "/app/mcp-server.py"]
