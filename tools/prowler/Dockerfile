# OpenSploit MCP Server: prowler
# Multi-cloud security auditing via Prowler v5.18

FROM python:3.12-slim

LABEL org.opencontainers.image.source="https://github.com/silicon-works/mcp-tools"
LABEL org.opencontainers.image.description="Prowler MCP server for OpenSploit"
LABEL org.opencontainers.image.licenses="MIT"

# Install prowler
RUN pip install --no-cache-dir prowler==5.18.3

WORKDIR /app

# Create venv for mcp-common (prowler installed system-wide)
RUN python3 -m venv /app/venv
ENV PATH="/app/venv/bin:$PATH"

# Install shared mcp-common package
COPY packages/mcp-common /app/packages/mcp-common
RUN pip install --no-cache-dir /app/packages/mcp-common

# Prowler is installed system-wide, make it importable from venv
ENV PYTHONPATH="/usr/local/lib/python3.12/site-packages:$PYTHONPATH"

# Create session directory
RUN mkdir -p /session

# Copy MCP server code
COPY tools/prowler/mcp-server.py .

CMD ["python3", "mcp-server.py"]
