# OpenSploit MCP Server: theharvester
# Email and subdomain OSINT via theHarvester v4.10.1

FROM python:3.12-slim

LABEL org.opencontainers.image.source="https://github.com/silicon-works/mcp-tools"
LABEL org.opencontainers.image.description="theHarvester MCP server for OpenSploit"
LABEL org.opencontainers.image.licenses="MIT"

# Install system deps (git for pip+git install, gcc for compiled deps)
RUN apt-get update && \
    apt-get install -y --no-install-recommends git gcc libffi-dev && \
    rm -rf /var/lib/apt/lists/*

# Install theHarvester from GitHub (not on PyPI as real package)
RUN pip install --no-cache-dir "git+https://github.com/laramies/theHarvester.git@4.10.1"

WORKDIR /app

# Create venv for mcp-common (theHarvester installed system-wide)
RUN python3 -m venv /app/venv
ENV PATH="/app/venv/bin:$PATH"

# Install shared mcp-common package
COPY packages/mcp-common /app/packages/mcp-common
RUN pip install --no-cache-dir /app/packages/mcp-common

# Make theHarvester importable from venv
ENV PYTHONPATH="/usr/local/lib/python3.12/site-packages:$PYTHONPATH"

# Create session directory
RUN mkdir -p /session

# Copy MCP server code
COPY tools/theharvester/mcp-server.py .

CMD ["python3", "mcp-server.py"]
