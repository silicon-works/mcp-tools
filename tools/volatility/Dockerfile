# OpenSploit MCP Server: volatility
# Memory forensics via Volatility 3 v2.27.0

FROM python:3.11-slim

LABEL org.opencontainers.image.source="https://github.com/silicon-works/mcp-tools"
LABEL org.opencontainers.image.description="Volatility MCP server for OpenSploit"
LABEL org.opencontainers.image.licenses="MIT"

WORKDIR /app

# Create venv
RUN python3 -m venv /app/venv
ENV PATH="/app/venv/bin:$PATH"

# Install volatility3 and crypto deps (needed for hashdump/lsadump)
RUN pip install --no-cache-dir volatility3 pycryptodome

# Install shared mcp-common package
COPY packages/mcp-common /app/packages/mcp-common
RUN pip install --no-cache-dir /app/packages/mcp-common

# Create session directory
RUN mkdir -p /session

# Copy MCP server code
COPY tools/volatility/mcp-server.py .

CMD ["python3", "mcp-server.py"]
