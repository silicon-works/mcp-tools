FROM python:3.11-slim

LABEL maintainer="OpenSploit"
LABEL description="Web technology fingerprinting MCP server"

WORKDIR /app

# Install mcp-common from local package
COPY packages/mcp-common /tmp/mcp-common
RUN pip install --no-cache-dir /tmp/mcp-common && rm -rf /tmp/mcp-common

# Install dependencies
COPY tools/web-fingerprint/requirements.txt /tmp/requirements.txt
RUN pip install --no-cache-dir -r /tmp/requirements.txt && rm /tmp/requirements.txt

# Copy server code
COPY tools/web-fingerprint/mcp-server.py .

EXPOSE 8080

CMD ["python", "mcp-server.py"]
