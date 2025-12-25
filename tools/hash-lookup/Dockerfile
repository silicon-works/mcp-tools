FROM python:3.11-slim

WORKDIR /app

# Install mcp-common package
COPY packages/mcp-common /tmp/mcp-common
RUN pip install --no-cache-dir /tmp/mcp-common && rm -rf /tmp/mcp-common

# Copy server
COPY tools/hash-lookup/mcp-server.py .

CMD ["python", "mcp-server.py"]
