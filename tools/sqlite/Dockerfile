FROM python:3.11-slim

WORKDIR /app

# SQLite is included in Python stdlib, no additional packages needed

# Install mcp-common package
COPY packages/mcp-common /tmp/mcp-common
RUN pip install --no-cache-dir /tmp/mcp-common && rm -rf /tmp/mcp-common

# Copy server
COPY tools/sqlite/mcp-server.py .

CMD ["python", "mcp-server.py"]
