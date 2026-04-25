FROM python:3.12-slim

# Install system dependencies (including libfaketime for clock testing)
RUN apt-get update && apt-get install -y --no-install-recommends \
    openssh-client \
    sshpass \
    libfaketime \
    && rm -rf /var/lib/apt/lists/*

# Install Python dependencies
RUN pip install --no-cache-dir \
    mcp \
    paramiko

# Create app directory
WORKDIR /app

# Copy common package
COPY packages/mcp-common/src/mcp_common /app/mcp_common

# Copy shared entrypoint (FAKETIME discovery)
COPY packages/mcp-common/entrypoint.sh /app/entrypoint.sh
RUN chmod +x /app/entrypoint.sh

# Copy server
COPY tools/shell-session/mcp-server.py /app/

# Make executable
RUN chmod +x /app/mcp-server.py

# Set Python path
ENV PYTHONPATH=/app

# Run server via entrypoint (handles FAKETIME setup)
ENTRYPOINT ["/app/entrypoint.sh"]
