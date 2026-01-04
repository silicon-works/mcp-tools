FROM python:3.12-slim

# Install Python dependencies
RUN pip install --no-cache-dir mcp

# Create app directory
WORKDIR /app

# Copy common package
COPY packages/mcp-common/src/mcp_common /app/mcp_common

# Copy server
COPY tools/target-tracker/mcp-server.py /app/

# Make executable
RUN chmod +x /app/mcp-server.py

# Set Python path
ENV PYTHONPATH=/app

# Run server
ENTRYPOINT ["python", "/app/mcp-server.py"]
