# OpenSploit MCP Server: mysql
# MySQL/MariaDB client for database enumeration and data extraction

FROM kalilinux/kali-rolling

LABEL org.opencontainers.image.source="https://github.com/silicon-works/mcp-tools"
LABEL org.opencontainers.image.description="MySQL MCP server for OpenSploit"
LABEL org.opencontainers.image.licenses="MIT"

# Install MySQL client and Python
RUN apt-get update && \
    apt-get install -y --no-install-recommends \
        default-mysql-client \
        python3 \
        python3-pip \
        python3-venv && \
    rm -rf /var/lib/apt/lists/* && \
    apt-get clean

# Create app directory
WORKDIR /app

# Create virtual environment
RUN python3 -m venv /app/venv
ENV PATH="/app/venv/bin:$PATH"

# Copy and install shared mcp-common package
COPY packages/mcp-common /app/packages/mcp-common
RUN pip install --no-cache-dir /app/packages/mcp-common

# Install tool-specific dependencies
COPY tools/mysql/requirements.txt .
RUN pip install --no-cache-dir -r requirements.txt

# Copy MCP server code
COPY tools/mysql/mcp-server.py .

# MCP servers communicate via stdio
CMD ["python3", "mcp-server.py"]
