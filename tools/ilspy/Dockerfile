# OpenSploit MCP Server: ilspy
# .NET assembly decompilation to C# source code via ILSpy CLI (ilspycmd)

FROM mcr.microsoft.com/dotnet/sdk:8.0

LABEL org.opencontainers.image.source="https://github.com/silicon-works/mcp-tools"
LABEL org.opencontainers.image.description="ilspy MCP server for OpenSploit"
LABEL org.opencontainers.image.licenses="MIT"

# Install ilspycmd and Python
ENV DOTNET_CLI_TELEMETRY_OPTOUT=1
RUN dotnet tool install -g ilspycmd && \
    apt-get update && \
    apt-get install -y --no-install-recommends \
        python3 \
        python3-pip \
        python3-venv \
        ca-certificates && \
    rm -rf /var/lib/apt/lists/* && \
    apt-get clean

ENV PATH="${PATH}:/root/.dotnet/tools"

# Create app directory
WORKDIR /app

# Create virtual environment
RUN python3 -m venv /app/venv
ENV PATH="/app/venv/bin:$PATH"

# Copy and install shared mcp-common package
COPY packages/mcp-common /app/packages/mcp-common
RUN pip install --no-cache-dir /app/packages/mcp-common

# Install tool-specific dependencies
COPY tools/ilspy/requirements.txt .
RUN pip install --no-cache-dir -r requirements.txt

# Copy MCP server code
COPY tools/ilspy/mcp-server.py .

# MCP servers communicate via stdio
CMD ["python3", "mcp-server.py"]
