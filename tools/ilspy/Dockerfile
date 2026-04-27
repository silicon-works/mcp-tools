# OpenSploit MCP Server: ilspy
# .NET assembly decompilation to C# source code via ILSpy CLI (ilspycmd)

FROM mcr.microsoft.com/dotnet/sdk:9.0

LABEL org.opencontainers.image.source="https://github.com/silicon-works/mcp-tools"
LABEL org.opencontainers.image.description="ilspy MCP server for OpenSploit"
LABEL org.opencontainers.image.licenses="MIT"

# Install ilspycmd via dotnet tool. .NET 9 SDK image includes the runtimes
# ilspycmd needs; .NET 8 base failed at runtime with "You must install or
# update .NET". Unconstrained `latest` had a broken NuGet package missing
# DotnetToolSettings.xml — pin to 8.2.0.7535 which packages cleanly.
ENV DOTNET_CLI_TELEMETRY_OPTOUT=1
RUN dotnet tool install -g ilspycmd --version 8.2.0.7535 && \
    apt-get update && \
    apt-get install -y --no-install-recommends \
        python3 \
        python3-pip \
        python3-venv \
        ca-certificates && \
    rm -rf /var/lib/apt/lists/* && \
    apt-get clean

ENV PATH="${PATH}:/root/.dotnet/tools"

# ilspycmd 8.2.0.7535 targets net6.0; .NET 9 SDK image has only the net9.0
# runtime, and major-version roll-forward is opt-in. Force it so the tool
# runs on net9 without bundling EOL .NET 6 runtime.
ENV DOTNET_ROLL_FORWARD=Major

# Create app directory
WORKDIR /app

# Create virtual environment
RUN python3 -m venv /app/venv
ENV PATH="/app/venv/bin:$PATH"

# Copy and install shared mcp-common package
COPY packages/mcp-common /app/packages/mcp-common
RUN pip install --no-cache-dir /app/packages/mcp-common

# Copy MCP server code
COPY tools/ilspy/mcp-server.py .

# MCP servers communicate via stdio
CMD ["python3", "mcp-server.py"]
