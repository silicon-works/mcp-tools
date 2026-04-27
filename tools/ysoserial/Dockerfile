# OpenSploit MCP Server: ysoserial
# .NET deserialization gadget chain generator via ysoserial.net

FROM kalilinux/kali-rolling

LABEL org.opencontainers.image.source="https://github.com/silicon-works/mcp-tools"
LABEL org.opencontainers.image.description="ysoserial MCP server for OpenSploit"
LABEL org.opencontainers.image.licenses="MIT"

# Install Mono runtime, wget, unzip, and Python (python3-full replaces the
# split python3 / python3-pip / python3-venv triad on current Kali).
RUN apt-get update && \
    apt-get install -y --no-install-recommends \
        mono-complete \
        wget \
        unzip \
        ca-certificates \
        python3-full && \
    rm -rf /var/lib/apt/lists/* && \
    apt-get clean

# Download ysoserial.net v1.36
RUN cd /tmp && \
    wget -q "https://github.com/pwntester/ysoserial.net/releases/download/v1.36/ysoserial-1dba9c4416ba6e79b6b262b758fa75e2ee9008e9.zip" -O ysoserial.zip && \
    unzip -q ysoserial.zip -d /opt/ysoserial && \
    rm ysoserial.zip

# Install a thin /usr/local/bin/ysoserial wrapper so the kind:cli binary on
# PATH matches tool.yaml's `binary: ysoserial`. The wrapper exec's mono on
# the bundled ysoserial.exe so all argv (gadget, formatter, command, output
# format, --minify, --test, -h, etc.) pass through unchanged.
RUN printf '#!/bin/sh\nexec mono /opt/ysoserial/Release/ysoserial.exe "$@"\n' > /usr/local/bin/ysoserial && \
    chmod +x /usr/local/bin/ysoserial

# Create app directory
WORKDIR /app

# Create virtual environment
RUN python3 -m venv /app/venv
ENV PATH="/app/venv/bin:$PATH"

# Copy and install shared mcp-common package
COPY packages/mcp-common /app/packages/mcp-common
RUN pip install --no-cache-dir /app/packages/mcp-common

# Copy MCP server code
COPY tools/ysoserial/mcp-server.py .

# MCP servers communicate via stdio
CMD ["python3", "mcp-server.py"]
