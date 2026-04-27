# OpenSploit MCP Server: phpggc
# PHP deserialization gadget chain generator

FROM kalilinux/kali-rolling

LABEL org.opencontainers.image.source="https://github.com/silicon-works/mcp-tools"
LABEL org.opencontainers.image.description="phpggc MCP server for OpenSploit"
LABEL org.opencontainers.image.licenses="MIT"

# Install PHP CLI, git, and Python (python3-full replaces the split
# python3 / python3-pip / python3-venv triad on current Kali).
RUN apt-get update && \
    apt-get install -y --no-install-recommends \
        php-cli \
        git \
        ca-certificates \
        python3-full && \
    rm -rf /var/lib/apt/lists/* && \
    apt-get clean

# Clone phpggc
RUN git clone --depth 1 https://github.com/ambionics/phpggc.git /opt/phpggc

# Symlink phpggc onto PATH so the kind:cli binary resolves to `phpggc`
# (matches tool.yaml's `binary: phpggc`). The phpggc script has a
# `#!/usr/bin/env php` shebang and runs directly.
RUN ln -s /opt/phpggc/phpggc /usr/local/bin/phpggc

# Create app directory
WORKDIR /app

# Create virtual environment
RUN python3 -m venv /app/venv
ENV PATH="/app/venv/bin:$PATH"

# Copy and install shared mcp-common package
COPY packages/mcp-common /app/packages/mcp-common
RUN pip install --no-cache-dir /app/packages/mcp-common

# Copy MCP server code
COPY tools/phpggc/mcp-server.py .

# MCP servers communicate via stdio
CMD ["python3", "mcp-server.py"]
