# OpenSploit MCP Server: trivy
# Container, filesystem, and IaC vulnerability scanning via Trivy v0.69

FROM python:3.11-slim

LABEL org.opencontainers.image.source="https://github.com/silicon-works/mcp-tools"
LABEL org.opencontainers.image.description="Trivy MCP server for OpenSploit"
LABEL org.opencontainers.image.licenses="MIT"

# Install trivy binary
RUN apt-get update && \
    apt-get install -y --no-install-recommends wget apt-transport-https gnupg lsb-release && \
    wget -qO - https://aquasecurity.github.io/trivy-repo/deb/public.key | gpg --dearmor -o /usr/share/keyrings/trivy.gpg && \
    echo "deb [signed-by=/usr/share/keyrings/trivy.gpg] https://aquasecurity.github.io/trivy-repo/deb generic main" > /etc/apt/sources.list.d/trivy.list && \
    apt-get update && \
    apt-get install -y --no-install-recommends trivy && \
    apt-get purge -y wget gnupg lsb-release && \
    apt-get autoremove -y && \
    rm -rf /var/lib/apt/lists/*

# Download vulnerability database (cached in image)
RUN trivy image --download-db-only 2>/dev/null || true

WORKDIR /app

# Create venv
RUN python3 -m venv /app/venv
ENV PATH="/app/venv/bin:$PATH"

# Install shared mcp-common package
COPY packages/mcp-common /app/packages/mcp-common
RUN pip install --no-cache-dir /app/packages/mcp-common

# Create session directory
RUN mkdir -p /session

# Copy MCP server code
COPY tools/trivy/mcp-server.py .

CMD ["python3", "mcp-server.py"]
