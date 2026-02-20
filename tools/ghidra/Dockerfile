# OpenSploit MCP Server: ghidra
# Binary decompilation and reverse engineering via bethington/ghidra-mcp
#
# Follows the Playwright pattern: external MCP server, minimal custom code.
# bethington's bridge_mcp_ghidra.py provides 127 MCP tools via stdio.
# We add one tool (load_binary) for loading binaries from the filesystem.
#
# Architecture:
#   Agent <-> bridge_mcp_ghidra.py (MCP stdio) <-> GhidraMCPHeadlessServer (HTTP:8089) <-> Ghidra API

FROM eclipse-temurin:21-jdk AS builder

ARG GHIDRA_VERSION=12.0.3
ARG GHIDRA_DATE=20260210
ARG GHIDRA_SHA256="90d3fffb20b00030dcef8d2a24dd0f422d3a61e432b3ad43f77233ac6d667981"

# Download and extract Ghidra
RUN apt-get update && apt-get install -y --no-install-recommends wget unzip && \
    wget -q "https://github.com/NationalSecurityAgency/ghidra/releases/download/Ghidra_${GHIDRA_VERSION}_build/ghidra_${GHIDRA_VERSION}_PUBLIC_${GHIDRA_DATE}.zip" \
        -O /tmp/ghidra.zip && \
    echo "${GHIDRA_SHA256}  /tmp/ghidra.zip" | sha256sum -c - && \
    unzip -q /tmp/ghidra.zip -d /opt && \
    mv /opt/ghidra_${GHIDRA_VERSION}_PUBLIC /opt/ghidra && \
    rm /tmp/ghidra.zip

# Clone bethington's fork and build headless plugin
RUN apt-get install -y --no-install-recommends git maven && \
    git clone --depth 1 https://github.com/bethington/ghidra-mcp.git /tmp/ghidra-mcp && \
    cd /tmp/ghidra-mcp && \
    mvn -q install:install-file -Dfile=/opt/ghidra/Ghidra/Framework/Generic/lib/Generic.jar \
        -DgroupId=ghidra -DartifactId=Generic -Dversion=${GHIDRA_VERSION} -Dpackaging=jar && \
    mvn -q install:install-file -Dfile=/opt/ghidra/Ghidra/Framework/SoftwareModeling/lib/SoftwareModeling.jar \
        -DgroupId=ghidra -DartifactId=SoftwareModeling -Dversion=${GHIDRA_VERSION} -Dpackaging=jar && \
    mvn -q install:install-file -Dfile=/opt/ghidra/Ghidra/Framework/Project/lib/Project.jar \
        -DgroupId=ghidra -DartifactId=Project -Dversion=${GHIDRA_VERSION} -Dpackaging=jar && \
    mvn -q install:install-file -Dfile=/opt/ghidra/Ghidra/Framework/Docking/lib/Docking.jar \
        -DgroupId=ghidra -DartifactId=Docking -Dversion=${GHIDRA_VERSION} -Dpackaging=jar && \
    mvn -q install:install-file -Dfile=/opt/ghidra/Ghidra/Framework/Utility/lib/Utility.jar \
        -DgroupId=ghidra -DartifactId=Utility -Dversion=${GHIDRA_VERSION} -Dpackaging=jar && \
    mvn -q install:install-file -Dfile=/opt/ghidra/Ghidra/Framework/Gui/lib/Gui.jar \
        -DgroupId=ghidra -DartifactId=Gui -Dversion=${GHIDRA_VERSION} -Dpackaging=jar && \
    mvn -q install:install-file -Dfile=/opt/ghidra/Ghidra/Framework/FileSystem/lib/FileSystem.jar \
        -DgroupId=ghidra -DartifactId=FileSystem -Dversion=${GHIDRA_VERSION} -Dpackaging=jar && \
    mvn -q install:install-file -Dfile=/opt/ghidra/Ghidra/Features/Base/lib/Base.jar \
        -DgroupId=ghidra -DartifactId=Base -Dversion=${GHIDRA_VERSION} -Dpackaging=jar && \
    mvn -q install:install-file -Dfile=/opt/ghidra/Ghidra/Features/Decompiler/lib/Decompiler.jar \
        -DgroupId=ghidra -DartifactId=Decompiler -Dversion=${GHIDRA_VERSION} -Dpackaging=jar && \
    mvn clean package -P headless -DskipTests -q

# --- Runtime stage ---
FROM eclipse-temurin:21-jre

LABEL org.opencontainers.image.source="https://github.com/silicon-works/mcp-tools"
LABEL org.opencontainers.image.description="Ghidra reverse engineering MCP server for OpenSploit"

# Install Python for the bridge + curl for health checks
RUN apt-get update && \
    apt-get install -y --no-install-recommends \
        python3 \
        python3-pip \
        python3-venv \
        curl && \
    rm -rf /var/lib/apt/lists/*

WORKDIR /app

# Python venv + bridge dependencies
RUN python3 -m venv /app/venv
ENV PATH="/app/venv/bin:$PATH"
RUN pip install --no-cache-dir "mcp>=1.5.0,<2.0.0" "requests>=2.28.0,<3.0.0"

# Copy Ghidra from builder
COPY --from=builder /opt/ghidra /opt/ghidra

# Copy built GhidraMCP headless JAR
COPY --from=builder /tmp/ghidra-mcp/target/GhidraMCP-*.jar /app/GhidraMCP.jar

# Copy bridge script from bethington's repo (the MCP server)
COPY --from=builder /tmp/ghidra-mcp/bridge_mcp_ghidra.py /app/bridge_mcp_ghidra.py

# Copy our thin wrapper (adds load_binary tool) and entrypoint
COPY tools/ghidra/mcp-wrapper.py /app/mcp-wrapper.py
COPY tools/ghidra/entrypoint.sh /app/entrypoint.sh
RUN chmod +x /app/entrypoint.sh

# Create directories for binary analysis
RUN mkdir -p /data /projects

ENV GHIDRA_HOME=/opt/ghidra
ENV GHIDRA_MCP_PORT=8089
ENV GHIDRA_SERVER_URL=http://127.0.0.1:8089

VOLUME ["/data", "/projects"]

# Entrypoint starts Java server in background, then runs MCP bridge via stdio
ENTRYPOINT ["/app/entrypoint.sh"]
