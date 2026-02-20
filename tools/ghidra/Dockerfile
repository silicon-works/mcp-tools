# OpenSploit MCP Server: ghidra
# Binary decompilation and reverse engineering via GhidraMCP (headless)
#
# Based on bethington/ghidra-mcp headless fork which provides a REST API
# without requiring the Ghidra GUI. Our mcp-server.py bridges this REST API
# to the standard MCP stdio protocol via BaseMCPServer.
#
# Architecture:
#   Agent <-> mcp-server.py (stdio/MCP) <-> GhidraMCPHeadlessServer (HTTP:8089) <-> Ghidra API

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

# Build the headless GhidraMCP plugin
# Clone bethington's fork which has headless support
RUN apt-get install -y --no-install-recommends git maven && \
    git clone --depth 1 https://github.com/bethington/ghidra-mcp.git /tmp/ghidra-mcp && \
    cd /tmp/ghidra-mcp && \
    # Install the 9 specific Ghidra JARs that the Maven build requires
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
LABEL org.opencontainers.image.licenses="MIT"

# Install Python for the MCP bridge
RUN apt-get update && \
    apt-get install -y --no-install-recommends \
        python3 \
        python3-pip \
        python3-venv && \
    rm -rf /var/lib/apt/lists/* && \
    apt-get clean

WORKDIR /app

# Create virtual environment
RUN python3 -m venv /app/venv
ENV PATH="/app/venv/bin:$PATH"

# Copy Ghidra from builder
COPY --from=builder /opt/ghidra /opt/ghidra

# Copy built GhidraMCP headless JAR from builder
COPY --from=builder /tmp/ghidra-mcp/target/GhidraMCP-*.jar /app/GhidraMCP.jar

# Install Python dependencies
RUN pip install --no-cache-dir requests

# Copy and install shared mcp-common package
COPY packages/mcp-common /tmp/mcp-common
RUN pip install --no-cache-dir /tmp/mcp-common && rm -rf /tmp/mcp-common

# Create directories for binary analysis
RUN mkdir -p /data /projects

# Copy MCP server code
COPY tools/ghidra/mcp-server.py .

ENV GHIDRA_HOME=/opt/ghidra
ENV GHIDRA_HEADLESS_PORT=8089
ENV GHIDRA_PROJECT_DIR=/projects

# MCP servers communicate via stdio
CMD ["python3", "mcp-server.py"]
