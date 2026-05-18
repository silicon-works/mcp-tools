# prowler (vendor MCP swap) — bundled self-hosted Prowler App + MCP server
#
# Bundles the entire prowler-cloud/prowler self-hosted stack into one
# container for OpenSploit's per-session container model:
#
#   postgres-16 (Debian apt)
#   redis-server (valkey-API-compatible per upstream README; Debian apt)
#   dozerdb (Apache 2.0 Neo4j fork — required for attack-paths analysis)
#   gunicorn + Django REST API (prowler-cloud/prowler @ pinned tag, source)
#   celery worker (same image, attack-paths-scans + 8 other queues)
#   prowler-mcp-server (pip package)
#
# Architecture rationale:
#   - Mirror metasploit + zap container pattern (multi-service in one image)
#   - service: true in tool.yaml so the stack runs once per opensploit session
#   - Cold start ~75-90s (one-time cost amortized over the session)
#   - Image ~3 GB; RAM minimum 4 GB (dozerdb heap is the heavy item)
#
# Mirror of mongodb's vendor-swap pattern but with the heavier service set
# the prowler ecosystem requires.

# Top-level ARGs available to ALL FROM lines below
# Pin to a stable upstream RELEASE TAG, not `master`: master is a moving target
# (5.27.0-dev) where prowler-api's poetry deps (prowler vs cartography) periodically
# fail `poetry lock` version-solving. 5.26.1 is the latest stable release tag.
# `git clone --depth 1 --branch` accepts a tag; do NOT set this to a raw commit SHA.
ARG PROWLER_REPO_REF=5.26.1
ARG DOZERDB_VERSION=5.26.3.0

# ── Stage 1: pull dozerdb from the official docker.io image ──────────────
# DozerDB has no GitHub releases (org has no github presence). The Docker
# image graphstack/dozerdb is the canonical distribution. Multi-stage
# COPY from it is cleaner + reproducible.
FROM graphstack/dozerdb:${DOZERDB_VERSION} AS dozerdb-source

# ── Stage 2: runtime image ───────────────────────────────────────────────
# python:3.12-bookworm matches upstream's API base (python:3.12.10-slim-
# bookworm). Their pyproject.toml requires Python >=3.11,<3.13, so 3.13 is
# rejected by poetry.
FROM python:3.12-bookworm

# Redeclare ARGs needed in this stage (ARGs don't cross FROM boundaries)
ARG PROWLER_REPO_REF=5.26.1

LABEL org.opencontainers.image.source="https://github.com/silicon-works/mcp-tools"
LABEL org.opencontainers.image.description="prowler (self-hosted Prowler App + vendor MCP, offensive-tuned) for OpenSploit"
LABEL org.opencontainers.image.licenses="MIT"

ENV DEBIAN_FRONTEND=noninteractive
ENV PIP_DISABLE_PIP_VERSION_CHECK=1
ENV PYTHONDONTWRITEBYTECODE=1
ENV PYTHONUNBUFFERED=1

# ── System packages ──────────────────────────────────────────────────────
# postgresql-16 — Debian 12 has 15 by default; we add the upstream Postgres
#   apt repo to get 16 (matching upstream compose's image: postgres:16.3).
# redis-server — used as the Valkey-compatible broker per upstream README:
#   "Any service that exposes the Redis 7.2 API can be used with Prowler
#   API." Debian bookworm doesn't ship valkey yet.
# openjdk-17-jre-headless — required by dozerdb (Neo4j 5.x fork on JDK 17).
# git — needed to clone the prowler API source for migrations + bootstrap.
# curl + wget — health checks and dozerdb download.
# openssl — entrypoint secret generation.
# postgresql-client-16 — pg_isready for entrypoint healthcheck.
RUN apt-get update && apt-get install -y --no-install-recommends \
        curl \
        wget \
        ca-certificates \
        gnupg \
        lsb-release && \
    install -d /usr/share/postgresql-common/pgdg && \
    curl -o /usr/share/postgresql-common/pgdg/apt.postgresql.org.asc --fail https://www.postgresql.org/media/keys/ACCC4CF8.asc && \
    sh -c 'echo "deb [signed-by=/usr/share/postgresql-common/pgdg/apt.postgresql.org.asc] https://apt.postgresql.org/pub/repos/apt bookworm-pgdg main" > /etc/apt/sources.list.d/pgdg.list' && \
    apt-get update && apt-get install -y --no-install-recommends \
        postgresql-16 \
        postgresql-client-16 \
        redis-server \
        openjdk-17-jre-headless \
        git \
        openssl \
        sudo \
        procps \
        gcc \
        g++ \
        make \
        pkg-config \
        libtool \
        libicu72 \
        libxml2-dev \
        libxmlsec1-dev \
        libxmlsec1-openssl \
        libxslt1-dev \
        python3-dev && \
    rm -rf /var/lib/apt/lists/* && apt-get clean

# ── DozerDB (Neo4j fork — Apache 2.0 license; avoids Neo4j Community
#    Edition's commercial-use restrictions for clustering/causal-cluster) ─
# Copy the entire neo4j installation from the official docker image; this
# matches what upstream's docker-compose pulls at runtime.
# The upstream image has logs→/logs and data→/data symlinks (volume-mount
# points). Docker COPY breaks those — replace with proper directories.
COPY --from=dozerdb-source /var/lib/neo4j /opt/dozerdb
RUN useradd -r -m -d /var/lib/neo4j-data neo4j 2>/dev/null || true && \
    rm -rf /opt/dozerdb/logs /opt/dozerdb/data && \
    mkdir -p /opt/dozerdb/logs /opt/dozerdb/data && \
    chown -R neo4j:neo4j /opt/dozerdb && \
    chmod -R u+rw /opt/dozerdb

ENV NEO4J_HOME=/opt/dozerdb
ENV PATH="$NEO4J_HOME/bin:$PATH"

# ── Prowler source (Django API + prowler library) ────────────────────────
# Clone full prowler repo to /opt/prowler-src and KEEP it. Two reasons:
#  1. bootstrap.py imports api.models, api.rls, api.db_utils — needs
#     /opt/prowler-src/api/src/backend on PYTHONPATH at runtime.
#  2. The api's pyproject.toml declares the prowler library as
#     `prowler @ git+https://github.com/prowler-cloud/prowler.git@master`.
#     Poetry 2.x's git fetch uses dulwich (pure-Python git client) which
#     crashed on the prowler repo's tree (verified live during build).
#     Workaround: rewrite the dep to a local-path install so poetry uses
#     pip's local installer (no dulwich, no git fetch).
RUN git clone --depth 1 --branch ${PROWLER_REPO_REF} \
        https://github.com/prowler-cloud/prowler.git /opt/prowler-src && \
    sed -i -E 's|"prowler @ git\+https://github.com/prowler-cloud/prowler\.git@[^"]*"|"prowler @ file:///opt/prowler-src"|' \
        /opt/prowler-src/api/pyproject.toml

# Install API dependencies via poetry 2.3.4 (matches upstream's API Dockerfile).
# Pinning the exact upstream version because pyproject.toml uses PEP 621
# [project] table + package-mode=false; poetry 1.x doesn't understand that.
# Upstream uses --no-root because the project itself is not a package.
RUN pip install --no-cache-dir --upgrade pip && \
    pip install --no-cache-dir 'poetry==2.3.4' && \
    poetry config virtualenvs.create false && \
    cd /opt/prowler-src/api && \
    # Regenerate lock — our sed-edit of pyproject.toml (git URL → file path)
    # makes the shipped poetry.lock stale; poetry refuses to install from a
    # mismatched lock without --no-lock (which 2.x removed).
    poetry lock --no-cache && \
    poetry install --no-root --no-interaction --no-ansi && \
    rm -rf /root/.cache/pip /root/.cache/pypoetry

# ── Prowler MCP server (install from local source) ───────────────────────
# Install from /opt/prowler-src/mcp_server/ rather than PyPI:
#  1. PyPI has only 'prowler-mcp' max v0.5.0; mcp_server/CHANGELOG mentions
#     v0.6/v0.7 but those aren't on PyPI yet (verified 2026-05-09).
#  2. Local source guarantees version coherence with the API source we
#     already cloned in step 18 — no drift between API + MCP client.
#  3. Provides the `prowler-mcp` script entrypoint via the wheel install.
RUN pip install --no-cache-dir /opt/prowler-src/mcp_server

# ── Entrypoint + bootstrap script ────────────────────────────────────────
COPY tools/prowler/entrypoint.sh /entrypoint.sh
COPY tools/prowler/bootstrap.py /app/bootstrap.py
RUN chmod +x /entrypoint.sh

# Create user (postgres needs uid:gid; we keep root for entrypoint simplicity
# but the agent never reaches inside this container interactively).
RUN useradd -r -m -d /home/prowler prowler 2>/dev/null || true

# Expose API port for debugging only — opensploit talks via stdio MCP.
EXPOSE 8080

ENV PROWLER_API_DIR=/opt/prowler-src/api/src/backend

ENTRYPOINT ["/entrypoint.sh"]
