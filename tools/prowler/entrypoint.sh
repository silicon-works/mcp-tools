#!/bin/bash
#
# prowler (vendor MCP swap) entrypoint
#
# Boot the full self-hosted Prowler App stack inside ONE container:
#   postgres-16 + valkey-7 + dozerdb (neo4j-fork) + gunicorn (django api) +
#   celery worker + prowler-mcp (stdio).
#
# All diagnostic output → stderr (fd 2). Stdout (fd 1) is reserved for the
# stdio MCP JSON-RPC traffic that prowler-mcp owns once we exec to it at the
# end. Same convention as metasploit/zap entrypoints.
#
# Service start order:
#   1. Generate secrets if missing (RSA token-signing keypair via openssl —
#      mitigates upstream bug #8897 deterministically; Fernet encryption
#      key for provider creds; postgres/neo4j passwords)
#   2. Postgres init (first boot only) + start; valkey start; dozerdb start
#   3. Wait for all three healthy
#   4. django migrate (admin connection — RLS bypass needed for DDL)
#   5. bootstrap.py if API key not cached on volume (creates Tenant + User +
#      TenantAPIKey, prints pk_xxx)
#   6. gunicorn (api) + celery worker in background
#   7. Poll /health on 8080 until 200
#   8. exec prowler-mcp --transport stdio (becomes container's foreground)
set -euo pipefail

log() { printf '[entrypoint] %s\n' "$*" >&2; }
die() { log "FATAL: $*"; exit 1; }

# ── Offensive tuning ──────────────────────────────────────────────────────
# These MUST be set BEFORE postgres/django/celery start so the worker boto3
# clients pick up an empty user_agent_extra. Defenders running CloudTrail
# would otherwise see APN_1826889 stamped on every Prowler API call.
export PROWLER_AWS_BOTO3_USER_AGENT_EXTRA="${PROWLER_AWS_BOTO3_USER_AGENT_EXTRA:-}"
export DJANGO_SENTRY_DSN="${DJANGO_SENTRY_DSN:-}"
export DJANGO_DEBUG="${DJANGO_DEBUG:-False}"
export DJANGO_LOGGING_LEVEL="${DJANGO_LOGGING_LEVEL:-WARNING}"
export DJANGO_LOGGING_FORMATTER="${DJANGO_LOGGING_FORMATTER:-ndjson}"
export DJANGO_SETTINGS_MODULE="${DJANGO_SETTINGS_MODULE:-config.django.production}"
export PYTHONUNBUFFERED=1

# ── Secret generation (first boot OR rotated-by-deletion) ─────────────────
SECRETS_DIR="/var/lib/prowler/secrets"
mkdir -p "$SECRETS_DIR"
chmod 700 "$SECRETS_DIR"

gen_or_load() {
  local name="$1" gen_cmd="$2"
  if [ ! -s "$SECRETS_DIR/$name" ]; then
    eval "$gen_cmd" > "$SECRETS_DIR/$name"
    chmod 600 "$SECRETS_DIR/$name"
    log "generated secret: $name"
  fi
  cat "$SECRETS_DIR/$name"
}

export DJANGO_SECRETS_ENCRYPTION_KEY="$(gen_or_load fernet_key 'python3 -c "from cryptography.fernet import Fernet; print(Fernet.generate_key().decode())"')"
export AUTH_SECRET="$(gen_or_load auth_secret 'openssl rand -base64 32')"
export POSTGRES_ADMIN_PASSWORD="$(gen_or_load pg_admin_pw 'openssl rand -base64 24 | tr -d /=+ | head -c 32')"
export POSTGRES_PASSWORD="$(gen_or_load pg_user_pw 'openssl rand -base64 24 | tr -d /=+ | head -c 32')"
export NEO4J_PASSWORD="$(gen_or_load neo4j_pw 'openssl rand -base64 24 | tr -d /=+ | head -c 32')"

# RSA token-signing keypair — mitigates upstream bug #8897 deterministically
# instead of hoping ~/.config/prowler-api/ is writable + persistent.
RSA_DIR="/home/prowler/.config/prowler-api"
mkdir -p "$RSA_DIR"
if [ ! -s "$RSA_DIR/signing_key.pem" ]; then
  openssl genrsa -out "$RSA_DIR/signing_key.pem" 4096 2>/dev/null
  openssl rsa -in "$RSA_DIR/signing_key.pem" -pubout -out "$RSA_DIR/verify_key.pem" 2>/dev/null
  chmod 600 "$RSA_DIR/signing_key.pem"
  chmod 644 "$RSA_DIR/verify_key.pem"
  log "generated RSA token signing keypair"
fi
export DJANGO_TOKEN_SIGNING_KEY="$(cat "$RSA_DIR/signing_key.pem")"
export DJANGO_TOKEN_VERIFYING_KEY="$(cat "$RSA_DIR/verify_key.pem")"

# ── Static config (compose .env defaults — none of these are secrets) ─────
export POSTGRES_HOST=127.0.0.1
export POSTGRES_PORT=5432
export POSTGRES_ADMIN_USER=prowler_admin
export POSTGRES_USER=prowler_user
export POSTGRES_DB=prowler_db
export VALKEY_HOST=127.0.0.1
export VALKEY_PORT=6379
export VALKEY_DB=0
export NEO4J_HOST=127.0.0.1
export NEO4J_PORT=7687
export NEO4J_USER=neo4j
export DJANGO_BIND_ADDRESS=127.0.0.1
export DJANGO_PORT=8080
export DJANGO_ALLOWED_HOSTS="localhost,127.0.0.1,prowler-api"
export DJANGO_ACCESS_TOKEN_LIFETIME=30
export DJANGO_REFRESH_TOKEN_LIFETIME=1440

# ── Postgres start ────────────────────────────────────────────────────────
# Debian's apt postgresql-16 auto-creates a 'main' cluster on install with
# config in /etc/postgresql/16/main/ and data in /var/lib/postgresql/16/main/.
# pg_ctlcluster is Debian's wrapper that knows about this layout — using
# bare pg_ctl breaks because postgresql.conf isn't in the data dir.
PG_RUN="/var/run/postgresql"
mkdir -p "$PG_RUN"
chown postgres:postgres "$PG_RUN"

# Configure listen + auth for the auto-created cluster
PG_CONF="/etc/postgresql/16/main/postgresql.conf"
PG_HBA="/etc/postgresql/16/main/pg_hba.conf"
sed -i "s/^#*listen_addresses.*/listen_addresses = '127.0.0.1'/" "$PG_CONF"
sed -i "s/^#*port.*/port = 5432/" "$PG_CONF"
# Trust local IPv4 for our containerized single-tenant use; postgres doesn't
# accept external connections (listen 127.0.0.1 only).
cat > "$PG_HBA" <<'HBA'
# TYPE  DATABASE        USER            ADDRESS                 METHOD
local   all             all                                     trust
host    all             all             127.0.0.1/32            md5
host    all             all             ::1/128                 md5
HBA
chown postgres:postgres "$PG_HBA"

log "starting postgres (Debian cluster 16/main)"
pg_ctlcluster 16 main start --skip-systemctl-redirect --foreground &>/var/log/postgres.log &
PG_PID=$!

for i in $(seq 1 30); do
  if pg_isready -h 127.0.0.1 -p 5432 -q 2>/dev/null; then
    log "postgres ready (after ${i}s, pid=$PG_PID)"
    break
  fi
  [ "$i" -eq 30 ] && {
    log "postgres failed to start (60s timeout). last 15 lines of log:"
    tail -15 /var/log/postgres.log >&2 2>&1 || true
    die "postgres failed to start"
  }
  sleep 1
done

# Create roles + DB if first boot
if ! PGPASSWORD="$POSTGRES_ADMIN_PASSWORD" psql -h 127.0.0.1 -U "$POSTGRES_ADMIN_USER" -d "$POSTGRES_DB" -c "SELECT 1" >/dev/null 2>&1; then
  log "creating postgres roles + db (first boot)"
  su postgres -c "psql -v ON_ERROR_STOP=1" >&2 <<SQL
CREATE ROLE $POSTGRES_ADMIN_USER WITH LOGIN SUPERUSER PASSWORD '$POSTGRES_ADMIN_PASSWORD';
CREATE ROLE $POSTGRES_USER WITH LOGIN PASSWORD '$POSTGRES_PASSWORD';
CREATE DATABASE $POSTGRES_DB OWNER $POSTGRES_ADMIN_USER;
GRANT ALL PRIVILEGES ON DATABASE $POSTGRES_DB TO $POSTGRES_ADMIN_USER;
GRANT CONNECT ON DATABASE $POSTGRES_DB TO $POSTGRES_USER;
SQL
fi

# ── Valkey-compatible broker (redis-server) start ────────────────────────
# Debian bookworm ships redis-server; upstream README explicitly notes
# "Any service that exposes the Redis 7.2 API can be used with Prowler API"
# so we use redis-server here. The tool.yaml description says "valkey" for
# clarity, but the binary is redis-server, the cli is redis-cli.
log "starting redis-server (valkey-compatible)"
mkdir -p /var/lib/redis
chown redis:redis /var/lib/redis 2>/dev/null || true
redis-server --daemonize yes --bind 127.0.0.1 --port 6379 --dir /var/lib/redis \
  --logfile /var/log/redis.log --save "" --appendonly no >&2

for i in $(seq 1 15); do
  if redis-cli -h 127.0.0.1 -p 6379 ping 2>/dev/null | grep -q PONG; then
    log "redis-server ready (after ${i}s)"
    break
  fi
  [ "$i" -eq 15 ] && die "redis-server failed to start"
  sleep 1
done

# ── DozerDB (neo4j-fork) start ────────────────────────────────────────────
log "starting dozerdb"
NEO4J_HOME="${NEO4J_HOME:-/opt/dozerdb}"
# Set initial password (one-shot, only if neo4j data dir is empty)
if [ ! -d "$NEO4J_HOME/data/databases/system" ]; then
  log "initializing dozerdb (first boot — setting initial password)"
  "$NEO4J_HOME/bin/neo4j-admin" dbms set-initial-password "$NEO4J_PASSWORD" >&2 2>&1 || \
    log "WARN: neo4j-admin set-initial-password failed (may be already-set)"
fi
"$NEO4J_HOME/bin/neo4j" start >&2 2>&1

for i in $(seq 1 60); do
  if wget -q -O- "http://127.0.0.1:7474" >/dev/null 2>&1; then
    log "dozerdb ready (after ${i}s)"
    break
  fi
  [ "$i" -eq 60 ] && die "dozerdb failed to start (60s timeout)"
  sleep 1
done

# ── Django: migrate + bootstrap ───────────────────────────────────────────
PROWLER_API_DIR="${PROWLER_API_DIR:-/app/api/src/backend}"
cd "$PROWLER_API_DIR"

log "running django migrations (admin connection)"
python manage.py migrate --database=admin --noinput >&2

# Bootstrap API key (cached on volume across restarts; mints fresh only if missing)
KEY_FILE="/var/lib/prowler/bootstrap/api_key"
mkdir -p "$(dirname "$KEY_FILE")"
if [ -s "$KEY_FILE" ]; then
  PROWLER_APP_API_KEY="$(cat "$KEY_FILE")"
  log "reusing cached API key (length=${#PROWLER_APP_API_KEY})"
else
  log "minting fresh tenant + user + API key via bootstrap.py"
  PROWLER_APP_API_KEY="$(python /app/bootstrap.py 2>>/var/log/bootstrap.log | tail -n1)"
  if [ -z "$PROWLER_APP_API_KEY" ] || ! [[ "$PROWLER_APP_API_KEY" =~ ^pk_ ]]; then
    log "bootstrap output (last 30 lines):"
    tail -n 30 /var/log/bootstrap.log >&2
    die "bootstrap.py did not produce a pk_-prefixed API key"
  fi
  printf '%s' "$PROWLER_APP_API_KEY" > "$KEY_FILE"
  chmod 600 "$KEY_FILE"
  log "API key cached at $KEY_FILE (length=${#PROWLER_APP_API_KEY})"
fi
export PROWLER_APP_API_KEY
export API_BASE_URL="http://127.0.0.1:8080/api/v1"

# ── Gunicorn (Django API) + Celery worker — both background ──────────────
log "starting gunicorn (django api) on 127.0.0.1:8080"
gunicorn -c config/guniconf.py config.wsgi:application >&2 2>&1 &
GUNICORN_PID=$!

log "starting celery worker"
python -m celery -A config.celery worker \
  -n "bundled@$(hostname)" \
  -l "${DJANGO_LOGGING_LEVEL:-warning}" \
  -Q celery,scans,scan-reports,deletion,backfill,overview,integrations,compliance,attack-paths-scans \
  -E --max-tasks-per-child 1 >&2 2>&1 &
CELERY_PID=$!

# Wait for /health to return 200
log "waiting for django api /health to return 200"
for i in $(seq 1 60); do
  if wget -q -O- "http://127.0.0.1:8080/api/v1/" >/dev/null 2>&1; then
    log "django api ready (after ${i}s, gunicorn_pid=$GUNICORN_PID, celery_pid=$CELERY_PID)"
    break
  fi
  [ "$i" -eq 60 ] && die "django api failed to start (60s timeout)"
  sleep 1
done

# ── exec prowler-mcp (stdio, foreground) ──────────────────────────────────
log "exec'ing prowler-mcp --transport stdio (foreground)"
log "  PROWLER_APP_API_KEY=pk_*** (length=${#PROWLER_APP_API_KEY})"
log "  API_BASE_URL=$API_BASE_URL"

exec prowler-mcp --transport stdio
