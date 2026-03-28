#!/usr/bin/env bash
set -euo pipefail

# Start PostgreSQL via Docker and initialize subpool schemas.
#
# Idempotent: reuses an existing container if already running, and schema
# creation uses IF NOT EXISTS.
#
# Usage:
#   ./services_db.sh              # uses default services.prod.env
#   ./services_db.sh my.env        # uses custom env file

SCRIPT_DIR="$(cd "$(dirname "${BASH_SOURCE[0]}")" && pwd)"
ENV_FILE="${1:-$SCRIPT_DIR/services.prod.env}"
INIT_SQL="$SCRIPT_DIR/init-schemas.sql"

if [[ ! -f "$ENV_FILE" ]]; then
  echo "ERROR: env file not found: $ENV_FILE" >&2
  exit 1
fi

# shellcheck disable=SC1090
source "$ENV_FILE"

# ── Helper: wait for a TCP port to accept connections ─────────────────────────
wait_for_port() {
  local host="$1" port="$2" label="$3" timeout="${4:-30}"
  echo "Waiting for $label ($host:$port) ..."
  for _ in $(seq 1 "$timeout"); do
    if bash -c "echo >/dev/tcp/$host/$port" 2>/dev/null; then
      echo "  $label is ready."
      return 0
    fi
    sleep 1
  done
  echo "ERROR: $label not ready after ${timeout}s." >&2
  return 1
}

# ── Start PostgreSQL container ────────────────────────────────────────────────
echo ""
echo "=== Starting PostgreSQL ==="

if docker ps --format '{{.Names}}' | grep -qx "$POSTGRES_CONTAINER_NAME"; then
  echo "  Container '$POSTGRES_CONTAINER_NAME' already running — reusing."
elif bash -c "echo >/dev/tcp/localhost/$POSTGRES_PORT" 2>/dev/null; then
  echo "  Port $POSTGRES_PORT already in use (external PostgreSQL?) — reusing."
else
  # Remove stopped container with same name if it exists.
  docker rm -f "$POSTGRES_CONTAINER_NAME" 2>/dev/null || true

  docker run -d \
    --name "$POSTGRES_CONTAINER_NAME" \
    -e POSTGRES_USER="$POSTGRES_USER" \
    -e POSTGRES_PASSWORD="$POSTGRES_PASSWORD" \
    -e POSTGRES_DB="$POSTGRES_DB" \
    -p "${POSTGRES_PORT}:5432" \
    postgres:16 >/dev/null

  echo "  Container '$POSTGRES_CONTAINER_NAME' started."
fi

wait_for_port localhost "$POSTGRES_PORT" "PostgreSQL" 30

# ── Initialize schemas ────────────────────────────────────────────────────────
if [[ -f "$INIT_SQL" ]]; then
  echo "  Initializing schemas ..."
  PGPASSWORD="$POSTGRES_PASSWORD" psql \
    -h localhost -p "$POSTGRES_PORT" \
    -U "$POSTGRES_USER" -d "$POSTGRES_DB" \
    -f "$INIT_SQL" -q 2>/dev/null || true
fi

echo ""
echo "PostgreSQL ready on localhost:${POSTGRES_PORT}"
echo "  Database: $POSTGRES_DB"
echo "  Schemas:  subpool_1, subpool_2, subpool_3"
