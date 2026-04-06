#!/usr/bin/env bash
set -euo pipefail

# Start PostgreSQL via Docker (shared container) and initialize a group's database + schemas.
#
# Idempotent: reuses an existing container, creates database and schemas only if missing.
#
# Usage:
#   ./services_db.sh <merged-env-file>

SCRIPT_DIR="$(cd "$(dirname "${BASH_SOURCE[0]}")" && pwd)"
ROOT_DIR="$(cd "$SCRIPT_DIR/../.." && pwd)"
ENV_FILE="${1:?Usage: services_db.sh <merged-env-file>}"
INIT_SQL="$ROOT_DIR/docker/init-schemas.sql"

if [[ ! -f "$ENV_FILE" ]]; then
  echo "ERROR: env file not found: $ENV_FILE" >&2
  exit 1
fi

# shellcheck disable=SC1090
source "$ENV_FILE"

# ── Helper: wait until PostgreSQL is ready inside the container ───────────────
wait_for_postgres() {
  local container="$1" timeout="${2:-30}"
  echo "Waiting for PostgreSQL in container '$container' ..."
  for _ in $(seq 1 "$timeout"); do
    if docker exec "$container" pg_isready -q 2>/dev/null; then
      echo "  PostgreSQL is ready."
      return 0
    fi
    sleep 1
  done
  echo "ERROR: PostgreSQL not ready after ${timeout}s." >&2
  return 1
}

# ── Start PostgreSQL container (shared across all groups) ─────────────────────
echo ""
echo "=== PostgreSQL ==="

if docker ps --format '{{.Names}}' | grep -qx "$POSTGRES_CONTAINER_NAME"; then
  echo "  Container '$POSTGRES_CONTAINER_NAME' already running — reusing."
elif bash -c "echo >/dev/tcp/localhost/$POSTGRES_PORT" 2>/dev/null; then
  echo "  Port $POSTGRES_PORT already in use (external PostgreSQL?) — reusing."
else
  docker rm -f "$POSTGRES_CONTAINER_NAME" 2>/dev/null || true
  docker run -d \
    --name "$POSTGRES_CONTAINER_NAME" \
    -e POSTGRES_USER="$POSTGRES_USER" \
    -e POSTGRES_PASSWORD="$POSTGRES_PASSWORD" \
    -e POSTGRES_DB=postgres \
    -p "${POSTGRES_PORT}:5432" \
    postgres:16 >/dev/null
  echo "  Container '$POSTGRES_CONTAINER_NAME' started."
fi

wait_for_postgres "$POSTGRES_CONTAINER_NAME" 30

# Helper: run psql inside the container via Unix socket (no local psql needed)
pgexec() {
  docker exec -e PGPASSWORD="$POSTGRES_PASSWORD" "$POSTGRES_CONTAINER_NAME" \
    psql -U "$POSTGRES_USER" "$@"
}

# ── Create group database if it doesn't exist ─────────────────────────────────
echo "  Ensuring database '$POSTGRES_DB' exists ..."
pgexec -d postgres -tc "SELECT 1 FROM pg_database WHERE datname = '${POSTGRES_DB}'" \
  | grep -q 1 \
  || pgexec -d postgres -c "CREATE DATABASE \"${POSTGRES_DB}\"" -q

# ── Initialize schemas inside the group database ──────────────────────────────
if [[ -f "$INIT_SQL" ]]; then
  echo "  Initializing schemas in '$POSTGRES_DB' ..."
  docker exec -i -e PGPASSWORD="$POSTGRES_PASSWORD" "$POSTGRES_CONTAINER_NAME" \
    psql -U "$POSTGRES_USER" -d "$POSTGRES_DB" -q \
    < "$INIT_SQL" 2>/dev/null || true
fi

echo "  Database '$POSTGRES_DB' ready  (schemas: subpool_1, subpool_2, subpool_3)"
