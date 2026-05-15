#!/usr/bin/env bash
set -euo pipefail

# Start all Tessera services as background daemons on EC2.
# Binaries must already be present in RELEASE_DIR (deployed by deploy.sh).
#
# Usage:
#   ./services_start.sh              # uses default services.prod.env
#   ./services_start.sh my.env        # uses custom env file

SCRIPT_DIR="$(cd "$(dirname "${BASH_SOURCE[0]}")" && pwd)"
ENV_FILE="${1:-$SCRIPT_DIR/services.prod.env}"
LOG_DIR="$SCRIPT_DIR/logs"
PID_FILE="$LOG_DIR/services.pid"

if [[ ! -f "$ENV_FILE" ]]; then
  echo "ERROR: env file not found: $ENV_FILE" >&2
  exit 1
fi

# shellcheck disable=SC1090
source "$ENV_FILE"

RELEASE_DIR="${RELEASE_DIR:-$HOME/tessera/bin}"
DB_API_BIND_HOST="${DB_API_BIND_HOST:-127.0.0.1}"

mkdir -p "$LOG_DIR"

# Clear stale PID file.
: > "$PID_FILE"

# ── Helper: record a PID ─────────────────────────────────────────────────────
record_pid() {
  local name="$1" pid="$2"
  echo "$name=$pid" >> "$PID_FILE"
  echo "  $name  pid=$pid"
}

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

# ── 1. PostgreSQL ─────────────────────────────────────────────────────────────
"$SCRIPT_DIR/services_db.sh" "$ENV_FILE"
record_pid "postgres" "docker:$POSTGRES_CONTAINER_NAME"

# ── 2. Sequencer ──────────────────────────────────────────────────────────────
echo ""
echo "=== Starting Sequencer ==="

DEMO_RPC_URL="$RPC_URL" \
DEMO_OPERATOR_KEY="$OPERATOR_KEY" \
DEMO_CHAIN_ID="$CHAIN_ID" \
DEMO_BRIDGE_ADDRESS="$BRIDGE_ADDRESS" \
DEMO_TOKEN_ADDRESS="$TOKEN_ADDRESS" \
DEMO_BIND_ADDR="$BIND_ADDR" \
DEMO_BATCH_TIMEOUT_SECS="$BATCH_TIMEOUT_SECS" \
DEMO_PROVE_DELAY_SECS="$PROVE_DELAY_SECS" \
  "$RELEASE_DIR/demo-sequencer" \
  > "$LOG_DIR/sequencer.log" 2>&1 &
record_pid "sequencer" "$!"

# Give the sequencer a moment to bind its port.
sleep 2

# ── 3. Subpool Database API (x3) ─────────────────────────────────────────────
echo ""
echo "=== Starting Subpool Database APIs ==="

DB_URL_BASE="postgres://${POSTGRES_USER}:${POSTGRES_PASSWORD}@localhost:${POSTGRES_PORT}/${POSTGRES_DB}"

for i in 1 2 3; do
  port_var="DB_API_PORT_$i"
  port="${!port_var}"

  DATABASE_URL="${DB_URL_BASE}?options=-c%20search_path%3Dsubpool_${i}" \
  TESSERA_SUBPOOL_API_ADDR="${DB_API_BIND_HOST}:${port}" \
  SUBPOOL_ID="$i" \
  DATABASE_MAX_CONNECTIONS="$DATABASE_MAX_CONNECTIONS" \
  FAUCET_PRIVATE_KEY="$OPERATOR_KEY" \
  SEPOLIA_RPC_URL="$RPC_URL" \
  USDX_CONTRACT_ADDR="$TOKEN_ADDRESS" \
    "$RELEASE_DIR/tessera-subpool-database" \
    > "$LOG_DIR/db-${i}.log" 2>&1 &
  record_pid "subpool-db-$i" "$!"
done

# Wait for all DB APIs to be ready (they run migrations on start).
for i in 1 2 3; do
  port_var="DB_API_PORT_$i"
  port="${!port_var}"
  wait_for_port "$DB_API_BIND_HOST" "$port" "subpool-db-$i" 30
done

# ── 4. Subpool Operators (x3) ────────────────────────────────────────────────
echo ""
echo "=== Starting Subpool Operators ==="

for i in 1 2 3; do
  DATABASE_URL="${DB_URL_BASE}?options=-c%20search_path%3Dsubpool_${i}" \
  DATABASE_MAX_CONNECTIONS="$OPERATOR_DB_MAX_CONNECTIONS" \
  SEQUENCER_URL="http://${BIND_ADDR}" \
  APPROVAL_PRIVATE_KEY="$APPROVAL_PRIVATE_KEY" \
  RPC_URL="$RPC_URL" \
  ROLLUP_ADDRESS="$BRIDGE_ADDRESS" \
  POLL_INTERVAL_SECS="$POLL_INTERVAL_SECS" \
  SUBPOOL_ID="$i" \
    "$RELEASE_DIR/tessera-subpool-operator" \
    > "$LOG_DIR/operator-${i}.log" 2>&1 &
  record_pid "operator-$i" "$!"
done

# ── Summary ───────────────────────────────────────────────────────────────────
echo ""
echo "=== All services started ==="
echo "  PID file: $PID_FILE"
echo "  Logs:     $LOG_DIR/"
echo ""
echo "  Sequencer:      http://${BIND_ADDR}/status"
echo "  Subpool DB 1:   https://<EC2_IP>:8081  (internal: ${DB_API_BIND_HOST}:${DB_API_PORT_1})"
echo "  Subpool DB 2:   https://<EC2_IP>:8082  (internal: ${DB_API_BIND_HOST}:${DB_API_PORT_2})"
echo "  Subpool DB 3:   https://<EC2_IP>:8083  (internal: ${DB_API_BIND_HOST}:${DB_API_PORT_3})"
echo ""
echo "Stop all:  $SCRIPT_DIR/services_stop.sh"
echo "Status:    $SCRIPT_DIR/services_status.sh"
