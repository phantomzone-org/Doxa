#!/usr/bin/env bash
set -euo pipefail

# Start all Tessera services as background daemons.
#
# Services started (in order):
#   1. PostgreSQL (via services_db.sh)
#   2. Sequencer (demo-sequencer)
#   3. Subpool Database API x3
#   4. Subpool Operator x3
#
# Usage:
#   ./tessera-demo/scripts/services_start.sh              # uses default services.env
#   ./tessera-demo/scripts/services_start.sh my.env        # uses custom env file

ROOT_DIR="$(cd "$(dirname "${BASH_SOURCE[0]}")/../.." && pwd)"
SCRIPT_DIR="$(cd "$(dirname "${BASH_SOURCE[0]}")" && pwd)"
ENV_FILE="${1:-$SCRIPT_DIR/services.env}"
LOG_DIR="$SCRIPT_DIR/logs"
PID_FILE="$LOG_DIR/services.pid"

if [[ ! -f "$ENV_FILE" ]]; then
  echo "ERROR: env file not found: $ENV_FILE" >&2
  exit 1
fi

# shellcheck disable=SC1090
source "$ENV_FILE"

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

# ── 2. Build all binaries ────────────────────────────────────────────────────
echo ""
echo "=== Building binaries ==="

if [[ $EUID -eq 0 && -n "${SUDO_USER:-}" ]]; then
  # Running under sudo — invoke cargo as the original user so ~/.cargo/bin is available.
  ORIGINAL_HOME="$(getent passwd "$SUDO_USER" | cut -d: -f6)"
  sudo -u "$SUDO_USER" env \
    HOME="$ORIGINAL_HOME" \
    PATH="$ORIGINAL_HOME/.cargo/bin:$PATH" \
    cargo build --release \
      -p tessera-demo \
      -p tessera-subpool-database \
      -p tessera-subpool-operator \
    2>&1 | tail -5
else
  cargo build --release \
    -p tessera-demo \
    -p tessera-subpool-database \
    -p tessera-subpool-operator \
    2>&1 | tail -5
fi

RELEASE_DIR="$ROOT_DIR/target/release"

# ── 3. Sequencer ──────────────────────────────────────────────────────────────
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

# ── 4. Subpool Database API (x3) ─────────────────────────────────────────────
echo ""
echo "=== Starting Subpool Database APIs ==="

DB_URL_BASE="postgres://${POSTGRES_USER}:${POSTGRES_PASSWORD}@localhost:${POSTGRES_PORT}/${POSTGRES_DB}"

for i in 1 2 3; do
  port_var="DB_API_PORT_$i"
  port="${!port_var}"

  DATABASE_URL="${DB_URL_BASE}?options=-c%20search_path%3Dsubpool_${i}" \
  TESSERA_SUBPOOL_API_ADDR="0.0.0.0:${port}" \
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
  wait_for_port localhost "$port" "subpool-db-$i" 30
done

# ── 5. Subpool Operators (x3) ────────────────────────────────────────────────
echo ""
echo "=== Starting Subpool Operators ==="

for i in 1 2 3; do
  DATABASE_URL="${DB_URL_BASE}?options=-c%20search_path%3Dsubpool_${i}" \
  DATABASE_MAX_CONNECTIONS="$OPERATOR_DB_MAX_CONNECTIONS" \
  SEQUENCER_URL="http://${BIND_ADDR}" \
  APPROVAL_PRIVATE_KEY="$APPROVAL_PRIVATE_KEY" \
  RPC_URL="$RPC_URL" \
  OPERATOR_KEY="$OPERATOR_KEY" \
  ROLLUP_ADDRESS="$BRIDGE_ADDRESS" \
  POLL_INTERVAL_SECS="$POLL_INTERVAL_SECS" \
  CHAINALYSIS_API_KEY="$CHAINALYSIS_API_KEY" \
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
echo "  Subpool DB 1:   http://localhost:${DB_API_PORT_1}"
echo "  Subpool DB 2:   http://localhost:${DB_API_PORT_2}"
echo "  Subpool DB 3:   http://localhost:${DB_API_PORT_3}"
echo ""
echo "Stop all:  $SCRIPT_DIR/services_stop.sh"
echo "Status:    $SCRIPT_DIR/services_status.sh"
