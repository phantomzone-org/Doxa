#!/usr/bin/env bash
set -euo pipefail

# Start all Tessera services for one or all demo groups.
#
# Each group gets its own: sequencer, subpool DB APIs, subpool operators, database.
# The PostgreSQL Docker container is shared across all groups.
#
# Usage:
#   ./services_start.sh --group <slug>   # start one group
#   ./services_start.sh --all            # start all groups in parallel
#   ./services_start.sh                  # same as --all

SCRIPT_DIR="$(cd "$(dirname "${BASH_SOURCE[0]}")" && pwd)"
ROOT_DIR="$(cd "$SCRIPT_DIR/../.." && pwd)"
SHARED_ENV="$SCRIPT_DIR/services.env"
DEMO_GROUPS_DIR="$SCRIPT_DIR/groups"
LOG_DIR="$SCRIPT_DIR/logs"
RELEASE_DIR="$ROOT_DIR/target/release"

GROUP=""
ALL=false

# ── Parse args ────────────────────────────────────────────────────────────────
while [[ $# -gt 0 ]]; do
  case "$1" in
    --group) GROUP="$2"; shift 2 ;;
    --all)   ALL=true; shift ;;
    *) echo "Unknown argument: $1"; exit 1 ;;
  esac
done

if [[ -z "$GROUP" && "$ALL" == false ]]; then
  ALL=true
fi

if [[ ! -f "$SHARED_ENV" ]]; then
  echo "ERROR: $SHARED_ENV not found" >&2
  exit 1
fi

# ── Build binaries once ───────────────────────────────────────────────────────
echo "=== Building binaries ==="

if [[ $EUID -eq 0 && -n "${SUDO_USER:-}" ]]; then
  ORIGINAL_HOME="$(getent passwd "$SUDO_USER" | cut -d: -f6)"
  sudo -u "$SUDO_USER" env \
    HOME="$ORIGINAL_HOME" \
    PATH="$ORIGINAL_HOME/.cargo/bin:$PATH" \
    cargo build --release \
      -p tessera-demo \
      -p tessera-subpool-database \
      -p tessera-subpool-operator
else
  cargo build --release \
    -p tessera-demo \
    -p tessera-subpool-database \
    -p tessera-subpool-operator
fi


echo "ASS"
# ── Collect groups to start ───────────────────────────────────────────────────
if [[ ! -d "$DEMO_GROUPS_DIR" ]]; then
  echo "ERROR: groups directory not found: $DEMO_GROUPS_DIR"
  exit 1
fi

DEMO_GROUPS=()
if [[ "$ALL" == true ]]; then
  for d in "$DEMO_GROUPS_DIR"/*/; do
    [[ -d "$d" ]] && DEMO_GROUPS+=("$(basename "$d")")
  done
  if [[ ${#DEMO_GROUPS[@]} -eq 0 ]]; then
    echo "ERROR: no groups found in $DEMO_GROUPS_DIR"
    exit 1
  fi
else
  if [[ ! -d "$DEMO_GROUPS_DIR/$GROUP" ]]; then
    echo "ERROR: group '$GROUP' not found in $DEMO_GROUPS_DIR"
    exit 1
  fi
  DEMO_GROUPS=("$GROUP")
fi

echo "Groups to start: ${DEMO_GROUPS[*]}"
echo "ASS1"



# ── Helpers ───────────────────────────────────────────────────────────────────
record_pid() {
  local pid_file="$1" name="$2" pid="$3"
  echo "$name=$pid" >> "$pid_file"
  echo "  $name  pid=$pid"
}

wait_for_port() {
  local host="$1" port="$2" label="$3" timeout="${4:-30}"
  echo "  Waiting for $label ($host:$port) ..."
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

# ── Start one group ───────────────────────────────────────────────────────────
start_group() {
  local group="$1"
  local group_env="$DEMO_GROUPS_DIR/$group/group.env"

  if [[ ! -f "$group_env" ]]; then
    echo "ERROR: group.env not found: $group_env" >&2
    return 1
  fi

  local group_log_dir="$LOG_DIR/$group"
  local pid_file="$group_log_dir/services.pid"
  mkdir -p "$group_log_dir"
  : > "$pid_file"

  # Merge shared + group env into a temp file (group vars override shared).
  local merged_env
  merged_env="$(mktemp)"
  cat "$SHARED_ENV" "$group_env" > "$merged_env"
  # shellcheck disable=SC1090
  source "$merged_env"

  echo ""
  echo "=== Group: $group ==="

  # ── Database ────────────────────────────────────────────────────────────────
  "$SCRIPT_DIR/services_db.sh" "$merged_env"
  record_pid "$pid_file" "postgres" "docker:$POSTGRES_CONTAINER_NAME"

  local db_url_base="postgres://${POSTGRES_USER}:${POSTGRES_PASSWORD}@localhost:${POSTGRES_PORT}/${POSTGRES_DB}"

  # ── Sequencer ───────────────────────────────────────────────────────────────
  echo ""
  local seq_port="${BIND_ADDR##*:}"
  if fuser "${seq_port}/tcp" >/dev/null 2>&1; then
    echo "  Port $seq_port in use — killing existing process ..."
    fuser -k "${seq_port}/tcp" 2>/dev/null || true
    sleep 1
  fi
  echo "  Starting sequencer on $BIND_ADDR ..."
  DEMO_RPC_URL="$RPC_URL" \
  DEMO_OPERATOR_KEY="$OPERATOR_KEY" \
  DEMO_CHAIN_ID="$CHAIN_ID" \
  DEMO_BRIDGE_ADDRESS="$BRIDGE_ADDRESS" \
  DEMO_TOKEN_ADDRESS="$TOKEN_ADDRESS" \
  DEMO_BIND_ADDR="$BIND_ADDR" \
  DEMO_BATCH_TIMEOUT_SECS="$BATCH_TIMEOUT_SECS" \
  DEMO_PROVE_DELAY_SECS="$PROVE_DELAY_SECS" \
    "$RELEASE_DIR/demo-sequencer" \
    > "$group_log_dir/sequencer.log" 2>&1 &
  record_pid "$pid_file" "sequencer" "$!"
  sleep 2

  # ── Subpool Database APIs ────────────────────────────────────────────────────
  echo ""
  echo "  Starting subpool database APIs ..."
  for i in 1 2 3; do
    local port_var port
    port_var="DB_API_PORT_$i"
    port="${!port_var}"
    if fuser "${port}/tcp" >/dev/null 2>&1; then
      echo "  Port $port in use — killing existing process ..."
      fuser -k "${port}/tcp" 2>/dev/null || true
      sleep 1
    fi
    DATABASE_URL="${db_url_base}?options=-c%20search_path%3Dsubpool_${i}" \
    TESSERA_SUBPOOL_API_ADDR="0.0.0.0:${port}" \
    SUBPOOL_ID="$i" \
    DATABASE_MAX_CONNECTIONS="$DATABASE_MAX_CONNECTIONS" \
    FAUCET_PRIVATE_KEY="$OPERATOR_KEY" \
    SEPOLIA_RPC_URL="$RPC_URL" \
    USDX_CONTRACT_ADDR="$TOKEN_ADDRESS" \
      "$RELEASE_DIR/tessera-subpool-database" \
      > "$group_log_dir/db-${i}.log" 2>&1 &
    record_pid "$pid_file" "subpool-db-$i" "$!"
  done

  for i in 1 2 3; do
    local port_var port
    port_var="DB_API_PORT_$i"
    port="${!port_var}"
    wait_for_port localhost "$port" "subpool-db-$i" 30 \
      || { echo "ERROR: subpool-db-$i failed to start. Log:"; cat "$group_log_dir/db-${i}.log"; return 1; }
  done

  # ── Subpool Operators ────────────────────────────────────────────────────────
  echo ""
  echo "  Starting subpool operators ..."
  for i in 1 2 3; do
    DATABASE_URL="${db_url_base}?options=-c%20search_path%3Dsubpool_${i}" \
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
      > "$group_log_dir/operator-${i}.log" 2>&1 &
    record_pid "$pid_file" "operator-$i" "$!"
  done

  rm -f "$merged_env"

  echo ""
  echo "  Group '$group' started."
  echo "    PID file : $pid_file"
  echo "    Logs     : $group_log_dir/"
  echo "    Sequencer: http://${BIND_ADDR}/status"
  echo "    DB APIs  : :${DB_API_PORT_1}  :${DB_API_PORT_2}  :${DB_API_PORT_3}"
}

# ── Launch ────────────────────────────────────────────────────────────────────
mkdir -p "$LOG_DIR"

if [[ ${#DEMO_GROUPS[@]} -eq 1 ]]; then
  start_group "${DEMO_GROUPS[0]}"
else
  declare -A BGPIDS
  mkdir -p "$LOG_DIR"
  for g in "${DEMO_GROUPS[@]}"; do
    mkdir -p "$LOG_DIR/$g"
    start_group "$g" > "$LOG_DIR/$g/startup.log" 2>&1 &
    BGPIDS["$g"]=$!
    echo "Started group '$g' in background (startup log: $LOG_DIR/$g/startup.log)"
  done

  FAILED=false
  for g in "${!BGPIDS[@]}"; do
    if wait "${BGPIDS[$g]}"; then
      echo "Group '$g' started successfully."
    else
      echo "ERROR: group '$g' failed — startup log:" >&2
      cat "$LOG_DIR/$g/startup.log" >&2
      FAILED=true
    fi
  done
  [[ "$FAILED" == false ]] || exit 1
fi

echo ""
echo "=== All groups started ==="
echo "Stop:   $SCRIPT_DIR/services_stop.sh [--group <slug> | --all]"
echo "Status: $SCRIPT_DIR/services_status.sh [--group <slug> | --all]"
