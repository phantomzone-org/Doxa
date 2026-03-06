#!/usr/bin/env bash
set -euo pipefail

# Full optimistic two-phase E2E orchestrator.
# Starts the prover and sequencer services in the background, then runs
# local_e2e_toy_d_flow.sh which exercises the complete optimistic register+confirm path.
# Handles cleanup of both services on exit.
#
# Intended to be called from the integration test harness (integration_scripts.rs)
# or manually for single-command local testing.
#
# Requires: artifacts built, anvil running, contracts deployed
#           (scripts/local_e2e_toy_b_deploy.sh must have run first).
#
# Args:
#   $1 optional env file path (default scripts/logs/tessera_e2e_latest.env)
#   $2 total deposits          (default 256)
#   $3 request count           (default TESSERA_CONSUME_BATCH_SIZE)

ROOT_DIR="$(cd "$(dirname "${BASH_SOURCE[0]}")/.." && pwd)"
source "$ROOT_DIR/scripts/local_env.sh"

E2E_ENV="${1:-$ROOT_DIR/scripts/logs/tessera_e2e_latest.env}"
TOTAL_DEPOSITS="${2:-256}"
REQUEST_COUNT="${3:-$TESSERA_CONSUME_BATCH_SIZE}"

if [[ ! -f "$E2E_ENV" ]]; then
  echo "ERROR: missing env file: $E2E_ENV" >&2
  echo "Run scripts/local_e2e_toy_b_deploy.sh first." >&2
  exit 1
fi

# shellcheck disable=SC1090
source "$E2E_ENV"

if [[ -z "${BRIDGE:-}" ]]; then
  echo "ERROR: BRIDGE missing in $E2E_ENV" >&2
  exit 1
fi

LOG_DIR="$ROOT_DIR/scripts/logs"
mkdir -p "$LOG_DIR"
PROVER_LOG="$LOG_DIR/tessera_full_flow_prover.log"
SEQ_LOG="$LOG_DIR/tessera_full_flow_sequencer.log"
STORE_PATH="$ROOT_DIR/tessera-server/data/trees_full_flow"

PROVER_PID=""
SEQ_PID=""

kill_stale_sequencers() {
  local pids
  pids="$(pgrep -f '/target/release/sequencer' || true)"
  if [[ -n "$pids" ]]; then
    echo "Cleaning stale sequencer PIDs: $pids"
    while read -r pid; do
      [[ -z "$pid" ]] && continue
      kill "$pid" 2>/dev/null || true
    done <<< "$pids"
    sleep 1
    while read -r pid; do
      [[ -z "$pid" ]] && continue
      kill -9 "$pid" 2>/dev/null || true
    done <<< "$pids"
  fi
}

kill_stale_provers() {
  local pids
  pids="$(pgrep -f '/target/release/prover' || true)"
  if [[ -n "$pids" ]]; then
    echo "Cleaning stale prover PIDs: $pids"
    while read -r pid; do
      [[ -z "$pid" ]] && continue
      kill "$pid" 2>/dev/null || true
    done <<< "$pids"
    sleep 1
    while read -r pid; do
      [[ -z "$pid" ]] && continue
      kill -9 "$pid" 2>/dev/null || true
    done <<< "$pids"
  fi
}

start_prover() {
  echo "Starting prover service..."
  kill_stale_provers
  setsid bash -c "
    set -euo pipefail
    cd '$ROOT_DIR/tessera-server'
    export TESSERA_SUPER_AGGREGATOR_ARTIFACTS_PATH='$TESSERA_SUPER_AGGREGATOR_ARTIFACTS_PATH'
    export TESSERA_NOTE_BATCH_SIZE='$TESSERA_NOTE_BATCH_SIZE'
    export TESSERA_ACCOUNT_BATCH_SIZE='$TESSERA_ACCOUNT_BATCH_SIZE'
    export TESSERA_PROVER_API_ADDR='$TESSERA_PROVER_API_ADDR'
    cargo run --bin prover --release
  " >"$PROVER_LOG" 2>&1 &
  PROVER_PID=$!
  sleep 2
  if ! kill -0 "$PROVER_PID" 2>/dev/null; then
    echo "ERROR: prover failed to start. Check $PROVER_LOG" >&2
    exit 1
  fi
  echo "Prover started (PID=$PROVER_PID, log=$PROVER_LOG)"
}

# Wait until the prover HTTP server accepts connections.
# Circuit loading happens before the Axum server binds, so any non-zero HTTP
# response code (e.g. 400/422 for an empty body) means the server is up and ready.
wait_for_prover_api() {
  echo "Waiting for prover API..."
  local deadline=$((SECONDS + 300))
  while (( SECONDS < deadline )); do
    local code
    code=$(curl -sS -o /dev/null -w "%{http_code}" \
      -X POST "$TESSERA_PROVER_API_URL/prove" \
      -H 'content-type: application/json' \
      -d '{}' 2>/dev/null || true)
    if [[ -n "$code" && "$code" != "000" ]]; then
      echo "Prover API ready (HTTP $code)."
      return 0
    fi
    sleep 2
  done
  echo "ERROR: prover API did not become ready. Check $PROVER_LOG" >&2
  return 1
}

start_sequencer() {
  echo "Starting sequencer service..."
  kill_stale_sequencers
  rm -rf "$STORE_PATH"
  setsid bash -c "
    set -euo pipefail
    cd '$ROOT_DIR/tessera-server'
    export TESSERA_RPC_URL='$RPC'
    export TESSERA_OPERATOR_KEY='$OPERATOR_KEY'
    export TESSERA_CHAIN_ID='$TESSERA_CHAIN_ID'
    export TESSERA_TREE_STORE_PATH='$STORE_PATH'
    export TESSERA_POLL_INTERVAL_SECS='$TESSERA_POLL_INTERVAL_SECS'
    export TESSERA_PENDING_DEPOSIT_BRIDGE_ADDRESS='$BRIDGE'
    export TESSERA_SEQUENCER_API_ADDR='$TESSERA_SEQUENCER_API_ADDR'
    export TESSERA_PROVER_API_URL='$TESSERA_PROVER_API_URL'
    export TESSERA_PROVER_API_TIMEOUT_SECS='$TESSERA_PROVER_API_TIMEOUT_SECS'
    cargo run --bin sequencer --release
  " >"$SEQ_LOG" 2>&1 &
  SEQ_PID=$!
  sleep 2
  if ! kill -0 "$SEQ_PID" 2>/dev/null; then
    echo "ERROR: sequencer failed to start. Check $SEQ_LOG" >&2
    exit 1
  fi
  echo "Sequencer started (PID=$SEQ_PID, log=$SEQ_LOG)"
}

wait_for_sequencer_api() {
  echo "Waiting for sequencer API..."
  local deadline=$((SECONDS + 90))
  while (( SECONDS < deadline )); do
    local code
    code=$(curl -sS -o /dev/null -w "%{http_code}" \
      -X POST "$TESSERA_SEQUENCER_API_URL/consume-request" \
      -H 'content-type: application/json' \
      -d '{"note_commitment":"0x01","input_proof":"0x01"}' 2>/dev/null || true)
    if [[ "$code" == "200" || "$code" == "400" ]]; then
      echo "Sequencer API ready."
      return 0
    fi
    sleep 2
  done
  echo "ERROR: sequencer API not ready within timeout. Check $SEQ_LOG" >&2
  return 1
}

cleanup() {
  echo "Shutting down sequencer and prover..."
  if [[ -n "${SEQ_PID:-}" ]] && kill -0 "$SEQ_PID" 2>/dev/null; then
    kill -TERM -- "-$SEQ_PID" 2>/dev/null || true
    sleep 1
    kill -KILL -- "-$SEQ_PID" 2>/dev/null || true
    wait "$SEQ_PID" 2>/dev/null || true
  fi
  kill_stale_sequencers
  if [[ -n "${PROVER_PID:-}" ]] && kill -0 "$PROVER_PID" 2>/dev/null; then
    kill -TERM -- "-$PROVER_PID" 2>/dev/null || true
    sleep 1
    kill -KILL -- "-$PROVER_PID" 2>/dev/null || true
    wait "$PROVER_PID" 2>/dev/null || true
  fi
  kill_stale_provers
}
trap cleanup EXIT

# --- Main ---

start_prover
wait_for_prover_api
start_sequencer
wait_for_sequencer_api

echo ""
echo "Running optimistic two-phase E2E flow (deposits=$TOTAL_DEPOSITS, requests=$REQUEST_COUNT)..."
echo "  Logs:  prover=$PROVER_LOG  sequencer=$SEQ_LOG"
echo "  Store: $STORE_PATH"
echo ""

bash "$ROOT_DIR/scripts/local_e2e_toy_d_flow.sh" "$TOTAL_DEPOSITS" "$REQUEST_COUNT" "$E2E_ENV"
