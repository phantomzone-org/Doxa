#!/usr/bin/env bash
set -euo pipefail

# End-to-end chain-recovery test for sequencer local persistence.
#
# Why this script exists:
# - Validates the exact failure mode where a sequencer's local store is behind chain state.
# - Proves restart catch-up works by reconstructing missing leaves from on-chain transactions.
#
# How it must be used:
# - Run against a local anvil deployment where BRIDGE points to the active test bridge.
# - Anvil + bridge deployment must already exist before running this script.
# - Run with no other sequencer process active; this script manages sequencer lifecycle.
#
# Step-by-step:
# 1) Sequencer A (store A) finalizes batch 1.
# 2) Sequencer B (store B) finalizes batch 2 while A is offline.
# 3) Sequencer A restarts from stale store A and must catch up from chain.
# 4) Sequencer A finalizes batch 3; this confirms successful catch-up + continued operation.

ROOT_DIR="$(cd "$(dirname "${BASH_SOURCE[0]}")/.." && pwd)"
source "$ROOT_DIR/scripts/local_env.sh"

if [[ -z "${BRIDGE:-}" ]]; then
  if [[ -f "$ROOT_DIR/tessera-server/.env" ]]; then
    BRIDGE="$(sed -n 's/^TESSERA_PENDING_DEPOSIT_BRIDGE_ADDRESS=//p' "$ROOT_DIR/tessera-server/.env" | tail -n1)"
  fi
fi

if [[ -z "${BRIDGE:-}" ]]; then
  echo "ERROR: BRIDGE not set." >&2
  exit 1
fi

BATCH_SIZE="${TESSERA_CONSUME_BATCH_SIZE:-128}"
TOTAL=$((BATCH_SIZE * 3))
LOG_DIR="$ROOT_DIR/scripts/logs"
mkdir -p "$LOG_DIR"

STORE_A="$ROOT_DIR/tessera-server/data/trees_recovery_a"
STORE_B="$ROOT_DIR/tessera-server/data/trees_recovery_b"
LOG_A1="$LOG_DIR/tessera_recovery_a_first.log"
LOG_B="$LOG_DIR/tessera_recovery_b.log"
LOG_A2="$LOG_DIR/tessera_recovery_a_second.log"
PROVER_LOG="$LOG_DIR/tessera_recovery_prover.log"
SEQ_PID=""
PROVER_PID=""

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
  echo "Starting dedicated prover service..."
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
}

wait_for_api() {
  local deadline=$((SECONDS + 90))
  while (( SECONDS < deadline )); do
    local code
    code=$(curl -sS -o /dev/null -w "%{http_code}" -X POST "$TESSERA_SEQUENCER_API_URL/consume-request" \
      -H 'content-type: application/json' \
      -d '{"note_commitment":"0x00","input_proof":"0x01"}' 2>/dev/null || true)
    if [[ "$code" == "200" || "$code" == "400" || "$code" == "422" ]]; then
      return 0
    fi
    sleep 1
  done
  return 1
}

start_sequencer_with_store() {
  local name="$1"
  local store_path="$2"
  local log_path="$3"
  echo "Starting sequencer $name (store=$store_path)..."
  kill_stale_sequencers
  # Run in a dedicated process group so stop logic can kill the full tree reliably.
  setsid bash -c "
    set -euo pipefail
    cd '$ROOT_DIR/tessera-server'
    export TESSERA_RPC_URL='$RPC'
    export TESSERA_OPERATOR_KEY='$OPERATOR_KEY'
    export TESSERA_CHAIN_ID='$TESSERA_CHAIN_ID'
    export TESSERA_TREE_STORE_PATH='$store_path'
    export TESSERA_POLL_INTERVAL_SECS='$TESSERA_POLL_INTERVAL_SECS'
    export TESSERA_PENDING_DEPOSIT_BRIDGE_ADDRESS='$BRIDGE'
    export TESSERA_SEQUENCER_API_ADDR='$TESSERA_SEQUENCER_API_ADDR'
    export TESSERA_PROVER_API_URL='$TESSERA_PROVER_API_URL'
    export TESSERA_PROVER_API_TIMEOUT_SECS='$TESSERA_PROVER_API_TIMEOUT_SECS'
    cargo run --bin sequencer --release
  " >"$log_path" 2>&1 &
  SEQ_PID=$!

  sleep 2
  if ! kill -0 "$SEQ_PID" 2>/dev/null; then
    echo "ERROR: sequencer $name failed to start. Check $log_path" >&2
    exit 1
  fi
  if ! wait_for_api; then
    echo "ERROR: sequencer API not ready for $name. Check $log_path" >&2
    exit 1
  fi
}

stop_sequencer() {
  if [[ -n "${SEQ_PID:-}" ]] && kill -0 "$SEQ_PID" 2>/dev/null; then
    echo "Stopping sequencer process group -$SEQ_PID..."
    kill -TERM -- "-$SEQ_PID" 2>/dev/null || true
    sleep 1
    kill -KILL -- "-$SEQ_PID" 2>/dev/null || true
    wait "$SEQ_PID" || true
  fi
  kill_stale_sequencers
}

find_first_missing_note() {
  local i=1
  while true; do
    local note status
    note=$(printf "0x%064x" "$i")
    status=$(cast call "$BRIDGE" "getDepositStatus(bytes32)(uint8)" "$note" --rpc-url "$RPC" 2>/dev/null || true)
    status="$(echo "$status" | tr -d '[:space:]')"
    if [[ "$status" == "0" ]]; then
      echo "$i"
      return 0
    fi
    i=$((i + 1))
  done
}

count_validated_in_range() {
  local start="$1"
  local end="$2"
  local validated=0
  local i note status
  for i in $(seq "$start" "$end"); do
    note=$(printf "0x%064x" "$i")
    status=$(cast call "$BRIDGE" "getDepositStatus(bytes32)(uint8)" "$note" --rpc-url "$RPC" 2>/dev/null || true)
    status="$(echo "$status" | tr -d '[:space:]')"
    if [[ "$status" == "2" ]]; then
      validated=$((validated + 1))
    fi
  done
  echo "$validated"
}

wait_until_validated() {
  local start="$1"
  local end="$2"
  local target="$3"
  # Recovery replay + proving can be slow in debug machines; keep a generous timeout.
  local deadline=$((SECONDS + 360))
  while (( SECONDS < deadline )); do
    local validated
    validated=$(count_validated_in_range "$start" "$end")
    echo "Validated in [$start..$end]: $validated/$target"
    if [[ "$validated" -ge "$target" ]]; then
      return 0
    fi
    sleep 3
  done
  return 1
}

cleanup() {
  stop_sequencer
  if [[ -n "${PROVER_PID:-}" ]] && kill -0 "$PROVER_PID" 2>/dev/null; then
    echo "Stopping prover process group -$PROVER_PID..."
    kill -TERM -- "-$PROVER_PID" 2>/dev/null || true
    sleep 1
    kill -KILL -- "-$PROVER_PID" 2>/dev/null || true
    wait "$PROVER_PID" || true
  fi
  kill_stale_provers
}
trap cleanup EXIT

rm -rf "$STORE_A" "$STORE_B"
start_prover

echo "Phase 0: seed $TOTAL deposits (3 batches)."
START_NOTE="$(find_first_missing_note)"
END_NOTE=$((START_NOTE + TOTAL - 1))
echo "Using note range [$START_NOTE..$END_NOTE]"
BRIDGE="$BRIDGE" "$ROOT_DIR/scripts/local_seed.sh" "$TOTAL" 0 "$START_NOTE"

echo "Phase 1: sequencer A processes batch 1."
start_sequencer_with_store "A-1" "$STORE_A" "$LOG_A1"
BRIDGE="$BRIDGE" "$ROOT_DIR/scripts/local_request.sh" "$START_NOTE" "$BATCH_SIZE" random
if ! wait_until_validated "$START_NOTE" "$((START_NOTE + BATCH_SIZE - 1))" "$BATCH_SIZE"; then
  echo "ERROR: batch 1 did not finalize with sequencer A. Check $LOG_A1" >&2
  exit 1
fi
stop_sequencer

echo "Phase 2: sequencer B (different local store) processes batch 2 while A is down."
start_sequencer_with_store "B" "$STORE_B" "$LOG_B"
BRIDGE="$BRIDGE" "$ROOT_DIR/scripts/local_request.sh" "$((START_NOTE + BATCH_SIZE))" "$BATCH_SIZE" random
if ! wait_until_validated "$((START_NOTE + BATCH_SIZE))" "$((START_NOTE + 2 * BATCH_SIZE - 1))" "$BATCH_SIZE"; then
  echo "ERROR: batch 2 did not finalize with sequencer B. Check $LOG_B" >&2
  exit 1
fi
ROOT_AFTER_B=$(cast call "$BRIDGE" "notesCommitmentRoot()(bytes32)" --rpc-url "$RPC" | tr -d '[:space:]')
echo "Root after sequencer B batch: $ROOT_AFTER_B"
stop_sequencer

echo "Phase 3: restart sequencer A and verify catch-up from chain by finalizing batch 3."
start_sequencer_with_store "A-2" "$STORE_A" "$LOG_A2"
BRIDGE="$BRIDGE" "$ROOT_DIR/scripts/local_request.sh" "$((START_NOTE + 2 * BATCH_SIZE))" "$BATCH_SIZE" random
if ! wait_until_validated "$((START_NOTE + 2 * BATCH_SIZE))" "$END_NOTE" "$BATCH_SIZE"; then
  echo "ERROR: batch 3 did not finalize after A restart/catch-up. Check $LOG_A2" >&2
  exit 1
fi

ROOT_FINAL=$(cast call "$BRIDGE" "notesCommitmentRoot()(bytes32)" --rpc-url "$RPC" | tr -d '[:space:]')
if [[ "$ROOT_FINAL" == "$ROOT_AFTER_B" ]]; then
  echo "ERROR: root did not change after batch 3; catch-up path likely failed." >&2
  exit 1
fi

echo "Chain-recovery test passed."
echo "Logs:"
echo "  A first run:  $LOG_A1"
echo "  B run:        $LOG_B"
echo "  A second run: $LOG_A2"
