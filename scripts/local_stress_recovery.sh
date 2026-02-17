#!/usr/bin/env bash
set -euo pipefail

# End-to-end restart recovery stress (API-driven flow).
#
# What this script tests:
# - A single sequencer instance can be stopped and restarted without breaking
#   continued batch finalization using the same local store.
#
# Prerequisites (must already be running):
# - Anvil on http://localhost:8545
# - A bridge deployed on that same Anvil (typically via scripts/local_e2e_toy_b_deploy.sh)
#
# Important:
# - This script starts/stops the sequencer itself.
# - Do NOT start a separate sequencer manually before running this script.
#
# Steps performed:
# 1) start sequencer
# 2) seed deposits
# 3) submit first batch and wait for finalization
# 4) restart sequencer
# 5) submit second batch and wait for finalization
# 6) report pass/fail

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
TOTAL=$((BATCH_SIZE * 2))
LOG_DIR="$ROOT_DIR/scripts/logs"
mkdir -p "$LOG_DIR"
SEQ_LOG="$LOG_DIR/tessera_sequencer_stress.log"
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

start_sequencer() {
  echo "Starting sequencer..."
  kill_stale_sequencers
  setsid bash -c "BRIDGE='$BRIDGE' '$ROOT_DIR/scripts/local_run_sequencer.sh'" >"$SEQ_LOG" 2>&1 &
  SEQ_PID=$!
  sleep 2
  if ! kill -0 "$SEQ_PID" 2>/dev/null; then
    echo "ERROR: sequencer failed to start. Check $SEQ_LOG" >&2
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

wait_until_validated() {
  local start="$1"
  local end="$2"
  local target="$3"
  local deadline=$((SECONDS + 300))
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
}
trap cleanup EXIT

start_sequencer

echo "Phase 1: create $TOTAL deposits (no requests yet)."
START_NOTE="$(find_first_missing_note)"
END_NOTE=$((START_NOTE + TOTAL - 1))
echo "Using note range [$START_NOTE..$END_NOTE]"
BRIDGE="$BRIDGE" "$ROOT_DIR/scripts/local_seed.sh" "$TOTAL" 0 "$START_NOTE"

echo "Phase 2: submit first batch ($BATCH_SIZE) in random order."
BRIDGE="$BRIDGE" "$ROOT_DIR/scripts/local_request.sh" "$START_NOTE" "$BATCH_SIZE" random

if ! wait_until_validated "$START_NOTE" "$((START_NOTE + BATCH_SIZE - 1))" "$BATCH_SIZE"; then
  echo "ERROR: first batch did not finalize in time. Check $SEQ_LOG" >&2
  exit 1
fi

echo "Phase 3: restart sequencer."
stop_sequencer
start_sequencer

echo "Phase 4: submit second batch ($BATCH_SIZE) in random order."
BRIDGE="$BRIDGE" "$ROOT_DIR/scripts/local_request.sh" "$((START_NOTE + BATCH_SIZE))" "$BATCH_SIZE" random

if ! wait_until_validated "$((START_NOTE + BATCH_SIZE))" "$END_NOTE" "$BATCH_SIZE"; then
  echo "ERROR: second batch did not finalize after restart. Check $SEQ_LOG" >&2
  exit 1
fi

echo "Recovery test passed."
echo "Sequencer log: $SEQ_LOG"
