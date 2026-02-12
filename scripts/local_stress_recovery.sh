#!/usr/bin/env bash
set -euo pipefail

# End-to-end recovery stress:
# - start sequencer
# - submit partial requests
# - stop sequencer
# - submit remaining requests while down
# - restart sequencer and verify consumption completes

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

LOG_DIR="$ROOT_DIR/scripts/logs"
mkdir -p "$LOG_DIR"
SEQ_LOG="$LOG_DIR/tessera_sequencer_stress.log"
SEQ_PID=""
WINDOW_START=0
WINDOW_END=0
WINDOW_COMMITMENTS_FILE=""

# Best-effort cleanup for stale local sequencer processes from prior runs.
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

# Build and cache commitments for the active test window.
build_window_commitments() {
  WINDOW_COMMITMENTS_FILE="$(mktemp)"
  local i resp commitment
  for i in $(seq "$WINDOW_START" "$WINDOW_END"); do
    resp=$(cast call "$BRIDGE" "getDeposit(uint256)((bytes32,uint256,address,address,uint8))" "$i" --rpc-url "$RPC")
    commitment=$(echo "$resp" | sed -E 's/^\((0x[0-9a-fA-F]{64}).*/\1/')
    echo "$commitment" >> "$WINDOW_COMMITMENTS_FILE"
  done
}

# Count consumeRequested=true inside the active test window.
count_requested_in_window() {
  local requested=0
  local commitment is_requested
  while read -r commitment; do
    is_requested=$(cast call "$BRIDGE" "consumeRequested(bytes32)(bool)" "$commitment" --rpc-url "$RPC")
    is_requested="$(echo "$is_requested" | tr -d '[:space:]')"
    if [[ "$is_requested" == "true" ]]; then
      requested=$((requested + 1))
    fi
  done < "$WINDOW_COMMITMENTS_FILE"
  echo "$requested"
}

# Launch sequencer in background and fail fast if it crashes.
start_sequencer() {
  echo "Starting sequencer..."
  kill_stale_sequencers
  # Launch in its own session so we can terminate the whole process group.
  setsid bash -c "BRIDGE='$BRIDGE' '$ROOT_DIR/scripts/local_run_sequencer.sh'" >"$SEQ_LOG" 2>&1 &
  SEQ_PID=$!
  sleep 2
  if ! kill -0 "$SEQ_PID" 2>/dev/null; then
    echo "ERROR: sequencer failed to start. Check $SEQ_LOG" >&2
    exit 1
  fi
}

# Gracefully stop sequencer process if running.
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

cleanup() {
  stop_sequencer
  if [[ -n "${WINDOW_COMMITMENTS_FILE:-}" && -f "$WINDOW_COMMITMENTS_FILE" ]]; then
    rm -f "$WINDOW_COMMITMENTS_FILE"
  fi
}

trap cleanup EXIT

start_sequencer

echo "Phase 1: create 256 deposits + only 64 consume requests."
BRIDGE="$BRIDGE" "$ROOT_DIR/scripts/local_seed.sh" 256 64

# Scope checks to the exact deposit window created by this run.
BASE_NEXT_ID_RAW=$(cast call "$BRIDGE" "nextDepositId()(uint256)" --rpc-url "$RPC")
BASE_NEXT_ID="$(echo "$BASE_NEXT_ID_RAW" | tr -d '[:space:]')"
WINDOW_START=$((BASE_NEXT_ID - 256))
WINDOW_END=$((BASE_NEXT_ID - 1))
build_window_commitments

echo "Phase 2: simulate crash before batch can finalize."
stop_sequencer

echo "Phase 3: enqueue remaining 64 consume requests while sequencer is down."
BRIDGE="$BRIDGE" "$ROOT_DIR/scripts/local_request.sh" 0 64 random-unconsumed

echo "Waiting for pending consume requests to reach 128 in [$WINDOW_START..$WINDOW_END]..."
req_deadline=$((SECONDS + 300))
while (( SECONDS < req_deadline )); do
  requested=$(count_requested_in_window)
  echo "Pending consume requests in [$WINDOW_START..$WINDOW_END]: $requested/128"
  if [[ "$requested" -eq 128 ]]; then
    break
  fi
  missing=$((128 - requested))
  echo "Top-up: submitting $missing additional requests..."
  BRIDGE="$BRIDGE" "$ROOT_DIR/scripts/local_request.sh" 0 "$missing" random-unconsumed
  sleep 1
done

if [[ "${requested:-0}" -ne 128 ]]; then
  echo "ERROR: pending requests did not reach 128 before restart." >&2
  echo "Check for reverted request txs and sequencer log: $SEQ_LOG" >&2
  exit 1
fi

echo "Phase 4: restart sequencer and wait for 128/256 in this window to be consumed."
start_sequencer

# Poll contract until 128 deposits in this run's window are consumed or timeout.
deadline=$((SECONDS + 300))
while (( SECONDS < deadline )); do
  consumed=0
  for i in $(seq "$WINDOW_START" "$WINDOW_END"); do
    resp=$(cast call "$BRIDGE" "getDeposit(uint256)((bytes32,uint256,address,address,uint8))" "$i" --rpc-url "$RPC")
    status=$(echo "$resp" | sed -E 's/.*,\s*([0-9]+)\)$/\1/')
    if [[ "$status" == "2" ]]; then
      consumed=$((consumed + 1))
    fi
  done

  echo "Consumed in [$WINDOW_START..$WINDOW_END]: $consumed/128"
  if [[ "$consumed" -eq 128 ]]; then
    echo "Recovery test passed."
    echo "Sequencer log: $SEQ_LOG"
    exit 0
  fi
  sleep 3
done

echo "Recovery test timed out. Check sequencer logs: $SEQ_LOG" >&2
exit 1
