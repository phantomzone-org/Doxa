#!/usr/bin/env bash
set -euo pipefail

# One-shot wrapper around console A/B/C/D scripts.
# Args:
#   $1 total deposits (default 256)
#   $2 consume requests (default TESSERA_CONSUME_BATCH_SIZE)

ROOT_DIR="$(cd "$(dirname "${BASH_SOURCE[0]}")/.." && pwd)"
source "$ROOT_DIR/scripts/local_env.sh"

TOTAL_DEPOSITS="${1:-256}"
REQUEST_COUNT="${2:-$TESSERA_BATCH_SIZE}"

LOG_DIR="$ROOT_DIR/scripts/logs"
mkdir -p "$LOG_DIR"
TS="$(date +%Y%m%d_%H%M%S)"
SEQ_LOG="$LOG_DIR/tessera_e2e_sequencer_${TS}.log"
SEQ_PID=""

kill_stale_sequencers() {
  local pids
  pids="$(pgrep -f '/target/release/sequencer' || true)"
  if [[ -n "$pids" ]]; then
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

cleanup() {
  if [[ -n "${SEQ_PID:-}" ]] && kill -0 "$SEQ_PID" 2>/dev/null; then
    kill -TERM -- "-$SEQ_PID" 2>/dev/null || true
    sleep 1
    kill -KILL -- "-$SEQ_PID" 2>/dev/null || true
    wait "$SEQ_PID" || true
  fi
  kill_stale_sequencers
}
trap cleanup EXIT

"$ROOT_DIR/scripts/local_e2e_toy_b_deploy.sh"

kill_stale_sequencers
setsid bash -c "'$ROOT_DIR/scripts/local_e2e_toy_c_sequencer.sh'" >"$SEQ_LOG" 2>&1 &
SEQ_PID=$!
sleep 2
if ! kill -0 "$SEQ_PID" 2>/dev/null; then
  echo "ERROR: sequencer failed to start. Log: $SEQ_LOG" >&2
  exit 1
fi

"$ROOT_DIR/scripts/local_e2e_toy_d_flow.sh" "$TOTAL_DEPOSITS" "$REQUEST_COUNT"

echo "Sequencer log: $SEQ_LOG"
