#!/usr/bin/env bash
set -euo pipefail

# E2E wrapper around deploy + flow only.
# Prover and sequencer must be started separately before running this script.
# Args:
#   $1 total deposits (default 256)
#   $2 consume requests (default TESSERA_CONSUME_BATCH_SIZE)

ROOT_DIR="$(cd "$(dirname "${BASH_SOURCE[0]}")/.." && pwd)"
source "$ROOT_DIR/scripts/local_env.sh"

TOTAL_DEPOSITS="${1:-256}"
REQUEST_COUNT="${2:-$TESSERA_BATCH_SIZE}"

LOG_DIR="$ROOT_DIR/scripts/logs"
mkdir -p "$LOG_DIR"

"$ROOT_DIR/scripts/local_e2e_toy_b_deploy.sh"

if ! pgrep -f '/target/release/prover' >/dev/null 2>&1; then
  echo "ERROR: prover is not running." >&2
  echo "Start it in a separate terminal with: scripts/local_run_prover.sh" >&2
  exit 1
fi

if ! pgrep -f '/target/release/sequencer' >/dev/null 2>&1; then
  echo "ERROR: sequencer is not running." >&2
  echo "Start it in a separate terminal with: scripts/local_e2e_toy_c_sequencer.sh" >&2
  exit 1
fi

"$ROOT_DIR/scripts/local_e2e_toy_d_flow.sh" "$TOTAL_DEPOSITS" "$REQUEST_COUNT"
