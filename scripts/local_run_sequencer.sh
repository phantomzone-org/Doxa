#!/usr/bin/env bash
set -euo pipefail

# Fresh-launch the Rust sequencer: wipes local tree state before starting.
# Use local_run_sequencer_hot.sh to preserve existing state (hot restart).
#
# When DOXA_TESTING=1 (default in local_env.sh), the sequencer binary also
# starts a thin HTTP test server at DOXA_TEST_API_ADDR exposing:
#   POST /test/deposits            — submit a deposit (no on-chain Pending check)
#   POST /test/deposits/validate   — flush + confirm deposit batch with zero proof
#   POST /test/transactions        — submit a TX slot (no Plonky2 proof required)
#   POST /test/transactions/validate — flush + confirm TX batch with zero proof
#   GET  /health                   — liveness probe

ROOT_DIR="$(cd "$(dirname "${BASH_SOURCE[0]}")/.." && pwd)"
source "$ROOT_DIR/scripts/local_env.sh"

# Resolve bridge address: prefer env override, then doxa-server/.env.
if [[ -z "${DOXA_PENDING_DEPOSIT_BRIDGE_ADDRESS:-}" ]]; then
  echo "ERROR: DOXA_PENDING_DEPOSIT_BRIDGE_ADDRESS not set." >&2
  echo "Run scripts/local_e2e_toy_b_deploy.sh first." >&2
  exit 1
fi

# Wipe local tree state so the sequencer starts fresh from on-chain genesis.
if [[ -d "$DOXA_TREE_STORE_PATH" ]]; then
  echo "Removing local tree state: $DOXA_TREE_STORE_PATH"
  rm -rf "$DOXA_TREE_STORE_PATH"
fi

LOG_DIR="$ROOT_DIR/scripts/logs"
mkdir -p "$LOG_DIR"
SEQ_LOG="$LOG_DIR/sequencer.log"

echo "Starting sequencer (fresh) for rollup: $DOXA_PENDING_DEPOSIT_BRIDGE_ADDRESS"
echo "Test API: $DOXA_TEST_API_URL  (DOXA_TESTING=$DOXA_TESTING)"
echo "Prover API: $DOXA_PROVER_API_URL"
echo "Logging to: $SEQ_LOG"

pushd "$ROOT_DIR/doxa-server" >/dev/null
export DOXA_RPC_URL="$RPC"
export DOXA_OPERATOR_KEY="$OPERATOR_KEY"
export DOXA_CHAIN_ID="$DOXA_CHAIN_ID"
export DOXA_TREE_STORE_PATH="$DOXA_TREE_STORE_PATH"
export DOXA_POLL_INTERVAL_SECS="$DOXA_POLL_INTERVAL_SECS"
export DOXA_BATCH_TIMEOUT_SECS="$DOXA_BATCH_TIMEOUT_SECS"
export DOXA_PENDING_DEPOSIT_BRIDGE_ADDRESS="$DOXA_PENDING_DEPOSIT_BRIDGE_ADDRESS"
export DOXA_PROVER_API_URL="$DOXA_PROVER_API_URL"
export DOXA_PROVER_API_TIMEOUT_SECS="$DOXA_PROVER_API_TIMEOUT_SECS"
export DOXA_TESTING="$DOXA_TESTING"
export DOXA_TEST_API_ADDR="$DOXA_TEST_API_ADDR"

cargo run --bin sequencer --release 2>&1 | tee "$SEQ_LOG"
popd >/dev/null
