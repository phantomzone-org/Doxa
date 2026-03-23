#!/usr/bin/env bash
set -euo pipefail

# Fresh-launch the Rust sequencer: wipes local tree state before starting.
# Use local_run_sequencer_hot.sh to preserve existing state (hot restart).
#
# When TESSERA_TESTING=1 (default in local_env.sh), the sequencer binary also
# starts a thin HTTP test server at TESSERA_TEST_API_ADDR exposing:
#   POST /test/deposits            — submit a deposit (no on-chain Pending check)
#   POST /test/deposits/validate   — flush + confirm deposit batch with zero proof
#   POST /test/transactions        — submit a TX slot (no Plonky2 proof required)
#   POST /test/transactions/validate — flush + confirm TX batch with zero proof
#   GET  /health                   — liveness probe

ROOT_DIR="$(cd "$(dirname "${BASH_SOURCE[0]}")/.." && pwd)"
source "$ROOT_DIR/scripts/local_env.sh"

# Resolve bridge address: prefer env override, then tessera-server/.env.
if [[ -z "${TESSERA_PENDING_DEPOSIT_BRIDGE_ADDRESS:-}" ]]; then
  echo "ERROR: TESSERA_PENDING_DEPOSIT_BRIDGE_ADDRESS not set." >&2
  echo "Run scripts/local_e2e_toy_b_deploy.sh first." >&2
  exit 1
fi

# Wipe local tree state so the sequencer starts fresh from on-chain genesis.
if [[ -d "$TESSERA_TREE_STORE_PATH" ]]; then
  echo "Removing local tree state: $TESSERA_TREE_STORE_PATH"
  rm -rf "$TESSERA_TREE_STORE_PATH"
fi

LOG_DIR="$ROOT_DIR/scripts/logs"
mkdir -p "$LOG_DIR"
SEQ_LOG="$LOG_DIR/sequencer.log"

echo "Starting sequencer (fresh) for rollup: $TESSERA_PENDING_DEPOSIT_BRIDGE_ADDRESS"
echo "Test API: $TESSERA_TEST_API_URL  (TESSERA_TESTING=$TESSERA_TESTING)"
echo "Prover API: $TESSERA_PROVER_API_URL"
echo "Logging to: $SEQ_LOG"

pushd "$ROOT_DIR/tessera-server" >/dev/null
export TESSERA_RPC_URL="$RPC"
export TESSERA_OPERATOR_KEY="$OPERATOR_KEY"
export TESSERA_CHAIN_ID="$TESSERA_CHAIN_ID"
export TESSERA_TREE_STORE_PATH="$TESSERA_TREE_STORE_PATH"
export TESSERA_POLL_INTERVAL_SECS="$TESSERA_POLL_INTERVAL_SECS"
export TESSERA_BATCH_TIMEOUT_SECS="$TESSERA_BATCH_TIMEOUT_SECS"
export TESSERA_PENDING_DEPOSIT_BRIDGE_ADDRESS="$TESSERA_PENDING_DEPOSIT_BRIDGE_ADDRESS"
export TESSERA_PROVER_API_URL="$TESSERA_PROVER_API_URL"
export TESSERA_PROVER_API_TIMEOUT_SECS="$TESSERA_PROVER_API_TIMEOUT_SECS"
export TESSERA_TESTING="$TESSERA_TESTING"
export TESSERA_TEST_API_ADDR="$TESSERA_TEST_API_ADDR"

cargo run --bin sequencer --release 2>&1 | tee "$SEQ_LOG"
popd >/dev/null
