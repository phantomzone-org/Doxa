#!/usr/bin/env bash
set -euo pipefail

# Start the Rust sequencer against the currently configured local bridge.

ROOT_DIR="$(cd "$(dirname "${BASH_SOURCE[0]}")/.." && pwd)"
source "$ROOT_DIR/scripts/local_env.sh"

if [[ -z "${BRIDGE:-}" ]]; then
  if [[ -f "$ROOT_DIR/tessera-server/.env" ]]; then
    BRIDGE="$(sed -n 's/^TESSERA_PENDING_DEPOSIT_BRIDGE_ADDRESS=//p' "$ROOT_DIR/tessera-server/.env" | tail -n1)"
  fi
fi

if [[ -z "${BRIDGE:-}" ]]; then
  echo "ERROR: BRIDGE not set. Run scripts/local_deploy.sh first or export BRIDGE=<address>." >&2
  exit 1
fi

pushd "$ROOT_DIR/tessera-server" >/dev/null
export TESSERA_RPC_URL="$RPC"
export TESSERA_OPERATOR_KEY="$OPERATOR_KEY"
export TESSERA_CHAIN_ID="$TESSERA_CHAIN_ID"
export TESSERA_PENDING_DEPOSITS_ARTIFACTS_PATH="$TESSERA_PENDING_DEPOSITS_ARTIFACTS_PATH"
export TESSERA_NULLIFIER_TREE_ARTIFACTS_PATH="$TESSERA_NULLIFIER_TREE_ARTIFACTS_PATH"
export TESSERA_TREE_STORE_PATH="$TESSERA_TREE_STORE_PATH"
export TESSERA_POLL_INTERVAL_SECS="$TESSERA_POLL_INTERVAL_SECS"
export TESSERA_PENDING_DEPOSIT_BRIDGE_ADDRESS="$BRIDGE"
export TESSERA_SEQUENCER_API_ADDR="$TESSERA_SEQUENCER_API_ADDR"
export TESSERA_PROVER_API_URL="$TESSERA_PROVER_API_URL"
export TESSERA_PROVER_API_TIMEOUT_SECS="$TESSERA_PROVER_API_TIMEOUT_SECS"

echo "Starting sequencer for bridge: $BRIDGE"
echo "Sequencer API: $TESSERA_SEQUENCER_API_URL"
echo "Prover API: $TESSERA_PROVER_API_URL"
cargo run --bin sequencer --release
popd >/dev/null
