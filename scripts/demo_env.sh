#!/usr/bin/env bash
set -euo pipefail

# Shared defaults for demo scripts.
# This file is intended to be sourced, not executed.

ROOT_DIR="$(cd "$(dirname "${BASH_SOURCE[0]}")/.." && pwd)"

# Ensure ~/.local/bin and ~/.foundry/bin are in PATH.
export PATH="$HOME/.local/bin:$HOME/.foundry/bin:$PATH"

# RPC + funded test keys (Anvil defaults).
export RPC="http://localhost:8545"
export OPERATOR_KEY="0xac0974bec39a17e36ba4a6b4d238ff944bacb478cbed5efcae784d7bf4f2ff80"

# V2 rollup parameters.
export CHAIN_ID="31337"
export TREE_DEPTH="20"
export POOL_CONFIG_ROOT="0x0000000000000000000000000000000000000000000000000000000000000000"

# Demo sequencer timing.
export DEMO_BATCH_TIMEOUT_SECS="10"
export DEMO_PROVE_DELAY_SECS="10"
export DEMO_BIND_ADDR="127.0.0.1:3000"

# State file written by demo_b_deploy.sh and read by later scripts.
export DEMO_LOG_DIR="$ROOT_DIR/scripts/logs"
export DEMO_STATE_ENV="$DEMO_LOG_DIR/demo_latest.env"

# Load previously deployed addresses if available.
if [[ -f "$DEMO_STATE_ENV" ]]; then
  # shellcheck disable=SC1090
  source "$DEMO_STATE_ENV"
fi

echo "=== Demo env ==="
echo "  RPC=$RPC"
echo "  CHAIN_ID=$CHAIN_ID"
echo "  TREE_DEPTH=$TREE_DEPTH"
echo "  DEMO_BIND_ADDR=$DEMO_BIND_ADDR"
echo "  DEMO_BATCH_TIMEOUT_SECS=$DEMO_BATCH_TIMEOUT_SECS"
echo "  DEMO_PROVE_DELAY_SECS=$DEMO_PROVE_DELAY_SECS"
echo "  ROLLUP=${ROLLUP:-"(not set — run demo_b_deploy.sh first)"}"
echo "  TOKEN=${TOKEN:-"(not set — run demo_b_deploy.sh first)"}"
