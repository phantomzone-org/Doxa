#!/usr/bin/env bash
set -euo pipefail

# Shared local defaults used by other helper scripts.
# This file is intended to be sourced, not executed.

ROOT_DIR="$(cd "$(dirname "${BASH_SOURCE[0]}")/.." && pwd)"

# This script intentionally overrides previously exported values.

# RPC + funded test keys (Anvil defaults).
export RPC="http://localhost:8545"
export OPERATOR_KEY="0xac0974bec39a17e36ba4a6b4d238ff944bacb478cbed5efcae784d7bf4f2ff80"
export CLIENT_KEY="0x5de4111afa1a4b94908f83103eb1f1706367c2e68ca870fc3fb9a804cdab365a"

# V2 rollup parameters.
export TESSERA_CHAIN_ID="31337"
export TESSERA_ACCOUNT_BATCH_SIZE="2"   # account slots per TX batch (small for fast tests)

# On-chain Poseidon tree depth and initial pool config root used at deploy time.
# TESSERA_POOL_CONFIG_ROOT: bytes32 initial value — zero is fine for local testing.
export TESSERA_TREE_DEPTH="20"
export TESSERA_POOL_CONFIG_ROOT="0x0000000000000000000000000000000000000000000000000000000000000000"

# Sequencer timing.
export TESSERA_POLL_INTERVAL_SECS="2"
export TESSERA_BATCH_TIMEOUT_SECS="5"

# Tree state persistence.
export TESSERA_TREE_STORE_PATH="$ROOT_DIR/tessera-server/data/trees"

# Remote prover (not needed for TESSERA_TESTING=1 flows; kept for production use).
export TESSERA_PROVER_API_ADDR="127.0.0.1:8091"
export TESSERA_PROVER_API_URL="http://$TESSERA_PROVER_API_ADDR"
export TESSERA_PROVER_API_TIMEOUT_SECS="1800"

# Test mode: enables /test/* HTTP endpoints on the sequencer binary.
export TESSERA_TESTING="1"
export TESSERA_TEST_API_ADDR="127.0.0.1:8081"
export TESSERA_TEST_API_URL="http://$TESSERA_TEST_API_ADDR"

# Load deployed contract addresses from tessera-server/.env if present.
if [[ -f "$ROOT_DIR/tessera-server/.env" ]]; then
  _bridge="$(sed -n 's/^TESSERA_PENDING_DEPOSIT_BRIDGE_ADDRESS=//p' "$ROOT_DIR/tessera-server/.env" | tail -n1)"
  _token="$(sed -n 's/^TESSERA_MONITORED_TOKEN=//p' "$ROOT_DIR/tessera-server/.env" | tail -n1)"
  [[ -n "${_bridge:-}" ]] && export TESSERA_PENDING_DEPOSIT_BRIDGE_ADDRESS="$_bridge"
  [[ -n "${_token:-}" ]]  && export TESSERA_MONITORED_TOKEN="$_token"
  unset _bridge _token
fi

echo "Loaded local env:"
echo "  RPC=$RPC"
echo "  TESSERA_CHAIN_ID=$TESSERA_CHAIN_ID"
echo "  TESSERA_ACCOUNT_BATCH_SIZE=$TESSERA_ACCOUNT_BATCH_SIZE"
echo "  TESSERA_TREE_DEPTH=$TESSERA_TREE_DEPTH"
echo "  TESSERA_POOL_CONFIG_ROOT=$TESSERA_POOL_CONFIG_ROOT"
echo "  TESSERA_TREE_STORE_PATH=$TESSERA_TREE_STORE_PATH"
echo "  TESSERA_TESTING=$TESSERA_TESTING"
echo "  TESSERA_TEST_API_URL=$TESSERA_TEST_API_URL"
echo "  TESSERA_PROVER_API_URL=$TESSERA_PROVER_API_URL"
echo "  TESSERA_PENDING_DEPOSIT_BRIDGE_ADDRESS=${TESSERA_PENDING_DEPOSIT_BRIDGE_ADDRESS:-"(not set — run deploy first)"}"
echo "  TESSERA_MONITORED_TOKEN=${TESSERA_MONITORED_TOKEN:-"(not set — run deploy first)"}"
