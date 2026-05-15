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
export DOXA_CHAIN_ID="31337"

# On-chain Poseidon tree depth and initial pool config root used at deploy time.
# DOXA_POOL_CONFIG_ROOT: bytes32 initial value — zero is fine for local testing.
export DOXA_TREE_DEPTH="20"
export DOXA_POOL_CONFIG_ROOT="0x0000000000000000000000000000000000000000000000000000000000000000"

# Sequencer timing.
export DOXA_POLL_INTERVAL_SECS="2"
export DOXA_BATCH_TIMEOUT_SECS="5"

# Tree state persistence.
export DOXA_TREE_STORE_PATH="$ROOT_DIR/doxa-server/data/trees"

# Remote prover (not needed for DOXA_TESTING=1 flows; kept for production use).
export DOXA_PROVER_API_ADDR="127.0.0.1:8091"
export DOXA_PROVER_API_URL="http://$DOXA_PROVER_API_ADDR"
export DOXA_PROVER_API_TIMEOUT_SECS="1800"

# Test mode: enables /test/* HTTP endpoints on the sequencer binary.
export DOXA_TESTING="1"
export DOXA_TEST_API_ADDR="127.0.0.1:8081"
export DOXA_TEST_API_URL="http://$DOXA_TEST_API_ADDR"

# Load deployed contract addresses from doxa-server/.env if present.
if [[ -f "$ROOT_DIR/doxa-server/.env" ]]; then
  _bridge="$(sed -n 's/^DOXA_PENDING_DEPOSIT_BRIDGE_ADDRESS=//p' "$ROOT_DIR/doxa-server/.env" | tail -n1)"
  _token="$(sed -n 's/^DOXA_MONITORED_TOKEN=//p' "$ROOT_DIR/doxa-server/.env" | tail -n1)"
  [[ -n "${_bridge:-}" ]] && export DOXA_PENDING_DEPOSIT_BRIDGE_ADDRESS="$_bridge"
  [[ -n "${_token:-}" ]]  && export DOXA_MONITORED_TOKEN="$_token"
  unset _bridge _token
fi

echo "Loaded local env:"
echo "  RPC=$RPC"
echo "  DOXA_CHAIN_ID=$DOXA_CHAIN_ID"
echo "  DOXA_TREE_DEPTH=$DOXA_TREE_DEPTH"
echo "  DOXA_POOL_CONFIG_ROOT=$DOXA_POOL_CONFIG_ROOT"
echo "  DOXA_TREE_STORE_PATH=$DOXA_TREE_STORE_PATH"
echo "  DOXA_TESTING=$DOXA_TESTING"
echo "  DOXA_TEST_API_URL=$DOXA_TEST_API_URL"
echo "  DOXA_PROVER_API_URL=$DOXA_PROVER_API_URL"
echo "  DOXA_PENDING_DEPOSIT_BRIDGE_ADDRESS=${DOXA_PENDING_DEPOSIT_BRIDGE_ADDRESS:-"(not set — run deploy first)"}"
echo "  DOXA_MONITORED_TOKEN=${DOXA_MONITORED_TOKEN:-"(not set — run deploy first)"}"
