#!/usr/bin/env bash
set -euo pipefail

# Shared local defaults used by other helper scripts.
# This file is intended to be sourced, not executed.

ROOT_DIR="$(cd "$(dirname "${BASH_SOURCE[0]}")/.." && pwd)"

# This script intentionally overrides previously exported values.

# RPC + funded test keys (Anvil defaults).
export RPC="http://localhost:8545"
export OPERATOR_KEY="0xac0974bec39a17e36ba4a6b4d238ff944bacb478cbed5efcae784d7bf4f2ff80"
export TRUSTED_KEY="0x59c6995e998f97a5a0044966f0945389dc9e86dae88c7a8412f4603b6b78690d"
export CLIENT_KEY="0x5de4111afa1a4b94908f83103eb1f1706367c2e68ca870fc3fb9a804cdab365a"

# New bridge parameters (current contracts).
export TESSERA_NOTE_BATCH_SIZE="1024"
export TESSERA_ACCOUNT_BATCH_SIZE="128"  # must equal NOTE_BATCH_SIZE / 8
#
# Nullifier-tree genesis is NOT the same as commitment-tree genesis.
# Nullifier trees are pre-padded to batch_size alignment with deterministic
# Keccak-derived leaves, so the genesis root depends on the batch size.
#
# Must match the sequencer's local empty-tree root (NullifierTreeState::genesis_root(batch_size)).
# Regenerate with: TESSERA_NOTE_BATCH_SIZE=1024 TESSERA_ACCOUNT_BATCH_SIZE=128 cargo run --bin genesis_roots --release
# If this differs, the sequencer will refuse to run because proofs would not match on-chain state.
export TESSERA_NOTES_NULLIFIER_ROOT="0x15e9f8d4eba009e86420baf5b2d3c7159ae560f7227b39aa30acdd1597c98daa"
export TESSERA_NOTES_COMMITMENT_ROOT="0x5d85139746d173c92bf3543b4c6ce3daf11bdff30e5b44879d216bc5f06256b6"
export TESSERA_ACCOUNTS_NULLIFIER_ROOT="0x50cfce4ae6dc8cd7d64a9c225469076daff4105d4e293547c6acfc8daebea518"
export TESSERA_ACCOUNTS_COMMITMENT_ROOT="0x5d85139746d173c92bf3543b4c6ce3daf11bdff30e5b44879d216bc5f06256b6"

# Back-compat alias: default request count for E2E flow scripts.
export TESSERA_CONSUME_BATCH_SIZE="$TESSERA_NOTE_BATCH_SIZE"
export TESSERA_CONSUMED_GENERIS_ROOT="$TESSERA_NOTES_NULLIFIER_ROOT"

# Sequencer / prover settings.
export TESSERA_TREE_STORE_PATH="$ROOT_DIR/tessera-server/data/trees"
# Required by the prover service to load the single SuperAggregator circuit + Groth16 keys.
export TESSERA_SUPER_AGGREGATOR_ARTIFACTS_PATH="$ROOT_DIR/tessera-server/artifacts/super-aggregator"
export TESSERA_CHAIN_ID="31337"
export TESSERA_POLL_INTERVAL_SECS="2"
export TESSERA_SEQUENCER_API_ADDR="127.0.0.1:8081"
export TESSERA_SEQUENCER_API_URL="http://$TESSERA_SEQUENCER_API_ADDR"
export TESSERA_PROVER_API_ADDR="127.0.0.1:8091"
export TESSERA_PROVER_API_URL="http://$TESSERA_PROVER_API_ADDR"
export TESSERA_PROVER_API_TIMEOUT_SECS="1800"

# Consume-circuit artifacts (4-PI trivial circuit for /consume-request validation).
_consume_dir="$ROOT_DIR/tessera-server/artifacts/consume"
if [[ -f "$_consume_dir/leaf_common.bin" ]]; then
  export TESSERA_CONSUME_ARTIFACTS_PATH="$_consume_dir"
else
  unset TESSERA_CONSUME_ARTIFACTS_PATH 2>/dev/null || true
fi
unset _consume_dir

# Aggregator artifacts (72-PI trivial circuit for /private-tx validation).
_agg_dir="$ROOT_DIR/tessera-server/artifacts/associated-input-aggregator"
if [[ -f "$_agg_dir/leaf_common.bin" ]]; then
  export TESSERA_AGGREGATOR_ARTIFACTS_PATH="$_agg_dir"
else
  unset TESSERA_AGGREGATOR_ARTIFACTS_PATH 2>/dev/null || true
fi
unset _agg_dir

# Client binary env vars (bridges local_env names → what `client` expects).
# Contract addresses are read from tessera-server/.env if present.
export TESSERA_RPC_URL="$RPC"
export TESSERA_CLIENT_KEY="$CLIENT_KEY"
if [[ -f "$ROOT_DIR/tessera-server/.env" ]]; then
  _bridge="$(sed -n 's/^TESSERA_PENDING_DEPOSIT_BRIDGE_ADDRESS=//p' "$ROOT_DIR/tessera-server/.env" | tail -n1)"
  _token="$(sed -n 's/^TESSERA_MONITORED_TOKEN=//p' "$ROOT_DIR/tessera-server/.env" | tail -n1)"
  [[ -n "$_bridge" ]] && export TESSERA_PENDING_DEPOSIT_BRIDGE_ADDRESS="$_bridge"
  [[ -n "$_token" ]] && export TESSERA_MONITORED_TOKEN="$_token"
  unset _bridge _token
fi

echo "Loaded local env:"
echo "  RPC=$RPC"
echo "  TESSERA_NOTE_BATCH_SIZE=$TESSERA_NOTE_BATCH_SIZE"
echo "  TESSERA_ACCOUNT_BATCH_SIZE=$TESSERA_ACCOUNT_BATCH_SIZE"
echo "  TESSERA_NOTES_NULLIFIER_ROOT=$TESSERA_NOTES_NULLIFIER_ROOT"
echo "  TESSERA_NOTES_COMMITMENT_ROOT=$TESSERA_NOTES_COMMITMENT_ROOT"
echo "  TESSERA_ACCOUNTS_NULLIFIER_ROOT=$TESSERA_ACCOUNTS_NULLIFIER_ROOT"
echo "  TESSERA_ACCOUNTS_COMMITMENT_ROOT=$TESSERA_ACCOUNTS_COMMITMENT_ROOT"
echo "  TESSERA_TREE_STORE_PATH=$TESSERA_TREE_STORE_PATH"
echo "  TESSERA_SEQUENCER_API_URL=$TESSERA_SEQUENCER_API_URL"
echo "  TESSERA_PROVER_API_URL=$TESSERA_PROVER_API_URL"
echo "  TESSERA_SUPER_AGGREGATOR_ARTIFACTS_PATH=$TESSERA_SUPER_AGGREGATOR_ARTIFACTS_PATH"
echo "  TESSERA_CONSUME_ARTIFACTS_PATH=${TESSERA_CONSUME_ARTIFACTS_PATH:-"(not set)"}"
echo "  TESSERA_AGGREGATOR_ARTIFACTS_PATH=${TESSERA_AGGREGATOR_ARTIFACTS_PATH:-"(not set)"}"
echo "  TESSERA_CLIENT_KEY=${TESSERA_CLIENT_KEY:0:10}..."
echo "  TESSERA_PENDING_DEPOSIT_BRIDGE_ADDRESS=${TESSERA_PENDING_DEPOSIT_BRIDGE_ADDRESS:-"(not set)"}"
echo "  TESSERA_MONITORED_TOKEN=${TESSERA_MONITORED_TOKEN:-"(not set)"}"
