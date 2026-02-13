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

# Bridge deployment/runtime parameters.
export TESSERA_TRUSTED_SOURCE="0x70997970C51812dc3A010C7d01b50e0d17dc79C8"

# New bridge parameters (current contracts).
export TESSERA_BATCH_SIZE="128"
export TESSERA_NOTES_NULLIFIER_ROOT="0x5d85139746d173c92bf3543b4c6ce3daf11bdff30e5b44879d216bc5f06256b6"
# Must match the sequencer's local empty-tree root (CommitmentTreeState::genesis_root()).
# If this differs, the sequencer will refuse to run because proofs would not match on-chain state.
export TESSERA_NOTES_COMMITMENT_ROOT="0x5d85139746d173c92bf3543b4c6ce3daf11bdff30e5b44879d216bc5f06256b6"

# Back-compat aliases used by older scripts/docs.
export TESSERA_CONSUME_BATCH_SIZE="$TESSERA_BATCH_SIZE"
export TESSERA_CONSUMED_GENERIS_ROOT="$TESSERA_NOTES_NULLIFIER_ROOT"

# Sequencer settings.
export TESSERA_PENDING_DEPOSITS_ARTIFACTS_PATH="$ROOT_DIR/tessera-server/artifacts/commitment-tree"
export TESSERA_CHAIN_ID="31337"
export TESSERA_POLL_INTERVAL_SECS="2"
export TESSERA_SEQUENCER_API_ADDR="127.0.0.1:8081"
export TESSERA_SEQUENCER_API_URL="http://$TESSERA_SEQUENCER_API_ADDR"

echo "Loaded local env:"
echo "  RPC=$RPC"
echo "  TESSERA_TRUSTED_SOURCE=$TESSERA_TRUSTED_SOURCE"
echo "  TESSERA_BATCH_SIZE=$TESSERA_BATCH_SIZE"
echo "  TESSERA_NOTES_NULLIFIER_ROOT=$TESSERA_NOTES_NULLIFIER_ROOT"
echo "  TESSERA_NOTES_COMMITMENT_ROOT=$TESSERA_NOTES_COMMITMENT_ROOT"
echo "  TESSERA_SEQUENCER_API_URL=$TESSERA_SEQUENCER_API_URL"
