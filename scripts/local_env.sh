#!/usr/bin/env bash
set -euo pipefail

# Shared local defaults used by other helper scripts.
# This file is intended to be sourced, not executed.

# Source this file:
#   source scripts/local_env.sh
#
# Override values beforehand if needed, e.g.:
#   export TESSERA_CONSUMED_GENERIS_ROOT=0x...
#   source scripts/local_env.sh

ROOT_DIR="$(cd "$(dirname "${BASH_SOURCE[0]}")/.." && pwd)"

# This script intentionally OVERRIDES any previously exported values.
# If you need custom values, edit this file or export after sourcing.

# RPC + funded test keys (Anvil defaults).
export RPC="http://localhost:8545"
export OPERATOR_KEY="0xac0974bec39a17e36ba4a6b4d238ff944bacb478cbed5efcae784d7bf4f2ff80"
export TRUSTED_KEY="0x59c6995e998f97a5a0044966f0945389dc9e86dae88c7a8412f4603b6b78690d"

# Bridge deployment/runtime parameters.
export TESSERA_TRUSTED_SOURCE="0x70997970C51812dc3A010C7d01b50e0d17dc79C8"
export TESSERA_CONSUME_BATCH_SIZE="128"
export TESSERA_CONSUMED_GENERIS_ROOT="0x1ef897f4a5c3f5c07cddaf7dec41197f2259296bb1bb56264ca73c3e1b998bf9"

# Addresses used by seed/request helper scripts.
export DEPOSITOR="0x3C44CdDdB6a900fa2b585dd299e03d12FA4293BC"
export RECIPIENT="0x3C44CdDdB6a900fa2b585dd299e03d12FA4293BC"

# Sequencer settings.
export TESSERA_PENDING_DEPOSITS_ARTIFACTS_PATH="$ROOT_DIR/tessera-server/artifacts/used-deposit"
export TESSERA_CHAIN_ID="31337"
export TESSERA_POLL_INTERVAL_SECS="2"

echo "Loaded local env:"
echo "  RPC=$RPC"
echo "  TESSERA_TRUSTED_SOURCE=$TESSERA_TRUSTED_SOURCE"
echo "  TESSERA_CONSUME_BATCH_SIZE=$TESSERA_CONSUME_BATCH_SIZE"
echo "  TESSERA_CONSUMED_GENERIS_ROOT=$TESSERA_CONSUMED_GENERIS_ROOT"
