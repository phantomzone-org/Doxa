#!/usr/bin/env bash
set -euo pipefail

# Start the standalone Rust prover service.

ROOT_DIR="$(cd "$(dirname "${BASH_SOURCE[0]}")/.." && pwd)"
source "$ROOT_DIR/scripts/local_env.sh"

pushd "$ROOT_DIR/tessera-server" >/dev/null
export TESSERA_PENDING_DEPOSITS_ARTIFACTS_PATH="$TESSERA_PENDING_DEPOSITS_ARTIFACTS_PATH"
export TESSERA_NULLIFIER_TREE_ARTIFACTS_PATH="$TESSERA_NULLIFIER_TREE_ARTIFACTS_PATH"
export TESSERA_BATCH_SIZE="$TESSERA_BATCH_SIZE"
export TESSERA_PROVER_API_ADDR="$TESSERA_PROVER_API_ADDR"

echo "Starting prover service on: $TESSERA_PROVER_API_URL"
cargo run --bin prover --release
popd >/dev/null
