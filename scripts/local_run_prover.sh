#!/usr/bin/env bash
set -euo pipefail

# Start the standalone Rust prover service.

ROOT_DIR="$(cd "$(dirname "${BASH_SOURCE[0]}")/.." && pwd)"
source "$ROOT_DIR/scripts/local_env.sh"

pushd "$ROOT_DIR/tessera-server" >/dev/null
# Required: single SuperAggregator circuit + Groth16 keys.
export TESSERA_SUPER_AGGREGATOR_ARTIFACTS_PATH="$TESSERA_SUPER_AGGREGATOR_ARTIFACTS_PATH"
export TESSERA_NOTE_BATCH_SIZE="$TESSERA_NOTE_BATCH_SIZE"
export TESSERA_ACCOUNT_BATCH_SIZE="$TESSERA_ACCOUNT_BATCH_SIZE"
export TESSERA_PROVER_API_ADDR="$TESSERA_PROVER_API_ADDR"
# Optional: path to GenericAggregator artifacts for validating private-tx leaf proofs.
# Unset or absent → leaf proof validation disabled (prover accepts dummy proofs only).
export TESSERA_AGGREGATOR_ARTIFACTS_PATH="${TESSERA_AGGREGATOR_ARTIFACTS_PATH:-}"

LOG_DIR="$ROOT_DIR/scripts/logs"
mkdir -p "$LOG_DIR"
PROVER_LOG="$LOG_DIR/prover.log"

echo "Starting prover service on: $TESSERA_PROVER_API_URL"
echo "  SuperAggregator artifacts: $TESSERA_SUPER_AGGREGATOR_ARTIFACTS_PATH"
if [[ -n "${TESSERA_AGGREGATOR_ARTIFACTS_PATH:-}" ]]; then
  echo "  TX aggregator artifacts: $TESSERA_AGGREGATOR_ARTIFACTS_PATH"
else
  echo "  TX aggregator: disabled (TESSERA_AGGREGATOR_ARTIFACTS_PATH not set)"
fi
echo "Logging to: $PROVER_LOG"
cargo run --bin prover --release 2>&1 | tee "$PROVER_LOG"
popd >/dev/null
