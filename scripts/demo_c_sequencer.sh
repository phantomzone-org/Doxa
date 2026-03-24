#!/usr/bin/env bash
set -euo pipefail

# Step C: start the demo sequencer.
#
# Reads deployed addresses from demo_latest.env and launches the
# tessera-demo sequencer binary.
#
# Prerequisites:
#   - Anvil running (demo_a_anvil.sh)
#   - Contracts deployed (demo_b_deploy.sh)

ROOT_DIR="$(cd "$(dirname "${BASH_SOURCE[0]}")/.." && pwd)"
source "$ROOT_DIR/scripts/demo_env.sh"

if [[ -z "${ROLLUP:-}" || -z "${TOKEN:-}" ]]; then
  echo "ERROR: ROLLUP or TOKEN not set. Run demo_b_deploy.sh first." >&2
  exit 1
fi

echo ""
echo "Starting demo sequencer..."
echo "  ROLLUP=$ROLLUP"
echo "  TOKEN=$TOKEN"
echo "  Bind=$DEMO_BIND_ADDR"
echo "  Batch timeout=${DEMO_BATCH_TIMEOUT_SECS}s"
echo "  Prove delay=${DEMO_PROVE_DELAY_SECS}s"
echo ""

export DEMO_RPC_URL="$RPC"
export DEMO_OPERATOR_KEY="$OPERATOR_KEY"
export DEMO_CHAIN_ID="$CHAIN_ID"
export DEMO_BRIDGE_ADDRESS="$ROLLUP"
export DEMO_TOKEN_ADDRESS="$TOKEN"
export DEMO_BIND_ADDR="$DEMO_BIND_ADDR"
export DEMO_BATCH_TIMEOUT_SECS="$DEMO_BATCH_TIMEOUT_SECS"
export DEMO_PROVE_DELAY_SECS="$DEMO_PROVE_DELAY_SECS"

cargo run -p tessera-demo --bin demo-sequencer --release 2>&1
