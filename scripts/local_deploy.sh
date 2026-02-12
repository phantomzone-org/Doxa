#!/usr/bin/env bash
set -euo pipefail

# Deploy Verifier + Bridge on local RPC and persist the bridge address
# into `tessera-server/.env` for sequencer convenience.

ROOT_DIR="$(cd "$(dirname "${BASH_SOURCE[0]}")/.." && pwd)"
source "$ROOT_DIR/scripts/local_env.sh"

pushd "$ROOT_DIR/tessera-solidity" >/dev/null

echo "Deploying Verifier + DepositsRollupBridge..."
# Capture output so we can parse the deployed bridge address.
DEPLOY_OUTPUT="$(
  forge script script/pending-deposit/Deploy.s.sol \
    --rpc-url "$RPC" \
    --private-key "$OPERATOR_KEY" \
    --broadcast 2>&1
)"
echo "$DEPLOY_OUTPUT"

BRIDGE="$(
  echo "$DEPLOY_OUTPUT" \
    | sed -n 's/.*Bridge deployed at:[[:space:]]*//p' \
    | tail -n1 \
    | tr -d '\r'
)"

if [[ -z "${BRIDGE:-}" ]]; then
  echo "ERROR: could not parse bridge address from deploy output" >&2
  exit 1
fi

echo "BRIDGE=$BRIDGE"

popd >/dev/null

# Persist bridge address into sequencer .env for convenience.
ENV_FILE="$ROOT_DIR/tessera-server/.env"
if [[ -f "$ENV_FILE" ]]; then
  if rg -q '^TESSERA_PENDING_DEPOSIT_BRIDGE_ADDRESS=' "$ENV_FILE"; then
    sed -i "s/^TESSERA_PENDING_DEPOSIT_BRIDGE_ADDRESS=.*/TESSERA_PENDING_DEPOSIT_BRIDGE_ADDRESS=$BRIDGE/" "$ENV_FILE"
  else
    echo "TESSERA_PENDING_DEPOSIT_BRIDGE_ADDRESS=$BRIDGE" >> "$ENV_FILE"
  fi
  echo "Updated $ENV_FILE"
fi

echo ""
echo "Next:"
echo "  export BRIDGE=$BRIDGE"
echo "  scripts/local_run_sequencer.sh"
