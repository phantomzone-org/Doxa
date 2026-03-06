#!/usr/bin/env bash
set -euo pipefail

# Deploy Verifier + Bridge on local RPC and persist the bridge address
# into `tessera-server/.env` for sequencer convenience.
#
# If `TESSERA_MONITORED_TOKEN` is not set, deploys local `ToyUSDT` first and
# uses that address for bridge deployment.

ROOT_DIR="$(cd "$(dirname "${BASH_SOURCE[0]}")/.." && pwd)"
source "$ROOT_DIR/scripts/local_env.sh"

echo "Syncing Solidity verifier contracts from prover artifacts..."
"$ROOT_DIR/scripts/sync_verifiers_from_artifacts.sh"

pushd "$ROOT_DIR/tessera-solidity" >/dev/null

if [[ -z "${TESSERA_MONITORED_TOKEN:-}" ]]; then
  echo "TESSERA_MONITORED_TOKEN not set; deploying ToyUSDT..."
  TOKEN="$(forge create src/ToyUSDT.sol:ToyUSDT \
    --rpc-url "$RPC" \
    --private-key "$OPERATOR_KEY" \
    --broadcast | sed -n 's/Deployed to: //p' | tail -n1)"

  if [[ -z "${TOKEN:-}" ]]; then
    echo "forge create failed to return token address, falling back to cast --create..."
    BYTECODE_TOKEN="$(forge inspect src/ToyUSDT.sol:ToyUSDT bytecode)"
    DEPLOY_TOKEN_OUT="$(cast send \
      --rpc-url "$RPC" \
      --private-key "$OPERATOR_KEY" \
      --create "$BYTECODE_TOKEN")"
    TOKEN="$(echo "$DEPLOY_TOKEN_OUT" | sed -n 's/^contractAddress[[:space:]]*//p' | head -n1)"
  fi

  if [[ -z "${TOKEN:-}" ]]; then
    echo "ERROR: could not deploy ToyUSDT." >&2
    exit 1
  fi

  export TESSERA_MONITORED_TOKEN="$TOKEN"
  echo "TESSERA_MONITORED_TOKEN=$TESSERA_MONITORED_TOKEN"
fi

echo "Deploying Verifier + DepositsRollupBridge..."
export TESSERA_NOTES_NULLIFIER_ROOT="$TESSERA_NOTES_NULLIFIER_ROOT"
export TESSERA_NOTES_COMMITMENT_ROOT="$TESSERA_NOTES_COMMITMENT_ROOT"
export TESSERA_ACCOUNTS_NULLIFIER_ROOT="$TESSERA_ACCOUNTS_NULLIFIER_ROOT"
export TESSERA_ACCOUNTS_COMMITMENT_ROOT="$TESSERA_ACCOUNTS_COMMITMENT_ROOT"
export TESSERA_NOTE_BATCH_SIZE="$TESSERA_NOTE_BATCH_SIZE"
export TESSERA_ACCOUNT_BATCH_SIZE="$TESSERA_ACCOUNT_BATCH_SIZE"
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

# Persist bridge address and token into sequencer .env for convenience.
ENV_FILE="$ROOT_DIR/tessera-server/.env"
if [[ -f "$ENV_FILE" ]]; then
  if grep -q '^TESSERA_PENDING_DEPOSIT_BRIDGE_ADDRESS=' "$ENV_FILE"; then
    sed -i "s/^TESSERA_PENDING_DEPOSIT_BRIDGE_ADDRESS=.*/TESSERA_PENDING_DEPOSIT_BRIDGE_ADDRESS=$BRIDGE/" "$ENV_FILE"
  else
    echo "TESSERA_PENDING_DEPOSIT_BRIDGE_ADDRESS=$BRIDGE" >> "$ENV_FILE"
  fi
  if grep -q '^TESSERA_MONITORED_TOKEN=' "$ENV_FILE"; then
    sed -i "s/^TESSERA_MONITORED_TOKEN=.*/TESSERA_MONITORED_TOKEN=$TESSERA_MONITORED_TOKEN/" "$ENV_FILE"
  else
    echo "TESSERA_MONITORED_TOKEN=$TESSERA_MONITORED_TOKEN" >> "$ENV_FILE"
  fi
  echo "Updated $ENV_FILE"
fi

echo ""
echo "Next:"
echo "  export BRIDGE=$BRIDGE"
echo "  scripts/local_run_sequencer.sh"
