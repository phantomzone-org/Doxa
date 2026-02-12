#!/usr/bin/env bash
set -euo pipefail

# Seed deposits and submit consume requests.
# Args:
#   $1 total deposits to record (default 256)
#   $2 number of consume requests to submit from random deposits (default 128)

ROOT_DIR="$(cd "$(dirname "${BASH_SOURCE[0]}")/.." && pwd)"
source "$ROOT_DIR/scripts/local_env.sh"

TOTAL_DEPOSITS="${1:-256}"
REQUEST_COUNT="${2:-128}"

if [[ "$REQUEST_COUNT" -gt "$TOTAL_DEPOSITS" ]]; then
  echo "ERROR: request count ($REQUEST_COUNT) cannot exceed deposits ($TOTAL_DEPOSITS)" >&2
  exit 1
fi

if [[ -z "${BRIDGE:-}" ]]; then
  if [[ -f "$ROOT_DIR/tessera-server/.env" ]]; then
    BRIDGE="$(sed -n 's/^TESSERA_PENDING_DEPOSIT_BRIDGE_ADDRESS=//p' "$ROOT_DIR/tessera-server/.env" | tail -n1)"
  fi
fi

if [[ -z "${BRIDGE:-}" ]]; then
  echo "ERROR: BRIDGE not set. Run scripts/local_deploy.sh first or export BRIDGE=<address>." >&2
  exit 1
fi

echo "RPC=$RPC"
echo "BRIDGE=$BRIDGE"

TRUSTED_ADDR=$(cast wallet address --private-key "$TRUSTED_KEY")
echo "trusted key addr: $TRUSTED_ADDR"

echo "on-chain trustedSource:"
cast call "$BRIDGE" "trustedSource()(address)" --rpc-url "$RPC"

echo "trusted key balance:"
cast balance "$TRUSTED_ADDR" --rpc-url "$RPC"


# 1) Record deposits via trusted source.
echo "Seeding deposits: $TOTAL_DEPOSITS (bridge=$BRIDGE)"
for i in $(seq 1 "$TOTAL_DEPOSITS"); do
  NOTE=$(printf "0x%064x" "$i")
  VALUE=$i
  cast send "$BRIDGE" \
    "recordDeposit(bytes32,uint256,address,address)" \
    "$NOTE" "$VALUE" "$DEPOSITOR" "$RECIPIENT" \
    --rpc-url "$RPC" --private-key "$TRUSTED_KEY" --gas-limit 500000 >/dev/null
done

# 2) Choose a random subset of deposit indices and compute commitments.
TMP_FILE="$(mktemp)"
for i in $(shuf -i 1-"$TOTAL_DEPOSITS" -n "$REQUEST_COUNT"); do
  NOTE=$(printf "0x%064x" "$i")
  VALUE=$i
  COMMITMENT=$(cast call "$BRIDGE" \
    "computeCommitment(bytes32,uint256,address)(bytes32)" \
    "$NOTE" "$VALUE" "$RECIPIENT" \
    --rpc-url "$RPC")
  echo "$COMMITMENT" >> "$TMP_FILE"
done

# 3) Submit consume requests in randomized order.
echo "Submitting $REQUEST_COUNT consume requests from random indices..."
submitted=0
while read -r C; do
  cast send "$BRIDGE" \
    "requestConsume(bytes32)" \
    "$C" \
    --rpc-url "$RPC" --private-key "$TRUSTED_KEY" --gas-limit 300000 >/dev/null
  submitted=$((submitted + 1))
done < <(shuf "$TMP_FILE")

rm -f "$TMP_FILE"
echo "Done. Submitted $submitted/$REQUEST_COUNT requests. Check sequencer logs for batch proof/finalization."
