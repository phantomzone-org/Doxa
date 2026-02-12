#!/usr/bin/env bash
set -euo pipefail

# Submit consume requests for existing deposits by recomputing commitments.
# Args:
#   $1 start index (default 1)
#   $2 count       (default 128)
#   $3 order       (random|ordered|random-unconsumed, default random)
#
# In `random-unconsumed` mode:
# - start index is ignored
# - script samples `count` random deposits from all currently Available deposits
#   that are not already consume-requested.

ROOT_DIR="$(cd "$(dirname "${BASH_SOURCE[0]}")/.." && pwd)"
source "$ROOT_DIR/scripts/local_env.sh"

START_INDEX="${1:-1}"
COUNT="${2:-128}"
ORDER="${3:-random}" # random | ordered | random-unconsumed

if [[ -z "${BRIDGE:-}" ]]; then
  if [[ -f "$ROOT_DIR/tessera-server/.env" ]]; then
    BRIDGE="$(sed -n 's/^TESSERA_PENDING_DEPOSIT_BRIDGE_ADDRESS=//p' "$ROOT_DIR/tessera-server/.env" | tail -n1)"
  fi
fi

if [[ -z "${BRIDGE:-}" ]]; then
  echo "ERROR: BRIDGE not set. Run scripts/local_deploy.sh first or export BRIDGE=<address>." >&2
  exit 1
fi

TMP_FILE="$(mktemp)"
END_INDEX=$((START_INDEX + COUNT - 1))

if [[ "$ORDER" == "random-unconsumed" ]]; then
  AVAILABLE_FILE="$(mktemp)"
  NEXT_ID_RAW=$(cast call "$BRIDGE" "nextDepositId()(uint256)" --rpc-url "$RPC")
  NEXT_ID="$(echo "$NEXT_ID_RAW" | tr -d '[:space:]')"

  for ((i = 0; i < NEXT_ID; i++)); do
    resp=$(cast call "$BRIDGE" "getDeposit(uint256)((bytes32,uint256,address,address,uint8))" "$i" --rpc-url "$RPC")
    commitment=$(echo "$resp" | sed -E 's/^\((0x[0-9a-fA-F]{64}).*/\1/')
    status=$(echo "$resp" | sed -E 's/.*,\s*([0-9]+)\)$/\1/')
    # Status 0 = Available; this excludes already consumed entries and avoids withdrawn ones.
    # Also require not already requested, to avoid reverted duplicate requests.
    requested=$(cast call "$BRIDGE" "consumeRequested(bytes32)(bool)" "$commitment" --rpc-url "$RPC")
    requested="$(echo "$requested" | tr -d '[:space:]')"
    if [[ "$status" == "0" && "$requested" == "false" ]]; then
      echo "$commitment" >> "$AVAILABLE_FILE"
    fi
  done

  AVAILABLE_COUNT=$(wc -l < "$AVAILABLE_FILE" | tr -d '[:space:]')
  if [[ "$COUNT" -gt "$AVAILABLE_COUNT" ]]; then
    echo "ERROR: requested $COUNT consume requests but only $AVAILABLE_COUNT unrequested available deposits remain." >&2
    rm -f "$TMP_FILE" "$AVAILABLE_FILE"
    exit 1
  fi

  shuf "$AVAILABLE_FILE" | head -n "$COUNT" > "$TMP_FILE"
  rm -f "$AVAILABLE_FILE"
else
  # Build the commitment list for the requested index range.
  for i in $(seq "$START_INDEX" "$END_INDEX"); do
    NOTE=$(printf "0x%064x" "$i")
    VALUE=$i
    COMMITMENT=$(cast call "$BRIDGE" \
      "computeCommitment(bytes32,uint256,address)(bytes32)" \
      "$NOTE" "$VALUE" "$RECIPIENT" \
      --rpc-url "$RPC")
    echo "$COMMITMENT" >> "$TMP_FILE"
  done
fi

# Optionally randomize request ordering to stress order-independence.
if [[ "$ORDER" == "random" || "$ORDER" == "random-unconsumed" ]]; then
  SOURCE_CMD=(shuf "$TMP_FILE")
else
  SOURCE_CMD=(cat "$TMP_FILE")
fi

if [[ "$ORDER" == "random-unconsumed" ]]; then
  echo "Submitting $COUNT consume requests sampled from current Available deposits..."
else
  echo "Submitting $COUNT consume requests ($ORDER order), indices [$START_INDEX..$END_INDEX]..."
fi
submitted=0
while read -r C; do
  cast send "$BRIDGE" \
    "requestConsume(bytes32)" \
    "$C" \
    --rpc-url "$RPC" --private-key "$TRUSTED_KEY" --gas-limit 300000 >/dev/null
  submitted=$((submitted + 1))
done < <("${SOURCE_CMD[@]}")

rm -f "$TMP_FILE"
echo "Done. Submitted $submitted/$COUNT requests."
