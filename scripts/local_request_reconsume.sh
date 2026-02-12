#!/usr/bin/env bash
set -euo pipefail

# Try to request consume for already consumed deposits.
# This is a negative test: each request is expected to fail.
# Args:
#   $1 count (default 10)

ROOT_DIR="$(cd "$(dirname "${BASH_SOURCE[0]}")/.." && pwd)"
source "$ROOT_DIR/scripts/local_env.sh"

COUNT="${1:-10}"

if [[ -z "${BRIDGE:-}" ]]; then
  if [[ -f "$ROOT_DIR/tessera-server/.env" ]]; then
    BRIDGE="$(sed -n 's/^TESSERA_PENDING_DEPOSIT_BRIDGE_ADDRESS=//p' "$ROOT_DIR/tessera-server/.env" | tail -n1)"
  fi
fi

if [[ -z "${BRIDGE:-}" ]]; then
  echo "ERROR: BRIDGE not set. Run scripts/local_deploy.sh first or export BRIDGE=<address>." >&2
  exit 1
fi

NEXT_ID_RAW=$(cast call "$BRIDGE" "nextDepositId()(uint256)" --rpc-url "$RPC")
NEXT_ID="$(echo "$NEXT_ID_RAW" | tr -d '[:space:]')"

TMP_CONSUMED="$(mktemp)"
for ((i = 0; i < NEXT_ID; i++)); do
  resp=$(cast call "$BRIDGE" "getDeposit(uint256)((bytes32,uint256,address,address,uint8))" "$i" --rpc-url "$RPC")
  commitment=$(echo "$resp" | sed -E 's/^\((0x[0-9a-fA-F]{64}).*/\1/')
  status=$(echo "$resp" | sed -E 's/.*,\s*([0-9]+)\)$/\1/')
  # Status 2 = Consumed
  if [[ "$status" == "2" ]]; then
    echo "$commitment" >> "$TMP_CONSUMED"
  fi
done

CONSUMED_COUNT=$(wc -l < "$TMP_CONSUMED" | tr -d '[:space:]')
if [[ "$CONSUMED_COUNT" -eq 0 ]]; then
  echo "No consumed deposits found. Nothing to re-request."
  rm -f "$TMP_CONSUMED"
  exit 0
fi

if [[ "$COUNT" -gt "$CONSUMED_COUNT" ]]; then
  COUNT="$CONSUMED_COUNT"
fi

echo "Trying to re-request consume for $COUNT already-consumed deposits (expected: all fail)..."
echo "Using eth_call simulation to detect reverts deterministically."

successes=0
failures=0
while read -r commitment; do
  if cast call "$BRIDGE" \
    "requestConsume(bytes32)" \
    "$commitment" \
    --rpc-url "$RPC" --from "$TESSERA_TRUSTED_SOURCE" >/dev/null 2>&1; then
    echo "UNEXPECTED SUCCESS: $commitment"
    successes=$((successes + 1))
  else
    echo "expected failure: $commitment"
    failures=$((failures + 1))
  fi
done < <(shuf "$TMP_CONSUMED" | head -n "$COUNT")

rm -f "$TMP_CONSUMED"
echo "Summary: expected_failures=$failures unexpected_successes=$successes"

if [[ "$successes" -gt 0 ]]; then
  exit 1
fi
