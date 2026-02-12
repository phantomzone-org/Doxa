#!/usr/bin/env bash
set -euo pipefail

# Print per-deposit status and summary for a range.
# Args:
#   $1 start index (default 0)
#   $2 count       (default 20)

ROOT_DIR="$(cd "$(dirname "${BASH_SOURCE[0]}")/.." && pwd)"
source "$ROOT_DIR/scripts/local_env.sh"

START_INDEX="${1:-0}"
COUNT="${2:-20}"

if [[ -z "${BRIDGE:-}" ]]; then
  if [[ -f "$ROOT_DIR/tessera-server/.env" ]]; then
    BRIDGE="$(sed -n 's/^TESSERA_PENDING_DEPOSIT_BRIDGE_ADDRESS=//p' "$ROOT_DIR/tessera-server/.env" | tail -n1)"
  fi
fi

if [[ -z "${BRIDGE:-}" ]]; then
  echo "ERROR: BRIDGE not set." >&2
  exit 1
fi

# Snapshot current consumed root and query each deposit in range.
ROOT=$(cast call "$BRIDGE" "consumedRoot()(bytes32)" --rpc-url "$RPC")
echo "Bridge: $BRIDGE"
echo "ConsumedRoot: $ROOT"

available=0
withdrawn=0
consumed=0

END_INDEX=$((START_INDEX + COUNT - 1))
for i in $(seq "$START_INDEX" "$END_INDEX"); do
  resp=$(cast call "$BRIDGE" "getDeposit(uint256)((bytes32,uint256,address,address,uint8))" "$i" --rpc-url "$RPC")
  status=$(echo "$resp" | sed -E 's/.*,\s*([0-9]+)\)$/\1/')
  case "$status" in
    0) available=$((available + 1)) ;;
    1) withdrawn=$((withdrawn + 1)) ;;
    2) consumed=$((consumed + 1)) ;;
  esac
  echo "deposit $i -> $resp"
done

# Aggregate status counts for quick sanity checks.
echo ""
echo "Summary ($START_INDEX..$END_INDEX): Available=$available Withdrawn=$withdrawn Consumed=$consumed"
