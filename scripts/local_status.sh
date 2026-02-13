#!/usr/bin/env bash
set -euo pipefail

# Print per-note status and summary for a note-index range.
# Args:
#   $1 start note index (default 1)
#   $2 count            (default 20)

ROOT_DIR="$(cd "$(dirname "${BASH_SOURCE[0]}")/.." && pwd)"
source "$ROOT_DIR/scripts/local_env.sh"

START_INDEX="${1:-1}"
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

ROOT=$(cast call "$BRIDGE" "consumedRoot()(bytes32)" --rpc-url "$RPC" | tr -d '[:space:]')
echo "Bridge: $BRIDGE"
echo "ConsumedRoot: $ROOT"

available=0
consumed=0
missing=0

END_INDEX=$((START_INDEX + COUNT - 1))
for i in $(seq "$START_INDEX" "$END_INDEX"); do
  note=$(printf "0x%064x" "$i")
  dep=$(cast call "$BRIDGE" "getDeposit(bytes32)((uint256,address,uint8))" "$note" --rpc-url "$RPC" 2>/dev/null || true)
  if [[ -z "$dep" ]]; then
    missing=$((missing + 1))
    echo "note $i ($note) -> <missing>"
    continue
  fi
  status=$(echo "$dep" | sed -E 's/.*,[[:space:]]*([0-9]+)\)$/\1/')
  case "$status" in
    0) available=$((available + 1)) ;;
    1) consumed=$((consumed + 1)) ;;
  esac
  echo "note $i ($note) -> $dep"
done

echo ""
echo "Summary ($START_INDEX..$END_INDEX): Available=$available Consumed=$consumed Missing=$missing"
