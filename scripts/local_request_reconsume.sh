#!/usr/bin/env bash
set -euo pipefail

# Try to re-submit already validated notes to the sequencer API.
# Expected behavior: API accepts request shape, but on-chain state should remain unchanged.
# Args:
#   $1 count (default 10)
#   $2 max note index to scan (default 1024)

ROOT_DIR="$(cd "$(dirname "${BASH_SOURCE[0]}")/.." && pwd)"
source "$ROOT_DIR/scripts/local_env.sh"

COUNT="${1:-10}"
MAX_INDEX="${2:-1024}"

if [[ -z "${BRIDGE:-}" ]]; then
  if [[ -f "$ROOT_DIR/tessera-server/.env" ]]; then
    BRIDGE="$(sed -n 's/^TESSERA_PENDING_DEPOSIT_BRIDGE_ADDRESS=//p' "$ROOT_DIR/tessera-server/.env" | tail -n1)"
  fi
fi

if [[ -z "${BRIDGE:-}" ]]; then
  echo "ERROR: BRIDGE not set. Run scripts/local_deploy.sh first or export BRIDGE=<address>." >&2
  exit 1
fi

TMP_VALIDATED="$(mktemp)"
for i in $(seq 1 "$MAX_INDEX"); do
  note=$(printf "0x%064x" "$i")
  status=$(cast call "$BRIDGE" "getDepositStatus(bytes32)(uint8)" "$note" --rpc-url "$RPC" 2>/dev/null || true)
  status="$(echo "$status" | tr -d '[:space:]')"
  if [[ "$status" == "2" ]]; then
    echo "$note" >> "$TMP_VALIDATED"
  fi
done

VALIDATED_COUNT=$(wc -l < "$TMP_VALIDATED" | tr -d '[:space:]')
if [[ "$VALIDATED_COUNT" -eq 0 ]]; then
  echo "No validated notes found in [1..$MAX_INDEX]. Nothing to re-submit."
  rm -f "$TMP_VALIDATED"
  exit 0
fi

if [[ "$COUNT" -gt "$VALIDATED_COUNT" ]]; then
  COUNT="$VALIDATED_COUNT"
fi

root_before=$(cast call "$BRIDGE" "notesCommitmentRoot()(bytes32)" --rpc-url "$RPC" | tr -d '[:space:]')
echo "Submitting $COUNT already-validated notes to API (notesCommitmentRoot before: $root_before)..."

submitted=0
while read -r note; do
  resp=$(curl -sS -X POST "$TESSERA_SEQUENCER_API_URL/consume-request" \
    -H 'content-type: application/json' \
    -d "{\"note_commitment\":\"$note\"}")
  if echo "$resp" | grep -Eq '"accepted"[[:space:]]*:[[:space:]]*true'; then
    submitted=$((submitted + 1))
  fi
done < <(shuf "$TMP_VALIDATED" | head -n "$COUNT")

sleep 2
root_after=$(cast call "$BRIDGE" "notesCommitmentRoot()(bytes32)" --rpc-url "$RPC" | tr -d '[:space:]')

rm -f "$TMP_VALIDATED"

echo "Submitted: $submitted/$COUNT"
echo "notesCommitmentRoot after: $root_after"
if [[ "$root_before" == "$root_after" ]]; then
  echo "OK: notesCommitmentRoot unchanged after re-submit attempts."
else
  echo "WARN: notesCommitmentRoot changed. A separate valid batch may have finalized concurrently." >&2
fi
