#!/usr/bin/env bash
set -euo pipefail

# Submit consume requests to sequencer API using note commitments.
# Args:
#   $1 start note index (default 1)
#   $2 count            (default 128)
#   $3 order            (random|ordered|random-unconsumed, default random)
#   $4 max note index   (only for random-unconsumed, default start+count-1)

ROOT_DIR="$(cd "$(dirname "${BASH_SOURCE[0]}")/.." && pwd)"
source "$ROOT_DIR/scripts/local_env.sh"

START_INDEX="${1:-1}"
COUNT="${2:-128}"
ORDER="${3:-random}"
MAX_INDEX="${4:-$((START_INDEX + COUNT - 1))}"

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

if [[ "$ORDER" == "random-unconsumed" ]]; then
  PENDING_FILE="$(mktemp)"
  for i in $(seq 1 "$MAX_INDEX"); do
    NOTE=$(printf "0x%064x" "$i")
    status=$(cast call "$BRIDGE" "getDepositStatus(bytes32)(uint8)" "$NOTE" --rpc-url "$RPC" 2>/dev/null || true)
    status="$(echo "$status" | tr -d '[:space:]')"
    # 1 = Pending (DepositStatus.None=0); ignore unknown notes/reverts.
    if [[ "$status" == "1" ]]; then
      echo "$NOTE" >> "$PENDING_FILE"
    fi
  done

  PENDING_COUNT=$(wc -l < "$PENDING_FILE" | tr -d '[:space:]')
  if [[ "$COUNT" -gt "$PENDING_COUNT" ]]; then
    echo "ERROR: requested $COUNT consume requests but only $PENDING_COUNT pending notes in [1..$MAX_INDEX]." >&2
    rm -f "$TMP_FILE" "$PENDING_FILE"
    exit 1
  fi

  shuf "$PENDING_FILE" | head -n "$COUNT" > "$TMP_FILE"
  rm -f "$PENDING_FILE"
else
  END_INDEX=$((START_INDEX + COUNT - 1))
  for i in $(seq "$START_INDEX" "$END_INDEX"); do
    printf "0x%064x\n" "$i" >> "$TMP_FILE"
  done
fi

if [[ "$ORDER" == "random" || "$ORDER" == "random-unconsumed" ]]; then
  SOURCE_CMD=(shuf "$TMP_FILE")
else
  SOURCE_CMD=(cat "$TMP_FILE")
fi

if [[ "$ORDER" == "random-unconsumed" ]]; then
  echo "Submitting $COUNT consume requests sampled from Pending notes in [1..$MAX_INDEX]..."
else
  END_INDEX=$((START_INDEX + COUNT - 1))
  echo "Submitting $COUNT consume requests ($ORDER order), notes [$START_INDEX..$END_INDEX]..."
fi

submitted=0
while read -r NOTE; do
  resp=$(curl -sS -X POST "$TESSERA_SEQUENCER_API_URL/consume-request" \
    -H 'content-type: application/json' \
    -d "{\"note_commitment\":\"$NOTE\",\"input_proof\":\"0x01\"}")
  if echo "$resp" | grep -Eq '"accepted"[[:space:]]*:[[:space:]]*true'; then
    submitted=$((submitted + 1))
  else
    echo "WARN: API did not accept note $NOTE (resp=$resp)" >&2
  fi
done < <("${SOURCE_CMD[@]}")

rm -f "$TMP_FILE"
echo "Done. Submitted $submitted/$COUNT requests."
