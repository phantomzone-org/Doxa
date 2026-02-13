#!/usr/bin/env bash
set -euo pipefail

# Console D: generate deposits via depositAndRecord, submit consume requests, and verify.
# Args:
#   $1 total deposits (default 256)
#   $2 consume requests (default TESSERA_CONSUME_BATCH_SIZE)
#   $3 optional env file path (default scripts/logs/tessera_e2e_latest.env)

ROOT_DIR="$(cd "$(dirname "${BASH_SOURCE[0]}")/.." && pwd)"
source "$ROOT_DIR/scripts/local_env.sh"

TOTAL_DEPOSITS="${1:-256}"
REQUEST_COUNT="${2:-$TESSERA_CONSUME_BATCH_SIZE}"
E2E_ENV="${3:-$ROOT_DIR/scripts/logs/tessera_e2e_latest.env}"

if [[ "$REQUEST_COUNT" -gt "$TOTAL_DEPOSITS" ]]; then
  echo "ERROR: request count ($REQUEST_COUNT) cannot exceed deposits ($TOTAL_DEPOSITS)." >&2
  exit 1
fi

if [[ ! -f "$E2E_ENV" ]]; then
  echo "ERROR: missing env file: $E2E_ENV" >&2
  echo "Run scripts/local_e2e_toy_b_deploy.sh first." >&2
  exit 1
fi

# shellcheck disable=SC1090
source "$E2E_ENV"

if [[ -z "${BRIDGE:-}" || -z "${TOKEN:-}" || -z "${TRUSTED_SOURCE:-}" ]]; then
  echo "ERROR: BRIDGE/TOKEN/TRUSTED_SOURCE missing in $E2E_ENV" >&2
  exit 1
fi

# Check sequencer API readiness.
for _ in $(seq 1 20); do
  code=$(curl -sS -o /dev/null -w "%{http_code}" -X POST "$TESSERA_SEQUENCER_API_URL/consume-request" \
    -H 'content-type: application/json' \
    -d '{"note_commitment":"0x01"}' || true)
  if [[ "$code" == "200" || "$code" == "400" ]]; then
    break
  fi
  sleep 1
done

LOG_DIR="$ROOT_DIR/scripts/logs"
mkdir -p "$LOG_DIR"
TS="$(date +%Y%m%d_%H%M%S)"
NOTES_FILE="$LOG_DIR/tessera_e2e_notes_${TS}.txt"
REQ_FILE="$LOG_DIR/tessera_e2e_requests_${TS}.txt"

USER_KEY="0x5de4111afa1a4b94908f83103eb1f1706367c2e68ca870fc3fb9a804cdab365a"
USER_ADDR=$(cast wallet address --private-key "$USER_KEY")
echo "USER_ADDR=$USER_ADDR"

echo "Funding user in ToyUSDT + approving bridge..."
cast send "$TOKEN" "mint(address,uint256)" "$USER_ADDR" 1000000000 \
  --rpc-url "$RPC" \
  --private-key "$OPERATOR_KEY" >/dev/null

cast send "$TOKEN" "approve(address,uint256)" "$BRIDGE" 1000000000 \
  --rpc-url "$RPC" \
  --private-key "$USER_KEY" >/dev/null

echo "Creating $TOTAL_DEPOSITS deposits via depositAndRecord..."
: > "$NOTES_FILE"
for i in $(seq 1 "$TOTAL_DEPOSITS"); do
  NOTE=$(printf "0x%064x" "$i")
  AMOUNT=$((1000 + i))
  cast send "$TRUSTED_SOURCE" "depositAndRecord(bytes32,uint256)" "$NOTE" "$AMOUNT" \
    --rpc-url "$RPC" \
    --private-key "$USER_KEY" >/dev/null
  echo "$NOTE" >> "$NOTES_FILE"
done

ROOT_BEFORE=$(cast call "$BRIDGE" "notesCommitmentRoot()(bytes32)" --rpc-url "$RPC" | tr -d '[:space:]')
echo "notesCommitmentRoot before requests: $ROOT_BEFORE"

echo "Submitting $REQUEST_COUNT random consume requests to sequencer API..."
shuf "$NOTES_FILE" | head -n "$REQUEST_COUNT" > "$REQ_FILE"
submitted=0
while read -r NOTE; do
  resp=$(curl -sS -X POST "$TESSERA_SEQUENCER_API_URL/consume-request" \
    -H 'content-type: application/json' \
    -d "{\"note_commitment\":\"$NOTE\"}")
  if echo "$resp" | grep -Eq '"accepted"[[:space:]]*:[[:space:]]*true'; then
    submitted=$((submitted + 1))
  fi
done < "$REQ_FILE"
echo "API accepted: $submitted/$REQUEST_COUNT"

deadline=$((SECONDS + 420))
while (( SECONDS < deadline )); do
  validated=0
  while read -r NOTE; do
    STATUS=$(cast call "$BRIDGE" "getDepositStatus(bytes32)(uint8)" "$NOTE" --rpc-url "$RPC" | tr -d '[:space:]')
    # 1 == Validated in current bridge.
    if [[ "$STATUS" == "1" ]]; then
      validated=$((validated + 1))
    fi
  done < "$REQ_FILE"

  echo "Validated in requested subset: $validated/$REQUEST_COUNT"
  if [[ "$validated" -eq "$REQUEST_COUNT" ]]; then
    break
  fi
  sleep 3
done

if [[ "${validated:-0}" -ne "$REQUEST_COUNT" ]]; then
  echo "ERROR: timeout waiting for all requested notes to become Validated." >&2
  echo "NOTE: This requires the sequencer/server to call validateDepositBatch/recordNotesNullifierTreeUpdate." >&2
  exit 1
fi

ROOT_AFTER=$(cast call "$BRIDGE" "notesCommitmentRoot()(bytes32)" --rpc-url "$RPC" | tr -d '[:space:]')
echo "notesCommitmentRoot after requests:  $ROOT_AFTER"

if [[ "$ROOT_AFTER" == "$ROOT_BEFORE" ]]; then
  echo "ERROR: notesCommitmentRoot did not change after batch finalization." >&2
  exit 1
fi

echo ""
echo "E2E FLOW PASSED"
echo "BRIDGE=$BRIDGE"
echo "TOKEN=$TOKEN"
echo "TRUSTED_SOURCE=$TRUSTED_SOURCE"
echo "NOTES_FILE=$NOTES_FILE"
echo "REQ_FILE=$REQ_FILE"

echo ""
echo "All deposits in contract (note_index 1..$TOTAL_DEPOSITS):"
for i in $(seq 1 "$TOTAL_DEPOSITS"); do
  NOTE=$(printf "0x%064x" "$i")
  dep=$(cast call "$BRIDGE" "getDeposit(bytes32)((uint256,address,uint8))" "$NOTE" --rpc-url "$RPC" 2>/dev/null || true)
  if [[ -z "$dep" ]]; then
    echo "note_index=$i note=$NOTE -> <missing>"
    continue
  fi
  status=$(echo "$dep" | sed -E 's/.*,[[:space:]]*([0-9]+)\)$/\1/')
  case "$status" in
    0) status_label="Pending" ;;
    1) status_label="Validated" ;;
    2) status_label="Withdrawn" ;;
    *) status_label="Unknown($status)" ;;
  esac
  echo "note_index=$i note=$NOTE status=$status_label data=$dep"
done
