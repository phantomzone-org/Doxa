#!/usr/bin/env bash
set -euo pipefail

# Step F: submit a private transaction to the demo sequencer.
#
# Sends one transaction with synthetic leaf data (no real Plonky2 proof).
#
# Prerequisites:
#   - Deposit batch confirmed (demo_e_deposit_validate.sh)

ROOT_DIR="$(cd "$(dirname "${BASH_SOURCE[0]}")/.." && pwd)"
source "$ROOT_DIR/scripts/demo_env.sh"

API="http://$DEMO_BIND_ADDR"

if [[ -z "${ROLLUP:-}" ]]; then
  echo "ERROR: ROLLUP not set. Run demo_b_deploy.sh first." >&2
  exit 1
fi

# ---------------------------------------------------------------------------
# Snapshot: on-chain root before transaction.
# ---------------------------------------------------------------------------
ROOT_BEFORE=$(cast call "$ROLLUP" "currentRoot()(uint256)" --rpc-url "$RPC" | tr -d '[:space:]' | sed 's/\[.*\]//')
echo ""
echo "=== On-chain state BEFORE transaction ==="
echo "  currentRoot = $ROOT_BEFORE"

STATUS=$(curl -sS "$API/status")
echo "  sequencer status = $STATUS"

# ---------------------------------------------------------------------------
# Build transaction payload.
# ---------------------------------------------------------------------------
# Use synthetic, non-zero leaf values (distinct from deposit leaves).
INPUT_ACCOUNT=$(printf "0x%064x" 1000)
OUTPUT_ACCOUNT=$(printf "0x%064x" 1001)

# 7 input notes (NOTE_BATCH = 7) and 7 output notes.
INPUT_NOTES=()
OUTPUT_NOTES=()
for j in $(seq 1 7); do
  INPUT_NOTES+=("$(printf '0x%064x' $((2000 + j)))")
  OUTPUT_NOTES+=("$(printf '0x%064x' $((3000 + j)))")
done
INPUT_JSON=$(printf '"%s",' "${INPUT_NOTES[@]}" | sed 's/,$//')
OUTPUT_JSON=$(printf '"%s",' "${OUTPUT_NOTES[@]}" | sed 's/,$//')

# Fake tx_proof (empty bytes, the demo sequencer doesn't verify it).
TX_PROOF="0x00"

echo ""
echo "--- Transaction ---"
echo "  input_account_leaf  = $INPUT_ACCOUNT"
echo "  output_account_leaf = $OUTPUT_ACCOUNT"
echo "  input_notes (7)     = [${INPUT_NOTES[0]}, ...]"
echo "  output_notes (7)    = [${OUTPUT_NOTES[0]}, ...]"

RESP=$(curl -sS -X POST "$API/transaction" \
  -H 'content-type: application/json' \
  -d "{
    \"tx_id\": \"demo-tx-1\",
    \"input_account_leaf\": \"$INPUT_ACCOUNT\",
    \"output_account_leaf\": \"$OUTPUT_ACCOUNT\",
    \"input_notes\": [$INPUT_JSON],
    \"output_notes\": [$OUTPUT_JSON],
    \"tx_proof\": \"$TX_PROOF\"
  }")

echo "  response = $RESP"

STATUS_FIELD=$(echo "$RESP" | jq -r '.status // empty' 2>/dev/null || true)
if [[ "$STATUS_FIELD" == "queued" ]]; then
  echo "  OK: transaction queued"
else
  echo "  ERROR: unexpected response" >&2
  exit 1
fi

# ---------------------------------------------------------------------------
# Post-transaction sequencer status.
# ---------------------------------------------------------------------------
echo ""
echo "=== Sequencer status after transaction ==="
STATUS=$(curl -sS "$API/status")
echo "  $STATUS"

echo ""
echo "Transaction submitted. The sequencer will auto-flush the TX batch"
echo "after ${DEMO_BATCH_TIMEOUT_SECS}s and prove it after ${DEMO_PROVE_DELAY_SECS}s more."
echo ""
echo "Next: wait for confirmation -> scripts/demo_g_tx_validate.sh"
