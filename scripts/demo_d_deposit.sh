#!/usr/bin/env bash
set -euo pipefail

# Step D: submit deposits to the demo sequencer and monitor on-chain state.
#
# Args:
#   $1  number of deposits (default 2)
#
# Prerequisites:
#   - Demo sequencer running (demo_c_sequencer.sh)

ROOT_DIR="$(cd "$(dirname "${BASH_SOURCE[0]}")/.." && pwd)"
source "$ROOT_DIR/scripts/demo_env.sh"

DEPOSIT_COUNT="${1:-2}"
API="http://$DEMO_BIND_ADDR"

if [[ -z "${ROLLUP:-}" ]]; then
  echo "ERROR: ROLLUP not set. Run demo_b_deploy.sh first." >&2
  exit 1
fi

# ---------------------------------------------------------------------------
# Wait for sequencer to be ready.
# ---------------------------------------------------------------------------
echo ""
echo "Waiting for sequencer at $API/status ..."
for _ in $(seq 1 30); do
  code=$(curl -sS -o /dev/null -w "%{http_code}" "$API/status" 2>/dev/null || true)
  if [[ "$code" == "200" ]]; then break; fi
  sleep 1
done
if [[ "$(curl -sS -o /dev/null -w "%{http_code}" "$API/status" 2>/dev/null || true)" != "200" ]]; then
  echo "ERROR: sequencer not ready after 30s." >&2
  exit 1
fi
echo "Sequencer ready."

# ---------------------------------------------------------------------------
# Snapshot: on-chain root before deposits.
# ---------------------------------------------------------------------------
ROOT_BEFORE=$(cast call "$ROLLUP" "currentRoot()(uint256)" --rpc-url "$RPC" | tr -d '[:space:]' | sed 's/\[.*\]//')
echo ""
echo "=== On-chain state BEFORE deposits ==="
echo "  currentRoot = $ROOT_BEFORE"

STATUS=$(curl -sS "$API/status")
echo "  sequencer status = $STATUS"

# ---------------------------------------------------------------------------
# Submit deposits.
# ---------------------------------------------------------------------------
echo ""
echo "Submitting $DEPOSIT_COUNT deposits..."
for i in $(seq 1 "$DEPOSIT_COUNT"); do
  # Generate a deterministic note commitment.
  NOTE=$(printf "0x%064x" "$i")
  AMOUNT=1000

  echo ""
  echo "--- Deposit $i ---"
  echo "  note_commitment = $NOTE"
  echo "  amount          = $AMOUNT"

  RESP=$(curl -sS -X POST "$API/deposit" \
    -H 'content-type: application/json' \
    -d "{\"note_commitment\":\"$NOTE\",\"amount\":$AMOUNT}")

  echo "  response = $RESP"

  # Check response status.
  STATUS_FIELD=$(echo "$RESP" | jq -r '.status // empty' 2>/dev/null || true)
  if [[ "$STATUS_FIELD" == "pending" ]]; then
    echo "  OK: deposit accepted"
  else
    echo "  ERROR: unexpected response" >&2
    exit 1
  fi

  # Check on-chain deposit status.
  DEP_STATUS=$(cast call "$ROLLUP" "getDeposit(bytes32)((uint8,uint256,address))" "$NOTE" --rpc-url "$RPC" 2>/dev/null || echo "call failed")
  echo "  on-chain deposit = $DEP_STATUS"
done

# ---------------------------------------------------------------------------
# Post-deposit sequencer status.
# ---------------------------------------------------------------------------
echo ""
echo "=== Sequencer status after deposits ==="
STATUS=$(curl -sS "$API/status")
echo "  $STATUS"

echo ""
echo "Deposits submitted. The sequencer will auto-flush the deposit batch"
echo "after ${DEMO_BATCH_TIMEOUT_SECS}s and prove it after ${DEMO_PROVE_DELAY_SECS}s more."
echo ""
echo "Next: wait for confirmation -> scripts/demo_e_deposit_validate.sh"
