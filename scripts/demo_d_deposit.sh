#!/usr/bin/env bash
set -euo pipefail

# Step D: deposit on-chain, then request validation from the sequencer.
#
# For each deposit this script:
#   1. Mints ToyUSDT to the operator
#   2. Approves the bridge to spend it
#   3. Calls depositAndRegister on-chain
#   4. Sends a validation request to the sequencer's POST /deposit
#
# Args:
#   $1  number of deposits (default 2)
#
# Prerequisites:
#   - Anvil running (demo_a_anvil.sh)
#   - Contracts deployed (demo_b_deploy.sh)
#   - Demo sequencer running (demo_c_sequencer.sh)

ROOT_DIR="$(cd "$(dirname "${BASH_SOURCE[0]}")/.." && pwd)"
source "$ROOT_DIR/scripts/demo_env.sh"

DEPOSIT_COUNT="${1:-2}"
API="http://$DEMO_BIND_ADDR"
AMOUNT=1000

if [[ -z "${ROLLUP:-}" ]]; then
  echo "ERROR: ROLLUP not set. Run demo_b_deploy.sh first." >&2
  exit 1
fi
if [[ -z "${TOKEN:-}" ]]; then
  echo "ERROR: TOKEN not set. Run demo_b_deploy.sh first." >&2
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
# Submit deposits (on-chain + sequencer validation request).
# ---------------------------------------------------------------------------
echo ""
echo "Submitting $DEPOSIT_COUNT deposits..."
for i in $(seq 1 "$DEPOSIT_COUNT"); do
  NOTE=$(printf "0x%064x" "$i")

  echo ""
  echo "--- Deposit $i ---"
  echo "  note_commitment = $NOTE"
  echo "  amount          = $AMOUNT"

  # 1. Mint ToyUSDT to operator.
  echo "  minting $AMOUNT tokens..."
  cast send "$TOKEN" "mint(address,uint256)" "$OPERATOR_ADDR" "$AMOUNT" \
    --private-key "$OPERATOR_KEY" --rpc-url "$RPC" > /dev/null

  # 2. Approve bridge to spend.
  echo "  approving bridge..."
  cast send "$TOKEN" "approve(address,uint256)" "$ROLLUP" "$AMOUNT" \
    --private-key "$OPERATOR_KEY" --rpc-url "$RPC" > /dev/null

  # 3. Deposit on-chain.
  echo "  calling depositAndRegister..."
  cast send "$ROLLUP" "depositAndRegister(bytes32,uint256)" "$NOTE" "$AMOUNT" \
    --private-key "$OPERATOR_KEY" --rpc-url "$RPC" > /dev/null

  # 4. Verify deposit is Pending on-chain.
  DEP_STATUS=$(cast call "$ROLLUP" "getDeposit(bytes32)((uint256,address,uint8))" "$NOTE" --rpc-url "$RPC" 2>/dev/null || echo "call failed")
  echo "  on-chain deposit = $DEP_STATUS"

  # 5. Request validation from sequencer.
  echo "  requesting validation from sequencer..."
  RESP=$(curl -sS -X POST "$API/deposit" \
    -H 'content-type: application/json' \
    -d "{\"note_commitment\":\"$NOTE\"}")

  echo "  response = $RESP"

  STATUS_FIELD=$(echo "$RESP" | jq -r '.status // empty' 2>/dev/null || true)
  if [[ "$STATUS_FIELD" == "queued" ]]; then
    echo "  OK: validation request queued"
  else
    echo "  ERROR: unexpected response" >&2
    exit 1
  fi
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
echo "Watch the sequencer logs for '=== Deposit batch CONFIRMED ==='."
