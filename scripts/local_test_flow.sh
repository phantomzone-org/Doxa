#!/usr/bin/env bash
set -euo pipefail

# Test flow against a running sequencer (DOXA_TESTING=1).
#
# Drives the full pipeline using the /test/* HTTP endpoints — no real prover or
# on-chain Pending deposits required.
#
# Steps:
#   1. Wait for sequencer test API to be ready.
#   2. Submit N deposits via POST /test/deposits.
#   3. Flush + confirm deposit batch via POST /test/deposits/validate.
#   4. Submit one TX slot via POST /test/transactions.
#   5. Flush + confirm TX batch via POST /test/transactions/validate.
#   6. Print on-chain root before / after for sanity check.
#
# Args:
#   $1  number of deposits   (default 3)
#   $2  optional env file    (default scripts/logs/doxa_e2e_latest.env)

ROOT_DIR="$(cd "$(dirname "${BASH_SOURCE[0]}")/.." && pwd)"
source "$ROOT_DIR/scripts/local_env.sh"

DEPOSIT_COUNT="${1:-3}"
E2E_ENV="${2:-$ROOT_DIR/scripts/logs/doxa_e2e_latest.env}"

if [[ ! -f "$E2E_ENV" ]]; then
  echo "ERROR: missing env file: $E2E_ENV" >&2
  echo "Run scripts/local_e2e_toy_b_deploy.sh first." >&2
  exit 1
fi

# shellcheck disable=SC1090
source "$E2E_ENV"

ROLLUP="${ROLLUP:-${DOXA_PENDING_DEPOSIT_BRIDGE_ADDRESS:-}}"
if [[ -z "${ROLLUP:-}" ]]; then
  echo "ERROR: ROLLUP address not set (check E2E_ENV or doxa-server/.env)." >&2
  exit 1
fi

API="$DOXA_TEST_API_URL"

# ---------------------------------------------------------------------------
# 1. Wait for sequencer test API to be ready.
# ---------------------------------------------------------------------------
echo "Waiting for sequencer test API at $API/health ..."
for _ in $(seq 1 60); do
  code=$(curl -sS -o /dev/null -w "%{http_code}" "$API/health" || true)
  if [[ "$code" == "200" ]]; then
    break
  fi
  sleep 1
done
if [[ "$(curl -sS -o /dev/null -w "%{http_code}" "$API/health" || true)" != "200" ]]; then
  echo "ERROR: sequencer test API not ready after 60s." >&2
  exit 1
fi
echo "Sequencer test API ready."

# ---------------------------------------------------------------------------
# Helper: assert accepted.
# ---------------------------------------------------------------------------
assert_accepted() {
  local resp="$1" label="$2"
  if echo "$resp" | grep -qE '"accepted"[[:space:]]*:[[:space:]]*true'; then
    echo "  OK: $label"
  else
    echo "ERROR: $label — response: $resp" >&2
    exit 1
  fi
}

# ---------------------------------------------------------------------------
# Snapshot: on-chain root before.
# ---------------------------------------------------------------------------
ROOT_BEFORE=$(cast call "$ROLLUP" "currentRoot()(uint256)" --rpc-url "$RPC" | tr -d '[:space:]')
echo ""
echo "currentRoot before: $ROOT_BEFORE"

# ---------------------------------------------------------------------------
# 2. Submit deposits.
# ---------------------------------------------------------------------------
echo ""
echo "Submitting $DEPOSIT_COUNT test deposits ..."
for i in $(seq 1 "$DEPOSIT_COUNT"); do
  NOTE=$(printf "0x%064x" "$i")
  resp=$(curl -sS -X POST "$API/test/deposits" \
    -H 'content-type: application/json' \
    -d "{\"note_commitment\":\"$NOTE\"}")
  assert_accepted "$resp" "deposit $i ($NOTE)"
done

# ---------------------------------------------------------------------------
# 3. Validate (flush + confirm) deposit batch.
# ---------------------------------------------------------------------------
echo ""
echo "Validating deposit batch (POST /test/deposits/validate) ..."
echo "  (this calls registerDepositBatch + proveDepositBatch on-chain; may take a few seconds)"
resp=$(curl -sS --max-time 120 -X POST "$API/test/deposits/validate" \
  -H 'content-type: application/json')
assert_accepted "$resp" "deposits/validate"

# ---------------------------------------------------------------------------
# 4. Submit one transaction.
# ---------------------------------------------------------------------------
echo ""
echo "Submitting one test transaction ..."
# Use sequential, non-zero leaf values so they don't collide with zero defaults.
AN=$(printf "0x%064x" 100)
AC=$(printf "0x%064x" 101)
# Build nn/nc arrays: first slot non-zero, rest zero.
NN_ARR=()
NC_ARR=()
for j in $(seq 1 8); do
  NN_ARR+=("$(printf '0x%064x' $((200 + j)))")
  NC_ARR+=("$(printf '0x%064x' $((300 + j)))")
done
NN_JSON=$(printf '"%s",' "${NN_ARR[@]}" | sed 's/,$//')
NC_JSON=$(printf '"%s",' "${NC_ARR[@]}" | sed 's/,$//')

resp=$(curl -sS -X POST "$API/test/transactions" \
  -H 'content-type: application/json' \
  -d "{\"an\":\"$AN\",\"ac\":\"$AC\",\"nn\":[$NN_JSON],\"nc\":[$NC_JSON]}")
assert_accepted "$resp" "transaction"

# ---------------------------------------------------------------------------
# 5. Validate (flush + confirm) TX batch.
# ---------------------------------------------------------------------------
echo ""
echo "Validating TX batch (POST /test/transactions/validate) ..."
echo "  (this calls registerTransactionBatch + proveTransactionBatch on-chain; may take a few seconds)"
resp=$(curl -sS --max-time 120 -X POST "$API/test/transactions/validate" \
  -H 'content-type: application/json')
assert_accepted "$resp" "transactions/validate"

# ---------------------------------------------------------------------------
# Snapshot: on-chain root after.
# ---------------------------------------------------------------------------
ROOT_AFTER=$(cast call "$ROLLUP" "currentRoot()(uint256)" --rpc-url "$RPC" | tr -d '[:space:]')
echo ""
echo "currentRoot after:  $ROOT_AFTER"

if [[ "$ROOT_AFTER" == "$ROOT_BEFORE" ]]; then
  echo "WARNING: currentRoot did not change — the on-chain tree was not updated." >&2
else
  echo "currentRoot advanced. "
fi

echo ""
echo "TEST FLOW PASSED"
echo "  ROLLUP=$ROLLUP"
echo "  deposits submitted: $DEPOSIT_COUNT"
echo "  transactions submitted: 1"
