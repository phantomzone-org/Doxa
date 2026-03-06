#!/usr/bin/env bash
set -euo pipefail

# Seed deposits and optionally submit consume requests to sequencer API.
# Args:
#   $1 total deposits to record (default 256)
#   $2 number of consume requests to submit from random notes (default 128)
#   $3 start note index (default: first missing note on-chain)

ROOT_DIR="$(cd "$(dirname "${BASH_SOURCE[0]}")/.." && pwd)"
source "$ROOT_DIR/scripts/local_env.sh"

# Directory of pre-generated leaf proofs (produced by `cargo run --bin aggregator_artifacts`).
# Scripts look up "$NOTE.hex" here; falls back to "0x01" when artifacts are absent.
LEAF_PROOFS_DIR="${TESSERA_AGGREGATOR_ARTIFACTS_PATH:-}/leaf_proofs"

TOTAL_DEPOSITS="${1:-256}"
REQUEST_COUNT="${2:-128}"
START_NOTE="${3:-}"

if [[ "$REQUEST_COUNT" -gt "$TOTAL_DEPOSITS" ]]; then
  echo "ERROR: request count ($REQUEST_COUNT) cannot exceed deposits ($TOTAL_DEPOSITS)" >&2
  exit 1
fi

if [[ -z "${BRIDGE:-}" ]]; then
  if [[ -f "$ROOT_DIR/tessera-server/.env" ]]; then
    BRIDGE="$(sed -n 's/^TESSERA_PENDING_DEPOSIT_BRIDGE_ADDRESS=//p' "$ROOT_DIR/tessera-server/.env" | tail -n1)"
  fi
fi

if [[ -z "${BRIDGE:-}" ]]; then
  echo "ERROR: BRIDGE not set. Run scripts/local_deploy.sh first or export BRIDGE=<address>." >&2
  exit 1
fi

echo "RPC=$RPC"
echo "BRIDGE=$BRIDGE"

TRUSTED_ADDR=$(cast wallet address --private-key "$TRUSTED_KEY")
echo "seed key addr: $TRUSTED_ADDR"

echo "seed key balance:"
cast balance "$TRUSTED_ADDR" --rpc-url "$RPC"

MONITORED_TOKEN=$(cast call "$BRIDGE" "monitoredToken()(address)" --rpc-url "$RPC" | tr -d '[:space:]')
echo "monitored token: $MONITORED_TOKEN"

find_first_missing_note() {
  local i=1
  while true; do
    local note status
    note=$(printf "0x%064x" "$i")
    status=$(cast call "$BRIDGE" "getDepositStatus(bytes32)(uint8)" "$note" --rpc-url "$RPC" 2>/dev/null || true)
    status="$(echo "$status" | tr -d '[:space:]')"
    if [[ "$status" == "0" ]]; then
      echo "$i"
      return 0
    fi
    i=$((i + 1))
  done
}

if [[ -z "$START_NOTE" ]]; then
  START_NOTE="$(find_first_missing_note)"
fi
END_NOTE=$((START_NOTE + TOTAL_DEPOSITS - 1))
echo "note range: [$START_NOTE..$END_NOTE]"

# 1) Record deposits by minting to an EOA, approving the bridge, then calling depositAndRegister(note, amount).
# This assumes local ToyUSDT-style token with open mint(address,uint256).
echo "Seeding deposits: $TOTAL_DEPOSITS (bridge=$BRIDGE)"
total_mint=0
for i in $(seq "$START_NOTE" "$END_NOTE"); do
  total_mint=$((total_mint + i))
done

cast send "$MONITORED_TOKEN" \
  "mint(address,uint256)" \
  "$TRUSTED_ADDR" "$total_mint" \
  --rpc-url "$RPC" --private-key "$OPERATOR_KEY" --gas-limit 200000 >/dev/null

cast send "$MONITORED_TOKEN" \
  "approve(address,uint256)" \
  "$BRIDGE" "$total_mint" \
  --rpc-url "$RPC" --private-key "$TRUSTED_KEY" --gas-limit 200000 >/dev/null

for i in $(seq "$START_NOTE" "$END_NOTE"); do
  NOTE=$(printf "0x%064x" "$i")
  VALUE=$i

  cast send "$BRIDGE" \
    "depositAndRegister(bytes32,uint256)" \
    "$NOTE" "$VALUE" \
    --rpc-url "$RPC" --private-key "$TRUSTED_KEY" --gas-limit 300000 >/dev/null
done

if [[ "$REQUEST_COUNT" -eq 0 ]]; then
  echo "Done. Deposits seeded, no consume requests submitted."
  exit 0
fi

# 2) Submit random consume requests directly to sequencer API.
TMP_FILE="$(mktemp)"
for i in $(shuf -i "$START_NOTE"-"$END_NOTE" -n "$REQUEST_COUNT"); do
  printf "0x%064x\n" "$i" >> "$TMP_FILE"
done

echo "Submitting $REQUEST_COUNT consume requests to sequencer API ($TESSERA_SEQUENCER_API_URL)..."
submitted=0
while read -r NOTE; do
  if [[ -f "$LEAF_PROOFS_DIR/$NOTE.hex" ]]; then
    INPUT_PROOF="$(cat "$LEAF_PROOFS_DIR/$NOTE.hex")"
  else
    INPUT_PROOF="0x01"
  fi
  resp=$(printf '{"note_commitment":"%s","input_proof":"%s"}' "$NOTE" "$INPUT_PROOF" | \
    curl -sS -X POST "$TESSERA_SEQUENCER_API_URL/consume-request" \
    -H 'content-type: application/json' \
    --data-binary @-)
  if echo "$resp" | grep -Eq '"accepted"[[:space:]]*:[[:space:]]*true'; then
    submitted=$((submitted + 1))
  else
    echo "WARN: API did not accept note $NOTE (resp=$resp)" >&2
  fi
done < <(shuf "$TMP_FILE")

rm -f "$TMP_FILE"
echo "Done. Submitted $submitted/$REQUEST_COUNT consume requests to sequencer API."
