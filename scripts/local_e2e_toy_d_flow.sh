#!/usr/bin/env bash
set -euo pipefail

# Console D: generate deposits via depositAndRecord, submit a private-tx covering
# all requested notes, and verify the full optimistic two-phase flow end-to-end.
#
# Two-phase optimistic flow:
#   Phase A — sequencer calls registerTransactionBatchUpdate():
#               all 4 latest roots advance immediately;
#               Pending deposits in noteCommitmentsOut become Validated.
#   Phase B — sequencer submits 4 Groth16 proof jobs; confirmTreeUpdate() is called
#               per tree; each confirmed*Root advances; TransactionBatchConfirmed fires
#               after all 4 trees are confirmed.
#
# Args:
#   $1 total deposits     (default 256)
#   $2 request count      (default TESSERA_CONSUME_BATCH_SIZE; must be ≤ TESSERA_BATCH_SIZE)
#   $3 optional env file  (default scripts/logs/tessera_e2e_latest.env)

ROOT_DIR="$(cd "$(dirname "${BASH_SOURCE[0]}")/.." && pwd)"

# Step 1: Load shared local environment variables (RPC, API URLs, keys, defaults).
source "$ROOT_DIR/scripts/local_env.sh"

# Step 2: Resolve runtime parameters with safe defaults.
TOTAL_DEPOSITS="${1:-256}"
REQUEST_COUNT="${2:-$TESSERA_CONSUME_BATCH_SIZE}"
E2E_ENV="${3:-$ROOT_DIR/scripts/logs/tessera_e2e_latest.env}"

# Step 3: Guardrail — REQUEST_COUNT must fit in a single batch (one /private-tx call).
if [[ "$REQUEST_COUNT" -gt "$TESSERA_BATCH_SIZE" ]]; then
  echo "ERROR: request count ($REQUEST_COUNT) cannot exceed batch size ($TESSERA_BATCH_SIZE)." >&2
  exit 1
fi

# Step 4: Guardrail — you cannot commit more notes than you deposit in this run.
if [[ "$REQUEST_COUNT" -gt "$TOTAL_DEPOSITS" ]]; then
  echo "ERROR: request count ($REQUEST_COUNT) cannot exceed deposits ($TOTAL_DEPOSITS)." >&2
  exit 1
fi

# Step 5: Ensure deployment metadata exists (produced by local_e2e_toy_b_deploy.sh).
if [[ ! -f "$E2E_ENV" ]]; then
  echo "ERROR: missing env file: $E2E_ENV" >&2
  echo "Run scripts/local_e2e_toy_b_deploy.sh first." >&2
  exit 1
fi

# Step 6: Load deployed contract addresses and actors (BRIDGE, TOKEN, TOY_USER).
# shellcheck disable=SC1090
source "$E2E_ENV"

# Step 7: Validate required deployment variables are available.
if [[ -z "${BRIDGE:-}" || -z "${TOKEN:-}" || -z "${TOY_USER:-}" ]]; then
  echo "ERROR: BRIDGE/TOKEN/TOY_USER missing in $E2E_ENV" >&2
  exit 1
fi

# Step 8: Wait for sequencer API readiness before sending real requests.
for _ in $(seq 1 20); do
  code=$(curl -sS -o /dev/null -w "%{http_code}" -X POST "$TESSERA_SEQUENCER_API_URL/consume-request" \
    -H 'content-type: application/json' \
    -d '{"note_commitment":"0x01","input_proof":"0x01"}' || true)
  if [[ "$code" == "200" || "$code" == "400" ]]; then
    break
  fi
  sleep 1
done

# Step 9: Prepare run-scoped log/output files.
LOG_DIR="$ROOT_DIR/scripts/logs"
mkdir -p "$LOG_DIR"
TS="$(date +%Y%m%d_%H%M%S)"
NOTES_FILE="$LOG_DIR/tessera_e2e_notes_${TS}.txt"
REQ_FILE="$LOG_DIR/tessera_e2e_requests_${TS}.txt"

# Derive the test user address from the fixed local private key.
USER_KEY="0x5de4111afa1a4b94908f83103eb1f1706367c2e68ca870fc3fb9a804cdab365a"
USER_ADDR=$(cast wallet address --private-key "$USER_KEY")
echo "USER_ADDR=$USER_ADDR"

# Step 10: Mint ToyUSDT to user and approve the bridge for deposits.
echo "Funding user in ToyUSDT + approving bridge..."
cast send "$TOKEN" "mint(address,uint256)" "$USER_ADDR" 1000000000 \
  --rpc-url "$RPC" \
  --private-key "$OPERATOR_KEY" >/dev/null

cast send "$TOKEN" "approve(address,uint256)" "$BRIDGE" 1000000000 \
  --rpc-url "$RPC" \
  --private-key "$USER_KEY" >/dev/null

# Step 11: Create deterministic deposits through ToyUser.depositAndRecord.
echo "Creating $TOTAL_DEPOSITS deposits via depositAndRecord..."
: > "$NOTES_FILE"
for i in $(seq 1 "$TOTAL_DEPOSITS"); do
  NOTE=$(printf "0x%064x" "$i")
  AMOUNT=$((1000 + i))
  cast send "$TOY_USER" "depositAndRecord(bytes32,uint256)" "$NOTE" "$AMOUNT" \
    --rpc-url "$RPC" \
    --private-key "$USER_KEY" >/dev/null
  echo "$NOTE" >> "$NOTES_FILE"
done

# Step 12: Snapshot pre-submit state for all 5 roots.
ROOT_BEFORE=$(cast call "$BRIDGE" "notesCommitmentRoot()(bytes32)" --rpc-url "$RPC" | tr -d '[:space:]')
CONF_NC_BEFORE=$(cast call "$BRIDGE" "confirmedNotesCommitmentRoot()(bytes32)" --rpc-url "$RPC" | tr -d '[:space:]')
CONF_NN_BEFORE=$(cast call "$BRIDGE" "confirmedNotesNullifierRoot()(bytes32)" --rpc-url "$RPC" | tr -d '[:space:]')
CONF_AC_BEFORE=$(cast call "$BRIDGE" "confirmedAccountsCommitmentRoot()(bytes32)" --rpc-url "$RPC" | tr -d '[:space:]')
CONF_AN_BEFORE=$(cast call "$BRIDGE" "confirmedAccountsNullifierRoot()(bytes32)" --rpc-url "$RPC" | tr -d '[:space:]')
echo "notesCommitmentRoot before:          $ROOT_BEFORE"
echo "confirmedNotesCommitmentRoot before: $CONF_NC_BEFORE"
echo "confirmedNotesNullifierRoot before:  $CONF_NN_BEFORE"
echo "confirmedAccountsCommitmentRoot before: $CONF_AC_BEFORE"
echo "confirmedAccountsNullifierRoot before:  $CONF_AN_BEFORE"

# Step 13: Build the private-tx JSON and REQ_FILE.
#
# output_notes: the first REQUEST_COUNT deposited notes (indices 1..REQUEST_COUNT).
#   These are Pending deposits; registerTransactionBatchUpdate marks them Validated.
# input_notes: synthetic nullifier notes (indices TOTAL_DEPOSITS+1 .. TOTAL_DEPOSITS+REQUEST_COUNT).
#   No deposit-status check applies to nullifiers.
# account leaves: synthetic dummy values beyond the note range.
#
# All indices are small enough that every 64-bit Goldilocks limb is in range.

: > "$REQ_FILE"
output_notes_json=""
for i in $(seq 1 "$REQUEST_COUNT"); do
  sep=$([[ "$i" -lt "$REQUEST_COUNT" ]] && echo "," || echo "")
  output_notes_json+="\"$(printf '0x%064x' "$i")\"${sep}"
  printf "0x%064x\n" "$i" >> "$REQ_FILE"
done

input_notes_json=""
IN_END=$((TOTAL_DEPOSITS + REQUEST_COUNT))
for i in $(seq $((TOTAL_DEPOSITS + 1)) "$IN_END"); do
  sep=$([[ "$i" -lt "$IN_END" ]] && echo "," || echo "")
  input_notes_json+="\"$(printf '0x%064x' "$i")\"${sep}"
done

IN_ACCOUNT=$(printf '0x%064x' $((TOTAL_DEPOSITS + REQUEST_COUNT + 1)))
OUT_ACCOUNT=$(printf '0x%064x' $((TOTAL_DEPOSITS + REQUEST_COUNT + 2)))

BODY="{\"input_notes\":[${input_notes_json}],\"output_notes\":[${output_notes_json}],\
\"input_account_commitment\":\"${IN_ACCOUNT}\",\"output_account_commitment\":\"${OUT_ACCOUNT}\",\
\"tx_proof\":\"0x01\"}"

echo "Submitting private tx ($REQUEST_COUNT output notes, $REQUEST_COUNT input notes)..."
resp=$(curl -sS -X POST "$TESSERA_SEQUENCER_API_URL/private-tx" \
  -H 'content-type: application/json' \
  -d "$BODY")
echo "$resp"
if ! echo "$resp" | grep -Eq '"accepted"[[:space:]]*:[[:space:]]*true'; then
  echo "ERROR: /private-tx not accepted." >&2
  exit 1
fi

# Step 14: Phase A — poll notesCommitmentRoot() until it advances.
# The latest root advances at register time (before any proof), so this proves
# the sequencer successfully called registerTransactionBatchUpdate on-chain.
echo "Phase A: waiting for notesCommitmentRoot to advance (register on-chain)..."
deadline_a=$((SECONDS + 120))
ROOT_AFTER="$ROOT_BEFORE"
while (( SECONDS < deadline_a )); do
  ROOT_AFTER=$(cast call "$BRIDGE" "notesCommitmentRoot()(bytes32)" --rpc-url "$RPC" | tr -d '[:space:]')
  if [[ "$ROOT_AFTER" != "$ROOT_BEFORE" ]]; then
    echo "Phase A: notesCommitmentRoot advanced to $ROOT_AFTER"
    break
  fi
  sleep 2
done
if [[ "$ROOT_AFTER" == "$ROOT_BEFORE" ]]; then
  echo "ERROR: notesCommitmentRoot did not advance within Phase A timeout." >&2
  exit 1
fi

# Step 15: Phase A — verify deposits are Validated.
# registerTransactionBatchUpdate marks Pending deposits Validated atomically.
validated=0
while read -r NOTE; do
  STATUS=$(cast call "$BRIDGE" "getDepositStatus(bytes32)(uint8)" "$NOTE" --rpc-url "$RPC" | tr -d '[:space:]')
  [[ "$STATUS" == "2" ]] && validated=$((validated + 1))
done < "$REQ_FILE"
echo "Phase A: Validated deposits: $validated/$REQUEST_COUNT"
if [[ "$validated" -ne "$REQUEST_COUNT" ]]; then
  echo "ERROR: only $validated/$REQUEST_COUNT deposits Validated after register." >&2
  exit 1
fi

# Step 16: Phase B — poll all 4 confirmed roots until they all advance.
# The prover proves each tree independently; confirmTreeUpdate() is called per tree.
# 1800 s generous upper bound (single proof ≤ 420 s observed; 4 sequential ≤ 1680 s).
echo "Phase B: waiting for all 4 tree proofs to be confirmed..."
nc=0; nn=0; ac=0; an=0
deadline_b=$((SECONDS + 1800))
while (( SECONDS < deadline_b )); do
  CONF_NC=$(cast call "$BRIDGE" "confirmedNotesCommitmentRoot()(bytes32)" --rpc-url "$RPC" | tr -d '[:space:]')
  CONF_NN=$(cast call "$BRIDGE" "confirmedNotesNullifierRoot()(bytes32)" --rpc-url "$RPC" | tr -d '[:space:]')
  CONF_AC=$(cast call "$BRIDGE" "confirmedAccountsCommitmentRoot()(bytes32)" --rpc-url "$RPC" | tr -d '[:space:]')
  CONF_AN=$(cast call "$BRIDGE" "confirmedAccountsNullifierRoot()(bytes32)" --rpc-url "$RPC" | tr -d '[:space:]')
  nc=$([[ "$CONF_NC" != "$CONF_NC_BEFORE" ]] && echo 1 || echo 0)
  nn=$([[ "$CONF_NN" != "$CONF_NN_BEFORE" ]] && echo 1 || echo 0)
  ac=$([[ "$CONF_AC" != "$CONF_AC_BEFORE" ]] && echo 1 || echo 0)
  an=$([[ "$CONF_AN" != "$CONF_AN_BEFORE" ]] && echo 1 || echo 0)
  echo "Phase B confirmed: NC=$nc NN=$nn AC=$ac AN=$an"
  if [[ $nc -eq 1 && $nn -eq 1 && $ac -eq 1 && $an -eq 1 ]]; then
    echo "Phase B: all 4 tree proofs confirmed."
    break
  fi
  sleep 5
done
if [[ $((nc + nn + ac + an)) -lt 4 ]]; then
  echo "ERROR: timed out waiting for all 4 tree proofs to be confirmed." >&2
  exit 1
fi

# Step 17: Verify latest root changed (redundant sanity check; ROOT_AFTER set in Phase A).
if [[ "$ROOT_AFTER" == "$ROOT_BEFORE" ]]; then
  echo "ERROR: notesCommitmentRoot did not change after batch finalization." >&2
  exit 1
fi

# Step 18: Print success summary and artifact file locations.
echo ""
echo "E2E FLOW PASSED"
echo "BRIDGE=$BRIDGE"
echo "TOKEN=$TOKEN"
echo "TOY_USER=$TOY_USER"
echo "NOTES_FILE=$NOTES_FILE"
echo "REQ_FILE=$REQ_FILE"

# Step 19: Print all deposits for manual auditing (status + raw tuple).
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
    0) status_label="None" ;;
    1) status_label="Pending" ;;
    2) status_label="Validated" ;;
    3) status_label="Withdrawn" ;;
    *) status_label="Unknown($status)" ;;
  esac
  echo "note_index=$i note=$NOTE status=$status_label data=$dep"
done
