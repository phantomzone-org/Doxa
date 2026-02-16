#!/usr/bin/env bash
set -euo pipefail

# Submit one private-TX style request carrying:
# - input notes
# - output notes
# - input account commitment
# - output account commitment
# Args:
#   $1 input start note index   (default 1)
#   $2 input notes count        (default 2)
#   $3 output start note index  (default 1001)
#   $4 output notes count       (default 2)
#   $5 input account index      (default 5001)
#   $6 output account index     (default 6001)
#   $7 proof hex                (default 0x01, Phase A dummy)
#
# Endpoint:
#   POST /private-tx
#   {
#     "input_notes":["0x..","0x.."],
#     "output_notes":["0x..","0x.."],
#     "input_account_commitment":"0x..",
#     "output_account_commitment":"0x..",
#     "tx_proof":"0x..."
#   }

ROOT_DIR="$(cd "$(dirname "${BASH_SOURCE[0]}")/.." && pwd)"
source "$ROOT_DIR/scripts/local_env.sh"

IN_START="${1:-1}"
IN_COUNT="${2:-2}"
OUT_START="${3:-1001}"
OUT_COUNT="${4:-2}"
IN_ACCOUNT_INDEX="${5:-5001}"
OUT_ACCOUNT_INDEX="${6:-6001}"
INPUT_PROOF="${7:-0x01}"

TMP_IN="$(mktemp)"
IN_END=$((IN_START + IN_COUNT - 1))
for i in $(seq "$IN_START" "$IN_END"); do
  printf "\"0x%064x\"%s\n" "$i" "$( [[ "$i" -lt "$IN_END" ]] && echo "," )" >> "$TMP_IN"
done
IN_NOTES_JSON=$(tr -d '\n' < "$TMP_IN")
rm -f "$TMP_IN"

TMP_OUT="$(mktemp)"
OUT_END=$((OUT_START + OUT_COUNT - 1))
for i in $(seq "$OUT_START" "$OUT_END"); do
  printf "\"0x%064x\"%s\n" "$i" "$( [[ "$i" -lt "$OUT_END" ]] && echo "," )" >> "$TMP_OUT"
done
OUT_NOTES_JSON=$(tr -d '\n' < "$TMP_OUT")
rm -f "$TMP_OUT"

IN_ACCOUNT=$(printf "0x%064x" "$IN_ACCOUNT_INDEX")
OUT_ACCOUNT=$(printf "0x%064x" "$OUT_ACCOUNT_INDEX")

BODY="{\"input_notes\":[${IN_NOTES_JSON}],\"output_notes\":[${OUT_NOTES_JSON}],\"input_account_commitment\":\"${IN_ACCOUNT}\",\"output_account_commitment\":\"${OUT_ACCOUNT}\",\"tx_proof\":\"${INPUT_PROOF}\"}"
echo "Submitting private tx:"
echo "  input notes [$IN_START..$IN_END]"
echo "  output notes [$OUT_START..$OUT_END]"
echo "  input account $IN_ACCOUNT"
echo "  output account $OUT_ACCOUNT"
echo "  endpoint $TESSERA_SEQUENCER_API_URL/private-tx"
resp=$(curl -sS -X POST "$TESSERA_SEQUENCER_API_URL/private-tx" \
  -H 'content-type: application/json' \
  -d "$BODY")
echo "$resp"
