#!/usr/bin/env bash
set -euo pipefail

# Query SuperPiDebug event logs from the local Anvil node.
# Prints per-tree Keccak sub-hashes emitted by registerTransactionBatchUpdate.
# Compare against the prover INFO log "native Keccak preimage sub-hashes".

ROOT_DIR="$(cd "$(dirname "${BASH_SOURCE[0]}")/.." && pwd)"
source "$ROOT_DIR/scripts/local_env.sh"

SERVER_ENV="$ROOT_DIR/tessera-server/.env"
if [[ ! -f "$SERVER_ENV" ]]; then
  echo "ERROR: $SERVER_ENV not found" >&2
  exit 1
fi

BRIDGE=$(grep '^TESSERA_PENDING_DEPOSIT_BRIDGE_ADDRESS=' "$SERVER_ENV" | tail -1 | cut -d= -f2)
if [[ -z "${BRIDGE:-}" ]]; then
  echo "ERROR: TESSERA_PENDING_DEPOSIT_BRIDGE_ADDRESS not set in $SERVER_ENV" >&2
  exit 1
fi

echo "Bridge: $BRIDGE"
echo "RPC:    $RPC"
echo ""

LOGS=$(cast logs \
  --rpc-url "$RPC" \
  --from-block 0 \
  --address "$BRIDGE" \
  "SuperPiDebug(bytes32,bytes32,bytes32,bytes32,bytes32)" \
  --json 2>/dev/null)

if [[ -z "$LOGS" ]] || [[ "$LOGS" == "[]" ]]; then
  echo "No SuperPiDebug events found. Has registerTransactionBatchUpdate been called yet?"
  exit 0
fi

echo "$LOGS" | python3 -c "
import sys, json

logs = json.load(sys.stdin)
for i, log in enumerate(logs):
    data = log.get('data', '0x')
    # data is 5 x 32 bytes = 160 bytes = 320 hex chars (after 0x prefix)
    raw = data[2:] if data.startswith('0x') else data
    if len(raw) < 320:
        print(f'Event {i}: data too short ({len(raw)} hex chars)')
        continue
    nc   = '0x' + raw[0:64]
    nn   = '0x' + raw[64:128]
    ac   = '0x' + raw[128:192]
    an   = '0x' + raw[192:256]
    full = '0x' + raw[256:320]
    tx   = log.get('transactionHash', '?')
    print(f'Event {i} (tx {tx}):')
    print(f'  ncHash   = {nc}')
    print(f'  nnHash   = {nn}')
    print(f'  acHash   = {ac}')
    print(f'  anHash   = {an}')
    print(f'  fullHash = {full}')
    print()
"
