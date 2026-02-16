#!/usr/bin/env bash
set -euo pipefail

# Post a single leaf to a non-deposit tree endpoint.
#
# Usage:
#   scripts/local_request_leaf.sh /notes/nullifier 0x...
#   scripts/local_request_leaf.sh /accounts/commitment 0x...
#   scripts/local_request_leaf.sh /accounts/nullifier 0x...

ROOT_DIR="$(cd "$(dirname "${BASH_SOURCE[0]}")/.." && pwd)"
source "$ROOT_DIR/scripts/local_env.sh"

ENDPOINT="${1:-}"
LEAF="${2:-}"

if [[ -z "$ENDPOINT" || -z "$LEAF" ]]; then
  echo "Usage: $0 <endpoint> <0x-leaf>" >&2
  exit 1
fi

resp=$(curl -sS -X POST "$TESSERA_SEQUENCER_API_URL$ENDPOINT" \
  -H 'Content-Type: application/json' \
  -d "{\"leaf\":\"$LEAF\"}" || true)

echo "$resp"

