#!/usr/bin/env bash
# Start client-wallet + admin-dashboard dev servers for a demo group.
# Usage: ./start_demo_frontends.sh --group <group-slug>
# Example: ./start_demo_frontends.sh --group example
set -euo pipefail

SCRIPT_DIR="$(cd "$(dirname "$0")" && pwd)"
CW_DIR="$SCRIPT_DIR/client-wallet"
ADMIN_DIR="$SCRIPT_DIR/tessera-admin"
GROUP=""

# ── Parse args ────────────────────────────────────────────────────────────────
while [[ $# -gt 0 ]]; do
  case "$1" in
    --group) GROUP="$2"; shift 2 ;;
    *) echo "Unknown argument: $1"; exit 1 ;;
  esac
done

if [[ -z "$GROUP" ]]; then
  echo "Usage: $0 --group <group-slug>"
  echo "Available groups: $(ls "$SCRIPT_DIR/groups/")"
  exit 1
fi

GROUP_DIR="$SCRIPT_DIR/groups/$GROUP"
if [[ ! -d "$GROUP_DIR" ]]; then
  echo "Group '$GROUP' not found in $SCRIPT_DIR/groups/"
  exit 1
fi

command -v jq >/dev/null 2>&1 || { echo "Error: jq is required (brew install jq / apt install jq)"; exit 1; }

# ── Activate this group's institutions.json ───────────────────────────────────
cp "$GROUP_DIR/institutions.json" "$SCRIPT_DIR/institutions.json"
echo "Loaded institutions: $GROUP_DIR/institutions.json"

# ── Load group .env into environment ─────────────────────────────────────────
set -a
# shellcheck source=/dev/null
source "$GROUP_DIR/.env"
set +a

# ── Start servers ─────────────────────────────────────────────────────────────
PIDS=()

cleanup() {
  echo ""
  echo "Stopping all dev servers…"
  for pid in "${PIDS[@]:-}"; do
    kill "$pid" 2>/dev/null || true
  done
}
trap cleanup EXIT INT TERM

echo ""
echo "Group: $GROUP"
echo "━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━"

i=0
while IFS= read -r hex; do
  slug=$(jq -r --arg h "$hex" '.[$h].slug'     "$GROUP_DIR/ports.json")
  api_port=$(jq -r --arg h "$hex" '.[$h].api_port' "$GROUP_DIR/ports.json")
  wallet_port=$((5173 + i))
  admin_port=$((5180 + i))

  echo "  [$slug]  wallet :$wallet_port  admin :$admin_port  API :$api_port"

  (
    cd "$CW_DIR"
    VITE_SUBPOOL_ID_HEX="$hex" \
    VITE_API_BASE_URL="http://localhost:${api_port}" \
      npx vite --port "$wallet_port" --strictPort 2>&1 | sed "s/^/[wallet-${slug}] /"
  ) &
  PIDS+=($!)

  (
    cd "$ADMIN_DIR"
    VITE_SUBPOOL_ID_HEX="$hex" \
    VITE_API_BASE_URL="http://localhost:${api_port}" \
      npx vite --port "$admin_port" --strictPort 2>&1 | sed "s/^/[admin-${slug}]  /"
  ) &
  PIDS+=($!)

  i=$((i + 1))
done < <(jq -r 'keys[]' "$GROUP_DIR/ports.json")

echo "━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━"
echo "Press Ctrl+C to stop all servers."
echo ""

wait
