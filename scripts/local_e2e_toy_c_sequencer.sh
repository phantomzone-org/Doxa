#!/usr/bin/env bash
set -euo pipefail

# Console C: run sequencer for the latest deployed bridge.
# Args:
#   $1 optional env file path (default scripts/logs/tessera_e2e_latest.env)

ROOT_DIR="$(cd "$(dirname "${BASH_SOURCE[0]}")/.." && pwd)"
source "$ROOT_DIR/scripts/local_env.sh"

E2E_ENV="${1:-$ROOT_DIR/scripts/logs/tessera_e2e_latest.env}"
if [[ ! -f "$E2E_ENV" ]]; then
  echo "ERROR: missing env file: $E2E_ENV" >&2
  echo "Run scripts/local_e2e_toy_b_deploy.sh first." >&2
  exit 1
fi

# shellcheck disable=SC1090
source "$E2E_ENV"

if [[ -z "${BRIDGE:-}" ]]; then
  echo "ERROR: BRIDGE missing in $E2E_ENV" >&2
  exit 1
fi

BRIDGE="$BRIDGE" "$ROOT_DIR/scripts/local_run_sequencer.sh"
