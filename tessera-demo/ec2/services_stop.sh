#!/usr/bin/env bash
set -euo pipefail

# Stop all Tessera services started by services_start.sh.
#
# Usage:
#   ./services_stop.sh             # stop everything including postgres
#   ./services_stop.sh --keep-db   # stop Rust processes, keep postgres

SCRIPT_DIR="$(cd "$(dirname "${BASH_SOURCE[0]}")" && pwd)"
LOG_DIR="$SCRIPT_DIR/logs"
PID_FILE="$LOG_DIR/services.pid"
KEEP_DB=false

for arg in "$@"; do
  case "$arg" in
    --keep-db) KEEP_DB=true ;;
  esac
done

if [[ ! -f "$PID_FILE" ]]; then
  echo "No PID file found at $PID_FILE — nothing to stop."
  exit 0
fi

echo "Stopping Tessera services ..."

# Read PIDs and stop in reverse order (operators -> DBs -> sequencer -> postgres).
mapfile -t lines < "$PID_FILE"

# Reverse the array for graceful shutdown ordering.
reversed=()
for (( i=${#lines[@]}-1; i>=0; i-- )); do
  reversed+=("${lines[$i]}")
done

for entry in "${reversed[@]}"; do
  name="${entry%%=*}"
  value="${entry#*=}"

  # Docker container.
  if [[ "$value" == docker:* ]]; then
    container="${value#docker:}"
    if [[ "$KEEP_DB" == true ]]; then
      echo "  $name  (keeping — --keep-db)"
      continue
    fi
    if docker ps -q --filter "name=^${container}$" | grep -q .; then
      docker stop "$container" >/dev/null 2>&1 || true
      docker rm "$container" >/dev/null 2>&1 || true
      echo "  $name  stopped (container: $container)"
    else
      echo "  $name  already stopped"
    fi
    continue
  fi

  # Regular process.
  pid="$value"
  if kill -0 "$pid" 2>/dev/null; then
    kill "$pid" 2>/dev/null || true
    # Wait up to 5s for graceful shutdown.
    for _ in $(seq 1 50); do
      kill -0 "$pid" 2>/dev/null || break
      sleep 0.1
    done
    # Force kill if still alive.
    if kill -0 "$pid" 2>/dev/null; then
      kill -9 "$pid" 2>/dev/null || true
      echo "  $name  killed (pid=$pid)"
    else
      echo "  $name  stopped (pid=$pid)"
    fi
  else
    echo "  $name  already stopped (pid=$pid)"
  fi
done

rm -f "$PID_FILE"
echo ""
echo "All services stopped."
