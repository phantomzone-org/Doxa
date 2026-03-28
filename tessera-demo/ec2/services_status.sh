#!/usr/bin/env bash
set -euo pipefail

# Check the status of all Tessera services.

SCRIPT_DIR="$(cd "$(dirname "${BASH_SOURCE[0]}")" && pwd)"
LOG_DIR="$SCRIPT_DIR/logs"
PID_FILE="$LOG_DIR/services.pid"

if [[ ! -f "$PID_FILE" ]]; then
  echo "No PID file found at $PID_FILE — no services tracked."
  exit 0
fi

printf "%-20s %-10s %s\n" "SERVICE" "STATUS" "DETAILS"
printf "%-20s %-10s %s\n" "-------" "------" "-------"

all_ok=true

while IFS='=' read -r name value; do
  [[ -z "$name" ]] && continue

  if [[ "$value" == docker:* ]]; then
    container="${value#docker:}"
    if docker ps -q --filter "name=^${container}$" 2>/dev/null | grep -q .; then
      printf "%-20s %-10s %s\n" "$name" "running" "container: $container"
    else
      printf "%-20s %-10s %s\n" "$name" "STOPPED" "container: $container"
      all_ok=false
    fi
    continue
  fi

  pid="$value"
  if kill -0 "$pid" 2>/dev/null; then
    printf "%-20s %-10s %s\n" "$name" "running" "pid=$pid"
  else
    printf "%-20s %-10s %s\n" "$name" "STOPPED" "pid=$pid (check $LOG_DIR/${name}.log)"
    all_ok=false
  fi
done < "$PID_FILE"

echo ""
if [[ "$all_ok" == true ]]; then
  echo "All services running."
else
  echo "Some services are stopped — check logs in $LOG_DIR/"
  exit 1
fi
