#!/usr/bin/env bash
set -euo pipefail

# Check the status of Tessera services for one or all groups.
#
# Usage:
#   ./services_status.sh --group <slug>
#   ./services_status.sh --all
#   ./services_status.sh             # same as --all

SCRIPT_DIR="$(cd "$(dirname "${BASH_SOURCE[0]}")" && pwd)"
LOG_DIR="$SCRIPT_DIR/logs"
GROUPS_DIR="$SCRIPT_DIR/groups"
GROUP=""
ALL=false

while [[ $# -gt 0 ]]; do
  case "$1" in
    --group) GROUP="$2"; shift 2 ;;
    --all)   ALL=true; shift ;;
    *) echo "Unknown argument: $1"; exit 1 ;;
  esac
done

if [[ -z "$GROUP" && "$ALL" == false ]]; then
  ALL=true
fi

# ── Print status from one PID file ───────────────────────────────────────────
status_pid_file() {
  local pid_file="$1"
  local log_dir
  log_dir="$(dirname "$pid_file")"
  local all_ok=true

  if [[ ! -f "$pid_file" ]]; then
    echo "  (no PID file — not started)"
    return
  fi

  while IFS='=' read -r name value; do
    [[ -z "$name" ]] && continue

    if [[ "$value" == docker:* ]]; then
      local container="${value#docker:}"
      if docker ps -q --filter "name=^${container}$" 2>/dev/null | grep -q .; then
        printf "  %-22s %-10s %s\n" "$name" "running" "container: $container"
      else
        printf "  %-22s %-10s %s\n" "$name" "STOPPED" "container: $container"
        all_ok=false
      fi
      continue
    fi

    local pid="$value"
    # Map service name to its actual log filename
    local log_name="$name"
    [[ "$name" =~ ^subpool-db-([0-9]+)$ ]] && log_name="db-${BASH_REMATCH[1]}"
    if kill -0 "$pid" 2>/dev/null; then
      printf "  %-22s %-10s %s\n" "$name" "running" "pid=$pid"
    else
      printf "  %-22s %-10s %s\n" "$name" "STOPPED" "pid=$pid  log: $log_dir/${log_name}.log"
      all_ok=false
    fi
  done < "$pid_file"

  if [[ "$all_ok" == true ]]; then
    echo "  → all running"
  else
    echo "  → some services STOPPED"
  fi
}

# ── Collect groups ────────────────────────────────────────────────────────────
DEMO_GROUPS=()
if [[ "$ALL" == true ]]; then
  for d in "$GROUPS_DIR"/*/; do
    [[ -d "$d" ]] && DEMO_GROUPS+=("$(basename "$d")")
  done
  if [[ ${#DEMO_GROUPS[@]} -eq 0 ]]; then
    echo "No groups found in $GROUPS_DIR"
    exit 0
  fi
else
  DEMO_GROUPS=("$GROUP")
fi

# ── Print status per group ────────────────────────────────────────────────────
overall_ok=true
for g in "${DEMO_GROUPS[@]}"; do
  echo ""
  echo "Group: $g"
  printf "  %-22s %-10s %s\n" "SERVICE" "STATUS" "DETAILS"
  printf "  %-22s %-10s %s\n" "-------" "------" "-------"
  pid_file="$LOG_DIR/$g/services.pid"
  if ! status_pid_file "$pid_file"; then
    overall_ok=false
  fi
done

echo ""
if [[ "$overall_ok" == true ]]; then
  echo "All services running."
else
  exit 1
fi
