#!/usr/bin/env bash
set -euo pipefail

# Stop Tessera services for one or all groups.
#
# Usage:
#   ./services_stop.sh --group <slug>            # stop one group (keeps postgres)
#   ./services_stop.sh --all                     # stop all groups + postgres
#   ./services_stop.sh --all --keep-db           # stop all groups, keep postgres
#   ./services_stop.sh                           # same as --all

SCRIPT_DIR="$(cd "$(dirname "${BASH_SOURCE[0]}")" && pwd)"
LOG_DIR="$SCRIPT_DIR/logs"
GROUPS_DIR="$SCRIPT_DIR/groups"
GROUP=""
ALL=false
KEEP_DB=false

while [[ $# -gt 0 ]]; do
  case "$1" in
    --group)   GROUP="$2"; shift 2 ;;
    --all)     ALL=true; shift ;;
    --keep-db) KEEP_DB=true; shift ;;
    *) echo "Unknown argument: $1"; exit 1 ;;
  esac
done

if [[ -z "$GROUP" && "$ALL" == false ]]; then
  ALL=true
fi

# ── Stop processes from one PID file ─────────────────────────────────────────
stop_pid_file() {
  local pid_file="$1"
  local keep_db="$2"

  if [[ ! -f "$pid_file" ]]; then
    echo "  No PID file: $pid_file"
    return
  fi

  mapfile -t lines < "$pid_file"
  # Reverse for graceful shutdown order (operators → DBs → sequencer → postgres).
  local reversed=()
  for (( i=${#lines[@]}-1; i>=0; i-- )); do
    reversed+=("${lines[$i]}")
  done

  for entry in "${reversed[@]}"; do
    [[ -z "$entry" ]] && continue
    local name="${entry%%=*}"
    local value="${entry#*=}"

    if [[ "$value" == docker:* ]]; then
      local container="${value#docker:}"
      if [[ "$keep_db" == true ]]; then
        echo "  $name  (keeping — --keep-db)"
        continue
      fi
      if docker ps -q --filter "name=^${container}$" | grep -q .; then
        docker stop "$container" >/dev/null 2>&1 || true
        docker rm   "$container" >/dev/null 2>&1 || true
        echo "  $name  stopped (container: $container)"
      else
        echo "  $name  already stopped"
      fi
      continue
    fi

    local pid="$value"
    if kill -0 "$pid" 2>/dev/null; then
      kill "$pid" 2>/dev/null || true
      for _ in $(seq 1 50); do
        kill -0 "$pid" 2>/dev/null || break
        sleep 0.1
      done
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

  rm -f "$pid_file"
}

# ── Collect groups ────────────────────────────────────────────────────────────
DEMO_GROUPS=()
if [[ "$ALL" == true ]]; then
  for d in "$GROUPS_DIR"/*/; do
    [[ -d "$d" ]] && DEMO_GROUPS+=("$(basename "$d")")
  done
else
  DEMO_GROUPS=("$GROUP")
fi

# ── Stop each group ───────────────────────────────────────────────────────────
for g in "${DEMO_GROUPS[@]}"; do
  pid_file="$LOG_DIR/$g/services.pid"
  echo "Stopping group '$g' ..."
  # When stopping a single group, always keep the shared postgres container.
  # Only stop it when --all is used without --keep-db.
  if [[ "$ALL" == true ]]; then
    stop_pid_file "$pid_file" "$KEEP_DB"
  else
    stop_pid_file "$pid_file" true   # single group: never touch postgres
  fi
  echo ""
done

echo "Done."
