#!/usr/bin/env bash
# Generate and optionally deploy backend nginx config for tessera-demo groups.
#
# Uses path-based routing on port 443 — only ports 22 and 443 need to be open.
# API URL scheme:  https://<domain>/<group>/<slug>/  →  localhost:<api-port>
#
# The main server block (/etc/nginx/sites-enabled/tessera-backend.conf) includes
# per-group location files from /etc/nginx/tessera-locations/<group>.conf.
# Running this script for multiple groups is safe — each group gets its own
# locations file and the main block is only written once.
#
# Usage:
#   ./deploy_backend_nginx.sh --domain <domain> [--group <slug> | --all] [--server <user@host>]
#
# Examples:
#   ./deploy_backend_nginx.sh --domain demo.tesseralabs.xyz --all
#   ./deploy_backend_nginx.sh --domain demo.tesseralabs.xyz --group example --server ubuntu@1.2.3.4
#
# DNS required:
#   <domain>  →  backend EC2 IP

set -euo pipefail

SCRIPT_DIR="$(cd "$(dirname "${BASH_SOURCE[0]}")" && pwd)"
ROOT_DIR="$(cd "$SCRIPT_DIR/../.." && pwd)"
DEMO_GROUPS_DIR="$SCRIPT_DIR/groups"
DEMO_INST_DIR="$ROOT_DIR/demo/groups"
BUILD_DIR="$SCRIPT_DIR/logs/nginx-build"

DOMAIN=""
SERVER=""
DEMO_GROUP=""
ALL=false
LOCAL=false

# ── Parse args ────────────────────────────────────────────────────────────────
while [[ $# -gt 0 ]]; do
  case "$1" in
    --domain)  DOMAIN="$2";      shift 2 ;;
    --server)  SERVER="$2";      shift 2 ;;
    --group)   DEMO_GROUP="$2";  shift 2 ;;
    --all)     ALL=true;         shift ;;
    --local)   LOCAL=true;       shift ;;
    *) echo "Unknown argument: $1"; exit 1 ;;
  esac
done

if [[ -z "$DOMAIN" ]]; then
  echo "Usage: $0 --domain <domain> [--group <slug> | --all] [--server <user@host>] [--local]"
  exit 1
fi

if [[ -z "$DEMO_GROUP" && "$ALL" == false ]]; then
  ALL=true
fi

API_DOMAIN="${DOMAIN}"

# ── Collect groups ────────────────────────────────────────────────────────────
DEMO_GROUPS=()
if [[ "$ALL" == true ]]; then
  for d in "$DEMO_GROUPS_DIR"/*/; do
    [[ -d "$d" ]] && DEMO_GROUPS+=("$(basename "$d")")
  done
  [[ ${#DEMO_GROUPS[@]} -gt 0 ]] || { echo "ERROR: no groups found in $DEMO_GROUPS_DIR"; exit 1; }
else
  [[ -d "$DEMO_GROUPS_DIR/$DEMO_GROUP" ]] || { echo "ERROR: group '$DEMO_GROUP' not found"; exit 1; }
  DEMO_GROUPS=("$DEMO_GROUP")
fi

mkdir -p "$BUILD_DIR"

# ── Generate per-group location files ────────────────────────────────────────
ALL_LOCATION_FILES=()

for group in "${DEMO_GROUPS[@]}"; do
  group_env="$DEMO_GROUPS_DIR/$group/group.env"
  inst_json="$DEMO_INST_DIR/$group/institutions.json"

  [[ -f "$group_env" ]] || { echo "ERROR: $group_env not found"; exit 1; }
  [[ -f "$inst_json" ]] || { echo "ERROR: $inst_json not found"; exit 1; }

  # Load ports
  # shellcheck source=/dev/null
  source "$group_env"

  LOCATION_BLOCKS=""
  i=1
  while IFS= read -r hex; do
    slug=$(jq -r --arg h "$hex" '.[$h].slug' "$inst_json")
    port_var="DB_API_PORT_${i}"
    port="${!port_var}"

    LOCATION_BLOCKS+="
    # ${group} / ${slug} → localhost:${port}
    location /${group}/${slug}/ {
        proxy_pass         http://127.0.0.1:${port}/;
        proxy_set_header   Host \$host;
        proxy_set_header   X-Real-IP \$remote_addr;
    }
"
    i=$((i + 1))
  done < <(jq -r 'keys[]' "$inst_json")

  locations_file="$BUILD_DIR/${group}.locations.conf"
  cat > "$locations_file" <<EOF
# Auto-generated — backend nginx locations for group: ${group}
# Included by /etc/nginx/sites-enabled/tessera-backend.conf
${LOCATION_BLOCKS}
EOF

  ALL_LOCATION_FILES+=("$locations_file")
  echo "Generated: $locations_file"
done

# ── Generate main server block ────────────────────────────────────────────────
MAIN_CONF="$BUILD_DIR/tessera-backend.conf"
cat > "$MAIN_CONF" <<EOF
# Tessera backend nginx — main server block.
# Deploy to /etc/nginx/sites-enabled/tessera-backend.conf (once).
# Per-group location blocks live in /etc/nginx/tessera-locations/*.conf.

server {
    listen 443 ssl;
    server_name ${API_DOMAIN};
    ssl_certificate     /etc/letsencrypt/live/${API_DOMAIN}/fullchain.pem;
    ssl_certificate_key /etc/letsencrypt/live/${API_DOMAIN}/privkey.pem;
    include /etc/nginx/tessera-locations/*.conf;
}

server {
    listen 80;
    server_name ${API_DOMAIN};
    return 301 https://\$host\$request_uri;
}
EOF

echo "Generated: $MAIN_CONF"
echo ""

if [[ "$LOCAL" == true ]]; then
  # ── Deploy locally ───────────────────────────────────────────────────────────
  echo "Installing locally…"
  sudo mkdir -p /etc/nginx/tessera-locations
  for f in "${ALL_LOCATION_FILES[@]}"; do
    g="$(basename "$f" .locations.conf)"
    echo "  Installing locations for group '${g}'…"
    sudo cp "$f" "/etc/nginx/tessera-locations/${g}.conf"
  done
  echo "  Installing main server block…"
  sudo cp "$MAIN_CONF" /etc/nginx/sites-enabled/tessera-backend.conf
  sudo nginx -t && sudo systemctl reload nginx

elif [[ -n "$SERVER" ]]; then
  # ── Deploy remotely ──────────────────────────────────────────────────────────
  echo "Deploying to ${SERVER}…"
  ssh "$SERVER" "sudo mkdir -p /etc/nginx/tessera-locations"
  for f in "${ALL_LOCATION_FILES[@]}"; do
    g="$(basename "$f" .locations.conf)"
    echo "  Uploading locations for group '${g}'…"
    scp "$f" "${SERVER}:/tmp/${g}.locations.conf"
    ssh "$SERVER" "sudo mv /tmp/${g}.locations.conf /etc/nginx/tessera-locations/${g}.conf"
  done
  echo "  Uploading main server block…"
  scp "$MAIN_CONF" "${SERVER}:/tmp/tessera-backend.conf"
  ssh "$SERVER" "sudo mv /tmp/tessera-backend.conf /etc/nginx/sites-enabled/tessera-backend.conf"
  ssh "$SERVER" "sudo nginx -t && sudo systemctl reload nginx"

else
  echo "Skipping deploy (pass --local to install on this machine, or --server <user@host> to deploy remotely)."
  exit 0
fi

echo ""
echo "━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━"
echo "Backend nginx deployed. API routes:"
for group in "${DEMO_GROUPS[@]}"; do
  inst_json="$DEMO_INST_DIR/$group/institutions.json"
  while IFS= read -r hex; do
    slug=$(jq -r --arg h "$hex" '.[$h].slug' "$inst_json")
    echo "  https://${API_DOMAIN}/${group}/${slug}/"
  done < <(jq -r 'keys[]' "$inst_json")
done
echo ""
echo "DNS:  ${API_DOMAIN}  →  backend EC2 IP"
echo "TLS:  certbot certonly --dns-<provider> -d \"${API_DOMAIN}\""
echo "━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━"
