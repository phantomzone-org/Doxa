#!/usr/bin/env bash
set -euo pipefail

# Sync source to EC2, build binaries there, install nginx config, restart services.
#
# Prerequisites:
#   - ec2_setup.sh already run on the instance (installs Rust, nginx, certbot)
#   - services.prod.env present on the instance (copied from services.prod.env.example)
#
# Usage:
#   EC2_HOST=api.example.com EC2_KEY=~/.ssh/key.pem ./deploy.sh

EC2_HOST="${EC2_HOST:?Set EC2_HOST}"
EC2_KEY="${EC2_KEY:?Set EC2_KEY to your SSH private key path}"
EC2_USER="${EC2_USER:-ubuntu}"
REMOTE="$EC2_USER@$EC2_HOST"
SSH="ssh -i $EC2_KEY -o StrictHostKeyChecking=no"

ROOT="$(cd "$(dirname "${BASH_SOURCE[0]}")/../.." && pwd)"
EC2_DIR="$ROOT/tessera-demo/ec2"

echo "=== Syncing source to $REMOTE:~/tessera/src/ ==="
rsync -avz --delete \
  -e "$SSH" \
  --exclude='.git' \
  --exclude='target/' \
  --exclude='tessera-js/node_modules' \
  --exclude='tessera-js/wasm' \
  --exclude='demo/' \
  "$ROOT/" \
  "$REMOTE:~/tessera/src/"

# Copy services.prod.env.example only if services.prod.env does not yet exist.
$SSH "$REMOTE" "test -f ~/tessera/services.prod.env" 2>/dev/null || \
  rsync -avz -e "$SSH" "$EC2_DIR/services.prod.env.example" "$REMOTE:~/tessera/services.prod.env"

echo ""
echo "=== Building binaries on EC2 ==="
$SSH "$REMOTE" "
  cd ~/tessera/src
  CARGO_BUILD_JOBS=2 cargo build --release \
    -p tessera-demo \
    -p tessera-subpool-database \
    -p tessera-subpool-operator
  mkdir -p ~/tessera/bin
  cp target/release/demo-sequencer ~/tessera/bin/
  cp target/release/tessera-subpool-database ~/tessera/bin/
  cp target/release/tessera-subpool-operator ~/tessera/bin/
"

echo ""
echo "=== Installing nginx config ==="
$SSH "$REMOTE" "
  sudo sed 's/DOMAIN/$EC2_HOST/g' ~/tessera/src/tessera-demo/ec2/nginx/tessera.conf \
    | sudo tee /etc/nginx/sites-available/tessera > /dev/null
  sudo ln -sf /etc/nginx/sites-available/tessera /etc/nginx/sites-enabled/tessera
  sudo nginx -t
  sudo systemctl reload nginx 2>/dev/null || sudo systemctl start nginx
"

echo ""
echo "=== Restarting services ==="
$SSH "$REMOTE" "
  cd ~/tessera/src/tessera-demo/ec2
  ./services_stop.sh 2>/dev/null || true
  sleep 2
  ./services_start.sh ~/tessera/services.prod.env
"

echo ""
echo "=== Deploy complete ==="
echo ""
echo "Health check:"
echo "  curl https://$EC2_HOST:8081/status"
echo "  curl https://$EC2_HOST:8082/status"
echo "  curl https://$EC2_HOST:8083/status"
