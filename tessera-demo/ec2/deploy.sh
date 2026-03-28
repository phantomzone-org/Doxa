#!/usr/bin/env bash
set -euo pipefail

# Sync source to EC2 and rebuild + restart all services there.
# No image registry needed — images are built directly on the instance.
#
# Prerequisites:
#   - ec2_setup.sh already run on the instance
#   - .env present on the instance (copied from .env.example, secrets filled in)
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

echo ""
echo "=== Syncing compose files ==="
rsync -avz -e "$SSH" \
  "$EC2_DIR/docker-compose.prod.yml" \
  "$EC2_DIR/nginx/" \
  "$REMOTE:~/tessera/"

# Copy .env.example only if .env does not yet exist on the server.
$SSH "$REMOTE" "test -f ~/tessera/.env" 2>/dev/null || \
  rsync -avz -e "$SSH" "$EC2_DIR/.env.example" "$REMOTE:~/tessera/.env"

echo ""
echo "=== Building and restarting on EC2 ==="
$SSH "$REMOTE" "
  cd ~/tessera
  docker compose -f docker-compose.prod.yml build
  docker compose -f docker-compose.prod.yml up -d
"

echo ""
echo "=== Deploy complete ==="
echo ""
echo "Status:       $SSH $REMOTE 'docker compose -f ~/tessera/docker-compose.prod.yml ps'"
echo "Health check: curl https://$EC2_HOST:8081/status"
