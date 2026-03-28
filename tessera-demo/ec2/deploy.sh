#!/usr/bin/env bash
set -euo pipefail

# Build Docker images, push to ghcr.io, and deploy to EC2.
#
# Prerequisites:
#   - docker login ghcr.io (run once with a GitHub personal access token)
#   - ec2_setup.sh already run on the instance
#   - .env present on the instance (copied from .env.example, secrets filled in)
#
# Usage:
#   EC2_HOST=api.example.com EC2_KEY=~/.ssh/key.pem ./deploy.sh
#
# Optional overrides:
#   IMAGE_TAG=v1.2.3   — tag to build and deploy (default: latest)

EC2_HOST="${EC2_HOST:?Set EC2_HOST}"
EC2_KEY="${EC2_KEY:?Set EC2_KEY to your SSH private key path}"
EC2_USER="${EC2_USER:-ubuntu}"
IMAGE_TAG="${IMAGE_TAG:-latest}"
REMOTE="$EC2_USER@$EC2_HOST"
SSH="ssh -i $EC2_KEY -o StrictHostKeyChecking=no"

ROOT="$(cd "$(dirname "${BASH_SOURCE[0]}")/../.." && pwd)"
EC2_DIR="$ROOT/tessera-demo/ec2"

# Load IMAGE_REGISTRY from local .env (must exist alongside deploy.sh).
if [[ -f "$EC2_DIR/.env" ]]; then
  # shellcheck disable=SC1090
  source <(grep '^IMAGE_REGISTRY=' "$EC2_DIR/.env")
fi
IMAGE_REGISTRY="${IMAGE_REGISTRY:?Set IMAGE_REGISTRY in tessera-demo/ec2/.env}"

echo "=== Building images (tag: $IMAGE_TAG) ==="

# All three images are built from the repo root so COPY . . captures the full workspace.
docker build \
  --cache-from "$IMAGE_REGISTRY-sequencer:cache" \
  --cache-to   "type=inline" \
  -f "$EC2_DIR/docker/Dockerfile.sequencer" \
  -t "$IMAGE_REGISTRY-sequencer:$IMAGE_TAG" \
  "$ROOT"

docker build \
  --cache-from "$IMAGE_REGISTRY-subpool-db:cache" \
  --cache-to   "type=inline" \
  -f "$EC2_DIR/docker/Dockerfile.subpool-db" \
  -t "$IMAGE_REGISTRY-subpool-db:$IMAGE_TAG" \
  "$ROOT"

docker build \
  --cache-from "$IMAGE_REGISTRY-operator:cache" \
  --cache-to   "type=inline" \
  -f "$EC2_DIR/docker/Dockerfile.operator" \
  -t "$IMAGE_REGISTRY-operator:$IMAGE_TAG" \
  "$ROOT"

echo ""
echo "=== Pushing images to registry ==="
docker push "$IMAGE_REGISTRY-sequencer:$IMAGE_TAG"
docker push "$IMAGE_REGISTRY-subpool-db:$IMAGE_TAG"
docker push "$IMAGE_REGISTRY-operator:$IMAGE_TAG"

echo ""
echo "=== Syncing compose files to $REMOTE:~/tessera/ ==="
rsync -avz -e "$SSH" \
  "$EC2_DIR/docker-compose.prod.yml" \
  "$EC2_DIR/nginx/" \
  "$ROOT/docker/init-schemas.sql" \
  "$REMOTE:~/tessera/"

# Copy .env.example only if .env does not yet exist on the server.
$SSH "$REMOTE" "test -f ~/tessera/.env" 2>/dev/null || \
  rsync -avz -e "$SSH" "$EC2_DIR/.env.example" "$REMOTE:~/tessera/.env"

echo ""
echo "=== Deploying on EC2 ==="
$SSH "$REMOTE" "
  cd ~/tessera
  docker compose -f docker-compose.prod.yml pull
  docker compose -f docker-compose.prod.yml up -d
"

echo ""
echo "=== Deploy complete ==="
echo ""
echo "Status:       $SSH $REMOTE 'docker compose -f ~/tessera/docker-compose.prod.yml ps'"
echo "Health check: curl https://$EC2_HOST:8081/status"
