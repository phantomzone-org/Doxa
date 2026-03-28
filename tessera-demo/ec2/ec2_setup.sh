#!/usr/bin/env bash
set -euo pipefail

# One-time setup for a fresh Ubuntu 22.04 EC2 instance.
# Run this once after launching the instance, before the first deploy.
#
# Usage:
#   DOMAIN=api.example.com EMAIL=you@example.com sudo -E ./ec2_setup.sh
#
# Must be run as root or with sudo.

DOMAIN="${DOMAIN:?Set DOMAIN to your fully-qualified domain name, e.g. api.example.com}"
EMAIL="${EMAIL:?Set EMAIL for Let's Encrypt renewal notices}"

echo "=== Installing Docker ==="
apt-get update -q
apt-get install -y ca-certificates curl

install -m 0755 -d /etc/apt/keyrings
curl -fsSL https://download.docker.com/linux/ubuntu/gpg -o /etc/apt/keyrings/docker.asc
chmod a+r /etc/apt/keyrings/docker.asc

echo \
  "deb [arch=$(dpkg --print-architecture) signed-by=/etc/apt/keyrings/docker.asc] \
  https://download.docker.com/linux/ubuntu \
  $(. /etc/os-release && echo "$VERSION_CODENAME") stable" \
  > /etc/apt/sources.list.d/docker.list

apt-get update -q
apt-get install -y docker-ce docker-ce-cli containerd.io docker-buildx-plugin docker-compose-plugin

systemctl enable --now docker

# Allow ubuntu user to run docker without sudo.
usermod -aG docker ubuntu
echo "  Docker installed. ubuntu added to docker group."
echo "  (Re-login or run 'newgrp docker' for group to take effect.)"

echo ""
echo "=== Obtaining Let's Encrypt certificate for $DOMAIN ==="
echo "  (Port 80 must be open in the EC2 security group.)"

# Use certbot via Docker — no host install needed.
docker run --rm \
  -p 80:80 \
  -v /etc/letsencrypt:/etc/letsencrypt \
  -v /var/lib/letsencrypt:/var/lib/letsencrypt \
  certbot/certbot certonly \
    --standalone \
    --non-interactive \
    --agree-tos \
    --email "$EMAIL" \
    -d "$DOMAIN"

echo "  Certificate issued at /etc/letsencrypt/live/$DOMAIN/"

echo ""
echo "=== Creating tessera directories ==="
mkdir -p /home/ubuntu/tessera
chown ubuntu:ubuntu /home/ubuntu/tessera

echo ""
echo "=== EC2 setup complete ==="
echo ""
echo "Next steps:"
echo "  1. Open EC2 security group inbound: TCP 80, 8081, 8082, 8083"
echo "  2. Run deploy.sh from your local machine:"
echo "       EC2_HOST=$DOMAIN EC2_KEY=~/.ssh/key.pem ./tessera-demo/ec2/deploy.sh"
echo "  3. Edit ~/tessera/.env on the instance with real secrets"
echo "     (deploy.sh copies .env.example on first run — then edit it)"
echo "  4. Re-run deploy.sh to restart with the correct secrets:"
echo "       EC2_HOST=$DOMAIN EC2_KEY=~/.ssh/key.pem ./tessera-demo/ec2/deploy.sh"
echo ""
echo "Health check after deploy:"
echo "  curl https://$DOMAIN:8081/status"
