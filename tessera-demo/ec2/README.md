# Tessera EC2 Deployment

## Overview

Everything runs in Docker containers managed by `docker-compose.prod.yml`.

```
Internet → EC2 :80  (nginx — ACME challenge only)
         → EC2 :8081/:8082/:8083 (nginx, HTTPS, Let's Encrypt cert)
                    ↓ proxy
           subpool-db-1:8080 / subpool-db-2:8080 / subpool-db-3:8080
           sequencer:3000
           postgres:5432
           operator-1 / operator-2 / operator-3  (internal, poll sequencer)
           certbot  (renewal loop, runs every 12 h)
```

Images are built directly on the EC2 instance from the rsynced source — no image registry needed.

---

## 1. AWS Console Configuration

### Launch the Instance

- **AMI**: Ubuntu 22.04 LTS (x86_64)
- **Instance type**: `t3.medium` or larger
- **Key pair**: create or select one — you'll need the `.pem` file locally

### Security Group — Inbound Rules

| Type       | Protocol | Port  | Source    | Purpose                               |
|------------|----------|-------|-----------|---------------------------------------|
| SSH        | TCP      | 22    | Your IP   | Remote access                         |
| HTTP       | TCP      | 80    | 0.0.0.0/0 | Let's Encrypt ACME challenge + renewal |
| Custom TCP | TCP      | 8081  | 0.0.0.0/0 | Subpool API — Entity A                |
| Custom TCP | TCP      | 8082  | 0.0.0.0/0 | Subpool API — Entity B                |
| Custom TCP | TCP      | 8083  | 0.0.0.0/0 | Subpool API — Entity C                |

### Elastic IP + DNS

1. Assign an **Elastic IP** to the instance (prevents the IP changing on reboot).
2. Create an **A record** in your DNS provider pointing your domain (e.g. `api.example.com`) to the Elastic IP.
3. Wait for DNS to propagate before running `ec2_setup.sh` — verify with `dig api.example.com`.

---

## 2. One-Time EC2 Setup

Run once on a fresh instance. Installs Docker and obtains the Let's Encrypt certificate.

```bash
ssh -i ~/.ssh/key.pem ubuntu@<EC2_IP>

# Clone or copy the repo, then:
DOMAIN=api.example.com EMAIL=you@example.com sudo -E ./tessera-demo/ec2/ec2_setup.sh
```

**What it does:**
- Installs Docker CE + the Compose plugin
- Adds `ubuntu` to the `docker` group
- Runs `certbot/certbot` as a Docker container (standalone, port 80) to issue the cert
- Cert is stored at `/etc/letsencrypt/live/api.example.com/` on the host and bind-mounted into the nginx and certbot containers

---

## 3. Configure Secrets

### On your local machine

```bash
cp tessera-demo/ec2/.env.example tessera-demo/ec2/.env
# Edit .env — fill in IMAGE_REGISTRY, DOMAIN, RPC_URL, keys, contract addresses
```

`deploy.sh` copies `.env.example` to `~/tessera/.env` on the instance on the first run. You can also SCP a pre-filled file:

```bash
scp -i ~/.ssh/key.pem tessera-demo/ec2/.env ubuntu@<EC2_IP>:~/tessera/.env
```

### Key variables

| Variable               | Description                                    |
|------------------------|------------------------------------------------|
| `DOMAIN`               | e.g. `api.example.com`                         |
| `RPC_URL`              | Sepolia Alchemy/Infura endpoint                |
| `BRIDGE_ADDRESS`       | Deployed Tessera contract address              |
| `TOKEN_ADDRESS`        | USDX ERC-20 contract address                   |
| `OPERATOR_KEY`         | Private key for sequencer / faucet             |
| `APPROVAL_PRIVATE_KEY` | Private key used by operators to approve txs   |

> `.env` is never overwritten by subsequent `deploy.sh` runs once it exists on the instance.

---

## 4. Deploy (from your local machine)

```bash
EC2_HOST=api.example.com EC2_KEY=~/.ssh/key.pem ./tessera-demo/ec2/deploy.sh
```

**What it does:**
1. Rsyncs the entire repo source to `~/tessera/src/` on the EC2 instance (excludes `.git`, `target/`, `node_modules`, `wasm`)
2. Rsyncs `docker-compose.prod.yml` and `nginx/` to `~/tessera/`
3. Copies `.env.example` → `~/tessera/.env` only on the first run (never overwrites)
4. SSHs in and runs `docker compose build && docker compose up -d` — images are built directly on EC2

Subsequent deploys are the same command — postgres data is preserved in the `tessera_postgres-data` named volume.

---

## 5. Restart

### Restart all services, keep existing database

```bash
# On EC2
cd ~/tessera
docker compose -f docker-compose.prod.yml restart
```

Or rebuild and recreate (after a new `deploy.sh` run has rsynced updated source):

```bash
docker compose -f docker-compose.prod.yml build
docker compose -f docker-compose.prod.yml up -d
```

### Full restart with a fresh database

**Warning: this wipes all data.**

```bash
# On EC2
cd ~/tessera
docker compose -f docker-compose.prod.yml down -v   # -v removes named volumes
docker compose -f docker-compose.prod.yml up -d
```

---

## 6. Stop

```bash
# On EC2 — stop all containers (data preserved in volumes)
cd ~/tessera
docker compose -f docker-compose.prod.yml down

# Stop and remove all data
docker compose -f docker-compose.prod.yml down -v
```

---

## 7. Status

```bash
# On EC2
docker compose -f ~/tessera/docker-compose.prod.yml ps
```

Example output:
```
NAME                  IMAGE                   STATUS          PORTS
tessera-postgres-1    postgres:16             Up (healthy)    5432/tcp
tessera-sequencer-1   tessera-sequencer       Up              3000/tcp
tessera-subpool-db-1  tessera-subpool-db-1    Up              8080/tcp
tessera-subpool-db-2  tessera-subpool-db-2    Up              8080/tcp
tessera-subpool-db-3  tessera-subpool-db-3    Up              8080/tcp
tessera-operator-1    tessera-operator-1      Up
tessera-operator-2    tessera-operator-2      Up
tessera-operator-3    tessera-operator-3      Up
tessera-nginx-1       nginx:alpine            Up              0.0.0.0:80->80/tcp, ...
tessera-certbot-1     certbot/certbot         Up
```

---

## 8. Logs

```bash
# All containers
docker compose -f ~/tessera/docker-compose.prod.yml logs -f

# Specific service
docker compose -f ~/tessera/docker-compose.prod.yml logs -f sequencer
docker compose -f ~/tessera/docker-compose.prod.yml logs -f subpool-db-1
docker compose -f ~/tessera/docker-compose.prod.yml logs -f nginx
```

---

## 9. Health Check

```bash
curl https://api.example.com:8081/status   # → 200 OK
curl https://api.example.com:8082/status
curl https://api.example.com:8083/status
```

---

## 10. TLS Certificate Renewal

Renewal is automatic. The `certbot` container checks every 12 hours and renews when fewer than 30 days remain. After renewal, nginx picks up the updated cert on the next request (Let's Encrypt certs are read from disk on each TLS handshake by nginx).

To force an immediate renewal:

```bash
# On EC2
docker compose -f ~/tessera/docker-compose.prod.yml run --rm certbot renew --force-renewal --webroot -w /var/www/certbot
docker compose -f ~/tessera/docker-compose.prod.yml restart nginx
```

To test renewal without issuing a cert:

```bash
docker compose -f ~/tessera/docker-compose.prod.yml run --rm certbot renew --dry-run --webroot -w /var/www/certbot
```

---

## File Reference

| File | Purpose |
|------|---------|
| `deploy.sh` | Run locally — rsyncs source to EC2, builds images there, restarts services |
| `ec2_setup.sh` | Run once on EC2 — installs Docker, obtains Let's Encrypt cert |
| `.env.example` | Environment variable template — copy to `.env` and fill in secrets |
| `docker-compose.prod.yml` | Defines all services (postgres, sequencer, APIs, operators, nginx, certbot) |
| `docker/Dockerfile.sequencer` | Sequencer image (corrected binary name: `demo-sequencer`) |
| `docker/Dockerfile.subpool-db` | Subpool database API image |
| `docker/Dockerfile.operator` | Subpool operator image |
| `nginx/tessera.conf.template` | nginx config template — `${DOMAIN}` substituted by nginx:alpine at start |
