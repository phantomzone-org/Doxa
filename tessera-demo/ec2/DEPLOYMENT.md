# Tessera Demo — EC2 Deployment Report

## Architecture

```
Internet → EC2 :8081 / :8082 / :8083  (nginx, HTTPS, Let's Encrypt)
                      ↓ proxy
           127.0.0.1:9081 / :9082 / :9083  (tessera-subpool-database × 3)
           127.0.0.1:3000                   (demo-sequencer)
           tessera-subpool-operator × 3     (internal, poll sequencer)
           tessera-postgres (Docker)        (PostgreSQL 16)
```

Binaries run directly on the host. PostgreSQL runs in a Docker container. nginx terminates TLS and reverse-proxies to the internal ports.

---

## 1. AWS Account Setup

### 1.1 Key Pair

1. Go to **EC2 → Key Pairs → Create key pair**
   - Name: `tessera-demo`
   - Type: RSA, Format: `.pem`
2. Move and lock the downloaded file:
   ```bash
   mv ~/Downloads/tessera-demo-key.pem ~/.ssh/tessera-demo-key.pem
   chmod 400 ~/.ssh/tessera-demo-key.pem
   ```

### 1.2 Security Group

Created `tessera-demo` with the following inbound rules:

| Type       | Port | Source    | Purpose                     |
|------------|------|-----------|-----------------------------|
| SSH        | 22   | My IP     | Remote access               |
| HTTP       | 80   | 0.0.0.0/0 | Let's Encrypt ACME          |
| Custom TCP | 8081 | 0.0.0.0/0 | Subpool API — Entity A      |
| Custom TCP | 8082 | 0.0.0.0/0 | Subpool API — Entity B      |
| Custom TCP | 8083 | 0.0.0.0/0 | Subpool API — Entity C      |

SSH source set to `0.0.0.0/0` to handle a dynamic IP.

### 1.3 EC2 Instance

- **AMI**: Ubuntu 22.04 LTS (x86_64)
- **Instance type**: `t3.medium` (2 vCPU, 8 GB RAM)
- **Storage**: 128 GB gp3 (increased from default 30 GB — see bug §6.3)
- **Key pair**: `tessera-demo`
- **Security group**: `tessera-demo`

### 1.4 Elastic IP

1. **EC2 → Elastic IPs → Allocate**
2. **Actions → Associate** → select `tessera-demo` instance
3. Noted the public IP (e.g. `13.50.206.39`)

---

## 2. DNS Setup (GoDaddy)

Domain `tesseralabs.xyz` was already registered on GoDaddy.

1. Logged into GoDaddy → **DNS** for `tesseralabs.xyz`
2. Added an **A record**:
   - Name: `api`
   - Value: Elastic IP (`13.50.206.39`)
   - TTL: 600
3. Verified propagation:
   ```bash
   dig api.tesseralabs.xyz @ns35.domaincontrol.com
   # Then via public resolver:
   dig api.tesseralabs.xyz @8.8.8.8
   ```

---

## 3. One-Time EC2 Setup

### 3.1 Copy and run `ec2_setup.sh`

`ec2_setup.sh` installs Docker and obtains the Let's Encrypt TLS certificate.

```bash
scp -i ~/.ssh/tessera-demo-key.pem tessera-demo/ec2/ec2_setup.sh ubuntu@api.tesseralabs.xyz:~/ec2_setup.sh
ssh -i ~/.ssh/tessera-demo-key.pem ubuntu@api.tesseralabs.xyz
DOMAIN=api.tesseralabs.xyz EMAIL=you@example.com sudo -E ./ec2_setup.sh
```

**Bug — shell syntax error in `ec2_setup.sh`:**
The script failed with `unexpected EOF while looking for matching '"'`. Root cause: nested double-quotes inside `$()` inside a double-quoted string in the `echo` command that writes the Docker apt repo. Fixed by pre-expanding the variables:

```bash
# Before (broken):
echo "deb [...] $(. /etc/os-release && echo "$VERSION_CODENAME") stable" > ...

# After (fixed):
ARCH=$(dpkg --print-architecture)
. /etc/os-release
echo "deb [arch=${ARCH} ...] ${VERSION_CODENAME} stable" > ...
```

### 3.2 Extend the root filesystem

The EBS volume was increased to 128 GB in the AWS console but the partition was not automatically extended:

```bash
sudo growpart /dev/nvme0n1 1
sudo resize2fs /dev/nvme0n1p1
df -h /   # verify ~128 GB available
```

### 3.3 Add swap

To prevent OOM kills during Rust compilation:

```bash
sudo fallocate -l 4G /swapfile
sudo chmod 600 /swapfile
sudo mkswap /swapfile
sudo swapon /swapfile
```

---

## 4. Building the Binaries

Built directly on EC2 to avoid cross-compilation and image registry overhead.

```bash
cd ~/tessera/src
CARGO_BUILD_JOBS=2 cargo build --release \
  -p tessera-demo \
  -p tessera-subpool-database \
  -p tessera-subpool-operator
mkdir -p ~/tessera/bin
cp target/release/demo-sequencer ~/tessera/bin/
cp target/release/tessera-subpool-database ~/tessera/bin/
cp target/release/tessera-subpool-operator ~/tessera/bin/
```

`CARGO_BUILD_JOBS=2` limits parallelism to avoid RAM exhaustion during compilation.

### Bugs encountered during build

**Bug — Rust version too old (`edition2024` not supported):**
The Rust toolchain on the instance was 1.83; `tessera-client` requires edition 2024 (stabilised in 1.85+). Fixed by installing the nightly toolchain via `rustup`.

**Bug — Go FFI compiled unconditionally:**
`tessera-utils/build.rs` invoked `go build` unconditionally, but none of the three demo binaries use the Groth16/BN128 proving pipeline. Fixed by introducing a `groth` cargo feature in `tessera-utils` and `tessera-server`:

- `build.rs` is now a no-op unless `--features groth` is passed
- `pub mod groth` in `tessera-utils/src/lib.rs` is gated with `#[cfg(feature = "groth")]`
- All groth-dependent code in `tessera-server` (`bn128_wrapper_service`, `store_artifacts`, `from_artifacts`, aggregator runtime) is gated with `#[cfg(feature = "groth")]`

This removed the Go and libclang build-time requirements for the demo binaries.

---

## 5. nginx Reverse Proxy

nginx is installed on the host and terminates TLS on ports 8081–8083, proxying to the binaries on internal ports 9081–9083.

### 5.1 Install nginx

```bash
sudo apt-get install -y nginx
```

### 5.2 Install the config

```bash
sudo sed 's/DOMAIN/api.tesseralabs.xyz/g' \
  ~/tessera/src/tessera-demo/ec2/nginx/tessera.conf \
  | sudo tee /etc/nginx/sites-available/tessera
sudo ln -sf /etc/nginx/sites-available/tessera /etc/nginx/sites-enabled/tessera
sudo nginx -t
sudo systemctl start nginx
```

The config (`tessera-demo/ec2/nginx/tessera.conf`) proxies:

| Public port (HTTPS) | Internal port |
|---------------------|---------------|
| 8081                | 9081          |
| 8082                | 9082          |
| 8083                | 9083          |

TLS certificates are at `/etc/letsencrypt/live/api.tesseralabs.xyz/` (issued by `ec2_setup.sh`).

**Bug — nginx could not bind ports 8081–8083:**
The old binaries were still running on those ports from a previous manual deployment (`/home/ubuntu/Tessera/target/release/tessera-subpool-database`). Fixed by killing those processes and restarting the services with the new internal ports (9081–9083).

**Bug — nginx proxying to wrong port (18081 instead of 9081):**
The old `tessera.conf` file on the instance still referenced port 18081. Fixed by re-running the `sed` substitution above to overwrite `/etc/nginx/sites-available/tessera` and reloading nginx.

---

## 6. Starting the Services

### 6.1 Configure secrets

```bash
# Copy the template (already done via scp from local machine):
nano ~/tessera/services.prod.env
```

Fill in:
```
DOMAIN=api.tesseralabs.xyz
RPC_URL=https://eth-sepolia.g.alchemy.com/v2/<ALCHEMY_KEY>
BRIDGE_ADDRESS=<CONTRACT_ADDR>
TOKEN_ADDRESS=<USDX_ADDR>
OPERATOR_KEY=<0x_PRIVATE_KEY>
APPROVAL_PRIVATE_KEY=<0x_PRIVATE_KEY>
```

Internal ports are pre-set in the template:
```
DB_API_BIND_HOST=127.0.0.1
DB_API_PORT_1=9081
DB_API_PORT_2=9082
DB_API_PORT_3=9083
```

### 6.2 Start

```bash
cd ~/tessera/src/tessera-demo/ec2
./services_start.sh ~/tessera/services.prod.env
```

### 6.3 Stop / Restart (without touching the database)

```bash
./services_stop.sh --keep-db
./services_start.sh ~/tessera/services.prod.env
```

---

## 7. Health Check

```bash
curl https://api.tesseralabs.xyz:8081/status   # → 200 OK
curl https://api.tesseralabs.xyz:8082/status   # → 200 OK
curl https://api.tesseralabs.xyz:8083/status   # → 200 OK
```

---

## 8. Re-deploying After Code Changes

From your local machine:

```bash
EC2_HOST=api.tesseralabs.xyz EC2_KEY=~/.ssh/tessera-demo-key.pem \
  ./tessera-demo/ec2/deploy.sh
```

`deploy.sh` will:
1. Rsync the source to `~/tessera/src/`
2. Build the three binaries on EC2
3. Copy them to `~/tessera/bin/`
4. Reinstall the nginx config
5. Stop and restart all services

The `services.prod.env` on the instance is never overwritten by `deploy.sh`.
