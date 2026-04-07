# Tessera Demo

## Setup a fresh ec2 instance
- point api.tesseralabs.xyz -> IP of ec2
- run setup.sh script on the ec2 instance. Logout and login
- get TLS certificate:
```
sudo certbot certonly --nginx -d "api.tesseralabs.xyz"
```
- copy Tessera repo to ec2 instance:
```
# Copy the entire repo (or just the necessary parts)
  rsync -az --progress \
    --filter=':- .gitignore' \
    --exclude target \
    --exclude node_modules \
    /home/janmjaya/Desktop/Tessera/ \
    ubuntu@<backend-ip>:~/tessera/ 
```
- copy relevant environment files for backend to the ec2 instance
```
rsync -az --progress \
  /home/janmjaya/Desktop/Tessera/tessera-demo/scripts/services.env \
  ubuntu@<backend-ip>:~/tessera/tessera-demo/scripts/
  
rsync -az --progress \
  /home/janmjaya/Desktop/Tessera/tessera-demo/scripts/groups/ \
  ubuntu@<backend-ip>:~/tessera/tessera-demo/scripts/groups/
```
- setup nginx for all groups (i.e. /DEMO_GROUP/SLUG -> PORT)
```
sudo ./tessera-demo/scripts/deploy_backend_nginx.sh \
  --domain api.tesseralabs.xyz \
  --all \
  --local
```
- switch to rustup nightly. Then start services for all groups.
```
sudo ./services_start.sh --all
```


setup.sh:
```bash
# Update & install system packages
sudo apt update && sudo apt install -y \
  docker.io \
  nginx \
  certbot \
  python3-certbot-nginx \
  jq \
  psmisc \
  curl \
  build-essential

# Enable services
sudo systemctl enable --now docker
sudo systemctl enable --now nginx

# Add ubuntu user to docker group (avoids needing sudo for docker)
sudo usermod -aG docker ubuntu

# Install Rust (for building binaries)
curl --proto '=https' --tlsv1.2 -sSf https://sh.rustup.rs | sh -s -- -y
source "$HOME/.cargo/env"

# Allow passwordless sudo for deploy script commands
echo "ubuntu ALL=(ALL) NOPASSWD: /bin/mv, /usr/sbin/nginx, /bin/systemctl, /bin/mkdir, /bin/chown" \
  | sudo tee /etc/sudoers.d/tessera-deploy

# Log out and back in for docker group to take effect
```
