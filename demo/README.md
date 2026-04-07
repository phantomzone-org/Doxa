# Demo depploy guide

## Setup an ec2 instance for frontend

- get an ec2 instance with elastic IP. Add A record for the elastic in the DNS dashboard for target *demo.tesseralabs.xyz
- make sure ports 80 and 443 are open (i.e. set inbound rules)
- setup the ec2 instance:
```
sudo apt update
sudo apt install -y nginx certbot python3-certbot-nginx
sudo systemctl enable --now nginx
```
- setup Letsencrypt TLS certificate:
```
sudo certbot certonly --manual --preferred-challenges dns \
  -d "*.demo.tesseralabs.xyz" \
  -d "demo.tesseralabs.xyz"
```
- Create web root
```
sudo mkdir -p /var/www
sudo chown -R ubuntu:ubuntu /var/www
```
- Creat nginx sites-enabled dir
```
sudo mkdir -p /etc/nginx/sites-enabled
# Make sure nginx includes it — check /etc/nginx/nginx.conf has:
# include /etc/nginx/sites-enabled/*;
grep "sites-enabled" /etc/nginx/nginx.conf
```

## Deploy frontend for a group

```
./build_and_deploy.sh --group {GROUP_NAME} --domain demo.tesseralabs.xyz --deploy --server {SERVER-NAME}
```

SERVE-NAME instance must be configured in ~/.ssh/config

## Add a new group

- create a folder with {GROUP_NAME} under demo/directory
