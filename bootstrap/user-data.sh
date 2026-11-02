#!/bin/bash
# EC2 first-boot script. Contains NO secrets: the app fetches them from Secrets Manager.
# Everything is echoed to the serial console, because this server has no SSH:
#   aws ec2 get-console-output --instance-id <id> --latest --output text
exec > >(tee /var/log/lab01-boot.log | logger -t lab01 -s 2>/dev/console) 2>&1
set -euxo pipefail
export DEBIAN_FRONTEND=noninteractive
apt-get update -y
apt-get install -y docker.io docker-compose-v2 git openssl
systemctl enable --now docker
# Cost safety net: terminate this instance automatically (shutdown behaviour = terminate)
shutdown -h +__SHUTDOWN_MIN__ "lab01 auto-shutdown" || true
git clone __REPO_URL__ /opt/nimbus
cd /opt/nimbus
# NETWORK: TLS for the console. Self signed certificate, key never leaves this server.
mkdir -p certs
IP="$(curl -s -H "X-aws-ec2-metadata-token: $(curl -s -X PUT http://169.254.169.254/latest/api/token -H 'X-aws-ec2-metadata-token-ttl-seconds: 60')" http://169.254.169.254/latest/meta-data/public-ipv4)"
openssl req -x509 -newkey rsa:2048 -nodes -days 3 -subj "/CN=$IP" -addext "subjectAltName=IP:$IP" -keyout certs/key.pem -out certs/cert.pem
chown 10001 certs/key.pem; chmod 600 certs/key.pem; chmod 644 certs/cert.pem
echo "SHA256 fingerprint: $(openssl x509 -in certs/cert.pem -noout -fingerprint -sha256)"
printf 'AWS_REGION=__REGION__\nNIMBUS_BUCKET=__BUCKET__\nWEB_PORT=8443\nWEB_TLS_ARGS=--certfile /certs/cert.pem --keyfile /certs/key.pem\nCOOKIE_SECURE=1\n' > .env
# LOGGING: the aws override file sends every container log to CloudWatch Logs group /lab01/app
docker compose -f docker-compose.yml -f docker-compose.aws.yml up -d --build
echo "lab01 ready"
