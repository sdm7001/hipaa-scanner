#!/bin/bash
# HIPAA Scanner Platform — Ubuntu 22.04 Server Setup
# Run as root on a fresh DigitalOcean droplet

set -euo pipefail

echo "=== HIPAA Scanner Platform — Server Setup ==="

# System updates
apt-get update && apt-get upgrade -y
apt-get install -y curl wget git build-essential software-properties-common ufw

# Python 3.11
add-apt-repository -y ppa:deadsnakes/ppa
apt-get install -y python3.11 python3.11-venv python3.11-dev python3-pip

# Node.js 20 (for frontend build)
curl -fsSL https://deb.nodesource.com/setup_20.x | bash -
apt-get install -y nodejs

# PostgreSQL 15
apt-get install -y postgresql-15 postgresql-client-15

# Nginx
apt-get install -y nginx

# WeasyPrint system deps
apt-get install -y libpango-1.0-0 libharfbuzz0b libpangoft2-1.0-0 libffi-dev

# Certbot for SSL
apt-get install -y certbot python3-certbot-nginx

# Create app user
useradd -m -s /bin/bash hipaa || true
mkdir -p /var/www/hipaa-scanner
chown hipaa:hipaa /var/www/hipaa-scanner

# PostgreSQL setup
sudo -u postgres psql -c "CREATE USER hipaa WITH PASSWORD 'CHANGE_ME_IN_SETUP';" || true
sudo -u postgres psql -c "CREATE DATABASE hipaa_scanner OWNER hipaa;" || true

# UFW firewall
ufw allow ssh
ufw allow 80/tcp
ufw allow 443/tcp
ufw --force enable

# Nginx config
cp /var/www/hipaa-scanner/deploy/nginx.conf /etc/nginx/sites-available/hipaa-scanner
ln -sf /etc/nginx/sites-available/hipaa-scanner /etc/nginx/sites-enabled/
rm -f /etc/nginx/sites-enabled/default
nginx -t && systemctl reload nginx

echo ""
echo "=== Setup Complete ==="
echo "Next steps:"
echo "1. Copy your .env file to /var/www/hipaa-scanner/backend/"
echo "2. Run: certbot --nginx -d hipaa.texmg.com"
echo "3. Deploy backend: cd backend && python3.11 -m venv venv && source venv/bin/activate && pip install -r requirements.txt"
echo "4. Run migrations: alembic upgrade head"
echo "5. Start API: uvicorn app.main:app --host 127.0.0.1 --port 8000 --workers 2"
echo "6. Build frontend: cd frontend && npm install && npm run build"
