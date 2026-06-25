#!/usr/bin/env bash
# Compila el frontend y publica el build en el web root de Nginx (/var/www/soc-pnnc).
# Uso: sudo ./deploy-frontend.sh
set -euo pipefail

APP_DIR="$(cd "$(dirname "${BASH_SOURCE[0]}")" && pwd)"
WEBROOT="/var/www/soc-pnnc"

echo "==> Compilando frontend..."
cd "$APP_DIR/frontend"
npm run build

echo "==> Publicando en $WEBROOT ..."
sudo mkdir -p "$WEBROOT"
sudo rm -rf "${WEBROOT:?}"/*
sudo cp -r "$APP_DIR/frontend/dist/." "$WEBROOT/"
sudo chown -R www-data:www-data "$WEBROOT"

echo "==> Recargando Nginx..."
sudo nginx -t && sudo systemctl reload nginx
echo "✅ Frontend publicado en http://192.168.50.4"
