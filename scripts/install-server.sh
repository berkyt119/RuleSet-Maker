#!/usr/bin/env bash
set -euo pipefail

APP_DIR="/opt/dogma-vpn"
SRC_DIR="$(cd "$(dirname "${BASH_SOURCE[0]}")/.." && pwd)"

if ! command -v sudo >/dev/null 2>&1; then
  echo "sudo is required" >&2
  exit 1
fi

sudo apt-get update
sudo apt-get install -y ca-certificates curl gnupg nginx

if ! command -v docker >/dev/null 2>&1; then
  sudo install -m 0755 -d /etc/apt/keyrings
  curl -fsSL https://download.docker.com/linux/ubuntu/gpg | sudo gpg --dearmor -o /etc/apt/keyrings/docker.gpg
  sudo chmod a+r /etc/apt/keyrings/docker.gpg
  . /etc/os-release
  echo "deb [arch=$(dpkg --print-architecture) signed-by=/etc/apt/keyrings/docker.gpg] https://download.docker.com/linux/ubuntu ${VERSION_CODENAME} stable" | sudo tee /etc/apt/sources.list.d/docker.list >/dev/null
  sudo apt-get update
  sudo apt-get install -y docker-ce docker-ce-cli containerd.io docker-buildx-plugin docker-compose-plugin
fi

sudo mkdir -p "$APP_DIR" "$APP_DIR/data/files" "$APP_DIR/data/app" "$APP_DIR/exports"
sudo tar \
  --exclude='.git' \
  --exclude='frontend/node_modules' \
  --exclude='frontend/dist' \
  --exclude='backend/runtime' \
  --exclude='backend/*.db' \
  --exclude='data' \
  -C "$SRC_DIR" -cf - . | sudo tar -C "$APP_DIR" -xf -
sudo chown -R "$USER:$USER" "$APP_DIR"

cd "$APP_DIR"
if docker compose version >/dev/null 2>&1; then
  docker compose up -d --build
else
  docker-compose up -d --build
fi

sudo cp "$APP_DIR/nginx/dogma-vpn.conf" /etc/nginx/sites-available/dogma-vpn.conf
sudo ln -sf /etc/nginx/sites-available/dogma-vpn.conf /etc/nginx/sites-enabled/dogma-vpn.conf
sudo nginx -t
sudo systemctl reload nginx

echo "Dogma VPN is running on http://<server-ip>/"
echo "Ruleset file URL: http://<server-ip>/files/data.json"
