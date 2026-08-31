#!/usr/bin/env bash
set -euo pipefail

ROOT_DIR="$(cd "$(dirname "${BASH_SOURCE[0]}")/.." && pwd)"
cd "$ROOT_DIR/backend"

export DATABASE_URL="${DATABASE_URL:-sqlite:///./dogma_vpn.db}"
export ENABLE_BROWSER_DISCOVERY="${ENABLE_BROWSER_DISCOVERY:-false}"

exec python3 -m uvicorn app.main:app --host 0.0.0.0 --port "${PORT:-8090}"
