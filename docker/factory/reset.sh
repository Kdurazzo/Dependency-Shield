#!/bin/bash
#
# reset.sh - Reset DepShield docker environment to factory defaults
#
# This script stops active DepShield Docker containers, purges runtime
# state (logs, generated audit reports, temporary cached data), and restores
# the factory-default Docker configuration files.

set -e

SCRIPT_DIR="$(cd "$(dirname "$0")" && pwd)"
DOCKER_DIR="$(cd "$SCRIPT_DIR/.." && pwd)"
FACTORY_DIR="$SCRIPT_DIR"
REPO_DIR="$(cd "$DOCKER_DIR/.." && pwd)"

echo ""
echo "=========================================================="
echo "  DepShield - Reset to Factory Defaults"
echo "=========================================================="
echo ""
echo "WARNING: This is a DESTRUCTIVE action. The following will"
echo "be permanently deleted / reset:"
echo ""
echo "  - Running DepShield containers (backend, dashboard, mcp)"
echo "  - Generated audit reports in docker/reports/"
echo "  - Runtime logs in docker/logs/ (backend, dashboard, mcp)"
echo "  - Persisted cache / data in docker/data/"
echo "  - Docker configuration changes to compose.yaml"
echo "  - Docker configuration changes to depshield.json and depshield-mcp.json"
echo "  - Docker configuration changes to nginx/nginx.conf"
echo "  - Environment file docker/.env (reset to .env.example)"
echo ""
echo "DepShield Docker configuration"
echo "will be restored to factory defaults."
echo ""
read -r -p "Type 'RESET' to confirm: " CONFIRM
echo ""

if [ "$CONFIRM" != "RESET" ]; then
  echo "Aborted. No changes were made."
  exit 1
fi

echo "[1/4] Stopping containers..."
cd "$DOCKER_DIR"
docker compose down --remove-orphans 2>/dev/null || true

echo "[2/4] Restoring factory configurations..."
cp "$FACTORY_DIR/compose.yaml" "$DOCKER_DIR/compose.yaml"
cp "$FACTORY_DIR/depshield.json" "$DOCKER_DIR/depshield.json"
cp "$FACTORY_DIR/depshield-mcp.json" "$DOCKER_DIR/depshield-mcp.json"
cp "$FACTORY_DIR/.env.example" "$DOCKER_DIR/.env.example"
cp "$FACTORY_DIR/.env.example" "$DOCKER_DIR/.env"
mkdir -p "$DOCKER_DIR/nginx"
cp "$FACTORY_DIR/nginx/nginx.conf" "$DOCKER_DIR/nginx/nginx.conf"
echo "        Restored compose.yaml, depshield.json, depshield-mcp.json, .env, and nginx.conf"

echo "[3/4] Resetting runtime directories..."
rm -rf "$DOCKER_DIR/logs" "$DOCKER_DIR/reports" "$DOCKER_DIR/data"
mkdir -p "$DOCKER_DIR/logs/backend" "$DOCKER_DIR/logs/dashboard" "$DOCKER_DIR/logs/mcp"
mkdir -p "$DOCKER_DIR/reports" "$DOCKER_DIR/data"
touch "$DOCKER_DIR/logs/backend/.gitkeep" "$DOCKER_DIR/logs/dashboard/.gitkeep" "$DOCKER_DIR/logs/mcp/.gitkeep"
touch "$DOCKER_DIR/reports/.gitkeep" "$DOCKER_DIR/data/.gitkeep"
echo "        Cleared runtime logs, reports, and data directories"

echo "[4/4] Factory reset complete."
echo ""
echo "To start the clean environment:"
echo "  cd $DOCKER_DIR"
echo "  docker compose up -d"
echo ""
