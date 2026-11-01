
#!/usr/bin/env bash
# ==============================================================================
# Stop & Remove Codechecker Production Containers
# ==============================================================================
set -e

SCRIPT_DIR="$(cd "$(dirname "${BASH_SOURCE[0]}")" && pwd)"

DOCKER_CMD="docker"
if ! docker ps >/dev/null 2>&1; then
  DOCKER_CMD="sudo docker"
fi

echo "Stopping Codechecker production containers..."

if $DOCKER_CMD compose version >/dev/null 2>&1; then
  $DOCKER_CMD compose -f "$SCRIPT_DIR/docker-compose.yml" down
elif command -v docker-compose >/dev/null 2>&1; then
  docker-compose -f "$SCRIPT_DIR/docker-compose.yml" down
else
  $DOCKER_CMD rm -f codechecker-ui codechecker-sast codechecker-sca codechecker-qdrant 2>/dev/null || true
fi

echo "✓ Codechecker production containers stopped."

