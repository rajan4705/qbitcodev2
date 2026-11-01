#!/usr/bin/env bash
# ==============================================================================
# Complete Environment Cleanup
#   1. Stops and removes all Codechecker containers (prod & test)
#   2. Removes Codechecker networks
#   3. Frees host ports (6333, 6334, 8080, 8082)
#   4. Deletes all Codechecker Docker images & purges builder cache
#   5. Reports reclaimed disk space
# ==============================================================================
set -e

SCRIPT_DIR="$(cd "$(dirname "${BASH_SOURCE[0]}")" && pwd)"
WORKSPACE_ROOT="$(cd "$SCRIPT_DIR/.." && pwd)"

DOCKER_CMD="docker"
if ! docker ps >/dev/null 2>&1; then
  DOCKER_CMD="sudo docker"
fi

echo "============================================================================"
echo "STARTING CODECHECKER ENVIRONMENT CLEANUP"
echo "============================================================================"

# Show initial disk space
echo ""
echo "Current disk space before cleanup:"
df -h / | awk 'NR==1 || NR==2 {print "  " $0}'

# 1. Stop and remove all codechecker containers
echo ""
echo "[1/4] Stopping and removing all Codechecker containers..."
$DOCKER_CMD rm -f \
  codechecker-sast \
  codechecker-sca \
  codechecker-qdrant \
  codechecker-sast-test \
  codechecker-sca-test \
  codechecker-qdrant-test 2>/dev/null || true

# 2. Remove Docker networks
$DOCKER_CMD network rm codechecker-net codechecker-test-net 2>/dev/null || true
echo "  ✓ Containers and networks removed."

# 3. Free host production ports
echo ""
echo "[2/4] Freeing host ports 6333, 6334, 8080, 8082..."
if [ -f "$WORKSPACE_ROOT/stop.sh" ]; then
  bash "$WORKSPACE_ROOT/stop.sh" >/dev/null 2>&1 || true
fi
pkill -f "./qdrant --config-path" >/dev/null 2>&1 || true
sleep 2
echo "  ✓ Host ports freed."

# 4. Remove Codechecker Docker images
echo ""
echo "[3/4] Removing all Codechecker Docker images..."
$DOCKER_CMD rmi -f \
  codechecker-sast:latest \
  codechecker-sca:latest \
  codechecker-qdrant:latest \
  codechecker-sast:test \
  codechecker-sca:test \
  codechecker-qdrant:test 2>/dev/null || true
echo "  ✓ Images deleted."

# 5. Prune dangling layers and build cache
echo ""
echo "[4/4] Purging dangling images & Docker builder cache..."
$DOCKER_CMD image prune -f 2>/dev/null || true
$DOCKER_CMD builder prune -f 2>/dev/null || true
echo "  ✓ Docker cache purged."

# Final report
echo ""
echo "============================================================================"
echo "CLEANUP COMPLETE! Disk space after cleanup:"
echo "============================================================================"
df -h / | awk 'NR==1 || NR==2 {print "  " $0}'
echo "============================================================================"
echo "Environment is completely clean. You are ready to build."
echo "============================================================================"

