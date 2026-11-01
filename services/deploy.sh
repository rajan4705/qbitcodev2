#!/usr/bin/env bash
# ==============================================================================
# One-Click Production Deployment
#   1. Cleans up test containers (16333, 18080, 18082)
#   2. Stops old local host processes (6333, 8080, 8082)
#   3. Starts standalone containers via Docker Compose on production ports:
#        • Qdrant   : 6333 / 6334
#        • SAST     : 8080
#        • SCA      : 8082
#   4. Waits for health and verifies endpoints
# ==============================================================================
set -e

SCRIPT_DIR="$(cd "$(dirname "${BASH_SOURCE[0]}")" && pwd)"
WORKSPACE_ROOT="$(cd "$SCRIPT_DIR/.." && pwd)"

DOCKER_CMD="docker"
if ! docker ps >/dev/null 2>&1; then
  DOCKER_CMD="sudo docker"
fi

echo "============================================================================"
echo "DEPLOYING CODECHECKER CONTAINERS TO PRODUCTION (8080, 8082, 6333)"
echo "============================================================================"

# Step 1: Clean up test containers and reclaim disk space
echo ""
echo "[Step 1/4] Stopping & removing test containers & reclaiming disk space..."
$DOCKER_CMD rm -f codechecker-sast-test codechecker-sca-test codechecker-qdrant-test 2>/dev/null || true
$DOCKER_CMD network rm codechecker-test-net 2>/dev/null || true
$DOCKER_CMD rmi codechecker-sast:test codechecker-sca:test codechecker-qdrant:test 2>/dev/null || true
$DOCKER_CMD image prune -f 2>/dev/null || true
echo "  ✓ Test containers removed and disk space reclaimed."

# Step 2: Stop old local host processes
echo ""
echo "[Step 2/4] Freeing production host ports 8080, 8082, 6333..."
if [ -f "$WORKSPACE_ROOT/stop.sh" ]; then
  bash "$WORKSPACE_ROOT/stop.sh" >/dev/null 2>&1 || true
fi
pkill -f "./qdrant --config-path" >/dev/null 2>&1 || true
fuser -k 8080/tcp 8082/tcp 6333/tcp >/dev/null 2>&1 || true

# Wait 2 seconds to ensure ports are completely released
sleep 2

# Step 3: Launch production containers
echo ""
echo "[Step 3/4] Starting Codechecker containers..."
cd "$WORKSPACE_ROOT"

if $DOCKER_CMD compose version >/dev/null 2>&1; then
  echo "  • Using Docker Compose plugin..."
  $DOCKER_CMD compose -f "$SCRIPT_DIR/docker-compose.yml" up -d --build
elif command -v docker-compose >/dev/null 2>&1; then
  echo "  • Using docker-compose binary..."
  docker-compose -f "$SCRIPT_DIR/docker-compose.yml" up -d --build
else
  echo "  • Docker Compose CLI not detected; launching directly via native Docker..."

  # Create bridge network
  if ! $DOCKER_CMD network inspect codechecker-net >/dev/null 2>&1; then
    $DOCKER_CMD network create codechecker-net
  fi

  # 1. Qdrant
  echo "    [1/3] Building & Starting codechecker-qdrant (Port 6333)..."
  $DOCKER_CMD build -f "$SCRIPT_DIR/Dockerfile.qdrant" -t codechecker-qdrant:latest "$WORKSPACE_ROOT"
  $DOCKER_CMD rm -f codechecker-qdrant >/dev/null 2>&1 || true
  $DOCKER_CMD run -d \
    --name codechecker-qdrant \
    --restart unless-stopped \
    --network codechecker-net \
    -p 6333:6333 \
    -p 6334:6334 \
    codechecker-qdrant:latest

  # Wait for Qdrant to be healthy
  for i in {1..20}; do
    if curl -s http://127.0.0.1:6333/healthz 2>/dev/null | grep -Eq "(passed|ok)"; then
      break
    fi
    sleep 1
  done

  # 2. SAST (GPU)
  echo "    [2/3] Building & Starting codechecker-sast (Port 8080, GPU)..."
  $DOCKER_CMD build -f "$SCRIPT_DIR/Dockerfile.sast" -t codechecker-sast:latest "$WORKSPACE_ROOT"
  $DOCKER_CMD rm -f codechecker-sast >/dev/null 2>&1 || true
  $DOCKER_CMD run -d \
    --name codechecker-sast \
    --restart unless-stopped \
    --network codechecker-net \
    --gpus all \
    -p 8080:8080 \
    -e QDRANT_HOST=codechecker-qdrant \
    -e QDRANT_PORT=6333 \
    -e STORAGE_DIR=/app/qdrant_storage \
    -e CUDA_VISIBLE_DEVICES=0 \
    codechecker-sast:latest

  # 3. SCA (CPU)
  echo "    [3/3] Building & Starting codechecker-sca (Port 8082, CPU)..."
  $DOCKER_CMD build -f "$SCRIPT_DIR/Dockerfile.sca" -t codechecker-sca:latest "$WORKSPACE_ROOT/API_qdrant_Vul_db/vul_packages"
  $DOCKER_CMD rm -f codechecker-sca >/dev/null 2>&1 || true
  $DOCKER_CMD run -d \
    --name codechecker-sca \
    --restart unless-stopped \
    --network codechecker-net \
    -p 8082:8082 \
    codechecker-sca:latest
fi

# Step 4: Health Check & Verification
echo ""
echo "[Step 4/4] Waiting for services to initialize..."
READY_QDRANT=false
READY_SAST=false
READY_SCA=false

for i in {1..40}; do
  if [ "$READY_QDRANT" = false ] && curl -s http://127.0.0.1:6333/healthz 2>/dev/null | grep -Eq "(passed|ok)"; then
    READY_QDRANT=true
    echo "  ✓ [Port 6333] Qdrant Vector DB is ONLINE"
  fi
  if [ "$READY_SCA" = false ] && curl -s http://127.0.0.1:8082/health 2>/dev/null | grep -q "healthy"; then
    READY_SCA=true
    echo "  ✓ [Port 8082] SCA Vulnerability Engine is ONLINE"
  fi
  if [ "$READY_SAST" = false ] && curl -s http://127.0.0.1:8080/health 2>/dev/null | grep -q "healthy"; then
    READY_SAST=true
    echo "  ✓ [Port 8080] SAST Threat Engine is ONLINE"
  fi

  if [ "$READY_QDRANT" = true ] && [ "$READY_SCA" = true ] && [ "$READY_SAST" = true ]; then
    break
  fi
  sleep 2
done

echo ""
bash "$SCRIPT_DIR/verify.sh"

