#!/usr/bin/env bash
# ==============================================================================
# QbitCode Microservices Launcher: Qdrant (:6333), SAST (:8080), SCA (:8082)
# Starts and verifies all security intelligence services.
# ==============================================================================
set -e

SCRIPT_DIR="$(cd "$(dirname "${BASH_SOURCE[0]}")" && pwd)"
WORKSPACE_ROOT="$(cd "$SCRIPT_DIR/.." && pwd)"
SERVICES_DIR="$WORKSPACE_ROOT/services"

echo "========================================================================"
echo "🛡️  Launching QbitCode Security Intelligence Microservices"
echo "========================================================================"

# Quick check if already running
READY=true
if ! curl -sf http://127.0.0.1:6333/healthz >/dev/null 2>&1; then READY=false; fi
if ! curl -sf http://127.0.0.1:8080/health >/dev/null 2>&1; then READY=false; fi
if ! curl -sf http://127.0.0.1:8082/health >/dev/null 2>&1; then READY=false; fi

if [ "$READY" = true ]; then
  echo "✓ All microservices (:6333 Qdrant, :8080 SAST, :8082 SCA) are already ONLINE!"
  bash "$SERVICES_DIR/verify.sh"
  exit 0
fi

# Ensure databases exist
SCA_DB="$SERVICES_DIR/services/sca/vulnerabilities.db"
if [ ! -f "$SCA_DB" ]; then
  echo "⚠️ Database files not detected. Running download_databases.sh first..."
  bash "$SCRIPT_DIR/download_databases.sh"
fi

# Start via Docker Compose if available
if command -v docker >/dev/null 2>&1; then
  echo "Starting services via Docker Compose..."
  docker compose -f "$SERVICES_DIR/docker-compose.yml" up -d 2>/dev/null || \
    sudo -n docker compose -f "$SERVICES_DIR/docker-compose.yml" up -d 2>/dev/null || true
fi

# Fallback: start native processes if any service is still offline
if ! curl -sf http://127.0.0.1:8082/health >/dev/null 2>&1; then
  echo "Starting SCA service natively on port 8082..."
  nohup python3 "$SERVICES_DIR/services/sca/api_server.py" --host 0.0.0.0 --port 8082 > /tmp/sca_server.log 2>&1 &
fi

if ! curl -sf http://127.0.0.1:8080/health >/dev/null 2>&1; then
  echo "Starting SAST threat attribution service natively on port 8080..."
  nohup python3 "$SERVICES_DIR/services/sast/Qdrant_Api/api_server.py" --host 0.0.0.0 --port 8080 > /tmp/sast_server.log 2>&1 &
fi

# Wait for services to report healthy
echo ""
echo "Waiting for services to report healthy..."
for i in {1..30}; do
  QDRANT_OK=$(curl -sf http://127.0.0.1:6333/healthz 2>/dev/null || true)
  SAST_OK=$(curl -sf http://127.0.0.1:8080/health 2>/dev/null || true)
  SCA_OK=$(curl -sf http://127.0.0.1:8082/health 2>/dev/null || true)
  
  if echo "$QDRANT_OK" | grep -Eq "(passed|ok)" && echo "$SAST_OK" | grep -q "healthy" && echo "$SCA_OK" | grep -q "healthy"; then
    echo "✓ All 3 services are ONLINE and responding!"
    break
  fi
  sleep 2
done

echo ""
bash "$SERVICES_DIR/verify.sh"

