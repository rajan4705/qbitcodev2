#!/usr/bin/env bash
# ==============================================================================
# Qbit Platform Complete One-Command Setup & Deployment Script
# Initializes Python Conda, Docker containers (:8080, :8082, :6333), and CLI/UI
# ==============================================================================
set -e

SCRIPT_DIR="$(cd "$(dirname "${BASH_SOURCE[0]}")" && pwd)"
BASE_DIR="$(dirname "$SCRIPT_DIR")"

echo "========================================================================"
echo "🛡️  Qbit Autonomous Security Review & Remediation Platform Deployment"
echo "========================================================================"
echo "Base Directory: $BASE_DIR"

# 1. System checks
echo "[1/5] Verifying system runtimes and GPU..."
if ! command -v node >/dev/null 2>&1; then
  echo "❌ Node.js not found. Please install Node >= 20."
  exit 1
fi
if ! command -v nvidia-smi >/dev/null 2>&1; then
  echo "⚠️ Warning: nvidia-smi not detected. GPU acceleration may not be available."
else
  GPU_NAME=$(nvidia-smi --query-gpu=name --format=csv,noheader | head -n 1)
  echo "✓ GPU Detected: $GPU_NAME"
fi

# 2. Build and verify UI
echo "[2/5] Building Qbit Web Cockpit UI..."
if [ -d "$BASE_DIR/qbit-code-reviewer/ui" ]; then
  npm --prefix "$BASE_DIR/qbit-code-reviewer/ui" run build
  echo "✓ Web UI built successfully into dist/."
fi

# 3. Ensure CLI symlink
echo "[3/5] Registering global 'qbit' and 'qbitcode' binaries..."
mkdir -p "$HOME/.local/bin"
ln -sf "$BASE_DIR/qbit-code-reviewer/bin/qbit.js" "$HOME/.local/bin/qbit"
ln -sf "$BASE_DIR/scripts/qbitcode" "$HOME/.local/bin/qbitcode"
export PATH="$HOME/.local/bin:$PATH"
echo "✓ Symlinks updated: $(which qbit 2>/dev/null || echo '~/.local/bin/qbit')"

# 4. Deploy Docker Containers (Port 6333, 8080, 8082)
echo "[4/5] Starting Docker Security Microservices..."
if command -v docker >/dev/null 2>&1; then
  COMPOSE_FILE="$BASE_DIR/services/docker-compose.yml"
  if [ ! -f "$COMPOSE_FILE" ]; then
    COMPOSE_FILE="$BASE_DIR/docker/docker-compose.yml"
  fi
  if [ -f "$COMPOSE_FILE" ]; then
    docker compose -f "$COMPOSE_FILE" up -d || true
  fi
fi

# 5. Launch vLLM default model (14B or 30B)
echo "[5/5] Launching local vLLM AI engine..."
if [ -f "$BASE_DIR/scripts/start_vllm_14b.sh" ]; then
  screen -dmS vllm_daemon "$BASE_DIR/scripts/start_vllm_14b.sh" 8000
  echo "✓ vLLM startup initiated in screen session 'vllm_daemon'."
fi

echo "========================================================================"
echo "✨ Deployment complete! Run 'qbitcode' to launch all services & UI."
echo "========================================================================"
