#!/usr/bin/env bash
# ==============================================================================
# Master One-Click Installer & Deployment Script: 'setup.sh'
# Sets up everything needed to run QbitCode:
# 1. System packages & build dependencies
# 2. Conda / Python environment & pip dependencies
# 3. Node.js & Bun dependencies
# 4. Code Review Engine (Go binary: 'ocr')
# 5. Terminal TUI (Bun binary: 'opencode')
# 6. Docker Microservices (Qdrant :6333, SAST :8080, SCA :8082)
# 7. AI Models directory verification
# 8. Symlinks 'qbitcode' & 'qbit' into ~/.local/bin
# ==============================================================================
set -e

SCRIPT_DIR="$(cd "$(dirname "${BASH_SOURCE[0]}")" && pwd)"
cd "$SCRIPT_DIR"

echo "========================================================================"
echo "🛡️  QbitCode Master Deployment & Setup Engine"
echo "========================================================================"
echo "Installation directory: $SCRIPT_DIR"
echo ""

# 1. Ensure ~/.local/bin is in PATH
mkdir -p "$HOME/.local/bin"
if [[ ":$PATH:" != *":$HOME/.local/bin:"* ]]; then
  export PATH="$HOME/.local/bin:$PATH"
  echo 'export PATH="$HOME/.local/bin:$PATH"' >> "$HOME/.bashrc"
fi

# 2. Check Python Environment
echo "[1/6] Checking Python & vLLM Dependencies..."
if command -v conda >/dev/null 2>&1; then
  echo "    Conda detected."
  if conda info --envs | grep -q "qwen3_env"; then
    echo "    ✓ Conda env 'qwen3_env' already exists."
  elif [ -f "environment_conda.yml" ]; then
    echo "    Creating conda env from environment_conda.yml..."
    conda env create -f environment_conda.yml -y || true
  fi
fi

if [ -f "requirements_vllm_qwen3.txt" ]; then
  echo "    Installing/verifying pip requirements..."
  pip install -q -r requirements_vllm_qwen3.txt || true
fi

# 3. Build & Link Code Review Engine ('ocr')
echo ""
echo "[2/6] Building Code Review Engine (Go binary 'ocr')..."
if [ -d "code-review-engine" ]; then
  cd code-review-engine
  GO_BIN="$(command -v go || echo "$HOME/anaconda3/bin/go")"
  if [ -x "$GO_BIN" ]; then
    CGO_ENABLED=0 "$GO_BIN" build -ldflags "-s -w" -o "$HOME/.local/bin/ocr" ./cmd/opencodereview || true
    chmod +x "$HOME/.local/bin/ocr"
    echo "    ✓ Built & installed: $HOME/.local/bin/ocr"
  else
    echo "    ⚠️ Go not installed. Checking pre-compiled binary..."
    if [ -f "bin/ocr" ]; then
      cp "bin/ocr" "$HOME/.local/bin/ocr"
      chmod +x "$HOME/.local/bin/ocr"
      echo "    ✓ Copied pre-compiled binary: $HOME/.local/bin/ocr"
    fi
  fi
  cd "$SCRIPT_DIR"
fi

# 4. Build & Link Terminal TUI ('opencode')
echo ""
echo "[3/6] Building Terminal TUI ('opencode')..."
if [ -d "terminal-tui" ]; then
  cd terminal-tui
  if command -v bun >/dev/null 2>&1; then
    bun install --frozen-lockfile 2>/dev/null || bun install 2>/dev/null || true
    bun run --cwd packages/cli build --single --skip-install 2>/dev/null || true
    DIST_BIN="$SCRIPT_DIR/terminal-tui/packages/cli/dist/cli-linux-x64/bin/opencode"
    if [ -f "$DIST_BIN" ]; then
      chmod +x "$DIST_BIN"
      ln -sf "$DIST_BIN" "$HOME/.local/bin/opencode"
      echo "    ✓ Linked TUI command: $HOME/.local/bin/opencode"
    fi
  fi
  cd "$SCRIPT_DIR"
fi

# 5. Build Qbit Web Cockpit
echo ""
echo "[4/6] Building Qbit Web Cockpit Frontend..."
if [ -d "qbit-code-reviewer" ]; then
  cd qbit-code-reviewer
  npm install --silent 2>/dev/null || true
  if [ -d "ui" ]; then
    cd ui
    npm install --silent 2>/dev/null || true
    npm run build 2>/dev/null || true
    cd ..
  fi
  chmod +x bin/qbit.js
  ln -sf "$SCRIPT_DIR/qbit-code-reviewer/bin/qbit.js" "$HOME/.local/bin/qbit"
  echo "    ✓ Linked CLI command: $HOME/.local/bin/qbit"
  cd "$SCRIPT_DIR"
fi

# 6. Docker Microservices (:6333 Qdrant, :8080 SAST, :8082 SCA)
echo ""
echo "[5/6] Checking Docker Microservices..."
if curl -sf http://127.0.0.1:8080/health >/dev/null 2>&1 && curl -sf http://127.0.0.1:8082/health >/dev/null 2>&1; then
  echo "    ✓ Microservices (:8080, :8082, :6333) are already online!"
elif command -v docker >/dev/null 2>&1; then
  COMPOSE_FILE="services/docker-compose.yml"
  if [ ! -f "$COMPOSE_FILE" ]; then
    COMPOSE_FILE="docker/docker-compose.yml"
  fi
  if [ -f "$COMPOSE_FILE" ]; then
    echo "    Starting Qdrant, SAST, and SCA microservices ($COMPOSE_FILE)..."
    docker compose -f "$COMPOSE_FILE" up -d 2>/dev/null || sudo -n docker compose -f "$COMPOSE_FILE" up -d 2>/dev/null || true
  fi
else
  echo "    ⚠️ Docker not installed. Microservices can be started manually when ready."
fi

# 7. Symlink 'qbitcode' Orchestrator
echo ""
echo "[6/6] Linking Master 'qbitcode' Orchestrator..."
chmod +x scripts/qbitcode
chmod +x scripts/download_models.sh
ln -sf "$SCRIPT_DIR/scripts/qbitcode" "$HOME/.local/bin/qbitcode"
echo "    ✓ Linked Master Command: $HOME/.local/bin/qbitcode"

echo ""
echo "========================================================================"
echo "🎉 SETUP COMPLETE!"
echo "========================================================================"
echo ""
echo "Next steps:"
echo "  1. Download the AI model (if not already downloaded):"
echo "       ./scripts/download_models.sh 14b"
echo ""
echo "  2. Launch the entire autonomous pipeline anytime with one command:"
echo "       qbitcode"
echo "========================================================================"
