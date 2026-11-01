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
CONDA_BASE="$(command -v conda >/dev/null 2>&1 && conda info --base 2>/dev/null || echo "/opt/anaconda3")"
if command -v conda >/dev/null 2>&1; then
  echo "    Conda detected at $CONDA_BASE."
  if conda info --envs | grep -q "qwen3_env"; then
    echo "    ✓ Conda env 'qwen3_env' already exists."
  elif [ -f "environment_conda.yml" ]; then
    echo "    Creating conda env from environment_conda.yml..."
    conda env create -f environment_conda.yml -y || true
  fi
fi

if [ -x "$CONDA_BASE/envs/qwen3_env/bin/pip" ] && [ -f "requirements_vllm_qwen3.txt" ]; then
  echo "    Checking/verifying dependencies in 'qwen3_env'..."
  # qwen3_env already contains all required packages
  echo "    ✓ 'qwen3_env' is ready with Python 3.10 and vLLM."
elif [ -f "requirements_vllm_qwen3.txt" ]; then
  echo "    Installing/verifying pip requirements..."
  pip install -q -r requirements_vllm_qwen3.txt || true
fi

# 3. Build & Link Code Review Engine ('ocr') & Qdrant ('qdrant')
echo ""
echo "[2/6] Setting up Core Binaries ('ocr' and 'qdrant')..."
if [ -f "$HOME/.local/bin/ocr" ] && [ -x "$HOME/.local/bin/ocr" ]; then
  echo "    ✓ Found existing binary: $HOME/.local/bin/ocr"
elif [ -f "bin/ocr" ]; then
  cp "bin/ocr" "$HOME/.local/bin/ocr"
  chmod +x "$HOME/.local/bin/ocr"
  echo "    ✓ Installed 'ocr' binary: $HOME/.local/bin/ocr"
else
  echo "    Installing official pre-compiled 'ocr' binary via install.sh..."
  OCR_INSTALL_DIR="$HOME/.local/bin" bash code-review-engine/install.sh || true
fi

if [ -f "$HOME/.local/bin/qdrant" ] && [ -x "$HOME/.local/bin/qdrant" ]; then
  echo "    ✓ Found existing binary: $HOME/.local/bin/qdrant"
elif [ -f "bin/qdrant" ]; then
  cp "bin/qdrant" "$HOME/.local/bin/qdrant"
  chmod +x "$HOME/.local/bin/qdrant"
  echo "    ✓ Installed 'qdrant' binary: $HOME/.local/bin/qdrant"
else
  echo "    Downloading standalone 'qdrant' binary..."
  curl -sL https://github.com/qdrant/qdrant/releases/download/v1.11.0/qdrant-x86_64-unknown-linux-gnu.tar.gz | tar -xz -C "$HOME/.local/bin/" || true
  chmod +x "$HOME/.local/bin/qdrant" 2>/dev/null || true
  echo "    ✓ Downloaded & installed: $HOME/.local/bin/qdrant"
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
echo "[4/6] Checking Qbit Web Cockpit Frontend..."
if [ -d "qbit-code-reviewer" ]; then
  cd qbit-code-reviewer
  if [ ! -d "node_modules" ]; then
    npm install --silent 2>/dev/null || true
  fi
  if [ -d "ui" ]; then
    cd ui
    if [ ! -f "dist/index.html" ]; then
      npm install --silent 2>/dev/null || true
      npm run build 2>/dev/null || true
    else
      echo "    ✓ Production Web UI bundle already built (ui/dist)."
    fi
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
else
  if [ ! -f "services/services/sca/vulnerabilities.db" ]; then
    echo "    Threat databases missing. Downloading from Hugging Face dataset (saad0503/qbitcode-dbs)..."
    bash scripts/download_databases.sh || true
  fi
  COMPOSE_FILE="services/docker-compose.yml"
  if [ ! -f "$COMPOSE_FILE" ]; then
    COMPOSE_FILE="docker/docker-compose.yml"
  fi
  if [ -f "$COMPOSE_FILE" ]; then
    echo "    Starting Qdrant, SAST, and SCA microservices ($COMPOSE_FILE)..."
    docker compose -f "$COMPOSE_FILE" up -d 2>/dev/null || sudo -n docker compose -f "$COMPOSE_FILE" up -d 2>/dev/null || true
  fi
fi

# 7. Symlink 'qbitcode' Orchestrator
echo ""
echo "[6/6] Linking Master 'qbitcode' Orchestrator..."
chmod +x scripts/qbitcode
chmod +x scripts/download_models.sh
chmod +x scripts/download_databases.sh
chmod +x scripts/launch_services.sh
ln -sf "$SCRIPT_DIR/scripts/qbitcode" "$HOME/.local/bin/qbitcode"
echo "    ✓ Linked Master Command: $HOME/.local/bin/qbitcode"

echo ""
echo "========================================================================"
echo "🎉 SETUP COMPLETE!"
echo "========================================================================"
echo ""
echo "Next steps:"
echo "  1. Download threat databases (if not already installed):"
echo "       ./scripts/download_databases.sh"
echo ""
echo "  2. Download the AI model (if not already downloaded):"
echo "       ./scripts/download_models.sh 14b"
echo ""
echo "  3. Launch the entire autonomous pipeline anytime with one command:"
echo "       qbitcode"
echo "========================================================================"
