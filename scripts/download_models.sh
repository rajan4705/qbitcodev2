#!/usr/bin/env bash
# ==============================================================================
# Model Downloader for QbitCode
# Downloads:
# 1. Qwen2.5-Coder-14B-Instruct (~28 GB, 6 safetensors shards) [Default Fast Engine]
# 2. Qwen3-Coder-30B-A3B-Instruct (Optional deep MoE model)
# ==============================================================================
set -e

SCRIPT_DIR="$(cd "$(dirname "${BASH_SOURCE[0]}")" && pwd)"
WORKSPACE_ROOT="$(cd "$SCRIPT_DIR/.." && pwd)"
MODELS_DIR="$WORKSPACE_ROOT/models"

mkdir -p "$MODELS_DIR"

MODEL_CHOICE="${1:-14b}"

echo "========================================================================"
echo "🤖 QbitCode AI Model Downloader"
echo "========================================================================"
echo "Target Directory: $MODELS_DIR"
echo "Model Selection : $MODEL_CHOICE"
echo ""

# Ensure huggingface_hub is installed
if ! python3 -c "import huggingface_hub" >/dev/null 2>&1; then
  echo "Installing huggingface_hub CLI..."
  pip install -q huggingface_hub
fi

if [ "$MODEL_CHOICE" = "14b" ] || [ "$MODEL_CHOICE" = "all" ]; then
  DEST_14B="$MODELS_DIR/qwen2.5-coder-14b-instruct"
  echo ">>> [1] Downloading Qwen2.5-Coder-14B-Instruct..."
  if [ -d "$DEST_14B" ] && [ -f "$DEST_14B/config.json" ]; then
    echo "    ✓ 14B model already present at $DEST_14B"
  else
    python3 -c "
from huggingface_hub import snapshot_download
import os

dest = '$DEST_14B'
print(f'Downloading Qwen/Qwen2.5-Coder-14B-Instruct to {dest}...')
snapshot_download(
    repo_id='Qwen/Qwen2.5-Coder-14B-Instruct',
    local_dir=dest,
    local_dir_use_symlinks=False,
    ignore_patterns=['*.bin', '*.pt', '*.msgpack']
)
print('✓ Qwen2.5-Coder-14B-Instruct downloaded successfully!')
"
  fi
fi

if [ "$MODEL_CHOICE" = "30b" ] || [ "$MODEL_CHOICE" = "all" ]; then
  DEST_30B="$MODELS_DIR/qwen3-coder-30b-a3b-instruct"
  echo ">>> [2] Downloading Qwen3-Coder-30B-A3B-Instruct..."
  if [ -d "$DEST_30B" ] && [ -f "$DEST_30B/config.json" ]; then
    echo "    ✓ 30B model already present at $DEST_30B"
  else
    python3 -c "
from huggingface_hub import snapshot_download
import os

dest = '$DEST_30B'
print(f'Downloading Qwen/Qwen3-Coder-30B-A3B-Instruct to {dest}...')
snapshot_download(
    repo_id='Qwen/Qwen3-Coder-30B-A3B-Instruct',
    local_dir=dest,
    local_dir_use_symlinks=False,
    ignore_patterns=['*.bin', '*.pt', '*.msgpack']
)
print('✓ Qwen3-Coder-30B-A3B-Instruct downloaded successfully!')
"
  fi
fi

echo ""
echo "========================================================================"
echo "✔ Model download check completed!"
echo "  Models available at: $MODELS_DIR"
echo "========================================================================"
