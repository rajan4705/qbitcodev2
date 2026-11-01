#!/usr/bin/env bash
# ==============================================================================
# Setup Dedicated Conda Environment for Qwen3-Coder Serving
# ==============================================================================
set -e

ENV_NAME="qwen3_env"
CONDA_DIR="/home/minakshi.katoch/anaconda3"
source "$CONDA_DIR/etc/profile.d/conda.sh"

echo "=== Setting up Conda Environment '$ENV_NAME' for Qwen3-Coder ==="

if conda info --envs | grep -E "^$ENV_NAME\s"; then
  echo "Environment '$ENV_NAME' already exists. Activating..."
  conda activate "$ENV_NAME"
else
  echo "Creating new conda environment '$ENV_NAME' with Python 3.10..."
  conda create -y -n "$ENV_NAME" python=3.10
  conda activate "$ENV_NAME"
fi

echo "Installing vLLM, PyTorch, and huggingface_hub..."
pip install --upgrade pip
pip install torch torchvision torchaudio --index-url https://download.pytorch.org/whl/cu121 || pip install torch torchvision torchaudio
pip install vllm huggingface_hub accelerate transformers

echo "✓ Conda environment '$ENV_NAME' is ready."
