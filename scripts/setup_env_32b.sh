#!/usr/bin/env bash
# ==============================================================================
# Setup Conda Environment for Qwen 2.5 Coder 32B with Native OpenCode Tool Support
# ==============================================================================
set -e

ENV_NAME="qwen32b"
CONDA_DIR="/home/minakshi.katoch/anaconda3"
source "$CONDA_DIR/etc/profile.d/conda.sh"

echo "=== Setting up Conda Environment '$ENV_NAME' ==="

if conda info --envs | grep -q "^$ENV_NAME "; then
  echo "Environment '$ENV_NAME' already exists. Activating..."
  conda activate "$ENV_NAME"
else
  echo "Creating new conda environment '$ENV_NAME' with Python 3.10..."
  conda create -y -n "$ENV_NAME" python=3.10
  conda activate "$ENV_NAME"
fi

echo "Installing PyTorch, vLLM, and HuggingFace Hub..."
pip install --upgrade pip
pip install torch torchvision torchaudio --index-url https://download.pytorch.org/whl/cu121 || pip install torch torchvision torchaudio
pip install vllm==0.6.3.post1 huggingface_hub accelerate transformers

echo "✓ Environment '$ENV_NAME' is configured and ready."
