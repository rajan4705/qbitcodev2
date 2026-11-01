#!/usr/bin/env bash
# ==============================================================================
# Download Qwen3-Coder-30B-A3B-Instruct into Local Models Directory
# ==============================================================================
set -e

MODEL_ID="Qwen/Qwen3-Coder-30B-A3B-Instruct"
DEST_DIR="/home/minakshi.katoch/Desktop/codechecker/Project/models/qwen3-coder-30b-a3b-instruct"
CONDA_DIR="/home/minakshi.katoch/anaconda3"
source "$CONDA_DIR/etc/profile.d/conda.sh"
conda activate qwen3_env || conda activate ps1

echo "Target Destination: $DEST_DIR"
mkdir -p "$DEST_DIR"

echo "Downloading $MODEL_ID..."
python -c "
from huggingface_hub import snapshot_download
import os

model_id = '$MODEL_ID'
dest_dir = '$DEST_DIR'

print(f'Starting snapshot download of {model_id} to {dest_dir}...')
snapshot_download(
    repo_id=model_id,
    local_dir=dest_dir,
    local_dir_use_symlinks=False,
    resume_download=True
)
print('✓ Model download completed successfully!')
"
