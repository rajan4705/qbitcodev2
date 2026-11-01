#!/usr/bin/env bash
# ==============================================================================
# Download Qwen2.5-Coder Models into opencode/models
# ==============================================================================
set -e

MODEL_VARIANT="${1:-14b}" # default 14b, or pass 7b
SCRIPT_DIR="$(cd "$(dirname "${BASH_SOURCE[0]}")" && pwd)"
TARGET_BASE="$(cd "$SCRIPT_DIR/.." && pwd)/models"

mkdir -p "$TARGET_BASE"

if [ "$MODEL_VARIANT" = "14b" ]; then
    MODEL_ID="Qwen/Qwen2.5-Coder-14B-Instruct"
    DEST_DIR="$TARGET_BASE/qwen2.5-coder-14b-instruct"
elif [ "$MODEL_VARIANT" = "7b" ]; then
    MODEL_ID="Qwen/Qwen2.5-Coder-7B-Instruct"
    DEST_DIR="$TARGET_BASE/qwen2.5-coder-7b-instruct"
else
    echo "Unknown model variant: $MODEL_VARIANT (choose '7b' or '14b')"
    exit 1
fi

echo "========================================================"
echo "Downloading $MODEL_ID into:"
echo "  $DEST_DIR"
echo "========================================================"

mkdir -p "$DEST_DIR"

/home/minakshi.katoch/anaconda3/envs/qwen3_env/bin/python3 -c "
import os
from huggingface_hub import snapshot_download

model_id = '$MODEL_ID'
dest_dir = '$DEST_DIR'

print(f'Starting download of {model_id}...')
snapshot_download(
    repo_id=model_id,
    local_dir=dest_dir,
    local_dir_use_symlinks=False,
    resume_download=True
)
print('✓ Download complete!')
"

echo "✓ Successfully downloaded to $DEST_DIR"
