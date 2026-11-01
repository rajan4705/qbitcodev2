#!/usr/bin/env bash
# ==============================================================================
# Launch Qwen 2.5 Coder 32B Instruct with Native Tool Calling on vLLM
# Compatible with standard OpenCode format & Hermes parser
# ==============================================================================
set -e

PORT=${1:-8000}
MODEL_NAME="Qwen/Qwen2.5-Coder-32B-Instruct"
LOCAL_DIR="/home/minakshi.katoch/Desktop/codechecker/Project/models/qwen2.5-coder-32b-instruct"
CONDA_DIR="/home/minakshi.katoch/anaconda3"
source "$CONDA_DIR/etc/profile.d/conda.sh"
conda activate qwen32b

# Target model path: local directory if downloaded, else HuggingFace repo
TARGET_MODEL="$MODEL_NAME"
if [ -d "$LOCAL_DIR" ] && [ -f "$LOCAL_DIR/config.json" ]; then
  TARGET_MODEL="$LOCAL_DIR"
fi

echo "Checking for running processes on port $PORT..."
PID=$(lsof -ti :$PORT || true)
if [ -n "$PID" ]; then
  echo "Stopping process $PID on port $PORT..."
  kill -9 $PID || true
  sleep 2
fi

echo "Launching vLLM with Qwen 2.5 Coder 32B on port $PORT..."
# H100 NVL has 94GB VRAM. 32B in bfloat16 takes ~65GB.
# Memory utilization of 0.88 gives ~83GB, plenty for 32B with KV cache.
nohup vllm serve "$TARGET_MODEL" \
  --served-model-name qwen2.5-coder-32b-instruct \
  --port $PORT \
  --max-model-len 32768 \
  --gpu-memory-utilization 0.88 \
  --enable-auto-tool-choice \
  --tool-call-parser hermes \
  --trust-remote-code > /tmp/vllm-32b.log 2>&1 &

NEW_PID=$!
echo "vLLM 32B started with PID $NEW_PID (Log: /tmp/vllm-32b.log)"
echo "Waiting for service to become ready..."

for i in $(seq 1 60); do
  if curl -s http://127.0.0.1:$PORT/health > /dev/null 2>&1; then
    echo "✓ vLLM 32B is online and responding on port $PORT!"
    exit 0
  fi
  sleep 3
done

echo "Check /tmp/vllm-32b.log for status."
