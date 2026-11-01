#!/usr/bin/env bash
# ==============================================================================
# Launch Qwen3-Coder-30B-A3B-Instruct with Native OpenCode Tool Calling on vLLM
# Uses qwen3_coder tool call parser for native OpenAI function calling
# ==============================================================================
set -e

PORT=${1:-8000}
MODEL_ID="Qwen/Qwen3-Coder-30B-A3B-Instruct"
SCRIPT_DIR="$(cd "$(dirname "${BASH_SOURCE[0]}")" && pwd)"
WORKSPACE_ROOT="$(cd "$SCRIPT_DIR/.." && pwd)"
LOCAL_DIR="$WORKSPACE_ROOT/models/qwen3-coder-30b-a3b-instruct"
CONDA_DIR="/home/minakshi.katoch/anaconda3"
source "$CONDA_DIR/etc/profile.d/conda.sh"

if conda info --envs | grep -q "^qwen3_env "; then
  conda activate qwen3_env
else
  conda activate ps1
fi

TARGET_MODEL="$MODEL_ID"
if [ -d "$LOCAL_DIR" ] && [ -f "$LOCAL_DIR/config.json" ]; then
  TARGET_MODEL="$LOCAL_DIR"
fi

echo "Checking for running processes on port $PORT and stale vLLM engine cores..."
fuser -k -9 $PORT/tcp 2>/dev/null || true
pkill -9 -f "vllm serve" 2>/dev/null || true
pkill -9 -f "VLLM::" 2>/dev/null || true
pkill -9 -f "EngineCore" 2>/dev/null || true
sleep 3

echo "Launching vLLM serving Qwen3-Coder-30B-A3B-Instruct on port $PORT..."
# H100 NVL has 94GB total VRAM (~80GB free after CVE vector DB processes)
nohup vllm serve "$TARGET_MODEL" \
  --served-model-name qwen3-coder-30b-a3b-instruct \
  --port $PORT \
  --max-model-len 32768 \
  --gpu-memory-utilization 0.82 \
  --kv-cache-dtype fp8 \
  --enable-auto-tool-choice \
  --tool-call-parser qwen3_coder \
  --trust-remote-code > /tmp/vllm-qwen3.log 2>&1 &

NEW_PID=$!
echo "vLLM started with PID $NEW_PID (Log: /tmp/vllm-qwen3.log)"
echo "Waiting for service to become ready on port $PORT..."

for i in $(seq 1 60); do
  if curl -s http://127.0.0.1:$PORT/health > /dev/null 2>&1; then
    echo "✓ vLLM Qwen3 Coder is online and responding on port $PORT!"
    exit 0
  fi
  sleep 3
done

echo "Check /tmp/vllm-qwen3.log for status."
