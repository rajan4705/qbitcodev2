#!/usr/bin/env bash
# ==============================================================================
# Switch Back to Qwen 2.5 Coder 14B Server
# ==============================================================================
set -e

PORT=${1:-8000}
SCRIPT_DIR="$(cd "$(dirname "${BASH_SOURCE[0]}")" && pwd)"
WORKSPACE_ROOT="$(cd "$SCRIPT_DIR/.." && pwd)"
MODEL_PATH="$WORKSPACE_ROOT/models/qwen2.5-coder-14b-instruct"
ENV_PYTHON="/home/minakshi.katoch/anaconda3/envs/ps1/bin/python3.10"
VLLM_BIN="/home/minakshi.katoch/anaconda3/envs/mrk_code_vul/bin/vllm"

echo "Checking for running vLLM instances on port $PORT..."
fuser -k -9 $PORT/tcp 2>/dev/null || true
pkill -9 -f "vllm serve" 2>/dev/null || true
pkill -9 -f "VLLM::" 2>/dev/null || true
pkill -9 -f "EngineCore" 2>/dev/null || true
sleep 3

echo "Starting vLLM server with Qwen2.5-Coder-14B-Instruct on port $PORT..."
nohup $ENV_PYTHON $VLLM_BIN serve "$MODEL_PATH" \
  --served-model-name qwen2.5-coder-14b-instruct \
  --port $PORT \
  --max-model-len 32768 \
  --gpu-memory-utilization 0.80 \
  --enable-auto-tool-choice \
  --tool-call-parser hermes \
  --trust-remote-code > /tmp/vllm-14b.log 2>&1 &

NEW_PID=$!
echo "Started vLLM 14B with PID $NEW_PID (Log: /tmp/vllm-14b.log)"
echo "Waiting for health endpoint (http://127.0.0.1:$PORT/health)..."

for i in $(seq 1 45); do
  if curl -s http://127.0.0.1:$PORT/health > /dev/null 2>&1; then
    echo "✓ vLLM 14B is online and ready!"
    exit 0
  fi
  sleep 2
done

echo "Warning: vLLM did not report ready within 90s. Check /tmp/vllm-14b.log"
