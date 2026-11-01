#!/usr/bin/env bash
# ==============================================================================
# Start vLLM with Qwen 2.5 Coder 7B AWQ (Optimized for 12GB GPUs)
# ==============================================================================
set -e

PORT=${1:-8000}
SCRIPT_DIR="$(cd "$(dirname "${BASH_SOURCE[0]}")" && pwd)"
WORKSPACE_ROOT="$(cd "$SCRIPT_DIR/.." && pwd)"

# Prefer 4-bit AWQ if available (fits in 5.2GB), otherwise fallback to standard 7B
if [ -d "$WORKSPACE_ROOT/models/qwen2.5-coder-7b-instruct-awq" ]; then
  MODEL_PATH="$WORKSPACE_ROOT/models/qwen2.5-coder-7b-instruct-awq"
else
  MODEL_PATH="$WORKSPACE_ROOT/models/qwen2.5-coder-7b-instruct"
fi

CONDA_BASE="$(command -v conda >/dev/null 2>&1 && conda info --base 2>/dev/null || echo "/opt/anaconda3")"
ENV_PYTHON="$CONDA_BASE/envs/qwen3_env/bin/python"
VLLM_BIN="$CONDA_BASE/envs/qwen3_env/bin/vllm"

if [ ! -x "$VLLM_BIN" ]; then
  VLLM_BIN="$(command -v vllm || echo "vllm")"
fi
if [ ! -x "$ENV_PYTHON" ]; then
  ENV_PYTHON="$(command -v python3 || echo "python3")"
fi

echo "Checking for running vLLM instances on port $PORT..."
fuser -k -9 $PORT/tcp 2>/dev/null || true
pkill -9 -f "vllm serve" 2>/dev/null || true
pkill -9 -f "VLLM::" 2>/dev/null || true
pkill -9 -f "EngineCore" 2>/dev/null || true
sleep 3

echo "Starting vLLM server with Qwen2.5-Coder-7B on port $PORT..."
echo "  • Model path: $MODEL_PATH"
nohup $ENV_PYTHON $VLLM_BIN serve "$MODEL_PATH" \
  --served-model-name qwen2.5-coder-7b-instruct \
  --port $PORT \
  --max-model-len 8192 \
  --gpu-memory-utilization 0.60 \
  --enforce-eager \
  --enable-auto-tool-choice \
  --tool-call-parser hermes \
  --trust-remote-code > /tmp/vllm-7b.log 2>&1 &

NEW_PID=$!
echo "Started vLLM 7B with PID $NEW_PID (Log: /tmp/vllm-7b.log)"
echo "Waiting for health endpoint (http://127.0.0.1:$PORT/health)..."

for i in $(seq 1 45); do
  if curl -s http://127.0.0.1:$PORT/health > /dev/null 2>&1; then
    echo "✓ vLLM 7B is online and ready!"
    exit 0
  fi
  sleep 2
done

echo "Warning: vLLM 7B did not report ready within 90s. Check /tmp/vllm-7b.log"
