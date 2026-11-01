#!/usr/bin/env bash
set -e

VARIANT="${1:-14b}"
PORT=8000
SCRIPT_DIR="$(cd "$(dirname "${BASH_SOURCE[0]}")" && pwd)"
MODELS_BASE="$(cd "$SCRIPT_DIR/.." && pwd)/models"
CONDA_DIR="/home/minakshi.katoch/anaconda3"
source "$CONDA_DIR/etc/profile.d/conda.sh"
conda activate qwen3_env

echo "Stopping existing vLLM processes on port $PORT..."
fuser -k -9 $PORT/tcp 2>/dev/null || true
pkill -9 -e -f "bin/vllm" 2>/dev/null || true
pkill -9 -e -f "EngineCore" 2>/dev/null || true
sleep 3

if [ "$VARIANT" = "14b" ]; then
    MODEL_PATH="$MODELS_BASE/qwen2.5-coder-14b-instruct"
    SERVED_NAME="qwen2.5-coder-14b-instruct"
    PARSER="hermes"
    UTIL="0.80"
    LOG="/tmp/vllm-14b.log"
    EXTRA_FLAGS=""
elif [ "$VARIANT" = "30b" ]; then
    MODEL_PATH="$MODELS_BASE/qwen3-coder-30b-a3b-instruct"
    SERVED_NAME="qwen3-coder-30b-a3b-instruct"
    PARSER="qwen3_coder"
    UTIL="0.82"
    LOG="/tmp/vllm-30b.log"
    EXTRA_FLAGS="--kv-cache-dtype fp8"
else
    echo "Unknown variant: $VARIANT (use 14b or 30b)"
    exit 1
fi

echo "Launching vLLM with $SERVED_NAME (Parser: $PARSER, Util: $UTIL)..."
nohup vllm serve "$MODEL_PATH" \
  --served-model-name "$SERVED_NAME" \
  --port $PORT \
  --max-model-len 32768 \
  --gpu-memory-utilization $UTIL \
  --enable-auto-tool-choice \
  --tool-call-parser "$PARSER" \
  --trust-remote-code $EXTRA_FLAGS > "$LOG" 2>&1 &

PID=$!
echo "vLLM spawned with PID $PID (Log: $LOG)"
echo "Waiting for health endpoint at http://127.0.0.1:$PORT/health..."

for i in $(seq 1 45); do
    if curl -sf http://127.0.0.1:$PORT/health > /dev/null 2>&1; then
        echo "✓ vLLM $VARIANT is ONLINE and ready!"
        exit 0
    fi
    sleep 2
done

echo "Check $LOG for startup issues."
exit 1
