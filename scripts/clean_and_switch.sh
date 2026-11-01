#!/usr/bin/env bash
TARGET="${1:-14b}"
fuser -k -9 8000/tcp 2>/dev/null || true
pkill -9 -f "bin/vllm" 2>/dev/null || true
pkill -9 -f "EngineCore" 2>/dev/null || true
sleep 4

SCRIPT_DIR="$(cd "$(dirname "${BASH_SOURCE[0]}")" && pwd)"

if [ "$TARGET" = "14b" ]; then
  "$SCRIPT_DIR/start_vllm_14b.sh" 8000
else
  "$SCRIPT_DIR/start_vllm_qwen3.sh" 8000
fi
