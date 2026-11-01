#!/usr/bin/env bash
# ==============================================================================
# Qbit Code Reviewer - Automated Production Setup & Engine Verification
# ==============================================================================
set -euo pipefail

SCRIPT_DIR="$(cd "$(dirname "${BASH_SOURCE[0]}")" && pwd)"
QBIT_ROOT="$(cd "$SCRIPT_DIR/.." && pwd)"

export PATH="$HOME/.local/bin:$HOME/.opencode/bin:$PATH"

VLLM_PORT="${VLLM_PORT:-8000}"
VLLM_HOST="http://127.0.0.1:${VLLM_PORT}"
MODEL="${VLLM_MODEL:-qwen2.5-coder-14b-instruct}"

echo "=========================================================="
echo "  Qbit Code Reviewer - Setup & Engine Verification"
echo "  vLLM Target : ${VLLM_HOST}/v1"
echo "  Model       : ${MODEL}"
echo "=========================================================="

# 1. Manage vLLM inference server
echo ""
echo "[Step 1/5] Checking vLLM inference server..."
ACTIVE_PIDS=$(lsof -ti :"$VLLM_PORT" 2>/dev/null || true)

if curl -sf "${VLLM_HOST}/health" >/dev/null 2>&1; then
    ACTIVE_MODEL=$(curl -s "${VLLM_HOST}/v1/models" 2>/dev/null | grep -o '"id":"[^"]*"' | head -n 1 | cut -d'"' -f4 || echo "unknown")
    echo "  [OK] vLLM server is currently running (PID: $ACTIVE_PIDS, Model: $ACTIVE_MODEL)"
    echo ""
    echo "  What would you like to do?"
    echo "    1) Use the currently running vLLM instance (Default)"
    echo "    2) Stop existing instance and restart fresh with 65k context"
    read -p "  Enter choice [1/2]: " -n 1 -r || true
    echo ""
    if [[ "${REPLY:-1}" == "2" ]]; then
        echo "  [INFO] Restarting vLLM with 65536 context..."
        bash "$SCRIPT_DIR/vllm-service.sh" stop
        MAX_MODEL_LEN=65536 bash "$SCRIPT_DIR/vllm-service.sh" start
    else
        echo "  [INFO] Continuing with existing instance."
    fi
else
    echo "  [WARN] vLLM server is not running on ${VLLM_HOST}."
    echo "  Launching production vLLM instance..."
    MAX_MODEL_LEN=65536 bash "$SCRIPT_DIR/vllm-service.sh" start
fi

# 2. Check binaries
echo ""
echo "[Step 2/5] Verifying tool installations..."
if command -v ocr >/dev/null 2>&1; then
    echo "  [OK] Scanner found: $(ocr --version | head -n 1)"
else
    echo "  [ERROR] Scanner binary not found."
fi

if command -v opencode >/dev/null 2>&1; then
    echo "  [OK] Remediation engine found: $(opencode --version)"
else
