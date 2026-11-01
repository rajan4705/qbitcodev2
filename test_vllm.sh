#!/usr/bin/env bash
# ==============================================================================
# OpenCodeReview (OCR) - vLLM Setup, Configuration, and Test Script
# Optimized for NVIDIA GPUs (Hopper / H100 / A100 / L40S)
# ==============================================================================
set -euo pipefail

# Ensure ~/.local/bin is in PATH
export PATH="$HOME/.local/bin:$PATH"

# Configuration defaults (can be overridden via args or env)
DEFAULT_LOCAL_MODEL_DIR="/home/minakshi.katoch/Desktop/codechecker/Project/models/qwen2.5-coder-14b-instruct"
SERVED_MODEL_NAME="qwen2.5-coder-14b-instruct"

# If an argument is provided, check if it is a path or model identifier
if [ -n "${1:-}" ]; then
    if [ -d "$1" ]; then
        MODEL_PATH="$1"
        MODEL="$SERVED_MODEL_NAME"
    elif [ -d "$DEFAULT_LOCAL_MODEL_DIR" ]; then
        MODEL_PATH="$DEFAULT_LOCAL_MODEL_DIR"
        MODEL="${1:-$SERVED_MODEL_NAME}"
    else
        MODEL_PATH="$1"
        MODEL="$1"
    fi
elif [ -d "$DEFAULT_LOCAL_MODEL_DIR" ]; then
    MODEL_PATH="$DEFAULT_LOCAL_MODEL_DIR"
    MODEL="$SERVED_MODEL_NAME"
else
    MODEL_PATH="qwen2.5-coder-14b-instruct"
    MODEL="qwen2.5-coder-14b-instruct"
fi

VLLM_PORT="${VLLM_PORT:-8000}"
VLLM_HOST="http://127.0.0.1:${VLLM_PORT}"

echo "=========================================================="
echo "  OpenCodeReview (OCR) - vLLM Test Script"
echo "  Model Path   : ${MODEL_PATH}"
echo "  Served Name  : ${MODEL}"
echo "  Endpoint     : ${VLLM_HOST}/v1"
echo "=========================================================="

# ------------------------------------------------------------------------------
# 1. Verify OCR CLI installation
# ------------------------------------------------------------------------------
echo ""
echo "[Step 1/5] Checking OpenCodeReview (ocr) CLI..."
if ! command -v ocr >/dev/null 2>&1; then
    echo "  [INFO] 'ocr' binary not found in PATH. Checking ~/.local/bin/ocr..."
    if [ -x "$HOME/.local/bin/ocr" ]; then
        echo "  [OK] Found at $HOME/.local/bin/ocr"
    else
        echo "  [INFO] Installing ocr CLI to $HOME/.local/bin..."
        mkdir -p "$HOME/.local/bin"
        OCR_INSTALL_DIR="$HOME/.local/bin" sh /home/minakshi.katoch/Desktop/qbitcode/code-review-engine/install.sh
    fi
else
    echo "  [OK] $(ocr --version | head -n 1)"
fi

# ------------------------------------------------------------------------------
# 2. Check if vLLM server is running or needs to be launched
# ------------------------------------------------------------------------------
echo ""
echo "[Step 2/5] Checking if vLLM service is running on port ${VLLM_PORT}..."
if curl -sf "${VLLM_HOST}/health" >/dev/null 2>&1; then
    echo "  [OK] vLLM server is active and healthy!"
    
    # Detect the actual model loaded on the server
    LOADED_MODEL=$(curl -s "${VLLM_HOST}/v1/models" | grep -o '"id":"[^"]*"' | head -n 1 | cut -d'"' -f4 || echo "")
    if [ -n "$LOADED_MODEL" ]; then
        echo "  [INFO] Detected active model on server: ${LOADED_MODEL}"
        MODEL="$LOADED_MODEL"
    fi
else
    echo "  [WARN] vLLM server is NOT currently running on ${VLLM_HOST}"
    echo ""
    echo "  To launch the vLLM server on your H100 GPU, run:"
    echo "  ----------------------------------------------------------------------"
    echo "  HF_HUB_OFFLINE=1 VLLM_HOST_IP=127.0.0.1 \\"
    echo "  vllm serve \"${MODEL_PATH}\" \\"
    echo "      --served-model-name \"${MODEL}\" \\"
    echo "      --port ${VLLM_PORT} \\"
    echo "      --max-model-len 65536 \\"
    echo "      --enable-auto-tool-choice \\"
    echo "      --tool-call-parser hermes \\"
    echo "      --trust-remote-code"
    echo "  ----------------------------------------------------------------------"
    echo ""
    
    # Locate working vLLM runner
    VLLM_CMD=""
    if command -v vllm >/dev/null 2>&1; then
        VLLM_CMD="vllm"
    elif [ -x "/home/minakshi.katoch/anaconda3/envs/ps1/bin/python3.10" ] && [ -x "/home/minakshi.katoch/anaconda3/envs/mrk_code_vul/bin/vllm" ]; then
        VLLM_CMD="/home/minakshi.katoch/anaconda3/envs/ps1/bin/python3.10 /home/minakshi.katoch/anaconda3/envs/mrk_code_vul/bin/vllm"
    fi

    if [ -n "$VLLM_CMD" ]; then
        read -p "  Would you like to start vLLM in the background now? [y/N] " -n 1 -r || true
        echo ""
        if [[ $REPLY =~ ^[Yy]$ ]]; then
            mkdir -p "$HOME/.opencodereview/logs"
            LOG_FILE="$HOME/.opencodereview/logs/vllm.log"
            echo "  [INFO] Launching vLLM in background (logs: $LOG_FILE)..."
            nohup env HF_HUB_OFFLINE=1 VLLM_HOST_IP=127.0.0.1 $VLLM_CMD serve "${MODEL_PATH}" \
                --served-model-name "${MODEL}" \
                --port "${VLLM_PORT}" \
                --max-model-len 32768 \
                --gpu-memory-utilization 0.80 \
                --enable-auto-tool-choice \
                --tool-call-parser hermes \
                --trust-remote-code > "$LOG_FILE" 2>&1 &
            VLLM_PID=$!
            echo "  [INFO] Process started with PID: $VLLM_PID"
            echo "  Waiting for vLLM to initialize weights and engine..."
            
            while true; do
                if curl -sf "${VLLM_HOST}/health" >/dev/null 2>&1; then
                    echo "  [OK] vLLM server is now up and healthy!"
                    break
                fi
                if ! kill -0 "$VLLM_PID" 2>/dev/null; then
                    echo "  [ERROR] vLLM process terminated unexpectedly. Check logs: $LOG_FILE"
                    exit 1
                fi
                sleep 5
                printf "."
            done
        else
            echo "  [ABORT] Please start your vLLM server and re-run this script."
            exit 1
        fi
    else
        echo "  [INFO] 'vllm' executable not found."
        echo "  Please start the server manually or activate your conda environment and retry."
        exit 1
    fi
fi

# ------------------------------------------------------------------------------
# 3. Verify Native Tool Calling on vLLM
# ------------------------------------------------------------------------------
echo ""
echo "[Step 3/5] Testing Tool Calling endpoint on '${MODEL}'..."
TOOL_TEST_PAYLOAD=$(cat <<EOF
{
  "model": "${MODEL}",
  "messages": [
    {"role": "user", "content": "Use the report_bug tool to report a bug in: func multiply(a, b int) int { return a + b }"}
  ],
  "tools": [
    {
      "type": "function",
      "function": {
        "name": "report_bug",
        "description": "Report a code defect",
        "parameters": {
          "type": "object",
          "properties": {
            "issue": {"type": "string", "description": "Issue summary"}
          },
          "required": ["issue"]
        }
      }
    }
  ]
}
EOF
)

TOOL_RESP=$(curl -s "${VLLM_HOST}/v1/chat/completions" \
    -H "Content-Type: application/json" \
    -d "$TOOL_TEST_PAYLOAD" || true)

if echo "$TOOL_RESP" | grep -q '"tool_calls"'; then
    echo "  [PASS] vLLM natively returned tool_calls!"
else
    echo "  [WARN] 'tool_calls' was not found in response. If reviews encounter errors,"
    echo "         make sure vLLM was started with:"
    echo "         --enable-auto-tool-choice --tool-call-parser hermes"
fi

# ------------------------------------------------------------------------------
# 4. Configure OpenCodeReview
# ------------------------------------------------------------------------------
echo ""
echo "[Step 4/5] Configuring OpenCodeReview (ocr) to use vLLM..."
ocr config set provider vllm
ocr config set custom_providers.vllm.url "${VLLM_HOST}/v1"
ocr config set custom_providers.vllm.protocol openai
ocr config set custom_providers.vllm.model "${MODEL}"
ocr config set custom_providers.vllm.api_key token
ocr config set custom_providers.vllm.timeout_sec 300
ocr config set max_tokens 4096

# ------------------------------------------------------------------------------
# 5. Run OCR LLM Connection Test
# ------------------------------------------------------------------------------
echo ""
echo "[Step 5/5] Running 'ocr llm test'..."
echo "----------------------------------------------------------"
ocr llm test
echo "----------------------------------------------------------"

echo ""
echo "=========================================================="
echo "  vLLM setup and test completed successfully!"
echo "=========================================================="
echo "You can now run code reviews in any git repository:"
echo "  1. Review uncommitted changes:  ocr review"
echo "  2. Review staged changes:       ocr review --staged"
echo "  3. Scan full files:             ocr scan --path <dir>"
echo "  4. Launch WebUI Viewer:         ocr viewer"
echo "=========================================================="
