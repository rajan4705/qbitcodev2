#!/usr/bin/env bash
# ==============================================================================
# OpenCodeReview (OCR) - Ollama Setup, Configuration, and Test Script
# ==============================================================================
set -euo pipefail

# Ensure ~/.local/bin is in PATH
export PATH="$HOME/.local/bin:$PATH"

# Configuration defaults (can be overridden via args or env)
MODEL="${1:-qwen2.5-coder:14b}"
OLLAMA_PORT="${OLLAMA_PORT:-11434}"
OLLAMA_HOST="http://127.0.0.1:${OLLAMA_PORT}"

echo "=========================================================="
echo "  OpenCodeReview (OCR) - Ollama Test Script"
echo "  Target Model : ${MODEL}"
echo "  Endpoint     : ${OLLAMA_HOST}/v1"
echo "=========================================================="

# ------------------------------------------------------------------------------
# 1. Verify OCR CLI installation
# ------------------------------------------------------------------------------
echo ""
echo "[Step 1/6] Checking OpenCodeReview (ocr) CLI..."
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
# 2. Verify Ollama installation (User-space fallback without sudo)
# ------------------------------------------------------------------------------
echo ""
echo "[Step 2/6] Checking Ollama installation..."
if ! command -v ollama >/dev/null 2>&1; then
    echo "  [WARN] 'ollama' command not found."
    echo "  [INFO] Installing standalone Ollama binary to $HOME/.local (No sudo required)..."
    mkdir -p "$HOME/.local/bin" "$HOME/.local/lib"
    TMP_DIR=$(mktemp -d)
    trap 'rm -rf "$TMP_DIR"' EXIT
    
    echo "  Downloading official Ollama Linux bundle..."
    curl -fL --progress-bar "https://ollama.com/download/ollama-linux-amd64.tgz" -o "$TMP_DIR/ollama.tgz"
    tar -xzf "$TMP_DIR/ollama.tgz" -C "$HOME/.local"
    chmod +x "$HOME/.local/bin/ollama"
    echo "  [OK] Ollama installed successfully into $HOME/.local/bin/ollama"
else
    echo "  [OK] Ollama found: $(which ollama)"
fi

# ------------------------------------------------------------------------------
# 3. Ensure Ollama server is running
# ------------------------------------------------------------------------------
echo ""
echo "[Step 3/6] Checking if Ollama service is running on port ${OLLAMA_PORT}..."
if ! curl -sf "${OLLAMA_HOST}/api/tags" >/dev/null 2>&1; then
    echo "  [INFO] Ollama service is not running. Starting background server..."
    mkdir -p "$HOME/.opencodereview/logs"
    nohup ollama serve > "$HOME/.opencodereview/logs/ollama.log" 2>&1 &
    OLLAMA_PID=$!
    echo "  [INFO] Started Ollama serve (PID: $OLLAMA_PID). Waiting for it to become ready..."

    for i in {1..30}; do
        if curl -sf "${OLLAMA_HOST}/api/tags" >/dev/null 2>&1; then
            echo "  [OK] Ollama server is ready."
            break
        fi
        sleep 1
        if [ "$i" -eq 30 ]; then
            echo "  [ERROR] Ollama server failed to start within 30 seconds."
            echo "  Check logs at: $HOME/.opencodereview/logs/ollama.log"
            exit 1
        fi
    done
else
    echo "  [OK] Ollama server is already responding at ${OLLAMA_HOST}"
fi

# ------------------------------------------------------------------------------
# 4. Check & Pull the Target Model
# ------------------------------------------------------------------------------
echo ""
echo "[Step 4/6] Verifying model '${MODEL}' in Ollama..."
if ! ollama list | awk '{print $1}' | grep -q "^${MODEL}"; then
    echo "  [INFO] Model '${MODEL}' not found locally. Pulling now (this may take a few minutes)..."
    ollama pull "${MODEL}"
    echo "  [OK] Model '${MODEL}' downloaded."
else
    echo "  [OK] Model '${MODEL}' is available locally."
fi

# ------------------------------------------------------------------------------
# 5. Verify Native Tool Calling Support
# ------------------------------------------------------------------------------
echo ""
echo "[Step 5/6] Testing Native Tool/Function Calling on '${MODEL}'..."
TOOL_TEST_PAYLOAD=$(cat <<EOF
{
  "model": "${MODEL}",
  "messages": [
    {"role": "user", "content": "Use the report_bug tool to report a bug in: func sub(a, b int) int { return a + b }"}
  ],
  "tools": [
    {
      "type": "function",
      "function": {
        "name": "report_bug",
        "description": "Report a code bug",
        "parameters": {
          "type": "object",
          "properties": {
            "summary": {"type": "string", "description": "Bug summary"}
          },
          "required": ["summary"]
        }
      }
    }
  ],
  "stream": false
}
EOF
)

TOOL_RESP=$(curl -s "${OLLAMA_HOST}/v1/chat/completions" \
    -H "Content-Type: application/json" \
    -d "$TOOL_TEST_PAYLOAD" || true)

if echo "$TOOL_RESP" | grep -q '"tool_calls"'; then
    echo "  [PASS] Model natively supports tool calling!"
else
    echo "  [WARN] 'tool_calls' was not parsed directly in the response."
    echo "         OpenCodeReview requires tool calling. If reviews stall with"
    echo "         'No tool calls parsed', ensure the model supports function calling."
    echo "         (Recommended: qwen2.5-coder:14b, qwen2.5-coder:32b, llama3.1)"
fi

# ------------------------------------------------------------------------------
# 6. Configure OpenCodeReview & Test Endpoint
# ------------------------------------------------------------------------------
echo ""
echo "[Step 6/6] Configuring OpenCodeReview (ocr) to use Ollama..."
ocr config set provider ollama
ocr config set custom_providers.ollama.url "${OLLAMA_HOST}/v1"
ocr config set custom_providers.ollama.protocol openai
ocr config set custom_providers.ollama.model "${MODEL}"
ocr config set custom_providers.ollama.api_key ollama
ocr config set custom_providers.ollama.timeout_sec 900

echo ""
echo "----------------------------------------------------------"
echo "  Running 'ocr llm test'..."
echo "----------------------------------------------------------"
ocr llm test

echo ""
echo "=========================================================="
echo "  Ollama setup and test completed successfully!"
echo "=========================================================="
echo "You can now run code reviews in any git repository:"
echo "  1. Review uncommitted changes:  ocr review"
echo "  2. Review staged changes:       ocr review --staged"
echo "  3. Scan full files:             ocr scan --path <dir>"
echo "  4. Launch WebUI Viewer:         ocr viewer"
echo "=========================================================="
