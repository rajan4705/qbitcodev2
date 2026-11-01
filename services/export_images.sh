#!/usr/bin/env bash
# ==============================================================================
# Export Built Docker Images for Offline Transfer to Another Machine
# ==============================================================================
set -e

SCRIPT_DIR="$(cd "$(dirname "${BASH_SOURCE[0]}")" && pwd)"
WORKSPACE_ROOT="$(cd "$SCRIPT_DIR/.." && pwd)"

OUTPUT_DIR="$WORKSPACE_ROOT/exported_images"
WITH_VLLM=false

# Parse flags and arguments
for arg in "$@"; do
  case "$arg" in
    --with-vllm)
      WITH_VLLM=true
      ;;
    --help|-h)
      echo "Usage: $0 [--with-vllm] [output_directory]"
      exit 0
      ;;
    *)
      if [[ "$arg" != -* ]]; then
        OUTPUT_DIR="$arg"
      fi
      ;;
  esac
done

if [ "${EXPORT_VLLM:-false}" = "true" ]; then
  WITH_VLLM=true
fi

# Robust Docker execution helper
run_docker() {
  if docker ps >/dev/null 2>&1; then
    docker "$@"
  elif sg docker -c "docker ps" >/dev/null 2>&1; then
    sg docker -c "docker $(printf '%q ' "$@")"
  else
    sudo docker "$@"
  fi
}

mkdir -p "$OUTPUT_DIR"

echo "============================================================================"
echo "EXPORTING CODECHECKER DOCKER IMAGES FOR OFFLINE TRANSFER"
echo "  • Output Directory : $OUTPUT_DIR"
echo "  • Include vLLM     : $WITH_VLLM"
echo "============================================================================"

# 1. Export Qdrant
echo ""
echo "[1/4] Exporting codechecker-qdrant:latest (~1.5 GB compressed)..."
run_docker save codechecker-qdrant:latest | gzip > "$OUTPUT_DIR/codechecker-qdrant.tar.gz"
echo "  ✓ Saved: $OUTPUT_DIR/codechecker-qdrant.tar.gz"

# 2. Export SCA
echo ""
echo "[2/4] Exporting codechecker-sca:latest (~300 MB compressed)..."
run_docker save codechecker-sca:latest | gzip > "$OUTPUT_DIR/codechecker-sca.tar.gz"
echo "  ✓ Saved: $OUTPUT_DIR/codechecker-sca.tar.gz"

# 3. Export SAST
echo ""
echo "[3/4] Exporting codechecker-sast:latest (~6.5 GB compressed)..."
run_docker save codechecker-sast:latest | gzip > "$OUTPUT_DIR/codechecker-sast.tar.gz"
echo "  ✓ Saved: $OUTPUT_DIR/codechecker-sast.tar.gz"

# 4. Export Web Cockpit UI
echo ""
echo "[4/4] Exporting codechecker-ui:latest (~250 MB compressed)..."
run_docker save codechecker-ui:latest | gzip > "$OUTPUT_DIR/codechecker-ui.tar.gz"
echo "  ✓ Saved: $OUTPUT_DIR/codechecker-ui.tar.gz"

# 5. Optional Export: vLLM Inference Engine (GPU)
if [ "$WITH_VLLM" = "true" ]; then
  echo ""
  echo "[5/5] Exporting vllm/vllm-openai:v0.20.1 (~8 GB compressed)..."
  run_docker save vllm/vllm-openai:v0.20.1 | gzip > "$OUTPUT_DIR/vllm-openai.tar.gz"
  echo "  ✓ Saved: $OUTPUT_DIR/vllm-openai.tar.gz"
fi

# 6. Copy management scripts
echo ""
echo "Copying deployment scripts into $OUTPUT_DIR..."
cp "$SCRIPT_DIR/deploy.sh" "$OUTPUT_DIR/"
cp "$SCRIPT_DIR/down.sh" "$OUTPUT_DIR/"
cp "$SCRIPT_DIR/verify.sh" "$OUTPUT_DIR/"
cp "$SCRIPT_DIR/docker-compose.yml" "$OUTPUT_DIR/"
if [ -f "$SCRIPT_DIR/Dockerfile.ui" ]; then cp "$SCRIPT_DIR/Dockerfile.ui" "$OUTPUT_DIR/"; fi
if [ -f "$SCRIPT_DIR/Dockerfile.sast" ]; then cp "$SCRIPT_DIR/Dockerfile.sast" "$OUTPUT_DIR/"; fi
if [ -f "$SCRIPT_DIR/Dockerfile.sca" ]; then cp "$SCRIPT_DIR/Dockerfile.sca" "$OUTPUT_DIR/"; fi
if [ -f "$SCRIPT_DIR/Dockerfile.qdrant" ]; then cp "$SCRIPT_DIR/Dockerfile.qdrant" "$OUTPUT_DIR/"; fi
if [ -f "$SCRIPT_DIR/README.md" ]; then cp "$SCRIPT_DIR/README.md" "$OUTPUT_DIR/"; fi

# Create quick-load script for target machine
cat << 'EOF' > "$OUTPUT_DIR/load_and_run.sh"
#!/usr/bin/env bash
set -e

DOCKER_CMD="docker"
if ! docker ps >/dev/null 2>&1; then
  if sg docker -c "docker ps" >/dev/null 2>&1; then
    DOCKER_CMD='sg docker -c "docker'
  else
    DOCKER_CMD="sudo docker"
  fi
fi

echo "Loading Codechecker Docker images from offline archives..."
gunzip -c codechecker-qdrant.tar.gz | $DOCKER_CMD load
gunzip -c codechecker-sca.tar.gz    | $DOCKER_CMD load
gunzip -c codechecker-sast.tar.gz   | $DOCKER_CMD load
if [ -f codechecker-ui.tar.gz ]; then
  gunzip -c codechecker-ui.tar.gz   | $DOCKER_CMD load
fi
if [ -f vllm-openai.tar.gz ]; then
  echo "Loading vllm-openai.tar.gz..."
  gunzip -c vllm-openai.tar.gz      | $DOCKER_CMD load
fi

echo "✓ All container images loaded successfully!"
echo "Starting production Docker Compose stack..."

EXTRA_PROFILES=""
if [ -f vllm-openai.tar.gz ]; then
  if [ -z "$MODEL_PATH" ]; then
    if [ -d "../models/qwen2.5-coder-14b-instruct" ]; then
      export MODEL_PATH="../models/qwen2.5-coder-14b-instruct"
    elif [ -d "./models/qwen2.5-coder-14b-instruct" ]; then
      export MODEL_PATH="./models/qwen2.5-coder-14b-instruct"
    elif [ -d "../models" ]; then
      FIRST_M=$(find ../models -mindepth 1 -maxdepth 1 -type d | head -n 1 || true)
      if [ -n "$FIRST_M" ]; then export MODEL_PATH="$FIRST_M"; fi
    fi
  fi
  if [ -n "$MODEL_PATH" ] && [ -d "$MODEL_PATH" ]; then
    echo "  • Detected model directory at: $MODEL_PATH"
    EXTRA_PROFILES="--profile vllm"
  else
    echo "  ℹ️  vLLM image loaded. To launch vLLM container, provide your model path:"
    echo "      MODEL_PATH=/path/to/weights $DOCKER_CMD compose --profile vllm up -d"
  fi
fi

$DOCKER_CMD compose -f docker-compose.yml $EXTRA_PROFILES up -d || ./deploy.sh
EOF

chmod +x "$OUTPUT_DIR/load_and_run.sh"

echo ""
echo "============================================================================"
echo "EXPORT COMPLETE!"
echo "============================================================================"
echo "To deploy on another machine:"
echo "  1. Copy the '$OUTPUT_DIR' folder to the new system."
echo "  2. On the new system, run:"
echo "       cd $(basename "$OUTPUT_DIR")"
echo "       ./load_and_run.sh"
echo "============================================================================"
