#!/usr/bin/env bash
# ==============================================================================
# Export Built Docker Images for Offline Transfer to Another Machine
# ==============================================================================
set -e

SCRIPT_DIR="$(cd "$(dirname "${BASH_SOURCE[0]}")" && pwd)"
WORKSPACE_ROOT="$(cd "$SCRIPT_DIR/.." && pwd)"
OUTPUT_DIR="${1:-$WORKSPACE_ROOT/exported_images}"

DOCKER_CMD="docker"
if ! docker ps >/dev/null 2>&1; then
  DOCKER_CMD="sudo docker"
fi

mkdir -p "$OUTPUT_DIR"

echo "============================================================================"
echo "EXPORTING CODECHECKER DOCKER IMAGES FOR OFFLINE TRANSFER"
echo "  • Output Directory: $OUTPUT_DIR"
echo "============================================================================"

# 1. Export Qdrant
echo ""
echo "[1/3] Exporting codechecker-qdrant:latest (~1.5 GB compressed)..."
$DOCKER_CMD save codechecker-qdrant:latest | gzip > "$OUTPUT_DIR/codechecker-qdrant.tar.gz"
echo "  ✓ Saved: $OUTPUT_DIR/codechecker-qdrant.tar.gz"

# 2. Export SCA
echo ""
echo "[2/3] Exporting codechecker-sca:latest (~300 MB compressed)..."
$DOCKER_CMD save codechecker-sca:latest | gzip > "$OUTPUT_DIR/codechecker-sca.tar.gz"
echo "  ✓ Saved: $OUTPUT_DIR/codechecker-sca.tar.gz"

# 3. Export SAST
echo ""
echo "[3/3] Exporting codechecker-sast:latest (~6.5 GB compressed)..."
$DOCKER_CMD save codechecker-sast:latest | gzip > "$OUTPUT_DIR/codechecker-sast.tar.gz"
echo "  ✓ Saved: $OUTPUT_DIR/codechecker-sast.tar.gz"

# 4. Copy management scripts
echo ""
echo "Copying deployment scripts into $OUTPUT_DIR..."
cp "$SCRIPT_DIR/deploy.sh" "$OUTPUT_DIR/"
cp "$SCRIPT_DIR/down.sh" "$OUTPUT_DIR/"
cp "$SCRIPT_DIR/verify.sh" "$OUTPUT_DIR/"
cp "$SCRIPT_DIR/docker-compose.yml" "$OUTPUT_DIR/"
cp "$SCRIPT_DIR/README.md" "$OUTPUT_DIR/"

# Create quick-load script for target machine
cat << 'EOF' > "$OUTPUT_DIR/load_and_run.sh"
#!/usr/bin/env bash
set -e

DOCKER_CMD="docker"
if ! docker ps >/dev/null 2>&1; then
  DOCKER_CMD="sudo docker"
fi

echo "Loading Codechecker Docker images..."
gunzip -c codechecker-qdrant.tar.gz | $DOCKER_CMD load
gunzip -c codechecker-sca.tar.gz    | $DOCKER_CMD load
gunzip -c codechecker-sast.tar.gz   | $DOCKER_CMD load

echo "✓ Images loaded successfully! Starting containers..."
./deploy.sh
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
echo "       sudo ./load_and_run.sh"
echo "============================================================================"

