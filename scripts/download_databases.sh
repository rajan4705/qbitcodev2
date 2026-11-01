#!/usr/bin/env bash
# ==============================================================================
# QbitCode Threat Intelligence & Vector Database Downloader
#
# Downloads:
# 1. SCA OSV Vulnerability Database (:8082) from Hugging Face dataset:
#    saad0503/qbitcode-dbs (sca_vulnerabilities_db.zip -> 185k+ advisories)
# 2. SAST NVD CVE Index (:8080) from Hugging Face dataset:
#    saad0503/qbitcode-dbs (sast_nvd_index.zip)
# 3. Qdrant Vector DB Storage (:6333) from Hugging Face dataset:
#    saad0503/qbitcode-dbs (qdrant_storage.tar.gz -> 206k threat vectors)
# 4. Jina Code Embeddings 1.5B model from official Hugging Face repository:
#    jinaai/jina-code-embeddings-1.5b
# ==============================================================================
set -e

SCRIPT_DIR="$(cd "$(dirname "${BASH_SOURCE[0]}")" && pwd)"
WORKSPACE_ROOT="$(cd "$SCRIPT_DIR/.." && pwd)"
SERVICES_DIR="$WORKSPACE_ROOT/services/services"
HF_DATASET_URL="https://huggingface.co/datasets/saad0503/qbitcode-dbs/resolve/main"

echo "========================================================================"
echo "🛡️  QbitCode Database & Model Downloader"
echo "========================================================================"
echo "Destination: $SERVICES_DIR"
echo ""

mkdir -p "$SERVICES_DIR/sca"
mkdir -p "$SERVICES_DIR/sast/data"
mkdir -p "$SERVICES_DIR/sast/models"
mkdir -p "$SERVICES_DIR/sast/Qdrant_Api"

# Helper function to download with curl or wget
download_file() {
  local url="$1"
  local dest="$2"
  echo ">>> Downloading $(basename "$dest")..."
  if command -v curl >/dev/null 2>&1; then
    curl -L --progress-bar -f -o "$dest" "$url"
  elif command -v wget >/dev/null 2>&1; then
    wget -q --show-progress -O "$dest" "$url"
  else
    echo "❌ Error: Neither curl nor wget found in PATH."
    exit 1
  fi
}

# 1. SCA Package Vulnerability SQLite Database (:8082)
echo "[1/4] Checking SCA Vulnerability Database (vulnerabilities.db)..."
SCA_DB="$SERVICES_DIR/sca/vulnerabilities.db"
if [ -f "$SCA_DB" ] && [ -s "$SCA_DB" ]; then
  echo "    ✓ SCA database already present ($(ls -lh "$SCA_DB" | awk '{print $5}'))."
else
  TMP_ZIP="/tmp/sca_vulnerabilities_db.zip"
  download_file "$HF_DATASET_URL/sca_vulnerabilities_db.zip" "$TMP_ZIP"
  echo "    Extracting to $SCA_DB..."
  unzip -o -q "$TMP_ZIP" -d "$SERVICES_DIR/sca/"
  rm -f "$TMP_ZIP"
  echo "    ✓ SCA database installed successfully!"
fi

# 2. SAST NVD CVE Index (:8080)
echo ""
echo "[2/4] Checking SAST NVD CVE Index (nvd_index.json)..."
NVD_JSON="$SERVICES_DIR/sast/data/nvd_index.json"
if [ -f "$NVD_JSON" ] && [ -s "$NVD_JSON" ]; then
  echo "    ✓ NVD index already present ($(ls -lh "$NVD_JSON" | awk '{print $5}'))."
else
  TMP_ZIP="/tmp/sast_nvd_index.zip"
  download_file "$HF_DATASET_URL/sast_nvd_index.zip" "$TMP_ZIP"
  echo "    Extracting to $SERVICES_DIR/sast/data/..."
  unzip -o -q "$TMP_ZIP" -d "$SERVICES_DIR/sast/data/"
  rm -f "$TMP_ZIP"
  echo "    ✓ NVD index installed successfully!"
fi

# 3. Qdrant Vector DB Storage (:6333)
echo ""
echo "[3/4] Checking Qdrant Vector Storage (206k vectors)..."
QDRANT_DIR="$SERVICES_DIR/sast/Qdrant_Api/qdrant_storage"
if [ -e "$QDRANT_DIR" ]; then
  echo "    ✓ Qdrant storage already present at $QDRANT_DIR."
else
  TMP_TAR="/tmp/qdrant_storage.tar.gz"
  download_file "$HF_DATASET_URL/qdrant_storage.tar.gz" "$TMP_TAR"
  echo "    Extracting vector storage..."
  tar -xzf "$TMP_TAR" -C "$SERVICES_DIR/sast/Qdrant_Api/"
  rm -f "$TMP_TAR"
  echo "    ✓ Qdrant vector storage installed successfully!"
fi

# 4. Jina Code Embeddings 1.5B Model from official Hugging Face
echo ""
echo "[4/4] Checking Jina Code Embeddings 1.5B Model..."
JINA_DIR="$SERVICES_DIR/sast/models/jina-code-embeddings-1.5b"
if [ -d "$JINA_DIR" ] && [ -f "$JINA_DIR/model.safetensors" ]; then
  echo "    ✓ Jina Code Embeddings 1.5B model already present at $JINA_DIR."
else
  echo "    Downloading official jinaai/jina-code-embeddings-1.5b from Hugging Face..."
  mkdir -p "$JINA_DIR"
  python3 -c "
from huggingface_hub import snapshot_download
import sys

print('Downloading official jinaai/jina-code-embeddings-1.5b checkpoint...')
snapshot_download(
    repo_id='jinaai/jina-code-embeddings-1.5b',
    local_dir='$JINA_DIR',
    local_dir_use_symlinks=False,
    ignore_patterns=['*.bin', '*.msgpack', '*.h5', '*.ot']
)
print('✓ Jina Code Embeddings 1.5B downloaded successfully!')
" || {
    echo "⚠️ Python download failed. Trying git lfs clone..."
    git clone https://huggingface.co/jinaai/jina-code-embeddings-1.5b "$JINA_DIR" || true
  }
fi

echo ""
echo "========================================================================"
echo "🎉 ALL DATABASES & MODELS READY!"
echo "========================================================================"
echo "You can now start all security services at any time via:"
echo "  ./scripts/launch_services.sh"
echo "or run the complete pipeline:"
echo "  qbitcode"
echo "========================================================================"
