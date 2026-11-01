#!/usr/bin/env bash
# ==============================================================================
# Build, compile, verify, and install OpenCodeReview (OCR) using Go
# ==============================================================================
set -e

SCRIPT_DIR="$(cd "$(dirname "${BASH_SOURCE[0]}")" && pwd)"
OCR_DIR="$(cd "$SCRIPT_DIR/../code-review-engine" && pwd)"
BIN_DIR="$HOME/.local/bin"
TARGET_BIN="$BIN_DIR/ocr"

echo "=================================================="
echo "🔨 Building & Compiling OpenCodeReview (ocr)"
echo "📂 Source Dir: $OCR_DIR"
echo "🎯 Target Bin: $TARGET_BIN"
echo "=================================================="

# Detect Go binary (check PATH or Conda)
GO_BIN=""
if command -v go >/dev/null 2>&1; then
  GO_BIN="$(command -v go)"
elif [ -x "$HOME/anaconda3/bin/go" ]; then
  GO_BIN="$HOME/anaconda3/bin/go"
elif [ -x "$HOME/.local/go/bin/go" ]; then
  GO_BIN="$HOME/.local/go/bin/go"
else
  echo "❌ Error: 'go' compiler not found. Install via conda: ~/anaconda3/bin/conda install -y go"
  exit 1
fi

echo "Using Go: $($GO_BIN version)"

cd "$OCR_DIR"

mkdir -p "$BIN_DIR"

echo "⏳ Compiling Go binary (CGO_ENABLED=0)..."
CGO_ENABLED=0 "$GO_BIN" build -ldflags "-s -w" -o "$TARGET_BIN" ./cmd/opencodereview

chmod +x "$TARGET_BIN"

echo ""
echo "=================================================="
echo "🔍 Verifying OpenCodeReview (ocr) Installation"
echo "=================================================="
echo "Artifact: $TARGET_BIN ($(ls -lh "$TARGET_BIN" | awk '{print $5}'))"
echo ""

echo "Checking CLI help for configured defaults:"
"$TARGET_BIN" scan --help | grep -E "concurrency|max-tools" || true

echo ""
echo "Testing version command:"
"$TARGET_BIN" version || true

echo ""
echo "✅ OpenCodeReview (ocr) compiled, verified, and installed successfully to $TARGET_BIN!"
