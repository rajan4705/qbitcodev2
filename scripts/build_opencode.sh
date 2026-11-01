#!/usr/bin/env bash
# ==============================================================================
# Build, verify, and link OpenCode / QbitCode CLI using Bun
# ==============================================================================
set -e

SCRIPT_DIR="$(cd "$(dirname "${BASH_SOURCE[0]}")" && pwd)"
if [ -d "$SCRIPT_DIR/../terminal-tui" ]; then
  OPENCODE_DIR="$(cd "$SCRIPT_DIR/../terminal-tui" && pwd)"
else
  OPENCODE_DIR="$(cd "$SCRIPT_DIR/../opencode" && pwd)"
fi
BIN_DIR="$HOME/.local/bin"

echo "=================================================="
echo "🔨 Building OpenCode / QbitCode CLI"
echo "📂 Project Dir: $OPENCODE_DIR"
echo "=================================================="

# Check for bun
if ! command -v bun >/dev/null 2>&1; then
  echo "❌ Error: 'bun' command not found in PATH."
  exit 1
fi

cd "$OPENCODE_DIR"

echo "⏳ Running Bun build (single target, skip-install)..."
bun run --cwd packages/cli build --single --skip-install

DIST_BIN="$OPENCODE_DIR/packages/cli/dist/cli-linux-x64/bin/opencode"

if [ ! -f "$DIST_BIN" ]; then
  # Fallback check if dist folder uses alternate naming
  DIST_BIN=$(find "$OPENCODE_DIR/packages/cli/dist" -type f -name "opencode" | head -n 1)
fi

if [ -z "$DIST_BIN" ] || [ ! -f "$DIST_BIN" ]; then
  echo "❌ Error: Built binary not found in $OPENCODE_DIR/packages/cli/dist"
  exit 1
fi

chmod +x "$DIST_BIN"
mkdir -p "$BIN_DIR"

# Ensure ~/.local/bin/opencode points to the newly built binary
ln -sf "$DIST_BIN" "$BIN_DIR/opencode"

echo ""
echo "=================================================="
echo "🔍 Verifying OpenCode / QbitCode Installation"
echo "=================================================="
echo "Artifact: $DIST_BIN ($(ls -lh "$DIST_BIN" | awk '{print $5}'))"
echo "Symlink:  $BIN_DIR/qbitcode -> $(readlink "$BIN_DIR/qbitcode")"
echo "Symlink:  $BIN_DIR/opencode -> $(readlink "$BIN_DIR/opencode")"
echo ""

echo "Executing: $BIN_DIR/opencode --version"
"$BIN_DIR/opencode" --version

echo ""
echo "✅ OpenCode / QbitCode built, verified, and installed successfully!"
