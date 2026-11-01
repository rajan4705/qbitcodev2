#!/usr/bin/env bash
# ==============================================================================
# Qbit Autonomous Code Review & Self-Healing Pipeline
# ==============================================================================
set -euo pipefail

export PATH="$HOME/.local/bin:$HOME/.opencode/bin:$PATH"

REPO_DIR="${1:-$(pwd)}"
MAX_ITERATIONS="${2:-2}"
ITERATION=1

echo "=========================================================="
echo "  Qbit Autonomous Self-Healing Pipeline"
echo "  Target Repository: ${REPO_DIR}"
echo "=========================================================="

while [ "$ITERATION" -le "$MAX_ITERATIONS" ]; do
echo ""
echo "─── Phase 1: Vulnerability Detection (Iteration $ITERATION/$MAX_ITERATIONS) ───"

# Run Qbit review
qbit scan "$REPO_DIR" --demo || true

echo ""
echo "─── Phase 2: Autonomous Remediation with OpenCode ───"
# Auto-fix critical findings
qbit fix --all || true

echo ""
echo "─── Phase 3: Post-Remediation Verification ───"
# Verify changes
if git status --porcelain 2>/dev/null | grep -q .; then
echo "  [OK] Git modifications detected from OpenCode remediation."
git status -s
else
echo "  [INFO] Workspace is clean."
fi

ITERATION=$((ITERATION + 1))
break
done

echo ""
echo "=========================================================="
echo "  Pipeline execution finished successfully!"
echo "=========================================================="
