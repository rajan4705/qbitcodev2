#!/usr/bin/env bash
# ==============================================================================
# Model Management & Setup for Qwen3-Coder (30B-A3B) and Qwen 2.5 Coder (14B)
# ==============================================================================
set -e

SCRIPT_DIR="$(cd "$(dirname "${BASH_SOURCE[0]}")" && pwd)"
CONDA_DIR="/home/minakshi.katoch/anaconda3"
source "$CONDA_DIR/etc/profile.d/conda.sh"

echo "================================================================="
echo "       QBIT Remediation Model & Environment Manager              "
echo "================================================================="
echo "Option 1: Qwen3-Coder-30B-A3B-Instruct (Recommended for OpenCode)"
echo "          - Native MoE Agentic Coding Model"
echo "          - Native vLLM parser: --tool-call-parser qwen3_coder"
echo "          - Direct tool calls: bash, edit, read, write (Standard OpenCode)"
echo ""
echo "Option 2: Qwen2.5-Coder-14B-Instruct"
echo "          - Current Local Setup (Preserved in scripts/start_vllm_14b.sh)"
echo "================================================================="
