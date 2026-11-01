#!/bin/bash
# ==============================================================================
# Stop Background CWE & CVE Extraction Server
# ==============================================================================

PIDS=$(pgrep -f "python.*api_server\.py.*8080")

if [ -z "$PIDS" ]; then
    echo "ℹ️  No running API Server found on port 8080."
    exit 0
fi

echo "Stopping API Server (PID: $PIDS)..."
kill $PIDS
sleep 1

# Force kill if still running
REMAINING=$(pgrep -f "python.*api_server\.py.*8080")
if [ -n "$REMAINING" ]; then
    kill -9 $REMAINING
fi

echo "✓ API Server stopped."

