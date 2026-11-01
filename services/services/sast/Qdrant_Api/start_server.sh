#!/bin/bash
# ==============================================================================
# Start CWE & CVE Extraction REST API Server in the Background
# ==============================================================================

DIR="$( cd "$( dirname "${BASH_SOURCE[0]}" )" >/dev/null 2>&1 && pwd )"
cd "$DIR"

# Check if already running
PID=$(pgrep -f "python.*api_server\.py.*8080")
if [ -n "$PID" ]; then
    echo "⚠️  API Server is already running (PID: $PID)."
    echo "   URL: http://0.0.0.0:8080"
    exit 0
fi

PYTHON_BIN="/home/minakshi.katoch/anaconda3/envs/mrk_code_vul/bin/python"
if [ ! -f "$PYTHON_BIN" ]; then
    PYTHON_BIN="python"
fi

echo "Starting CWE & CVE Extraction Server on port 8080..."
nohup "$PYTHON_BIN" api_server.py --host 0.0.0.0 --port 8080 > server.log 2>&1 &
SERVER_PID=$!

echo "✓ Server started in background with PID: $SERVER_PID"
echo "  • Local Web UI & API : http://localhost:8080"
echo "  • Network IP for Teammate : http://10.10.0.12:8080"
echo "  • Swagger API Docs : http://10.10.0.12:8080/docs"
echo "  • Logs file : $DIR/server.log"
echo ""
echo "Run './stop_server.sh' anytime to stop the server."

