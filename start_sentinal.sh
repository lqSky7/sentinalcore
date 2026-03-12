#!/bin/bash
# Sentinal Startup Script

set -euo pipefail

SCRIPT_DIR="$(cd "$(dirname "${BASH_SOURCE[0]}")" && pwd)"
cd "$SCRIPT_DIR"

echo "Starting Sentinal Analysis Framework..."

# macOS network/process monitoring often requires elevated permissions.
# Set USE_SUDO=0 to run without sudo.
USE_SUDO="${USE_SUDO:-1}"
if [ "$USE_SUDO" = "1" ] && [ "${EUID:-$(id -u)}" -ne 0 ]; then
    echo "Re-running with sudo (USE_SUDO=1) for enhanced monitoring access..."
    exec sudo -E bash "$0" "$@"
fi

# Activate virtual environment
if [ -f "venv/bin/activate" ]; then
    source venv/bin/activate
fi

# Ensure old/stale Flask processes do not hold port 3000
EXISTING_PIDS="$(lsof -ti tcp:3000 -sTCP:LISTEN 2>/dev/null || true)"
if [ -n "$EXISTING_PIDS" ]; then
    echo "Stopping existing process(es) on port 3000: $EXISTING_PIDS"
    kill $EXISTING_PIDS 2>/dev/null || true
    sleep 1
    STILL_RUNNING="$(lsof -ti tcp:3000 -sTCP:LISTEN 2>/dev/null || true)"
    if [ -n "$STILL_RUNNING" ]; then
        echo "Force stopping remaining process(es): $STILL_RUNNING"
        kill -9 $STILL_RUNNING 2>/dev/null || true
    fi
fi

# Check if monitor is compiled
if [ ! -f "backend/process_monitor" ]; then
    echo "Compiling process monitor..."
    cd monitor && make && make install && cd ..
fi

# Start the Flask application with reloader disabled (avoids dropped requests)
echo "Starting web server on http://localhost:3000"
cd backend
export FLASK_DEBUG=0
export FLASK_USE_RELOADER=0
exec python3 app.py
