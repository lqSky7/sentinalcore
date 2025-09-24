#!/bin/bash
# Sentinal Startup Script

echo "===========================================" 
echo "  SENTINAL - Linux Malware Analysis Tool  "
echo "==========================================="
echo ""

# Get the directory where the script is located
SCRIPT_DIR="$(cd "$(dirname "${BASH_SOURCE[0]}")" && pwd)"
cd "$SCRIPT_DIR"

# Check if virtual environment exists
if [ ! -d "venv" ]; then
    echo "Creating Python virtual environment..."
    python3 -m venv venv
    if [ $? -ne 0 ]; then
        echo "ERROR: Failed to create virtual environment"
        echo "Please ensure Python 3 is installed"
        exit 1
    fi
fi

# Activate virtual environment
echo "Activating virtual environment..."
source venv/bin/activate

# Install dependencies if needed
if [ ! -f "venv/.deps_installed" ]; then
    echo "Installing Python dependencies..."
    pip install --upgrade pip
    pip install -r requirements.txt
    if [ $? -eq 0 ]; then
        touch venv/.deps_installed
        echo "Dependencies installed successfully"
    else
        echo "WARNING: Some dependencies may have failed to install"
    fi
fi

# Compile C monitor if needed
if [ ! -f "backend/process_monitor" ]; then
    echo "Compiling process monitor..."
    cd monitor
    if make clean && make; then
        if make install; then
            echo "Process monitor compiled and installed"
        else
            echo "WARNING: Monitor installation failed, copying manually..."
            cp process_monitor ../backend/ 2>/dev/null || echo "Manual copy failed"
        fi
    else
        echo "WARNING: Process monitor compilation failed"
        echo "System will use fallback monitoring methods"
    fi
    cd ..
fi

# Make sample files executable
chmod +x samples/test_malware.py 2>/dev/null
chmod +x samples/test_malware.sh 2>/dev/null

# Create necessary directories
mkdir -p results logs /tmp/sentinal

echo ""
echo "Starting Sentinal Analysis Server..."
echo "Platform: $(uname -s) on $(uname -m)"
echo "Web Interface: http://localhost:3000"
echo "Sample files available in samples/ directory"
echo ""
echo "⚠️  SECURITY WARNING ⚠️"
echo "This tool executes potentially malicious files!"
echo "Only run in isolated environments (VMs/containers)"
echo ""
echo "Press Ctrl+C to stop the server"
echo "=========================================="
echo ""

# Use the clean UI
if [ -f "frontend/index_clean.html" ]; then
    cp frontend/index_clean.html frontend/index.html
fi

# Start the Flask application
cd backend
export FLASK_ENV=development
python3 app_simple.py