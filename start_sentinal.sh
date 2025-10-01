#!/bin/bash
# Sentinal Startup Script

echo "Starting Sentinal Analysis Framework..."

# Activate virtual environment
source venv/bin/activate

# Check if monitor is compiled
if [ ! -f "backend/process_monitor" ]; then
    echo "Compiling process monitor..."
    cd monitor && make && make install && cd ..
fi

# Start the Flask application
echo "Starting web server on http://localhost:3000"
cd backend
python3 app.py
