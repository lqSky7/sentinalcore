#!/bin/bash
# VirusTotal Scan Wrapper Script
# Usage: ./virustotal_scan.sh <api_key> <file_path>

set -e

# Check arguments
if [ $# -lt 2 ]; then
    echo "Usage: $0 <api_key> <file_path>"
    echo ""
    echo "Examples:"
    echo "  $0 YOUR_API_KEY samples/test_malware.apk"
    echo "  $0 YOUR_API_KEY /path/to/suspicious.exe"
    echo ""
    echo "Or set VT_API_KEY environment variable:"
    echo "  export VT_API_KEY=your_api_key"
    echo "  $0 skip samples/malware.apk"
    exit 1
fi

API_KEY="$1"
FILE_PATH="$2"

# Check if using environment variable
if [ "$API_KEY" = "skip" ] || [ "$API_KEY" = "-" ]; then
    if [ -z "$VT_API_KEY" ]; then
        echo "Error: VT_API_KEY environment variable not set"
        exit 1
    fi
    API_KEY="$VT_API_KEY"
fi

# Check if file exists
if [ ! -f "$FILE_PATH" ]; then
    echo "Error: File not found: $FILE_PATH"
    exit 1
fi

echo "=================================================="
echo "  VirusTotal Scanner - SentinalCore"
echo "=================================================="
echo ""
echo "File: $FILE_PATH"
echo "Starting scan..."
echo ""

# Activate virtual environment if it exists
if [ -d "venv" ]; then
    source venv/bin/activate
fi

# Run Python scanner
python3 backend/virustotal_scanner.py \
    --api-key "$API_KEY" \
    --file "$FILE_PATH"

echo ""
echo "Scan complete!"
