#!/bin/bash
# VirusTotal Integration Demo for SentinalCore
# This script demonstrates all VirusTotal scanning capabilities

echo "=================================================="
echo "  SentinalCore VirusTotal Integration Demo"
echo "=================================================="
echo ""

# Check if API key is provided
if [ -z "$1" ] && [ -z "$VT_API_KEY" ]; then
    echo "❌ Error: VirusTotal API key required"
    echo ""
    echo "Usage:"
    echo "  $0 YOUR_API_KEY [file_path]"
    echo ""
    echo "Or set environment variable:"
    echo "  export VT_API_KEY=your_api_key"
    echo "  $0 [file_path]"
    echo ""
    echo "Get your API key from: https://www.virustotal.com/gui/user/YOUR_USERNAME/apikey"
    exit 1
fi

# Set API key
if [ -n "$1" ] && [ "$1" != "skip" ]; then
    API_KEY="$1"
    FILE_ARG="$2"
else
    API_KEY="$VT_API_KEY"
    FILE_ARG="$1"
fi

# Activate virtual environment
if [ -d "venv" ]; then
    echo "📦 Activating virtual environment..."
    source venv/bin/activate
else
    echo "⚠️  Virtual environment not found. Creating one..."
    python3 -m venv venv
    source venv/bin/activate
    pip install -r requirements.txt
fi

echo ""
echo "✅ Environment ready"
echo ""

# Function to scan a file
scan_file() {
    local file="$1"
    echo "=================================================="
    echo "  Scanning: $file"
    echo "=================================================="
    echo ""
    
    if [ ! -f "$file" ]; then
        echo "❌ File not found: $file"
        return 1
    fi
    
    python3 backend/virustotal_scanner.py \
        --api-key "$API_KEY" \
        --file "$file"
    
    echo ""
    return 0
}

# If specific file provided, scan it
if [ -n "$FILE_ARG" ]; then
    scan_file "$FILE_ARG"
    exit $?
fi

# Otherwise, run demonstration with sample files
echo "🎯 VirusTotal Scanning Demo"
echo ""
echo "This demo will show different scanning scenarios:"
echo "1. Scanning test files"
echo "2. Hash-based lookups (fast)"
echo "3. JSON output format"
echo ""

# Check for sample files
echo "📁 Checking for sample files..."
SAMPLES_DIR="samples"

if [ ! -d "$SAMPLES_DIR" ]; then
    echo "⚠️  Samples directory not found"
    echo ""
    echo "To scan your own file:"
    echo "  $0 $API_KEY /path/to/your/file.apk"
    exit 1
fi

# Find test files
TEST_FILES=$(find "$SAMPLES_DIR" -type f \( -name "*.py" -o -name "*.sh" -o -name "*.c" \) | head -3)

if [ -z "$TEST_FILES" ]; then
    echo "⚠️  No sample files found in $SAMPLES_DIR"
    echo ""
    echo "To scan your own file:"
    echo "  $0 $API_KEY /path/to/your/file.apk"
    exit 1
fi

echo "Found test files:"
echo "$TEST_FILES"
echo ""

# Scan first test file
FIRST_FILE=$(echo "$TEST_FILES" | head -1)
echo "📊 Demo 1: Standard Scan"
scan_file "$FIRST_FILE"

echo ""
echo "⏸️  Press Enter to continue to next demo..."
read

# Demo 2: Hash check (fast lookup)
echo ""
echo "📊 Demo 2: Hash-Based Lookup (Fast)"
echo "=================================================="
echo ""
echo "This checks if the file is already in VirusTotal database"
echo "without uploading it again - much faster!"
echo ""

FILE_HASH=$(python3 -c "
from backend.virustotal_scanner import VirusTotalScanner
scanner = VirusTotalScanner('$API_KEY')
print(scanner.calculate_file_hash('$FIRST_FILE'))
")

echo "File hash: $FILE_HASH"
echo ""

python3 -c "
from backend.virustotal_scanner import VirusTotalScanner
import json

scanner = VirusTotalScanner('$API_KEY')
report = scanner.check_existing_report('$FILE_HASH')

if report and 'error' not in report:
    parsed = scanner.parse_scan_results(report)
    print(f\"✅ Found existing report!\")
    print(f\"Threat Level: {parsed['threat_level']}\")
    print(f\"Detection Rate: {parsed['detection_rate']}%\")
    print(f\"Malicious Detections: {parsed['malicious_count']}/{parsed['total_engines']}\")
else:
    print('ℹ️  File not found in database - would need to upload')
"

echo ""
echo "⏸️  Press Enter to continue to next demo..."
read

# Demo 3: JSON output
echo ""
echo "📊 Demo 3: JSON Output Format"
echo "=================================================="
echo ""
echo "This shows machine-readable JSON output for integration"
echo ""

python3 backend/virustotal_scanner.py \
    --api-key "$API_KEY" \
    --file "$FIRST_FILE" \
    --json | python3 -m json.tool

echo ""
echo "=================================================="
echo "  Demo Complete!"
echo "=================================================="
echo ""
echo "Next Steps:"
echo ""
echo "1️⃣  Scan your own files:"
echo "   $0 $API_KEY /path/to/malware.apk"
echo ""
echo "2️⃣  Use the shell wrapper:"
echo "   ./virustotal_scan.sh $API_KEY samples/test_malware.apk"
echo ""
echo "3️⃣  Use via API (start server with ./start_sentinal.sh):"
echo "   curl -X POST http://localhost:3000/api/virustotal/scan \\"
echo "     -H 'Content-Type: application/json' \\"
echo "     -d '{\"file_path\":\"/path/to/file\", \"api_key\":\"$API_KEY\"}'"
echo ""
echo "4️⃣  Set environment variable for easier use:"
echo "   export VT_API_KEY=$API_KEY"
echo "   python3 backend/virustotal_scanner.py --file your_file.apk"
echo ""
echo "📚 For more information, see VIRUSTOTAL.md"
echo ""
