# VirusTotal Integration for SentinalCore

## Overview
SentinalCore now includes VirusTotal API v3 integration for comprehensive malware scanning. This allows you to scan any file (including APKs) using VirusTotal's extensive malware database.

## Setup

### 1. Get VirusTotal API Key
1. Sign up at [VirusTotal](https://www.virustotal.com/)
2. Go to your profile and get your API key
3. Free tier allows 500 requests/day, 4 requests/minute

### 2. Configure API Key

You can provide the API key in two ways:

**Option A: Environment Variable (Recommended)**
```bash
# Add to your shell profile (~/.bashrc, ~/.zshrc, etc.)
export VT_API_KEY="your_api_key_here"

# Or create a .env file in the project root
echo "VT_API_KEY=your_api_key_here" > .env
```

**Option B: Pass directly in command/API call**
```bash
# Pass as command argument
python3 backend/virustotal_scanner.py --api-key YOUR_KEY --file malware.apk
```

## Usage

### Method 1: Command Line Interface

#### Basic scan:
```bash
python3 backend/virustotal_scanner.py --api-key YOUR_KEY --file samples/test_malware.apk
```

#### Using environment variable:
```bash
export VT_API_KEY="your_key"
python3 backend/virustotal_scanner.py --file samples/malware.apk
```

#### Quick scan without waiting:
```bash
python3 backend/virustotal_scanner.py --file suspicious.exe --no-wait
```

#### JSON output:
```bash
python3 backend/virustotal_scanner.py --file malware.apk --json
```

### Method 2: Using Shell Script

```bash
# Make script executable
chmod +x virustotal_scan.sh

# Run scan
./virustotal_scan.sh YOUR_API_KEY samples/test_malware.apk

# Or with environment variable
export VT_API_KEY="your_key"
./virustotal_scan.sh skip samples/test_malware.apk
```

### Method 3: REST API (via SentinalCore Server)

Start the server:
```bash
./start_sentinal.sh
```

Then use the API endpoints:

#### Scan a file:
```bash
curl -X POST http://localhost:3000/api/virustotal/scan \
  -H "Content-Type: application/json" \
  -d '{
    "file_path": "/path/to/malware.apk",
    "api_key": "your_api_key",
    "wait_for_result": true
  }'
```

#### Check if file hash exists:
```bash
curl -X POST http://localhost:3000/api/virustotal/check-hash \
  -H "Content-Type: application/json" \
  -d '{
    "file_path": "/path/to/file.apk",
    "api_key": "your_api_key"
  }'
```

#### Check VirusTotal status:
```bash
curl http://localhost:3000/api/virustotal/status
```

### Method 4: Python API

```python
from backend.virustotal_scanner import VirusTotalScanner

# Initialize scanner
scanner = VirusTotalScanner(api_key="your_api_key")

# Scan a file
result = scanner.scan_file("samples/malware.apk")

# Check results
if result['success']:
    print(f"Threat Level: {result['results']['threat_level']}")
    print(f"Detection Rate: {result['results']['detection_rate']}%")
    print(f"Malicious: {result['results']['malicious_count']}")
```

## Features

### Supported File Types
- **APK files** (Android applications)
- **Executables** (.exe, .dll, .so)
- **Scripts** (.sh, .py, .js, .ps1)
- **Documents** (.pdf, .doc, .xls)
- **Archives** (.zip, .rar, .tar)
- **Any other file type** (up to 650MB)

### Scan Capabilities
- ✅ Automatic hash checking (avoid duplicate scans)
- ✅ Large file support (>32MB files)
- ✅ Real-time scan status monitoring
- ✅ Comprehensive threat analysis
- ✅ 70+ antivirus engine results
- ✅ Threat classification and labeling
- ✅ Historical scan data

### Scan Results Include
- **Detection Statistics**: How many engines flagged the file
- **Threat Level**: CLEAN, LOW, MEDIUM, HIGH
- **Threat Label**: Common malware name/family
- **File Metadata**: Hashes (SHA256, SHA1, MD5), file type, size
- **Engine Details**: Individual results from 70+ antivirus engines
- **Reputation Score**: VirusTotal community reputation
- **Permalink**: Link to full web report

## Examples

### Scan an APK file:
```bash
python3 backend/virustotal_scanner.py \
  --api-key YOUR_KEY \
  --file /path/to/suspicious.apk
```

**Example Output:**
```
================================================================================
VIRUSTOTAL SCAN RESULTS
================================================================================

📁 File: suspicious.apk
📏 Size: 2,458,392 bytes
🔑 SHA256: a1b2c3d4e5f6...

🎯 THREAT LEVEL: HIGH
🏷️  Threat Label: Android.Trojan.Generic

📊 Detection Statistics:
   • Total Engines: 62
   • Malicious: 45
   • Suspicious: 3
   • Clean: 14
   • Detection Rate: 72.58%

🚨 Malicious Detections (45):
   • Kaspersky: HEUR:Trojan.AndroidOS.Generic
   • Avast: Android:Malware-gen [Trj]
   • ESET-NOD32: Android/TrojanDropper.Agent.BWB
   • Microsoft: Trojan:AndroidOS/FakeApp
   ...

🔗 Full Report: https://www.virustotal.com/gui/file/a1b2c3d4...
```

### Scan multiple files:
```bash
for file in samples/*.apk; do
    echo "Scanning $file..."
    python3 backend/virustotal_scanner.py --file "$file"
done
```

### Check existing report (fast):
```bash
# Calculate hash first
FILE_HASH=$(shasum -a 256 malware.apk | awk '{print $1}')

# Check if already scanned
curl -X POST http://localhost:3000/api/virustotal/check-hash \
  -H "Content-Type: application/json" \
  -d "{\"file_hash\": \"$FILE_HASH\", \"api_key\": \"your_key\"}"
```

## API Rate Limits

**Free Tier:**
- 500 requests per day
- 4 requests per minute

**Premium Tier:**
- Higher limits available
- Priority scanning
- Advanced features

## Troubleshooting

### API Key Issues:
```bash
# Test API key
curl --request GET \
  --url 'https://www.virustotal.com/api/v3/files/upload_url' \
  --header 'x-apikey: YOUR_API_KEY'
```

### File Not Found:
Make sure to use absolute paths or correct relative paths:
```bash
# Use absolute path
python3 backend/virustotal_scanner.py --file /Users/user/Desktop/malware.apk

# Or relative from project root
python3 backend/virustotal_scanner.py --file ./samples/test_malware.apk
```

### Rate Limit Exceeded:
Wait 60 seconds or upgrade to premium:
```
Error: API Error 429: Quota exceeded
```

### Large File Upload Timeout:
Increase max wait time:
```bash
python3 backend/virustotal_scanner.py \
  --file large_file.apk \
  --max-wait 600  # 10 minutes
```

## Integration with SentinalCore

When using the full SentinalCore analysis:

1. **Static Analysis** → File signature, entropy, strings
2. **VirusTotal Scan** → Cloud-based multi-engine detection
3. **Dynamic Analysis** → Sandboxed execution monitoring
4. **AI Analysis** → Gemini AI threat assessment

This provides comprehensive multi-layer malware detection!

## Security Notes

- ⚠️ **Never share your API key publicly**
- ⚠️ **Files uploaded to VirusTotal become public** after scan
- ⚠️ Use private scanning (premium) for sensitive files
- ⚠️ Hash checks don't upload files (safe for sensitive data)

## Resources

- [VirusTotal API Documentation](https://developers.virustotal.com/reference/overview)
- [Get API Key](https://www.virustotal.com/gui/user/YOUR_USERNAME/apikey)
- [Rate Limits](https://support.virustotal.com/hc/en-us/articles/115002118525-Rate-limits)

## Support

For issues or questions:
1. Check API key is valid
2. Verify file exists and is readable
3. Check network connectivity
4. Review rate limits
5. Check SentinalCore logs
