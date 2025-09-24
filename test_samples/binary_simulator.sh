#!/bin/bash

# Compiled Binary Test Sample
# This creates suspicious patterns that compiled malware might exhibit
# Tests: Binary analysis, entropy detection, process behavior

echo "=== Compiled Binary Simulator ==="
echo "Process PID: $$"
echo "Starting binary-like behavior simulation..."

# Simulate process reconnaissance
echo "Performing system reconnaissance..."

# Check system information
cat /proc/version 2>/dev/null | head -1
cat /proc/cpuinfo 2>/dev/null | grep "model name" | head -1
cat /proc/meminfo 2>/dev/null | grep "MemTotal" | head -1

# Simulate network reconnaissance
echo "Checking network configuration..."
ls /sys/class/net/ 2>/dev/null
cat /proc/net/route 2>/dev/null | head -3

# Simulate file system reconnaissance  
echo "Scanning file system..."
find /tmp -name "*.log" -o -name "*.conf" 2>/dev/null | head -10
find /var/log -name "*.log" 2>/dev/null | head -5

# Create suspicious files
echo "Creating suspicious files..."
TEMP_DIR="/tmp/binary_sim_$$"
mkdir -p "$TEMP_DIR"

# Create configuration file
cat > "$TEMP_DIR/config.dat" << EOF
# Binary simulator configuration
target_host=127.0.0.1
target_port=8080
persistence_enabled=true
stealth_mode=true
encryption_key=ABCD1234567890EF
command_server=evil.test.domain.com
EOF

# Create a "packed" file with high entropy
echo "Creating high entropy file..."
dd if=/dev/urandom of="$TEMP_DIR/packed_payload.bin" bs=1024 count=4 2>/dev/null

# Create fake persistence script
cat > "$TEMP_DIR/.persistence.sh" << 'EOF'
#!/bin/bash
# Fake persistence script (harmless)
echo "Persistence script executed at $(date)" >> /tmp/persistence.log
crontab -l 2>/dev/null | grep -v "persistence" > /tmp/cron_backup
echo "0 * * * * /bin/echo 'Hourly persistence check' >> /tmp/persistence.log" >> /tmp/cron_backup
# NOTE: Not actually installing crontab for safety
echo "Would install crontab entry (simulation)"
EOF
chmod +x "$TEMP_DIR/.persistence.sh"

# Simulate network activity
echo "Simulating network activity..."

# Attempt connections (will fail but show in monitoring)
for port in 80 443 8080 9999; do
    echo "Attempting connection to 127.0.0.1:$port"
    timeout 2 bash -c "echo test | nc 127.0.0.1 $port" 2>/dev/null || echo "Connection to $port failed (expected)"
    sleep 1
done

# Simulate data exfiltration staging
echo "Staging data for exfiltration..."
cat > "$TEMP_DIR/exfil_data.txt" << EOF
=== SIMULATED EXFILTRATION DATA ===
Timestamp: $(date)
System: $(uname -a)
User: $(whoami)
Working Directory: $(pwd)
Process Tree:
$(ps -ef | grep $$ | head -5)

Network Interfaces:
$(ip addr show 2>/dev/null || ifconfig 2>/dev/null | head -20)

Fake sensitive data:
user:password123
admin:secretpass
database_connection:localhost:5432
api_key:sk_test_123456789
EOF

# Simulate process spawning
echo "Spawning child processes..."

# Background processes
for i in {1..3}; do
    {
        echo "Child process $i (PID: $$) started"
        sleep 10
        echo "Child process $i completing"
    } &
    echo "Spawned background process $i"
    sleep 2
done

# Simulate memory operations
echo "Performing memory operations..."

# Create large files to trigger memory usage
for i in {1..3}; do
    dd if=/dev/zero of="$TEMP_DIR/memory_test_$i.dat" bs=1M count=10 2>/dev/null
    echo "Created memory test file $i (10MB)"
done

# Simulate encryption/decryption
echo "Simulating encryption operations..."

# Simple XOR "encryption" of a file
INPUT_FILE="$TEMP_DIR/exfil_data.txt"
ENCRYPTED_FILE="$TEMP_DIR/encrypted_data.enc"

# XOR encryption (demonstrative only)
python3 - << EOF
import sys
key = b"MALWARE_TEST_KEY_123"
try:
    with open("$INPUT_FILE", "rb") as f:
        data = f.read()
    
    encrypted = bytes(a ^ b for a, b in zip(data, (key * (len(data) // len(key) + 1))[:len(data)]))
    
    with open("$ENCRYPTED_FILE", "wb") as f:
        f.write(encrypted)
    
    print("File encrypted successfully")
except Exception as e:
    print(f"Encryption failed: {e}")
EOF

# Simulate self-modification attempt
echo "Simulating self-modification..."
SCRIPT_COPY="$TEMP_DIR/modified_binary.sh"
cp "$0" "$SCRIPT_COPY" 2>/dev/null
echo "# Modified at $(date)" >> "$SCRIPT_COPY"
echo "# This demonstrates self-modifying behavior" >> "$SCRIPT_COPY"

# Simulate anti-analysis techniques
echo "Simulating anti-analysis techniques..."

# Check for debugging/analysis tools
ANALYSIS_TOOLS="gdb strace ltrace valgrind"
for tool in $ANALYSIS_TOOLS; do
    if command -v $tool >/dev/null 2>&1; then
        echo "Analysis tool detected: $tool"
    fi
done

# Check if running under ptrace (simplified check)
if grep -q "TracerPid:" /proc/self/status 2>/dev/null; then
    TRACER_PID=$(grep "TracerPid:" /proc/self/status | awk '{print $2}')
    if [ "$TRACER_PID" != "0" ]; then
        echo "Process being traced by PID: $TRACER_PID"
        echo "Anti-analysis: Tracer detected!"
    fi
fi

# Simulate timing-based evasion
echo "Performing timing checks..."
START_TIME=$(date +%s)
sleep 1
END_TIME=$(date +%s)
ELAPSED=$((END_TIME - START_TIME))

if [ $ELAPSED -gt 2 ]; then
    echo "Timing anomaly detected - possible sandboxing"
else
    echo "Timing check passed"
fi

# Wait for background processes
echo "Waiting for child processes to complete..."
wait

# Clean up (simulate self-deletion)
echo "Performing cleanup..."

# Don't actually delete the script, just simulate it
echo "Would delete temporary files:"
ls -la "$TEMP_DIR/"

# Actually clean up temp directory
rm -rf "$TEMP_DIR"
echo "Cleaned up temporary directory: $TEMP_DIR"

echo "=== Binary simulation complete ==="
echo "Total runtime: $(($(date +%s) - $(date +%s)))" 2>/dev/null || echo "Runtime calculation failed"