#!/usr/bin/env python3
"""
File System Activity Simulator
Simulates malware file system behavior patterns
Tests: File monitoring, suspicious file operations, encryption simulation
"""

import os
import time
import shutil
import random
import hashlib
import tempfile
from pathlib import Path

class FileSystemSimulator:
    def __init__(self):
        self.temp_dir = tempfile.mkdtemp(prefix="malware_sim_")
        self.created_files = []
        self.active = True
        
        print(f"Using temporary directory: {self.temp_dir}")
    
    def simulate_file_encryption(self):
        """Simulate ransomware-like file encryption"""
        print("=== Simulating File Encryption (Ransomware-like) ===")
        
        # Create test files to "encrypt"
        test_files = [
            "document.txt",
            "photo.jpg", 
            "spreadsheet.xlsx",
            "presentation.pptx",
            "database.db"
        ]
        
        # Create original files with random content
        for filename in test_files:
            file_path = os.path.join(self.temp_dir, filename)
            
            with open(file_path, 'wb') as f:
                # Create files with different entropy levels
                if filename.endswith('.txt'):
                    # Low entropy - text file
                    content = "This is a test document.\n" * 100
                    f.write(content.encode())
                else:
                    # Higher entropy - binary-like data
                    content = bytes([random.randint(0, 255) for _ in range(2048)])
                    f.write(content)
            
            self.created_files.append(file_path)
            print(f"Created test file: {file_path}")
        
        # Simulate encryption process
        for file_path in self.created_files[:]:
            if not self.active:
                break
                
            print(f"Encrypting file: {file_path}")
            
            # Read original file
            with open(file_path, 'rb') as f:
                original_data = f.read()
            
            # Simulate encryption (simple XOR for demonstration)
            key = b"MALWARE_SIM_KEY_123"
            encrypted_data = bytes(a ^ b for a, b in zip(original_data, (key * (len(original_data) // len(key) + 1))[:len(original_data)]))
            
            # Create encrypted version
            encrypted_path = file_path + ".encrypted"
            with open(encrypted_path, 'wb') as f:
                f.write(encrypted_data)
            
            # Remove original
            os.remove(file_path)
            self.created_files.remove(file_path)
            self.created_files.append(encrypted_path)
            
            print(f"File encrypted: {encrypted_path}")
            time.sleep(1)
        
        # Create ransom note
        ransom_note = os.path.join(self.temp_dir, "RANSOM_NOTE.txt")
        with open(ransom_note, 'w') as f:
            f.write("=== TEST RANSOM NOTE (SIMULATION ONLY) ===\n")
            f.write("Your files have been encrypted for testing purposes.\n")
            f.write("This is a simulation for malware analysis testing.\n")
            f.write(f"Simulation ID: {random.randint(1000, 9999)}\n")
            f.write(f"Timestamp: {time.ctime()}\n")
        
        self.created_files.append(ransom_note)
        print(f"Created ransom note: {ransom_note}")
    
    def simulate_data_collection(self):
        """Simulate malware collecting system information"""
        print("=== Simulating Data Collection ===")
        
        collection_dir = os.path.join(self.temp_dir, "collected_data")
        os.makedirs(collection_dir, exist_ok=True)
        
        # Simulate collecting various system information
        collections = [
            ("system_info.txt", self.collect_system_info),
            ("process_list.txt", self.collect_process_info),
            ("network_info.txt", self.collect_network_info),
            ("user_files.txt", self.collect_user_files),
            ("browser_data.txt", self.collect_browser_data)
        ]
        
        for filename, collector_func in collections:
            if not self.active:
                break
                
            file_path = os.path.join(collection_dir, filename)
            print(f"Collecting data: {filename}")
            
            try:
                data = collector_func()
                with open(file_path, 'w') as f:
                    f.write(f"=== {filename.upper()} (TEST COLLECTION) ===\n")
                    f.write(f"Collection time: {time.ctime()}\n")
                    f.write(f"Collector PID: {os.getpid()}\n")
                    f.write("\nData:\n")
                    f.write(data)
                
                self.created_files.append(file_path)
                print(f"Collected data saved to: {file_path}")
                
            except Exception as e:
                print(f"Failed to collect {filename}: {e}")
            
            time.sleep(2)
    
    def collect_system_info(self):
        """Collect system information"""
        info = []
        
        try:
            # OS information
            with open('/proc/version', 'r') as f:
                info.append(f"OS Version: {f.read().strip()}")
        except:
            info.append("OS Version: Unable to read")
        
        try:
            # CPU information
            with open('/proc/cpuinfo', 'r') as f:
                cpu_lines = f.readlines()[:10]  # First 10 lines
                info.append("CPU Info:")
                info.extend(cpu_lines)
        except:
            info.append("CPU Info: Unable to read")
        
        try:
            # Memory information
            with open('/proc/meminfo', 'r') as f:
                mem_lines = f.readlines()[:5]  # First 5 lines
                info.append("Memory Info:")
                info.extend(mem_lines)
        except:
            info.append("Memory Info: Unable to read")
        
        return '\n'.join(info)
    
    def collect_process_info(self):
        """Collect running processes"""
        try:
            import subprocess
            result = subprocess.run(['ps', 'aux'], capture_output=True, text=True)
            return result.stdout
        except:
            return "Unable to collect process information"
    
    def collect_network_info(self):
        """Collect network configuration"""
        info = []
        
        try:
            # Network interfaces
            interfaces = os.listdir('/sys/class/net/')
            info.append(f"Network Interfaces: {', '.join(interfaces)}")
        except:
            info.append("Network Interfaces: Unable to read")
        
        try:
            # Routing table
            with open('/proc/net/route', 'r') as f:
                routes = f.readlines()[:10]  # First 10 lines
                info.append("Routing Table:")
                info.extend(routes)
        except:
            info.append("Routing Table: Unable to read")
        
        return '\n'.join(info)
    
    def collect_user_files(self):
        """Simulate collecting user file listings"""
        info = []
        
        # Common directories to scan
        scan_dirs = ['/home', '/tmp', '/var/tmp']
        
        for scan_dir in scan_dirs:
            if os.path.exists(scan_dir):
                info.append(f"\n=== Files in {scan_dir} ===")
                try:
                    for root, dirs, files in os.walk(scan_dir):
                        # Limit depth and number of files
                        if root.count(os.sep) - scan_dir.count(os.sep) > 2:
                            continue
                        if len(files) > 20:
                            files = files[:20]
                        
                        for file in files:
                            info.append(os.path.join(root, file))
                        
                        if len(info) > 100:  # Limit total entries
                            break
                    
                except Exception as e:
                    info.append(f"Error scanning {scan_dir}: {e}")
        
        return '\n'.join(info)
    
    def collect_browser_data(self):
        """Simulate collecting browser-related data"""
        info = []
        
        # Common browser data locations (most won't exist)
        browser_paths = [
            "~/.mozilla/firefox",
            "~/.config/google-chrome",
            "~/.config/chromium",
            "~/.cache/mozilla",
            "~/.cache/google-chrome"
        ]
        
        for path in browser_paths:
            expanded_path = os.path.expanduser(path)
            if os.path.exists(expanded_path):
                info.append(f"Found browser data: {expanded_path}")
                try:
                    files = os.listdir(expanded_path)
                    info.append(f"  Files: {files[:10]}")  # First 10 files
                except:
                    info.append("  Unable to list files")
            else:
                info.append(f"Browser path not found: {expanded_path}")
        
        return '\n'.join(info)
    
    def simulate_file_modifications(self):
        """Simulate suspicious file modifications"""
        print("=== Simulating File Modifications ===")
        
        # Create files with different types
        file_types = [
            ("script.sh", "#!/bin/bash\necho 'Test script'\n"),
            ("config.conf", "[settings]\ntest=true\ndebug=false\n"),
            ("data.json", '{"test": true, "data": [1,2,3,4,5]}'),
            ("binary.dat", bytes([i % 256 for i in range(1000)])),
            ("log.txt", "Log entry 1\nLog entry 2\nLog entry 3\n")
        ]
        
        for filename, content in file_types:
            if not self.active:
                break
                
            file_path = os.path.join(self.temp_dir, filename)
            
            # Create original file
            if isinstance(content, str):
                with open(file_path, 'w') as f:
                    f.write(content)
            else:
                with open(file_path, 'wb') as f:
                    f.write(content)
            
            print(f"Created file: {file_path}")
            self.created_files.append(file_path)
            
            # Simulate modifications
            time.sleep(1)
            
            # Modify file multiple times
            for i in range(3):
                print(f"Modifying {filename} (attempt {i+1})")
                
                if isinstance(content, str):
                    with open(file_path, 'a') as f:
                        f.write(f"\nModification {i+1} at {time.ctime()}")
                else:
                    with open(file_path, 'ab') as f:
                        f.write(bytes([random.randint(0, 255) for _ in range(100)]))
                
                time.sleep(1)
    
    def simulate_file_hiding(self):
        """Simulate attempts to hide files"""
        print("=== Simulating File Hiding Attempts ===")
        
        hidden_dir = os.path.join(self.temp_dir, ".hidden_malware")
        os.makedirs(hidden_dir, exist_ok=True)
        
        # Create hidden files
        hidden_files = [
            ".malware_config",
            ".persistence_script", 
            ".data_cache",
            "...hidden_payload",  # Multiple dots to hide in listings
            " hidden_space"       # Leading space
        ]
        
        for filename in hidden_files:
            if not self.active:
                break
                
            file_path = os.path.join(hidden_dir, filename)
            
            with open(file_path, 'w') as f:
                f.write(f"Hidden malware simulation file: {filename}\n")
                f.write(f"Created: {time.ctime()}\n")
                f.write(f"PID: {os.getpid()}\n")
                f.write("This is a test file for malware analysis\n")
            
            # Try to change permissions to make it less visible
            try:
                os.chmod(file_path, 0o600)  # Owner read/write only
                print(f"Created hidden file: {file_path}")
            except:
                print(f"Created file (permission change failed): {file_path}")
            
            self.created_files.append(file_path)
            time.sleep(1)
    
    def create_high_entropy_files(self):
        """Create files with high entropy to trigger detection"""
        print("=== Creating High Entropy Files ===")
        
        entropy_files = [
            ("packed_executable", 4096, "random"),
            ("encrypted_data.enc", 8192, "random"),
            ("compressed.dat", 2048, "semi_random"),
            ("normal_text.txt", 1024, "text"),
            ("mixed_content.bin", 3072, "mixed")
        ]
        
        for filename, size, entropy_type in entropy_files:
            if not self.active:
                break
                
            file_path = os.path.join(self.temp_dir, filename)
            
            print(f"Creating {entropy_type} entropy file: {filename}")
            
            with open(file_path, 'wb') as f:
                if entropy_type == "random":
                    # High entropy - random data
                    data = bytes([random.randint(0, 255) for _ in range(size)])
                elif entropy_type == "semi_random":
                    # Medium entropy - some patterns
                    data = b''
                    for i in range(size):
                        if i % 10 == 0:
                            data += b'PATTERN'
                        else:
                            data += bytes([random.randint(0, 255)])
                elif entropy_type == "text":
                    # Low entropy - text
                    text = "This is normal text content. " * (size // 30)
                    data = text.encode()[:size]
                elif entropy_type == "mixed":
                    # Mixed entropy
                    data = b"HEADER" + bytes([random.randint(0, 255) for _ in range(size-12)]) + b"FOOTER"
                
                f.write(data)
            
            self.created_files.append(file_path)
            time.sleep(1)
    
    def run_all_simulations(self):
        """Run all file system simulations"""
        print("=== File System Activity Simulator Starting ===")
        print(f"Process PID: {os.getpid()}")
        print(f"Working directory: {self.temp_dir}")
        
        try:
            # Run simulations in sequence
            self.simulate_data_collection()
            time.sleep(2)
            
            self.simulate_file_modifications()
            time.sleep(2)
            
            self.create_high_entropy_files()
            time.sleep(2)
            
            self.simulate_file_hiding()
            time.sleep(2)
            
            self.simulate_file_encryption()
            
            print(f"\n=== File System Simulation Summary ===")
            print(f"Total files created: {len(self.created_files)}")
            print(f"Temporary directory: {self.temp_dir}")
            print("Simulation complete - files will be cleaned up on exit")
            
        except Exception as e:
            print(f"Simulation error: {e}")
    
    def cleanup(self):
        """Clean up created files and directories"""
        print("\n=== Cleaning up simulation files ===")
        
        try:
            # Remove all created files
            for file_path in self.created_files:
                try:
                    if os.path.exists(file_path):
                        os.remove(file_path)
                        print(f"Removed: {file_path}")
                except Exception as e:
                    print(f"Failed to remove {file_path}: {e}")
            
            # Remove temporary directory
            shutil.rmtree(self.temp_dir, ignore_errors=True)
            print(f"Removed temporary directory: {self.temp_dir}")
            
        except Exception as e:
            print(f"Cleanup error: {e}")

def main():
    """Main function"""
    simulator = FileSystemSimulator()
    
    try:
        simulator.run_all_simulations()
        
        # Keep files for a bit to allow analysis
        print("\nKeeping files for 30 seconds to allow analysis...")
        time.sleep(30)
        
    except KeyboardInterrupt:
        print("\nReceived interrupt, stopping...")
        simulator.active = False
    except Exception as e:
        print(f"Simulation error: {e}")
    finally:
        simulator.cleanup()

if __name__ == "__main__":
    main()