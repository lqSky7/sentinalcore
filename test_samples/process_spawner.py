#!/usr/bin/env python3
"""
Process Spawner Test Sample
Simulates malware that creates multiple child processes
Tests: Process tree analysis, process monitoring, suspicious process detection
"""

import os
import sys
import time
import subprocess
import multiprocessing
from pathlib import Path

def create_child_process(process_id, duration=5):
    """Create a child process that performs various activities"""
    print(f"Child process {process_id} (PID: {os.getpid()}) started")
    
    # Simulate some file operations
    temp_file = f"/tmp/child_process_{process_id}_{os.getpid()}.txt"
    with open(temp_file, 'w') as f:
        f.write(f"Child process {process_id} data\n")
        f.write(f"PID: {os.getpid()}\n")
        f.write(f"PPID: {os.getppid()}\n")
        f.write("This is test data for malware analysis\n")
    
    # Simulate some system calls
    try:
        # Read /proc/version (common malware reconnaissance)
        with open('/proc/version', 'r') as f:
            version = f.read().strip()
        print(f"Child {process_id}: System version: {version[:50]}...")
        
        # List processes (reconnaissance activity)
        result = subprocess.run(['ps', 'aux'], capture_output=True, text=True)
        process_count = len(result.stdout.split('\n'))
        print(f"Child {process_id}: Found {process_count} processes")
        
        # Network-like activity (without actual network calls)
        print(f"Child {process_id}: Simulating network activity...")
        
    except Exception as e:
        print(f"Child {process_id} error: {e}")
    
    # Sleep to allow monitoring
    time.sleep(duration)
    
    # Cleanup
    try:
        os.remove(temp_file)
        print(f"Child {process_id}: Cleaned up temp file")
    except:
        pass
    
    print(f"Child process {process_id} (PID: {os.getpid()}) terminating")

def spawn_grandchild(child_id):
    """Spawn a grandchild process to test deep process trees"""
    print(f"Grandchild of {child_id} (PID: {os.getpid()}) started")
    
    # Simulate suspicious file access
    suspicious_paths = ['/etc/passwd', '/etc/hosts', '/proc/cpuinfo']
    for path in suspicious_paths:
        try:
            with open(path, 'r') as f:
                content = f.read(100)  # Read just first 100 chars
            print(f"Grandchild {child_id}: Accessed {path}")
        except Exception as e:
            print(f"Grandchild {child_id}: Failed to access {path}: {e}")
    
    time.sleep(3)
    print(f"Grandchild of {child_id} terminating")

def main():
    """Main process spawner function"""
    print(f"=== Process Spawner Test Sample ===")
    print(f"Main process PID: {os.getpid()}")
    print(f"PPID: {os.getppid()}")
    
    # Create multiple child processes
    num_children = 5
    processes = []
    
    print(f"Spawning {num_children} child processes...")
    
    for i in range(num_children):
        process = multiprocessing.Process(
            target=create_child_process, 
            args=(i, 8)
        )
        process.start()
        processes.append(process)
        print(f"Started child process {i} with PID: {process.pid}")
        time.sleep(1)  # Stagger process creation
    
    # Create some grandchildren from a separate process
    grandchild_process = multiprocessing.Process(
        target=spawn_grandchild,
        args=(99,)
    )
    grandchild_process.start()
    processes.append(grandchild_process)
    
    # Simulate main process activity
    print("Main process performing activities...")
    
    # Simulate reconnaissance
    try:
        # Check system information
        with open('/proc/meminfo', 'r') as f:
            meminfo = f.readline()
        print(f"Memory info: {meminfo.strip()}")
        
        # Check network interfaces
        result = subprocess.run(['ls', '/sys/class/net/'], capture_output=True, text=True)
        interfaces = result.stdout.strip().split()
        print(f"Network interfaces: {interfaces}")
        
        # Create some temporary files
        for i in range(3):
            temp_file = f"/tmp/main_process_file_{i}.dat"
            with open(temp_file, 'wb') as f:
                # Write some binary data to trigger entropy analysis
                import random
                data = bytes([random.randint(0, 255) for _ in range(1024)])
                f.write(data)
            print(f"Created temp file: {temp_file}")
    
    except Exception as e:
        print(f"Main process error: {e}")
    
    # Wait for children to complete
    print("Waiting for child processes to complete...")
    for i, process in enumerate(processes):
        process.join()
        print(f"Child process {i} completed")
    
    # Cleanup temp files
    import glob
    temp_files = glob.glob("/tmp/main_process_file_*.dat")
    for temp_file in temp_files:
        try:
            os.remove(temp_file)
            print(f"Cleaned up: {temp_file}")
        except:
            pass
    
    print("=== Process Spawner Test Complete ===")

if __name__ == "__main__":
    main()