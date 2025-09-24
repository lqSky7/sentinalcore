#!/usr/bin/env python3
"""
System Call Simulator
Generates various system calls to test eBPF monitoring
Tests: System call tracing, suspicious syscall patterns, kernel interaction monitoring
"""

import os
import sys
import time
import mmap
import signal
import subprocess
import ctypes
from ctypes import util
import tempfile

class SystemCallSimulator:
    def __init__(self):
        self.active = True
        self.temp_files = []
        
    def simulate_memory_operations(self):
        """Simulate suspicious memory operations"""
        print("=== Simulating Memory Operations ===")
        
        # Test mmap operations
        print("Testing mmap operations...")
        
        try:
            # Create a temporary file
            temp_file = tempfile.NamedTemporaryFile(delete=False)
            temp_file.write(b"A" * 4096)  # 4KB of data
            temp_file.close()
            self.temp_files.append(temp_file.name)
            
            # mmap the file
            with open(temp_file.name, 'r+b') as f:
                # Map file into memory
                mm = mmap.mmap(f.fileno(), 0)
                print(f"Memory mapped file: {temp_file.name}")
                
                # Read from mapped memory
                data = mm[:100]
                print(f"Read from mmap: {len(data)} bytes")
                
                # Write to mapped memory
                mm[0:10] = b"MODIFIED!!"
                print("Modified mapped memory")
                
                # Sync changes
                mm.flush()
                mm.close()
                print("Unmapped memory")
                
        except Exception as e:
            print(f"Memory mapping failed: {e}")
        
        time.sleep(2)
        
        # Test memory allocation
        print("Testing memory allocation...")
        try:
            # Allocate large chunks of memory
            memory_chunks = []
            for i in range(10):
                chunk = bytearray(1024 * 1024)  # 1MB chunks
                chunk[0] = i  # Write to it
                memory_chunks.append(chunk)
                print(f"Allocated memory chunk {i}: {len(chunk)} bytes")
                time.sleep(0.5)
            
            # Free memory
            del memory_chunks
            print("Freed allocated memory")
            
        except Exception as e:
            print(f"Memory allocation failed: {e}")
    
    def simulate_process_operations(self):
        """Simulate process-related system calls"""
        print("=== Simulating Process Operations ===")
        
        # Test fork operations
        print("Testing process forking...")
        
        try:
            # Create child process
            pid = os.fork()
            
            if pid == 0:
                # Child process
                print(f"Child process started (PID: {os.getpid()})")
                
                # Child does some work
                time.sleep(2)
                
                # Test exec operations
                try:
                    # Execute a simple command
                    os.execv('/bin/echo', ['echo', 'Child process exec test'])
                except Exception as e:
                    print(f"Child exec failed: {e}")
                    os._exit(1)
            else:
                # Parent process
                print(f"Parent process created child PID: {pid}")
                
                # Wait for child
                status = os.waitpid(pid, 0)
                print(f"Child process {pid} finished with status: {status}")
                
        except Exception as e:
            print(f"Fork operation failed: {e}")
    
    def simulate_file_operations(self):
        """Simulate file-related system calls"""
        print("=== Simulating File Operations ===")
        
        # Test various file operations
        operations = [
            ("create", self.test_file_create),
            ("read", self.test_file_read),
            ("write", self.test_file_write),
            ("stat", self.test_file_stat),
            ("chmod", self.test_file_chmod),
            ("link", self.test_file_link),
            ("unlink", self.test_file_unlink)
        ]
        
        for op_name, op_func in operations:
            if not self.active:
                break
                
            print(f"Testing {op_name} operations...")
            try:
                op_func()
            except Exception as e:
                print(f"{op_name} operation failed: {e}")
            time.sleep(1)
    
    def test_file_create(self):
        """Test file creation syscalls"""
        temp_file = f"/tmp/syscall_test_{os.getpid()}_{int(time.time())}.txt"
        
        # Test different creation methods
        fd = os.open(temp_file, os.O_CREAT | os.O_WRONLY, 0o644)
        os.write(fd, b"Test data for syscall simulation")
        os.close(fd)
        
        self.temp_files.append(temp_file)
        print(f"Created file using os.open: {temp_file}")
    
    def test_file_read(self):
        """Test file reading syscalls"""
        if not self.temp_files:
            return
            
        test_file = self.temp_files[0]
        
        # Test different read methods
        fd = os.open(test_file, os.O_RDONLY)
        data = os.read(fd, 1024)
        os.close(fd)
        print(f"Read {len(data)} bytes using os.read")
        
        # Test with regular file operations
        with open(test_file, 'r') as f:
            content = f.read()
            print(f"Read {len(content)} chars using file.read")
    
    def test_file_write(self):
        """Test file writing syscalls"""
        if not self.temp_files:
            return
            
        test_file = self.temp_files[0]
        
        # Append to file
        fd = os.open(test_file, os.O_WRONLY | os.O_APPEND)
        os.write(fd, b"\nAppended data via syscall")
        os.fsync(fd)  # Force sync to disk
        os.close(fd)
        print("Appended data using os.write and fsync")
    
    def test_file_stat(self):
        """Test file stat syscalls"""
        if not self.temp_files:
            return
            
        test_file = self.temp_files[0]
        
        # Various stat operations
        stat_info = os.stat(test_file)
        print(f"File stat - size: {stat_info.st_size}, mode: {oct(stat_info.st_mode)}")
        
        # Test lstat
        lstat_info = os.lstat(test_file)
        print(f"File lstat - inode: {lstat_info.st_ino}")
        
        # Test access
        readable = os.access(test_file, os.R_OK)
        writable = os.access(test_file, os.W_OK)
        print(f"File access - readable: {readable}, writable: {writable}")
    
    def test_file_chmod(self):
        """Test permission change syscalls"""
        if not self.temp_files:
            return
            
        test_file = self.temp_files[0]
        
        # Change permissions
        os.chmod(test_file, 0o755)
        print(f"Changed file permissions to 755")
        
        time.sleep(0.5)
        
        os.chmod(test_file, 0o644)
        print(f"Changed file permissions to 644")
    
    def test_file_link(self):
        """Test link-related syscalls"""
        if not self.temp_files:
            return
            
        test_file = self.temp_files[0]
        link_file = test_file + ".link"
        
        # Create hard link
        try:
            os.link(test_file, link_file)
            self.temp_files.append(link_file)
            print(f"Created hard link: {link_file}")
            
            # Create symbolic link
            symlink_file = test_file + ".symlink"
            os.symlink(test_file, symlink_file)
            self.temp_files.append(symlink_file)
            print(f"Created symbolic link: {symlink_file}")
            
        except Exception as e:
            print(f"Link creation failed: {e}")
    
    def test_file_unlink(self):
        """Test file deletion syscalls"""
        # Create a temporary file just for deletion
        temp_file = f"/tmp/delete_test_{os.getpid()}.txt"
        
        with open(temp_file, 'w') as f:
            f.write("File to be deleted")
        
        print(f"Created file for deletion: {temp_file}")
        time.sleep(0.5)
        
        # Delete using unlink
        os.unlink(temp_file)
        print(f"Deleted file using unlink: {temp_file}")
    
    def simulate_network_syscalls(self):
        """Simulate network-related system calls"""
        print("=== Simulating Network System Calls ===")
        
        import socket
        
        try:
            # Test socket creation
            sock = socket.socket(socket.AF_INET, socket.SOCK_STREAM)
            print("Created TCP socket")
            
            # Test socket options
            sock.setsockopt(socket.SOL_SOCKET, socket.SO_REUSEADDR, 1)
            print("Set socket options")
            
            # Test bind (to localhost only)
            sock.bind(('127.0.0.1', 0))  # Bind to any available port
            addr = sock.getsockname()
            print(f"Bound socket to {addr}")
            
            # Test listen
            sock.listen(5)
            print("Socket listening")
            
            time.sleep(2)
            
            # Close socket
            sock.close()
            print("Closed socket")
            
        except Exception as e:
            print(f"Network syscall simulation failed: {e}")
        
        try:
            # Test UDP socket
            udp_sock = socket.socket(socket.AF_INET, socket.SOCK_DGRAM)
            print("Created UDP socket")
            
            # Test sendto/recvfrom (to localhost)
            udp_sock.bind(('127.0.0.1', 0))
            addr = udp_sock.getsockname()
            print(f"UDP socket bound to {addr}")
            
            udp_sock.close()
            print("Closed UDP socket")
            
        except Exception as e:
            print(f"UDP syscall simulation failed: {e}")
    
    def simulate_signal_operations(self):
        """Simulate signal-related system calls"""
        print("=== Simulating Signal Operations ===")
        
        def signal_handler(signum, frame):
            print(f"Received signal {signum}")
        
        try:
            # Install signal handlers
            signal.signal(signal.SIGUSR1, signal_handler)
            signal.signal(signal.SIGUSR2, signal_handler)
            print("Installed signal handlers for SIGUSR1 and SIGUSR2")
            
            # Send signals to self
            os.kill(os.getpid(), signal.SIGUSR1)
            time.sleep(0.5)
            os.kill(os.getpid(), signal.SIGUSR2)
            time.sleep(0.5)
            
            # Test alarm
            signal.alarm(1)
            print("Set alarm for 1 second")
            time.sleep(2)
            
        except Exception as e:
            print(f"Signal operation failed: {e}")
    
    def simulate_ipc_operations(self):
        """Simulate inter-process communication syscalls"""
        print("=== Simulating IPC Operations ===")
        
        try:
            # Test pipe creation
            r_fd, w_fd = os.pipe()
            print(f"Created pipe: read_fd={r_fd}, write_fd={w_fd}")
            
            # Write to pipe
            message = b"IPC test message"
            os.write(w_fd, message)
            print("Wrote message to pipe")
            
            # Read from pipe
            data = os.read(r_fd, 1024)
            print(f"Read from pipe: {data.decode()}")
            
            # Close pipe
            os.close(r_fd)
            os.close(w_fd)
            print("Closed pipe")
            
        except Exception as e:
            print(f"IPC operation failed: {e}")
    
    def simulate_time_operations(self):
        """Simulate time-related system calls"""
        print("=== Simulating Time Operations ===")
        
        try:
            # Test time-related syscalls
            current_time = time.time()
            print(f"Current time: {current_time}")
            
            # Test nanosleep
            print("Testing nanosleep (0.1 seconds)...")
            time.sleep(0.1)
            
            # Test clock operations
            try:
                import os
                # Try to access clock-related files
                with open('/proc/uptime', 'r') as f:
                    uptime = f.read().strip()
                print(f"System uptime: {uptime}")
                
                with open('/proc/loadavg', 'r') as f:
                    loadavg = f.read().strip()
                print(f"Load average: {loadavg}")
                
            except Exception as e:
                print(f"Clock info access failed: {e}")
                
        except Exception as e:
            print(f"Time operation failed: {e}")
    
    def run_all_simulations(self):
        """Run all system call simulations"""
        print("=== System Call Simulator Starting ===")
        print(f"Process PID: {os.getpid()}")
        print(f"PPID: {os.getppid()}")
        
        # List of all simulations
        simulations = [
            ("Memory Operations", self.simulate_memory_operations),
            ("File Operations", self.simulate_file_operations), 
            ("Network System Calls", self.simulate_network_syscalls),
            ("Signal Operations", self.simulate_signal_operations),
            ("IPC Operations", self.simulate_ipc_operations),
            ("Time Operations", self.simulate_time_operations),
            ("Process Operations", self.simulate_process_operations)  # Last because it forks
        ]
        
        for sim_name, sim_func in simulations:
            if not self.active:
                break
                
            print(f"\n{'='*50}")
            print(f"Starting: {sim_name}")
            print('='*50)
            
            try:
                sim_func()
            except Exception as e:
                print(f"Simulation {sim_name} failed: {e}")
            
            print(f"Completed: {sim_name}")
            time.sleep(2)
        
        print(f"\n=== System Call Simulation Complete ===")
        self.cleanup()
    
    def cleanup(self):
        """Clean up temporary files"""
        print("Cleaning up temporary files...")
        
        for temp_file in self.temp_files:
            try:
                if os.path.exists(temp_file):
                    os.unlink(temp_file)
                    print(f"Removed: {temp_file}")
            except Exception as e:
                print(f"Failed to remove {temp_file}: {e}")

def main():
    """Main function"""
    simulator = SystemCallSimulator()
    
    try:
        simulator.run_all_simulations()
    except KeyboardInterrupt:
        print("\nReceived interrupt, stopping...")
        simulator.active = False
        simulator.cleanup()
    except Exception as e:
        print(f"Simulation error: {e}")
        simulator.cleanup()

if __name__ == "__main__":
    main()