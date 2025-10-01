#!/usr/bin/env python3
"""
Linux Namespace Manager for Malware Analysis Isolation

Provides secure namespace isolation using:
- PID namespace: Isolates process tree
- Mount namespace: Isolates filesystem mounts  
- Network namespace: Isolates network interfaces
- User namespace: Maps root inside to unprivileged outside
- IPC namespace: Isolates inter-process communication
"""

import os
import sys
import subprocess
import tempfile
import json
import logging
from pathlib import Path
from typing import Dict, List, Optional, Tuple
from dataclasses import dataclass
from contextlib import contextmanager

@dataclass
class NamespaceConfig:
    """Configuration for namespace isolation"""
    use_pid_ns: bool = True
    use_mount_ns: bool = True  
    use_net_ns: bool = True
    use_user_ns: bool = True
    use_ipc_ns: bool = True
    use_uts_ns: bool = True
    hostname: str = "sandbox"
    uid_map: Optional[str] = None  # "0 1000 1" maps container root to host uid 1000
    gid_map: Optional[str] = None
    use_chroot: bool = False  # Enable chroot filesystem isolation
    chroot_dir: Optional[str] = None  # Custom chroot directory
    
class NamespaceManager:
    """Manages Linux namespace isolation for secure malware analysis"""
    
    def __init__(self, config: Optional[NamespaceConfig] = None):
        self.config = config or NamespaceConfig()
        self.logger = logging.getLogger(__name__)
        self.temp_dirs = []
        
    def check_namespace_support(self) -> Dict[str, bool]:
        """Check which namespace types are supported on this system"""
        support = {}
        
        # Check for namespace support by attempting to read /proc/self/ns/
        namespace_types = ['pid', 'mnt', 'net', 'user', 'ipc', 'uts']
        
        for ns_type in namespace_types:
            ns_path = f"/proc/self/ns/{ns_type}"
            support[ns_type] = os.path.exists(ns_path)
            
        # Check for unshare command
        try:
            result = subprocess.run(['which', 'unshare'], 
                                   capture_output=True, text=True)
            support['unshare_available'] = result.returncode == 0
        except:
            support['unshare_available'] = False
            
        # Check for newuidmap/newgidmap for user namespaces
        try:
            newuidmap_result = subprocess.run(['which', 'newuidmap'], 
                                            capture_output=True, text=True)
            newgidmap_result = subprocess.run(['which', 'newgidmap'], 
                                            capture_output=True, text=True)
            support['user_ns_helpers'] = (newuidmap_result.returncode == 0 and 
                                        newgidmap_result.returncode == 0)
        except:
            support['user_ns_helpers'] = False
            
        return support
    
    def create_namespace_command(self, command: List[str]) -> List[str]:
        """Create unshare command with configured namespaces"""
        unshare_cmd = ['unshare']
        
        if self.config.use_pid_ns:
            unshare_cmd.append('--pid')
            unshare_cmd.append('--fork')  # Required for PID namespace
            
        if self.config.use_mount_ns:
            unshare_cmd.append('--mount')
            
        if self.config.use_net_ns:
            unshare_cmd.append('--net')
            
        # Skip user namespace for now - it causes permission issues
        # if self.config.use_user_ns:
        #     unshare_cmd.append('--user')
            
        if self.config.use_ipc_ns:
            unshare_cmd.append('--ipc')
            
        if self.config.use_uts_ns:
            unshare_cmd.append('--uts')
            
        # Don't use --hostname option as it's not available in all versions
        # Hostname will be set in the child process if needed
            
        unshare_cmd.extend(command)
        return unshare_cmd
    
    def _can_setup_user_namespace(self):
        """Check if we can setup user namespace mappings"""
        try:
            # Check if we have permission to write to /proc/self/uid_map
            test_uid_map = f"0 {os.getuid()} 1"
            
            # Try to read current mappings to see if we're already in a user namespace
            try:
                with open("/proc/self/uid_map", 'r') as f:
                    current_map = f.read().strip()
                    # If we already have a mapping, we can't create nested user namespaces
                    if current_map and current_map != f"{os.getuid()} {os.getuid()} 1":
                        return False
            except:
                pass
                
            # Check if user namespaces are available
            if not os.path.exists("/proc/sys/user/max_user_namespaces"):
                return False
                
            try:
                with open("/proc/sys/user/max_user_namespaces", 'r') as f:
                    max_user_ns = int(f.read().strip())
                    if max_user_ns <= 0:
                        return False
            except:
                return False
                
            return True
            
        except Exception as e:
            self.logger.debug(f"Cannot setup user namespace: {e}")
            return False

    def setup_user_namespace_mappings(self, pid: int):
        """Setup UID/GID mappings for user namespace"""
        if not self.config.use_user_ns:
            return True
            
        uid_map = self.config.uid_map or f"0 {os.getuid()} 1"
        gid_map = self.config.gid_map or f"0 {os.getgid()} 1"
        
        try:
            # Write UID mapping
            with open(f"/proc/{pid}/uid_map", 'w') as f:
                f.write(uid_map)
                
            # Deny setgroups (required before GID mapping)
            with open(f"/proc/{pid}/setgroups", 'w') as f:
                f.write("deny")
                
            # Write GID mapping  
            with open(f"/proc/{pid}/gid_map", 'w') as f:
                f.write(gid_map)
                
            return True
                
        except Exception as e:
            self.logger.warning(f"Failed to setup user namespace mappings: {e}")
            # Disable user namespace for this session
            self.config.use_user_ns = False
            return False
    
    def create_minimal_procfs(self, mount_point: str):
        """Create minimal /proc filesystem in namespace"""
        proc_dir = Path(mount_point) / "proc"
        proc_dir.mkdir(exist_ok=True)
        
        try:
            # Mount proc filesystem
            subprocess.run(['mount', '-t', 'proc', 'proc', str(proc_dir)], 
                          check=True)
        except subprocess.CalledProcessError as e:
            self.logger.warning(f"Failed to mount procfs: {e}")
    
    def _call_sudo_helper(self, action: str, config: dict) -> dict:
        """Call the sudo helper for privileged operations"""
        sudo_helper_path = os.path.join(os.path.dirname(__file__), 'sudo_helper.py')
        
        try:
            cmd = ['sudo', 'python3', sudo_helper_path, action]
            result = subprocess.run(
                cmd,
                input=json.dumps(config),
                capture_output=True,
                text=True,
                check=True
            )
            return json.loads(result.stdout)
        except subprocess.CalledProcessError as e:
            self.logger.error(f"Sudo helper failed: {e.stderr}")
            return {'success': False, 'error': f"Sudo helper failed: {e.stderr}"}
        except Exception as e:
            self.logger.error(f"Error calling sudo helper: {e}")
            return {'success': False, 'error': str(e)}

    def setup_network_isolation(self):
        """Setup isolated network namespace"""
        if not self.config.use_net_ns:
            return
            
        try:
            # Create loopback interface in network namespace
            subprocess.run(['ip', 'link', 'set', 'lo', 'up'], check=True)
        except subprocess.CalledProcessError as e:
            # This is expected in network namespace without user namespace
            self.logger.debug(f"Network setup failed (expected without user namespace): {e}")
        except FileNotFoundError:
            self.logger.debug("ip command not found, skipping network setup")
    
    @contextmanager
    def isolated_execution(self, command: List[str], working_dir: str = "/tmp"):
        """Context manager for executing commands in isolated namespace"""
        temp_dir = None
        process = None
        
        try:
            # Create temporary directory for this execution
            temp_dir = tempfile.mkdtemp(prefix='sentinal_ns_')
            self.temp_dirs.append(temp_dir)
            
            # Check if we need sudo privileges for full isolation
            needs_sudo = (self.config.use_net_ns or self.config.use_mount_ns or 
                         self.config.use_user_ns)
            
            if needs_sudo:
                # Use sudo helper for full isolation
                self.logger.info("Using sudo helper for privileged namespace operations")
                
                # Create a mock process object to return
                class MockProcess:
                    def __init__(self, result):
                        self.returncode = result.get('returncode', 0)
                        self._stdout = result.get('stdout', '')
                        self._stderr = result.get('stderr', '')
                        self.pid = None
                    
                    def communicate(self, timeout=None):
                        return (self._stdout, self._stderr)
                    
                    def wait(self):
                        return self.returncode
                
                # Call sudo helper
                sudo_config = {
                    'command': command,
                    'working_dir': working_dir,
                    'timeout': 60,
                    'use_namespaces': True,
                    'namespace_config': {
                        'use_pid_ns': self.config.use_pid_ns,
                        'use_mount_ns': self.config.use_mount_ns,
                        'use_net_ns': self.config.use_net_ns,
                        'use_user_ns': self.config.use_user_ns,
                        'use_ipc_ns': self.config.use_ipc_ns,
                        'use_uts_ns': self.config.use_uts_ns
                    }
                }
                
                # Add chroot configuration if enabled
                if self.config.use_chroot:
                    if self.config.chroot_dir:
                        sudo_config['chroot_dir'] = self.config.chroot_dir
                    else:
                        # Create temporary chroot directory
                        import tempfile as tf
                        chroot_dir = tf.mkdtemp(prefix='sentinal_chroot_')
                        sudo_config['chroot_dir'] = chroot_dir
                        self.logger.info(f"Created temporary chroot: {chroot_dir}")
                
                result = self._call_sudo_helper('execute', sudo_config)
                if not result.get('success'):
                    raise RuntimeError(f"Sudo execution failed: {result.get('error')}")
                
                process = MockProcess(result)
                yield process
                
            else:
                # Use unprivileged namespaces only
                ns_command = self.create_namespace_command(command)
                
                self.logger.info(f"Executing in namespace: {' '.join(ns_command)}")
                
                # Start the process
                process = subprocess.Popen(
                    ns_command,
                    stdout=subprocess.PIPE,
                    stderr=subprocess.PIPE,
                    cwd=working_dir,
                    text=True,
                    preexec_fn=self._setup_child_process
                )
                
                yield process
            
        except Exception as e:
            self.logger.error(f"Namespace execution failed: {e}")
            if process and hasattr(process, 'kill'):
                process.kill()
            raise
            
        finally:
            if process and hasattr(process, 'wait'):
                process.wait()
            self._cleanup()
    
    def _setup_child_process(self):
        """Setup function called in child process"""
        try:
            # Setup network in network namespace
            if self.config.use_net_ns:
                self.setup_network_isolation()
                
        except Exception as e:
            # Log error but don't fail the process
            print(f"Child setup warning: {e}", file=sys.stderr)
    
    def execute_with_namespaces(self, command: List[str], 
                               timeout: int = 30,
                               capture_output: bool = True,
                               working_dir: str = "/tmp") -> Dict:
        """Execute command with namespace isolation and return results"""
        
        with self.isolated_execution(command, working_dir) as process:
            try:
                stdout, stderr = process.communicate(timeout=timeout)
                return {
                    'returncode': process.returncode,
                    'stdout': stdout,
                    'stderr': stderr,
                    'pid': process.pid,
                    'timed_out': False
                }
            except subprocess.TimeoutExpired:
                process.kill()
                stdout, stderr = process.communicate()
                return {
                    'returncode': -1,
                    'stdout': stdout,
                    'stderr': stderr,
                    'pid': process.pid,
                    'timed_out': True
                }
    
    def _cleanup(self):
        """Cleanup temporary directories and resources"""
        for temp_dir in self.temp_dirs:
            try:
                # Unmount any mounted filesystems in temp directories
                for proc_entry in Path("/proc/mounts").read_text().splitlines():
                    if temp_dir in proc_entry:
                        mount_point = proc_entry.split()[1]
                        subprocess.run(['umount', mount_point], 
                                     stderr=subprocess.DEVNULL)
                
                # Remove temporary directory
                subprocess.run(['rm', '-rf', temp_dir])
            except:
                pass
                
        self.temp_dirs.clear()

def create_sandbox_namespace(config: Optional[NamespaceConfig] = None) -> NamespaceManager:
    """Factory function to create a sandbox namespace manager"""
    return NamespaceManager(config)

# Example usage and testing
if __name__ == "__main__":
    # Test namespace support
    ns_manager = NamespaceManager()
    support = ns_manager.check_namespace_support()
    
    print("Namespace Support:")
    for feature, supported in support.items():
        status = "✓" if supported else "✗"
        print(f"  {status} {feature}")
    
    # Test simple command execution
    if support.get('unshare_available', False):
        result = ns_manager.execute_with_namespaces(['whoami'])
        print(f"\nNamespace execution test:")
        print(f"  Command: whoami")
        print(f"  Output: {result['stdout'].strip()}")
        print(f"  Return code: {result['returncode']}")