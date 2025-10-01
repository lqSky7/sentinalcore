#!/usr/bin/env python3
"""
Resource Limiter for Malware Analysis

Provides resource limits using cgroups to prevent malware from:
- Consuming excessive CPU
- Using too much memory
- Creating too many processes
- Performing excessive I/O operations
"""

import os
import sys
import time
import logging
import subprocess
from pathlib import Path
from typing import Dict, Optional, Union
from dataclasses import dataclass

@dataclass
class ResourceLimits:
    """Resource limit configuration"""
    # CPU limits
    cpu_quota: Optional[int] = 50000  # 50% CPU (50000/100000)
    cpu_period: int = 100000  # 100ms period
    cpu_shares: int = 512  # Relative CPU weight (default 1024)
    
    # Memory limits
    memory_limit: str = "256M"  # Maximum memory usage
    memory_swap_limit: str = "512M"  # Maximum swap usage
    
    # Process limits  
    pids_max: int = 32  # Maximum number of processes
    
    # I/O limits
    io_read_bps: Optional[str] = "10M"  # Read bytes per second
    io_write_bps: Optional[str] = "10M"  # Write bytes per second
    io_read_iops: Optional[int] = 1000  # Read IOPS
    io_write_iops: Optional[int] = 1000  # Write IOPS
    
    # Time limits
    execution_timeout: int = 60  # Maximum execution time in seconds

class ResourceLimiter:
    """Manages resource limits using cgroups v1 and v2"""
    
    def __init__(self, limits: Optional[ResourceLimits] = None):
        self.limits = limits or ResourceLimits()
        self.logger = logging.getLogger(__name__)
        self.cgroup_path = None
        self.cgroup_version = self._detect_cgroup_version()
        self.cgroup_name = f"sentinal_{os.getpid()}_{int(time.time())}"
        
    def _detect_cgroup_version(self) -> int:
        """Detect whether system uses cgroups v1 or v2"""
        if os.path.exists('/sys/fs/cgroup/cgroup.controllers'):
            return 2  # cgroups v2
        elif os.path.exists('/sys/fs/cgroup/memory'):
            return 1  # cgroups v1
        else:
            return 0  # No cgroups support
    
    def check_cgroup_support(self) -> Dict[str, Union[bool, int, str]]:
        """Check cgroups support and available controllers"""
        support = {
            'cgroup_version': self.cgroup_version,
            'cgroup_mounted': False,
            'controllers_available': [],
            'write_access': False
        }
        
        if self.cgroup_version == 0:
            return support
        
        # Check if cgroup filesystem is mounted
        if self.cgroup_version == 2:
            cgroup_root = Path('/sys/fs/cgroup')
            support['cgroup_mounted'] = cgroup_root.exists()
            
            # Check available controllers
            controllers_file = cgroup_root / 'cgroup.controllers'
            if controllers_file.exists():
                try:
                    controllers = controllers_file.read_text().strip().split()
                    support['controllers_available'] = controllers
                except:
                    pass
        else:  # cgroups v1
            cgroup_root = Path('/sys/fs/cgroup')
            support['cgroup_mounted'] = cgroup_root.exists()
            
            # Check available controllers
            if cgroup_root.exists():
                controllers = []
                for item in cgroup_root.iterdir():
                    if item.is_dir():
                        controllers.append(item.name)
                support['controllers_available'] = controllers
        
        # Check write access
        try:
            if self.cgroup_version == 2:
                test_path = Path('/sys/fs/cgroup') / 'user.slice'
            else:
                test_path = Path('/sys/fs/cgroup/memory')
                
            support['write_access'] = os.access(test_path, os.W_OK)
        except:
            support['write_access'] = False
            
        return support
    
    def create_cgroup(self) -> str:
        """Create a new cgroup for resource limiting"""
        if self.cgroup_version == 0:
            raise RuntimeError("No cgroups support available")
        
        if self.cgroup_version == 2:
            return self._create_cgroup_v2()
        else:
            return self._create_cgroup_v1()
    
    def _create_cgroup_v2(self) -> str:
        """Create cgroup using cgroups v2"""
        # Use user.slice for unprivileged operations
        base_path = Path('/sys/fs/cgroup/user.slice')
        if not base_path.exists():
            base_path = Path('/sys/fs/cgroup')
        
        cgroup_path = base_path / self.cgroup_name
        
        try:
            cgroup_path.mkdir(parents=True, exist_ok=True)
            self.cgroup_path = str(cgroup_path)
            
            # Enable controllers
            controllers = ['cpu', 'memory', 'pids', 'io']
            available_controllers = self._get_available_controllers_v2(base_path)
            
            for controller in controllers:
                if controller in available_controllers:
                    self._enable_controller_v2(base_path, controller)
            
            # Set resource limits
            self._set_limits_v2(cgroup_path)
            
            return self.cgroup_path
            
        except Exception as e:
            self.logger.error(f"Failed to create cgroup v2: {e}")
            raise
    
    def _create_cgroup_v1(self) -> str:
        """Create cgroup using cgroups v1"""
        cgroup_dirs = []
        
        try:
            # Create cgroups for each controller
            controllers = ['cpu', 'memory', 'pids', 'blkio']
            
            for controller in controllers:
                controller_path = Path(f'/sys/fs/cgroup/{controller}')
                if controller_path.exists():
                    cgroup_dir = controller_path / self.cgroup_name
                    cgroup_dir.mkdir(parents=True, exist_ok=True)
                    cgroup_dirs.append(str(cgroup_dir))
            
            if cgroup_dirs:
                self.cgroup_path = cgroup_dirs[0]  # Use first as reference
                
                # Set resource limits
                self._set_limits_v1(cgroup_dirs)
                
                return self.cgroup_path
            else:
                raise RuntimeError("No cgroup controllers available")
                
        except Exception as e:
            self.logger.error(f"Failed to create cgroup v1: {e}")
            # Cleanup partial creation
            for cgroup_dir in cgroup_dirs:
                try:
                    Path(cgroup_dir).rmdir()
                except:
                    pass
            raise
    
    def _get_available_controllers_v2(self, cgroup_path: Path) -> list:
        """Get available controllers for cgroups v2"""
        try:
            controllers_file = cgroup_path / 'cgroup.controllers'
            if controllers_file.exists():
                return controllers_file.read_text().strip().split()
        except:
            pass
        return []
    
    def _enable_controller_v2(self, cgroup_path: Path, controller: str):
        """Enable a controller in cgroups v2"""
        try:
            subtree_control = cgroup_path / 'cgroup.subtree_control'
            if subtree_control.exists():
                current = subtree_control.read_text().strip()
                if controller not in current:
                    subtree_control.write_text(f"{current} +{controller}")
        except Exception as e:
            self.logger.debug(f"Could not enable controller {controller}: {e}")
    
    def _set_limits_v2(self, cgroup_path: Path):
        """Set resource limits for cgroups v2"""
        try:
            # CPU limits
            if self.limits.cpu_quota:
                cpu_max = cgroup_path / 'cpu.max'
                if cpu_max.exists():
                    cpu_max.write_text(f"{self.limits.cpu_quota} {self.limits.cpu_period}")
            
            cpu_weight = cgroup_path / 'cpu.weight'
            if cpu_weight.exists():
                # Convert shares to weight (shares * 256 / 1024)
                weight = max(1, min(10000, self.limits.cpu_shares * 256 // 1024))
                cpu_weight.write_text(str(weight))
            
            # Memory limits
            memory_max = cgroup_path / 'memory.max'
            if memory_max.exists():
                memory_max.write_text(self.limits.memory_limit)
            
            memory_swap = cgroup_path / 'memory.swap.max'
            if memory_swap.exists():
                memory_swap.write_text(self.limits.memory_swap_limit)
            
            # Process limits
            pids_max = cgroup_path / 'pids.max'
            if pids_max.exists():
                pids_max.write_text(str(self.limits.pids_max))
            
            # I/O limits (simplified)
            if self.limits.io_read_bps or self.limits.io_write_bps:
                io_max = cgroup_path / 'io.max'
                if io_max.exists():
                    # Format: major:minor rbps=X wbps=Y riops=X wiops=Y
                    limits = []
                    if self.limits.io_read_bps:
                        limits.append(f"rbps={self.limits.io_read_bps}")
                    if self.limits.io_write_bps:
                        limits.append(f"wbps={self.limits.io_write_bps}")
                    if self.limits.io_read_iops:
                        limits.append(f"riops={self.limits.io_read_iops}")
                    if self.limits.io_write_iops:
                        limits.append(f"wiops={self.limits.io_write_iops}")
                    
                    if limits:
                        io_max.write_text(f"8:0 {' '.join(limits)}")
                        
        except Exception as e:
            self.logger.warning(f"Failed to set some cgroup v2 limits: {e}")
    
    def _set_limits_v1(self, cgroup_dirs: list):
        """Set resource limits for cgroups v1"""
        for cgroup_dir in cgroup_dirs:
            cgroup_path = Path(cgroup_dir)
            controller = cgroup_path.parent.name
            
            try:
                if controller == 'cpu':
                    # CPU limits
                    if self.limits.cpu_quota:
                        (cgroup_path / 'cpu.cfs_quota_us').write_text(str(self.limits.cpu_quota))
                        (cgroup_path / 'cpu.cfs_period_us').write_text(str(self.limits.cpu_period))
                    
                    (cgroup_path / 'cpu.shares').write_text(str(self.limits.cpu_shares))
                
                elif controller == 'memory':
                    # Memory limits
                    (cgroup_path / 'memory.limit_in_bytes').write_text(self.limits.memory_limit)
                    
                    swap_file = cgroup_path / 'memory.memsw.limit_in_bytes'
                    if swap_file.exists():
                        swap_file.write_text(self.limits.memory_swap_limit)
                
                elif controller == 'pids':
                    # Process limits
                    (cgroup_path / 'pids.max').write_text(str(self.limits.pids_max))
                
                elif controller == 'blkio':
                    # I/O limits (simplified)
                    if self.limits.io_read_bps:
                        (cgroup_path / 'blkio.throttle.read_bps_device').write_text(f"8:0 {self.limits.io_read_bps}")
                    if self.limits.io_write_bps:
                        (cgroup_path / 'blkio.throttle.write_bps_device').write_text(f"8:0 {self.limits.io_write_bps}")
                        
            except Exception as e:
                self.logger.warning(f"Failed to set {controller} limits: {e}")
    
    def add_process_to_cgroup(self, pid: int):
        """Add a process to the cgroup"""
        if not self.cgroup_path:
            raise RuntimeError("No cgroup created")
        
        try:
            if self.cgroup_version == 2:
                procs_file = Path(self.cgroup_path) / 'cgroup.procs'
                procs_file.write_text(str(pid))
            else:
                # For cgroups v1, add to all controller cgroups
                base_path = Path(self.cgroup_path).parent.parent
                for controller in ['cpu', 'memory', 'pids', 'blkio']:
                    controller_path = base_path / controller / self.cgroup_name
                    procs_file = controller_path / 'cgroup.procs'
                    if procs_file.exists():
                        procs_file.write_text(str(pid))
                        
        except Exception as e:
            self.logger.error(f"Failed to add process {pid} to cgroup: {e}")
            raise
    
    def get_resource_usage(self) -> Dict:
        """Get current resource usage from cgroup"""
        if not self.cgroup_path:
            return {}
        
        usage = {}
        cgroup_path = Path(self.cgroup_path)
        
        try:
            if self.cgroup_version == 2:
                # CPU usage
                cpu_stat = cgroup_path / 'cpu.stat'
                if cpu_stat.exists():
                    for line in cpu_stat.read_text().splitlines():
                        if line.startswith('usage_usec'):
                            usage['cpu_usage_usec'] = int(line.split()[1])
                
                # Memory usage
                memory_current = cgroup_path / 'memory.current'
                if memory_current.exists():
                    usage['memory_bytes'] = int(memory_current.read_text().strip())
                
                # Process count
                pids_current = cgroup_path / 'pids.current'
                if pids_current.exists():
                    usage['pids_current'] = int(pids_current.read_text().strip())
                    
            else:  # cgroups v1
                # This would need to read from multiple controller directories
                pass
                
        except Exception as e:
            self.logger.warning(f"Failed to read resource usage: {e}")
        
        return usage
    
    def cleanup_cgroup(self):
        """Remove the cgroup"""
        if not self.cgroup_path:
            return
        
        try:
            if self.cgroup_version == 2:
                cgroup_path = Path(self.cgroup_path)
                if cgroup_path.exists():
                    cgroup_path.rmdir()
            else:
                # Remove from all controllers
                base_path = Path(self.cgroup_path).parent.parent
                for controller in ['cpu', 'memory', 'pids', 'blkio']:
                    controller_path = base_path / controller / self.cgroup_name
                    if controller_path.exists():
                        controller_path.rmdir()
                        
            self.logger.info(f"Cleaned up cgroup: {self.cgroup_name}")
            
        except Exception as e:
            self.logger.warning(f"Failed to cleanup cgroup: {e}")

# Factory function
def create_resource_limiter(limits: Optional[ResourceLimits] = None) -> ResourceLimiter:
    """Factory function to create a resource limiter"""
    return ResourceLimiter(limits)

# Example usage and testing
if __name__ == "__main__":
    # Test resource limiting capabilities
    limiter = ResourceLimiter()
    support = limiter.check_cgroup_support()
    
    print("Resource Limiting Support:")
    for feature, value in support.items():
        print(f"  {feature}: {value}")
    
    # Test cgroup creation (may require privileges)
    if support.get('write_access', False):
        try:
            cgroup_path = limiter.create_cgroup()
            print(f"\nCreated cgroup: {cgroup_path}")
            
            # Test adding current process
            limiter.add_process_to_cgroup(os.getpid())
            
            # Get usage
            usage = limiter.get_resource_usage()
            print(f"Resource usage: {usage}")
            
            # Cleanup
            limiter.cleanup_cgroup()
            
        except Exception as e:
            print(f"Cgroup test failed: {e}")
    else:
        print("\nNote: Write access required for cgroup functionality")