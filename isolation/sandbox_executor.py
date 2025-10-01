#!/usr/bin/env python3
"""
Sandbox Executor for Malware Analysis

Combines namespace isolation, chroot jails, and resource limits
for secure malware execution and analysis.
"""

import os
import sys
import time
import json
import logging
import tempfile
import subprocess
from pathlib import Path
from typing import Dict, List, Optional, Any
from dataclasses import dataclass, asdict
from contextlib import contextmanager

from .namespace_manager import NamespaceManager, NamespaceConfig
from .chroot_manager import ChrootManager, ChrootConfig
from .resource_limiter import ResourceLimiter, ResourceLimits

@dataclass
class SandboxConfig:
    """Complete sandbox configuration"""
    # Namespace configuration
    use_namespaces: bool = True
    namespace_config: Optional[NamespaceConfig] = None
    
    # Chroot configuration  
    use_chroot: bool = True
    chroot_config: Optional[ChrootConfig] = None
    
    # Resource limits
    use_resource_limits: bool = True
    resource_limits: Optional[ResourceLimits] = None
    
    # Execution parameters
    execution_timeout: int = 60
    capture_strace: bool = True
    capture_network: bool = True
    
    # Analysis options
    monitor_file_access: bool = True
    monitor_network_activity: bool = True
    monitor_process_creation: bool = True
    
    def __post_init__(self):
        if self.namespace_config is None:
            self.namespace_config = NamespaceConfig()
        if self.chroot_config is None:
            self.chroot_config = ChrootConfig()
        if self.resource_limits is None:
            self.resource_limits = ResourceLimits()

@dataclass 
class ExecutionResult:
    """Results from sandbox execution"""
    returncode: int
    stdout: str
    stderr: str
    execution_time: float
    timed_out: bool
    
    # Analysis data
    strace_output: Optional[str] = None
    network_activity: Optional[List[Dict]] = None
    file_accesses: Optional[List[str]] = None
    process_tree: Optional[Dict] = None
    resource_usage: Optional[Dict] = None
    
    # Metadata
    sandbox_config: Optional[Dict] = None
    execution_id: Optional[str] = None
    timestamp: Optional[str] = None

class SandboxExecutor:
    """Main sandbox executor combining all isolation mechanisms"""
    
    def __init__(self, config: Optional[SandboxConfig] = None):
        self.config = config or SandboxConfig()
        self.logger = logging.getLogger(__name__)
        
        # Initialize components
        self.namespace_manager = None
        self.chroot_manager = None
        self.resource_limiter = None
        
        if self.config.use_namespaces:
            self.namespace_manager = NamespaceManager(self.config.namespace_config)
        if self.config.use_chroot:
            self.chroot_manager = ChrootManager(self.config.chroot_config)
        if self.config.use_resource_limits:
            self.resource_limiter = ResourceLimiter(self.config.resource_limits)
    
    def check_sandbox_capabilities(self) -> Dict[str, Any]:
        """Check what sandbox capabilities are available"""
        capabilities = {
            'timestamp': time.time(),
            'system': {
                'uid': os.getuid(),
                'gid': os.getgid(),
                'platform': sys.platform,
                'kernel': os.uname().release if hasattr(os, 'uname') else 'unknown'
            }
        }
        
        if self.namespace_manager:
            capabilities['namespaces'] = self.namespace_manager.check_namespace_support()
        else:
            capabilities['namespaces'] = {'enabled': False}
            
        if self.chroot_manager:
            capabilities['chroot'] = self.chroot_manager.check_chroot_requirements()
        else:
            capabilities['chroot'] = {'enabled': False}
            
        if self.resource_limiter:
            capabilities['resource_limits'] = self.resource_limiter.check_cgroup_support()
        else:
            capabilities['resource_limits'] = {'enabled': False}
            
        return capabilities
    
    def execute_sample(self, sample_path: str, 
                      args: Optional[List[str]] = None,
                      working_dir: str = "/tmp") -> ExecutionResult:
        """Execute malware sample in sandbox with full isolation"""
        
        start_time = time.time()
        execution_id = f"exec_{int(start_time)}"
        
        self.logger.info(f"Starting sandbox execution {execution_id} for {sample_path}")
        
        # Validate sample exists
        if not os.path.exists(sample_path):
            raise FileNotFoundError(f"Sample file not found: {sample_path}")
        
        # Prepare execution command
        args = args or []
        sample_name = os.path.basename(sample_path)
        
        try:
            if self.config.use_chroot and self.chroot_manager:
                return self._execute_with_chroot(sample_path, args, execution_id, start_time)
            elif self.config.use_namespaces and self.namespace_manager:
                return self._execute_with_namespaces(sample_path, args, execution_id, start_time)
            else:
                return self._execute_basic(sample_path, args, execution_id, start_time)
                
        except Exception as e:
            self.logger.error(f"Sandbox execution failed: {e}")
            return ExecutionResult(
                returncode=-1,
                stdout="",
                stderr=f"Sandbox execution failed: {str(e)}",
                execution_time=time.time() - start_time,
                timed_out=False,
                execution_id=execution_id,
                timestamp=time.ctime(start_time)
            )
    
    def _execute_with_chroot(self, sample_path: str, args: List[str],
                           execution_id: str, start_time: float) -> ExecutionResult:
        """Execute sample using chroot isolation"""
        
        with self.chroot_manager.chroot_environment() as chroot_dir:
            # Copy sample to chroot
            chroot_sample_path = self.chroot_manager.copy_sample_to_chroot(
                sample_path, chroot_dir
            )
            
            # Prepare execution command
            exec_command = [chroot_sample_path] + args
            
            # Add strace if requested
            if self.config.capture_strace:
                exec_command = ['strace', '-f', '-o', '/tmp/strace.out'] + exec_command
            
            # Execute in chroot
            result = self.chroot_manager.execute_in_chroot(
                chroot_dir, exec_command, self.config.execution_timeout
            )
            
            # Collect additional analysis data
            strace_output = None
            if self.config.capture_strace:
                strace_file = os.path.join(chroot_dir, 'tmp', 'strace.out')
                if os.path.exists(strace_file):
                    with open(strace_file, 'r') as f:
                        strace_output = f.read()
            
            return ExecutionResult(
                returncode=result['returncode'],
                stdout=result['stdout'],
                stderr=result['stderr'],
                execution_time=time.time() - start_time,
                timed_out=result['timed_out'],
                strace_output=strace_output,
                execution_id=execution_id,
                timestamp=time.ctime(start_time),
                sandbox_config=asdict(self.config)
            )
    
    def _execute_with_namespaces(self, sample_path: str, args: List[str],
                               execution_id: str, start_time: float) -> ExecutionResult:
        """Execute sample using namespace isolation"""
        
        # Prepare execution command
        exec_command = [sample_path] + args
        
        # Add strace if requested
        if self.config.capture_strace:
            exec_command = ['strace', '-f', '-tt', '-T'] + exec_command
        
        # Execute with namespace isolation
        result = self.namespace_manager.execute_with_namespaces(
            exec_command, 
            timeout=self.config.execution_timeout
        )
        
        return ExecutionResult(
            returncode=result['returncode'],
            stdout=result['stdout'],
            stderr=result['stderr'],
            execution_time=time.time() - start_time,
            timed_out=result['timed_out'],
            strace_output=result['stderr'] if self.config.capture_strace else None,
            execution_id=execution_id,
            timestamp=time.ctime(start_time),
            sandbox_config=asdict(self.config)
        )
    
    def _execute_basic(self, sample_path: str, args: List[str],
                      execution_id: str, start_time: float) -> ExecutionResult:
        """Basic execution without isolation (fallback)"""
        
        self.logger.warning("Executing without isolation - use with caution!")
        
        exec_command = [sample_path] + args
        
        try:
            result = subprocess.run(
                exec_command,
                capture_output=True,
                text=True,
                timeout=self.config.execution_timeout
            )
            
            return ExecutionResult(
                returncode=result.returncode,
                stdout=result.stdout,
                stderr=result.stderr,
                execution_time=time.time() - start_time,
                timed_out=False,
                execution_id=execution_id,
                timestamp=time.ctime(start_time),
                sandbox_config=asdict(self.config)
            )
            
        except subprocess.TimeoutExpired:
            return ExecutionResult(
                returncode=-1,
                stdout="",
                stderr="Execution timed out",
                execution_time=time.time() - start_time,
                timed_out=True,
                execution_id=execution_id,
                timestamp=time.ctime(start_time)
            )
    
    def analyze_execution_result(self, result: ExecutionResult) -> Dict[str, Any]:
        """Analyze execution results and extract security insights"""
        
        analysis = {
            'execution_summary': {
                'success': result.returncode == 0,
                'timed_out': result.timed_out,
                'execution_time': result.execution_time,
                'output_size': len(result.stdout) + len(result.stderr)
            },
            'behavioral_indicators': [],
            'system_calls': [],
            'file_operations': [],
            'network_operations': [],
            'suspicious_activities': []
        }
        
        # Analyze strace output if available
        if result.strace_output:
            analysis.update(self._analyze_strace_output(result.strace_output))
        
        # Analyze stdout/stderr for suspicious patterns
        output_text = result.stdout + result.stderr
        suspicious_patterns = [
            'password', 'secret', 'key', 'token',
            'download', 'upload', 'connect', 'bind',
            'exec', 'fork', 'clone', 'kill'
        ]
        
        for pattern in suspicious_patterns:
            if pattern.lower() in output_text.lower():
                analysis['suspicious_activities'].append({
                    'type': 'text_pattern',
                    'pattern': pattern,
                    'context': 'output_analysis'
                })
        
        return analysis
    
    def _analyze_strace_output(self, strace_output: str) -> Dict[str, List]:
        """Analyze strace output for behavioral patterns"""
        
        analysis = {
            'system_calls': [],
            'file_operations': [],
            'network_operations': [],
            'process_operations': []
        }
        
        for line in strace_output.split('\n'):
            line = line.strip()
            if not line:
                continue
                
            # Extract system call name
            if '(' in line:
                syscall = line.split('(')[0].split()[-1]
                
                # Categorize system calls
                if syscall in ['open', 'openat', 'read', 'write', 'close', 'unlink']:
                    analysis['file_operations'].append(line)
                elif syscall in ['socket', 'connect', 'bind', 'listen', 'accept']:
                    analysis['network_operations'].append(line)
                elif syscall in ['fork', 'clone', 'execve', 'kill']:
                    analysis['process_operations'].append(line)
                
                analysis['system_calls'].append({
                    'syscall': syscall,
                    'full_line': line
                })
        
        return analysis

# Factory function
def create_sandbox(config: Optional[SandboxConfig] = None) -> SandboxExecutor:
    """Factory function to create a sandbox executor"""
    return SandboxExecutor(config)

# Example usage
if __name__ == "__main__":
    # Create sandbox with default configuration
    sandbox = SandboxExecutor()
    
    # Check capabilities
    capabilities = sandbox.check_sandbox_capabilities()
    print("Sandbox Capabilities:")
    print(json.dumps(capabilities, indent=2))
    
    # Example execution (uncomment to test with actual sample)
    # result = sandbox.execute_sample("/path/to/sample")
    # analysis = sandbox.analyze_execution_result(result)
    # print(f"Execution completed: {result.returncode}")
    # print(f"Analysis: {json.dumps(analysis, indent=2)}")