#!/usr/bin/env python3
"""
Main Isolation Interface for SentinalCore

Provides a unified interface for all isolation mechanisms:
- Namespace isolation
- Chroot jails  
- Resource limiting
- Sandboxed execution

Usage:
    from isolation import IsolationManager
    
    # Create isolation manager with default security settings
    isolation = IsolationManager()
    
    # Execute malware sample safely
    result = isolation.execute_sample('/path/to/malware.bin')
    
    # Analyze results
    analysis = isolation.analyze_results(result)
"""

import os
import sys
import json
import logging
import subprocess
from pathlib import Path
from typing import Dict, List, Optional, Any
from contextlib import contextmanager

from .sandbox_executor import SandboxExecutor, SandboxConfig, ExecutionResult
from .namespace_manager import NamespaceManager, NamespaceConfig
from .chroot_manager import ChrootManager, ChrootConfig
from .resource_limiter import ResourceLimiter, ResourceLimits

class IsolationManager:
    """Main interface for malware isolation and analysis"""
    
    def __init__(self, config_file: Optional[str] = None):
        self.logger = logging.getLogger(__name__)
        
        # Load configuration
        if config_file and os.path.exists(config_file):
            self.config = self._load_config(config_file)
        else:
            self.config = self._get_default_config()
        
        # Initialize sandbox executor
        self.sandbox = SandboxExecutor(self.config)
        
        # Check capabilities
        self.capabilities = self.sandbox.check_sandbox_capabilities()
        
        self.logger.info("Isolation manager initialized")
        self._log_capabilities()
    
    def _load_config(self, config_file: str) -> SandboxConfig:
        """Load configuration from JSON file"""
        try:
            with open(config_file, 'r') as f:
                config_data = json.load(f)
            
            # Convert dict to SandboxConfig
            # This is a simplified conversion - in practice you'd want more robust parsing
            return SandboxConfig(**config_data)
            
        except Exception as e:
            self.logger.warning(f"Failed to load config file {config_file}: {e}")
            return self._get_default_config()
    
    def _get_default_config(self) -> SandboxConfig:
        """Get default security configuration"""
        
        # Default namespace configuration - maximum isolation
        namespace_config = NamespaceConfig(
            use_pid_ns=True,
            use_mount_ns=True,
            use_net_ns=True,
            use_user_ns=True,
            use_ipc_ns=True,
            use_uts_ns=True,
            hostname="malware-sandbox"
        )
        
        # Default chroot configuration
        chroot_config = ChrootConfig()
        
        # Default resource limits - restrictive but functional
        resource_limits = ResourceLimits(
            cpu_quota=30000,  # 30% CPU max
            memory_limit="128M",  # 128MB RAM max
            memory_swap_limit="256M",  # 256MB swap max
            pids_max=16,  # Max 16 processes
            execution_timeout=30  # 30 second timeout
        )
        
        return SandboxConfig(
            use_namespaces=True,
            namespace_config=namespace_config,
            use_chroot=False,  # Disable chroot by default (requires root)
            chroot_config=chroot_config,
            use_resource_limits=True,
            resource_limits=resource_limits,
            execution_timeout=30,
            capture_strace=True,
            capture_network=True
        )
    
    def _log_capabilities(self):
        """Log available isolation capabilities"""
        self.logger.info("Isolation Capabilities:")
        
        # Namespace capabilities
        ns_caps = self.capabilities.get('namespaces', {})
        if ns_caps.get('unshare_available', False):
            self.logger.info("  ✓ Namespace isolation available")
            for ns_type, available in ns_caps.items():
                if ns_type != 'unshare_available' and available:
                    self.logger.debug(f"    ✓ {ns_type} namespace")
        else:
            self.logger.warning("  ✗ Namespace isolation not available")
        
        # Chroot capabilities  
        chroot_caps = self.capabilities.get('chroot', {})
        if chroot_caps.get('root_access', False):
            self.logger.info("  ✓ Chroot isolation available")
        else:
            self.logger.warning("  ✗ Chroot isolation requires root access")
        
        # Resource limit capabilities
        rl_caps = self.capabilities.get('resource_limits', {})
        cgroup_version = rl_caps.get('cgroup_version', 0)
        if cgroup_version > 0:
            self.logger.info(f"  ✓ Resource limits available (cgroups v{cgroup_version})")
        else:
            self.logger.warning("  ✗ Resource limits not available")
    
    def get_isolation_level(self) -> str:
        """Determine the effective isolation level"""
        
        ns_available = self.capabilities.get('namespaces', {}).get('unshare_available', False)
        chroot_available = self.capabilities.get('chroot', {}).get('root_access', False)
        cgroups_available = self.capabilities.get('resource_limits', {}).get('cgroup_version', 0) > 0
        
        if ns_available and chroot_available and cgroups_available:
            return "maximum"  # Full isolation
        elif ns_available and cgroups_available:
            return "high"  # Namespace + resource limits
        elif ns_available or chroot_available:
            return "medium"  # Either namespace or chroot
        else:
            return "minimal"  # No isolation
    
    def execute_sample(self, sample_path: str, 
                      args: Optional[List[str]] = None,
                      timeout: Optional[int] = None) -> ExecutionResult:
        """Execute a malware sample with full isolation"""
        
        # Validate sample file
        if not os.path.exists(sample_path):
            raise FileNotFoundError(f"Sample file not found: {sample_path}")
        
        # Check file permissions and make executable if needed
        if not os.access(sample_path, os.X_OK):
            try:
                os.chmod(sample_path, 0o755)
            except Exception as e:
                self.logger.warning(f"Could not make sample executable: {e}")
        
        # Override timeout if specified
        if timeout:
            original_timeout = self.config.execution_timeout
            self.config.execution_timeout = timeout
        
        try:
            self.logger.info(f"Executing sample: {sample_path}")
            self.logger.info(f"Isolation level: {self.get_isolation_level()}")
            
            # Check if we should use namespace isolation
            if (hasattr(self.config, 'namespace_config') and 
                self.config.namespace_config and
                (self.config.namespace_config.use_pid_ns or 
                 self.config.namespace_config.use_mount_ns or
                 self.config.namespace_config.use_net_ns or
                 self.config.namespace_config.use_ipc_ns or
                 self.config.namespace_config.use_uts_ns)):
                
                self.logger.info("Using namespace isolation for execution")
                result = self._execute_with_namespaces(sample_path, args)
            else:
                # Execute in regular sandbox
                result = self.sandbox.execute_sample(sample_path, args)
            
            self.logger.info(f"Execution completed - Return code: {result.returncode}")
            if result.timed_out:
                self.logger.warning("Execution timed out")
            
            return result
            
        finally:
            # Restore original timeout
            if timeout:
                self.config.execution_timeout = original_timeout
    
    def _execute_with_namespaces(self, sample_path: str, 
                                args: Optional[List[str]] = None) -> ExecutionResult:
        """Execute sample using namespace isolation"""
        from .namespace_manager import NamespaceManager
        import time
        
        try:
            # Create namespace manager with our configuration
            namespace_manager = NamespaceManager(self.config.namespace_config)
            
            # Build execution command
            if sample_path.endswith('.py'):
                command = ['python3', sample_path]
            elif sample_path.endswith('.sh'):
                command = ['bash', sample_path]
            else:
                # Try to execute directly
                command = [sample_path]
            
            if args:
                command.extend(args)
            
            start_time = time.time()
            
            # Execute in namespace
            with namespace_manager.isolated_execution(command) as process:
                try:
                    stdout, stderr = process.communicate(timeout=self.config.execution_timeout)
                    execution_time = time.time() - start_time
                    timed_out = False
                except subprocess.TimeoutExpired:
                    process.kill()
                    stdout, stderr = process.communicate()
                    execution_time = time.time() - start_time
                    timed_out = True
            
            # Create ExecutionResult
            return ExecutionResult(
                returncode=process.returncode,
                stdout=stdout,
                stderr=stderr,
                execution_time=execution_time,
                timed_out=timed_out,
                strace_output=None,  # Not available in namespace isolation
                network_activity=None,  # Not monitored in namespace isolation
                file_accesses=None,  # Not monitored in namespace isolation
                process_tree=None,  # Not available in namespace isolation
                resource_usage=None,  # Not monitored in namespace isolation
                sandbox_config=None,
                execution_id=f"ns_exec_{int(time.time())}",
                timestamp=time.ctime()
            )
            
        except Exception as e:
            self.logger.error(f"Namespace execution failed: {e}")
            # Fallback to regular sandbox execution
            return self.sandbox.execute_sample(sample_path, args)
    
    def analyze_sample(self, sample_path: str, 
                      args: Optional[List[str]] = None) -> Dict[str, Any]:
        """Execute and analyze a malware sample"""
        
        # Execute sample
        result = self.execute_sample(sample_path, args)
        
        # Analyze execution results
        analysis = self.sandbox.analyze_execution_result(result)
        
        # Add additional metadata
        analysis['isolation_info'] = {
            'isolation_level': self.get_isolation_level(),
            'capabilities': self.capabilities,
            'sample_path': sample_path,
            'sample_size': os.path.getsize(sample_path) if os.path.exists(sample_path) else 0
        }
        
        return {
            'execution_result': result,
            'analysis': analysis
        }
    
    def batch_analyze(self, sample_paths: List[str]) -> List[Dict[str, Any]]:
        """Analyze multiple samples in batch"""
        
        results = []
        
        for i, sample_path in enumerate(sample_paths):
            self.logger.info(f"Processing sample {i+1}/{len(sample_paths)}: {sample_path}")
            
            try:
                result = self.analyze_sample(sample_path)
                results.append(result)
                
            except Exception as e:
                self.logger.error(f"Failed to analyze {sample_path}: {e}")
                results.append({
                    'sample_path': sample_path,
                    'error': str(e),
                    'execution_result': None,
                    'analysis': None
                })
        
        return results
    
    def create_test_environment(self) -> str:
        """Create a test environment for manual analysis"""
        
        if not self.capabilities.get('chroot', {}).get('root_access', False):
            raise RuntimeError("Test environment requires root access for chroot")
        
        # Create chroot environment
        chroot_manager = ChrootManager(self.config.chroot_config)
        
        with chroot_manager.chroot_environment() as chroot_dir:
            self.logger.info(f"Test environment created at: {chroot_dir}")
            self.logger.info("Use 'sudo chroot {chroot_dir} /bin/bash' to enter")
            
            # Keep environment alive
            input("Press Enter to cleanup test environment...")
            
        return chroot_dir
    
    def get_status_report(self) -> Dict[str, Any]:
        """Get comprehensive status report"""
        
        return {
            'isolation_level': self.get_isolation_level(),
            'capabilities': self.capabilities,
            'configuration': {
                'use_namespaces': self.config.use_namespaces,
                'use_chroot': self.config.use_chroot,
                'use_resource_limits': self.config.use_resource_limits,
                'execution_timeout': self.config.execution_timeout
            },
            'system_info': {
                'uid': os.getuid(),
                'gid': os.getgid(),
                'platform': sys.platform,
                'python_version': sys.version.split()[0]
            }
        }

# Factory functions
def create_isolation_manager(config_file: Optional[str] = None) -> IsolationManager:
    """Create isolation manager with optional config file"""
    return IsolationManager(config_file)

def quick_analyze(sample_path: str) -> Dict[str, Any]:
    """Quick analysis with default settings"""
    isolation = IsolationManager()
    return isolation.analyze_sample(sample_path)

# Example usage
if __name__ == "__main__":
    # Initialize logging
    logging.basicConfig(
        level=logging.INFO,
        format='%(asctime)s - %(name)s - %(levelname)s - %(message)s'
    )
    
    # Create isolation manager
    isolation = IsolationManager()
    
    # Print status report
    status = isolation.get_status_report()
    print("SentinalCore Isolation Status:")
    print(json.dumps(status, indent=2))
    
    # Example analysis (uncomment to test)
    # if len(sys.argv) > 1:
    #     sample_path = sys.argv[1]
    #     result = isolation.analyze_sample(sample_path)
    #     print(f"\nAnalysis Results:")
    #     print(json.dumps(result['analysis'], indent=2))