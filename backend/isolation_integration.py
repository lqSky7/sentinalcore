"""
Integration module for SentinalCore backend with isolation system
"""

import os
import sys
import subprocess
import json
import logging
import tempfile
from typing import Dict, Any, Optional
from pathlib import Path

# Add isolation module to path
sys.path.append(os.path.join(os.path.dirname(__file__), '..'))

try:
    from isolation.isolation_manager import IsolationManager
    from isolation.sandbox_executor import SandboxConfig
    from isolation.namespace_manager import NamespaceConfig  
    from isolation.resource_limiter import ResourceLimits
    from isolation.risk_assessor import RiskAssessor, assess_file_risk
except ImportError as e:
    print(f"Import error: {e}")
    print("Make sure you're running from the sentinalcore directory")
    sys.exit(1)

class MalwareAnalysisIsolation:
    """
    Integration class for using isolation in malware analysis
    Designed to work with existing SentinalCore backend
    """
    
    def __init__(self):
        self.logger = logging.getLogger(__name__)
        
        # Initialize risk assessor
        self.risk_assessor = RiskAssessor()
        
        # Create a working configuration that doesn't require root
        self.config = self._create_working_config()
        self.isolation_manager = IsolationManager()
        self.isolation_manager.config = self.config
        
        # Check what's actually available
        self.capabilities = self.isolation_manager.get_status_report()
        self.isolation_level = self.isolation_manager.get_isolation_level()
        
        self.logger.info(f"Malware isolation initialized - Level: {self.isolation_level}")
        self.logger.info("Risk-based automatic isolation enabled")
    
    def _create_working_config(self) -> SandboxConfig:
        """Create a configuration that works in most environments"""
        
        # Simplified namespace config - disable features that need special privileges
        namespace_config = NamespaceConfig(
            use_pid_ns=True,
            use_mount_ns=True,
            use_net_ns=False,  # Disable network namespace (often needs privileges)
            use_user_ns=False,  # Disable user namespace (mapping issues)
            use_ipc_ns=True,
            use_uts_ns=True,
            hostname="sentinal-analysis"
        )
        
        # Basic resource limits
        resource_limits = ResourceLimits(
            cpu_quota=50000,  # 50% CPU max
            memory_limit="512M",  # 512MB RAM
            memory_swap_limit="1G",
            pids_max=32,
            execution_timeout=60
        )
        
        return SandboxConfig(
            use_namespaces=True,
            namespace_config=namespace_config,
            use_chroot=False,  # Disable chroot (needs root)
            use_resource_limits=False,  # Disable for now (may need privileges)
            execution_timeout=60,
            capture_strace=True,
            monitor_file_access=True,
            monitor_process_creation=True
        )
    
    def analyze_sample_isolated(self, sample_path: str, timeout: int = 60, 
                               isolation_override: Optional[str] = None,
                               enable_auto_isolation: bool = True) -> Dict[str, Any]:
        """
        Analyze a malware sample with automatic or manual isolation
        
        Args:
            sample_path: Path to the sample to analyze
            timeout: Execution timeout in seconds
            isolation_override: Manual isolation level override ('basic', 'medium', 'high', 'maximum')
            enable_auto_isolation: Enable automatic risk-based isolation selection
            
        Returns:
            Comprehensive analysis including isolation metadata and risk assessment
        """
        
        if not os.path.exists(sample_path):
            raise FileNotFoundError(f"Sample not found: {sample_path}")
        
        try:
            # Perform risk assessment
            risk_assessment = self.risk_assessor.assess_file_risk(
                sample_path, isolation_override
            )
            
            # Determine isolation configuration
            if isolation_override and not enable_auto_isolation:
                # Use manual override
                isolation_config = self._get_isolation_config_for_level(isolation_override)
                self.logger.info(f"Using manual isolation override: {isolation_override}")
            elif enable_auto_isolation:
                # Use automatic risk-based isolation
                auto_level = risk_assessment.recommended_isolation
                isolation_config = self._get_isolation_config_for_level(auto_level)
                self.logger.info(f"Auto-selected isolation level '{auto_level}' based on risk score: {risk_assessment.overall_score}/100")
            else:
                # Use default configuration
                isolation_config = self.config
                self.logger.info("Using default isolation configuration")
            
            # Update isolation manager with selected configuration
            original_config = self.isolation_manager.config
            self.isolation_manager.config = isolation_config
            
            try:
                # Execute with selected isolation
                result = self.isolation_manager.analyze_sample(sample_path)
                
                # Add comprehensive metadata
                result['isolation_metadata'] = {
                    'isolation_level': risk_assessment.recommended_isolation if enable_auto_isolation else (isolation_override or 'default'),
                    'capabilities_used': self._get_used_capabilities(),
                    'security_score': self._calculate_security_score(),
                    'auto_isolation_enabled': enable_auto_isolation,
                    'manual_override': isolation_override,
                    'effective_isolation': risk_assessment.recommended_isolation if enable_auto_isolation else (isolation_override or 'default')
                }
                
                # Add risk assessment results
                result['risk_assessment'] = {
                    'overall_score': risk_assessment.overall_score,
                    'risk_level': risk_assessment.risk_level.value,
                    'auto_isolation': risk_assessment.auto_isolation,
                    'reasoning': risk_assessment.reasoning,
                    'factors': [
                        {
                            'name': factor.name,
                            'score': factor.score,
                            'weight': factor.weight,
                            'description': factor.description,
                            'evidence': factor.evidence
                        }
                        for factor in risk_assessment.factors
                    ]
                }
                
                return result
                
            finally:
                # Restore original configuration
                self.isolation_manager.config = original_config
            
        except Exception as e:
            self.logger.error(f"Isolated analysis failed: {e}")
            return {
                'error': f"Isolation failed: {str(e)}",
                'fallback_required': True,
                'isolation_metadata': {
                    'isolation_level': 'failed',
                    'error': str(e)
                },
                'risk_assessment': {
                    'error': 'Risk assessment unavailable due to execution failure'
                }
            }
    
    def _get_used_capabilities(self) -> Dict[str, bool]:
        """Get which isolation capabilities are actually being used"""
        caps = self.capabilities.get('capabilities', {})
        
        return {
            'pid_namespace': caps.get('namespaces', {}).get('pid', False) and self.config.use_namespaces,
            'mount_namespace': caps.get('namespaces', {}).get('mnt', False) and self.config.use_namespaces,
            'ipc_namespace': caps.get('namespaces', {}).get('ipc', False) and self.config.use_namespaces,
            'uts_namespace': caps.get('namespaces', {}).get('uts', False) and self.config.use_namespaces,
            'strace_monitoring': True,  # Always available
            'chroot_jail': False,  # Disabled in working config
            'resource_limits': False  # Disabled in working config
        }
    
    def _calculate_security_score(self) -> int:
        """Calculate a security score based on available isolation"""
        score = 0
        used_caps = self._get_used_capabilities()
        
        # Scoring system
        if used_caps['pid_namespace']: score += 20
        if used_caps['mount_namespace']: score += 20
        if used_caps['ipc_namespace']: score += 10
        if used_caps['uts_namespace']: score += 10
        if used_caps['strace_monitoring']: score += 15
        if used_caps['chroot_jail']: score += 20
        if used_caps['resource_limits']: score += 15
        
        return min(score, 100)  # Max 100
    
    def get_isolation_status(self) -> Dict[str, Any]:
        """Get current isolation status for dashboard"""
        return {
            'level': self.isolation_level,
            'security_score': self._calculate_security_score(),
            'capabilities': self._get_used_capabilities(),
            'system_info': self.capabilities.get('system_info', {}),
            'recommendations': self._get_recommendations()
        }
    
    def _get_recommendations(self) -> list:
        """Get recommendations for improving isolation"""
        recommendations = []
        
        caps = self.capabilities.get('capabilities', {})
        
        if not caps.get('chroot', {}).get('root_access', False):
            recommendations.append("Run with sudo for chroot isolation")
        
        if caps.get('resource_limits', {}).get('cgroup_version', 0) == 0:
            recommendations.append("Enable cgroups for resource limiting")
        
        if not caps.get('namespaces', {}).get('user_ns_helpers', False):
            recommendations.append("Install newuidmap/newgidmap for user namespace support")
        
        return recommendations
    
    def _get_isolation_config_for_level(self, level: str) -> SandboxConfig:
        """Create isolation configuration for specific security level"""
        
        if level == 'basic' or level == 'minimal':
            # Minimal isolation - just monitoring
            namespace_config = NamespaceConfig(
                use_pid_ns=False,
                use_mount_ns=False,
                use_net_ns=False,
                use_user_ns=False,
                use_ipc_ns=False,
                use_uts_ns=False
            )
            use_chroot = False
            use_resource_limits = False
            
        elif level == 'medium':
            # Standard isolation - basic namespaces + chroot
            namespace_config = NamespaceConfig(
                use_pid_ns=True,
                use_mount_ns=True,
                use_net_ns=True,   # Enable network isolation
                use_user_ns=False, # Skip user ns (complex mapping)
                use_ipc_ns=True,
                use_uts_ns=True,
                use_chroot=True    # Enable chroot filesystem isolation
            )
            use_chroot = True      # Enable filesystem isolation
            use_resource_limits = True
            
        elif level == 'high':
            # Enhanced isolation - full namespaces + chroot
            namespace_config = NamespaceConfig(
                use_pid_ns=True,
                use_mount_ns=True,
                use_net_ns=True,   # Network isolation enabled
                use_user_ns=False, # Skip user namespace (causes issues)
                use_ipc_ns=True,
                use_uts_ns=True,
                use_chroot=True    # Enable chroot filesystem isolation
            )
            use_chroot = True   # Enable filesystem isolation
            use_resource_limits = True
            
        elif level == 'maximum' or level == 'critical':
            # Maximum isolation - everything including chroot
            namespace_config = NamespaceConfig(
                use_pid_ns=True,
                use_mount_ns=True,
                use_net_ns=True,
                use_user_ns=False, # Skip user namespace (causes issues)
                use_ipc_ns=True,
                use_uts_ns=True,
                use_chroot=True    # Enable chroot filesystem isolation
            )
            use_chroot = True   # Requires sudo
            use_resource_limits = True
            
        else:
            # Default to medium level
            self.logger.warning(f"Unknown isolation level '{level}', using medium")
            return self._get_isolation_config_for_level('medium')
        
        # Create resource limits configuration
        resource_limits = ResourceLimits(
            cpu_quota=30000,      # 30% CPU
            memory_limit="128M",  # 128MB RAM
            pids_max=16,          # Max 16 processes
            execution_timeout=60  # 1 minute timeout
        ) if use_resource_limits else ResourceLimits(execution_timeout=60)
        
        return SandboxConfig(
            use_namespaces=any([
                namespace_config.use_pid_ns,
                namespace_config.use_mount_ns,
                namespace_config.use_net_ns,
                namespace_config.use_user_ns,
                namespace_config.use_ipc_ns,
                namespace_config.use_uts_ns
            ]),
            namespace_config=namespace_config,
            use_chroot=use_chroot,
            use_resource_limits=use_resource_limits,
            resource_limits=resource_limits,
            execution_timeout=60,
            capture_strace=True,
            monitor_file_access=True,
            monitor_process_creation=True
        )
    
    def check_sudo_availability(self):
        """Check if sudo is available for enhanced isolation"""
        try:
            # Test the sudo helper script
            sudo_helper = Path(__file__).parent.parent / "isolation" / "sudo_helper.py"
            result = subprocess.run(
                ['sudo', '-n', str(sudo_helper), 'test'], 
                capture_output=True, text=True, timeout=5
            )
            
            if result.returncode == 0:
                # Parse the JSON response to verify it's working
                response = json.loads(result.stdout)
                return response.get('success', False)
            return False
        except Exception as e:
            self.logger.warning(f"Sudo check failed: {e}")
            return False
    
    def request_sudo_access(self, action: str = "enhanced_isolation") -> Dict[str, Any]:
        """Request sudo access for enhanced isolation features"""
        try:
            # Check if already available
            if self.check_sudo_availability():
                return {
                    'success': True,
                    'message': 'Sudo access already available',
                    'enhanced_features': ['chroot_isolation', 'network_namespaces', 'device_control']
                }
            
            # Provide instructions for manual sudo setup
            sudo_helper = Path(__file__).parent.parent / "isolation" / "sudo_helper.py"
            return {
                'success': False,
                'requires_manual_setup': True,
                'message': 'Sudo access required for enhanced isolation',
                'instructions': [
                    f"Run: sudo {sudo_helper} test",
                    "Or add to sudoers for passwordless access",
                    "Enhanced isolation provides chroot jails and network namespaces"
                ],
                'enhanced_features': ['chroot_isolation', 'network_namespaces', 'device_control']
            }
            
        except Exception as e:
            return {
                'success': False,
                'error': f"Sudo check failed: {str(e)}"
            }

# Global instance for backend integration
isolation_system = None

def get_isolation_system() -> MalwareAnalysisIsolation:
    """Get or create global isolation system instance"""
    global isolation_system
    if isolation_system is None:
        isolation_system = MalwareAnalysisIsolation()
    return isolation_system

def analyze_with_isolation(sample_path: str, timeout: int = 60) -> Dict[str, Any]:
    """
    Convenience function for backend integration
    Analyze sample with best available isolation
    """
    isolation = get_isolation_system()
    return isolation.analyze_sample_isolated(sample_path, timeout)

def get_isolation_info() -> Dict[str, Any]:
    """Get isolation system information for API responses"""
    isolation = get_isolation_system()
    return isolation.get_isolation_status()

# Test function
if __name__ == "__main__":
    logging.basicConfig(level=logging.INFO)
    
    # Test the integration
    isolation = MalwareAnalysisIsolation()
    status = isolation.get_isolation_status()
    
    print("Integration Test Results:")
    print(json.dumps(status, indent=2))
    
    # Test with a sample if provided
    if len(sys.argv) > 1:
        sample_path = sys.argv[1]
        print(f"\nTesting with sample: {sample_path}")
        result = isolation.analyze_sample_isolated(sample_path)
        
        if 'error' in result:
            print(f"Analysis failed: {result['error']}")
        else:
            execution_result = result.get('execution_result')
            if execution_result:
                print(f"Analysis completed: Return code {execution_result.returncode}")
                print(f"Execution time: {execution_result.execution_time:.2f}s")
                print(f"Timed out: {execution_result.timed_out}")
            
            isolation_meta = result.get('isolation_metadata', {})
            print(f"Security score: {isolation_meta.get('security_score', 'N/A')}")
            print(f"Isolation level: {isolation_meta.get('isolation_level', 'N/A')}")