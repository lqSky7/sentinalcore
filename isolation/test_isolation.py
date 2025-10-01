#!/usr/bin/env python3
"""
Test Script for SentinalCore Isolation System

Tests isolation capabilities and demonstrates usage.
Run with: python3 test_isolation.py [sample_path]
"""

import os
import sys
import json
import logging
from pathlib import Path

# Add parent directory to path for imports
sys.path.insert(0, str(Path(__file__).parent.parent))

from isolation.isolation_manager import IsolationManager

def setup_logging():
    """Setup logging for tests"""
    logging.basicConfig(
        level=logging.INFO,
        format='%(asctime)s - %(name)s - %(levelname)s - %(message)s'
    )

def test_capabilities():
    """Test and report isolation capabilities"""
    print("=== SentinalCore Isolation System Test ===\n")
    
    # Create isolation manager
    isolation = IsolationManager()
    
    # Get status report
    status = isolation.get_status_report()
    
    print("System Status:")
    print(f"  Isolation Level: {status['isolation_level']}")
    print(f"  Platform: {status['system_info']['platform']}")
    print(f"  User ID: {status['system_info']['uid']}")
    print(f"  Python Version: {status['system_info']['python_version']}")
    
    print("\nCapabilities:")
    
    # Namespace capabilities
    ns_caps = status['capabilities'].get('namespaces', {})
    print(f"  Namespaces: {'✓' if ns_caps.get('unshare_available') else '✗'}")
    if ns_caps.get('unshare_available'):
        for ns_type in ['pid', 'mnt', 'net', 'user', 'ipc', 'uts']:
            available = ns_caps.get(ns_type, False)
            print(f"    {ns_type}: {'✓' if available else '✗'}")
    
    # Chroot capabilities
    chroot_caps = status['capabilities'].get('chroot', {})
    print(f"  Chroot: {'✓' if chroot_caps.get('root_access') else '✗'}")
    
    # Resource limit capabilities
    rl_caps = status['capabilities'].get('resource_limits', {})
    cgroup_version = rl_caps.get('cgroup_version', 0)
    print(f"  Resource Limits: {'✓' if cgroup_version > 0 else '✗'}")
    if cgroup_version > 0:
        print(f"    Cgroups Version: v{cgroup_version}")
        controllers = rl_caps.get('controllers_available', [])
        print(f"    Available Controllers: {', '.join(controllers)}")
    
    return isolation, status

def test_sample_execution(isolation, sample_path):
    """Test executing a sample"""
    print(f"\n=== Testing Sample Execution ===")
    print(f"Sample: {sample_path}")
    
    if not os.path.exists(sample_path):
        print(f"✗ Sample file not found: {sample_path}")
        return None
    
    try:
        # Analyze the sample
        print("Executing sample in sandbox...")
        result = isolation.analyze_sample(sample_path)
        
        execution = result['execution_result']
        analysis = result['analysis']
        
        print(f"\nExecution Results:")
        print(f"  Return Code: {execution.returncode}")
        print(f"  Execution Time: {execution.execution_time:.2f}s")
        print(f"  Timed Out: {execution.timed_out}")
        print(f"  Output Size: {len(execution.stdout) + len(execution.stderr)} bytes")
        
        if execution.stdout:
            print(f"\nStdout (first 200 chars):")
            print(f"  {execution.stdout[:200]}...")
        
        if execution.stderr:
            print(f"\nStderr (first 200 chars):")
            print(f"  {execution.stderr[:200]}...")
        
        # Analysis results
        exec_summary = analysis['execution_summary']
        print(f"\nAnalysis Summary:")
        print(f"  Success: {exec_summary['success']}")
        print(f"  Suspicious Activities: {len(analysis['suspicious_activities'])}")
        print(f"  System Calls: {len(analysis['system_calls'])}")
        print(f"  File Operations: {len(analysis['file_operations'])}")
        print(f"  Network Operations: {len(analysis['network_operations'])}")
        
        # Show some suspicious activities
        if analysis['suspicious_activities']:
            print(f"\nSuspicious Activities (first 3):")
            for activity in analysis['suspicious_activities'][:3]:
                print(f"  - {activity}")
        
        return result
        
    except Exception as e:
        print(f"✗ Execution failed: {e}")
        return None

def test_configurations():
    """Test different isolation configurations"""
    print(f"\n=== Testing Configurations ===")
    
    config_dir = Path(__file__).parent
    configs = [
        ('Strict', config_dir / 'config_strict.json'),
        ('Permissive', config_dir / 'config_permissive.json')
    ]
    
    for name, config_path in configs:
        if config_path.exists():
            print(f"\n{name} Configuration:")
            try:
                isolation = IsolationManager(str(config_path))
                level = isolation.get_isolation_level()
                print(f"  Isolation Level: {level}")
                print(f"  ✓ Configuration loaded successfully")
            except Exception as e:
                print(f"  ✗ Configuration failed: {e}")
        else:
            print(f"\n{name} Configuration: ✗ Config file not found")

def main():
    """Main test function"""
    setup_logging()
    
    # Test capabilities
    isolation, status = test_capabilities()
    
    # Test configurations
    test_configurations()
    
    # Test sample execution if provided
    if len(sys.argv) > 1:
        sample_path = sys.argv[1]
        test_sample_execution(isolation, sample_path)
    else:
        print(f"\n=== Sample Test ===")
        print("To test sample execution, run:")
        print(f"  python3 {sys.argv[0]} /path/to/sample")
        
        # Test with a simple command
        print("\nTesting with simple command...")
        
        # Create a simple test script
        test_script = "/tmp/test_sample.sh"
        with open(test_script, 'w') as f:
            f.write("#!/bin/bash\n")
            f.write("echo 'Hello from sandbox!'\n")
            f.write("whoami\n")
            f.write("ps aux\n")
            f.write("ls -la /\n")
        
        os.chmod(test_script, 0o755)
        
        try:
            test_sample_execution(isolation, test_script)
        finally:
            # Cleanup
            if os.path.exists(test_script):
                os.unlink(test_script)
    
    print(f"\n=== Test Complete ===")

if __name__ == "__main__":
    main()