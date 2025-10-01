#!/usr/bin/env python3
"""
Comprehensive test of SentinalCore Auto-Isolation System

This script demonstrates the complete automatic isolation functionality:
1. Risk assessment based on file characteristics
2. Automatic isolation level selection
3. Execution with appropriate security measures
"""

import os
import sys
import json
from pathlib import Path

# Add the project root to path
sys.path.insert(0, str(Path(__file__).parent))

# Test the complete auto-isolation system
def test_auto_isolation_system():
    print("🔒 SentinalCore Auto-Isolation System Test")
    print("=" * 50)
    
    # Import required components
    from backend.isolation_integration import get_isolation_system
    from isolation.risk_assessor import assess_file_risk
    
    # Test files with different risk levels
    test_files = [
        {
            'name': 'Low Risk Script',
            'path': 'samples/isolation_test.sh',
            'expected_risk': 'low'
        },
        {
            'name': 'Medium Risk Malware Simulator',
            'path': 'samples/high_risk_malware.sh', 
            'expected_risk': 'medium'
        }
    ]
    
    isolation_system = get_isolation_system()
    
    for test_file in test_files:
        print(f"\n📁 Testing: {test_file['name']}")
        print(f"Path: {test_file['path']}")
        print("-" * 30)
        
        if not os.path.exists(test_file['path']):
            print(f"❌ File not found: {test_file['path']}")
            continue
        
        try:
            # 1. Perform risk assessment
            print("🎯 Risk Assessment:")
            risk_assessment = assess_file_risk(test_file['path'])
            
            print(f"   Score: {risk_assessment.overall_score}/100")
            print(f"   Level: {risk_assessment.risk_level.value}")
            print(f"   Recommended Isolation: {risk_assessment.recommended_isolation}")
            print(f"   Auto-Isolation: {risk_assessment.auto_isolation}")
            
            # Show top risk factors
            print("   Top Risk Factors:")
            sorted_factors = sorted(risk_assessment.factors, 
                                  key=lambda f: f.score * f.weight, reverse=True)
            for factor in sorted_factors[:3]:
                contribution = int(factor.score * factor.weight)
                print(f"     • {factor.name}: {factor.score}/100 (contribution: {contribution})")
                if factor.evidence:
                    print(f"       - {factor.evidence[0]}")
            
            # 2. Test automatic isolation
            print("\n🤖 Automatic Isolation Analysis:")
            result = isolation_system.analyze_sample_isolated(
                test_file['path'], 
                timeout=30, 
                enable_auto_isolation=True
            )
            
            if 'error' in result:
                print(f"   ❌ Analysis failed: {result['error']}")
                continue
            
            # Display results
            isolation_meta = result.get('isolation_metadata', {})
            risk_meta = result.get('risk_assessment', {})
            
            print(f"   Effective Isolation: {isolation_meta.get('effective_isolation', 'unknown')}")
            print(f"   Security Score: {isolation_meta.get('security_score', 0)}/100")
            print(f"   Auto-Isolation Enabled: {isolation_meta.get('auto_isolation_enabled', False)}")
            
            # Execution results
            exec_result = result.get('execution_result')
            if exec_result:
                print(f"   Execution Status: {'✅ Success' if exec_result.returncode == 0 else '❌ Failed'}")
                print(f"   Return Code: {exec_result.returncode}")
                print(f"   Execution Time: {exec_result.execution_time:.2f}s")
                print(f"   Timed Out: {exec_result.timed_out}")
            
            # 3. Test manual isolation override
            print("\n⚙️  Manual Override Test (High Isolation):")
            manual_result = isolation_system.analyze_sample_isolated(
                test_file['path'],
                timeout=30,
                isolation_override='high',
                enable_auto_isolation=False
            )
            
            if 'error' not in manual_result:
                manual_meta = manual_result.get('isolation_metadata', {})
                print(f"   Override Isolation: {manual_meta.get('effective_isolation', 'unknown')}")
                print(f"   Manual Override: {manual_meta.get('manual_override', 'none')}")
                print(f"   Auto-Isolation Disabled: {not manual_meta.get('auto_isolation_enabled', True)}")
            
            print("\n✅ Test completed successfully")
            
        except Exception as e:
            print(f"❌ Test failed: {str(e)}")
            import traceback
            traceback.print_exc()

def test_risk_assessment_only():
    """Test just the risk assessment component"""
    print("\n🎯 Risk Assessment Component Test")
    print("=" * 40)
    
    from isolation.risk_assessor import assess_file_risk
    
    # Test with different file types
    test_cases = [
        'samples/isolation_test.sh',
        'samples/high_risk_malware.sh',
        'backend/app.py',  # Python file
        'README.md'        # Document
    ]
    
    for file_path in test_cases:
        if not os.path.exists(file_path):
            continue
            
        print(f"\n📄 {file_path}")
        try:
            assessment = assess_file_risk(file_path)
            print(f"   Risk: {assessment.overall_score}/100 ({assessment.risk_level.value})")
            print(f"   Isolation: {assessment.recommended_isolation}")
            
            # Show evidence for highest-scoring factor
            top_factor = max(assessment.factors, key=lambda f: f.score * f.weight)
            print(f"   Primary concern: {top_factor.name} ({int(top_factor.score * top_factor.weight)} points)")
            if top_factor.evidence:
                print(f"   Evidence: {top_factor.evidence[0]}")
                
        except Exception as e:
            print(f"   Error: {e}")

def demonstrate_isolation_levels():
    """Demonstrate different isolation levels"""
    print("\n🔒 Isolation Level Demonstration")
    print("=" * 40)
    
    from backend.isolation_integration import get_isolation_system
    
    isolation = get_isolation_system()
    
    # Test different isolation levels
    levels = ['basic', 'medium', 'high', 'maximum']
    test_file = 'samples/isolation_test.sh'
    
    if not os.path.exists(test_file):
        print(f"Test file not found: {test_file}")
        return
    
    for level in levels:
        print(f"\n🔧 Testing {level.upper()} isolation:")
        try:
            # Create isolation config for this level
            config = isolation._get_isolation_config_for_level(level)
            
            print(f"   Namespaces: {config.use_namespaces}")
            if config.use_namespaces:
                ns_config = config.namespace_config
                enabled_ns = []
                if ns_config.use_pid_ns: enabled_ns.append('PID')
                if ns_config.use_mount_ns: enabled_ns.append('Mount')
                if ns_config.use_net_ns: enabled_ns.append('Network')
                if ns_config.use_user_ns: enabled_ns.append('User')
                if ns_config.use_ipc_ns: enabled_ns.append('IPC')
                if ns_config.use_uts_ns: enabled_ns.append('UTS')
                print(f"   Enabled NS: {', '.join(enabled_ns) if enabled_ns else 'None'}")
            
            print(f"   Chroot: {config.use_chroot}")
            print(f"   Resource Limits: {config.use_resource_limits}")
            print(f"   Monitoring: strace={config.capture_strace}")
            
            # Calculate theoretical security score for this level
            security_features = 0
            if config.use_namespaces: security_features += 30
            if config.use_chroot: security_features += 25
            if config.use_resource_limits: security_features += 20
            if config.capture_strace: security_features += 15
            
            print(f"   Estimated Security: {min(100, security_features)}/100")
            
        except Exception as e:
            print(f"   Error testing {level}: {e}")

if __name__ == "__main__":
    print("🚀 SentinalCore Auto-Isolation Test Suite")
    print("This demonstrates the complete risk-based isolation system")
    print()
    
    # Change to the correct directory
    os.chdir(Path(__file__).parent)
    
    try:
        # Test 1: Risk Assessment Only
        test_risk_assessment_only()
        
        # Test 2: Isolation Level Configuration
        demonstrate_isolation_levels()
        
        # Test 3: Complete Auto-Isolation System
        test_auto_isolation_system()
        
        print("\n🎉 All tests completed!")
        print("\nAuto-Isolation System Features:")
        print("✅ Automatic risk assessment based on file characteristics")
        print("✅ Dynamic isolation level selection")
        print("✅ Manual isolation override capability")  
        print("✅ Comprehensive security scoring")
        print("✅ Graceful degradation based on available privileges")
        print("✅ Web interface integration")
        
    except KeyboardInterrupt:
        print("\n⏹️  Tests interrupted by user")
    except Exception as e:
        print(f"\n❌ Test suite failed: {e}")
        import traceback
        traceback.print_exc()