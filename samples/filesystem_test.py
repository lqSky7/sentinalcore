#!/usr/bin/env python3
"""
Test script to verify chroot filesystem isolation
This script tries to access host filesystem areas that should be blocked
"""

import os
import sys

def test_filesystem_access():
    """Test if we can access host filesystem areas"""
    
    print("Testing filesystem access from isolated environment...")
    
    # Try to access various host directories
    test_paths = [
        '/home',           # User home directories 
        '/etc/passwd',     # System configuration
        '/var/log',        # System logs
        '/usr/local',      # Local installations
        '/root',           # Root home directory
    ]
    
    accessible_paths = []
    blocked_paths = []
    
    for path in test_paths:
        try:
            if os.path.exists(path):
                accessible_paths.append(path)
                print(f"⚠️  ACCESSIBLE: {path}")
            else:
                blocked_paths.append(path)
                print(f"✅ BLOCKED: {path} (does not exist)")
        except Exception as e:
            blocked_paths.append(path)
            print(f"✅ BLOCKED: {path} (error: {e})")
    
    # List what's actually visible at root level
    try:
        root_contents = os.listdir('/')
        print(f"\n📂 Visible directories at /: {', '.join(sorted(root_contents))}")
    except Exception as e:
        print(f"❌ Cannot list root directory: {e}")
    
    # Check if we can read/write in current directory 
    try:
        with open('test_write.txt', 'w') as f:
            f.write('test data')
        os.remove('test_write.txt')
        print("✅ Can write to current directory")
    except Exception as e:
        print(f"❌ Cannot write to current directory: {e}")
        
    print(f"\n🔒 ISOLATION SUMMARY:")
    print(f"   Blocked paths: {len(blocked_paths)}/{len(test_paths)}")
    print(f"   Security status: {'🛡️  SECURE' if len(accessible_paths) == 0 else '⚠️  VULNERABLE'}")
    
    return len(accessible_paths) == 0

if __name__ == '__main__':
    is_secure = test_filesystem_access()
    sys.exit(0 if is_secure else 1)