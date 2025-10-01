#!/usr/bin/env python3
"""
Quick test of the static analyzer functionality
"""

import sys
import os
sys.path.append('/Users/ca5/Desktop/sentinal/backend')

from static_analyzer import StaticAnalyzer

def test_static_analyzer():
    analyzer = StaticAnalyzer()
    
    # Test entropy analysis
    print("=== Testing Entropy Analysis ===")
    test_file = "/Users/ca5/Desktop/sentinal/samples/static_test_malware.py"
    
    if os.path.exists(test_file):
        result = analyzer.analyze_file_entropy(test_file)
        print(f"File: {test_file}")
        print(f"Entropy: {result.get('overall_entropy', 'N/A')}")
        print(f"Suspicion: {result.get('suspicion_level', 'N/A')}")
        print(f"Reasons: {result.get('suspicion_reasons', [])}")
        print()
    
    # Test hash calculation
    print("=== Testing Hash Calculation ===")
    if os.path.exists(test_file):
        hashes = analyzer.get_file_hash(test_file)
        print(f"MD5: {hashes.get('md5', 'N/A')}")
        print(f"SHA256: {hashes.get('sha256', 'N/A')}")
        print()
    
    # Test string extraction
    print("=== Testing String Extraction ===")
    if os.path.exists(test_file):
        strings = analyzer.extract_strings(test_file)
        print(f"Total strings: {strings.get('total_strings', 0)}")
        print(f"Suspicious strings: {len(strings.get('suspicious_strings', []))}")
        if strings.get('suspicious_strings'):
            print("Sample suspicious strings:")
            for s in strings['suspicious_strings'][:5]:
                print(f"  - {s}")
        print()

if __name__ == "__main__":
    test_static_analyzer()