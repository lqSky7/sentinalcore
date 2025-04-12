#!/usr/bin/env python3
"""
Test module for the entropy analyzer.
"""

import os
import sys
import unittest
import tempfile
import random
from pathlib import Path

# Add detection directory to path to import modules
sys.path.insert(0, os.path.abspath(os.path.join(os.path.dirname(__file__), '..')))
from detection.entropy import EntropyAnalyzer

class TestEntropyAnalyzer(unittest.TestCase):
    """Tests for the EntropyAnalyzer class"""
    
    def setUp(self):
        """Set up test environment"""
        self.analyzer = EntropyAnalyzer()
        self.temp_dir = tempfile.TemporaryDirectory()
        
        # Create test files
        # 1. Normal text file (low entropy)
        self.normal_file = os.path.join(self.temp_dir.name, "normal.txt")
        with open(self.normal_file, "wb") as f:
            f.write(b"This is a normal text file with relatively low entropy. " * 100)
            
        # 2. Binary file with high entropy (simulating encrypted/compressed data)
        self.high_entropy_file = os.path.join(self.temp_dir.name, "high_entropy.bin")
        with open(self.high_entropy_file, "wb") as f:
            f.write(bytes(random.getrandbits(8) for _ in range(10000)))
            
        # 3. Empty file
        self.empty_file = os.path.join(self.temp_dir.name, "empty.txt")
        open(self.empty_file, "w").close()
        
        # 4. Medium entropy file
        self.medium_entropy_file = os.path.join(self.temp_dir.name, "medium_entropy.bin")
        with open(self.medium_entropy_file, "wb") as f:
            # Mix of patterns and random data
            for _ in range(50):
                f.write(b"PATTERN" * 10)
                f.write(bytes(random.getrandbits(8) for _ in range(100)))
    
    def tearDown(self):
        """Clean up after tests"""
        self.temp_dir.cleanup()
    
    def test_calculate_entropy(self):
        """Test entropy calculation on different data types"""
        # Empty data
        self.assertEqual(self.analyzer.calculate_entropy(b""), 0.0)
        
        # Uniform data (all bytes the same) should have low entropy
        uniform_data = b"A" * 1000
        uniform_entropy = self.analyzer.calculate_entropy(uniform_data)
        self.assertLess(uniform_entropy, 0.1)
        
        # Random data should have high entropy (close to 8.0)
        random_data = bytes(random.getrandbits(8) for _ in range(1000))
        random_entropy = self.analyzer.calculate_entropy(random_data)
        self.assertGreater(random_entropy, 7.0)
    
    def test_analyze_file(self):
        """Test file analysis"""
        # Test normal file
        normal_result = self.analyzer.analyze_file(self.normal_file)
        self.assertFalse(normal_result["is_suspicious"])
        self.assertLess(normal_result["entropy"], 5.0)
        
        # Test high entropy file
        high_entropy_result = self.analyzer.analyze_file(self.high_entropy_file)
        self.assertTrue(high_entropy_result["is_suspicious"])
        self.assertGreater(high_entropy_result["entropy"], 7.0)
        
        # Test empty file
        empty_result = self.analyzer.analyze_file(self.empty_file)
        self.assertFalse(empty_result["is_suspicious"])
        self.assertEqual(empty_result["entropy"], 0.0)
    
    def test_analyze_large_file(self):
        """Test analysis of a large file"""
        # Create a "large" file for testing the chunking functionality
        # We'll use a smaller size than the actual threshold for testing purposes
        large_file = os.path.join(self.temp_dir.name, "large.bin")
        
        # Set a special attribute to trick the analyzer into treating this as a large file
        original_threshold = EntropyAnalyzer._analyze_large_file.__defaults__
        try:
            # Mock the large file threshold by monkey patching
            self.analyzer._analyze_large_file = lambda file_path, file_size: self.analyzer._analyze_large_file(file_path, 10000000)
            
            with open(large_file, "wb") as f:
                # Write both highly random and uniform sections
                for _ in range(3):
                    # High entropy section
                    f.write(bytes(random.getrandbits(8) for _ in range(1000)))
                    # Low entropy section
                    f.write(b"A" * 1000)
                    
            result = self.analyzer.analyze_file(large_file)
            
            # The analysis should have detected both high and low entropy sections
            self.assertIn("high_entropy_sections", result)
        finally:
            # Restore original behavior
            EntropyAnalyzer._analyze_large_file.__defaults__ = original_threshold
    
    def test_scan_directory(self):
        """Test directory scanning"""
        results = self.analyzer.scan_directory(self.temp_dir.name)
        
        # We should have results for each file
        self.assertEqual(len(results), 4)
        
        # At least one file should be marked as suspicious
        suspicious_count = sum(1 for result in results if result.get("is_suspicious", False))
        self.assertGreater(suspicious_count, 0)
        
    def test_calculate_file_md5(self):
        """Test MD5 calculation"""
        # Create a file with known content
        known_file = os.path.join(self.temp_dir.name, "known.txt")
        with open(known_file, "wb") as f:
            f.write(b"hello world")
            
        # MD5 of "hello world" is 5eb63bbbe01eeed093cb22bb8f5acdc3
        expected_md5 = "5eb63bbbe01eeed093cb22bb8f5acdc3"
        calculated_md5 = self.analyzer.calculate_file_md5(known_file)
        
        self.assertEqual(calculated_md5, expected_md5)


if __name__ == "__main__":
    unittest.main()