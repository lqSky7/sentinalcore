#!/usr/bin/env python3
"""
Entropy-based malware detection module.
This module calculates the entropy of files to help identify potentially malicious files.
High entropy often indicates encryption, packing, or obfuscation - common in malware.
"""

import os
import math
import hashlib
from collections import Counter
from typing import Dict, Tuple, List, Optional

class EntropyAnalyzer:
    """Class that handles entropy-based analysis of files"""
    
    # Entropy thresholds based on research and common practices
    ENTROPY_THRESHOLD = 7.0  # Files with entropy > 7.0 are suspicious (max is 8.0)
    HIGH_ENTROPY_SECTIONS_THRESHOLD = 0.4  # If 40% of sections have high entropy, flag it
    
    @staticmethod
    def calculate_entropy(data: bytes) -> float:
        """
        Calculate Shannon entropy of the given data
        
        Args:
            data: Bytes to analyze
            
        Returns:
            float: Entropy value between 0 and 8
        """
        if not data:
            return 0.0
            
        occurrences = Counter(bytearray(data))
        filesize = len(data)
        
        # Calculate entropy using Shannon's formula
        entropy = 0.0
        for count in occurrences.values():
            probability = count / filesize
            entropy -= probability * math.log2(probability)
            
        return entropy
    
    @staticmethod
    def calculate_file_md5(file_path: str) -> str:
        """
        Calculate MD5 hash of a file
        
        Args:
            file_path: Path to the file
            
        Returns:
            str: MD5 hash as hexadecimal string
        """
        hash_md5 = hashlib.md5()
        with open(file_path, "rb") as f:
            for chunk in iter(lambda: f.read(4096), b""):
                hash_md5.update(chunk)
        return hash_md5.hexdigest()
    
    def analyze_file(self, file_path: str) -> Dict:
        """
        Analyze a file for entropy and other characteristics
        
        Args:
            file_path: Path to the file to analyze
            
        Returns:
            Dict: Analysis results including entropy, MD5, and malware probability
        """
        try:
            file_size = os.path.getsize(file_path)
            
            # Skip empty files
            if file_size == 0:
                return {
                    "file_path": file_path,
                    "md5": self.calculate_file_md5(file_path),
                    "entropy": 0.0,
                    "file_size": 0,
                    "is_suspicious": False,
                    "reason": "Empty file"
                }
            
            # For large files, analyze in chunks
            if file_size > 10_000_000:  # 10MB
                return self._analyze_large_file(file_path, file_size)
            
            # For smaller files, analyze the whole file
            with open(file_path, "rb") as f:
                data = f.read()
                
            entropy = self.calculate_entropy(data)
            md5_hash = self.calculate_file_md5(file_path)
            
            return {
                "file_path": file_path,
                "md5": md5_hash,
                "entropy": entropy,
                "file_size": file_size,
                "is_suspicious": entropy > self.ENTROPY_THRESHOLD,
                "reason": f"High entropy ({entropy:.2f})" if entropy > self.ENTROPY_THRESHOLD else "Normal entropy"
            }
            
        except Exception as e:
            return {
                "file_path": file_path,
                "error": str(e),
                "is_suspicious": True,  # Consider files that can't be analyzed as suspicious
                "reason": f"Error during analysis: {str(e)}"
            }
    
    def _analyze_large_file(self, file_path: str, file_size: int) -> Dict:
        """
        Analyze a large file by chunking it
        
        Args:
            file_path: Path to the large file
            file_size: Size of the file in bytes
            
        Returns:
            Dict: Analysis results
        """
        md5_hash = self.calculate_file_md5(file_path)
        
        # Analyze file in chunks of 1MB
        chunk_size = 1_000_000
        num_chunks = min(10, file_size // chunk_size)
        if num_chunks == 0:
            num_chunks = 1
            
        high_entropy_chunks = 0
        total_entropy = 0.0
        
        with open(file_path, "rb") as f:
            for i in range(num_chunks):
                # Sample from different parts of the file
                offset = (i * file_size) // num_chunks
                f.seek(offset)
                chunk = f.read(chunk_size)
                
                entropy = self.calculate_entropy(chunk)
                total_entropy += entropy
                
                if entropy > self.ENTROPY_THRESHOLD:
                    high_entropy_chunks += 1
        
        avg_entropy = total_entropy / num_chunks
        high_entropy_ratio = high_entropy_chunks / num_chunks
        
        is_suspicious = (avg_entropy > self.ENTROPY_THRESHOLD or 
                        high_entropy_ratio > self.HIGH_ENTROPY_SECTIONS_THRESHOLD)
                        
        return {
            "file_path": file_path,
            "md5": md5_hash,
            "entropy": avg_entropy,
            "file_size": file_size,
            "high_entropy_sections": high_entropy_ratio,
            "is_suspicious": is_suspicious,
            "reason": (f"High average entropy ({avg_entropy:.2f})" if avg_entropy > self.ENTROPY_THRESHOLD 
                     else f"High proportion of high-entropy sections ({high_entropy_ratio:.2f})" 
                     if high_entropy_ratio > self.HIGH_ENTROPY_SECTIONS_THRESHOLD 
                     else "Normal entropy pattern")
        }
        
    def scan_directory(self, directory_path: str, recursive: bool = True) -> List[Dict]:
        """
        Scan all files in a directory
        
        Args:
            directory_path: Path to the directory to scan
            recursive: Whether to scan subdirectories recursively
            
        Returns:
            List[Dict]: List of analysis results for each file
        """
        results = []
        
        for root, dirs, files in os.walk(directory_path):
            for filename in files:
                file_path = os.path.join(root, filename)
                
                try:
                    # Skip symlinks and special files
                    if not os.path.isfile(file_path) or os.path.islink(file_path):
                        continue
                        
                    result = self.analyze_file(file_path)
                    results.append(result)
                    
                except Exception as e:
                    results.append({
                        "file_path": file_path,
                        "error": str(e),
                        "is_suspicious": True,
                        "reason": f"Error during analysis: {str(e)}"
                    })
            
            # If not recursive, break after the first iteration
            if not recursive:
                break
                
        return results
    
    def get_pids_for_suspicious_files(self, results: List[Dict]) -> List[int]:
        """
        Get PIDs of processes using suspicious files
        
        Args:
            results: List of file analysis results
            
        Returns:
            List[int]: List of PIDs
        """
        suspicious_pids = []
        suspicious_files = [r["file_path"] for r in results if r.get("is_suspicious", False)]
        
        # This uses Linux-specific /proc filesystem to find processes using these files
        if not suspicious_files:
            return []
            
        try:
            # Check /proc for open file handles
            for pid in os.listdir('/proc'):
                if not pid.isdigit():
                    continue
                    
                try:
                    fd_dir = f'/proc/{pid}/fd'
                    if not os.path.isdir(fd_dir):
                        continue
                        
                    for fd in os.listdir(fd_dir):
                        try:
                            link = os.readlink(f'{fd_dir}/{fd}')
                            if any(suspicious_file in link for suspicious_file in suspicious_files):
                                suspicious_pids.append(int(pid))
                                break
                        except (FileNotFoundError, PermissionError):
                            continue
                except (FileNotFoundError, PermissionError):
                    continue
                    
        except Exception as e:
            print(f"Error while scanning /proc: {str(e)}")
            
        return suspicious_pids


if __name__ == "__main__":
    # Simple command line interface for testing
    import sys
    
    if len(sys.argv) < 2:
        print(f"Usage: {sys.argv[0]} <file_or_directory_path>")
        sys.exit(1)
        
    path = sys.argv[1]
    analyzer = EntropyAnalyzer()
    
    if os.path.isfile(path):
        result = analyzer.analyze_file(path)
        print(f"Analysis for {path}:")
        for key, value in result.items():
            print(f"  {key}: {value}")
    elif os.path.isdir(path):
        results = analyzer.scan_directory(path)
        suspicious_count = sum(1 for r in results if r.get("is_suspicious", False))
        print(f"Scanned {len(results)} files in {path}")
        print(f"Found {suspicious_count} suspicious files")
        
        if suspicious_count > 0:
            print("\nSuspicious files:")
            for result in results:
                if result.get("is_suspicious", False):
                    print(f"  {result['file_path']}: {result.get('reason', 'Unknown')}")
                    
            pids = analyzer.get_pids_for_suspicious_files(results)
            if pids:
                print(f"\nProcesses using suspicious files: {pids}")
    else:
        print(f"Path {path} does not exist")