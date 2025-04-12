#!/usr/bin/env python3
"""
VirusTotal integration module.
This module handles the upload and checking of files against the VirusTotal API.
"""

import os
import time
import json
import hashlib
import requests
from typing import Dict, List, Optional, Union, Tuple


class VirusTotalClient:
    """Client for interacting with the VirusTotal API"""
    
    BASE_URL = "https://www.virustotal.com/api/v3"
    
    def __init__(self, api_key: str):
        """
        Initialize the VirusTotal client
        
        Args:
            api_key: VirusTotal API key
        """
        self.api_key = api_key
        self.headers = {
            "x-apikey": self.api_key,
            "Accept": "application/json"
        }
        
    def get_file_report_by_hash(self, file_hash: str) -> Dict:
        """
        Get a file report by its hash
        
        Args:
            file_hash: MD5, SHA-1, or SHA-256 hash of the file
            
        Returns:
            Dict: Report data from VirusTotal
        """
        url = f"{self.BASE_URL}/files/{file_hash}"
        response = requests.get(url, headers=self.headers)
        
        if response.status_code == 200:
            return response.json()
        elif response.status_code == 404:
            return {"error": "File not found in VirusTotal database"}
        else:
            return {"error": f"VirusTotal API error: {response.status_code} - {response.text}"}
    
    def upload_file(self, file_path: str) -> Dict:
        """
        Upload a file to VirusTotal for scanning
        
        Args:
            file_path: Path to the file to upload
            
        Returns:
            Dict: Upload response from VirusTotal
        """
        url = f"{self.BASE_URL}/files"
        
        # Check file size before uploading (VirusTotal has a size limit)
        file_size = os.path.getsize(file_path)
        if file_size > 32 * 1024 * 1024:  # 32MB is the current limit
            return {"error": "File too large for VirusTotal upload (max 32MB)"}
            
        with open(file_path, "rb") as file:
            files = {"file": (os.path.basename(file_path), file)}
            response = requests.post(url, headers=self.headers, files=files)
        
        if response.status_code == 200:
            return response.json()
        else:
            return {"error": f"VirusTotal upload error: {response.status_code} - {response.text}"}
    
    def get_upload_analysis(self, analysis_id: str) -> Dict:
        """
        Get the analysis result for a previously uploaded file
        
        Args:
            analysis_id: Analysis ID returned by upload_file
            
        Returns:
            Dict: Analysis data from VirusTotal
        """
        url = f"{self.BASE_URL}/analyses/{analysis_id}"
        response = requests.get(url, headers=self.headers)
        
        if response.status_code == 200:
            return response.json()
        else:
            return {"error": f"VirusTotal analysis error: {response.status_code} - {response.text}"}
            
    def check_file(self, file_path: str, wait_for_analysis: bool = True, max_wait_time: int = 60) -> Dict:
        """
        Check a file against VirusTotal - first try by hash, then upload if needed
        
        Args:
            file_path: Path to the file to check
            wait_for_analysis: Whether to wait for analysis to complete if file is uploaded
            max_wait_time: Maximum time to wait for analysis in seconds
            
        Returns:
            Dict: Analysis results with malware detection details
        """
        # First calculate the file hash
        sha256 = self._calculate_sha256(file_path)
        
        # Check if the file is already in VirusTotal database
        report = self.get_file_report_by_hash(sha256)
        
        # If file was found in database
        if "error" not in report:
            return self._process_report(report)
            
        # If file was not found, upload it
        upload_result = self.upload_file(file_path)
        if "error" in upload_result:
            return {"file_path": file_path, "error": upload_result["error"], "is_malicious": False}
            
        # If we don't need to wait for analysis
        if not wait_for_analysis:
            return {"file_path": file_path, "status": "Submitted for analysis", "is_malicious": False}
            
        # Wait for analysis to complete
        analysis_id = upload_result.get("data", {}).get("id")
        if not analysis_id:
            return {"file_path": file_path, "error": "No analysis ID in response", "is_malicious": False}
            
        # Poll for results
        wait_time = 0
        poll_interval = 5  # seconds
        
        while wait_time < max_wait_time:
            time.sleep(poll_interval)
            wait_time += poll_interval
            
            analysis_result = self.get_upload_analysis(analysis_id)
            
            if "error" not in analysis_result:
                status = analysis_result.get("data", {}).get("attributes", {}).get("status")
                
                if status == "completed":
                    # Get the full report using the file hash
                    report = self.get_file_report_by_hash(sha256)
                    if "error" not in report:
                        return self._process_report(report)
                    else:
                        # If we can't get the report, return the analysis result
                        return self._process_analysis_result(analysis_result)
            
        # If we timed out
        return {"file_path": file_path, "status": "Analysis timeout", "is_malicious": False}
    
    def _process_report(self, report: Dict) -> Dict:
        """
        Process a VirusTotal report into a standardized format
        
        Args:
            report: Full report from VirusTotal API
            
        Returns:
            Dict: Processed report with key information
        """
        attributes = report.get("data", {}).get("attributes", {})
        stats = attributes.get("last_analysis_stats", {})
        
        total_engines = sum(stats.values())
        malicious_count = stats.get("malicious", 0)
        suspicious_count = stats.get("suspicious", 0)
        detection_ratio = f"{malicious_count + suspicious_count}/{total_engines}"
        
        # Determine if file is malicious based on detections
        threshold = 3  # Consider malicious if 3 or more engines flag it
        is_malicious = (malicious_count + suspicious_count) >= threshold
        
        return {
            "sha256": attributes.get("sha256", ""),
            "md5": attributes.get("md5", ""),
            "detection_ratio": detection_ratio,
            "is_malicious": is_malicious,
            "first_seen": attributes.get("first_submission_date", ""),
            "last_seen": attributes.get("last_analysis_date", ""),
            "file_type": attributes.get("type_description", ""),
            "names": attributes.get("names", []),
        }
    
    def _process_analysis_result(self, analysis_result: Dict) -> Dict:
        """
        Process an analysis result into a standardized format
        
        Args:
            analysis_result: Analysis result from VirusTotal API
            
        Returns:
            Dict: Processed analysis with key information
        """
        attributes = analysis_result.get("data", {}).get("attributes", {})
        stats = attributes.get("stats", {})
        
        total_engines = sum(stats.values())
        malicious_count = stats.get("malicious", 0)
        suspicious_count = stats.get("suspicious", 0)
        detection_ratio = f"{malicious_count + suspicious_count}/{total_engines}"
        
        # Determine if file is malicious based on detections
        threshold = 3  # Consider malicious if 3 or more engines flag it
        is_malicious = (malicious_count + suspicious_count) >= threshold
        
        return {
            "detection_ratio": detection_ratio,
            "is_malicious": is_malicious,
            "status": attributes.get("status", ""),
            "analysis_id": analysis_result.get("data", {}).get("id", ""),
        }
    
    @staticmethod
    def _calculate_sha256(file_path: str) -> str:
        """
        Calculate SHA-256 hash of a file
        
        Args:
            file_path: Path to the file
            
        Returns:
            str: SHA-256 hash as hexadecimal string
        """
        sha256_hash = hashlib.sha256()
        with open(file_path, "rb") as f:
            for byte_block in iter(lambda: f.read(4096), b""):
                sha256_hash.update(byte_block)
        return sha256_hash.hexdigest()
            
    def get_pids_for_malicious_files(self, malicious_files: List[str]) -> List[int]:
        """
        Get PIDs of processes using malicious files
        
        Args:
            malicious_files: List of malicious file paths
            
        Returns:
            List[int]: List of PIDs
        """
        malicious_pids = []
        
        # This uses Linux-specific /proc filesystem to find processes using these files
        if not malicious_files:
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
                            if any(malicious_file in link for malicious_file in malicious_files):
                                malicious_pids.append(int(pid))
                                break
                        except (FileNotFoundError, PermissionError):
                            continue
                except (FileNotFoundError, PermissionError):
                    continue
                    
        except Exception as e:
            print(f"Error while scanning /proc: {str(e)}")
            
        return malicious_pids


if __name__ == "__main__":
    # Simple command line interface for testing
    import sys
    
    if len(sys.argv) < 3:
        print(f"Usage: {sys.argv[0]} <api_key> <file_path>")
        sys.exit(1)
    
    api_key = sys.argv[1]
    file_path = sys.argv[2]
    
    client = VirusTotalClient(api_key)
    result = client.check_file(file_path)
    
    print(f"VirusTotal results for {file_path}:")
    for key, value in result.items():
        print(f"  {key}: {value}")
        
    if result.get("is_malicious", False):
        print("\nWARNING: This file is flagged as malicious by VirusTotal!")