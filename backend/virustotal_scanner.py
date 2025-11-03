#!/usr/bin/env python3
"""
VirusTotal API Integration Module
Scans files using VirusTotal API v3
"""

import os
import time
import hashlib
import requests
import json
from datetime import datetime


class VirusTotalScanner:
    """
    VirusTotal API v3 integration for file scanning
    Supports all file types including APK files
    """
    
    def __init__(self, api_key):
        """
        Initialize VirusTotal scanner
        
        Args:
            api_key (str): VirusTotal API key
        """
        self.api_key = api_key
        self.base_url = "https://www.virustotal.com/api/v3"
        self.headers = {
            "x-apikey": api_key,
            "Accept": "application/json"
        }
    
    def calculate_file_hash(self, file_path):
        """
        Calculate SHA256 hash of file
        
        Args:
            file_path (str): Path to file
            
        Returns:
            str: SHA256 hash
        """
        sha256_hash = hashlib.sha256()
        
        with open(file_path, "rb") as f:
            # Read file in chunks to handle large files
            for byte_block in iter(lambda: f.read(4096), b""):
                sha256_hash.update(byte_block)
        
        return sha256_hash.hexdigest()
    
    def check_existing_report(self, file_hash):
        """
        Check if file hash already has a scan report
        
        Args:
            file_hash (str): SHA256 hash of file
            
        Returns:
            dict: Scan report if exists, None otherwise
        """
        url = f"{self.base_url}/files/{file_hash}"
        
        try:
            response = requests.get(url, headers=self.headers, timeout=30)
            
            if response.status_code == 200:
                return response.json()
            elif response.status_code == 404:
                # File not found in VirusTotal database
                return None
            else:
                return {
                    'error': f'API Error {response.status_code}: {response.text}'
                }
        except requests.exceptions.RequestException as e:
            return {'error': f'Network error: {str(e)}'}
    
    def upload_file(self, file_path):
        """
        Upload file to VirusTotal for scanning
        
        Args:
            file_path (str): Path to file to upload
            
        Returns:
            dict: Upload response with analysis ID
        """
        url = f"{self.base_url}/files"
        
        # Check file size
        file_size = os.path.getsize(file_path)
        
        # VirusTotal has different endpoints based on file size
        # Files > 32MB need special upload URL
        if file_size > 32 * 1024 * 1024:  # 32MB
            return self._upload_large_file(file_path)
        
        try:
            with open(file_path, 'rb') as f:
                files = {'file': (os.path.basename(file_path), f)}
                response = requests.post(
                    url, 
                    headers={"x-apikey": self.api_key}, 
                    files=files,
                    timeout=300  # 5 minute timeout for upload
                )
            
            if response.status_code == 200:
                return response.json()
            else:
                return {
                    'error': f'Upload failed: {response.status_code} - {response.text}'
                }
        except requests.exceptions.RequestException as e:
            return {'error': f'Upload error: {str(e)}'}
    
    def _upload_large_file(self, file_path):
        """
        Upload large file (>32MB) to VirusTotal
        
        Args:
            file_path (str): Path to large file
            
        Returns:
            dict: Upload response
        """
        # Get upload URL for large files
        url = f"{self.base_url}/files/upload_url"
        
        try:
            response = requests.get(url, headers=self.headers, timeout=30)
            
            if response.status_code != 200:
                return {
                    'error': f'Failed to get upload URL: {response.status_code}'
                }
            
            upload_url = response.json().get('data')
            
            # Upload to the special URL
            with open(file_path, 'rb') as f:
                files = {'file': (os.path.basename(file_path), f)}
                response = requests.post(
                    upload_url,
                    headers={"x-apikey": self.api_key},
                    files=files,
                    timeout=600  # 10 minute timeout for large files
                )
            
            if response.status_code == 200:
                return response.json()
            else:
                return {
                    'error': f'Large file upload failed: {response.status_code}'
                }
        except requests.exceptions.RequestException as e:
            return {'error': f'Large file upload error: {str(e)}'}
    
    def get_analysis_result(self, analysis_id):
        """
        Get analysis results for a file
        
        Args:
            analysis_id (str): Analysis ID from upload response
            
        Returns:
            dict: Analysis results
        """
        url = f"{self.base_url}/analyses/{analysis_id}"
        
        try:
            response = requests.get(url, headers=self.headers, timeout=30)
            
            if response.status_code == 200:
                return response.json()
            else:
                return {
                    'error': f'Analysis retrieval failed: {response.status_code}'
                }
        except requests.exceptions.RequestException as e:
            return {'error': f'Analysis retrieval error: {str(e)}'}
    
    def wait_for_analysis(self, analysis_id, max_wait=300, check_interval=10):
        """
        Wait for analysis to complete
        
        Args:
            analysis_id (str): Analysis ID to monitor
            max_wait (int): Maximum time to wait in seconds
            check_interval (int): Time between checks in seconds
            
        Returns:
            dict: Final analysis results
        """
        start_time = time.time()
        
        while time.time() - start_time < max_wait:
            result = self.get_analysis_result(analysis_id)
            
            if 'error' in result:
                return result
            
            status = result.get('data', {}).get('attributes', {}).get('status')
            
            if status == 'completed':
                return result
            elif status == 'queued' or status == 'in-progress':
                time.sleep(check_interval)
            else:
                return {
                    'error': f'Unknown analysis status: {status}'
                }
        
        return {
            'error': 'Analysis timeout - check VirusTotal dashboard for results',
            'analysis_id': analysis_id
        }
    
    def parse_scan_results(self, result_data):
        """
        Parse and summarize scan results
        
        Args:
            result_data (dict): Raw VirusTotal API response
            
        Returns:
            dict: Parsed and summarized results
        """
        if 'error' in result_data:
            return result_data
        
        data = result_data.get('data', {})
        attributes = data.get('attributes', {})
        
        # Try to get metadata - might be in different places for analysis vs file report
        meta = result_data.get('meta', {}).get('file_info', {})
        
        # Get detection statistics
        stats = attributes.get('stats', {})
        last_analysis_stats = attributes.get('last_analysis_stats', stats)
        
        # Get individual scanner results
        results = attributes.get('last_analysis_results', {})
        
        # If no results yet, might still be processing
        if not results:
            return {
                'processing': True,
                'message': 'Scan in progress - results not yet available'
            }
        
        # Categorize detections
        malicious_detections = []
        suspicious_detections = []
        clean_detections = []
        
        for engine, result in results.items():
            category = result.get('category', 'undetected')
            result_text = result.get('result')
            
            detection = {
                'engine': engine,
                'category': category,
                'result': result_text,
                'method': result.get('method', 'unknown'),
                'engine_version': result.get('engine_version', 'unknown')
            }
            
            if category == 'malicious':
                malicious_detections.append(detection)
            elif category in ['suspicious', 'undetected']:
                if result_text and result_text != 'None':
                    suspicious_detections.append(detection)
            elif category == 'undetected':
                clean_detections.append(detection)
        
        # Get file metadata - try multiple sources
        file_info = {
            'sha256': attributes.get('sha256') or meta.get('sha256', ''),
            'sha1': attributes.get('sha1') or meta.get('sha1', ''),
            'md5': attributes.get('md5') or meta.get('md5', ''),
            'file_type': attributes.get('type_description') or meta.get('type_description', 'Unknown'),
            'file_size': attributes.get('size') or meta.get('size', 0),
            'magic': attributes.get('magic', ''),
            'meaningful_name': attributes.get('meaningful_name') or attributes.get('names', [None])[0] or '',
            'tags': attributes.get('tags', [])
        }
        
        # Calculate detection rate
        total_scans = (last_analysis_stats.get('malicious', 0) + 
                      last_analysis_stats.get('suspicious', 0) + 
                      last_analysis_stats.get('undetected', 0) + 
                      last_analysis_stats.get('harmless', 0) + 
                      last_analysis_stats.get('failure', 0) + 
                      last_analysis_stats.get('timeout', 0))
        
        detection_rate = 0
        if total_scans > 0:
            detection_rate = (last_analysis_stats.get('malicious', 0) / total_scans) * 100
        
        # Determine threat level
        malicious_count = last_analysis_stats.get('malicious', 0)
        if malicious_count == 0:
            threat_level = 'CLEAN'
            threat_color = 'green'
        elif malicious_count <= 3:
            threat_level = 'LOW'
            threat_color = 'yellow'
        elif malicious_count <= 10:
            threat_level = 'MEDIUM'
            threat_color = 'orange'
        else:
            threat_level = 'HIGH'
            threat_color = 'red'
        
        # Get popular threat names
        popular_threat_label = attributes.get('popular_threat_classification', {}).get('popular_threat_name', [])
        if isinstance(popular_threat_label, list):
            popular_threat_label = popular_threat_label[0] if popular_threat_label else 'Unknown'
        
        summary = {
            'scan_date': attributes.get('last_analysis_date', 
                                       attributes.get('first_submission_date', 
                                                     int(time.time()))),
            'detection_stats': last_analysis_stats,
            'total_engines': total_scans,
            'malicious_count': malicious_count,
            'suspicious_count': last_analysis_stats.get('suspicious', 0),
            'clean_count': last_analysis_stats.get('undetected', 0) + last_analysis_stats.get('harmless', 0),
            'detection_rate': round(detection_rate, 2),
            'threat_level': threat_level,
            'threat_color': threat_color,
            'threat_label': popular_threat_label,
            'file_info': file_info,
            'malicious_detections': malicious_detections,
            'suspicious_detections': suspicious_detections,
            'reputation': attributes.get('reputation', 0),
            'times_submitted': attributes.get('times_submitted', 0),
            'permalink': f"https://www.virustotal.com/gui/file/{file_info['sha256']}"
        }
        
        return summary
    
    def scan_file(self, file_path, wait_for_result=True, max_wait=300):
        """
        Complete scan workflow: check existing report, upload if needed, wait for results
        
        Args:
            file_path (str): Path to file to scan
            wait_for_result (bool): Whether to wait for scan completion
            max_wait (int): Maximum time to wait for results in seconds
            
        Returns:
            dict: Comprehensive scan results
        """
        if not os.path.exists(file_path):
            return {
                'success': False,
                'error': f'File not found: {file_path}'
            }
        
        scan_info = {
            'success': True,
            'file_path': file_path,
            'file_name': os.path.basename(file_path),
            'file_size': os.path.getsize(file_path),
            'scan_timestamp': datetime.now().isoformat()
        }
        
        # Step 1: Calculate file hash
        print(f"Calculating file hash for {file_path}...")
        file_hash = self.calculate_file_hash(file_path)
        scan_info['file_hash'] = file_hash
        
        # Step 2: Check for existing report
        print(f"Checking existing report for hash: {file_hash}...")
        existing_report = self.check_existing_report(file_hash)
        
        if existing_report and 'error' not in existing_report:
            print("Found existing scan report!")
            scan_info['scan_type'] = 'existing_report'
            scan_info['results'] = self.parse_scan_results(existing_report)
            return scan_info
        
        # Step 3: Upload file for scanning
        print(f"Uploading file to VirusTotal...")
        upload_response = self.upload_file(file_path)
        
        if 'error' in upload_response:
            scan_info['success'] = False
            scan_info['error'] = upload_response['error']
            return scan_info
        
        analysis_id = upload_response.get('data', {}).get('id')
        
        if not analysis_id:
            scan_info['success'] = False
            scan_info['error'] = 'No analysis ID received from upload'
            return scan_info
        
        scan_info['analysis_id'] = analysis_id
        scan_info['scan_type'] = 'new_upload'
        
        if not wait_for_result:
            scan_info['message'] = 'File uploaded successfully. Check VirusTotal dashboard for results.'
            return scan_info
        
        # Step 4: Wait for analysis to complete
        print(f"Waiting for analysis to complete (ID: {analysis_id})...")
        analysis_result = self.wait_for_analysis(analysis_id, max_wait=max_wait)
        
        if 'error' in analysis_result:
            scan_info['success'] = False
            scan_info['error'] = analysis_result['error']
            return scan_info
        
        # Step 5: Fetch the complete file report using the hash
        print("Fetching complete file report...")
        file_report = self.check_existing_report(file_hash)
        
        if file_report and 'error' not in file_report:
            print("Analysis complete! Parsing results...")
            scan_info['results'] = self.parse_scan_results(file_report)
        else:
            # Fallback to analysis result if file report not available yet
            print("Using analysis result...")
            scan_info['results'] = self.parse_scan_results(analysis_result)
        
        return scan_info


def main():
    """
    Command-line interface for VirusTotal scanning
    """
    import sys
    import argparse
    
    parser = argparse.ArgumentParser(
        description='Scan files using VirusTotal API',
        formatter_class=argparse.RawDescriptionHelpFormatter,
        epilog="""
Examples:
  # Scan a file with API key
  python virustotal_scanner.py --api-key YOUR_API_KEY --file /path/to/malware.apk
  
  # Scan without waiting for results
  python virustotal_scanner.py --api-key YOUR_API_KEY --file sample.exe --no-wait
  
  # Use API key from environment variable
  export VT_API_KEY=your_api_key_here
  python virustotal_scanner.py --file suspicious.apk
        """
    )
    
    parser.add_argument(
        '--api-key',
        help='VirusTotal API key (or set VT_API_KEY environment variable)',
        default=os.getenv('VT_API_KEY')
    )
    parser.add_argument(
        '--file',
        required=True,
        help='Path to file to scan (supports APK and all file types)'
    )
    parser.add_argument(
        '--no-wait',
        action='store_true',
        help='Upload file but don\'t wait for results'
    )
    parser.add_argument(
        '--max-wait',
        type=int,
        default=300,
        help='Maximum time to wait for results in seconds (default: 300)'
    )
    parser.add_argument(
        '--json',
        action='store_true',
        help='Output results in JSON format'
    )
    
    args = parser.parse_args()
    
    if not args.api_key:
        print("Error: API key required. Provide via --api-key or VT_API_KEY environment variable")
        sys.exit(1)
    
    # Initialize scanner
    scanner = VirusTotalScanner(args.api_key)
    
    # Scan file
    result = scanner.scan_file(
        args.file,
        wait_for_result=not args.no_wait,
        max_wait=args.max_wait
    )
    
    # Output results
    if args.json:
        print(json.dumps(result, indent=2))
    else:
        # Pretty print results
        print("\n" + "="*80)
        print("VIRUSTOTAL SCAN RESULTS")
        print("="*80)
        
        if not result.get('success'):
            print(f"\n❌ SCAN FAILED: {result.get('error', 'Unknown error')}")
            sys.exit(1)
        
        print(f"\n📁 File: {result['file_name']}")
        print(f"📏 Size: {result['file_size']:,} bytes")
        print(f"🔑 SHA256: {result['file_hash']}")
        
        if 'results' in result:
            res = result['results']
            
            print(f"\n🎯 THREAT LEVEL: {res['threat_level']}")
            print(f"🏷️  Threat Label: {res['threat_label']}")
            print(f"\n📊 Detection Statistics:")
            print(f"   • Total Engines: {res['total_engines']}")
            print(f"   • Malicious: {res['malicious_count']}")
            print(f"   • Suspicious: {res['suspicious_count']}")
            print(f"   • Clean: {res['clean_count']}")
            print(f"   • Detection Rate: {res['detection_rate']}%")
            
            if res['malicious_detections']:
                print(f"\n🚨 Malicious Detections ({len(res['malicious_detections'])}):")
                for det in res['malicious_detections'][:10]:  # Show first 10
                    print(f"   • {det['engine']}: {det['result']}")
                
                if len(res['malicious_detections']) > 10:
                    print(f"   ... and {len(res['malicious_detections']) - 10} more")
            
            print(f"\n🔗 Full Report: {res['permalink']}")
        else:
            print(f"\n⏳ File uploaded. Analysis ID: {result.get('analysis_id')}")
            print(f"   Check VirusTotal dashboard for results")
        
        print("\n" + "="*80)


if __name__ == '__main__':
    main()
