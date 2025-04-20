#!/usr/bin/env python3
"""
Main malware detection module.
This module integrates all the detection components.
"""

import os
import sys
import json
import argparse
import psutil
import datetime
from typing import Dict, List, Optional, Set

# Import other detection modules
from entropy import EntropyAnalyzer
from virustotalUpload import VirusTotalClient
from LLMlogs import LogAnalyzer
from clamav_scan import ClamAVScanner  # Add this import

# Define path for the isolation data file
MALWARE_PROCESS_FILE = os.environ.get("MALWARE_PROCESS_FILE", 
                                    os.path.join(os.path.dirname(os.path.abspath(__file__)), 
                                               "..", "isolation", "malware_processes.txt"))

class MalwareDetector:
    """Main malware detection class integrating all detection methods"""
    
    def __init__(self, virustotal_api_key: str, gemini_api_key: str, clamd_socket: Optional[str] = None):
        """
        Initialize the malware detector
        
        Args:
            virustotal_api_key: VirusTotal API key
            gemini_api_key: Google Gemini API key
            clamd_socket: Path to the clamd socket for ClamAV scanning (optional)
        """
        self.entropy_analyzer = EntropyAnalyzer()
        self.virustotal_client = VirusTotalClient(virustotal_api_key)
        self.log_analyzer = LogAnalyzer(gemini_api_key)
        self.clamav_scanner = ClamAVScanner(clamd_socket=clamd_socket)  # Add ClamAV scanner
        
    def scan_file(self, file_path: str, check_virustotal: bool = True, use_clamav: bool = True) -> Dict:
        """
        Scan a single file for malware
        
        Args:
            file_path: Path to the file to scan
            check_virustotal: Whether to check the file against VirusTotal
            use_clamav: Whether to scan the file with ClamAV
            
        Returns:
            Dict: Scan results
        """
        results = {
            "file_path": file_path,
            "is_malicious": False,
            "suspicious_pids": [],
            "detection_methods": []
        }
        
        # Check if file exists
        if not os.path.exists(file_path):
            results["error"] = f"File {file_path} does not exist"
            return results
            
        # Entropy analysis
        entropy_result = self.entropy_analyzer.analyze_file(file_path)
        results["entropy_analysis"] = entropy_result
        
        if entropy_result.get("is_suspicious", False):
            results["is_malicious"] = True
            results["detection_methods"].append("entropy")
        
        # ClamAV scanning
        if use_clamav:
            try:
                clamav_result = self.clamav_scanner.scan_file(file_path)
                results["clamav_analysis"] = clamav_result
                
                if clamav_result.get("is_malicious", False):
                    results["is_malicious"] = True
                    results["detection_methods"].append("clamav")
            except Exception as e:
                results["clamav_error"] = str(e)
            
        # VirusTotal analysis
        if check_virustotal:
            virustotal_result = self.virustotal_client.check_file(file_path, wait_for_analysis=False)
            results["virustotal_analysis"] = virustotal_result
            
            if virustotal_result.get("is_malicious", False):
                results["is_malicious"] = True
                results["detection_methods"].append("virustotal")
                
        # Find processes using the file if it's suspicious
        if results["is_malicious"]:
            pids = self.entropy_analyzer.get_pids_for_suspicious_files([entropy_result])
            results["suspicious_pids"].extend(pids)
            
        return results
    
    def scan_directory(self, directory_path: str, recursive: bool = True, 
                      check_virustotal: bool = False, use_clamav: bool = True) -> Dict:
        """
        Scan a directory for malware
        
        Args:
            directory_path: Path to the directory to scan
            recursive: Whether to scan subdirectories recursively
            check_virustotal: Whether to check files against VirusTotal
            use_clamav: Whether to scan files with ClamAV
            
        Returns:
            Dict: Scan results
        """
        results = {
            "directory_path": directory_path,
            "is_malicious": False,
            "suspicious_pids": [],
            "suspicious_files": [],
            "detection_methods": [],
            "file_results": []
        }
        
        # Check if directory exists
        if not os.path.exists(directory_path) or not os.path.isdir(directory_path):
            results["error"] = f"Directory {directory_path} does not exist"
            return results
        
        # ClamAV directory scan if enabled
        if use_clamav:
            try:
                clamav_results = self.clamav_scanner.scan_directory(directory_path, recursive=recursive)
                results["clamav_analysis"] = clamav_results
                
                if clamav_results.get("is_malicious", False):
                    results["is_malicious"] = True
                    results["detection_methods"].append("clamav")
                    
                    # Add infected files to suspicious files list
                    for infected_file in clamav_results.get("infected_files", []):
                        file_path = infected_file.get("file_path")
                        if file_path and file_path not in results["suspicious_files"]:
                            results["suspicious_files"].append(file_path)
                    
                    # Get PIDs for infected files
                    infected_files = [info.get("file_path") for info in clamav_results.get("infected_files", []) 
                                     if "file_path" in info]
                    if infected_files:
                        pids = self.clamav_scanner.get_pids_using_infected_files(infected_files)
                        results["suspicious_pids"].extend(pids)
            except Exception as e:
                results["clamav_error"] = str(e)
        
        # Continue with entropy analysis
        entropy_results = self.entropy_analyzer.scan_directory(directory_path, recursive)
        
        # Process entropy results
        suspicious_files = []
        for file_result in entropy_results:
            if file_result.get("is_suspicious", False):
                results["is_malicious"] = True
                if "entropy" not in results["detection_methods"]:
                    results["detection_methods"].append("entropy")
                suspicious_files.append(file_result.get("file_path"))
                results["suspicious_files"].append(file_result.get("file_path"))
                
            results["file_results"].append({
                "file_path": file_result.get("file_path"),
                "entropy_analysis": file_result
            })
                
        # Get PIDs of processes using suspicious files
        if suspicious_files:
            pids = self.entropy_analyzer.get_pids_for_suspicious_files(entropy_results)
            results["suspicious_pids"].extend(pids)
            
        # Check suspicious files with VirusTotal
        if check_virustotal and suspicious_files:
            for file_path in suspicious_files[:10]:  # Limit to 10 files to avoid API rate limits
                virustotal_result = self.virustotal_client.check_file(file_path, wait_for_analysis=False)
                
                # Find the file's result in our results list
                for file_result in results["file_results"]:
                    if file_result["file_path"] == file_path:
                        file_result["virustotal_analysis"] = virustotal_result
                        
                        if virustotal_result.get("is_malicious", False):
                            if "virustotal" not in results["detection_methods"]:
                                results["detection_methods"].append("virustotal")
            
        # Remove duplicate PIDs
        results["suspicious_pids"] = list(set(results["suspicious_pids"]))
        
        # Return the full results
        return results
    
    def analyze_logs(self, time_window: int = 60) -> Dict:
        """
        Analyze system logs for signs of malware
        
        Args:
            time_window: Time window in minutes to filter logs (0 for all logs)
            
        Returns:
            Dict: Analysis results
        """
        return self.log_analyzer.analyze_system_logs(time_window)
        
    def full_system_scan(self, home_dir: str = None, check_virustotal: bool = False, 
                         use_clamav: bool = True, log_time_window: int = 60) -> Dict:
        """
        Perform a full system scan, including file analysis and logs
        
        Args:
            home_dir: Home directory to scan (defaults to current user's home)
            check_virustotal: Whether to check files against VirusTotal
            use_clamav: Whether to use ClamAV for scanning
            log_time_window: Time window in minutes for log analysis
            
        Returns:
            Dict: Scan results
        """
        results = {
            "is_malicious": False,
            "suspicious_pids": [],
            "detection_methods": []
        }
        
        # Default to current user's home directory if not specified
        if home_dir is None:
            home_dir = os.path.expanduser('~')
            
        # Scan the home directory
        dir_scan_results = self.scan_directory(home_dir, recursive=True, 
                                              check_virustotal=check_virustotal,
                                              use_clamav=use_clamav)
        results["directory_scan"] = dir_scan_results
        
        # Update results based on directory scan
        if dir_scan_results.get("is_malicious", False):
            results["is_malicious"] = True
            results["suspicious_pids"].extend(dir_scan_results.get("suspicious_pids", []))
            for method in dir_scan_results.get("detection_methods", []):
                if method not in results["detection_methods"]:
                    results["detection_methods"].append(method)
                    
        # Analyze logs
        log_results = self.analyze_logs(log_time_window)
        results["log_analysis"] = log_results
        
        # Update results based on log analysis
        if log_results.get("is_suspicious", False):
            results["is_malicious"] = True
            results["suspicious_pids"].extend(log_results.get("suspicious_pids", []))
            if "logs" not in results["detection_methods"]:
                results["detection_methods"].append("logs")
                
        # Remove duplicate PIDs
        results["suspicious_pids"] = list(set(results["suspicious_pids"]))
        
        return results
        
    def get_detection_summary(self, full_results: Dict) -> str:
        """
        Get a human-readable summary of detection results
        
        Args:
            full_results: Full scan results
            
        Returns:
            str: Human-readable summary
        """
        summary = []
        
        # Overall status
        if full_results.get("is_malicious", False):
            summary.append("⚠️ ALERT: Suspicious/malicious activity detected!")
            
            # Detection methods
            methods = full_results.get("detection_methods", [])
            if methods:
                summary.append(f"Detection methods: {', '.join(methods)}")
                
            # Suspicious PIDs
            pids = full_results.get("suspicious_pids", [])
            if pids:
                summary.append(f"Suspicious processes (PIDs): {', '.join(map(str, pids))}")
                
            # File scan results
            dir_scan = full_results.get("directory_scan", {})
            suspicious_files = dir_scan.get("suspicious_files", [])
            if suspicious_files:
                summary.append(f"Number of suspicious files: {len(suspicious_files)}")
                if len(suspicious_files) <= 5:
                    for file_path in suspicious_files:
                        summary.append(f"  - {file_path}")
                else:
                    for file_path in suspicious_files[:5]:
                        summary.append(f"  - {file_path}")
                    summary.append(f"  - ... and {len(suspicious_files) - 5} more")
                    
            # Log analysis
            log_analysis = full_results.get("log_analysis", {})
            if log_analysis.get("is_suspicious", False):
                combined_analysis = log_analysis.get("combined_analysis", {})
                analysis_summary = combined_analysis.get("analysis_summary", "")
                if analysis_summary:
                    summary.append(f"Log analysis: {analysis_summary}")
        else:
            summary.append("✓ No malicious activity detected.")
            
        return "\n".join(summary)
    
    def write_malicious_processes_to_file(self, suspicious_pids: List[int]) -> None:
        """
        Write detected malicious processes to a file
        
        Args:
            suspicious_pids: List of suspicious process IDs
        """
        if not suspicious_pids:
            return
        
        try:
            # Ensure directory exists
            os.makedirs(os.path.dirname(MALWARE_PROCESS_FILE), exist_ok=True)
            
            with open(MALWARE_PROCESS_FILE, 'a') as f:
                timestamp = datetime.datetime.now().strftime("%Y-%m-%d %H:%M:%S")
                f.write(f"\n--- Malicious processes detected at {timestamp} ---\n")
                
                for pid in suspicious_pids:
                    try:
                        # Get detailed process information
                        process = psutil.Process(pid)
                        exec_path = process.exe()
                        cmdline = " ".join(process.cmdline())
                        username = process.username()
                        create_time = datetime.datetime.fromtimestamp(
                            process.create_time()).strftime("%Y-%m-%d %H:%M:%S")
                        
                        # Write detailed process information
                        process_info = (
                            f"PID: {pid}\n"
                            f"Executable: {exec_path}\n"
                            f"Command: {cmdline}\n"
                            f"User: {username}\n"
                            f"Created: {create_time}\n"
                            f"Detection time: {timestamp}\n"
                            f"---\n"
                        )
                        f.write(process_info)
                    except (psutil.NoSuchProcess, psutil.AccessDenied, psutil.ZombieProcess):
                        # Process may have terminated or we don't have permission
                        f.write(f"PID: {pid} (Unable to get process details - may have terminated)\n---\n")
                    except Exception as e:
                        f.write(f"PID: {pid} (Error getting process details: {str(e)})\n---\n")
                        
            print(f"Malicious process information written to {MALWARE_PROCESS_FILE}")
        except Exception as e:
            print(f"Error writing malicious processes to file: {e}")


if __name__ == "__main__":
    parser = argparse.ArgumentParser(description="SentinalCore malware detection system")
    parser.add_argument("--virustotal-key", help="VirusTotal API key")
    parser.add_argument("--gemini-key", help="Google Gemini API key")
    parser.add_argument("--clamd-socket", help="Path to ClamAV clamd socket")
    parser.add_argument("--scan-file", help="Path to a file to scan")
    parser.add_argument("--scan-dir", help="Path to a directory to scan")
    parser.add_argument("--scan-home", action="store_true", help="Scan user's home directory")
    parser.add_argument("--check-virustotal", action="store_true", help="Check suspicious files with VirusTotal")
    parser.add_argument("--use-clamav", action="store_true", help="Use ClamAV for antivirus scanning")
    parser.add_argument("--clamav-update", action="store_true", help="Update ClamAV virus definitions")
    parser.add_argument("--analyze-logs", action="store_true", help="Analyze system logs for malicious activity")
    parser.add_argument("--log-time", type=int, default=60, help="Time window in minutes for log analysis")
    parser.add_argument("--full-scan", action="store_true", help="Perform a full system scan")
    parser.add_argument("--output-file", help="Write results to JSON file")
    parser.add_argument("--verbose", action="store_true", help="Show detailed results")
    
    args = parser.parse_args()
    
    # Check for required API keys
    virustotal_key = args.virustotal_key or os.environ.get("VIRUSTOTAL_API_KEY", "")
    gemini_key = args.gemini_key or os.environ.get("GEMINI_API_KEY", "")
    clamd_socket = args.clamd_socket or os.environ.get("CLAMD_SOCKET", "")
    
    # Update ClamAV if requested
    if args.clamav_update:
        try:
            scanner = ClamAVScanner(clamd_socket=clamd_socket)
            update_result = scanner.update_database()
            print(json.dumps(update_result, indent=2))
            if not args.scan_file and not args.scan_dir and not args.scan_home and not args.full_scan:
                sys.exit(0)
        except Exception as e:
            print(f"Error updating ClamAV database: {e}")
            sys.exit(1)
            
    # Continue with other functionality
    
    # Initialize the detector
    detector = MalwareDetector(virustotal_key, gemini_key, clamd_socket=clamd_socket)
    
    # Track if any action was performed
    action_performed = False
    results = None
    
    # Scan a single file
    if args.scan_file:
        action_performed = True
        print(f"Scanning file: {args.scan_file}")
        results = detector.scan_file(args.scan_file, check_virustotal=args.check_virustotal, use_clamav=args.use_clamav)
        
        if results.get("is_malicious", False):
            print("⚠️ File appears to be suspicious/malicious!")
            print(f"Detection methods: {', '.join(results.get('detection_methods', []))}")
            
            if results.get("suspicious_pids"):
                print(f"Suspicious processes (PIDs): {results['suspicious_pids']}")
                detector.write_malicious_processes_to_file(results['suspicious_pids'])
        else:
            print("✓ No malicious indicators found in the file.")
            
    # Scan a directory
    if args.scan_dir:
        action_performed = True
        print(f"Scanning directory: {args.scan_dir}")
        results = detector.scan_directory(args.scan_dir, recursive=True, check_virustotal=args.check_virustotal, use_clamav=args.use_clamav)
        
        if results.get("is_malicious", False):
            print("⚠️ Suspicious/malicious files found!")
            print(f"Detection methods: {', '.join(results.get('detection_methods', []))}")
            print(f"Number of suspicious files: {len(results.get('suspicious_files', []))}")
            
            if results.get("suspicious_pids"):
                print(f"Suspicious processes (PIDs): {results['suspicious_pids']}")
                detector.write_malicious_processes_to_file(results['suspicious_pids'])
        else:
            print("✓ No suspicious files found.")
            
    # Scan user's home directory
    if args.scan_home:
        action_performed = True
        home_dir = os.path.expanduser('~')
        print(f"Scanning home directory: {home_dir}")
        results = detector.scan_directory(home_dir, recursive=True, check_virustotal=args.check_virustotal, use_clamav=args.use_clamav)
        
        if results.get("is_malicious", False):
            print("⚠️ Suspicious/malicious files found!")
            print(f"Detection methods: {', '.join(results.get('detection_methods', []))}")
            print(f"Number of suspicious files: {len(results.get('suspicious_files', []))}")
            
            if results.get("suspicious_pids"):
                print(f"Suspicious processes (PIDs): {results['suspicious_pids']}")
                detector.write_malicious_processes_to_file(results['suspicious_pids'])
        else:
            print("✓ No suspicious files found.")
            
    # Analyze logs
    if args.analyze_logs:
        action_performed = True
        print(f"Analyzing system logs (time window: {args.log_time} minutes)...")
        results = detector.analyze_logs(args.log_time)
        
        if results.get("is_suspicious", False):
            print("⚠️ Suspicious activity found in logs!")
            
            if results.get("suspicious_pids"):
                print(f"Suspicious processes (PIDs): {results['suspicious_pids']}")
                detector.write_malicious_processes_to_file(results['suspicious_pids'])
                
            combined_analysis = results.get("combined_analysis", {})
            if combined_analysis.get("success"):
                print(f"Analysis: {combined_analysis.get('analysis_summary', 'No details provided')}")
        else:
            print("✓ No suspicious activity found in logs.")
            
    # Full system scan
    if args.full_scan:
        action_performed = True
        print("Performing full system scan...")
        summary = detector.get_detection_summary(results)
        print("\nScan complete. Results summary:")
        print(summary)
        
        if results.get("suspicious_pids"):
            detector.write_malicious_processes_to_file(results['suspicious_pids'])
            
    # Show detailed results if requested
    if args.verbose and results:
        print("\nDetailed results:")
        print(json.dumps(results, indent=2))
        
    # Write results to file if requested
    if args.output_file and results:
        with open(args.output_file, 'w') as f:
            json.dump(results, f, indent=2)
        print(f"Results written to {args.output_file}")
        
    # If no action was performed, show help
    if not action_performed:
        parser.print_help()