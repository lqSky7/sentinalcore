#!/usr/bin/env python3
"""
ClamAV integration module.
This module integrates with ClamAV for signature-based malware detection.
"""

import os
import subprocess
import tempfile
import re
import time
import json
from typing import Dict, List, Optional, Union, Tuple, Set

class ClamAVScanner:
    """Class for interfacing with ClamAV antivirus"""
    
    def __init__(self, clamd_socket: Optional[str] = None, clamscan_path: Optional[str] = None):
        """
        Initialize the ClamAV scanner
        
        Args:
            clamd_socket: Path to the clamd socket (for clamd scanning)
            clamscan_path: Path to the clamscan executable (as fallback)
        """
        self.clamd_socket = clamd_socket
        self.clamscan_path = clamscan_path or self._find_clamscan()
        self._check_clamav_installed()
    
    def _find_clamscan(self) -> str:
        """
        Find the path to the clamscan executable
        
        Returns:
            str: Path to clamscan or just 'clamscan' if in PATH
        """
        # Common paths to check
        common_paths = [
            '/usr/bin/clamscan',
            '/usr/local/bin/clamscan',
            '/opt/homebrew/bin/clamscan'  # For macOS with Homebrew
        ]
        
        for path in common_paths:
            if os.path.exists(path) and os.access(path, os.X_OK):
                return path
                
        # Default to just the command name, which will work if it's in PATH
        return 'clamscan'
    
    def _check_clamav_installed(self) -> bool:
        """
        Check if ClamAV is installed and available
        
        Returns:
            bool: True if ClamAV is installed, otherwise raises an exception
        """
        try:
            # Try to run clamscan with version flag
            result = subprocess.run(
                [self.clamscan_path, '--version'],
                capture_output=True,
                text=True,
                timeout=5
            )
            
            if result.returncode != 0:
                raise RuntimeError(f"ClamAV check failed: {result.stderr}")
                
            self.clamav_version = result.stdout.strip().split("\n")[0]
            return True
            
        except (subprocess.SubprocessError, FileNotFoundError) as e:
            raise RuntimeError(f"ClamAV does not appear to be installed: {str(e)}")
    
    def scan_file(self, file_path: str) -> Dict:
        """
        Scan a single file with ClamAV
        
        Args:
            file_path: Path to the file to scan
            
        Returns:
            Dict: Scan results
        """
        if not os.path.exists(file_path) or not os.path.isfile(file_path):
            return {
                "file_path": file_path,
                "error": f"File {file_path} does not exist or is not a regular file",
                "is_malicious": False
            }
        
        # Try clamd socket if available (faster)
        if self.clamd_socket and os.path.exists(self.clamd_socket):
            return self._scan_with_clamd(file_path)
        else:
            # Fall back to clamscan command line
            return self._scan_with_clamscan(file_path)
    
    def _scan_with_clamd(self, file_path: str) -> Dict:
        """
        Scan a file using clamd daemon for better performance
        
        Args:
            file_path: Path to the file to scan
            
        Returns:
            Dict: Scan results
        """
        try:
            # Import only when needed to avoid dependency issues
            import pyclamd
            
            # Connect to clamd
            cd = pyclamd.ClamdUnixSocket(self.clamd_socket)
            if not cd.ping():
                raise ConnectionError("Could not connect to clamd")
                
            # Scan the file
            scan_result = cd.scan_file(file_path)
            
            if scan_result is None:
                # No virus found
                return {
                    "file_path": file_path,
                    "is_malicious": False,
                    "scan_result": "Clean",
                    "scan_method": "clamd"
                }
            else:
                # Virus found
                result_file, virus_name = list(scan_result.items())[0]
                return {
                    "file_path": file_path,
                    "is_malicious": True,
                    "scan_result": virus_name,
                    "scan_method": "clamd",
                    "detection_name": virus_name.split(":", 1)[1].strip() if ":" in virus_name else virus_name
                }
                
        except (ImportError, ConnectionError, Exception) as e:
            # Fall back to clamscan if clamd fails
            print(f"clamd scan failed, falling back to clamscan: {str(e)}")
            return self._scan_with_clamscan(file_path)
    
    def _scan_with_clamscan(self, file_path: str) -> Dict:
        """
        Scan a file using the clamscan command line tool
        
        Args:
            file_path: Path to the file to scan
            
        Returns:
            Dict: Scan results
        """
        try:
            # Run clamscan
            result = subprocess.run(
                [self.clamscan_path, '--no-summary', file_path],
                capture_output=True,
                text=True,
                timeout=30  # Timeout after 30 seconds
            )
            
            # Check for malware
            if result.returncode == 1:
                # Malware found - parse the output
                match = re.search(f"{re.escape(file_path)}: ([^:]+)(?:: ([^:]+))?", result.stdout)
                if match:
                    detection_name = match.group(1).strip()
                    return {
                        "file_path": file_path,
                        "is_malicious": True,
                        "scan_result": result.stdout.strip(),
                        "scan_method": "clamscan",
                        "detection_name": detection_name 
                    }
                else:
                    return {
                        "file_path": file_path,
                        "is_malicious": True,
                        "scan_result": result.stdout.strip(),
                        "scan_method": "clamscan"
                    }
            elif result.returncode == 0:
                # No malware found
                return {
                    "file_path": file_path,
                    "is_malicious": False,
                    "scan_result": "Clean",
                    "scan_method": "clamscan"
                }
            else:
                # Error in scanning
                return {
                    "file_path": file_path,
                    "error": f"ClamAV scan error (code {result.returncode}): {result.stderr}",
                    "is_malicious": False,
                    "scan_method": "clamscan"
                }
                
        except subprocess.TimeoutExpired:
            return {
                "file_path": file_path,
                "error": "ClamAV scan timed out",
                "is_malicious": False,
                "scan_method": "clamscan"
            }
        except Exception as e:
            return {
                "file_path": file_path,
                "error": f"ClamAV scan exception: {str(e)}",
                "is_malicious": False,
                "scan_method": "clamscan"
            }
    
    def scan_directory(self, directory_path: str, recursive: bool = True, 
                       exclude_dirs: Optional[List[str]] = None, 
                       max_file_size: int = 100) -> Dict:
        """
        Scan a directory with ClamAV
        
        Args:
            directory_path: Path to the directory to scan
            recursive: Whether to scan subdirectories
            exclude_dirs: List of directory names to exclude
            max_file_size: Maximum file size in MB to scan
            
        Returns:
            Dict: Scan results
        """
        if not os.path.exists(directory_path) or not os.path.isdir(directory_path):
            return {
                "directory_path": directory_path,
                "error": f"Directory {directory_path} does not exist",
                "is_malicious": False,
                "scan_method": "none"
            }
            
        # Default exclusions
        exclude_dirs = exclude_dirs or ['.git', 'node_modules', 'venv', '.venv', '__pycache__']
        
        # Prepare temp file to store scan results
        with tempfile.NamedTemporaryFile(mode='w+', delete=False) as tmp_file:
            tmp_filename = tmp_file.name
        
        try:
            # Build command
            cmd = [self.clamscan_path]
            
            # Add recursive flag if needed
            if recursive:
                cmd.append('-r')
                
            # Add exclusions
            for exclude in exclude_dirs:
                cmd.extend(['--exclude-dir=', exclude])
                
            # Add max file size
            cmd.append(f'--max-filesize={max_file_size}M')
            
            # Add other useful flags
            cmd.extend([
                '--no-summary',      # Skip printing summary
                '--infected',        # Only print infected files
                '--stdout',          # Print to stdout
            ])
            
            # Add directory to scan
            cmd.append(directory_path)
            
            # Run the scan
            start_time = time.time()
            
            scan_process = subprocess.run(
                cmd,
                capture_output=True,
                text=True,
                timeout=300  # 5 minute timeout
            )
            
            scan_time = time.time() - start_time
            
            # Parse the results
            infected_files = []
            for line in scan_process.stdout.splitlines():
                if ': ' in line and not line.endswith(': OK'):
                    file_path, detection = line.rsplit(': ', 1)
                    infected_files.append({
                        "file_path": file_path,
                        "detection": detection,
                        "is_malicious": True
                    })
            
            # Create the result dictionary
            result = {
                "directory_path": directory_path,
                "is_malicious": len(infected_files) > 0,
                "infected_files": infected_files,
                "total_infected": len(infected_files),
                "scan_time_seconds": scan_time,
                "scan_method": "clamscan directory",
                "scan_options": {
                    "recursive": recursive,
                    "exclude_dirs": exclude_dirs,
                    "max_file_size_mb": max_file_size
                }
            }
            
            if scan_process.returncode > 1:
                # Error occurred
                result["error"] = f"ClamAV scan error (code {scan_process.returncode}): {scan_process.stderr}"
                
            return result
            
        except subprocess.TimeoutExpired:
            return {
                "directory_path": directory_path,
                "error": "ClamAV scan timed out",
                "is_malicious": False,
                "scan_method": "clamscan directory"
            }
        except Exception as e:
            return {
                "directory_path": directory_path,
                "error": f"ClamAV scan exception: {str(e)}",
                "is_malicious": False,
                "scan_method": "clamscan directory"
            }
        finally:
            # Clean up temp file
            if os.path.exists(tmp_filename):
                os.unlink(tmp_filename)
    
    def get_clamav_database_info(self) -> Dict:
        """
        Get information about ClamAV virus database
        
        Returns:
            Dict: Database information
        """
        try:
            # Run clamscan with version flag
            result = subprocess.run(
                [self.clamscan_path, '--version'],
                capture_output=True,
                text=True,
                timeout=5
            )
            
            if result.returncode != 0:
                return {"error": f"ClamAV check failed: {result.stderr}"}
            
            version_info = {}
            
            # Parse output for database information
            for line in result.stdout.splitlines():
                if ":" in line:
                    key, value = line.split(":", 1)
                    version_info[key.strip()] = value.strip()
            
            # Extract specific database info
            database_info = {
                "clamav_version": version_info.get("ClamAV version", "Unknown"),
                "database_version": version_info.get("Database version", "Unknown"),
                "database_time": version_info.get("Build time", "Unknown"),
                "signature_count": version_info.get("Main.cvd", "Unknown").split()[0]
                                   if "Main.cvd" in version_info else "Unknown"
            }
            
            return database_info
            
        except (subprocess.SubprocessError, FileNotFoundError, Exception) as e:
            return {"error": f"Could not get ClamAV database info: {str(e)}"}
    
    def create_test_virus_file(self, output_path: str) -> Dict:
        """
        Create a test EICAR file to verify ClamAV detection
        
        Args:
            output_path: Path where the test file should be created
            
        Returns:
            Dict: Result of the operation
        """
        try:
            # EICAR test string - this is a safe test virus recognized by all antiviruses
            eicar = 'X5O!P%@AP[4\\PZX54(P^)7CC)7}$EICAR-STANDARD-ANTIVIRUS-TEST-FILE!$H+H*'
            
            with open(output_path, 'w') as f:
                f.write(eicar)
                
            # Scan to verify detection
            scan_result = self.scan_file(output_path)
            
            if scan_result.get("is_malicious", False):
                return {
                    "success": True, 
                    "file_path": output_path,
                    "detection": scan_result.get("detection_name", "Detected as malicious"),
                    "message": "EICAR test file created and detected successfully"
                }
            else:
                return {
                    "success": False,
                    "file_path": output_path,
                    "error": "EICAR test file was created but not detected as malicious",
                    "scan_result": scan_result
                }
        except Exception as e:
            return {
                "success": False,
                "error": f"Failed to create EICAR test file: {str(e)}"
            }
    
    def update_database(self) -> Dict:
        """
        Update the ClamAV virus database
        
        Returns:
            Dict: Result of the update operation
        """
        try:
            # Check for freshclam command
            freshclam_path = self.clamscan_path.replace('clamscan', 'freshclam')
            if not os.path.exists(freshclam_path):
                freshclam_path = 'freshclam'  # Try using PATH
            
            # Run freshclam to update
            result = subprocess.run(
                [freshclam_path],
                capture_output=True,
                text=True,
                timeout=300  # 5 minute timeout
            )
            
            if result.returncode == 0:
                return {
                    "success": True,
                    "message": "ClamAV database updated successfully",
                    "output": result.stdout
                }
            else:
                return {
                    "success": False,
                    "error": f"Database update failed (code {result.returncode})",
                    "output": result.stderr or result.stdout
                }
        except Exception as e:
            return {
                "success": False,
                "error": f"Failed to update ClamAV database: {str(e)}"
            }
    
    def get_pids_using_infected_files(self, infected_files: List[str]) -> List[int]:
        """
        Get PIDs of processes using infected files
        
        Args:
            infected_files: List of infected file paths
            
        Returns:
            List[int]: List of PIDs
        """
        infected_pids = []
        
        # This uses Linux-specific /proc filesystem to find processes using these files
        if not infected_files:
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
                            if any(infected_file in link for infected_file in infected_files):
                                infected_pids.append(int(pid))
                                break
                        except (FileNotFoundError, PermissionError):
                            continue
                except (FileNotFoundError, PermissionError):
                    continue
                    
        except Exception as e:
            print(f"Error while scanning /proc: {str(e)}")
            
        return infected_pids


if __name__ == "__main__":
    # Simple command line interface for testing
    import argparse
    
    parser = argparse.ArgumentParser(description="ClamAV Scanner")
    parser.add_argument("--socket", help="Path to clamd socket")
    parser.add_argument("--path", required=True, help="File or directory to scan")
    parser.add_argument("--recursive", action="store_true", help="Scan directories recursively")
    parser.add_argument("--create-test", action="store_true", help="Create EICAR test file")
    parser.add_argument("--update", action="store_true", help="Update virus database")
    parser.add_argument("--db-info", action="store_true", help="Show database information")
    
    args = parser.parse_args()
    
    try:
        scanner = ClamAVScanner(clamd_socket=args.socket)
        
        if args.update:
            result = scanner.update_database()
            print(json.dumps(result, indent=2))
            
        if args.db_info:
            info = scanner.get_clamav_database_info()
            print(json.dumps(info, indent=2))
            
        if args.create_test:
            if os.path.isdir(args.path):
                test_path = os.path.join(args.path, "eicar_test.txt")
            else:
                test_path = args.path
                
            result = scanner.create_test_virus_file(test_path)
            print(json.dumps(result, indent=2))
            
        elif os.path.isfile(args.path):
            result = scanner.scan_file(args.path)
            print(json.dumps(result, indent=2))
            
        elif os.path.isdir(args.path):
            result = scanner.scan_directory(args.path, recursive=args.recursive)
            
            # Print summary
            print(f"Scan completed: {args.path}")
            print(f"Infected files: {result['total_infected']}")
            print(f"Scan time: {result['scan_time_seconds']:.2f} seconds")
            
            if result["is_malicious"]:
                print("\nInfected files:")
                for infected in result["infected_files"]:
                    print(f"  {infected['file_path']} - {infected.get('detection', 'Unknown')}")
            
    except Exception as e:
        print(f"Error: {str(e)}")