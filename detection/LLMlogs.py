#!/usr/bin/env python3
"""
Log analyzer module using Google Gemini API.
This module analyzes system and kernel logs to detect malicious activity.
"""

import os
import re
import json
import subprocess
from datetime import datetime, timedelta
import requests
from typing import Dict, List, Optional, Union, Tuple

class LogAnalyzer:
    """Class for analyzing system logs using Google Gemini API"""
    
    # Common log paths on Linux systems
    LOG_PATHS = {
        "auth": "/var/log/auth.log",
        "syslog": "/var/log/syslog",
        "kern": "/var/log/kern.log",
        "messages": "/var/log/messages",
        "secure": "/var/log/secure",
        "audit": "/var/log/audit/audit.log",
        "dmesg": "dmesg"  # This is a command, not a file path
    }
    
    # Suspicious patterns to look for in logs (without LLM)
    SUSPICIOUS_PATTERNS = [
        r"Failed password .* from (\d+\.\d+\.\d+\.\d+)",  # Failed SSH logins
        r"Invalid user .* from (\d+\.\d+\.\d+\.\d+)",     # Invalid SSH users
        r"script '/tmp/.*' not found",                    # Possible webshell attempts
        r"kernel: \[ *\d+\.\d+\] Denied .* comm=\"([^\"]+)\"", # AppArmor/SELinux denials
        r"segfault at .* ip .* sp .* error .* in ([^\(]+)", # Segfaults (could be exploits)
        r"kernel: \[ *\d+\.\d+\] Resource temporarily unavailable.*", # Resource exhaustion
        r"execve\(\"([^\"]+)\"",  # Program execution via auditd
        r"process \d+ \(([^\)]+)\) has RLIMIT_CORE changed", # Process manipulating limits
        r"Intrusion detected by lfd on",  # CSF/LFD alerts
        r"PAM \d+ more authentication failures" # Multiple auth failures
    ]
    
    # Patterns that likely indicate malicious activity (without LLM)
    CRITICAL_PATTERNS = [
        r"kernel: \[ *\d+\.\d+\] Protection fault",       # Memory protection faults
        r"kernel: \[ *\d+\.\d+\] Possible PTRACE",        # Possible ptrace attacks
        r"kernel: \[ *\d+\.\d+\] Code: Bad .* to .* %",   # Bad memory references
        r"kernel: \[ *\d+\.\d+\] general protection fault", # General protection faults
        r"kernel: \[ *\d+\.\d+\] BUG: ",                  # Kernel bugs
        r"EXPLOIT",                                        # Explicit mention of exploits
        r"INFO: task .* blocked for more than \d+ seconds", # Potential kernel issues
        r"kernel: \[ *\d+\.\d+\] Corrupted low memory", # Memory corruption
        r"Rootkit",                                        # Rootkit mentions
        r"kernel: \[ *\d+\.\d+\] NMI watchdog: BUG: soft lockup" # CPU lockups
    ]
    
    # Process names that are suspicious when showing unusual behavior
    SUSPICIOUS_PROCESSES = [
        "bash", "sh", "dash", "zsh", "ksh",  # Shells running from unusual locations
        "nc", "netcat", "ncat",              # Network utilities used for backdoors
        "wget", "curl",                      # Download utilities
        "python", "perl", "ruby", "php",     # Scripting languages
        "base64", "uudecode",                # Encoding/decoding tools
        "chmod", "chown",                    # File permission changes
        "socat", "gdb", "strace"             # Advanced utilities
    ]
    
    def __init__(self, gemini_api_key: str):
        """
        Initialize the log analyzer
        
        Args:
            gemini_api_key: Google Gemini API key
        """
        self.gemini_api_key = gemini_api_key
        self.gemini_api_url = "https://generativelanguage.googleapis.com/v1beta/models/gemini-pro:generateContent"
    
    def _read_log_file(self, log_path: str, time_window: int = 60) -> str:
        """
        Read a log file with option to filter by time window
        
        Args:
            log_path: Path to the log file
            time_window: Time window in minutes to filter logs (0 for all logs)
            
        Returns:
            str: Log content
        """
        # Special case for dmesg command
        if log_path == "dmesg":
            try:
                result = subprocess.run(["dmesg"], capture_output=True, text=True)
                if result.returncode == 0:
                    return result.stdout
                else:
                    return ""
            except Exception as e:
                print(f"Error running dmesg: {str(e)}")
                return ""
        
        # For regular log files
        if not os.path.exists(log_path):
            return ""
            
        try:
            if time_window <= 0:
                # Read the entire file
                with open(log_path, 'r') as f:
                    return f.read()
            else:
                # Filter by time
                cutoff_time = datetime.now() - timedelta(minutes=time_window)
                
                # Use grep to get recent logs
                # This assumes a standard log format with timestamps
                date_str = cutoff_time.strftime("%b %d %H:%M:%S")
                grep_cmd = ["grep", "-A", "1000000", date_str, log_path]
                
                try:
                    result = subprocess.run(grep_cmd, capture_output=True, text=True)
                    if result.returncode == 0:
                        return result.stdout
                    else:
                        # Fallback to reading the entire file
                        with open(log_path, 'r') as f:
                            return f.read()
                except Exception:
                    # Fallback to reading the entire file
                    with open(log_path, 'r') as f:
                        return f.read()
                        
        except Exception as e:
            print(f"Error reading log file {log_path}: {str(e)}")
            return ""
    
    def _basic_log_analysis(self, log_content: str) -> Dict:
        """
        Perform basic pattern-based analysis of logs without LLM
        
        Args:
            log_content: Log content to analyze
            
        Returns:
            Dict: Analysis results
        """
        if not log_content:
            return {"suspicious_patterns": [], "critical_patterns": []}
            
        suspicious_findings = []
        critical_findings = []
        
        # Check for suspicious patterns
        for pattern in self.SUSPICIOUS_PATTERNS:
            matches = re.finditer(pattern, log_content)
            for match in matches:
                line_start = max(0, match.start() - 100)
                line_end = min(len(log_content), match.end() + 100)
                context = log_content[line_start:line_end].strip()
                
                suspicious_findings.append({
                    "pattern": pattern,
                    "match": match.group(0),
                    "context": context
                })
                
        # Check for critical patterns
        for pattern in self.CRITICAL_PATTERNS:
            matches = re.finditer(pattern, log_content)
            for match in matches:
                line_start = max(0, match.start() - 100)
                line_end = min(len(log_content), match.end() + 100)
                context = log_content[line_start:line_end].strip()
                
                critical_findings.append({
                    "pattern": pattern,
                    "match": match.group(0),
                    "context": context
                })
                
        return {
            "suspicious_patterns": suspicious_findings,
            "critical_patterns": critical_findings
        }
    
    def analyze_log_with_gemini(self, log_content: str) -> Dict:
        """
        Analyze logs using Google Gemini API
        
        Args:
            log_content: Log content to analyze
            
        Returns:
            Dict: Analysis results from Gemini
        """
        if not log_content.strip():
            return {"success": False, "error": "Empty log content", "is_suspicious": False}
            
        # Create an appropriate prompt for Gemini
        # We'll specifically instruct Gemini to look for malicious activity
        # and return only PIDs if found
        prompt = {
            "contents": [
                {
                    "parts": [
                        {"text": "You are a malware and intrusion detection expert analyzing system logs. "
                                "Analyze these logs and identify signs of malicious activity like intrusions, "
                                "exploits, unusual process behavior, or malware activity. "
                                "Focus on unexpected behavior patterns, privilege escalation, network anomalies, "
                                "or suspicious process execution. "
                                "Respond with JSON only and no explanations or additional text:\n"
                                "{\n"
                                "  \"is_suspicious\": boolean (true if you detect malicious activity, otherwise false),\n"
                                "  \"suspicious_pids\": [list of process IDs if found, otherwise empty array],\n"
                                "  \"analysis_summary\": \"Brief one sentence explanation of what was found or why it's suspicious\"\n"
                                "}\n\n"
                                "Here are the logs to analyze:\n\n" + log_content[:20000]}  # Limit log size
                    ]
                }
            ]
        }
        
        # API call to Gemini
        headers = {
            "Content-Type": "application/json"
        }
        
        url = f"{self.gemini_api_url}?key={self.gemini_api_key}"
        
        try:
            response = requests.post(url, headers=headers, json=prompt)
            
            if response.status_code == 200:
                result = response.json()
                
                # Extract the text response
                text = result.get("candidates", [{}])[0].get("content", {}).get("parts", [{}])[0].get("text", "")
                
                # Try to parse JSON from the response
                try:
                    # Find JSON in the response (it might be surrounded by markdown or other text)
                    json_match = re.search(r'\{.*\}', text, re.DOTALL)
                    if json_match:
                        json_str = json_match.group(0)
                        analysis_result = json.loads(json_str)
                        
                        # Ensure the result has the expected structure
                        if "is_suspicious" not in analysis_result:
                            analysis_result["is_suspicious"] = False
                        if "suspicious_pids" not in analysis_result:
                            analysis_result["suspicious_pids"] = []
                        if "analysis_summary" not in analysis_result:
                            analysis_result["analysis_summary"] = "No explanation provided"
                            
                        analysis_result["success"] = True
                        return analysis_result
                    else:
                        # If we can't find JSON, try to infer a result
                        is_suspicious = "suspicious" in text.lower() or "malicious" in text.lower()
                        return {
                            "success": True, 
                            "is_suspicious": is_suspicious,
                            "suspicious_pids": [],
                            "analysis_summary": text[:200] if is_suspicious else "No clear malicious activity detected",
                            "raw_response": text
                        }
                except Exception as e:
                    return {
                        "success": False,
                        "error": f"Failed to parse Gemini response: {str(e)}",
                        "is_suspicious": False,
                        "raw_response": text
                    }
            else:
                return {
                    "success": False,
                    "error": f"Gemini API error: {response.status_code} - {response.text}",
                    "is_suspicious": False
                }
                
        except Exception as e:
            return {
                "success": False,
                "error": f"Exception during Gemini API call: {str(e)}",
                "is_suspicious": False
            }
            
    def extract_pids_from_findings(self, findings: Dict) -> List[int]:
        """
        Extract PIDs from log analysis findings
        
        Args:
            findings: Analysis findings from _basic_log_analysis
            
        Returns:
            List[int]: List of suspicious PIDs
        """
        pids = []
        
        # Extract PIDs from suspicious patterns
        for finding in findings.get("suspicious_patterns", []) + findings.get("critical_patterns", []):
            # Look for PIDs in the context
            context = finding.get("context", "")
            
            # Common format: pid=1234
            pid_matches = re.findall(r'pid=(\d+)', context)
            pids.extend([int(pid) for pid in pid_matches])
            
            # Common format: process 1234
            process_matches = re.findall(r'process (\d+)', context)
            pids.extend([int(pid) for pid in process_matches])
            
            # Common format: [1234]
            bracket_matches = re.findall(r'\[(\d+)\]', context)
            # Only consider numbers in brackets as PIDs if they're reasonable
            for pid_str in bracket_matches:
                pid = int(pid_str)
                if 1 < pid < 100000:  # Reasonable PID range
                    pids.append(pid)
        
        # Remove duplicates and return
        return list(set(pids))
    
    def analyze_system_logs(self, time_window: int = 60) -> Dict:
        """
        Analyze all system logs
        
        Args:
            time_window: Time window in minutes to filter logs (0 for all logs)
            
        Returns:
            Dict: Analysis results
        """
        all_results = {
            "is_suspicious": False,
            "suspicious_pids": [],
            "log_findings": {},
            "combined_analysis": {}
        }
        
        combined_log_content = ""
        
        # Analyze each log file
        for log_name, log_path in self.LOG_PATHS.items():
            log_content = self._read_log_file(log_path, time_window)
            
            if not log_content:
                all_results["log_findings"][log_name] = {
                    "error": f"Could not read log file {log_path}",
                    "findings": {"suspicious_patterns": [], "critical_patterns": []}
                }
                continue
                
            # Perform basic pattern analysis
            basic_findings = self._basic_log_analysis(log_content)
            
            # Extract suspicious PIDs
            suspicious_pids = self.extract_pids_from_findings(basic_findings)
            
            all_results["log_findings"][log_name] = {
                "file_path": log_path,
                "findings": basic_findings,
                "suspicious_pids": suspicious_pids
            }
            
            # Combine the most important parts of logs for LLM analysis
            # We'll take any log entries that triggered our pattern matches
            for finding in basic_findings.get("suspicious_patterns", []) + basic_findings.get("critical_patterns", []):
                combined_log_content += f"From {log_name}: {finding.get('context', '')}\n\n"
            
            # Update the overall list of suspicious PIDs
            all_results["suspicious_pids"].extend(suspicious_pids)
        
        # If we found suspicious patterns through basic analysis
        if combined_log_content:
            # Perform LLM analysis on combined suspicious log entries
            gemini_result = self.analyze_log_with_gemini(combined_log_content)
            all_results["combined_analysis"] = gemini_result
            
            # Update suspicious flag and PIDs based on Gemini's analysis
            if gemini_result.get("is_suspicious", False):
                all_results["is_suspicious"] = True
                all_results["suspicious_pids"].extend(gemini_result.get("suspicious_pids", []))
        
        # Basic analysis might have found suspicious patterns too
        for log_findings in all_results["log_findings"].values():
            if (log_findings.get("findings", {}).get("suspicious_patterns") or 
                log_findings.get("findings", {}).get("critical_patterns")):
                all_results["is_suspicious"] = True
                break
        
        # Remove duplicates in the final PID list
        all_results["suspicious_pids"] = list(set(all_results["suspicious_pids"]))
        
        return all_results


if __name__ == "__main__":
    # Simple command line interface for testing
    import sys
    import argparse
    
    parser = argparse.ArgumentParser(description="Analyze system logs for malicious activity")
    parser.add_argument("--api-key", required=True, help="Google Gemini API key")
    parser.add_argument("--time-window", type=int, default=60,
                        help="Time window in minutes (0 for all logs)")
    parser.add_argument("--log-file", help="Specific log file to analyze (instead of all logs)")
    
    args = parser.parse_args()
    
    analyzer = LogAnalyzer(args.api_key)
    
    if args.log_file:
        # Analyze a specific log file
        log_content = analyzer._read_log_file(args.log_file, args.time_window)
        
        if not log_content:
            print(f"Could not read log file: {args.log_file}")
            sys.exit(1)
            
        # Perform basic analysis
        basic_findings = analyzer._basic_log_analysis(log_content)
        suspicious_pids = analyzer.extract_pids_from_findings(basic_findings)
        
        print(f"Basic analysis of {args.log_file}:")
        print(f"  Suspicious patterns found: {len(basic_findings.get('suspicious_patterns', []))}")
        print(f"  Critical patterns found: {len(basic_findings.get('critical_patterns', []))}")
        
        if suspicious_pids:
            print(f"  Suspicious PIDs found: {suspicious_pids}")
        
        # Perform LLM analysis
        print("\nPerforming LLM analysis with Google Gemini...")
        gemini_result = analyzer.analyze_log_with_gemini(log_content)
        
        print(f"Gemini analysis result:")
        print(f"  Is suspicious: {gemini_result.get('is_suspicious', False)}")
        print(f"  Analysis summary: {gemini_result.get('analysis_summary', 'No summary provided')}")
        
        if gemini_result.get("suspicious_pids"):
            print(f"  Suspicious PIDs: {gemini_result.get('suspicious_pids')}")
    else:
        # Analyze all system logs
        print(f"Analyzing system logs (time window: {args.time_window} minutes)...")
        results = analyzer.analyze_system_logs(args.time_window)
        
        print(f"Analysis complete.")
        print(f"Is suspicious: {results['is_suspicious']}")
        
        if results["suspicious_pids"]:
            print(f"Suspicious PIDs: {results['suspicious_pids']}")
            
        print("\nLog findings summary:")
        for log_name, log_data in results["log_findings"].items():
            susp_count = len(log_data.get("findings", {}).get("suspicious_patterns", []))
            crit_count = len(log_data.get("findings", {}).get("critical_patterns", []))
            
            if "error" in log_data:
                print(f"  {log_name}: Error - {log_data['error']}")
            elif susp_count > 0 or crit_count > 0:
                print(f"  {log_name}: {susp_count} suspicious, {crit_count} critical patterns")
        
        if "combined_analysis" in results and results["combined_analysis"].get("success"):
            print("\nGemini analysis:")
            print(f"  Is suspicious: {results['combined_analysis'].get('is_suspicious', False)}")
            print(f"  Analysis summary: {results['combined_analysis'].get('analysis_summary', 'No summary provided')}")