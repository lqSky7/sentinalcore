#!/usr/bin/env python3
"""
Test module for the log analyzer.
Uses mocks to avoid making actual API calls.
"""

import os
import sys
import unittest
import tempfile
from unittest.mock import patch, MagicMock

# Add detection directory to path to import modules
sys.path.insert(0, os.path.abspath(os.path.join(os.path.dirname(__file__), '..')))
from detection.LLMlogs import LogAnalyzer

class TestLogAnalyzer(unittest.TestCase):
    """Tests for the LogAnalyzer class"""
    
    def setUp(self):
        """Set up test environment"""
        self.api_key = "fake_gemini_api_key"
        self.analyzer = LogAnalyzer(self.api_key)
        self.temp_dir = tempfile.TemporaryDirectory()
        
        # Create sample log files for testing
        self.normal_log = os.path.join(self.temp_dir.name, "normal.log")
        with open(self.normal_log, "w") as f:
            f.write("May 12 13:45:01 localhost systemd[1]: Starting System Logging Service...\n")
            f.write("May 12 13:45:02 localhost systemd[1]: Started System Logging Service.\n")
            f.write("May 12 13:46:15 localhost kernel: [    0.000000] Linux version 5.15.0-generic\n")
            
        self.suspicious_log = os.path.join(self.temp_dir.name, "suspicious.log")
        with open(self.suspicious_log, "w") as f:
            f.write("May 12 14:01:23 localhost sshd[1234]: Failed password for invalid user admin from 192.168.1.100 port 53270 ssh2\n")
            f.write("May 12 14:01:25 localhost sshd[1234]: Failed password for invalid user admin from 192.168.1.100 port 53270 ssh2\n")
            f.write("May 12 14:01:27 localhost sshd[1234]: Failed password for invalid user root from 192.168.1.100 port 53271 ssh2\n")
            f.write("May 12 14:02:01 localhost sudo: pam_unix(sudo:auth): authentication failure; logname=user uid=1000 euid=0 tty=/dev/pts/0 ruser=user rhost=  user=user\n")
            
        self.critical_log = os.path.join(self.temp_dir.name, "critical.log")
        with open(self.critical_log, "w") as f:
            f.write("May 12 15:30:45 localhost kernel: [ 1234.567890] general protection fault, probably for address 0x7f8b4c3d2a1\n")
            f.write("May 12 15:30:46 localhost kernel: [ 1234.567891] BUG: unable to handle kernel NULL pointer dereference at 0000000000000000\n")
            f.write("May 12 15:30:47 localhost kernel: [ 1234.567892] Rootkit Hunter started. Checking system...\n")
            f.write("May 12 15:30:48 localhost kernel: [ 1234.567893] INFO: task suspicious_process:1234 blocked for more than 120 seconds\n")
    
    def tearDown(self):
        """Clean up after tests"""
        self.temp_dir.cleanup()
        
    @patch('subprocess.run')
    def test_read_log_file_dmesg(self, mock_run):
        """Test reading from dmesg command"""
        # Mock dmesg command output
        mock_process = MagicMock()
        mock_process.returncode = 0
        mock_process.stdout = "Sample dmesg output"
        mock_run.return_value = mock_process
        
        # Call the function
        result = self.analyzer._read_log_file("dmesg")
        
        # Check results
        mock_run.assert_called_once_with(["dmesg"], capture_output=True, text=True)
        self.assertEqual(result, "Sample dmesg output")
        
        # Test failed command
        mock_process.returncode = 1
        mock_run.reset_mock()
        result = self.analyzer._read_log_file("dmesg")
        
        # Check empty result on error
        self.assertEqual(result, "")
        
    def test_read_log_file(self):
        """Test reading from regular log files"""
        # Read a normal log file
        result = self.analyzer._read_log_file(self.normal_log)
        
        # The result should be the content of the file
        with open(self.normal_log, "r") as f:
            expected = f.read()
        self.assertEqual(result, expected)
        
        # Test with non-existent file
        result = self.analyzer._read_log_file("/path/to/nonexistent/file")
        self.assertEqual(result, "")
        
    def test_basic_log_analysis_normal(self):
        """Test basic log analysis with normal logs"""
        with open(self.normal_log, "r") as f:
            log_content = f.read()
            
        results = self.analyzer._basic_log_analysis(log_content)
        
        # Normal logs should not trigger any patterns
        self.assertEqual(len(results["suspicious_patterns"]), 0)
        self.assertEqual(len(results["critical_patterns"]), 0)
        
    def test_basic_log_analysis_suspicious(self):
        """Test basic log analysis with suspicious logs"""
        with open(self.suspicious_log, "r") as f:
            log_content = f.read()
            
        results = self.analyzer._basic_log_analysis(log_content)
        
        # Suspicious logs should trigger suspicious patterns
        self.assertGreater(len(results["suspicious_patterns"]), 0)
        self.assertEqual(len(results["critical_patterns"]), 0)
        
        # Specifically, there should be at least 3 failed login attempts
        failed_logins = [p for p in results["suspicious_patterns"] 
                        if "Failed password" in p["match"]]
        self.assertGreaterEqual(len(failed_logins), 3)
        
    def test_basic_log_analysis_critical(self):
        """Test basic log analysis with critical logs"""
        with open(self.critical_log, "r") as f:
            log_content = f.read()
            
        results = self.analyzer._basic_log_analysis(log_content)
        
        # Critical logs should trigger both suspicious and critical patterns
        self.assertGreater(len(results["critical_patterns"]), 0)
        
        # Check if specific critical patterns were found
        rootkit_patterns = [p for p in results["critical_patterns"] 
                          if "Rootkit" in p["match"]]
        fault_patterns = [p for p in results["critical_patterns"] 
                         if "general protection fault" in p["match"]]
        bug_patterns = [p for p in results["critical_patterns"] 
                       if "BUG:" in p["match"]]
                       
        self.assertGreaterEqual(len(rootkit_patterns), 1)
        self.assertGreaterEqual(len(fault_patterns), 1)
        self.assertGreaterEqual(len(bug_patterns), 1)
        
    def test_extract_pids_from_findings(self):
        """Test extracting PIDs from pattern findings"""
        # Create mock findings
        findings = {
            "suspicious_patterns": [
                {
                    "pattern": "test pattern",
                    "match": "process 1234 is suspicious",
                    "context": "This is a test where process 1234 is suspicious"
                },
                {
                    "pattern": "another pattern",
                    "match": "pid=5678",
                    "context": "Another test with pid=5678 in context"
                }
            ],
            "critical_patterns": [
                {
                    "pattern": "critical pattern",
                    "match": "kernel: [9876] critical error",
                    "context": "Critical error in kernel: [9876] critical error found"
                }
            ]
        }
        
        pids = self.analyzer.extract_pids_from_findings(findings)
        
        # Should find all three PIDs
        self.assertEqual(len(pids), 3)
        self.assertIn(1234, pids)
        self.assertIn(5678, pids)
        self.assertIn(9876, pids)
        
    @patch('requests.post')
    def test_analyze_log_with_gemini(self, mock_post):
        """Test log analysis with Gemini API"""
        # Create mock API response for suspicious logs
        mock_suspicious_response = MagicMock()
        mock_suspicious_response.status_code = 200
        mock_suspicious_response.json.return_value = {
            "candidates": [
                {
                    "content": {
                        "parts": [
                            {
                                "text": '{"is_suspicious": true, "suspicious_pids": [1234, 5678], "analysis_summary": "Multiple failed SSH login attempts detected"}'
                            }
                        ]
                    }
                }
            ]
        }
        
        # Create mock API response for normal logs
        mock_normal_response = MagicMock()
        mock_normal_response.status_code = 200
        mock_normal_response.json.return_value = {
            "candidates": [
                {
                    "content": {
                        "parts": [
                            {
                                "text": '{"is_suspicious": false, "suspicious_pids": [], "analysis_summary": "No suspicious activities detected"}'
                            }
                        ]
                    }
                }
            ]
        }
        
        # Test with suspicious logs
        mock_post.return_value = mock_suspicious_response
        with open(self.suspicious_log, "r") as f:
            log_content = f.read()
        
        result = self.analyzer.analyze_log_with_gemini(log_content)
        
        # Verify API was called with correct parameters
        mock_post.assert_called_once()
        self.assertTrue("gemini_api_url" in str(mock_post.call_args[0][0]))
        
        # Verify response parsing
        self.assertTrue(result["success"])
        self.assertTrue(result["is_suspicious"])
        self.assertEqual(len(result["suspicious_pids"]), 2)
        self.assertEqual(result["suspicious_pids"][0], 1234)
        self.assertEqual(result["analysis_summary"], "Multiple failed SSH login attempts detected")
        
        # Test with normal logs
        mock_post.reset_mock()
        mock_post.return_value = mock_normal_response
        with open(self.normal_log, "r") as f:
            log_content = f.read()
            
        result = self.analyzer.analyze_log_with_gemini(log_content)
        
        # Verify response parsing for non-suspicious case
        self.assertTrue(result["success"])
        self.assertFalse(result["is_suspicious"])
        self.assertEqual(len(result["suspicious_pids"]), 0)
        
        # Test error handling (API error)
        mock_post.reset_mock()
        mock_error_response = MagicMock()
        mock_error_response.status_code = 400
        mock_error_response.text = "Bad Request"
        mock_post.return_value = mock_error_response
        
        result = self.analyzer.analyze_log_with_gemini("test content")
        
        self.assertFalse(result["success"])
        self.assertFalse(result["is_suspicious"])
        self.assertIn("error", result)
        
        # Test parsing of malformed JSON response
        mock_post.reset_mock()
        mock_malformed_response = MagicMock()
        mock_malformed_response.status_code = 200
        mock_malformed_response.json.return_value = {
            "candidates": [
                {
                    "content": {
                        "parts": [
                            {
                                "text": "This is not valid JSON"
                            }
                        ]
                    }
                }
            ]
        }
        mock_post.return_value = mock_malformed_response
        
        result = self.analyzer.analyze_log_with_gemini("test content")
        
        self.assertFalse(result["success"])
        self.assertFalse(result["is_suspicious"])
        self.assertIn("error", result)
        
    @patch.object(LogAnalyzer, '_read_log_file')
    @patch.object(LogAnalyzer, '_basic_log_analysis')
    @patch.object(LogAnalyzer, 'analyze_log_with_gemini')
    @patch.object(LogAnalyzer, 'extract_pids_from_findings')
    def test_analyze_system_logs(self, mock_extract_pids, mock_analyze_gemini, mock_basic_analysis, mock_read_file):
        """Test the system log analysis workflow"""
        # Set up mocks
        mock_read_file.side_effect = [
            "auth log content",  # auth.log
            "syslog content",    # syslog
            "kernel log content", # kern.log
            "",                  # messages (empty/not found)
            "secure log content", # secure
            "",                  # audit.log (empty/not found)
            "dmesg content"      # dmesg output
        ]
        
        mock_basic_analysis.side_effect = [
            # auth.log results - suspicious
            {"suspicious_patterns": ["suspicious pattern 1"], "critical_patterns": []},
            # syslog results - normal
            {"suspicious_patterns": [], "critical_patterns": []},
            # kern.log results - critical
            {"suspicious_patterns": [], "critical_patterns": ["critical pattern 1"]},
            # messages results (empty file) - normal
            {"suspicious_patterns": [], "critical_patterns": []},
            # secure log results - normal
            {"suspicious_patterns": [], "critical_patterns": []},
            # audit.log results (empty file) - normal
            {"suspicious_patterns": [], "critical_patterns": []},
            # dmesg results - normal
            {"suspicious_patterns": [], "critical_patterns": []}
        ]
        
        mock_extract_pids.side_effect = [
            [1234],  # auth.log PIDs
            [],      # syslog PIDs
            [5678],  # kern.log PIDs
            [],      # messages PIDs
            [],      # secure PIDs
            [],      # audit.log PIDs
            []       # dmesg PIDs
        ]
        
        # Gemini API results
        mock_analyze_gemini.return_value = {
            "success": True,
            "is_suspicious": True,
            "suspicious_pids": [9012],
            "analysis_summary": "Found suspicious activity in logs"
        }
        
        # Perform system log analysis
        result = self.analyzer.analyze_system_logs()
        
        # Check that all logs were checked
        self.assertEqual(mock_read_file.call_count, 7)  # One for each log file
        self.assertEqual(mock_basic_analysis.call_count, 7)  # One for each log file
        
        # Check that Gemini analysis was performed (since we found suspicious patterns)
        mock_analyze_gemini.assert_called_once()
        
        # Check that results were properly aggregated
        self.assertTrue(result["is_suspicious"])
        self.assertIn(1234, result["suspicious_pids"])
        self.assertIn(5678, result["suspicious_pids"])
        self.assertIn(9012, result["suspicious_pids"])
        
        # Check log-specific results
        self.assertIn("auth", result["log_findings"])
        self.assertIn("kern", result["log_findings"])

        # Test when all logs are normal
        mock_read_file.reset_mock()
        mock_basic_analysis.reset_mock()
        mock_analyze_gemini.reset_mock()
        mock_extract_pids.reset_mock()
        
        mock_read_file.side_effect = ["content"] * 7  # All logs have content
        mock_basic_analysis.side_effect = [
            {"suspicious_patterns": [], "critical_patterns": []}
        ] * 7  # All logs are normal
        mock_extract_pids.side_effect = [[]] * 7  # No PIDs found
        
        # Perform system log analysis
        result = self.analyzer.analyze_system_logs()
        
        # Check that all logs were checked
        self.assertEqual(mock_read_file.call_count, 7)
        self.assertEqual(mock_basic_analysis.call_count, 7)
        
        # Since no suspicious patterns were found, Gemini analysis should not be called
        mock_analyze_gemini.assert_not_called()
        
        # Results should indicate no suspicious activity
        self.assertFalse(result["is_suspicious"])
        self.assertEqual(len(result["suspicious_pids"]), 0)


if __name__ == "__main__":
    unittest.main()