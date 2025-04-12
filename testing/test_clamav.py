#!/usr/bin/env python3
"""
Test module for the ClamAV scanner.
Uses mocks to avoid actual virus scanning in some tests.
"""

import os
import sys
import unittest
import tempfile
import json
from unittest.mock import patch, MagicMock

# Add detection directory to path to import modules
sys.path.insert(0, os.path.abspath(os.path.join(os.path.dirname(__file__), '..')))
from detection.clamav_scan import ClamAVScanner

class TestClamAVScanner(unittest.TestCase):
    """Tests for the ClamAVScanner class"""
    
    def setUp(self):
        """Set up test environment"""
        # Create a mock for clamscan to avoid requiring ClamAV for tests
        self.mock_clamscan_path = '/mock/path/to/clamscan'
        
        # Create temporary directory for test files
        self.temp_dir = tempfile.TemporaryDirectory()
        
        # Create test file
        self.test_file = os.path.join(self.temp_dir.name, "test_file.txt")
        with open(self.test_file, "w") as f:
            f.write("This is a test file for ClamAV scanning")
        
    def tearDown(self):
        """Clean up after tests"""
        self.temp_dir.cleanup()
    
    @patch('subprocess.run')
    def test_initialization(self, mock_run):
        """Test initialization of the ClamAV scanner"""
        # Mock the version check
        mock_process = MagicMock()
        mock_process.returncode = 0
        mock_process.stdout = "ClamAV 0.103.7/26842/Tue Mar 21 07:09:14 2023\n"
        mock_run.return_value = mock_process
        
        # Create scanner
        scanner = ClamAVScanner(clamscan_path=self.mock_clamscan_path)
        
        # Check that version check was called
        mock_run.assert_called_once()
        self.assertEqual(scanner.clamscan_path, self.mock_clamscan_path)
        
        # Test failed initialization
        mock_process.returncode = 1
        mock_process.stderr = "Error: clamscan not found"
        
        with self.assertRaises(RuntimeError):
            ClamAVScanner(clamscan_path=self.mock_clamscan_path)
    
    @patch('subprocess.run')
    def test_scan_file_clean(self, mock_run):
        """Test scanning a clean file"""
        # Mock the version check
        mock_version = MagicMock()
        mock_version.returncode = 0
        mock_version.stdout = "ClamAV 0.103.7/26842/Tue Mar 21 07:09:14 2023\n"
        
        # Mock the scan result - return code 0 means no virus
        mock_scan = MagicMock()
        mock_scan.returncode = 0
        mock_scan.stdout = f"{self.test_file}: OK\n"
        
        mock_run.side_effect = [mock_version, mock_scan]
        
        # Create scanner and scan file
        scanner = ClamAVScanner(clamscan_path=self.mock_clamscan_path)
        result = scanner.scan_file(self.test_file)
        
        # Check result
        self.assertFalse(result["is_malicious"])
        self.assertEqual(result["scan_result"], "Clean")
    
    @patch('subprocess.run')
    def test_scan_file_infected(self, mock_run):
        """Test scanning an infected file"""
        # Mock the version check
        mock_version = MagicMock()
        mock_version.returncode = 0
        mock_version.stdout = "ClamAV 0.103.7/26842/Tue Mar 21 07:09:14 2023\n"
        
        # Mock the scan result - return code 1 means virus found
        mock_scan = MagicMock()
        mock_scan.returncode = 1
        mock_scan.stdout = f"{self.test_file}: Eicar-Test-Signature FOUND\n"
        
        mock_run.side_effect = [mock_version, mock_scan]
        
        # Create scanner and scan file
        scanner = ClamAVScanner(clamscan_path=self.mock_clamscan_path)
        result = scanner.scan_file(self.test_file)
        
        # Check result
        self.assertTrue(result["is_malicious"])
        self.assertEqual(result["scan_method"], "clamscan")
        self.assertEqual(result["detection_name"], "Eicar-Test-Signature FOUND")
    
    @patch('subprocess.run')
    def test_scan_file_error(self, mock_run):
        """Test scanning with error"""
        # Mock the version check
        mock_version = MagicMock()
        mock_version.returncode = 0
        mock_version.stdout = "ClamAV 0.103.7/26842/Tue Mar 21 07:09:14 2023\n"
        
        # Mock the scan result - return code 2 means error
        mock_scan = MagicMock()
        mock_scan.returncode = 2
        mock_scan.stderr = "ERROR: Can't access file"
        
        mock_run.side_effect = [mock_version, mock_scan]
        
        # Create scanner and scan file
        scanner = ClamAVScanner(clamscan_path=self.mock_clamscan_path)
        result = scanner.scan_file(self.test_file)
        
        # Check result
        self.assertFalse(result["is_malicious"])
        self.assertTrue("error" in result)
    
    @patch('subprocess.run')
    def test_scan_directory(self, mock_run):
        """Test scanning a directory"""
        # Mock the version check
        mock_version = MagicMock()
        mock_version.returncode = 0
        mock_version.stdout = "ClamAV 0.103.7/26842/Tue Mar 21 07:09:14 2023\n"
        
        # Mock the scan result - return code 1 means virus found
        mock_scan = MagicMock()
        mock_scan.returncode = 1
        mock_scan.stdout = f"{self.test_file}: Eicar-Test-Signature FOUND\n/some/other/file.txt: Malware.Generic FOUND\n"
        
        mock_run.side_effect = [mock_version, mock_scan]
        
        # Create scanner and scan directory
        scanner = ClamAVScanner(clamscan_path=self.mock_clamscan_path)
        result = scanner.scan_directory(self.temp_dir.name)
        
        # Check result
        self.assertTrue(result["is_malicious"])
        self.assertEqual(result["total_infected"], 2)
        self.assertEqual(len(result["infected_files"]), 2)
        self.assertEqual(result["scan_method"], "clamscan directory")
        
        # Check that recursive was set by default
        mock_run.assert_called_with(
            [self.mock_clamscan_path, '-r', '--exclude-dir=', '.git', 
             '--exclude-dir=', 'node_modules', '--exclude-dir=', 'venv', 
             '--exclude-dir=', '.venv', '--exclude-dir=', '__pycache__', 
             '--max-filesize=100M', '--no-summary', '--infected', 
             '--stdout', self.temp_dir.name],
            capture_output=True, text=True, timeout=300
        )
    
    @patch('subprocess.run')
    def test_database_info(self, mock_run):
        """Test getting database info"""
        # Mock the version check
        mock_version = MagicMock()
        mock_version.returncode = 0
        mock_version.stdout = """ClamAV 0.103.7/26842/Tue Mar 21 07:09:14 2023
Database: /var/lib/clamav/main.cvd
Database version: 62
Build time: Tue Mar 21 07:09:14 2023
Main.cvd: 4569249 signatures
"""
        
        mock_run.side_effect = [mock_version, mock_version]
        
        # Create scanner and get info
        scanner = ClamAVScanner(clamscan_path=self.mock_clamscan_path)
        result = scanner.get_clamav_database_info()
        
        # Check result
        self.assertEqual(result["clamav_version"], "0.103.7/26842/Tue Mar 21 07:09:14 2023")
        self.assertEqual(result["signature_count"], "4569249")
    
    @patch('subprocess.run')
    def test_update_database(self, mock_run):
        """Test updating the database"""
        # Mock the version check
        mock_version = MagicMock()
        mock_version.returncode = 0
        mock_version.stdout = "ClamAV 0.103.7/26842/Tue Mar 21 07:09:14 2023\n"
        
        # Mock the update result
        mock_update = MagicMock()
        mock_update.returncode = 0
        mock_update.stdout = "Database updated successfully"
        
        mock_run.side_effect = [mock_version, mock_update]
        
        # Create scanner and update
        scanner = ClamAVScanner(clamscan_path=self.mock_clamscan_path)
        result = scanner.update_database()
        
        # Check result
        self.assertTrue(result["success"])
    
    @patch('subprocess.run')
    def test_create_test_virus(self, mock_run):
        """Test creating and detecting EICAR test file"""
        # Mock the version check
        mock_version = MagicMock()
        mock_version.returncode = 0
        mock_version.stdout = "ClamAV 0.103.7/26842/Tue Mar 21 07:09:14 2023\n"
        
        # Mock the scan result - return code 1 means virus found
        mock_scan = MagicMock()
        mock_scan.returncode = 1
        mock_scan.stdout = f"{self.test_file}: Eicar-Test-Signature FOUND\n"
        
        mock_run.side_effect = [mock_version, mock_scan]
        
        # Create scanner and test file
        scanner = ClamAVScanner(clamscan_path=self.mock_clamscan_path)
        result = scanner.create_test_virus_file(self.test_file)
        
        # Check result
        self.assertTrue(result["success"])
        
        # Verify EICAR content was written
        with open(self.test_file, 'r') as f:
            content = f.read()
            self.assertTrue("EICAR-STANDARD-ANTIVIRUS-TEST-FILE" in content)
    
    @patch('os.listdir')
    @patch('os.path.isdir')
    @patch('os.readlink')
    @patch('subprocess.run')
    def test_get_pids_using_infected_files(self, mock_run, mock_readlink, mock_isdir, mock_listdir):
        """Test finding processes using infected files"""
        # Mock the version check
        mock_version = MagicMock()
        mock_version.returncode = 0
        mock_version.stdout = "ClamAV 0.103.7/26842/Tue Mar 21 07:09:14 2023\n"
        mock_run.return_value = mock_version
        
        # Setup mocks for process inspection
        mock_listdir.side_effect = [
            ['1', '2', 'not_a_pid'],  # /proc contents
            ['0', '1', '2'],          # file descriptors for pid 1
            ['0', '1', '2'],          # file descriptors for pid 2
        ]
        mock_isdir.return_value = True
        mock_readlink.side_effect = [
            '/some/other/file',        # pid 1, fd 0
            self.test_file,            # pid 1, fd 1 - matches our infected file
            '/some/other/file',        # pid 1, fd 2
            '/some/other/file',        # pid 2, fd 0
            '/some/other/file',        # pid 2, fd 1
            '/some/other/file',        # pid 2, fd 2
        ]
        
        # Create scanner and find PIDs
        scanner = ClamAVScanner(clamscan_path=self.mock_clamscan_path)
        result = scanner.get_pids_using_infected_files([self.test_file])
        
        # Check result - should find PID 1
        self.assertEqual(result, [1])


# Integration test - only run if ClamAV is actually installed
@unittest.skipIf(not os.path.exists('/usr/bin/clamscan') and 
                 not os.path.exists('/usr/local/bin/clamscan') and
                 not os.path.exists('/opt/homebrew/bin/clamscan'),
                 "ClamAV not installed")
class TestClamAVIntegration(unittest.TestCase):
    """Integration tests for ClamAVScanner with real ClamAV"""
    
    def setUp(self):
        """Set up test environment"""
        self.temp_dir = tempfile.TemporaryDirectory()
        self.scanner = ClamAVScanner()
        
    def tearDown(self):
        """Clean up after tests"""
        self.temp_dir.cleanup()
    
    def test_eicar_detection(self):
        """Test that ClamAV can detect the EICAR test virus"""
        # Create an EICAR test file
        eicar_path = os.path.join(self.temp_dir.name, "eicar.txt")
        eicar = 'X5O!P%@AP[4\\PZX54(P^)7CC)7}$EICAR-STANDARD-ANTIVIRUS-TEST-FILE!$H+H*'
        
        with open(eicar_path, 'w') as f:
            f.write(eicar)
        
        # Scan it
        result = self.scanner.scan_file(eicar_path)
        
        # Should be detected
        self.assertTrue(result["is_malicious"])
        self.assertTrue("Eicar-Test-Signature" in str(result) or 
                        "EICAR" in str(result) or
                        "Test-File" in str(result))
    
    def test_clean_file_detection(self):
        """Test that ClamAV correctly identifies clean files"""
        # Create a clean file
        clean_path = os.path.join(self.temp_dir.name, "clean.txt")
        with open(clean_path, 'w') as f:
            f.write("This is a clean file with no malicious content.")
        
        # Scan it
        result = self.scanner.scan_file(clean_path)
        
        # Should be clean
        self.assertFalse(result["is_malicious"])
        self.assertEqual(result["scan_result"], "Clean")
    
    def test_database_info_real(self):
        """Test getting real database info"""
        info = self.scanner.get_clamav_database_info()
        
        # Should have version info
        self.assertTrue("clamav_version" in info)
        self.assertTrue("database_version" in info)


if __name__ == "__main__":
    unittest.main()