#!/usr/bin/env python3
"""
Test module for the VirusTotal client.
Uses mocks to avoid making actual API calls.
"""

import os
import sys
import unittest
import tempfile
import json
from unittest.mock import patch, MagicMock

# Add detection directory to path to import modules
sys.path.insert(0, os.path.abspath(os.path.join(os.path.dirname(__file__), '..')))
from detection.virustotalUpload import VirusTotalClient

class TestVirusTotalClient(unittest.TestCase):
    """Tests for the VirusTotalClient class"""
    
    def setUp(self):
        """Set up test environment"""
        self.api_key = "fake_api_key"
        self.client = VirusTotalClient(self.api_key)
        self.temp_dir = tempfile.TemporaryDirectory()
        
        # Create test files
        self.test_file = os.path.join(self.temp_dir.name, "test_file.txt")
        with open(self.test_file, "w") as f:
            f.write("This is a test file for VirusTotal API testing")
            
    def tearDown(self):
        """Clean up after tests"""
        self.temp_dir.cleanup()
        
    def test_initialization(self):
        """Test initialization of the VirusTotal client"""
        self.assertEqual(self.client.api_key, self.api_key)
        self.assertEqual(self.client.headers["x-apikey"], self.api_key)
        self.assertEqual(self.client.headers["Accept"], "application/json")
        
    @patch('requests.get')
    def test_get_file_report_by_hash(self, mock_get):
        """Test getting a file report by hash"""
        # Mock successful response
        mock_response = MagicMock()
        mock_response.status_code = 200
        mock_response.json.return_value = {
            "data": {
                "attributes": {
                    "last_analysis_stats": {
                        "malicious": 5,
                        "suspicious": 2,
                        "undetected": 63,
                        "harmless": 10
                    },
                    "sha256": "fake_sha256",
                    "md5": "fake_md5"
                }
            }
        }
        mock_get.return_value = mock_response
        
        result = self.client.get_file_report_by_hash("fake_hash")
        
        # Check that get was called with expected parameters
        mock_get.assert_called_once()
        self.assertEqual(mock_get.call_args[0][0], f"{self.client.BASE_URL}/files/fake_hash")
        
        # Check that response was parsed correctly
        self.assertEqual(result["data"]["attributes"]["sha256"], "fake_sha256")
        
        # Test file not found
        mock_response.status_code = 404
        result = self.client.get_file_report_by_hash("nonexistent_hash")
        self.assertIn("error", result)
        
        # Test other error
        mock_response.status_code = 500
        mock_response.text = "Server error"
        result = self.client.get_file_report_by_hash("problem_hash")
        self.assertIn("error", result)
        
    @patch('requests.post')
    def test_upload_file(self, mock_post):
        """Test uploading a file"""
        # Mock successful response
        mock_response = MagicMock()
        mock_response.status_code = 200
        mock_response.json.return_value = {
            "data": {
                "id": "fake_analysis_id"
            }
        }
        mock_post.return_value = mock_response
        
        result = self.client.upload_file(self.test_file)
        
        # Check that post was called with expected parameters
        mock_post.assert_called_once()
        self.assertEqual(mock_post.call_args[0][0], f"{self.client.BASE_URL}/files")
        
        # Check that response was parsed correctly
        self.assertEqual(result["data"]["id"], "fake_analysis_id")
        
        # Test upload error
        mock_response.status_code = 400
        mock_response.text = "Bad request"
        result = self.client.upload_file(self.test_file)
        self.assertIn("error", result)

        # Create a file larger than the upload limit to test size check
        large_file = os.path.join(self.temp_dir.name, "large_file.bin")
        mock_getsize = MagicMock(return_value=33 * 1024 * 1024)  # Just over 32MB
        with patch('os.path.getsize', mock_getsize):
            result = self.client.upload_file(large_file)
            self.assertIn("error", result)
            self.assertIn("too large", result["error"])
        
    @patch('requests.get')
    def test_get_upload_analysis(self, mock_get):
        """Test getting analysis results"""
        # Mock successful response
        mock_response = MagicMock()
        mock_response.status_code = 200
        mock_response.json.return_value = {
            "data": {
                "attributes": {
                    "status": "completed",
                    "stats": {
                        "malicious": 3,
                        "suspicious": 0
                    }
                }
            }
        }
        mock_get.return_value = mock_response
        
        result = self.client.get_upload_analysis("fake_analysis_id")
        
        # Check that get was called with expected parameters
        mock_get.assert_called_once()
        self.assertEqual(mock_get.call_args[0][0], f"{self.client.BASE_URL}/analyses/fake_analysis_id")
        
        # Check that response was parsed correctly
        self.assertEqual(result["data"]["attributes"]["status"], "completed")
        
        # Test error response
        mock_response.status_code = 500
        mock_response.text = "Server error"
        result = self.client.get_upload_analysis("problem_analysis_id")
        self.assertIn("error", result)
        
    @patch.object(VirusTotalClient, 'get_file_report_by_hash')
    @patch.object(VirusTotalClient, 'upload_file')
    @patch.object(VirusTotalClient, 'get_upload_analysis')
    @patch.object(VirusTotalClient, '_calculate_sha256')
    def test_check_file(self, mock_sha256, mock_analysis, mock_upload, mock_report):
        """Test checking a file"""
        # Setup mocks
        mock_sha256.return_value = "fake_sha256"
        
        # Test when file is found in database
        mock_report.return_value = {
            "data": {
                "attributes": {
                    "last_analysis_stats": {
                        "malicious": 10,  # High number of detections
                        "suspicious": 0,
                        "undetected": 60
                    },
                    "sha256": "fake_sha256",
                    "md5": "fake_md5"
                }
            }
        }
        
        result = self.client.check_file(self.test_file)
        
        # Check that the report function was called and file detected as malicious
        mock_report.assert_called_once_with("fake_sha256")
        self.assertTrue(result["is_malicious"])
        
        # Test when file is not found and must be uploaded
        mock_report.reset_mock()
        mock_report.return_value = {"error": "File not found in VirusTotal database"}
        mock_upload.return_value = {"data": {"id": "fake_analysis_id"}}
        mock_analysis.return_value = {
            "data": {
                "attributes": {
                    "status": "completed",
                    "stats": {
                        "malicious": 0,  # Low number of detections
                        "suspicious": 0,
                        "undetected": 70
                    }
                }
            }
        }
        
        # Don't wait for analysis to complete
        result = self.client.check_file(self.test_file, wait_for_analysis=False)
        
        # Check that upload function was called
        mock_upload.assert_called_once()
        self.assertEqual(result["status"], "Submitted for analysis")
        
        # Test error in upload
        mock_report.reset_mock()
        mock_upload.reset_mock()
        mock_upload.return_value = {"error": "Upload error"}
        
        result = self.client.check_file(self.test_file)
        
        self.assertIn("error", result)
        
    def test_calculate_sha256(self):
        """Test SHA-256 calculation"""
        # Create a file with known content
        known_file = os.path.join(self.temp_dir.name, "known.txt")
        with open(known_file, "wb") as f:
            f.write(b"hello world")
            
        # SHA-256 of "hello world" is b94d27b9934d3e08a52e52d7da7dabfac484efe37a5380ee9088f7ace2efcde9
        expected_sha256 = "b94d27b9934d3e08a52e52d7da7dabfac484efe37a5380ee9088f7ace2efcde9"
        calculated_sha256 = self.client._calculate_sha256(known_file)
        
        self.assertEqual(calculated_sha256, expected_sha256)
        
    def test_process_report(self):
        """Test processing a VirusTotal report"""
        # Test with malicious report
        report = {
            "data": {
                "attributes": {
                    "last_analysis_stats": {
                        "malicious": 5,
                        "suspicious": 2,
                        "undetected": 63,
                        "harmless": 10
                    },
                    "sha256": "fake_sha256",
                    "md5": "fake_md5",
                    "first_submission_date": 1600000000,
                    "last_analysis_date": 1600001000,
                    "type_description": "Portable Executable",
                    "names": ["suspicious.exe"]
                }
            }
        }
        
        result = self.client._process_report(report)
        
        # With 5 malicious + 2 suspicious detections, it should be flagged
        self.assertTrue(result["is_malicious"])
        self.assertEqual(result["detection_ratio"], "7/80")
        self.assertEqual(result["sha256"], "fake_sha256")
        self.assertEqual(result["md5"], "fake_md5")
        self.assertEqual(result["file_type"], "Portable Executable")
        
        # Test with clean report
        report = {
            "data": {
                "attributes": {
                    "last_analysis_stats": {
                        "malicious": 1,
                        "suspicious": 1,
                        "undetected": 68,
                        "harmless": 10
                    },
                    "sha256": "clean_sha256",
                    "md5": "clean_md5"
                }
            }
        }
        
        result = self.client._process_report(report)
        
        # With only 1+1=2 detections (below threshold of 3), it should not be flagged
        self.assertFalse(result["is_malicious"])
        self.assertEqual(result["detection_ratio"], "2/80")
        
    def test_process_analysis_result(self):
        """Test processing an analysis result"""
        # Test with malicious analysis
        analysis = {
            "data": {
                "id": "fake_analysis_id",
                "attributes": {
                    "status": "completed",
                    "stats": {
                        "malicious": 4,
                        "suspicious": 0,
                        "undetected": 66,
                        "harmless": 10
                    }
                }
            }
        }
        
        result = self.client._process_analysis_result(analysis)
        
        # With 4 malicious detections, it should be flagged
        self.assertTrue(result["is_malicious"])
        self.assertEqual(result["detection_ratio"], "4/80")
        self.assertEqual(result["status"], "completed")
        self.assertEqual(result["analysis_id"], "fake_analysis_id")
        
        # Test with clean analysis
        analysis = {
            "data": {
                "id": "clean_analysis_id",
                "attributes": {
                    "status": "completed",
                    "stats": {
                        "malicious": 1,
                        "suspicious": 1,
                        "undetected": 68,
                        "harmless": 10
                    }
                }
            }
        }
        
        result = self.client._process_analysis_result(analysis)
        
        # With only 1+1=2 detections (below threshold of 3), it should not be flagged
        self.assertFalse(result["is_malicious"])


if __name__ == "__main__":
    unittest.main()