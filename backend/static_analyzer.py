import os
import math
import hashlib
import struct
import re
import requests
import time
from collections import Counter
from datetime import datetime
import json
from dotenv import load_dotenv

load_dotenv()

class StaticAnalyzer:
    def __init__(self):
        self.virustotal_api_key = os.getenv('VIRUSTOTAL_API_KEY')
        self.malware_bazaar_api = "https://mb-api.abuse.ch/api/v1/"
        
    def calculate_entropy(self, data):
        """Calculate Shannon entropy of data"""
        if not data:
            return 0
        
        # Count frequency of each byte
        counts = Counter(data)
        length = len(data)
        
        # Calculate entropy
        entropy = 0
        for count in counts.values():
            probability = count / length
            if probability > 0:
                entropy -= probability * math.log2(probability)
        
        return entropy
    
    def analyze_file_entropy(self, file_path):
        """Analyze file entropy and detect packing/encryption"""
        try:
            with open(file_path, 'rb') as f:
                data = f.read()
            
            file_size = len(data)
            if file_size == 0:
                return {'error': 'Empty file'}
            
            # Calculate overall entropy
            overall_entropy = self.calculate_entropy(data)
            
            # Analyze entropy in chunks (detect entropy variations)
            chunk_size = min(1024, file_size // 10) if file_size > 1024 else file_size
            chunk_entropies = []
            
            for i in range(0, file_size, chunk_size):
                chunk = data[i:i + chunk_size]
                chunk_entropy = self.calculate_entropy(chunk)
                chunk_entropies.append(chunk_entropy)
            
            avg_chunk_entropy = sum(chunk_entropies) / len(chunk_entropies) if chunk_entropies else 0
            entropy_variance = sum((e - avg_chunk_entropy) ** 2 for e in chunk_entropies) / len(chunk_entropies) if chunk_entropies else 0
            
            # Determine suspicion level
            suspicion_level = "Low"
            suspicion_reasons = []
            
            if overall_entropy > 7.5:
                suspicion_level = "High"
                suspicion_reasons.append("Very high entropy (possible encryption/packing)")
            elif overall_entropy > 6.5:
                suspicion_level = "Medium"
                suspicion_reasons.append("High entropy (possible compression/obfuscation)")
            
            if entropy_variance > 1.0:
                suspicion_reasons.append("High entropy variance (mixed content)")
            
            # Check for specific patterns
            if self._check_packer_signatures(data):
                suspicion_level = "High"
                suspicion_reasons.append("Known packer signatures detected")
            
            return {
                'file_path': file_path,
                'file_size': file_size,
                'overall_entropy': round(overall_entropy, 3),
                'average_chunk_entropy': round(avg_chunk_entropy, 3),
                'entropy_variance': round(entropy_variance, 3),
                'chunk_count': len(chunk_entropies),
                'suspicion_level': suspicion_level,
                'suspicion_reasons': suspicion_reasons,
                'analysis_type': 'entropy'
            }
            
        except Exception as e:
            return {'error': f'Entropy analysis failed: {str(e)}'}
    
    def _check_packer_signatures(self, data):
        """Check for known packer signatures"""
        packer_signatures = [
            b'UPX!',  # UPX packer
            b'PK\x03\x04',  # ZIP/JAR
            b'\x4d\x5a\x90\x00',  # PE executable
            b'FSG!',  # FSG packer
            b'Rar!',  # RAR archive
        ]
        
        for signature in packer_signatures:
            if signature in data[:1024]:  # Check first 1KB
                return True
        return False
    
    def get_file_hash(self, file_path):
        """Calculate MD5, SHA1, and SHA256 hashes"""
        try:
            with open(file_path, 'rb') as f:
                data = f.read()
            
            return {
                'md5': hashlib.md5(data).hexdigest(),
                'sha1': hashlib.sha1(data).hexdigest(),
                'sha256': hashlib.sha256(data).hexdigest()
            }
        except Exception as e:
            return {'error': f'Hash calculation failed: {str(e)}'}
    
    def calculate_file_hashes(self, file_path):
        """Alias for get_file_hash for consistency"""
        return self.get_file_hash(file_path)
    
    def extract_suspicious_strings(self, file_path, min_length=4):
        """Extract and identify suspicious strings from file"""
        return self.extract_strings(file_path, min_length)
    
    def check_virustotal(self, file_hash):
        """Check file hash against VirusTotal"""
        if not self.virustotal_api_key:
            return {'error': 'VirusTotal API key not configured'}
        
        try:
            url = f"https://www.virustotal.com/vtapi/v2/file/report"
            params = {
                'apikey': self.virustotal_api_key,
                'resource': file_hash,
                'allinfo': 1
            }
            
            response = requests.get(url, params=params, timeout=10)
            
            if response.status_code == 200:
                result = response.json()
                if result['response_code'] == 1:
                    return {
                        'found': True,
                        'positives': result.get('positives', 0),
                        'total': result.get('total', 0),
                        'scan_date': result.get('scan_date', ''),
                        'permalink': result.get('permalink', ''),
                        'detection_names': [name for name in result.get('scans', {}).keys() if result['scans'][name]['detected']],
                        'source': 'VirusTotal'
                    }
                else:
                    return {'found': False, 'source': 'VirusTotal'}
            else:
                return {'error': f'VirusTotal API error: {response.status_code}'}
                
        except Exception as e:
            return {'error': f'VirusTotal check failed: {str(e)}'}
    
    def check_malware_bazaar(self, file_hash):
        """Check file hash against MalwareBazaar"""
        try:
            url = f"{self.malware_bazaar_api}"
            data = {
                'query': 'get_info',
                'hash': file_hash
            }
            
            response = requests.post(url, data=data, timeout=10)
            
            if response.status_code == 200:
                result = response.json()
                if result.get('query_status') == 'ok':
                    data = result.get('data', [])
                    if data:
                        sample = data[0]
                        return {
                            'found': True,
                            'malware_family': sample.get('signature', 'Unknown'),
                            'file_type': sample.get('file_type', 'Unknown'),
                            'first_seen': sample.get('first_seen', ''),
                            'tags': sample.get('tags', []),
                            'source': 'MalwareBazaar'
                        }
                else:
                    return {'found': False, 'source': 'MalwareBazaar'}
            else:
                return {'error': f'MalwareBazaar API error: {response.status_code}'}
                
        except Exception as e:
            return {'error': f'MalwareBazaar check failed: {str(e)}'}
    
    def extract_strings(self, file_path, min_length=4):
        """Extract readable strings from file"""
        try:
            with open(file_path, 'rb') as f:
                data = f.read()
            
            # Extract ASCII strings
            ascii_strings = re.findall(rb'[\\x20-\\x7e]{' + str(min_length).encode() + b',}', data)
            
            # Extract Unicode strings (basic)
            unicode_strings = []
            for match in re.finditer(rb'(?:[\\x20-\\x7e]\\x00){' + str(min_length).encode() + b',}', data):
                try:
                    unicode_strings.append(match.group().decode('utf-16le').rstrip('\\x00'))
                except:
                    pass
            
            all_strings = [s.decode('ascii', errors='ignore') for s in ascii_strings] + unicode_strings
            
            # Filter for suspicious strings
            suspicious_patterns = [
                r'\\\\\\\\[\\w\\.-]+\\\\',  # Network paths
                r'https?://[\\w\\.-]+',     # URLs
                r'[\\w\\.-]+@[\\w\\.-]+',   # Email addresses
                r'cmd\\.exe|powershell',    # System commands
                r'HKEY_|Registry',          # Registry keys
                r'CreateProcess|WriteFile', # API calls
                r'password|admin|root',     # Credentials
            ]
            
            suspicious_strings = []
            for string in all_strings:
                for pattern in suspicious_patterns:
                    if re.search(pattern, string, re.IGNORECASE):
                        suspicious_strings.append(string)
                        break
            
            return {
                'total_strings': len(all_strings),
                'suspicious_strings': suspicious_strings[:50],  # Limit output
                'sample_strings': all_strings[:20]  # First 20 strings
            }
            
        except Exception as e:
            return {'error': f'String extraction failed: {str(e)}'}
    
    def analyze_pe_header(self, file_path):
        """Basic PE header analysis"""
        try:
            with open(file_path, 'rb') as f:
                # Check DOS header
                dos_header = f.read(64)
                if len(dos_header) < 64 or dos_header[:2] != b'MZ':
                    return {'error': 'Not a valid PE file'}
                
                # Get PE header offset
                pe_offset = struct.unpack('<I', dos_header[60:64])[0]
                f.seek(pe_offset)
                
                # Check PE signature
                pe_signature = f.read(4)
                if pe_signature != b'PE\\x00\\x00':
                    return {'error': 'Invalid PE signature'}
                
                # Read COFF header
                coff_header = f.read(20)
                machine, num_sections, timestamp = struct.unpack('<HHI', coff_header[:8])
                
                # Read optional header
                opt_header_size = struct.unpack('<H', coff_header[16:18])[0]
                opt_header = f.read(opt_header_size)
                
                if len(opt_header) >= 28:
                    entry_point = struct.unpack('<I', opt_header[16:20])[0]
                    image_base = struct.unpack('<I', opt_header[28:32])[0] if len(opt_header) >= 32 else 0
                else:
                    entry_point = 0
                    image_base = 0
                
                return {
                    'machine_type': hex(machine),
                    'num_sections': num_sections,
                    'compilation_timestamp': datetime.fromtimestamp(timestamp).isoformat() if timestamp > 0 else 'Invalid',
                    'entry_point': hex(entry_point),
                    'image_base': hex(image_base),
                    'file_type': 'PE Executable'
                }
                
        except Exception as e:
            return {'error': f'PE analysis failed: {str(e)}'}
    
    def quick_static_scan(self, file_path):
        """Perform comprehensive static analysis"""
        results = {
            'file_path': file_path,
            'timestamp': datetime.now().isoformat(),
            'analysis_type': 'static'
        }
        
        # File basic info
        try:
            stat = os.stat(file_path)
            results['file_info'] = {
                'size': stat.st_size,
                'created': datetime.fromtimestamp(stat.st_ctime).isoformat(),
                'modified': datetime.fromtimestamp(stat.st_mtime).isoformat(),
                'extension': os.path.splitext(file_path)[1].lower()
            }
        except Exception as e:
            results['file_info'] = {'error': str(e)}
        
        # Entropy analysis
        results['entropy'] = self.analyze_file_entropy(file_path)
        
        # Hash calculation
        hashes = self.get_file_hash(file_path)
        results['hashes'] = hashes
        
        # Threat intelligence lookup (if hashes available)
        if 'sha256' in hashes:
            results['virustotal'] = self.check_virustotal(hashes['sha256'])
            time.sleep(1)  # Rate limiting
            results['malware_bazaar'] = self.check_malware_bazaar(hashes['sha256'])
        
        # String extraction
        results['strings'] = self.extract_strings(file_path)
        
        # PE header analysis (if applicable)
        if results['file_info'].get('extension') in ['.exe', '.dll', '.scr']:
            results['pe_header'] = self.analyze_pe_header(file_path)
        
        # Overall risk assessment
        risk_score = self._calculate_risk_score(results)
        results['risk_assessment'] = risk_score
        
        return results
    
    def scan_directory(self, directory_path, recursive=False):
        """Scan multiple files in a directory"""
        results = []
        
        try:
            if recursive:
                for root, dirs, files in os.walk(directory_path):
                    for file in files:
                        file_path = os.path.join(root, file)
                        result = self.quick_static_scan(file_path)
                        results.append(result)
            else:
                for item in os.listdir(directory_path):
                    item_path = os.path.join(directory_path, item)
                    if os.path.isfile(item_path):
                        result = self.quick_static_scan(item_path)
                        results.append(result)
        
        except Exception as e:
            return {'error': f'Directory scan failed: {str(e)}'}
        
        # Summary statistics
        summary = self._generate_scan_summary(results)
        
        return {
            'directory': directory_path,
            'scan_timestamp': datetime.now().isoformat(),
            'total_files': len(results),
            'results': results,
            'summary': summary
        }
    
    def _calculate_risk_score(self, analysis_results):
        """Calculate overall risk score based on analysis results"""
        score = 0
        risk_factors = []
        
        # Entropy-based scoring
        entropy = analysis_results.get('entropy', {})
        if entropy.get('suspicion_level') == 'High':
            score += 40
            risk_factors.append('High entropy detected')
        elif entropy.get('suspicion_level') == 'Medium':
            score += 20
            risk_factors.append('Medium entropy detected')
        
        # Threat intelligence scoring
        vt = analysis_results.get('virustotal', {})
        if vt.get('found'):
            positives = vt.get('positives', 0)
            total = vt.get('total', 1)
            if positives > 0:
                score += min(50, positives * 5)
                risk_factors.append(f'VirusTotal: {positives}/{total} detections')
        
        mb = analysis_results.get('malware_bazaar', {})
        if mb.get('found'):
            score += 50
            risk_factors.append(f'Known malware: {mb.get("malware_family", "Unknown")}')
        
        # String-based scoring
        strings = analysis_results.get('strings', {})
        if strings.get('suspicious_strings'):
            score += min(30, len(strings['suspicious_strings']) * 2)
            risk_factors.append(f'Suspicious strings found: {len(strings["suspicious_strings"])}')
        
        # File type scoring
        file_info = analysis_results.get('file_info', {})
        suspicious_extensions = ['.exe', '.scr', '.bat', '.cmd', '.pif', '.com']
        if file_info.get('extension') in suspicious_extensions:
            score += 10
            risk_factors.append('Potentially executable file type')
        
        # Determine risk level
        if score >= 70:
            risk_level = 'High'
        elif score >= 40:
            risk_level = 'Medium'
        elif score >= 20:
            risk_level = 'Low'
        else:
            risk_level = 'Very Low'
        
        return {
            'risk_score': min(100, score),
            'risk_level': risk_level,
            'risk_factors': risk_factors
        }
    
    def _generate_scan_summary(self, results):
        """Generate summary statistics for directory scan"""
        if not results:
            return {}
        
        risk_levels = {'High': 0, 'Medium': 0, 'Low': 0, 'Very Low': 0}
        total_detections = 0
        file_types = {}
        
        for result in results:
            # Risk level counts
            risk_level = result.get('risk_assessment', {}).get('risk_level', 'Very Low')
            risk_levels[risk_level] += 1
            
            # Detection counts
            vt = result.get('virustotal', {})
            if vt.get('found') and vt.get('positives', 0) > 0:
                total_detections += 1
            
            mb = result.get('malware_bazaar', {})
            if mb.get('found'):
                total_detections += 1
            
            # File type counts
            ext = result.get('file_info', {}).get('extension', 'unknown')
            file_types[ext] = file_types.get(ext, 0) + 1
        
        return {
            'risk_distribution': risk_levels,
            'total_detections': total_detections,
            'file_types': file_types,
            'detection_rate': f"{(total_detections / len(results) * 100):.1f}%" if results else "0%"
        }