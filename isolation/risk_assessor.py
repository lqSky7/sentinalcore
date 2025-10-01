#!/usr/bin/env python3
"""
Risk Assessment System for SentinalCore

Automatically determines isolation requirements based on file characteristics,
metadata, and threat intelligence indicators.
"""

import os
import hashlib
import subprocess
import json
import logging
from pathlib import Path
from typing import Dict, List, Tuple, Any, Optional
from dataclasses import dataclass
from enum import Enum

# Optional dependency - graceful fallback if not available
try:
    import magic
    MAGIC_AVAILABLE = True
except ImportError:
    MAGIC_AVAILABLE = False
    magic = None

class RiskLevel(Enum):
    """Risk levels for automatic isolation determination"""
    MINIMAL = "minimal"      # 0-25: Basic monitoring only
    LOW = "low"             # 26-50: Light isolation
    MEDIUM = "medium"       # 51-75: Standard isolation  
    HIGH = "high"           # 76-90: Enhanced isolation
    CRITICAL = "critical"   # 91-100: Maximum isolation

@dataclass
class RiskFactor:
    """Individual risk factor assessment"""
    name: str
    score: int              # 0-100
    weight: float           # 0.0-1.0 multiplier
    description: str
    evidence: List[str]

@dataclass
class RiskAssessment:
    """Complete risk assessment result"""
    overall_score: int      # 0-100
    risk_level: RiskLevel
    factors: List[RiskFactor]
    recommended_isolation: str
    auto_isolation: bool
    manual_override_allowed: bool
    reasoning: str

class ThreatIndicators:
    """Known threat indicators and patterns"""
    
    # Suspicious file extensions
    SUSPICIOUS_EXTENSIONS = {
        '.exe', '.bat', '.cmd', '.com', '.pif', '.scr', '.vbs', 
        '.js', '.jar', '.ps1', '.sh', '.bin', '.run', '.app'
    }
    
    # High-risk extensions (auto-isolate)
    HIGH_RISK_EXTENSIONS = {
        '.exe', '.dll', '.sys', '.bin', '.scr', '.bat', '.cmd'
    }
    
    # Suspicious file names/patterns
    SUSPICIOUS_NAMES = [
        'setup', 'install', 'update', 'patch', 'crack', 'keygen',
        'ransomware', 'trojan', 'backdoor', 'malware', 'virus',
        'cryptor', 'miner', 'stealer', 'loader', 'dropper'
    ]
    
    # Network-related indicators
    NETWORK_INDICATORS = [
        'socket', 'connect', 'bind', 'listen', 'send', 'recv',
        'urllib', 'requests', 'http', 'ftp', 'smtp', 'tcp', 'udp'
    ]
    
    # Persistence indicators
    PERSISTENCE_INDICATORS = [
        'registry', 'startup', 'service', 'task', 'cron', 'autorun',
        'systemd', 'init', '/etc/', '.bashrc', '.profile'
    ]
    
    # Evasion indicators
    EVASION_INDICATORS = [
        'obfuscat', 'encrypt', 'encode', 'pack', 'compress',
        'anti', 'debug', 'vm', 'sandbox', 'analysis'
    ]

class RiskAssessor:
    """Main risk assessment engine"""
    
    def __init__(self):
        self.logger = logging.getLogger(__name__)
        self.indicators = ThreatIndicators()
        
        # Initialize file type detection
        if MAGIC_AVAILABLE:
            try:
                self.magic_mime = magic.Magic(mime=True)
                self.magic_desc = magic.Magic()
            except Exception as e:
                self.logger.warning(f"Could not initialize python-magic: {e}")
                self.magic_mime = None
                self.magic_desc = None
        else:
            self.logger.info("python-magic not available, using basic file type detection")
            self.magic_mime = None
            self.magic_desc = None
    
    def assess_file_risk(self, file_path: str, 
                        user_override: Optional[str] = None) -> RiskAssessment:
        """
        Perform comprehensive risk assessment on a file
        
        Args:
            file_path: Path to file to assess
            user_override: Optional manual isolation level override
            
        Returns:
            Complete risk assessment with recommended isolation
        """
        if not os.path.exists(file_path):
            raise FileNotFoundError(f"File not found: {file_path}")
        
        factors = []
        
        # 1. File extension analysis
        factors.append(self._assess_file_extension(file_path))
        
        # 2. File size analysis
        factors.append(self._assess_file_size(file_path))
        
        # 3. File type detection
        factors.append(self._assess_file_type(file_path))
        
        # 4. Entropy analysis (packed/encrypted files)
        factors.append(self._assess_entropy(file_path))
        
        # 5. String analysis for suspicious content
        factors.append(self._assess_string_content(file_path))
        
        # 6. Source/location analysis
        factors.append(self._assess_file_source(file_path))
        
        # 7. Permissions analysis
        factors.append(self._assess_permissions(file_path))
        
        # Calculate weighted overall score
        total_weighted_score = sum(
            factor.score * factor.weight for factor in factors
        )
        overall_score = min(100, int(total_weighted_score))
        
        # Determine risk level and isolation
        risk_level = self._score_to_risk_level(overall_score)
        recommended_isolation = self._risk_to_isolation(risk_level)
        
        # Check for user override
        auto_isolation = True
        manual_override_allowed = True
        
        if user_override:
            if user_override in ['none', 'basic', 'medium', 'high', 'maximum']:
                recommended_isolation = user_override
                auto_isolation = False
            else:
                self.logger.warning(f"Invalid isolation override: {user_override}")
        
        # Generate reasoning
        reasoning = self._generate_reasoning(factors, overall_score, risk_level)
        
        return RiskAssessment(
            overall_score=overall_score,
            risk_level=risk_level,
            factors=factors,
            recommended_isolation=recommended_isolation,
            auto_isolation=auto_isolation,
            manual_override_allowed=manual_override_allowed,
            reasoning=reasoning
        )
    
    def _assess_file_extension(self, file_path: str) -> RiskFactor:
        """Assess risk based on file extension"""
        ext = Path(file_path).suffix.lower()
        
        if ext in self.indicators.HIGH_RISK_EXTENSIONS:
            score = 80
            evidence = [f"High-risk executable extension: {ext}"]
        elif ext in self.indicators.SUSPICIOUS_EXTENSIONS:
            score = 60
            evidence = [f"Suspicious extension: {ext}"]
        elif ext in ['.txt', '.log', '.md', '.json', '.xml']:
            score = 10
            evidence = [f"Low-risk document extension: {ext}"]
        else:
            score = 30
            evidence = [f"Unknown/neutral extension: {ext}"]
        
        return RiskFactor(
            name="File Extension",
            score=score,
            weight=0.2,
            description="Risk assessment based on file extension",
            evidence=evidence
        )
    
    def _assess_file_size(self, file_path: str) -> RiskFactor:
        """Assess risk based on file size"""
        size = os.path.getsize(file_path)
        
        if size == 0:
            score = 15
            evidence = ["Empty file"]
        elif size < 1024:  # < 1KB
            score = 20
            evidence = [f"Very small file: {size} bytes"]
        elif size < 10 * 1024:  # < 10KB
            score = 25
            evidence = [f"Small file: {size} bytes"]
        elif size < 1024 * 1024:  # < 1MB
            score = 35
            evidence = [f"Medium file: {size // 1024}KB"]
        elif size < 10 * 1024 * 1024:  # < 10MB
            score = 45
            evidence = [f"Large file: {size // (1024*1024)}MB"]
        else:
            score = 60
            evidence = [f"Very large file: {size // (1024*1024)}MB - potential dropper"]
        
        return RiskFactor(
            name="File Size",
            score=score,
            weight=0.1,
            description="Risk assessment based on file size patterns",
            evidence=evidence
        )
    
    def _assess_file_type(self, file_path: str) -> RiskFactor:
        """Assess risk based on detected file type"""
        evidence = []
        
        # Try to detect MIME type
        if self.magic_mime:
            try:
                mime_type = self.magic_mime.from_file(file_path)
                evidence.append(f"MIME type: {mime_type}")
                
                if 'executable' in mime_type or 'application/x-' in mime_type:
                    score = 70
                elif 'application/' in mime_type:
                    score = 50
                elif 'text/' in mime_type:
                    score = 20
                else:
                    score = 40
            except Exception as e:
                score = 50
                evidence.append(f"Could not detect MIME type: {e}")
        else:
            score = 50
            evidence.append("File type detection unavailable")
        
        # Check for ELF/PE headers
        try:
            with open(file_path, 'rb') as f:
                header = f.read(4)
                if header.startswith(b'\x7fELF'):
                    score = max(score, 75)
                    evidence.append("ELF executable detected")
                elif header.startswith(b'MZ'):
                    score = max(score, 80)
                    evidence.append("PE executable detected")
                elif header.startswith(b'PK'):
                    score = max(score, 45)
                    evidence.append("ZIP/archive format detected")
        except Exception:
            pass
        
        return RiskFactor(
            name="File Type",
            score=score,
            weight=0.25,
            description="Risk assessment based on detected file type",
            evidence=evidence
        )
    
    def _assess_entropy(self, file_path: str) -> RiskFactor:
        """Assess risk based on file entropy (indicates packing/encryption)"""
        try:
            with open(file_path, 'rb') as f:
                data = f.read(8192)  # Sample first 8KB
                
            if len(data) == 0:
                return RiskFactor("Entropy Analysis", 15, 0.15, 
                                "Empty file", ["File is empty"])
            
            # Calculate Shannon entropy
            entropy = 0.0
            for i in range(256):
                count = data.count(bytes([i]))
                if count > 0:
                    freq = count / len(data)
                    entropy -= freq * (freq.bit_length() - 1)
            
            # Normalize entropy (0-8 bits -> 0-100 score)
            entropy_score = min(100, int(entropy * 12.5))
            
            evidence = [f"Shannon entropy: {entropy:.2f} bits"]
            
            if entropy > 7.5:
                score = 85
                evidence.append("Very high entropy - likely packed/encrypted")
            elif entropy > 6.5:
                score = 65
                evidence.append("High entropy - possibly packed")
            elif entropy > 4.0:
                score = 35
                evidence.append("Normal entropy levels")
            else:
                score = 25
                evidence.append("Low entropy - mostly plaintext/structured")
            
        except Exception as e:
            score = 40
            evidence = [f"Entropy analysis failed: {e}"]
        
        return RiskFactor(
            name="Entropy Analysis",
            score=score,
            weight=0.15,
            description="File entropy analysis for packed/obfuscated content",
            evidence=evidence
        )
    
    def _assess_string_content(self, file_path: str) -> RiskFactor:
        """Assess risk based on strings found in the file"""
        evidence = []
        suspicious_score = 0
        
        try:
            # Extract printable strings
            result = subprocess.run(
                ['strings', '-n', '4', file_path],
                capture_output=True, text=True, timeout=10
            )
            
            if result.returncode == 0:
                strings = result.stdout.lower()
                
                # Check for suspicious patterns
                for pattern in self.indicators.SUSPICIOUS_NAMES:
                    if pattern in strings:
                        suspicious_score += 15
                        evidence.append(f"Suspicious string: '{pattern}'")
                
                # Check for network indicators
                network_count = sum(1 for indicator in self.indicators.NETWORK_INDICATORS 
                                  if indicator in strings)
                if network_count > 0:
                    suspicious_score += min(30, network_count * 5)
                    evidence.append(f"Network-related strings: {network_count}")
                
                # Check for persistence indicators
                persistence_count = sum(1 for indicator in self.indicators.PERSISTENCE_INDICATORS 
                                      if indicator in strings)
                if persistence_count > 0:
                    suspicious_score += min(25, persistence_count * 5)
                    evidence.append(f"Persistence-related strings: {persistence_count}")
                
                # Check for evasion indicators
                evasion_count = sum(1 for indicator in self.indicators.EVASION_INDICATORS 
                                  if indicator in strings)
                if evasion_count > 0:
                    suspicious_score += min(35, evasion_count * 7)
                    evidence.append(f"Evasion-related strings: {evasion_count}")
                
            else:
                suspicious_score = 30
                evidence.append("Could not extract strings")
                
        except subprocess.TimeoutExpired:
            suspicious_score = 25
            evidence.append("String extraction timed out")
        except Exception as e:
            suspicious_score = 35
            evidence.append(f"String analysis failed: {e}")
        
        score = min(100, suspicious_score + 15)  # Base score + suspicious findings
        
        if not evidence:
            evidence.append("No suspicious strings detected")
        
        return RiskFactor(
            name="String Analysis",
            score=score,
            weight=0.2,
            description="Analysis of embedded strings for threat indicators",
            evidence=evidence
        )
    
    def _assess_file_source(self, file_path: str) -> RiskFactor:
        """Assess risk based on file location and source"""
        path_obj = Path(file_path).resolve()
        evidence = []
        
        # Check file location
        path_str = str(path_obj).lower()
        
        if '/tmp/' in path_str or '/var/tmp/' in path_str:
            score = 60
            evidence.append("File in temporary directory")
        elif '/downloads/' in path_str:
            score = 50
            evidence.append("File in downloads directory")
        elif path_obj.name.startswith('.'):
            score = 40
            evidence.append("Hidden file")
        elif '/home/' in path_str and '/samples/' in path_str:
            score = 70
            evidence.append("File in malware samples directory")
        elif '/usr/bin/' in path_str or '/bin/' in path_str:
            score = 20
            evidence.append("File in system binary directory")
        else:
            score = 30
            evidence.append(f"File location: {path_obj.parent}")
        
        return RiskFactor(
            name="File Source",
            score=score,
            weight=0.1,
            description="Risk assessment based on file location and source",
            evidence=evidence
        )
    
    def _assess_permissions(self, file_path: str) -> RiskFactor:
        """Assess risk based on file permissions"""
        try:
            stat = os.stat(file_path)
            mode = stat.st_mode
            evidence = []
            
            score = 20  # Base score
            
            # Check if executable
            if os.access(file_path, os.X_OK):
                score += 30
                evidence.append("File is executable")
            
            # Check for world-writable
            if mode & 0o002:
                score += 25
                evidence.append("World-writable permissions")
            
            # Check for setuid/setgid
            if mode & 0o4000:
                score += 40
                evidence.append("Setuid bit set")
            if mode & 0o2000:
                score += 35
                evidence.append("Setgid bit set")
            
            # Check ownership
            if stat.st_uid == 0:
                score += 20
                evidence.append("Owned by root")
            
            if not evidence:
                evidence.append("Normal file permissions")
            
        except Exception as e:
            score = 30
            evidence = [f"Permission analysis failed: {e}"]
        
        return RiskFactor(
            name="File Permissions",
            score=score,
            weight=0.1,
            description="Risk assessment based on file permissions",
            evidence=evidence
        )
    
    def _score_to_risk_level(self, score: int) -> RiskLevel:
        """Convert numerical score to risk level"""
        if score >= 91:
            return RiskLevel.CRITICAL
        elif score >= 76:
            return RiskLevel.HIGH
        elif score >= 51:
            return RiskLevel.MEDIUM
        elif score >= 26:
            return RiskLevel.LOW
        else:
            return RiskLevel.MINIMAL
    
    def _risk_to_isolation(self, risk_level: RiskLevel) -> str:
        """Map risk level to isolation configuration"""
        mapping = {
            RiskLevel.MINIMAL: 'basic',
            RiskLevel.LOW: 'medium',     # Use namespace isolation for low risk
            RiskLevel.MEDIUM: 'medium',  # Keep medium risk at medium isolation
            RiskLevel.HIGH: 'high',
            RiskLevel.CRITICAL: 'maximum'
        }
        return mapping[risk_level]
    
    def _generate_reasoning(self, factors: List[RiskFactor], 
                          score: int, risk_level: RiskLevel) -> str:
        """Generate human-readable reasoning for the assessment"""
        reasoning = f"Overall risk score: {score}/100 ({risk_level.value.title()} Risk)\n\n"
        
        # Sort factors by weighted contribution
        sorted_factors = sorted(factors, 
                              key=lambda f: f.score * f.weight, reverse=True)
        
        reasoning += "Key risk factors:\n"
        for factor in sorted_factors[:3]:  # Top 3 factors
            contribution = int(factor.score * factor.weight)
            reasoning += f"• {factor.name}: {factor.score}/100 (weight: {factor.weight}) = {contribution} points\n"
            if factor.evidence:
                reasoning += f"  - {', '.join(factor.evidence[:2])}\n"
        
        reasoning += f"\nRecommended isolation: {self._risk_to_isolation(risk_level)}"
        
        return reasoning

def assess_file_risk(file_path: str, user_override: Optional[str] = None) -> RiskAssessment:
    """Convenience function for risk assessment"""
    assessor = RiskAssessor()
    return assessor.assess_file_risk(file_path, user_override)

if __name__ == "__main__":
    import sys
    
    if len(sys.argv) < 2:
        print("Usage: python risk_assessor.py <file_path> [isolation_override]")
        sys.exit(1)
    
    file_path = sys.argv[1]
    override = sys.argv[2] if len(sys.argv) > 2 else None
    
    try:
        assessment = assess_file_risk(file_path, override)
        
        print("=== SentinalCore Risk Assessment ===")
        print(f"File: {file_path}")
        print(f"Overall Risk Score: {assessment.overall_score}/100")
        print(f"Risk Level: {assessment.risk_level.value.title()}")
        print(f"Recommended Isolation: {assessment.recommended_isolation}")
        print(f"Auto-Isolation: {'Yes' if assessment.auto_isolation else 'No (Manual Override)'}")
        print("\nReasoning:")
        print(assessment.reasoning)
        
    except Exception as e:
        print(f"Risk assessment failed: {e}")
        sys.exit(1)