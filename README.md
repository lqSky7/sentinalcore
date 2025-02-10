<<<<<<< HEAD
# Sentinal - Linux Malware Analysis Tool (x86 Version)

A comprehensive malware analysis framework for Linux x86/x86_64 systems that provides:

## Features
- **System Call Monitoring**: Track all system calls using strace integration
- **Process Tree Analysis**: Monitor parent-child process relationships
- **Network Activity Monitoring**: Capture and analyze network connections
- **Memory Forensics**: Memory usage analysis and pattern detection
- **Web Interface**: Simple mono-spaced text UI on localhost:3000
- **Real-time Visualization**: Process trees and analysis graphs
- **🔒 Isolation System**: Secure malware execution using namespaces, chroot, and resource limits

## Components
- `backend/`: Python Flask API server with isolation integration
- `monitor/`: C-based process and system call monitor
- `frontend/`: Simple HTML/CSS/JS web interface
- `samples/`: Test malware samples for analysis
- `config/`: Configuration files and security settings
- `isolation/`: **NEW** - Comprehensive sandbox isolation system

## Usage
1. Start the analysis server: `python backend/app.py`
2. Open web interface: http://localhost:3000
3. Enter file path and execute analysis
4. View results with graphs and detailed reports

## Dependencies
- Python 3.8+
- Flask, psutil, matplotlib, networkx
- GCC for compiling C monitoring modules
- strace, netstat system tools

## Security Note
⚠️ This tool executes potentially malicious files. Always run in isolated environments or VMs.
=======
# SentinelCore: Malware Detection Engine TODO List  

## Phase 1: Static Analysis Core (Weeks 1-4)  
- [ ] **Environment Setup**  
  - [ ] Create Python virtual environment with `poetry`  
  - [ ] Install core dependencies: `pytsk3`, `python-magic`, `numpy`  

- [ ] **Entropy Module**  
  - [ ] Implement Shannon entropy calculator (Python)  
  - [ ] Add block-based analysis (256-byte chunks)  
  - [ ] Benchmark against 1000+ file corpus (benign/malware)  

- [ ] **File Validation**  
  - [ ] Integrate libmagic for magic number detection  
  - [ ] Create allowlist/blocklist for file types (e.g., `.exe`, `.docm`)  

- [ ] **Testing Foundation**  
  - [ ] Collect 50+ test samples (25% malware from VirusShare)  
  - [ ] Implement pytest framework with coverage ≥80%  

---

## Phase 2: CLI & Threshold Logic (Weeks 3-4)  
- [ ] **Command Line Interface**  
  - [ ] Add `--scan-file` argument with file path validation  
  - [ ] Implement `--threshold` parameter (default: 6.8)  
  - [ ] Create JSON output option  

- [ ] **Threshold Calibration**  
  - [ ] Statistical analysis of 1000+ files to set baseline  
  - [ ] Implement context-aware thresholds (e.g., `/tmp` vs `/usr/bin`)  

---

## Phase 3: Dynamic Analysis (Weeks 5-6)  
- [ ] **System Call Monitoring**  
  - [ ] Implement `strace` wrapper for Linux process tracing  
  - [ ] Create suspicious pattern detector (e.g., `execve`, `ptrace`)  

- [ ] **Sandboxing**  
  - [ ] Integrate Firejail with custom profile  
  - [ ] Redirect filesystem writes to RAM disk (`tmpfs`)  

---

## Phase 4: AI Integration (Weeks 7-8)  
- [ ] **API Connectors**  
  - [ ] VirusTotal v3 API integration (file hash lookup)  
  - [ ] Hybrid-Analysis quick-scan implementation  

- [ ] **Local ML Model**  
  - [ ] Train RandomForest classifier on 10k syscall logs  
  - [ ] Implement risk scoring formula:  
    ```
    risk_score = (entropy * 0.4) + (vt_malicious * 30) + (ml_probability * 30)
    ```

---

## Phase 5: Quarantine & Reporting (Weeks 9-10)  
- [ ] **Containment System**  
  - [ ] Develop chroot-based quarantine directory  
  - [ ] Implement file hashing (SHA256) for tracking  

- [ ] **Report Generation**  
  - [ ] Create PDF report template with entropy graphs  
  - [ ] Add CSV export for batch processing  

---

## Phase 6: Optimization & Testing (Weeks 11-12)  
- [ ] **Performance Tuning**  
  - [ ] Port entropy calculation to Cython  
  - [ ] Implement async I/O for file scanning  

- [ ] **Packaging**  
  - [ ] Build .deb package for Debian/Ubuntu  
  - [ ] Create systemd service file for daemon mode  

---

# Critical Dependencies  
- [ ] Obtain VirusTotal API key (free tier)  
- [ ] Set up isolated KVM testing environment  
- [ ] Curate malware sample dataset (500+ files)  

# Risks  
| Risk | Owner | Mitigation |  
|------|-------|------------|  
| API rate limiting | Dev 2 | Implement 24-hour caching |  
| False positives | QA | Context-aware thresholds |  
| Sandbox escape | Sec | AppArmor hardening |  
>>>>>>> ee64751 (Create README.md)
