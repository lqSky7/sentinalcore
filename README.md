<<<<<<< HEAD
<<<<<<< HEAD
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
=======
What we're doing:
>>>>>>> 13cc650 (revise readme)
=======
# SentinalCore
>>>>>>> 690c70f (update readme)

![License](https://img.shields.io/badge/license-GPL--3.0-blue.svg)
![Python](https://img.shields.io/badge/python-3.10+-green.svg)
![Status](https://img.shields.io/badge/status-alpha-orange.svg)

**SentinalCore** is a comprehensive malware detection and isolation framework designed for Linux systems. It combines multiple detection methods with advanced isolation techniques to identify and contain potential threats.

## Features

### Malware Detection
SentinalCore uses a multi-layered approach to detect potential threats:

- **ClamAV Integration** - Signature-based detection using the established ClamAV antivirus engine
- **File Entropy Analysis** - Statistical analysis to identify suspicious encryption or packing
- **VirusTotal API** - Cloud-based malware intelligence platform integration
- **LLM-Powered Log Analysis** - Advanced system log analysis using large language models
- **File System Scanning** - Comprehensive scanning of the user's file system with configurable parameters

### Threat Isolation
When threats are detected, SentinalCore can isolate them using:

- **Passive Isolation** - Linux namespace separation (PID, mount, network, etc.)
- **Process Containment** - Restricting process capabilities and access
- **Network Restriction** - Preventing malicious processes from communicating with the network

## Technical Overview

### Core Components

#### Detection Engine
- **ClamAV Scanner**: Integrates with ClamAV for signature-based detection
- **Entropy Analyzer**: Performs statistical analysis to detect suspicious files
- **VirusTotal Client**: Interfaces with VirusTotal API for cloud-based detection
- **Log Analyzer**: Uses LLM to identify suspicious patterns in system logs

#### Isolation Framework
- **Namespace-based Isolation**: Uses Linux kernel namespaces to isolate processes
- **Resource Limiting**: Controls CPU, memory, and network usage for suspicious processes
- **Monitoring Interface**: Real-time monitoring of isolated processes

## Requirements

```
- Python 3.10+
- ClamAV (with freshclam)
- BCC (eBPF Compiler Collection)
- Linux kernel 4.15+ (for namespace functionality)
```

## Installation

### 1. Install dependencies

```bash
# Install system dependencies
sudo apt update
sudo apt install clamav clamav-daemon bpfcc-tools python3-dev python3-pip

# Start ClamAV services
sudo systemctl enable clamav-freshclam
sudo systemctl start clamav-freshclam
sudo systemctl enable clamav-daemon
sudo systemctl start clamav-daemon
```

### 2. Install SentinalCore

```bash
# Clone the repository
git clone https://github.com/username/sentinalcore.git
cd sentinalcore

# Install Python dependencies
pip install -e .
```

### 3. Configuration

```bash
# Set up API keys (optional but recommended)
export VIRUSTOTAL_API_KEY="your_virustotal_api_key"
export GEMINI_API_KEY="your_gemini_api_key"
```

## Usage

### Basic Scanning

```bash
# Scan a single file
python detection/main.py --scan-file /path/to/file

# Scan a directory
python detection/main.py --scan-dir /path/to/directory

# Scan home directory
# Scan a directory
python detection/main.py --scan-dir /path/to/directory

# Scan home directory
python detection/main.py --scan-home

# Full system scan with VirusTotal integration
python detection/main.py --full-scan --check-virustotal
```

### Log Analysis

```bash
# Analyze system logs for the past hour
python detection/main.py --analyze-logs --log-time 60

# Analyze logs with custom output file
python detection/main.py --analyze-logs --output-file results.json
```

### Advanced Usage

```bash
# Perform full system scan with all detection methods
python detection/main.py --full-scan --check-virustotal --analyze-logs --log-time 120 --verbose
```

## 🧪 Testing

The project includes a comprehensive test suite:

```bash
# Run all tests
pytest

# Run specific test module
pytest testing/test_clamav.py
```

Test data and logs are stored in the `testing/logs/` directory.

## 💻 Development

### Project Structure

```
sentinalcore/
├── detection/          # Detection modules
│   ├── clamav_scan.py  # ClamAV integration
│   ├── entropy.py      # File entropy analysis
│   ├── LLMlogs.py      # Log analysis with LLM
│   ├── main.py         # Main detection interface
│   └── virustotalUpload.py  # VirusTotal API client
├── gui/                # GUI interface (under development)
├── isolation/          # Process isolation modules
│   └── passive_isolation.py  # Namespace-based isolation
└── testing/            # Test modules and fixtures
    ├── test_*.py       # Test files
    └── logs/           # Sample logs for testing
```

### Contributing

Contributions are welcome! Please feel free to submit a Pull Request.

## 📜 License

This project is licensed under the GNU General Public License v3.0 - see the [LICENSE](LICENSE) file for details.

## ⚠️ Disclaimer

SentinalCore is designed for security research and legitimate system administration purposes only. Always obtain proper authorization before scanning systems or networks you don't own. The developers are not responsible for any misuse of this software.

## 📧 Contact

For questions, feedback, or contributions, please open an issue on the project repository.

---

<<<<<<< HEAD
### Note¹: ClamAV Capabilities

<<<<<<< HEAD
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
=======
- **User file uploads**: ClamAV can scan files uploaded by users to detect malicious content
- **System scanning**: While ClamAV doesn't natively scan system logs, it can scan the entire `/home/username/*` directory structure as requested
- **Real-time protection**: ClamAV offers real-time protection specifically for Linux systems through ClamOnAcc, which can block file access until scanning is complete
>>>>>>> 13cc650 (revise readme)
=======
_SentinalCore: Detect, Isolate, Protect._
>>>>>>> 690c70f (update readme)
