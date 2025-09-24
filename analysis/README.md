# SentinelCore - Advanced Malware Analysis System

A comprehensive malware analysis and detection system that provides deep behavioral analysis, network monitoring, process tracing, and real-time detection capabilities through a unified web dashboard.

## 🚀 Features

### Malware Analysis
- **Process Monitoring**: Track process creation, termination, and parent-child relationships
- **Network Analysis**: Monitor network connections, DNS queries, and data flows
- **System Call Tracing**: eBPF-based comprehensive syscall monitoring (50+ syscalls)
- **Stack Trace Analysis**: GDB integration for crash analysis and debugging
- **File System Monitoring**: Track file operations, modifications, and access patterns
- **Memory Analysis**: Monitor memory allocations and suspicious patterns

### Detection Engines
- **ClamAV Integration**: Real-time virus scanning
- **VirusTotal API**: Cloud-based threat intelligence
- **Entropy Analysis**: Statistical analysis for packed/encrypted malware
- **AI-Powered Analysis**: Google Gemini integration for log analysis
- **Behavioral Detection**: Pattern recognition for malicious activities

### Web Dashboard
- **Real-time Monitoring**: Live updates of analysis results
- **Interactive Visualization**: Process trees, network flows, timeline views
- **Detection Interface**: File/directory scanning, log analysis
- **System Status**: Real-time system health and detection engine status
- **Export Capabilities**: JSON export of analysis results

## 📋 Requirements

### System Requirements
- Linux (Ubuntu 18.04+ recommended)
- Python 3.7+
- Root privileges (for eBPF and system monitoring)

### Python Dependencies
```bash
# Core dependencies
flask
psutil
requests
python-magic

# eBPF monitoring (optional but recommended)
bcc-tools
python3-bpf

# Detection engines
clamav
clamav-daemon
```

### Optional Dependencies
```bash
# For enhanced debugging
gdb
strace
tcpdump

# For system monitoring
htop
iotop
nethogs
```

## 🛠️ Installation

### 1. Clone Repository
```bash
git clone <repository-url>
cd sentinalcore/analysis
```

### 2. Install System Dependencies
```bash
# Ubuntu/Debian
sudo apt update
sudo apt install python3-pip python3-venv bcc-tools linux-headers-$(uname -r)
sudo apt install clamav clamav-daemon gdb strace tcpdump

# Start ClamAV daemon
sudo systemctl start clamav-daemon
sudo systemctl enable clamav-daemon

# Update virus definitions
sudo freshclam
```

### 3. Setup Python Environment
```bash
# Create virtual environment
python3 -m venv venv
source venv/bin/activate

# Install Python packages
pip install flask psutil requests python-magic
pip install bcc  # May require compilation
```

### 4. Configure API Keys (Optional)
```bash
# For VirusTotal integration
export VIRUSTOTAL_API_KEY="your_virustotal_api_key"

# For AI-powered log analysis
export GEMINI_API_KEY="your_google_gemini_api_key"
```

## 🚀 Usage

### Quick Start - Complete Analysis
```bash
# Analyze malware sample with full tracing
sudo bash analyze_malware.sh /path/to/malware/sample

# Start web dashboard
python3 web_dashboard.py
# Access at: http://localhost:5000
```

### Individual Components

#### 1. Malware Tracer (Main Analysis Engine)
```python
from malware_tracer import MalwareTracer

tracer = MalwareTracer()
results = tracer.analyze_malware("/path/to/malware")
```

#### 2. eBPF System Call Monitor
```python
from enhanced_ebpf_tracer import EnhancedEBPFTracer

tracer = EnhancedEBPFTracer()
tracer.start_monitoring()
tracer.execute_target("/path/to/target")
events = tracer.get_events()
```

#### 3. Process & Network Analysis
```python
from process_network_analyzer import ProcessTreeAnalyzer, NetworkFlowAnalyzer

# Process analysis
process_analyzer = ProcessTreeAnalyzer()
process_tree = process_analyzer.analyze_process_tree(target_pid)

# Network analysis
network_analyzer = NetworkFlowAnalyzer()
flows = network_analyzer.analyze_network_flows(target_pid)
```

#### 4. Stack Trace Analysis
```python
from stack_trace_analyzer import StackTraceAnalyzer

analyzer = StackTraceAnalyzer()
traces = analyzer.analyze_process(target_pid)
```

#### 5. Detection Engines
```python
# File scanning
detector.scan_file("/path/to/file")

# Directory scanning
detector.scan_directory("/path/to/directory")

# Log analysis
detector.analyze_logs(time_window=3600)

# Entropy analysis
entropy_analyzer = EntropyAnalyzer()
results = entropy_analyzer.analyze_file("/path/to/file")
```

## 🌐 Web Dashboard

### Access
- **URL**: http://localhost:5000
- **Tabs**: Analysis Results, Detection & Scanning, System Logs

### Analysis Tab
- Real-time process monitoring
- Network flow visualization
- System call timeline
- Stack trace display
- File system operations

### Detection Tab
- File/directory scanning
- Real-time threat detection
- Entropy analysis
- Log analysis with AI insights

### Logs Tab
- System event logs
- Detection alerts
- Analysis summaries
- Export capabilities

## 📁 Project Structure

```
analysis/
├── malware_tracer.py          # Main analysis orchestrator
├── enhanced_ebpf_tracer.py    # eBPF syscall monitoring
├── process_network_analyzer.py # Process/network analysis
├── stack_trace_analyzer.py    # Stack trace & debugging
├── web_dashboard.py           # Web interface
├── analyze_malware.sh         # Automation script
└── README.md                  # This file

../detection/                  # Detection modules
├── main.py                   # Detection orchestrator
├── clamav_scan.py           # ClamAV integration
├── virustotalUpload.py      # VirusTotal API
├── entropy.py               # Entropy analysis
└── LLMlogs.py              # AI log analysis

../testing/                   # Test files and samples
```

## 🔧 Configuration

### eBPF Settings
- Requires Linux kernel 4.4+
- BCC tools properly installed
- Root privileges for system monitoring

### Detection Engine Config
- ClamAV daemon running
- Valid API keys for external services
- Proper file permissions

### Web Dashboard Settings
- Default port: 5000
- Auto-refresh intervals configurable
- Real-time updates enabled

## 🔍 Analysis Outputs

### JSON Results Structure
```json
{
  "analysis_id": "unique_identifier",
  "target_info": {
    "path": "/path/to/malware",
    "hash": "sha256_hash",
    "file_type": "ELF executable"
  },
  "process_analysis": {
    "process_tree": [...],
    "suspicious_processes": [...]
  },
  "network_analysis": {
    "connections": [...],
    "dns_queries": [...],
    "suspicious_flows": [...]
  },
  "syscall_analysis": {
    "events": [...],
    "suspicious_calls": [...]
  },
  "detection_results": {
    "is_malicious": true,
    "detection_methods": ["clamav", "entropy"],
    "threat_score": 0.85
  }
}
```

## 🚨 Security Considerations

1. **Isolation**: Run in isolated VM/container environments
2. **Privileges**: Requires root for system monitoring
3. **Network**: Monitor network access during analysis
4. **Storage**: Secure storage for analysis results
5. **API Keys**: Protect external service credentials

## 🐛 Troubleshooting

### Common Issues

#### eBPF Not Working
```bash
# Check kernel version
uname -r

# Install kernel headers
sudo apt install linux-headers-$(uname -r)

# Verify BCC installation
python3 -c "from bcc import BPF; print('BCC working')"
```

#### ClamAV Issues
```bash
# Check daemon status
sudo systemctl status clamav-daemon

# Update signatures
sudo freshclam

# Check permissions
sudo chown clamav:clamav /var/lib/clamav/*
```

#### Permission Errors
```bash
# Run with proper privileges
sudo python3 web_dashboard.py

# Check file permissions
ls -la analysis_results/
```

#### Web Dashboard Not Loading
```bash
# Check port availability
netstat -tlnp | grep 5000

# Check firewall
sudo ufw status

# Test local access
curl http://localhost:5000
```

### Debug Mode
```bash
# Enable detailed logging
export DEBUG=1
python3 malware_tracer.py

# Monitor system resources
htop
iotop
nethogs
```

## 🔄 Updates & Maintenance

### Regular Tasks
1. Update ClamAV signatures: `sudo freshclam`
2. Update system packages: `sudo apt update && sudo apt upgrade`
3. Monitor disk space for analysis results
4. Review and rotate log files

### Performance Monitoring
- Monitor CPU/memory usage during analysis
- Check eBPF program efficiency
- Optimize web dashboard refresh rates
- Clean old analysis results

## 📞 Support & Contributing

### Getting Help
1. Check troubleshooting section
2. Review log files in analysis results
3. Test with known samples
4. Check system requirements

### Contributing
1. Follow Python PEP 8 style guidelines
2. Add comprehensive error handling
3. Include unit tests for new features
4. Document API changes
5. Test with multiple malware families

## 📄 License

See LICENSE file for details.

## 🙏 Acknowledgments

- BCC project for eBPF tracing capabilities
- ClamAV team for antivirus engine
- VirusTotal for threat intelligence API
- Google Gemini for AI analysis capabilities
- Flask framework for web dashboard
- Open source security community

---

**⚠️ Warning**: This tool is designed for malware analysis in controlled environments. Always use proper isolation and security measures when analyzing potentially malicious files.