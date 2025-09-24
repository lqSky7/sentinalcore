# SENTINAL - Linux Malware Analysis Framework

## 📋 Project Overview
Sentinal is a comprehensive malware analysis framework specifically designed for Linux systems. It provides dynamic analysis capabilities including system call monitoring, process tree visualization, network activity tracking, and memory forensics through a clean, monospace web interface.

## 🏗️ Architecture

### Core Components

1. **Process Monitor (C)** - `monitor/process_monitor.c`
   - Uses ptrace() system calls for low-level process monitoring
   - Captures system calls, process spawning, and memory operations
   - Outputs structured data for analysis

2. **Backend API (Python)** - `backend/app.py`
   - Flask-based REST API server
   - Orchestrates analysis execution and data processing
   - Provides endpoints for file analysis and result retrieval

3. **Network Monitor (Python)** - `backend/network_monitor.py`
   - Tracks network connections and DNS queries
   - Monitors suspicious network behavior patterns
   - Integrates with psutil for comprehensive network analysis

4. **Visualization Engine (Python)** - `backend/visualizer.py`
   - Generates process trees and analysis graphs
   - Creates matplotlib-based visualizations
   - Provides base64-encoded images for web display

5. **Web Interface (HTML/JS)** - `frontend/index.html`
   - Clean, monospace terminal-style interface
   - Real-time analysis progress and results display
   - Interactive graphs and detailed reporting

## 🚀 Quick Start

### Prerequisites
- Linux operating system (Ubuntu/Debian/CentOS/RHEL)
- Python 3.8+ with pip
- GCC compiler
- Make build system
- strace utility

### Installation
```bash
# Clone or navigate to the Sentinal directory
cd /path/to/sentinal

# Run the setup script
./setup.sh

# Start the analysis server
./start_sentinal.sh
```

### Manual Installation
```bash
# Install Python dependencies
python3 -m venv venv
source venv/bin/activate
pip install -r requirements.txt

# Compile the C process monitor
cd monitor
make
make install
cd ..

# Compile sample malware for testing
cd samples
make
cd ..

# Start the server
cd backend
python3 app.py
```

## 🖥️ Usage

### Web Interface
1. Open http://localhost:3000 in your browser
2. Enter the full path to the file you want to analyze
3. Set analysis timeout (5-300 seconds)
4. Click "Analyze File" to start the analysis
5. View real-time results including:
   - System call analysis
   - Process tree visualization
   - Network activity monitoring
   - Suspicious pattern detection

### API Endpoints
- `POST /api/analyze` - Start file analysis
- `GET /api/results/<analysis_id>` - Get analysis results
- `GET /api/status` - Get server status

### Sample Analysis
Test the framework with provided sample files:
```bash
# Python malware sample
python3 samples/test_malware.py

# C malware sample  
./samples/test_malware

# Shell script malware sample
./samples/test_malware.sh
```

## 📊 Analysis Features

### System Call Monitoring
- **Comprehensive Coverage**: Monitors file, network, process, and memory operations
- **Suspicious Pattern Detection**: Identifies potential malicious behaviors
- **Real-time Capture**: Uses ptrace for low-latency syscall interception
- **Detailed Arguments**: Captures system call arguments and return values

### Process Tree Analysis
- **Parent-Child Relationships**: Visual process hierarchy mapping
- **Process Lifecycle**: Tracks process creation and termination
- **Execution Context**: Captures executable paths and PIDs
- **Multi-level Spawning**: Handles complex process injection scenarios

### Network Activity Monitoring
- **Connection Tracking**: Monitors TCP/UDP connections
- **DNS Query Analysis**: Captures domain resolution attempts
- **Port Activity**: Identifies suspicious port usage patterns
- **Backdoor Detection**: Detects listening sockets and incoming connections

### Memory Forensics
- **Memory Usage Tracking**: Monitors memory allocation patterns
- **Resident Set Size (RSS)**: Tracks physical memory usage
- **Virtual Memory Analysis**: Monitors virtual memory operations
- **Memory Operation Patterns**: Detects suspicious memory behavior

## 🛡️ Security Features

### File Validation
- **Extension Filtering**: Configurable allowed file types
- **Path Restrictions**: Blocks analysis of system-critical files
- **Size Limits**: Prevents analysis of oversized files
- **Permission Checks**: Validates file accessibility

### Analysis Sandboxing
- **Timeout Protection**: Automatic termination of long-running analyses
- **Resource Limits**: Memory and CPU usage constraints
- **Isolated Execution**: Configurable sandbox environments
- **Network Isolation**: Optional network access blocking

### Security Configuration
```ini
[security]
allowed_extensions = .py,.sh,.elf,.out,.bin
blocked_paths = /etc/,/usr/bin/,/bin/,/sbin/
enable_sandboxing = false
max_memory_usage = 1024
```

## 📈 Visualization and Reporting

### Process Tree Graphs
- **Hierarchical Layout**: Clear parent-child relationships
- **Status Indicators**: Running vs. exited process states
- **Interactive Display**: Hover details and navigation
- **Export Options**: PNG/SVG format support

### System Call Analytics
- **Frequency Analysis**: Most common system calls
- **Timeline Visualization**: Temporal pattern analysis
- **Category Breakdown**: File/Network/Process/Memory operations
- **Suspicious Highlighting**: Dangerous syscalls marked in red

### Analysis Summary
- **Metric Dashboard**: Key statistics and counts
- **Pattern Detection**: Automated threat identification
- **Risk Assessment**: Severity scoring and recommendations
- **Export Reports**: JSON/CSV format results

## 🧪 Sample Malware

### Python Test Malware (`samples/test_malware.py`)
- **File Operations**: Creates, modifies, and deletes files
- **Network Activity**: Attempts connections to various hosts
- **Process Spawning**: Forks multiple child processes
- **System Reconnaissance**: Gathers system information
- **Persistence Attempts**: Tries to establish persistence mechanisms

### C Test Malware (`samples/test_malware.c`)
- **Low-level System Calls**: Direct syscall usage
- **Memory Operations**: Large memory allocations and patterns
- **Network Programming**: Socket creation and connection attempts
- **Process Control**: Fork/exec operations
- **Anti-forensics**: File deletion and cleanup

### Shell Script Malware (`samples/test_malware.sh`)
- **Command Execution**: Various system commands
- **Data Exfiltration**: Simulated sensitive data collection
- **Persistence Scripts**: Startup script creation
- **Log Manipulation**: Attempts to clear system logs
- **Network Reconnaissance**: Port scanning and service discovery

## 🔧 Configuration

### Analysis Settings
```ini
[analysis]
max_timeout = 300
default_timeout = 30
max_file_size = 100
max_concurrent_analyses = 3
```

### Monitoring Configuration
```ini
[monitoring]
enable_process_monitor = true
enable_network_monitor = true
enable_memory_analysis = true
max_syscalls = 10000
```

### Path Configuration
```ini
[paths]
temp_dir = /tmp/sentinal
output_dir = ./results
monitor_binary = ./process_monitor
```

## 🐛 Troubleshooting

### Common Issues

**Permission Denied**
- Ensure user has execute permissions on analysis files
- Check if files are in blocked paths
- Verify file extensions are allowed

**Monitor Compilation Fails**
- Install build-essential package
- Check GCC version compatibility
- Ensure make utility is available

**Network Monitoring Limited**
- Some network features require root privileges
- Use `sudo` for complete network analysis
- Check firewall settings

**High Memory Usage**
- Adjust max_memory_usage in configuration
- Monitor system resources during analysis
- Use shorter timeout values for large files

### Debug Mode
```bash
# Enable debug logging
export FLASK_ENV=development
export FLASK_DEBUG=1
cd backend
python3 app.py
```

## ⚠️ Security Warnings

### Critical Safety Guidelines
1. **Never run on production systems** - Always use isolated environments
2. **VM/Container recommended** - Use virtual machines for analysis
3. **Network isolation** - Disconnect from critical networks during analysis
4. **Backup important data** - Malware may corrupt or delete files
5. **Monitor system resources** - Watch for resource exhaustion attacks
6. **Review sample files** - Understand test malware before execution
7. **Keep systems updated** - Use latest OS and security patches

### Risk Mitigation
- Run in dedicated analysis VMs
- Use network segmentation
- Implement proper backup procedures
- Monitor system logs for anomalies
- Regular security audits of analysis environment

## 📝 Development

### Project Structure
```
sentinal/
├── backend/           # Python Flask API server
├── monitor/           # C process monitoring module  
├── frontend/          # HTML/CSS/JS web interface
├── samples/           # Test malware samples
├── config/            # Configuration files
├── requirements.txt   # Python dependencies
├── setup.sh          # Installation script
└── README.md         # This file
```

### Contributing
1. Fork the repository
2. Create feature branch
3. Add comprehensive tests
4. Follow security guidelines
5. Submit pull request with detailed description

### Testing
```bash
# Test C monitor compilation
cd monitor && make test

# Test Python backend
cd backend && python3 -m pytest

# Test sample malware
cd samples && make test
```

## 📚 Technical Details

### System Call Interception
The framework uses ptrace(2) system calls to intercept and analyze process behavior:
- `PTRACE_TRACEME` - Child process enables tracing
- `PTRACE_SYSCALL` - Trace system call entry/exit
- `PTRACE_GETREGS` - Extract system call arguments
- `PTRACE_SETOPTIONS` - Configure tracing options

### Network Monitoring Implementation
Network analysis combines multiple approaches:
- `psutil.net_connections()` - Active connection enumeration
- Socket monitoring via /proc filesystem
- DNS query detection through port 53 monitoring
- Network interface statistics via `psutil.net_io_counters()`

### Memory Analysis Techniques
Memory forensics employs various methods:
- RSS/VMS tracking via /proc/[pid]/status
- Memory mapping analysis via /proc/[pid]/maps
- Heap pattern detection through allocation monitoring
- Stack analysis via process memory regions

## 📊 Performance Metrics

### Typical Analysis Times
- Small Python scripts: 5-15 seconds
- Medium C binaries: 15-45 seconds  
- Complex shell scripts: 10-30 seconds
- Network-heavy samples: 30-60 seconds

### Resource Requirements
- **RAM**: 256MB - 2GB depending on analysis complexity
- **CPU**: Single core sufficient, multi-core beneficial
- **Disk**: 100MB for framework, variable for analysis data
- **Network**: Optional for DNS resolution and updates

### Scalability Considerations
- Maximum concurrent analyses: 3 (configurable)
- System call capture limit: 10,000 per analysis
- Process tracking limit: 500 processes per analysis
- Analysis timeout: 300 seconds maximum

## 🤝 Support and Community

### Getting Help
- Review this documentation thoroughly
- Check configuration files for proper settings
- Test with provided sample malware first
- Enable debug logging for troubleshooting

### Reporting Issues
When reporting problems, include:
- Operating system and version
- Python version and virtual environment details
- Complete error messages and logs
- Steps to reproduce the issue
- Configuration file contents (sanitized)

### Security Reporting
For security vulnerabilities:
- Do not create public issues
- Contact maintainers directly
- Provide detailed vulnerability information
- Allow time for responsible disclosure

---

**⚠️ DISCLAIMER**: This tool is for educational and research purposes only. Users are responsible for ensuring compliance with all applicable laws and regulations. The authors assume no liability for misuse or damages resulting from the use of this software.

**🔒 SECURITY REMINDER**: Always analyze potentially malicious files in isolated, non-production environments!