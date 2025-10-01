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