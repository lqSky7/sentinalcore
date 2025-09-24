# Sentinal - Linux Malware Analysis Tool

A comprehensive malware analysis framework for Linux systems that provides:

## Features
- **System Call Monitoring**: Track all system calls using strace integration
- **Process Tree Analysis**: Monitor parent-child process relationships
- **Network Activity Monitoring**: Capture and analyze network connections
- **Memory Forensics**: Memory usage analysis and pattern detection
- **Web Interface**: Simple mono-spaced text UI on localhost:3000
- **Real-time Visualization**: Process trees and analysis graphs

## Components
- `backend/`: Python Flask API server
- `monitor/`: C-based process and system call monitor
- `frontend/`: Simple HTML/CSS/JS web interface
- `samples/`: Test malware samples for analysis
- `config/`: Configuration files and security settings

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