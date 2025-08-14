# SentinalCore: Linux Malware Analysis Framework
## Operating Systems Course Presentation

---

## Slide 1: Introduction & Project Overview

**SentinalCore: Multi-layered Malware Analysis Framework for Linux**

- **Project Type**: Security research & OS-level malware detection system
- **Target Platform**: Linux systems (kernel 4.15+)
- **Original Context**: Hackathon project, now adapted for OS coursework
- **Core Philosophy**: Defense through multiple detection layers and system-level isolation

**Key Value Proposition:**
- Real-time malware detection using OS primitives
- Process isolation using Linux kernel features
- Multi-source threat intelligence integration

---

## Slide 2: System Architecture & OS Integration

**OS-Level Components:**

1. **Kernel Integration**
   - eBPF programs for syscall monitoring
   - Linux namespace manipulation
   - Process control groups (cgroups)

2. **File System Monitoring**
   - Entropy analysis using file I/O operations
   - Real-time file scanning via kernel hooks
   - Process-to-file mapping via `/proc` filesystem

3. **System Resource Management**
   - Memory isolation using namespace separation
   - Network isolation via network namespaces
   - CPU/memory resource limiting

**Architecture Pattern**: Multi-layered defense with OS kernel as security boundary

---

## Slide 3: Detection Engine Components

**Multi-Modal Detection System:**

1. **Signature-based Detection (ClamAV)**
   - Integration with established antivirus engine
   - Real-time scanning of file operations
   - Database updates via `freshclam`

2. **Statistical Analysis (Entropy Calculation)**
   - Mathematical entropy calculation: `H(X) = -Σ p(xi) log2 p(xi)`
   - High entropy indicates encryption/packing (malware characteristics)
   - File structure analysis for PE/ELF headers

3. **Cloud Intelligence (VirusTotal API)**
   - External threat intelligence correlation
   - File hash reputation checking
   - Multi-engine scanning results

4. **Behavioral Analysis (LLM-powered)**
   - System log pattern analysis using Google Gemini
   - Anomaly detection in auth logs, kernel messages

---

## Slide 4: Process Isolation & Containment

**Linux Namespace-based Isolation:**

```python
# Core isolation using Linux namespaces
CLONE_NEWNS   # Mount namespace isolation
CLONE_NEWPID  # Process ID isolation  
CLONE_NEWNET  # Network isolation
CLONE_NEWUTS  # Hostname isolation
CLONE_NEWIPC  # IPC isolation
```

**Security Mechanisms:**
- **AppArmor Integration**: Dynamic profile generation and enforcement
- **Seccomp Filters**: System call filtering and restriction
- **Resource Limits**: CPU, memory, file descriptor limits
- **Network Isolation**: Preventing C&C communication

**Process Monitoring**: Real-time tracking of isolated malware execution

---

## Slide 5: eBPF-based System Call Monitoring

**Kernel-level Monitoring using eBPF:**

```c
// Critical syscalls monitored:
execve, clone, fork, vfork    // Process creation
openat, read, write, close    // File operations
connect, socket, accept4      // Network operations  
mmap, mprotect               // Memory operations
ptrace, unlinkat            // Suspicious operations
```

**OS Benefits:**
- Zero kernel modification required
- High-performance in-kernel filtering
- Real-time threat detection
- Parent-child process tree tracking

**Technical Implementation**: BCC (BPF Compiler Collection) for simplified eBPF program development

---

## Slide 6: File System Integration & Analysis

**File System Security Integration:**

1. **Entropy Analysis Engine**
   - Shannon entropy calculation on file contents
   - Threshold-based suspicious file detection
   - Process-to-file correlation via `/proc/<pid>/fd/`

2. **Real-time File Monitoring**
   - Integration with ClamAV daemon (`clamd`)
   - Recursive directory scanning with exclusion lists
   - File type detection via `file` command and MIME analysis

3. **Process Correlation**
   - Mapping infected files to running processes
   - PID extraction from `/proc` filesystem
   - Process genealogy tracking

**OS Concepts Applied**: Virtual file systems, file descriptors, inode tracking

---

## Slide 7: Memory Management & Security

**Memory Protection Mechanisms:**

1. **Namespace Memory Isolation**
   - Separate memory spaces for suspicious processes
   - Virtual memory isolation via `CLONE_NEWNS`
   - Process memory limiting through cgroups

2. **Dynamic Executable Analysis**
   - ELF binary format analysis
   - Dynamic library dependency tracking
   - Memory mapping analysis via `/proc/<pid>/maps`

3. **Exploit Prevention**
   - ASLR (Address Space Layout Randomization) enforcement
   - NX bit enforcement for code execution prevention
   - Stack canary detection in process analysis

**Security Model**: Principle of least privilege through OS-enforced boundaries

---

## Slide 8: Network Security & Isolation

**Network-level Threat Mitigation:**

1. **Network Namespace Isolation**
   - Complete network stack separation
   - Preventing malware network communication
   - Custom routing table per isolated process

2. **Traffic Analysis Integration**
   - Socket monitoring via eBPF
   - Connection attempt logging
   - External API communication (VirusTotal)

3. **Communication Protocols**
   - HTTPS API integration for threat intelligence
   - Local socket communication with ClamAV daemon
   - Inter-process communication security

**OS Networking Stack**: Socket APIs, network namespaces, iptables integration potential

---

## Slide 9: Testing Framework & Validation

**Comprehensive Testing Strategy:**

1. **EICAR Test Integration**
   - Standard antivirus test file creation
   - Validation of detection engines
   - False positive/negative analysis

2. **Synthetic Malware Testing**
   - High-entropy file generation
   - Suspicious behavior simulation
   - Process isolation validation

3. **System Integration Testing**
   - Multi-component interaction testing
   - Performance impact analysis
   - Resource consumption monitoring

**OS Testing Concepts**: Unit testing with system calls, integration testing with kernel modules, performance profiling

---

## Slide 10: Future Enhancements & Advanced Features

**Planned OS-Level Improvements:**

1. **Advanced Isolation Mechanisms**
   - **Rootkit Detection**: Kernel module verification, system call table integrity
   - **Hardware-assisted Security**: Intel CET, ARM Pointer Authentication
   - **Container Integration**: Docker/LXC security enhancement

2. **Enhanced User Experience**
   - **GUI Development**: Real-time threat visualization dashboard
   - **System Tray Integration**: Background monitoring with notifications
   - **Log Aggregation**: Centralized logging with ELK stack integration

3. **Advanced Detection Techniques**
   - **Machine Learning Integration**: Behavioral pattern recognition
   - **Kernel-level Hooking**: Advanced API monitoring
   - **Hardware Performance Counters**: CPU-level anomaly detection

4. **Distributed Security**
   - **Multi-host Coordination**: Threat intelligence sharing
   - **Cloud Integration**: Scalable analysis infrastructure
   - **Zero-trust Architecture**: Identity-based security model

**Research Opportunities**: Kernel security research, novel isolation techniques, performance optimization

---

**Questions & Discussion**

*SentinalCore: Demonstrating OS security principles through practical malware analysis*
