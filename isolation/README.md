# SentinalCore Isolation System

A comprehensive malware analysis isolation system using Linux namespaces, chroot jails, and resource limits to provide secure sandboxed execution environments.

## Features

### 🔒 **Namespace Isolation**
- **PID Namespace**: Isolates process tree from host
- **Mount Namespace**: Isolates filesystem mounts
- **Network Namespace**: Isolates network interfaces and traffic
- **User Namespace**: Maps container root to unprivileged host user
- **IPC Namespace**: Isolates inter-process communication
- **UTS Namespace**: Isolates hostname and domain

### 🏛️ **Chroot Jails**
- Minimal root filesystem construction
- Essential binaries and libraries copying
- Device node creation (/dev/null, /dev/zero, etc.)
- Filesystem mount management
- Automatic cleanup after analysis

### ⚡ **Resource Limiting**
- **CPU Limits**: Prevent CPU exhaustion attacks
- **Memory Limits**: Control RAM and swap usage
- **Process Limits**: Limit number of child processes
- **I/O Limits**: Control disk read/write bandwidth
- **Execution Timeouts**: Prevent infinite loops

### 📊 **Analysis & Monitoring**
- System call tracing with strace integration
- File access monitoring
- Network activity capture
- Process creation tracking
- Behavioral pattern analysis

## Architecture

```
┌─────────────────────────────────────────────────────────────┐
│                    IsolationManager                         │
│                  (Main Interface)                           │
└─────────────────┬───────────────┬───────────────┬───────────┘
                  │               │               │
         ┌────────▼────────┐ ┌────▼────┐ ┌───────▼────────┐
         │ SandboxExecutor │ │ Strace  │ │ ResourceLimiter│
         │   (Orchestr.)   │ │Monitor  │ │   (cgroups)    │
         └────────┬────────┘ └─────────┘ └────────────────┘
                  │
    ┌─────────────▼─────────────┐
    │     NamespaceManager      │
    │    (unshare, clone)       │
    └─────────────┬─────────────┘
                  │
    ┌─────────────▼─────────────┐
    │      ChrootManager        │
    │   (minimal rootfs)        │
    └───────────────────────────┘
```

## Installation & Setup

The isolation system is included with SentinalCore. No additional installation required.

### Requirements

- Linux kernel with namespace support (kernel >= 3.8)
- `unshare` command (util-linux package)
- `strace` for system call monitoring
- Root access for chroot functionality (optional)
- cgroups v1 or v2 for resource limits (optional)

### Check System Compatibility

```bash
cd /path/to/sentinalcore/isolation
python3 test_isolation.py
```

## Usage

### Basic Usage

```python
from isolation import IsolationManager

# Create isolation manager with default security settings
isolation = IsolationManager()

# Execute malware sample safely
result = isolation.execute_sample('/path/to/malware.bin')

# Analyze results
analysis = isolation.analyze_sample('/path/to/malware.bin')
```

### Custom Configuration

```python
# Load custom configuration
isolation = IsolationManager('config_strict.json')

# Or create programmatically
from isolation.sandbox_executor import SandboxConfig
from isolation.namespace_manager import NamespaceConfig

config = SandboxConfig(
    use_namespaces=True,
    namespace_config=NamespaceConfig(
        use_net_ns=False,  # Allow network access
        hostname="analysis-box"
    ),
    execution_timeout=120  # 2 minute timeout
)

isolation = IsolationManager()
isolation.config = config
```

### Batch Analysis

```python
# Analyze multiple samples
samples = ['/path/to/sample1', '/path/to/sample2', '/path/to/sample3']
results = isolation.batch_analyze(samples)

for result in results:
    if result.get('error'):
        print(f"Failed: {result['sample_path']} - {result['error']}")
    else:
        analysis = result['analysis']
        print(f"Analyzed: {result['sample_path']}")
        print(f"  Suspicious activities: {len(analysis['suspicious_activities'])}")
```

## Configuration Files

### Strict Configuration (`config_strict.json`)
- Maximum isolation (all namespaces, chroot, tight resource limits)
- 20 second timeout
- 64MB RAM limit
- 8 process limit
- Network isolation enabled

### Permissive Configuration (`config_permissive.json`)
- Namespace isolation without chroot
- 60 second timeout
- 256MB RAM limit
- 32 process limit
- Network access allowed

## Security Considerations

### ⚠️ **Important Security Warnings**

1. **Always run in isolated environments** (VMs, containers)
2. **Never analyze samples on production systems**
3. **Monitor resource usage** to prevent DoS attacks
4. **Review sample files** before execution
5. **Keep analysis logs** for forensic purposes

### 🛡️ **Isolation Levels**

- **Maximum**: Full namespaces + chroot + resource limits
- **High**: Namespaces + resource limits (no chroot)
- **Medium**: Either namespaces OR chroot
- **Minimal**: No isolation (dangerous!)

### 🔐 **Permission Requirements**

| Feature | Requires Root | Alternative |
|---------|---------------|-------------|
| Namespaces | No | User namespaces |
| Chroot | Yes | Container/VM |
| Cgroups | Depends | User slice |
| Strace | No | Built-in |

## API Reference

### IsolationManager

```python
class IsolationManager:
    def __init__(config_file: Optional[str] = None)
    def execute_sample(sample_path: str, args: List[str] = None) -> ExecutionResult
    def analyze_sample(sample_path: str) -> Dict[str, Any]
    def batch_analyze(sample_paths: List[str]) -> List[Dict[str, Any]]
    def get_isolation_level() -> str
    def get_status_report() -> Dict[str, Any]
```

### ExecutionResult

```python
@dataclass
class ExecutionResult:
    returncode: int
    stdout: str
    stderr: str
    execution_time: float
    timed_out: bool
    strace_output: Optional[str]
    network_activity: Optional[List[Dict]]
    file_accesses: Optional[List[str]]
    process_tree: Optional[Dict]
```

## Testing

### Run Capability Tests

```bash
# Test isolation capabilities
python3 isolation/test_isolation.py

# Test with a sample
python3 isolation/test_isolation.py /path/to/malware.bin

# Test specific configuration
python3 -c "
from isolation import IsolationManager
isolation = IsolationManager('isolation/config_strict.json')
print(isolation.get_status_report())
"
```

### Example Test Output

```
=== SentinalCore Isolation System Test ===

System Status:
  Isolation Level: high
  Platform: linux
  User ID: 1000
  Python Version: 3.13.7

Capabilities:
  Namespaces: ✓
    pid: ✓
    mnt: ✓
    net: ✓
    user: ✓
    ipc: ✓
    uts: ✓
  Chroot: ✗
  Resource Limits: ✓
    Cgroups Version: v2
    Available Controllers: cpu, memory, pids, io
```

## Troubleshooting

### Common Issues

1. **"No namespace support"**
   - Check kernel version: `uname -r`
   - Ensure util-linux is installed: `which unshare`

2. **"Chroot requires root access"**
   - Run with sudo for chroot functionality
   - Use namespace-only mode as alternative

3. **"Cgroups not available"**
   - Check cgroups mount: `ls /sys/fs/cgroup`
   - Verify write permissions to cgroup directories

4. **"Sample execution failed"**
   - Check sample file exists and is executable
   - Verify timeout settings are adequate
   - Review strace output for system call failures

### Debug Mode

```python
import logging
logging.basicConfig(level=logging.DEBUG)

isolation = IsolationManager()
# Detailed debug logs will show isolation setup steps
```

## Integration with SentinalCore

The isolation system is designed to integrate seamlessly with SentinalCore's analysis pipeline:

```python
# In backend/app.py
from isolation import IsolationManager

isolation = IsolationManager()

@app.route('/analyze', methods=['POST'])
def analyze_sample():
    sample_path = request.json['sample_path']
    result = isolation.analyze_sample(sample_path)
    return jsonify(result)
```

## Contributing

When contributing to the isolation system:

1. Test on multiple Linux distributions
2. Verify compatibility with different kernel versions
3. Document security implications of changes
4. Add appropriate test cases
5. Follow the existing code structure

## License

Part of the SentinalCore project. See main project LICENSE file.