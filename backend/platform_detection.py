"""
Platform detection and compatibility utilities for Sentinal
Handles differences between Linux, macOS, and different architectures
"""

import platform
import subprocess
import os
import sys

class PlatformInfo:
    def __init__(self):
        self.system = platform.system().lower()
        self.machine = platform.machine().lower()
        self.python_version = platform.python_version()
        self.architecture = self._normalize_architecture()
        
        # Platform identification (needed before capability detection)
        self.is_linux = self.system == 'linux'
        self.is_macos = self.system == 'darwin'
        self.is_arm64 = self.architecture in ['arm64', 'aarch64']
        self.is_x86_64 = self.architecture in ['x86_64', 'amd64']
        
        # Capability detection
        self.has_strace = self._check_strace()
        self.has_ptrace = self._check_ptrace()
        self.has_procfs = self._check_procfs()
        
    def _normalize_architecture(self):
        """Normalize architecture names across platforms"""
        arch = self.machine.lower()
        
        # ARM64 variants
        if arch in ['arm64', 'aarch64']:
            return 'arm64'
        
        # x86_64 variants  
        if arch in ['x86_64', 'amd64']:
            return 'x86_64'
            
        # x86_32 variants
        if arch in ['i386', 'i686', 'x86']:
            return 'x86_32'
            
        # ARM32 variants
        if arch.startswith('arm'):
            return 'arm32'
            
        return arch
    
    def _check_strace(self):
        """Check if strace is available"""
        try:
            result = subprocess.run(['which', 'strace'], 
                                  capture_output=True, text=True, timeout=5)
            return result.returncode == 0
        except:
            return False
    
    def _check_ptrace(self):
        """Check if ptrace functionality is available"""
        if self.is_linux:
            return True
        elif self.is_macos:
            # macOS has ptrace but it's more limited
            return True
        else:
            return False
    
    def _check_procfs(self):
        """Check if /proc filesystem is available"""
        return os.path.exists('/proc') and os.path.isdir('/proc')
    
    def get_monitoring_strategy(self):
        """Determine the best monitoring strategy for this platform"""
        if self.is_linux and self.has_strace:
            return 'strace_enhanced'
        elif self.is_linux and self.has_ptrace:
            return 'ptrace_basic'
        elif self.is_macos and self.has_ptrace:
            return 'macos_ptrace'
        elif self.has_strace:
            return 'strace_only'
        else:
            return 'process_basic'
    
    def get_syscall_table(self):
        """Get platform-specific syscall mappings"""
        if self.is_linux and self.is_x86_64:
            return self._get_linux_x86_64_syscalls()
        elif self.is_linux and self.is_arm64:
            return self._get_linux_arm64_syscalls()
        elif self.is_macos:
            return self._get_macos_syscalls()
        else:
            return self._get_generic_syscalls()
    
    def _get_linux_x86_64_syscalls(self):
        """Linux x86_64 syscall mappings"""
        return {
            0: 'read', 1: 'write', 2: 'open', 3: 'close', 4: 'stat',
            5: 'fstat', 6: 'lstat', 7: 'poll', 8: 'lseek', 9: 'mmap',
            10: 'mprotect', 11: 'munmap', 12: 'brk', 13: 'rt_sigaction',
            14: 'rt_sigprocmask', 16: 'ioctl', 21: 'access', 22: 'pipe',
            23: 'select', 41: 'socket', 42: 'connect', 43: 'accept',
            44: 'sendto', 45: 'recvfrom', 49: 'bind', 50: 'listen',
            57: 'fork', 58: 'vfork', 59: 'execve', 60: 'exit', 61: 'wait4',
            62: 'kill', 63: 'uname', 72: 'fcntl', 73: 'flock', 74: 'fsync',
            75: 'fdatasync', 76: 'truncate', 77: 'ftruncate', 78: 'getdents',
            79: 'getcwd', 80: 'chdir', 81: 'fchdir', 82: 'rename',
            83: 'mkdir', 84: 'rmdir', 85: 'creat', 86: 'link', 87: 'unlink',
            88: 'symlink', 89: 'readlink', 90: 'chmod', 91: 'fchmod',
            92: 'chown', 93: 'fchown', 94: 'lchown', 95: 'umask',
            102: 'getuid', 104: 'getgid', 110: 'getppid', 186: 'gettid',
            217: 'getdents64', 221: 'fadvise64', 228: 'clock_gettime',
            231: 'exit_group', 262: 'newfstatat', 288: 'accept4',
            319: 'memfd_create', 435: 'clone3'
        }
    
    def _get_linux_arm64_syscalls(self):
        """Linux ARM64 syscall mappings"""
        return {
            63: 'read', 64: 'write', 56: 'openat', 57: 'close', 79: 'fstatat',
            80: 'fstat', 78: 'readlinkat', 23: 'dup', 24: 'dup3', 25: 'fcntl',
            26: 'ioctl', 27: 'flock', 28: 'mknodat', 29: 'mkdirat',
            30: 'unlinkat', 31: 'symlinkat', 32: 'linkat', 33: 'renameat',
            34: 'umount2', 35: 'mount', 36: 'pivot_root', 37: 'nfsservctl',
            38: 'statfs', 39: 'fstatfs', 40: 'truncate', 41: 'ftruncate',
            42: 'fallocate', 43: 'faccessat', 44: 'chdir', 45: 'fchdir',
            46: 'chroot', 47: 'fchmod', 48: 'fchmodat', 49: 'fchownat',
            50: 'fchown', 51: 'openat', 52: 'close', 53: 'vhangup',
            54: 'pipe2', 55: 'quotactl', 56: 'getdents64', 57: 'lseek',
            58: 'read', 59: 'write', 60: 'readv', 61: 'writev', 62: 'pread64',
            198: 'socket', 203: 'connect', 202: 'accept', 206: 'sendto',
            207: 'recvfrom', 200: 'bind', 201: 'listen', 220: 'clone',
            221: 'execve', 93: 'exit', 260: 'wait4', 129: 'kill',
            160: 'uname', 174: 'getpid', 173: 'getppid', 178: 'gettid',
            113: 'statx', 291: 'statx'
        }
    
    def _get_macos_syscalls(self):
        """macOS syscall mappings (BSD-style)"""
        return {
            1: 'exit', 2: 'fork', 3: 'read', 4: 'write', 5: 'open',
            6: 'close', 7: 'wait4', 8: 'creat', 9: 'link', 10: 'unlink',
            12: 'chdir', 15: 'chmod', 16: 'chown', 18: 'getfsstat',
            20: 'getpid', 23: 'setuid', 24: 'getuid', 25: 'geteuid',
            27: 'recvmsg', 28: 'sendmsg', 29: 'recvfrom', 30: 'accept',
            31: 'getpeername', 32: 'getsockname', 33: 'access', 34: 'chflags',
            35: 'fchflags', 36: 'sync', 37: 'kill', 39: 'getppid',
            41: 'dup', 42: 'pipe', 43: 'getegid', 46: 'sigaction',
            47: 'getgid', 48: 'sigprocmask', 49: 'getlogin', 50: 'setlogin',
            59: 'execve', 65: 'msync', 66: 'vfork', 73: 'munmap',
            74: 'mprotect', 75: 'madvise', 78: 'mincore', 79: 'getgroups',
            97: 'socket', 98: 'connect', 104: 'bind', 106: 'listen',
            116: 'gettimeofday', 117: 'getrusage', 118: 'getsockopt',
            120: 'readv', 121: 'writev', 123: 'fchown', 124: 'fchmod',
            131: 'setgid', 136: 'mkdir', 137: 'rmdir', 181: 'setgid',
            197: 'mmap', 202: 'sysctl', 230: 'lstat', 338: 'sendfile'
        }
    
    def _get_generic_syscalls(self):
        """Generic syscall mappings for unknown platforms"""
        return {
            -1: 'unknown', 0: 'read', 1: 'write', 2: 'open', 3: 'close',
            4: 'stat', 5: 'fstat', 6: 'lstat', 7: 'poll', 8: 'lseek',
            9: 'mmap', 10: 'mprotect', 11: 'munmap', 12: 'brk'
        }
    
    def get_platform_summary(self):
        """Get a summary of platform capabilities"""
        return {
            'system': self.system,
            'architecture': self.architecture,
            'python_version': self.python_version,
            'monitoring_strategy': self.get_monitoring_strategy(),
            'capabilities': {
                'strace': self.has_strace,
                'ptrace': self.has_ptrace,
                'procfs': self.has_procfs,
                'is_linux': self.is_linux,
                'is_macos': self.is_macos,
                'is_arm64': self.is_arm64,
                'is_x86_64': self.is_x86_64
            }
        }

# Global platform instance
platform_info = PlatformInfo()

def get_platform_info():
    """Get the global platform information instance"""
    return platform_info

def is_platform_supported():
    """Check if the current platform is supported"""
    return platform_info.has_ptrace or platform_info.has_strace

def get_recommended_settings():
    """Get recommended settings for the current platform"""
    settings = {
        'max_timeout': 300,
        'default_timeout': 30,
        'enable_process_monitor': True,
        'enable_network_monitor': True,
        'enable_memory_analysis': True
    }
    
    # Adjust settings based on platform
    if not platform_info.is_linux:
        settings['max_timeout'] = 60  # Shorter on non-Linux
        settings['enable_memory_analysis'] = False  # Limited on non-Linux
    
    if not platform_info.has_strace:
        settings['enable_process_monitor'] = False
    
    return settings