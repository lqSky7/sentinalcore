"""
SentinalCore Isolation Module

This module provides secure malware analysis environments using:
- Linux namespaces (PID, mount, network, user)
- chroot jails
- Resource limits (cgroups)
- Sandboxed execution environments
"""

from .namespace_manager import NamespaceManager
from .chroot_manager import ChrootManager  
from .sandbox_executor import SandboxExecutor
from .resource_limiter import ResourceLimiter

__all__ = [
    'NamespaceManager',
    'ChrootManager', 
    'SandboxExecutor',
    'ResourceLimiter'
]