#!/usr/bin/env python3
"""
Chroot Jail Manager for Malware Analysis Isolation

Provides secure chroot environments for malware execution:
- Creates minimal root filesystem
- Mounts essential directories
- Handles file system isolation
- Manages chroot environment lifecycle
"""

import os
import sys
import shutil
import subprocess
import tempfile
import logging
from pathlib import Path
from typing import Dict, List, Optional, Set
from dataclasses import dataclass
from contextlib import contextmanager

@dataclass
class ChrootConfig:
    """Configuration for chroot jail"""
    base_dir: Optional[str] = None
    essential_dirs: List[str] = None
    copy_files: List[str] = None
    mount_proc: bool = True
    mount_dev: bool = True
    mount_tmp: bool = True
    shell: str = "/bin/bash"
    
    def __post_init__(self):
        if self.essential_dirs is None:
            self.essential_dirs = [
                '/bin', '/lib', '/lib64', '/usr/bin', '/usr/lib',
                '/etc', '/dev', '/proc', '/tmp', '/var/tmp'
            ]
        
        if self.copy_files is None:
            self.copy_files = [
                '/bin/bash', '/bin/sh', '/bin/ls', '/bin/cat',
                '/bin/echo', '/bin/ps', '/bin/kill', '/bin/chmod',
                '/usr/bin/python3', '/usr/bin/strace'
            ]

class ChrootManager:
    """Manages chroot jail environments for secure malware analysis"""
    
    def __init__(self, config: Optional[ChrootConfig] = None):
        self.config = config or ChrootConfig()
        self.logger = logging.getLogger(__name__)
        self.chroot_dirs = []
        self.mounted_dirs = []
        
    def check_chroot_requirements(self) -> Dict[str, bool]:
        """Check system requirements for chroot functionality"""
        requirements = {}
        
        # Check if running as root or with sudo
        requirements['root_access'] = os.geteuid() == 0
        
        # Check for required commands
        commands = ['chroot', 'mount', 'umount', 'cp', 'mkdir']
        for cmd in commands:
            try:
                result = subprocess.run(['which', cmd], 
                                      capture_output=True, text=True)
                requirements[f'{cmd}_available'] = result.returncode == 0
            except:
                requirements[f'{cmd}_available'] = False
        
        # Check for essential directories
        essential_exists = all(os.path.exists(d) for d in ['/bin', '/lib', '/usr'])
        requirements['essential_dirs_exist'] = essential_exists
        
        return requirements
    
    def create_chroot_environment(self, chroot_dir: str) -> str:
        """Create a minimal chroot environment"""
        chroot_path = Path(chroot_dir)
        chroot_path.mkdir(parents=True, exist_ok=True)
        
        self.logger.info(f"Creating chroot environment at {chroot_dir}")
        
        # Create essential directory structure
        for dir_name in self.config.essential_dirs:
            target_dir = chroot_path / dir_name.lstrip('/')
            target_dir.mkdir(parents=True, exist_ok=True)
        
        # Copy essential files
        self._copy_essential_files(chroot_path)
        
        # Copy shared libraries
        self._copy_shared_libraries(chroot_path)
        
        # Setup device nodes
        self._setup_device_nodes(chroot_path)
        
        # Mount essential filesystems
        self._mount_essential_filesystems(chroot_path)
        
        return str(chroot_path)
    
    def _copy_essential_files(self, chroot_path: Path):
        """Copy essential executables and files to chroot"""
        for file_path in self.config.copy_files:
            if os.path.exists(file_path):
                # Determine target path in chroot
                target_path = chroot_path / file_path.lstrip('/')
                target_path.parent.mkdir(parents=True, exist_ok=True)
                
                try:
                    shutil.copy2(file_path, target_path)
                    # Preserve executable permissions
                    shutil.copystat(file_path, target_path)
                except Exception as e:
                    self.logger.warning(f"Failed to copy {file_path}: {e}")
        
        # Copy essential configuration files
        config_files = [
            '/etc/passwd', '/etc/group', '/etc/hosts',
            '/etc/resolv.conf', '/etc/nsswitch.conf'
        ]
        
        for config_file in config_files:
            if os.path.exists(config_file):
                target = chroot_path / config_file.lstrip('/')
                target.parent.mkdir(parents=True, exist_ok=True)
                try:
                    shutil.copy2(config_file, target)
                except Exception as e:
                    self.logger.warning(f"Failed to copy config {config_file}: {e}")
    
    def _copy_shared_libraries(self, chroot_path: Path):
        """Copy shared libraries required by executables"""
        lib_dirs = ['/lib', '/lib64', '/usr/lib', '/usr/lib64']
        
        for lib_dir in lib_dirs:
            if os.path.exists(lib_dir):
                target_lib_dir = chroot_path / lib_dir.lstrip('/')
                target_lib_dir.mkdir(parents=True, exist_ok=True)
                
                # Copy essential libraries
                essential_libs = [
                    'libc.so*', 'libdl.so*', 'libm.so*', 'libpthread.so*',
                    'ld-linux*.so*', 'libz.so*', 'libssl.so*', 'libcrypto.so*'
                ]
                
                for lib_pattern in essential_libs:
                    try:
                        result = subprocess.run(
                            ['find', lib_dir, '-name', lib_pattern, '-type', 'f'],
                            capture_output=True, text=True
                        )
                        
                        for lib_file in result.stdout.strip().split('\n'):
                            if lib_file and os.path.exists(lib_file):
                                rel_path = os.path.relpath(lib_file, '/')
                                target = chroot_path / rel_path
                                target.parent.mkdir(parents=True, exist_ok=True)
                                shutil.copy2(lib_file, target)
                                
                    except Exception as e:
                        self.logger.warning(f"Failed to copy libraries {lib_pattern}: {e}")
    
    def _setup_device_nodes(self, chroot_path: Path):
        """Setup essential device nodes in chroot"""
        dev_dir = chroot_path / 'dev'
        dev_dir.mkdir(exist_ok=True)
        
        device_nodes = [
            ('null', 'c', 1, 3),
            ('zero', 'c', 1, 5),
            ('random', 'c', 1, 8),
            ('urandom', 'c', 1, 9)
        ]
        
        for name, dev_type, major, minor in device_nodes:
            dev_path = dev_dir / name
            try:
                # Create device node
                subprocess.run([
                    'mknod', str(dev_path), dev_type, str(major), str(minor)
                ], check=True)
                os.chmod(dev_path, 0o666)
            except Exception as e:
                self.logger.warning(f"Failed to create device node {name}: {e}")
    
    def _mount_essential_filesystems(self, chroot_path: Path):
        """Mount essential filesystems in chroot"""
        mounts = []
        
        if self.config.mount_proc:
            proc_dir = chroot_path / 'proc'
            proc_dir.mkdir(exist_ok=True)
            mounts.append(('proc', str(proc_dir), 'proc'))
        
        if self.config.mount_dev:
            dev_dir = chroot_path / 'dev'
            dev_dir.mkdir(exist_ok=True)
            mounts.append(('/dev', str(dev_dir), 'bind'))
        
        if self.config.mount_tmp:
            tmp_dir = chroot_path / 'tmp'
            tmp_dir.mkdir(exist_ok=True)
            mounts.append(('tmpfs', str(tmp_dir), 'tmpfs'))
        
        for source, target, fs_type in mounts:
            try:
                if fs_type == 'bind':
                    subprocess.run(['mount', '--bind', source, target], check=True)
                elif fs_type == 'tmpfs':
                    subprocess.run(['mount', '-t', 'tmpfs', source, target], check=True)
                else:
                    subprocess.run(['mount', '-t', fs_type, source, target], check=True)
                
                self.mounted_dirs.append(target)
                self.logger.debug(f"Mounted {source} at {target}")
                
            except subprocess.CalledProcessError as e:
                self.logger.warning(f"Failed to mount {source} at {target}: {e}")
    
    def execute_in_chroot(self, chroot_dir: str, command: List[str], 
                         timeout: int = 30) -> Dict:
        """Execute command inside chroot jail"""
        
        chroot_command = ['chroot', chroot_dir] + command
        
        try:
            self.logger.info(f"Executing in chroot: {' '.join(command)}")
            
            result = subprocess.run(
                chroot_command,
                capture_output=True,
                text=True,
                timeout=timeout,
                cwd='/'  # Change to root directory in chroot
            )
            
            return {
                'returncode': result.returncode,
                'stdout': result.stdout,
                'stderr': result.stderr,
                'timed_out': False
            }
            
        except subprocess.TimeoutExpired:
            return {
                'returncode': -1,
                'stdout': '',
                'stderr': 'Command timed out',
                'timed_out': True
            }
        except Exception as e:
            return {
                'returncode': -1,
                'stdout': '',
                'stderr': f'Execution failed: {str(e)}',
                'timed_out': False
            }
    
    @contextmanager
    def chroot_environment(self, base_name: str = "sentinal_chroot"):
        """Context manager for chroot environment lifecycle"""
        chroot_dir = None
        
        try:
            # Create temporary directory for chroot
            temp_base = tempfile.mkdtemp(prefix=f'{base_name}_')
            chroot_dir = os.path.join(temp_base, 'chroot')
            
            # Setup chroot environment
            self.create_chroot_environment(chroot_dir)
            self.chroot_dirs.append(chroot_dir)
            
            yield chroot_dir
            
        finally:
            if chroot_dir:
                self.cleanup_chroot(chroot_dir)
    
    def cleanup_chroot(self, chroot_dir: str):
        """Cleanup chroot environment and unmount filesystems"""
        chroot_path = Path(chroot_dir)
        
        # Unmount all mounted filesystems
        for mount_point in reversed(self.mounted_dirs):
            try:
                subprocess.run(['umount', mount_point], 
                             stderr=subprocess.DEVNULL, check=False)
                self.logger.debug(f"Unmounted {mount_point}")
            except:
                pass
        
        # Remove chroot directory
        try:
            shutil.rmtree(chroot_dir, ignore_errors=True)
            self.logger.info(f"Cleaned up chroot directory: {chroot_dir}")
        except Exception as e:
            self.logger.warning(f"Failed to cleanup chroot {chroot_dir}: {e}")
        
        # Clear mounted directories list
        self.mounted_dirs.clear()
    
    def copy_sample_to_chroot(self, sample_path: str, chroot_dir: str, 
                            target_name: str = "sample") -> str:
        """Copy malware sample into chroot environment"""
        target_path = Path(chroot_dir) / "tmp" / target_name
        target_path.parent.mkdir(parents=True, exist_ok=True)
        
        try:
            shutil.copy2(sample_path, target_path)
            os.chmod(target_path, 0o755)  # Make executable
            
            # Return path relative to chroot
            return f"/tmp/{target_name}"
            
        except Exception as e:
            self.logger.error(f"Failed to copy sample to chroot: {e}")
            raise

def create_chroot_jail(config: Optional[ChrootConfig] = None) -> ChrootManager:
    """Factory function to create a chroot jail manager"""
    return ChrootManager(config)

# Example usage and testing
if __name__ == "__main__":
    # Test chroot requirements
    chroot_manager = ChrootManager()
    requirements = chroot_manager.check_chroot_requirements()
    
    print("Chroot Requirements:")
    for feature, available in requirements.items():
        status = "✓" if available else "✗"
        print(f"  {status} {feature}")
    
    # Test chroot creation (requires root)
    if requirements.get('root_access', False):
        with chroot_manager.chroot_environment() as chroot_dir:
            print(f"\nCreated chroot environment: {chroot_dir}")
            
            # Test simple command
            result = chroot_manager.execute_in_chroot(chroot_dir, ['ls', '-la', '/'])
            print(f"Command output: {result['stdout']}")
    else:
        print("\nNote: Root access required for chroot functionality")