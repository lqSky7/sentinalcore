#!/usr/bin/env python3
"""
Sudo Helper for SentinalCore Isolation

This helper script runs with sudo privileges to enable enhanced isolation features:
- Chroot jail creation
- Network namespace configuration
- Device node creation
- Filesystem mounting
"""

import os
import sys
import json
import subprocess
import argparse
import logging
from pathlib import Path

def setup_logging():
    """Setup logging for the sudo helper"""
    logging.basicConfig(
        level=logging.INFO,
        format='%(asctime)s - %(name)s - %(levelname)s - %(message)s',
        handlers=[
            logging.FileHandler('/tmp/sentinal_sudo.log'),
            logging.StreamHandler()
        ]
    )

def check_privileges():
    """Check if running with root privileges"""
    if os.geteuid() != 0:
        print("Error: This script must be run with sudo privileges", file=sys.stderr)
        return False
    return True

def create_chroot_environment(config):
    """Create chroot environment with sudo privileges"""
    chroot_dir = config.get('chroot_dir')
    if not chroot_dir:
        return {'success': False, 'error': 'No chroot directory specified'}
    
    try:
        # Create directory structure
        os.makedirs(chroot_dir, exist_ok=True)
        
        # Create essential directories
        essential_dirs = ['bin', 'lib', 'lib64', 'usr/bin', 'usr/lib', 'usr/lib64', 'etc', 'dev', 'proc', 'tmp']
        for dir_name in essential_dirs:
            dir_path = os.path.join(chroot_dir, dir_name)
            os.makedirs(dir_path, exist_ok=True)
        
        # Copy essential binaries and libraries
        _copy_essential_binaries(chroot_dir)
        
        # Create device nodes
        device_nodes = [
            ('dev/null', 'c', 1, 3, 0o666),
            ('dev/zero', 'c', 1, 5, 0o666),
            ('dev/random', 'c', 1, 8, 0o644),
            ('dev/urandom', 'c', 1, 9, 0o644)
        ]
        
        for device, dev_type, major, minor, mode in device_nodes:
            device_path = os.path.join(chroot_dir, device)
            try:
                subprocess.run([
                    'mknod', device_path, dev_type, str(major), str(minor)
                ], check=True)
                os.chmod(device_path, mode)
            except subprocess.CalledProcessError as e:
                logging.warning(f"Failed to create device {device}: {e}")
        
        # Mount essential filesystems
        mounts = [
            ('proc', os.path.join(chroot_dir, 'proc'), 'proc'),
            ('tmpfs', os.path.join(chroot_dir, 'tmp'), 'tmpfs')
        ]
        
        for source, target, fs_type in mounts:
            try:
                subprocess.run(['mount', '-t', fs_type, source, target], check=True)
                logging.info(f"Mounted {source} at {target}")
            except subprocess.CalledProcessError as e:
                logging.warning(f"Failed to mount {source} at {target}: {e}")
        
        return {'success': True, 'chroot_dir': chroot_dir}
        
    except Exception as e:
        return {'success': False, 'error': f'Chroot setup failed: {str(e)}'}

def _copy_samples_to_chroot(command, chroot_dir):
    """Copy sample files referenced in command into chroot and return modified command"""
    import shutil
    
    new_command = []
    
    for arg in command:
        # Check if argument is a file path that needs to be copied
        if (isinstance(arg, str) and 
            '/' in arg and 
            os.path.exists(arg) and 
            os.path.isfile(arg)):
            
            # Create destination path in chroot
            filename = os.path.basename(arg)
            chroot_path = f"/tmp/{filename}"
            chroot_full_path = os.path.join(chroot_dir, chroot_path.lstrip('/'))
            
            try:
                # Copy file into chroot
                shutil.copy2(arg, chroot_full_path)
                os.chmod(chroot_full_path, 0o755)  # Make executable
                logging.info(f"Copied sample {arg} to chroot at {chroot_path}")
                
                # Use chroot path in command
                new_command.append(chroot_path)
            except Exception as e:
                logging.error(f"Failed to copy {arg} to chroot: {e}")
                # Fall back to original path (will likely fail)
                new_command.append(arg)
        else:
            # Keep non-file arguments as-is
            new_command.append(arg)
    
    return new_command

def _copy_essential_binaries(chroot_dir):
    """Copy essential binaries and libraries into chroot"""
    import subprocess
    import shutil
    
    # Essential binaries to copy
    binaries = ['/bin/bash', '/bin/sh', '/usr/bin/python3', '/bin/ls', '/bin/cat', 
               '/bin/echo', '/usr/bin/env', '/bin/ps', '/usr/bin/id', '/bin/pwd',
               '/usr/bin/which', '/bin/grep', '/bin/sed', '/bin/awk']
    
    for binary in binaries:
        if os.path.exists(binary):
            try:
                dest_dir = os.path.join(chroot_dir, os.path.dirname(binary).lstrip('/'))
                os.makedirs(dest_dir, exist_ok=True)
                dest_path = os.path.join(chroot_dir, binary.lstrip('/'))
                shutil.copy2(binary, dest_path)
                
                # Copy shared libraries for this binary
                try:
                    result = subprocess.run(['ldd', binary], capture_output=True, text=True)
                    for line in result.stdout.split('\n'):
                        line = line.strip()
                        if '=>' in line and '/' in line:
                            lib_path = line.split('=>')[1].strip().split()[0]
                            if lib_path and os.path.exists(lib_path):
                                lib_dest_dir = os.path.join(chroot_dir, os.path.dirname(lib_path).lstrip('/'))
                                os.makedirs(lib_dest_dir, exist_ok=True)
                                lib_dest = os.path.join(chroot_dir, lib_path.lstrip('/'))
                                if not os.path.exists(lib_dest):
                                    shutil.copy2(lib_path, lib_dest)
                                    logging.debug(f"Copied library {lib_path}")
                        elif line.startswith('/') and '(' in line:
                            # Handle direct library paths like /lib64/ld-linux-x86-64.so.2
                            lib_path = line.split()[0]
                            if lib_path and os.path.exists(lib_path):
                                lib_dest_dir = os.path.join(chroot_dir, os.path.dirname(lib_path).lstrip('/'))
                                os.makedirs(lib_dest_dir, exist_ok=True)
                                lib_dest = os.path.join(chroot_dir, lib_path.lstrip('/'))
                                if not os.path.exists(lib_dest):
                                    shutil.copy2(lib_path, lib_dest)
                                    logging.debug(f"Copied library {lib_path}")
                except Exception as e:
                    logging.warning(f"Failed to copy libraries for {binary}: {e}")
                    
                logging.info(f"Copied {binary} to chroot")
            except Exception as e:
                logging.warning(f"Failed to copy {binary}: {e}")
    
    # Ensure dynamic linker is available in both usr/lib64 and lib64 
    linker_usr_path = os.path.join(chroot_dir, 'usr/lib64/ld-linux-x86-64.so.2')
    linker_lib64_path = os.path.join(chroot_dir, 'lib64/ld-linux-x86-64.so.2')
    
    if os.path.exists(linker_usr_path) and not os.path.exists(linker_lib64_path):
        try:
            shutil.copy2(linker_usr_path, linker_lib64_path)
            logging.info("Ensured dynamic linker is available in /lib64")
        except Exception as e:
            logging.warning(f"Failed to ensure dynamic linker availability: {e}")
    
    # Copy essential Python modules for basic functionality
    python_paths = [
        '/usr/lib/python3.*/encodings',
        '/usr/lib/python3.*/codecs.py', 
        '/usr/lib/python3.*/collections',
        '/usr/lib/python3.*/_collections_abc.py',
        '/usr/lib/python3.*/os.py',
        '/usr/lib/python3.*/sys.py',
        '/usr/lib/python3.*/io.py'
    ]
    
    import glob
    try:
        chroot_python_lib = os.path.join(chroot_dir, 'usr/lib')
        for pattern in python_paths:
            for path in glob.glob(pattern):
                if os.path.exists(path):
                    rel_path = os.path.relpath(path, '/')
                    dest_path = os.path.join(chroot_dir, rel_path)
                    dest_dir = os.path.dirname(dest_path)
                    os.makedirs(dest_dir, exist_ok=True)
                    if os.path.isdir(path):
                        if not os.path.exists(dest_path):
                            shutil.copytree(path, dest_path)
                    else:
                        if not os.path.exists(dest_path):
                            shutil.copy2(path, dest_path)
        logging.info("Added basic Python modules to chroot")
    except Exception as e:
        logging.warning(f"Failed to copy Python modules: {e}")

def cleanup_chroot_environment(config):
    """Cleanup chroot environment"""
    chroot_dir = config.get('chroot_dir')
    if not chroot_dir or not os.path.exists(chroot_dir):
        return {'success': True, 'message': 'Nothing to cleanup'}
    
    try:
        # Unmount filesystems
        mount_points = [
            os.path.join(chroot_dir, 'proc'),
            os.path.join(chroot_dir, 'tmp')
        ]
        
        for mount_point in mount_points:
            try:
                subprocess.run(['umount', mount_point], 
                             stderr=subprocess.DEVNULL, check=False)
            except:
                pass
        
        # Remove directory
        subprocess.run(['rm', '-rf', chroot_dir], check=True)
        
        return {'success': True, 'message': f'Cleaned up {chroot_dir}'}
        
    except Exception as e:
        return {'success': False, 'error': f'Cleanup failed: {str(e)}'}

def setup_network_namespace(config):
    """Setup network namespace with proper isolation"""
    try:
        # Create network namespace
        ns_name = config.get('namespace_name', 'sentinal_ns')
        
        # Create namespace
        subprocess.run(['ip', 'netns', 'add', ns_name], check=True)
        
        # Setup loopback in namespace
        subprocess.run(['ip', 'netns', 'exec', ns_name, 'ip', 'link', 'set', 'lo', 'up'], check=True)
        
        return {'success': True, 'namespace': ns_name}
        
    except subprocess.CalledProcessError as e:
        return {'success': False, 'error': f'Network namespace setup failed: {str(e)}'}

def cleanup_network_namespace(config):
    """Cleanup network namespace"""
    try:
        ns_name = config.get('namespace_name', 'sentinal_ns')
        subprocess.run(['ip', 'netns', 'delete', ns_name], 
                      stderr=subprocess.DEVNULL, check=False)
        return {'success': True, 'message': f'Cleaned up namespace {ns_name}'}
    except Exception as e:
        return {'success': False, 'error': f'Namespace cleanup failed: {str(e)}'}

def execute_in_isolation(config):
    """Execute command with full sudo-enabled isolation"""
    command = config.get('command', [])
    chroot_dir = config.get('chroot_dir')
    timeout = config.get('timeout', 60)
    use_namespaces = config.get('use_namespaces', False)
    namespace_config = config.get('namespace_config', {})
    working_dir = config.get('working_dir', '/tmp')
    
    if not command:
        return {'success': False, 'error': 'No command specified'}
    
    try:
        # Build execution command
        if use_namespaces:
            # Build unshare command with namespaces
            exec_command = ['unshare']
            
            if namespace_config.get('use_pid_ns', False):
                exec_command.extend(['--pid', '--fork'])
            
            if namespace_config.get('use_mount_ns', False):
                exec_command.append('--mount')
                
            if namespace_config.get('use_net_ns', False):
                exec_command.append('--net')
                
            if namespace_config.get('use_user_ns', False):
                exec_command.append('--user')
                
            if namespace_config.get('use_ipc_ns', False):
                exec_command.append('--ipc')
                
            if namespace_config.get('use_uts_ns', False):
                exec_command.append('--uts')
            
            # Add chroot if specified
            if chroot_dir:
                chroot_result = create_chroot_environment(config)
                if not chroot_result['success']:
                    return chroot_result
                    
                # Copy sample files into chroot
                chrooted_command = _copy_samples_to_chroot(command, chroot_dir)
                exec_command.extend(['chroot', chroot_dir])
                exec_command.extend(chrooted_command)
            else:
                exec_command.extend(command)
        else:
            # Setup chroot if specified
            if chroot_dir:
                chroot_result = create_chroot_environment(config)
                if not chroot_result['success']:
                    return chroot_result
                    
                # Copy sample files into chroot
                chrooted_command = _copy_samples_to_chroot(command, chroot_dir)
                exec_command = ['chroot', chroot_dir] + chrooted_command
            else:
                exec_command = command
        
        logging.info(f"Executing with sudo: {' '.join(exec_command)}")
        
        result = subprocess.run(
            exec_command,
            capture_output=True,
            text=True,
            timeout=timeout,
            cwd=working_dir
        )
        
        execution_result = {
            'success': True,
            'returncode': result.returncode,
            'stdout': result.stdout,
            'stderr': result.stderr,
            'timed_out': False
        }
        
        # Cleanup
        if chroot_dir:
            cleanup_chroot_environment(config)
        
        return execution_result
        
    except subprocess.TimeoutExpired:
        # Cleanup on timeout
        if chroot_dir:
            cleanup_chroot_environment(config)
        
        return {
            'success': True,
            'returncode': -1,
            'stdout': '',
            'stderr': 'Command timed out',
            'timed_out': True
        }
    except Exception as e:
        # Cleanup on error
        if chroot_dir:
            cleanup_chroot_environment(config)
            
        return {'success': False, 'error': f'Execution failed: {str(e)}'}

def main():
    parser = argparse.ArgumentParser(description='SentinalCore Sudo Helper')
    parser.add_argument('action', choices=[
        'create-chroot', 'cleanup-chroot', 'setup-netns', 
        'cleanup-netns', 'execute', 'test'
    ])
    parser.add_argument('--config', type=str, help='JSON configuration string')
    parser.add_argument('--config-file', type=str, help='Configuration file path')
    
    args = parser.parse_args()
    
    setup_logging()
    
    if not check_privileges():
        sys.exit(1)
    
    # Load configuration
    config = {}
    if args.config:
        try:
            config = json.loads(args.config)
        except json.JSONDecodeError as e:
            print(f"Error: Invalid JSON config: {e}", file=sys.stderr)
            sys.exit(1)
    elif args.config_file:
        try:
            with open(args.config_file, 'r') as f:
                config = json.load(f)
        except Exception as e:
            print(f"Error: Could not read config file: {e}", file=sys.stderr)
            sys.exit(1)
    else:
        # Read from stdin if no config provided
        try:
            stdin_data = sys.stdin.read().strip()
            if stdin_data:
                config = json.loads(stdin_data)
        except json.JSONDecodeError as e:
            print(f"Error: Invalid JSON from stdin: {e}", file=sys.stderr)
            sys.exit(1)
        except Exception as e:
            print(f"Error: Could not read from stdin: {e}", file=sys.stderr)
            sys.exit(1)
    
    # Execute action
    if args.action == 'create-chroot':
        result = create_chroot_environment(config)
    elif args.action == 'cleanup-chroot':
        result = cleanup_chroot_environment(config)
    elif args.action == 'setup-netns':
        result = setup_network_namespace(config)
    elif args.action == 'cleanup-netns':
        result = cleanup_network_namespace(config)
    elif args.action == 'execute':
        result = execute_in_isolation(config)
    elif args.action == 'test':
        result = {
            'success': True,
            'message': 'Sudo helper is working correctly',
            'uid': os.getuid(),
            'gid': os.getgid()
        }
    
    # Output result as JSON
    print(json.dumps(result, indent=2))
    
    if not result.get('success', False):
        sys.exit(1)

if __name__ == '__main__':
    main()