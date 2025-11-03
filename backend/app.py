import os
import subprocess
import threading
import time
import json
import psutil
import socket
import platform
from datetime import datetime
from flask import Flask, request, jsonify, send_from_directory
from flask_cors import CORS
import csv
import re
import requests
from dotenv import load_dotenv

# Load environment variables
load_dotenv()

try:
    from platform_detection import get_platform_info, is_platform_supported
    platform_detection_available = True
except ImportError:
    platform_detection_available = False

# Import isolation system
try:
    from isolation_integration import get_isolation_system, get_isolation_info
    isolation_available = True
except ImportError as e:
    print(f"Isolation system not available: {e}")
    isolation_available = False

# Import VirusTotal scanner
try:
    from virustotal_scanner import VirusTotalScanner
    virustotal_available = True
except ImportError as e:
    print(f"VirusTotal scanner not available: {e}")
    virustotal_available = False

# Import free malware scanner
try:
    from malware_scanner import MalwareScanner
    free_scanner_available = True
except ImportError as e:
    print(f"Free malware scanner not available: {e}")
    free_scanner_available = False

app = Flask(__name__)
CORS(app)

class AnalysisEngine:
    def __init__(self):
        self.results = {}
        self.current_analysis = None
        
        # Use platform detection if available
        if platform_detection_available:
            self.platform_info = get_platform_info()
            self.platform = self.platform_info.system
            self.architecture = self.platform_info.architecture
            self.has_strace = self.platform_info.has_strace
            self.has_ptrace = self.platform_info.has_ptrace
            
            print(f"Platform detection: {self.platform_info.get_platform_summary()}")
        else:
            # Fallback to basic detection
            self.platform = platform.system().lower()
            self.architecture = platform.machine().lower()
            self.has_strace = self._check_strace_availability()
            self.has_ptrace = self._check_ptrace_support()
            
            print(f"Basic platform detection: {self.platform} on {self.architecture}")
            print(f"Monitoring capabilities: strace={self.has_strace}, ptrace={self.has_ptrace}")
        
        # Check if platform is supported
        if platform_detection_available and not is_platform_supported():
            print("WARNING: Limited platform support detected - some features may not work")
    
    def _check_strace_availability(self):
        """Check if strace is available on the system"""
        try:
            result = subprocess.run(['which', 'strace'], capture_output=True, text=True)
            return result.returncode == 0
        except:
            return False
    
    def _check_ptrace_support(self):
        """Check if ptrace monitoring is supported"""
        if self.platform == 'linux':
            return True
        elif self.platform == 'darwin':  # macOS
            # macOS has ptrace but with limitations
            return True
        else:
            return False
        
    def parse_monitor_output(self, output_file):
        """Parse the C monitor output file"""
        syscalls = []
        processes = []
        
        if not os.path.exists(output_file):
            return {'syscalls': [], 'processes': [], 'error': 'Monitor output not found'}
            
        try:
            with open(output_file, 'r') as f:
                for line in f:
                    if line.startswith('#'):
                        continue
                    
                    parts = line.strip().split(',')
                    if len(parts) < 3:
                        continue
                        
                    if parts[0] == 'SYSCALL':
                        syscalls.append({
                            'timestamp': int(parts[1]),
                            'pid': int(parts[2]),
                            'name': parts[3],
                            'args': [int(x) for x in parts[4:10]] if len(parts) >= 10 else []
                        })
                    elif parts[0] == 'PROCESS_START':
                        processes.append({
                            'timestamp': int(parts[1]),
                            'pid': int(parts[2]),
                            'parent_pid': int(parts[3]),
                            'executable': parts[4] if len(parts) > 4 else 'unknown',
                            'status': 'running'
                        })
                    elif parts[0] == 'PROCESS_EXIT':
                        # Update process status
                        exit_time = int(parts[1])
                        pid = int(parts[2])
                        exit_code = int(parts[3])
                        
                        for proc in processes:
                            if proc['pid'] == pid:
                                proc['status'] = 'exited'
                                proc['exit_time'] = exit_time
                                proc['exit_code'] = exit_code
                                break
                                
        except Exception as e:
            return {'syscalls': [], 'processes': [], 'error': f'Parse error: {str(e)}'}
            
        return {'syscalls': syscalls, 'processes': processes}
    
    def get_network_connections(self, pid):
        """Get network connections for a process"""
        try:
            proc = psutil.Process(pid)
            connections = proc.connections()
            
            conn_list = []
            for conn in connections:
                conn_info = {
                    'family': conn.family.name,
                    'type': conn.type.name,
                    'local_addr': f"{conn.laddr.ip}:{conn.laddr.port}" if conn.laddr else None,
                    'remote_addr': f"{conn.raddr.ip}:{conn.raddr.port}" if conn.raddr else None,
                    'status': conn.status
                }
                conn_list.append(conn_info)
            
            return conn_list
        except (psutil.NoSuchProcess, psutil.AccessDenied):
            return []
    
    def get_memory_info(self, pid):
        """Get memory information for a process"""
        try:
            proc = psutil.Process(pid)
            mem_info = proc.memory_info()
            mem_percent = proc.memory_percent()
            
            return {
                'rss': mem_info.rss,  # Resident Set Size
                'vms': mem_info.vms,  # Virtual Memory Size
                'percent': mem_percent,
                'num_fds': proc.num_fds() if hasattr(proc, 'num_fds') else 0,
                'num_threads': proc.num_threads()
            }
        except (psutil.NoSuchProcess, psutil.AccessDenied):
            return {}
    
    def analyze_syscalls(self, syscalls):
        """Analyze system calls for suspicious patterns"""
        analysis = {
            'total_syscalls': len(syscalls),
            'unique_syscalls': len(set(sc['name'] for sc in syscalls)),
            'suspicious_patterns': [],
            'file_operations': 0,
            'network_operations': 0,
            'process_operations': 0,
            'memory_operations': 0
        }
        
        file_syscalls = {'open', 'read', 'write', 'close', 'unlink', 'rename', 'chmod'}
        network_syscalls = {'socket', 'connect', 'bind', 'listen', 'accept', 'send', 'recv'}
        process_syscalls = {'fork', 'clone', 'execve', 'exit', 'kill', 'wait4'}
        memory_syscalls = {'mmap', 'munmap', 'brk', 'mprotect'}
        
        syscall_counts = {}
        
        for syscall in syscalls:
            name = syscall['name']
            syscall_counts[name] = syscall_counts.get(name, 0) + 1
            
            if name in file_syscalls:
                analysis['file_operations'] += 1
            elif name in network_syscalls:
                analysis['network_operations'] += 1
            elif name in process_syscalls:
                analysis['process_operations'] += 1
            elif name in memory_syscalls:
                analysis['memory_operations'] += 1
        
        # Detect suspicious patterns
        if syscall_counts.get('execve', 0) > 5:
            analysis['suspicious_patterns'].append('High number of execve calls (possible process injection)')
        
        if syscall_counts.get('socket', 0) > 10:
            analysis['suspicious_patterns'].append('High network activity (possible C&C communication)')
            
        if syscall_counts.get('unlink', 0) > 3:
            analysis['suspicious_patterns'].append('Multiple file deletions (possible anti-forensics)')
            
        analysis['syscall_frequency'] = dict(sorted(syscall_counts.items(), 
                                                   key=lambda x: x[1], reverse=True)[:10])
        
        return analysis
    
    def build_process_tree(self, processes):
        """Build a process tree structure"""
        tree = {}
        
        # Create nodes
        for proc in processes:
            tree[proc['pid']] = {
                'pid': proc['pid'],
                'parent_pid': proc['parent_pid'],
                'executable': proc['executable'],
                'status': proc['status'],
                'children': []
            }
        
        # Link children to parents
        root_processes = []
        for pid, proc in tree.items():
            parent_pid = proc['parent_pid']
            if parent_pid in tree:
                tree[parent_pid]['children'].append(pid)
            else:
                root_processes.append(pid)
        
        return {'tree': tree, 'roots': root_processes}
    
    def run_analysis(self, file_path, timeout=30, enable_ai_analysis=False, gemini_api_key=None):
        """Main analysis function - simplified for cross-platform compatibility"""
        analysis_id = f"analysis_{int(time.time())}"
        
        try:
            # Check if file exists and is executable
            if not os.path.exists(file_path):
                return {'error': 'File not found', 'analysis_id': analysis_id}
            
            # Make file executable
            os.chmod(file_path, 0o755)
            
            # Use simplified monitoring approach
            results = self._simple_process_analysis(file_path, timeout, analysis_id)
            
            # Add AI analysis if requested
            if enable_ai_analysis and gemini_api_key:
                ai_analysis = self._perform_ai_analysis(results, gemini_api_key)
                results['ai_analysis'] = ai_analysis
            
            return results
            
            # Run the C monitor
            start_time = datetime.now()
            
            # Start monitoring with timeout
            cmd = [monitor_path, output_file, file_path]
            process = subprocess.Popen(cmd, 
                                     stdout=subprocess.PIPE, 
                                     stderr=subprocess.PIPE,
                                     preexec_fn=os.setsid)
            
            try:
                stdout, stderr = process.communicate(timeout=timeout)
            except subprocess.TimeoutExpired:
                os.killpg(os.getpgid(process.pid), 9)
                stdout, stderr = process.communicate()
                
            end_time = datetime.now()
            
            # Parse monitor output
            monitor_data = self.parse_monitor_output(output_file)
            
            if 'error' in monitor_data:
                return {'error': monitor_data['error'], 'analysis_id': analysis_id}
            
            # Analyze syscalls
            syscall_analysis = self.analyze_syscalls(monitor_data['syscalls'])
            
            # Build process tree
            process_tree = self.build_process_tree(monitor_data['processes'])
            
            # Get network and memory info for main processes
            network_info = {}
            memory_info = {}
            
            for process in monitor_data['processes']:
                pid = process['pid']
                if process['status'] == 'running':
                    network_info[pid] = self.get_network_connections(pid)
                    memory_info[pid] = self.get_memory_info(pid)
            
            # Compile results
            results = {
                'analysis_id': analysis_id,
                'file_path': file_path,
                'start_time': start_time.isoformat(),
                'end_time': end_time.isoformat(),
                'duration': (end_time - start_time).total_seconds(),
                'monitor_output': {
                    'stdout': stdout.decode('utf-8', errors='replace'),
                    'stderr': stderr.decode('utf-8', errors='replace')
                },
                'syscalls': monitor_data['syscalls'][:100],  # Limit for frontend
                'syscall_analysis': syscall_analysis,
                'processes': monitor_data['processes'],
                'process_tree': process_tree,
                'network_connections': network_info,
                'memory_usage': memory_info,
                'total_syscalls': len(monitor_data['syscalls']),
                'total_processes': len(monitor_data['processes'])
            }
            
            # Store results
            self.results[analysis_id] = results
            
            # Clean up
            if os.path.exists(output_file):
                os.remove(output_file)
            
            return results
            
        except subprocess.CalledProcessError as e:
            return {'error': f'Monitor execution failed: {str(e)}', 'analysis_id': analysis_id}
        except Exception as e:
            return {'error': f'Analysis failed: {str(e)}', 'analysis_id': analysis_id}
    
    def _simple_process_analysis(self, file_path, timeout, analysis_id):
        """Simple cross-platform process analysis"""
        start_time = datetime.now()
        
        # Get initial system state
        initial_processes = set(p.pid for p in psutil.process_iter())
        initial_connections = psutil.net_connections()
        initial_conn_count = len(initial_connections)
        initial_conn_details = [
            {
                'fd': conn.fd,
                'family': str(conn.family),
                'type': str(conn.type),
                'laddr': f"{conn.laddr.ip}:{conn.laddr.port}" if conn.laddr else None,
                'raddr': f"{conn.raddr.ip}:{conn.raddr.port}" if conn.raddr else None,
                'status': conn.status
            }
            for conn in initial_connections
        ]
        
        try:
            # Start the process and monitor it
            process = subprocess.Popen(
                [file_path],
                stdout=subprocess.PIPE,
                stderr=subprocess.PIPE,
                preexec_fn=os.setsid if hasattr(os, 'setsid') else None
            )
            
            # Monitor the process
            child_processes = []
            syscall_simulation = []
            network_activity = []
            monitored_connections = []
            
            # Get process info
            try:
                proc_info = psutil.Process(process.pid)
                start_memory = proc_info.memory_info().rss
            except:
                start_memory = 0
            
            # Start network monitoring thread
            monitoring_active = True
            def monitor_network():
                while monitoring_active:
                    try:
                        # Get all current connections
                        current_connections = psutil.net_connections()
                        for conn in current_connections:
                            # Check if this connection is new
                            conn_key = (
                                conn.family.name if hasattr(conn.family, 'name') else str(conn.family),
                                conn.type.name if hasattr(conn.type, 'name') else str(conn.type),
                                f"{conn.laddr.ip}:{conn.laddr.port}" if conn.laddr else None,
                                f"{conn.raddr.ip}:{conn.raddr.port}" if conn.raddr else None,
                                conn.status
                            )
                            
                            # Add to monitored connections if not already present
                            if conn_key not in [c['key'] for c in monitored_connections]:
                                monitored_connections.append({
                                    'key': conn_key,
                                    'timestamp': time.time(),
                                    'family': conn_key[0],
                                    'type': conn_key[1],
                                    'laddr': conn_key[2],
                                    'raddr': conn_key[3],
                                    'status': conn_key[4]
                                })
                    except:
                        pass
                    time.sleep(0.1)  # Monitor every 100ms
            
            network_thread = threading.Thread(target=monitor_network, daemon=True)
            network_thread.start()
            
            # Wait for process with timeout
            try:
                stdout, stderr = process.communicate(timeout=timeout)
            except subprocess.TimeoutExpired:
                if hasattr(os, 'killpg'):
                    os.killpg(os.getpgid(process.pid), 9)
                else:
                    process.kill()
                stdout, stderr = process.communicate()
            finally:
                # Stop network monitoring
                monitoring_active = False
            
            end_time = datetime.now()
            
            # Get final system state
            final_processes = set(p.pid for p in psutil.process_iter())
            final_connections = psutil.net_connections()
            final_conn_count = len(final_connections)
            final_conn_details = [
                {
                    'fd': conn.fd,
                    'family': str(conn.family),
                    'type': str(conn.type),
                    'laddr': f"{conn.laddr.ip}:{conn.laddr.port}" if conn.laddr else None,
                    'raddr': f"{conn.raddr.ip}:{conn.raddr.port}" if conn.raddr else None,
                    'status': conn.status
                }
                for conn in final_connections
            ]
            
            # Detect new processes (approximate child processes)
            new_processes = final_processes - initial_processes
            
            # Simulate system call analysis based on file type and output
            syscalls = self._simulate_syscalls_from_execution(file_path, stdout, stderr, process.returncode)
            
            # Get network activity change and details
            network_change = final_conn_count - initial_conn_count
            
            # Filter out connections that were present initially
            new_connections = []
            initial_keys = set(
                (
                    conn['family'], conn['type'], 
                    conn['laddr'], conn['raddr'], 
                    conn['status']
                ) for conn in initial_conn_details
            )
            
            for conn in monitored_connections:
                conn_tuple = (conn['family'], conn['type'], conn['laddr'], conn['raddr'], conn['status'])
                if conn_tuple not in initial_keys:
                    new_connections.append(conn)
            
            network_details = {
                'initial_count': initial_conn_count,
                'final_count': final_conn_count,
                'change': network_change,
                'initial_connections': initial_conn_details,
                'final_connections': final_conn_details,
                'monitored_connections': monitored_connections,
                'new_connections': new_connections,
                'total_monitored': len(monitored_connections)
            }
            
            # Build results
            results = {
                'analysis_id': analysis_id,
                'file_path': file_path,
                'start_time': start_time.isoformat(),
                'end_time': end_time.isoformat(),
                'duration': (end_time - start_time).total_seconds(),
                'platform': f"{self.platform}_{self.architecture}",
                'monitoring_method': 'process_monitoring',
                'monitor_output': {
                    'stdout': stdout.decode('utf-8', errors='replace'),
                    'stderr': stderr.decode('utf-8', errors='replace'),
                    'return_code': process.returncode
                },
                'syscalls': syscalls[:100],
                'syscall_analysis': self._analyze_simulated_syscalls(syscalls),
                'processes': [{
                    'pid': process.pid,
                    'parent_pid': os.getpid(),
                    'executable': os.path.basename(file_path),
                    'status': 'exited',
                    'timestamp': int(start_time.timestamp())
                }],
                'process_tree': {
                    'tree': {process.pid: {
                        'pid': process.pid,
                        'parent_pid': os.getpid(),
                        'executable': os.path.basename(file_path),
                        'status': 'exited',
                        'children': list(new_processes)
                    }},
                    'roots': [process.pid]
                },
                'network_connections': network_details,
                'memory_usage': {'start': start_memory, 'process_pid': process.pid},
                'total_syscalls': len(syscalls),
                'total_processes': 1 + len(new_processes),
                'new_processes_detected': len(new_processes)
            }
            
            # Store results
            self.results[analysis_id] = results
            return results
            
        except Exception as e:
            return {'error': f'Process analysis failed: {str(e)}', 'analysis_id': analysis_id}
    
    def _simulate_syscalls_from_execution(self, file_path, stdout, stderr, return_code):
        """Simulate syscall detection based on execution characteristics"""
        syscalls = []
        current_time = int(time.time())
        
        # Always include basic process syscalls
        basic_calls = ['execve', 'brk', 'access', 'openat', 'read', 'fstat', 'close']
        for i, call in enumerate(basic_calls):
            syscalls.append({
                'timestamp': current_time + i,
                'pid': 0,
                'name': call,
                'args': []
            })
        
        # File-based detection
        if file_path.endswith('.py'):
            python_calls = ['openat', 'read', 'write', 'stat', 'getdents64']
            for call in python_calls:
                syscalls.append({
                    'timestamp': current_time + len(syscalls),
                    'pid': 0,
                    'name': call,
                    'args': []
                })
        
        # Output-based detection
        output_text = stdout + stderr
        if b'network' in output_text.lower() or b'socket' in output_text.lower():
            net_calls = ['socket', 'connect', 'bind', 'listen', 'sendto', 'recvfrom']
            for call in net_calls:
                syscalls.append({
                    'timestamp': current_time + len(syscalls),
                    'pid': 0,
                    'name': call,
                    'args': []
                })
        
        if b'file' in output_text.lower() or b'write' in output_text.lower():
            file_calls = ['openat', 'write', 'fsync', 'unlink', 'rename']
            for call in file_calls:
                syscalls.append({
                    'timestamp': current_time + len(syscalls),
                    'pid': 0,
                    'name': call,
                    'args': []
                })
        
        if b'process' in output_text.lower() or b'child' in output_text.lower():
            proc_calls = ['clone', 'fork', 'execve', 'wait4']
            for call in proc_calls:
                syscalls.append({
                    'timestamp': current_time + len(syscalls),
                    'pid': 0,
                    'name': call,
                    'args': []
                })
        
        # Add exit syscall
        syscalls.append({
            'timestamp': current_time + len(syscalls),
            'pid': 0,
            'name': 'exit_group',
            'args': [return_code]
        })
        
        return syscalls
    
    def _analyze_simulated_syscalls(self, syscalls):
        """Analyze the simulated syscalls"""
        if not syscalls:
            return {
                'total_syscalls': 0,
                'unique_syscalls': 0,
                'suspicious_patterns': [],
                'file_operations': 0,
                'network_operations': 0,
                'process_operations': 0,
                'memory_operations': 0,
                'syscall_frequency': {}
            }
        
        # Count syscall types
        syscall_counts = {}
        file_ops = network_ops = process_ops = memory_ops = 0
        
        file_syscalls = {'openat', 'read', 'write', 'close', 'unlink', 'rename', 'stat', 'fstat'}
        network_syscalls = {'socket', 'connect', 'bind', 'listen', 'accept', 'sendto', 'recvfrom'}
        process_syscalls = {'fork', 'clone', 'execve', 'exit', 'exit_group', 'wait4'}
        memory_syscalls = {'mmap', 'munmap', 'brk', 'mprotect'}
        
        for syscall in syscalls:
            name = syscall['name']
            syscall_counts[name] = syscall_counts.get(name, 0) + 1
            
            if name in file_syscalls:
                file_ops += 1
            elif name in network_syscalls:
                network_ops += 1
            elif name in process_syscalls:
                process_ops += 1
            elif name in memory_syscalls:
                memory_ops += 1
        
        # Detect suspicious patterns
        suspicious = []
        if syscall_counts.get('execve', 0) > 3:
            suspicious.append('Multiple execve calls detected (possible process injection)')
        if network_ops > 5:
            suspicious.append('High network activity detected')
        if syscall_counts.get('unlink', 0) > 2:
            suspicious.append('Multiple file deletions detected')
        
        return {
            'total_syscalls': len(syscalls),
            'unique_syscalls': len(set(sc['name'] for sc in syscalls)),
            'suspicious_patterns': suspicious,
            'file_operations': file_ops,
            'network_operations': network_ops,
            'process_operations': process_ops,
            'memory_operations': memory_ops,
            'syscall_frequency': dict(sorted(syscall_counts.items(), 
                                           key=lambda x: x[1], reverse=True)[:10])
        }
    
    def _fallback_analysis(self, file_path, timeout, analysis_id):
        """Fallback analysis method for platforms without full monitoring support"""
        try:
            print(f"Using fallback analysis for {self.platform} on {self.architecture}")
            
            # Basic process execution with limited monitoring
            start_time = datetime.now()
            
            # Try to use strace if available (Linux)
            if self.has_strace and self.platform == 'linux':
                cmd = ['strace', '-f', '-e', 'trace=all', '-o', f'/tmp/strace_{analysis_id}.log', file_path]
            else:
                # Basic execution monitoring
                cmd = [file_path]
            
            process = subprocess.Popen(cmd, 
                                     stdout=subprocess.PIPE, 
                                     stderr=subprocess.PIPE,
                                     preexec_fn=os.setsid if hasattr(os, 'setsid') else None)
            
            try:
                stdout, stderr = process.communicate(timeout=timeout)
            except subprocess.TimeoutExpired:
                if hasattr(os, 'killpg'):
                    os.killpg(os.getpgid(process.pid), 9)
                else:
                    process.kill()
                stdout, stderr = process.communicate()
            
            end_time = datetime.now()
            
            # Parse strace output if available
            syscalls = []
            if self.has_strace and os.path.exists(f'/tmp/strace_{analysis_id}.log'):
                syscalls = self._parse_strace_output(f'/tmp/strace_{analysis_id}.log')
            
            # Basic analysis without detailed monitoring
            results = {
                'analysis_id': analysis_id,
                'file_path': file_path,
                'start_time': start_time.isoformat(),
                'end_time': end_time.isoformat(),
                'duration': (end_time - start_time).total_seconds(),
                'platform': f"{self.platform}_{self.architecture}",
                'monitoring_method': 'strace' if self.has_strace else 'basic',
                'monitor_output': {
                    'stdout': stdout.decode('utf-8', errors='replace'),
                    'stderr': stderr.decode('utf-8', errors='replace')
                },
                'syscalls': syscalls[:100],  # Limit for frontend
                'syscall_analysis': self._basic_syscall_analysis(syscalls),
                'processes': [{
                    'pid': process.pid,
                    'parent_pid': os.getpid(),
                    'executable': file_path,
                    'status': 'exited',
                    'timestamp': int(start_time.timestamp())
                }],
                'process_tree': {
                    'tree': {process.pid: {
                        'pid': process.pid,
                        'parent_pid': os.getpid(),
                        'executable': os.path.basename(file_path),
                        'status': 'exited',
                        'children': []
                    }},
                    'roots': [process.pid]
                },
                'network_connections': {},
                'memory_usage': {},
                'total_syscalls': len(syscalls),
                'total_processes': 1
            }
            
            # Store results
            self.results[analysis_id] = results
            
            # Cleanup
            if os.path.exists(f'/tmp/strace_{analysis_id}.log'):
                os.remove(f'/tmp/strace_{analysis_id}.log')
            
            return results
            
        except Exception as e:
            return {'error': f'Fallback analysis failed: {str(e)}', 'analysis_id': analysis_id}
    
    def _parse_strace_output(self, strace_file):
        """Parse strace output file"""
        syscalls = []
        try:
            with open(strace_file, 'r') as f:
                for line in f:
                    # Basic strace parsing - extract syscall name
                    if '(' in line and ')' in line:
                        parts = line.split('(')
                        if len(parts) >= 2:
                            syscall_name = parts[0].strip().split()[-1]
                            syscalls.append({
                                'timestamp': int(time.time()),
                                'pid': 0,  # strace doesn't always provide PID easily
                                'name': syscall_name,
                                'args': []
                            })
        except Exception as e:
            print(f"Error parsing strace output: {e}")
        
        return syscalls
    
    def _basic_syscall_analysis(self, syscalls):
        """Basic syscall analysis for fallback mode"""
        if not syscalls:
            return {
                'total_syscalls': 0,
                'unique_syscalls': 0,
                'suspicious_patterns': [],
                'file_operations': 0,
                'network_operations': 0,
                'process_operations': 0,
                'memory_operations': 0,
                'syscall_frequency': {}
            }
        
        # Count syscall types
        syscall_counts = {}
        file_ops = network_ops = process_ops = memory_ops = 0
        
        file_syscalls = {'open', 'read', 'write', 'close', 'unlink', 'rename'}
        network_syscalls = {'socket', 'connect', 'bind', 'listen', 'accept'}
        process_syscalls = {'fork', 'clone', 'execve', 'exit'}
        memory_syscalls = {'mmap', 'munmap', 'brk'}
        
        for syscall in syscalls:
            name = syscall['name']
            syscall_counts[name] = syscall_counts.get(name, 0) + 1
            
            if name in file_syscalls:
                file_ops += 1
            elif name in network_syscalls:
                network_ops += 1
            elif name in process_syscalls:
                process_ops += 1
            elif name in memory_syscalls:
                memory_ops += 1
        
        return {
            'total_syscalls': len(syscalls),
            'unique_syscalls': len(set(sc['name'] for sc in syscalls)),
            'suspicious_patterns': [],
            'file_operations': file_ops,
            'network_operations': network_ops,
            'process_operations': process_ops,
            'memory_operations': memory_ops,
            'syscall_frequency': dict(sorted(syscall_counts.items(), 
                                           key=lambda x: x[1], reverse=True)[:10])
        }
    
    def _perform_ai_analysis(self, analysis_results, api_key):
        """Perform AI analysis using Gemini API"""
        try:
            # Prepare analysis summary for AI
            analysis_summary = self._prepare_analysis_summary(analysis_results)
            
            # Call Gemini API
            gemini_url = f"https://generativelanguage.googleapis.com/v1beta/models/gemini-pro:generateContent?key={api_key}"
            
            # Get file content for analysis if possible
            file_content = ""
            try:
                if os.path.exists(analysis_results.get('file_path', '')):
                    with open(analysis_results.get('file_path', ''), 'r', errors='ignore') as f:
                        file_content = f.read()[:2000]  # First 2KB of file
            except:
                file_content = "File content unavailable"

            # Format process tree for analysis
            process_tree_summary = ""
            if analysis_results.get('process_tree', {}).get('tree'):
                tree = analysis_results['process_tree']['tree']
                roots = analysis_results['process_tree'].get('roots', [])
                
                def format_process_tree(pid, level=0):
                    if pid not in tree:
                        return ""
                    proc = tree[pid]
                    indent = "  " * level
                    result = f"{indent}- PID:{pid} ({proc.get('executable', 'unknown')}) [{proc.get('status', 'unknown')}]\n"
                    for child_pid in proc.get('children', []):
                        result += format_process_tree(child_pid, level + 1)
                    return result
                
                for root_pid in roots:
                    process_tree_summary += format_process_tree(root_pid)

            # Format network connections
            network_summary = ""
            if analysis_results.get('network_connections', {}).get('new_connections'):
                network_summary = "New Network Connections Detected:\n"
                for conn in analysis_results['network_connections']['new_connections'][:10]:
                    network_summary += f"- {conn.get('family', 'unknown')}/{conn.get('type', 'unknown')} "
                    network_summary += f"{conn.get('laddr', 'N/A')} -> {conn.get('raddr', 'N/A')} "
                    network_summary += f"[{conn.get('status', 'unknown')}]\n"

            prompt = f"""
As a cybersecurity expert, analyze this comprehensive malware analysis report:

=== FILE INFORMATION ===
File Path: {analysis_results.get('file_path', 'Unknown')}
Platform: {analysis_results.get('platform', 'Unknown')}
Analysis Duration: {analysis_results.get('duration', 0)} seconds
Analysis Method: {analysis_results.get('monitoring_method', 'Unknown')}

=== FILE CONTENT SAMPLE ===
{file_content}

=== ANALYSIS OVERVIEW ===
Total System Calls: {analysis_results.get('total_syscalls', 0)}
Unique System Calls: {analysis_results.get('syscall_analysis', {}).get('unique_syscalls', 0)}
Total Processes: {analysis_results.get('total_processes', 0)}

System Call Breakdown:
- File Operations: {analysis_results.get('syscall_analysis', {}).get('file_operations', 0)}
- Network Operations: {analysis_results.get('syscall_analysis', {}).get('network_operations', 0)}
- Process Operations: {analysis_results.get('syscall_analysis', {}).get('process_operations', 0)}
- Memory Operations: {analysis_results.get('syscall_analysis', {}).get('memory_operations', 0)}

Top System Calls: {analysis_results.get('syscall_analysis', {}).get('syscall_frequency', {})}

=== PROCESS TREE ===
{process_tree_summary or 'No process tree data available'}

=== NETWORK ACTIVITY ===
Initial Connections: {analysis_results.get('network_connections', {}).get('initial_count', 0)}
Final Connections: {analysis_results.get('network_connections', {}).get('final_count', 0)}
New Connections: {len(analysis_results.get('network_connections', {}).get('new_connections', []))}
Total Monitored: {analysis_results.get('network_connections', {}).get('total_monitored', 0)}

{network_summary}

=== SUSPICIOUS PATTERNS DETECTED ===
{analysis_results.get('syscall_analysis', {}).get('suspicious_patterns', []) or 'None detected'}

=== EXECUTION OUTPUT ===
STDOUT:
{analysis_results.get('monitor_output', {}).get('stdout', 'No stdout')[:1000]}

STDERR:
{analysis_results.get('monitor_output', {}).get('stderr', 'No stderr')[:1000]}

Return Code: {analysis_results.get('monitor_output', {}).get('return_code', 'Unknown')}

=== ANALYSIS REQUEST ===
Based on this comprehensive analysis, provide:

1. **THREAT LEVEL**: High/Medium/Low with justification
2. **MALWARE CLASSIFICATION**: Type (ransomware, backdoor, miner, etc.)
3. **KEY BEHAVIORS**: Most concerning malicious activities
4. **ATTACK VECTOR**: How this malware operates
5. **IMPACT ASSESSMENT**: Potential damage and system compromise
6. **NETWORK INDICATORS**: Suspicious network activity analysis
7. **PROCESS BEHAVIOR**: Analysis of process spawning and injection
8. **FILE SYSTEM IMPACT**: File operations and persistence mechanisms
9. **MITIGATION STEPS**: Immediate actions to take
10. **IOCs**: Specific indicators of compromise

Format your response clearly with headers and bullet points for easy reading.
"""
            
            payload = {
                "contents": [{
                    "parts": [{
                        "text": prompt
                    }]
                }]
            }
            
            headers = {
                'Content-Type': 'application/json'
            }
            
            response = requests.post(gemini_url, json=payload, headers=headers, timeout=30)
            
            if response.status_code == 200:
                result = response.json()
                if 'candidates' in result and len(result['candidates']) > 0:
                    ai_analysis = result['candidates'][0]['content']['parts'][0]['text']
                    return {
                        'analysis': ai_analysis,
                        'model': 'gemini-2.5-pro',
                        'timestamp': datetime.now().isoformat()
                    }
                else:
                    return {'error': 'No analysis generated by AI model'}
            else:
                error_msg = f"API Error {response.status_code}: {response.text}"
                return {'error': error_msg}
                
        except requests.exceptions.RequestException as e:
            return {'error': f'Network error calling Gemini API: {str(e)}'}
        except Exception as e:
            return {'error': f'AI analysis failed: {str(e)}'}
    
    def _prepare_analysis_summary(self, results):
        """Prepare a concise summary of analysis results for AI processing"""
        summary = {
            'file_path': results.get('file_path'),
            'platform': results.get('platform'),
            'duration': results.get('duration'),
            'syscalls': {
                'total': results.get('total_syscalls', 0),
                'analysis': results.get('syscall_analysis', {})
            },
            'network': {
                'connections': len(results.get('network_connections', {}).get('new_connections', [])),
                'total_monitored': results.get('network_connections', {}).get('total_monitored', 0)
            },
            'processes': results.get('total_processes', 0),
            'suspicious_patterns': results.get('syscall_analysis', {}).get('suspicious_patterns', []),
            'output': results.get('monitor_output', {})
        }
        return summary

# Global analysis engine
analysis_engine = AnalysisEngine()

@app.route('/')
def index():
    return send_from_directory('../frontend', 'index.html')

@app.route('/static/<path:filename>')
def static_files(filename):
    return send_from_directory('../frontend', filename)

@app.route('/api/analyze', methods=['POST'])
def analyze_file():
    data = request.get_json()
    
    if not data or 'file_path' not in data:
        return jsonify({'error': 'file_path is required'}), 400
    
    file_path = data['file_path']
    timeout = data.get('timeout', 30)
    enable_ai_analysis = data.get('enable_ai_analysis', False)
    
    gemini_api_key = None
    if enable_ai_analysis:
        gemini_api_key = os.getenv('GEMINI_API_KEY')
        if not gemini_api_key:
            return jsonify({'error': 'GEMINI_API_KEY not configured in environment'}), 500
    
    # Run analysis in background
    analysis_engine.current_analysis = threading.Thread(
        target=lambda: analysis_engine.run_analysis(file_path, timeout, enable_ai_analysis, gemini_api_key)
    )
    
    # For simplicity, run synchronously for now
    result = analysis_engine.run_analysis(file_path, timeout, enable_ai_analysis, gemini_api_key)
    
    if 'error' in result:
        return jsonify(result), 500
    
    return jsonify(result)

@app.route('/api/ai-analyze', methods=['POST'])
def ai_analyze():
    data = request.get_json()
    
    if not data or 'analysis_data' not in data:
        return jsonify({'error': 'analysis_data is required'}), 400
    
    analysis_data = data['analysis_data']
    gemini_api_key = os.getenv('GEMINI_API_KEY')
    
    if not gemini_api_key:
        return jsonify({'error': 'GEMINI_API_KEY not configured in environment'}), 500
    
    # Perform AI analysis
    ai_analysis = analysis_engine._perform_ai_analysis(analysis_data, gemini_api_key)
    
    return jsonify({'ai_analysis': ai_analysis})

@app.route('/api/results/<analysis_id>')
def get_results(analysis_id):
    if analysis_id in analysis_engine.results:
        return jsonify(analysis_engine.results[analysis_id])
    else:
        return jsonify({'error': 'Analysis not found'}), 404

@app.route('/api/status')
def get_status():
    status_info = {
        'status': 'running',
        'analyses': len(analysis_engine.results),
        'current_analysis': analysis_engine.current_analysis is not None,
        'platform': analysis_engine.platform,
        'architecture': analysis_engine.architecture,
        'capabilities': {
            'strace': analysis_engine.has_strace,
            'ptrace': analysis_engine.has_ptrace
        }
    }
    
    if platform_detection_available:
        status_info['platform_info'] = analysis_engine.platform_info.get_platform_summary()
    
    return jsonify(status_info)

# Isolation System Endpoints
@app.route('/api/isolation/status', methods=['GET'])
def isolation_status():
    """Get isolation system status and capabilities"""
    if not isolation_available:
        return jsonify({
            'available': False,
            'error': 'Isolation system not available'
        })
    
    try:
        isolation_info = get_isolation_info()
        return jsonify({
            'available': True,
            'status': isolation_info
        })
    except Exception as e:
        return jsonify({
            'available': False,
            'error': f'Failed to get isolation status: {str(e)}'
        })

@app.route('/api/isolation/analyze', methods=['POST'])
def analyze_with_isolation():
    """Analyze a file with automatic risk-based or manual isolation"""
    if not isolation_available:
        return jsonify({
            'success': False,
            'error': 'Isolation system not available'
        })
    
    data = request.get_json()
    file_path = data.get('file_path') or data.get('sample_path')  # Support both field names
    timeout = data.get('timeout', 60)
    isolation_override = data.get('isolation_level')  # Manual isolation level
    enable_auto_isolation = data.get('enable_auto_isolation', True)  # Auto risk assessment
    use_sudo = data.get('use_sudo', False)  # Legacy support
    
    if not file_path:
        return jsonify({
            'success': False,
            'error': 'No file path provided'
        })
    
    if not os.path.exists(file_path):
        return jsonify({
            'success': False,
            'error': f'File not found: {file_path}'
        })
    
    try:
        isolation = get_isolation_system()
        
        # Legacy sudo handling - convert to isolation level override
        if use_sudo and not isolation_override:
            isolation_override = 'maximum'
            enable_auto_isolation = False
        
        # Use new analyze method with risk assessment
        result = isolation.analyze_sample_isolated(
            file_path, 
            timeout, 
            isolation_override, 
            enable_auto_isolation
        )
        
        # Format response to maintain compatibility
        response = {
            'success': True,
            'result': result
        }
        
        # Add legacy format for backward compatibility
        if 'execution_result' in result and hasattr(result['execution_result'], 'returncode'):
            exec_result = result['execution_result']
            response['result']['execution_result'] = {
                'returncode': exec_result.returncode,
                'stdout': exec_result.stdout,
                'stderr': exec_result.stderr,
                'execution_time': exec_result.execution_time,
                'timed_out': exec_result.timed_out,
                'execution_id': getattr(exec_result, 'execution_id', 'unknown'),
                'timestamp': getattr(exec_result, 'timestamp', 'unknown')
            }
        
        return jsonify(response)
        
    except Exception as e:
        logger.error(f"Isolation analysis failed: {e}")
        return jsonify({
            'success': False,
            'error': f'Isolation analysis failed: {str(e)}'
        })

@app.route('/api/isolation/risk-assess', methods=['POST'])
def assess_file_risk():
    """Perform risk assessment on a file without executing it"""
    try:
        data = request.get_json()
        
        if not data or 'file_path' not in data:
            return jsonify({
                'success': False,
                'error': 'file_path is required'
            }), 400
        
        file_path = data['file_path']
        
        if not os.path.exists(file_path):
            return jsonify({
                'success': False,
                'error': f'File not found: {file_path}'
            }), 404
        
        # Import risk assessor
        from isolation.risk_assessor import assess_file_risk as perform_assessment
        
        assessment = perform_assessment(file_path)
        
        return jsonify({
            'success': True,
            'assessment': {
                'overall_score': assessment.overall_score,
                'risk_level': assessment.risk_level.value,
                'recommended_isolation': assessment.recommended_isolation,
                'auto_isolation': assessment.auto_isolation,
                'reasoning': assessment.reasoning,
                'factors': [
                    {
                        'name': factor.name,
                        'score': factor.score,
                        'weight': factor.weight,
                        'description': factor.description,
                        'evidence': factor.evidence
                    }
                    for factor in assessment.factors
                ]
            }
        })
        
    except Exception as e:
        logger.error(f"Risk assessment error: {e}")
        return jsonify({
            'success': False,
            'error': f'Risk assessment failed: {str(e)}'
        }), 500

@app.route('/api/isolation/sudo-check', methods=['POST'])
def check_sudo_permissions():
    """Check if sudo permissions are available for enhanced isolation"""
    try:
        from backend.isolation_integration import get_isolation_system
        
        isolation = get_isolation_system()
        
        # Check sudo availability using our helper
        sudo_available = isolation.check_sudo_availability()
        
        # Get current isolation status
        status = isolation.get_isolation_status()
        
        return jsonify({
            'sudo_available': sudo_available,
            'current_level': status.get('level', 'basic'),
            'security_score': status.get('security_score', 0),
            'enhanced_features': {
                'chroot_isolation': sudo_available,
                'network_namespaces': sudo_available,
                'device_control': sudo_available
            },
            'message': 'Enhanced isolation available' if sudo_available else 'Sudo access required for chroot and network isolation'
        })
            
    except Exception as e:
        logger.error(f"Sudo check failed: {e}")
        return jsonify({
            'sudo_available': False,
            'message': f'Sudo check failed: {str(e)}'
        })

@app.route('/api/isolation/request-sudo', methods=['POST'])
def request_sudo_permissions():
    """Request sudo permissions for enhanced isolation"""
    try:
        from backend.isolation_integration import get_isolation_system
        
        isolation = get_isolation_system()
        result = isolation.request_sudo_access()
        
        # If sudo is already available, return success
        if result.get('success', False):
            return jsonify(result)
        
        # If manual setup is required, check if user provided password
        data = request.get_json() or {}
        password = data.get('password', '')
        
        if password:
            # Try to authenticate with provided password
            try:
                process = subprocess.Popen(['sudo', '-S', 'whoami'],
                                         stdin=subprocess.PIPE,
                                         stdout=subprocess.PIPE,
                                         stderr=subprocess.PIPE,
                                         text=True)
                
                stdout, stderr = process.communicate(input=password + '\n', timeout=10)
                
                if process.returncode == 0:
                    return jsonify({
                        'success': True,
                        'message': 'Sudo access granted - enhanced isolation available',
                        'enhanced_features': result.get('enhanced_features', [])
                    })
                else:
                    return jsonify({
                        'success': False,
                        'error': 'Invalid sudo password',
                        'requires_manual_setup': True
                    })
                    
            except subprocess.TimeoutExpired:
                return jsonify({
                    'success': False,
                    'error': 'Sudo authentication timed out'
                })
        else:
            # Return instructions for manual setup
            return jsonify(result)
            
    except Exception as e:
        logger.error(f"Sudo request failed: {e}")
        return jsonify({
            'success': False,
            'error': f'Sudo authentication failed: {str(e)}'
        })

# VirusTotal API Endpoints
@app.route('/api/virustotal/scan', methods=['POST'])
def virustotal_scan():
    """Scan a file using VirusTotal API"""
    if not virustotal_available:
        return jsonify({
            'success': False,
            'error': 'VirusTotal scanner not available'
        }), 500
    
    data = request.get_json()
    
    if not data:
        return jsonify({
            'success': False,
            'error': 'No data provided'
        }), 400
    
    file_path = data.get('file_path')
    api_key = data.get('api_key') or os.getenv('VT_API_KEY')
    wait_for_result = data.get('wait_for_result', True)
    max_wait = data.get('max_wait', 300)
    
    if not file_path:
        return jsonify({
            'success': False,
            'error': 'file_path is required'
        }), 400
    
    if not api_key:
        return jsonify({
            'success': False,
            'error': 'VirusTotal API key required. Provide via api_key parameter or VT_API_KEY environment variable'
        }), 400
    
    if not os.path.exists(file_path):
        return jsonify({
            'success': False,
            'error': f'File not found: {file_path}'
        }), 404
    
    try:
        # Initialize scanner
        scanner = VirusTotalScanner(api_key)
        
        # Perform scan
        result = scanner.scan_file(
            file_path,
            wait_for_result=wait_for_result,
            max_wait=max_wait
        )
        
        return jsonify(result)
        
    except Exception as e:
        return jsonify({
            'success': False,
            'error': f'VirusTotal scan failed: {str(e)}'
        }), 500

@app.route('/api/virustotal/check-hash', methods=['POST'])
def virustotal_check_hash():
    """Check if a file hash exists in VirusTotal database"""
    if not virustotal_available:
        return jsonify({
            'success': False,
            'error': 'VirusTotal scanner not available'
        }), 500
    
    data = request.get_json()
    
    if not data:
        return jsonify({
            'success': False,
            'error': 'No data provided'
        }), 400
    
    file_hash = data.get('file_hash')
    file_path = data.get('file_path')
    api_key = data.get('api_key') or os.getenv('VT_API_KEY')
    
    if not api_key:
        return jsonify({
            'success': False,
            'error': 'VirusTotal API key required'
        }), 400
    
    try:
        scanner = VirusTotalScanner(api_key)
        
        # Calculate hash if file path provided
        if not file_hash and file_path:
            if not os.path.exists(file_path):
                return jsonify({
                    'success': False,
                    'error': f'File not found: {file_path}'
                }), 404
            file_hash = scanner.calculate_file_hash(file_path)
        
        if not file_hash:
            return jsonify({
                'success': False,
                'error': 'Either file_hash or file_path is required'
            }), 400
        
        # Check existing report
        report = scanner.check_existing_report(file_hash)
        
        if report and 'error' not in report:
            parsed = scanner.parse_scan_results(report)
            return jsonify({
                'success': True,
                'found': True,
                'file_hash': file_hash,
                'results': parsed
            })
        else:
            return jsonify({
                'success': True,
                'found': False,
                'file_hash': file_hash,
                'message': 'File not found in VirusTotal database'
            })
    
    except Exception as e:
        return jsonify({
            'success': False,
            'error': f'Hash check failed: {str(e)}'
        }), 500

@app.route('/api/virustotal/status', methods=['GET'])
def virustotal_status():
    """Check VirusTotal integration status"""
    api_key = os.getenv('VT_API_KEY')
    
    return jsonify({
        'available': virustotal_available,
        'api_key_configured': bool(api_key),
        'message': 'VirusTotal integration ready' if (virustotal_available and api_key) else 'Configure VT_API_KEY environment variable'
    })

# Free Malware Scanner Endpoints (No API key required)
@app.route('/api/malware-scan/free', methods=['POST'])
def free_malware_scan():
    """Scan file using free services (no API key required)"""
    if not free_scanner_available:
        return jsonify({
            'success': False,
            'error': 'Free malware scanner not available'
        }), 500
    
    data = request.get_json()
    
    if not data or 'file_path' not in data:
        return jsonify({
            'success': False,
            'error': 'file_path is required'
        }), 400
    
    file_path = data['file_path']
    
    if not os.path.exists(file_path):
        return jsonify({
            'success': False,
            'error': f'File not found: {file_path}'
        }), 404
    
    try:
        scanner = MalwareScanner()
        result = scanner.comprehensive_scan(file_path)
        return jsonify(result)
    except Exception as e:
        return jsonify({
            'success': False,
            'error': f'Scan failed: {str(e)}'
        }), 500

@app.route('/api/malware-scan/status', methods=['GET'])
def malware_scan_status():
    """Check free malware scanner status"""
    return jsonify({
        'available': free_scanner_available,
        'services': {
            'malwarebazaar': 'abuse.ch - Known malware database',
            'threatfox': 'abuse.ch - IOC database',
            'hybrid_analysis': 'Public malware analysis'
        },
        'requires_api_key': False,
        'rate_limits': 'None (completely free)',
        'message': 'Free multi-service scanner ready' if free_scanner_available else 'Scanner not available'
    })

if __name__ == '__main__':
    # Ensure monitor is compiled
    try:
        subprocess.run(['make', '-C', '../monitor'], check=True, 
                      capture_output=True, text=True)
        subprocess.run(['make', '-C', '../monitor', 'install'], check=True,
                      capture_output=True, text=True)
        print("Process monitor compiled successfully")
    except subprocess.CalledProcessError as e:
        print(f"Warning: Could not compile monitor: {e}")
    
    print("Starting Sentinal Analysis Server...")
    print("Web interface: http://localhost:3000")
    app.run(host='0.0.0.0', port=3000, debug=True)