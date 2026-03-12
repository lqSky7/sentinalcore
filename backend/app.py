import os
import subprocess
import threading
import time
import json
import uuid
import io
import random
import psutil
import socket
import platform
from datetime import datetime
from flask import Flask, request, jsonify, send_from_directory, send_file
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

# Import static analyzer
try:
    from static_analyzer import StaticAnalyzer
    static_analyzer = StaticAnalyzer()
    static_analyzer_available = True
except ImportError as e:
    print(f"Static analyzer not available: {e}")
    static_analyzer_available = False

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

    @staticmethod
    def _format_socket_address(address):
        """Normalize psutil socket address tuples to ip:port strings."""
        if not address:
            return None

        if hasattr(address, 'ip') and hasattr(address, 'port'):
            return f"{address.ip}:{address.port}"

        if isinstance(address, (tuple, list)) and len(address) >= 2:
            return f"{address[0]}:{address[1]}"

        return str(address)

    @staticmethod
    def _extract_ip(address):
        """Extract an IP portion from ip:port or [ipv6]:port formatted strings."""
        if not address:
            return None

        if address.startswith('[') and ']:' in address:
            end = address.rfind(']:')
            if end > 1:
                return address[1:end]

        if ':' in address:
            return address.rsplit(':', 1)[0]

        return address

    def _resolve_remote_host(self, remote_addr):
        """Use the IP as a stable hostname fallback for dashboard rendering."""
        return self._extract_ip(remote_addr)

    def _normalize_connection_record(self, connection):
        """Provide both legacy and frontend-friendly address keys."""
        local_addr = connection.get('local_addr') or connection.get('laddr')
        remote_addr = connection.get('remote_addr') or connection.get('raddr')
        remote_host = connection.get('remote_host') or self._resolve_remote_host(remote_addr)

        normalized = dict(connection)
        normalized.update({
            'local_addr': local_addr,
            'remote_addr': remote_addr,
            'laddr': local_addr,
            'raddr': remote_addr,
            'remote_host': remote_host
        })
        return normalized

    def _analyze_network_requests(self, connections, stdout_text='', stderr_text=''):
        """Build a simple request list from observed connections and output hints."""
        requests = []
        seen = set()

        for conn in connections:
            remote_addr = conn.get('remote_addr')
            if not remote_addr:
                continue

            req_key = (
                conn.get('pid'),
                conn.get('type'),
                remote_addr,
                conn.get('status')
            )
            if req_key in seen:
                continue
            seen.add(req_key)

            requests.append({
                'timestamp': conn.get('timestamp', time.time()),
                'type': 'connection',
                'pid': conn.get('pid'),
                'protocol': conn.get('type', 'unknown'),
                'destination': remote_addr,
                'hostname': conn.get('remote_host') or self._resolve_remote_host(remote_addr) or 'unknown',
                'status': conn.get('status', 'unknown'),
                'description': f"{conn.get('family', 'unknown')}/{conn.get('type', 'unknown')} connection observed"
            })

        output_text = f"{stdout_text}\n{stderr_text}"
        for url in set(re.findall(r'https?://[^\s\'\"<>]+', output_text, flags=re.IGNORECASE)):
            requests.append({
                'timestamp': time.time(),
                'type': 'http_request',
                'pid': None,
                'protocol': 'http',
                'destination': url,
                'hostname': 'from_output',
                'status': 'detected',
                'description': f"URL reference detected in process output: {url}"
            })

        return requests

    def _build_network_analysis(self, network_details, stdout_text='', stderr_text=''):
        """Build the frontend network payload from captured connection details."""
        monitored = [
            self._normalize_connection_record(conn)
            for conn in (network_details.get('new_connections') or network_details.get('monitored_connections') or [])
        ]

        unique_destinations = sorted(
            set(conn.get('remote_addr') for conn in monitored if conn.get('remote_addr'))
        )
        protocols_used = sorted(
            set(conn.get('type') for conn in monitored if conn.get('type'))
        )
        remote_hosts = sorted(
            set(conn.get('remote_host') for conn in monitored if conn.get('remote_host'))
        )

        return {
            'total_connections': len(monitored),
            'unique_destinations': len(unique_destinations),
            'connection_change': network_details.get('change', 0),
            'initial_count': network_details.get('initial_count', 0),
            'final_count': network_details.get('final_count', 0),
            'total_monitored': network_details.get('total_monitored', len(monitored)),
            'monitored_connections': monitored,
            'network_requests': self._analyze_network_requests(monitored, stdout_text, stderr_text),
            'protocols_used': protocols_used,
            'remote_hosts': remote_hosts
        }
    
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
        
        # Try to get network connections (requires root on macOS)
        try:
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
            network_monitoring_available = True
        except (psutil.AccessDenied, PermissionError, OSError) as e:
            # Network monitoring requires root on macOS
            print(f"Network monitoring unavailable (requires root on macOS): {e}")
            initial_connections = []
            initial_conn_count = 0
            initial_conn_details = []
            network_monitoring_available = False
        
        try:
            # Start the process and monitor it
            # On macOS, os.setsid fails with SIP (System Integrity Protection)
            # Only use process groups on Linux where it works reliably
            popen_kwargs = {
                'stdout': subprocess.PIPE,
                'stderr': subprocess.PIPE
            }
            if self.platform == 'linux' and hasattr(os, 'setsid'):
                popen_kwargs['preexec_fn'] = os.setsid
            
            process = subprocess.Popen([file_path], **popen_kwargs)
            
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
            
            # Start network monitoring thread (only if available)
            monitoring_active = True
            target_pids = {process.pid}
            seen_connections = set()
            def monitor_network():
                while monitoring_active:
                    try:
                        # Track current child processes of the target process.
                        for proc_snapshot in psutil.process_iter(['pid', 'ppid']):
                            proc_pid = proc_snapshot.info.get('pid')
                            proc_ppid = proc_snapshot.info.get('ppid')
                            if proc_pid and proc_ppid in target_pids:
                                target_pids.add(proc_pid)

                        for tracked_pid in list(target_pids):
                            try:
                                tracked_proc = psutil.Process(tracked_pid)
                                try:
                                    proc_connections = tracked_proc.connections(kind='inet')
                                except TypeError:
                                    proc_connections = tracked_proc.connections()
                            except (psutil.NoSuchProcess, psutil.AccessDenied):
                                continue

                            for conn in proc_connections:
                                local_addr = self._format_socket_address(conn.laddr)
                                remote_addr = self._format_socket_address(conn.raddr)
                                if not local_addr and not remote_addr:
                                    continue

                                family = conn.family.name if hasattr(conn.family, 'name') else str(conn.family)
                                conn_type = conn.type.name if hasattr(conn.type, 'name') else str(conn.type)
                                status = conn.status if hasattr(conn, 'status') else 'unknown'

                                conn_key = (tracked_pid, family, conn_type, local_addr, remote_addr, status)
                                if conn_key in seen_connections:
                                    continue
                                seen_connections.add(conn_key)

                                monitored_connections.append({
                                    'key': conn_key,
                                    'timestamp': time.time(),
                                    'pid': tracked_pid,
                                    'family': family,
                                    'type': conn_type,
                                    'local_addr': local_addr,
                                    'remote_addr': remote_addr,
                                    'laddr': local_addr,
                                    'raddr': remote_addr,
                                    'status': status,
                                    'remote_host': self._resolve_remote_host(remote_addr)
                                })
                    except (psutil.AccessDenied, PermissionError, OSError):
                        pass
                    except Exception:
                        pass
                    time.sleep(0.1)  # Monitor every 100ms
            
            network_thread = threading.Thread(target=monitor_network, daemon=True)
            network_thread.start()
            
            # Wait for process with timeout
            try:
                stdout, stderr = process.communicate(timeout=timeout)
            except subprocess.TimeoutExpired:
                # On Linux with process groups, kill the entire group
                # On macOS or when process groups aren't used, just kill the process
                try:
                    if self.platform == 'linux' and hasattr(os, 'killpg'):
                        os.killpg(os.getpgid(process.pid), 9)
                    else:
                        process.kill()
                except (ProcessLookupError, PermissionError, OSError):
                    # Process may have already exited
                    pass
                stdout, stderr = process.communicate()
            finally:
                # Stop network monitoring
                monitoring_active = False
            
            end_time = datetime.now()
            
            # Get final system state
            final_processes = set(p.pid for p in psutil.process_iter())
            
            # Try to get final network state (requires root on macOS)
            if network_monitoring_available:
                try:
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
                except (psutil.AccessDenied, PermissionError, OSError):
                    final_connections = []
                    final_conn_count = 0
                    final_conn_details = []
            else:
                final_connections = []
                final_conn_count = 0
                final_conn_details = []
            
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
                conn_tuple = (
                    conn.get('family'),
                    conn.get('type'),
                    conn.get('local_addr') or conn.get('laddr'),
                    conn.get('remote_addr') or conn.get('raddr'),
                    conn.get('status')
                )
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
                'total_monitored': len(monitored_connections),
                'monitoring_available': network_monitoring_available
            }

            stdout_text = stdout.decode('utf-8', errors='replace')
            stderr_text = stderr.decode('utf-8', errors='replace')
            network_analysis = self._build_network_analysis(network_details, stdout_text, stderr_text)
            
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
                    'stdout': stdout_text,
                    'stderr': stderr_text,
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
                'network_analysis': network_analysis,
                'memory_usage': {'start': start_memory, 'process_pid': process.pid},
                'total_syscalls': len(syscalls),
                'total_processes': 1 + len(new_processes),
                'new_processes_detected': len(new_processes)
            }
            
            # Store results
            self.results[analysis_id] = results
            return results
            
        except Exception as e:
            import traceback
            error_details = traceback.format_exc()
            print(f"Analysis error: {error_details}")  # Log to console
            return {
                'error': f'Process analysis failed: {str(e)}',
                'error_details': error_details,
                'analysis_id': analysis_id
            }
    
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
            
            # Use process groups only on Linux where they work reliably
            popen_kwargs = {
                'stdout': subprocess.PIPE,
                'stderr': subprocess.PIPE
            }
            if self.platform == 'linux' and hasattr(os, 'setsid'):
                popen_kwargs['preexec_fn'] = os.setsid
            
            process = subprocess.Popen(cmd, **popen_kwargs)
            
            try:
                stdout, stderr = process.communicate(timeout=timeout)
            except subprocess.TimeoutExpired:
                try:
                    if self.platform == 'linux' and hasattr(os, 'killpg'):
                        os.killpg(os.getpgid(process.pid), 9)
                    else:
                        process.kill()
                except (ProcessLookupError, PermissionError, OSError):
                    pass
                stdout, stderr = process.communicate()
            
            end_time = datetime.now()
            
            # Parse strace output if available
            syscalls = []
            if self.has_strace and os.path.exists(f'/tmp/strace_{analysis_id}.log'):
                syscalls = self._parse_strace_output(f'/tmp/strace_{analysis_id}.log')
            
            # Basic analysis without detailed monitoring
            stdout_text = stdout.decode('utf-8', errors='replace')
            stderr_text = stderr.decode('utf-8', errors='replace')
            network_details = {
                'initial_count': 0,
                'final_count': 0,
                'change': 0,
                'initial_connections': [],
                'final_connections': [],
                'monitored_connections': [],
                'new_connections': [],
                'total_monitored': 0,
                'monitoring_available': False
            }
            results = {
                'analysis_id': analysis_id,
                'file_path': file_path,
                'start_time': start_time.isoformat(),
                'end_time': end_time.isoformat(),
                'duration': (end_time - start_time).total_seconds(),
                'platform': f"{self.platform}_{self.architecture}",
                'monitoring_method': 'strace' if self.has_strace else 'basic',
                'monitor_output': {
                    'stdout': stdout_text,
                    'stderr': stderr_text
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
                'network_connections': network_details,
                'network_analysis': self._build_network_analysis(network_details, stdout_text, stderr_text),
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
            gemini_url = f"https://generativelanguage.googleapis.com/v1beta/models/gemini-2.5-flash:generateContent?key={api_key}"
            
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
                        'model': 'gemini-2.5-flash',
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

class CollaborationStore:
    """Minimal JSON-backed store for analysis sharing and collaboration."""

    def __init__(self, relative_path='data/collab_store.json'):
        self.storage_path = os.path.join(os.path.dirname(__file__), relative_path)
        self._lock = threading.Lock()
        self._ensure_store()
        self._seed_demo_data_if_needed()

    def _default_store(self):
        return {
            'analyses': {},
            'groups': {},
            'group_shares': []
        }

    def _ensure_store(self):
        directory = os.path.dirname(self.storage_path)
        os.makedirs(directory, exist_ok=True)
        if not os.path.exists(self.storage_path):
            with open(self.storage_path, 'w', encoding='utf-8') as f:
                json.dump(self._default_store(), f, indent=2)

    def _build_demo_analysis_data(self, user_id, title, file_path, risk_level, rng):
        risk_profiles = {
            'Low': {'syscalls': 78, 'suspicious': [], 'network': 1, 'processes': 2},
            'Medium': {
                'syscalls': 162,
                'suspicious': ['Suspicious outbound connection to uncommon port'],
                'network': 4,
                'processes': 3
            },
            'High': {
                'syscalls': 354,
                'suspicious': [
                    'High number of execve calls (possible process injection)',
                    'Multiple file deletions (possible anti-forensics)'
                ],
                'network': 9,
                'processes': 5
            }
        }
        profile = risk_profiles.get(risk_level, risk_profiles['Medium'])
        duration = round(rng.uniform(8.2, 47.6), 2)
        timestamp = int(time.time()) - rng.randint(1000, 80000)

        return {
            'analysis_id': f"analysis_demo_{uuid.uuid4().hex[:8]}",
            'file_path': file_path,
            'duration': duration,
            'total_syscalls': profile['syscalls'] + rng.randint(-12, 20),
            'total_processes': profile['processes'],
            'syscalls': [
                {'timestamp': timestamp + 1, 'pid': 4412, 'name': 'execve', 'args': []},
                {'timestamp': timestamp + 2, 'pid': 4412, 'name': 'openat', 'args': []},
                {'timestamp': timestamp + 3, 'pid': 4412, 'name': 'read', 'args': []},
                {'timestamp': timestamp + 4, 'pid': 4412, 'name': 'socket', 'args': []}
            ],
            'syscall_analysis': {
                'unique_syscalls': 22 + rng.randint(0, 12),
                'file_operations': 30 + rng.randint(0, 18),
                'network_operations': profile['network'],
                'process_operations': 4 + rng.randint(0, 5),
                'suspicious_patterns': profile['suspicious']
            },
            'network_analysis': {
                'total_connections': profile['network'],
                'unique_destinations': max(1, profile['network'] // 2),
                'protocols_used': ['SOCK_STREAM', 'SOCK_DGRAM'][:1 + int(profile['network'] > 2)],
                'network_requests': []
            },
            'monitor_output': {
                'stdout': f"[{user_id}] Completed sandbox execution for {title}",
                'stderr': '' if risk_level != 'High' else 'warning: anomalous syscall burst detected',
                'return_code': 0 if risk_level != 'High' else 1
            },
            'risk_assessment': {
                'risk_level': risk_level,
                'risk_score': {'Low': 24, 'Medium': 57, 'High': 86}.get(risk_level, 57)
            },
            'created_for_demo': True
        }

    def _seed_demo_data_if_needed(self):
        seed_users = ['diljot', 'rakshit', 'harish']
        demo_templates = [
            ('C2 Beacon Behavior Hunt', '/samples/high_risk_malware.sh', 'High'),
            ('Packed Binary Sandbox Run', '/samples/high_entropy_binary.bin', 'Medium'),
            ('Crypto Miner Process Trace', '/samples/crypto_miner.py', 'Medium'),
            ('Filesystem Mutation Sweep', '/samples/filesystem_test.py', 'Low'),
            ('Ransomware Simulator Execution', '/samples/ransomware_simulator.sh', 'High'),
            ('Network Callback Inspection', '/samples/simple_network_malware.py', 'Medium')
        ]

        with self._lock:
            store = self._read_store()

            user_record_ids = {user: [] for user in seed_users}
            for record_id, record in store['analyses'].items():
                owner = record.get('owner_user_id')
                if owner in user_record_ids:
                    user_record_ids[owner].append(record_id)

            needs_seed = any(len(user_record_ids[user]) == 0 for user in seed_users)
            if not needs_seed:
                return

            rng = random.Random(1337)
            existing_group_keys = {}
            for group_id, group in store['groups'].items():
                key = (group.get('name'), tuple(sorted(group.get('members', []))))
                existing_group_keys[key] = group_id

            template_index = 0
            for user in seed_users:
                missing = 2 - len(user_record_ids[user])
                if missing <= 0:
                    continue

                for _ in range(missing):
                    title, file_path, risk = demo_templates[template_index % len(demo_templates)]
                    template_index += 1
                    created_at = datetime.now().isoformat()
                    demo_data = self._build_demo_analysis_data(user, title, file_path, risk, rng)
                    record_id = self._new_id('record')
                    record = {
                        'id': record_id,
                        'title': title,
                        'owner_user_id': user,
                        'source_analysis_id': demo_data.get('analysis_id'),
                        'created_at': created_at,
                        'summary': self._extract_summary(demo_data),
                        'analysis_data': demo_data
                    }
                    store['analyses'][record_id] = record
                    user_record_ids[user].append(record_id)

            desired_groups = [
                {
                    'name': 'Rapid Response Cell',
                    'owner_user_id': 'diljot',
                    'members': ['diljot', 'rakshit']
                },
                {
                    'name': 'Sandbox Lab',
                    'owner_user_id': 'rakshit',
                    'members': ['rakshit', 'harish']
                },
                {
                    'name': 'Threat Intel Sync',
                    'owner_user_id': 'harish',
                    'members': ['diljot', 'rakshit', 'harish']
                }
            ]

            group_ids = {}
            for group_spec in desired_groups:
                key = (group_spec['name'], tuple(sorted(group_spec['members'])))
                existing_id = existing_group_keys.get(key)
                if existing_id:
                    group_ids[group_spec['name']] = existing_id
                    continue

                group_id = self._new_id('group')
                group = {
                    'id': group_id,
                    'name': group_spec['name'],
                    'owner_user_id': group_spec['owner_user_id'],
                    'members': sorted(set(group_spec['members'])),
                    'created_at': datetime.now().isoformat()
                }
                store['groups'][group_id] = group
                group_ids[group_spec['name']] = group_id

            existing_share_keys = set(
                (share.get('group_id'), share.get('analysis_record_id'))
                for share in store['group_shares']
            )

            demo_share_plan = [
                ('diljot', 'Rapid Response Cell'),
                ('diljot', 'Threat Intel Sync'),
                ('rakshit', 'Rapid Response Cell'),
                ('rakshit', 'Sandbox Lab'),
                ('harish', 'Sandbox Lab'),
                ('harish', 'Threat Intel Sync')
            ]

            for user, group_name in demo_share_plan:
                record_id = user_record_ids.get(user, [None])[0]
                group_id = group_ids.get(group_name)
                if not record_id or not group_id:
                    continue
                key = (group_id, record_id)
                if key in existing_share_keys:
                    continue

                store['group_shares'].append({
                    'id': self._new_id('share'),
                    'group_id': group_id,
                    'analysis_record_id': record_id,
                    'shared_by': user,
                    'shared_at': datetime.now().isoformat()
                })
                existing_share_keys.add(key)

            self._write_store(store)

    def _read_store(self):
        try:
            with open(self.storage_path, 'r', encoding='utf-8') as f:
                data = json.load(f)
            if not isinstance(data, dict):
                return self._default_store()
            data.setdefault('analyses', {})
            data.setdefault('groups', {})
            data.setdefault('group_shares', [])
            return data
        except (json.JSONDecodeError, OSError):
            return self._default_store()

    def _write_store(self, data):
        with open(self.storage_path, 'w', encoding='utf-8') as f:
            json.dump(data, f, indent=2)

    def _new_id(self, prefix):
        return f"{prefix}_{uuid.uuid4().hex[:12]}"

    def _json_safe(self, value):
        return json.loads(json.dumps(value, default=str))

    def _extract_summary(self, analysis_data):
        syscall_analysis = analysis_data.get('syscall_analysis', {})
        risk_assessment = analysis_data.get('risk_assessment', {})
        risk_level = (
            risk_assessment.get('risk_level')
            or analysis_data.get('threat_level')
            or analysis_data.get('summary', {}).get('threat_level')
            or ('Medium' if syscall_analysis.get('suspicious_patterns') else 'Unknown')
        )

        return {
            'file_path': (
                analysis_data.get('file_path')
                or analysis_data.get('file_name')
                or analysis_data.get('directory')
                or 'N/A'
            ),
            'duration': analysis_data.get('duration'),
            'total_syscalls': analysis_data.get('total_syscalls', 0),
            'total_processes': analysis_data.get('total_processes', 0),
            'risk_level': risk_level
        }

    def _user_can_access_record(self, store, user_id, record_id):
        record = store['analyses'].get(record_id)
        if not record:
            return False

        if record.get('owner_user_id') == user_id:
            return True

        for share in store['group_shares']:
            if share.get('analysis_record_id') != record_id:
                continue
            group = store['groups'].get(share.get('group_id'))
            if group and user_id in group.get('members', []):
                return True
        return False

    def save_analysis(self, user_id, title, analysis_data, source_analysis_id=None):
        with self._lock:
            store = self._read_store()
            record_id = self._new_id('record')
            safe_data = self._json_safe(analysis_data)
            record = {
                'id': record_id,
                'title': title or f"Analysis {record_id}",
                'owner_user_id': user_id,
                'source_analysis_id': source_analysis_id,
                'created_at': datetime.now().isoformat(),
                'summary': self._extract_summary(safe_data),
                'analysis_data': safe_data
            }
            store['analyses'][record_id] = record
            self._write_store(store)
            return record

    def list_user_analyses(self, user_id):
        with self._lock:
            store = self._read_store()
            accessible = []

            for record in store['analyses'].values():
                record_id = record.get('id')
                if not self._user_can_access_record(store, user_id, record_id):
                    continue

                shared_groups = []
                for share in store['group_shares']:
                    if share.get('analysis_record_id') != record_id:
                        continue
                    group = store['groups'].get(share.get('group_id'))
                    if group and user_id in group.get('members', []):
                        shared_groups.append({
                            'group_id': group.get('id'),
                            'group_name': group.get('name')
                        })

                item = {
                    'id': record.get('id'),
                    'title': record.get('title'),
                    'owner_user_id': record.get('owner_user_id'),
                    'created_at': record.get('created_at'),
                    'summary': record.get('summary', {}),
                    'shared_groups': shared_groups
                }
                accessible.append(item)

            accessible.sort(key=lambda x: x.get('created_at', ''), reverse=True)
            return accessible

    def get_record_for_user(self, user_id, record_id):
        with self._lock:
            store = self._read_store()
            if not self._user_can_access_record(store, user_id, record_id):
                return None
            return store['analyses'].get(record_id)

    def create_group(self, owner_user_id, name, members=None):
        members = members or []
        normalized_members = sorted(set(
            [owner_user_id] + [member.strip() for member in members if member and member.strip()]
        ))

        with self._lock:
            store = self._read_store()
            group_id = self._new_id('group')
            group = {
                'id': group_id,
                'name': name,
                'owner_user_id': owner_user_id,
                'members': normalized_members,
                'created_at': datetime.now().isoformat()
            }
            store['groups'][group_id] = group
            self._write_store(store)
            return group

    def list_user_groups(self, user_id):
        with self._lock:
            store = self._read_store()
            groups = []
            for group in store['groups'].values():
                if user_id in group.get('members', []):
                    groups.append(group)
            groups.sort(key=lambda x: x.get('created_at', ''), reverse=True)
            return groups

    def list_known_users(self):
        with self._lock:
            store = self._read_store()
            users = set()

            for record in store['analyses'].values():
                owner = record.get('owner_user_id')
                if owner:
                    users.add(owner)

            for group in store['groups'].values():
                for member in group.get('members', []):
                    if member:
                        users.add(member)

            ordered = sorted(users)
            return [{'user_id': user_id} for user_id in ordered]

    def share_analysis_to_group(self, user_id, group_id, analysis_record_id):
        with self._lock:
            store = self._read_store()
            group = store['groups'].get(group_id)
            if not group:
                return {'error': 'Group not found'}

            if user_id not in group.get('members', []):
                return {'error': 'User is not a member of this group'}

            if analysis_record_id not in store['analyses']:
                return {'error': 'Analysis record not found'}

            if not self._user_can_access_record(store, user_id, analysis_record_id):
                return {'error': 'User cannot share this analysis record'}

            for share in store['group_shares']:
                if (
                    share.get('group_id') == group_id and
                    share.get('analysis_record_id') == analysis_record_id
                ):
                    return share

            share = {
                'id': self._new_id('share'),
                'group_id': group_id,
                'analysis_record_id': analysis_record_id,
                'shared_by': user_id,
                'shared_at': datetime.now().isoformat()
            }
            store['group_shares'].append(share)
            self._write_store(store)
            return share

    def get_group_feed(self, user_id, group_id):
        with self._lock:
            store = self._read_store()
            group = store['groups'].get(group_id)
            if not group:
                return {'error': 'Group not found'}

            if user_id not in group.get('members', []):
                return {'error': 'User is not a member of this group'}

            feed = []
            for share in store['group_shares']:
                if share.get('group_id') != group_id:
                    continue
                record = store['analyses'].get(share.get('analysis_record_id'))
                if not record:
                    continue
                feed.append({
                    'share_id': share.get('id'),
                    'shared_by': share.get('shared_by'),
                    'shared_at': share.get('shared_at'),
                    'analysis': {
                        'id': record.get('id'),
                        'title': record.get('title'),
                        'owner_user_id': record.get('owner_user_id'),
                        'created_at': record.get('created_at'),
                        'summary': record.get('summary', {})
                    }
                })

            feed.sort(key=lambda x: x.get('shared_at', ''), reverse=True)
            return {
                'group': group,
                'feed': feed
            }


def _get_user_id(payload=None, required=True):
    payload = payload or {}
    user_id = (
        payload.get('user_id')
        or request.args.get('user_id')
        or request.headers.get('X-User-Id')
    )
    if user_id:
        user_id = str(user_id).strip()

    if required and not user_id:
        return None

    return user_id or 'anonymous'


def _pdf_escape_text(text):
    if text is None:
        return ''
    text = str(text).replace('\\', '\\\\').replace('(', '\\(').replace(')', '\\)')
    text = text.replace('\n', ' ').replace('\r', ' ')
    return ''.join(ch if 32 <= ord(ch) <= 126 else '?' for ch in text)


def _split_pdf_lines(line, max_chars=100):
    if line is None:
        return ['']

    text = str(line).replace('\r', '')
    if text == '':
        return ['']

    output = []
    for part in text.split('\n'):
        if part == '':
            output.append('')
            continue
        while len(part) > max_chars:
            output.append(part[:max_chars])
            part = part[max_chars:]
        output.append(part)
    return output or ['']


def _to_json_lines(value):
    try:
        payload = json.dumps(value, indent=2, default=str, ensure_ascii=True)
    except (TypeError, ValueError):
        payload = str(value)
    return payload.splitlines()


def _build_simple_pdf(lines):
    normalized_lines = []
    for line in lines:
        normalized_lines.extend(_split_pdf_lines(line, max_chars=100))

    if not normalized_lines:
        normalized_lines = ['No report data available']

    lines_per_page = 45
    pages = [
        normalized_lines[index:index + lines_per_page]
        for index in range(0, len(normalized_lines), lines_per_page)
    ] or [['No report data available']]

    objects = {
        1: "<< /Type /Catalog /Pages 2 0 R >>",
        3: "<< /Type /Font /Subtype /Type1 /BaseFont /Courier >>"
    }

    next_id = 4
    page_refs = []
    total_pages = len(pages)

    for page_number, page_lines in enumerate(pages, start=1):
        page_id = next_id
        content_id = next_id + 1
        next_id += 2
        page_refs.append(f"{page_id} 0 R")

        stream_lines = ['BT', '/F1 10 Tf', '50 760 Td']
        for index, line in enumerate(page_lines):
            if index > 0:
                stream_lines.append('0 -14 Td')
            stream_lines.append(f"({_pdf_escape_text(line)}) Tj")
        stream_lines.append('0 -20 Td')
        stream_lines.append(f"({_pdf_escape_text(f'Page {page_number} of {total_pages}')}) Tj")
        stream_lines.append('ET')

        content_stream = '\n'.join(stream_lines) + '\n'
        content_bytes = content_stream.encode('latin-1', errors='replace')

        objects[page_id] = (
            f"<< /Type /Page /Parent 2 0 R /MediaBox [0 0 612 792] "
            f"/Resources << /Font << /F1 3 0 R >> >> /Contents {content_id} 0 R >>"
        )
        objects[content_id] = f"<< /Length {len(content_bytes)} >>\nstream\n{content_stream}endstream"

    objects[2] = f"<< /Type /Pages /Kids [{' '.join(page_refs)}] /Count {len(page_refs)} >>"
    max_obj_id = max(objects)

    pdf = bytearray(b"%PDF-1.4\n")
    offsets = [0]

    for idx in range(1, max_obj_id + 1):
        obj = objects[idx]
        offsets.append(len(pdf))
        pdf.extend(f"{idx} 0 obj\n{obj}\nendobj\n".encode('latin-1', errors='replace'))

    xref_start = len(pdf)
    pdf.extend(f"xref\n0 {max_obj_id + 1}\n".encode('latin-1'))
    pdf.extend(b"0000000000 65535 f \n")
    for offset in offsets[1:]:
        pdf.extend(f"{offset:010d} 00000 n \n".encode('latin-1'))

    trailer = (
        f"trailer\n<< /Size {max_obj_id + 1} /Root 1 0 R >>\n"
        f"startxref\n{xref_start}\n%%EOF\n"
    )
    pdf.extend(trailer.encode('latin-1'))
    return bytes(pdf)


def _analysis_record_to_pdf_lines(record):
    summary = record.get('summary', {})
    analysis_data = record.get('analysis_data', {})
    monitor_output = analysis_data.get('monitor_output', {})
    ai_analysis = analysis_data.get('ai_analysis')

    lines = []
    lines.append("Sentinal Core Malware Analysis Report")
    lines.append("=" * 78)
    lines.append(f"Generated At: {datetime.now().isoformat()}")
    lines.append("")
    lines.append("Record Metadata")
    lines.append("-" * 78)
    lines.append(f"Title: {record.get('title', 'N/A')}")
    lines.append(f"Record ID: {record.get('id', 'N/A')}")
    lines.append(f"Saved By: {record.get('owner_user_id', 'N/A')}")
    lines.append(f"Saved At: {record.get('created_at', 'N/A')}")
    lines.append(f"Source Analysis ID: {record.get('source_analysis_id', 'N/A')}")
    lines.append("")
    lines.append("Summary")
    lines.append("-" * 78)
    lines.append(f"File Path: {summary.get('file_path', 'N/A')}")
    lines.append(f"Risk Level: {summary.get('risk_level', 'Unknown')}")
    lines.append(f"Duration: {summary.get('duration', 'N/A')} seconds")
    lines.append(f"Total Syscalls: {summary.get('total_syscalls', 0)}")
    lines.append(f"Total Processes: {summary.get('total_processes', 0)}")
    lines.append("")
    lines.append("Execution Output (Full)")
    lines.append("-" * 78)
    lines.append("STDOUT:")
    lines.extend((monitor_output.get('stdout') or '').splitlines() or [''])
    lines.append("")
    lines.append("STDERR:")
    lines.extend((monitor_output.get('stderr') or '').splitlines() or [''])
    lines.append("")

    lines.append("AI Analysis")
    lines.append("-" * 78)
    if ai_analysis is None:
        lines.append("No AI analysis was attached to this saved record.")
    elif isinstance(ai_analysis, dict):
        if ai_analysis.get('analysis'):
            lines.append("AI Narrative:")
            lines.extend(str(ai_analysis.get('analysis', '')).splitlines())
            lines.append("")
        lines.append("AI Payload:")
        lines.extend(_to_json_lines(ai_analysis))
    else:
        lines.extend(str(ai_analysis).splitlines() or [str(ai_analysis)])
    lines.append("")

    # Include the full saved analysis payload to guarantee all details are exported.
    lines.append("Full Saved Analysis Record (JSON)")
    lines.append("-" * 78)
    lines.extend(_to_json_lines(record))
    lines.append("")
    lines.append("End of report")
    return lines


def _record_summary_response(record):
    return {
        'id': record.get('id'),
        'title': record.get('title'),
        'owner_user_id': record.get('owner_user_id'),
        'created_at': record.get('created_at'),
        'summary': record.get('summary', {}),
        'source_analysis_id': record.get('source_analysis_id')
    }

# Global analysis engine
analysis_engine = AnalysisEngine()
collaboration_store = CollaborationStore()

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

# Collaboration Endpoints
@app.route('/api/collab/analysis/save', methods=['POST'])
def save_analysis_record():
    data = request.get_json(silent=True) or {}
    user_id = _get_user_id(data, required=True)
    if not user_id:
        return jsonify({'error': 'user_id is required'}), 400

    analysis_data = data.get('analysis_data')
    analysis_id = data.get('analysis_id')
    if analysis_data is None and analysis_id:
        analysis_data = analysis_engine.results.get(analysis_id)

    if analysis_data is None:
        return jsonify({'error': 'analysis_data or valid analysis_id is required'}), 400

    title = data.get('title') or f"Analysis by {user_id}"
    record = collaboration_store.save_analysis(user_id, title, analysis_data, source_analysis_id=analysis_id)

    return jsonify({
        'success': True,
        'record': _record_summary_response(record),
        'pdf_url': f"/api/collab/analysis/{record.get('id')}/pdf"
    })


@app.route('/api/collab/analysis/list', methods=['GET'])
def list_analysis_records():
    user_id = _get_user_id(required=True)
    if not user_id:
        return jsonify({'error': 'user_id is required'}), 400

    records = collaboration_store.list_user_analyses(user_id)
    return jsonify({
        'success': True,
        'records': records
    })


@app.route('/api/collab/group/create', methods=['POST'])
def create_collab_group():
    data = request.get_json(silent=True) or {}
    user_id = _get_user_id(data, required=True)
    if not user_id:
        return jsonify({'error': 'user_id is required'}), 400

    group_name = (data.get('group_name') or data.get('name') or '').strip()
    if not group_name:
        return jsonify({'error': 'group_name is required'}), 400

    members = data.get('members', [])
    if isinstance(members, str):
        members = [member.strip() for member in members.split(',') if member.strip()]

    group = collaboration_store.create_group(user_id, group_name, members)
    return jsonify({
        'success': True,
        'group': group
    })


@app.route('/api/collab/groups', methods=['GET'])
def list_collab_groups():
    user_id = _get_user_id(required=True)
    if not user_id:
        return jsonify({'error': 'user_id is required'}), 400

    groups = collaboration_store.list_user_groups(user_id)
    return jsonify({
        'success': True,
        'groups': groups
    })


@app.route('/api/collab/users', methods=['GET'])
def list_collab_users():
    return jsonify({
        'success': True,
        'users': collaboration_store.list_known_users()
    })


@app.route('/api/collab/group/share', methods=['POST'])
def share_analysis_with_group():
    data = request.get_json(silent=True) or {}
    user_id = _get_user_id(data, required=True)
    if not user_id:
        return jsonify({'error': 'user_id is required'}), 400

    group_id = data.get('group_id')
    analysis_record_id = data.get('analysis_record_id')
    if not group_id or not analysis_record_id:
        return jsonify({'error': 'group_id and analysis_record_id are required'}), 400

    share = collaboration_store.share_analysis_to_group(user_id, group_id, analysis_record_id)
    if 'error' in share:
        return jsonify(share), 400

    return jsonify({
        'success': True,
        'share': share
    })


@app.route('/api/collab/group/<group_id>/feed', methods=['GET'])
def get_group_feed(group_id):
    user_id = _get_user_id(required=True)
    if not user_id:
        return jsonify({'error': 'user_id is required'}), 400

    feed = collaboration_store.get_group_feed(user_id, group_id)
    if 'error' in feed:
        return jsonify(feed), 400

    return jsonify({
        'success': True,
        **feed
    })


@app.route('/api/collab/analysis/<record_id>', methods=['GET'])
def get_analysis_record(record_id):
    user_id = _get_user_id(required=True)
    if not user_id:
        return jsonify({'error': 'user_id is required'}), 400

    record = collaboration_store.get_record_for_user(user_id, record_id)
    if not record:
        return jsonify({'error': 'Analysis record not found or access denied'}), 404

    return jsonify({
        'success': True,
        'record': record
    })


@app.route('/api/collab/analysis/<record_id>/pdf', methods=['GET'])
def download_analysis_pdf(record_id):
    user_id = _get_user_id(required=True)
    if not user_id:
        return jsonify({'error': 'user_id is required'}), 400

    record = collaboration_store.get_record_for_user(user_id, record_id)
    if not record:
        return jsonify({'error': 'Analysis record not found or access denied'}), 404

    report_lines = _analysis_record_to_pdf_lines(record)
    pdf_bytes = _build_simple_pdf(report_lines)
    file_name = f"{record_id}.pdf"

    return send_file(
        io.BytesIO(pdf_bytes),
        mimetype='application/pdf',
        as_attachment=True,
        download_name=file_name
    )

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

# Static Analysis Endpoints
@app.route('/api/static-scan', methods=['POST'])
def static_scan():
    """Perform comprehensive static analysis"""
    if not static_analyzer_available:
        return jsonify({
            'success': False,
            'error': 'Static analyzer not available'
        }), 500
    
    data = request.get_json()
    file_path = data.get('file_path')
    
    if not file_path:
        return jsonify({
            'success': False,
            'error': 'file_path is required'
        }), 400
    
    if not os.path.exists(file_path):
        return jsonify({
            'success': False,
            'error': f'File not found: {file_path}'
        }), 404
    
    try:
        # Perform comprehensive static analysis
        result = {
            'file_path': file_path,
            'timestamp': datetime.now().isoformat(),
            'file_info': {},
            'entropy': {},
            'hashes': {},
            'strings': {},
            'risk_assessment': {}
        }
        
        # Get file info
        file_stat = os.stat(file_path)
        result['file_info'] = {
            'size': file_stat.st_size,
            'extension': os.path.splitext(file_path)[1],
            'name': os.path.basename(file_path)
        }
        
        # Entropy analysis
        entropy_result = static_analyzer.analyze_file_entropy(file_path)
        if 'error' not in entropy_result:
            result['entropy'] = entropy_result
        
        # Calculate hashes
        result['hashes'] = static_analyzer.calculate_file_hashes(file_path)
        
        # Extract and analyze strings
        strings_result = static_analyzer.extract_suspicious_strings(file_path)
        result['strings'] = strings_result
        
        # Risk assessment
        risk_score = 0
        risk_factors = []
        
        if entropy_result.get('suspicion_level') == 'High':
            risk_score += 40
            risk_factors.append('High entropy detected')
        elif entropy_result.get('suspicion_level') == 'Medium':
            risk_score += 20
            risk_factors.append('Medium entropy detected')
        
        if len(strings_result.get('suspicious_strings', [])) > 5:
            risk_score += 30
            risk_factors.append(f"{len(strings_result['suspicious_strings'])} suspicious strings found")
        elif len(strings_result.get('suspicious_strings', [])) > 0:
            risk_score += 15
            risk_factors.append(f"{len(strings_result['suspicious_strings'])} suspicious strings found")
        
        # Determine risk level
        if risk_score >= 60:
            risk_level = 'High'
        elif risk_score >= 30:
            risk_level = 'Medium'
        else:
            risk_level = 'Low'
        
        result['risk_assessment'] = {
            'risk_score': risk_score,
            'risk_level': risk_level,
            'risk_factors': risk_factors
        }
        
        return jsonify(result)
        
    except Exception as e:
        return jsonify({
            'success': False,
            'error': f'Static analysis failed: {str(e)}'
        }), 500

@app.route('/api/entropy-analysis', methods=['POST'])
def entropy_analysis():
    """Analyze file entropy"""
    if not static_analyzer_available:
        return jsonify({
            'success': False,
            'error': 'Static analyzer not available'
        }), 500
    
    data = request.get_json()
    file_path = data.get('file_path')
    
    if not file_path:
        return jsonify({
            'success': False,
            'error': 'file_path is required'
        }), 400
    
    if not os.path.exists(file_path):
        return jsonify({
            'success': False,
            'error': f'File not found: {file_path}'
        }), 404
    
    try:
        result = static_analyzer.analyze_file_entropy(file_path)
        
        if 'error' in result:
            return jsonify({
                'success': False,
                'error': result['error']
            }), 500
        
        return jsonify(result)
        
    except Exception as e:
        return jsonify({
            'success': False,
            'error': f'Entropy analysis failed: {str(e)}'
        }), 500

@app.route('/api/hash-lookup', methods=['POST'])
def hash_lookup():
    """Calculate hashes and check threat intelligence databases"""
    if not static_analyzer_available:
        return jsonify({
            'success': False,
            'error': 'Static analyzer not available'
        }), 500
    
    data = request.get_json()
    file_path = data.get('file_path')
    
    if not file_path:
        return jsonify({
            'success': False,
            'error': 'file_path is required'
        }), 400
    
    if not os.path.exists(file_path):
        return jsonify({
            'success': False,
            'error': f'File not found: {file_path}'
        }), 404
    
    try:
        # Calculate hashes
        hashes = static_analyzer.calculate_file_hashes(file_path)
        
        result = {
            'file_path': file_path,
            'hashes': hashes,
            'virustotal': {'found': False},
            'malware_bazaar': {'found': False}
        }
        
        # Check MalwareBazaar (free, no API key needed)
        try:
            mb_result = static_analyzer.check_malware_bazaar(hashes['sha256'])
            if mb_result and 'error' not in mb_result:
                result['malware_bazaar'] = mb_result
        except Exception as e:
            result['malware_bazaar'] = {'error': str(e)}
        
        # Check VirusTotal if API key is available
        if static_analyzer.virustotal_api_key:
            try:
                vt_result = static_analyzer.check_virustotal(hashes['sha256'])
                if vt_result and 'error' not in vt_result:
                    result['virustotal'] = vt_result
            except Exception as e:
                result['virustotal'] = {'error': str(e)}
        else:
            result['virustotal'] = {'error': 'API key not configured'}
        
        return jsonify(result)
        
    except Exception as e:
        return jsonify({
            'success': False,
            'error': f'Hash lookup failed: {str(e)}'
        }), 500

@app.route('/api/directory-scan', methods=['POST'])
def directory_scan():
    """Scan directory for suspicious files"""
    if not static_analyzer_available:
        return jsonify({
            'success': False,
            'error': 'Static analyzer not available'
        }), 500
    
    data = request.get_json()
    directory_path = data.get('directory_path')
    recursive = data.get('recursive', False)
    
    if not directory_path:
        return jsonify({
            'success': False,
            'error': 'directory_path is required'
        }), 400
    
    if not os.path.exists(directory_path) or not os.path.isdir(directory_path):
        return jsonify({
            'success': False,
            'error': f'Directory not found: {directory_path}'
        }), 404
    
    try:
        results = []
        file_count = 0
        
        # Scan directory
        if recursive:
            for root, dirs, files in os.walk(directory_path):
                for filename in files:
                    file_path = os.path.join(root, filename)
                    try:
                        entropy_result = static_analyzer.analyze_file_entropy(file_path)
                        if 'error' not in entropy_result:
                            results.append(entropy_result)
                            file_count += 1
                            if file_count >= 100:  # Limit to prevent timeout
                                break
                    except:
                        pass
                if file_count >= 100:
                    break
        else:
            for filename in os.listdir(directory_path):
                file_path = os.path.join(directory_path, filename)
                if os.path.isfile(file_path):
                    try:
                        entropy_result = static_analyzer.analyze_file_entropy(file_path)
                        if 'error' not in entropy_result:
                            results.append(entropy_result)
                            file_count += 1
                            if file_count >= 100:
                                break
                    except:
                        pass
        
        # Summary
        high_risk = [r for r in results if r.get('suspicion_level') == 'High']
        medium_risk = [r for r in results if r.get('suspicion_level') == 'Medium']
        low_risk = [r for r in results if r.get('suspicion_level') == 'Low']
        
        summary = {
            'total_files': len(results),
            'high_risk': len(high_risk),
            'medium_risk': len(medium_risk),
            'low_risk': len(low_risk),
            'detection_rate': f"{((len(high_risk) + len(medium_risk)) / len(results) * 100):.1f}%" if results else "0%"
        }
        
        return jsonify({
            'directory': directory_path,
            'recursive': recursive,
            'scan_timestamp': datetime.now().isoformat(),
            'total_files': len(results),
            'summary': summary,
            'results': results,
            'high_risk_files': high_risk[:10]  # Top 10
        })
        
    except Exception as e:
        return jsonify({
            'success': False,
            'error': f'Directory scan failed: {str(e)}'
        }), 500
    

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
    # Keep reloader off by default to avoid dropped requests during long analyses.
    debug_mode = os.getenv('FLASK_DEBUG', '0').lower() in ('1', 'true', 'yes')
    use_reloader = os.getenv('FLASK_USE_RELOADER', '0').lower() in ('1', 'true', 'yes')
    app.run(host='0.0.0.0', port=3000, debug=debug_mode, use_reloader=use_reloader)
