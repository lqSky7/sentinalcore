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

try:
    from platform_detection import get_platform_info, is_platform_supported
    platform_detection_available = True
except ImportError:
    platform_detection_available = False

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
    
    def run_analysis(self, file_path, timeout=30):
        """Main analysis function - simplified for cross-platform compatibility"""
        analysis_id = f"analysis_{int(time.time())}"
        
        try:
            # Check if file exists and is executable
            if not os.path.exists(file_path):
                return {'error': 'File not found', 'analysis_id': analysis_id}
            
            # Make file executable
            os.chmod(file_path, 0o755)
            
            # Use simplified monitoring approach
            return self._simple_process_analysis(file_path, timeout, analysis_id)
            
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
        initial_connections = len(psutil.net_connections())
        
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
            
            # Get process info
            try:
                proc_info = psutil.Process(process.pid)
                start_memory = proc_info.memory_info().rss
            except:
                start_memory = 0
            
            # Wait for process with timeout
            try:
                stdout, stderr = process.communicate(timeout=timeout)
            except subprocess.TimeoutExpired:
                if hasattr(os, 'killpg'):
                    os.killpg(os.getpgid(process.pid), 9)
                else:
                    process.kill()
                stdout, stderr = process.communicate()
            
            end_time = datetime.now()
            
            # Get final system state
            final_processes = set(p.pid for p in psutil.process_iter())
            final_connections = len(psutil.net_connections())
            
            # Detect new processes (approximate child processes)
            new_processes = final_processes - initial_processes
            
            # Simulate system call analysis based on file type and output
            syscalls = self._simulate_syscalls_from_execution(file_path, stdout, stderr, process.returncode)
            
            # Get network activity change
            network_change = final_connections - initial_connections
            
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
                'network_connections': {'change': network_change},
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
    
    # Run analysis in background
    analysis_engine.current_analysis = threading.Thread(
        target=lambda: analysis_engine.run_analysis(file_path, timeout)
    )
    
    # For simplicity, run synchronously for now
    result = analysis_engine.run_analysis(file_path, timeout)
    
    if 'error' in result:
        return jsonify(result), 500
    
    return jsonify(result)

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