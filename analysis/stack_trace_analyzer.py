#!/usr/bin/env python3
"""
Stack Trace and Debugging Analyzer
Advanced analysis of process stack traces, memory layout, and debugging information
"""

import os
import sys
import time
import json
import psutil
import signal
import subprocess
import threading
from datetime import datetime
from typing import Dict, List, Optional, Any
import logging
import re

logging.basicConfig(level=logging.INFO)

class StackTraceAnalyzer:
    """Analyzes process stack traces and memory layout"""
    
    def __init__(self):
        self.logger = logging.getLogger('StackTraceAnalyzer')
        self.traces = {}
        self.memory_maps = {}
        self.debug_info = {}
        
    def get_process_stack_trace(self, pid: int) -> Dict[str, Any]:
        """Get comprehensive stack trace information for a process"""
        self.logger.info(f"Getting stack trace for PID {pid}")
        
        trace_info = {
            'pid': pid,
            'timestamp': datetime.now().isoformat(),
            'stack_trace': '',
            'memory_maps': [],
            'register_info': {},
            'thread_info': [],
            'shared_libraries': [],
            'heap_info': {},
            'environment': {},
            'file_descriptors': [],
            'error': None
        }
        
        try:
            process = psutil.Process(pid)
            trace_info['process_name'] = process.name()
            trace_info['exe_path'] = process.exe()
            trace_info['cmdline'] = process.cmdline()
            trace_info['status'] = process.status()
            
            # Get stack trace using gdb
            stack_trace = self.get_gdb_stack_trace(pid)
            if stack_trace:
                trace_info['stack_trace'] = stack_trace
                
            # Get memory maps
            trace_info['memory_maps'] = self.get_memory_maps(pid)
            
            # Get thread information
            trace_info['thread_info'] = self.get_thread_info(pid)
            
            # Get shared libraries
            trace_info['shared_libraries'] = self.get_shared_libraries(pid)
            
            # Get file descriptors
            trace_info['file_descriptors'] = self.get_file_descriptors(pid)
            
            # Get environment
            try:
                trace_info['environment'] = dict(process.environ())
            except (psutil.AccessDenied, psutil.NoSuchProcess):
                pass
                
            # Get heap info
            trace_info['heap_info'] = self.analyze_heap_layout(pid)
            
        except (psutil.NoSuchProcess, psutil.AccessDenied, psutil.ZombieProcess) as e:
            trace_info['error'] = f"Process access error: {str(e)}"
            self.logger.error(f"Error accessing process {pid}: {e}")
        except Exception as e:
            trace_info['error'] = f"Unexpected error: {str(e)}"
            self.logger.error(f"Unexpected error for process {pid}: {e}")
            
        return trace_info
    
    def get_gdb_stack_trace(self, pid: int) -> Optional[str]:
        """Get stack trace using gdb"""
        try:
            # Create gdb batch script
            gdb_commands = f"""attach {pid}
thread apply all bt
info registers
info proc mappings
detach
quit
"""
            
            gdb_script = f"/tmp/gdb_script_{pid}.txt"
            with open(gdb_script, 'w') as f:
                f.write(gdb_commands)
            
            # Run gdb
            result = subprocess.run([
                'gdb', '-batch', '-x', gdb_script
            ], capture_output=True, text=True, timeout=30)
            
            # Clean up
            os.unlink(gdb_script)
            
            if result.returncode == 0:
                return result.stdout
            else:
                self.logger.warning(f"gdb failed for PID {pid}: {result.stderr}")
                return None
                
        except subprocess.TimeoutExpired:
            self.logger.warning(f"gdb timeout for PID {pid}")
            return None
        except Exception as e:
            self.logger.error(f"Error running gdb for PID {pid}: {e}")
            return None
    
    def get_memory_maps(self, pid: int) -> List[Dict]:
        """Get process memory mappings"""
        memory_maps = []
        
        try:
            # Read /proc/pid/maps
            maps_file = f"/proc/{pid}/maps"
            if os.path.exists(maps_file):
                with open(maps_file, 'r') as f:
                    for line in f:
                        parts = line.strip().split()
                        if len(parts) >= 5:
                            addr_range = parts[0]
                            perms = parts[1]
                            offset = parts[2]
                            device = parts[3]
                            inode = parts[4]
                            pathname = ' '.join(parts[5:]) if len(parts) > 5 else ''
                            
                            start_addr, end_addr = addr_range.split('-')
                            
                            memory_maps.append({
                                'start_address': f"0x{start_addr}",
                                'end_address': f"0x{end_addr}",
                                'size': int(end_addr, 16) - int(start_addr, 16),
                                'permissions': perms,
                                'offset': offset,
                                'device': device,
                                'inode': inode,
                                'pathname': pathname,
                                'is_executable': 'x' in perms,
                                'is_writable': 'w' in perms,
                                'is_readable': 'r' in perms
                            })
            
        except Exception as e:
            self.logger.error(f"Error reading memory maps for PID {pid}: {e}")
            
        return memory_maps
    
    def get_thread_info(self, pid: int) -> List[Dict]:
        """Get information about process threads"""
        threads = []
        
        try:
            # Read /proc/pid/task directory
            task_dir = f"/proc/{pid}/task"
            if os.path.exists(task_dir):
                for tid in os.listdir(task_dir):
                    if tid.isdigit():
                        thread_info = {
                            'tid': int(tid),
                            'name': '',
                            'state': '',
                            'stack_trace': ''
                        }
                        
                        # Get thread name
                        try:
                            with open(f"{task_dir}/{tid}/comm", 'r') as f:
                                thread_info['name'] = f.read().strip()
                        except:
                            pass
                            
                        # Get thread state
                        try:
                            with open(f"{task_dir}/{tid}/stat", 'r') as f:
                                stat_data = f.read().split()
                                if len(stat_data) > 2:
                                    thread_info['state'] = stat_data[2]
                        except:
                            pass
                            
                        # Get thread stack trace
                        stack_file = f"{task_dir}/{tid}/stack"
                        if os.path.exists(stack_file):
                            try:
                                with open(stack_file, 'r') as f:
                                    thread_info['stack_trace'] = f.read().strip()
                            except:
                                pass
                        
                        threads.append(thread_info)
                        
        except Exception as e:
            self.logger.error(f"Error getting thread info for PID {pid}: {e}")
            
        return threads
    
    def get_shared_libraries(self, pid: int) -> List[Dict]:
        """Get shared libraries loaded by the process"""
        libraries = []
        
        try:
            # Use lsof to get library information
            result = subprocess.run([
                'lsof', '-p', str(pid), '-Fn'
            ], capture_output=True, text=True, timeout=10)
            
            if result.returncode == 0:
                for line in result.stdout.split('\\n'):
                    if line.startswith('n') and '.so' in line:
                        lib_path = line[1:]  # Remove 'n' prefix
                        
                        lib_info = {
                            'path': lib_path,
                            'name': os.path.basename(lib_path),
                            'size': 0,
                            'type': 'shared_library'
                        }
                        
                        # Get file size
                        try:
                            if os.path.exists(lib_path):
                                lib_info['size'] = os.path.getsize(lib_path)
                        except:
                            pass
                            
                        libraries.append(lib_info)
                        
        except Exception as e:
            self.logger.error(f"Error getting shared libraries for PID {pid}: {e}")
            
        return libraries
    
    def get_file_descriptors(self, pid: int) -> List[Dict]:
        """Get detailed file descriptor information"""
        file_descriptors = []
        
        try:
            fd_dir = f"/proc/{pid}/fd"
            if os.path.exists(fd_dir):
                for fd_name in os.listdir(fd_dir):
                    if fd_name.isdigit():
                        fd_path = f"{fd_dir}/{fd_name}"
                        
                        try:
                            # Get the target of the symlink
                            target = os.readlink(fd_path)
                            
                            fd_info = {
                                'fd': int(fd_name),
                                'target': target,
                                'type': self.classify_fd_type(target)
                            }
                            
                            # Get additional info for regular files
                            if os.path.exists(target) and os.path.isfile(target):
                                try:
                                    stat_info = os.stat(target)
                                    fd_info['size'] = stat_info.st_size
                                    fd_info['permissions'] = oct(stat_info.st_mode)[-3:]
                                except:
                                    pass
                                    
                            file_descriptors.append(fd_info)
                            
                        except OSError:
                            # Broken symlink or inaccessible
                            file_descriptors.append({
                                'fd': int(fd_name),
                                'target': 'inaccessible',
                                'type': 'unknown'
                            })
                            
        except Exception as e:
            self.logger.error(f"Error getting file descriptors for PID {pid}: {e}")
            
        return file_descriptors
    
    def classify_fd_type(self, target: str) -> str:
        """Classify file descriptor type based on target"""
        if target.startswith('/dev/'):
            return 'device'
        elif target.startswith('/tmp/') or target.startswith('/var/tmp/'):
            return 'temporary_file'
        elif target.startswith('socket:'):
            return 'socket'
        elif target.startswith('pipe:'):
            return 'pipe'
        elif target.startswith('anon_inode:'):
            return 'anonymous_inode'
        elif target in ['/dev/stdin', '/dev/stdout', '/dev/stderr']:
            return 'standard_io'
        elif os.path.isfile(target):
            return 'regular_file'
        elif os.path.isdir(target):
            return 'directory'
        else:
            return 'unknown'
    
    def analyze_heap_layout(self, pid: int) -> Dict:
        """Analyze heap layout and memory usage patterns"""
        heap_info = {
            'heap_segments': [],
            'total_heap_size': 0,
            'fragmentation_info': {},
            'suspicious_patterns': []
        }
        
        try:
            # Analyze memory maps for heap segments
            maps = self.get_memory_maps(pid)
            
            heap_segments = []
            for mapping in maps:
                if (mapping['pathname'] == '[heap]' or 
                    'heap' in mapping['pathname'].lower() or
                    mapping['is_writable'] and not mapping['pathname']):
                    heap_segments.append(mapping)
                    heap_info['total_heap_size'] += mapping['size']
            
            heap_info['heap_segments'] = heap_segments
            
            # Look for suspicious patterns
            executable_heap_count = sum(1 for seg in heap_segments if seg['is_executable'])
            if executable_heap_count > 0:
                heap_info['suspicious_patterns'].append(
                    f"Executable heap segments detected: {executable_heap_count}"
                )
            
            # Check for unusually large heap allocations
            large_segments = [seg for seg in heap_segments if seg['size'] > 100 * 1024 * 1024]  # > 100MB
            if large_segments:
                heap_info['suspicious_patterns'].append(
                    f"Large heap allocations detected: {len(large_segments)} segments > 100MB"
                )
            
        except Exception as e:
            self.logger.error(f"Error analyzing heap layout for PID {pid}: {e}")
            heap_info['error'] = str(e)
            
        return heap_info
    
    def analyze_call_stack_patterns(self, stack_trace: str) -> List[str]:
        """Analyze call stack for suspicious patterns"""
        suspicious_patterns = []
        
        if not stack_trace:
            return suspicious_patterns
        
        # Look for common exploit patterns
        exploit_indicators = [
            'system', 'execve', 'execl', 'popen',  # Code execution
            'strcpy', 'strcat', 'sprintf', 'gets',  # Buffer overflow functions
            'mprotect', 'mmap', 'VirtualProtect',   # Memory protection changes
            'LoadLibrary', 'dlopen', 'dlsym',      # Dynamic library loading
            'CreateProcess', 'ShellExecute',       # Process creation
        ]
        
        for indicator in exploit_indicators:
            if indicator in stack_trace:
                suspicious_patterns.append(f"Potentially dangerous function in stack: {indicator}")
        
        # Look for ROP/JOP gadgets patterns
        if re.search(r'0x[0-9a-f]+.*ret', stack_trace, re.IGNORECASE):
            suspicious_patterns.append("Potential ROP gadget pattern detected")
        
        # Look for stack smashing indicators
        if 'stack smashing detected' in stack_trace.lower():
            suspicious_patterns.append("Stack smashing protection triggered")
        
        # Look for segmentation faults
        if 'segmentation fault' in stack_trace.lower() or 'sigsegv' in stack_trace.lower():
            suspicious_patterns.append("Segmentation fault detected - possible exploit attempt")
        
        return suspicious_patterns
    
    def save_analysis_results(self, results: Dict, output_dir: str = "/tmp"):
        """Save analysis results to file"""
        timestamp = int(time.time())
        output_file = os.path.join(output_dir, f"stack_trace_analysis_{timestamp}.json")
        
        try:
            with open(output_file, 'w') as f:
                json.dump(results, f, indent=2, default=str)
            
            self.logger.info(f"Analysis results saved to: {output_file}")
            return output_file
            
        except Exception as e:
            self.logger.error(f"Error saving results: {e}")
            return None


class ProcessMonitor:
    """Monitors processes for crashes and suspicious behavior"""
    
    def __init__(self):
        self.logger = logging.getLogger('ProcessMonitor')
        self.monitored_pids = set()
        self.crash_reports = []
        self.stack_analyzer = StackTraceAnalyzer()
        self.monitoring_active = False
        
    def add_process_to_monitor(self, pid: int):
        """Add process to monitoring list"""
        self.monitored_pids.add(pid)
        self.logger.info(f"Added PID {pid} to monitoring list")
        
    def start_monitoring(self, duration: int = 300):
        """Start process monitoring"""
        self.logger.info(f"Starting process monitoring for {duration} seconds")
        self.monitoring_active = True
        
        monitor_thread = threading.Thread(
            target=self._monitor_processes,
            args=(duration,),
            daemon=True
        )
        monitor_thread.start()
        
        return monitor_thread
    
    def _monitor_processes(self, duration: int):
        """Main monitoring loop"""
        start_time = time.time()
        
        while self.monitoring_active and (time.time() - start_time) < duration:
            try:
                current_pids = set()
                
                # Check if monitored processes are still alive
                for pid in list(self.monitored_pids):
                    try:
                        process = psutil.Process(pid)
                        current_pids.add(pid)
                        
                        # Check for process state changes
                        status = process.status()
                        if status in [psutil.STATUS_ZOMBIE, psutil.STATUS_DEAD]:
                            self.logger.warning(f"Process {pid} died with status: {status}")
                            self.handle_process_death(pid, status)
                            
                    except psutil.NoSuchProcess:
                        self.logger.warning(f"Process {pid} no longer exists")
                        self.handle_process_death(pid, "no_such_process")
                    except Exception as e:
                        self.logger.error(f"Error monitoring PID {pid}: {e}")
                
                # Update monitored PIDs
                self.monitored_pids = current_pids
                
                time.sleep(1)  # Check every second
                
            except Exception as e:
                self.logger.error(f"Error in monitoring loop: {e}")
                time.sleep(1)
                
        self.logger.info("Process monitoring stopped")
    
    def handle_process_death(self, pid: int, status: str):
        """Handle process death/crash"""
        self.logger.warning(f"Handling death of PID {pid} (status: {status})")
        
        # Generate crash report
        crash_report = {
            'pid': pid,
            'timestamp': datetime.now().isoformat(),
            'death_status': status,
            'stack_trace_analysis': None,
            'system_logs': []
        }
        
        # Try to get stack trace if process still exists
        try:
            if psutil.pid_exists(pid):
                trace_analysis = self.stack_analyzer.get_process_stack_trace(pid)
                crash_report['stack_trace_analysis'] = trace_analysis
        except:
            pass
        
        # Check system logs for crash information
        crash_report['system_logs'] = self.get_crash_logs(pid)
        
        self.crash_reports.append(crash_report)
        
        # Remove from monitoring
        self.monitored_pids.discard(pid)
        
    def get_crash_logs(self, pid: int) -> List[str]:
        """Get system logs related to process crash"""
        crash_logs = []
        
        try:
            # Check dmesg for segfaults
            result = subprocess.run([
                'dmesg', '--time-format=iso'
            ], capture_output=True, text=True, timeout=10)
            
            if result.returncode == 0:
                for line in result.stdout.split('\\n'):
                    if str(pid) in line and ('segfault' in line.lower() or 'killed' in line.lower()):
                        crash_logs.append(line.strip())
                        
        except Exception as e:
            self.logger.error(f"Error getting crash logs: {e}")
            
        return crash_logs
    
    def stop_monitoring(self):
        """Stop process monitoring"""
        self.monitoring_active = False
        self.logger.info("Stopping process monitoring")
        
    def generate_crash_report(self, output_dir: str = "/tmp") -> str:
        """Generate comprehensive crash report"""
        timestamp = int(time.time())
        report_file = os.path.join(output_dir, f"crash_report_{timestamp}.json")
        
        report_data = {
            'analysis_timestamp': datetime.now().isoformat(),
            'total_crashes': len(self.crash_reports),
            'monitored_processes': len(self.monitored_pids),
            'crash_reports': self.crash_reports
        }
        
        try:
            with open(report_file, 'w') as f:
                json.dump(report_data, f, indent=2, default=str)
            
            self.logger.info(f"Crash report saved to: {report_file}")
            return report_file
            
        except Exception as e:
            self.logger.error(f"Error saving crash report: {e}")
            return ""


def main():
    """Main function for testing stack trace analysis"""
    if len(sys.argv) < 2:
        print("Usage: python3 stack_trace_analyzer.py <target_pid> [monitor_duration]")
        print("Example: python3 stack_trace_analyzer.py 1234 300")
        sys.exit(1)
    
    target_pid = int(sys.argv[1])
    monitor_duration = int(sys.argv[2]) if len(sys.argv) > 2 else 60
    
    print(f"Stack Trace Analysis for PID: {target_pid}")
    print("=" * 50)
    
    # Analyze stack trace
    analyzer = StackTraceAnalyzer()
    trace_results = analyzer.get_process_stack_trace(target_pid)
    
    print(f"Process: {trace_results.get('process_name', 'unknown')}")
    print(f"Executable: {trace_results.get('exe_path', 'unknown')}")
    print(f"Status: {trace_results.get('status', 'unknown')}")
    
    if trace_results.get('error'):
        print(f"Error: {trace_results['error']}")
    else:
        print(f"Memory mappings: {len(trace_results['memory_maps'])}")
        print(f"Threads: {len(trace_results['thread_info'])}")
        print(f"File descriptors: {len(trace_results['file_descriptors'])}")
        print(f"Shared libraries: {len(trace_results['shared_libraries'])}")
        
        # Analyze stack trace for suspicious patterns
        if trace_results['stack_trace']:
            suspicious = analyzer.analyze_call_stack_patterns(trace_results['stack_trace'])
            if suspicious:
                print("\\nSuspicious patterns in stack trace:")
                for pattern in suspicious:
                    print(f"  - {pattern}")
        
        # Show heap analysis
        heap_info = trace_results.get('heap_info', {})
        if heap_info.get('suspicious_patterns'):
            print("\\nSuspicious heap patterns:")
            for pattern in heap_info['suspicious_patterns']:
                print(f"  - {pattern}")
    
    # Start process monitoring
    print(f"\\nStarting process monitoring for {monitor_duration} seconds...")
    monitor = ProcessMonitor()
    monitor.add_process_to_monitor(target_pid)
    
    # Find child processes
    try:
        process = psutil.Process(target_pid)
        for child in process.children(recursive=True):
            monitor.add_process_to_monitor(child.pid)
            print(f"Added child process {child.pid} to monitoring")
    except:
        pass
    
    monitor_thread = monitor.start_monitoring(monitor_duration)
    
    try:
        monitor_thread.join()
    except KeyboardInterrupt:
        print("\\nMonitoring interrupted by user")
        monitor.stop_monitoring()
    
    # Generate final reports
    print("\\nGenerating reports...")
    
    # Save stack trace analysis
    output_file = analyzer.save_analysis_results({
        'target_pid': target_pid,
        'analysis_results': trace_results,
        'monitoring_duration': monitor_duration
    })
    
    # Save crash report
    crash_report_file = monitor.generate_crash_report()
    
    print(f"\\nAnalysis completed!")
    if output_file:
        print(f"Stack trace analysis saved to: {output_file}")
    if crash_report_file:
        print(f"Crash report saved to: {crash_report_file}")


if __name__ == "__main__":
    main()