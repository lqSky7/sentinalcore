#!/usr/bin/env python3
"""
Process Tree and Network Flow Analyzer
Advanced visualization and analysis of malware process trees and network communications
"""

import os
import sys
import json
import time
import psutil
import socket
import struct
import threading
from datetime import datetime
from typing import Dict, List, Set, Optional, Tuple
from collections import defaultdict, deque
import logging

# Network protocol mappings
PROTOCOL_MAP = {
    1: 'ICMP', 6: 'TCP', 17: 'UDP', 41: 'IPv6', 
    47: 'GRE', 50: 'ESP', 51: 'AH', 132: 'SCTP'
}

SOCKET_TYPE_MAP = {
    1: 'STREAM', 2: 'DGRAM', 3: 'RAW', 4: 'RDM', 
    5: 'SEQPACKET', 10: 'PACKET'
}

FAMILY_MAP = {
    2: 'AF_INET', 10: 'AF_INET6', 16: 'AF_NETLINK', 
    17: 'AF_PACKET', 1: 'AF_UNIX'
}

class ProcessTreeAnalyzer:
    """Analyzes and tracks process trees with advanced features"""
    
    def __init__(self):
        self.logger = logging.getLogger('ProcessTreeAnalyzer')
        self.process_tree = {}
        self.process_relationships = defaultdict(list)
        self.process_history = []
        self.suspicious_patterns = []
        
    def build_process_tree(self, root_pid: int) -> Dict:
        """Build comprehensive process tree from root PID"""
        self.logger.info(f"Building process tree from root PID: {root_pid}")
        
        def get_process_details(pid: int) -> Dict:
            """Get detailed process information"""
            try:
                process = psutil.Process(pid)
                
                # Get process info
                info = {
                    'pid': pid,
                    'ppid': process.ppid(),
                    'name': process.name(),
                    'exe': process.exe(),
                    'cmdline': process.cmdline(),
                    'cwd': process.cwd(),
                    'username': process.username(),
                    'status': process.status(),
                    'create_time': datetime.fromtimestamp(process.create_time()).isoformat(),
                    'cpu_percent': process.cpu_percent(),
                    'memory_percent': process.memory_percent(),
                    'memory_info': process.memory_info()._asdict(),
                    'num_threads': process.num_threads(),
                    'num_fds': process.num_fds(),
                    'children': [],
                    'open_files': [],
                    'connections': [],
                    'environment': {},
                    'limits': {},
                    'io_counters': {},
                    'ctx_switches': {},
                    'cpu_times': {}
                }
                
                # Get additional details
                try:
                    info['open_files'] = [f._asdict() for f in process.open_files()]
                except (psutil.AccessDenied, psutil.NoSuchProcess):
                    pass
                    
                try:
                    info['connections'] = [c._asdict() for c in process.connections()]
                except (psutil.AccessDenied, psutil.NoSuchProcess):
                    pass
                    
                try:
                    info['environment'] = dict(process.environ())
                except (psutil.AccessDenied, psutil.NoSuchProcess):
                    pass
                    
                try:
                    info['limits'] = process.rlimit(psutil.RLIMIT_NOFILE)
                except (psutil.AccessDenied, psutil.NoSuchProcess):
                    pass
                    
                try:
                    info['io_counters'] = process.io_counters()._asdict()
                except (psutil.AccessDenied, psutil.NoSuchProcess):
                    pass
                    
                try:
                    info['ctx_switches'] = process.num_ctx_switches()._asdict()
                except (psutil.AccessDenied, psutil.NoSuchProcess):
                    pass
                    
                try:
                    info['cpu_times'] = process.cpu_times()._asdict()
                except (psutil.AccessDenied, psutil.NoSuchProcess):
                    pass
                
                return info
                
            except (psutil.NoSuchProcess, psutil.AccessDenied, psutil.ZombieProcess) as e:
                self.logger.warning(f"Error getting process info for PID {pid}: {e}")
                return {
                    'pid': pid,
                    'error': str(e),
                    'status': 'inaccessible'
                }
        
        def traverse_children(pid: int, depth: int = 0) -> None:
            """Recursively traverse and build process tree"""
            if depth > 10:  # Prevent infinite recursion
                return
                
            try:
                process = psutil.Process(pid)
                children = process.children(recursive=False)
                
                # Add current process to tree
                if pid not in self.process_tree:
                    self.process_tree[pid] = get_process_details(pid)
                
                # Process children
                child_pids = []
                for child in children:
                    child_pid = child.pid
                    child_pids.append(child_pid)
                    
                    # Add relationship
                    self.process_relationships[pid].append(child_pid)
                    
                    # Recursively process child
                    traverse_children(child_pid, depth + 1)
                
                # Update children list
                self.process_tree[pid]['children'] = child_pids
                
            except (psutil.NoSuchProcess, psutil.AccessDenied):
                pass
        
        # Start traversal from root
        traverse_children(root_pid)
        
        # Analyze for suspicious patterns
        self.analyze_suspicious_patterns()
        
        return self.process_tree
    
    def analyze_suspicious_patterns(self):
        """Analyze process tree for suspicious patterns"""
        self.logger.info("Analyzing process tree for suspicious patterns")
        
        suspicious_names = [
            'nc', 'netcat', 'ncat', 'socat', 'wget', 'curl', 'python', 'python3',
            'perl', 'ruby', 'php', 'bash', 'sh', 'dash', 'zsh', 'ksh',
            'base64', 'uudecode', 'xxd', 'hexdump', 'od',
            'gdb', 'strace', 'ltrace', 'ptrace', 'objdump', 'readelf'
        ]
        
        suspicious_paths = [
            '/tmp/', '/var/tmp/', '/dev/shm/', '/proc/', '/sys/',
            '/.', '/home/', '/usr/local/', '/opt/'
        ]
        
        for pid, info in self.process_tree.items():
            patterns = []
            
            # Check process name
            name = info.get('name', '').lower()
            if any(sus_name in name for sus_name in suspicious_names):
                patterns.append(f"Suspicious process name: {name}")
            
            # Check executable path
            exe = info.get('exe', '')
            if any(sus_path in exe for sus_path in suspicious_paths):
                patterns.append(f"Suspicious executable path: {exe}")
            
            # Check command line arguments
            cmdline = ' '.join(info.get('cmdline', []))
            if any(keyword in cmdline.lower() for keyword in ['download', 'wget', 'curl', 'base64', 'reverse', 'shell']):
                patterns.append(f"Suspicious command line: {cmdline}")
            
            # Check network connections
            connections = info.get('connections', [])
            if connections:
                patterns.append(f"Network connections detected: {len(connections)} connections")
            
            # Check open files in suspicious locations
            open_files = info.get('open_files', [])
            for file_info in open_files:
                path = file_info.get('path', '')
                if any(sus_path in path for sus_path in suspicious_paths):
                    patterns.append(f"Suspicious file access: {path}")
            
            # Check for high resource usage
            cpu_percent = info.get('cpu_percent', 0)
            memory_percent = info.get('memory_percent', 0)
            if cpu_percent > 50 or memory_percent > 25:
                patterns.append(f"High resource usage: CPU {cpu_percent}%, Memory {memory_percent}%")
            
            # Check for process injection indicators
            num_threads = info.get('num_threads', 0)
            if num_threads > 20:
                patterns.append(f"High thread count: {num_threads} threads")
            
            if patterns:
                self.suspicious_patterns.append({
                    'pid': pid,
                    'name': info.get('name', 'unknown'),
                    'patterns': patterns,
                    'severity': 'high' if len(patterns) > 3 else 'medium'
                })
    
    def get_process_lineage(self, target_pid: int) -> List[Dict]:
        """Get complete lineage (ancestry) of a process"""
        lineage = []
        current_pid = target_pid
        
        while current_pid and current_pid in self.process_tree:
            process_info = self.process_tree[current_pid]
            lineage.append({
                'pid': current_pid,
                'name': process_info.get('name', 'unknown'),
                'exe': process_info.get('exe', 'unknown'),
                'cmdline': ' '.join(process_info.get('cmdline', [])),
                'create_time': process_info.get('create_time')
            })
            
            # Move to parent
            current_pid = process_info.get('ppid')
            if current_pid == 0 or current_pid == current_pid:  # Avoid infinite loop
                break
        
        return lineage
    
    def visualize_tree(self, root_pid: int, max_depth: int = 5) -> str:
        """Generate ASCII visualization of process tree"""
        output = []
        
        def draw_process(pid: int, prefix: str = "", depth: int = 0):
            if depth > max_depth or pid not in self.process_tree:
                return
                
            info = self.process_tree[pid]
            name = info.get('name', 'unknown')
            cmdline = ' '.join(info.get('cmdline', []))[:50]
            cpu = info.get('cpu_percent', 0)
            mem = info.get('memory_percent', 0)
            
            output.append(f"{prefix}├─ PID {pid}: {name}")
            output.append(f"{prefix}│  Command: {cmdline}")
            output.append(f"{prefix}│  CPU: {cpu:.1f}%, Memory: {mem:.1f}%")
            
            children = info.get('children', [])
            for i, child_pid in enumerate(children):
                is_last = (i == len(children) - 1)
                child_prefix = prefix + ("   " if is_last else "│  ")
                draw_process(child_pid, child_prefix, depth + 1)
        
        output.append(f"Process Tree (Root: {root_pid})")
        output.append("=" * 50)
        draw_process(root_pid)
        
        return "\\n".join(output)


class NetworkFlowAnalyzer:
    """Analyzes network flows and communications"""
    
    def __init__(self):
        self.logger = logging.getLogger('NetworkFlowAnalyzer')
        self.active_connections = {}
        self.connection_history = []
        self.dns_queries = []
        self.suspicious_connections = []
        self.network_stats = defaultdict(int)
        
    def analyze_connections(self, processes: Dict[int, Dict]) -> Dict:
        """Analyze network connections from process data"""
        self.logger.info("Analyzing network connections")
        
        connection_data = {
            'active_connections': [],
            'connection_summary': {},
            'suspicious_connections': [],
            'network_statistics': {},
            'dns_analysis': [],
            'traffic_patterns': []
        }
        
        all_connections = []
        
        # Collect all connections
        for pid, process_info in processes.items():
            connections = process_info.get('connections', [])
            
            for conn in connections:
                conn_info = {
                    'pid': pid,
                    'process_name': process_info.get('name', 'unknown'),
                    'exe': process_info.get('exe', 'unknown'),
                    'family': FAMILY_MAP.get(conn.get('family', 0), f"Family_{conn.get('family', 0)}"),
                    'type': SOCKET_TYPE_MAP.get(conn.get('type', 0), f"Type_{conn.get('type', 0)}"),
                    'local_address': f"{conn.get('laddr', {}).get('ip', '0.0.0.0')}:{conn.get('laddr', {}).get('port', 0)}",
                    'remote_address': f"{conn.get('raddr', {}).get('ip', '0.0.0.0')}:{conn.get('raddr', {}).get('port', 0)}" if conn.get('raddr') else "",
                    'status': conn.get('status', 'UNKNOWN'),
                    'fd': conn.get('fd', -1)
                }
                
                all_connections.append(conn_info)
                
                # Check for suspicious connections
                self.check_suspicious_connection(conn_info)
        
        connection_data['active_connections'] = all_connections
        
        # Generate summary statistics
        connection_data['connection_summary'] = self.generate_connection_summary(all_connections)
        
        # Analyze traffic patterns
        connection_data['traffic_patterns'] = self.analyze_traffic_patterns(all_connections)
        
        # DNS analysis (if available)
        connection_data['dns_analysis'] = self.analyze_dns_patterns(all_connections)
        
        connection_data['suspicious_connections'] = self.suspicious_connections
        connection_data['network_statistics'] = dict(self.network_stats)
        
        return connection_data
    
    def check_suspicious_connection(self, conn_info: Dict):
        """Check if a connection is suspicious"""
        suspicious_indicators = []
        
        remote_addr = conn_info.get('remote_address', '')
        remote_ip = remote_addr.split(':')[0] if ':' in remote_addr else ''
        remote_port = int(remote_addr.split(':')[1]) if ':' in remote_addr and remote_addr.split(':')[1].isdigit() else 0
        
        # Check for suspicious ports
        suspicious_ports = [
            1234, 4444, 5555, 6666, 7777, 8888, 9999,  # Common backdoor ports
            31337, 12345, 54321,  # Well-known trojan ports
            6667, 6697,  # IRC
            1337, 8080, 8443, 9001  # Common alternative ports
        ]
        
        if remote_port in suspicious_ports:
            suspicious_indicators.append(f"Connection to suspicious port: {remote_port}")
        
        # Check for suspicious IPs
        if remote_ip:
            # Private IP ranges (could be internal C&C)
            private_ranges = [
                ('10.0.0.0', '10.255.255.255'),
                ('172.16.0.0', '172.31.255.255'),
                ('192.168.0.0', '192.168.255.255')
            ]
            
            # Convert IP to int for comparison
            def ip_to_int(ip):
                try:
                    return struct.unpack("!I", socket.inet_aton(ip))[0]
                except:
                    return 0
            
            remote_ip_int = ip_to_int(remote_ip)
            
            for start_ip, end_ip in private_ranges:
                if ip_to_int(start_ip) <= remote_ip_int <= ip_to_int(end_ip):
                    suspicious_indicators.append(f"Connection to private IP range: {remote_ip}")
                    break
            
            # Check for loopback connections (could be local backdoors)
            if remote_ip.startswith('127.'):
                suspicious_indicators.append(f"Loopback connection: {remote_ip}")
        
        # Check for suspicious process names
        process_name = conn_info.get('process_name', '').lower()
        suspicious_processes = ['nc', 'netcat', 'python', 'perl', 'ruby', 'bash', 'sh']
        if any(sus_proc in process_name for sus_proc in suspicious_processes):
            suspicious_indicators.append(f"Connection from suspicious process: {process_name}")
        
        if suspicious_indicators:
            self.suspicious_connections.append({
                'connection': conn_info,
                'indicators': suspicious_indicators,
                'risk_level': 'high' if len(suspicious_indicators) > 2 else 'medium'
            })
    
    def generate_connection_summary(self, connections: List[Dict]) -> Dict:
        """Generate summary statistics for connections"""
        summary = {
            'total_connections': len(connections),
            'by_protocol': defaultdict(int),
            'by_status': defaultdict(int),
            'by_process': defaultdict(int),
            'unique_remote_ips': set(),
            'unique_remote_ports': set(),
            'listening_ports': [],
            'outbound_connections': [],
            'connection_families': defaultdict(int)
        }
        
        for conn in connections:
            # Protocol breakdown
            conn_type = conn.get('type', 'UNKNOWN')
            summary['by_protocol'][conn_type] += 1
            
            # Status breakdown
            status = conn.get('status', 'UNKNOWN')
            summary['by_status'][status] += 1
            
            # Process breakdown
            process_name = conn.get('process_name', 'unknown')
            summary['by_process'][process_name] += 1
            
            # Family breakdown
            family = conn.get('family', 'UNKNOWN')
            summary['connection_families'][family] += 1
            
            # Remote analysis
            remote_addr = conn.get('remote_address', '')
            if remote_addr and remote_addr != '0.0.0.0:0':
                remote_ip = remote_addr.split(':')[0]
                remote_port = remote_addr.split(':')[1] if ':' in remote_addr else '0'
                
                summary['unique_remote_ips'].add(remote_ip)
                if remote_port.isdigit():
                    summary['unique_remote_ports'].add(int(remote_port))
                    
                summary['outbound_connections'].append({
                    'remote_ip': remote_ip,
                    'remote_port': remote_port,
                    'process': process_name,
                    'status': status
                })
            
            # Listening ports
            if status == 'LISTEN':
                local_addr = conn.get('local_address', '')
                if local_addr:
                    local_port = local_addr.split(':')[1] if ':' in local_addr else '0'
                    if local_port.isdigit():
                        summary['listening_ports'].append({
                            'port': int(local_port),
                            'process': process_name,
                            'pid': conn.get('pid', 0)
                        })
        
        # Convert sets to lists for JSON serialization
        summary['unique_remote_ips'] = list(summary['unique_remote_ips'])
        summary['unique_remote_ports'] = sorted(list(summary['unique_remote_ports']))
        
        return dict(summary)
    
    def analyze_traffic_patterns(self, connections: List[Dict]) -> List[Dict]:
        """Analyze traffic patterns for anomalies"""
        patterns = []
        
        # Port scanning detection
        port_connections = defaultdict(list)
        for conn in connections:
            remote_addr = conn.get('remote_address', '')
            if remote_addr and remote_addr != '0.0.0.0:0':
                remote_ip = remote_addr.split(':')[0]
                remote_port = remote_addr.split(':')[1] if ':' in remote_addr else '0'
                
                if remote_port.isdigit():
                    port_connections[remote_ip].append(int(remote_port))
        
        # Look for connections to many ports on same IP (potential port scan)
        for ip, ports in port_connections.items():
            if len(set(ports)) > 10:
                patterns.append({
                    'type': 'potential_port_scan',
                    'description': f"Multiple port connections to {ip}",
                    'details': f"Connected to {len(set(ports))} different ports",
                    'severity': 'medium'
                })
        
        # High volume connection detection
        process_conn_count = defaultdict(int)
        for conn in connections:
            process_conn_count[conn.get('process_name', 'unknown')] += 1
        
        for process, count in process_conn_count.items():
            if count > 20:
                patterns.append({
                    'type': 'high_connection_volume',
                    'description': f"High connection count for process: {process}",
                    'details': f"{count} total connections",
                    'severity': 'high'
                })
        
        return patterns
    
    def analyze_dns_patterns(self, connections: List[Dict]) -> List[Dict]:
        """Analyze DNS-related patterns"""
        dns_analysis = []
        
        # Look for DNS connections (port 53)
        dns_connections = [
            conn for conn in connections 
            if '53' in conn.get('remote_address', '')
        ]
        
        if dns_connections:
            dns_analysis.append({
                'type': 'dns_activity',
                'description': f"DNS connections detected",
                'details': f"{len(dns_connections)} DNS connections",
                'connections': dns_connections[:5]  # Show first 5
            })
        
        return dns_analysis


def main():
    """Main function for testing analyzers"""
    if len(sys.argv) < 2:
        print("Usage: python3 process_network_analyzer.py <target_pid>")
        sys.exit(1)
    
    target_pid = int(sys.argv[1])
    
    # Setup logging
    logging.basicConfig(level=logging.INFO)
    
    print(f"Analyzing process tree and network flows for PID: {target_pid}")
    print("=" * 60)
    
    # Analyze process tree
    tree_analyzer = ProcessTreeAnalyzer()
    process_tree = tree_analyzer.build_process_tree(target_pid)
    
    print("\\nProcess Tree Analysis:")
    print(tree_analyzer.visualize_tree(target_pid))
    
    if tree_analyzer.suspicious_patterns:
        print("\\nSuspicious Patterns Detected:")
        for pattern in tree_analyzer.suspicious_patterns:
            print(f"  PID {pattern['pid']} ({pattern['name']}): {pattern['severity'].upper()}")
            for p in pattern['patterns']:
                print(f"    - {p}")
    
    # Analyze network flows
    network_analyzer = NetworkFlowAnalyzer()
    network_data = network_analyzer.analyze_connections(process_tree)
    
    print(f"\\nNetwork Analysis:")
    print(f"  Total Connections: {network_data['connection_summary']['total_connections']}")
    print(f"  Unique Remote IPs: {len(network_data['connection_summary']['unique_remote_ips'])}")
    print(f"  Listening Ports: {len(network_data['connection_summary']['listening_ports'])}")
    
    if network_data['suspicious_connections']:
        print("\\nSuspicious Network Activity:")
        for susp_conn in network_data['suspicious_connections']:
            conn = susp_conn['connection']
            print(f"  PID {conn['pid']}: {conn['remote_address']} ({susp_conn['risk_level'].upper()})")
            for indicator in susp_conn['indicators']:
                print(f"    - {indicator}")
    
    # Save detailed results
    output_file = f"/tmp/process_network_analysis_{target_pid}_{int(time.time())}.json"
    
    results = {
        'analysis_time': datetime.now().isoformat(),
        'target_pid': target_pid,
        'process_tree': process_tree,
        'suspicious_patterns': tree_analyzer.suspicious_patterns,
        'network_analysis': network_data
    }
    
    with open(output_file, 'w') as f:
        json.dump(results, f, indent=2, default=str)
    
    print(f"\\nDetailed results saved to: {output_file}")


if __name__ == "__main__":
    main()