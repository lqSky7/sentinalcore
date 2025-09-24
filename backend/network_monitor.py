import psutil
import socket
import threading
import time
import json
from datetime import datetime
import subprocess
import re

class NetworkMonitor:
    def __init__(self):
        self.connections = []
        self.dns_queries = []
        self.network_stats = {}
        self.monitoring = False
        self.monitor_thread = None
        
    def start_monitoring(self, target_pid=None, duration=30):
        """Start network monitoring for specified duration"""
        self.monitoring = True
        self.connections = []
        self.dns_queries = []
        
        def monitor_loop():
            start_time = time.time()
            
            while self.monitoring and (time.time() - start_time) < duration:
                # Monitor network connections
                self._capture_connections(target_pid)
                
                # Monitor DNS queries (requires root for packet capture)
                self._capture_dns_queries()
                
                # Monitor network statistics
                self._capture_network_stats()
                
                time.sleep(1)
        
        self.monitor_thread = threading.Thread(target=monitor_loop)
        self.monitor_thread.start()
    
    def stop_monitoring(self):
        """Stop network monitoring"""
        self.monitoring = False
        if self.monitor_thread:
            self.monitor_thread.join()
    
    def _capture_connections(self, target_pid=None):
        """Capture active network connections"""
        try:
            connections = psutil.net_connections(kind='inet')
            
            for conn in connections:
                # Filter by target PID if specified
                if target_pid and conn.pid != target_pid:
                    continue
                
                conn_info = {
                    'timestamp': datetime.now().isoformat(),
                    'pid': conn.pid,
                    'family': conn.family.name if conn.family else 'unknown',
                    'type': conn.type.name if conn.type else 'unknown',
                    'local_addr': None,
                    'remote_addr': None,
                    'status': conn.status if hasattr(conn, 'status') else 'unknown'
                }
                
                if conn.laddr:
                    conn_info['local_addr'] = f"{conn.laddr.ip}:{conn.laddr.port}"
                
                if conn.raddr:
                    conn_info['remote_addr'] = f"{conn.raddr.ip}:{conn.raddr.port}"
                    
                    # Try to get process name
                    try:
                        if conn.pid:
                            proc = psutil.Process(conn.pid)
                            conn_info['process_name'] = proc.name()
                    except (psutil.NoSuchProcess, psutil.AccessDenied):
                        conn_info['process_name'] = 'unknown'
                
                # Avoid duplicates (simple check)
                if not any(c['local_addr'] == conn_info['local_addr'] and 
                          c['remote_addr'] == conn_info['remote_addr'] 
                          for c in self.connections[-10:]):
                    self.connections.append(conn_info)
                    
        except (psutil.AccessDenied, Exception) as e:
            pass  # Continue monitoring despite errors
    
    def _capture_dns_queries(self):
        """Capture DNS queries using netstat or ss"""
        try:
            # Try to capture DNS queries by monitoring port 53 connections
            result = subprocess.run(['ss', '-tuln'], 
                                  capture_output=True, text=True, timeout=2)
            
            if result.returncode == 0:
                lines = result.stdout.split('\n')
                for line in lines:
                    if ':53' in line:  # DNS port
                        # Parse DNS-related connections
                        parts = line.split()
                        if len(parts) >= 5:
                            dns_info = {
                                'timestamp': datetime.now().isoformat(),
                                'type': 'dns',
                                'local_addr': parts[4] if len(parts) > 4 else '',
                                'state': parts[1] if len(parts) > 1 else ''
                            }
                            self.dns_queries.append(dns_info)
                            
        except (subprocess.TimeoutExpired, subprocess.CalledProcessError, FileNotFoundError):
            pass
    
    def _capture_network_stats(self):
        """Capture network interface statistics"""
        try:
            stats = psutil.net_io_counters(pernic=True)
            self.network_stats = {
                'timestamp': datetime.now().isoformat(),
                'interfaces': {}
            }
            
            for interface, stat in stats.items():
                self.network_stats['interfaces'][interface] = {
                    'bytes_sent': stat.bytes_sent,
                    'bytes_recv': stat.bytes_recv,
                    'packets_sent': stat.packets_sent,
                    'packets_recv': stat.packets_recv,
                    'errin': stat.errin,
                    'errout': stat.errout,
                    'dropin': stat.dropin,
                    'dropout': stat.dropout
                }
                
        except Exception:
            pass
    
    def analyze_network_activity(self):
        """Analyze captured network activity for suspicious patterns"""
        analysis = {
            'total_connections': len(self.connections),
            'unique_remote_ips': set(),
            'port_activity': {},
            'suspicious_patterns': [],
            'connection_summary': {},
            'dns_activity': len(self.dns_queries)
        }
        
        # Analyze connections
        for conn in self.connections:
            if conn.get('remote_addr'):
                remote_ip = conn['remote_addr'].split(':')[0]
                analysis['unique_remote_ips'].add(remote_ip)
                
                # Count port activity
                remote_port = conn['remote_addr'].split(':')[1] if ':' in conn['remote_addr'] else 'unknown'
                analysis['port_activity'][remote_port] = analysis['port_activity'].get(remote_port, 0) + 1
        
        analysis['unique_remote_ips'] = len(analysis['unique_remote_ips'])
        
        # Detect suspicious patterns
        suspicious_ports = ['1337', '4444', '5555', '6666', '8080', '9999']
        for port in suspicious_ports:
            if port in analysis['port_activity']:
                analysis['suspicious_patterns'].append(f'Connection to suspicious port {port}')
        
        # Check for high number of connections
        if analysis['total_connections'] > 50:
            analysis['suspicious_patterns'].append('High number of network connections')
        
        # Check for connections to private IP ranges that might indicate lateral movement
        private_ips = 0
        for conn in self.connections:
            if conn.get('remote_addr'):
                remote_ip = conn['remote_addr'].split(':')[0]
                if (remote_ip.startswith('192.168.') or 
                    remote_ip.startswith('10.') or 
                    remote_ip.startswith('172.16.')):
                    private_ips += 1
        
        if private_ips > 10:
            analysis['suspicious_patterns'].append('Multiple connections to private IP ranges (possible lateral movement)')
        
        # Most active ports
        analysis['top_ports'] = dict(sorted(analysis['port_activity'].items(), 
                                           key=lambda x: x[1], reverse=True)[:10])
        
        return analysis
    
    def get_results(self):
        """Get monitoring results"""
        return {
            'connections': self.connections,
            'dns_queries': self.dns_queries,
            'network_stats': self.network_stats,
            'analysis': self.analyze_network_activity()
        }

class ProcessNetworkTracker:
    """Track network activity for specific processes"""
    
    def __init__(self, target_pids=None):
        self.target_pids = target_pids or []
        self.process_connections = {}
    
    def track_process_network(self, pid, duration=30):
        """Track network activity for a specific process"""
        monitor = NetworkMonitor()
        monitor.start_monitoring(target_pid=pid, duration=duration)
        
        # Wait for monitoring to complete
        time.sleep(duration + 1)
        monitor.stop_monitoring()
        
        results = monitor.get_results()
        self.process_connections[pid] = results
        
        return results
    
    def get_process_network_summary(self, pid):
        """Get network summary for a process"""
        if pid not in self.process_connections:
            return {'error': 'No network data for this process'}
        
        data = self.process_connections[pid]
        return {
            'connections': len(data['connections']),
            'unique_ips': len(set(conn.get('remote_addr', '').split(':')[0] 
                                 for conn in data['connections'] 
                                 if conn.get('remote_addr'))),
            'suspicious_activity': data['analysis']['suspicious_patterns'],
            'top_ports': data['analysis']['top_ports']
        }