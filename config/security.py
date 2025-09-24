import configparser
import os
import logging
import tempfile
from pathlib import Path

class SentinalConfig:
    def __init__(self, config_file=None):
        self.config = configparser.ConfigParser()
        
        # Set defaults
        self._set_defaults()
        
        # Load configuration file
        if config_file is None:
            config_file = os.path.join(os.path.dirname(__file__), '..', 'config', 'sentinal.conf')
        
        if os.path.exists(config_file):
            self.config.read(config_file)
    
    def _set_defaults(self):
        """Set default configuration values"""
        self.config['analysis'] = {
            'max_timeout': '300',
            'default_timeout': '30',
            'max_file_size': '100',
            'max_concurrent_analyses': '3'
        }
        
        self.config['monitoring'] = {
            'enable_process_monitor': 'true',
            'enable_network_monitor': 'true',
            'enable_memory_analysis': 'true',
            'max_syscalls': '10000',
            'max_processes': '500'
        }
        
        self.config['security'] = {
            'allowed_extensions': '.py,.sh,.elf,.out,.bin,.exe',
            'blocked_paths': '/etc/,/usr/bin/,/bin/,/sbin/',
            'enable_sandboxing': 'false',
            'sandbox_timeout': '60',
            'max_memory_usage': '1024'
        }
        
        self.config['network'] = {
            'monitor_duration': '30',
            'capture_dns': 'true',
            'suspicious_ports': '1337,4444,5555,6666,8080,9999',
            'block_network': 'false'
        }
        
        self.config['logging'] = {
            'log_level': 'INFO',
            'log_file': '/tmp/sentinal.log',
            'rotate_logs': 'true',
            'max_log_size': '10'
        }
        
        self.config['paths'] = {
            'temp_dir': '/tmp/sentinal',
            'output_dir': './results',
            'monitor_binary': './process_monitor'
        }
        
        self.config['visualization'] = {
            'enable_graphs': 'true',
            'graph_format': 'png',
            'graph_dpi': '150',
            'max_graph_nodes': '100'
        }
    
    def get_analysis_config(self):
        """Get analysis configuration"""
        return {
            'max_timeout': self.config.getint('analysis', 'max_timeout'),
            'default_timeout': self.config.getint('analysis', 'default_timeout'),
            'max_file_size': self.config.getint('analysis', 'max_file_size'),
            'max_concurrent_analyses': self.config.getint('analysis', 'max_concurrent_analyses')
        }
    
    def get_security_config(self):
        """Get security configuration"""
        allowed_ext = self.config.get('security', 'allowed_extensions').split(',')
        blocked_paths = self.config.get('security', 'blocked_paths').split(',')
        
        return {
            'allowed_extensions': [ext.strip() for ext in allowed_ext],
            'blocked_paths': [path.strip() for path in blocked_paths],
            'enable_sandboxing': self.config.getboolean('security', 'enable_sandboxing'),
            'sandbox_timeout': self.config.getint('security', 'sandbox_timeout'),
            'max_memory_usage': self.config.getint('security', 'max_memory_usage')
        }
    
    def get_monitoring_config(self):
        """Get monitoring configuration"""
        return {
            'enable_process_monitor': self.config.getboolean('monitoring', 'enable_process_monitor'),
            'enable_network_monitor': self.config.getboolean('monitoring', 'enable_network_monitor'),
            'enable_memory_analysis': self.config.getboolean('monitoring', 'enable_memory_analysis'),
            'max_syscalls': self.config.getint('monitoring', 'max_syscalls'),
            'max_processes': self.config.getint('monitoring', 'max_processes')
        }
    
    def get_paths_config(self):
        """Get paths configuration"""
        return {
            'temp_dir': self.config.get('paths', 'temp_dir'),
            'output_dir': self.config.get('paths', 'output_dir'),
            'monitor_binary': self.config.get('paths', 'monitor_binary')
        }
    
    def setup_logging(self):
        """Setup logging based on configuration"""
        log_level = getattr(logging, self.config.get('logging', 'log_level').upper())
        log_file = self.config.get('logging', 'log_file')
        
        logging.basicConfig(
            level=log_level,
            format='%(asctime)s - %(name)s - %(levelname)s - %(message)s',
            handlers=[
                logging.FileHandler(log_file),
                logging.StreamHandler()
            ]
        )
    
    def ensure_directories(self):
        """Ensure required directories exist"""
        paths = self.get_paths_config()
        
        for dir_path in [paths['temp_dir'], paths['output_dir']]:
            Path(dir_path).mkdir(parents=True, exist_ok=True)

class SecurityValidator:
    def __init__(self, config):
        self.config = config
        self.security_config = config.get_security_config()
    
    def validate_file_path(self, file_path):
        """Validate if file path is allowed for analysis"""
        errors = []
        
        # Check if file exists
        if not os.path.exists(file_path):
            errors.append(f"File does not exist: {file_path}")
            return errors
        
        # Check file extension
        file_ext = os.path.splitext(file_path)[1].lower()
        if file_ext not in self.security_config['allowed_extensions']:
            errors.append(f"File extension '{file_ext}' not allowed")
        
        # Check blocked paths
        abs_path = os.path.abspath(file_path)
        for blocked_path in self.security_config['blocked_paths']:
            if abs_path.startswith(blocked_path):
                errors.append(f"File in blocked path: {blocked_path}")
        
        # Check file size
        try:
            file_size = os.path.getsize(file_path) / (1024 * 1024)  # MB
            max_size = self.config.get_analysis_config()['max_file_size']
            if file_size > max_size:
                errors.append(f"File too large: {file_size:.1f}MB > {max_size}MB")
        except OSError as e:
            errors.append(f"Cannot access file: {e}")
        
        return errors
    
    def validate_timeout(self, timeout):
        """Validate analysis timeout"""
        max_timeout = self.config.get_analysis_config()['max_timeout']
        
        if timeout > max_timeout:
            return f"Timeout too large: {timeout}s > {max_timeout}s"
        
        if timeout < 1:
            return "Timeout must be at least 1 second"
        
        return None

class SandboxManager:
    def __init__(self, config):
        self.config = config
        self.security_config = config.get_security_config()
    
    def create_sandbox_environment(self):
        """Create a sandboxed environment for analysis"""
        if not self.security_config['enable_sandboxing']:
            return None
        
        # Create temporary directory for sandbox
        sandbox_dir = tempfile.mkdtemp(prefix='sentinal_sandbox_')
        
        # TODO: Implement proper sandboxing with:
        # - chroot jail
        # - resource limits
        # - network isolation
        # - filesystem restrictions
        
        return {
            'sandbox_dir': sandbox_dir,
            'cleanup_required': True
        }
    
    def cleanup_sandbox(self, sandbox_info):
        """Clean up sandbox environment"""
        if sandbox_info and sandbox_info.get('cleanup_required'):
            sandbox_dir = sandbox_info.get('sandbox_dir')
            if sandbox_dir and os.path.exists(sandbox_dir):
                import shutil
                shutil.rmtree(sandbox_dir, ignore_errors=True)