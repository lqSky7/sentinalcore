#!/usr/bin/env python3
"""
Comprehensive Malware Analysis & Detection Web Dashboard
Real-time web interface to display malware analysis results and run detection scans
"""

import os
import sys
import json
import time
import glob
import threading
from datetime import datetime
from flask import Flask, render_template, jsonify, request, send_from_directory, redirect, url_for
from pathlib import Path
import subprocess
import tempfile

# Add detection directory to Python path
detection_dir = os.path.join(os.path.dirname(os.path.dirname(__file__)), 'detection')
sys.path.insert(0, detection_dir)

try:
    from main import MalwareDetector
    from entropy import EntropyAnalyzer
    from LLMlogs import LogAnalyzer
    DETECTION_AVAILABLE = True
except ImportError as e:
    print(f"Detection modules not available: {e}")
    DETECTION_AVAILABLE = False

app = Flask(__name__)
app.config['SECRET_KEY'] = 'malware-analysis-dashboard-2024'

# Global variables
ANALYSIS_DIR = "/tmp/malware_analysis"
EBPF_TRACES_DIR = "/tmp"
current_analysis = None
analysis_files = []
detection_results = {}
scan_jobs = {}

# Detection configuration
VIRUSTOTAL_API_KEY = os.environ.get('VIRUSTOTAL_API_KEY', '')
GEMINI_API_KEY = os.environ.get('GEMINI_API_KEY', '')
detector = None

if DETECTION_AVAILABLE and (VIRUSTOTAL_API_KEY or GEMINI_API_KEY):
    try:
        detector = MalwareDetector(
            virustotal_api_key=VIRUSTOTAL_API_KEY,
            gemini_api_key=GEMINI_API_KEY
        )
        print("Detection engines initialized")
    except Exception as e:
        print(f"Failed to initialize detection engines: {e}")
        detector = None

def load_latest_analysis():
    """Load the latest analysis results"""
    global current_analysis, analysis_files
    
    try:
        # Find all analysis JSON files
        pattern = os.path.join(ANALYSIS_DIR, "malware_analysis_*.json")
        files = glob.glob(pattern)
        
        # Also check for eBPF trace files
        ebpf_pattern = os.path.join(EBPF_TRACES_DIR, "ebpf_trace_*.json")
        ebpf_files = glob.glob(ebpf_pattern)
        
        analysis_files = sorted(files + ebpf_files, key=os.path.getmtime, reverse=True)
        
        if analysis_files:
            latest_file = analysis_files[0]
            with open(latest_file, 'r') as f:
                current_analysis = json.load(f)
                current_analysis['source_file'] = latest_file
                current_analysis['last_updated'] = datetime.fromtimestamp(
                    os.path.getmtime(latest_file)
                ).isoformat()
        else:
            current_analysis = None
            
    except Exception as e:
        print(f"Error loading analysis: {e}")
        current_analysis = None

def watch_analysis_files():
    """Background thread to watch for new analysis files"""
    last_check = 0
    
    while True:
        try:
            # Check if any files have been modified
            current_time = time.time()
            if current_time - last_check > 5:  # Check every 5 seconds
                load_latest_analysis()
                last_check = current_time
                
        except Exception as e:
            print(f"Error in file watcher: {e}")
            
        time.sleep(5)

# Start file watcher thread
watcher_thread = threading.Thread(target=watch_analysis_files, daemon=True)
watcher_thread.start()

@app.route('/')
def dashboard():
    """Main dashboard page"""
    load_latest_analysis()
    return render_template('dashboard.html')

@app.route('/api/analysis')
def get_analysis():
    """API endpoint to get current analysis data"""
    if current_analysis:
        return jsonify(current_analysis)
    else:
        return jsonify({"error": "No analysis data available"}), 404

@app.route('/api/analysis/list')
def list_analyses():
    """API endpoint to list all available analyses"""
    analyses = []
    
    for file_path in analysis_files:
        try:
            stat_info = os.stat(file_path)
            analyses.append({
                'file': os.path.basename(file_path),
                'path': file_path,
                'size': stat_info.st_size,
                'modified': datetime.fromtimestamp(stat_info.st_mtime).isoformat()
            })
        except Exception as e:
            continue
            
    return jsonify(analyses)

@app.route('/api/analysis/<filename>')
def get_specific_analysis(filename):
    """API endpoint to get specific analysis file"""
    file_path = None
    
    # Find the file
    for path in analysis_files:
        if os.path.basename(path) == filename:
            file_path = path
            break
            
    if not file_path or not os.path.exists(file_path):
        return jsonify({"error": "Analysis file not found"}), 404
        
    try:
        with open(file_path, 'r') as f:
            data = json.load(f)
        return jsonify(data)
    except Exception as e:
        return jsonify({"error": f"Failed to load analysis: {e}"}), 500

@app.route('/api/stats')
def get_stats():
    """API endpoint to get analysis statistics"""
    if not current_analysis:
        return jsonify({"error": "No analysis data available"}), 404
        
    stats = {
        'total_processes': len(current_analysis.get('process_tree', {})),
        'child_processes': len(current_analysis.get('child_processes', [])),
        'network_connections': len(current_analysis.get('network_connections', [])),
        'file_operations': len(current_analysis.get('file_operations', [])),
        'suspicious_behaviors': len(current_analysis.get('suspicious_behaviors', [])),
        'syscalls': len(current_analysis.get('syscalls', [])),
        'network_events': len(current_analysis.get('network_events', [])),
        'process_events': len(current_analysis.get('process_events', [])),
        'file_events': len(current_analysis.get('file_events', [])),
        'memory_events': len(current_analysis.get('memory_events', [])),
        'analysis_duration': current_analysis.get('analysis_duration', 0),
        'malware_path': current_analysis.get('malware_info', {}).get('path', 'Unknown')
    }
    
    return jsonify(stats)

@app.route('/api/timeline')
def get_timeline():
    """API endpoint to get analysis timeline"""
    if not current_analysis:
        return jsonify({"error": "No analysis data available"}), 404
        
    timeline_events = []
    
    # Add process events
    for event in current_analysis.get('process_events', []):
        timeline_events.append({
            'timestamp': event.get('timestamp'),
            'type': 'process',
            'event': event.get('event_type', 'unknown'),
            'description': f"Process {event.get('event_type', 'event')}: PID {event.get('child_pid')} ({event.get('child_comm', 'unknown')})",
            'details': event
        })
        
    # Add network events
    for event in current_analysis.get('network_events', []):
        timeline_events.append({
            'timestamp': event.get('timestamp'),
            'type': 'network',
            'event': event.get('event_type', 'unknown'),
            'description': f"Network {event.get('event_type', 'event')}: PID {event.get('pid')} ({event.get('comm', 'unknown')})",
            'details': event
        })
        
    # Add file events
    for event in current_analysis.get('file_events', []):
        timeline_events.append({
            'timestamp': event.get('timestamp'),
            'type': 'file',
            'event': event.get('event_type', 'unknown'),
            'description': f"File {event.get('event_type', 'event')}: {event.get('filename', 'unknown')}",
            'details': event
        })
        
    # Add memory events
    for event in current_analysis.get('memory_events', []):
        timeline_events.append({
            'timestamp': event.get('timestamp'),
            'type': 'memory',
            'event': event.get('event_type', 'unknown'),
            'description': f"Memory {event.get('event_type', 'event')}: {event.get('size', 0)} bytes at {event.get('addr', '0x0')}",
            'details': event
        })
        
    # Sort by timestamp
    timeline_events.sort(key=lambda x: x['timestamp'] if x['timestamp'] else '')
    
    return jsonify(timeline_events)

@app.route('/api/detection/scan_file', methods=['POST'])
def scan_file():
    """API endpoint to scan a single file"""
    if not detector:
        return jsonify({"error": "Detection engines not available"}), 503
        
    data = request.get_json()
    if not data or 'file_path' not in data:
        return jsonify({"error": "file_path is required"}), 400
        
    file_path = data['file_path']
    check_virustotal = data.get('check_virustotal', True)
    use_clamav = data.get('use_clamav', True)
    
    if not os.path.exists(file_path):
        return jsonify({"error": f"File not found: {file_path}"}), 404
        
    try:
        # Generate scan job ID
        scan_id = f"scan_{int(time.time())}_{hash(file_path) % 10000}"
        
        # Start scan in background
        def run_scan():
            try:
                results = detector.scan_file(
                    file_path, 
                    check_virustotal=check_virustotal, 
                    use_clamav=use_clamav
                )
                results['scan_id'] = scan_id
                results['scan_time'] = datetime.now().isoformat()
                results['status'] = 'completed'
                detection_results[scan_id] = results
            except Exception as e:
                detection_results[scan_id] = {
                    'scan_id': scan_id,
                    'error': str(e),
                    'status': 'failed',
                    'scan_time': datetime.now().isoformat()
                }
                
        # Mark scan as pending
        scan_jobs[scan_id] = {
            'scan_id': scan_id,
            'file_path': file_path,
            'status': 'pending',
            'start_time': datetime.now().isoformat()
        }
        
        # Run scan in background thread
        scan_thread = threading.Thread(target=run_scan, daemon=True)
        scan_thread.start()
        
        return jsonify({
            'scan_id': scan_id,
            'status': 'pending',
            'message': 'Scan started successfully'
        })
        
    except Exception as e:
        return jsonify({"error": f"Scan failed: {str(e)}"}), 500

@app.route('/api/detection/scan_directory', methods=['POST'])
def scan_directory():
    """API endpoint to scan a directory"""
    if not detector:
        return jsonify({"error": "Detection engines not available"}), 503
        
    data = request.get_json()
    if not data or 'directory_path' not in data:
        return jsonify({"error": "directory_path is required"}), 400
        
    directory_path = data['directory_path']
    recursive = data.get('recursive', True)
    check_virustotal = data.get('check_virustotal', False)  # Default off for directories
    use_clamav = data.get('use_clamav', True)
    
    if not os.path.exists(directory_path) or not os.path.isdir(directory_path):
        return jsonify({"error": f"Directory not found: {directory_path}"}), 404
        
    try:
        # Generate scan job ID
        scan_id = f"dirscan_{int(time.time())}_{hash(directory_path) % 10000}"
        
        # Start scan in background
        def run_directory_scan():
            try:
                results = detector.scan_directory(
                    directory_path,
                    recursive=recursive,
                    check_virustotal=check_virustotal,
                    use_clamav=use_clamav
                )
                results['scan_id'] = scan_id
                results['scan_time'] = datetime.now().isoformat()
                results['status'] = 'completed'
                detection_results[scan_id] = results
            except Exception as e:
                detection_results[scan_id] = {
                    'scan_id': scan_id,
                    'error': str(e),
                    'status': 'failed',
                    'scan_time': datetime.now().isoformat()
                }
                
        # Mark scan as pending
        scan_jobs[scan_id] = {
            'scan_id': scan_id,
            'directory_path': directory_path,
            'status': 'pending',
            'start_time': datetime.now().isoformat()
        }
        
        # Run scan in background thread
        scan_thread = threading.Thread(target=run_directory_scan, daemon=True)
        scan_thread.start()
        
        return jsonify({
            'scan_id': scan_id,
            'status': 'pending',
            'message': 'Directory scan started successfully'
        })
        
    except Exception as e:
        return jsonify({"error": f"Directory scan failed: {str(e)}"}), 500

@app.route('/api/detection/scan_status/<scan_id>')
def get_scan_status(scan_id):
    """Get status of a scan job"""
    if scan_id in detection_results:
        return jsonify(detection_results[scan_id])
    elif scan_id in scan_jobs:
        return jsonify(scan_jobs[scan_id])
    else:
        return jsonify({"error": "Scan not found"}), 404

@app.route('/api/detection/scans')
def list_scans():
    """List all scan jobs and results"""
    all_scans = {}
    all_scans.update(scan_jobs)
    all_scans.update(detection_results)
    
    # Sort by start time (newest first)
    sorted_scans = sorted(
        all_scans.values(),
        key=lambda x: x.get('start_time', x.get('scan_time', '')),
        reverse=True
    )
    
    return jsonify(sorted_scans)

@app.route('/api/detection/analyze_logs')
def analyze_logs():
    """Analyze system logs for suspicious activity"""
    if not detector or not hasattr(detector, 'log_analyzer'):
        return jsonify({"error": "Log analyzer not available"}), 503
        
    try:
        time_window = request.args.get('time_window', 60, type=int)
        
        def run_log_analysis():
            try:
                results = detector.analyze_logs(time_window)
                results['analysis_time'] = datetime.now().isoformat()
                detection_results['log_analysis'] = results
            except Exception as e:
                detection_results['log_analysis'] = {
                    'error': str(e),
                    'analysis_time': datetime.now().isoformat()
                }
        
        # Run analysis in background
        log_thread = threading.Thread(target=run_log_analysis, daemon=True)
        log_thread.start()
        
        return jsonify({"message": "Log analysis started", "check_id": "log_analysis"})
        
    except Exception as e:
        return jsonify({"error": f"Log analysis failed: {str(e)}"}), 500

@app.route('/api/detection/entropy_analysis', methods=['POST'])
def entropy_analysis():
    """Perform entropy analysis on a file"""
    if not DETECTION_AVAILABLE:
        return jsonify({"error": "Detection modules not available"}), 503
        
    data = request.get_json()
    if not data or 'file_path' not in data:
        return jsonify({"error": "file_path is required"}), 400
        
    file_path = data['file_path']
    
    if not os.path.exists(file_path):
        return jsonify({"error": f"File not found: {file_path}"}), 404
        
    try:
        entropy_analyzer = EntropyAnalyzer()
        results = entropy_analyzer.analyze_file(file_path)
        results['analysis_time'] = datetime.now().isoformat()
        return jsonify(results)
        
    except Exception as e:
        return jsonify({"error": f"Entropy analysis failed: {str(e)}"}), 500

@app.route('/api/detection/quick_scan', methods=['POST'])
def quick_scan():
    """Quick scan using multiple detection methods"""
    if not detector:
        return jsonify({"error": "Detection engines not available"}), 503
        
    data = request.get_json()
    if not data or 'target' not in data:
        return jsonify({"error": "target (file or directory path) is required"}), 400
        
    target = data['target']
    
    if not os.path.exists(target):
        return jsonify({"error": f"Target not found: {target}"}), 404
        
    try:
        results = {
            'target': target,
            'scan_time': datetime.now().isoformat(),
            'results': {}
        }
        
        if os.path.isfile(target):
            # File scan
            scan_result = detector.scan_file(target, check_virustotal=False, use_clamav=True)
            results['results'] = scan_result
            results['scan_type'] = 'file'
            
            # Add entropy analysis
            entropy_analyzer = EntropyAnalyzer()
            entropy_result = entropy_analyzer.analyze_file(target)
            results['results']['entropy_analysis'] = entropy_result
            
        else:
            # Directory scan
            scan_result = detector.scan_directory(target, recursive=False, check_virustotal=False, use_clamav=True)
            results['results'] = scan_result
            results['scan_type'] = 'directory'
            
        return jsonify(results)
        
    except Exception as e:
        return jsonify({"error": f"Quick scan failed: {str(e)}"}), 500

@app.route('/api/system_info')
def get_system_info():
    """Get system information and detection engine status"""
    system_info = {
        'detection_available': DETECTION_AVAILABLE,
        'virustotal_configured': bool(VIRUSTOTAL_API_KEY),
        'gemini_configured': bool(GEMINI_API_KEY),
        'detector_initialized': detector is not None,
        'system_time': datetime.now().isoformat(),
        'analysis_dir': ANALYSIS_DIR,
        'python_version': sys.version.split()[0]
    }
    
    try:
        import psutil
        system_info['system_stats'] = {
            'cpu_percent': psutil.cpu_percent(),
            'memory_percent': psutil.virtual_memory().percent,
            'disk_usage': psutil.disk_usage('/').percent
        }
    except:
        pass
        
    return jsonify(system_info)

# Template for the dashboard
dashboard_template = '''<!DOCTYPE html>
<html lang="en">
<head>
    <meta charset="UTF-8">
    <meta name="viewport" content="width=device-width, initial-scale=1.0">
    <title>Malware Analysis & Detection Dashboard</title>
    <style>
        * {
            margin: 0;
            padding: 0;
            box-sizing: border-box;
        }
        
        body {
            font-family: 'Segoe UI', Tahoma, Geneva, Verdana, sans-serif;
            background: linear-gradient(135deg, #1e3c72 0%, #2a5298 100%);
            color: #fff;
            min-height: 100vh;
        }
        
        .header {
            background: rgba(0, 0, 0, 0.2);
            padding: 1rem 2rem;
            border-bottom: 1px solid rgba(255, 255, 255, 0.1);
        }
        
        .header h1 {
            color: #00ff88;
            font-size: 2rem;
            font-weight: 300;
        }
        
        .nav-tabs {
            display: flex;
            margin-top: 1rem;
        }
        
        .nav-tab {
            background: rgba(255, 255, 255, 0.1);
            border: none;
            color: #fff;
            padding: 0.75rem 1.5rem;
            cursor: pointer;
            transition: all 0.3s ease;
            border-radius: 5px 5px 0 0;
            margin-right: 0.25rem;
        }
        
        .nav-tab.active {
            background: #00ff88;
            color: #000;
        }
        
        .container {
            padding: 2rem;
            max-width: 1400px;
            margin: 0 auto;
        }
        
        .tab-panel {
            display: none;
        }
        
        .tab-panel.active {
            display: block;
        }
        
        .stats-grid {
            display: grid;
            grid-template-columns: repeat(auto-fit, minmax(250px, 1fr));
            gap: 1rem;
            margin-bottom: 2rem;
        }
        
        .stat-card {
            background: rgba(255, 255, 255, 0.1);
            border-radius: 10px;
            padding: 1.5rem;
            backdrop-filter: blur(10px);
            border: 1px solid rgba(255, 255, 255, 0.1);
            transition: transform 0.3s ease;
        }
        
        .stat-card:hover {
            transform: translateY(-2px);
        }
        
        .stat-value {
            font-size: 2.5rem;
            font-weight: bold;
            color: #00ff88;
            margin-bottom: 0.5rem;
        }
        
        .stat-label {
            color: #ccc;
            font-size: 0.9rem;
        }
        
        .section {
            background: rgba(255, 255, 255, 0.05);
            border-radius: 10px;
            padding: 1.5rem;
            margin-bottom: 2rem;
            backdrop-filter: blur(10px);
            border: 1px solid rgba(255, 255, 255, 0.1);
        }
        
        .section h2 {
            color: #00ff88;
            margin-bottom: 1rem;
            font-size: 1.5rem;
        }
        
        .input-group {
            margin-bottom: 1rem;
        }
        
        .input-group label {
            display: block;
            margin-bottom: 0.5rem;
            color: #ddd;
        }
        
        .input-group input,
        .input-group select {
            width: 100%;
            padding: 0.75rem;
            border: 1px solid rgba(255, 255, 255, 0.2);
            border-radius: 5px;
            background: rgba(255, 255, 255, 0.1);
            color: #fff;
            font-size: 1rem;
        }
        
        .input-group input::placeholder {
            color: #888;
        }
        
        .btn {
            background: #00ff88;
            color: #000;
            border: none;
            padding: 0.75rem 1.5rem;
            border-radius: 5px;
            cursor: pointer;
            font-weight: bold;
            font-size: 1rem;
            transition: background 0.3s ease;
            margin-right: 0.5rem;
            margin-bottom: 0.5rem;
        }
        
        .btn:hover {
            background: #00cc6a;
        }
        
        .btn-secondary {
            background: rgba(255, 255, 255, 0.1);
            color: #fff;
        }
        
        .btn-secondary:hover {
            background: rgba(255, 255, 255, 0.2);
        }
        
        .btn-danger {
            background: #ff6b6b;
            color: #fff;
        }
        
        .btn-danger:hover {
            background: #ff5252;
        }
        
        .timeline {
            max-height: 500px;
            overflow-y: auto;
        }
        
        .timeline-item {
            display: flex;
            align-items: center;
            padding: 0.75rem;
            margin-bottom: 0.5rem;
            background: rgba(255, 255, 255, 0.05);
            border-radius: 5px;
            border-left: 4px solid #00ff88;
        }
        
        .timeline-time {
            color: #888;
            font-size: 0.8rem;
            min-width: 150px;
            margin-right: 1rem;
        }
        
        .timeline-type {
            display: inline-block;
            padding: 0.2rem 0.5rem;
            border-radius: 3px;
            font-size: 0.7rem;
            font-weight: bold;
            margin-right: 0.5rem;
            min-width: 60px;
            text-align: center;
        }
        
        .type-process { background: #ff6b6b; }
        .type-network { background: #4ecdc4; }
        .type-file { background: #45b7d1; }
        .type-memory { background: #f9ca24; color: #000; }
        .type-detection { background: #00ff88; color: #000; }
        
        .timeline-description {
            color: #ddd;
        }
        
        .process-tree {
            font-family: monospace;
            background: rgba(0, 0, 0, 0.3);
            padding: 1rem;
            border-radius: 5px;
            max-height: 400px;
            overflow-y: auto;
        }
        
        .process-item {
            margin: 0.25rem 0;
            padding: 0.25rem;
        }
        
        .suspicious-item {
            background: rgba(255, 107, 107, 0.2);
            border-left: 4px solid #ff6b6b;
            padding: 0.5rem;
            margin: 0.5rem 0;
            border-radius: 3px;
        }
        
        .scan-result {
            background: rgba(255, 255, 255, 0.05);
            border-radius: 5px;
            padding: 1rem;
            margin: 1rem 0;
            border-left: 4px solid #00ff88;
        }
        
        .scan-result.malicious {
            border-left-color: #ff6b6b;
            background: rgba(255, 107, 107, 0.1);
        }
        
        .scan-result.pending {
            border-left-color: #f9ca24;
            background: rgba(249, 202, 36, 0.1);
        }
        
        .loading {
            text-align: center;
            padding: 2rem;
            color: #888;
        }
        
        .error {
            background: rgba(255, 107, 107, 0.2);
            border: 1px solid #ff6b6b;
            color: #ff6b6b;
            padding: 1rem;
            border-radius: 5px;
            margin: 1rem 0;
        }
        
        .success {
            background: rgba(0, 255, 136, 0.2);
            border: 1px solid #00ff88;
            color: #00ff88;
            padding: 1rem;
            border-radius: 5px;
            margin: 1rem 0;
        }
        
        .tabs {
            display: flex;
            margin-bottom: 1rem;
        }
        
        .tab {
            background: rgba(255, 255, 255, 0.1);
            border: none;
            color: #fff;
            padding: 0.75rem 1.5rem;
            cursor: pointer;
            transition: all 0.3s ease;
            border-radius: 5px 5px 0 0;
            margin-right: 0.25rem;
        }
        
        .tab.active {
            background: #00ff88;
            color: #000;
        }
        
        .tab-content {
            display: none;
        }
        
        .tab-content.active {
            display: block;
        }
        
        .checkbox-group {
            display: flex;
            gap: 1rem;
            margin: 1rem 0;
        }
        
        .checkbox-item {
            display: flex;
            align-items: center;
            gap: 0.5rem;
        }
        
        .checkbox-item input[type="checkbox"] {
            width: auto;
        }
        
        .scan-jobs {
            max-height: 400px;
            overflow-y: auto;
        }
        
        .progress-bar {
            background: rgba(255, 255, 255, 0.1);
            border-radius: 10px;
            height: 20px;
            overflow: hidden;
            margin: 0.5rem 0;
        }
        
        .progress-fill {
            background: #00ff88;
            height: 100%;
            transition: width 0.3s ease;
        }
        
        .detection-status {
            font-size: 0.8em;
            padding: 2px 8px;
            border-radius: 4px;
            margin-left: 10px;
            font-weight: normal;
        }
        
        .detection-status.success {
            background-color: rgba(0, 255, 136, 0.2);
            color: #00ff88;
            border: 1px solid #00ff88;
        }
        
        .detection-status.error {
            background-color: rgba(255, 107, 107, 0.2);
            color: #ff6b6b;
            border: 1px solid #ff6b6b;
        }
        
        .auto-refresh-btn {
            background-color: #007bff;
            color: white;
            border: none;
            padding: 5px 10px;
            border-radius: 3px;
            cursor: pointer;
            font-size: 0.9em;
            margin-left: 10px;
        }
        
        .auto-refresh-btn:hover {
            background-color: #0056b3;
        }
        
        .system-stats {
            background-color: #f8f9fa;
            padding: 10px;
            border-radius: 5px;
            margin: 10px 0;
            font-size: 0.9em;
            border: 1px solid #dee2e6;
        }
    </style>
</head>
<body>
    <div class="header">
        <h1>🔍 Malware Analysis & Detection Dashboard</h1>
        <div class="nav-tabs">
            <button class="nav-tab active" onclick="showMainTab('analysis')">Analysis</button>
            <button class="nav-tab" onclick="showMainTab('detection')">Detection</button>
            <button class="nav-tab" onclick="showMainTab('logs')">System Logs</button>
        </div>
    </div>
    
    <div class="container">
        <!-- Analysis Tab -->
        <div class="tab-panel active" id="analysis-panel">
            <button class="btn" onclick="refreshAnalysisData()">🔄 Refresh Analysis Data</button>
            
            <div class="stats-grid" id="stats-grid">
                <div class="loading">Loading analysis data...</div>
            </div>
            
            <div class="section">
                <div class="tabs">
                    <button class="tab active" onclick="showAnalysisTab('timeline')">Timeline</button>
                    <button class="tab" onclick="showAnalysisTab('processes')">Process Tree</button>
                    <button class="tab" onclick="showAnalysisTab('suspicious')">Suspicious Behavior</button>
                    <button class="tab" onclick="showAnalysisTab('network')">Network Activity</button>
                </div>
                
                <div class="tab-content active" id="analysis-timeline-content">
                    <h2>Event Timeline</h2>
                    <div class="timeline" id="timeline">
                        <div class="loading">Loading timeline...</div>
                    </div>
                </div>
                
                <div class="tab-content" id="analysis-processes-content">
                    <h2>Process Tree</h2>
                    <div class="process-tree" id="process-tree">
                        <div class="loading">Loading process tree...</div>
                    </div>
                </div>
                
                <div class="tab-content" id="analysis-suspicious-content">
                    <h2>Suspicious Behaviors</h2>
                    <div id="suspicious-behaviors">
                        <div class="loading">Loading suspicious behaviors...</div>
                    </div>
                </div>
                
                <div class="tab-content" id="analysis-network-content">
                    <h2>Network Connections</h2>
                    <div id="network-connections">
                        <div class="loading">Loading network connections...</div>
                    </div>
                </div>
            </div>
        </div>
        
        <!-- Detection Tab -->
        <div class="tab-panel" id="detection-panel">
            <div class="section">
                <h2>File & Directory Scanner <span class="detection-status">Loading...</span></h2>
                <div class="input-group">
                    <label for="scan-target">Target Path (File or Directory):</label>
                    <input type="text" id="scan-target" placeholder="/path/to/file/or/directory">
                </div>
                
                <div class="checkbox-group">
                    <div class="checkbox-item">
                        <input type="checkbox" id="use-clamav" checked>
                        <label for="use-clamav">ClamAV Scan</label>
                    </div>
                    <div class="checkbox-item">
                        <input type="checkbox" id="use-virustotal">
                        <label for="use-virustotal">VirusTotal Check</label>
                    </div>
                    <div class="checkbox-item">
                        <input type="checkbox" id="recursive-scan" checked>
                        <label for="recursive-scan">Recursive (Directories)</label>
                    </div>
                </div>
                
                <button class="btn" onclick="startScan()">🔍 Start Scan</button>
                <button class="btn btn-secondary" onclick="quickScan()">⚡ Quick Scan</button>
                <button class="btn btn-secondary" onclick="entropyAnalysis()">📊 Entropy Analysis</button>
                
                <div id="scan-status"></div>
            </div>
            
            <div class="section">
                <h2>Scan Results</h2>
                <button class="btn btn-secondary" onclick="refreshScans()">🔄 Refresh</button>
                <div class="scan-jobs" id="scan-results">
                    <div class="loading">No scans yet</div>
                </div>
            </div>
        </div>
        
        <!-- Logs Tab -->
        <div class="tab-panel" id="logs-panel">
            <div class="section">
                <h2>System Log Analysis</h2>
                <div class="input-group">
                    <label for="log-time-window">Time Window (minutes):</label>
                    <select id="log-time-window">
                        <option value="30">30 minutes</option>
                        <option value="60" selected>1 hour</option>
                        <option value="120">2 hours</option>
                        <option value="360">6 hours</option>
                        <option value="720">12 hours</option>
                        <option value="1440">24 hours</option>
                    </select>
                </div>
                
                <button class="btn" onclick="analyzeLogs()">🔍 Analyze Logs</button>
                
                <div id="log-analysis-results">
                    <div class="loading">Click "Analyze Logs" to start</div>
                </div>
            </div>
        </div>
    </div>

    <script>
        let currentAnalysisData = null;
        let currentScans = {};
        let scanRefreshInterval = null;
        
        // Main tab switching
        function showMainTab(tabName) {
            // Hide all tab panels
            document.querySelectorAll('.tab-panel').forEach(panel => {
                panel.classList.remove('active');
            });
            
            // Remove active class from all nav tabs
            document.querySelectorAll('.nav-tab').forEach(tab => {
                tab.classList.remove('active');
            });
            
            // Show selected tab panel
            document.getElementById(tabName + '-panel').classList.add('active');
            
            // Add active class to clicked tab
            event.target.classList.add('active');
            
            // Load tab-specific data
            if (tabName === 'detection') {
                refreshScans();
            }
        }
        
        // Analysis sub-tab switching
        function showAnalysisTab(tabName) {
            document.querySelectorAll('#analysis-panel .tab-content').forEach(content => {
                content.classList.remove('active');
            });
            
            document.querySelectorAll('#analysis-panel .tab').forEach(tab => {
                tab.classList.remove('active');
            });
            
            document.getElementById('analysis-' + tabName + '-content').classList.add('active');
            event.target.classList.add('active');
        }
        
        function formatTime(timestamp) {
            if (!timestamp) return 'Unknown';
            try {
                return new Date(timestamp).toLocaleTimeString();
            } catch (e) {
                return timestamp;
            }
        }
        
        // Analysis functions (keep existing ones)
        function loadStats() {
            fetch('/api/stats')
                .then(response => response.json())
                .then(data => {
                    const statsGrid = document.getElementById('stats-grid');
                    statsGrid.innerHTML = `
                        <div class="stat-card">
                            <div class="stat-value">${data.total_processes || 0}</div>
                            <div class="stat-label">Total Processes</div>
                        </div>
                        <div class="stat-card">
                            <div class="stat-value">${data.child_processes || 0}</div>
                            <div class="stat-label">Child Processes</div>
                        </div>
                        <div class="stat-card">
                            <div class="stat-value">${data.network_connections || 0}</div>
                            <div class="stat-label">Network Connections</div>
                        </div>
                        <div class="stat-card">
                            <div class="stat-value">${data.file_operations || 0}</div>
                            <div class="stat-label">File Operations</div>
                        </div>
                        <div class="stat-card">
                            <div class="stat-value">${data.suspicious_behaviors || 0}</div>
                            <div class="stat-label">Suspicious Behaviors</div>
                        </div>
                        <div class="stat-card">
                            <div class="stat-value">${data.syscalls || 0}</div>
                            <div class="stat-label">System Calls</div>
                        </div>
                        <div class="stat-card">
                            <div class="stat-value">${Math.round(data.analysis_duration || 0)}s</div>
                            <div class="stat-label">Analysis Duration</div>
                        </div>
                        <div class="stat-card">
                            <div class="stat-value">${data.malware_path ? '✓' : '✗'}</div>
                            <div class="stat-label">Malware Loaded</div>
                        </div>
                    `;
                })
                .catch(error => {
                    document.getElementById('stats-grid').innerHTML = `
                        <div class="error">Failed to load statistics: ${error.message}</div>
                    `;
                });
        }
        
        function loadTimeline() {
            fetch('/api/timeline')
                .then(response => response.json())
                .then(data => {
                    const timeline = document.getElementById('timeline');
                    if (data.length === 0) {
                        timeline.innerHTML = '<div class="loading">No timeline events available</div>';
                        return;
                    }
                    
                    timeline.innerHTML = data.map(event => `
                        <div class="timeline-item">
                            <div class="timeline-time">${formatTime(event.timestamp)}</div>
                            <span class="timeline-type type-${event.type}">${event.type}</span>
                            <div class="timeline-description">${event.description}</div>
                        </div>
                    `).join('');
                })
                .catch(error => {
                    document.getElementById('timeline').innerHTML = `
                        <div class="error">Failed to load timeline: ${error.message}</div>
                    `;
                });
        }
        
        function loadProcessTree() {
            fetch('/api/analysis')
                .then(response => response.json())
                .then(data => {
                    const processTree = document.getElementById('process-tree');
                    const processes = data.process_tree || {};
                    
                    if (Object.keys(processes).length === 0) {
                        processTree.innerHTML = '<div class="loading">No process data available</div>';
                        return;
                    }
                    
                    let html = '';
                    for (const [pid, info] of Object.entries(processes)) {
                        html += `
                            <div class="process-item">
                                <strong>PID ${pid}</strong>: ${info.name || 'unknown'} (${info.exe || 'unknown'})<br>
                                Command: ${(info.cmdline || []).join(' ')}<br>
                                User: ${info.username || 'unknown'}, Status: ${info.status || 'unknown'}<br>
                                Memory: ${info.memory_percent || 0}%, CPU: ${info.cpu_percent || 0}%<br>
                                Children: [${(info.children || []).join(', ')}]
                            </div>
                        `;
                    }
                    processTree.innerHTML = html;
                })
                .catch(error => {
                    document.getElementById('process-tree').innerHTML = `
                        <div class="error">Failed to load process tree: ${error.message}</div>
                    `;
                });
        }
        
        function loadSuspiciousBehaviors() {
            fetch('/api/analysis')
                .then(response => response.json())
                .then(data => {
                    const suspicious = document.getElementById('suspicious-behaviors');
                    const behaviors = data.suspicious_behaviors || [];
                    
                    if (behaviors.length === 0) {
                        suspicious.innerHTML = '<div class="loading">No suspicious behaviors detected</div>';
                        return;
                    }
                    
                    suspicious.innerHTML = behaviors.map(behavior => `
                        <div class="suspicious-item">⚠️ ${behavior}</div>
                    `).join('');
                })
                .catch(error => {
                    document.getElementById('suspicious-behaviors').innerHTML = `
                        <div class="error">Failed to load suspicious behaviors: ${error.message}</div>
                    `;
                });
        }
        
        function loadNetworkConnections() {
            fetch('/api/analysis')
                .then(response => response.json())
                .then(data => {
                    const network = document.getElementById('network-connections');
                    const connections = data.network_connections || [];
                    
                    if (connections.length === 0) {
                        network.innerHTML = '<div class="loading">No network connections detected</div>';
                        return;
                    }
                    
                    let html = '<div class="process-tree">';
                    connections.forEach(conn => {
                        html += `
                            <div class="process-item">
                                <strong>${formatTime(conn.timestamp)}</strong><br>
                                PID ${conn.pid}: ${conn.local_address} → ${conn.remote_address}<br>
                                Status: ${conn.status}, Type: ${conn.type}
                            </div>
                        `;
                    });
                    html += '</div>';
                    network.innerHTML = html;
                })
                .catch(error => {
                    document.getElementById('network-connections').innerHTML = `
                        <div class="error">Failed to load network connections: ${error.message}</div>
                    `;
                });
        }
        
        function refreshAnalysisData() {
            loadStats();
            loadTimeline();
            loadProcessTree();
            loadSuspiciousBehaviors();
            loadNetworkConnections();
        }
        
        // Detection functions
        function startScan() {
            const target = document.getElementById('scan-target').value.trim();
            if (!target) {
                showStatus('Please enter a target path', 'error');
                return;
            }
            
            const isDirectory = target.endsWith('/') || !target.includes('.');
            const data = {
                [isDirectory ? 'directory_path' : 'file_path']: target,
                use_clamav: document.getElementById('use-clamav').checked,
                check_virustotal: document.getElementById('use-virustotal').checked
            };
            
            if (isDirectory) {
                data.recursive = document.getElementById('recursive-scan').checked;
            }
            
            const endpoint = isDirectory ? '/api/detection/scan_directory' : '/api/detection/scan_file';
            
            fetch(endpoint, {
                method: 'POST',
                headers: { 'Content-Type': 'application/json' },
                body: JSON.stringify(data)
            })
            .then(response => response.json())
            .then(data => {
                if (data.error) {
                    showStatus(data.error, 'error');
                } else {
                    showStatus(`Scan started: ${data.scan_id}`, 'success');
                    startScanMonitoring(data.scan_id);
                }
            })
            .catch(error => {
                showStatus(`Scan failed: ${error.message}`, 'error');
            });
        }
        
        function quickScan() {
            const target = document.getElementById('scan-target').value.trim();
            if (!target) {
                showStatus('Please enter a target path', 'error');
                return;
            }
            
            showStatus('Running quick scan...', 'pending');
            
            fetch('/api/detection/quick_scan', {
                method: 'POST',
                headers: { 'Content-Type': 'application/json' },
                body: JSON.stringify({ target: target })
            })
            .then(response => response.json())
            .then(data => {
                if (data.error) {
                    showStatus(data.error, 'error');
                } else {
                    displayScanResult(data);
                    showStatus('Quick scan completed', 'success');
                }
            })
            .catch(error => {
                showStatus(`Quick scan failed: ${error.message}`, 'error');
            });
        }
        
        function entropyAnalysis() {
            const target = document.getElementById('scan-target').value.trim();
            if (!target) {
                showStatus('Please enter a file path', 'error');
                return;
            }
            
            showStatus('Running entropy analysis...', 'pending');
            
            fetch('/api/detection/entropy_analysis', {
                method: 'POST',
                headers: { 'Content-Type': 'application/json' },
                body: JSON.stringify({ file_path: target })
            })
            .then(response => response.json())
            .then(data => {
                if (data.error) {
                    showStatus(data.error, 'error');
                } else {
                    displayEntropyResult(data);
                    showStatus('Entropy analysis completed', 'success');
                }
            })
            .catch(error => {
                showStatus(`Entropy analysis failed: ${error.message}`, 'error');
            });
        }
        
        function analyzeLogs() {
            const timeWindow = document.getElementById('log-time-window').value;
            const resultsDiv = document.getElementById('log-analysis-results');
            
            resultsDiv.innerHTML = '<div class="loading">Analyzing system logs...</div>';
            
            fetch(`/api/detection/analyze_logs?time_window=${timeWindow}`)
                .then(response => response.json())
                .then(data => {
                    if (data.error) {
                        resultsDiv.innerHTML = `<div class="error">${data.error}</div>`;
                    } else {
                        resultsDiv.innerHTML = '<div class="success">Log analysis started. Check back in a moment...</div>';
                        // Poll for results
                        setTimeout(() => checkLogResults(), 3000);
                    }
                })
                .catch(error => {
                    resultsDiv.innerHTML = `<div class="error">Failed to start log analysis: ${error.message}</div>`;
                });
        }
        
        function checkLogResults() {
            fetch('/api/detection/scan_status/log_analysis')
                .then(response => response.json())
                .then(data => {
                    if (data && !data.error) {
                        displayLogAnalysisResult(data);
                    }
                })
                .catch(() => {
                    // Results not ready yet, try again
                    setTimeout(() => checkLogResults(), 3000);
                });
        }
        
        function refreshScans() {
            fetch('/api/detection/scans')
                .then(response => response.json())
                .then(data => {
                    displayAllScans(data);
                })
                .catch(error => {
                    document.getElementById('scan-results').innerHTML = 
                        `<div class="error">Failed to load scans: ${error.message}</div>`;
                });
        }
        
        function startScanMonitoring(scanId) {
            if (scanRefreshInterval) {
                clearInterval(scanRefreshInterval);
            }
            
            scanRefreshInterval = setInterval(() => {
                fetch(`/api/detection/scan_status/${scanId}`)
                    .then(response => response.json())
                    .then(data => {
                        if (data.status === 'completed' || data.status === 'failed') {
                            clearInterval(scanRefreshInterval);
                            scanRefreshInterval = null;
                            refreshScans();
                        }
                    });
            }, 2000);
        }
        
        function showStatus(message, type) {
            const statusDiv = document.getElementById('scan-status');
            statusDiv.innerHTML = `<div class="${type}">${message}</div>`;
            setTimeout(() => {
                statusDiv.innerHTML = '';
            }, 5000);
        }
        
        function displayScanResult(result) {
            const resultsDiv = document.getElementById('scan-results');
            const isMalicious = result.results.is_malicious;
            
            const resultHtml = `
                <div class="scan-result ${isMalicious ? 'malicious' : ''}">
                    <h3>${result.scan_type === 'file' ? '📄' : '📁'} ${result.target}</h3>
                    <p><strong>Status:</strong> ${isMalicious ? '🚨 MALICIOUS' : '✅ Clean'}</p>
                    <p><strong>Scan Time:</strong> ${formatTime(result.scan_time)}</p>
                    ${result.results.detection_methods ? 
                        `<p><strong>Detection Methods:</strong> ${result.results.detection_methods.join(', ')}</p>` : ''}
                    ${result.results.entropy_analysis ? 
                        `<p><strong>Entropy:</strong> ${result.results.entropy_analysis.entropy?.toFixed(2) || 'N/A'}</p>` : ''}
                </div>
            `;
            
            resultsDiv.innerHTML = resultHtml + resultsDiv.innerHTML;
        }
        
        function displayEntropyResult(result) {
            const resultsDiv = document.getElementById('scan-results');
            
            const resultHtml = `
                <div class="scan-result ${result.is_suspicious ? 'malicious' : ''}">
                    <h3>📊 Entropy Analysis</h3>
                    <p><strong>File:</strong> ${result.file_path}</p>
                    <p><strong>Entropy:</strong> ${result.entropy?.toFixed(2) || 'N/A'} / 8.0</p>
                    <p><strong>Status:</strong> ${result.is_suspicious ? '🚨 Suspicious' : '✅ Normal'}</p>
                    <p><strong>File Size:</strong> ${result.file_size} bytes</p>
                    ${result.reason ? `<p><strong>Reason:</strong> ${result.reason}</p>` : ''}
                </div>
            `;
            
            resultsDiv.innerHTML = resultHtml + resultsDiv.innerHTML;
        }
        
        function displayLogAnalysisResult(result) {
            const resultsDiv = document.getElementById('log-analysis-results');
            
            let html = '<div class="section"><h3>📋 Log Analysis Results</h3>';
            
            if (result.suspicious_entries && result.suspicious_entries.length > 0) {
                html += '<h4>🚨 Suspicious Log Entries:</h4>';
                result.suspicious_entries.slice(0, 10).forEach(entry => {
                    html += `<div class="suspicious-item">${entry}</div>`;
                });
            }
            
            if (result.analysis_summary) {
                html += `<div class="success">Analysis Summary: ${result.analysis_summary}</div>`;
            }
            
            html += '</div>';
            resultsDiv.innerHTML = html;
        }
        
        function displayAllScans(scans) {
            const resultsDiv = document.getElementById('scan-results');
            
            if (!scans || scans.length === 0) {
                resultsDiv.innerHTML = '<div class="loading">No scans found</div>';
                return;
            }
            
            let html = '';
            scans.slice(0, 10).forEach(scan => {
                const isMalicious = scan.is_malicious || (scan.results && scan.results.is_malicious);
                const isPending = scan.status === 'pending';
                
                html += `
                    <div class="scan-result ${isMalicious ? 'malicious' : ''} ${isPending ? 'pending' : ''}">
                        <h4>${scan.scan_id || 'Unknown Scan'}</h4>
                        <p><strong>Target:</strong> ${scan.file_path || scan.directory_path || scan.target || 'Unknown'}</p>
                        <p><strong>Status:</strong> ${scan.status || 'Unknown'}</p>
                        <p><strong>Time:</strong> ${formatTime(scan.start_time || scan.scan_time)}</p>
                        ${isMalicious ? '<p><strong>Result:</strong> 🚨 MALICIOUS DETECTED</p>' : ''}
                        ${scan.error ? `<p class="error">Error: ${scan.error}</p>` : ''}
                    </div>
                `;
            });
            
            resultsDiv.innerHTML = html;
        }
        
        // Auto-refresh for analysis data
        setInterval(refreshAnalysisData, 15000);
        
        // Auto-refresh for detection scans when on detection tab
        setInterval(() => {
            if (document.getElementById('detection-panel').classList.contains('active')) {
                refreshScans();
            }
        }, 10000);
        
        // System status functions
        async function loadSystemStatus() {
            try {
                const response = await fetch('/api/system_info');
                const data = await response.json();
                updateSystemStatus(data);
            } catch (error) {
                console.error('Error loading system status:', error);
            }
        }
        
        function updateSystemStatus(info) {
            // Update detection availability status
            const detectionStatus = document.querySelectorAll('.detection-status');
            detectionStatus.forEach(el => {
                el.textContent = info.detection_available ? 'Available' : 'Unavailable';
                el.className = `detection-status ${info.detection_available ? 'success' : 'error'}`;
            });
        }
        
        // Auto-refresh system status every 30 seconds
        setInterval(loadSystemStatus, 30000);
        
        // Initial load
        refreshAnalysisData();
        loadSystemStatus();
    </script>
</body>
</html>'''

# Create templates directory and save template
def setup_templates():
    templates_dir = os.path.join(os.path.dirname(__file__), 'templates')
    os.makedirs(templates_dir, exist_ok=True)
    
    template_path = os.path.join(templates_dir, 'dashboard.html')
    with open(template_path, 'w') as f:
        f.write(dashboard_template)

def main():
    """Main function to start the web dashboard"""
    if len(sys.argv) > 1:
        global ANALYSIS_DIR
        ANALYSIS_DIR = sys.argv[1]
    
    # Ensure analysis directory exists
    os.makedirs(ANALYSIS_DIR, exist_ok=True)
    
    # Setup templates
    setup_templates()
    
    # Load initial analysis
    load_latest_analysis()
    
    print(f"Malware Analysis Dashboard")
    print(f"Analysis directory: {ANALYSIS_DIR}")
    print(f"Starting web server on http://localhost:5000")
    print("Press Ctrl+C to stop")
    
    try:
        app.run(host='0.0.0.0', port=5000, debug=False, threaded=True)
    except KeyboardInterrupt:
        print("\\nShutting down dashboard...")
        sys.exit(0)

if __name__ == "__main__":
    main()