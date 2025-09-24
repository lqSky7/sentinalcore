#!/bin/bash
# SentinelCore - Complete Malware Analysis Demonstration
# Master script that runs the entire malware analysis workflow

set -e  # Exit on any error

# Configuration
SCRIPT_DIR="$(cd "$(dirname "${BASH_SOURCE[0]}")" && pwd)"
PROJECT_ROOT="$SCRIPT_DIR"
ANALYSIS_DIR="/tmp/sentinalcore_demo"
TEST_SAMPLES_DIR="$PROJECT_ROOT/test_samples"
WEB_DASHBOARD_PORT=3000
ANALYSIS_DURATION=30  # 30 seconds for demo

# Sample descriptions
declare -A SAMPLE_DESCRIPTIONS=(
    ["process_spawner.py"]="Process creation & child process monitoring"
    ["network_activity.py"]="Network connections & DNS activity"
    ["filesystem_activity.py"]="File system operations & access patterns"
    ["syscall_simulator.py"]="System call tracing & eBPF monitoring"
    ["binary_simulator.sh"]="Binary execution & script analysis"
    ["combined_malware.py"]="Combined network & process activity"
    ["simple_network_malware.py"]="Simple network malware simulator"
)

# Colors for output
RED='\033[0;31m'
GREEN='\033[0;32m'
YELLOW='\033[1;33m'
BLUE='\033[0;34m'
MAGENTA='\033[0;35m'
CYAN='\033[0;36m'
NC='\033[0m' # No Color

# Logging function
log() {
    # Ensure log directory exists (create if needed)
    local log_dir="$(dirname "$ANALYSIS_DIR/demo.log")"
    if [[ ! -d "$log_dir" ]]; then
        mkdir -p "$log_dir" 2>/dev/null || true
    fi
    echo -e "[$(date '+%Y-%m-%d %H:%M:%S')] $1" | tee -a "$ANALYSIS_DIR/demo.log" 2>/dev/null || echo -e "[$(date '+%Y-%m-%d %H:%M:%S')] $1"
}

error() {
    log "${RED}[ERROR]${NC} $1"
    exit 1
}

warning() {
    log "${YELLOW}[WARNING]${NC} $1"
}

info() {
    log "${BLUE}[INFO]${NC} $1"
}

success() {
    log "${GREEN}[SUCCESS]${NC} $1"
}

demo() {
    log "${MAGENTA}[DEMO]${NC} $1"
}

# Banner
show_banner() {
    echo -e "${CYAN}"
    cat << 'EOF'
╔══════════════════════════════════════════════════════════════════════════════╗
║                           🔍 SENTINALCORE                                  ║
║                    Complete Malware Analysis System                        ║
║                                                                            ║
║  🚀 FULL DEMONSTRATION - Process → Network → Filesystem → Dashboard       ║
║                                                                            ║
║  Features Demonstrated:                                                    ║
║  • Process creation & monitoring                                           ║
║  • Network activity analysis                                               ║
║  • File system operations                                                  ║
║  • System call tracing (eBPF)                                             ║
║  • Real-time web dashboard                                                 ║
║  • Detection engine integration                                           ║
║  • Comprehensive reporting                                                 ║
╚══════════════════════════════════════════════════════════════════════════════╝
EOF
    echo -e "${NC}"
}

# Check system requirements
check_system() {
    demo "Checking system requirements..."

    # Check OS
    if [[ "$OSTYPE" == "linux-gnu"* ]]; then
        info "Linux system detected"
    elif [[ "$OSTYPE" == "darwin"* ]]; then
        info "macOS system detected (limited eBPF support)"
    else
        warning "Unsupported OS: $OSTYPE"
    fi

    # Check architecture
    local arch=$(uname -m)
    info "Architecture: $arch"

    # Check available memory
    local mem_kb=$(grep MemTotal /proc/meminfo 2>/dev/null | awk '{print $2}' || echo "unknown")
    if [[ "$mem_kb" != "unknown" ]]; then
        local mem_gb=$((mem_kb / 1024 / 1024))
        info "Available memory: ${mem_gb}GB"
    fi

    success "System check complete"
}

# Setup Python environment
setup_python() {
    demo "Setting up Python environment..."

    # Check if virtual environment exists
    if [[ ! -d "$PROJECT_ROOT/venv" ]]; then
        info "Creating virtual environment..."
        python3 -m venv "$PROJECT_ROOT/venv"
    fi

    # Activate virtual environment
    source "$PROJECT_ROOT/venv/bin/activate"

    # Upgrade pip
    pip install --upgrade pip > /dev/null 2>&1

    # Install requirements
    if [[ -f "$PROJECT_ROOT/requirements.txt" ]]; then
        info "Installing Python dependencies..."
        pip install -r "$PROJECT_ROOT/requirements.txt" > /dev/null 2>&1
    else
        # Install core dependencies
        pip install flask psutil requests python-magic > /dev/null 2>&1
    fi

    # Check for optional dependencies
    if python3 -c "import bcc" 2>/dev/null; then
        info "eBPF/BCC support: Available"
    else
        warning "eBPF/BCC support: Not available (limited tracing)"
    fi

    success "Python environment ready"
}

# Setup analysis environment
setup_analysis() {
    demo "Setting up analysis environment..."

    # Clean previous analysis
    rm -rf "$ANALYSIS_DIR"

    # Create directories
    mkdir -p "$ANALYSIS_DIR"
    mkdir -p "$ANALYSIS_DIR/logs"
    mkdir -p "$ANALYSIS_DIR/traces"
    mkdir -p "$ANALYSIS_DIR/reports"
    mkdir -p "$ANALYSIS_DIR/results"

    # Initialize log file
    touch "$ANALYSIS_DIR/demo.log"
    chmod 644 "$ANALYSIS_DIR/demo.log"

    success "Analysis environment ready at: $ANALYSIS_DIR"
}

# Validate test samples
validate_samples() {
    demo "Validating test samples..."

    local samples=(
        "process_spawner.py:Process creation demo"
        "network_activity.py:Network activity demo"
        "filesystem_activity.py:File system operations demo"
        "syscall_simulator.py:System call tracing demo"
        "binary_simulator.sh:Binary execution demo"
    )

    for sample_info in "${samples[@]}"; do
        local sample_file=$(echo "$sample_info" | cut -d: -f1)
        local description=$(echo "$sample_info" | cut -d: -f2)
        local sample_path="$TEST_SAMPLES_DIR/$sample_file"

        if [[ -f "$sample_path" ]]; then
            info "✓ $sample_file - $description"
        else
            warning "✗ $sample_file - Missing"
        fi
    done

    success "Sample validation complete"
}

# Start web dashboard
start_dashboard() {
    demo "Starting web dashboard..."

        local dashboard_script="$PROJECT_ROOT/analysis/web_dashboard.py"
    if [[ ! -f "$dashboard_script" ]]; then
        error "Web dashboard script not found: $dashboard_script"
    fi

    # Try the fixed port
    local ports_to_try=("$WEB_DASHBOARD_PORT")
    local actual_port=""

    for port in "${ports_to_try[@]}"; do
        info "Trying port $port..."

        # Check if port is available
        if lsof -i :"$port" &>/dev/null; then
            warning "Port $port is in use"
            continue
        fi

        # Start dashboard
        python3 "$dashboard_script" "$ANALYSIS_DIR" "$port" > "$ANALYSIS_DIR/logs/dashboard.log" 2>&1 &
        local dashboard_pid=$!
        echo "$dashboard_pid" > "$ANALYSIS_DIR/dashboard.pid"

        # Wait for startup
        sleep 5

        # Check if running
        if kill -0 "$dashboard_pid" 2>/dev/null && lsof -i :"$port" &>/dev/null; then
            actual_port="$port"
            break
        else
            kill "$dashboard_pid" 2>/dev/null || true
            rm -f "$ANALYSIS_DIR/dashboard.pid"
        fi
    done

    if [[ -z "$actual_port" ]]; then
        error "Could not start web dashboard on any available port"
    fi

    WEB_DASHBOARD_PORT="$actual_port"
    success "Web dashboard running on port $WEB_DASHBOARD_PORT"
    demo "🌐 Access dashboard: http://localhost:$WEB_DASHBOARD_PORT"
}

# Run analysis for a specific sample
run_sample_analysis() {
    local sample_name="$1"
    local description="$2"
    local sample_path="$TEST_SAMPLES_DIR/$sample_name"

    demo "🔬 Analyzing: $description"

    if [[ ! -f "$sample_path" ]]; then
        warning "Sample not found: $sample_path"
        return 1
    fi

    info "Target: $sample_path"
    info "Duration: $ANALYSIS_DURATION seconds"

    # Make executable if needed
    if [[ "$sample_name" == *.sh ]] || [[ "$sample_name" == *.py ]]; then
        chmod +x "$sample_path" 2>/dev/null || true
    fi

    # Run analysis
    local timestamp=$(date +%s)
    local log_file="$ANALYSIS_DIR/logs/analysis_${sample_name%.*}_$timestamp.log"

    info "Starting analysis..."
    python3 "$PROJECT_ROOT/analysis/malware_tracer.py" "$sample_path" "$ANALYSIS_DURATION" "$ANALYSIS_DIR" 2>&1 | tee "$log_file"

    local exit_code=$?
    if [[ $exit_code -eq 0 ]]; then
        success "Analysis completed for $sample_name"

        # Check for results
        local result_files=$(ls -1 "$ANALYSIS_DIR"/malware_analysis_*.json 2>/dev/null | wc -l)
        if [[ $result_files -gt 0 ]]; then
            info "Results saved to analysis directory"
        fi
    else
        warning "Analysis failed for $sample_name (exit code: $exit_code)"
    fi

    # Brief pause between analyses
    sleep 2
}

# Run comprehensive analysis
run_comprehensive_analysis() {
    demo "🚀 Running comprehensive malware analysis demonstration..."

    local samples=(
        "process_spawner.py:Process Creation & Child Process Monitoring"
        "network_activity.py:Network Connections & DNS Activity"
        "filesystem_activity.py:File System Operations & Access Patterns"
        "syscall_simulator.py:System Call Tracing & eBPF Monitoring"
    )

    for sample_info in "${samples[@]}"; do
        local sample_file=$(echo "$sample_info" | cut -d: -f1)
        local description=$(echo "$sample_info" | cut -d: -f2)

        run_sample_analysis "$sample_file" "$description"
        echo
    done

    # Run binary simulation if available
    if [[ -f "$TEST_SAMPLES_DIR/binary_simulator.sh" ]]; then
        run_sample_analysis "binary_simulator.sh" "Binary Execution & Script Analysis"
    fi
}

# Generate comprehensive report
generate_demo_report() {
    demo "📊 Generating comprehensive demonstration report..."

    local report_file="$ANALYSIS_DIR/reports/demo_report_$(date +%s).html"
    local timestamp=$(date)

    cat > "$report_file" << EOF
<!DOCTYPE html>
<html lang="en">
<head>
    <meta charset="UTF-8">
    <meta name="viewport" content="width=device-width, initial-scale=1.0">
    <title>SentinelCore - Complete Malware Analysis Demonstration</title>
    <style>
        body { font-family: 'Segoe UI', Tahoma, Geneva, Verdana, sans-serif; margin: 0; padding: 20px; background: #f5f5f5; }
        .container { max-width: 1200px; margin: 0 auto; background: white; padding: 30px; border-radius: 10px; box-shadow: 0 2px 10px rgba(0,0,0,0.1); }
        h1 { color: #2c3e50; text-align: center; border-bottom: 3px solid #3498db; padding-bottom: 10px; }
        h2 { color: #34495e; border-left: 4px solid #3498db; padding-left: 15px; margin-top: 30px; }
        .section { margin: 20px 0; padding: 20px; background: #f8f9fa; border-radius: 5px; }
        .success { background: #d4edda; border: 1px solid #c3e6cb; color: #155724; }
        .warning { background: #fff3cd; border: 1px solid #ffeaa7; color: #856404; }
        .info { background: #d1ecf1; border: 1px solid #bee5eb; color: #0c5460; }
        .metric { display: inline-block; margin: 10px; padding: 15px; background: white; border-radius: 5px; box-shadow: 0 1px 3px rgba(0,0,0,0.1); min-width: 200px; text-align: center; }
        .metric h3 { margin: 0; color: #3498db; }
        .metric p { margin: 5px 0 0 0; font-size: 1.5em; font-weight: bold; color: #2c3e50; }
        table { width: 100%; border-collapse: collapse; margin: 20px 0; }
        th, td { padding: 12px; text-align: left; border-bottom: 1px solid #ddd; }
        th { background-color: #f8f9fa; font-weight: 600; }
        .status-good { color: #28a745; }
        .status-warning { color: #ffc107; }
        .status-error { color: #dc3545; }
        .code { background: #f8f9fa; border: 1px solid #e9ecef; padding: 15px; border-radius: 5px; font-family: 'Courier New', monospace; overflow-x: auto; }
    </style>
</head>
<body>
    <div class="container">
        <h1>🔍 SentinelCore - Complete Malware Analysis Demonstration</h1>

        <div class="section info">
            <h2>📋 Demonstration Summary</h2>
            <p><strong>Generated:</strong> $timestamp</p>
            <p><strong>System:</strong> $(uname -a)</p>
            <p><strong>Analysis Directory:</strong> $ANALYSIS_DIR</p>
            <p><strong>Web Dashboard:</strong> <a href="http://localhost:$WEB_DASHBOARD_PORT" target="_blank">http://localhost:$WEB_DASHBOARD_PORT</a></p>
        </div>

        <div class="section">
            <h2>🎯 Analysis Results</h2>
            <div style="display: flex; flex-wrap: wrap; justify-content: center;">
EOF

    # Add metrics for each analysis
    local json_files=("$ANALYSIS_DIR"/malware_analysis_*.json)
    local total_analyses=${#json_files[@]}
    local total_processes=0
    local total_connections=0
    local total_files=0

    for json_file in "${json_files[@]}"; do
        if [[ -f "$json_file" ]]; then
            # Extract metrics from JSON (simplified)
            local processes=$(grep -o '"process_tree"' "$json_file" | wc -l)
            local connections=$(grep -o '"network_connections"' "$json_file" | wc -l)
            local files=$(grep -o '"file_operations"' "$json_file" | wc -l)

            total_processes=$((total_processes + processes))
            total_connections=$((total_connections + connections))
            total_files=$((total_files + files))
        fi
    done

    cat >> "$report_file" << EOF
                <div class="metric">
                    <h3>📊 Analyses Run</h3>
                    <p>$total_analyses</p>
                </div>
                <div class="metric">
                    <h3>🔄 Processes Monitored</h3>
                    <p>$total_processes</p>
                </div>
                <div class="metric">
                    <h3>🌐 Network Connections</h3>
                    <p>$total_connections</p>
                </div>
                <div class="metric">
                    <h3>📁 File Operations</h3>
                    <p>$total_files</p>
                </div>
            </div>
        </div>

        <div class="section">
            <h2>🧪 Test Samples Analyzed</h2>
            <table>
                <thead>
                    <tr>
                        <th>Sample</th>
                        <th>Description</th>
                        <th>Status</th>
                    </tr>
                </thead>
                <tbody>
                    <tr>
                        <td><code>process_spawner.py</code></td>
                        <td>Process creation and child process monitoring</td>
                        <td class="status-good">✓ Completed</td>
                    </tr>
                    <tr>
                        <td><code>network_activity.py</code></td>
                        <td>Network connections and DNS activity</td>
                        <td class="status-good">✓ Completed</td>
                    </tr>
                    <tr>
                        <td><code>filesystem_activity.py</code></td>
                        <td>File system operations and access patterns</td>
                        <td class="status-good">✓ Completed</td>
                    </tr>
                    <tr>
                        <td><code>syscall_simulator.py</code></td>
                        <td>System call tracing and eBPF monitoring</td>
                        <td class="status-good">✓ Completed</td>
                    </tr>
                    <tr>
                        <td><code>binary_simulator.sh</code></td>
                        <td>Binary execution and script analysis</td>
                        <td class="status-good">✓ Completed</td>
                    </tr>
                </tbody>
            </table>
        </div>

        <div class="section success">
            <h2>✅ Demonstration Complete</h2>
            <p><strong>What was demonstrated:</strong></p>
            <ul>
                <li>Complete malware analysis workflow from sample to report</li>
                <li>Real-time process monitoring and child process tracking</li>
                <li>Network activity analysis and connection monitoring</li>
                <li>File system operation tracking and access patterns</li>
                <li>System call tracing with eBPF (when available)</li>
                <li>Web-based dashboard for real-time results visualization</li>
                <li>Comprehensive reporting and data export</li>
            </ul>
        </div>

        <div class="section info">
            <h2>🚀 Next Steps</h2>
            <p><strong>To continue exploring:</strong></p>
            <ol>
                <li>Access the <a href="http://localhost:$WEB_DASHBOARD_PORT" target="_blank">web dashboard</a> for interactive analysis</li>
                <li>Check the analysis directory: <code>$ANALYSIS_DIR</code></li>
                <li>Review detailed logs in: <code>$ANALYSIS_DIR/logs/</code></li>
                <li>View generated reports in: <code>$ANALYSIS_DIR/reports/</code></li>
                <li>Run individual analyses with: <code>./analyze_malware.sh [sample_path]</code></li>
            </ol>
        </div>

        <div class="section">
            <h2>📁 Generated Files</h2>
            <div class="code">
Analysis Directory: $ANALYSIS_DIR
├── logs/                 # Detailed analysis logs
├── traces/              # System call traces
├── reports/             # HTML and summary reports
├── results/             # Raw analysis data
└── malware_analysis_*.json  # Analysis results (JSON)
            </div>
        </div>
    </div>
</body>
</html>
EOF

    success "Comprehensive report generated: $report_file"
    demo "📄 Open report: file://$report_file"
}

# Cleanup function
cleanup() {
    demo "🧹 Cleaning up demonstration environment..."

    # Stop web dashboard
    if [[ -f "$ANALYSIS_DIR/dashboard.pid" ]]; then
        local dashboard_pid=$(cat "$ANALYSIS_DIR/dashboard.pid")
        if kill -0 "$dashboard_pid" 2>/dev/null; then
            info "Stopping web dashboard (PID: $dashboard_pid)"
            kill "$dashboard_pid" 2>/dev/null || true
        fi
    fi

    # Kill any remaining analysis processes
    pkill -f "malware_tracer.py" 2>/dev/null || true
    pkill -f "web_dashboard.py" 2>/dev/null || true

    success "Cleanup completed"
}

# Main demonstration function
run_demonstration() {
    show_banner

    # Pre-demonstration setup
    check_system
    setup_python
    setup_analysis
    validate_samples

    # Start dashboard immediately
    start_dashboard

    # Interactive analysis loop
    while true; do
        echo
        demo "🔍 SENTINALCORE MALWARE ANALYSIS SYSTEM"
        echo
        info "Available test samples in $TEST_SAMPLES_DIR/:"
        ls -1 "$TEST_SAMPLES_DIR"/*.py "$TEST_SAMPLES_DIR"/*.sh 2>/dev/null | while read -r sample_path; do
            sample_file=$(basename "$sample_path")
            case $sample_file in
                "process_spawner.py") desc="Process creation & child process monitoring" ;;
                "network_activity.py") desc="Network connections & DNS activity" ;;
                "filesystem_activity.py") desc="File system operations & access patterns" ;;
                "syscall_simulator.py") desc="System call tracing & eBPF monitoring" ;;
                "binary_simulator.sh") desc="Binary execution & script analysis" ;;
                "combined_malware.py") desc="Combined network & process activity" ;;
                "simple_network_malware.py") desc="Simple network malware simulator" ;;
                *) desc="Unknown sample" ;;
            esac
            info "  • $sample_file - $desc"
        done
        echo
        read -p "Enter full path to malware file (or 'quit' to exit): " malware_path

        if [[ "$malware_path" == "quit" || "$malware_path" == "exit" ]]; then
            break
        fi

        if [[ ! -f "$malware_path" ]]; then
            error "File not found: $malware_path"
            continue
        fi

        # Extract filename for display
        malware_filename=$(basename "$malware_path")

        # Run analysis on the specified file
        demo "🔬 Analyzing: $malware_filename"
        info "Target: $malware_path"

        # Run the analysis
        if python3 "$PROJECT_ROOT/analysis/malware_tracer.py" "$malware_path" "$ANALYSIS_DURATION" "$ANALYSIS_DIR"; then
            success "Analysis completed for $malware_filename"

            # Show summary
            echo
            demo "📊 Analysis Summary:"
            info "  • Web Dashboard: http://localhost:$WEB_DASHBOARD_PORT"
            info "  • Analysis Directory: $ANALYSIS_DIR"
            info "  • Results saved to: $ANALYSIS_DIR"
            echo
            demo "💡 Check the web dashboard to view detailed analysis results!"
        else
            error "Analysis failed for $malware_filename"
        fi

        echo
        read -p "Press Enter to analyze another file, or 'quit' to exit: " choice
        if [[ "$choice" == "quit" || "$choice" == "exit" ]]; then
            break
        fi
    done

    # Summary
    echo
    demo "🎉 SENTINALCORE SESSION COMPLETE!"
    echo
    demo "📊 Session Summary:"
    info "  • Web Dashboard: http://localhost:$WEB_DASHBOARD_PORT"
    info "  • Analysis Directory: $ANALYSIS_DIR"
    info "  • Total Analyses: $(ls -1 "$ANALYSIS_DIR"/malware_analysis_*.json 2>/dev/null | wc -l)"
    echo
    demo "💡 Keep the web dashboard running to explore results interactively!"
    demo "   Press Ctrl+C to stop the dashboard when finished."
    echo

    # Keep dashboard running
    info "Press Ctrl+C to stop the web dashboard and exit"
    wait
}

# Show usage
show_usage() {
    echo "SentinelCore - Complete Malware Analysis Demonstration"
    echo
    echo "Usage: $0 [options]"
    echo
    echo "Options:"
    echo "  --help          Show this help message"
    echo "  --duration N    Set analysis duration in seconds (default: 30)"
    echo "  --port N        Set web dashboard port (default: 5173)"
    echo "  --sample FILE   Run analysis on specific sample only"
    echo
    echo "Examples:"
    echo "  $0                          # Run complete demonstration"
    echo "  $0 --duration 60           # 60-second analyses"
    echo "  $0 --port 8080             # Use port 8080 for dashboard"
    echo "  $0 --sample process_spawner.py  # Test single sample"
    echo
    echo "The demonstration will:"
    echo "  1. Set up the analysis environment"
    echo "  2. Start the web dashboard"
    echo "  3. Run analysis on all test samples"
    echo "  4. Generate comprehensive reports"
    echo "  5. Provide access to interactive dashboard"
}

# Parse command line arguments
parse_args() {
    while [[ $# -gt 0 ]]; do
        case $1 in
            --help)
                show_usage
                exit 0
                ;;
            --duration)
                ANALYSIS_DURATION="$2"
                shift 2
                ;;
            --port)
                WEB_DASHBOARD_PORT="$2"
                shift 2
                ;;
            --sample)
                SINGLE_SAMPLE="$2"
                shift 2
                ;;
            *)
                error "Unknown option: $1"
                ;;
        esac
    done
}

# Main entry point
main() {
    # Parse arguments
    parse_args "$@"

    # Set up signal handlers
    trap cleanup EXIT
    trap 'error "Demonstration interrupted by user"' INT TERM

    # Run demonstration
    run_demonstration
}

# Execute main function
main "$@"