#!/bin/bash

# Sentinal Setup Script
# This script sets up the development environment for the Sentinal malware analysis framework

set -e

echo "=== Sentinal Setup Script ==="
echo "Setting up Linux malware analysis framework..."

# Colors for output
RED='\033[0;31m'
GREEN='\033[0;32m'
YELLOW='\033[1;33m'
NC='\033[0m' # No Color

print_status() {
    echo -e "${GREEN}[INFO]${NC} $1"
}

print_warning() {
    echo -e "${YELLOW}[WARN]${NC} $1"
}

print_error() {
    echo -e "${RED}[ERROR]${NC} $1"
}

# Detect platform and architecture
PLATFORM=$(uname -s)
ARCH=$(uname -m)

print_status "Detected platform: $PLATFORM on $ARCH"

# Check platform compatibility
if [[ "$PLATFORM" == "Linux" ]]; then
    print_status "Running on Linux - full functionality available"
    LINUX_SYSTEM=true
elif [[ "$PLATFORM" == "Darwin" ]]; then
    print_warning "Running on macOS - some features will use fallback methods"
    print_warning "Process monitoring will be limited compared to Linux"
    LINUX_SYSTEM=false
else
    print_warning "Running on $PLATFORM - limited functionality expected"
    LINUX_SYSTEM=false
fi

# Architecture-specific notes
if [[ "$ARCH" == "arm64" ]] || [[ "$ARCH" == "aarch64" ]]; then
    print_status "ARM64 architecture detected - cross-platform support enabled"
elif [[ "$ARCH" == "x86_64" ]] || [[ "$ARCH" == "amd64" ]]; then
    print_status "x86_64 architecture detected"
else
    print_status "Architecture: $ARCH (may have limited support)"
fi

# Check for required system tools
print_status "Checking system requirements..."

# Core requirements for all platforms
core_tools=("gcc" "make" "python3")
missing_core=()

for tool in "${core_tools[@]}"; do
    if ! command -v "$tool" &> /dev/null; then
        missing_core+=("$tool")
    fi
done

# Check for pip3 or pip
if ! command -v "pip3" &> /dev/null && ! command -v "pip" &> /dev/null; then
    missing_core+=("pip3")
fi

# Linux-specific tools
linux_tools=("strace")
missing_linux=()

if [[ "$LINUX_SYSTEM" == true ]]; then
    for tool in "${linux_tools[@]}"; do
        if ! command -v "$tool" &> /dev/null; then
            missing_linux+=("$tool")
        fi
    done
fi

# Handle missing core tools
if [ ${#missing_core[@]} -ne 0 ]; then
    print_error "Missing required core tools: ${missing_core[*]}"
    print_status "Please install missing tools and run setup again"
    if [[ "$PLATFORM" == "Darwin" ]]; then
        print_status "On macOS: brew install gcc make python3"
        print_status "Or install Xcode Command Line Tools: xcode-select --install"
    elif [[ -f /etc/debian_version ]]; then
        print_status "On Ubuntu/Debian: sudo apt-get install gcc make python3 python3-pip"
    elif [[ -f /etc/redhat-release ]]; then
        print_status "On CentOS/RHEL: sudo yum install gcc make python3 python3-pip"
    fi
    exit 1
fi

# Handle missing Linux tools (warnings only)
if [[ "$LINUX_SYSTEM" == true ]] && [ ${#missing_linux[@]} -ne 0 ]; then
    print_warning "Missing Linux-specific tools: ${missing_linux[*]}"
    print_warning "Some advanced monitoring features will be limited"
    if [[ -f /etc/debian_version ]]; then
        print_status "To install: sudo apt-get install ${missing_linux[*]}"
    elif [[ -f /etc/redhat-release ]]; then
        print_status "To install: sudo yum install ${missing_linux[*]}"
    fi
    print_status "Continuing with available tools..."
fi

print_status "All required system tools found"

# Create Python virtual environment
print_status "Setting up Python virtual environment..."

if [ ! -d "venv" ]; then
    python3 -m venv venv
    print_status "Created virtual environment"
else
    print_status "Virtual environment already exists"
fi

# Activate virtual environment
source venv/bin/activate
print_status "Activated virtual environment"

# Install Python dependencies
print_status "Installing Python dependencies..."

# Use pip3 if available, otherwise pip
if command -v pip3 &> /dev/null; then
    PIP_CMD="pip3"
else
    PIP_CMD="pip"
fi

$PIP_CMD install --upgrade pip
$PIP_CMD install -r requirements.txt

print_status "Python dependencies installed"

# Compile C monitor
print_status "Compiling process monitor..."
cd monitor

# Clean previous builds
make clean 2>/dev/null || true

# Attempt compilation
if make; then
    if make install; then
        print_status "Process monitor compiled successfully"
    else
        print_warning "Monitor installation failed, but binary may still work"
    fi
else
    print_warning "Process monitor compilation failed"
    print_warning "The system will use fallback monitoring methods"
    print_warning "This is expected on some platforms (e.g., macOS with limited ptrace)"
fi

cd ..

# Compile sample malware
print_status "Compiling sample malware..."
cd samples

# Create a simple Makefile if it doesn't exist
if [ ! -f Makefile ]; then
    cat > Makefile << 'EOF'
CC=gcc
CFLAGS=-Wall -Wextra -std=c99 -g

all: test_malware

test_malware: test_malware.c
	$(CC) $(CFLAGS) -o test_malware test_malware.c

clean:
	rm -f test_malware

test:
	@echo "Sample malware compiled for $(shell uname -s) on $(shell uname -m)"

.PHONY: all clean test
EOF
fi

# Attempt compilation
make clean 2>/dev/null || true

if make; then
    print_status "Sample C malware compiled successfully"
else
    print_warning "Sample C malware compilation failed"
    print_warning "Python and shell samples will still work"
fi

# Make scripts executable
chmod +x test_malware.sh 2>/dev/null || true
chmod +x test_malware.py 2>/dev/null || true

cd ..

print_status "Sample malware setup completed"

# Create necessary directories
print_status "Creating directory structure..."
mkdir -p results
mkdir -p logs
mkdir -p /tmp/sentinal

print_status "Directory structure created"

# Set up configuration
print_status "Setting up configuration..."
if [ ! -f "config/sentinal_local.conf" ]; then
    cp config/sentinal.conf config/sentinal_local.conf
    print_status "Created local configuration file"
fi

# Check permissions
print_status "Checking permissions..."

if [ "$(id -u)" -eq 0 ]; then
    print_warning "Running as root detected"
    print_warning "For security, consider running as a non-root user"
fi

# Test basic functionality
print_status "Testing basic functionality..."

# Test Python import
python3 -c "
import sys
sys.path.append('backend')
try:
    import app
    print('✓ Backend imports successfully')
except ImportError as e:
    print(f'✗ Backend import failed: {e}')
    sys.exit(1)
"

# Test C monitor
if [ -f "backend/process_monitor" ]; then
    print_status "✓ Process monitor available"
else
    print_error "✗ Process monitor not found"
    exit 1
fi

# Create startup script
print_status "Creating startup script..."

cat > start_sentinal.sh << 'EOF'
#!/bin/bash
# Sentinal Startup Script

echo "Starting Sentinal Analysis Framework..."

# Activate virtual environment
source venv/bin/activate

# Check if monitor is compiled
if [ ! -f "backend/process_monitor" ]; then
    echo "Compiling process monitor..."
    cd monitor && make && make install && cd ..
fi

# Start the Flask application
echo "Starting web server on http://localhost:3000"
cd backend
python3 app.py
EOF

chmod +x start_sentinal.sh
print_status "Startup script created: ./start_sentinal.sh"

# Security warnings
print_status "Security setup complete"
print_warning "IMPORTANT SECURITY NOTICES:"
print_warning "1. This tool executes potentially malicious files"
print_warning "2. Always run in isolated environments (VMs/containers)"
print_warning "3. Never analyze files on production systems"
print_warning "4. Monitor system resources during analysis"
print_warning "5. Review and understand sample files before execution"

echo ""
print_status "=== Setup Complete ==="
print_status "To start Sentinal:"
print_status "  ./start_sentinal.sh"
print_status ""
print_status "Or manually:"
print_status "  source venv/bin/activate"
print_status "  cd backend && python3 app.py"
print_status ""
print_status "Web interface will be available at: http://localhost:3000"
print_status ""
print_status "Sample files for testing:"
print_status "  - samples/test_malware.py (Python)"
print_status "  - samples/test_malware (C binary)"
print_status "  - samples/test_malware.sh (Shell script)"

echo ""
print_warning "Remember: Only analyze files in isolated environments!"