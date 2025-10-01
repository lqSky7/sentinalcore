#!/bin/bash
# Simple test script that demonstrates isolation capabilities
echo "Test script starting..."
echo "Current user: $(whoami)"
echo "Current PID: $$"
echo "Current working directory: $(pwd)"
echo "Network interfaces:"
ip addr show 2>/dev/null || echo "No network interfaces visible (isolated)"
echo "Process list:"
ps aux 2>/dev/null | head -5 || echo "Limited process visibility (isolated)"
echo "File system:"
ls -la / 2>/dev/null | head -10 || echo "Limited filesystem access (isolated)"
echo "Test script completed successfully"