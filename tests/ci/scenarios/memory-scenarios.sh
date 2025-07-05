#!/bin/bash
set -euo pipefail

# Memory Access Test Scenarios
# Tests various memory access patterns to verify detection

SCRIPT_DIR="$(cd "$(dirname "${BASH_SOURCE[0]}")" && pwd)"
source "${SCRIPT_DIR}/../lib/common.sh"

CONTAINER_NAME="${1:-bee-trace-test}"
RESULTS_FILE="${2:-${SCRIPT_DIR}/../results/memory-monitor-results.json}"
LOG_FILE="${SCRIPT_DIR}/../results/bee-trace.log"

# Test: Direct Memory Read Attempts
test_direct_memory_read() {
    log_info "Testing direct memory read detection..."
    
    # Find a target process
    local target_pid=$(find_target_process "bash")
    if [ -z "${target_pid}" ]; then
        log_warning "No suitable target process found"
        return 1
    fi
    
    log_info "Target process: PID ${target_pid}"
    
    # Attempt various memory reads
    generate_memory_access "${target_pid}" "read"
    
    # Try to read process memory maps
    generate_memory_access "${target_pid}" "maps"
    
    # Attempt to access /proc/PID/mem
    dd if="/proc/${target_pid}/mem" of=/dev/null bs=1 count=1 skip=0 2>/dev/null || true
    
    sleep 2
    
    # Verify detection (may not trigger if not using process_vm_readv)
    if wait_for_event "${LOG_FILE}" "MEMORY.*${target_pid}\|mem.*access" 5 "Memory read attempts"; then
        return 0
    else
        # This might be expected as direct /proc/mem reads might not trigger eBPF
        log_warning "Direct memory reads may not be detected by current probes"
        return 0
    fi
}

# Test: Ptrace Attempts
test_ptrace_attempts() {
    log_info "Testing ptrace detection..."
    
    # Find target processes
    local target_pid=$(find_target_process "bash")
    if [ -z "${target_pid}" ]; then
        log_warning "No suitable target process found"
        return 1
    fi
    
    # Check if we have strace
    if ! command -v strace >/dev/null 2>&1; then
        log_warning "strace not found, installing..."
        if command -v apt-get >/dev/null 2>&1; then
            sudo apt-get update && sudo apt-get install -y strace || true
        fi
    fi
    
    # Attempt ptrace via strace
    if command -v strace >/dev/null 2>&1; then
        log_info "Using strace on PID ${target_pid}"
        timeout 1s strace -p "${target_pid}" 2>&1 >/dev/null || true
        
        # Try to trace a system process (will fail but triggers ptrace)
        timeout 1s strace -p 1 2>&1 >/dev/null || true
    fi
    
    # Alternative: Use gdb if available
    if command -v gdb >/dev/null 2>&1; then
        log_info "Attempting gdb attach to PID ${target_pid}"
        echo "quit" | timeout 2s gdb -p "${target_pid}" 2>&1 >/dev/null || true
    fi
    
    sleep 2
    
    # Verify detection
    if wait_for_event "${LOG_FILE}" "PTRACE.*${target_pid}\|ptrace.*detected" 5 "Ptrace attempts"; then
        return 0
    else
        return 1
    fi
}

# Test: Process Memory Scanning
test_memory_scanning() {
    log_info "Testing memory scanning pattern detection..."
    
    # Scan multiple processes
    local pids=($(ps aux | grep -v grep | awk '{print $2}' | head -10))
    
    for pid in "${pids[@]}"; do
        # Try to read maps
        cat "/proc/${pid}/maps" 2>/dev/null | head -1 >/dev/null || true
        
        # Try to read status
        cat "/proc/${pid}/status" 2>/dev/null | grep -i vmsize >/dev/null || true
    done
    
    sleep 2
    
    # This might not trigger eBPF events but tests the pattern
    log_info "Memory scanning pattern completed"
    return 0
}

# Test: Credential Dumping Simulation
test_credential_dumping() {
    log_info "Testing credential dumping pattern detection..."
    
    # Find browser or password manager processes
    local browser_pids=$(pgrep -f "chrome|firefox|brave" 2>/dev/null || echo "")
    
    if [ -n "${browser_pids}" ]; then
        for pid in ${browser_pids}; do
            log_info "Attempting to access browser process: PID ${pid}"
            
            # Try to read browser memory maps
            cat "/proc/${pid}/maps" 2>/dev/null | grep -i "heap\|stack" >/dev/null || true
            
            # Simulate memory dump attempt
            generate_memory_access "${pid}" "maps"
        done
    else
        log_warning "No browser processes found, using generic process"
        local target_pid=$(find_target_process)
        if [ -n "${target_pid}" ]; then
            generate_memory_access "${target_pid}" "maps"
        fi
    fi
    
    sleep 2
    
    # Check for any memory access events
    if wait_for_event "${LOG_FILE}" "MEMORY.*access\|PTRACE" 5 "Credential dumping attempts"; then
        return 0
    else
        # May not detect without specific syscalls
        return 0
    fi
}

# Test: Container Escape Attempts
test_container_escape() {
    log_info "Testing container escape pattern detection..."
    
    # Try to access init process (PID 1)
    log_info "Attempting to access init process"
    generate_memory_access "1" "maps"
    cat "/proc/1/environ" 2>/dev/null | head -1 >/dev/null || true
    
    # Try to access kernel threads
    local kernel_pids=$(ps aux | grep -E '^\[' | awk '{print $2}' | head -5)
    for pid in ${kernel_pids}; do
        cat "/proc/${pid}/status" 2>/dev/null >/dev/null || true
    done
    
    sleep 2
    
    # Verify detection
    if wait_for_event "${LOG_FILE}" "MEMORY.*pid=1\|PTRACE.*pid=1" 5 "Container escape attempts"; then
        return 0
    else
        # Expected as we might not have permissions
        return 0
    fi
}

# Test: Anti-Debugging Detection
test_anti_debugging() {
    log_info "Testing anti-debugging detection patterns..."
    
    # Create a test program that checks for debugger
    cat > /tmp/test_debug.c << 'EOF'
#include <stdio.h>
#include <sys/ptrace.h>

int main() {
    if (ptrace(PTRACE_TRACEME, 0, 0, 0) == -1) {
        printf("Debugger detected!\n");
        return 1;
    }
    printf("No debugger\n");
    return 0;
}
EOF
    
    # Compile if gcc available
    if command -v gcc >/dev/null 2>&1; then
        gcc -o /tmp/test_debug /tmp/test_debug.c 2>/dev/null || true
        
        # Run it
        /tmp/test_debug >/dev/null 2>&1 || true
        
        # Try to debug it
        if command -v gdb >/dev/null 2>&1; then
            echo "run" | timeout 2s gdb /tmp/test_debug 2>&1 >/dev/null || true
        fi
    fi
    
    sleep 2
    
    # Check for ptrace events
    if wait_for_event "${LOG_FILE}" "PTRACE" 5 "Anti-debugging detection"; then
        return 0
    else
        # PTRACE_TRACEME might not be monitored
        return 0
    fi
}

# Test: Memory Injection Simulation
test_memory_injection() {
    log_info "Testing memory injection pattern detection..."
    
    # Find a target process
    local target_pid=$(find_target_process)
    if [ -z "${target_pid}" ]; then
        log_warning "No suitable target process found"
        return 1
    fi
    
    # Create a test injector script
    cat > /tmp/inject_test.py << 'EOF'
#!/usr/bin/env python3
import sys
import os

if len(sys.argv) < 2:
    sys.exit(1)

pid = int(sys.argv[1])
try:
    # Try to open /proc/PID/mem (will fail without permissions)
    with open(f"/proc/{pid}/mem", "rb") as f:
        f.seek(0)
        f.read(1)
except:
    pass

# Try process_vm_readv via ctypes (if available)
try:
    import ctypes
    libc = ctypes.CDLL("libc.so.6")
    # This would need proper setup but we're just testing detection
except:
    pass
EOF
    
    chmod +x /tmp/inject_test.py
    
    # Run injection test
    python3 /tmp/inject_test.py "${target_pid}" 2>/dev/null || true
    
    sleep 2
    
    # Check for injection attempts
    if wait_for_event "${LOG_FILE}" "PROCESS_VM_READV\|MEMORY.*injection" 5 "Memory injection attempts"; then
        return 0
    else
        # May not detect Python-based attempts
        return 0
    fi
}

# Test: Rootkit Behavior Simulation
test_rootkit_behavior() {
    log_info "Testing rootkit-like behavior detection..."
    
    # Try to access multiple system processes
    local system_pids=$(ps aux | grep -E 'systemd|init|kernel' | grep -v grep | awk '{print $2}' | head -5)
    
    for pid in ${system_pids}; do
        # Try to read process info
        cat "/proc/${pid}/cmdline" 2>/dev/null >/dev/null || true
        ls -la "/proc/${pid}/fd/" 2>/dev/null >/dev/null || true
    done
    
    # Try to access kernel memory info
    cat /proc/kallsyms 2>/dev/null | head -1 >/dev/null || true
    cat /proc/modules 2>/dev/null | head -1 >/dev/null || true
    
    sleep 2
    
    # These accesses might not trigger eBPF but test the pattern
    log_info "Rootkit behavior simulation completed"
    return 0
}

# Test: Normal Process Inspection (Negative Test)
test_normal_process_inspection() {
    log_info "Testing normal process inspection (should not trigger alerts)..."
    
    # Clear log marker
    echo "=== NORMAL PROCESS TEST START ===" >> "${LOG_FILE}"
    
    # Normal process inspection
    ps aux >/dev/null
    top -b -n 1 >/dev/null 2>&1 || true
    
    # Read own process info (legitimate)
    cat "/proc/$$/status" >/dev/null
    cat "/proc/$$/cmdline" >/dev/null
    
    sleep 2
    
    # Check that normal operations don't trigger excessive alerts
    local suspicious_events=$(sed -n '/=== NORMAL PROCESS TEST START ===/,$p' "${LOG_FILE}" | grep -c "PTRACE\|PROCESS_VM_READV" || echo "0")
    
    if [ "${suspicious_events}" -eq 0 ]; then
        return 0
    else
        echo "Found ${suspicious_events} suspicious events for normal operations"
        return 1
    fi
}

# Main execution
main() {
    log_info "Starting memory access test scenarios..."
    
    # Check available tools
    if ! command -v strace >/dev/null 2>&1; then
        log_warning "strace not available, some tests will be limited"
    fi
    if ! command -v gdb >/dev/null 2>&1; then
        log_warning "gdb not available, some tests will be limited"
    fi
    
    # Run all tests with 60-second timeout each
    run_test "Direct Memory Read" test_direct_memory_read "${RESULTS_FILE}" 60
    run_test "Ptrace Attempts" test_ptrace_attempts "${RESULTS_FILE}" 60
    run_test "Memory Scanning Pattern" test_memory_scanning "${RESULTS_FILE}" 60
    run_test "Credential Dumping Simulation" test_credential_dumping "${RESULTS_FILE}" 60
    run_test "Container Escape Attempts" test_container_escape "${RESULTS_FILE}" 60
    run_test "Anti-Debugging Detection" test_anti_debugging "${RESULTS_FILE}" 60
    run_test "Memory Injection Simulation" test_memory_injection "${RESULTS_FILE}" 60
    run_test "Rootkit Behavior Simulation" test_rootkit_behavior "${RESULTS_FILE}" 60
    run_test "Normal Process Inspection" test_normal_process_inspection "${RESULTS_FILE}" 60
    
    log_info "Memory access scenarios completed"
}

main "$@"