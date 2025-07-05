#!/bin/bash
# Common functions for eBPF CI tests

# Colors for output
RED='\033[0;31m'
GREEN='\033[0;32m'
YELLOW='\033[1;33m'
BLUE='\033[0;34m'
NC='\033[0m' # No Color

# Logging functions
log_info() {
    echo -e "${BLUE}[INFO]${NC} $(date '+%Y-%m-%d %H:%M:%S') - $*"
}

log_success() {
    echo -e "${GREEN}[SUCCESS]${NC} $(date '+%Y-%m-%d %H:%M:%S') - $*"
}

log_warning() {
    echo -e "${YELLOW}[WARNING]${NC} $(date '+%Y-%m-%d %H:%M:%S') - $*"
}

log_error() {
    echo -e "${RED}[ERROR]${NC} $(date '+%Y-%m-%d %H:%M:%S') - $*" >&2
}

# Wait for event to appear in logs
wait_for_event() {
    local log_file="$1"
    local pattern="$2"
    local timeout="${3:-10}"
    local description="${4:-event}"
    
    log_info "Waiting for ${description}..."
    
    local count=0
    while [ $count -lt $timeout ]; do
        if grep -q "${pattern}" "${log_file}"; then
            log_success "Found ${description}"
            return 0
        fi
        sleep 1
        ((count++))
    done
    
    log_error "Timeout waiting for ${description}"
    return 1
}

# Record test result
record_test_result() {
    local results_file="$1"
    local test_name="$2"
    local status="$3"
    local message="${4:-}"
    local duration="${5:-0}"
    
    # Use Python with proper JSON escaping
    python3 -c "
import json
import sys
import os

results_file = '${results_file}'
test_name = '''${test_name}'''
status = '''${status}'''
message = '''${message}'''
duration = ${duration}

try:
    with open(results_file, 'r') as f:
        data = json.load(f)
except:
    data = {'test_suite': 'unknown', 'tests': []}

test_result = {
    'name': test_name,
    'status': status,
    'message': message.replace('\x1b', '\\x1b'),  # Escape ANSI codes
    'duration': duration
}

data['tests'].append(test_result)

with open(results_file, 'w') as f:
    json.dump(data, f, indent=2)
" 2>/dev/null || {
    # Fallback: create simple test result without message
    python3 -c "
import json
try:
    with open('${results_file}', 'r') as f:
        data = json.load(f)
except:
    data = {'test_suite': 'unknown', 'tests': []}

data['tests'].append({
    'name': '''${test_name}''',
    'status': '''${status}''',
    'message': 'Error message contained invalid characters',
    'duration': ${duration}
})

with open('${results_file}', 'w') as f:
    json.dump(data, f, indent=2)
"
}
}

# Execute test with timing
run_test() {
    local test_name="$1"
    local test_function="$2"
    local results_file="$3"
    
    log_info "Running test: ${test_name}"
    
    local start_time=$(date +%s)
    local status="failed"
    local message=""
    
    if output=$(${test_function} 2>&1); then
        status="passed"
        log_success "Test passed: ${test_name}"
    else
        message="${output}"
        log_error "Test failed: ${test_name}"
        log_error "${message}"
    fi
    
    local end_time=$(date +%s)
    local duration=$((end_time - start_time))
    
    record_test_result "${results_file}" "${test_name}" "${status}" "${message}" "${duration}"
}

# Generate suspicious file access
generate_file_access() {
    local file_path="$1"
    local content="${2:-test-content}"
    
    # Create parent directory if needed
    mkdir -p "$(dirname "${file_path}")"
    
    # Write content
    echo "${content}" > "${file_path}"
    
    # Read to trigger access event
    cat "${file_path}" >/dev/null
    
    # Optional: try different access patterns
    head -n 1 "${file_path}" >/dev/null 2>&1 || true
    tail -n 1 "${file_path}" >/dev/null 2>&1 || true
}

# Generate network connection
generate_network_connection() {
    local host="$1"
    local port="$2"
    local timeout="${3:-1}"
    
    # Try to connect (will likely fail/timeout for test IPs)
    timeout ${timeout}s nc -z "${host}" "${port}" 2>/dev/null || true
    
    # Alternative methods
    timeout ${timeout}s bash -c "echo >/dev/tcp/${host}/${port}" 2>/dev/null || true
}

# Generate memory access attempt
generate_memory_access() {
    local target_pid="$1"
    local access_type="${2:-read}"
    
    case "${access_type}" in
        read)
            # Attempt to read /proc/PID/mem (will fail without permissions)
            dd if="/proc/${target_pid}/mem" of=/dev/null bs=1 count=1 2>/dev/null || true
            ;;
        ptrace)
            # Use strace to trigger ptrace (requires strace installed)
            timeout 1s strace -p "${target_pid}" 2>/dev/null || true
            ;;
        maps)
            # Read memory maps
            cat "/proc/${target_pid}/maps" 2>/dev/null || true
            ;;
    esac
}

# Find a suitable target process
find_target_process() {
    local process_name="${1:-bash}"
    
    # Find a process owned by current user
    pgrep -u "$(id -u)" "${process_name}" | head -1
}

# Validate JSON in file
validate_json() {
    local file="$1"
    python3 -m json.tool "${file}" >/dev/null 2>&1
}

# Extract events from log
extract_events() {
    local log_file="$1"
    local event_type="${2:-}"
    
    if [ -n "${event_type}" ]; then
        grep "Event sent successfully" "${log_file}" | grep -i "${event_type}" || true
    else
        grep "Event sent successfully" "${log_file}" || true
    fi
}

# Check container health
check_container_health() {
    local container="$1"
    
    if ! docker ps --format "{{.Names}}" | grep -q "^${container}$"; then
        log_error "Container ${container} is not running"
        return 1
    fi
    
    # Check if eBPF programs are loaded
    if ! docker exec "${container}" ls /sys/kernel/debug/tracing/events/raw_syscalls 2>/dev/null; then
        log_warning "Cannot verify eBPF programs (may need different kernel version)"
    fi
    
    return 0
}