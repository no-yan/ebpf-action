#!/bin/bash
set -euo pipefail

# eBPF CI Test Orchestrator
# This script manages the execution of eBPF security tests in CI

# Source common functions
SCRIPT_DIR="$(cd "$(dirname "${BASH_SOURCE[0]}")" && pwd)"
source "${SCRIPT_DIR}/lib/common.sh"

# Configuration
CONTAINER_NAME="bee-trace-test-${RANDOM}"
TEST_SUITE="${1:-all}"
VERBOSE="${VERBOSE:-false}"
TEST_TIMEOUT="${TEST_TIMEOUT:-120}"
RESULTS_DIR="${SCRIPT_DIR}/results"

# Initialize
mkdir -p "${RESULTS_DIR}"
TEST_REPORT="${RESULTS_DIR}/test-report-$(date +%Y%m%d-%H%M%S).json"

# Test execution
main() {
    log_info "Starting eBPF CI tests - Suite: ${TEST_SUITE}"
    
    # Build container if needed
    if ! docker images | grep -q "myapp"; then
        log_info "Building bee-trace container..."
        docker buildx bake --load
    fi
    
    # Start bee-trace container
    start_bee_trace_container
    
    # Wait for container to be ready
    wait_for_container_ready
    
    # Execute test suite
    case "${TEST_SUITE}" in
        file-monitor)
            run_file_monitor_tests
            ;;
        network-monitor)
            run_network_monitor_tests
            ;;
        memory-monitor)
            run_memory_monitor_tests
            ;;
        all)
            run_file_monitor_tests
            run_network_monitor_tests
            run_memory_monitor_tests
            ;;
        *)
            log_error "Unknown test suite: ${TEST_SUITE}"
            exit 1
            ;;
    esac
    
    # Collect results
    collect_test_results
    
    # Cleanup
    cleanup_container
    
    # Generate report
    generate_test_report
    
    log_info "Test execution completed. Report: ${TEST_REPORT}"
}

start_bee_trace_container() {
    local probe_type="all"
    if [[ "${TEST_SUITE}" != "all" ]]; then
        probe_type="${TEST_SUITE/-monitor/}_monitor"
    fi
    
    log_info "Starting bee-trace container with probe type: ${probe_type}"
    
    docker run -d \
        --name "${CONTAINER_NAME}" \
        --privileged \
        --pid=host \
        -v /:/host \
        -v /sys/kernel/tracing:/sys/kernel/tracing \
        -v /proc:/host/proc:ro \
        -e RUST_LOG=debug \
        myapp --probe-type "${probe_type}" --security-mode --verbose \
        > "${RESULTS_DIR}/container-id.txt"
    
    # Start log collection in background
    docker logs -f "${CONTAINER_NAME}" 2>&1 > "${RESULTS_DIR}/bee-trace.log" &
    echo $! > "${RESULTS_DIR}/log-collector.pid"
}

wait_for_container_ready() {
    log_info "Waiting for bee-trace to initialize..."
    local count=0
    while [ $count -lt 30 ]; do
        if docker logs "${CONTAINER_NAME}" 2>&1 | grep -q "eBPF program attached successfully"; then
            log_info "bee-trace is ready"
            sleep 2  # Extra time for stabilization
            return 0
        fi
        sleep 1
        ((count++))
    done
    
    log_error "bee-trace failed to initialize"
    docker logs "${CONTAINER_NAME}"
    exit 1
}

run_file_monitor_tests() {
    log_info "Running file monitor tests..."
    
    # Create test results file
    local test_results="${RESULTS_DIR}/file-monitor-results.json"
    echo '{"test_suite": "file-monitor", "tests": []}' > "${test_results}"
    
    # Run test scenarios
    "${SCRIPT_DIR}/scenarios/file-access-scenarios.sh" "${CONTAINER_NAME}" "${test_results}"
    
    # Validate results
    python3 "${SCRIPT_DIR}/validate-events.py" \
        --log-file "${RESULTS_DIR}/bee-trace.log" \
        --test-results "${test_results}" \
        --event-type file
}

run_network_monitor_tests() {
    log_info "Running network monitor tests..."
    
    local test_results="${RESULTS_DIR}/network-monitor-results.json"
    echo '{"test_suite": "network-monitor", "tests": []}' > "${test_results}"
    
    "${SCRIPT_DIR}/scenarios/network-scenarios.sh" "${CONTAINER_NAME}" "${test_results}"
    
    python3 "${SCRIPT_DIR}/validate-events.py" \
        --log-file "${RESULTS_DIR}/bee-trace.log" \
        --test-results "${test_results}" \
        --event-type network
}

run_memory_monitor_tests() {
    log_info "Running memory monitor tests..."
    
    local test_results="${RESULTS_DIR}/memory-monitor-results.json"
    echo '{"test_suite": "memory-monitor", "tests": []}' > "${test_results}"
    
    "${SCRIPT_DIR}/scenarios/memory-scenarios.sh" "${CONTAINER_NAME}" "${test_results}"
    
    python3 "${SCRIPT_DIR}/validate-events.py" \
        --log-file "${RESULTS_DIR}/bee-trace.log" \
        --test-results "${test_results}" \
        --event-type memory
}

collect_test_results() {
    log_info "Collecting test results..."
    
    # Stop log collection
    if [ -f "${RESULTS_DIR}/log-collector.pid" ]; then
        kill $(cat "${RESULTS_DIR}/log-collector.pid") 2>/dev/null || true
    fi
    
    # Get final logs
    docker logs "${CONTAINER_NAME}" > "${RESULTS_DIR}/bee-trace-final.log" 2>&1
    
    # Extract metrics
    local events_count=$(grep -c "Event sent successfully" "${RESULTS_DIR}/bee-trace.log" || echo "0")
    echo "{\"total_events\": ${events_count}}" > "${RESULTS_DIR}/metrics.json"
}

cleanup_container() {
    log_info "Cleaning up..."
    docker stop "${CONTAINER_NAME}" >/dev/null 2>&1 || true
    docker rm "${CONTAINER_NAME}" >/dev/null 2>&1 || true
}

generate_test_report() {
    log_info "Generating test report..."
    
    # Combine all results
    python3 -c "
import json
import glob
import sys

results = {
    'timestamp': '$(date -u +%Y-%m-%dT%H:%M:%SZ)',
    'test_suite': '${TEST_SUITE}',
    'status': 'completed',
    'suites': {}
}

for result_file in glob.glob('${RESULTS_DIR}/*-results.json'):
    with open(result_file) as f:
        data = json.load(f)
        suite_name = data.get('test_suite', 'unknown')
        results['suites'][suite_name] = data

# Add metrics
try:
    with open('${RESULTS_DIR}/metrics.json') as f:
        results['metrics'] = json.load(f)
except:
    results['metrics'] = {}

# Determine overall status
failed_tests = 0
for suite in results['suites'].values():
    for test in suite.get('tests', []):
        if test.get('status') != 'passed':
            failed_tests += 1

results['status'] = 'passed' if failed_tests == 0 else 'failed'
results['summary'] = {
    'total_tests': sum(len(s.get('tests', [])) for s in results['suites'].values()),
    'failed_tests': failed_tests
}

with open('${TEST_REPORT}', 'w') as f:
    json.dump(results, f, indent=2)

# Exit with error if tests failed
sys.exit(0 if failed_tests == 0 else 1)
"
}

# Handle signals
trap cleanup_container EXIT INT TERM

# Run main
main "$@"