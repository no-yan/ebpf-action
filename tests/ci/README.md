# eBPF CI Test Framework

This directory contains the comprehensive CI testing framework for bee-trace's eBPF security monitoring capabilities.

## Overview

The framework tests bee-trace by running it in a privileged container that monitors the host system, while test scenarios generate various suspicious activities to verify detection capabilities.

## Directory Structure

```
tests/ci/
├── test-orchestrator.sh     # Main test runner
├── validate-events.py       # Event validation script
├── lib/
│   └── common.sh           # Shared test utilities
├── scenarios/
│   ├── file-access-scenarios.sh    # File monitoring tests
│   ├── network-scenarios.sh        # Network monitoring tests
│   └── memory-scenarios.sh         # Memory monitoring tests
└── results/                # Test results (created at runtime)
```

## Running Tests

### Local Testing

```bash
# Run all tests
./tests/ci/test-orchestrator.sh all

# Run specific test suite
./tests/ci/test-orchestrator.sh file-monitor
./tests/ci/test-orchestrator.sh network-monitor
./tests/ci/test-orchestrator.sh memory-monitor

# Run with verbose output
VERBOSE=true ./tests/ci/test-orchestrator.sh all
```

### CI Integration

Tests run automatically on:
- Push to main/develop branches
- Pull requests
- Manual workflow dispatch

See `.github/workflows/ebpf-security-tests.yml` for CI configuration.

## Test Scenarios

### File Monitor Tests
- SSH key access detection
- Environment file access (.env, .env.local)
- Certificate and key file access
- Credential file patterns
- Git configuration access
- Rapid file access (brute force patterns)
- Hidden file detection
- Database configuration files
- Container secrets
- Negative tests (non-sensitive files)

### Network Monitor Tests
- Suspicious port connections (4444, 6667, 31337)
- Crypto mining pool connections
- DNS exfiltration patterns
- Rapid connection attempts
- C2 server communication patterns
- Data exfiltration ports
- Localhost connections (lateral movement)
- UDP suspicious traffic
- Port scanning patterns
- Normal traffic handling

### Memory Monitor Tests
- Direct memory read attempts
- Ptrace detection
- Memory scanning patterns
- Credential dumping simulation
- Container escape attempts
- Anti-debugging detection
- Memory injection patterns
- Rootkit behavior simulation
- Normal process inspection (negative test)

## Test Results

Test results are stored in JSON format:
```json
{
  "timestamp": "2024-01-15T10:30:00Z",
  "test_suite": "file-monitor",
  "status": "passed",
  "summary": {
    "total_tests": 10,
    "failed_tests": 0
  },
  "suites": {
    "file-monitor": {
      "tests": [
        {
          "name": "SSH Key Access",
          "status": "passed",
          "duration": 3
        }
      ]
    }
  },
  "metrics": {
    "total_events": 245
  }
}
```

## Extending the Framework

### Adding New Test Scenarios

1. Create a new function in the appropriate scenario file:
```bash
test_new_detection() {
    log_info "Testing new detection..."
    
    # Generate suspicious activity
    generate_file_access "/tmp/suspicious.file" "content"
    
    # Wait for detection
    if wait_for_event "${LOG_FILE}" "pattern" 5 "description"; then
        return 0
    else
        return 1
    fi
}
```

2. Add to the main() function:
```bash
run_test "New Detection Test" test_new_detection "${RESULTS_FILE}"
```

### Adding New eBPF Programs

1. Create new scenario file: `tests/ci/scenarios/new-feature-scenarios.sh`
2. Update `test-orchestrator.sh` to handle the new test suite
3. Add validation logic to `validate-events.py`
4. Update CI workflow matrix

## Troubleshooting

### Common Issues

1. **Container fails to start**
   - Check Docker daemon is running
   - Verify sufficient permissions (--privileged)

2. **No events detected**
   - Check bee-trace logs for errors
   - Verify eBPF programs loaded successfully
   - Ensure kernel supports required eBPF features

3. **Tests timeout**
   - Increase TEST_TIMEOUT environment variable
   - Check system load during tests

### Debug Mode

Enable detailed logging:
```bash
VERBOSE=true TEST_TIMEOUT=300 ./tests/ci/test-orchestrator.sh all
```

Check container logs:
```bash
docker logs bee-trace-test-<random>
```

## Requirements

- Docker with buildx support
- Linux kernel with eBPF support (5.8+)
- Python 3 for event validation
- Tools: netcat, strace (installed by CI)

## Security Considerations

- Tests run with privileged access
- Some tests attempt real security operations (ptrace, memory access)
- All test data is contained in /tmp or test directories
- No actual exploits or malicious code is executed