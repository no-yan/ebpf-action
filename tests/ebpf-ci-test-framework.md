# eBPF CI Test Framework Design

## Overview
This framework enables testing eBPF security monitoring features in CI by running bee-trace in a container while simulating suspicious activities on the host.

## Architecture

```
┌─────────────────────────────────────────┐
│         GitHub Actions Runner           │
├─────────────────────────────────────────┤
│                                         │
│  ┌───────────────────┐  ┌────────────┐ │
│  │   bee-trace       │  │   Test     │ │
│  │   Container       │  │ Orchestrator│ │
│  │  (--pid=host)     │  │            │ │
│  │                   │  │  - Create  │ │
│  │  - File Monitor   │  │    threats │ │
│  │  - Network Mon    │  │  - Validate│ │
│  │  - Memory Mon     │  │    events  │ │
│  └───────────────────┘  └────────────┘ │
│           ↑                    │        │
│           └────────────────────┘        │
│         Monitors host processes         │
└─────────────────────────────────────────┘
```

## Test Components

### 1. Test Orchestrator Script (`tests/ci/test-orchestrator.sh`)
```bash
#!/bin/bash
# Main test orchestration script
# - Starts bee-trace container
# - Executes test scenarios
# - Validates detection results
# - Generates test reports
```

### 2. Test Scenarios (`tests/ci/scenarios/`)
- `file-access-scenarios.sh` - Test sensitive file access patterns
- `network-scenarios.sh` - Test suspicious network connections
- `memory-scenarios.sh` - Test process memory access attempts
- `combined-scenarios.sh` - Multi-vector attack simulations

### 3. Event Validator (`tests/ci/validate-events.py`)
Python script to parse and validate bee-trace output:
- JSON event parsing
- Event correlation
- Timing validation
- False positive checks

### 4. Test Utilities (`tests/ci/lib/`)
- `common.sh` - Shared test functions
- `event-generator.sh` - Create specific security events
- `container-manager.sh` - Docker container lifecycle

## Test Scenarios

### File Monitor Tests
1. **Basic Detection**
   - Access known sensitive files (id_rsa, .env, etc.)
   - Verify event generation with correct metadata

2. **Advanced Patterns**
   - Rapid file access (brute force simulation)
   - Hidden file access (.git/config, .docker/config.json)
   - Certificate/key file patterns

3. **Negative Tests**
   - Non-sensitive file access (should not trigger)
   - Performance under high file I/O load

### Network Monitor Tests
1. **Outbound Connections**
   - Suspicious ports (IRC, crypto mining)
   - Known malicious IPs (test list)
   - Rapid connection attempts

2. **Data Exfiltration Patterns**
   - Large data transfers
   - DNS tunneling attempts
   - Non-standard ports

### Memory Monitor Tests
1. **Process Inspection**
   - ptrace attempts
   - /proc/mem access
   - Memory dump tools

2. **Credential Theft**
   - Browser memory access
   - Password manager targeting

## Implementation Plan

### Phase 1: Core Framework
1. Create test orchestrator
2. Implement basic file monitor tests
3. Add event validation

### Phase 2: Extended Coverage
1. Add network monitoring tests
2. Add memory monitoring tests
3. Implement combined scenarios

### Phase 3: Advanced Features
1. Performance benchmarking
2. Kernel compatibility matrix
3. Security boundary testing

## CI Integration

### GitHub Actions Workflow
```yaml
name: eBPF Security Tests
on: [push, pull_request]

jobs:
  ebpf-security-tests:
    runs-on: ubuntu-latest
    strategy:
      matrix:
        test-suite: [file-monitor, network-monitor, memory-monitor, combined]
    
    steps:
      - name: Run eBPF Security Tests
        run: |
          ./tests/ci/test-orchestrator.sh --suite ${{ matrix.test-suite }}
```

## Success Criteria
- All test scenarios detect expected threats
- No false positives on benign operations
- Performance impact < 5% on system
- Works across Ubuntu 20.04, 22.04, 24.04

## Extensibility
The framework is designed to be extended for:
- New eBPF programs
- Additional threat patterns
- Different container runtimes
- Integration with security benchmarks (CIS, MITRE)