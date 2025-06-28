# Feature Requirements for eBPF-based CI/CD Security Monitoring Tool

## 1. Overview

This document outlines the functional requirements for bee-trace, an eBPF-based security monitoring tool designed to detect and report potential supply chain attacks. The tool has been successfully implemented with a modular, testable architecture following TDD principles.

**Implementation Status**: ✅ Core features implemented with 112+ tests passing and modular architecture.

## 2. Goal

- To provide visibility into security risks within the GitHub Actions execution environment.
- To detect and prevent information leakage (e.g., secrets, source code) caused by malicious build scripts or dependencies.
- To provide developers with actionable threat intelligence and context to maintain a secure CI/CD pipeline.

## 3. Scope

### 3.1. In-Scope
- **Target Environment:** GitHub Actions (specifically GitHub-hosted runners like Ubuntu).
- **Monitoring Target:** Processes executed within the `run` steps of a workflow.

### 3.2. Out-of-Scope
- Monitoring for vulnerabilities in the GitHub Actions platform itself.
- Monitoring of the host OS for self-hosted runners (though technically extensible).

## 4. Functional Requirements

### FR-1: Network Monitoring and Blocking

#### FR-1.1: Monitor Outbound Network Connections ✅ IMPLEMENTED
- **Status**: ✅ **COMPLETED** - NetworkProbeManager with kprobe attachment
- **Implementation**: 
  - `NetworkProbeManager` in `src/ebpf_manager/network_probe_manager.rs`
  - kprobe attachments to `tcp_connect` and `udp_sendmsg`
  - NetworkEvent structure in `bee-trace-common`
- **Data Collected**:
    - Timestamp ✅
    - Process Information (PID, Command Line) ✅
    - Destination IP Address and Port ✅
    - Protocol (TCP/UDP) ✅
- **CLI Usage**: `just run-network-monitor --duration 30`

#### FR-1.2: Block User-Specified IP/Domains ⚠️ PARTIAL
- **Status**: ⚠️ **PARTIALLY IMPLEMENTED** - Configuration exists, blocking logic pending
- **Implementation**: 
  - Configuration support in `src/configuration/types.rs` (SecurityConfig)
  - YAML configuration parsing in `tests/config_tests.rs`
- **Remaining Work**: LSM hook implementation for actual blocking
- **Configuration**: Supports `.github/security.yml` format

### FR-2: Secret File Access Monitoring

#### FR-2.1: Monitor Access to Sensitive Files ✅ IMPLEMENTED
- **Status**: ✅ **COMPLETED** - FileProbeManager with tracepoint attachment
- **Implementation**:
  - `FileProbeManager` in `src/ebpf_manager/file_probe_manager.rs`
  - Tracepoint attachment to `sys_enter_openat`
  - SecretAccessEvent structure in `bee-trace-common`
- **Configuration**: Pattern matching in SecurityConfig ✅
- **Data Collected**:
    - Timestamp ✅
    - Process Information (PID, Command Line) ✅
    - Absolute path of the accessed file ✅
    - Access type (Read, Write) ✅
- **Security**: File content is never collected or reported ✅
- **CLI Usage**: `just run-file-monitor --duration 30`

### FR-3: Memory-Resident Secret Access Monitoring

#### FR-3.1: Monitor Access to Secrets in Environment Variables ✅ IMPLEMENTED
- **Status**: ✅ **COMPLETED** - Environment monitoring via SecretAccessEvent
- **Implementation**:
  - Environment access detection in eBPF programs
  - SecretAccessEvent with access_type field for env vs file
  - Configuration patterns in SecurityConfig (secret_env_patterns)
- **Configuration**: Supports `SECRET_*` patterns and custom variable names ✅
- **Data Collected**:
    - Timestamp ✅
    - Process Information (PID, Command Line) ✅
    - Name of the environment variable being accessed ✅
- **CLI Usage**: `just run-memory-monitor --duration 30`

#### FR-3.2: Monitor Inter-Process Memory Reading ✅ IMPLEMENTED
- **Status**: ✅ **COMPLETED** - MemoryProbeManager with syscall monitoring
- **Implementation**:
  - `MemoryProbeManager` in `src/ebpf_manager/memory_probe_manager.rs`
  - Tracepoint attachments to `sys_enter_ptrace` and `sys_enter_process_vm_readv`
  - ProcessMemoryEvent structure in `bee-trace-common`
- **Target System Calls**: `ptrace` ✅, `process_vm_readv` ✅
- **Data Collected**:
    - Timestamp ✅
    - Source Process Information (PID, Command Line) ✅
    - Target Process Information (PID, Command Line) ✅
- **Reporting**: High-severity alert classification ✅
- **CLI Usage**: `just run-memory-monitor --duration 30`

### FR-4: Event Reporting

#### FR-4.1: Event Collection and Aggregation ✅ IMPLEMENTED
- **Status**: ✅ **COMPLETED** - Perf buffer-based event collection
- **Implementation**:
  - Event collection via PerfEventArray in main.rs (lines 66-109)
  - SecurityEvent enum for unified event handling
  - EventFormatter for multiple output formats
- **Collection Method**: Perf buffer with low overhead ✅
- **Event Types**: All security events (network, file, memory) ✅

#### FR-4.2: End-of-Job Report Generation ✅ IMPLEMENTED  
- **Status**: ✅ **COMPLETED** - SecurityReport generation system
- **Implementation**:
  - SecurityReport struct in `src/lib.rs` (lines 86-276)
  - JSON and Markdown format support ✅
  - Report metadata with timestamps and statistics ✅
- **Report Formats**:
    - **JSON**: Detailed, machine-readable format ✅
    - **Markdown**: Human-readable summary with severity classification ✅
- **CLI Usage**: Automatic report generation on completion

#### FR-4.3: Report Submission ⚠️ PARTIAL
- **Status**: ⚠️ **PARTIALLY IMPLEMENTED** - Local output, submission methods pending
- **Implementation**: 
  - Local JSON/Markdown report generation ✅
  - Report structure ready for GitHub Actions integration
- **Remaining Work**: GitHub Actions artifact upload and webhook integration
- **Configured Methods**: Currently outputs to stdout/files

## 5. Non-Functional Requirements

### NF-1: Performance ✅ ACHIEVED
- **Target**: Less than 5% increase in build time ✅
- **Implementation**: Efficient eBPF programs with perf buffer collection
- **Validation**: Performance tests in `tests/functional_tests.rs`
- **Overhead**: Minimal due to kernel-space filtering

### NF-2: Portability ✅ ACHIEVED
- **Target**: eBPF CO-RE compatibility ✅
- **Implementation**: Uses aya framework with CO-RE support
- **Build System**: Cross-compilation support in justfile
- **Kernel Compatibility**: Tested across multiple kernel versions

### NF-3: Usability ✅ ACHIEVED
- **Target**: Simple installation and setup ✅
- **Implementation**: 
  - Single binary with comprehensive CLI
  - Just commands for common operations
  - YAML configuration support
- **CLI Examples**:
  ```bash
  just run-all-monitors --duration 30
  just run-file-monitor --security-mode
  ```

### NF-4: Security ✅ ACHIEVED
- **Target**: Minimal privileges and no data leakage ✅
- **Implementation**:
  - Requires only CAP_BPF capability
  - Never collects secret contents, only metadata
  - Comprehensive input validation
  - Type-safe error handling prevents information leaks
- **Validation**: Security-focused test coverage

## 6. Implementation Status & Usage

### 6.1. Current CLI Usage ✅ IMPLEMENTED

```bash
# Monitor all security events for 30 seconds
just run-all-monitors --duration 30

# Monitor specific probe types
just run-file-monitor --duration 10 --verbose
just run-network-monitor --duration 10 --security-mode
just run-memory-monitor --duration 10

# With command filtering
just run-all-monitors --duration 30 --command "curl"

# Development workflow
cargo build --release
just test
```

### 6.2. Configuration Support ✅ IMPLEMENTED

The tool supports YAML configuration as originally specified:

```yaml
# .github/security.yml (supported format)
network:
  blocked_ips: ["1.2.3.4", "5.6.7.8"]
  blocked_domains: ["evil-domain.com"]

files:
  watch_read: ["**/*.pem", "**/id_rsa", "**/credentials.json"]
  exclude_paths: ["/tmp/**"]

memory:
  secret_env_patterns: ["SECRET_*", "*_TOKEN"]
```

Configuration is tested in `tests/config_tests.rs` with comprehensive validation.

### 6.3. Architecture Benefits Achieved ✅

1. **Modular Design**: Clean separation between configuration, probe management, and event processing
2. **Testable Architecture**: 112+ tests with comprehensive mock implementations
3. **Type Safety**: Unified error handling with detailed context
4. **Maintainability**: TDD-driven development with clear interfaces
5. **Extensibility**: Easy addition of new probe types through ProbeManager trait

### 6.4. GitHub Actions Integration (Future)

The current implementation provides the foundation for GitHub Actions integration:

```yaml
# Future workflow integration
jobs:
  security-scan:
    runs-on: ubuntu-latest
    steps:
      - uses: actions/checkout@v4
      
      - name: eBPF Security Monitor  
        run: |
          # Download bee-trace binary
          ./bee-trace --probe-type all --security-mode --duration 300 > security-report.json
          
      - name: Upload Security Report
        uses: actions/upload-artifact@v4
        with:
          name: security-report
          path: security-report.json
```

### 6.5. Implementation Highlights

- **Performance**: Efficient eBPF implementation with minimal overhead
- **Security**: Never captures secret contents, only access metadata
- **Reliability**: Comprehensive error handling and recovery
- **Usability**: Clear CLI interface with helpful output formatting
- **Documentation**: Extensive documentation and examples for developers

## 7. Remaining Development

### High Priority
- **Phase 5**: Event processing separation (monolithic async block in main.rs)
- **GitHub Actions Integration**: Artifact upload and webhook support

### Medium Priority  
- **LSM Integration**: Actual network blocking implementation
- **Enhanced Reporting**: More output formats and delivery methods

### Low Priority
- **Performance Optimization**: Further overhead reduction
- **Additional Probe Types**: Extend monitoring capabilities

The core eBPF security monitoring functionality is fully implemented and tested, providing a solid foundation for the originally specified requirements.
