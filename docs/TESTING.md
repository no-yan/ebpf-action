# Testing Strategy for bee-trace

This document outlines the comprehensive testing approach for the bee-trace eBPF security monitoring project, following t-wada's testing principles. The project includes 120+ tests covering all aspects of the security monitoring functionality.

## Testing Philosophy

Our testing strategy follows these core principles from t-wada:

1. **Test behavior, not implementation** - Tests focus on what the code does, not how it does it
2. **Clear test naming** - Test names describe the expected behavior in plain English
3. **Arrange-Act-Assert structure** - Each test has clear setup, execution, and verification phases
4. **Single responsibility** - Each test validates one specific behavior
5. **Fast feedback** - Tests run quickly and provide immediate feedback
6. **Maintainable tests** - Tests are easy to read, understand, and modify

## Test Structure Overview

```
bee-trace/
├── bee-trace-common/
│   └── src/
│       └── lib.rs                 # Unit tests for all event structures
│                                  # NetworkEvent, SecretAccessEvent, ProcessMemoryEvent
├── bee-trace-ebpf/
│   └── tests/
│       └── ebpf_tests.rs          # eBPF structure and safety tests
└── bee-trace/
    ├── src/
    │   ├── lib.rs                 # Unit tests for business logic
    │   └── config.rs              # Configuration system tests
    └── tests/
        ├── integration_tests.rs    # CLI and end-to-end scenarios
        ├── functional_tests.rs     # Event processing workflows
        ├── config_tests.rs         # Security configuration tests
        └── test_helpers.rs         # Reusable test utilities
```

## Test Statistics

| Component | Test Count | Coverage Focus |
|-----------|------------|----------------|
| bee-trace-common | 35 tests | Event structures, memory layout |
| bee-trace (lib) | 28 tests | Business logic, formatting |
| bee-trace (integration) | 28 tests | CLI argument parsing |
| bee-trace (functional) | 14 tests | Event processing workflows |
| bee-trace (config) | 11 tests | Security configuration |
| bee-trace-ebpf | 4 tests | eBPF structure validation |
| **Total** | **120 tests** | **Comprehensive coverage** |

## Test Categories

### 1. Unit Tests (`bee-trace-common/src/lib.rs`)

**Purpose**: Test all security event data structures and their behavior in isolation.

**Test Modules**:
- `network_event_*` - NetworkEvent creation, IP handling, protocol validation
- `secret_access_event_*` - SecretAccessEvent paths, environment variables
- `process_memory_event_*` - ProcessMemoryEvent syscall types, target processes
- `event_memory_layout` - Memory safety and size validation for eBPF compatibility

**Key Test Examples**:
```rust
#[test]
fn should_truncate_long_filename() {
    let long_filename = vec![b'a'; 100]; // Longer than 64 bytes
    let event = FileReadEvent::new().with_filename(&long_filename);

    assert_eq!(event.filename_len, 64);
    assert_eq!(event.filename_as_str().len(), 64);
    assert!(event.filename_as_str().chars().all(|c| c == 'a'));
}

#[test]
fn should_create_network_event_with_tcp_protocol() {
    let event = NetworkEvent::new()
        .with_pid(1234)
        .with_command(b"curl")
        .with_protocol_tcp()
        .with_dest_port(443);

    assert_eq!(event.pid, 1234);
    assert_eq!(event.protocol, 0); // TCP
    assert_eq!(event.dest_port, 443);
    assert_eq!(event.command_as_str(), "curl");
}

#[test]
fn should_handle_secret_access_event_path_truncation() {
    let long_path = "a".repeat(200);
    let event = SecretAccessEvent::new()
        .with_file_path(long_path.as_bytes());

    assert_eq!(event.path_len, 128); // Max buffer size
    assert_eq!(event.path_or_var_as_str().len(), 128);
}
```

### 2. Business Logic Tests (`bee-trace/src/lib.rs`)

**Purpose**: Test command-line argument processing, security event filtering, and multi-format output.

**Test Modules**:
- `args_validation` - Enhanced CLI argument validation (security mode, probe types)
- `event_filtering` - Security event filtering by command and type
- `event_visibility` - Show/hide logic for security vs legacy modes
- `event_formatting` - Multi-format output (legacy FileRead + new SecurityEvent)
- `string_utilities` - String extraction and conversion utilities

**Key Security Event Features Tested**:
```rust
#[test]
fn should_format_security_event_in_verbose_mode() {
    let network_event = NetworkEvent::new()
        .with_pid(1234)
        .with_uid(1000)
        .with_command(b"curl")
        .with_dest_port(443);

    let security_event = SecurityEvent::Network(network_event);
    let formatter = EventFormatter::new(true);
    let output = formatter.format_security_event(&security_event);

    assert!(output.contains("1234"));      // PID
    assert!(output.contains("1000"));      // UID
    assert!(output.contains("curl"));      // Command
    assert!(output.contains("NETWORK"));   // Event type
    assert!(output.contains("443"));       // Port details
}

#[test]
fn should_validate_enhanced_probe_types() {
    let security_args = Args {
        probe_type: "all".to_string(),
        security_mode: true,
        // ... other fields
    };
    assert!(security_args.validate().is_ok());

    let network_args = Args {
        probe_type: "network_monitor".to_string(),
        security_mode: true,
        // ... other fields
    };
    assert!(network_args.validate().is_ok());
}
```

### 3. Security Configuration Tests (`bee-trace/tests/config_tests.rs`)

**Purpose**: Test the YAML-based security configuration system.

**Test Modules**:
- `yaml_parsing` - YAML configuration file parsing and validation
- `network_config_validation` - Network blocking and monitoring rules
- `file_config_validation` - File pattern matching and path exclusions
- `memory_config_validation` - Environment variable patterns and memory access rules
- `config_error_handling` - Invalid configuration handling and fallbacks

**Key Test Examples**:
```rust
#[test]
fn should_parse_complete_security_config() {
    let yaml = r#"
network:
  blocked_ips: ["1.2.3.4", "5.6.7.8"]
  blocked_domains: ["malicious.com"]
files:
  watch_read: ["**/*.pem", "**/id_rsa"]
  exclude_paths: ["/tmp/**"]
memory:
  secret_env_patterns: ["SECRET_*", "*_TOKEN"]
"#;

    let config: SecurityConfig = serde_yaml::from_str(yaml).unwrap();
    assert_eq!(config.network.blocked_ips.len(), 2);
    assert_eq!(config.files.watch_read.len(), 2);
    assert_eq!(config.memory.secret_env_patterns.len(), 2);
}

#[test]
fn should_handle_partial_config_with_defaults() {
    let yaml = r#"
network:
  blocked_ips: ["1.2.3.4"]
"#;

    let config: SecurityConfig = serde_yaml::from_str(yaml).unwrap();
    assert_eq!(config.network.blocked_ips.len(), 1);
    assert!(config.files.watch_read.is_empty()); // Default
    assert!(config.memory.secret_env_patterns.is_empty()); // Default
}
```

### 4. Integration Tests (`bee-trace/tests/integration_tests.rs`)

**Purpose**: Test the enhanced CLI interface with security monitoring options.

**Test Modules**:
- `cli_argument_parsing` - Enhanced command-line parsing (security mode, probe types)
- `security_mode_scenarios` - Security monitoring end-to-end workflows
- `probe_type_validation` - Validation of new probe types (file_monitor, network_monitor, etc.)
- `config_file_integration` - Configuration file loading and application

**Key Test Examples**:
```rust
#[test]
fn should_parse_security_monitoring_arguments() {
    let args = Args::try_parse_from(&[
        "bee-trace",
        "--probe-type", "all",
        "--security-mode",
        "--config", ".github/security.yml",
        "--duration", "300",
        "--verbose"
    ]).unwrap();

    assert_eq!(args.probe_type, "all");
    assert!(args.security_mode);
    assert_eq!(args.config, Some(".github/security.yml".to_string()));
    assert_eq!(args.duration, Some(300));
    assert!(args.verbose);
}

#[test]
fn should_validate_new_probe_types() {
    let probe_types = ["file_monitor", "network_monitor", "memory_monitor", "all"];

    for probe_type in &probe_types {
        let args = Args {
            probe_type: probe_type.to_string(),
            security_mode: true,
            // ... other fields
        };
        assert!(args.validate().is_ok(), "Probe type {} should be valid", probe_type);
    }
}
```

### 5. Functional Tests (`bee-trace/tests/functional_tests.rs`)

**Purpose**: Test event processing workflows and high-level security monitoring behavior.

**Test Modules**:
- `event_stream_processing` - Processing sequences of mixed security events
- `multi_event_type_handling` - Concurrent processing of different event types
- `performance_characteristics` - Performance with high-volume security event streams
- `edge_case_handling` - Boundary conditions and error scenarios
- `security_event_workflows` - End-to-end security monitoring workflows

**Key Test Examples**:
```rust
#[test]
fn should_handle_mixed_security_event_stream() {
    let processor = MockEventProcessor::new();

    // Generate mixed security events
    let file_events = (0..100).map(|i| create_file_access_event(i));
    let network_events = (0..50).map(|i| create_network_event(i));
    let memory_events = (0..25).map(|i| create_memory_access_event(i));

    // Process all event types
    for event in file_events.chain(network_events).chain(memory_events) {
        processor.process_mixed_event(event, &args, &formatter);
    }

    assert_eq!(processor.get_total_events(), 175);
    assert!(processor.get_event_types().contains(&"FILE_READ"));
    assert!(processor.get_event_types().contains(&"NETWORK"));
    assert!(processor.get_event_types().contains(&"PROC_MEMORY"));
}

#[test]
fn should_filter_security_events_by_severity() {
    let processor = MockEventProcessor::new();
    let high_severity_event = create_secret_access_event("id_rsa");

    processor.process_security_event(&high_severity_event, &args, &formatter);
    processor.process_security_event(&low_severity_event, &args, &formatter);

    let high_severity_count = processor.get_events_by_severity("high").len();
    let low_severity_count = processor.get_events_by_severity("low").len();

    assert_eq!(high_severity_count, 1);
    assert_eq!(low_severity_count, 1);
}
```

### 6. eBPF Structure Tests (`bee-trace-ebpf/tests/ebpf_tests.rs`)

**Purpose**: Test eBPF-specific requirements for all security event types.

**Test Modules**:
- `ebpf_event_structure_validation` - Memory layout validation for all event types
- `ebpf_size_constraints` - Stack footprint limits for kernel compatibility
- `ebpf_memory_safety` - Buffer safety and initialization across event types
- `ebpf_cross_platform_compatibility` - Size and alignment validation

**Key Test Examples**:
```rust
#[test]
fn should_validate_all_security_event_sizes() {
    assert!(core::mem::size_of::<FileReadEvent>() <= 128);
    assert!(core::mem::size_of::<NetworkEvent>() <= 128);
    assert!(core::mem::size_of::<SecretAccessEvent>() <= 256);
    assert!(core::mem::size_of::<ProcessMemoryEvent>() <= 128);
}

#[test]
fn should_ensure_proper_alignment_for_ebpf() {
    assert_eq!(core::mem::align_of::<NetworkEvent>(), 4);
    assert_eq!(core::mem::align_of::<SecretAccessEvent>(), 4);
    assert_eq!(core::mem::align_of::<ProcessMemoryEvent>(), 4);
}

#[test]
fn should_validate_c_repr_compatibility() {
    // Ensure #[repr(C)] structures are properly laid out
    let network_event = NetworkEvent::new();
    let ptr = &network_event as *const _ as *const u8;

    // Test that first field (pid) is at offset 0
    let pid_offset = &network_event.pid as *const _ as *const u8;
    assert_eq!(ptr, pid_offset);
}
```

## Test Utilities (`bee-trace/tests/test_helpers.rs`)

### Enhanced Builder Patterns for Security Events
```rust
// File access events
let file_event = FileReadEventBuilder::new()
    .pid(1234)
    .command("cat")
    .filename("/etc/passwd")
    .build();

// Network events
let network_event = NetworkEventBuilder::new()
    .pid(5678)
    .command("curl")
    .dest_ip_v4([1, 2, 3, 4])
    .dest_port(443)
    .protocol_tcp()
    .build();

// Secret access events
let secret_event = SecretAccessEventBuilder::new()
    .pid(9012)
    .command("node")
    .file_access("/home/user/.ssh/id_rsa")
    .build();

// Memory access events
let memory_event = ProcessMemoryEventBuilder::new()
    .pid(3456)
    .command("strace")
    .target_pid(1234)
    .ptrace_syscall()
    .build();
```

### Pre-built Security Test Scenarios
```rust
use test_helpers::security_events;

// High-severity security events
let credential_theft = security_events::ssh_key_access();
let data_exfiltration = security_events::suspicious_network_connection();
let process_injection = security_events::ptrace_attack();

// Normal activity events
let legitimate_file_read = security_events::normal_config_access();
let system_network_call = security_events::dns_lookup();

// Edge case events
let unicode_path_event = security_events::with_unicode_filename();
let max_length_event = security_events::with_maximum_path_length();
let zero_values_event = security_events::with_all_zeros();
```

### Performance Test Utilities
```rust
use test_helpers::performance;

#[test]
fn should_meet_performance_benchmarks() {
    let tests = vec![
        performance::security_event_creation_performance(),
        performance::multi_event_formatting_performance(),
        performance::config_parsing_performance(),
        performance::report_generation_performance(),
    ];

    for test in tests {
        assert!(test.run().is_ok(), "Performance test '{}' failed", test.name);
    }
}
```

### Mock Event Processors
```rust
let processor = MockSecurityEventProcessor::new()
    .with_severity_classification(true)
    .with_event_filtering(true)
    .with_rate_limiting(1000); // events per second

// Process mixed event types
processor.process_security_event(&file_event, &args, &formatter);
processor.process_security_event(&network_event, &args, &formatter);

// Verify processing results
assert_eq!(processor.get_high_severity_count(), 1);
assert_eq!(processor.get_unique_event_types().len(), 2);
```

## Running Tests

### Complete Test Suite
```bash
# Run all 120+ tests
cargo test

# Run tests by component
cargo test -p bee-trace-common    # Event structure tests (35 tests)
cargo test --lib -p bee-trace     # Business logic tests (28 tests)
cargo test --test integration_tests  # CLI integration tests (28 tests)
cargo test --test functional_tests   # Event processing tests (14 tests)
cargo test --test config_tests       # Security config tests (11 tests)
cargo test -p bee-trace-ebpf      # eBPF validation tests (4 tests)

# Run security-specific tests
just test-security

# Run performance tests
cargo test performance --release
```

### Test Categories by Purpose
```bash
# Unit tests (data structures and business logic)
cargo test -p bee-trace-common && cargo test --lib -p bee-trace

# Integration tests (CLI and workflows)
cargo test --test integration_tests --test functional_tests

# System tests (eBPF and configuration)
cargo test -p bee-trace-ebpf --test config_tests

# Performance and stress tests
cargo test performance --release
```

### Continuous Integration
```bash
# Full CI pipeline
just fmt && just lint && just test-security && just test-ebpf
```

## Test Data Management

### Event Test Data Generators
```rust
// Generate realistic test events
let file_generator = FileEventGenerator::new()
    .with_commands(&["cat", "vim", "less", "grep"])
    .with_paths(&["/etc/passwd", "/var/log/auth.log", "/home/user/.ssh/config"])
    .with_pid_range(1000..9999);

let batch = file_generator.generate_batch(100);
assert_eq!(batch.len(), 100);

// Generate security-focused test data
let security_generator = SecurityEventGenerator::new()
    .with_sensitive_files(&["id_rsa", "credentials.json", ".env"])
    .with_suspicious_ips(&["1.2.3.4", "evil-domain.com"])
    .with_memory_access_patterns(&["ptrace", "process_vm_readv"]);

let security_events = security_generator.generate_mixed_events(50);
```

### Test Scenario Templates
```rust
// Scenario-based testing for common security patterns
let scenarios = vec![
    scenarios::credential_theft_attempt(),
    scenarios::data_exfiltration_via_network(),
    scenarios::process_injection_attack(),
    scenarios::environment_variable_enumeration(),
    scenarios::legitimate_development_workflow(),
];

for scenario in scenarios {
    let result = run_security_scenario(scenario);
    assert!(result.validate_expected_behavior());
}
```

## Testing Best Practices

### Test Naming Conventions
- Use descriptive names that explain the expected behavior
- Start with `should_` for positive cases, `should_not_` for negative cases
- Include context about the scenario being tested

### Example Test Names
```rust
// Good test names
should_detect_ssh_private_key_access()
should_block_connection_to_blacklisted_ip()
should_format_network_event_with_ipv6_address()
should_handle_unicode_filename_in_security_event()
should_not_capture_secret_content_in_environment_monitoring()

// Poor test names (avoid these)
test_file_access()
network_test()
test_event()
```

### Assertion Patterns
```rust
// Specific assertions with clear failure messages
assert_eq!(event.pid, expected_pid, "PID should match the process that accessed the file");
assert!(event.filename_as_str().contains("credentials"),
    "Event should capture access to credential files");

// Test behavior, not implementation
assert!(processor.detected_high_severity_event(),
    "Processor should classify SSH key access as high severity");

// Multiple related assertions grouped logically
assert_eq!(report.summary.file_events, 5);
assert_eq!(report.summary.network_events, 3);
assert_eq!(report.summary.high_severity_events, 2);
assert!(report.events.iter().any(|e| e.severity == "high"));
```

### Error Testing
```rust
#[test]
fn should_handle_invalid_security_config_gracefully() {
    let invalid_yaml = "invalid: [unclosed array";

    let result = SecurityConfig::from_yaml(invalid_yaml);

    assert!(result.is_err());
    assert!(result.unwrap_err().to_string().contains("YAML parse error"));
}

#[test]
fn should_provide_defaults_for_missing_config_sections() {
    let minimal_config = SecurityConfig::from_yaml("network: {}").unwrap();

    // Should not panic and should provide sensible defaults
    assert!(minimal_config.files.watch_read.is_empty());
    assert!(minimal_config.memory.secret_env_patterns.is_empty());
    assert!(!minimal_config.network.alert_on_any_connection);
}
```

This comprehensive testing strategy ensures the reliability and security of the bee-trace eBPF security monitoring system while maintaining high code quality and following t-wada's proven testing principles.

