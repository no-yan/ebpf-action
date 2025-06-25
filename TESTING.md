# Testing Strategy for bee-trace

This document outlines the comprehensive testing approach for the bee-trace eBPF file reading monitoring project, following t-wada's testing principles.

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
│       └── lib.rs                 # Unit tests for FileReadEvent
├── bee-trace-ebpf/
│   └── tests/
│       └── ebpf_tests.rs          # eBPF structure and safety tests
└── bee-trace/
    ├── src/
    │   └── lib.rs                 # Unit tests for business logic
    └── tests/
        ├── integration_tests.rs    # CLI and end-to-end scenarios
        ├── functional_tests.rs     # Event processing workflows
        └── test_helpers.rs         # Reusable test utilities
```

## Test Categories

### 1. Unit Tests (`bee-trace-common/src/lib.rs`)

**Purpose**: Test the core data structures and their behavior in isolation.

**Test Modules**:
- `file_read_event_creation` - Event construction and initialization
- `file_read_event_builder_pattern` - Fluent API for building events
- `file_read_event_filename_handling` - Filename storage and truncation
- `file_read_event_command_handling` - Command name processing
- `file_read_event_string_conversion` - UTF-8 handling and error cases
- `file_read_event_memory_layout` - Memory safety and size validation

**Key Test Patterns**:
```rust
#[test]
fn should_truncate_long_filename() {
    let long_filename = vec![b'a'; 100]; // Longer than 64 bytes
    let event = FileReadEvent::new().with_filename(&long_filename);
    
    assert_eq!(event.filename_len, 64);
    assert_eq!(event.filename_as_str().len(), 64);
    assert!(event.filename_as_str().chars().all(|c| c == 'a'));
}
```

### 2. Business Logic Tests (`bee-trace/src/lib.rs`)

**Purpose**: Test command-line argument processing, event filtering, and formatting logic.

**Test Modules**:
- `args_validation` - Command-line argument validation
- `event_filtering` - Event filtering by command name
- `event_visibility` - Show/hide logic for different modes
- `event_formatting` - Output formatting in verbose and normal modes
- `string_utilities` - String extraction and conversion utilities

**Key Test Patterns**:
```rust
#[test]
fn should_filter_events_by_command() {
    let args = Args {
        command: Some("cat".to_string()),
        // ... other fields
    };

    let matching_event = FileReadEvent::new().with_command(b"cat");
    assert!(args.should_filter_event(&matching_event));

    let non_matching_event = FileReadEvent::new().with_command(b"vim");
    assert!(!args.should_filter_event(&non_matching_event));
}
```

### 3. Integration Tests (`bee-trace/tests/integration_tests.rs`)

**Purpose**: Test the CLI interface and end-to-end argument processing.

**Test Modules**:
- `cli_argument_parsing` - Command-line argument parsing with clap
- `end_to_end_scenarios` - Complete workflows from args to output
- `complex_filtering_scenarios` - Advanced filtering combinations
- `output_formatting_edge_cases` - Edge cases in output formatting

**Key Test Patterns**:
```rust
#[test]
fn should_parse_all_arguments_together() {
    let args = Args::try_parse_from(&[
        "bee-trace",
        "--probe-type", "sys_enter_read",
        "--duration", "120",
        "--command", "python",
        "--verbose"
    ]).unwrap();
    
    assert_eq!(args.probe_type, "sys_enter_read");
    assert_eq!(args.duration, Some(120));
    assert_eq!(args.command, Some("python".to_string()));
    assert!(args.verbose);
}
```

### 4. Functional Tests (`bee-trace/tests/functional_tests.rs`)

**Purpose**: Test event processing workflows and high-level system behavior.

**Test Modules**:
- `event_stream_processing` - Processing sequences of events
- `performance_characteristics` - Performance and efficiency tests
- `edge_case_handling` - Boundary conditions and error scenarios
- `state_management` - State handling across multiple operations

**Key Test Patterns**:
```rust
#[test]
fn should_handle_high_volume_event_stream() {
    let processor = MockEventProcessor::new();
    
    // Generate 1000 events
    let events = (0..1000).map(|i| {
        let mut event = create_test_event();
        event.pid = i;
        event
    }).collect::<Vec<_>>();

    for event in &events {
        processor.process_event(event, &args, &formatter);
    }

    assert_eq!(processor.get_processed_events().len(), 1000);
}
```

### 5. eBPF Structure Tests (`bee-trace-ebpf/tests/ebpf_tests.rs`)

**Purpose**: Test eBPF-specific requirements like memory layout, stack usage, and kernel compatibility.

**Test Modules**:
- `ebpf_program_structure` - Memory layout and size validation
- `ebpf_data_validation` - Data type ranges and constraints
- `ebpf_memory_safety` - Buffer safety and initialization
- `ebpf_performance_characteristics` - Stack footprint and efficiency
- `ebpf_string_handling` - String processing in kernel context

**Key Test Patterns**:
```rust
#[test]
fn should_have_minimal_stack_footprint() {
    let size = core::mem::size_of::<FileReadEvent>();
    assert!(size <= 128, "Event structure too large for eBPF stack: {} bytes", size);
}
```

## Test Utilities (`bee-trace/tests/test_helpers.rs`)

### Builder Pattern for Test Data
```rust
let event = FileReadEventBuilder::new()
    .pid(1234)
    .command("cat")
    .filename("/etc/passwd")
    .bytes_read(1024)
    .build();
```

### Pre-built Test Scenarios
```rust
use test_helpers::events;

let typical_event = events::typical_cat_reading_passwd();
let system_event = events::system_process_reading_proc();
let unicode_event = events::with_unicode_path();
```

### Performance Testing Framework
```rust
let test = performance::event_formatting_performance();
assert!(test.run().is_ok());
```

### Scenario-Based Testing
```rust
for scenario in scenarios::all_scenarios() {
    // Test each scenario
    assert_eq!(process_events(&scenario), scenario.expected_output_count);
}
```

## Running Tests

### All Tests
```bash
cargo test
```

### Specific Test Categories
```bash
# Unit tests only
cargo test --lib

# Integration tests only  
cargo test --test integration_tests

# Functional tests only
cargo test --test functional_tests

# eBPF structure tests
cargo test -p bee-trace-ebpf

# Common library tests
cargo test -p bee-trace-common
```

### Performance Tests
```bash
cargo test performance --release
```

### Verbose Output
```bash
cargo test -- --nocapture
```

## Test Organization Principles

### 1. Descriptive Test Names
- ✅ `should_truncate_long_filename`
- ✅ `should_filter_events_by_command`
- ✅ `should_handle_unicode_in_paths`
- ❌ `test_filename`
- ❌ `test_filtering`

### 2. Clear Test Structure
```rust
#[test]
fn should_do_something_when_condition() {
    // Arrange - Set up test data
    let input = create_test_input();
    let expected = expected_output();
    
    // Act - Execute the behavior being tested
    let result = function_under_test(input);
    
    // Assert - Verify the outcome
    assert_eq!(result, expected);
}
```

### 3. Test Organization by Behavior
Tests are grouped by the behavior they validate, not by the class or function they test:

```rust
mod event_filtering {
    // All tests related to filtering behavior
}

mod output_formatting {
    // All tests related to formatting behavior
}
```

### 4. Edge Case Coverage
Each module includes tests for:
- Normal/happy path cases
- Boundary conditions (empty, maximum values)
- Error conditions
- Performance requirements

### 5. Test Data Management
- Use builders for complex test objects
- Pre-built scenarios for common cases
- Generators for property-based testing
- Clear separation of test data from test logic

## Continuous Integration

Tests are designed to:
- Run quickly (< 30 seconds total)
- Be deterministic (no flaky tests)
- Provide clear failure messages
- Be independent of each other
- Clean up after themselves

## Testing eBPF Components

Since eBPF programs run in kernel space, we focus on:

1. **Structure validation** - Memory layout, size, alignment
2. **Data safety** - Buffer bounds, initialization
3. **Compilation tests** - Verify code compiles for eBPF target
4. **Interface contracts** - Shared data structures work in both contexts

We do not attempt to run actual eBPF programs in tests, as this requires:
- Kernel modules
- Root privileges  
- Specific kernel versions
- Complex test infrastructure

Instead, we validate the components that can be tested in userspace and rely on integration testing with real kernel environments for full validation.

## Best Practices

1. **Write tests first** - When adding new features, write tests that describe the expected behavior
2. **Keep tests simple** - Each test should verify one specific behavior
3. **Use meaningful assertions** - Assert on the actual behavior, not implementation details
4. **Maintain test data** - Keep test helper functions and data up to date
5. **Review test failures** - When tests fail, understand why before fixing
6. **Refactor tests** - Keep test code clean and maintainable
7. **Document complex scenarios** - Add comments for non-obvious test cases

## Test Coverage Goals

- **Unit tests**: >95% line coverage for business logic
- **Integration tests**: All CLI argument combinations
- **Functional tests**: All user-facing workflows
- **Edge cases**: All boundary conditions and error paths
- **Performance**: All critical paths meet performance requirements

This comprehensive testing approach ensures that the bee-trace file monitoring feature is reliable, performant, and maintainable.