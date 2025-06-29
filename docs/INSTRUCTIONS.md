# Development Instructions for bee-trace

This document provides guidance for developers working on the `bee-trace` project after the major TDD refactoring to achieve loose coupling and high cohesion architecture.

## Project Overview

`bee-trace` is an eBPF-based security monitoring tool built with a modular architecture following "A Philosophy of Software Design" principles. The system uses trait-based interfaces and comprehensive configuration management for maintainability and testability.

## Architecture (Post-Refactoring)

The project is a Rust workspace with the following crates and new modular structure:

### Core Crates
-   **`bee-trace`**: Main userspace application with modular architecture
-   **`bee-trace-ebpf`**: eBPF programs that run in kernel space
-   **`bee-trace-common`**: Shared data structures between userspace and eBPF code

### New Modular Structure (`bee-trace/src/`)
-   **`configuration/`**: Unified configuration system with builder pattern
    -   `mod.rs` - Main Configuration struct and validation
    -   `builder.rs` - ConfigurationBuilder with fluent API
    -   `types.rs` - Type definitions for different config categories
    -   `validation.rs` - Validation logic and error handling
-   **`ebpf_manager/`**: ProbeManager trait and implementations
    -   `mod.rs` - UnifiedProbeManager coordinator
    -   `probe_manager.rs` - Core ProbeManager trait
    -   `file_probe_manager.rs` - File monitoring probe management
    -   `network_probe_manager.rs` - Network monitoring probe management  
    -   `memory_probe_manager.rs` - Memory monitoring probe management
    -   `application.rs` - EbpfApplication integration layer
-   **`errors.rs`**: Unified error handling with BeeTraceError enum
-   **`lib.rs`**: Business logic, event formatting, and utilities

### Test Structure (`bee-trace/tests/`)
-   **`configuration_tests.rs`**: New configuration system tests
-   **`ebpf_integration_tests.rs`**: eBPF management integration tests
-   **`probe_manager_tests.rs`**: ProbeManager trait tests
-   **`tdd_methodology_validation.rs`**: TDD pattern validation tests
-   **`integration_tests.rs`**: CLI and end-to-end scenarios
-   **`functional_tests.rs`**: Event processing workflows
-   **`config_tests.rs`**: Legacy security configuration tests
-   **`test_helpers.rs`**: Reusable test utilities

## Development Workflow

### Prerequisites
1. **Rust Toolchain**: Stable and nightly with rust-src component
   ```bash
   rustup toolchain install nightly --component rust-src
   ```
2. **eBPF Tooling**: bpf-linker for eBPF compilation
   ```bash
   cargo install bpf-linker
   # On macOS: cargo install bpf-linker --no-default-features
   ```
3. **Development Tools**: just for task automation
   ```bash
   cargo install just
   ```

### Building and Running
```bash
# Build the project
cargo build

# Run with proper eBPF privileges (required)
just run-all-monitors --duration 10

# Run specific probe types
just run-file-monitor --duration 10
just run-network-monitor --duration 10
just run-memory-monitor --duration 10

# Development build
cargo build --release
```

### Testing Workflow
```bash
# Run all tests (recommended)
just test

# Run specific test categories
cargo test configuration    # Configuration system tests
cargo test ebpf_manager     # eBPF management tests
cargo test probe_manager    # ProbeManager trait tests

# Run TDD validation tests
cargo test --test tdd_methodology_validation

# Run integration tests
cargo test --test ebpf_integration_tests
```

### Code Quality
```bash
# Format code
cargo fmt

# Check for issues
cargo check

# Run linter
cargo clippy
```

## Development Guidelines

### Architecture Principles
1. **Loose Coupling**: Minimize dependencies between components
2. **High Cohesion**: Each module has a single, clear responsibility
3. **Interface-Based Design**: Use traits for abstraction and testability
4. **Deep Modules**: Hide complexity behind simple interfaces

### TDD Methodology
Follow the Red-Green-Refactor cycle:
1. **Red**: Write failing tests that define desired behavior
2. **Green**: Write minimal code to make tests pass
3. **Refactor**: Improve code structure while maintaining passing tests

### Module Responsibilities

#### Configuration System
- **Purpose**: Unified configuration from multiple sources
- **Key Pattern**: Builder pattern with validation
- **Testing**: Mock different configuration sources

```rust
// Example: Adding new configuration option
let config = Configuration::builder()
    .from_cli_args(&["--new-option", "value"])
    .unwrap()
    .build()
    .unwrap();
```

#### eBPF Management
- **Purpose**: Abstract eBPF probe operations
- **Key Pattern**: Trait-based management with state tracking
- **Testing**: Mock eBPF without kernel dependencies

```rust
// Example: Implementing new probe type
impl ProbeManager for NewProbeManager {
    fn attach(&mut self, ebpf: &mut Ebpf, probe_type: ProbeType) -> Result<()> {
        // Implementation specific to new probe type
    }
    // ... other trait methods
}
```

#### Error Handling
- **Purpose**: Type-safe error propagation with context
- **Key Pattern**: Structured errors with detailed information
- **Testing**: Comprehensive error scenario coverage

```rust
// Example: Creating contextual errors
return Err(BeeTraceError::EbpfAttachmentFailed {
    program_name: "sys_enter_openat".to_string(),
    source: anyhow::anyhow!("Tracepoint not found"),
});
```

## Adding New Features

### 1. Configuration Changes
When adding new configuration options:

1. **Add to types**: Update relevant config struct in `configuration/types.rs`
2. **Update builder**: Add parsing logic in `configuration/builder.rs`
3. **Add validation**: Update validation in `configuration/mod.rs`
4. **Write tests**: Add comprehensive tests in `tests/configuration_tests.rs`

### 2. New Probe Types
When adding new probe monitoring:

1. **Create manager**: Implement `ProbeManager` trait for new probe type
2. **Update unified manager**: Add to `UnifiedProbeManager` in `ebpf_manager/mod.rs`
3. **Add error types**: Update `ProbeType` enum in `errors.rs`
4. **Write tests**: Add tests in `tests/probe_manager_tests.rs`

### 3. Event Processing Changes
When modifying event processing:

1. **Update common**: Modify event structures in `bee-trace-common`
2. **Update formatting**: Modify event formatting in `lib.rs`
3. **Update eBPF**: Modify kernel programs in `bee-trace-ebpf`
4. **Write tests**: Add tests in `tests/functional_tests.rs`

## Testing Guidelines

### Test Categories
1. **Unit Tests**: Individual component behavior
2. **Integration Tests**: Component interaction
3. **Mock Tests**: External dependency isolation
4. **TDD Validation**: Architecture pattern verification

### Mock Implementation Pattern
```rust
// Example: Mock for testing without external dependencies
pub struct MockEbpf {
    pub loaded_programs: HashMap<String, bool>,
    pub should_fail: bool,
}

impl MockEbpf {
    pub fn with_failure(mut self) -> Self {
        self.should_fail = true;
        self
    }
}
```

### Test Naming Convention
- Use descriptive names: `should_attach_file_monitor_probe_based_on_config`
- Follow behavior focus: `should_reject_invalid_probe_type`
- Include context: `should_handle_attachment_failures_gracefully`

## Remaining Architecture Work

### Phase 5: Event Processing Separation (High Priority)
The main.rs still contains a monolithic event processing block (lines 130-235) that needs extraction:

**Required Components**:
- `EventProcessor` trait for perf buffer management
- `SecurityEventDispatcher` for event routing
- `PerfBufferManager` for CPU/buffer coordination
- `EventStreamHandler` for async event streaming

**Files to Create**:
- `src/event_processing/mod.rs`
- `src/event_processing/event_processor.rs`
- `src/event_processing/perf_buffer_manager.rs`
- `src/event_processing/security_event_dispatcher.rs`

### Future Phases
- **Phase 6**: Reporting responsibility separation
- **Phase 7**: Main application simplification (target: <100 lines)
- **Phase 8**: Existing test migration and validation

## Documentation

### Key Documents
- **`docs/ARCHITECTURE.md`**: Complete architecture overview
- **`docs/TDD_METHODOLOGY.md`**: TDD methodology and lessons learned
- **`examples/tdd_refactoring_patterns.rs`**: Reusable patterns and examples
- **`todo.md`**: Current progress and remaining work

### When to Update Documentation
- **Architecture changes**: Update `ARCHITECTURE.md`
- **New patterns**: Add to `examples/tdd_refactoring_patterns.rs`
- **Process changes**: Update this file (`instructions.md`)
- **Progress updates**: Update `todo.md`

## Debugging and Troubleshooting

### Common Issues
1. **eBPF Permission Errors**: Always run with `sudo -E` or use `just` commands
2. **Tracepoint Not Found**: Check kernel version compatibility
3. **Test Failures**: Run `just test` to use proper test environment
4. **Build Errors**: Ensure nightly Rust with rust-src component

### Debug Commands
```bash
# Check eBPF program loading
sudo bpftool prog list

# Monitor system tracepoints
ls /sys/kernel/debug/tracing/events/syscalls/

# Check available tracepoints
cat /sys/kernel/debug/tracing/available_events | grep openat
```

### Performance Optimization
- Keep eBPF programs simple
- Offload complex logic to userspace
- Use efficient data structures for high-frequency operations
- Profile with `perf` for performance bottlenecks

This refactored architecture provides a solid foundation for maintainable, testable, and extensible eBPF security monitoring while following proven software design principles.