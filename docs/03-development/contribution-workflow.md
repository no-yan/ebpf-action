# Contribution Workflow Guide

This guide explains how to contribute code to bee-trace, following the established architecture principles and development patterns.

## Development Guidelines

### Architecture Principles

All contributions must adhere to these core principles:

1. **Loose Coupling**: Minimize dependencies between components
2. **High Cohesion**: Each module has a single, clear responsibility
3. **Interface-Based Design**: Use traits for abstraction and testability
4. **Deep Modules**: Hide complexity behind simple interfaces

### TDD Methodology

Follow the Red-Green-Refactor cycle for all new features:

1. **Red**: Write failing tests that define desired behavior
2. **Green**: Write minimal code to make tests pass
3. **Refactor**: Improve code structure while maintaining passing tests

### Component Responsibilities

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

When adding new configuration options, follow this workflow:

1. **Add to types**: Update relevant config struct in `configuration/types.rs`
2. **Update builder**: Add parsing logic in `configuration/builder.rs`
3. **Add validation**: Update validation in `configuration/mod.rs`
4. **Write tests**: Add comprehensive tests in `tests/configuration_tests.rs`

**Example Implementation**:
```rust
// In configuration/types.rs
pub struct MonitoringConfig {
    pub probe_types: Vec<ProbeType>,
    pub new_option: Option<String>,  // New field
}

// In configuration/builder.rs
impl ConfigurationBuilder {
    pub fn with_new_option(mut self, value: String) -> Self {
        self.monitoring.new_option = Some(value);
        self
    }
}

// In tests/configuration_tests.rs
#[test]
fn should_parse_new_option_from_cli() {
    let config = Configuration::builder()
        .from_cli_args(&["--new-option", "test_value"])
        .unwrap()
        .build()
        .unwrap();
    
    assert_eq!(config.monitoring.new_option, Some("test_value".to_string()));
}
```

### 2. New Probe Types

When adding new probe monitoring capabilities:

1. **Create manager**: Implement `ProbeManager` trait for new probe type
2. **Update unified manager**: Add to `UnifiedProbeManager` in `ebpf_manager/mod.rs`
3. **Add error types**: Update `ProbeType` enum in `errors.rs`
4. **Write tests**: Add tests in `tests/probe_manager_tests.rs`

**Example Implementation**:
```rust
// In ebpf_manager/new_probe_manager.rs
pub struct NewProbeManager {
    attached_probes: HashSet<ProbeType>,
}

impl ProbeManager for NewProbeManager {
    fn attach(&mut self, ebpf: &mut Ebpf, probe_type: ProbeType) -> Result<()> {
        match probe_type {
            ProbeType::NewProbeType => {
                let program: &mut TracePoint = ebpf
                    .program_mut("new_tracepoint")
                    .ok_or_else(|| BeeTraceError::MapNotFound {
                        name: "new_tracepoint".to_string(),
                    })?
                    .try_into()?;
                
                program.load()?;
                program.attach("category", "new_tracepoint")?;
                self.attached_probes.insert(probe_type);
                Ok(())
            }
            _ => Err(BeeTraceError::UnsupportedProbeType { probe_type })
        }
    }
}
```

### 3. Event Processing Changes

When modifying event processing:

1. **Update common**: Modify event structures in `bee-trace-common`
2. **Update formatting**: Modify event formatting in `lib.rs`
3. **Update eBPF**: Modify kernel programs in `bee-trace-ebpf`
4. **Write tests**: Add tests in `tests/functional_tests.rs`

**Example Event Structure**:
```rust
// In bee-trace-common/src/lib.rs
#[repr(C)]
pub struct NewEvent {
    pub pid: u32,
    pub uid: u32,
    pub command: [u8; 64],
    pub new_field: u16,
}

impl NewEvent {
    pub fn command_as_str(&self) -> &str {
        // Safe string conversion implementation
    }
}
```

## Testing Guidelines

### Test Categories

1. **Unit Tests**: Individual component behavior
2. **Integration Tests**: Component interaction
3. **Mock Tests**: External dependency isolation
4. **TDD Validation**: Architecture pattern verification

### Mock Implementation Pattern

Always provide mock implementations for external dependencies:

```rust
// Example: Mock for testing without external dependencies
pub struct MockEbpf {
    pub loaded_programs: HashMap<String, bool>,
    pub attached_programs: HashMap<String, bool>,
    pub should_fail: bool,
}

impl MockEbpf {
    pub fn with_failure(mut self) -> Self {
        self.should_fail = true;
        self
    }
    
    pub fn attach_program(&mut self, name: &str) -> Result<(), String> {
        if self.should_fail {
            return Err(format!("Mock failure for {}", name));
        }
        self.attached_programs.insert(name.to_string(), true);
        Ok(())
    }
}
```

### Test Naming Convention

Follow descriptive naming that explains behavior:

- Use descriptive names: `should_attach_file_monitor_probe_based_on_config`
- Follow behavior focus: `should_reject_invalid_probe_type`
- Include context: `should_handle_attachment_failures_gracefully`

### Test Structure

Follow the Arrange-Act-Assert pattern:

```rust
#[test]
fn should_handle_configuration_validation_errors() {
    // Arrange
    let invalid_config = Configuration::builder()
        .from_cli_args(&["--probe-type", "invalid_type"]);
    
    // Act
    let result = invalid_config.and_then(|b| b.build());
    
    // Assert
    assert!(result.is_err());
    match result.unwrap_err() {
        BeeTraceError::InvalidProbeType { probe_type, .. } => {
            assert_eq!(probe_type, "invalid_type");
        }
        _ => panic!("Expected InvalidProbeType error"),
    }
}
```

## Code Quality Standards

### Error Handling

Always provide detailed, actionable error messages:

```rust
// Good: Specific error with context
Err(BeeTraceError::EbpfAttachmentFailed {
    program_name: "sys_enter_openat".to_string(),
    source: anyhow::anyhow!("Tracepoint not found in kernel version 5.4"),
})

// Poor: Generic error without context
Err(BeeTraceError::GeneralError)
```

### Documentation

Document all public APIs:

```rust
/// Manages eBPF probe lifecycle for file monitoring.
/// 
/// This manager handles attachment and detachment of file access monitoring
/// probes, providing a clean interface over complex eBPF operations.
pub struct FileProbeManager {
    attached_probes: HashSet<ProbeType>,
}

impl FileProbeManager {
    /// Attaches a file monitoring probe to the specified tracepoint.
    /// 
    /// # Arguments
    /// * `ebpf` - The eBPF instance to attach to
    /// * `probe_type` - The type of probe to attach
    /// 
    /// # Returns
    /// * `Ok(())` if attachment succeeds
    /// * `Err(BeeTraceError)` if attachment fails
    pub fn attach(&mut self, ebpf: &mut Ebpf, probe_type: ProbeType) -> Result<()> {
        // Implementation
    }
}
```

### Performance Considerations

- Keep eBPF programs simple and efficient
- Offload complex logic to userspace
- Use efficient data structures for high-frequency operations
- Profile with `perf` for performance bottlenecks

```rust
// Good: Efficient field access
impl NetworkEvent {
    #[inline]
    pub fn dest_port(&self) -> u16 {
        self.dest_port
    }
}

// Avoid: Unnecessary allocations in hot paths
impl NetworkEvent {
    // Avoid this in performance-critical code
    pub fn dest_port_string(&self) -> String {
        self.dest_port.to_string()
    }
}
```

## Contribution Process

### 1. Pre-Development
- Review current progress in [Current Progress](../04-project-status/current-progress.md)
- Check [Development Roadmap](../04-project-status/development-roadmap.md) for priorities
- Understand the architecture in [System Architecture](../02-architecture/system-architecture.md)

### 2. Development Workflow
1. Create feature branch: `git checkout -b feature/your-feature-name`
2. Write tests first (TDD approach)
3. Implement minimal code to pass tests
4. Refactor for quality and maintainability
5. Ensure all tests pass: `just test`
6. Format code: `cargo fmt`
7. Check with linter: `cargo clippy`

### 3. Testing Requirements
- All new code must have corresponding tests
- Tests must follow naming conventions
- Mock implementations required for external dependencies
- Integration tests for component interactions

### 4. Documentation Updates
When making changes, update relevant documentation:

- **Architecture changes**: Update architecture documents
- **New patterns**: Document in contribution guidelines
- **API changes**: Update component reference
- **Configuration changes**: Update configuration documentation

## Common Patterns

### Builder Pattern Usage
```rust
// Standard builder pattern for configuration
let config = Configuration::builder()
    .from_cli_args(&args)
    .unwrap()
    .with_additional_config(value)
    .build()
    .unwrap();
```

### Trait Implementation
```rust
// Consistent trait implementation pattern
impl ProbeManager for YourProbeManager {
    fn attach(&mut self, ebpf: &mut Ebpf, probe_type: ProbeType) -> Result<()> {
        // Validate probe type
        // Perform attachment
        // Update state
        // Return result
    }
    
    fn detach(&mut self, probe_type: ProbeType) -> Result<()> {
        // Validate state
        // Perform detachment
        // Update state
        // Return result
    }
}
```

### Error Propagation
```rust
// Consistent error handling
fn complex_operation() -> Result<()> {
    let result = risky_operation()
        .map_err(|e| BeeTraceError::OperationFailed {
            operation: "risky_operation".to_string(),
            source: e.into(),
        })?;
    
    Ok(())
}
```

## Getting Help

If you need assistance:

1. Check existing documentation in the docs/ directory
2. Review similar implementations in the codebase
3. Look at test files for usage examples
4. Check [Current Progress](../04-project-status/current-progress.md) for known issues

## Related Documentation

- [Development Setup](../01-getting-started/development-setup.md) - Environment setup
- [Testing Strategy](testing-strategy.md) - Detailed testing approach
- [Component Reference](../02-architecture/component-reference.md) - Detailed component information
- [Design Principles](../02-architecture/design-principles.md) - TDD methodology and patterns