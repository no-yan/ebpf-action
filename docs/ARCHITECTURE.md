# Architecture Documentation

## Overview

This document describes the architectural design of bee-trace, focusing on the loose coupling and high cohesion principles implemented through Test-Driven Development (TDD).

## Design Philosophy

### Core Principles
1. **A Philosophy of Software Design** - Deep modules that hide complexity
2. **Loose Coupling** - Minimal dependencies between components
3. **High Cohesion** - Single responsibility per module
4. **Test-Driven Development** - t-wada methodology with Red-Green-Refactor cycles

### Architecture Goals
- Replace monolithic 330+ line main.rs with clean separation of concerns
- Create testable interfaces for all major components
- Maintain backward compatibility while improving maintainability
- Enable independent evolution of components

## Current Architecture (Post-Refactoring)

### Component Overview

```
┌─────────────────┐    ┌─────────────────┐    ┌─────────────────┐
│   CLI Args      │───▶│  Configuration  │───▶│ EbpfApplication │
└─────────────────┘    └─────────────────┘    └─────────────────┘
                                                       │
                                                       ▼
┌─────────────────┐    ┌─────────────────┐    ┌─────────────────┐
│ ProbeManager    │◀───│ UnifiedProbe    │◀───│   aya::Ebpf     │
│ (Interface)     │    │ Manager         │    └─────────────────┘
└─────────────────┘    └─────────────────┘
        △                       │
        │                       ▼
┌───────┴───────┬─────────────────┬─────────────────┐
│ FileProbe     │ NetworkProbe    │ MemoryProbe     │
│ Manager       │ Manager         │ Manager         │
└───────────────┴─────────────────┴─────────────────┘
```

### Module Responsibilities

#### 1. Configuration System (`src/configuration/`)
**Purpose**: Unified configuration management
**Cohesion**: High - Single responsibility for all configuration concerns
**Coupling**: Loose - No dependencies on eBPF or probe specifics

**Components**:
- `Configuration` - Immutable configuration state
- `ConfigurationBuilder` - Fluent builder with validation
- Type definitions for different config categories
- CLI argument parsing and conversion

**Key Design Decisions**:
- Builder pattern for complex configuration construction
- Validation separated from construction
- Backward compatibility through legacy conversion methods

#### 2. eBPF Management (`src/ebpf_manager/`)
**Purpose**: Abstract eBPF probe operations
**Cohesion**: High - Each manager handles one probe type
**Coupling**: Loose - Interface-based with dependency injection

**Components**:
- `ProbeManager` trait - Clean interface hiding eBPF complexity
- `UnifiedProbeManager` - Coordinator for multiple probe types
- Individual probe managers (File, Network, Memory)
- `EbpfApplication` - High-level integration layer

**Key Design Decisions**:
- Trait-based abstraction for testability
- State tracking separate from eBPF operations
- Error handling with detailed context

#### 3. Error Handling (`src/errors.rs`)
**Purpose**: Type-safe error propagation
**Cohesion**: High - Single error hierarchy
**Coupling**: Loose - Used throughout but doesn't depend on specifics

**Components**:
- `BeeTraceError` enum with detailed variants
- `ProbeType` enum with conversion utilities
- Integration with `anyhow` for error chaining

## TDD Implementation Methodology

### Phase-by-Phase Development

#### Phase 1: Foundation
- Test environment setup
- Branch isolation
- Initial test structure

#### Phase 2: Interface Design (ProbeManager)
**TDD Cycle**:
1. **Red**: Write tests for ProbeManager trait behavior
2. **Green**: Implement minimal ProbeManager interface
3. **Refactor**: Extract individual probe managers

**Key Tests**:
- Probe attachment/detachment state management
- Error handling for invalid operations
- Program name discovery

#### Phase 3: Configuration Unification
**TDD Cycle**:
1. **Red**: Write tests for Configuration builder pattern
2. **Green**: Implement ConfigurationBuilder with CLI parsing
3. **Refactor**: Extract validation and type definitions

**Key Tests**:
- CLI argument parsing with various combinations
- Validation error handling
- Builder pattern completeness

#### Phase 4: eBPF Integration
**TDD Cycle**:
1. **Red**: Write integration tests for EbpfApplication
2. **Green**: Implement EbpfApplication coordinating Configuration + ProbeManager
3. **Refactor**: Extract production vs test interfaces

**Key Tests**:
- Configuration-driven probe attachment
- Error propagation from ProbeManager
- State consistency validation

### Testing Strategy

#### Test Categories
1. **Unit Tests**: Individual component behavior
2. **Integration Tests**: Component interaction
3. **Mock-based Tests**: External dependency isolation
4. **End-to-end Tests**: CLI to eBPF flow

#### Mock Implementation Pattern
```rust
// Example: MockEbpf for testing without kernel dependencies
pub struct MockEbpf {
    pub loaded_programs: HashMap<String, bool>,
    pub attached_programs: HashMap<String, bool>,
    pub should_fail: bool,
}

impl MockEbpf {
    pub fn attach_program(&mut self, name: &str) -> Result<(), String> {
        if self.should_fail {
            return Err(format!("Mock failure for {}", name));
        }
        self.attached_programs.insert(name.to_string(), true);
        Ok(())
    }
}
```

## Remaining Architecture Debt

### Phase 5: Event Processing (High Priority)
**Current Problem**: 100+ line monolithic async block in main.rs
**Location**: `main.rs` lines 130-235

**Required Extraction**:
```rust
// Current monolithic structure
let event_processor = async move {
    // CPU discovery
    // Perf buffer management  
    // Event parsing
    // Event dispatching
    // Error handling
};

// Target modular structure
struct EventProcessor {
    buffer_manager: PerfBufferManager,
    dispatcher: SecurityEventDispatcher,
    stream_handler: EventStreamHandler,
}
```

**Design Requirements**:
- Separate perf buffer concerns from event processing
- Extract unsafe pointer operations to dedicated module
- Create testable async interfaces
- Maintain performance characteristics

### Metrics

#### Current Status
- **Loose Coupling**: 70% complete
- **High Cohesion**: 60% complete  
- **Test Coverage**: 112 tests passing
- **Lines Reduced**: main.rs simplified while maintaining functionality

#### Success Criteria
- [ ] Event processing extracted (Phase 5)
- [ ] Reporting separated (Phase 6)
- [ ] Main.rs < 100 lines (Phase 7)
- [ ] All existing tests migrated (Phase 8)

## Benefits Achieved

### Maintainability
- Clear module boundaries
- Interface-based testing
- Independent component evolution
- Comprehensive error handling

### Testability  
- Mock-based testing without eBPF dependencies
- Fast feedback cycles
- Comprehensive test coverage
- TDD-driven design

### Flexibility
- Configuration system supports multiple sources
- ProbeManager enables different implementation strategies
- Error handling provides detailed context
- Backward compatibility maintained

## Usage Examples

### Basic Configuration
```rust
let config = Configuration::builder()
    .from_cli_args(&["--probe-type", "all", "--verbose"])
    .unwrap()
    .build()
    .unwrap();
```

### eBPF Application Setup
```rust
let mut app = EbpfApplication::new(config);
app.attach_configured_probes(&mut ebpf)?;

if app.is_ready_for_monitoring() {
    println!("All probes attached successfully");
}
```

### Probe Management
```rust
let mut manager = UnifiedProbeManager::new();
manager.attach(&mut ebpf, ProbeType::FileMonitor)?;
assert!(manager.is_attached(ProbeType::FileMonitor));
```

## Future Considerations

### Phase 5+ Architecture
The completion of event processing separation will achieve:
- Full loose coupling between all major components
- High cohesion with single-responsibility modules
- Complete testability without external dependencies
- Main.rs as pure coordination layer

### Extensibility
The current interface-based design enables:
- Additional probe types without core changes
- Different configuration sources (files, environment, etc.)
- Alternative eBPF implementations
- Custom event processing strategies

This architecture serves as the foundation for a maintainable, testable, and extensible eBPF monitoring system.