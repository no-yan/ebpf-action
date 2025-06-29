# bee-trace Component Reference

This document provides detailed information about individual components, their responsibilities, and implementation details.

## Core Components

### 1. Configuration System (`src/configuration/`)

**Purpose**: Unified configuration management  
**Design**: Builder pattern with comprehensive validation  
**Status**: ✅ Production-ready

**Components**:
- `Configuration` - Immutable configuration state
- `ConfigurationBuilder` - Fluent builder with validation
- Type definitions for different config categories
- CLI argument parsing and conversion

**Key Features**:
- Builder pattern for complex configuration construction
- Validation separated from construction
- Backward compatibility through legacy conversion methods
- Support for multiple input sources (CLI, files, environment)

**Usage Example**:
```rust
let config = Configuration::builder()
    .from_cli_args(&["--probe-type", "all", "--verbose"])
    .unwrap()
    .build()
    .unwrap();
```

### 2. eBPF Management (`src/ebpf_manager/`)

**Purpose**: Abstract eBPF probe operations  
**Design**: Trait-based abstraction with dependency injection  
**Status**: ✅ Production-ready

**Components**:
- `ProbeManager` trait - Clean interface hiding eBPF complexity
- `UnifiedProbeManager` - Coordinator for multiple probe types
- Individual probe managers (File, Network, Memory)
- `EbpfApplication` - High-level integration layer

**Key Features**:
- Trait-based abstraction for testability
- State tracking separate from eBPF operations
- Error handling with detailed context
- Mock implementations for testing

**ProbeManager Trait**:
```rust
pub trait ProbeManager {
    fn attach(&mut self, ebpf: &mut Ebpf, probe_type: ProbeType) -> Result<()>;
    fn detach(&mut self, probe_type: ProbeType) -> Result<()>;
    fn is_attached(&self, probe_type: ProbeType) -> bool;
    fn program_names(&self, probe_type: ProbeType) -> Vec<String>;
}
```

### 3. Error Handling (`src/errors.rs`)

**Purpose**: Type-safe error propagation  
**Design**: Comprehensive error enum with context  
**Status**: ✅ Production-ready

**Components**:
- `BeeTraceError` enum with detailed variants
- `ProbeType` enum with conversion utilities
- Integration with `anyhow` for error chaining

**Error Types**:
```rust
pub enum BeeTraceError {
    EbpfAttachmentFailed { program_name: String, source: anyhow::Error },
    ProbeAlreadyAttached { probe_type: ProbeType },
    ConfigError { message: String },
    InvalidProbeType { probe_type: String, valid_types: Vec<String> },
    // ... other variants
}
```

## Security Monitoring Components

### File Access Monitoring

**Implementation**: `FileProbeManager` in `src/ebpf_manager/file_probe_manager.rs`

**Features**:
- Monitors access to sensitive files (SSH keys, credentials)
- Configurable file patterns and exclusions
- Real-time detection with process context
- Tracepoint attachment to `sys_enter_openat`

**Event Structure**:
```rust
pub struct SecretAccessEvent {
    pub pid: u32,
    pub uid: u32,
    pub command: [u8; 64],
    pub path_len: u16,
    pub path_or_var: [u8; 128],
    pub access_type: u8,  // 0 = file, 1 = env_var
}
```

### Network Connection Tracking

**Implementation**: `NetworkProbeManager` in `src/ebpf_manager/network_probe_manager.rs`

**Features**:
- TCP/UDP connection monitoring
- IP address and domain blocking capabilities
- Protocol-specific event classification
- kprobe attachments to `tcp_connect` and `udp_sendmsg`

**Event Structure**:
```rust
pub struct NetworkEvent {
    pub pid: u32,
    pub uid: u32,
    pub command: [u8; 64],
    pub dest_ip: [u8; 16],
    pub dest_port: u16,
    pub protocol: u8,  // 0 = TCP, 1 = UDP
}
```

### Memory Access Detection

**Implementation**: `MemoryProbeManager` in `src/ebpf_manager/memory_probe_manager.rs`

**Features**:
- Process memory access monitoring (ptrace, process_vm_readv)
- Environment variable access tracking
- Inter-process communication detection
- Tracepoint attachments to `sys_enter_ptrace` and `sys_enter_process_vm_readv`

**Event Structure**:
```rust
pub struct ProcessMemoryEvent {
    pub pid: u32,
    pub uid: u32,
    pub command: [u8; 64],
    pub target_pid: u32,
    pub target_comm: [u8; 64],
    pub syscall_type: u8,  // 0 = ptrace, 1 = process_vm_readv
}
```

## Event Processing Components

### Event Collection

**Implementation**: Perf event arrays in main.rs (pending Phase 5 extraction)

**Current Structure**:
```rust
// Per-CPU perf buffer management
let cpus = online_cpus()?;
for cpu_id in &cpus {
    let mut perf_buffer = PerfEventArray::try_from(ebpf.map_mut("EVENTS")?)?
        .open(cpu_id, None)?;
    
    // Event processing loop
    tokio::spawn(async move {
        // Process events from this CPU
    });
}
```

**Target Architecture (Phase 5)**:
- `EventProcessor` trait for perf buffer management
- `SecurityEventDispatcher` for event routing
- `PerfBufferManager` for CPU/buffer coordination
- `EventStreamHandler` for async event streaming

### Event Formatting

**Implementation**: `EventFormatter` in `src/lib.rs`

**Features**:
- Multi-format output (JSON, Markdown, PlainText)
- Security event classification and severity assessment
- Configurable verbosity levels
- Process context enrichment

**Usage Example**:
```rust
let formatter = EventFormatter::new(verbose);
let output = formatter.format_security_event(&security_event);
println!("{}", output);
```

## Testing Components

### Mock Implementations

**MockEbpf**: Simulates eBPF operations without kernel dependencies
```rust
pub struct MockEbpf {
    pub loaded_programs: HashMap<String, bool>,
    pub attached_programs: HashMap<String, bool>,
    pub should_fail: bool,
}
```

**MockProbeManager**: Test implementation of ProbeManager trait
```rust
pub struct MockProbeManager {
    attached_probes: HashSet<ProbeType>,
}
```

### Test Categories

1. **Unit Tests**: Component behavior validation
   - Configuration builder pattern
   - Error handling scenarios
   - Event formatting logic

2. **Integration Tests**: Component interaction testing
   - Configuration + ProbeManager integration
   - eBPF application coordination
   - End-to-end CLI workflows

3. **Mock-based Tests**: External dependency isolation
   - eBPF operations without kernel privileges
   - File system operations without actual files
   - Network operations without real connections

4. **Performance Tests**: Benchmarking and optimization
   - Event processing throughput
   - Memory usage under load
   - CPU overhead measurements

## Future Components (Phase 5+)

### Event Processing Enhancement

**Target Components**:
- `EventProcessor` trait for unified event handling
- `SecurityEventDispatcher` for intelligent routing
- `PerfBufferManager` for optimized buffer management
- `EventStreamHandler` for async processing

### Reporting System

**Planned Components**:
- `ReportGenerator` for structured report creation
- `EventClassifier` for advanced security classification
- `OutputStrategy` for pluggable output formats
- `AlertManager` for real-time notifications

### Plugin Architecture

**Future Extensions**:
- `SecurityPlugin` trait for custom analysis logic
- `PluginManager` for plugin lifecycle management
- Built-in plugins for common security patterns
- Configuration-driven plugin selection

## Component Dependencies

```
┌─────────────────┐
│ EbpfApplication │
├─────────────────┤
│ Configuration   │
│ ProbeManager    │
│ EventFormatter  │
└─────────────────┘
        │
        ▼
┌─────────────────┐
│ UnifiedProbe    │
│ Manager         │
├─────────────────┤
│ FileProbe       │
│ NetworkProbe    │
│ MemoryProbe     │
└─────────────────┘
        │
        ▼
┌─────────────────┐
│ aya::Ebpf       │
│ (External)      │
└─────────────────┘
```

## Performance Considerations

### Memory Layout Optimization
- Event structures designed for eBPF stack constraints
- Efficient field packing for kernel-userspace communication
- Minimal allocation during event processing

### CPU Efficiency
- Kernel-space filtering reduces userspace overhead
- Per-CPU event processing prevents contention
- Optimized data structures for high-frequency operations

### Scalability Design
- Stateless component design enables horizontal scaling
- Configurable resource limits prevent memory exhaustion
- Graceful degradation under high load conditions

## Related Documentation

- [System Architecture](system-architecture.md) - High-level architectural overview
- [Testing Strategy](../03-development/testing-strategy.md) - Comprehensive testing approach
- [Feature Specifications](../04-project-status/feature-specifications.md) - Detailed feature requirements