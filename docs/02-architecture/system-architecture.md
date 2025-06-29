# bee-trace System Architecture

## Overview

bee-trace is an eBPF-based security monitoring tool built with Rust, demonstrating modern software design principles including loose coupling, high cohesion, and Test-Driven Development (TDD).

## Project Structure

```
bee-trace/
├── bee-trace-common/          # Shared types between userspace and kernel
├── bee-trace-ebpf/           # eBPF kernel programs
├── bee-trace/                # Main userspace application
│   ├── src/
│   │   ├── configuration/    # Unified configuration system
│   │   ├── ebpf_manager/    # eBPF probe management
│   │   ├── errors.rs        # Unified error handling
│   │   └── lib.rs           # Core business logic
│   └── tests/               # Comprehensive test suite
└── docs/                    # Documentation
```

## Design Philosophy

### Core Principles

1. **Loose Coupling**: Minimal dependencies between components
2. **High Cohesion**: Single responsibility per module
3. **Deep Modules**: Hide complexity behind simple interfaces
4. **Test-Driven Development**: Comprehensive test coverage with mock implementations

### Architecture Goals

- Replace monolithic structures with clean separation of concerns
- Create testable interfaces for all major components
- Maintain backward compatibility while improving maintainability
- Enable independent evolution of components

## System Architecture

### High-Level Component Flow

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

### Architecture Layers

#### 1. CLI Interface Layer
- Argument parsing and validation
- User interaction and command handling
- Configuration bootstrapping

#### 2. Configuration Layer
- Unified configuration management
- Multi-source configuration (CLI, files, environment)
- Validation and error handling

#### 3. Application Coordination Layer
- EbpfApplication integration point
- High-level workflow orchestration
- Cross-component communication

#### 4. Probe Management Layer
- Abstract probe operations via traits
- Unified probe coordination
- Individual probe type implementations

#### 5. eBPF Runtime Layer
- Kernel program loading and attachment
- Event collection via perf buffers
- Low-level eBPF operations

## Implementation Evolution

### Phase 1-4: Foundation (Completed ✅)
- **Interface Design**: ProbeManager trait abstraction
- **Configuration Unification**: Single source of truth for configuration
- **eBPF Management Separation**: Clean abstraction over eBPF operations
- **Production Integration**: Backward-compatible integration

### Phase 5+: Advanced Features (Future)

#### Event Processing Separation (High Priority)
**Goal**: Extract monolithic event processing from main.rs

**Target Architecture**:
```
┌─────────────────────┐
│  EventProcessor     │
├─────────────────────┤
│ PerfBufferManager   │
│ SecurityEventDispat │
│ EventStreamHandler  │
└─────────────────────┘
```

#### Reporting System Enhancement (Medium Priority)
**Goal**: Dedicated reporting subsystem

**Components**:
- ReportGenerator for structured output
- EventClassifier for security classification
- OutputStrategy for multiple formats

## Performance Characteristics

### Efficiency Targets
- **CPU Overhead**: <5% under normal workload
- **Memory Usage**: <100MB for all probe types active
- **Latency Impact**: <10% increase for monitored operations
- **Event Processing**: Zero event loss under 1000 events/second

### eBPF Optimization Strategy
- Kernel-space filtering to minimize userspace overhead
- Efficient perf buffer management with per-CPU processing
- Minimal data copying between kernel and userspace
- Optimized event structure layouts for memory efficiency

## Deployment Architecture

### Requirements
- Rust toolchain (stable + nightly with rust-src)
- eBPF toolchain (bpf-linker, llvm)
- Elevated privileges (CAP_BPF or root)
- Compatible kernel version with eBPF support

### Containerization Strategy
- Docker support with minimal privileges
- Required capabilities: CAP_BPF, CAP_SYS_ADMIN (if needed)
- Read-only filesystem mounts for security
- Resource limits for production deployment

## Success Metrics

### Architecture Quality
- **Loose Coupling**: 70% complete (Phase 5 will achieve 100%)
- **High Cohesion**: Clear single responsibility per module
- **Test Coverage**: 112+ tests with comprehensive mock support
- **Maintainability**: Clear module boundaries and interfaces

### Operational Metrics
- **Reliability**: 99.9% uptime target in production
- **Performance**: <5% system overhead under normal load
- **Security**: Zero critical vulnerabilities in reviews
- **Usability**: Clear documentation and error messages

This architecture demonstrates how modern software design principles can be successfully applied to systems programming projects, creating a maintainable and extensible eBPF security monitoring system.

## Related Documentation

- [Component Reference](component-reference.md) - Detailed breakdown of individual components
- [Design Principles](design-principles.md) - TDD methodology and design patterns
- [Testing Strategy](../03-development/testing-strategy.md) - Comprehensive testing approach