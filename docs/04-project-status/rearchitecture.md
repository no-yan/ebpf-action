# Architecture Refactoring Progress

> **📅 Implementation Timeline**: For when these architectural changes should be implemented, see the [Development Roadmap](development-roadmap.md#implementation-timeline-integration).

## Overview
This document tracks the TDD-based refactoring of bee-trace to achieve loose coupling and high cohesion design, following "A Philosophy of Software Design" principles.

## Original Problem Analysis
- **File**: `bee-trace/src/main.rs` was 330+ lines with tight coupling
- **Issues**: Monolithic probe management, scattered configuration, mixed responsibilities
- **Goal**: Extract clean interfaces, separate concerns, improve maintainability
- **Approach**: Test-Driven Development with t-wada methodology

## Progress Status: 70% Complete

### ✅ COMPLETED PHASES (1-4)

#### Phase 1: Setup test environment and branch ✅
- **Status**: COMPLETED
- **Branch**: `refactor/loose-coupling-design` 
- **Test Suite**: Comprehensive test suite passing
- **Files Added**: Test infrastructure

#### Phase 2: TDD Cycle 1 - Interface design (ProbeManager trait) ✅
- **Status**: COMPLETED
- **Files**: 
  - `bee-trace/src/ebpf_manager/probe_manager.rs` - Core trait
  - `bee-trace/src/ebpf_manager/file_probe_manager.rs`
  - `bee-trace/src/ebpf_manager/network_probe_manager.rs`
  - `bee-trace/src/ebpf_manager/memory_probe_manager.rs`
  - `bee-trace/src/ebpf_manager/mod.rs` - UnifiedProbeManager
- **Achievement**: Clean trait abstraction for eBPF probe management

#### Phase 3: TDD Cycle 2 - Configuration unification ✅
- **Status**: COMPLETED
- **Files**:
  - `bee-trace/src/configuration/mod.rs` - Unified Configuration
  - `bee-trace/src/configuration/builder.rs` - Builder pattern
  - `bee-trace/src/configuration/types.rs` - Type definitions
  - `bee-trace/src/configuration/validation.rs` - Validation logic
  - `bee-trace/src/errors.rs` - Unified error handling
- **Achievement**: Single source of truth for all configuration

#### Phase 4: TDD Cycle 3 - eBPF management separation ✅  
- **Status**: COMPLETED
- **Files**:
  - `bee-trace/src/ebpf_manager/application.rs` - EbpfApplication integration layer
- **Achievement**: Production-ready integration between Configuration and ProbeManager

#### BONUS: Main.rs Integration ✅
- **Status**: COMPLETED  
- **Files**: `bee-trace/src/main.rs` - Converted to use new architecture
- **Achievement**: CLI arguments → Configuration → EbpfApplication working
- **Validation**: `just run-all-monitors` uses new architecture successfully

### ❌ REMAINING PHASES (5-8)

#### Phase 5: TDD Cycle 4 - Event Processing Separation ⚠️ HIGH PRIORITY
- **Status**: PENDING
- **Problem**: Lines 130-235 in main.rs contain monolithic event processing (100+ lines)
- **Current Code Issue**:
  ```rust
  let event_processor = async move {
      let cpus = match online_cpus() { ... };
      for (event_type, mut perf_array) in event_arrays {
          for cpu_id in &cpus {
              // Complex perf buffer management
              // CPU-specific task spawning  
              // Event parsing and dispatching
              // Raw unsafe pointer operations
          }
      }
  };
  ```

**Required Refactoring**:
1. **Create EventProcessor trait** for perf buffer management abstraction
2. **Extract SecurityEventDispatcher** for event routing logic  
3. **Create PerfBufferManager** for CPU/buffer coordination
4. **Implement EventStreamHandler** for async event streaming
5. **Move unsafe pointer operations** to dedicated event parsing module

**Files to Create**:
- `bee-trace/src/event_processing/mod.rs`
- `bee-trace/src/event_processing/event_processor.rs` 
- `bee-trace/src/event_processing/perf_buffer_manager.rs`
- `bee-trace/src/event_processing/security_event_dispatcher.rs`
- `bee-trace/src/event_processing/event_stream_handler.rs`

**TDD Approach**:
1. Write tests for EventProcessor interface
2. Create mock implementations for testing
3. Extract one concern at a time (Red-Green-Refactor)
4. Integration tests for complete event flow

#### Phase 6: TDD Cycle 5 - Reporting responsibility separation
- **Status**: PENDING  
- **Problem**: SecurityReport logic scattered, event classification mixed
- **Target**: Extract reporting concerns from main.rs
- **Files to Create**:
  - `bee-trace/src/reporting/mod.rs`
  - `bee-trace/src/reporting/report_generator.rs`
  - `bee-trace/src/reporting/event_classifier.rs`

#### Phase 7: TDD Cycle 6 - Main application simplification  
- **Status**: PENDING
- **Goal**: Reduce main.rs to pure coordination (<100 lines)
- **Target**: Simple composition of interfaces, no implementation details

#### Phase 8: Existing test migration and validation
- **Status**: PENDING
- **Goal**: Update existing tests to use new interfaces
- **Priority**: LOW (current tests passing with new architecture)

## Current Architecture State

### Loose Coupling: 70% ✅
- ✅ Configuration system decoupled
- ✅ ProbeManager abstracted via traits
- ✅ eBPF management separated  
- ❌ Event processing still monolithic (main blocker)
- ❌ Reporting still embedded

### High Cohesion: 60% ⚠️
- ✅ Each module has clear single responsibility
- ✅ Deep module design implemented (complex logic hidden)
- ❌ Event processing crosses multiple concerns (perf buffers + parsing + dispatching)
- ❌ Main.rs still mixing coordination + implementation

## Test Coverage: 112 tests passing ✅
- Configuration system: 11 tests
- eBPF management: 8 integration tests  
- ProbeManager: 9 unit tests
- Individual probe managers: 9 tests
- Security event processing: 5 tests
- Plus comprehensive coverage across all modules

## Working Validation ✅
- **Command**: `just run-all-monitors --duration 10` 
- **Result**: New architecture working, proper error handling
- **Evidence**: Args → Configuration → EbpfApplication → ProbeManager flow confirmed

## Next Action Priority
**Start Phase 5**: Event Processing Separation is the highest priority to complete the loose coupling goal. The 100+ line monolithic async block in main.rs is the largest remaining architectural debt.

## Branch Information
- **Current Branch**: `refactor/loose-coupling-design`
- **Base**: `main`
- **Status**: Ready for Phase 5 implementation

## Development Context
- **Language**: Rust
- **Framework**: eBPF with Aya
- **Testing**: TDD with t-wada methodology
- **Design**: A Philosophy of Software Design principles
- **Build**: `just test` for testing, `just run-all-monitors` for validation