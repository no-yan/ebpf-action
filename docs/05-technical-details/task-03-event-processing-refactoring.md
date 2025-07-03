# Task 03: Main.rs Event Processing Refactoring

**Priority:** HIGH  
**Estimated Time:** 8-12 hours  
**Complexity:** High  
**Dependencies:** None (can be done in parallel)  

## Overview

The `main.rs` file contains a large monolithic async block (lines 126-232) that handles event processing for all probe types. This violates the single responsibility principle and makes the code difficult to test, maintain, and extend. This task extracts the event processing logic into dedicated, testable modules.

## Current Problem

**File:** `bee-trace/src/main.rs:126-232`

The current code has several issues:
- 100+ line async block with multiple responsibilities
- Hard to unit test event processing logic
- Tight coupling between main function and event processing
- Unsafe memory operations scattered throughout
- Error handling mixed with business logic
- Difficult to add new event types or processing strategies

```rust
// Current problematic structure:
let event_processor = async move {
    // 100+ lines of mixed concerns:
    // - CPU enumeration
    // - Event array management  
    // - Async task spawning
    // - Event deserialization
    // - Event filtering
    // - Event formatting
    // - Error handling
};
```

## Proposed Solution

### 1. Create Event Processing Module

**New File:** `bee-trace/src/event_processor/mod.rs`

```rust
//! Event Processing Module
//! 
//! Provides clean abstractions for processing eBPF events from kernel space.
//! Follows the single responsibility principle with clear separation of concerns.

pub mod event_stream;
pub mod event_handler;
pub mod event_deserializer;
pub mod cpu_manager;

use crate::configuration::Configuration;
use crate::errors::BeeTraceError;
use aya::maps::PerfEventArray;
use aya::Ebpf;
use std::collections::HashMap;

pub use event_handler::{EventHandler, DefaultEventHandler};
pub use event_stream::{EventStream, EventStreamConfig};

/// Main event processor that coordinates all event processing activities
pub struct EventProcessor {
    config: Configuration,
    event_streams: HashMap<String, EventStream>,
    event_handler: Box<dyn EventHandler>,
}

impl EventProcessor {
    /// Create a new event processor with configuration
    pub fn new(config: Configuration) -> Self {
        Self {
            config: config.clone(),
            event_streams: HashMap::new(),
            event_handler: Box::new(DefaultEventHandler::new(config)),
        }
    }

    /// Initialize event streams from eBPF maps
    pub fn initialize_from_ebpf(&mut self, ebpf: &mut Ebpf) -> Result<(), BeeTraceError> {
        for &probe_type in &self.config.monitoring.probe_types {
            match probe_type {
                crate::errors::ProbeType::FileMonitor => {
                    self.add_secret_access_stream(ebpf)?;
                }
                crate::errors::ProbeType::NetworkMonitor => {
                    self.add_network_stream(ebpf)?;
                }
                crate::errors::ProbeType::MemoryMonitor => {
                    self.add_memory_streams(ebpf)?;
                }
            }
        }
        Ok(())
    }

    /// Start processing events asynchronously
    pub async fn start_processing(&mut self) -> Result<(), BeeTraceError> {
        let mut tasks = Vec::new();

        for (event_type, event_stream) in &mut self.event_streams {
            let handler = self.event_handler.clone_handler();
            let stream_task = event_stream.spawn_processing_task(handler).await?;
            tasks.push(stream_task);
        }

        // Wait for all tasks to complete
        futures::future::join_all(tasks).await;
        Ok(())
    }

    fn add_secret_access_stream(&mut self, ebpf: &mut Ebpf) -> Result<(), BeeTraceError> {
        if let Some(Ok(secret_array)) = ebpf
            .take_map("SECRET_ACCESS_EVENTS")
            .map(PerfEventArray::try_from)
        {
            let config = EventStreamConfig {
                name: "secret".to_string(),
                event_type: "SecretAccess".to_string(),
                buffer_size: 1024,
            };
            let stream = EventStream::new(config, secret_array)?;
            self.event_streams.insert("secret".to_string(), stream);
        }
        Ok(())
    }

    fn add_network_stream(&mut self, ebpf: &mut Ebpf) -> Result<(), BeeTraceError> {
        if let Some(Ok(network_array)) = ebpf
            .take_map("NETWORK_EVENTS")
            .map(PerfEventArray::try_from)
        {
            let config = EventStreamConfig {
                name: "network".to_string(),
                event_type: "Network".to_string(),
                buffer_size: 1024,
            };
            let stream = EventStream::new(config, network_array)?;
            self.event_streams.insert("network".to_string(), stream);
        }
        Ok(())
    }

    fn add_memory_streams(&mut self, ebpf: &mut Ebpf) -> Result<(), BeeTraceError> {
        // Process memory events
        if let Some(Ok(memory_array)) = ebpf
            .take_map("PROCESS_MEMORY_EVENTS")
            .map(PerfEventArray::try_from)
        {
            let config = EventStreamConfig {
                name: "memory".to_string(),
                event_type: "ProcessMemory".to_string(),
                buffer_size: 1024,
            };
            let stream = EventStream::new(config, memory_array)?;
            self.event_streams.insert("memory".to_string(), stream);
        }

        // Environment access events
        if let Some(Ok(env_array)) = ebpf
            .take_map("ENV_ACCESS_EVENTS")
            .map(PerfEventArray::try_from)
        {
            let config = EventStreamConfig {
                name: "env".to_string(),
                event_type: "EnvAccess".to_string(),
                buffer_size: 1024,
            };
            let stream = EventStream::new(config, env_array)?;
            self.event_streams.insert("env".to_string(), stream);
        }
        Ok(())
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::configuration::Configuration;

    #[test]
    fn should_create_event_processor_with_config() {
        let config = Configuration::builder()
            .with_probe_types(vec![crate::errors::ProbeType::FileMonitor])
            .build()
            .unwrap();
        
        let processor = EventProcessor::new(config);
        assert_eq!(processor.event_streams.len(), 0); // No streams until initialized
    }
}
```

### 2. Create Event Stream Abstraction

**New File:** `bee-trace/src/event_processor/event_stream.rs`

```rust
//! Event Stream Management
//! 
//! Handles individual event streams from eBPF perf event arrays.

use crate::event_processor::event_handler::EventHandler;
use crate::event_processor::event_deserializer::EventDeserializer;
use crate::errors::BeeTraceError;
use aya::maps::PerfEventArray;
use aya::util::online_cpus;
use bytes::BytesMut;
use log::warn;
use tokio::task::JoinHandle;

#[derive(Debug, Clone)]
pub struct EventStreamConfig {
    pub name: String,
    pub event_type: String,
    pub buffer_size: usize,
}

pub struct EventStream {
    config: EventStreamConfig,
    perf_array: PerfEventArray<bee_trace_common::SecretAccessEvent>, // Generic type to be made more flexible
    deserializer: EventDeserializer,
}

impl EventStream {
    pub fn new(
        config: EventStreamConfig,
        perf_array: PerfEventArray<bee_trace_common::SecretAccessEvent>,
    ) -> Result<Self, BeeTraceError> {
        let deserializer = EventDeserializer::for_event_type(&config.event_type)?;
        
        Ok(Self {
            config,
            perf_array,
            deserializer,
        })
    }

    /// Spawn async processing task for this event stream
    pub async fn spawn_processing_task(
        &mut self,
        event_handler: Box<dyn EventHandler>,
    ) -> Result<Vec<JoinHandle<()>>, BeeTraceError> {
        let cpus = online_cpus().map_err(|e| BeeTraceError::EventProcessingError {
            message: format!("Failed to get online CPUs: {:?}", e),
        })?;

        let mut tasks = Vec::new();

        for cpu_id in cpus {
            let mut buf = self.perf_array.open(cpu_id, None).map_err(|e| {
                BeeTraceError::EventProcessingError {
                    message: format!("Failed to open perf buffer for CPU {}: {}", cpu_id, e),
                }
            })?;

            let handler = event_handler.clone_handler();
            let deserializer = self.deserializer.clone();
            let event_type = self.config.event_type.clone();
            let buffer_size = self.config.buffer_size;

            let task = tokio::spawn(async move {
                let mut buffers = (0..10)
                    .map(|_| BytesMut::with_capacity(buffer_size))
                    .collect::<Vec<_>>();

                loop {
                    match buf.read_events(&mut buffers) {
                        Ok(events) => {
                            for buf in buffers.iter().take(events.read) {
                                match deserializer.deserialize_event(buf, &event_type) {
                                    Ok(security_event) => {
                                        handler.handle_event(&security_event).await;
                                    }
                                    Err(e) => {
                                        warn!("Failed to deserialize {} event: {}", event_type, e);
                                    }
                                }
                            }
                        }
                        Err(e) => {
                            warn!("Error reading perf events ({}): {}", event_type, e);
                        }
                    }
                    tokio::task::yield_now().await;
                }
            });

            tasks.push(task);
        }

        Ok(tasks)
    }
}
```

### 3. Create Event Handler Abstraction

**New File:** `bee-trace/src/event_processor/event_handler.rs`

```rust
//! Event Handler Trait and Implementations
//! 
//! Provides pluggable event handling strategies for different use cases.

use crate::{SecurityEvent, TableFormatter};
use crate::configuration::Configuration;
use async_trait::async_trait;

/// Trait for handling security events
#[async_trait]
pub trait EventHandler: Send + Sync {
    /// Handle a single security event
    async fn handle_event(&self, event: &SecurityEvent);
    
    /// Clone this handler for use in another task
    fn clone_handler(&self) -> Box<dyn EventHandler>;
}

/// Default event handler that filters and formats events
pub struct DefaultEventHandler {
    config: Configuration,
    formatter: TableFormatter,
}

impl DefaultEventHandler {
    pub fn new(config: Configuration) -> Self {
        let formatter = TableFormatter::new(config.is_verbose());
        Self { config, formatter }
    }
}

#[async_trait]
impl EventHandler for DefaultEventHandler {
    async fn handle_event(&self, event: &SecurityEvent) {
        // Apply command filter
        if let Some(cmd_filter) = self.config.command_filter() {
            let comm = event.command_as_str();
            if !comm.contains(cmd_filter) {
                return;
            }
        }

        // In security mode, show all events
        if self.config.is_security_mode() {
            println!("{}", self.formatter.format_event(event));
        }
    }

    fn clone_handler(&self) -> Box<dyn EventHandler> {
        Box::new(Self {
            config: self.config.clone(),
            formatter: TableFormatter::new(self.config.is_verbose()),
        })
    }
}

/// Test event handler that collects events for testing
#[cfg(test)]
pub struct TestEventHandler {
    events: std::sync::Arc<std::sync::Mutex<Vec<SecurityEvent>>>,
}

#[cfg(test)]
impl TestEventHandler {
    pub fn new() -> Self {
        Self {
            events: std::sync::Arc::new(std::sync::Mutex::new(Vec::new())),
        }
    }

    pub fn get_events(&self) -> Vec<SecurityEvent> {
        self.events.lock().unwrap().clone()
    }
}

#[cfg(test)]
#[async_trait]
impl EventHandler for TestEventHandler {
    async fn handle_event(&self, event: &SecurityEvent) {
        self.events.lock().unwrap().push(event.clone());
    }

    fn clone_handler(&self) -> Box<dyn EventHandler> {
        Box::new(Self {
            events: self.events.clone(),
        })
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use bee_trace_common::{SecretAccessEvent, SecurityEventBuilder};

    #[tokio::test]
    async fn should_collect_events_in_test_handler() {
        let handler = TestEventHandler::new();
        
        let event = SecurityEvent::SecretAccess(
            SecretAccessEvent::new()
                .with_pid(1234)
                .with_file_access(b"/etc/passwd")
        );

        handler.handle_event(&event).await;
        
        let events = handler.get_events();
        assert_eq!(events.len(), 1);
    }
}
```

### 4. Create Event Deserializer

**New File:** `bee-trace/src/event_processor/event_deserializer.rs`

```rust
//! Event Deserialization
//! 
//! Safely converts raw bytes from eBPF into typed SecurityEvent structures.

use crate::{SecurityEvent, errors::BeeTraceError};
use bee_trace_common::{SecretAccessEvent, NetworkEvent, ProcessMemoryEvent};
use bytes::BytesMut;

#[derive(Clone)]
pub struct EventDeserializer {
    event_type: String,
}

impl EventDeserializer {
    pub fn for_event_type(event_type: &str) -> Result<Self, BeeTraceError> {
        match event_type {
            "SecretAccess" | "EnvAccess" | "Network" | "ProcessMemory" => {
                Ok(Self {
                    event_type: event_type.to_string(),
                })
            }
            _ => Err(BeeTraceError::EventProcessingError {
                message: format!("Unknown event type: {}", event_type),
            }),
        }
    }

    /// Safely deserialize bytes into a SecurityEvent
    pub fn deserialize_event(
        &self,
        buf: &BytesMut,
        event_type: &str,
    ) -> Result<SecurityEvent, BeeTraceError> {
        match event_type {
            "SecretAccess" | "EnvAccess" => {
                if buf.len() < std::mem::size_of::<SecretAccessEvent>() {
                    return Err(BeeTraceError::EventProcessingError {
                        message: "Buffer too small for SecretAccessEvent".to_string(),
                    });
                }
                
                let event = unsafe {
                    buf.as_ptr()
                        .cast::<SecretAccessEvent>()
                        .read_unaligned()
                };
                Ok(SecurityEvent::SecretAccess(event))
            }
            "Network" => {
                if buf.len() < std::mem::size_of::<NetworkEvent>() {
                    return Err(BeeTraceError::EventProcessingError {
                        message: "Buffer too small for NetworkEvent".to_string(),
                    });
                }
                
                let event = unsafe {
                    buf.as_ptr()
                        .cast::<NetworkEvent>()
                        .read_unaligned()
                };
                Ok(SecurityEvent::Network(event))
            }
            "ProcessMemory" => {
                if buf.len() < std::mem::size_of::<ProcessMemoryEvent>() {
                    return Err(BeeTraceError::EventProcessingError {
                        message: "Buffer too small for ProcessMemoryEvent".to_string(),
                    });
                }
                
                let event = unsafe {
                    buf.as_ptr()
                        .cast::<ProcessMemoryEvent>()
                        .read_unaligned()
                };
                Ok(SecurityEvent::ProcessMemory(event))
            }
            _ => Err(BeeTraceError::EventProcessingError {
                message: format!("Unknown event type for deserialization: {}", event_type),
            }),
        }
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn should_create_deserializer_for_valid_event_types() {
        assert!(EventDeserializer::for_event_type("SecretAccess").is_ok());
        assert!(EventDeserializer::for_event_type("Network").is_ok());
        assert!(EventDeserializer::for_event_type("ProcessMemory").is_ok());
    }

    #[test]
    fn should_reject_invalid_event_types() {
        assert!(EventDeserializer::for_event_type("Invalid").is_err());
    }
}
```

### 5. Update Main.rs

**File:** `bee-trace/src/main.rs` (simplified)

```rust
use bee_trace::event_processor::EventProcessor;

#[tokio::main]
async fn main() -> anyhow::Result<()> {
    let args = Args::parse();
    
    if let Err(e) = args.validate() {
        eprintln!("Configuration validation failed: {}", e);
        eprintln!("Use --help for usage information");
        std::process::exit(1);
    }

    let config = convert_args_to_configuration(&args)?;
    
    env_logger::init();
    
    // Setup eBPF
    let rlim = libc::rlimit {
        rlim_cur: libc::RLIM_INFINITY,
        rlim_max: libc::RLIM_INFINITY,
    };
    let ret = unsafe { libc::setrlimit(libc::RLIMIT_MEMLOCK, &rlim) };
    if ret != 0 {
        debug!("remove limit on locked memory failed, ret is: {ret}");
    }

    let mut ebpf = Ebpf::load(aya::include_bytes_aligned!(concat!(
        env!("OUT_DIR"),
        "/bee-trace"
    )))?;

    if let Err(e) = EbpfLogger::init(&mut ebpf) {
        warn!("failed to initialize eBPF logger: {e}");
    }

    // Create and configure the eBPF application
    let mut app = EbpfApplication::new(config.clone());
    app.attach_configured_probes(&mut ebpf)
        .map_err(|e| anyhow::anyhow!("Failed to attach probes: {}", e))?;

    info!("✅ All configured probes attached successfully");

    // Create event processor and initialize from eBPF
    let mut event_processor = EventProcessor::new(config.clone());
    event_processor.initialize_from_ebpf(&mut ebpf)?;

    // Print startup information
    println!("🐝 bee-trace security monitoring started");
    let formatter = TableFormatter::new(config.is_verbose());
    println!("{}", formatter.header());
    println!("{}", formatter.separator());

    // Handle duration or wait for Ctrl+C
    if let Some(duration_secs) = config.duration_secs() {
        match timeout(
            Duration::from_secs(duration_secs),
            event_processor.start_processing(),
        )
        .await
        {
            Ok(_) => {}
            Err(_) => println!("\nTracing completed after {} seconds", duration_secs),
        }
    } else {
        tokio::select! {
            _ = event_processor.start_processing() => {},
            _ = signal::ctrl_c() => {
                println!("\nReceived Ctrl+C, exiting...");
            }
        }
    }

    Ok(())
}
```

## Implementation Steps

### Phase 1: Create Module Structure (2-3 hours)
1. Create `bee-trace/src/event_processor/` directory
2. Create `mod.rs` with basic structure
3. Add module declaration to `bee-trace/src/lib.rs`
4. Create placeholder files for submodules

### Phase 2: Implement Event Handler (2-3 hours)
1. Create `event_handler.rs` with trait definition
2. Implement `DefaultEventHandler`
3. Add test handler for unit testing
4. Add comprehensive tests

### Phase 3: Implement Event Stream (2-3 hours)
1. Create `event_stream.rs` with stream abstraction
2. Implement CPU management and task spawning
3. Add error handling and logging
4. Create unit tests

### Phase 4: Implement Event Deserializer (2-3 hours)
1. Create `event_deserializer.rs` with safe deserialization
2. Add buffer size validation
3. Implement all event type support
4. Add comprehensive error handling

### Phase 5: Update Main and Integration (1-2 hours)
1. Update `main.rs` to use new event processor
2. Remove old monolithic async block
3. Test integration with existing functionality
4. Update any affected tests

## Dependencies Required

Add to `bee-trace/Cargo.toml`:
```toml
[dependencies]
async-trait = "0.1"
futures = "0.3"
```

## Acceptance Criteria

- [ ] Event processing logic extracted from main.rs
- [ ] Clean separation of concerns with testable modules
- [ ] All event types (file, network, memory) supported
- [ ] Comprehensive error handling throughout
- [ ] Unit tests for all new modules (>95% coverage)
- [ ] Integration tests pass without modification
- [ ] No performance regression in event processing
- [ ] Memory safety maintained in all unsafe operations
- [ ] Pluggable event handler interface for future extensions

## Testing Strategy

### Unit Tests
```bash
# Test individual modules
cargo test -p bee-trace event_processor::
cargo test -p bee-trace event_handler::
cargo test -p bee-trace event_stream::
cargo test -p bee-trace event_deserializer::
```

### Integration Tests
```bash
# Ensure existing functionality works
cargo test --test integration_tests
cargo test --test functional_tests
cargo test --test ebpf_integration_tests
```

### Manual Testing
```bash
# Verify event processing still works
just run-all-monitors --duration 30 --verbose

# Test with different probe types
just run-file-monitor --duration 10
just run-network-monitor --duration 10
just run-memory-monitor --duration 10
```

## Risk Assessment

**Risk Level:** MEDIUM-HIGH

- **Technical Risk:** High - Major refactoring of core functionality
- **Breaking Changes:** None - internal refactoring only
- **Performance Impact:** Should be neutral or positive
- **Security Impact:** Positive - better error handling and validation

## Performance Considerations

- Async task overhead should be similar to current implementation
- Better error handling may have slight overhead
- Event deserialization is now safer with bounds checking
- Future optimizations enabled by cleaner architecture

## Benefits

### Immediate Benefits
- **Testability**: Each component can be unit tested independently
- **Maintainability**: Clear separation of concerns
- **Error Handling**: Centralized and consistent error management
- **Memory Safety**: Explicit bounds checking in deserialization

### Future Benefits
- **Extensibility**: Easy to add new event handlers or processing strategies
- **Performance**: Easier to optimize individual components
- **Reliability**: Better error recovery and handling
- **Debugging**: Clearer code paths and logging

## Migration Strategy

This refactoring maintains complete backward compatibility:
1. All existing CLI arguments work unchanged
2. Event output format remains identical
3. Performance characteristics maintained
4. All existing tests continue to pass

## Success Metrics

- Code organization score improvement (subjective assessment)
- Test coverage increase for event processing logic
- Reduced complexity metrics in main.rs
- No regression in event processing performance
- All 179+ existing tests continue passing