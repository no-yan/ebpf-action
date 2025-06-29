//! Event Processing Module
//!
//! This module provides a clean abstraction for eBPF event processing,
//! replacing the monolithic async block in main.rs with modular components.
//!
//! Key components:
//! - EventProcessor: Main interface for event processing lifecycle
//! - PerfBufferManager: CPU coordination and buffer management  
//! - EventParser: Safe event parsing (eliminates unsafe code)
//! - EventDispatcher: Event routing and formatting

pub mod buffer_manager;
pub mod parser;
pub mod processor;

pub use buffer_manager::PerfBufferManager;
pub use parser::SecurityEventParser;
pub use processor::{EventProcessor, SecurityEventProcessor};

use aya::maps::PerfEventArray;
use bee_trace_common::{NetworkEvent, ProcessMemoryEvent, SecretAccessEvent};

/// Event array mapping for cleaner interface (matches main.rs usage)
pub type EventArrayMap = Vec<(&'static str, PerfEventArray<&'static mut [u8]>)>;

/// Security event types that can be parsed
#[derive(Clone)]
pub enum ParsedSecurityEvent {
    SecretAccess(SecretAccessEvent),
    Network(NetworkEvent),
    ProcessMemory(ProcessMemoryEvent),
}

impl ParsedSecurityEvent {
    /// Convert to the main SecurityEvent enum
    pub fn into_security_event(self) -> crate::SecurityEvent {
        match self {
            ParsedSecurityEvent::SecretAccess(event) => crate::SecurityEvent::SecretAccess(event),
            ParsedSecurityEvent::Network(event) => crate::SecurityEvent::Network(event),
            ParsedSecurityEvent::ProcessMemory(event) => crate::SecurityEvent::ProcessMemory(event),
        }
    }
}
