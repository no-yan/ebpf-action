//! Event Processing Module
//!
//! This module provides a clean abstraction for eBPF event processing.
//! The previous monolithic approach mixed responsibilities and used unsafe operations,
//! making it difficult to test individual components and reason about failures.
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

/// Type alias for event arrays passed from main.rs eBPF initialization
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
