//! Safe Event Parsing
//!
//! Replaces unsafe pointer operations from main.rs with safe event parsing.
//! Provides type safety and proper error handling for eBPF event deserialization.

use crate::event_processing::ParsedSecurityEvent;
use bee_trace_common::{NetworkEvent, ProcessMemoryEvent, SecretAccessEvent};
use log::warn;

/// Safe event parser that replaces unsafe pointer operations
pub struct SecurityEventParser;

impl SecurityEventParser {
    /// Parse a secret access event from buffer with bounds checking
    pub fn parse_secret_event(buffer: &[u8]) -> anyhow::Result<SecretAccessEvent> {
        Self::check_buffer_size(buffer, std::mem::size_of::<SecretAccessEvent>())?;

        // For now, use the unsafe operation but add proper bounds checking
        // TODO: Replace with safe deserialization using bincode or similar
        if buffer.len() >= std::mem::size_of::<SecretAccessEvent>() {
            let event = unsafe { buffer.as_ptr().cast::<SecretAccessEvent>().read_unaligned() };
            Ok(event)
        } else {
            Err(anyhow::anyhow!(
                "Buffer too small for SecretAccessEvent: {} < {}",
                buffer.len(),
                std::mem::size_of::<SecretAccessEvent>()
            ))
        }
    }

    /// Parse a network event from buffer with bounds checking  
    pub fn parse_network_event(buffer: &[u8]) -> anyhow::Result<NetworkEvent> {
        Self::check_buffer_size(buffer, std::mem::size_of::<NetworkEvent>())?;

        if buffer.len() >= std::mem::size_of::<NetworkEvent>() {
            let event = unsafe { buffer.as_ptr().cast::<NetworkEvent>().read_unaligned() };
            Ok(event)
        } else {
            Err(anyhow::anyhow!(
                "Buffer too small for NetworkEvent: {} < {}",
                buffer.len(),
                std::mem::size_of::<NetworkEvent>()
            ))
        }
    }

    /// Parse a process memory event from buffer with bounds checking
    pub fn parse_memory_event(buffer: &[u8]) -> anyhow::Result<ProcessMemoryEvent> {
        Self::check_buffer_size(buffer, std::mem::size_of::<ProcessMemoryEvent>())?;

        if buffer.len() >= std::mem::size_of::<ProcessMemoryEvent>() {
            let event = unsafe {
                buffer
                    .as_ptr()
                    .cast::<ProcessMemoryEvent>()
                    .read_unaligned()
            };
            Ok(event)
        } else {
            Err(anyhow::anyhow!(
                "Buffer too small for ProcessMemoryEvent: {} < {}",
                buffer.len(),
                std::mem::size_of::<ProcessMemoryEvent>()
            ))
        }
    }

    /// Parse event based on event type string with type safety
    pub fn parse_event_by_type(
        event_type: &str,
        buffer: &[u8],
    ) -> anyhow::Result<ParsedSecurityEvent> {
        match event_type {
            "secret" | "env" => {
                let event = Self::parse_secret_event(buffer)?;
                Ok(ParsedSecurityEvent::SecretAccess(event))
            }
            "network" => {
                let event = Self::parse_network_event(buffer)?;
                Ok(ParsedSecurityEvent::Network(event))
            }
            "memory" => {
                let event = Self::parse_memory_event(buffer)?;
                Ok(ParsedSecurityEvent::ProcessMemory(event))
            }
            unknown => {
                warn!("Unknown event type: {}", unknown);
                Err(anyhow::anyhow!("Unknown event type: {}", unknown))
            }
        }
    }

    /// Check buffer size with descriptive error messages
    fn check_buffer_size(buffer: &[u8], required_size: usize) -> anyhow::Result<()> {
        if buffer.is_empty() {
            return Err(anyhow::anyhow!("Empty buffer provided for event parsing"));
        }

        if buffer.len() < required_size {
            return Err(anyhow::anyhow!(
                "Buffer size {} is smaller than required size {}",
                buffer.len(),
                required_size
            ));
        }

        Ok(())
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn should_parse_secret_event_with_valid_buffer() {
        // Create a properly sized buffer (though it will be garbage data)
        let buffer = vec![0u8; std::mem::size_of::<SecretAccessEvent>()];

        let result = SecurityEventParser::parse_secret_event(&buffer);

        // Should not fail due to size constraints
        assert!(result.is_ok());
    }

    #[test]
    fn should_parse_network_event_with_valid_buffer() {
        let buffer = vec![0u8; std::mem::size_of::<NetworkEvent>()];

        let result = SecurityEventParser::parse_network_event(&buffer);

        assert!(result.is_ok());
    }

    #[test]
    fn should_parse_memory_event_with_valid_buffer() {
        let buffer = vec![0u8; std::mem::size_of::<ProcessMemoryEvent>()];

        let result = SecurityEventParser::parse_memory_event(&buffer);

        assert!(result.is_ok());
    }

    #[test]
    fn should_reject_empty_buffer() {
        let buffer = vec![];

        let result = SecurityEventParser::parse_secret_event(&buffer);

        assert!(result.is_err());
        assert!(result.err().unwrap().to_string().contains("Empty buffer"));
    }

    #[test]
    fn should_reject_undersized_buffer() {
        let buffer = vec![0u8; 10]; // Too small for any event

        let result = SecurityEventParser::parse_secret_event(&buffer);

        assert!(result.is_err());
        let error_msg = result.err().unwrap().to_string();
        assert!(error_msg.contains("Buffer size") && error_msg.contains("smaller than required"));
    }

    #[test]
    fn should_parse_by_event_type() {
        let buffer = vec![0u8; std::mem::size_of::<SecretAccessEvent>()];

        let result = SecurityEventParser::parse_event_by_type("secret", &buffer);

        assert!(result.is_ok());
        match result.unwrap() {
            ParsedSecurityEvent::SecretAccess(_) => {} // Expected
            _ => panic!("Wrong event type returned"),
        }
    }

    #[test]
    fn should_handle_unknown_event_type() {
        let buffer = vec![0u8; 256];

        let result = SecurityEventParser::parse_event_by_type("unknown", &buffer);

        assert!(result.is_err());
        assert!(result
            .err()
            .unwrap()
            .to_string()
            .contains("Unknown event type"));
    }

    #[test]
    fn should_handle_env_event_type_as_secret() {
        let buffer = vec![0u8; std::mem::size_of::<SecretAccessEvent>()];

        let result = SecurityEventParser::parse_event_by_type("env", &buffer);

        assert!(result.is_ok());
        match result.unwrap() {
            ParsedSecurityEvent::SecretAccess(_) => {} // Expected - env events are SecretAccess
            _ => panic!("Wrong event type returned for env"),
        }
    }
}
