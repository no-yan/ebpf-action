//! Unified error types for bee-trace
//!
//! This module provides a comprehensive error handling system following
//! A Philosophy of Software Design principles - errors are well-defined
//! and provide clear context for debugging.

use thiserror::Error;

#[derive(Debug, Error)]
pub enum BeeTraceError {
    #[error("eBPF program failed to attach: {program_name} - {source}")]
    EbpfAttachmentFailed {
        program_name: String,
        source: anyhow::Error,
    },

    #[error("eBPF program failed to load: {program_name} - {source}")]
    EbpfLoadFailed {
        program_name: String,
        source: anyhow::Error,
    },

    #[error("Invalid probe type: {probe_type}. Valid types: {valid_types:?}")]
    InvalidProbeType {
        probe_type: String,
        valid_types: Vec<String>,
    },

    #[error("Configuration error: {message}")]
    ConfigError { message: String },

    #[error("Event processing error: {message}")]
    EventProcessingError { message: String },

    #[error("Probe already attached: {probe_type:?}")]
    ProbeAlreadyAttached { probe_type: ProbeType },

    #[error("Probe not found: {probe_type:?}")]
    ProbeNotFound { probe_type: ProbeType },

    #[error("eBPF map not found: {map_name}")]
    MapNotFound { map_name: String },
}

#[derive(Debug, Clone, Copy, PartialEq, Eq, Hash)]
pub enum ProbeType {
    FileMonitor,
    NetworkMonitor,
    MemoryMonitor,
}

impl ProbeType {
    pub fn all() -> Vec<ProbeType> {
        vec![Self::FileMonitor, Self::NetworkMonitor, Self::MemoryMonitor]
    }

    pub fn as_str(&self) -> &'static str {
        match self {
            ProbeType::FileMonitor => "file_monitor",
            ProbeType::NetworkMonitor => "network_monitor",
            ProbeType::MemoryMonitor => "memory_monitor",
        }
    }
}

impl std::fmt::Display for ProbeType {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        write!(f, "{}", self.as_str())
    }
}

impl std::str::FromStr for ProbeType {
    type Err = BeeTraceError;

    fn from_str(s: &str) -> std::result::Result<Self, Self::Err> {
        match s {
            "file_monitor" => Ok(ProbeType::FileMonitor),
            "network_monitor" => Ok(ProbeType::NetworkMonitor),
            "memory_monitor" => Ok(ProbeType::MemoryMonitor),
            _ => Err(BeeTraceError::InvalidProbeType {
                probe_type: s.to_string(),
                valid_types: ProbeType::all()
                    .iter()
                    .map(|p| p.as_str().to_string())
                    .collect(),
            }),
        }
    }
}

pub type Result<T> = std::result::Result<T, BeeTraceError>;

#[cfg(test)]
mod tests {
    use super::*;

    mod probe_type_tests {
        use super::*;

        #[test]
        fn should_convert_probe_type_to_string() {
            assert_eq!(ProbeType::FileMonitor.as_str(), "file_monitor");
            assert_eq!(ProbeType::NetworkMonitor.as_str(), "network_monitor");
            assert_eq!(ProbeType::MemoryMonitor.as_str(), "memory_monitor");
        }

        #[test]
        fn should_parse_valid_probe_type_from_string() {
            assert_eq!(
                "file_monitor".parse::<ProbeType>().unwrap(),
                ProbeType::FileMonitor
            );
            assert_eq!(
                "network_monitor".parse::<ProbeType>().unwrap(),
                ProbeType::NetworkMonitor
            );
            assert_eq!(
                "memory_monitor".parse::<ProbeType>().unwrap(),
                ProbeType::MemoryMonitor
            );
        }

        #[test]
        fn should_reject_invalid_probe_type_string() {
            let result = "invalid_probe".parse::<ProbeType>();
            assert!(result.is_err());

            if let Err(BeeTraceError::InvalidProbeType {
                probe_type,
                valid_types,
            }) = result
            {
                assert_eq!(probe_type, "invalid_probe");
                assert_eq!(valid_types.len(), 3);
            } else {
                panic!("Expected InvalidProbeType error");
            }
        }

        #[test]
        fn should_list_all_probe_types() {
            let all_types = ProbeType::all();
            assert_eq!(all_types.len(), 3);
            assert!(all_types.contains(&ProbeType::FileMonitor));
            assert!(all_types.contains(&ProbeType::NetworkMonitor));
            assert!(all_types.contains(&ProbeType::MemoryMonitor));
        }
    }
}
