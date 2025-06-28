//! Unified Configuration System
//!
//! This module provides a deep module design that hides the complexity
//! of configuration management from multiple sources (CLI, files, environment).

pub mod builder;
pub mod types;
pub mod validation;

pub use builder::ConfigurationBuilder;
pub use types::*;

use crate::errors::{BeeTraceError, ProbeType};

/// Unified configuration that combines CLI, file, and environment settings
///
/// This follows A Philosophy of Software Design principles:
/// - Deep module that hides configuration complexity
/// - Single source of truth for all configuration
/// - Clear validation and error handling
#[derive(Debug, Clone, PartialEq)]
pub struct Configuration {
    pub monitoring: MonitoringConfig,
    pub output: OutputConfig,
    pub security: SecurityConfig,
    pub runtime: RuntimeConfig,
}

impl Configuration {
    /// Create a new builder for configuration
    pub fn builder() -> ConfigurationBuilder {
        ConfigurationBuilder::new()
    }

    /// Validate the configuration for consistency and correctness
    pub fn validate(&self) -> Result<(), BeeTraceError> {
        // Basic validation - can be expanded later
        if self.monitoring.probe_types.is_empty() {
            return Err(BeeTraceError::ConfigError {
                message: "At least one probe type must be specified".to_string(),
            });
        }

        // Validate that include and exclude PIDs are not both specified
        if !self.monitoring.exclude_pids.is_empty() && !self.monitoring.include_pids.is_empty() {
            return Err(BeeTraceError::ConfigError {
                message: "Cannot specify both include_pids and exclude_pids".to_string(),
            });
        }

        // Validate CPU limit
        if let Some(cpu_limit) = self.monitoring.cpu_limit {
            if cpu_limit == 0 || cpu_limit > 100 {
                return Err(BeeTraceError::ConfigError {
                    message: "CPU limit must be between 1 and 100".to_string(),
                });
            }
        }

        Ok(())
    }

    /// Get probe types as a single combined type for backward compatibility
    pub fn probe_type_legacy(&self) -> String {
        if self.monitoring.probe_types.len() == 3 {
            "all".to_string()
        } else if self.monitoring.probe_types.len() == 1 {
            self.monitoring.probe_types[0].as_str().to_string()
        } else {
            "custom".to_string()
        }
    }

    /// Check if a specific probe type is enabled
    pub fn has_probe_type(&self, probe_type: ProbeType) -> bool {
        self.monitoring.probe_types.contains(&probe_type)
    }

    /// Get duration in seconds for backward compatibility
    pub fn duration_secs(&self) -> Option<u64> {
        self.monitoring.duration.map(|d| d.as_secs())
    }

    /// Check if verbose output is enabled
    pub fn is_verbose(&self) -> bool {
        self.output.verbose
    }

    /// Check if security mode is enabled
    pub fn is_security_mode(&self) -> bool {
        self.monitoring.security_mode
    }

    /// Get command filter for backward compatibility
    pub fn command_filter(&self) -> Option<&str> {
        self.monitoring.command_filter.as_deref()
    }
}
