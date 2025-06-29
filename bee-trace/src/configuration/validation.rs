//! Configuration validation logic
//!
//! Provides comprehensive validation for configuration values
//! to ensure system safety and correctness.

use super::Configuration;
use crate::errors::BeeTraceError;

impl Configuration {
    /// Validate probe types are compatible
    pub fn validate_probe_types(&self) -> Result<(), BeeTraceError> {
        if self.monitoring.probe_types.is_empty() {
            return Err(BeeTraceError::ConfigError {
                message: "At least one probe type must be specified".to_string(),
            });
        }
        Ok(())
    }

    /// Validate PID filtering configuration
    pub fn validate_pid_filters(&self) -> Result<(), BeeTraceError> {
        if !self.monitoring.exclude_pids.is_empty() && !self.monitoring.include_pids.is_empty() {
            return Err(BeeTraceError::ConfigError {
                message: "Cannot specify both include_pids and exclude_pids".to_string(),
            });
        }
        Ok(())
    }

    /// Validate resource limits
    pub fn validate_resource_limits(&self) -> Result<(), BeeTraceError> {
        if let Some(cpu_limit) = self.monitoring.cpu_limit {
            if cpu_limit == 0 || cpu_limit > 100 {
                return Err(BeeTraceError::ConfigError {
                    message: "CPU limit must be between 1 and 100".to_string(),
                });
            }
        }
        Ok(())
    }

    /// Validate output configuration
    pub fn validate_output_config(&self) -> Result<(), BeeTraceError> {
        if self.output.verbose && self.output.quiet {
            return Err(BeeTraceError::ConfigError {
                message: "Cannot specify both verbose and quiet modes".to_string(),
            });
        }
        Ok(())
    }
}
