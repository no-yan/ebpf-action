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
use std::collections::HashSet;

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

/// Optimized configuration provider implementation with HashSet lookups
///
/// This implementation caches commonly accessed values in HashSets for
/// O(1) lookup performance, making it suitable for high-frequency
/// security event classification.
pub struct OptimizedConfigurationProvider {
    config: Configuration,
    sensitive_files_set: HashSet<String>,
    sensitive_extensions_set: HashSet<String>,
    suspicious_ports_set: HashSet<u16>,
    excluded_processes_set: HashSet<String>,
    blocked_ips_set: HashSet<String>,
    blocked_domains_set: HashSet<String>,
}

impl OptimizedConfigurationProvider {
    pub fn new(config: Configuration) -> Self {
        let sensitive_files_set: HashSet<String> = config
            .security
            .file_monitoring
            .sensitive_files
            .iter()
            .cloned()
            .collect();

        let sensitive_extensions_set: HashSet<String> = config
            .security
            .file_monitoring
            .sensitive_extensions
            .iter()
            .cloned()
            .collect();

        let suspicious_ports_set: HashSet<u16> = config
            .security
            .network_monitoring
            .suspicious_ports
            .iter()
            .cloned()
            .collect();

        let excluded_processes_set: HashSet<String> = config
            .security
            .memory_monitoring
            .excluded_processes
            .iter()
            .cloned()
            .collect();

        let blocked_ips_set: HashSet<String> = config
            .security
            .network_monitoring
            .blocked_ips
            .iter()
            .cloned()
            .collect();

        let blocked_domains_set: HashSet<String> =
            config.security.blocked_domains.iter().cloned().collect();

        Self {
            config,
            sensitive_files_set,
            sensitive_extensions_set,
            suspicious_ports_set,
            excluded_processes_set,
            blocked_ips_set,
            blocked_domains_set,
        }
    }

    /// Get access to the underlying configuration
    pub fn config(&self) -> &Configuration {
        &self.config
    }
}

impl ConfigurationProvider for OptimizedConfigurationProvider {
    fn is_sensitive_file(&self, filename: &str) -> bool {
        // Check exact filename match first
        if self.sensitive_files_set.contains(filename) {
            return true;
        }

        // Check file extension
        if let Some(extension_pos) = filename.rfind('.') {
            let extension = &filename[extension_pos..];
            if self.sensitive_extensions_set.contains(extension) {
                return true;
            }
        }

        false
    }

    fn is_suspicious_port(&self, port: u16) -> bool {
        self.suspicious_ports_set.contains(&port)
    }

    fn should_monitor_process(&self, process_name: &str) -> bool {
        !self.excluded_processes_set.contains(process_name)
    }

    fn get_security_config(&self) -> &SecurityConfig {
        &self.config.security
    }

    fn is_ip_blocked(&self, ip: &str) -> bool {
        self.blocked_ips_set.contains(ip)
    }

    fn is_domain_blocked(&self, domain: &str) -> bool {
        self.blocked_domains_set.contains(domain)
    }
}

// Also implement the trait directly for Configuration for simpler cases
impl ConfigurationProvider for Configuration {
    fn is_sensitive_file(&self, filename: &str) -> bool {
        // Check exact filename match
        if self
            .security
            .file_monitoring
            .sensitive_files
            .contains(&filename.to_string())
        {
            return true;
        }

        // Check file extension
        if let Some(extension_pos) = filename.rfind('.') {
            let extension = &filename[extension_pos..];
            if self
                .security
                .file_monitoring
                .sensitive_extensions
                .contains(&extension.to_string())
            {
                return true;
            }
        }

        false
    }

    fn is_suspicious_port(&self, port: u16) -> bool {
        self.security
            .network_monitoring
            .suspicious_ports
            .contains(&port)
    }

    fn should_monitor_process(&self, process_name: &str) -> bool {
        !self
            .security
            .memory_monitoring
            .excluded_processes
            .contains(&process_name.to_string())
    }

    fn get_security_config(&self) -> &SecurityConfig {
        &self.security
    }

    fn is_ip_blocked(&self, ip: &str) -> bool {
        self.security
            .network_monitoring
            .blocked_ips
            .contains(&ip.to_string())
    }

    fn is_domain_blocked(&self, domain: &str) -> bool {
        self.security.blocked_domains.contains(&domain.to_string())
    }
}
