//! Configuration Builder
//!
//! Provides a builder pattern for constructing Configuration instances
//! from multiple sources with proper validation.

use super::{Configuration, Monitoring, Output, Runtime, Security};
use crate::errors::{BeeTraceError, ProbeType};
use std::time::Duration;

/// Builder for creating Configuration instances
///
/// Simplified builder that supports:
/// - CLI arguments
/// - Defaults
#[derive(Debug)]
pub struct ConfigurationBuilder {
    monitoring: Monitoring,
    output: Output,
    security: Security,
    runtime: Runtime,
}

impl ConfigurationBuilder {
    pub fn new() -> Self {
        Self {
            monitoring: Monitoring::default(),
            output: Output::default(),
            security: Security::default(),
            runtime: Runtime::default(),
        }
    }

    /// Configure from CLI arguments (Vec<String> format for testing)
    pub fn from_cli_args(mut self, args: &[&str]) -> Result<Self, BeeTraceError> {
        let mut i = 0;
        while i < args.len() {
            match args[i] {
                "--probe-type" | "-p" => {
                    if i + 1 < args.len() {
                        match args[i + 1] {
                            "file_monitor" => {
                                self.monitoring.probe_types = vec![ProbeType::FileMonitor]
                            }
                            "network_monitor" => {
                                self.monitoring.probe_types = vec![ProbeType::NetworkMonitor]
                            }
                            "memory_monitor" => {
                                self.monitoring.probe_types = vec![ProbeType::MemoryMonitor]
                            }
                            "all" => self.monitoring.probe_types = ProbeType::all(),
                            _ => {
                                return Err(BeeTraceError::InvalidProbeType {
                                    probe_type: args[i + 1].to_string(),
                                    valid_types: vec![
                                        "file_monitor".to_string(),
                                        "network_monitor".to_string(),
                                        "memory_monitor".to_string(),
                                        "all".to_string(),
                                    ],
                                })
                            }
                        }
                        i += 2;
                    } else {
                        return Err(BeeTraceError::ConfigError {
                            message: "Missing value for --probe-type".to_string(),
                        });
                    }
                }
                "--duration" | "-d" => {
                    if i + 1 < args.len() {
                        let duration_secs: u64 =
                            args[i + 1]
                                .parse()
                                .map_err(|_| BeeTraceError::ConfigError {
                                    message: format!("Invalid duration: {}", args[i + 1]),
                                })?;
                        self.monitoring.duration = Some(Duration::from_secs(duration_secs));
                        i += 2;
                    } else {
                        return Err(BeeTraceError::ConfigError {
                            message: "Missing value for --duration".to_string(),
                        });
                    }
                }
                "--verbose" | "-v" => {
                    self.output.verbose = true;
                    i += 1;
                }
                "--security-mode" => {
                    self.monitoring.security_mode = true;
                    i += 1;
                }
                "--command" | "-c" => {
                    if i + 1 < args.len() {
                        self.monitoring.command_filter = Some(args[i + 1].to_string());
                        i += 2;
                    } else {
                        return Err(BeeTraceError::ConfigError {
                            message: "Missing value for --command".to_string(),
                        });
                    }
                }
                _ => {
                    i += 1; // Skip unknown arguments for now
                }
            }
        }

        Ok(self)
    }

    /// Build the final configuration
    pub fn build(self) -> Result<Configuration, BeeTraceError> {
        let config = Configuration {
            monitoring: self.monitoring,
            output: self.output,
            security: self.security,
            runtime: self.runtime,
            cached_sensitive_files: Default::default(),
            cached_sensitive_extensions: Default::default(),
            cached_suspicious_ports: Default::default(),
            cached_excluded_processes: Default::default(),
            cached_blocked_ips: Default::default(),
            cached_blocked_domains: Default::default(),
        };

        config.validate()?;
        Ok(config)
    }
}

impl Default for ConfigurationBuilder {
    fn default() -> Self {
        Self::new()
    }
}
