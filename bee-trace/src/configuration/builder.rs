//! Configuration Builder
//!
//! Provides a builder pattern for constructing Configuration instances
//! from multiple sources with proper validation.

use super::{Configuration, MonitoringConfig, OutputConfig, RuntimeConfig, SecurityConfig};
use crate::errors::{BeeTraceError, ProbeType};
use std::time::Duration;

/// Builder for creating Configuration instances
///
/// Supports fluent API and multiple sources:
/// - CLI arguments
/// - Configuration files  
/// - Environment variables
/// - Defaults
#[derive(Debug)]
pub struct ConfigurationBuilder {
    monitoring: MonitoringConfig,
    output: OutputConfig,
    security: SecurityConfig,
    runtime: RuntimeConfig,
}

impl ConfigurationBuilder {
    pub fn new() -> Self {
        Self {
            monitoring: MonitoringConfig::default(),
            output: OutputConfig::default(),
            security: SecurityConfig::default(),
            runtime: RuntimeConfig::default(),
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

    /// Configure from YAML configuration file
    pub fn from_config_file<P: AsRef<std::path::Path>>(
        mut self,
        path: P,
    ) -> Result<Self, BeeTraceError> {
        // Store the path for now - actual YAML parsing can be added later
        self.runtime.config_file = Some(path.as_ref().to_path_buf());
        Ok(self)
    }

    /// Configure from environment variables
    pub fn from_environment(self) -> Result<Self, BeeTraceError> {
        // Environment variable support can be added here later
        Ok(self)
    }

    /// Build the final configuration
    pub fn build(self) -> Result<Configuration, BeeTraceError> {
        let config = Configuration {
            monitoring: self.monitoring,
            output: self.output,
            security: self.security,
            runtime: self.runtime,
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
