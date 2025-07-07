//! Unified Configuration System
//!
//! This module provides a unified configuration interface that combines settings from
//! multiple sources (CLI arguments, configuration files, environment variables) into
//! a single, validated configuration object with optimized runtime performance.
//!
//! # Basic Usage
//!
//! ```rust
//! use bee_trace::configuration::Configuration;
//!
//! // Create configuration using builder pattern
//! let config = Configuration::builder()
//!     .from_cli_args(&["--probe-type", "all", "--verbose"])
//!     .unwrap()
//!     .build()
//!     .unwrap();
//!
//! // Use optimized security checks (O(1) lookups)
//! if config.is_sensitive_file("id_rsa") {
//!     println!("Sensitive file detected!");
//! }
//!
//! if config.is_suspicious_port(22) {
//!     println!("Suspicious port access!");
//! }
//! ```
//!
//! # Performance
//!
//! The configuration system uses lazy-loaded HashSet caches for O(1) security
//! lookups, making it suitable for high-frequency event processing without
//! performance penalties.

pub mod builder;
pub mod types;

pub use builder::ConfigurationBuilder;
pub use types::*;

use crate::errors::{BeeTraceError, ProbeType};
use std::collections::HashSet;
use std::sync::OnceLock;

/// Unified configuration with optimized security lookups
///
/// This struct combines configuration from multiple sources and provides
/// high-performance security checking methods. Internal caching ensures
/// O(1) lookup performance for security-critical operations.
///
/// # Examples
///
/// ```rust
/// use bee_trace::configuration::Configuration;
/// let config = Configuration::builder()
///     .from_cli_args(&["--probe-type", "all", "--verbose"])
///     .unwrap()
///     .build()
///     .unwrap();
///
/// // Fast security checks (internally cached)
/// assert!(config.is_sensitive_file("credentials.json"));
/// assert!(config.is_suspicious_port(22));
/// assert!(!config.should_monitor_process("gdb"));
/// ```
#[derive(Debug, Clone, PartialEq)]
pub struct Configuration {
    pub monitoring: Monitoring,
    pub output: Output,
    pub security: Security,
    pub runtime: Runtime,
    #[doc(hidden)]
    cached_sensitive_files: OnceLock<HashSet<String>>,
    #[doc(hidden)]
    cached_sensitive_extensions: OnceLock<HashSet<String>>,
    #[doc(hidden)]
    cached_suspicious_ports: OnceLock<HashSet<u16>>,
    #[doc(hidden)]
    cached_excluded_processes: OnceLock<HashSet<String>>,
    #[doc(hidden)]
    cached_blocked_ips: OnceLock<HashSet<String>>,
    #[doc(hidden)]
    cached_blocked_domains: OnceLock<HashSet<String>>,
}

impl Configuration {
    /// Create a new builder for configuration
    pub fn builder() -> ConfigurationBuilder {
        ConfigurationBuilder::new()
    }

    /// Validate the configuration for consistency and correctness
    pub fn validate(&self) -> Result<(), BeeTraceError> {
        // Validate probe types are specified
        if self.monitoring.probe_types.is_empty() {
            return Err(BeeTraceError::ConfigError {
                message: "At least one probe type must be specified".to_string(),
            });
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

    /// Check if a file path is considered sensitive
    ///
    /// Uses optimized O(1) lookup with lazy-loaded HashSet cache.
    /// Checks both exact filename matches and file extensions.
    ///
    /// # Examples
    ///
    /// ```rust
    /// use bee_trace::configuration::Configuration;
    /// # fn main() -> Result<(), Box<dyn std::error::Error>> {
    /// let config = Configuration::builder().build()?;
    /// assert!(config.is_sensitive_file("id_rsa"));        // exact match
    /// assert!(config.is_sensitive_file("cert.pem"));      // extension match
    /// assert!(!config.is_sensitive_file("readme.txt"));   // no match
    /// # Ok(())
    /// # }
    /// ```
    pub fn is_sensitive_file(&self, path: &str) -> bool {
        let cache = self.cached_sensitive_files.get_or_init(|| {
            self.security
                .file_monitoring
                .sensitive_files
                .iter()
                .cloned()
                .collect()
        });
        cache.contains(path) || self.is_sensitive_by_extension(path)
    }

    /// Check if a file has a sensitive extension
    fn is_sensitive_by_extension(&self, path: &str) -> bool {
        let cache = self.cached_sensitive_extensions.get_or_init(|| {
            self.security
                .file_monitoring
                .sensitive_extensions
                .iter()
                .cloned()
                .collect()
        });

        if let Some(extension_pos) = path.rfind('.') {
            let extension = &path[extension_pos..];
            cache.contains(extension)
        } else {
            false
        }
    }

    /// Check if a port is considered suspicious
    ///
    /// Uses optimized O(1) lookup for high-frequency network monitoring.
    ///
    /// # Examples
    ///
    /// ```rust
    /// use bee_trace::configuration::Configuration;
    /// # fn main() -> Result<(), Box<dyn std::error::Error>> {
    /// let config = Configuration::builder().build()?;
    /// assert!(config.is_suspicious_port(22));    // SSH
    /// assert!(config.is_suspicious_port(3389));  // RDP
    /// assert!(!config.is_suspicious_port(443));  // HTTPS (safe)
    /// # Ok(())
    /// # }
    /// ```
    pub fn is_suspicious_port(&self, port: u16) -> bool {
        let cache = self.cached_suspicious_ports.get_or_init(|| {
            self.security
                .network_monitoring
                .suspicious_ports
                .iter()
                .cloned()
                .collect()
        });
        cache.contains(&port)
    }

    /// Check if a process should be monitored (not excluded)
    ///
    /// Returns `false` for development tools like debuggers to reduce noise.
    /// Uses optimized O(1) lookup for process filtering.
    ///
    /// # Examples
    ///
    /// ```rust
    /// use bee_trace::configuration::Configuration;
    /// # fn main() -> Result<(), Box<dyn std::error::Error>> {
    /// let config = Configuration::builder().build()?;
    /// assert!(!config.should_monitor_process("gdb"));      // excluded
    /// assert!(!config.should_monitor_process("strace"));   // excluded  
    /// assert!(config.should_monitor_process("malware"));   // monitored
    /// # Ok(())
    /// # }
    /// ```
    pub fn should_monitor_process(&self, process: &str) -> bool {
        let cache = self.cached_excluded_processes.get_or_init(|| {
            self.security
                .memory_monitoring
                .excluded_processes
                .iter()
                .cloned()
                .collect()
        });
        !cache.contains(process)
    }

    /// Get access to the security configuration
    pub fn security_config(&self) -> &Security {
        &self.security
    }

    /// Check if an IP address is blocked
    pub fn is_ip_blocked(&self, ip: &str) -> bool {
        let cache = self.cached_blocked_ips.get_or_init(|| {
            self.security
                .network_monitoring
                .blocked_ips
                .iter()
                .cloned()
                .collect()
        });
        cache.contains(ip)
    }

    /// Check if a domain is blocked
    pub fn is_domain_blocked(&self, domain: &str) -> bool {
        let cache = self
            .cached_blocked_domains
            .get_or_init(|| self.security.blocked_domains.iter().cloned().collect());
        cache.contains(domain)
    }
}
