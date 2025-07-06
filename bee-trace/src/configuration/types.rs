//! Configuration type definitions
//!
//! Defines the core configuration structures used throughout the system.

use crate::errors::ProbeType;
use serde::{Deserialize, Serialize};
use std::path::PathBuf;
use std::time::Duration;

#[derive(Debug, Clone, PartialEq, Serialize, Deserialize)]
pub struct MonitoringConfig {
    pub probe_types: Vec<ProbeType>,
    pub duration: Option<Duration>,
    pub command_filter: Option<String>,
    pub security_mode: bool,
    pub exclude_pids: Vec<u32>,
    pub include_pids: Vec<u32>,
    pub cpu_limit: Option<u8>,
}

#[derive(Debug, Clone, PartialEq, Serialize, Deserialize)]
pub struct OutputConfig {
    pub verbose: bool,
    pub quiet: bool,
    pub no_header: bool,
    pub output_file: Option<PathBuf>,
    pub format: OutputFormat,
    pub timestamp_format: TimestampFormat,
    pub filter_severity: Option<SeverityLevel>,
}

#[derive(Debug, Clone, PartialEq, Serialize, Deserialize)]
pub struct SecurityConfig {
    pub file_monitoring: FileMonitoringConfig,
    pub network_monitoring: NetworkMonitoringConfig,
    pub memory_monitoring: MemoryMonitoringConfig,
    pub blocked_domains: Vec<String>,
    pub watch_files: Vec<String>,
    pub secret_env_patterns: Vec<String>,
}

#[derive(Debug, Clone, PartialEq, Serialize, Deserialize)]
pub struct FileMonitoringConfig {
    pub sensitive_files: Vec<String>,
    pub sensitive_extensions: Vec<String>,
    pub watch_directories: Vec<String>,
    pub exclude_patterns: Vec<String>,
}

#[derive(Debug, Clone, PartialEq, Serialize, Deserialize)]
pub struct NetworkMonitoringConfig {
    pub suspicious_ports: Vec<u16>,
    pub safe_ports: Vec<u16>,
    pub blocked_ips: Vec<String>,
    pub allowed_ips: Vec<String>,
}

#[derive(Debug, Clone, PartialEq, Serialize, Deserialize)]
pub struct MemoryMonitoringConfig {
    pub monitor_ptrace: bool,
    pub monitor_process_vm: bool,
    pub excluded_processes: Vec<String>,
}

#[derive(Debug, Clone, PartialEq, Serialize, Deserialize)]
pub struct RuntimeConfig {
    pub config_file: Option<PathBuf>,
    pub working_directory: PathBuf,
}

#[derive(Debug, Clone, PartialEq, Serialize, Deserialize)]
pub enum OutputFormat {
    Json,
    Markdown,
    Csv,
}

#[derive(Debug, Clone, PartialEq, Serialize, Deserialize)]
pub enum TimestampFormat {
    Unix,
    Iso8601,
    Relative,
}

#[derive(Debug, Clone, PartialEq, Serialize, Deserialize)]
pub enum SeverityLevel {
    Low,
    Medium,
    High,
    Critical,
}

impl Default for MonitoringConfig {
    fn default() -> Self {
        Self {
            probe_types: vec![ProbeType::FileMonitor],
            duration: None,
            command_filter: None,
            security_mode: false,
            exclude_pids: vec![],
            include_pids: vec![],
            cpu_limit: None,
        }
    }
}

impl Default for OutputConfig {
    fn default() -> Self {
        Self {
            verbose: false,
            quiet: false,
            no_header: false,
            output_file: None,
            format: OutputFormat::Json,
            timestamp_format: TimestampFormat::Iso8601,
            filter_severity: None,
        }
    }
}

impl Default for SecurityConfig {
    fn default() -> Self {
        Self {
            file_monitoring: FileMonitoringConfig {
                sensitive_files: vec![
                    "credentials.json".to_string(),
                    "id_rsa".to_string(),
                    "id_dsa".to_string(),
                    "id_ecdsa".to_string(),
                    "id_ed25519".to_string(),
                    ".env".to_string(),
                    "config.json".to_string(),
                    "secrets.yaml".to_string(),
                    "secrets.yml".to_string(),
                    "private.key".to_string(),
                ],
                sensitive_extensions: vec![
                    ".pem".to_string(),
                    ".key".to_string(),
                    ".p12".to_string(),
                    ".pfx".to_string(),
                    ".crt".to_string(),
                    ".cer".to_string(),
                    ".der".to_string(),
                ],
                watch_directories: vec![
                    "/etc".to_string(),
                    "/home".to_string(),
                    "/root".to_string(),
                ],
                exclude_patterns: vec!["/tmp".to_string(), "/var/log".to_string()],
            },
            network_monitoring: NetworkMonitoringConfig {
                suspicious_ports: vec![22, 23, 3389, 5900, 6000],
                safe_ports: vec![80, 443, 53, 993, 995, 587, 465],
                blocked_ips: vec![],
                allowed_ips: vec!["127.0.0.1".to_string(), "::1".to_string()],
            },
            memory_monitoring: MemoryMonitoringConfig {
                monitor_ptrace: true,
                monitor_process_vm: true,
                excluded_processes: vec![
                    "gdb".to_string(),
                    "strace".to_string(),
                    "ltrace".to_string(),
                ],
            },
            blocked_domains: vec![],
            watch_files: vec![],
            secret_env_patterns: vec![],
        }
    }
}

impl Default for RuntimeConfig {
    fn default() -> Self {
        Self {
            config_file: None,
            working_directory: std::env::current_dir().unwrap_or_else(|_| PathBuf::from(".")),
        }
    }
}

/// Unified configuration provider trait for security monitoring
///
/// Replaces the legacy SecurityConfigProvider trait with optimized lookups
/// and unified configuration access patterns.
pub trait ConfigurationProvider {
    /// Check if a filename is considered sensitive
    fn is_sensitive_file(&self, filename: &str) -> bool;

    /// Check if a port is considered suspicious
    fn is_suspicious_port(&self, port: u16) -> bool;

    /// Check if a process should be monitored (not excluded)
    fn should_monitor_process(&self, process_name: &str) -> bool;

    /// Get access to the underlying security configuration
    fn get_security_config(&self) -> &SecurityConfig;

    /// Check if an IP address is blocked
    fn is_ip_blocked(&self, ip: &str) -> bool;

    /// Check if a domain is blocked
    fn is_domain_blocked(&self, domain: &str) -> bool;
}
