//! Configuration type definitions
//!
//! Defines the core configuration structures used throughout the system.

use crate::errors::ProbeType;
use std::path::PathBuf;
use std::time::Duration;

#[derive(Debug, Clone, PartialEq)]
pub struct MonitoringConfig {
    pub probe_types: Vec<ProbeType>,
    pub duration: Option<Duration>,
    pub command_filter: Option<String>,
    pub security_mode: bool,
    pub exclude_pids: Vec<u32>,
    pub include_pids: Vec<u32>,
    pub cpu_limit: Option<u8>,
}

#[derive(Debug, Clone, PartialEq)]
pub struct OutputConfig {
    pub verbose: bool,
    pub quiet: bool,
    pub no_header: bool,
    pub output_file: Option<PathBuf>,
    pub format: OutputFormat,
    pub timestamp_format: TimestampFormat,
    pub filter_severity: Option<SeverityLevel>,
}

#[derive(Debug, Clone, PartialEq, Default)]
pub struct SecurityConfig {
    pub blocked_ips: Vec<String>,
    pub blocked_domains: Vec<String>,
    pub watch_files: Vec<String>,
    pub secret_env_patterns: Vec<String>,
}

#[derive(Debug, Clone, PartialEq)]
pub struct RuntimeConfig {
    pub config_file: Option<PathBuf>,
    pub working_directory: PathBuf,
}

#[derive(Debug, Clone, PartialEq)]
pub enum OutputFormat {
    Json,
    Markdown,
    Csv,
}

#[derive(Debug, Clone, PartialEq)]
pub enum TimestampFormat {
    Unix,
    Iso8601,
    Relative,
}

#[derive(Debug, Clone, PartialEq)]
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

impl Default for RuntimeConfig {
    fn default() -> Self {
        Self {
            config_file: None,
            working_directory: std::env::current_dir().unwrap_or_else(|_| PathBuf::from(".")),
        }
    }
}
