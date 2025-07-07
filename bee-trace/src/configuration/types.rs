//! Configuration type definitions
//!
//! Defines the core configuration structures used throughout the system.

use crate::errors::ProbeType;
use serde::{Deserialize, Serialize};
use std::time::Duration;

#[derive(Debug, Clone, PartialEq, Serialize, Deserialize)]
pub struct Monitoring {
    pub probe_types: Vec<ProbeType>,
    pub duration: Option<Duration>,
    pub command_filter: Option<String>,
    pub security_mode: bool,
}

#[derive(Debug, Clone, PartialEq, Serialize, Deserialize, Default)]
pub struct Output {
    pub verbose: bool,
}

#[derive(Debug, Clone, PartialEq, Serialize, Deserialize)]
pub struct Security {
    pub file_monitoring: FileMonitoring,
    pub network_monitoring: NetworkMonitoring,
    pub memory_monitoring: MemoryMonitoring,
    pub blocked_domains: Vec<String>,
}

#[derive(Debug, Clone, PartialEq, Serialize, Deserialize)]
pub struct FileMonitoring {
    pub sensitive_files: Vec<String>,
    pub sensitive_extensions: Vec<String>,
    pub watch_directories: Vec<String>,
    pub exclude_patterns: Vec<String>,
}

#[derive(Debug, Clone, PartialEq, Serialize, Deserialize)]
pub struct NetworkMonitoring {
    pub suspicious_ports: Vec<u16>,
    pub safe_ports: Vec<u16>,
    pub blocked_ips: Vec<String>,
    pub allowed_ips: Vec<String>,
}

#[derive(Debug, Clone, PartialEq, Serialize, Deserialize)]
pub struct MemoryMonitoring {
    pub monitor_ptrace: bool,
    pub monitor_process_vm: bool,
    pub excluded_processes: Vec<String>,
}

#[derive(Debug, Clone, PartialEq, Serialize, Deserialize, Default)]
pub struct Runtime {}

#[derive(Debug, Clone, PartialEq, Serialize, Deserialize)]
pub enum SeverityLevel {
    Low,
    Medium,
    High,
    Critical,
}

impl Default for Monitoring {
    fn default() -> Self {
        Self {
            probe_types: vec![ProbeType::FileMonitor],
            duration: None,
            command_filter: None,
            security_mode: false,
        }
    }
}

impl Default for Security {
    fn default() -> Self {
        Self {
            file_monitoring: FileMonitoring {
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
            network_monitoring: NetworkMonitoring {
                suspicious_ports: vec![22, 23, 3389, 5900, 6000],
                safe_ports: vec![80, 443, 53, 993, 995, 587, 465],
                blocked_ips: vec![],
                allowed_ips: vec!["127.0.0.1".to_string(), "::1".to_string()],
            },
            memory_monitoring: MemoryMonitoring {
                monitor_ptrace: true,
                monitor_process_vm: true,
                excluded_processes: vec![
                    "gdb".to_string(),
                    "strace".to_string(),
                    "ltrace".to_string(),
                ],
            },
            blocked_domains: vec![],
        }
    }
}
