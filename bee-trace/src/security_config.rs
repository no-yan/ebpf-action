//! Legacy security configuration module - DEPRECATED
//! Use bee_trace::configuration instead

#![allow(deprecated)]

use serde::{Deserialize, Serialize};
use std::collections::HashSet;
use std::fs;
use std::path::Path;

#[deprecated(
    since = "0.2.0",
    note = "Use `bee_trace::configuration::SecurityConfig` instead. This legacy security configuration system will be removed in v0.3.0. See docs/05-technical-details/configuration-migration.md for migration guide."
)]
#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct SecurityConfig {
    pub file_monitoring: FileMonitoringConfig,
    pub network_monitoring: NetworkMonitoringConfig,
    pub memory_monitoring: MemoryMonitoringConfig,
}

#[deprecated(
    since = "0.2.0",
    note = "Use `bee_trace::configuration::FileMonitoringConfig` instead. This legacy configuration system will be removed in v0.3.0."
)]
#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct FileMonitoringConfig {
    pub sensitive_files: Vec<String>,
    pub sensitive_extensions: Vec<String>,
    pub watch_directories: Vec<String>,
    pub exclude_patterns: Vec<String>,
}

#[deprecated(
    since = "0.2.0",
    note = "Use `bee_trace::configuration::NetworkMonitoringConfig` instead. This legacy configuration system will be removed in v0.3.0."
)]
#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct NetworkMonitoringConfig {
    pub suspicious_ports: Vec<u16>,
    pub safe_ports: Vec<u16>,
    pub blocked_ips: Vec<String>,
    pub allowed_ips: Vec<String>,
}

#[deprecated(
    since = "0.2.0",
    note = "Use `bee_trace::configuration::MemoryMonitoringConfig` instead. This legacy configuration system will be removed in v0.3.0."
)]
#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct MemoryMonitoringConfig {
    pub monitor_ptrace: bool,
    pub monitor_process_vm: bool,
    pub excluded_processes: Vec<String>,
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
        }
    }
}

#[deprecated(
    since = "0.2.0",
    note = "Use `bee_trace::configuration::ConfigurationProvider` instead. This legacy trait will be removed in v0.3.0. The new trait provides unified configuration access with optimized HashSet lookups."
)]
pub trait SecurityConfigProvider {
    fn get_config(&self) -> &SecurityConfig;
    fn is_sensitive_file(&self, filename: &str) -> bool;
    fn is_suspicious_port(&self, port: u16) -> bool;
    fn should_monitor_process(&self, process_name: &str) -> bool;
}

#[deprecated(
    since = "0.2.0",
    note = "Use `bee_trace::configuration::OptimizedConfigurationProvider` instead. This legacy provider will be removed in v0.3.0. The new provider offers better performance and unified configuration access."
)]
pub struct FileBasedConfigProvider {
    config: SecurityConfig,
    sensitive_files_set: HashSet<String>,
    sensitive_extensions_set: HashSet<String>,
}

impl FileBasedConfigProvider {
    pub fn new() -> Self {
        let config = SecurityConfig::default();
        let sensitive_files_set: HashSet<String> = config
            .file_monitoring
            .sensitive_files
            .iter()
            .cloned()
            .collect();
        let sensitive_extensions_set: HashSet<String> = config
            .file_monitoring
            .sensitive_extensions
            .iter()
            .cloned()
            .collect();

        Self {
            config,
            sensitive_files_set,
            sensitive_extensions_set,
        }
    }
    pub fn from_file(path: &Path) -> anyhow::Result<Self> {
        let content = fs::read_to_string(path)?;
        let config: SecurityConfig = if path.extension().and_then(|s| s.to_str()) == Some("toml") {
            toml::from_str(&content)?
        } else {
            serde_json::from_str(&content)?
        };

        let sensitive_files_set: HashSet<String> = config
            .file_monitoring
            .sensitive_files
            .iter()
            .cloned()
            .collect();
        let sensitive_extensions_set: HashSet<String> = config
            .file_monitoring
            .sensitive_extensions
            .iter()
            .cloned()
            .collect();

        Ok(Self {
            config,
            sensitive_files_set,
            sensitive_extensions_set,
        })
    }

    pub fn save_to_file(&self, path: &Path) -> anyhow::Result<()> {
        let content = if path.extension().and_then(|s| s.to_str()) == Some("toml") {
            toml::to_string_pretty(&self.config)?
        } else {
            serde_json::to_string_pretty(&self.config)?
        };

        fs::write(path, content)?;
        Ok(())
    }
}

impl SecurityConfigProvider for FileBasedConfigProvider {
    fn get_config(&self) -> &SecurityConfig {
        &self.config
    }

    fn is_sensitive_file(&self, filename: &str) -> bool {
        if self.sensitive_files_set.contains(filename) {
            return true;
        }

        if let Some(extension_pos) = filename.rfind('.') {
            let extension = &filename[extension_pos..];
            if self.sensitive_extensions_set.contains(extension) {
                return true;
            }
        }

        false
    }

    fn is_suspicious_port(&self, port: u16) -> bool {
        self.config
            .network_monitoring
            .suspicious_ports
            .contains(&port)
    }

    fn should_monitor_process(&self, process_name: &str) -> bool {
        !self
            .config
            .memory_monitoring
            .excluded_processes
            .contains(&process_name.to_string())
    }
}

impl Default for FileBasedConfigProvider {
    fn default() -> Self {
        Self::new()
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use tempfile::NamedTempFile;

    #[test]
    fn should_create_default_config() {
        let config = SecurityConfig::default();
        assert!(!config.file_monitoring.sensitive_files.is_empty());
        assert!(!config.network_monitoring.suspicious_ports.is_empty());
        assert!(config.memory_monitoring.monitor_ptrace);
    }

    #[test]
    fn should_detect_sensitive_files() {
        let provider = FileBasedConfigProvider::new();

        assert!(provider.is_sensitive_file("id_rsa"));
        assert!(provider.is_sensitive_file("credentials.json"));
        assert!(provider.is_sensitive_file("test.pem"));
        assert!(provider.is_sensitive_file("cert.key"));
        assert!(!provider.is_sensitive_file("regular.txt"));
    }

    #[test]
    fn should_detect_suspicious_ports() {
        let provider = FileBasedConfigProvider::new();

        assert!(provider.is_suspicious_port(22));
        assert!(provider.is_suspicious_port(3389));
        assert!(!provider.is_suspicious_port(80));
        assert!(!provider.is_suspicious_port(443));
    }

    #[test]
    fn should_save_and_load_config() -> anyhow::Result<()> {
        let original_provider = FileBasedConfigProvider::new();
        let temp_file = NamedTempFile::new()?;

        original_provider.save_to_file(temp_file.path())?;
        let loaded_provider = FileBasedConfigProvider::from_file(temp_file.path())?;

        assert_eq!(
            original_provider.config.file_monitoring.sensitive_files,
            loaded_provider.config.file_monitoring.sensitive_files
        );

        Ok(())
    }

    #[test]
    fn should_handle_process_monitoring_exclusions() {
        let provider = FileBasedConfigProvider::new();

        assert!(!provider.should_monitor_process("gdb"));
        assert!(!provider.should_monitor_process("strace"));
        assert!(provider.should_monitor_process("malicious_process"));
    }
}
