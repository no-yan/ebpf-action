//! Legacy configuration module - DEPRECATED
//! Use bee_trace::configuration instead

#![allow(deprecated)]

use std::{fs, net::IpAddr, path::Path};

use serde::{Deserialize, Serialize};

#[deprecated(
    since = "0.2.0",
    note = "Use `bee_trace::configuration::Configuration` instead. This legacy configuration system will be removed in v0.3.0. See docs/05-technical-details/configuration-migration.md for migration guide."
)]
#[derive(Debug, Clone, Serialize, Deserialize, Default)]
pub struct Config {
    #[serde(default)]
    pub monitoring: MonitoringConfig,
    #[serde(default)]
    pub output: OutputConfig,
    #[serde(default)]
    pub security: SecurityConfig,
}

#[deprecated(
    since = "0.2.0",
    note = "Use `bee_trace::configuration::MonitoringConfig` instead. This legacy configuration system will be removed in v0.3.0."
)]
#[derive(Debug, Clone, Serialize, Deserialize, Default)]
pub struct MonitoringConfig {
    pub default_duration_seconds: Option<u64>,
    pub security_mode: Option<bool>,
    pub min_severity: Option<String>,
    pub exclude_pids: Option<Vec<u32>>,
    pub include_pids: Option<Vec<u32>>,
    pub cpu_limit: Option<u8>,
}

#[deprecated(
    since = "0.2.0",
    note = "Use `bee_trace::configuration::OutputConfig` instead. This legacy configuration system will be removed in v0.3.0."
)]
#[derive(Debug, Clone, Serialize, Deserialize, Default)]
pub struct OutputConfig {
    pub verbose: Option<bool>,
    pub format: Option<String>,
    pub no_header: Option<bool>,
}

#[deprecated(
    since = "0.2.0",
    note = "Use `bee_trace::configuration::SecurityConfig` instead. This legacy configuration system will be removed in v0.3.0."
)]
#[derive(Debug, Clone, Serialize, Deserialize, Default)]
pub struct SecurityConfig {
    #[serde(default)]
    pub network: NetworkConfig,
    #[serde(default)]
    pub files: FileConfig,
}

#[deprecated(
    since = "0.2.0",
    note = "Use `bee_trace::configuration::NetworkMonitoringConfig` instead. This legacy configuration system will be removed in v0.3.0."
)]
#[derive(Debug, Clone, Serialize, Deserialize, Default)]
pub struct NetworkConfig {
    #[serde(default)]
    pub block: Vec<String>,
}

#[deprecated(
    since = "0.2.0",
    note = "Use `bee_trace::configuration::FileMonitoringConfig` instead. This legacy configuration system will be removed in v0.3.0."
)]
#[derive(Debug, Clone, Serialize, Deserialize, Default)]
pub struct FileConfig {
    #[serde(default)]
    pub watch_read: Vec<String>,
}

impl Config {
    pub fn from_file<P: AsRef<Path>>(path: P) -> Result<Self, Box<dyn std::error::Error>> {
        let content = fs::read_to_string(path)?;
        Self::from_yaml_str(&content)
    }

    pub fn from_yaml_str(yaml_str: &str) -> Result<Self, Box<dyn std::error::Error>> {
        let config: Config = serde_yaml::from_str(yaml_str)?;
        Ok(config)
    }
}

impl SecurityConfig {
    pub fn from_file<P: AsRef<Path>>(path: P) -> Result<Self, Box<dyn std::error::Error>> {
        let content = fs::read_to_string(path)?;
        Self::from_yaml_str(&content)
    }

    pub fn from_yaml_str(yaml_str: &str) -> Result<Self, Box<dyn std::error::Error>> {
        let config: SecurityConfig = serde_yaml::from_str(yaml_str)?;
        Ok(config)
    }

    pub fn get_valid_blocked_ips(&self) -> Vec<IpAddr> {
        self.network
            .block
            .iter()
            .filter_map(|addr_str| addr_str.parse::<IpAddr>().ok())
            .collect()
    }

    pub fn should_monitor_file(&self, file_path: &str) -> bool {
        for pattern in &self.files.watch_read {
            if self.matches_glob_pattern(file_path, pattern) {
                return true;
            }
        }
        false
    }

    pub fn is_domain_blocked(&self, domain: &str) -> bool {
        for blocked_entry in &self.network.block {
            // Skip IP addresses, only check domains
            if blocked_entry.parse::<IpAddr>().is_ok() {
                continue;
            }

            if self.matches_domain_pattern(domain, blocked_entry) {
                return true;
            }
        }
        false
    }

    fn matches_glob_pattern(&self, path: &str, pattern: &str) -> bool {
        // Simple glob pattern matching implementation
        if pattern == "**/*" {
            return true;
        }

        // Handle exact matches
        if pattern == path {
            return true;
        }

        // Handle extension patterns like "*.pem"
        if let Some(extension) = pattern.strip_prefix("*.") {
            return path.ends_with(&format!(".{}", extension));
        }

        // Handle recursive patterns like "**/*.pem"
        if let Some(suffix) = pattern.strip_prefix("**/") {
            if let Some(extension) = suffix.strip_prefix("*.") {
                return path.ends_with(&format!(".{}", extension));
            } else {
                return path.ends_with(suffix) || path.contains(&format!("/{}", suffix));
            }
        }

        // Handle directory patterns like "/etc/ssl/**"
        if let Some(prefix) = pattern.strip_suffix("/**") {
            return path.starts_with(prefix);
        }

        // Handle simple filename matches
        if !pattern.contains('/') && !pattern.contains('*') {
            return path.ends_with(&format!("/{}", pattern)) || path == pattern;
        }

        false
    }

    fn matches_domain_pattern(&self, domain: &str, pattern: &str) -> bool {
        // Exact match
        if domain == pattern {
            return true;
        }

        // Wildcard subdomain match like "*.example.com"
        if let Some(base_domain) = pattern.strip_prefix("*.") {
            return domain.ends_with(base_domain) && domain != base_domain;
        }

        false
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    mod config_creation {
        use super::*;

        #[test]
        fn should_create_default_config() {
            let config = SecurityConfig::default();

            assert!(config.network.block.is_empty());
            assert!(config.files.watch_read.is_empty());
        }
    }

    mod glob_pattern_matching {
        use super::*;

        #[test]
        fn should_match_extension_patterns() {
            let config = SecurityConfig::default();

            assert!(config.matches_glob_pattern("file.pem", "*.pem"));
            assert!(config.matches_glob_pattern("/path/to/file.key", "*.key"));
            assert!(!config.matches_glob_pattern("file.txt", "*.pem"));
        }

        #[test]
        fn should_match_recursive_patterns() {
            let config = SecurityConfig::default();

            assert!(config.matches_glob_pattern("/deep/path/file.pem", "**/*.pem"));
            assert!(config.matches_glob_pattern("file.pem", "**/*.pem"));
            assert!(config.matches_glob_pattern("/home/user/.ssh/id_rsa", "**/id_rsa"));
        }

        #[test]
        fn should_match_directory_patterns() {
            let config = SecurityConfig::default();

            assert!(config.matches_glob_pattern("/etc/ssl/cert.pem", "/etc/ssl/**"));
            assert!(config.matches_glob_pattern("/etc/ssl/private/key.pem", "/etc/ssl/**"));
            assert!(!config.matches_glob_pattern("/var/log/app.log", "/etc/ssl/**"));
        }
    }

    mod domain_pattern_matching {
        use super::*;

        #[test]
        fn should_match_exact_domains() {
            let config = SecurityConfig::default();

            assert!(config.matches_domain_pattern("example.com", "example.com"));
            assert!(!config.matches_domain_pattern("other.com", "example.com"));
        }

        #[test]
        fn should_match_wildcard_subdomains() {
            let config = SecurityConfig::default();

            assert!(config.matches_domain_pattern("api.example.com", "*.example.com"));
            assert!(config.matches_domain_pattern("sub.example.com", "*.example.com"));
            assert!(!config.matches_domain_pattern("example.com", "*.example.com"));
            assert!(!config.matches_domain_pattern("other.com", "*.example.com"));
        }
    }
}
