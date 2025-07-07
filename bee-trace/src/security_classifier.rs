use crate::configuration::ConfigurationProvider;
use crate::SecurityEvent;
use bee_trace_common::AccessType;

#[derive(Debug, Clone, PartialEq)]
pub enum SeverityLevel {
    Low,
    Medium,
    High,
    Critical,
}

impl SeverityLevel {
    pub fn as_str(&self) -> &str {
        match self {
            SeverityLevel::Low => "low",
            SeverityLevel::Medium => "medium",
            SeverityLevel::High => "high",
            SeverityLevel::Critical => "critical",
        }
    }
}

#[derive(Debug, Clone)]
pub struct SecurityClassification {
    pub severity: SeverityLevel,
    pub category: String,
    pub description: String,
    pub risk_score: u8, // 0-100
}

pub trait SecurityEventClassifier {
    fn classify(&self, event: &SecurityEvent) -> SecurityClassification;
    fn should_alert(&self, classification: &SecurityClassification) -> bool;
}

pub struct ConfigurableSecurityClassifier<T: ConfigurationProvider> {
    config_provider: T,
    alert_threshold: SeverityLevel,
}

impl<T: ConfigurationProvider> ConfigurableSecurityClassifier<T> {
    pub fn new(config_provider: T, alert_threshold: SeverityLevel) -> Self {
        Self {
            config_provider,
            alert_threshold,
        }
    }

    fn classify_network_event(
        &self,
        event: &bee_trace_common::NetworkEvent,
    ) -> SecurityClassification {
        let dest_ip_str = event.dest_ip_as_str();
        let port = event.dest_port;

        // Check for suspicious ports first using unified provider
        if self.config_provider.is_suspicious_port(port) {
            return SecurityClassification {
                severity: SeverityLevel::High,
                category: "Suspicious Network Access".to_string(),
                description: format!(
                    "Connection to suspicious port {} ({})",
                    port,
                    event.protocol_as_str()
                ),
                risk_score: 85,
            };
        }

        // Check for safe ports using config access
        let config = self.config_provider.security_config();
        if config.network_monitoring.safe_ports.contains(&port) {
            // Check if it's to a local address
            if dest_ip_str.starts_with("127.") || dest_ip_str.starts_with("::1") {
                return SecurityClassification {
                    severity: SeverityLevel::Low,
                    category: "Local Network Access".to_string(),
                    description: format!(
                        "Local connection to port {} ({})",
                        port,
                        event.protocol_as_str()
                    ),
                    risk_score: 10,
                };
            }

            return SecurityClassification {
                severity: SeverityLevel::Medium,
                category: "External Network Access".to_string(),
                description: format!(
                    "External connection to port {} ({})",
                    port,
                    event.protocol_as_str()
                ),
                risk_score: 40,
            };
        }

        // Default classification for unknown ports
        SecurityClassification {
            severity: SeverityLevel::Medium,
            category: "Unknown Network Access".to_string(),
            description: format!(
                "Connection to unknown port {} ({})",
                port,
                event.protocol_as_str()
            ),
            risk_score: 60,
        }
    }

    fn classify_secret_access_event(
        &self,
        event: &bee_trace_common::SecretAccessEvent,
    ) -> SecurityClassification {
        let path = event.path_or_var_as_str();

        match event.access_type {
            AccessType::File => {
                // Use the unified provider to check for sensitive files
                if self.config_provider.is_sensitive_file(path) {
                    // Determine criticality based on file content
                    if path.contains("id_rsa")
                        || path.contains("id_dsa")
                        || path.contains("id_ecdsa")
                        || path.contains("id_ed25519")
                        || path.ends_with(".pem")
                        || path.ends_with(".key")
                    {
                        SecurityClassification {
                            severity: SeverityLevel::Critical,
                            category: "Critical Secret File Access".to_string(),
                            description: format!("Access to cryptographic key file: {}", path),
                            risk_score: 95,
                        }
                    } else {
                        SecurityClassification {
                            severity: SeverityLevel::High,
                            category: "Secret File Access".to_string(),
                            description: format!(
                                "Access to sensitive configuration file: {}",
                                path
                            ),
                            risk_score: 80,
                        }
                    }
                }
                // System files
                else if path.starts_with("/etc/") {
                    SecurityClassification {
                        severity: SeverityLevel::Medium,
                        category: "System File Access".to_string(),
                        description: format!("Access to system configuration file: {}", path),
                        risk_score: 50,
                    }
                } else {
                    SecurityClassification {
                        severity: SeverityLevel::Medium,
                        category: "File Access".to_string(),
                        description: format!("Access to monitored file: {}", path),
                        risk_score: 45,
                    }
                }
            }
            AccessType::EnvVar => {
                // Critical environment variables
                if path.to_uppercase().contains("API_KEY")
                    || path.to_uppercase().contains("SECRET")
                    || path.to_uppercase().contains("TOKEN")
                    || path.to_uppercase().contains("PASSWORD")
                {
                    SecurityClassification {
                        severity: SeverityLevel::High,
                        category: "Secret Environment Variable Access".to_string(),
                        description: format!("Access to sensitive environment variable: {}", path),
                        risk_score: 85,
                    }
                } else {
                    SecurityClassification {
                        severity: SeverityLevel::Medium,
                        category: "Environment Variable Access".to_string(),
                        description: format!("Access to environment variable: {}", path),
                        risk_score: 40,
                    }
                }
            }
        }
    }

    fn classify_memory_event(
        &self,
        event: &bee_trace_common::ProcessMemoryEvent,
    ) -> SecurityClassification {
        let target_process = event.target_command_as_str();
        let syscall = event.syscall_type_as_str();

        // Use the unified provider to check if process should be monitored
        if !self.config_provider.should_monitor_process(target_process) {
            SecurityClassification {
                severity: SeverityLevel::Low,
                category: "Development Memory Access".to_string(),
                description: format!("Debug operation on {} using {}", target_process, syscall),
                risk_score: 20,
            }
        }
        // System processes
        else if target_process.starts_with("systemd") || target_process == "init" {
            SecurityClassification {
                severity: SeverityLevel::Critical,
                category: "Critical System Process Memory Access".to_string(),
                description: format!(
                    "Memory access to system process {} using {}",
                    target_process, syscall
                ),
                risk_score: 98,
            }
        }
        // Other processes
        else {
            SecurityClassification {
                severity: SeverityLevel::High,
                category: "Process Memory Access".to_string(),
                description: format!(
                    "Memory access to process {} using {}",
                    target_process, syscall
                ),
                risk_score: 75,
            }
        }
    }
}

impl<T: ConfigurationProvider> SecurityEventClassifier for ConfigurableSecurityClassifier<T> {
    fn classify(&self, event: &SecurityEvent) -> SecurityClassification {
        match event {
            SecurityEvent::Network(e) => self.classify_network_event(e),
            SecurityEvent::SecretAccess(e) => self.classify_secret_access_event(e),
            SecurityEvent::ProcessMemory(e) => self.classify_memory_event(e),
        }
    }

    fn should_alert(&self, classification: &SecurityClassification) -> bool {
        let severity_threshold = match self.alert_threshold {
            SeverityLevel::Low => 0,
            SeverityLevel::Medium => 1,
            SeverityLevel::High => 2,
            SeverityLevel::Critical => 3,
        };

        let event_severity = match classification.severity {
            SeverityLevel::Low => 0,
            SeverityLevel::Medium => 1,
            SeverityLevel::High => 2,
            SeverityLevel::Critical => 3,
        };

        event_severity >= severity_threshold
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::configuration::{Configuration, OptimizedConfigurationProvider};
    use bee_trace_common::{NetworkEvent, ProcessMemoryEvent, SecretAccessEvent};

    #[test]
    fn should_classify_suspicious_network_port() {
        let config = Configuration::builder().build().unwrap();
        let config_provider = OptimizedConfigurationProvider::new(config);
        let classifier =
            ConfigurableSecurityClassifier::new(config_provider, SeverityLevel::Medium);

        let network_event = NetworkEvent::new().with_dest_port(22).with_protocol_tcp();
        let security_event = SecurityEvent::Network(network_event);

        let classification = classifier.classify(&security_event);
        assert_eq!(classification.severity, SeverityLevel::High);
        assert!(classification.description.contains("suspicious port"));
        assert!(classification.risk_score >= 80);
    }

    #[test]
    fn should_classify_safe_network_port() {
        let config = Configuration::builder().build().unwrap();
        let config_provider = OptimizedConfigurationProvider::new(config);
        let classifier =
            ConfigurableSecurityClassifier::new(config_provider, SeverityLevel::Medium);

        let network_event = NetworkEvent::new().with_dest_port(443).with_protocol_tcp();
        let security_event = SecurityEvent::Network(network_event);

        let classification = classifier.classify(&security_event);
        assert_eq!(classification.severity, SeverityLevel::Medium);
        assert!(classification.risk_score < 80);
    }

    #[test]
    fn should_classify_critical_secret_file() {
        let config = Configuration::builder().build().unwrap();
        let config_provider = OptimizedConfigurationProvider::new(config);
        let classifier =
            ConfigurableSecurityClassifier::new(config_provider, SeverityLevel::Medium);

        let secret_event = SecretAccessEvent::new().with_file_access(b"id_rsa");
        let security_event = SecurityEvent::SecretAccess(secret_event);

        let classification = classifier.classify(&security_event);
        assert_eq!(classification.severity, SeverityLevel::Critical);
        assert!(classification.description.contains("cryptographic key"));
        assert!(classification.risk_score >= 90);
    }

    #[test]
    fn should_classify_memory_access_to_system_process() {
        let config = Configuration::builder().build().unwrap();
        let config_provider = OptimizedConfigurationProvider::new(config);
        let classifier =
            ConfigurableSecurityClassifier::new(config_provider, SeverityLevel::Medium);

        let memory_event = ProcessMemoryEvent::new()
            .with_target_command(b"systemd")
            .with_ptrace();
        let security_event = SecurityEvent::ProcessMemory(memory_event);

        let classification = classifier.classify(&security_event);
        assert_eq!(classification.severity, SeverityLevel::Critical);
        assert!(classification.description.contains("system process"));
        assert!(classification.risk_score >= 95);
    }

    #[test]
    fn should_determine_alert_threshold() {
        let config = Configuration::builder().build().unwrap();
        let config_provider = OptimizedConfigurationProvider::new(config);
        let high_threshold_classifier =
            ConfigurableSecurityClassifier::new(config_provider, SeverityLevel::High);

        let medium_classification = SecurityClassification {
            severity: SeverityLevel::Medium,
            category: "Test".to_string(),
            description: "Test event".to_string(),
            risk_score: 50,
        };

        let high_classification = SecurityClassification {
            severity: SeverityLevel::High,
            category: "Test".to_string(),
            description: "Test event".to_string(),
            risk_score: 80,
        };

        assert!(!high_threshold_classifier.should_alert(&medium_classification));
        assert!(high_threshold_classifier.should_alert(&high_classification));
    }
}
