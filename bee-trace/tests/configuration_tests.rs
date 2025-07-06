//! Tests for unified configuration system following t-wada's TDD principles
//!
//! These tests define the expected behavior of the new configuration
//! system before implementation exists (Red phase of TDD).

use bee_trace::configuration::types::*;
use bee_trace::configuration::Configuration;
use bee_trace::errors::{BeeTraceError, ProbeType};
use std::time::Duration;

// Test modules following t-wada's principles

mod configuration_builder_tests {
    use super::*;

    #[test]
    fn should_create_default_configuration() {
        let config = Configuration::builder().build().unwrap();

        assert_eq!(config.monitoring.probe_types, vec![ProbeType::FileMonitor]);
        assert_eq!(config.monitoring.duration, None);
        assert!(!config.monitoring.security_mode);
        assert!(!config.output.verbose);
        assert_eq!(config.output.format, OutputFormat::Json);
        assert!(config.security.blocked_ips.is_empty());
    }

    #[test]
    fn should_build_configuration_from_cli_args() {
        let config = Configuration::builder()
            .from_cli_args(&[
                "--probe-type",
                "network_monitor",
                "--verbose",
                "--security-mode",
            ])
            .unwrap()
            .build()
            .unwrap();

        assert_eq!(
            config.monitoring.probe_types,
            vec![ProbeType::NetworkMonitor]
        );
        assert!(config.output.verbose);
        assert!(config.monitoring.security_mode);
    }

    #[test]
    fn should_handle_all_probe_types() {
        let config = Configuration::builder()
            .from_cli_args(&["--probe-type", "all"])
            .unwrap()
            .build()
            .unwrap();

        assert_eq!(config.monitoring.probe_types, ProbeType::all());
        assert_eq!(config.probe_type_legacy(), "all");
    }

    #[test]
    fn should_parse_duration_from_cli() {
        let config = Configuration::builder()
            .from_cli_args(&["--duration", "60"])
            .unwrap()
            .build()
            .unwrap();

        assert_eq!(config.monitoring.duration, Some(Duration::from_secs(60)));
    }

    #[test]
    fn should_parse_command_filter_from_cli() {
        let config = Configuration::builder()
            .from_cli_args(&["--command", "nginx"])
            .unwrap()
            .build()
            .unwrap();

        assert_eq!(config.monitoring.command_filter, Some("nginx".to_string()));
    }
}

mod configuration_validation_tests {
    use super::*;

    #[test]
    fn should_reject_invalid_probe_type() {
        let result = Configuration::builder().from_cli_args(&["--probe-type", "invalid_probe"]);

        assert!(result.is_err());
        match result.unwrap_err() {
            BeeTraceError::InvalidProbeType { probe_type, .. } => {
                assert_eq!(probe_type, "invalid_probe");
            }
            _ => panic!("Expected InvalidProbeType error"),
        }
    }

    #[test]
    fn should_reject_invalid_duration() {
        let result = Configuration::builder().from_cli_args(&["--duration", "invalid"]);

        assert!(result.is_err());
        match result.unwrap_err() {
            BeeTraceError::ConfigError { message } => {
                assert!(message.contains("Invalid duration"));
            }
            _ => panic!("Expected ConfigError"),
        }
    }

    #[test]
    fn should_handle_missing_required_values() {
        let result = Configuration::builder().from_cli_args(&["--probe-type"]);

        assert!(result.is_err());
        match result.unwrap_err() {
            BeeTraceError::ConfigError { message } => {
                assert!(message.contains("Missing value for --probe-type"));
            }
            _ => panic!("Expected ConfigError"),
        }
    }
}

mod configuration_file_loading_tests {
    use super::*;
    use std::io::Write;
    use tempfile::NamedTempFile;

    #[test]
    fn should_load_yaml_configuration_from_file() {
        let yaml_content = r#"
file_monitoring:
  sensitive_files:
    - "custom.key"
    - "secret.json"
  sensitive_extensions:
    - ".custom"
  watch_directories: []
  exclude_patterns: []
network_monitoring:
  suspicious_ports:
    - 9999
  safe_ports: []
  blocked_ips:
    - "192.168.1.1"
  allowed_ips: []
memory_monitoring:
  monitor_ptrace: false
  monitor_process_vm: true
  excluded_processes:
    - "custom_process"
blocked_ips: []
blocked_domains: []
watch_files: []
secret_env_patterns: []
"#;

        let mut temp_file = NamedTempFile::new().unwrap();
        write!(temp_file, "{}", yaml_content).unwrap();

        let config = Configuration::builder()
            .from_config_file(temp_file.path())
            .unwrap()
            .build()
            .unwrap();

        assert_eq!(config.security.file_monitoring.sensitive_files.len(), 2);
        assert!(config
            .security
            .file_monitoring
            .sensitive_files
            .contains(&"custom.key".to_string()));
        assert!(config
            .security
            .network_monitoring
            .suspicious_ports
            .contains(&9999));
        assert!(!config.security.memory_monitoring.monitor_ptrace);
    }

    #[test]
    fn should_load_json_configuration_from_file() {
        let json_content = r#"
{
  "file_monitoring": {
    "sensitive_files": ["test.key"],
    "sensitive_extensions": [".test"],
    "watch_directories": ["/test"],
    "exclude_patterns": []
  },
  "network_monitoring": {
    "suspicious_ports": [8080],
    "safe_ports": [80],
    "blocked_ips": [],
    "allowed_ips": ["127.0.0.1"]
  },
  "memory_monitoring": {
    "monitor_ptrace": true,
    "monitor_process_vm": false,
    "excluded_processes": []
  },
  "blocked_ips": [],
  "blocked_domains": [],
  "watch_files": [],
  "secret_env_patterns": []
}
"#;

        let mut temp_file = NamedTempFile::with_suffix(".json").unwrap();
        write!(temp_file, "{}", json_content).unwrap();

        let config = Configuration::builder()
            .from_config_file(temp_file.path())
            .unwrap()
            .build()
            .unwrap();

        assert_eq!(config.security.file_monitoring.sensitive_files.len(), 1);
        assert!(config
            .security
            .file_monitoring
            .sensitive_files
            .contains(&"test.key".to_string()));
        assert!(config
            .security
            .network_monitoring
            .suspicious_ports
            .contains(&8080));
        assert!(!config.security.memory_monitoring.monitor_process_vm);
    }

    #[test]
    fn should_handle_invalid_yaml_config() {
        let invalid_yaml = "invalid: yaml: content: [";

        let mut temp_file = NamedTempFile::new().unwrap();
        write!(temp_file, "{}", invalid_yaml).unwrap();

        let result = Configuration::builder().from_config_file(temp_file.path());

        assert!(result.is_err());
        match result.unwrap_err() {
            BeeTraceError::ConfigError { message } => {
                assert!(message.contains("Failed to parse YAML config"));
            }
            _ => panic!("Expected ConfigError"),
        }
    }

    #[test]
    fn should_handle_missing_config_file() {
        let result = Configuration::builder().from_config_file("/nonexistent/path/config.yaml");

        assert!(result.is_err());
        match result.unwrap_err() {
            BeeTraceError::ConfigError { message } => {
                assert!(message.contains("Failed to read config file"));
            }
            _ => panic!("Expected ConfigError"),
        }
    }

    #[test]
    fn should_parse_yaml_from_string() {
        let yaml_content = r#"
file_monitoring:
  sensitive_files: ["string.key"]
  sensitive_extensions: []
  watch_directories: []
  exclude_patterns: []
network_monitoring:
  suspicious_ports: []
  safe_ports: []
  blocked_ips: []
  allowed_ips: []
memory_monitoring:
  monitor_ptrace: true
  monitor_process_vm: true
  excluded_processes: []
blocked_ips: []
blocked_domains: []
watch_files: []
secret_env_patterns: []
"#;

        let config = Configuration::builder()
            .from_yaml_str(yaml_content)
            .unwrap()
            .build()
            .unwrap();

        assert!(config
            .security
            .file_monitoring
            .sensitive_files
            .contains(&"string.key".to_string()));
    }

    #[test]
    fn should_parse_json_from_string() {
        let json_content = r#"
{
  "file_monitoring": {
    "sensitive_files": ["json.key"],
    "sensitive_extensions": [],
    "watch_directories": [],
    "exclude_patterns": []
  },
  "network_monitoring": {
    "suspicious_ports": [],
    "safe_ports": [],
    "blocked_ips": [],
    "allowed_ips": []
  },
  "memory_monitoring": {
    "monitor_ptrace": true,
    "monitor_process_vm": true,
    "excluded_processes": []
  },
  "blocked_ips": [],
  "blocked_domains": [],
  "watch_files": [],
  "secret_env_patterns": []
}
"#;

        let config = Configuration::builder()
            .from_json_str(json_content)
            .unwrap()
            .build()
            .unwrap();

        assert!(config
            .security
            .file_monitoring
            .sensitive_files
            .contains(&"json.key".to_string()));
    }
}

mod configuration_integration_tests {
    use super::*;

    #[test]
    fn should_combine_multiple_configuration_sources() {
        let config = Configuration::builder()
            .from_cli_args(&["--probe-type", "all", "--verbose"])
            .unwrap()
            .from_environment()
            .unwrap()
            .build()
            .unwrap();

        assert_eq!(config.monitoring.probe_types, ProbeType::all());
        assert!(config.output.verbose);
    }

    #[test]
    fn should_provide_backward_compatibility() {
        let config = Configuration::builder()
            .from_cli_args(&["--probe-type", "file_monitor"])
            .unwrap()
            .build()
            .unwrap();

        assert_eq!(config.probe_type_legacy(), "file_monitor");
        assert!(config.has_probe_type(ProbeType::FileMonitor));
        assert!(!config.has_probe_type(ProbeType::NetworkMonitor));
    }

    #[test]
    fn should_handle_complex_configuration_scenarios() {
        let config = Configuration::builder()
            .from_cli_args(&[
                "--probe-type",
                "all",
                "--duration",
                "300",
                "--command",
                "suspicious-app",
                "--verbose",
                "--security-mode",
            ])
            .unwrap()
            .build()
            .unwrap();

        assert_eq!(config.monitoring.probe_types.len(), 3);
        assert_eq!(config.monitoring.duration, Some(Duration::from_secs(300)));
        assert_eq!(
            config.monitoring.command_filter,
            Some("suspicious-app".to_string())
        );
        assert!(config.output.verbose);
        assert!(config.monitoring.security_mode);
    }
}
