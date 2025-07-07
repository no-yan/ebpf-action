//! Tests for unified configuration system following t-wada's TDD principles
//!
//! These tests define the expected behavior of the new configuration
//! system before implementation exists (Red phase of TDD).

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
        // Output format removed - always JSON
        assert!(config.security.network_monitoring.blocked_ips.is_empty());
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

// File configuration tests removed as YAGNI - functionality not used in production

mod configuration_integration_tests {
    use super::*;

    #[test]
    fn should_combine_multiple_configuration_sources() {
        let config = Configuration::builder()
            .from_cli_args(&["--probe-type", "all", "--verbose"])
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

mod configuration_provider_tests {
    use super::*;
    #[test]
    fn should_detect_sensitive_files_via_configuration() {
        let config = Configuration::builder().build().unwrap();

        // Test optimized implementation with internal caching
        assert!(config.is_sensitive_file("id_rsa"));
        assert!(config.is_sensitive_file("credentials.json"));
        assert!(config.is_sensitive_file("test.pem"));
        assert!(!config.is_sensitive_file("regular.txt"));
    }

    #[test]
    fn should_detect_suspicious_ports_via_configuration() {
        let config = Configuration::builder().build().unwrap();

        // Test optimized implementation with internal caching
        assert!(config.is_suspicious_port(22));
        assert!(config.is_suspicious_port(3389));
        assert!(!config.is_suspicious_port(80));
        assert!(!config.is_suspicious_port(443));
    }

    #[test]
    fn should_handle_process_monitoring_via_configuration() {
        let config = Configuration::builder().build().unwrap();

        // Test optimized implementation with internal caching
        assert!(!config.should_monitor_process("gdb"));
        assert!(!config.should_monitor_process("strace"));
        assert!(config.should_monitor_process("suspicious_process"));
    }

    #[test]
    fn should_provide_security_config_access() {
        let config = Configuration::builder().build().unwrap();

        let security_config = config.security_config();
        assert!(!security_config.file_monitoring.sensitive_files.is_empty());
        assert!(!security_config
            .network_monitoring
            .suspicious_ports
            .is_empty());
        assert!(security_config.memory_monitoring.monitor_ptrace);
    }

    #[test]
    fn should_handle_ip_and_domain_blocking() {
        let config = Configuration::builder().build().unwrap();

        // Default config should not block any IPs or domains
        assert!(!config.is_ip_blocked("192.168.1.1"));
        assert!(!config.is_domain_blocked("example.com"));
    }
}
