//! Tests for unified configuration system following t-wada's TDD principles
//!
//! These tests define the expected behavior of the new configuration
//! system before implementation exists (Red phase of TDD).

use bee_trace::configuration::types::*;
use bee_trace::configuration::Configuration;
use bee_trace::errors::{BeeTraceError, ProbeType};
use std::path::PathBuf;
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

mod configuration_integration_tests {
    use super::*;

    #[test]
    fn should_combine_multiple_configuration_sources() {
        let config = Configuration::builder()
            .from_cli_args(&["--probe-type", "all", "--verbose"])
            .unwrap()
            .from_config_file("test-config.yaml")
            .unwrap()
            .from_environment()
            .unwrap()
            .build()
            .unwrap();

        assert_eq!(config.monitoring.probe_types, ProbeType::all());
        assert!(config.output.verbose);
        assert_eq!(
            config.runtime.config_file,
            Some(PathBuf::from("test-config.yaml"))
        );
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
