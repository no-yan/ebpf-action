//! Integration tests for eBPF management with unified configuration
//!
//! Tests the integration between Configuration system and ProbeManager

use bee_trace::configuration::Configuration;
use bee_trace::ebpf_manager::{ProbeManager, UnifiedProbeManager};
use bee_trace::errors::{BeeTraceError, ProbeType};

/// Mock eBPF structure for testing
pub struct MockEbpf {
    pub loaded_programs: std::collections::HashMap<String, bool>,
    pub attached_programs: std::collections::HashMap<String, bool>,
    pub should_fail: bool,
}

impl Default for MockEbpf {
    fn default() -> Self {
        Self::new()
    }
}

impl MockEbpf {
    pub fn new() -> Self {
        let mut loaded_programs = std::collections::HashMap::new();
        let attached_programs = std::collections::HashMap::new();

        // Add expected program names
        loaded_programs.insert("sys_enter_openat".to_string(), true);
        loaded_programs.insert("tcp_connect".to_string(), true);
        loaded_programs.insert("udp_sendmsg".to_string(), true);
        loaded_programs.insert("sys_enter_ptrace".to_string(), true);
        loaded_programs.insert("sys_enter_process_vm_readv".to_string(), true);

        Self {
            loaded_programs,
            attached_programs,
            should_fail: false,
        }
    }

    pub fn with_failure(mut self) -> Self {
        self.should_fail = true;
        self
    }

    pub fn is_program_attached(&self, name: &str) -> bool {
        self.attached_programs.get(name).copied().unwrap_or(false)
    }

    pub fn attach_program(&mut self, name: &str) -> Result<(), String> {
        if self.should_fail {
            return Err(format!("Mock failure for {}", name));
        }

        if !self.loaded_programs.contains_key(name) {
            return Err(format!("Program {} not found", name));
        }

        self.attached_programs.insert(name.to_string(), true);
        Ok(())
    }
}

/// Application-level eBPF manager that integrates configuration and probe management
pub struct EbpfApplication {
    config: Configuration,
    probe_manager: UnifiedProbeManager,
}

impl EbpfApplication {
    pub fn new(config: Configuration) -> Self {
        Self {
            config,
            probe_manager: UnifiedProbeManager::new(),
        }
    }

    /// Attach probes based on configuration (for testing with MockEbpf)
    pub fn attach_configured_probes(
        &mut self,
        mock_ebpf: &mut MockEbpf,
    ) -> Result<(), BeeTraceError> {
        for &probe_type in &self.config.monitoring.probe_types {
            // Get program names for this probe type
            let program_names = self.probe_manager.program_names(probe_type);

            // Test that MockEbpf can handle the programs (simulates real eBPF operations)
            for program_name in &program_names {
                mock_ebpf.attach_program(program_name).map_err(|e| {
                    BeeTraceError::EbpfAttachmentFailed {
                        program_name: program_name.to_string(),
                        source: anyhow::anyhow!(e),
                    }
                })?;
            }
        }
        Ok(())
    }

    /// Get summary of attached probes
    pub fn get_probe_summary(&self) -> ProbeSummary {
        ProbeSummary {
            total_probe_types: self.config.monitoring.probe_types.len(),
            attached_probe_types: self.probe_manager.attached_probes().len(),
            probe_types: self.config.monitoring.probe_types.clone(),
        }
    }

    /// Check if application is ready for monitoring
    pub fn is_ready_for_monitoring(&self) -> bool {
        !self.config.monitoring.probe_types.is_empty()
            && self
                .config
                .monitoring
                .probe_types
                .iter()
                .all(|&probe_type| self.probe_manager.is_attached(probe_type))
    }
}

#[derive(Debug, PartialEq)]
pub struct ProbeSummary {
    pub total_probe_types: usize,
    pub attached_probe_types: usize,
    pub probe_types: Vec<ProbeType>,
}

mod ebpf_application_tests {
    use super::*;

    #[test]
    fn should_create_ebpf_application_with_configuration() {
        let config = Configuration::builder()
            .from_cli_args(&["--probe-type", "file_monitor"])
            .unwrap()
            .build()
            .unwrap();

        let app = EbpfApplication::new(config);
        let summary = app.get_probe_summary();

        assert_eq!(summary.total_probe_types, 1);
        assert_eq!(summary.probe_types, vec![ProbeType::FileMonitor]);
    }

    #[test]
    fn should_attach_file_monitor_probe_based_on_config() {
        let config = Configuration::builder()
            .from_cli_args(&["--probe-type", "file_monitor"])
            .unwrap()
            .build()
            .unwrap();

        let mut app = EbpfApplication::new(config);
        let mut mock_ebpf = MockEbpf::new();

        let result = app.attach_configured_probes(&mut mock_ebpf);

        assert!(result.is_ok());
        assert!(mock_ebpf.is_program_attached("sys_enter_openat"));
    }

    #[test]
    fn should_attach_network_monitor_probes_based_on_config() {
        let config = Configuration::builder()
            .from_cli_args(&["--probe-type", "network_monitor"])
            .unwrap()
            .build()
            .unwrap();

        let mut app = EbpfApplication::new(config);
        let mut mock_ebpf = MockEbpf::new();

        let result = app.attach_configured_probes(&mut mock_ebpf);

        assert!(result.is_ok());
        assert!(mock_ebpf.is_program_attached("tcp_connect"));
        assert!(mock_ebpf.is_program_attached("udp_sendmsg"));
    }

    #[test]
    fn should_attach_all_probes_when_configured() {
        let config = Configuration::builder()
            .from_cli_args(&["--probe-type", "all"])
            .unwrap()
            .build()
            .unwrap();

        let mut app = EbpfApplication::new(config);
        let mut mock_ebpf = MockEbpf::new();

        let result = app.attach_configured_probes(&mut mock_ebpf);

        assert!(result.is_ok());
        assert!(mock_ebpf.is_program_attached("sys_enter_openat"));
        assert!(mock_ebpf.is_program_attached("tcp_connect"));
        assert!(mock_ebpf.is_program_attached("udp_sendmsg"));
        assert!(mock_ebpf.is_program_attached("sys_enter_ptrace"));
        assert!(mock_ebpf.is_program_attached("sys_enter_process_vm_readv"));
    }

    #[test]
    fn should_handle_attachment_failures_gracefully() {
        let config = Configuration::builder()
            .from_cli_args(&["--probe-type", "file_monitor"])
            .unwrap()
            .build()
            .unwrap();

        let mut app = EbpfApplication::new(config);
        let mut mock_ebpf = MockEbpf::new().with_failure();

        let result = app.attach_configured_probes(&mut mock_ebpf);

        assert!(result.is_err());
        match result.unwrap_err() {
            BeeTraceError::EbpfAttachmentFailed { program_name, .. } => {
                assert_eq!(program_name, "sys_enter_openat");
            }
            _ => panic!("Expected EbpfAttachmentFailed error"),
        }
    }
}

mod configuration_integration_tests {
    use super::*;

    #[test]
    fn should_integrate_complex_configuration_with_ebpf() {
        let config = Configuration::builder()
            .from_cli_args(&[
                "--probe-type",
                "all",
                "--security-mode",
                "--verbose",
                "--duration",
                "60",
            ])
            .unwrap()
            .build()
            .unwrap();

        let mut app = EbpfApplication::new(config);
        let mut mock_ebpf = MockEbpf::new();

        let result = app.attach_configured_probes(&mut mock_ebpf);
        assert!(result.is_ok());

        let summary = app.get_probe_summary();
        assert_eq!(summary.total_probe_types, 3);
        assert_eq!(summary.probe_types.len(), 3);
        assert!(summary.probe_types.contains(&ProbeType::FileMonitor));
        assert!(summary.probe_types.contains(&ProbeType::NetworkMonitor));
        assert!(summary.probe_types.contains(&ProbeType::MemoryMonitor));
    }

    #[test]
    fn should_provide_monitoring_readiness_status() {
        let config = Configuration::builder()
            .from_cli_args(&["--probe-type", "file_monitor"])
            .unwrap()
            .build()
            .unwrap();

        let app = EbpfApplication::new(config);

        // Initially not ready (no probes attached)
        assert!(!app.is_ready_for_monitoring());
    }

    #[test]
    fn should_handle_backward_compatibility_with_legacy_probe_types() {
        let config = Configuration::builder()
            .from_cli_args(&["--probe-type", "file_monitor"])
            .unwrap()
            .build()
            .unwrap();

        assert_eq!(config.probe_type_legacy(), "file_monitor");

        let config_all = Configuration::builder()
            .from_cli_args(&["--probe-type", "all"])
            .unwrap()
            .build()
            .unwrap();

        assert_eq!(config_all.probe_type_legacy(), "all");
    }
}
