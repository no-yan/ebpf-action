//! eBPF Application Integration
//!
//! This module provides the high-level application interface that integrates
//! Configuration and ProbeManager for complete eBPF management.

use super::{ProbeManager, UnifiedProbeManager};
use crate::configuration::Configuration;
use crate::errors::{ProbeType, Result};
use aya::Ebpf;

/// Production eBPF application that integrates configuration and probe management
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

    /// Attach probes based on configuration
    pub fn attach_configured_probes(&mut self, ebpf: &mut Ebpf) -> Result<()> {
        for &probe_type in &self.config.monitoring.probe_types {
            self.probe_manager.attach(ebpf, probe_type)?;
        }
        Ok(())
    }

    /// Detach all currently attached probes
    pub fn detach_all_probes(&mut self) -> Result<()> {
        self.probe_manager.detach_all()
    }

    /// Check if a specific probe type is attached
    pub fn is_probe_attached(&self, probe_type: ProbeType) -> bool {
        self.probe_manager.is_attached(probe_type)
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

    /// Get configuration reference
    pub fn config(&self) -> &Configuration {
        &self.config
    }

    /// Get list of all program names that should be loaded for current configuration
    pub fn required_program_names(&self) -> Vec<&'static str> {
        let mut programs = Vec::new();
        for &probe_type in &self.config.monitoring.probe_types {
            programs.extend(self.probe_manager.program_names(probe_type));
        }
        programs.sort();
        programs.dedup();
        programs
    }
}

#[derive(Debug, PartialEq)]
pub struct ProbeSummary {
    pub total_probe_types: usize,
    pub attached_probe_types: usize,
    pub probe_types: Vec<ProbeType>,
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::configuration::Configuration;

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
        assert_eq!(summary.attached_probe_types, 0); // None attached initially
    }

    #[test]
    fn should_provide_required_program_names() {
        let config = Configuration::builder()
            .from_cli_args(&["--probe-type", "all"])
            .unwrap()
            .build()
            .unwrap();

        let app = EbpfApplication::new(config);
        let programs = app.required_program_names();

        // Should include programs from all probe types
        assert!(programs.contains(&"sys_enter_openat"));
        assert!(programs.contains(&"tcp_connect"));
        assert!(programs.contains(&"udp_sendmsg"));
        assert!(programs.contains(&"sys_enter_ptrace"));
        assert!(programs.contains(&"sys_enter_process_vm_readv"));
    }

    #[test]
    fn should_not_be_ready_for_monitoring_initially() {
        let config = Configuration::builder()
            .from_cli_args(&["--probe-type", "file_monitor"])
            .unwrap()
            .build()
            .unwrap();

        let app = EbpfApplication::new(config);

        // Should not be ready until probes are attached
        assert!(!app.is_ready_for_monitoring());
    }

    #[test]
    fn should_use_default_probe_type_when_none_specified() {
        // Default configuration should include FileMonitor
        let config = Configuration::builder().build().unwrap();

        assert_eq!(config.monitoring.probe_types, vec![ProbeType::FileMonitor]);

        let app = EbpfApplication::new(config);
        let summary = app.get_probe_summary();
        assert_eq!(summary.total_probe_types, 1);
        assert_eq!(summary.probe_types, vec![ProbeType::FileMonitor]);
    }
}
