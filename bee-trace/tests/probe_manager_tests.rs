//! Tests for ProbeManager trait following t-wada's TDD principles
//!
//! These tests define the expected behavior of probe management
//! before implementation exists (Red phase of TDD).

use bee_trace::errors::{BeeTraceError, ProbeType, Result};
use std::collections::HashSet;

/// Abstract interface for managing eBPF probes
///
/// This trait follows A Philosophy of Software Design principles:
/// - Simple interface hiding complex implementation
/// - Each method has a single, well-defined responsibility
/// - Error handling is explicit and informative
pub trait ProbeManager {
    /// Attach a specific probe type - for testing we don't require actual eBPF
    fn attach(&mut self, probe_type: ProbeType) -> Result<()>;

    /// Detach a specific probe type
    fn detach(&mut self, probe_type: ProbeType) -> Result<()>;

    /// Check if a probe type is currently attached
    fn is_attached(&self, probe_type: ProbeType) -> bool;

    /// Get all currently attached probe types
    fn attached_probes(&self) -> &HashSet<ProbeType>;

    /// Get probe-specific program names for a probe type
    fn program_names(&self, probe_type: ProbeType) -> Vec<&'static str>;
}

/// Mock implementation for testing
struct MockProbeManager {
    attached: HashSet<ProbeType>,
    should_fail_attachment: bool,
}

impl MockProbeManager {
    fn new() -> Self {
        Self {
            attached: HashSet::new(),
            should_fail_attachment: false,
        }
    }

    fn with_attachment_failure(mut self) -> Self {
        self.should_fail_attachment = true;
        self
    }
}

impl ProbeManager for MockProbeManager {
    fn attach(&mut self, probe_type: ProbeType) -> Result<()> {
        if self.should_fail_attachment {
            return Err(BeeTraceError::EbpfAttachmentFailed {
                program_name: probe_type.as_str().to_string(),
                source: anyhow::anyhow!("Mock attachment failure"),
            });
        }

        if self.attached.contains(&probe_type) {
            return Err(BeeTraceError::ProbeAlreadyAttached { probe_type });
        }

        self.attached.insert(probe_type);
        Ok(())
    }

    fn detach(&mut self, probe_type: ProbeType) -> Result<()> {
        if !self.attached.remove(&probe_type) {
            return Err(BeeTraceError::ProbeNotFound { probe_type });
        }
        Ok(())
    }

    fn is_attached(&self, probe_type: ProbeType) -> bool {
        self.attached.contains(&probe_type)
    }

    fn attached_probes(&self) -> &HashSet<ProbeType> {
        &self.attached
    }

    fn program_names(&self, probe_type: ProbeType) -> Vec<&'static str> {
        match probe_type {
            ProbeType::FileMonitor => vec!["sys_enter_openat"],
            ProbeType::NetworkMonitor => vec!["tcp_connect", "udp_sendmsg"],
            ProbeType::MemoryMonitor => vec!["sys_enter_ptrace", "sys_enter_process_vm_readv"],
        }
    }
}

mod probe_manager_basic_operations {
    use super::*;

    #[test]
    fn should_attach_file_monitor_probe() {
        let mut manager = MockProbeManager::new();

        let result = manager.attach(ProbeType::FileMonitor);

        assert!(result.is_ok());
        assert!(manager.is_attached(ProbeType::FileMonitor));
        assert_eq!(manager.attached_probes().len(), 1);
    }

    #[test]
    fn should_not_attach_already_attached_probe() {
        let mut manager = MockProbeManager::new();

        // First attachment should succeed
        let _ = manager.attach(ProbeType::FileMonitor);

        // Second attachment should fail
        let result = manager.attach(ProbeType::FileMonitor);

        assert!(result.is_err());
        match result.unwrap_err() {
            BeeTraceError::ProbeAlreadyAttached { probe_type } => {
                assert_eq!(probe_type, ProbeType::FileMonitor);
            }
            _ => panic!("Expected ProbeAlreadyAttached error"),
        }
    }

    #[test]
    fn should_detach_attached_probe() {
        let mut manager = MockProbeManager::new();

        // Attach first
        let _ = manager.attach(ProbeType::NetworkMonitor);
        assert!(manager.is_attached(ProbeType::NetworkMonitor));

        // Then detach
        let result = manager.detach(ProbeType::NetworkMonitor);
        assert!(result.is_ok());
        assert!(!manager.is_attached(ProbeType::NetworkMonitor));
        assert_eq!(manager.attached_probes().len(), 0);
    }

    #[test]
    fn should_fail_to_detach_non_attached_probe() {
        let mut manager = MockProbeManager::new();

        let result = manager.detach(ProbeType::MemoryMonitor);
        assert!(result.is_err());

        match result.unwrap_err() {
            BeeTraceError::ProbeNotFound { probe_type } => {
                assert_eq!(probe_type, ProbeType::MemoryMonitor);
            }
            _ => panic!("Expected ProbeNotFound error"),
        }
    }

    #[test]
    fn should_track_multiple_attached_probes() {
        let mut manager = MockProbeManager::new();

        let _ = manager.attach(ProbeType::FileMonitor);
        let _ = manager.attach(ProbeType::NetworkMonitor);

        assert!(manager.is_attached(ProbeType::FileMonitor));
        assert!(manager.is_attached(ProbeType::NetworkMonitor));
        assert!(!manager.is_attached(ProbeType::MemoryMonitor));
        assert_eq!(manager.attached_probes().len(), 2);
    }
}

mod probe_manager_program_names {
    use super::*;

    #[test]
    fn should_return_correct_program_names_for_file_monitor() {
        let manager = MockProbeManager::new();
        let programs = manager.program_names(ProbeType::FileMonitor);

        assert_eq!(programs, vec!["sys_enter_openat"]);
    }

    #[test]
    fn should_return_correct_program_names_for_network_monitor() {
        let manager = MockProbeManager::new();
        let programs = manager.program_names(ProbeType::NetworkMonitor);

        assert_eq!(programs, vec!["tcp_connect", "udp_sendmsg"]);
    }

    #[test]
    fn should_return_correct_program_names_for_memory_monitor() {
        let manager = MockProbeManager::new();
        let programs = manager.program_names(ProbeType::MemoryMonitor);

        assert_eq!(
            programs,
            vec!["sys_enter_ptrace", "sys_enter_process_vm_readv"]
        );
    }
}

mod probe_manager_error_handling {
    use super::*;

    #[test]
    fn should_handle_attachment_failures_gracefully() {
        let mut manager = MockProbeManager::new().with_attachment_failure();

        let result = manager.attach(ProbeType::FileMonitor);

        assert!(result.is_err());
        match result.unwrap_err() {
            BeeTraceError::EbpfAttachmentFailed { program_name, .. } => {
                assert_eq!(program_name, "file_monitor");
            }
            _ => panic!("Expected EbpfAttachmentFailed error"),
        }

        // Probe should not be marked as attached on failure
        assert!(!manager.is_attached(ProbeType::FileMonitor));
    }
}
