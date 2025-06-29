//! File Monitoring Probe Manager
//!
//! Manages eBPF probes for file system monitoring,
//! specifically focused on secret file access detection.

use super::probe_manager::ProbeManager;
use crate::errors::{BeeTraceError, ProbeType, Result};
use aya::{programs::TracePoint, Ebpf};
use log::info;
use std::collections::HashSet;

pub struct FileProbeManager {
    attached_probes: HashSet<ProbeType>,
}

impl FileProbeManager {
    pub fn new() -> Self {
        Self {
            attached_probes: HashSet::new(),
        }
    }
}

impl ProbeManager for FileProbeManager {
    fn attach(&mut self, ebpf: &mut Ebpf, probe_type: ProbeType) -> Result<()> {
        if probe_type != ProbeType::FileMonitor {
            return Err(BeeTraceError::InvalidProbeType {
                probe_type: probe_type.as_str().to_string(),
                valid_types: vec!["file_monitor".to_string()],
            });
        }

        if self.attached_probes.contains(&probe_type) {
            return Err(BeeTraceError::ProbeAlreadyAttached { probe_type });
        }

        // Attach sys_enter_openat tracepoint
        let program: &mut TracePoint = ebpf
            .program_mut("sys_enter_openat")
            .ok_or_else(|| BeeTraceError::MapNotFound {
                map_name: "sys_enter_openat".to_string(),
            })?
            .try_into()
            .map_err(|e| BeeTraceError::EbpfLoadFailed {
                program_name: "sys_enter_openat".to_string(),
                source: anyhow::anyhow!("Failed to convert to TracePoint: {:?}", e),
            })?;

        program.load().map_err(|e| BeeTraceError::EbpfLoadFailed {
            program_name: "sys_enter_openat".to_string(),
            source: anyhow::anyhow!("Load failed: {:?}", e),
        })?;

        program
            .attach("syscalls", "sys_enter_openat")
            .map_err(|e| BeeTraceError::EbpfAttachmentFailed {
                program_name: "sys_enter_openat".to_string(),
                source: anyhow::anyhow!("Attach failed: {:?}", e),
            })?;

        info!("Attached tracepoint to sys_enter_openat for file monitoring");
        self.attached_probes.insert(probe_type);
        Ok(())
    }

    fn detach(&mut self, probe_type: ProbeType) -> Result<()> {
        if !self.attached_probes.remove(&probe_type) {
            return Err(BeeTraceError::ProbeNotFound { probe_type });
        }

        // Note: aya doesn't provide explicit detach methods for programs
        // The programs are automatically detached when the Ebpf instance is dropped
        info!("File monitoring probe detached");
        Ok(())
    }

    fn is_attached(&self, probe_type: ProbeType) -> bool {
        self.attached_probes.contains(&probe_type)
    }

    fn attached_probes(&self) -> &HashSet<ProbeType> {
        &self.attached_probes
    }

    fn program_names(&self, probe_type: ProbeType) -> Vec<&'static str> {
        match probe_type {
            ProbeType::FileMonitor => vec!["sys_enter_openat"],
            _ => vec![],
        }
    }
}

impl Default for FileProbeManager {
    fn default() -> Self {
        Self::new()
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn should_create_file_probe_manager() {
        let manager = FileProbeManager::new();
        assert_eq!(manager.attached_probes().len(), 0);
        assert!(!manager.is_attached(ProbeType::FileMonitor));
    }

    #[test]
    fn should_return_correct_program_names() {
        let manager = FileProbeManager::new();
        let programs = manager.program_names(ProbeType::FileMonitor);
        assert_eq!(programs, vec!["sys_enter_openat"]);
    }

    #[test]
    fn should_reject_non_file_probe_types() {
        let manager = FileProbeManager::new();
        let programs = manager.program_names(ProbeType::NetworkMonitor);
        assert!(programs.is_empty());
    }
}
