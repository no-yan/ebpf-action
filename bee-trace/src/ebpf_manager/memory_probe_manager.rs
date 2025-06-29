//! Memory Access Monitoring Probe Manager
//!
//! Manages eBPF probes for process memory access monitoring,
//! including ptrace and process_vm_readv system calls.

use super::probe_manager::ProbeManager;
use crate::errors::{BeeTraceError, ProbeType, Result};
use aya::{programs::TracePoint, Ebpf};
use log::info;
use std::collections::HashSet;

pub struct MemoryProbeManager {
    attached_probes: HashSet<ProbeType>,
}

impl MemoryProbeManager {
    pub fn new() -> Self {
        Self {
            attached_probes: HashSet::new(),
        }
    }
}

impl ProbeManager for MemoryProbeManager {
    fn attach(&mut self, ebpf: &mut Ebpf, probe_type: ProbeType) -> Result<()> {
        if probe_type != ProbeType::MemoryMonitor {
            return Err(BeeTraceError::InvalidProbeType {
                probe_type: probe_type.as_str().to_string(),
                valid_types: vec!["memory_monitor".to_string()],
            });
        }

        if self.attached_probes.contains(&probe_type) {
            return Err(BeeTraceError::ProbeAlreadyAttached { probe_type });
        }

        // Attach ptrace monitoring
        let ptrace_program: &mut TracePoint = ebpf
            .program_mut("sys_enter_ptrace")
            .ok_or_else(|| BeeTraceError::MapNotFound {
                map_name: "sys_enter_ptrace".to_string(),
            })?
            .try_into()
            .map_err(|e| BeeTraceError::EbpfLoadFailed {
                program_name: "sys_enter_ptrace".to_string(),
                source: anyhow::anyhow!("Failed to convert to TracePoint: {:?}", e),
            })?;

        ptrace_program
            .load()
            .map_err(|e| BeeTraceError::EbpfLoadFailed {
                program_name: "sys_enter_ptrace".to_string(),
                source: anyhow::anyhow!("Load failed: {:?}", e),
            })?;

        ptrace_program
            .attach("syscalls", "sys_enter_ptrace")
            .map_err(|e| BeeTraceError::EbpfAttachmentFailed {
                program_name: "sys_enter_ptrace".to_string(),
                source: anyhow::anyhow!("Attach failed: {:?}", e),
            })?;

        info!("Attached tracepoint to sys_enter_ptrace");

        // Attach process_vm_readv monitoring
        let vm_program: &mut TracePoint = ebpf
            .program_mut("sys_enter_process_vm_readv")
            .ok_or_else(|| BeeTraceError::MapNotFound {
                map_name: "sys_enter_process_vm_readv".to_string(),
            })?
            .try_into()
            .map_err(|e| BeeTraceError::EbpfLoadFailed {
                program_name: "sys_enter_process_vm_readv".to_string(),
                source: anyhow::anyhow!("Failed to convert to TracePoint: {:?}", e),
            })?;

        vm_program
            .load()
            .map_err(|e| BeeTraceError::EbpfLoadFailed {
                program_name: "sys_enter_process_vm_readv".to_string(),
                source: anyhow::anyhow!("Load failed: {:?}", e),
            })?;

        vm_program
            .attach("syscalls", "sys_enter_process_vm_readv")
            .map_err(|e| BeeTraceError::EbpfAttachmentFailed {
                program_name: "sys_enter_process_vm_readv".to_string(),
                source: anyhow::anyhow!("Attach failed: {:?}", e),
            })?;

        info!("Attached tracepoint to sys_enter_process_vm_readv");

        self.attached_probes.insert(probe_type);
        Ok(())
    }

    fn detach(&mut self, probe_type: ProbeType) -> Result<()> {
        if !self.attached_probes.remove(&probe_type) {
            return Err(BeeTraceError::ProbeNotFound { probe_type });
        }

        info!("Memory monitoring probes detached");
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
            ProbeType::MemoryMonitor => vec!["sys_enter_ptrace", "sys_enter_process_vm_readv"],
            _ => vec![],
        }
    }
}

impl Default for MemoryProbeManager {
    fn default() -> Self {
        Self::new()
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn should_create_memory_probe_manager() {
        let manager = MemoryProbeManager::new();
        assert_eq!(manager.attached_probes().len(), 0);
        assert!(!manager.is_attached(ProbeType::MemoryMonitor));
    }

    #[test]
    fn should_return_correct_program_names() {
        let manager = MemoryProbeManager::new();
        let programs = manager.program_names(ProbeType::MemoryMonitor);
        assert_eq!(
            programs,
            vec!["sys_enter_ptrace", "sys_enter_process_vm_readv"]
        );
    }

    #[test]
    fn should_reject_non_memory_probe_types() {
        let manager = MemoryProbeManager::new();
        let programs = manager.program_names(ProbeType::FileMonitor);
        assert!(programs.is_empty());
    }
}
