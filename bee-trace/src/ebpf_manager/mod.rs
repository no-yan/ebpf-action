//! eBPF Probe Management
//!
//! This module provides a clean interface for managing eBPF probes,
//! following A Philosophy of Software Design principles:
//! - Deep modules that hide complexity
//! - Clear interfaces with minimal dependencies
//! - Proper error handling and state management

pub mod application;
pub mod file_probe_manager;
pub mod memory_probe_manager;
pub mod network_probe_manager;
pub mod probe_manager;

pub use application::{EbpfApplication, ProbeSummary};
pub use file_probe_manager::FileProbeManager;
pub use memory_probe_manager::MemoryProbeManager;
pub use network_probe_manager::NetworkProbeManager;
pub use probe_manager::ProbeManager;

use crate::errors::{BeeTraceError, ProbeType, Result};
use aya::Ebpf;
use std::collections::HashSet;

/// Unified probe manager that coordinates different probe types
pub struct UnifiedProbeManager {
    file_manager: FileProbeManager,
    network_manager: NetworkProbeManager,
    memory_manager: MemoryProbeManager,
    attached_probes: HashSet<ProbeType>,
}

impl UnifiedProbeManager {
    pub fn new() -> Self {
        Self {
            file_manager: FileProbeManager::new(),
            network_manager: NetworkProbeManager::new(),
            memory_manager: MemoryProbeManager::new(),
            attached_probes: HashSet::new(),
        }
    }

    pub fn attach_multiple(&mut self, ebpf: &mut Ebpf, probe_types: &[ProbeType]) -> Result<()> {
        for &probe_type in probe_types {
            self.attach(ebpf, probe_type)?;
        }
        Ok(())
    }

    pub fn detach_all(&mut self) -> Result<()> {
        let probe_types: Vec<ProbeType> = self.attached_probes.iter().cloned().collect();
        for probe_type in probe_types {
            self.detach(probe_type)?;
        }
        Ok(())
    }
}

impl ProbeManager for UnifiedProbeManager {
    fn attach(&mut self, ebpf: &mut Ebpf, probe_type: ProbeType) -> Result<()> {
        if self.attached_probes.contains(&probe_type) {
            return Err(BeeTraceError::ProbeAlreadyAttached { probe_type });
        }

        match probe_type {
            ProbeType::FileMonitor => self.file_manager.attach(ebpf, probe_type)?,
            ProbeType::NetworkMonitor => self.network_manager.attach(ebpf, probe_type)?,
            ProbeType::MemoryMonitor => self.memory_manager.attach(ebpf, probe_type)?,
        }

        self.attached_probes.insert(probe_type);
        Ok(())
    }

    fn detach(&mut self, probe_type: ProbeType) -> Result<()> {
        if !self.attached_probes.remove(&probe_type) {
            return Err(BeeTraceError::ProbeNotFound { probe_type });
        }

        match probe_type {
            ProbeType::FileMonitor => self.file_manager.detach(probe_type)?,
            ProbeType::NetworkMonitor => self.network_manager.detach(probe_type)?,
            ProbeType::MemoryMonitor => self.memory_manager.detach(probe_type)?,
        }

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
            ProbeType::FileMonitor => self.file_manager.program_names(probe_type),
            ProbeType::NetworkMonitor => self.network_manager.program_names(probe_type),
            ProbeType::MemoryMonitor => self.memory_manager.program_names(probe_type),
        }
    }
}

impl Default for UnifiedProbeManager {
    fn default() -> Self {
        Self::new()
    }
}
