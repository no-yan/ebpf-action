//! Network Monitoring Probe Manager
//!
//! Manages eBPF probes for network connection monitoring,
//! including TCP and UDP traffic analysis.

use super::probe_manager::ProbeManager;
use crate::errors::{BeeTraceError, ProbeType, Result};
use aya::{programs::KProbe, Ebpf};
use log::info;
use std::collections::HashSet;

pub struct NetworkProbeManager {
    attached_probes: HashSet<ProbeType>,
}

impl NetworkProbeManager {
    pub fn new() -> Self {
        Self {
            attached_probes: HashSet::new(),
        }
    }
}

impl ProbeManager for NetworkProbeManager {
    fn attach(&mut self, ebpf: &mut Ebpf, probe_type: ProbeType) -> Result<()> {
        if probe_type != ProbeType::NetworkMonitor {
            return Err(BeeTraceError::InvalidProbeType {
                probe_type: probe_type.as_str().to_string(),
                valid_types: vec!["network_monitor".to_string()],
            });
        }

        if self.attached_probes.contains(&probe_type) {
            return Err(BeeTraceError::ProbeAlreadyAttached { probe_type });
        }

        // Attach TCP connection monitoring
        let tcp_program: &mut KProbe = ebpf
            .program_mut("tcp_connect")
            .ok_or_else(|| BeeTraceError::MapNotFound {
                map_name: "tcp_connect".to_string(),
            })?
            .try_into()
            .map_err(|e| BeeTraceError::EbpfLoadFailed {
                program_name: "tcp_connect".to_string(),
                source: anyhow::anyhow!("Failed to convert to KProbe: {:?}", e),
            })?;

        tcp_program
            .load()
            .map_err(|e| BeeTraceError::EbpfLoadFailed {
                program_name: "tcp_connect".to_string(),
                source: anyhow::anyhow!("Load failed: {:?}", e),
            })?;

        tcp_program
            .attach("tcp_connect", 0)
            .map_err(|e| BeeTraceError::EbpfAttachmentFailed {
                program_name: "tcp_connect".to_string(),
                source: anyhow::anyhow!("Attach failed: {:?}", e),
            })?;

        info!("Attached kprobe to tcp_connect");

        // Attach UDP monitoring
        let udp_program: &mut KProbe = ebpf
            .program_mut("udp_sendmsg")
            .ok_or_else(|| BeeTraceError::MapNotFound {
                map_name: "udp_sendmsg".to_string(),
            })?
            .try_into()
            .map_err(|e| BeeTraceError::EbpfLoadFailed {
                program_name: "udp_sendmsg".to_string(),
                source: anyhow::anyhow!("Failed to convert to KProbe: {:?}", e),
            })?;

        udp_program
            .load()
            .map_err(|e| BeeTraceError::EbpfLoadFailed {
                program_name: "udp_sendmsg".to_string(),
                source: anyhow::anyhow!("Load failed: {:?}", e),
            })?;

        udp_program
            .attach("udp_sendmsg", 0)
            .map_err(|e| BeeTraceError::EbpfAttachmentFailed {
                program_name: "udp_sendmsg".to_string(),
                source: anyhow::anyhow!("Attach failed: {:?}", e),
            })?;

        info!("Attached kprobe to udp_sendmsg");
        info!("Network monitoring active");

        self.attached_probes.insert(probe_type);
        Ok(())
    }

    fn detach(&mut self, probe_type: ProbeType) -> Result<()> {
        if !self.attached_probes.remove(&probe_type) {
            return Err(BeeTraceError::ProbeNotFound { probe_type });
        }

        info!("Network monitoring probes detached");
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
            ProbeType::NetworkMonitor => vec!["tcp_connect", "udp_sendmsg"],
            _ => vec![],
        }
    }
}

impl Default for NetworkProbeManager {
    fn default() -> Self {
        Self::new()
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn should_create_network_probe_manager() {
        let manager = NetworkProbeManager::new();
        assert_eq!(manager.attached_probes().len(), 0);
        assert!(!manager.is_attached(ProbeType::NetworkMonitor));
    }

    #[test]
    fn should_return_correct_program_names() {
        let manager = NetworkProbeManager::new();
        let programs = manager.program_names(ProbeType::NetworkMonitor);
        assert_eq!(programs, vec!["tcp_connect", "udp_sendmsg"]);
    }

    #[test]
    fn should_reject_non_network_probe_types() {
        let manager = NetworkProbeManager::new();
        let programs = manager.program_names(ProbeType::FileMonitor);
        assert!(programs.is_empty());
    }
}
