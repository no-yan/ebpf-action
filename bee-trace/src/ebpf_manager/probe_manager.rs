//! Core ProbeManager trait definition
//!
//! This trait defines the interface for eBPF probe management,
//! following deep module design principles from A Philosophy of Software Design.

use crate::errors::{ProbeType, Result};
use aya::Ebpf;
use std::collections::HashSet;

/// Abstract interface for managing eBPF probes
///
/// This trait provides a clean abstraction over complex eBPF operations:
/// - Hides the complexity of eBPF program loading and attachment
/// - Provides clear error handling and state management
/// - Enables different implementation strategies (real vs mock)
pub trait ProbeManager {
    /// Attach a specific probe type to the eBPF program
    ///
    /// This method encapsulates all the complexity of:
    /// - Loading the appropriate eBPF programs
    /// - Attaching them to the correct kernel hooks
    /// - Managing the attachment state
    fn attach(&mut self, ebpf: &mut Ebpf, probe_type: ProbeType) -> Result<()>;

    /// Detach a specific probe type
    ///
    /// Cleanly removes probes and updates internal state
    fn detach(&mut self, probe_type: ProbeType) -> Result<()>;

    /// Check if a probe type is currently attached
    fn is_attached(&self, probe_type: ProbeType) -> bool;

    /// Get all currently attached probe types
    fn attached_probes(&self) -> &HashSet<ProbeType>;

    /// Get probe-specific program names for a probe type
    ///
    /// This provides transparency into which eBPF programs
    /// are associated with each probe type
    fn program_names(&self, probe_type: ProbeType) -> Vec<&'static str>;
}
