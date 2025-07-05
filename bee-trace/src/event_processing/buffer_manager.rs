//! Perf Buffer Management
//!
//! Handles CPU detection and buffer coordination for eBPF perf event arrays.
//! eBPF perf buffers are per-CPU, so we must coordinate across all online CPUs
//! to avoid missing events. Buffer pools prevent allocation overhead in hot paths.

use aya::util::online_cpus;
use bytes::BytesMut;
use log::warn;

/// Manages perf buffers and CPU coordination
pub struct PerfBufferManager {
    cpus: Vec<u32>,
}

impl PerfBufferManager {
    /// Create a new buffer manager with online CPU detection
    pub fn new() -> anyhow::Result<Self> {
        let cpus = Self::detect_online_cpus()?;
        Ok(Self { cpus })
    }

    /// Get the list of online CPUs
    pub fn online_cpus(&self) -> &[u32] {
        &self.cpus
    }

    /// Create a pool of buffers for event reading
    pub fn create_buffer_pool(&self, buffer_size: usize, pool_size: usize) -> Vec<BytesMut> {
        (0..pool_size)
            .map(|_| BytesMut::with_capacity(buffer_size))
            .collect()
    }

    /// Detect online CPUs with error handling
    fn detect_online_cpus() -> anyhow::Result<Vec<u32>> {
        match online_cpus() {
            Ok(cpus) => {
                if cpus.is_empty() {
                    warn!("No online CPUs detected, defaulting to CPU 0");
                    Ok(vec![0])
                } else {
                    Ok(cpus)
                }
            }
            Err(e) => {
                warn!("Failed to detect online CPUs: {:?}, defaulting to CPU 0", e);
                Ok(vec![0])
            }
        }
    }
}

impl Default for PerfBufferManager {
    fn default() -> Self {
        Self::new().unwrap_or_else(|_| Self { cpus: vec![0] })
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn should_create_buffer_manager_with_cpus() {
        let manager = PerfBufferManager::new().unwrap();

        // Should have at least one CPU
        assert!(!manager.online_cpus().is_empty());
    }

    #[test]
    fn should_create_buffer_pool_with_correct_size() {
        let manager = PerfBufferManager::default();

        let buffers = manager.create_buffer_pool(1024, 10);

        assert_eq!(buffers.len(), 10);
        for buffer in &buffers {
            assert_eq!(buffer.capacity(), 1024);
        }
    }

    #[test]
    fn should_handle_empty_buffer_pool_request() {
        let manager = PerfBufferManager::default();

        let buffers = manager.create_buffer_pool(512, 0);

        assert!(buffers.is_empty());
    }

    #[test]
    fn should_provide_cpu_list() {
        let manager = PerfBufferManager::default();

        let cpus = manager.online_cpus();

        // Should provide at least CPU 0 as fallback
        assert!(!cpus.is_empty());
        assert!(cpus.contains(&0));
    }
}
