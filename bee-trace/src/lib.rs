use bee_trace_common::{NetworkEvent, ProcessMemoryEvent, SecretAccessEvent};
use clap::Parser;
use serde::{Deserialize, Serialize};

pub mod cli;
pub mod config;
pub mod report;

#[derive(Clone)]
pub enum SecurityEvent {
    Network(NetworkEvent),
    SecretAccess(SecretAccessEvent),
    ProcessMemory(ProcessMemoryEvent),
}

impl SecurityEvent {
    pub fn pid(&self) -> u32 {
        match self {
            SecurityEvent::Network(e) => e.pid,
            SecurityEvent::SecretAccess(e) => e.pid,
            SecurityEvent::ProcessMemory(e) => e.pid,
        }
    }

    pub fn command_as_str(&self) -> String {
        match self {
            SecurityEvent::Network(e) => e.command_as_str().to_string(),
            SecurityEvent::SecretAccess(e) => e.command_as_str().to_string(),
            SecurityEvent::ProcessMemory(e) => e.command_as_str().to_string(),
        }
    }
}

#[derive(Debug, Clone, Parser)]
#[clap(name = "bee-trace", about = "eBPF security monitoring tool")]
pub struct Args {
    #[clap(short, long, default_value = "file_monitor")]
    pub probe_type: String,

    #[clap(short, long, help = "Duration to run the tracer in seconds")]
    pub duration: Option<u64>,

    #[clap(short, long, help = "Filter by process name")]
    pub command: Option<String>,

    #[clap(short, long, help = "Show verbose output")]
    pub verbose: bool,

    #[clap(long, help = "Enable security monitoring mode")]
    pub security_mode: bool,

    #[clap(long, help = "Configuration file path")]
    pub config: Option<String>,
}

impl Args {
    pub fn validate(&self) -> Result<(), String> {
        match self.probe_type.as_str() {
            "file_monitor" | "network_monitor" | "memory_monitor" | "all" => Ok(()),
            _ => Err(format!("Unsupported probe type: {}", self.probe_type)),
        }
    }

    pub fn should_filter_security_event(&self, event: &SecurityEvent) -> bool {
        if let Some(cmd_filter) = &self.command {
            let comm = event.command_as_str();
            return comm.contains(cmd_filter);
        }
        true
    }

    pub fn should_show_security_event(&self, _event: &SecurityEvent) -> bool {
        // In security mode, show all events by default
        if self.security_mode {
            return true;
        }

        // Show all security events
        true
    }
}

#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct SecurityReport {
    pub metadata: ReportMetadata,
    pub summary: EventSummary,
    pub events: Vec<ReportEvent>,
}

#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct ReportMetadata {
    pub timestamp: String,
    pub duration_seconds: u64,
    pub probe_type: String,
    pub total_events: u64,
    pub version: String,
}

#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct EventSummary {
    pub file_events: u64,
    pub network_events: u64,
    pub secret_access_events: u64,
    pub memory_events: u64,
    pub high_severity_events: u64,
}

#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct ReportEvent {
    pub timestamp: String,
    pub event_type: String,
    pub severity: String,
    pub pid: u32,
    pub uid: u32,
    pub command: String,
    pub details: String,
}

impl SecurityReport {
    pub fn new(probe_type: String, duration: u64) -> Self {
        Self {
            metadata: ReportMetadata {
                timestamp: chrono::Utc::now().to_rfc3339(),
                duration_seconds: duration,
                probe_type,
                total_events: 0,
                version: env!("CARGO_PKG_VERSION").to_string(),
            },
            summary: EventSummary {
                file_events: 0,
                network_events: 0,
                secret_access_events: 0,
                memory_events: 0,
                high_severity_events: 0,
            },
            events: Vec::new(),
        }
    }

    pub fn add_event(&mut self, event: ReportEvent) {
        match event.event_type.as_str() {
            "FILE_READ" => self.summary.file_events += 1,
            "NETWORK" => self.summary.network_events += 1,
            "SECRET_FILE" | "SECRET_ENV" => self.summary.secret_access_events += 1,
            "PROC_MEMORY" => self.summary.memory_events += 1,
            _ => {}
        }

        if event.severity == "high" || event.severity == "critical" {
            self.summary.high_severity_events += 1;
        }

        self.events.push(event);
        self.metadata.total_events += 1;
    }

    pub fn to_json(&self) -> anyhow::Result<String> {
        Ok(serde_json::to_string_pretty(self)?)
    }

    pub fn to_markdown(&self) -> String {
        let mut md = String::new();

        md.push_str("# eBPF Security Monitoring Report\n\n");

        // Metadata
        md.push_str("## Metadata\n\n");
        md.push_str(&format!("- **Timestamp**: {}\n", self.metadata.timestamp));
        md.push_str(&format!(
            "- **Duration**: {} seconds\n",
            self.metadata.duration_seconds
        ));
        md.push_str(&format!("- **Probe Type**: {}\n", self.metadata.probe_type));
        md.push_str(&format!(
            "- **Total Events**: {}\n",
            self.metadata.total_events
        ));
        md.push_str(&format!("- **Version**: {}\n\n", self.metadata.version));

        // Summary
        md.push_str("## Summary\n\n");
        md.push_str("| Event Type | Count |\n");
        md.push_str("|------------|-------|\n");
        md.push_str(&format!("| File Access | {} |\n", self.summary.file_events));
        md.push_str(&format!(
            "| Network Activity | {} |\n",
            self.summary.network_events
        ));
        md.push_str(&format!(
            "| Secret Access | {} |\n",
            self.summary.secret_access_events
        ));
        md.push_str(&format!(
            "| Memory Access | {} |\n",
            self.summary.memory_events
        ));
        md.push_str(&format!(
            "| **High Severity** | **{}** |\n\n",
            self.summary.high_severity_events
        ));

        // Severity breakdown
        if self.summary.high_severity_events > 0 {
            md.push_str("⚠️  **High severity events detected!** ⚠️\n\n");
        } else {
            md.push_str("✅ No high severity events detected.\n\n");
        }

        // Events
        if !self.events.is_empty() {
            md.push_str("## Detailed Events\n\n");

            // Group events by severity
            let mut high_severity = Vec::new();
            let mut medium_severity = Vec::new();
            let mut low_severity = Vec::new();

            for event in &self.events {
                match event.severity.as_str() {
                    "high" | "critical" => high_severity.push(event),
                    "medium" => medium_severity.push(event),
                    _ => low_severity.push(event),
                }
            }

            if !high_severity.is_empty() {
                md.push_str("### 🔴 High Severity Events\n\n");
                for event in high_severity {
                    md.push_str(&format!(
                        "- **{}** [{}] PID:{} UID:{} CMD:{} - {}\n",
                        event.timestamp,
                        event.event_type,
                        event.pid,
                        event.uid,
                        event.command,
                        event.details
                    ));
                }
                md.push('\n');
            }

            if !medium_severity.is_empty() {
                md.push_str("### 🟡 Medium Severity Events\n\n");
                for event in medium_severity.iter().take(10) {
                    // Limit to first 10
                    md.push_str(&format!(
                        "- **{}** [{}] PID:{} CMD:{} - {}\n",
                        event.timestamp, event.event_type, event.pid, event.command, event.details
                    ));
                }
                if medium_severity.len() > 10 {
                    md.push_str(&format!(
                        "\n... and {} more medium severity events\n",
                        medium_severity.len() - 10
                    ));
                }
                md.push('\n');
            }

            if !low_severity.is_empty() {
                md.push_str(&format!(
                    "### 🟢 Low Severity Events: {} total\n\n",
                    low_severity.len()
                ));
                md.push_str("Low severity events are not detailed in this report for brevity.\n\n");
            }
        }

        md.push_str("---\n");
        md.push_str("*Generated by bee-trace eBPF Security Monitor*\n");

        md
    }
}

pub struct EventFormatter {
    verbose: bool,
}

impl EventFormatter {
    pub fn new(verbose: bool) -> Self {
        Self { verbose }
    }

    pub fn header(&self) -> String {
        if self.verbose {
            format!(
                "{:<8} {:<8} {:<16} {:<12} {:<64}",
                "PID", "UID", "COMMAND", "EVENT_TYPE", "DETAILS"
            )
        } else {
            format!(
                "{:<8} {:<16} {:<12} {:<48}",
                "PID", "COMMAND", "EVENT_TYPE", "DETAILS"
            )
        }
    }

    pub fn separator(&self) -> String {
        if self.verbose {
            "-".repeat(118)
        } else {
            "-".repeat(86)
        }
    }

    pub fn format_security_event(&self, event: &SecurityEvent) -> String {
        let pid = event.pid();
        let comm = event.command_as_str();

        match event {
            SecurityEvent::Network(e) => {
                let details = format!(
                    "{}:{} ({})",
                    e.dest_ip_as_str(),
                    e.dest_port,
                    if e.protocol == 0 { "TCP" } else { "UDP" }
                );
                if self.verbose {
                    format!(
                        "{:<8} {:<8} {:<16} {:<12} {:<64}",
                        pid, e.uid, comm, "NETWORK", details
                    )
                } else {
                    format!("{:<8} {:<16} {:<12} {:<48}", pid, comm, "NETWORK", details)
                }
            }
            SecurityEvent::SecretAccess(e) => {
                let details = e.path_or_var_as_str();
                let event_type = if e.access_type == 0 {
                    "SECRET_FILE"
                } else {
                    "SECRET_ENV"
                };
                if self.verbose {
                    format!(
                        "{:<8} {:<8} {:<16} {:<12} {:<64}",
                        pid, e.uid, comm, event_type, details
                    )
                } else {
                    let truncated = if details.len() > 48 {
                        format!("{}...", &details[..45])
                    } else {
                        details.to_string()
                    };
                    format!(
                        "{:<8} {:<16} {:<12} {:<48}",
                        pid, comm, event_type, truncated
                    )
                }
            }
            SecurityEvent::ProcessMemory(e) => {
                let details = format!(
                    "target_pid:{} ({})",
                    e.target_pid,
                    if e.syscall_type == 0 {
                        "ptrace"
                    } else {
                        "process_vm_readv"
                    }
                );
                if self.verbose {
                    format!(
                        "{:<8} {:<8} {:<16} {:<12} {:<64}",
                        pid, e.uid, comm, "PROC_MEMORY", details
                    )
                } else {
                    format!(
                        "{:<8} {:<16} {:<12} {:<48}",
                        pid, comm, "PROC_MEMORY", details
                    )
                }
            }
        }
    }
}

pub fn extract_string(bytes: &[u8]) -> String {
    let end = bytes.iter().position(|&b| b == 0).unwrap_or(bytes.len());
    String::from_utf8_lossy(&bytes[..end]).to_string()
}

pub fn extract_string_with_len(bytes: &[u8], len: usize) -> String {
    let actual_len = std::cmp::min(len, bytes.len());
    if actual_len == 0 {
        return String::new();
    }
    String::from_utf8_lossy(&bytes[..actual_len]).to_string()
}

#[cfg(test)]
mod tests {
    use super::*;

    mod args_validation {
        use super::*;

        #[test]
        fn should_accept_valid_probe_types() {
            let vfs_args = Args {
                probe_type: "file_monitor".to_string(),
                duration: None,
                command: None,
                verbose: false,
                security_mode: false,
                config: None,
            };
            assert!(vfs_args.validate().is_ok());

            let network_args = Args {
                probe_type: "network_monitor".to_string(),
                duration: None,
                command: None,
                verbose: false,
                security_mode: false,
                config: None,
            };
            assert!(network_args.validate().is_ok());
        }

        #[test]
        fn should_reject_invalid_probe_types() {
            let invalid_args = Args {
                probe_type: "invalid_probe".to_string(),
                duration: None,
                command: None,
                verbose: false,
                security_mode: false,
                config: None,
            };

            let result = invalid_args.validate();
            assert!(result.is_err());
            assert!(result.unwrap_err().contains("Unsupported probe type"));
        }
    }

    mod event_formatting {
        use super::*;

        #[test]
        fn should_format_header_for_verbose_mode() {
            let formatter = EventFormatter::new(true);
            let header = formatter.header();

            assert!(header.contains("PID"));
            assert!(header.contains("UID"));
            assert!(header.contains("COMMAND"));
            assert!(header.contains("EVENT_TYPE"));
            assert!(header.contains("DETAILS"));
        }

        #[test]
        fn should_format_header_for_non_verbose_mode() {
            let formatter = EventFormatter::new(false);
            let header = formatter.header();

            assert!(header.contains("PID"));
            assert!(!header.contains("UID"));
            assert!(header.contains("COMMAND"));
            assert!(header.contains("EVENT_TYPE"));
            assert!(header.contains("DETAILS"));
        }

        #[test]
        fn should_provide_correct_separator_length() {
            let verbose_formatter = EventFormatter::new(true);
            assert_eq!(verbose_formatter.separator().len(), 118);

            let non_verbose_formatter = EventFormatter::new(false);
            assert_eq!(non_verbose_formatter.separator().len(), 86);
        }
    }

    mod string_utilities {
        use super::*;

        #[test]
        fn should_extract_null_terminated_string() {
            let bytes = b"hello\0world";
            let result = extract_string(bytes);
            assert_eq!(result, "hello");
        }

        #[test]
        fn should_extract_string_without_null_terminator() {
            let bytes = b"hello";
            let result = extract_string(bytes);
            assert_eq!(result, "hello");
        }

        #[test]
        fn should_handle_empty_string() {
            let bytes = b"";
            let result = extract_string(bytes);
            assert_eq!(result, "");
        }

        #[test]
        fn should_extract_string_with_length() {
            let bytes = b"helloworld";
            let result = extract_string_with_len(bytes, 5);
            assert_eq!(result, "hello");
        }

        #[test]
        fn should_handle_length_exceeding_buffer() {
            let bytes = b"hello";
            let result = extract_string_with_len(bytes, 10);
            assert_eq!(result, "hello");
        }

        #[test]
        fn should_handle_zero_length() {
            let bytes = b"hello";
            let result = extract_string_with_len(bytes, 0);
            assert_eq!(result, "");
        }

        #[test]
        fn should_handle_invalid_utf8_gracefully() {
            let bytes = vec![0xFF, 0xFE, 0xFD];
            let result = extract_string(&bytes);
            // Should not panic and should produce some string representation
            assert!(!result.is_empty());
        }
    }
}
